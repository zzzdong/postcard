use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::StreamExt;
use http_body_util::{BodyExt, BodyStream, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{service::service_fn, Request, Response, Version};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HttpClient;
use hyper_util::rt::TokioExecutor;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{BytesCodec, FramedRead};
use tracing::{debug, error, info, Instrument};

use crate::error::Error;
use crate::secure_stream::{load_identify, SecureStream, DEST_ADDR, PROXY_METHOD};
use crate::BoxBody;

fn get_http_client() -> HttpClient<HttpConnector, Incoming> {
    static HTTP_CLIENT: OnceLock<HttpClient<HttpConnector, Incoming>> = OnceLock::new();

    HTTP_CLIENT
        .get_or_init(|| {
            let connector = HttpConnector::new();
            HttpClient::builder(hyper_util::rt::TokioExecutor::new()).build(connector)
        })
        .clone()
}

fn bad_request(msg: impl ToString) -> Response<BoxBody> {
    Response::builder()
        .status(400)
        .body(
            Full::new(Bytes::from(msg.to_string()))
                .map_err(Into::into)
                .boxed(),
        )
        .unwrap()
}

async fn proxy(req: Request<Incoming>) -> Result<Response<BoxBody>, Error> {
    debug!("new connect");

    if req.version() != Version::HTTP_2 {
        return Ok(bad_request("not http2"));
    }

    let host = req.headers().get(DEST_ADDR);
    if host.is_none() {
        return Ok(bad_request("no host"));
    }

    let proxy_method = req.headers().get(PROXY_METHOD);
    if proxy_method.is_some() {
        let dest = String::from_utf8(host.unwrap().as_bytes().to_vec()).unwrap();
        let mut req = req;
        *req.uri_mut() = hyper::Uri::from_maybe_shared(dest).unwrap();
        *req.version_mut() = Version::HTTP_11;
        let http_client = get_http_client();
        let resp = http_client.request(req).await?;
        let resp = resp.map(|body| body.map_err(Into::into).boxed());
        return Ok(resp);
    }

    let send_count = Arc::new(AtomicUsize::new(0));
    let recv_count = Arc::new(AtomicUsize::new(0));

    let recv_count_cloned = recv_count.clone();

    let dest = String::from_utf8(host.unwrap().as_bytes().to_vec()).unwrap();

    debug!("start connect to {}", dest);

    let socket = TcpStream::connect(&dest).await?;

    let (read_half, mut write_half) = socket.into_split();

    tokio::spawn(
        async move {
            let mut stream = BodyStream::new(req.into_body());
            while let Some(data) = stream.next().await {
                match data {
                    Ok(frame) => {
                        if frame.is_data() {
                            let mut buf = frame.into_data().unwrap();
                            recv_count_cloned.fetch_add(buf.len(), Ordering::SeqCst);
                            if let Err(err) = write_half.write_buf(&mut buf).await {
                                error!(%err, "send body failed");
                                break;
                            }
                        }
                    }
                    Err(err) => {
                        error!(%err, "read body failed");
                        break;
                    }
                }
            }
        }
        .instrument(tracing::info_span!("conn", %dest)),
    );

    let stream = FramedRead::new(
        ResponseMetric::new(read_half, send_count, recv_count, dest),
        BytesCodec::new(),
    );

    let body = BodyExt::boxed(StreamBody::new(
        stream.map(|b| b.map(|b| Frame::data(b.freeze())).map_err(Into::into)),
    ));

    let resp = Response::builder().status(200).body(body).unwrap();

    Ok(resp)
}

struct ResponseMetric<R> {
    inner: R,
    send_count: Arc<AtomicUsize>,
    recv_count: Arc<AtomicUsize>,
    dest: String,
}

impl<R> ResponseMetric<R> {
    pub fn new(
        inner: R,
        send_count: Arc<AtomicUsize>,
        recv_count: Arc<AtomicUsize>,
        dest: String,
    ) -> Self {
        ResponseMetric {
            inner,
            send_count,
            recv_count,
            dest,
        }
    }
}

impl<R> Drop for ResponseMetric<R> {
    fn drop(&mut self) {
        info!(
            "proxy {:?} done, send {:?} bytes, recv {:?} bytes",
            self.dest, self.send_count, self.recv_count
        )
    }
}

impl<R> AsyncRead for ResponseMetric<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let start = buf.remaining();
        let ret = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.send_count
            .fetch_add(start - buf.remaining(), Ordering::SeqCst);
        ret
    }
}

pub async fn start_server(host: &str, private_key: &str, public_key: &str) -> Result<(), Error> {
    let addr: SocketAddr = host.parse().expect("can not parse host");

    let private_key = Arc::new(load_identify(private_key)?);
    let public_key = Arc::new(load_identify(public_key)?);

    let listener = TcpListener::bind(addr).await?;

    let http = hyper::server::conn::http2::Builder::new(TokioExecutor::new());

    while let Ok((socket, remote_addr)) = listener.accept().await {
        let http = http.clone();

        let privte_key_cloned = private_key.clone();
        let public_key_cloned = public_key.clone();

        tokio::spawn(
            async move {
                match SecureStream::handshake(
                    socket,
                    privte_key_cloned.as_ref(),
                    public_key_cloned.as_ref(),
                )
                .await
                {
                    Ok(secured_stream) => {
                        debug!("SecureStream handshake done");
                        let ret = http.serve_connection(
                            secured_stream,
                            service_fn(|req| async move { proxy(req).await }),
                        );

                        if let Err(e) = ret.await {
                            error!("server connection error: {}", e);
                        }
                    }
                    Err(err) => {
                        error!("SecureStream handshake failed, {:?}", err);
                    }
                }
            }
            .instrument(tracing::info_span!("remote_addr", %remote_addr)),
        );
    }

    Ok(())
}
