use std::io::{self};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use clap::Parser;
use futures::StreamExt;
use http_body_util::{BodyStream, Full};
use hyper::body::{Frame, Incoming};
use hyper::{service::service_fn, Request, Response, Version};
use hyper_util::rt::TokioExecutor;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{BytesCodec, FramedRead};
use tracing::{debug, error, info, Instrument};

use postcard::secure_stream::{load_identify, SecureStream, DEST_ADDR};

#[derive(Parser, Debug)]
struct Args {
    /// Host to listen on
    #[clap(long, default_value = "0.0.0.0:8080")]
    host: String,
    /// Private key
    #[clap(long)]
    private_key: String,
    /// Public key
    #[clap(long)]
    public_key: String,
}

fn bad_request(msg: impl ToString) -> Response<HttpBody> {
    Response::builder()
        .status(400)
        .body(HttpBody::Simple(Full::new(Bytes::from(msg.to_string()))))
        .unwrap()
}

async fn proxy(req: Request<Incoming>) -> Result<Response<HttpBody>, anyhow::Error> {
    debug!("new connect");

    if req.version() != Version::HTTP_2 {
        return Ok(bad_request("not http2"));
    }

    let host = req.headers().get(DEST_ADDR);
    if host.is_none() {
        return Ok(bad_request("no host"));
    }

    let send_count = Arc::new(AtomicUsize::new(0));
    let recv_count = Arc::new(AtomicUsize::new(0));

    let recv_count_cloned = recv_count.clone();

    let dest = String::from_utf8(host.unwrap().as_bytes().to_vec()).unwrap();

    debug!("start connect to {}", dest);

    let socket = TcpStream::connect(&dest).await?;

    debug!("connected to {}", dest);

    let (read_half, mut write_half) = tokio::io::split(socket);

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

    let resp = Response::builder()
        .status(200)
        .body(HttpBody::Stream(stream))
        .unwrap();

    Ok(resp)
}

enum HttpBody {
    Simple(Full<Bytes>),
    Stream(FramedRead<ResponseMetric<OwnedReadHalf>, BytesCodec>),
}

impl hyper::body::Body for HttpBody {
    type Data = Bytes;

    type Error = anyhow::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            HttpBody::Simple(s) => {
                hyper::body::Body::poll_frame(Pin::new(s), cx).map_err(Into::into)
            }
            HttpBody::Stream(s) => s
                .poll_next_unpin(cx)
                .map(|b| b.map(|b| b.map(|b| Frame::data(b.freeze())).map_err(Into::into))),
        }
    }
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let args = Args::parse();

    tracing_subscriber::fmt::init();

    let addr: SocketAddr = args.host.parse().expect("can not parse host");

    let private_key = Arc::new(load_identify(&args.private_key)?);
    let public_key = Arc::new(load_identify(&args.public_key)?);

    let listener = TcpListener::bind(addr)
        .await
        .expect(&format!("can not bind {}", addr));

    info!("listening on {}", addr);

    let http = hyper::server::conn::http2::Builder::new(TokioExecutor::new());

    while let Ok((socket, remote_addr)) = listener.accept().await {
        let http = http.clone();

        let private_key_cloned = private_key.as_ref().clone();
        let public_key_cloned = public_key.as_ref().clone();

        tokio::spawn(
            async move {
                match SecureStream::handshake(socket, private_key_cloned, public_key_cloned).await {
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
