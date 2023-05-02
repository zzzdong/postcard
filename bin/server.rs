use std::io::{self};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use clap::Parser;
use hyper::body::HttpBody;
use hyper::{service::service_fn, Body, Request, Response, Version};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
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

fn bad_request(msg: impl ToString) -> Response<Body> {
    Response::builder()
        .status(400)
        .body(Body::from(msg.to_string()))
        .unwrap()
}

async fn proxy(mut req: Request<hyper::Body>) -> Result<Response<Body>, anyhow::Error> {
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
            while let Some(data) = req.body_mut().data().await {
                match data {
                    Ok(mut buf) => {
                        recv_count_cloned.fetch_add(buf.len(), Ordering::SeqCst);
                        if let Err(err) = write_half.write_buf(&mut buf).await {
                            error!(%err, "send body failed");
                            break;
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
        .body(Body::wrap_stream(stream))
        .unwrap();

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

    let mut http = hyper::server::conn::Http::new();

    let http = http.http2_only(true);

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
