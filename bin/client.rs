use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use bytes::BytesMut;
use clap::Parser;

use hyper::client::connect::{Connected, Connection as HyperConnection};
use hyper::service::Service;
use hyper::{Body, Client, Uri};
use snowstorm::NoiseStream;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;

use std::net::SocketAddr;

use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{BytesCodec, Framed, FramedParts, FramedRead};
use tracing::{debug, error, info, trace, Instrument};

use postcard::codecs::socks5::*;
use postcard::errors::*;
use postcard::proto::socks5::consts::*;
use postcard::proto::socks5::*;
use postcard::utils::{load_identify, PATTERN};

#[derive(Parser, Debug)]
struct Args {
    /// Host to listen on
    #[clap(long, short, default_value = "0.0.0.0:1080")]
    host: String,
    /// Server to connect to
    #[clap(long, short)]
    server: String,
    /// Private key
    #[clap(long)]
    private_key: PathBuf,
    /// Public key
    #[clap(long)]
    public_key: PathBuf,
}

type CmdFramed = Framed<TcpStream, CmdCodec>;

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

fn dest_addr(req: &CmdRequest) -> Result<String, RsocksError> {
    let req = req.clone();
    match req.address {
        Address::IPv4(ip) => Ok(format!("{}:{}", ip, req.port)),
        Address::IPv6(ip) => Ok(format!("{}:{}", ip, req.port)),
        Address::DomainName(ref dn) => Ok(format!("{}:{}", dn, req.port)),
        Address::Unknown(_t) => Err(socks_error("bad address")),
    }
}

struct MyStream {
    inner: NoiseStream<TcpStream>,
    // inner: TcpStream,
}

impl AsyncRead for MyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.inner), cx, buf)
    }
}

impl AsyncWrite for MyStream {
    fn is_write_vectored(&self) -> bool {
        AsyncWrite::is_write_vectored(&self.inner)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.inner), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.inner), cx)
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.inner), cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        AsyncWrite::poll_write_vectored(Pin::new(&mut self.inner), cx, bufs)
    }
}

#[derive(Clone)]
struct NoiseConnector {
    private_key: Arc<Vec<u8>>,
    public_key: Arc<Vec<u8>>,
}

impl NoiseConnector {
    pub fn new(private_key: Arc<Vec<u8>>, public_key: Arc<Vec<u8>>) -> Self {
        NoiseConnector {
            private_key,
            public_key,
        }
    }
}

impl Service<Uri> for NoiseConnector {
    type Response = MyStream;
    type Error = anyhow::Error;
    type Future = Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let NoiseConnector {
            private_key,
            public_key,
        } = self.clone();

        Box::pin(async move {
            let authority = req
                .authority()
                .ok_or_else(|| error("uri not ok".to_string()))?;

            let remote = format!(
                "{}:{}",
                authority.host(),
                authority.port_u16().unwrap_or(8080)
            );

            debug!("try tcp connect to {:?}", &remote);

            // Connect to the peer
            let stream = TcpStream::connect(remote).await?;

            debug!("tcp connect done");

            // The client should build an initiator to launch the handshake process
            let initiator = snowstorm::Builder::new(PATTERN.parse()?)
                .local_private_key(&private_key)
                .remote_public_key(&public_key)
                .build_initiator()?;

            // Start handshaking
            let secured_stream = NoiseStream::handshake(stream, initiator).await?;

            // let secured_stream = stream;

            debug!("NoiseStream handshake done");

            Ok(MyStream {
                inner: secured_stream,
            })
        })
    }
}

impl HyperConnection for MyStream {
    fn connected(&self) -> Connected {
        self.inner.get_inner().connected()
        // self.inner.connected()
    }
}

#[derive(Clone)]
struct Connection {
    remote: String,
    http: hyper::Client<NoiseConnector, Body>,
}

impl Connection {
    pub fn new(remote: impl ToString, http: hyper::Client<NoiseConnector, Body>) -> Self {
        Connection {
            remote: remote.to_string(),
            http,
        }
    }

    pub async fn proxy(&mut self, socket: TcpStream) -> Result<(), anyhow::Error> {
        let cmd = self.handshake(socket).await?;

        let (body, write_half) = self.socks5_cmd(cmd).await?;

        Self::streaming(body, write_half).await?;

        Ok(())
    }

    async fn handshake(&self, socket: TcpStream) -> Result<CmdFramed, RsocksError> {
        let (framed, mut stream) = Framed::new(socket, HandshakeCodec).into_future().await;
        let req = match framed {
            Some(req) => req,
            None => return Err(socks_error("read request failed")),
        }?;

        let resp = HandshakeResponse::new(SOCKS5_AUTH_METHOD_NONE);
        stream.send(resp).await?;

        if !req.methods.contains(&SOCKS5_AUTH_METHOD_NONE) {
            return Err(socks_error("method not support"));
        }

        let FramedParts {
            io,
            read_buf,
            write_buf,
            ..
        } = stream.into_parts();

        let mut new_parts = FramedParts::new(io, CmdCodec);

        new_parts.write_buf = write_buf;
        new_parts.read_buf = read_buf;

        let cmd = Framed::from_parts(new_parts);

        Ok(cmd)
    }

    async fn socks5_cmd(
        &mut self,
        stream: CmdFramed,
    ) -> Result<(Option<Body>, OwnedWriteHalf), RsocksError> {
        let (framed, mut stream) = stream.into_future().await;

        let req = match framed {
            Some(req) => req,
            None => return Err(socks_error("read request failed")),
        }?;

        debug!("cmd request: {:?} from {:?}", req, stream);
        let CmdRequest { address, port, .. } = req.clone();

        // only support TCPConnect
        if req.command != Command::TCPConnect {
            let resp = CmdResponse::new(Reply::CommandNotSupported, address, port);
            stream.send(resp).await?;
            return Err(socks_error("command not support"));
        }

        let FramedParts { io, .. } = stream.into_parts();

        let (read_half, mut write_half) = io.into_split();

        let stream = FramedRead::new(read_half, BytesCodec::new());

        let addr = dest_addr(&req)?;

        // use http2
        let h2_req = hyper::Request::builder()
            .version(hyper::http::Version::HTTP_2)
            .uri(&self.remote)
            .header("dest", addr)
            .body(Body::wrap_stream(stream))
            .unwrap();

        let CmdRequest { address, port, .. } = req.clone();

        let mut socks_resp = CmdResponse::new(Reply::GeneralFailure, address, port);

        let (cmd_resp, body) = match self.http.request(h2_req).await {
            Ok(resp) => {
                trace!("connected {:?}", req.address);

                let (parts, body) = resp.into_parts();

                if !parts.status.is_success() {
                    (socks_resp, None)
                } else {
                    socks_resp.reply = Reply::Succeeded;

                    (socks_resp, Some(body))
                }
            }
            Err(err) => {
                error!(%err, "connect remote failed");

                socks_resp.reply = Reply::HostUnreachable;

                (socks_resp, None)
            }
        };

        let mut buf = BytesMut::new();
        cmd_resp.write_to(&mut buf);
        write_half.write_buf(&mut buf).await?;

        Ok((body, write_half))
    }

    async fn streaming(
        stream_body: Option<Body>,
        mut write_half: OwnedWriteHalf,
    ) -> anyhow::Result<()> {
        if let Some(mut body) = stream_body {
            while let Some(data) = body.next().await {
                match data {
                    Ok(mut bs) => {
                        if let Err(err) = write_half.write_buf(&mut bs).await {
                            error!(%err, "send body buf failed");
                            return Err(err.into());
                        }
                    }
                    Err(err) => {
                        error!(%err, "recv body data failed");
                        return Err(err.into());
                    }
                }
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let args = Args::parse();

    let addr: SocketAddr = args.host.parse().expect("can not parse host");

    tracing_subscriber::fmt::init();

    let listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("can not bind {}, {:?}", addr, e));

    info!("listening on {}", addr);

    let url = format!("http://{}/", &args.server);

    let private_key = load_identify(args.private_key)?;
    let public_key = load_identify(args.public_key)?;

    let connector = NoiseConnector::new(Arc::new(private_key), Arc::new(public_key));

    let http_client = Client::builder().http2_only(true).build(connector);

    loop {
        let (socket, remote_addr) = listener.accept().await.expect("accpet failed");

        let mut conn = Connection::new(url.clone(), http_client.clone());

        tokio::spawn(
            async move {
                match conn.proxy(socket).await {
                    Ok(_) => {}
                    Err(e) => error!("socks5 proxy error, {:?}", e),
                }
            }
            .instrument(tracing::info_span!("conn", %remote_addr)),
        );
    }
}
