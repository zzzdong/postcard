use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use clap::Parser;
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use hyper::{Body, Client};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{BytesCodec, Framed, FramedParts, FramedRead};
use tracing::{debug, error, info, trace, Instrument};

use postcard::codecs::socks5::*;
use postcard::errors::*;
use postcard::proto::socks5::consts::*;
use postcard::proto::socks5::*;
use postcard::secure_stream::{load_identify, NoiseConnector, DEST_ADDR};

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
    private_key: String,
    /// Public key
    #[clap(long)]
    public_key: String,
}

type CmdFramed = Framed<TcpStream, CmdCodec>;

fn dest_addr(req: &CmdRequest) -> Result<String, RsocksError> {
    let req = req.clone();
    match req.address {
        Address::IPv4(ip) => Ok(format!("{}:{}", ip, req.port)),
        Address::IPv6(ip) => Ok(format!("{}:{}", ip, req.port)),
        Address::DomainName(ref dn) => Ok(format!("{}:{}", dn, req.port)),
        Address::Unknown(_t) => Err(socks_error("bad address")),
    }
}

#[derive(Clone)]
struct ProxyHandler {
    remote: String,
    http: hyper::Client<NoiseConnector, Body>,
}

impl ProxyHandler {
    pub fn new(remote: impl ToString, http: hyper::Client<NoiseConnector, Body>) -> Self {
        ProxyHandler {
            remote: remote.to_string(),
            http,
        }
    }

    pub async fn handshake(
        &mut self,
        socket: TcpStream,
    ) -> Result<(Option<Body>, OwnedWriteHalf), anyhow::Error> {
        let cmd = self.accept_socks5(socket).await?;

        self.connect_dest(cmd).await.map_err(Into::into)
    }

    async fn accept_socks5(&self, socket: TcpStream) -> Result<CmdFramed, RsocksError> {
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

    async fn connect_dest(
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
            .header(DEST_ADDR, addr)
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

    let private_key = load_identify(&args.private_key)?;
    let public_key = load_identify(&args.public_key)?;

    let connector = NoiseConnector::new(Arc::new(private_key), Arc::new(public_key));

    let http_client = Client::builder().http2_only(true).build(connector);

    loop {
        let (socket, remote_addr) = listener.accept().await.expect("accpet failed");

        let mut conn = ProxyHandler::new(url.clone(), http_client.clone());

        tokio::spawn(
            async move {
                match conn.handshake(socket).await {
                    Ok((body, write_half)) => {
                        match ProxyHandler::streaming(body, write_half).await {
                            Ok(_) => {
                                info!("proxy streaming done")
                            }
                            Err(err) => {
                                error!("proxy streaming error, {:?}", err);
                            }
                        }
                    }
                    Err(e) => error!("proxy handshake error, {:?}", e),
                }
            }
            .instrument(tracing::info_span!("conn", %remote_addr)),
        );
    }
}
