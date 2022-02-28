use std::io::{self, Read};
use std::path::{Path, PathBuf};

use bytes::BytesMut;
use clap::Parser;

use hyper::client::HttpConnector;
use hyper::Body;
use hyper_tls::HttpsConnector;
use hyper_tls::native_tls::Certificate;
use tokio::io::AsyncWriteExt;
use tokio_native_tls::native_tls::Identity;

use std::net::SocketAddr;

use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{BytesCodec, Framed, FramedParts, FramedRead};
use tracing::{debug, error, info, trace, Instrument};

mod codecs;
mod errors;
mod parser;
mod proto;

use crate::codecs::socks5::*;
use crate::errors::*;
use crate::proto::socks5::consts::*;
use crate::proto::socks5::*;

#[derive(Parser, Debug)]
struct Args {
    /// Host to listen on
    #[clap(long, short, default_value = "0.0.0.0:1080")]
    host: String,
    /// Server to connect to
    #[clap(long, short)]
    server: String,
    /// Identity.pfx file
    #[clap(long)]
    identity: PathBuf,
    /// Password for Identity
    #[clap(long)]
    password: String,
    /// ca file
    #[clap(long)]
    ca: PathBuf,
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
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

struct Connection {
    remote: String,
    http: hyper::Client<HttpsConnector<HttpConnector>, Body>,
}

impl Connection {
    pub fn new(
        remote: impl ToString,
        http: hyper::Client<HttpsConnector<HttpConnector>, Body>,
    ) -> Self {
        Connection {
            remote: remote.to_string(),
            http,
        }
    }

    pub async fn proxy(&self, socket: TcpStream) -> Result<(), anyhow::Error> {
        let cmd = self.handshake(socket).await?;

        self.socks5_cmd(cmd).await?;

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

    async fn socks5_cmd(&self, stream: CmdFramed) -> Result<(), RsocksError> {
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
            .uri(&self.remote)
            .header("dest", addr)
            .body(Body::wrap_stream(stream))
            .unwrap();

        let client = self.http.clone();

        match client.request(h2_req).await {
            Ok(mut resp) => {
                trace!("connected {:?}", req.address);

                if !resp.status().is_success() {
                    Self::cmd_response(&mut write_half, Reply::GeneralFailure, req.clone()).await?;
                    return Ok(());
                }

                Self::cmd_response(&mut write_half, Reply::Succeeded, req.clone()).await?;

                let body = resp.body_mut();
                while let Some(data) = &mut body.next().await {
                    match data {
                        Ok(bs) => {
                            if let Err(err) = write_half.write_buf(bs).await {
                                error!(%err, "send body buf failed");
                                break;
                            }
                        }
                        Err(err) => {
                            error!(%err, "recv body data failed");
                            break;
                        }
                    }
                }

                Ok(())
            }
            Err(err) => {
                error!(%err, "connect remote failed");
                Self::cmd_response(&mut write_half, Reply::HostUnreachable, req.clone()).await?;
                Err(socks_error(format!(
                    "connect {:?} failed, {:?}",
                    req.address, err
                )))
            }
        }
    }

    async fn cmd_response<W: AsyncWriteExt + Unpin>(
        w: &mut W,
        reply: Reply,
        req: CmdRequest,
    ) -> Result<(), RsocksError> {
        let CmdRequest { address, port, .. } = req;
        let cmd_resp = CmdResponse::new(reply, address, port);
        let mut buf = BytesMut::new();
        cmd_resp.write_to(&mut buf);
        w.write_buf(&mut buf).await?;

        Ok(())
    }
}

fn load_identify(args: &Args) -> anyhow::Result<Identity> {
    let mut file = std::fs::File::open(&args.identity)?;
    let mut identity = vec![];
    file.read_to_end(&mut identity)?;

    let identity = Identity::from_pkcs12(&identity, &args.password)?;

    Ok(identity)
}

fn load_cert(args: &Args) -> anyhow::Result<Certificate> {
    let mut file = std::fs::File::open(&args.ca)?;
    let mut cert = vec![];
    file.read_to_end(&mut cert)?;

    let cert = Certificate::from_pem(&cert)?;

    Ok(cert)
}

fn tls_connector(args: &Args) -> anyhow::Result<tokio_native_tls::TlsConnector> {
    let ca = load_cert(args)?;
    let identity = load_identify(args)?;


    let connector = tokio_native_tls::native_tls::TlsConnector::builder()
        .identity(identity)
        .disable_built_in_roots(true)
        .add_root_certificate(ca)
        .danger_accept_invalid_hostnames(true)
        .use_sni(false)
        // .danger_accept_invalid_certs(true)
        .build()?;

    Ok(connector.into())
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

    let url = format!("https://{}/", &args.server);

    let tls = tls_connector(&args).expect("tls config error");

    let mut http = HttpConnector::new();
    http.enforce_http(false);

    let mut https = hyper_tls::HttpsConnector::from((http, tls));

    https.https_only(true);

    let http = hyper::Client::builder()
        .http2_only(true)
        .build::<_, hyper::Body>(https);

    loop {
        let (socket, remote_addr) = listener.accept().await.expect("accpet failed");
        let url = url.clone();
        let http = http.clone();

        tokio::spawn(
            async move {
                let conn = Connection::new(url, http);
                match conn.proxy(socket).await {
                    Ok(_) => {}
                    Err(e) => error!("socks5 proxy error, {:?}", e),
                }
            }
            .instrument(tracing::info_span!("conn", %remote_addr)),
        );
    }
}
