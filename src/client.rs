use std::{net::SocketAddr, sync::Arc};

use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use http_body_util::BodyStream;
use hyper::body::{Frame, Incoming};
use hyper_util::client::legacy::Client as HttpClient;
use tokio::{
    io::AsyncWriteExt,
    net::{tcp::OwnedWriteHalf, TcpStream},
};
use tokio_util::codec::{BytesCodec, Framed, FramedRead};
use tracing::{debug, error, info, info_span, trace, Instrument};

use crate::{
    codecs::socks5::{CmdCodec, HandshakeCodec},
    errors::{socks_error, RsocksError},
    proto::socks5::{
        consts::SOCKS5_AUTH_METHOD_NONE, Address, CmdRequest, CmdResponse, Command,
        HandshakeResponse, Reply,
    },
    secure_stream::{load_identify, NoiseConnector, DEST_ADDR},
};

type CmdFramed = Framed<TcpStream, CmdCodec>;

pub async fn start_client(
    host: &str,
    server: &str,
    private_key: &str,
    public_key: &str,
) -> anyhow::Result<()> {
    let addr: SocketAddr = host.parse().expect("can not parse host");

    let url = Uri::from_maybe_shared(format!("http://{}/", server)).expect("build uri failed");

    let private_key = load_identify(private_key)?;
    let public_key = load_identify(public_key)?;

    let connector = NoiseConnector::new(Arc::new(private_key), Arc::new(public_key));

    let http_client = HttpClient::builder(hyper_util::rt::TokioExecutor::new())
        .http2_only(true)
        .build(connector);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect(&format!("can not bind {}", addr));

    info!("listening on {}", addr);

    let socks5_proxy = ProxyHandler::new(http_client.clone(), url.clone());

    let http = hyper::server::conn::Http::new();
    let http_proxy = HttpProxyHandler::new(http, http_client.clone(), url.clone());

    loop {
        let (socket, incoming) = listener.accept().await.expect("accpet failed");

        let mut conn: ProxyHandler = ProxyHandler::new(url.clone(), http_client.clone());

        tokio::spawn(async move {
            match handle_incoming(socket, socks5_proxy, http_proxy)
                .instrument(info_span!("accepted", %incoming))
                .await
            {
                Ok(_) => {
                    info!("proxy finished");
                }
                Err(err) => {
                    error!(%err, "proxy failed");
                }
            }
        });
    }
}

async fn handle_incoming(
    socket: TcpStream,
    mut socks5: ProxyHandler,
    http_handler: HttpProxyHandler,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 3];
    let _n = socket.peek(&mut buf).await?;

    if buf[0] == 0x05 {
        // socks5
        debug!("start socks proxy");
        socks5.handle(socket).await?;
        Ok(())
    } else {
        // fallback to http
        debug!("start http proxy");
        http_handler
            .http
            .serve_connection(socket, http_handler.clone())
            .with_upgrades()
            .await?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
struct ProxyHandler {
    remote: String,
    http: HttpClient<NoiseConnector, BodyReader>,
}

impl ProxyHandler {
    pub fn new(remote: impl ToString, http: HttpClient<NoiseConnector, BodyReader>) -> Self {
        ProxyHandler {
            remote,
            http_client,
        }
    }

    pub async fn handle(&mut self, socket: TcpStream) -> Result<(), anyhow::Error> {
        let (cmd, stream) = self.accept_socks5(socket).await?;

        let dest = dest_addr(&cmd)?;

        async move {
            match self.forward(cmd, stream).await {
                Ok(_) => {
                    info!("handle socket finished");
                }
                Err(err) => {
                    error!("handle socket error: {:?}", err);
                }
            };

            Ok::<_, anyhow::Error>(())
        }
        .instrument(info_span!("connect", %dest))
        .await
        .unwrap();

        Ok(())
    }

    async fn forward(&mut self, cmd: CmdRequest, stream: CmdFramed) -> Result<(), anyhow::Error> {
        let (body, write_half) = self.connect_dest(cmd, stream).await?;

        ProxyHandler::streaming(body, write_half).await
    }

    async fn accept_socks5(
        &self,
        socket: TcpStream,
    ) -> Result<(CmdRequest, CmdFramed), RsocksError> {
        // handshake frame
        let mut stream = Framed::new(socket, HandshakeCodec);

        let req = stream
            .next()
            .await
            .ok_or_else(|| socks_error("read socks5 request failed"))??;

        if !req.methods.contains(&SOCKS5_AUTH_METHOD_NONE) {
            return Err(socks_error("method not support"));
        }

        let resp = HandshakeResponse::new(SOCKS5_AUTH_METHOD_NONE);
        stream.send(resp).await?;

        // cmd frame
        let mut stream = stream.map_codec(|_| CmdCodec);

        let req = stream
            .next()
            .await
            .ok_or_else(|| socks_error("read socks5 cmd failed"))??;

        Ok((req, stream))
    }

    async fn connect_dest(
        &mut self,
        cmd: CmdRequest,
        mut stream: CmdFramed,
    ) -> Result<(Incoming, OwnedWriteHalf), RsocksError> {
        debug!("cmd request: {:?}", cmd);
        let CmdRequest { address, port, .. } = cmd.clone();

        // only support TCPConnect
        if cmd.command != Command::TCPConnect {
            let resp = CmdResponse::new(Reply::CommandNotSupported, address, port);
            stream.send(resp).await?;
            return Err(socks_error("command not support"));
        }

        let (read_half, mut write_half) = stream.into_inner().into_split();

        let body = BodyReader::new(read_half);

        let dest = dest_addr(&cmd)?;

        // use http2
        let h2_req = hyper::Request::builder()
            .version(hyper::http::Version::HTTP_2)
            .uri(&self.remote)
            .header(DEST_ADDR, &dest)
            .body(body)
            .unwrap();

        let CmdRequest { address, port, .. } = cmd.clone();

        let mut socks_resp = CmdResponse::new(Reply::GeneralFailure, address, port);

        // let h2_req = build_request_with_body(self.remote.try_into().unwrap(), &dest, body);

        let ret = self.http.request(h2_req).await.map(|resp| {
            trace!("connected {:?}", cmd.address);

            let (parts, body) = resp.into_parts();

            if parts.status.is_success() {
                socks_resp.reply = Reply::Succeeded;
            }

            body
        });
        if let Err(ref _err) = ret {
            socks_resp.reply = Reply::HostUnreachable;
        }

        let mut buf = BytesMut::new();
        socks_resp.write_to(&mut buf);
        write_half.write_buf(&mut buf).await?;

        ret.map_err(|err| socks_error(format!("connect {dest} failed, {err}")))
            .map(|body| (body, write_half))
    }

    async fn streaming(
        stream_body: Incoming,
        mut write_half: OwnedWriteHalf,
    ) -> anyhow::Result<()> {
        let mut stream = BodyStream::new(stream_body);
        while let Some(data) = stream.next().await {
            match data {
                Ok(frame) => {
                    if frame.is_data() {
                        if let Err(err) =
                            write_half.write_buf(&mut frame.into_data().unwrap()).await
                        {
                            error!(%err, "send body buf failed");
                            return Err(err.into());
                        }
                    }
                }
                Err(err) => {
                    error!(%err, "recv body data failed");
                    return Err(err.into());
                }
            }
        }

        Ok(())
    }
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

struct BodyReader(FramedRead<tokio::net::tcp::OwnedReadHalf, BytesCodec>);

impl BodyReader {
    pub fn new(stream: tokio::net::tcp::OwnedReadHalf) -> Self {
        BodyReader(FramedRead::new(stream, BytesCodec::new()))
    }
}

impl hyper::body::Body for BodyReader {
    type Data = Bytes;

    type Error = anyhow::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.0
            .poll_next_unpin(cx)
            .map(|b| b.map(|b| b.map(|b| Frame::data(b.freeze())).map_err(Into::into)))
    }
}
