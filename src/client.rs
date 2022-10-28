use std::{net::SocketAddr, sync::Arc};

use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use hyper::Body;
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

    info!("listening on {}", addr);

    let url = format!("http://{}/", server);

    let private_key = load_identify(private_key)?;
    let public_key = load_identify(public_key)?;

    let connector = NoiseConnector::new(Arc::new(private_key), Arc::new(public_key));

    let http_client = hyper::Client::builder().http2_only(true).build(connector);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("can not bind {}, {:?}", addr, e));

    loop {
        let (socket, income_addr) = listener.accept().await.expect("accpet failed");

        let mut conn = ProxyHandler::new(url.clone(), http_client.clone());

        tokio::spawn(
            async move { conn.handle(socket).await.unwrap() }
                .instrument(info_span!("conn", %income_addr)),
        );
    }
}

#[derive(Clone, Debug)]
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
        .instrument(info_span!("dest", %dest))
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
    ) -> Result<(Body, OwnedWriteHalf), RsocksError> {
        debug!("cmd request: {:?}", cmd);
        let CmdRequest { address, port, .. } = cmd.clone();

        // only support TCPConnect
        if cmd.command != Command::TCPConnect {
            let resp = CmdResponse::new(Reply::CommandNotSupported, address, port);
            stream.send(resp).await?;
            return Err(socks_error("command not support"));
        }

        let (read_half, mut write_half) = stream.into_inner().into_split();

        let stream = FramedRead::new(read_half, BytesCodec::new());

        let dest = dest_addr(&cmd)?;

        // use http2
        let h2_req = hyper::Request::builder()
            .version(hyper::http::Version::HTTP_2)
            .uri(&self.remote)
            .header(DEST_ADDR, &dest)
            .body(Body::wrap_stream(stream))
            .unwrap();

        let CmdRequest { address, port, .. } = cmd.clone();

        let mut socks_resp = CmdResponse::new(Reply::GeneralFailure, address, port);

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
        mut stream_body: Body,
        mut write_half: OwnedWriteHalf,
    ) -> anyhow::Result<()> {
        while let Some(data) = stream_body.next().await {
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
