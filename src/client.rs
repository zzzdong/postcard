use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use http_body_util::{BodyExt, BodyStream, Empty, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::HeaderValue;
use hyper::server::conn::http1::Builder;
use hyper::{Method, Request, Response, Uri};
use hyper_util::client::legacy::Client as HttpClient;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt;
use tokio::net::{tcp::OwnedWriteHalf, TcpStream};
use tokio_util::codec::{BytesCodec, Framed, FramedRead};
use tracing::{debug, error, info, info_span, trace, Instrument};

use crate::UnsyncBoxBody;
use crate::{
    codecs::socks5::{CmdCodec, HandshakeCodec},
    error::{socks_error, Error},
    proto::socks5::{
        consts::SOCKS5_AUTH_METHOD_NONE, Address, CmdRequest, CmdResponse, Command,
        HandshakeResponse, Reply,
    },
    secure_stream::{load_identify, NoiseConnector, DEST_ADDR},
    BoxBody,
};

type CmdFramed = Framed<TcpStream, CmdCodec>;

pub async fn start_client(
    host: &str,
    server: &str,
    private_key: &str,
    public_key: &str,
) -> Result<(), Error> {
    let addr: SocketAddr = host.parse().expect("can not parse host");

    let url = Uri::from_maybe_shared(format!("http://{}/", server)).expect("build uri failed");

    let private_key = load_identify(private_key)?;
    let public_key = load_identify(public_key)?;

    let connector = NoiseConnector::new(Arc::new(private_key), Arc::new(public_key));

    let http_client = HttpClient::builder(hyper_util::rt::TokioExecutor::new())
        .http2_only(true)
        .build(connector.clone());

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|_| panic!("can not bind {}", addr));

    info!("listening on {}", addr);

    let socks5_proxy = ProxyHandler::new(url.clone(), http_client.clone());

    let http = hyper::server::conn::http1::Builder::new();

    let unsync_http_client = HttpClient::builder(hyper_util::rt::TokioExecutor::new())
        .http2_only(true)
        .build(connector);
    let http_proxy = HttpProxyHandler::new(http, unsync_http_client.clone(), url.clone());

    loop {
        let (socket, incoming) = listener.accept().await.expect("accpet failed");

        let socks5_proxy_cloned = socks5_proxy.clone();
        let http_proxy_cloned = http_proxy.clone();

        tokio::spawn(async move {
            match handle_incoming(socket, socks5_proxy_cloned, http_proxy_cloned)
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
) -> Result<(), Error> {
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
            .serve_connection(TokioIo::new(socket), http_handler.clone())
            .with_upgrades()
            .await?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
struct ProxyHandler {
    remote: String,
    http: HttpClient<NoiseConnector, BoxBody>,
}

impl ProxyHandler {
    pub fn new(remote: impl ToString, http: HttpClient<NoiseConnector, BoxBody>) -> Self {
        ProxyHandler {
            remote: remote.to_string(),
            http,
        }
    }

    pub async fn handle(&mut self, socket: TcpStream) -> Result<(), Error> {
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

            Ok::<_, Error>(())
        }
        .instrument(info_span!("connect", %dest))
        .await
        .unwrap();

        Ok(())
    }

    async fn forward(&mut self, cmd: CmdRequest, stream: CmdFramed) -> Result<(), Error> {
        let (body, write_half) = self.connect_dest(cmd, stream).await?;

        ProxyHandler::streaming(body, write_half).await
    }

    async fn accept_socks5(&self, socket: TcpStream) -> Result<(CmdRequest, CmdFramed), Error> {
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
    ) -> Result<(Incoming, OwnedWriteHalf), Error> {
        debug!("cmd request: {:?}", cmd);
        let CmdRequest { address, port, .. } = cmd.clone();

        // only support TCPConnect
        if cmd.command != Command::TCPConnect {
            let resp = CmdResponse::new(Reply::CommandNotSupported, address, port);
            stream.send(resp).await?;
            return Err(socks_error("command not support"));
        }

        let (read_half, mut write_half) = stream.into_inner().into_split();

        let body = FramedRead::new(read_half, BytesCodec::new());
        let body = BodyExt::boxed(StreamBody::new(
            body.map(|b| b.map(|b| Frame::data(b.freeze())).map_err(Into::into)),
        ));
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

    async fn streaming(stream_body: Incoming, mut write_half: OwnedWriteHalf) -> Result<(), Error> {
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

fn dest_addr(req: &CmdRequest) -> Result<String, Error> {
    let req = req.clone();
    match req.address {
        Address::IPv4(ip) => Ok(format!("{}:{}", ip, req.port)),
        Address::IPv6(ip) => Ok(format!("{}:{}", ip, req.port)),
        Address::DomainName(ref dn) => Ok(format!("{}:{}", dn, req.port)),
        Address::Unknown(_t) => Err(socks_error("bad address")),
    }
}

#[derive(Clone)]
struct HttpProxyHandler {
    http: Builder,
    client: HttpClient<NoiseConnector, UnsyncBoxBody>,
    remote: Uri,
}

impl HttpProxyHandler {
    fn new(http: Builder, client: HttpClient<NoiseConnector, UnsyncBoxBody>, remote: Uri) -> Self {
        HttpProxyHandler {
            http,
            client,
            remote,
        }
    }
}

impl hyper::service::Service<Request<Incoming>> for HttpProxyHandler {
    type Response = Response<BoxBody>;

    type Error = Error;

    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>,
    >;

    fn call(&self, mut req: Request<Incoming>) -> Self::Future {
        let host = req.uri().authority().map(|auth| auth.to_string());

        let dest = host.expect("failed to get dest");

        match req.method() {
            &Method::CONNECT => {
                let remote = self.remote.clone();
                let client = self.client.clone();

                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            let upgraded: TokioIo<hyper::upgrade::Upgraded> =
                                TokioIo::new(upgraded);

                            let (read_half, mut write_half) = tokio::io::split(upgraded);

                            let framed = FramedRead::new(read_half, BytesCodec::new());
                            let body =
                                BodyExt::boxed_unsync(StreamBody::new(framed.map(|b| {
                                    b.map(|b| Frame::data(b.freeze())).map_err(Into::into)
                                })));
                            // use http2
                            let h2_req = hyper::Request::builder()
                                .version(hyper::http::Version::HTTP_2)
                                .uri(&remote)
                                .header(DEST_ADDR, &dest)
                                .body(body)
                                .unwrap();

                            match client.request(h2_req).await {
                                Ok(resp) => {
                                    let mut body = resp.into_body();

                                    while let Some(frame) = body.frame().await {
                                        match frame {
                                            Ok(frame) => {
                                                if frame.is_data() {
                                                    if let Err(err) = write_half
                                                        .write_buf(&mut frame.into_data().unwrap())
                                                        .await
                                                    {
                                                        error!(%err, "send body buf failed");
                                                        return;
                                                    }
                                                }
                                            }
                                            Err(err) => {
                                                error!(%err, "recv body data failed");
                                                return;
                                            }
                                        }
                                    }
                                }
                                Err(err) => {
                                    error!(%err, %remote, "proxy failed");
                                }
                            }
                        }

                        Err(e) => error!("upgrade error: {}", e),
                    }
                });

                Box::pin(async move { Ok(Response::new(Empty::new().map_err(Into::into).boxed())) })
            }
            _ => {
                *req.uri_mut() = self.remote.clone();
                *req.version_mut() = hyper::Version::HTTP_2;
                req.headers_mut().append(
                    DEST_ADDR,
                    HeaderValue::from_maybe_shared(dest).expect("dest header failed"),
                );

                let client = self.client.clone();
                Box::pin(async move {
                    let resp = client
                        .request(req.map(|body| body.map_err(Into::into).boxed_unsync()))
                        .await
                        .map(|resp| resp.map(|body| body.map_err(Into::into).boxed()));
                    resp.map_err(Into::into)
                })
            }
        }
    }
}
