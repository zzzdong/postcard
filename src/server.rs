use std::fs::File;
use std::io::{self, BufReader, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{self, Poll};

use clap::Parser;
use hyper::body::HttpBody;
use hyper::{service::service_fn, Body, Request, Response, Version};
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{Certificate, PrivateKey, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, rsa_private_keys};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::{BytesCodec, FramedRead};
use tracing::{debug, error, info, Instrument};

#[derive(Parser, Debug)]
struct Args {
    /// Host to listen on
    #[clap(long, short, default_value = "0.0.0.0:8080")]
    host: String,
    /// cert file
    #[clap(long)]
    cert: PathBuf,
    /// key file
    #[clap(long)]
    key: PathBuf,
    /// ca file
    #[clap(long)]
    ca: PathBuf,
}

fn bad_request(msg: impl ToString) -> Response<Body> {
    Response::builder()
        .status(400)
        .body(Body::from(msg.to_string()))
        .unwrap()
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

async fn proxy(mut req: Request<hyper::Body>) -> Result<Response<Body>, anyhow::Error> {
    if req.version() != Version::HTTP_2 {
        return Ok(bad_request("not http2"));
    }

    let host = req.headers().get("dest");
    if host.is_none() {
        return Ok(bad_request("no host"));
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
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let start = buf.remaining();
        let ret = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.send_count
            .fetch_add(start - buf.remaining(), Ordering::SeqCst);
        ret
    }
}

// fn load_cert(args: &Args) -> anyhow::Result<Certificate> {
//     let mut file = std::fs::File::open(&args.cert)?;
//     let mut cert = vec![];
//     file.read_to_end(&mut cert)?;

//     let cert = Certificate::from_pem(&cert)?;

//     Ok(cert)
// }

// fn load_identify(args: &Args) -> anyhow::Result<Identity> {
//     let mut file = std::fs::File::open(&args.identity)?;
//     let mut identity = vec![];
//     file.read_to_end(&mut identity)?;

//     let identity = Identity::from_pkcs12(&identity, &args.password)?;

//     Ok(identity)
// }

// fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
//     certs(&mut BufReader::new(File::open(path)?))
//         .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
//         .map(|mut certs| certs.drain(..).map(Certificate).collect())
// }

// fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
//     rsa_private_keys(&mut BufReader::new(File::open(path)?))
//         .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
//         .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
// }

// Load public certificate from file.
fn load_certs(filename: &Path) -> io::Result<Vec<rustls::Certificate>> {
    // Open certificate file.
    let certfile = std::fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {:?}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|_| error("failed to load certificate".into()))?;
    Ok(certs
        .into_iter()
        .map(rustls::Certificate)
        .collect())
}

// Load private key from file.
fn load_private_key(filename: &Path) -> io::Result<rustls::PrivateKey> {
    // Open keyfile.
    let keyfile = std::fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {:?}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(rustls::PrivateKey(key)),
            None => break,
            _e => {
                break;
            }
        }

    }

    Err(error("expected a single private key".into()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let args = Args::parse();

    tracing_subscriber::fmt::init();

    let addr: SocketAddr = args.host.parse().expect("can not parse host");

    // let cert = load_cert(&args)?;
    // let identity = load_identify(&args)?;

    // let acceptor: tokio_rustls::TlsAcceptor = TlsAcceptor::builder(identity).build()?.into();

    println!("=> {:?}", args);



    let certs = load_certs(&args.ca)?;
    let mut roots = RootCertStore::empty();

    for c in &certs {
        roots.add(c).expect("cert failed");
    }

    let client_verify = AllowAnyAuthenticatedClient::new(roots);

    let certs = load_certs(&args.cert)?;
    let key = load_private_key(&args.key)?;


    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(client_verify)
        .with_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(addr).await?;

    let http = hyper::server::conn::Http::new();

    while let Ok((socket, remote_addr)) = listener.accept().await {
        let http = http.clone();
        let acceptor = acceptor.clone();

        tokio::spawn(
            async move {
                let stream = acceptor.accept(socket).await.unwrap();

                let ret = http
                    .serve_connection(stream, service_fn(|req| async move { proxy(req).await }));

                if let Err(e) = ret.await {
                    eprintln!("server connection error: {}", e);
                }
            }
            .instrument(tracing::info_span!("remote_addr", %remote_addr)),
        );
    }

    Ok(())
}
