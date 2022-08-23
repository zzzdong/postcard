use std::{io, pin::Pin, sync::Arc, task::Poll};

use hyper::client::connect::{Connected, Connection};
use hyper::{service::Service, Uri};
use snowstorm::NoiseStream;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tracing::debug;

use crate::errors::new_error;

// Noise protocol params, see: http://www.noiseprotocol.org/noise.html#protocol-names-and-modifiers
// Use `KK` to enable bidirectional identity verification
pub static PATTERN: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";

pub static DEST_ADDR: &str = "x-dest-addr";

pub fn load_identify(key_str: &str) -> anyhow::Result<Vec<u8>> {
    let identity = base64::decode(key_str)?;

    Ok(identity)
}

pub struct SecureStream<T> {
    inner: NoiseStream<T>,
}

impl<T> AsyncRead for SecureStream<T>
where
    T: AsyncRead + Unpin + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.inner), cx, buf)
    }
}

impl<T> AsyncWrite for SecureStream<T>
where
    T: AsyncWrite + Unpin + 'static,
{
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

impl<T> Connection for SecureStream<T>
where
    T: Connection,
{
    fn connected(&self) -> Connected {
        self.inner.get_inner().connected()
    }
}

#[derive(Clone)]
pub struct NoiseConnector {
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
    type Response = SecureStream<TcpStream>;
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
                .ok_or_else(|| new_error("uri not ok".to_string()))?;

            let remote = format!(
                "{}:{}",
                authority.host(),
                authority.port_u16().unwrap_or(8080)
            );

            debug!("try tcp connect to {:?}", &remote);

            // Connect to the peer
            let stream = TcpStream::connect(&remote).await?;

            debug!("tcp connect {:?} done", &remote);

            // The client should build an initiator to launch the handshake process
            let initiator = snowstorm::Builder::new(PATTERN.parse()?)
                .local_private_key(&private_key)
                .remote_public_key(&public_key)
                .build_initiator()?;

            // Start handshaking
            let secured_stream = NoiseStream::handshake(stream, initiator).await?;

            debug!("NoiseStream handshake done");

            Ok(SecureStream {
                inner: secured_stream,
            })
        })
    }
}

impl<T> SecureStream<T> {
    pub async fn handshake(
        socket: T,
        private_key: impl AsRef<[u8]>,
        public_key: impl AsRef<[u8]>,
    ) -> Result<Self, anyhow::Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + 'static,
    {
        // The server needs a responder to handle handshake reqeusts from clients
        let responder = snowstorm::Builder::new(PATTERN.parse().unwrap())
            .local_private_key(private_key.as_ref())
            .remote_public_key(public_key.as_ref())
            .build_responder()
            .unwrap();

        // Start handshaking
        let secured_stream = NoiseStream::handshake(socket, responder).await?;

        Ok(SecureStream {
            inner: secured_stream,
        })
    }
}
