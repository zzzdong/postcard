#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Parse error: {}", msg)]
    Parser { msg: String },
    #[error("IO error: {}", 0)]
    Io(#[from] std::io::Error),
    #[error("Socks error: {}", msg)]
    Socks { msg: String },
    #[error("Timeout error: {}", 0)]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("Http error: {}", 0)]
    Http(#[from] hyper::Error),
    #[error("Infallible")]
    Infallible(#[from] std::convert::Infallible),
    #[error("Base64 decode error: {}", 0)]
    Base64Decode(#[from] base64::DecodeError),
    #[error("Snow error: {}", 0)]
    Snow(#[from] snowstorm::snow::Error),
    #[error("Snowstorm error: {}", 0)]
    Snowstorm(#[from] snowstorm::SnowstormError),
}

pub fn parser_error(msg: impl ToString) -> Error {
    Error::Parser {
        msg: msg.to_string(),
    }
}

pub fn socks_error(msg: impl ToString) -> Error {
    Error::Socks {
        msg: msg.to_string(),
    }
}

pub fn new_error(err: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, err)
}
