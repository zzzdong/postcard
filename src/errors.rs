use thiserror::Error;

#[derive(Debug, Error)]
pub enum RsocksError {
    #[error("Parse error: {}", msg)]
    Parser { msg: String },
    #[error("IO error: {}", 0)]
    Io(#[from] std::io::Error),
    #[error("Socks error: {}", msg)]
    Socks { msg: String },
    #[error("Timeout error: {}", 0)]
    Timeout(#[from] tokio::time::error::Elapsed),
}

pub fn parser_error(msg: impl ToString) -> RsocksError {
    RsocksError::Parser {
        msg: msg.to_string(),
    }
}

pub fn socks_error(msg: impl ToString) -> RsocksError {
    RsocksError::Socks {
        msg: msg.to_string(),
    }
}
