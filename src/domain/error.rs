use thiserror::Error;

#[derive(Error, Debug)]
pub enum RevError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Binary parsing error: {0}")]
    Parse(String),

    #[error("Unsupported binary format: {0}")]
    UnsupportedFormat(String),

    #[error("Invalid ASAR archive: {0}")]
    InvalidAsar(String),

    #[error("Disassembly error: {0}")]
    Disassembly(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Evidence error: {0}")]
    Evidence(String),
}

pub type RevResult<T> = Result<T, RevError>;
