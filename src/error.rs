use std::path::PathBuf;

/// Error returned by capture parsing, schema decoding, or metric evaluation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid WRPV capture: {0}")]
    InvalidCapture(String),

    #[error("protobuf error: {0}")]
    Protobuf(String),

    #[error("PerfWorks error: {0}")]
    PerfWorks(String),

    #[error("dynamic library error: {0}")]
    Library(#[from] libloading::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("regular expression error: {0}")]
    Regex(#[from] regex::Error),

    #[error("required file was not found: {kind}; searched {searched:?}")]
    Discovery {
        kind: &'static str,
        searched: Vec<PathBuf>,
    },

    #[error("trace path error: {0}")]
    TracePath(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<prost::DecodeError> for Error {
    fn from(value: prost::DecodeError) -> Self {
        Self::Protobuf(value.to_string())
    }
}

impl From<prost_reflect::DescriptorError> for Error {
    fn from(value: prost_reflect::DescriptorError) -> Self {
        Self::Protobuf(value.to_string())
    }
}
