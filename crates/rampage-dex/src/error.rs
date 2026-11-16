//! Errors from reading DEX files, binary XML and APKs.

#[derive(Debug, thiserror::Error)]
pub enum DexError {
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// A safety cap stopped the work.
    #[error("refused: {0}")]
    Limit(String),
    #[error("{0}")]
    NotFound(String),
}

pub type Result<T> = std::result::Result<T, DexError>;

pub(crate) fn malformed(reason: impl Into<String>) -> DexError {
    DexError::Malformed(reason.into())
}
