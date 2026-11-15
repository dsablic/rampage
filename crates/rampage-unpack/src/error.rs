//! Errors from reading and extracting images.

/// Why an image could not be listed, read or extracted.
#[derive(Debug, thiserror::Error)]
pub enum UnpackError {
    #[error("cannot {action}: {source}")]
    Io { action: String, source: std::io::Error },
    #[error("malformed {format} image: {reason}")]
    Malformed { format: &'static str, reason: String },
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// A safety limit stopped the work; output written so far stays where it is.
    #[error("refused: {0}")]
    Limit(String),
    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, UnpackError>;

impl UnpackError {
    pub(crate) fn io(action: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io { action: action.into(), source }
    }

    pub(crate) fn malformed(format: &'static str, reason: impl Into<String>) -> Self {
        Self::Malformed { format, reason: reason.into() }
    }
}

/// `value` or a malformed-image error naming `what` overflowed: checked arithmetic on header fields.
pub(crate) fn checked<T>(value: Option<T>, format: &'static str, what: &str) -> Result<T> {
    value.ok_or_else(|| UnpackError::malformed(format, format!("{what} overflows")))
}
