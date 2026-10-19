use std::sync::Arc;

use rampage_arch::{Disassembler, UnsupportedArch};
use rampage_loaders::Binary;

use crate::ApiError;

#[derive(Debug, Clone, thiserror::Error)]
pub enum DecoderInitializationError {
    #[error(transparent)]
    Unsupported(#[from] UnsupportedArch),
    #[error("instruction decoder: {0}")]
    Sleigh(#[source] Arc<rampage_decompiler::Error>),
}

impl DecoderInitializationError {
    pub(crate) fn to_api_error(&self) -> ApiError {
        match self {
            Self::Unsupported(error) => ApiError::Unsupported(*error),
            Self::Sleigh(error) => ApiError::DecoderInitialization(Arc::clone(error)),
        }
    }
}

pub(crate) fn decoder_for_project(binary: &Binary) -> Result<Box<dyn Disassembler>, DecoderInitializationError> {
    binary.decoder().map_err(DecoderInitializationError::Unsupported)
}
