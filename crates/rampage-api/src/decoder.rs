#[cfg(test)]
std::thread_local! {
    static FAIL_ANALYSIS_BINDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn with_failed_analysis_binding<T>(work: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            FAIL_ANALYSIS_BINDING.with(|failed| failed.set(self.0));
        }
    }
    let _restore = Restore(FAIL_ANALYSIS_BINDING.with(|failed| failed.replace(true)));
    work()
}

use sha2::{Digest, Sha256};
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

pub(crate) fn analysis_binding(binary: &Binary) -> Result<Option<String>, DecoderInitializationError> {
    let Some(raw) = binary.raw_interpretation_identity().map_err(|error| initialization(error.to_string()))? else {
        return Ok(None);
    };
    #[cfg(test)]
    if FAIL_ANALYSIS_BINDING.with(|failed| failed.get()) {
        return Err(initialization("injected specification revalidation failure"));
    }
    let context = rampage_decompiler::require_verified_bundled_native_context()
        .map_err(|error| DecoderInitializationError::Sleigh(Arc::new(error)))?;
    let mut hash = Sha256::new();
    hash.update(b"rampage-project-sleigh-analysis-v1\0");
    hash.update(raw.schema.as_bytes());
    hash.update([0]);
    hash.update(raw.sha256.as_bytes());
    hash.update(context.manifest_sha256());
    Ok(Some(rampage_arch::hex::bytes(&hash.finalize())))
}

pub(crate) fn decoder_for_project(binary: &Binary) -> Result<Box<dyn Disassembler>, DecoderInitializationError> {
    let identity = binary.raw_interpretation_identity().map_err(|error| initialization(error.to_string()))?;
    let Some(raw) = binary.raw_code_image() else {
        return binary.decoder().map_err(DecoderInitializationError::Unsupported);
    };
    if identity.is_none() {
        return Err(initialization("Raw decoder has no interpretation identity"));
    }
    let decoder = rampage_decompiler::sleigh_decode::SleighDecoder::open(raw.profile().language_id())
        .map_err(|error| DecoderInitializationError::Sleigh(Arc::new(error)))?;
    validate_raw_metadata(raw, decoder.metadata())?;
    Ok(Box::new(decoder))
}

fn initialization(message: impl Into<String>) -> DecoderInitializationError {
    DecoderInitializationError::Sleigh(Arc::new(rampage_decompiler::Error::Ghidra(message.into())))
}

fn validate_raw_metadata(
    raw: &rampage_loaders::RawCodeImage,
    metadata: &rampage_decompiler::sleigh_decode::ProfileMetadata,
) -> Result<(), DecoderInitializationError> {
    let expected = raw.profile().code_space();
    let code = metadata.spaces.iter().find(|space| space.id == metadata.code_space);
    let matches = code.is_some_and(|space| {
        space.kind == 1
            && space.name == expected.name
            && space.address_size == u32::from(expected.address_size)
            && space.word_size == u32::from(expected.word_size)
            && space.highest == expected.highest_byte
    });
    if !matches
        || metadata.profile != raw.profile().language_id()
        || metadata.alignment_bytes != u32::from(expected.instruction_alignment)
        || metadata.required_parallel_helper.is_some()
    {
        return Err(initialization("Raw admission facts disagree with the verified native translator"));
    }
    Ok(())
}

pub(crate) fn project_decoder(project: &crate::Project) -> Result<Box<dyn Disassembler>, ApiError> {
    decoder_for_project(&project.binary).map_err(|error| error.to_api_error())
}

#[cfg(test)]
#[path = "decoder_project_tests.rs"]
mod tests;
