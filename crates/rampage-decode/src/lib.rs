//! Internal, bounded decoder providers. Inputs are decoded only when explicitly requested.

use std::error::Error;
use std::fmt;

pub mod encode;
mod lz4;
mod lzss;
pub mod probe;

pub use lz4::Lz4Block;
pub use lzss::{FlagOrder, Lzss, OffsetMode, ReferenceLayout, Scan, ScanEnd, ScanStats};

pub trait Decoder {
    fn id(&self) -> &'static str;

    fn decode(
        &self,
        input: &[u8],
        options: &DecodeOptions,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Decoded, DecodeError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeOptions {
    pub expected_output_size: usize,
    pub max_output_size: usize,
    /// Nonzero maximum ratio against the entire supplied input, including trailing bytes.
    pub max_expansion_ratio: usize,
    /// One step per token plus one step per emitted byte; flag reads are included in token work.
    pub max_steps: u64,
}

impl DecodeOptions {
    /// Rejects budgets that cannot hold the expected output, before any allocation or cancellation poll.
    /// `max_token_output` is the most output one token (one work step of token overhead) can emit.
    pub(crate) fn preflight(&self, input: &[u8], max_token_output: usize) -> Result<(), DecodeError> {
        if self.max_expansion_ratio == 0 {
            return Err(DecodeError::InvalidBudget);
        }
        let expected = self.expected_output_size;
        if expected > self.max_output_size {
            return Err(DecodeError::OutputLimitExceeded);
        }
        if expected != 0 && (input.is_empty() || expected.div_ceil(input.len()) > self.max_expansion_ratio) {
            return Err(DecodeError::ExpansionLimitExceeded);
        }
        let minimum_steps = expected as u128 + expected.div_ceil(max_token_output) as u128;
        if minimum_steps > u128::from(self.max_steps) {
            return Err(DecodeError::WorkLimitExceeded);
        }
        Ok(())
    }
}

/// The classic 4 KiB ring variant: [`Lzss::classic_4k`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lzss4k {
    /// Initial ring write position, in 0..4096 (4096 itself is invalid).
    pub initial_write_offset: u16,
    pub dictionary_fill: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub bytes: Vec<u8>,
    pub consumed: usize,
    pub steps: u64,
}

/// Errors deliberately contain no source or decoded payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    InvalidParameters,
    InvalidBudget,
    OutputLimitExceeded,
    ExpansionLimitExceeded,
    TruncatedInput,
    OutputSizeMismatch,
    InvalidReference,
    WorkLimitExceeded,
    Cancelled,
    AllocationFailure,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidParameters => "invalid decoder parameters",
            Self::InvalidBudget => "invalid decoder budget",
            Self::OutputLimitExceeded => "expected output exceeds the output limit",
            Self::ExpansionLimitExceeded => "expected output exceeds the expansion limit",
            Self::TruncatedInput => "truncated decoder input",
            Self::OutputSizeMismatch => "token exceeds the expected output size",
            Self::InvalidReference => "reference outside the decoded output",
            Self::WorkLimitExceeded => "decoder work limit exceeded",
            Self::Cancelled => "decoding cancelled",
            Self::AllocationFailure => "decoder output allocation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for DecodeError {}

impl Decoder for Lzss4k {
    fn id(&self) -> &'static str {
        "lzss-4k"
    }

    fn decode(
        &self,
        input: &[u8],
        options: &DecodeOptions,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Decoded, DecodeError> {
        Lzss::classic_4k(self.initial_write_offset, self.dictionary_fill).decode(input, options, cancelled)
    }
}

fn check_cancelled(cancelled: &mut dyn FnMut() -> bool) -> Result<(), DecodeError> {
    if cancelled() { Err(DecodeError::Cancelled) } else { Ok(()) }
}

fn take_step(steps: &mut u64, limit: u64, cancelled: &mut dyn FnMut() -> bool) -> Result<(), DecodeError> {
    check_cancelled(cancelled)?;
    if *steps >= limit {
        return Err(DecodeError::WorkLimitExceeded);
    }
    *steps += 1;
    Ok(())
}

fn read_byte(input: &[u8], consumed: &mut usize) -> Result<u8, DecodeError> {
    let byte = *input.get(*consumed).ok_or(DecodeError::TruncatedInput)?;
    *consumed += 1;
    Ok(byte)
}
