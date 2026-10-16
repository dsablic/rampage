//! Internal, bounded decoder providers. Inputs are decoded only when explicitly requested.

use std::error::Error;
use std::fmt;

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
            Self::WorkLimitExceeded => "decoder work limit exceeded",
            Self::Cancelled => "decoding cancelled",
            Self::AllocationFailure => "decoder output allocation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for DecodeError {}

const RING_SIZE: usize = 4096;
const RING_MASK: usize = RING_SIZE - 1;
const MAX_REFERENCE_LENGTH: usize = 18;

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
        if usize::from(self.initial_write_offset) >= RING_SIZE {
            return Err(DecodeError::InvalidParameters);
        }
        if options.max_expansion_ratio == 0 {
            return Err(DecodeError::InvalidBudget);
        }
        let expected = options.expected_output_size;
        if expected > options.max_output_size {
            return Err(DecodeError::OutputLimitExceeded);
        }
        if expected != 0 && (input.is_empty() || expected.div_ceil(input.len()) > options.max_expansion_ratio) {
            return Err(DecodeError::ExpansionLimitExceeded);
        }
        // Every token emits at most 18 bytes. Reject impossible work budgets before reserving output.
        let minimum_steps = expected as u128 + expected.div_ceil(MAX_REFERENCE_LENGTH) as u128;
        if minimum_steps > u128::from(options.max_steps) {
            return Err(DecodeError::WorkLimitExceeded);
        }
        check_cancelled(cancelled)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(expected).map_err(|_| DecodeError::AllocationFailure)?;
        let mut ring = [self.dictionary_fill; RING_SIZE];
        let mut write_position = usize::from(self.initial_write_offset);
        let mut consumed = 0;
        let mut steps = 0;
        let mut flags = 0u8;
        let mut remaining_flags = 0;

        while bytes.len() < expected {
            take_step(&mut steps, options.max_steps, cancelled)?;
            if remaining_flags == 0 {
                flags = read_byte(input, &mut consumed)?;
                remaining_flags = 8;
            }
            let literal = flags & 1 != 0;
            flags >>= 1;
            remaining_flags -= 1;

            if literal {
                let byte = read_byte(input, &mut consumed)?;
                take_step(&mut steps, options.max_steps, cancelled)?;
                bytes.push(byte);
                ring[write_position] = byte;
                write_position = (write_position + 1) & RING_MASK;
            } else {
                let low = read_byte(input, &mut consumed)?;
                let high = read_byte(input, &mut consumed)?;
                let mut read_position = usize::from(low) | (usize::from(high & 0xf0) << 4);
                let length = usize::from(high & 0x0f) + 3;
                if length > expected - bytes.len() {
                    return Err(DecodeError::OutputSizeMismatch);
                }
                for _ in 0..length {
                    take_step(&mut steps, options.max_steps, cancelled)?;
                    let byte = ring[read_position];
                    bytes.push(byte);
                    ring[write_position] = byte;
                    read_position = (read_position + 1) & RING_MASK;
                    write_position = (write_position + 1) & RING_MASK;
                }
            }
        }

        Ok(Decoded { bytes, consumed, steps })
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
