//! The LZ4 block format: sequences of a token, literals, a 16-bit little-endian distance and a match of at least
//! four bytes. No frame header, checksum or dictionary.

use crate::lzss::{Scan, ScanEnd, ScanStats};
use crate::{DecodeError, DecodeOptions, Decoded, Decoder, check_cancelled, read_byte, take_step};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Lz4Block;

const MIN_MATCH: usize = 4;
/// The longest run one input byte can add to a length.
const MAX_BYTES_PER_INPUT_BYTE: usize = 255;
const NEAR_DISTANCE: usize = 512;

impl Lz4Block {
    /// Decodes whole sequences until the input ends, a sequence is invalid or `max_output` would be passed.
    /// A block that ends with its literals exactly at the input's end stops as [`ScanEnd::InputExhausted`].
    pub fn decode_available(
        &self,
        input: &[u8],
        max_output: usize,
        max_steps: u64,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Scan, DecodeError> {
        check_cancelled(cancelled)?;
        run(input, max_output, false, max_steps, cancelled)
    }
}

impl Decoder for Lz4Block {
    fn id(&self) -> &'static str {
        "lz4-block"
    }

    fn decode(
        &self,
        input: &[u8],
        options: &DecodeOptions,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Decoded, DecodeError> {
        options.preflight(input, MAX_BYTES_PER_INPUT_BYTE)?;
        check_cancelled(cancelled)?;
        let scan = run(input, options.expected_output_size, true, options.max_steps, cancelled)?;
        Ok(Decoded { bytes: scan.bytes, consumed: scan.consumed, steps: scan.steps })
    }
}

/// Why a sequence could not be decoded: the scan's end, or the error in exact mode.
enum Fault {
    Stop(ScanEnd, DecodeError),
    Fatal(DecodeError),
}

impl From<DecodeError> for Fault {
    fn from(error: DecodeError) -> Self {
        Self::Fatal(error)
    }
}

struct State<'a> {
    input: &'a [u8],
    target: usize,
    exact: bool,
    max_steps: u64,
    bytes: Vec<u8>,
    consumed: usize,
    steps: u64,
    stats: ScanStats,
}

impl State<'_> {
    fn byte(&mut self) -> Result<u8, Fault> {
        read_byte(self.input, &mut self.consumed).map_err(|error| Fault::Stop(ScanEnd::PartialToken, error))
    }

    fn length(&mut self, nibble: u8, cancelled: &mut dyn FnMut() -> bool) -> Result<usize, Fault> {
        let mut length = usize::from(nibble);
        if nibble == 15 {
            loop {
                take_step(&mut self.steps, self.max_steps, cancelled)?;
                let byte = self.byte()?;
                length += usize::from(byte);
                if byte != 255 {
                    break;
                }
            }
        }
        Ok(length)
    }

    /// Decodes one sequence. `Ok(true)` means the block ended with this sequence's literals.
    fn sequence(&mut self, cancelled: &mut dyn FnMut() -> bool) -> Result<bool, Fault> {
        let token = self.byte()?;
        let literals = self.length(token >> 4, cancelled)?;
        if literals > self.target - self.bytes.len() {
            return Err(Fault::Stop(ScanEnd::OutputLimit, DecodeError::OutputSizeMismatch));
        }
        if literals > self.input.len() - self.consumed {
            return Err(Fault::Stop(ScanEnd::PartialToken, DecodeError::TruncatedInput));
        }
        for &byte in &self.input[self.consumed..self.consumed + literals] {
            take_step(&mut self.steps, self.max_steps, cancelled)?;
            self.bytes.push(byte);
        }
        self.consumed += literals;
        self.stats.literals += literals as u64;
        if self.bytes.len() == self.target || self.consumed == self.input.len() {
            return Ok(true);
        }
        // Without a size, a block that ends with these literals may be followed by padding (one repeated byte).
        if !self.exact && padding(&self.input[self.consumed..]) {
            return Ok(true);
        }
        let low = self.byte()?;
        let high = self.byte()?;
        let distance = usize::from(low) | (usize::from(high) << 8);
        let length = self.length(token & 15, cancelled)? + MIN_MATCH;
        if distance == 0 || distance > self.bytes.len() {
            return Err(Fault::Stop(ScanEnd::InvalidToken, DecodeError::InvalidReference));
        }
        if length > self.target - self.bytes.len() {
            return Err(Fault::Stop(ScanEnd::OutputLimit, DecodeError::OutputSizeMismatch));
        }
        for _ in 0..length {
            take_step(&mut self.steps, self.max_steps, cancelled)?;
            self.bytes.push(self.bytes[self.bytes.len() - distance]);
        }
        self.stats.references += 1;
        self.stats.length_fields[usize::from(token & 15)] += 1;
        self.stats.near_references += u64::from(distance <= NEAR_DISTANCE);
        Ok(false)
    }
}

/// Whether `bytes` is a run of one repeated byte, as padding after a stream is. Empty counts.
pub(crate) fn padding(bytes: &[u8]) -> bool {
    bytes.iter().all(|&byte| byte == bytes[0])
}

fn run(
    input: &[u8],
    target: usize,
    exact: bool,
    max_steps: u64,
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<Scan, DecodeError> {
    let mut state = State {
        input,
        target,
        exact,
        max_steps,
        bytes: Vec::new(),
        consumed: 0,
        steps: 0,
        stats: ScanStats::default(),
    };
    if exact {
        state.bytes.try_reserve_exact(target).map_err(|_| DecodeError::AllocationFailure)?;
    }
    let mut sequence_end = 0;
    // Output and literal count at `sequence_end`: a sequence that fails leaves nothing behind in a scan.
    let (mut output_end, mut literals_end) = (0, 0);
    let mut end = ScanEnd::OutputLimit;
    while state.bytes.len() < target {
        take_step(&mut state.steps, max_steps, cancelled)?;
        if !exact && state.consumed == input.len() {
            end = ScanEnd::InputExhausted;
            break;
        }
        match state.sequence(cancelled) {
            Ok(last) => {
                sequence_end = state.consumed;
                (output_end, literals_end) = (state.bytes.len(), state.stats.literals);
                if last {
                    if state.bytes.len() < target {
                        // The input ended with these literals. Exact decoding needed more output.
                        if exact {
                            return Err(DecodeError::TruncatedInput);
                        }
                        end = ScanEnd::InputExhausted;
                    }
                    break;
                }
            }
            Err(Fault::Fatal(error)) => return Err(error),
            Err(Fault::Stop(_, error)) if exact => return Err(error),
            Err(Fault::Stop(stop, _)) => {
                end = stop;
                state.bytes.truncate(output_end);
                state.stats.literals = literals_end;
                break;
            }
        }
    }
    let consumed = if exact { state.consumed } else { sequence_end };
    Ok(Scan { bytes: state.bytes, consumed, steps: state.steps, end, stats: state.stats })
}
