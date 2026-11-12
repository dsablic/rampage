//! Parameterised LZSS: flag bytes of eight tokens, byte literals and 16-bit references.

use crate::{DecodeError, DecodeOptions, Decoded, Decoder, check_cancelled, read_byte, take_step};

/// Which bit of a flag byte describes the first token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlagOrder {
    LsbFirst,
    MsbFirst,
}

/// How the two reference bytes `b0 b1` split into an offset of `window_bits` and a length of the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReferenceLayout {
    /// Offset is `b0` plus the high bits of `b1` above it; length is the low bits of `b1`.
    SplitByte,
    /// Little-endian word; offset in the low bits, length above.
    Le16OffsetLow,
    /// Little-endian word; length in the low bits, offset above.
    Le16LengthLow,
    /// Big-endian word; offset in the low bits, length above.
    Be16OffsetLow,
    /// Big-endian word; length in the low bits, offset above.
    Be16LengthLow,
}

/// What a reference's offset field means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OffsetMode {
    /// An absolute position in a ring of `1 << window_bits` bytes, which starts filled with `dictionary_fill`
    /// and is written from `initial_write_offset`.
    RingPosition,
    /// The distance back from the next output byte; zero and distances past the output start are invalid.
    Distance,
    /// The distance back minus one; distances past the output start are invalid.
    DistanceMinusOne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Lzss {
    /// Offset bits, 10..=13; the length field has the other `16 - window_bits` bits.
    pub window_bits: u8,
    /// Added to the length field, 2 or 3.
    pub min_match: u8,
    pub flag_order: FlagOrder,
    /// The flag bit value that means literal.
    pub literal_flag: bool,
    pub layout: ReferenceLayout,
    pub offset_mode: OffsetMode,
    /// Ring mode only: initial write position, below `1 << window_bits`. Zero in the distance modes.
    pub initial_write_offset: u16,
    /// Ring mode only: the ring's initial contents. Zero in the distance modes.
    pub dictionary_fill: u8,
}

impl Lzss {
    /// The variant the `lzss-4k` provider names.
    pub const fn classic_4k(initial_write_offset: u16, dictionary_fill: u8) -> Self {
        Self {
            window_bits: 12,
            min_match: 3,
            flag_order: FlagOrder::LsbFirst,
            literal_flag: true,
            layout: ReferenceLayout::SplitByte,
            offset_mode: OffsetMode::RingPosition,
            initial_write_offset,
            dictionary_fill,
        }
    }

    pub fn window_size(&self) -> usize {
        1 << self.window_bits
    }

    pub fn length_bits(&self) -> u8 {
        16 - self.window_bits
    }

    pub fn max_match(&self) -> usize {
        (1usize << self.length_bits()) - 1 + usize::from(self.min_match)
    }

    pub fn is_valid(&self) -> bool {
        let ring = self.offset_mode == OffsetMode::RingPosition;
        (10..=13).contains(&self.window_bits)
            && (2..=3).contains(&self.min_match)
            && usize::from(self.initial_write_offset) < self.window_size()
            && (ring || (self.initial_write_offset == 0 && self.dictionary_fill == 0))
    }

    /// The offset and length fields of a reference's two bytes.
    pub(crate) fn fields(&self, b0: u8, b1: u8) -> (usize, usize) {
        let (b0, b1) = (usize::from(b0), usize::from(b1));
        let length_bits = usize::from(self.length_bits());
        let length_mask = (1 << length_bits) - 1;
        let offset_mask = self.window_size() - 1;
        match self.layout {
            ReferenceLayout::SplitByte => (b0 | ((b1 >> length_bits) << 8), b1 & length_mask),
            ReferenceLayout::Le16OffsetLow => ((b0 | (b1 << 8)) & offset_mask, (b0 | (b1 << 8)) >> self.window_bits),
            ReferenceLayout::Le16LengthLow => ((b0 | (b1 << 8)) >> length_bits, b0 & length_mask),
            ReferenceLayout::Be16OffsetLow => (((b0 << 8) | b1) & offset_mask, ((b0 << 8) | b1) >> self.window_bits),
            ReferenceLayout::Be16LengthLow => (((b0 << 8) | b1) >> length_bits, b1 & length_mask),
        }
    }

    /// Walks the tokens without copying and returns the input bytes consumed when the output would be exactly
    /// `expected` bytes long, or `None` when a token passes that size or the input ends first. Only the flag
    /// order, the literal flag, the length field and `min_match` matter. The second value is the tokens walked.
    pub fn measure(&self, input: &[u8], expected: usize) -> (Option<usize>, u64) {
        let min_match = usize::from(self.min_match);
        let (mut consumed, mut output, mut tokens) = (0, 0, 0u64);
        while output < expected {
            let Some(&flags) = input.get(consumed) else { return (None, tokens) };
            consumed += 1;
            for index in 0..8 {
                let bit = match self.flag_order {
                    FlagOrder::LsbFirst => flags >> index & 1 != 0,
                    FlagOrder::MsbFirst => flags << index & 0x80 != 0,
                };
                tokens += 1;
                if bit == self.literal_flag {
                    consumed += 1;
                    output += 1;
                } else {
                    let Some(pair) = input.get(consumed..consumed + 2) else { return (None, tokens) };
                    consumed += 2;
                    output += self.fields(pair[0], pair[1]).1 + min_match;
                }
                if output >= expected {
                    break;
                }
            }
        }
        ((output == expected && consumed <= input.len()).then_some(consumed), tokens)
    }

    /// Decodes until the input ends or `max_output` would be passed, for probing a stream of unknown length.
    /// A token that would pass `max_output` is not decoded.
    pub fn decode_available(
        &self,
        input: &[u8],
        max_output: usize,
        max_steps: u64,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Scan, DecodeError> {
        if !self.is_valid() {
            return Err(DecodeError::InvalidParameters);
        }
        check_cancelled(cancelled)?;
        run(self, input, Limit::Available(max_output), max_steps, cancelled)
    }
}

impl Decoder for Lzss {
    fn id(&self) -> &'static str {
        "lzss"
    }

    fn decode(
        &self,
        input: &[u8],
        options: &DecodeOptions,
        cancelled: &mut dyn FnMut() -> bool,
    ) -> Result<Decoded, DecodeError> {
        if !self.is_valid() {
            return Err(DecodeError::InvalidParameters);
        }
        options.preflight(input, self.max_match())?;
        check_cancelled(cancelled)?;
        let scan = run(self, input, Limit::Exact(options.expected_output_size), options.max_steps, cancelled)?;
        Ok(Decoded { bytes: scan.bytes, consumed: scan.consumed, steps: scan.steps })
    }
}

/// Why a [`Lzss::decode_available`] or LZ4 scan stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanEnd {
    /// The input ended on a token boundary.
    InputExhausted,
    /// The input ended inside a token; `consumed` stops before it.
    PartialToken,
    /// The next token would pass the output limit, or the limit was reached.
    OutputLimit,
    /// The next token is not valid for this codec; `consumed` stops before it.
    InvalidToken,
}

/// Parse statistics, which depend on the stream and parameters but not on what the data means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanStats {
    pub literals: u64,
    pub references: u64,
    /// References by length-field value (LZ4: by the token's match nibble).
    pub length_fields: [u32; 64],
    /// References whose source starts within an eighth of the window (LZ4: 512 bytes) of the output end.
    pub near_references: u64,
    /// Ring mode: output bytes copied from ring positions that no output byte had been written to.
    pub unwritten_bytes: u64,
    /// Ring mode: `(ring position, output bytes so far)` of the first references before the ring was full.
    pub early_references: Vec<(u16, u32)>,
    /// References shorter than the longest encodable length that a later output byte followed.
    pub maximal_checked: u64,
    /// Of those, the ones whose next output byte equals the byte after the copied source: a match the encoder
    /// could have made one byte longer. Greedy and lazy encoders rarely leave one, so wrong parameters that shift
    /// sources (a ring start or distance bias off by some bytes) show many.
    pub extendable: u64,
}

impl Default for ScanStats {
    fn default() -> Self {
        Self {
            literals: 0,
            references: 0,
            length_fields: [0; 64],
            near_references: 0,
            unwritten_bytes: 0,
            early_references: Vec::new(),
            maximal_checked: 0,
            extendable: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    pub bytes: Vec<u8>,
    /// Input bytes of whole tokens, including their flag bytes.
    pub consumed: usize,
    pub steps: u64,
    pub end: ScanEnd,
    pub stats: ScanStats,
}

pub(crate) const EARLY_REFERENCES: usize = 64;

enum Limit {
    Exact(usize),
    Available(usize),
}

fn run(
    lzss: &Lzss,
    input: &[u8],
    limit: Limit,
    max_steps: u64,
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<Scan, DecodeError> {
    let (target, exact) = match limit {
        Limit::Exact(size) => (size, true),
        Limit::Available(size) => (size, false),
    };
    let mut bytes = Vec::new();
    if exact {
        bytes.try_reserve_exact(target).map_err(|_| DecodeError::AllocationFailure)?;
    }
    let window = lzss.window_size();
    let mask = window - 1;
    let ring_mode = lzss.offset_mode == OffsetMode::RingPosition;
    let mut ring = if ring_mode { vec![lzss.dictionary_fill; window] } else { Vec::new() };
    let mut write_position = usize::from(lzss.initial_write_offset);
    let min_match = usize::from(lzss.min_match);
    let mut stats = ScanStats::default();
    let mut consumed = 0;
    let mut token_end = 0;
    let mut steps = 0;
    let mut flags = 0u8;
    let mut remaining_flags = 0;
    let mut end = ScanEnd::OutputLimit;
    // The byte after the previous short reference's source, compared with the next output byte.
    let mut pending: Option<u8> = None;
    macro_rules! observe {
        ($byte:expr) => {
            if let Some(expected) = pending.take() {
                stats.maximal_checked += 1;
                stats.extendable += u64::from($byte == expected);
            }
        };
    }

    // In exact mode a short input is an error; otherwise it ends the scan before the unfinished token.
    macro_rules! next_byte {
        () => {
            match read_byte(input, &mut consumed) {
                Ok(byte) => byte,
                Err(error) if exact => return Err(error),
                Err(_) => {
                    end = if consumed == token_end { ScanEnd::InputExhausted } else { ScanEnd::PartialToken };
                    break;
                }
            }
        };
    }

    while bytes.len() < target {
        take_step(&mut steps, max_steps, cancelled)?;
        if remaining_flags == 0 {
            flags = next_byte!();
            remaining_flags = 8;
        }
        let bit = match lzss.flag_order {
            FlagOrder::LsbFirst => {
                let bit = flags & 1 != 0;
                flags >>= 1;
                bit
            }
            FlagOrder::MsbFirst => {
                let bit = flags & 0x80 != 0;
                flags <<= 1;
                bit
            }
        };
        remaining_flags -= 1;

        if bit == lzss.literal_flag {
            let byte = next_byte!();
            take_step(&mut steps, max_steps, cancelled)?;
            observe!(byte);
            bytes.push(byte);
            if ring_mode {
                ring[write_position] = byte;
                write_position = (write_position + 1) & mask;
            }
            stats.literals += 1;
        } else {
            let b0 = next_byte!();
            let b1 = next_byte!();
            let (offset, length_field) = lzss.fields(b0, b1);
            let length = length_field + min_match;
            if length > target - bytes.len() {
                if exact {
                    return Err(DecodeError::OutputSizeMismatch);
                }
                break;
            }
            let distance = match lzss.offset_mode {
                OffsetMode::RingPosition => match write_position.wrapping_sub(offset) & mask {
                    0 => window,
                    distance => distance,
                },
                OffsetMode::Distance => offset,
                OffsetMode::DistanceMinusOne => offset + 1,
            };
            if ring_mode {
                if bytes.len() < window {
                    if stats.early_references.len() < EARLY_REFERENCES {
                        stats.early_references.push((offset as u16, bytes.len() as u32));
                    }
                    stats.unwritten_bytes += distance.saturating_sub(bytes.len()).min(length) as u64;
                }
                let mut read_position = offset;
                for _ in 0..length {
                    take_step(&mut steps, max_steps, cancelled)?;
                    let byte = ring[read_position];
                    observe!(byte);
                    bytes.push(byte);
                    ring[write_position] = byte;
                    read_position = (read_position + 1) & mask;
                    write_position = (write_position + 1) & mask;
                }
            } else {
                if distance == 0 || distance > bytes.len() {
                    if exact {
                        return Err(DecodeError::InvalidReference);
                    }
                    end = ScanEnd::InvalidToken;
                    break;
                }
                for _ in 0..length {
                    take_step(&mut steps, max_steps, cancelled)?;
                    let byte = bytes[bytes.len() - distance];
                    observe!(byte);
                    bytes.push(byte);
                }
            }
            if length < lzss.max_match() {
                pending = Some(if distance <= bytes.len() {
                    bytes[bytes.len() - distance]
                } else {
                    ring[(offset + length) & mask]
                });
            }
            stats.references += 1;
            stats.length_fields[length_field] += 1;
            stats.near_references += u64::from(distance <= window / 8);
        }
        token_end = consumed;
    }

    let consumed = if exact { consumed } else { token_end };
    Ok(Scan { bytes, consumed, steps, end, stats })
}
