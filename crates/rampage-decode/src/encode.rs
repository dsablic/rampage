//! Reference encoders and synthetic content for owned test vectors. Nothing here is used to decode: the encoders
//! are simple greedy ones that exist so tests and measurements can build streams for every decoder variant.

use crate::{FlagOrder, Lzss, OffsetMode, ReferenceLayout};

const CHAIN_DEPTH: usize = 48;
const HASH_BITS: u32 = 15;

/// A small deterministic generator (xorshift64).
#[derive(Debug, Clone)]
pub struct Random(pub u64);

impl Random {
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, bound: usize) -> usize {
        ((self.next_u64() >> 16) % bound as u64) as usize
    }

    pub fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length).map(|_| (self.next_u64() >> 24) as u8).collect()
    }
}

fn hash(bytes: &[u8]) -> usize {
    let value = bytes.iter().fold(0u32, |value, &byte| (value << 8) | u32::from(byte));
    (value.wrapping_mul(0x9e37_79b1) >> (32 - HASH_BITS)) as usize
}

/// Hash chains over every position of a buffer, for the longest earlier match within a distance.
struct Matcher {
    key: usize,
    head: Vec<u32>,
    previous: Vec<u32>,
}

impl Matcher {
    fn new(key: usize, length: usize) -> Self {
        Self { key, head: vec![u32::MAX; 1 << HASH_BITS], previous: vec![u32::MAX; length] }
    }

    fn insert(&mut self, buffer: &[u8], position: usize) {
        if position + self.key <= buffer.len() {
            let slot = hash(&buffer[position..position + self.key]);
            self.previous[position] = self.head[slot];
            self.head[slot] = position as u32;
        }
    }

    /// The longest match for `position` at most `max_distance` back and `max_length` long: `(start, length)`.
    fn longest(&self, buffer: &[u8], position: usize, max_distance: usize, max_length: usize) -> (usize, usize) {
        let max_length = max_length.min(buffer.len() - position);
        let mut best = (0, 0);
        if position + self.key > buffer.len() {
            return best;
        }
        let mut candidate = self.head[hash(&buffer[position..position + self.key])];
        for _ in 0..CHAIN_DEPTH {
            if candidate == u32::MAX || position - candidate as usize > max_distance {
                break;
            }
            let start = candidate as usize;
            let length = (0..max_length).take_while(|&index| buffer[start + index] == buffer[position + index]).count();
            if length > best.1 {
                best = (start, length);
            }
            candidate = self.previous[start];
        }
        best
    }
}

/// Greedily encodes `data` as the stream `lzss` decodes. In ring mode the encoder also matches against the
/// ring's initial fill, as the classic encoder does.
pub fn lzss(lzss: &Lzss, data: &[u8]) -> Vec<u8> {
    assert!(lzss.is_valid(), "invalid LZSS parameters");
    let window = lzss.window_size();
    let ring = lzss.offset_mode == OffsetMode::RingPosition;
    let start = if ring { window } else { 0 };
    let mut buffer = vec![lzss.dictionary_fill; start];
    buffer.extend_from_slice(data);
    let max_distance = if lzss.offset_mode == OffsetMode::DistanceMinusOne { window } else { window - 1 };
    let min_match = usize::from(lzss.min_match);
    let mut matcher = Matcher::new(min_match, buffer.len());
    // The fill is one repeated byte, so its last positions stand for all of it.
    for position in start.saturating_sub(lzss.max_match())..start {
        matcher.insert(&buffer, position);
    }

    let mut output = Vec::new();
    let mut flag_at = 0;
    let mut tokens = 0;
    let mut position = start;
    while position < buffer.len() {
        if tokens % 8 == 0 {
            flag_at = output.len();
            output.push(if lzss.literal_flag { 0 } else { 0xff });
        }
        let bit = match lzss.flag_order {
            FlagOrder::LsbFirst => 1u8 << (tokens % 8),
            FlagOrder::MsbFirst => 0x80u8 >> (tokens % 8),
        };
        tokens += 1;
        let (source, length) = matcher.longest(&buffer, position, max_distance, lzss.max_match());
        if length >= min_match {
            // The flag byte starts as all references.
            let distance = position - source;
            let offset = match lzss.offset_mode {
                OffsetMode::RingPosition => {
                    (usize::from(lzss.initial_write_offset) + window + source - start) & (window - 1)
                }
                OffsetMode::Distance => distance,
                OffsetMode::DistanceMinusOne => distance - 1,
            };
            output.extend(pack(lzss, offset, length - min_match));
            for covered in position..position + length {
                matcher.insert(&buffer, covered);
            }
            position += length;
        } else {
            output[flag_at] ^= bit;
            output.push(buffer[position]);
            matcher.insert(&buffer, position);
            position += 1;
        }
    }
    output
}

fn pack(lzss: &Lzss, offset: usize, length: usize) -> [u8; 2] {
    let length_bits = usize::from(lzss.length_bits());
    let word = match lzss.layout {
        ReferenceLayout::SplitByte => return [offset as u8, (((offset >> 8) << length_bits) | length) as u8],
        ReferenceLayout::Le16OffsetLow | ReferenceLayout::Be16OffsetLow => offset | (length << lzss.window_bits),
        ReferenceLayout::Le16LengthLow | ReferenceLayout::Be16LengthLow => length | (offset << length_bits),
    } as u16;
    match lzss.layout {
        ReferenceLayout::Le16OffsetLow | ReferenceLayout::Le16LengthLow => word.to_le_bytes(),
        _ => word.to_be_bytes(),
    }
}

fn lz4_length(output: &mut Vec<u8>, mut rest: usize) {
    while rest >= 255 {
        output.push(255);
        rest -= 255;
    }
    output.push(rest as u8);
}

fn lz4_sequence(output: &mut Vec<u8>, literals: &[u8], reference: Option<(usize, usize)>) {
    let match_field = reference.map_or(0, |(_, length)| length - 4);
    output.push(((literals.len().min(15) as u8) << 4) | match_field.min(15) as u8);
    if literals.len() >= 15 {
        lz4_length(output, literals.len() - 15);
    }
    output.extend_from_slice(literals);
    if let Some((distance, _)) = reference {
        output.extend((distance as u16).to_le_bytes());
        if match_field >= 15 {
            lz4_length(output, match_field - 15);
        }
    }
}

/// Greedily encodes `data` as one LZ4 block, which ends with a literal-only sequence.
pub fn lz4_block(data: &[u8]) -> Vec<u8> {
    let mut matcher = Matcher::new(4, data.len());
    let mut output = Vec::new();
    let mut literal_start = 0;
    let mut position = 0;
    // The format keeps the last five bytes literal and starts no match in the last twelve.
    let match_limit = data.len().saturating_sub(12);
    while position < match_limit {
        let (source, length) = matcher.longest(data, position, 65535, data.len() - 5 - position);
        if length >= 4 {
            lz4_sequence(&mut output, &data[literal_start..position], Some((position - source, length)));
            for covered in position..position + length {
                matcher.insert(data, covered);
            }
            position += length;
            literal_start = position;
        } else {
            matcher.insert(data, position);
            position += 1;
        }
    }
    lz4_sequence(&mut output, &data[literal_start..], None);
    output
}

const WORDS: [&str; 24] = [
    "error",
    "timeout",
    "init",
    "sensor",
    "config",
    "update",
    "version",
    "failed",
    "ready",
    "channel",
    "buffer",
    "voltage",
    "calibration",
    "checksum",
    "bootloader",
    "watchdog",
    "overflow",
    "status",
    "invalid",
    "device",
    "threshold",
    "register",
    "interrupt",
    "firmware",
];

/// Synthetic firmware-like bytes: Thumb-shaped functions with literal pools, message strings, small-integer and
/// pointer tables and short zero runs. Deterministic for a seed. It is not valid code for any device.
pub fn synthetic_firmware(length: usize, seed: u64) -> Vec<u8> {
    let mut random = Random(seed | 1);
    let mut bytes = Vec::with_capacity(length + 256);
    // A fixed vocabulary of 16-bit instruction words, reused with a skew as compilers reuse idioms.
    let vocabulary: Vec<u16> = (0..384)
        .map(|_| match random.below(8) {
            0 => 0x6800 | (random.below(0x800) as u16),
            1 => 0x6000 | (random.below(0x800) as u16),
            2 => 0x2000 | (random.below(0x800) as u16),
            3 => 0x4600 | (random.below(0x100) as u16),
            4 => 0xd000 | (random.below(0xe00) as u16),
            5 => 0x1800 | (random.below(0x400) as u16),
            6 => 0x4800 | (random.below(0x800) as u16),
            _ => 0x9000 | (random.below(0x1000) as u16),
        })
        .collect();
    while bytes.len() < length {
        match random.below(16) {
            0..=10 => {
                bytes.extend([0xf0 | (random.below(16) as u8), 0xb5]);
                for _ in 0..8 + random.below(120) {
                    if random.below(9) == 0 {
                        let target = random.below(0x800) as u16;
                        bytes.extend((0xf000 | (target >> 3)).to_le_bytes());
                        bytes.extend((0xf800 | target).to_le_bytes());
                    } else {
                        // The minimum of two draws favours the low indices.
                        let index = random.below(vocabulary.len()).min(random.below(vocabulary.len()));
                        bytes.extend(vocabulary[index].to_le_bytes());
                    }
                }
                bytes.extend([0xf0 | (random.below(16) as u8), 0xbd]);
                for _ in 0..random.below(4) {
                    let base = if random.below(2) == 0 { 0x0800_0000u32 } else { 0x2000_0000 };
                    bytes.extend((base + (random.below(0x4000) as u32) * 4).to_le_bytes());
                }
            }
            11 | 12 => {
                for _ in 0..4 + random.below(12) {
                    for word in 0..2 + random.below(4) {
                        if word > 0 {
                            bytes.push(b' ');
                        }
                        bytes.extend(WORDS[random.below(WORDS.len())].as_bytes());
                    }
                    if random.below(3) == 0 {
                        bytes.extend(b": %d");
                    }
                    bytes.push(0);
                }
            }
            13 => {
                for _ in 0..8 + random.below(56) {
                    bytes.extend((random.below(1024) as u32).to_le_bytes());
                }
            }
            14 => {
                for _ in 0..4 + random.below(28) {
                    bytes.extend((0x0800_0001u32 + (random.below(0x8000) as u32) * 2).to_le_bytes());
                }
            }
            _ => bytes.extend(std::iter::repeat_n(0u8, 4 + random.below(60))),
        }
    }
    bytes.truncate(length);
    bytes
}
