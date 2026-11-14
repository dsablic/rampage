//! Checksum, CRC and digest algorithms as streaming states that can be read at any point of a range.

use std::sync::OnceLock;

use md5::Md5;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Rocksoft-model CRC parameters; every algorithm here has refin == refout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrcParams {
    pub width: u32,
    pub poly: u32,
    pub init: u32,
    pub reflected: bool,
    pub xorout: u32,
    /// Input taken as image-endian 32-bit words, each fed most significant byte first (STM32-style CRC units).
    pub words: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Algorithm {
    Crc32,
    Crc32Bzip2,
    Crc32Mpeg2,
    Crc32Mpeg2Words,
    Crc32Jamcrc,
    Crc32c,
    Adler32,
    Fletcher32,
    Sha256,
    Md5,
    Crc16CcittFalse,
    Crc16Xmodem,
    Crc16Kermit,
    Crc16Modbus,
    Crc16Arc,
    Fletcher16,
    Crc8Smbus,
    Crc8Maxim,
    Sum32Words,
    Sum32WordsNeg,
    Sum16Words,
    Sum16WordsNeg,
    Sum32,
    Sum32Neg,
    Sum16,
    Sum16Neg,
    Sum8,
    Sum8Neg,
    Xor32Words,
    Xor8,
}

/// Every algorithm, strongest first: the search spends its budget in this order.
pub const ALL: [Algorithm; 30] = [
    Algorithm::Crc32,
    Algorithm::Crc32Bzip2,
    Algorithm::Crc32Mpeg2,
    Algorithm::Crc32Mpeg2Words,
    Algorithm::Crc32Jamcrc,
    Algorithm::Crc32c,
    Algorithm::Adler32,
    Algorithm::Fletcher32,
    Algorithm::Sha256,
    Algorithm::Md5,
    Algorithm::Crc16CcittFalse,
    Algorithm::Crc16Xmodem,
    Algorithm::Crc16Kermit,
    Algorithm::Crc16Modbus,
    Algorithm::Crc16Arc,
    Algorithm::Fletcher16,
    Algorithm::Crc8Smbus,
    Algorithm::Crc8Maxim,
    Algorithm::Sum32Words,
    Algorithm::Sum32WordsNeg,
    Algorithm::Sum16Words,
    Algorithm::Sum16WordsNeg,
    Algorithm::Sum32,
    Algorithm::Sum32Neg,
    Algorithm::Sum16,
    Algorithm::Sum16Neg,
    Algorithm::Sum8,
    Algorithm::Sum8Neg,
    Algorithm::Xor32Words,
    Algorithm::Xor8,
];

const fn crc(width: u32, poly: u32, init: u32, reflected: bool, xorout: u32) -> CrcParams {
    CrcParams { width, poly, init, reflected, xorout, words: false }
}

impl Algorithm {
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Crc32 => "crc32",
            Algorithm::Crc32Bzip2 => "crc32_bzip2",
            Algorithm::Crc32Mpeg2 => "crc32_mpeg2",
            Algorithm::Crc32Mpeg2Words => "crc32_mpeg2_words",
            Algorithm::Crc32Jamcrc => "crc32_jamcrc",
            Algorithm::Crc32c => "crc32c",
            Algorithm::Adler32 => "adler32",
            Algorithm::Fletcher32 => "fletcher32",
            Algorithm::Sha256 => "sha256",
            Algorithm::Md5 => "md5",
            Algorithm::Crc16CcittFalse => "crc16_ccitt_false",
            Algorithm::Crc16Xmodem => "crc16_xmodem",
            Algorithm::Crc16Kermit => "crc16_kermit",
            Algorithm::Crc16Modbus => "crc16_modbus",
            Algorithm::Crc16Arc => "crc16_arc",
            Algorithm::Fletcher16 => "fletcher16",
            Algorithm::Crc8Smbus => "crc8_smbus",
            Algorithm::Crc8Maxim => "crc8_maxim",
            Algorithm::Sum32Words => "sum32_words",
            Algorithm::Sum32WordsNeg => "sum32_words_neg",
            Algorithm::Sum16Words => "sum16_words",
            Algorithm::Sum16WordsNeg => "sum16_words_neg",
            Algorithm::Sum32 => "sum32",
            Algorithm::Sum32Neg => "sum32_neg",
            Algorithm::Sum16 => "sum16",
            Algorithm::Sum16Neg => "sum16_neg",
            Algorithm::Sum8 => "sum8",
            Algorithm::Sum8Neg => "sum8_neg",
            Algorithm::Xor32Words => "xor32_words",
            Algorithm::Xor8 => "xor8",
        }
    }

    pub fn crc(self) -> Option<CrcParams> {
        Some(match self {
            Algorithm::Crc32 => crc(32, 0x04c1_1db7, 0xffff_ffff, true, 0xffff_ffff),
            Algorithm::Crc32Bzip2 => crc(32, 0x04c1_1db7, 0xffff_ffff, false, 0xffff_ffff),
            Algorithm::Crc32Mpeg2 => crc(32, 0x04c1_1db7, 0xffff_ffff, false, 0),
            Algorithm::Crc32Mpeg2Words => CrcParams { words: true, ..crc(32, 0x04c1_1db7, 0xffff_ffff, false, 0) },
            Algorithm::Crc32Jamcrc => crc(32, 0x04c1_1db7, 0xffff_ffff, true, 0),
            Algorithm::Crc32c => crc(32, 0x1edc_6f41, 0xffff_ffff, true, 0xffff_ffff),
            Algorithm::Crc16CcittFalse => crc(16, 0x1021, 0xffff, false, 0),
            Algorithm::Crc16Xmodem => crc(16, 0x1021, 0, false, 0),
            Algorithm::Crc16Kermit => crc(16, 0x1021, 0, true, 0),
            Algorithm::Crc16Modbus => crc(16, 0x8005, 0xffff, true, 0),
            Algorithm::Crc16Arc => crc(16, 0x8005, 0, true, 0),
            Algorithm::Crc8Smbus => crc(8, 0x07, 0, false, 0),
            Algorithm::Crc8Maxim => crc(8, 0x31, 0, true, 0),
            _ => return None,
        })
    }

    /// Bytes of the stored value.
    pub fn width(self) -> usize {
        match self {
            Algorithm::Sha256 => 32,
            Algorithm::Md5 => 16,
            Algorithm::Crc8Smbus | Algorithm::Crc8Maxim | Algorithm::Sum8 | Algorithm::Sum8Neg | Algorithm::Xor8 => 1,
            Algorithm::Crc16CcittFalse
            | Algorithm::Crc16Xmodem
            | Algorithm::Crc16Kermit
            | Algorithm::Crc16Modbus
            | Algorithm::Crc16Arc
            | Algorithm::Fletcher16
            | Algorithm::Sum16Words
            | Algorithm::Sum16WordsNeg
            | Algorithm::Sum16
            | Algorithm::Sum16Neg => 2,
            _ => 4,
        }
    }

    /// Input granularity: a range's length must be a multiple of it.
    pub fn granule(self) -> usize {
        match self {
            Algorithm::Crc32Mpeg2Words | Algorithm::Sum32Words | Algorithm::Sum32WordsNeg | Algorithm::Xor32Words => 4,
            Algorithm::Sum16Words | Algorithm::Sum16WordsNeg => 2,
            _ => 1,
        }
    }

    /// A 32-bit CRC, Adler-32, Fletcher-32 or a digest: a chance match is unlikely enough to search for the value
    /// anywhere. The others match only where the value sits right after or right before the range.
    pub fn strong(self) -> bool {
        self.width() >= 4 && self.crc().is_some()
            || matches!(self, Algorithm::Adler32 | Algorithm::Fletcher32 | Algorithm::Sha256 | Algorithm::Md5)
    }

    /// The model parameters, as reported.
    pub fn parameters(self) -> Value {
        if let Some(params) = self.crc() {
            let digits = params.width as usize / 4;
            let mut value = json!({
                "width": params.width,
                "poly": format!("0x{:0digits$x}", params.poly),
                "init": format!("0x{:0digits$x}", params.init),
                "refin": params.reflected,
                "refout": params.reflected,
                "xorout": format!("0x{:0digits$x}", params.xorout),
            });
            if params.words {
                value["input"] = json!("32-bit words, image byte order, most significant byte first");
            }
            return value;
        }
        let text = match self {
            Algorithm::Adler32 => "Adler-32 (RFC 1950)",
            Algorithm::Fletcher32 => "Fletcher-32 over image-endian 16-bit words, odd tail zero-padded",
            Algorithm::Fletcher16 => "Fletcher-16 over bytes, modulo 255",
            Algorithm::Sha256 => "SHA-256 digest (unkeyed)",
            Algorithm::Md5 => "MD5 digest (unkeyed)",
            Algorithm::Sum32Words => "sum of image-endian 32-bit words, modulo 2^32",
            Algorithm::Sum32WordsNeg => {
                "two's complement of the sum of image-endian 32-bit words (range plus value sums to 0)"
            }
            Algorithm::Sum16Words => "sum of image-endian 16-bit words, modulo 2^16",
            Algorithm::Sum16WordsNeg => "two's complement of the sum of image-endian 16-bit words",
            Algorithm::Sum32 => "sum of bytes, modulo 2^32",
            Algorithm::Sum32Neg => "two's complement of the sum of bytes, modulo 2^32",
            Algorithm::Sum16 => "sum of bytes, modulo 2^16",
            Algorithm::Sum16Neg => "two's complement of the sum of bytes, modulo 2^16",
            Algorithm::Sum8 => "sum of bytes, modulo 256",
            Algorithm::Sum8Neg => "two's complement of the sum of bytes, modulo 256 (range plus value sums to 0)",
            Algorithm::Xor32Words => "XOR of image-endian 32-bit words",
            _ => "XOR of bytes",
        };
        json!({ "description": text })
    }

    pub fn start(self, big_endian: bool) -> State {
        let kind = match self {
            Algorithm::Sha256 => Kind::Sha256(Box::default()),
            Algorithm::Md5 => Kind::Md5(Box::default()),
            Algorithm::Adler32 => Kind::Fletcher { low: 1, high: 0 },
            Algorithm::Fletcher16 | Algorithm::Fletcher32 => Kind::Fletcher { low: 0, high: 0 },
            _ => match self.crc() {
                Some(params) => {
                    let init = if params.reflected { reflect(params.init, params.width) } else { params.init };
                    Kind::Crc { register: init, params, table: table(self) }
                }
                None => Kind::Accumulator(0),
            },
        };
        State { algorithm: self, big_endian, kind, pending: [0; 4], pending_len: 0, length: 0 }
    }

    /// The whole computation over `bytes`; `None` when the length is not a multiple of the granule.
    pub fn compute(self, bytes: &[u8], big_endian: bool) -> Option<Vec<u8>> {
        let mut state = self.start(big_endian);
        state.update(bytes);
        state.value()
    }
}

fn reflect(value: u32, width: u32) -> u32 {
    value.reverse_bits() >> (32 - width)
}

fn table(algorithm: Algorithm) -> &'static [u32; 256] {
    static TABLES: OnceLock<Vec<(Algorithm, [u32; 256])>> = OnceLock::new();
    let tables = TABLES.get_or_init(|| {
        ALL.iter().filter_map(|&algorithm| algorithm.crc().map(|params| (algorithm, build_table(params)))).collect()
    });
    &tables.iter().find(|(entry, _)| *entry == algorithm).expect("CRC table").1
}

fn build_table(params: CrcParams) -> [u32; 256] {
    let mut table = [0u32; 256];
    let mask = if params.width == 32 { u32::MAX } else { (1 << params.width) - 1 };
    for (index, entry) in table.iter_mut().enumerate() {
        let mut value = index as u32;
        if params.reflected {
            let poly = reflect(params.poly, params.width);
            for _ in 0..8 {
                value = if value & 1 != 0 { (value >> 1) ^ poly } else { value >> 1 };
            }
        } else {
            value <<= params.width - 8;
            let top = 1 << (params.width - 1);
            for _ in 0..8 {
                value = if value & top != 0 { (value << 1) ^ params.poly } else { value << 1 };
            }
        }
        *entry = value & mask;
    }
    table
}

#[derive(Clone)]
enum Kind {
    Crc { register: u32, params: CrcParams, table: &'static [u32; 256] },
    Fletcher { low: u32, high: u32 },
    Accumulator(u64),
    Sha256(Box<Sha256>),
    Md5(Box<Md5>),
}

/// A computation in progress; [`State::value`] reads it without ending it.
#[derive(Clone)]
pub struct State {
    algorithm: Algorithm,
    big_endian: bool,
    kind: Kind,
    pending: [u8; 4],
    pending_len: usize,
    length: u64,
}

impl State {
    pub fn update(&mut self, bytes: &[u8]) {
        self.length += bytes.len() as u64;
        let granule = self.algorithm.granule().max(if self.algorithm == Algorithm::Fletcher32 { 2 } else { 1 });
        if granule == 1 {
            self.bytes(bytes);
            return;
        }
        let mut rest = bytes;
        if self.pending_len > 0 {
            let take = (granule - self.pending_len).min(rest.len());
            self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&rest[..take]);
            self.pending_len += take;
            rest = &rest[take..];
            if self.pending_len < granule {
                return;
            }
            let word = self.pending;
            self.word(&word[..granule]);
            self.pending_len = 0;
        }
        let (words, tail) = rest.split_at(rest.len() - rest.len() % granule);
        for word in words.chunks_exact(granule) {
            self.word(word);
        }
        self.pending[..tail.len()].copy_from_slice(tail);
        self.pending_len = tail.len();
    }

    fn word_value(&self, word: &[u8]) -> u64 {
        let fold = |value: u64, &byte: &u8| (value << 8) | u64::from(byte);
        if self.big_endian { word.iter().fold(0, fold) } else { word.iter().rev().fold(0, fold) }
    }

    fn word(&mut self, word: &[u8]) {
        let value = self.word_value(word);
        match self.algorithm {
            Algorithm::Crc32Mpeg2Words => {
                let bytes = (value as u32).to_be_bytes();
                self.bytes(&bytes);
            }
            Algorithm::Fletcher32 => {
                if let Kind::Fletcher { low, high } = &mut self.kind {
                    *low = (*low + value as u32) % 65535;
                    *high = (*high + *low) % 65535;
                }
            }
            Algorithm::Xor32Words => {
                if let Kind::Accumulator(total) = &mut self.kind {
                    *total ^= value;
                }
            }
            _ => {
                if let Kind::Accumulator(total) = &mut self.kind {
                    *total = total.wrapping_add(value);
                }
            }
        }
    }

    fn bytes(&mut self, bytes: &[u8]) {
        match &mut self.kind {
            Kind::Crc { register, params, table } => {
                if params.reflected {
                    for &byte in bytes {
                        *register = table[((*register ^ u32::from(byte)) & 0xff) as usize] ^ (*register >> 8);
                    }
                } else {
                    let shift = params.width - 8;
                    let mask = if params.width == 32 { u32::MAX } else { (1 << params.width) - 1 };
                    for &byte in bytes {
                        let index = ((*register >> shift) ^ u32::from(byte)) & 0xff;
                        *register = (table[index as usize] ^ (*register << 8)) & mask;
                    }
                }
            }
            Kind::Fletcher { low, high } => {
                let modulus = if self.algorithm == Algorithm::Adler32 { 65521 } else { 255 };
                // Reduce often enough that the sums never overflow.
                for chunk in bytes.chunks(4096) {
                    for &byte in chunk {
                        *low += u32::from(byte);
                        *high += *low;
                    }
                    *low %= modulus;
                    *high %= modulus;
                }
            }
            Kind::Accumulator(total) => {
                if self.algorithm == Algorithm::Xor8 {
                    *total ^= bytes.iter().fold(0u64, |value, &byte| value ^ u64::from(byte));
                } else {
                    *total = total.wrapping_add(bytes.iter().map(|&byte| u64::from(byte)).sum::<u64>());
                }
            }
            Kind::Sha256(hash) => hash.update(bytes),
            Kind::Md5(hash) => hash.update(bytes),
        }
    }

    /// The value over everything fed so far, as an unsigned integer (digests: `None`), or `None` when the
    /// length is not a multiple of the granule.
    pub fn number(&self) -> Option<u64> {
        if !self.length.is_multiple_of(self.algorithm.granule() as u64) {
            return None;
        }
        let bits = 8 * self.algorithm.width() as u32;
        let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
        let value = match &self.kind {
            Kind::Crc { register, params, .. } => u64::from(*register ^ params.xorout),
            Kind::Fletcher { low, high } => {
                let (mut low, mut high) = (*low, *high);
                if self.algorithm == Algorithm::Fletcher32 && self.pending_len == 1 {
                    // A zero-padded final 16-bit word.
                    let word =
                        if self.big_endian { u32::from(self.pending[0]) << 8 } else { u32::from(self.pending[0]) };
                    low = (low + word) % 65535;
                    high = (high + low) % 65535;
                }
                let shift = if self.algorithm == Algorithm::Fletcher16 { 8 } else { 16 };
                u64::from((high << shift) | low)
            }
            Kind::Accumulator(total) => {
                let negated = matches!(
                    self.algorithm,
                    Algorithm::Sum32WordsNeg
                        | Algorithm::Sum16WordsNeg
                        | Algorithm::Sum32Neg
                        | Algorithm::Sum16Neg
                        | Algorithm::Sum8Neg
                );
                if negated { total.wrapping_neg() } else { *total }
            }
            Kind::Sha256(_) | Kind::Md5(_) => return None,
        };
        Some(value & mask)
    }

    /// The stored-value bytes: a number little-endian (callers reverse it for big-endian), a digest as is.
    pub fn value(&self) -> Option<Vec<u8>> {
        match &self.kind {
            Kind::Sha256(hash) => Some(hash.as_ref().clone().finalize().to_vec()),
            Kind::Md5(hash) => Some(hash.as_ref().clone().finalize().to_vec()),
            _ => self.number().map(|value| value.to_le_bytes()[..self.algorithm.width()].to_vec()),
        }
    }
}
