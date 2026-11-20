//! Reference implementations a `computes` claim compares a function with: parameterised CRCs, checksums, hashes,
//! digests, one SHA-256 block and byte transforms. Each is written from its definition, and checked here against the
//! published check values (the CRC catalogue's "123456789" and the digests' test vectors).

use md5::Md5;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// A Rocksoft-model CRC of 8 to 64 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Crc {
    pub width: u32,
    pub poly: u64,
    pub init: u64,
    pub refin: bool,
    pub refout: bool,
    pub xorout: u64,
}

impl Crc {
    const fn new(width: u32, poly: u64, init: u64, reflected: bool, xorout: u64) -> Self {
        Self { width, poly, init, refin: reflected, refout: reflected, xorout }
    }

    fn mask(self) -> u64 {
        if self.width == 64 { u64::MAX } else { (1 << self.width) - 1 }
    }

    pub fn compute(self, data: &[u8]) -> u64 {
        let mask = self.mask();
        let top = 1u64 << (self.width - 1);
        let mut register = self.init & mask;
        for &byte in data {
            let byte = if self.refin { byte.reverse_bits() } else { byte };
            register ^= u64::from(byte) << (self.width - 8);
            for _ in 0..8 {
                register = if register & top != 0 { (register << 1) ^ self.poly } else { register << 1 } & mask;
            }
        }
        if self.refout {
            register = register.reverse_bits() >> (64 - self.width);
        }
        (register ^ self.xorout) & mask
    }

    /// The parameters as a claim spells them, for evidence.
    pub fn describe(self) -> String {
        let digits = self.width.div_ceil(4) as usize;
        format!(
            "crc width {} poly 0x{:0digits$x} init 0x{:0digits$x} refin {} refout {} xorout 0x{:0digits$x}",
            self.width, self.poly, self.init, self.refin, self.refout, self.xorout
        )
    }
}

/// Named CRC presets (the CRC catalogue's names), with aliases.
const PRESETS: [(&str, Crc); 21] = [
    ("crc32", Crc::new(32, 0x04c1_1db7, 0xffff_ffff, true, 0xffff_ffff)),
    ("crc32_iso_hdlc", Crc::new(32, 0x04c1_1db7, 0xffff_ffff, true, 0xffff_ffff)),
    ("crc32c", Crc::new(32, 0x1edc_6f41, 0xffff_ffff, true, 0xffff_ffff)),
    ("crc32_bzip2", Crc::new(32, 0x04c1_1db7, 0xffff_ffff, false, 0xffff_ffff)),
    ("crc32_mpeg2", Crc::new(32, 0x04c1_1db7, 0xffff_ffff, false, 0)),
    ("crc32_jamcrc", Crc::new(32, 0x04c1_1db7, 0xffff_ffff, true, 0)),
    ("crc32_posix", Crc::new(32, 0x04c1_1db7, 0, false, 0xffff_ffff)),
    ("crc16_arc", Crc::new(16, 0x8005, 0, true, 0)),
    ("crc16", Crc::new(16, 0x8005, 0, true, 0)),
    ("crc16_ibm", Crc::new(16, 0x8005, 0, true, 0)),
    ("crc16_modbus", Crc::new(16, 0x8005, 0xffff, true, 0)),
    ("crc16_ccitt_false", Crc::new(16, 0x1021, 0xffff, false, 0)),
    ("crc16_ibm_3740", Crc::new(16, 0x1021, 0xffff, false, 0)),
    ("crc16_xmodem", Crc::new(16, 0x1021, 0, false, 0)),
    ("crc16_kermit", Crc::new(16, 0x1021, 0, true, 0)),
    ("crc16_x25", Crc::new(16, 0x1021, 0xffff, true, 0xffff)),
    ("crc8", Crc::new(8, 0x07, 0, false, 0)),
    ("crc8_smbus", Crc::new(8, 0x07, 0, false, 0)),
    ("crc8_maxim", Crc::new(8, 0x31, 0, true, 0)),
    ("crc64_xz", Crc::new(64, 0x42f0_e1eb_a9ea_3693, u64::MAX, true, u64::MAX)),
    ("crc64_ecma", Crc::new(64, 0x42f0_e1eb_a9ea_3693, 0, false, 0)),
];

/// What a claim names: a preset or a family member.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum AlgorithmSpec {
    Name(String),
    Crc { crc: CrcSpec },
    Xor { xor: String },
    Add { add: u8 },
    Sub { sub: u8 },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CrcSpec {
    width: u32,
    poly: crate::evaluate::IntegerText,
    #[serde(default)]
    init: Option<crate::evaluate::IntegerText>,
    #[serde(default)]
    refin: bool,
    /// Defaults to refin.
    #[serde(default)]
    refout: Option<bool>,
    #[serde(default)]
    xorout: Option<crate::evaluate::IntegerText>,
}

/// What a reference computes, which decides how a function's arguments and result are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    /// An integer of this many bits over a byte buffer.
    Checksum(u32),
    /// A digest of this many bytes over a byte buffer.
    Digest(usize),
    /// A byte buffer transformed into one of the same length.
    Transform,
    /// SHA-256's compression of one 64-byte block into an eight-word state.
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reference {
    Crc(Crc),
    Adler32,
    Fletcher16,
    /// Over 16-bit words in the image's byte order, an odd tail zero-padded.
    Fletcher32,
    Fnv1a32,
    Fnv1a64,
    Fnv1_32,
    Fnv1_64,
    /// `h = h * 33 + c` from 5381.
    Djb2,
    /// `h = h * 33 ^ c` from 5381.
    Djb2Xor,
    /// `h = c + (h << 6) + (h << 16) - h`.
    Sdbm,
    Sum8,
    Sum16,
    Sum32,
    Xor8,
    Sha256,
    Sha1,
    Md5,
    Sha256Block,
    Xor(Vec<u8>),
    Add(u8),
    Sub(u8),
    Rot13,
    Not,
}

fn integer(text: &crate::evaluate::IntegerText) -> Result<u64, String> {
    match text {
        crate::evaluate::IntegerText::Unsigned(value) => Ok(*value),
        crate::evaluate::IntegerText::Signed(value) => Ok(*value as u64),
        crate::evaluate::IntegerText::Text(text) => {
            let clean = text.trim().replace('_', "");
            match clean.strip_prefix("0x").or_else(|| clean.strip_prefix("0X")) {
                Some(hex) => u64::from_str_radix(hex, 16),
                None => clean.parse(),
            }
            .map_err(|_| format!("{text:?} is not an integer"))
        }
    }
}

/// Every name [`Reference::parse`] accepts, for an error message.
pub(crate) fn names() -> String {
    let mut names: Vec<&str> = PRESETS.iter().map(|(name, _)| *name).collect();
    names.extend([
        "adler32",
        "fletcher16",
        "fletcher32",
        "fnv1a32",
        "fnv1a64",
        "fnv1_32",
        "fnv1_64",
        "djb2",
        "djb2_xor",
        "sdbm",
        "sum8",
        "sum16",
        "sum32",
        "xor8",
        "sha256",
        "sha1",
        "md5",
        "sha256_block",
        "rot13",
        "not",
    ]);
    names.join(", ")
}

impl Reference {
    pub fn parse(spec: &AlgorithmSpec) -> Result<Self, String> {
        Ok(match spec {
            AlgorithmSpec::Name(name) => {
                let name = name.trim().to_ascii_lowercase().replace(['-', '/'], "_");
                if let Some((_, crc)) = PRESETS.iter().find(|(preset, _)| *preset == name) {
                    return Ok(Reference::Crc(*crc));
                }
                match name.as_str() {
                    "adler32" => Reference::Adler32,
                    "fletcher16" => Reference::Fletcher16,
                    "fletcher32" => Reference::Fletcher32,
                    "fnv1a32" | "fnv1a" => Reference::Fnv1a32,
                    "fnv1a64" => Reference::Fnv1a64,
                    "fnv1_32" | "fnv1" => Reference::Fnv1_32,
                    "fnv1_64" => Reference::Fnv1_64,
                    "djb2" => Reference::Djb2,
                    "djb2_xor" => Reference::Djb2Xor,
                    "sdbm" => Reference::Sdbm,
                    "sum8" => Reference::Sum8,
                    "sum16" => Reference::Sum16,
                    "sum32" => Reference::Sum32,
                    "xor8" => Reference::Xor8,
                    "sha256" => Reference::Sha256,
                    "sha1" => Reference::Sha1,
                    "md5" => Reference::Md5,
                    "sha256_block" => Reference::Sha256Block,
                    "rot13" => Reference::Rot13,
                    "not" => Reference::Not,
                    _ => {
                        return Err(format!(
                            "unknown algorithm {name:?}; known: {}, or {{crc: {{...}}}}, {{xor: hex}}, {{add: n}}, {{sub: n}}",
                            names()
                        ));
                    }
                }
            }
            AlgorithmSpec::Crc { crc } => {
                if !(8..=64).contains(&crc.width) {
                    return Err("crc width must be 8..=64".to_owned());
                }
                let mask = if crc.width == 64 { u64::MAX } else { (1 << crc.width) - 1 };
                let field = |name: &str, value: Option<&crate::evaluate::IntegerText>| -> Result<u64, String> {
                    let value = value.map(integer).transpose()?.unwrap_or(0);
                    if value & !mask != 0 {
                        return Err(format!("crc {name} {value:#x} is wider than {} bits", crc.width));
                    }
                    Ok(value)
                };
                let poly = field("poly", Some(&crc.poly))?;
                if poly & 1 == 0 {
                    return Err("a CRC polynomial in normal form has its lowest bit set".to_owned());
                }
                Reference::Crc(Crc {
                    width: crc.width,
                    poly,
                    init: field("init", crc.init.as_ref())?,
                    refin: crc.refin,
                    refout: crc.refout.unwrap_or(crc.refin),
                    xorout: field("xorout", crc.xorout.as_ref())?,
                })
            }
            AlgorithmSpec::Xor { xor } => {
                let key = super::decode_hex(xor).map_err(|error| format!("xor key: {error}"))?;
                if key.is_empty() || key.len() > 256 {
                    return Err("an xor key is 1..=256 bytes".to_owned());
                }
                Reference::Xor(key)
            }
            AlgorithmSpec::Add { add } => Reference::Add(*add),
            AlgorithmSpec::Sub { sub } => Reference::Sub(*sub),
        })
    }

    pub fn shape(&self) -> Shape {
        match self {
            Reference::Crc(crc) => Shape::Checksum(crc.width),
            Reference::Fnv1a64 | Reference::Fnv1_64 => Shape::Checksum(64),
            Reference::Adler32
            | Reference::Fletcher32
            | Reference::Fnv1a32
            | Reference::Fnv1_32
            | Reference::Djb2
            | Reference::Djb2Xor
            | Reference::Sdbm
            | Reference::Sum32 => Shape::Checksum(32),
            Reference::Fletcher16 | Reference::Sum16 => Shape::Checksum(16),
            Reference::Sum8 | Reference::Xor8 => Shape::Checksum(8),
            Reference::Sha256 => Shape::Digest(32),
            Reference::Sha1 => Shape::Digest(20),
            Reference::Md5 => Shape::Digest(16),
            Reference::Sha256Block => Shape::Block,
            Reference::Xor(_) | Reference::Add(_) | Reference::Sub(_) | Reference::Rot13 | Reference::Not => {
                Shape::Transform
            }
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Reference::Crc(crc) => match PRESETS.iter().find(|(_, preset)| preset == crc) {
                Some((name, _)) => format!("{name} ({})", crc.describe()),
                None => crc.describe(),
            },
            Reference::Xor(key) => format!("xor with the repeating key {}", super::hex(key)),
            Reference::Add(key) => format!("add {key:#x} to each byte"),
            Reference::Sub(key) => format!("subtract {key:#x} from each byte"),
            other => format!("{other:?}").to_ascii_lowercase(),
        }
    }

    /// A checksum's value (masked to its width).
    pub fn checksum(&self, data: &[u8], big_endian: bool) -> u64 {
        match self {
            Reference::Crc(crc) => crc.compute(data),
            Reference::Adler32 => {
                let (mut a, mut b) = (1u32, 0u32);
                for &byte in data {
                    a = (a + u32::from(byte)) % 65521;
                    b = (b + a) % 65521;
                }
                u64::from((b << 16) | a)
            }
            Reference::Fletcher16 => {
                let (mut a, mut b) = (0u32, 0u32);
                for &byte in data {
                    a = (a + u32::from(byte)) % 255;
                    b = (b + a) % 255;
                }
                u64::from((b << 8) | a)
            }
            Reference::Fletcher32 => {
                let (mut a, mut b) = (0u32, 0u32);
                for pair in data.chunks(2) {
                    let (first, second) = (pair[0], pair.get(1).copied().unwrap_or(0));
                    let word = if big_endian {
                        u16::from_be_bytes([first, second])
                    } else {
                        u16::from_le_bytes([first, second])
                    };
                    a = (a + u32::from(word)) % 65535;
                    b = (b + a) % 65535;
                }
                u64::from((b << 16) | a)
            }
            Reference::Fnv1a32 => u64::from(
                data.iter().fold(0x811c_9dc5u32, |hash, &byte| (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193)),
            ),
            Reference::Fnv1_32 => u64::from(
                data.iter().fold(0x811c_9dc5u32, |hash, &byte| hash.wrapping_mul(0x0100_0193) ^ u32::from(byte)),
            ),
            Reference::Fnv1a64 => data
                .iter()
                .fold(0xcbf2_9ce4_8422_2325u64, |hash, &byte| (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)),
            Reference::Fnv1_64 => data
                .iter()
                .fold(0xcbf2_9ce4_8422_2325u64, |hash, &byte| hash.wrapping_mul(0x0100_0000_01b3) ^ u64::from(byte)),
            Reference::Djb2 => {
                u64::from(data.iter().fold(5381u32, |hash, &byte| hash.wrapping_mul(33).wrapping_add(u32::from(byte))))
            }
            Reference::Djb2Xor => {
                u64::from(data.iter().fold(5381u32, |hash, &byte| hash.wrapping_mul(33) ^ u32::from(byte)))
            }
            Reference::Sdbm => u64::from(data.iter().fold(0u32, |hash, &byte| {
                u32::from(byte).wrapping_add(hash << 6).wrapping_add(hash << 16).wrapping_sub(hash)
            })),
            Reference::Sum8 => u64::from(data.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte))),
            Reference::Sum16 => u64::from(data.iter().fold(0u16, |sum, &byte| sum.wrapping_add(u16::from(byte)))),
            Reference::Sum32 => u64::from(data.iter().fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte)))),
            Reference::Xor8 => u64::from(data.iter().fold(0u8, |sum, &byte| sum ^ byte)),
            _ => 0,
        }
    }

    /// A digest's bytes.
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Reference::Sha256 => Sha256::digest(data).to_vec(),
            Reference::Md5 => Md5::digest(data).to_vec(),
            Reference::Sha1 => <sha1::Sha1 as Digest>::digest(data).to_vec(),
            _ => Vec::new(),
        }
    }

    /// A transform's output for `data`.
    pub fn transform(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Reference::Xor(key) => data.iter().zip(key.iter().cycle()).map(|(byte, key)| byte ^ key).collect(),
            Reference::Add(key) => data.iter().map(|byte| byte.wrapping_add(*key)).collect(),
            Reference::Sub(key) => data.iter().map(|byte| byte.wrapping_sub(*key)).collect(),
            Reference::Not => data.iter().map(|byte| !byte).collect(),
            Reference::Rot13 => data
                .iter()
                .map(|&byte| match byte {
                    b'a'..=b'z' => (byte - b'a' + 13) % 26 + b'a',
                    b'A'..=b'Z' => (byte - b'A' + 13) % 26 + b'A',
                    other => other,
                })
                .collect(),
            _ => data.to_vec(),
        }
    }
}

/// SHA-256's compression function: `state` after one 64-byte `block`.
pub(crate) fn sha256_block(state: [u32; 8], block: &[u8; 64]) -> [u32; 8] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
        0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut w = [0u32; 64];
    for (index, word) in block.as_chunks::<4>().0.iter().enumerate() {
        w[index] = u32::from_be_bytes(*word);
    }
    for index in 16..64 {
        let s0 = w[index - 15].rotate_right(7) ^ w[index - 15].rotate_right(18) ^ (w[index - 15] >> 3);
        let s1 = w[index - 2].rotate_right(17) ^ w[index - 2].rotate_right(19) ^ (w[index - 2] >> 10);
        w[index] = w[index - 16].wrapping_add(s0).wrapping_add(w[index - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
    for index in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choice = (e & f) ^ (!e & g);
        let t1 = h.wrapping_add(s1).wrapping_add(choice).wrapping_add(K[index]).wrapping_add(w[index]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(majority);
        (h, g, f, e, d, c, b, a) = (g, f, e, d.wrapping_add(t1), c, b, a, t1.wrapping_add(t2));
    }
    let mut out = state;
    for (slot, value) in out.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(name: &str) -> Reference {
        Reference::parse(&AlgorithmSpec::Name(name.to_owned())).unwrap()
    }

    #[test]
    fn crc_presets_match_the_catalogue_check_values() {
        let check = b"123456789";
        for (name, expected) in [
            ("crc32", 0xcbf4_3926),
            ("crc32c", 0xe306_9283),
            ("crc32_bzip2", 0xfc89_1918),
            ("crc32_mpeg2", 0x0376_e6e7),
            ("crc32_jamcrc", 0x340b_c6d9),
            ("crc32_posix", 0x765e_7680),
            ("crc16_arc", 0xbb3d),
            ("crc16_modbus", 0x4b37),
            ("crc16_ccitt_false", 0x29b1),
            ("crc16_xmodem", 0x31c3),
            ("crc16_kermit", 0x2189),
            ("crc16_x25", 0x906e),
            ("crc8", 0xf4),
            ("crc8_maxim", 0xa1),
            ("crc64_xz", 0x995d_c9bb_df19_39fa),
            ("crc64_ecma", 0x6c40_df5f_0b49_7347),
        ] {
            assert_eq!(named(name).checksum(check, false), expected, "{name}");
        }
    }

    #[test]
    fn checksums_and_hashes_match_known_values() {
        assert_eq!(named("adler32").checksum(b"Wikipedia", false), 0x11e6_0398);
        assert_eq!(named("fletcher16").checksum(b"abcde", false), 0xc8f0);
        assert_eq!(named("fletcher32").checksum(b"abcde", false), 0xf04f_c729);
        assert_eq!(named("fnv1a32").checksum(b"", false), 0x811c_9dc5);
        assert_eq!(named("fnv1a32").checksum(b"a", false), 0xe40c_292c);
        assert_eq!(named("fnv1_32").checksum(b"a", false), 0x050c_5d7e);
        assert_eq!(named("fnv1a64").checksum(b"a", false), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(named("fnv1_64").checksum(b"a", false), 0xaf63_bd4c_8601_b7be);
        assert_eq!(named("djb2").checksum(b"a", false), 5381 * 33 + 97);
        assert_eq!(named("sum8").checksum(&[0xff, 2], false), 1);
        assert_eq!(named("xor8").checksum(&[0xf0, 0x0f, 1], false), 0xfe);
    }

    #[test]
    fn digests_and_the_sha256_block_match_their_test_vectors() {
        assert_eq!(
            super::super::hex(&named("sha256").digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(super::super::hex(&named("md5").digest(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(super::super::hex(&named("sha1").digest(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        // "abc" padded into one block, from the standard initial state.
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        block[63] = 24;
        let initial = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        assert_eq!(sha256_block(initial, &block)[0], 0xba7816bf);
    }

    #[test]
    fn crc_families_take_their_parameters_and_refuse_impossible_ones() {
        let spec: AlgorithmSpec = serde_json::from_value(serde_json::json!(
            {"crc": {"width": 32, "poly": "0x04c11db7", "init": "0xffffffff", "refin": true, "xorout": "0xffffffff"}}
        ))
        .unwrap();
        assert_eq!(Reference::parse(&spec).unwrap(), named("crc32"));
        let even: AlgorithmSpec =
            serde_json::from_value(serde_json::json!({"crc": {"width": 16, "poly": "0x8004"}})).unwrap();
        assert!(Reference::parse(&even).is_err());
        let wide: AlgorithmSpec =
            serde_json::from_value(serde_json::json!({"crc": {"width": 16, "poly": "0x18005"}})).unwrap();
        assert!(Reference::parse(&wide).is_err());
        assert!(Reference::parse(&AlgorithmSpec::Name("crc33".into())).is_err());
    }

    #[test]
    fn transforms_apply_their_keys() {
        let xor = Reference::parse(&AlgorithmSpec::Xor { xor: "0102".into() }).unwrap();
        assert_eq!(xor.transform(&[0, 0, 0]), vec![1, 2, 1]);
        assert_eq!(named("rot13").transform(b"Hello!"), b"Uryyb!");
        assert_eq!(Reference::Add(1).transform(&[0xff]), vec![0]);
    }
}
