//! Tables computed from their published definitions rather than pasted, so each is both our own authoring and
//! checked against the spec by the tests below.

use crate::math::{first_primes, fractional_root, pi_fraction_words, scaled_root};

/// Multiplication in GF(2^8) modulo the AES polynomial x^8 + x^4 + x^3 + x + 1 (FIPS 197 section 4.2).
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        a = (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 };
        b >>= 1;
    }
    product
}

/// FIPS 197 section 5.1.1: the multiplicative inverse followed by the affine transformation.
pub fn aes_sbox() -> [u8; 256] {
    let mut sbox = [0u8; 256];
    for (value, entry) in sbox.iter_mut().enumerate() {
        // a^254 is the inverse of a in GF(2^8), and maps 0 to 0 as the standard requires.
        let (mut b, mut base, mut exponent) = (1u8, value as u8, 254u8);
        while exponent != 0 {
            if exponent & 1 != 0 {
                b = gf_mul(b, base);
            }
            base = gf_mul(base, base);
            exponent >>= 1;
        }
        *entry = b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63;
    }
    sbox
}

pub fn aes_inverse_sbox() -> [u8; 256] {
    let mut inverse = [0u8; 256];
    for (index, &value) in aes_sbox().iter().enumerate() {
        inverse[usize::from(value)] = index as u8;
    }
    inverse
}

/// The Rijndael reference implementation's combined round tables: Te0[x] packs the MixColumns column
/// (2s, s, s, 3s) of s = S[x]; Td0[x] packs (14s', 9s', 13s', 11s') of s' = InvS[x]. Te1..Te3 and Td1..Td3 are
/// the same words rotated right by 8, 16 and 24 bits.
pub fn aes_round_tables(decrypt: bool) -> [Vec<u32>; 4] {
    let (sbox, factors) = if decrypt { (aes_inverse_sbox(), [14, 9, 13, 11]) } else { (aes_sbox(), [2, 1, 1, 3]) };
    let first: Vec<u32> = sbox.iter().map(|&s| u32::from_be_bytes(factors.map(|factor| gf_mul(s, factor)))).collect();
    std::array::from_fn(|rotation| first.iter().map(|word| word.rotate_right(8 * rotation as u32)).collect())
}

/// FIPS 197 section 5.2: Rcon[i] = x^(i-1) in GF(2^8), in the high byte of a word.
pub fn aes_rcon() -> Vec<u32> {
    let mut value = 1u8;
    (0..10)
        .map(|_| {
            let word = u32::from(value) << 24;
            value = gf_mul(value, 2);
            word
        })
        .collect()
}

/// A byte-at-a-time CRC table for a least-significant-bit-first (reflected) polynomial.
pub fn crc_table_reflected(polynomial: u64) -> Vec<u64> {
    (0..256u64)
        .map(|byte| (0..8).fold(byte, |crc, _| if crc & 1 != 0 { crc >> 1 ^ polynomial } else { crc >> 1 }))
        .collect()
}

/// A byte-at-a-time CRC table for a most-significant-bit-first polynomial of `width` bits.
pub fn crc_table_msb_first(polynomial: u64, width: u32) -> Vec<u64> {
    let top = 1u64 << (width - 1);
    let mask = if width == 64 { u64::MAX } else { (1 << width) - 1 };
    (0..256u64)
        .map(|byte| {
            (0..8).fold(byte << (width - 8), |crc, _| {
                if crc & top != 0 { (crc << 1 ^ polynomial) & mask } else { crc << 1 & mask }
            })
        })
        .collect()
}

/// FIPS 180-4 section 4.2.2: the first 32 bits of the fractional parts of the cube roots of the first 64 primes.
pub fn sha256_k() -> Vec<u32> {
    first_primes(64).into_iter().map(|p| fractional_root(p, 3, 32) as u32).collect()
}

/// FIPS 180-4 section 4.2.3: the first 64 bits of the fractional parts of the cube roots of the first 80 primes.
pub fn sha512_k() -> Vec<u64> {
    first_primes(80).into_iter().map(|p| fractional_root(p, 3, 64)).collect()
}

/// FIPS 180-4 sections 5.3.3 and 5.3.5: square roots of the first 8 primes (SHA-512 keeps 64 fractional bits,
/// SHA-256 the first 32 of them).
pub fn sha512_iv() -> Vec<u64> {
    first_primes(8).into_iter().map(|p| fractional_root(p, 2, 64)).collect()
}

pub fn sha256_iv() -> Vec<u32> {
    sha512_iv().into_iter().map(|word| (word >> 32) as u32).collect()
}

/// FIPS 180-4 section 5.3.4: square roots of the 9th through 16th primes; SHA-224 keeps the second 32 bits.
pub fn sha384_iv() -> Vec<u64> {
    first_primes(16).into_iter().skip(8).map(|p| fractional_root(p, 2, 64)).collect()
}

pub fn sha224_iv() -> Vec<u32> {
    sha384_iv().into_iter().map(|word| word as u32).collect()
}

/// FIPS 180-4 section 4.2.1: floor(2^30 * sqrt(n)) for n = 2, 3, 5, 10.
pub fn sha1_k() -> Vec<u32> {
    [2, 3, 5, 10].map(|n| scaled_root(n, 2, 30)).to_vec()
}

/// RIPEMD-160 (Dobbertin, Bosselaers, Preneel): the left line uses floor(2^30 * sqrt(n)) and the right line
/// floor(2^30 * cbrt(n)) for n = 2, 3, 5, 7. Each line's zero constant is omitted.
pub fn ripemd160_k(right: bool) -> Vec<u32> {
    [2, 3, 5, 7].map(|n| scaled_root(n, if right { 3 } else { 2 }, 30)).to_vec()
}

/// RFC 1321 section 3.4: T[i] = floor(4294967296 * abs(sin(i))) for i = 1..64, in radians.
pub fn md5_t() -> Vec<u32> {
    (1..=64).map(|i| (f64::from(i).sin().abs() * 4_294_967_296.0) as u32).collect()
}

/// FIPS 202 section 3.2.5: the iota step's round constants from the rc(t) linear feedback shift register.
pub fn keccak_round_constants() -> Vec<u64> {
    let rc = |t: u32| -> u64 {
        let mut register = 1u16;
        for _ in 0..t % 255 {
            register <<= 1;
            if register & 0x100 != 0 {
                register ^= 0x171;
            }
        }
        u64::from(register & 1)
    };
    (0..24).map(|round| (0..7).fold(0, |constant, j| constant | rc(j + 7 * round) << ((1 << j) - 1))).collect()
}

/// The Blowfish initial state (Schneier, 1993): the P-array then the four S-boxes, filled in order with the
/// hexadecimal digits of pi's fractional part.
pub fn blowfish_state() -> (Vec<u32>, [Vec<u32>; 4]) {
    let digits = pi_fraction_words(18 + 4 * 256);
    let sboxes = std::array::from_fn(|index| digits[18 + 256 * index..18 + 256 * (index + 1)].to_vec());
    (digits[..18].to_vec(), sboxes)
}

/// Twofish's fixed permutations q0 and q1, built from four 4-bit tables each (Twofish paper, section 4.3.5).
pub fn twofish_q(which: usize) -> [u8; 256] {
    const T: [[[u8; 16]; 4]; 2] = [
        [
            [0x8, 0x1, 0x7, 0xd, 0x6, 0xf, 0x3, 0x2, 0x0, 0xb, 0x5, 0x9, 0xe, 0xc, 0xa, 0x4],
            [0xe, 0xc, 0xb, 0x8, 0x1, 0x2, 0x3, 0x5, 0xf, 0x4, 0xa, 0x6, 0x7, 0x0, 0x9, 0xd],
            [0xb, 0xa, 0x5, 0xe, 0x6, 0xd, 0x9, 0x0, 0xc, 0x8, 0xf, 0x3, 0x2, 0x4, 0x7, 0x1],
            [0xd, 0x7, 0xf, 0x4, 0x1, 0x2, 0x6, 0xe, 0x9, 0xb, 0x3, 0x0, 0x8, 0x5, 0xc, 0xa],
        ],
        [
            [0x2, 0x8, 0xb, 0xd, 0xf, 0x7, 0x6, 0xe, 0x3, 0x1, 0x9, 0x4, 0x0, 0xa, 0xc, 0x5],
            [0x1, 0xe, 0x2, 0xb, 0x4, 0xc, 0x3, 0x7, 0x6, 0xd, 0xa, 0x5, 0xf, 0x9, 0x0, 0x8],
            [0x4, 0xc, 0x7, 0x5, 0x1, 0x6, 0x9, 0xa, 0x0, 0xe, 0xd, 0x8, 0x2, 0xb, 0x3, 0xf],
            [0xb, 0x9, 0x5, 0x1, 0xc, 0x3, 0xd, 0xe, 0x6, 0x4, 0x7, 0xf, 0x2, 0x0, 0x8, 0xa],
        ],
    ];
    let t = &T[which];
    let ror4 = |x: u8| (x >> 1 | x << 3) & 0xf;
    std::array::from_fn(|x| {
        let (a0, b0) = (x as u8 >> 4, x as u8 & 0xf);
        let (a1, b1) = (a0 ^ b0, a0 ^ ror4(b0) ^ ((8 * a0) & 0xf));
        let (a2, b2) = (t[0][usize::from(a1)], t[1][usize::from(b1)]);
        let (a3, b3) = (a2 ^ b2, a2 ^ ror4(b2) ^ ((8 * a2) & 0xf));
        let (a4, b4) = (t[2][usize::from(a3)], t[3][usize::from(b3)]);
        16 * b4 + a4
    })
}

/// FIPS 46-3 S-boxes S1..S8, each 4 rows of 16 entries.
pub const DES_SBOXES: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4,
        1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0,
        14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13,
        6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10,
        6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4,
        2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9,
        14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1,
        4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7,
        11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// FIPS 46-3 permutation P, 1-based bit numbers counted from the most significant bit.
pub const DES_P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4,
    25,
];

/// FIPS 46-3 initial permutation IP: rows read the even then the odd bit columns of the block bottom-up.
pub fn des_ip() -> Vec<u8> {
    [58u8, 60, 62, 64, 57, 59, 61, 63].iter().flat_map(|&start| (0..8).map(move |row| start - 8 * row)).collect()
}

/// FIPS 46-3 inverse initial permutation IP^-1.
pub fn des_fp() -> Vec<u8> {
    let mut inverse = vec![0u8; 64];
    for (position, &source) in des_ip().iter().enumerate() {
        inverse[usize::from(source) - 1] = position as u8 + 1;
    }
    inverse
}

/// FIPS 46-3 expansion E: each 6-bit group repeats its neighbours' edge bits, wrapping around the block.
pub fn des_e() -> Vec<u8> {
    (0..8u8).flat_map(|group| (0..6u8).map(move |bit| (4 * group + bit + 31) % 32 + 1)).collect()
}

/// The combined S-box-and-P tables (SP1..SP8) of the widespread Outerbridge d3des layout: entry j is
/// P(S_box(j)) indexed by the six E-expanded input bits in order, kept rotated left by one bit as that code
/// keeps its data halves.
pub fn des_sp(sbox: usize) -> Vec<u32> {
    let permute = |value: u32| {
        DES_P
            .iter()
            .enumerate()
            .fold(0u32, |out, (index, &source)| out | ((value >> (32 - u32::from(source))) & 1) << (31 - index))
    };
    (0..64usize)
        .map(|j| {
            let row = (j >> 4 & 2) | (j & 1);
            let column = j >> 1 & 0xf;
            let output = u32::from(DES_SBOXES[sbox][row * 16 + column]) << (28 - 4 * sbox);
            permute(output).rotate_left(1)
        })
        .collect()
}

/// The GHASH 4-bit reduction table (`rem_4bit`, `last4`) used by table-driven AES-GCM: entry i folds the four
/// bits shifted out of the field element back in with R = 0xE1 || 0^120 (NIST SP 800-38D section 6.3).
pub fn ghash_rem_4bit() -> Vec<u16> {
    (0..16u16).map(|i| (0..4).filter(|bit| i >> bit & 1 != 0).fold(0, |acc, bit| acc ^ 0xe100 >> (3 - bit))).collect()
}

/// RFC 1951 section 3.2.5: base lengths of length codes 257..285 (each base adds 2^extra to the previous one;
/// code 285 is the special case 258).
pub fn deflate_length_base() -> Vec<u32> {
    let mut base = 3;
    let mut table: Vec<u32> = (0..28)
        .map(|code| {
            let current = base;
            base += 1 << if code < 8 { 0 } else { (code - 4) / 4 };
            current
        })
        .collect();
    table.push(258);
    table
}

/// RFC 1951 section 3.2.5: base distances of distance codes 0..29.
pub fn deflate_distance_base() -> Vec<u32> {
    let mut base = 1;
    (0..30)
        .map(|code| {
            let current = base;
            base += 1 << if code < 4 { 0 } else { (code - 2) / 2 };
            current
        })
        .collect()
}

/// RFC 1951 section 3.2.7: the order in which code length code lengths are sent.
pub const DEFLATE_CODE_LENGTH_ORDER: [u8; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// RFC 4648 alphabets.
pub fn base64_alphabet(url_safe: bool) -> Vec<u8> {
    let tail: &[u8] = if url_safe { b"-_" } else { b"+/" };
    (b'A'..=b'Z').chain(b'a'..=b'z').chain(b'0'..=b'9').chain(tail.iter().copied()).collect()
}

pub fn base32_alphabet() -> Vec<u8> {
    (b'A'..=b'Z').chain(b'2'..=b'7').collect()
}

/// The ChaCha and Salsa20 constant words: the ASCII string read as four little-endian words.
pub fn sigma_words(text: &[u8; 16]) -> Vec<u32> {
    text.as_chunks::<4>().0.iter().map(|&chunk| u32::from_le_bytes(chunk)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crc(table: &[u64], width: u32, reflected: bool, init: u64, xor_out: u64, data: &[u8]) -> u64 {
        let mask = if width == 64 { u64::MAX } else { (1 << width) - 1 };
        let state = data.iter().fold(init, |state, &byte| {
            if reflected {
                table[((state ^ u64::from(byte)) & 0xff) as usize] ^ state >> 8
            } else {
                (table[((state >> (width - 8) ^ u64::from(byte)) & 0xff) as usize] ^ state << 8) & mask
            }
        });
        state ^ xor_out
    }

    #[test]
    fn aes_tables_match_fips_197() {
        let sbox = aes_sbox();
        assert_eq!((sbox[0x00], sbox[0x01], sbox[0x53], sbox[0xff]), (0x63, 0x7c, 0xed, 0x16));
        let inverse = aes_inverse_sbox();
        assert_eq!((inverse[0x00], inverse[0x63], inverse[0xff]), (0x52, 0x00, 0x7d));
        let te = aes_round_tables(false);
        assert_eq!((te[0][0], te[0][1], te[1][0], te[3][0]), (0xc663_63a5, 0xf87c_7c84, 0xa5c6_6363, 0x6363_a5c6));
        let td = aes_round_tables(true);
        assert_eq!((td[0][0], td[0][1]), (0x51f4_a750, 0x7e41_6553));
        assert_eq!(aes_rcon()[..3], [0x0100_0000, 0x0200_0000, 0x0400_0000]);
        assert_eq!(aes_rcon()[8..], [0x1b00_0000, 0x3600_0000]);
    }

    #[test]
    fn crc_tables_reproduce_catalogue_check_values() {
        let check = b"123456789";
        let crc32 = crc_table_reflected(0xedb8_8320);
        assert_eq!(crc32[1], 0x7707_3096);
        assert_eq!(crc(&crc32, 32, true, 0xffff_ffff, 0xffff_ffff, check), 0xcbf4_3926);
        let crc32c = crc_table_reflected(0x82f6_3b78);
        assert_eq!(crc(&crc32c, 32, true, 0xffff_ffff, 0xffff_ffff, check), 0xe306_9283);
        let bzip2 = crc_table_msb_first(0x04c1_1db7, 32);
        assert_eq!(bzip2[1], 0x04c1_1db7);
        assert_eq!(crc(&bzip2, 32, false, 0xffff_ffff, 0xffff_ffff, check), 0xfc89_1918);
        let arc = crc_table_reflected(0xa001);
        assert_eq!(crc(&arc, 16, true, 0, 0, check), 0xbb3d);
        let xmodem = crc_table_msb_first(0x1021, 16);
        assert_eq!(crc(&xmodem, 16, false, 0, 0, check), 0x31c3);
        let xz = crc_table_reflected(0xc96c_5795_d787_0f42);
        assert_eq!(crc(&xz, 64, true, u64::MAX, u64::MAX, check), 0x995d_c9bb_df19_39fa);
    }

    #[test]
    fn hash_constants_match_their_specifications() {
        let k = sha256_k();
        assert_eq!((k[0], k[1], k[63]), (0x428a_2f98, 0x7137_4491, 0xc671_78f2));
        assert_eq!(sha256_iv()[..2], [0x6a09_e667, 0xbb67_ae85]);
        assert_eq!(sha256_iv()[7], 0x5be0_cd19);
        assert_eq!(sha224_iv()[..2], [0xc105_9ed8, 0x367c_d507]);
        let k = sha512_k();
        assert_eq!((k[0], k[79]), (0x428a_2f98_d728_ae22, 0x6c44_198c_4a47_5817));
        assert_eq!(sha512_iv()[7], 0x5be0_cd19_137e_2179);
        assert_eq!(sha384_iv()[0], 0xcbbb_9d5d_c105_9ed8);
        assert_eq!(sha1_k(), [0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xca62_c1d6]);
        assert_eq!(ripemd160_k(false)[3], 0xa953_fd4e);
        assert_eq!(ripemd160_k(true), [0x50a2_8be6, 0x5c4d_d124, 0x6d70_3ef3, 0x7a6d_76e9]);
        let t = md5_t();
        assert_eq!((t[0], t[1], t[31], t[63]), (0xd76a_a478, 0xe8c7_b756, 0x8d2a_4c8a, 0xeb86_d391));
        let rc = keccak_round_constants();
        assert_eq!((rc[0], rc[1], rc[23]), (1, 0x8082, 0x8000_0000_8000_8008));
    }

    #[test]
    fn cipher_tables_match_their_specifications() {
        let (p, sboxes) = blowfish_state();
        assert_eq!((p[0], p[17]), (0x243f_6a88, 0x8979_fb1b));
        assert_eq!((sboxes[0][0], sboxes[0][255], sboxes[3][255]), (0xd131_0ba6, 0x6e85_076a, 0x3ac3_72e6));
        assert_eq!(twofish_q(0)[..4], [0xa9, 0x67, 0xb3, 0xe8]);
        assert_eq!(twofish_q(1)[..4], [0x75, 0xf3, 0xc6, 0xf4]);
        assert_eq!(des_sp(0)[..4], [0x0101_0400, 0, 0x0001_0000, 0x0101_0404]);
        assert_eq!(des_sp(1)[..2], [0x8010_8020, 0x8000_8000]);
        assert_eq!(des_ip()[..9], [58, 50, 42, 34, 26, 18, 10, 2, 60]);
        assert_eq!(des_fp()[..8], [40, 8, 48, 16, 56, 24, 64, 32]);
        assert_eq!(des_e()[..7], [32, 1, 2, 3, 4, 5, 4]);
        assert_eq!(des_e()[47], 1);
        assert_eq!(ghash_rem_4bit()[..4], [0x0000, 0x1c20, 0x3840, 0x2460]);
        assert_eq!(ghash_rem_4bit()[15], 0xb5e0);
    }

    #[test]
    fn deflate_and_encoding_tables_match_their_rfcs() {
        let lengths = deflate_length_base();
        assert_eq!((lengths.len(), lengths[8], lengths[27], lengths[28]), (29, 11, 227, 258));
        let distances = deflate_distance_base();
        assert_eq!((distances.len(), distances[4], distances[29]), (30, 5, 24577));
        assert_eq!(&base64_alphabet(false)[60..], b"89+/");
        assert_eq!(&base64_alphabet(true)[62..], b"-_");
        assert_eq!(base32_alphabet().len(), 32);
        assert_eq!(sigma_words(b"expand 32-byte k"), [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    }
}
