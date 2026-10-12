//! The bundled constant database. Every entry is authored here from its specification; the curve parameters are
//! the only long literals, and each was checked offline against its curve equation and group order.

use std::borrow::Cow;

use crate::generate::*;
use crate::{ConstantSignature, Kind, Pattern};

/// How much of a large table must match: 64 bytes (16 words, or 64 S-box entries) is far beyond chance yet
/// still finds a table stored truncated or split.
const TABLE_HEAD: usize = 64;

fn signature(
    algorithm: &'static str,
    kind: Kind,
    what: impl Into<Cow<'static, str>>,
    source: &'static str,
    pattern: Pattern,
    min_len: Option<usize>,
) -> ConstantSignature {
    let min_len = min_len.unwrap_or_else(|| pattern.byte_len());
    ConstantSignature {
        algorithm: Cow::Borrowed(algorithm),
        kind,
        what: what.into(),
        source: Cow::Borrowed(source),
        pattern,
        min_len,
    }
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex literal")).collect()
}

fn widen<T: Copy + Into<u64>>(values: &[T]) -> Vec<u64> {
    values.iter().map(|&value| value.into()).collect()
}

pub fn signatures() -> Vec<ConstantSignature> {
    let mut all = Vec::new();
    all.extend(block_ciphers());
    all.extend(hashes());
    all.extend(other_primitives());
    all.extend(checksums_and_formats());
    all.extend(curves());
    all
}

fn block_ciphers() -> Vec<ConstantSignature> {
    use Kind::BlockCipher;
    const FIPS197: &str = "FIPS 197";
    const FIPS46: &str = "FIPS 46-3";
    let head = Some(TABLE_HEAD);
    let mut all = vec![
        signature("AES", BlockCipher, "AES forward S-box", FIPS197, Pattern::Bytes(aes_sbox().to_vec()), head),
        signature("AES", BlockCipher, "AES inverse S-box", FIPS197, Pattern::Bytes(aes_inverse_sbox().to_vec()), head),
        signature("AES", BlockCipher, "AES key expansion Rcon", FIPS197, Pattern::U32(aes_rcon()), None),
    ];
    for (decrypt, name) in [(false, "Te"), (true, "Td")] {
        for (index, table) in aes_round_tables(decrypt).into_iter().enumerate() {
            let what = format!("AES round table {name}{index}");
            all.push(signature(
                "AES",
                BlockCipher,
                what,
                "FIPS 197; Rijndael reference code",
                Pattern::U32(table),
                head,
            ));
        }
    }
    let sboxes = DES_SBOXES.concat();
    all.push(signature("DES", BlockCipher, "DES S-boxes S1..S8", FIPS46, Pattern::Bytes(sboxes), head));
    all.push(signature("DES", BlockCipher, "DES initial permutation IP", FIPS46, Pattern::Bytes(des_ip()), None));
    all.push(signature("DES", BlockCipher, "DES final permutation IP^-1", FIPS46, Pattern::Bytes(des_fp()), None));
    all.push(signature("DES", BlockCipher, "DES expansion E", FIPS46, Pattern::Bytes(des_e()), None));
    all.push(signature("DES", BlockCipher, "DES permutation P", FIPS46, Pattern::Bytes(DES_P.to_vec()), None));
    for index in 0..8 {
        let what = format!("DES combined S-box/P table SP{}", index + 1);
        all.push(signature("DES", BlockCipher, what, FIPS46, Pattern::U32(des_sp(index)), head));
    }
    const BLOWFISH: &str = "Schneier, Blowfish (FSE 1993): hexadecimal digits of pi";
    let (p_array, sboxes) = blowfish_state();
    all.push(signature("Blowfish", BlockCipher, "Blowfish P-array", BLOWFISH, Pattern::U32(p_array), None));
    for (index, sbox) in sboxes.into_iter().enumerate() {
        let what = format!("Blowfish S-box {}", index + 1);
        all.push(signature("Blowfish", BlockCipher, what, BLOWFISH, Pattern::U32(sbox), head));
    }
    const TWOFISH: &str = "Schneier et al., Twofish (1998), section 4.3.5";
    for index in 0..2 {
        let what = format!("Twofish permutation q{index}");
        all.push(signature("Twofish", BlockCipher, what, TWOFISH, Pattern::Bytes(twofish_q(index).to_vec()), head));
    }
    all
}

fn hashes() -> Vec<ConstantSignature> {
    use Kind::Hash;
    const FIPS180: &str = "FIPS 180-4";
    let head = Some(TABLE_HEAD);
    let md_state = vec![0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let mut sha1_state = md_state.clone();
    sha1_state.push(0xc3d2_e1f0);
    let ripemd = "Dobbertin, Bosselaers, Preneel, RIPEMD-160 (1996)";
    vec![
        signature("MD5 / MD4", Hash, "MD4/MD5 initial state", "RFC 1321; RFC 1320", Pattern::U32(md_state), None),
        signature("MD5", Hash, "MD5 sine table T", "RFC 1321 section 3.4", Pattern::U32(md5_t()), head),
        signature("SHA-1 / RIPEMD-160", Hash, "SHA-1 initial hash value", FIPS180, Pattern::U32(sha1_state), None),
        signature("SHA-1", Hash, "SHA-1 round constants", FIPS180, Pattern::U32(sha1_k()), None),
        signature("SHA-256", Hash, "SHA-256 round constants K", FIPS180, Pattern::U32(sha256_k()), head),
        signature("SHA-256 / BLAKE2s", Hash, "SHA-256 initial hash value", FIPS180, Pattern::U32(sha256_iv()), None),
        signature("SHA-224", Hash, "SHA-224 initial hash value", FIPS180, Pattern::U32(sha224_iv()), None),
        signature("SHA-512", Hash, "SHA-512 round constants K", FIPS180, Pattern::U64(sha512_k()), head),
        signature("SHA-512 / BLAKE2b", Hash, "SHA-512 initial hash value", FIPS180, Pattern::U64(sha512_iv()), None),
        signature("SHA-384", Hash, "SHA-384 initial hash value", FIPS180, Pattern::U64(sha384_iv()), None),
        signature("RIPEMD-160", Hash, "RIPEMD-160 left-line constants", ripemd, Pattern::U32(ripemd160_k(false)), None),
        signature("RIPEMD-160", Hash, "RIPEMD-160 right-line constants", ripemd, Pattern::U32(ripemd160_k(true)), None),
        signature(
            "SHA-3 / Keccak",
            Hash,
            "Keccak-f[1600] round constants",
            "FIPS 202 section 3.2.5",
            Pattern::U64(keccak_round_constants()),
            head,
        ),
    ]
}

fn other_primitives() -> Vec<ConstantSignature> {
    const CHACHA: &str = "RFC 8439 section 2.3; Bernstein, Salsa20 specification";
    const GCM: &str = "NIST SP 800-38D section 6.3 (reduction by R = 0xE1 || 0^120)";
    let ghash = ghash_rem_4bit();
    let packed: Vec<u64> = ghash.iter().map(|&value| u64::from(value) << 48).collect();
    vec![
        signature(
            "ChaCha / Salsa20",
            Kind::StreamCipher,
            "\"expand 32-byte k\" constant",
            CHACHA,
            Pattern::Text(b"expand 32-byte k".to_vec()),
            None,
        ),
        signature(
            "ChaCha / Salsa20",
            Kind::StreamCipher,
            "\"expand 16-byte k\" constant",
            CHACHA,
            Pattern::Text(b"expand 16-byte k".to_vec()),
            None,
        ),
        signature("AES-GCM", Kind::Mac, "GHASH 4-bit reduction table (16-bit)", GCM, Pattern::U16(ghash.clone()), None),
        signature("AES-GCM", Kind::Mac, "GHASH 4-bit reduction table (64-bit)", GCM, Pattern::U64(widen(&ghash)), None),
        signature("AES-GCM", Kind::Mac, "GHASH 4-bit reduction table (packed high)", GCM, Pattern::U64(packed), None),
    ]
}

fn checksums_and_formats() -> Vec<ConstantSignature> {
    use Kind::{Checksum, Compression, Encoding};
    let head = Some(TABLE_HEAD);
    let narrow = |table: Vec<u64>| table.into_iter().map(|value| value as u32).collect::<Vec<_>>();
    let narrow16 = |table: Vec<u64>| table.into_iter().map(|value| value as u16).collect::<Vec<_>>();
    const CRC: &str = "Williams, A Painless Guide to CRC Error Detection Algorithms; table from the polynomial";
    const DEFLATE: &str = "RFC 1951 section 3.2.5";
    let lengths = deflate_length_base();
    let distances = deflate_distance_base();
    let to16 = |values: &[u32]| values.iter().map(|&value| value as u16).collect::<Vec<_>>();
    let order = DEFLATE_CODE_LENGTH_ORDER;
    vec![
        signature(
            "CRC-32",
            Checksum,
            "CRC-32 table (reflected 0xEDB88320)",
            "ISO-HDLC / IEEE 802.3 polynomial; RFC 1952",
            Pattern::U32(narrow(crc_table_reflected(0xedb8_8320))),
            head,
        ),
        signature(
            "CRC-32C",
            Checksum,
            "CRC-32C table (reflected 0x82F63B78)",
            "Castagnoli polynomial; RFC 3720",
            Pattern::U32(narrow(crc_table_reflected(0x82f6_3b78))),
            head,
        ),
        signature(
            "CRC-32",
            Checksum,
            "CRC-32 table (MSB-first 0x04C11DB7, bzip2/MPEG-2)",
            CRC,
            Pattern::U32(narrow(crc_table_msb_first(0x04c1_1db7, 32))),
            head,
        ),
        signature(
            "CRC-16",
            Checksum,
            "CRC-16/ARC table (reflected 0xA001)",
            CRC,
            Pattern::U16(narrow16(crc_table_reflected(0xa001))),
            head,
        ),
        signature(
            "CRC-16",
            Checksum,
            "CRC-16/CCITT table (MSB-first 0x1021)",
            "ITU-T V.41 polynomial",
            Pattern::U16(narrow16(crc_table_msb_first(0x1021, 16))),
            head,
        ),
        signature(
            "CRC-64",
            Checksum,
            "CRC-64/XZ table (reflected 0xC96C5795D7870F42)",
            "ECMA-182 polynomial; XZ file format",
            Pattern::U64(crc_table_reflected(0xc96c_5795_d787_0f42)),
            head,
        ),
        signature("Deflate", Compression, "Deflate length base (16-bit)", DEFLATE, Pattern::U16(to16(&lengths)), None),
        signature("Deflate", Compression, "Deflate length base (32-bit)", DEFLATE, Pattern::U32(lengths), None),
        signature(
            "Deflate",
            Compression,
            "Deflate distance base (16-bit)",
            DEFLATE,
            Pattern::U16(to16(&distances)),
            None,
        ),
        signature("Deflate", Compression, "Deflate distance base (32-bit)", DEFLATE, Pattern::U32(distances), None),
        signature(
            "Deflate",
            Compression,
            "Deflate code length order (8-bit)",
            "RFC 1951 section 3.2.7",
            Pattern::Bytes(order.to_vec()),
            None,
        ),
        signature(
            "Deflate",
            Compression,
            "Deflate code length order (16-bit)",
            "RFC 1951 section 3.2.7",
            Pattern::U16(order.map(u16::from).to_vec()),
            None,
        ),
        signature(
            "Base64",
            Encoding,
            "Base64 alphabet",
            "RFC 4648 section 4",
            Pattern::Bytes(base64_alphabet(false)),
            None,
        ),
        signature(
            "Base64",
            Encoding,
            "Base64url alphabet",
            "RFC 4648 section 5",
            Pattern::Bytes(base64_alphabet(true)),
            None,
        ),
        signature("Base32", Encoding, "Base32 alphabet", "RFC 4648 section 6", Pattern::Bytes(base32_alphabet()), None),
    ]
}

fn curves() -> Vec<ConstantSignature> {
    const P256: &str = "FIPS 186-4 appendix D.1.2.3; SEC 2 secp256r1";
    const K256: &str = "SEC 2 section 2.4.1 secp256k1";
    const ED25519: &str = "RFC 8032 section 5.1; RFC 7748";
    let curve = |algorithm, what, source, value: &str| {
        signature(algorithm, Kind::PublicKey, what, source, Pattern::BigInt(hex(value)), None)
    };
    // The field primes (P-256's 2^256 - 2^224 + 2^192 + 2^96 - 1, secp256k1's 2^256 - 2^32 - 977,
    // 2^255 - 19) are mostly 0xff and 0x00 bytes and fail the distinct-byte guard, so they are not bundled.
    vec![
        curve("P-256", "P-256 coefficient b", P256, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
        curve("P-256", "P-256 base point x", P256, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        curve("P-256", "P-256 base point y", P256, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        curve("P-256", "P-256 group order n", P256, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
        curve(
            "secp256k1",
            "secp256k1 base point x",
            K256,
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
        curve(
            "secp256k1",
            "secp256k1 base point y",
            K256,
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        ),
        curve(
            "secp256k1",
            "secp256k1 group order n",
            K256,
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        ),
        curve(
            "Ed25519",
            "Ed25519 curve constant d",
            ED25519,
            "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
        ),
        curve(
            "Ed25519",
            "Ed25519 base point x",
            ED25519,
            "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",
        ),
        curve(
            "Ed25519",
            "sqrt(-1) mod 2^255-19",
            ED25519,
            "2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0",
        ),
    ]
}
