//! A FindCrypt-style scanner for the constant tables that cryptographic, checksum, compression and encoding
//! algorithms embed: S-boxes, round constants, initial hash values, CRC tables, alphabets and curve parameters.
//!
//! A hit is evidence that a binary contains a constant, not proof that the algorithm runs: the table may be dead
//! code, part of a library that is linked but unused, or (rarely) a coincidence. Constants that compilers fold
//! into instruction immediates instead of storing contiguously are not found, and algorithms with no
//! distinctive constant table cannot be detected this way at all. RC4, for example, builds its state from the
//! key at run time and has nothing to find; the same holds for Adler-32 (its modulus 65521 is a lone
//! immediate), HMAC (bytes 0x36 and 0x5c), TEA (the 4-byte delta) and Poly1305 (a low-entropy clamp mask).
//!
//! The bundled database is our own authoring from the published specifications; most of its tables are computed
//! from their definitions in [`generate`] and checked against the specifications' values by tests.

mod bundled;
pub mod generate;
mod math;
mod user;

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use rampage_loaders::Binary;
use serde::Serialize;

pub use user::{MAX_USER_CONSTANT_BYTES, MAX_USER_CONSTANTS, UserConstants};

/// The fewest bytes a signature may require; shorter runs recur by chance in large images.
pub const MIN_PATTERN_LEN: usize = 16;
/// A signature's required prefix must contain this many distinct byte values, or else
/// [`MIN_DISTINCT_WINDOWS`] distinct 4-byte windows. This rejects runs such as `ff ff ff ... 00 00 01` that look
/// long but carry little information, while admitting sparse word tables (DES SP tables use few byte values,
/// yet their 64 words form many distinct combinations).
pub const MIN_DISTINCT_BYTES: usize = 8;
pub const MIN_DISTINCT_WINDOWS: usize = 32;
/// The most hits one scan returns; a hostile or degenerate image cannot make the result unbounded.
pub const MAX_HITS: usize = 4096;

const ANCHOR_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    BlockCipher,
    StreamCipher,
    Hash,
    Mac,
    Checksum,
    Compression,
    Encoding,
    PublicKey,
}

/// The byte order a word table was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    Little,
    Big,
}

/// The values a signature looks for. Word tables match both their little- and big-endian layouts; a big integer
/// matches as big-endian bytes and fully reversed (the layout of little-endian limbs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Pattern {
    Bytes(Vec<u8>),
    U16(Vec<u16>),
    U32(Vec<u32>),
    U64(Vec<u64>),
    BigInt(Vec<u8>),
    /// Text that code keeps either as a string or as 32-bit words loaded little-endian, such as ChaCha's
    /// "expand 32-byte k". The string itself has no byte order; the words stored big-endian (each 4-byte group
    /// reversed) report [`Endian::Big`]. The length must be a multiple of 4.
    Text(Vec<u8>),
}

impl Pattern {
    fn forms(&self) -> Vec<(Vec<u8>, Option<Endian>)> {
        let (little, big): (Vec<u8>, Vec<u8>) = match self {
            Self::Bytes(bytes) => return vec![(bytes.clone(), None)],
            Self::Text(text) => {
                let swapped = text.chunks(4).flat_map(|word| word.iter().rev().copied()).collect();
                return vec![(text.clone(), None), (swapped, Some(Endian::Big))];
            }
            Self::U16(values) => (
                values.iter().flat_map(|value| value.to_le_bytes()).collect(),
                values.iter().flat_map(|value| value.to_be_bytes()).collect(),
            ),
            Self::U32(values) => (
                values.iter().flat_map(|value| value.to_le_bytes()).collect(),
                values.iter().flat_map(|value| value.to_be_bytes()).collect(),
            ),
            Self::U64(values) => (
                values.iter().flat_map(|value| value.to_le_bytes()).collect(),
                values.iter().flat_map(|value| value.to_be_bytes()).collect(),
            ),
            Self::BigInt(bytes) => (bytes.iter().rev().copied().collect(), bytes.clone()),
        };
        if little == big {
            return vec![(little, Some(Endian::Little))];
        }
        vec![(little, Some(Endian::Little)), (big, Some(Endian::Big))]
    }

    pub fn byte_len(&self) -> usize {
        match self {
            Self::Bytes(bytes) | Self::BigInt(bytes) | Self::Text(bytes) => bytes.len(),
            Self::U16(values) => 2 * values.len(),
            Self::U32(values) => 4 * values.len(),
            Self::U64(values) => 8 * values.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConstantSignature {
    pub algorithm: Cow<'static, str>,
    pub kind: Kind,
    /// Which constant this is, such as "AES forward S-box".
    pub what: Cow<'static, str>,
    /// The specification the values come from.
    pub source: Cow<'static, str>,
    pub pattern: Pattern,
    /// How many leading bytes of the pattern must match; less than the pattern's length admits a hit on a
    /// table that is truncated, split, or stored with only its head intact.
    pub min_len: usize,
    /// The one byte order a word table or big integer is looked for in; `None` looks for both.
    pub byte_order: Option<Endian>,
}

impl ConstantSignature {
    /// Checks the information guards every signature must pass: [`MIN_PATTERN_LEN`] required bytes, enough
    /// distinct values in them, and a byte order the pattern can take.
    pub fn validate(&self) -> Result<(), InvalidSignature> {
        validate(self, &self.layouts())
    }

    /// The byte layouts searched for, restricted to [`ConstantSignature::byte_order`] when set.
    fn layouts(&self) -> Vec<(Vec<u8>, Option<Endian>)> {
        let mut layouts = self.pattern.forms();
        if let Some(order) = self.byte_order {
            layouts.retain(|(_, endian)| *endian == Some(order));
        }
        layouts
    }
}

#[derive(Debug, thiserror::Error)]
#[error("signature {what:?}: {reason}")]
pub struct InvalidSignature {
    pub what: String,
    pub reason: String,
}

/// One byte layout of a signature, indexed by a 4-byte window inside its required prefix.
#[derive(Debug)]
struct Form {
    signature: usize,
    bytes: Vec<u8>,
    endian: Option<Endian>,
    anchor: usize,
}

#[derive(Debug)]
pub struct ConstantDb {
    signatures: Vec<ConstantSignature>,
    forms: Vec<Form>,
    index: HashMap<[u8; ANCHOR_LEN], Vec<usize>>,
    /// One bit per possible first two anchor bytes, so most positions are rejected without hashing.
    prefilter: Vec<u64>,
}

impl ConstantDb {
    pub fn new(signatures: Vec<ConstantSignature>) -> Result<Self, InvalidSignature> {
        for signature in &signatures {
            signature.validate()?;
        }
        Ok(Self::index(signatures))
    }

    /// The bundled database with user constants (from data packs) added; their names are distinct from the
    /// bundled ones, so a hit's `what` tells which it came from.
    pub fn bundled_with(user: &[&UserConstants]) -> Self {
        let mut signatures = Self::bundled().signatures.clone();
        signatures.extend(user.iter().flat_map(|constants| constants.signatures().iter().cloned()));
        Self::index(signatures)
    }

    /// Indexes signatures already validated.
    fn index(signatures: Vec<ConstantSignature>) -> Self {
        let mut forms = Vec::new();
        for (index, signature) in signatures.iter().enumerate() {
            for (bytes, endian) in signature.layouts() {
                let anchor = best_anchor(&bytes[..signature.min_len]);
                forms.push(Form { signature: index, bytes, endian, anchor });
            }
        }
        let mut index: HashMap<[u8; ANCHOR_LEN], Vec<usize>> = HashMap::new();
        let mut prefilter = vec![0u64; 1 << 10];
        for (position, form) in forms.iter().enumerate() {
            let key: [u8; ANCHOR_LEN] = form.bytes[form.anchor..form.anchor + ANCHOR_LEN].try_into().expect("anchor");
            index.entry(key).or_default().push(position);
            let pair = usize::from(u16::from_le_bytes([key[0], key[1]]));
            prefilter[pair >> 6] |= 1 << (pair & 63);
        }
        Self { signatures, forms, index, prefilter }
    }

    /// The database shipped with rampage.
    pub fn bundled() -> &'static Self {
        static DB: OnceLock<ConstantDb> = OnceLock::new();
        DB.get_or_init(|| Self::new(bundled::signatures()).expect("bundled signatures are valid"))
    }

    pub fn signatures(&self) -> &[ConstantSignature] {
        &self.signatures
    }
}

fn validate(signature: &ConstantSignature, layouts: &[(Vec<u8>, Option<Endian>)]) -> Result<(), InvalidSignature> {
    let fail = |reason: String| Err(InvalidSignature { what: signature.what.to_string(), reason });
    let len = signature.pattern.byte_len();
    if layouts.is_empty() {
        let order = signature.byte_order.map_or("any", |order| if order == Endian::Little { "little" } else { "big" });
        return fail(format!("the pattern has no {order}-endian layout"));
    }
    if signature.min_len < MIN_PATTERN_LEN {
        return fail(format!("min_len {} is below {MIN_PATTERN_LEN}", signature.min_len));
    }
    if signature.min_len > len {
        return fail(format!("min_len {} exceeds the pattern's {len} bytes", signature.min_len));
    }
    if matches!(signature.pattern, Pattern::Text(_)) && !len.is_multiple_of(4) {
        return fail(format!("text pattern of {len} bytes does not split into 32-bit words"));
    }
    for (bytes, _) in layouts {
        let prefix = &bytes[..signature.min_len];
        let mut seen = [false; 256];
        prefix.iter().for_each(|&byte| seen[usize::from(byte)] = true);
        let distinct = seen.iter().filter(|&&present| present).count();
        let windows: HashSet<&[u8]> = prefix.windows(ANCHOR_LEN).collect();
        if distinct < MIN_DISTINCT_BYTES && windows.len() < MIN_DISTINCT_WINDOWS {
            return fail(format!(
                "required prefix has only {distinct} distinct byte values and {} distinct 4-byte windows",
                windows.len()
            ));
        }
    }
    Ok(())
}

/// The window with the most distinct bytes, so that runs of zeros (a CRC table's first entry) do not make every
/// zero-filled region a candidate.
fn best_anchor(prefix: &[u8]) -> usize {
    let distinct = |window: &[u8]| (0..window.len()).filter(|&i| !window[..i].contains(&window[i])).count();
    let mut best = 0;
    for (offset, window) in prefix.windows(ANCHOR_LEN).enumerate() {
        if distinct(window) > distinct(&prefix[best..best + ANCHOR_LEN]) {
            best = offset;
        }
    }
    best
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConstantHit {
    pub algorithm: Cow<'static, str>,
    pub kind: Kind,
    pub what: Cow<'static, str>,
    /// The hit's virtual address, or its offset within [`ConstantHit::section`] when that is set.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    /// The section holding the hit, set only for relocatable objects: all their sections start at address 0, so
    /// an address alone cannot tell hits in different sections apart.
    pub section: Option<String>,
    /// The byte order of a word table or big integer; `None` for byte strings.
    pub endian: Option<Endian>,
    /// How many bytes matched: the whole pattern, or a prefix at least `min_len` long.
    pub length: usize,
    pub complete: bool,
}

/// The hits of one scan, and whether [`MAX_HITS`] cut it short: a single buffer stops being searched at the cap,
/// and of the hits pooled from several segments only the lowest-addressed [`MAX_HITS`] are kept.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ScanReport {
    pub hits: Vec<ConstantHit>,
    pub truncated: bool,
}

/// Finds every signature in `bytes`, which are mapped at `base`. Returns at most [`MAX_HITS`] hits, ordered by
/// address. When two hits start at the same place in the same byte order, only the longer is kept: the
/// MD5 initial state is a prefix of SHA-1's, and naming both would hide the more specific answer.
pub fn scan(bytes: &[u8], base: u64, db: &ConstantDb) -> Vec<ConstantHit> {
    scan_report(bytes, base, db).hits
}

/// [`scan`], also reporting whether the hit cap was reached.
pub fn scan_report(bytes: &[u8], base: u64, db: &ConstantDb) -> ScanReport {
    let mut hits = Vec::new();
    for position in 0..bytes.len().saturating_sub(ANCHOR_LEN - 1) {
        // Checked only between positions: stopping among one position's candidates could keep a short prefix
        // match and drop the longer one that would have suppressed it.
        if hits.len() >= MAX_HITS {
            return finish(hits, true);
        }
        let pair = usize::from(u16::from_le_bytes([bytes[position], bytes[position + 1]]));
        if db.prefilter[pair >> 6] & 1 << (pair & 63) == 0 {
            continue;
        }
        let key: [u8; ANCHOR_LEN] = bytes[position..position + ANCHOR_LEN].try_into().expect("window");
        let Some(candidates) = db.index.get(&key) else { continue };
        for &candidate in candidates {
            let form = &db.forms[candidate];
            let Some(start) = position.checked_sub(form.anchor) else { continue };
            let length = bytes[start..].iter().zip(&form.bytes).take_while(|(a, b)| a == b).count();
            let signature = &db.signatures[form.signature];
            if length < signature.min_len {
                continue;
            }
            hits.push(ConstantHit {
                algorithm: signature.algorithm.clone(),
                kind: signature.kind,
                what: signature.what.clone(),
                address: base.wrapping_add(start as u64),
                section: None,
                endian: form.endian,
                length,
                complete: length == form.bytes.len(),
            });
        }
    }
    finish(hits, false)
}

fn finish(mut hits: Vec<ConstantHit>, truncated: bool) -> ScanReport {
    // Longest first within each start and byte order, so each group's first hit carries the length to keep.
    hits.sort_by(|a, b| (a.address, a.endian, b.length, &a.what).cmp(&(b.address, b.endian, a.length, &b.what)));
    // Overlapping segments report the same hit twice.
    hits.dedup();
    let hits = hits
        .chunk_by(|a, b| (a.address, a.endian) == (b.address, b.endian))
        .flat_map(|group| group.iter().take_while(|hit| hit.length == group[0].length).cloned())
        .collect();
    cap(hits, truncated)
}

fn cap(mut hits: Vec<ConstantHit>, truncated: bool) -> ScanReport {
    let truncated = truncated || hits.len() > MAX_HITS;
    hits.truncate(MAX_HITS);
    ScanReport { hits, truncated }
}

/// Scans the file-backed bytes of every readable segment at its virtual address. Images without segments
/// (relocatable objects) are scanned section by section instead, in section order, each hit naming its section
/// and giving its offset within it.
pub fn scan_binary(binary: &Binary, db: &ConstantDb) -> Vec<ConstantHit> {
    scan_binary_report(binary, db).hits
}

/// [`scan_binary`], also reporting whether the hit cap was reached.
pub fn scan_binary_report(binary: &Binary, db: &ConstantDb) -> ScanReport {
    let mut hits = Vec::new();
    let mut truncated = false;
    let mut add = |report: ScanReport| {
        truncated |= report.truncated;
        report.hits
    };
    if binary.segments.is_empty() {
        // Sections are finished one by one rather than pooled: they share address 0, so pooling would let a hit
        // in one section suppress, or deduplicate, a different hit in another.
        for section in &binary.sections {
            if let Some(bytes) = binary.section_file_bytes(section) {
                let name = Some(section.name.clone());
                let found = add(scan_report(bytes, 0, db));
                hits.extend(found.into_iter().map(|hit| ConstantHit { section: name.clone(), ..hit }));
            }
        }
        return cap(hits, truncated);
    }
    for segment in binary.segments.iter().filter(|segment| segment.perms.read && segment.file_size > 0) {
        if let Some(bytes) = binary.read_to_segment_end(segment.address) {
            hits.extend(add(scan_report(bytes, segment.address, db)));
        }
    }
    finish(hits, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
    }

    /// Deterministic noise (xorshift64), so a failure reproduces.
    fn noise(len: usize, mut state: u64) -> Vec<u8> {
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    fn le(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn be(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_be_bytes()).collect()
    }

    fn summary(hits: &[ConstantHit]) -> Vec<(u64, &str, Option<Endian>, usize, bool)> {
        hits.iter().map(|hit| (hit.address, &*hit.what, hit.endian, hit.length, hit.complete)).collect()
    }

    #[test]
    fn bundled_database_is_valid_with_unique_names() {
        let db = ConstantDb::bundled();
        let names: HashSet<_> = db.signatures().iter().map(|signature| &signature.what).collect();
        assert_eq!(names.len(), db.signatures().len());
        assert!(db.signatures().len() >= 60, "{}", db.signatures().len());
    }

    #[test]
    fn finds_a_word_table_in_both_byte_orders() {
        let k = generate::sha256_k();
        let mut buffer = noise(4096, 1);
        buffer[101..101 + 256].copy_from_slice(&le(&k));
        buffer[2003..2003 + 256].copy_from_slice(&be(&k));
        let hits = scan(&buffer, 0x40_0000, ConstantDb::bundled());
        let what = "SHA-256 round constants K";
        assert_eq!(
            summary(&hits),
            [(0x40_0065, what, Some(Endian::Little), 256, true), (0x40_07d3, what, Some(Endian::Big), 256, true)]
        );
    }

    #[test]
    fn finds_byte_tables_big_integers_and_truncated_heads() {
        let db = ConstantDb::bundled();
        let mut buffer = noise(2048, 2);
        buffer[10..266].copy_from_slice(&generate::aes_sbox());
        buffer[300..364].copy_from_slice(&generate::aes_inverse_sbox()[..64]);
        buffer[400..463].copy_from_slice(&generate::aes_inverse_sbox()[..63]);
        let gx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        let gx: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&gx[2 * i..2 * i + 2], 16).unwrap()).collect();
        buffer[600..632].copy_from_slice(&gx);
        buffer[700..732].copy_from_slice(&gx.iter().rev().copied().collect::<Vec<_>>());
        assert_eq!(
            summary(&scan(&buffer, 0, db)),
            [
                (10, "AES forward S-box", None, 256, true),
                (300, "AES inverse S-box", None, 64, false),
                (600, "P-256 base point x", Some(Endian::Big), 32, true),
                (700, "P-256 base point x", Some(Endian::Little), 32, true),
            ]
        );
    }

    #[test]
    fn a_longer_constant_hides_its_own_prefix() {
        let db = ConstantDb::bundled();
        let sha1 = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0];
        let mut buffer = noise(256, 3);
        buffer[16..36].copy_from_slice(&le(&sha1));
        buffer[100..116].copy_from_slice(&le(&sha1[..4]));
        assert_eq!(
            summary(&scan(&buffer, 0, db)),
            [
                (16, "SHA-1 initial hash value", Some(Endian::Little), 20, true),
                (100, "MD4/MD5 initial state", Some(Endian::Little), 16, true),
            ]
        );
    }

    #[test]
    fn noise_and_uniform_buffers_yield_nothing() {
        let db = ConstantDb::bundled();
        assert!(scan(&noise(1 << 22, 4), 0, db).is_empty());
        assert!(scan(&vec![0; 1 << 20], 0, db).is_empty());
        assert!(scan(&vec![0xff; 1 << 20], 0, db).is_empty());
        let ramp: Vec<u8> = (0..1 << 20).map(|i| i as u8).collect();
        assert!(scan(&ramp, 0, db).is_empty());
        assert!(scan(&[0x65, 0x78], 0, db).is_empty());
    }

    #[test]
    fn hits_are_capped() {
        let buffer = b"expand 32-byte k".repeat(MAX_HITS + 100);
        assert_eq!(scan(&buffer, 0, ConstantDb::bundled()).len(), MAX_HITS);
    }

    #[test]
    fn the_cap_never_splits_one_position_s_candidates() {
        // "short" is a prefix of "long" and is tried first. One lone "short" makes the raw count odd, so the cap
        // lands between a position's "short" and "long" candidates.
        let signature = |what: &'static str, len: u8| ConstantSignature {
            algorithm: "test".into(),
            kind: Kind::Hash,
            what: what.into(),
            source: "test".into(),
            pattern: Pattern::Bytes((0..len).collect()),
            min_len: usize::from(len),
            byte_order: None,
        };
        let db = ConstantDb::new(vec![signature("short", 16), signature("long", 24)]).unwrap();
        let mut buffer: Vec<u8> = (0..16).chain([0xee; 8]).collect();
        buffer.extend((0..24).cycle().take(24 * MAX_HITS));
        let report = scan_report(&buffer, 0, &db);
        assert!(report.truncated);
        assert_eq!(report.hits[0].what, "short");
        assert!(report.hits[1..].iter().all(|hit| hit.what == "long"), "{:?}", report.hits.last());
        assert!(!scan_report(&buffer[..100], 0, &db).truncated);
    }

    #[test]
    fn low_information_signatures_are_rejected() {
        let p256_prime = (0..32).map(|i| [0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1][i.min(7)]).collect();
        let signature = ConstantSignature {
            algorithm: "P-256".into(),
            kind: Kind::PublicKey,
            what: "P-256 prime".into(),
            source: "FIPS 186-4".into(),
            pattern: Pattern::BigInt(p256_prime),
            min_len: 32,
            byte_order: None,
        };
        assert!(ConstantDb::new(vec![signature.clone()]).is_err());
        let short = ConstantSignature { pattern: Pattern::Bytes((0..12).collect()), min_len: 12, ..signature };
        assert!(ConstantDb::new(vec![short]).is_err());
    }

    #[test]
    fn hits_serialize_with_hex_addresses() {
        let hits = scan(b"..expand 32-byte k..", 0x1000, ConstantDb::bundled());
        let json = serde_json::to_value(&hits).unwrap();
        assert_eq!(json[0]["address"], "0x1002");
        assert_eq!(json[0]["kind"], "stream_cipher");
        assert_eq!(json[0]["endian"], serde_json::Value::Null);
    }

    #[test]
    fn chacha_text_has_no_byte_order_but_its_big_endian_words_do() {
        let db = ConstantDb::bundled();
        let mut buffer = noise(128, 6);
        buffer[8..24].copy_from_slice(b"expand 32-byte k");
        buffer[64..80].copy_from_slice(b"apxe3 dnyb-2k et");
        let what = "\"expand 32-byte k\" constant";
        assert_eq!(
            summary(&scan(&buffer, 0, db)),
            [(8, what, None, 16, true), (64, what, Some(Endian::Big), 16, true)]
        );
    }

    #[test]
    fn go_runtime_carries_the_chacha_constant() {
        // Go's runtime seeds its random source with ChaCha8, whose generic code keeps the constant words.
        let binary = Binary::open(fixture("hello-go-arm64.elf")).unwrap();
        let hits = scan_binary(&binary, ConstantDb::bundled());
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].what, "\"expand 32-byte k\" constant");
        assert_eq!(binary.read(hits[0].address, 16), Some(&b"expand 32-byte k"[..]));
    }

    /// A minimal x86-64 ELF relocatable object holding the given `PROGBITS` sections, all at address 0.
    fn elf_object(sections: &[(&str, &[u8])]) -> Vec<u8> {
        let mut names = vec![0u8];
        let mut name_offsets = Vec::new();
        for (name, _) in sections.iter().copied().chain([(".shstrtab", &[][..])]) {
            name_offsets.push(names.len() as u32);
            names.extend_from_slice(name.as_bytes());
            names.push(0);
        }
        let mut file = vec![0u8; 64];
        let mut headers = vec![[0u8; 64]];
        let mut add = |file: &mut Vec<u8>, name: u32, kind: u32, bytes: &[u8]| {
            let mut header = [0u8; 64];
            header[0..4].copy_from_slice(&name.to_le_bytes());
            header[4..8].copy_from_slice(&kind.to_le_bytes());
            header[24..32].copy_from_slice(&(file.len() as u64).to_le_bytes());
            header[32..40].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
            header[48..56].copy_from_slice(&1u64.to_le_bytes());
            file.extend_from_slice(bytes);
            headers.push(header);
        };
        for ((_, bytes), &name) in sections.iter().zip(&name_offsets) {
            add(&mut file, name, 1, bytes);
        }
        add(&mut file, name_offsets[sections.len()], 3, &names);
        let section_headers = file.len() as u64;
        file.extend(headers.iter().flatten());
        file[..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        file[16..18].copy_from_slice(&1u16.to_le_bytes());
        file[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        file[20..24].copy_from_slice(&1u32.to_le_bytes());
        file[40..48].copy_from_slice(&section_headers.to_le_bytes());
        file[52..54].copy_from_slice(&64u16.to_le_bytes());
        file[58..60].copy_from_slice(&64u16.to_le_bytes());
        file[60..62].copy_from_slice(&(headers.len() as u16).to_le_bytes());
        file[62..64].copy_from_slice(&(sections.len() as u16 + 1).to_le_bytes());
        file
    }

    #[test]
    fn object_sections_at_address_zero_do_not_cancel_each_other() {
        let sha1 = le(&[0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0]);
        let mut text = noise(64, 5);
        text[8..28].copy_from_slice(&sha1);
        let object = elf_object(&[(".text", &text), (".rodata.md5", &sha1[..16]), (".rodata.sha1", &sha1)]);
        let path = std::env::temp_dir().join(format!("rampage-constants-{}.o", std::process::id()));
        std::fs::write(&path, object).unwrap();
        let binary = Binary::open(&path);
        std::fs::remove_file(&path).unwrap();
        let binary = binary.unwrap();
        assert!(binary.segments.is_empty());
        let hits = scan_binary(&binary, ConstantDb::bundled());
        let found: Vec<_> = hits.iter().map(|hit| (hit.section.as_deref(), hit.address, &*hit.what)).collect();
        assert_eq!(
            found,
            [
                (Some(".text"), 8, "SHA-1 initial hash value"),
                (Some(".rodata.md5"), 0, "MD4/MD5 initial state"),
                (Some(".rodata.sha1"), 0, "SHA-1 initial hash value"),
            ]
        );
    }

    #[test]
    fn plain_programs_yield_nothing() {
        for name in
            ["musl-static-x86_64.elf", "musl-static-aarch64.elf", "hello-x64.exe", "hello-x64.macho", "hello-x64.o"]
        {
            let binary = Binary::open(fixture(name)).unwrap();
            assert_eq!(scan_binary(&binary, ConstantDb::bundled()), [], "{name}");
        }
    }
}
