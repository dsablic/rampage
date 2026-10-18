//! Bounded, data-only persistence and collision-safe corpus composition.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};

use flate2::{Compression, GzBuilder, bufread::GzDecoder};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::{CURRENT_SCHEME, LEGACY_SCHEME, SignatureDb, add_unambiguous};

/// Limits apply to the compressed API only; ordinary JSON loading remains compatible.
const MAX_COMPRESSED_BYTES: usize = 64 * 1024 * 1024;
const MAX_JSON_BYTES: usize = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 1_000_000;
const MAX_NAME_BYTES: usize = 4096;

/// Stable error categories for bounded gzip database reads and writes.
#[derive(Debug, thiserror::Error)]
pub enum SignatureDbError {
    #[error("signature database limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// Includes malformed headers, checksum/length failures and truncated streams.
    #[error("invalid signature database gzip stream")]
    InvalidGzip,
    /// A second gzip member is trailing data too, not another database to accept.
    #[error("trailing data after signature database gzip member")]
    TrailingData,
    #[error("invalid signature database JSON")]
    InvalidJson,
    #[error("invalid signature database: {0}")]
    InvalidDatabase(&'static str),
    #[error("signature database compression failed")]
    CompressionFailed,
}

/// Corpus databases must describe the same architecture and hash scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CombineError {
    #[error("signature database architectures differ")]
    ArchitectureMismatch,
    #[error("signature database hash schemes differ")]
    SchemeMismatch,
}

impl SignatureDb {
    /// Reads exactly one gzip member containing a strict data-only database. Rejects trailing bytes,
    /// concatenated members, truncation and checksum failures without returning a partial database.
    /// Limits: 64 MiB compressed, 256 MiB JSON, one million total keys, 4096 UTF-8 bytes per name.
    /// Hashes must be 64 lowercase hexadecimal digits, fields must be known and keys unique.
    pub fn from_gzip(bytes: &[u8]) -> Result<Self, SignatureDbError> {
        let json = decode_gzip(bytes)?;
        preflight_json(&json)?;
        let strict: StrictDb = serde_json::from_slice(&json).map_err(|_| SignatureDbError::InvalidJson)?;
        let arch = strict.arch.parse().map_err(|_| SignatureDbError::InvalidDatabase("unknown architecture"))?;
        if strict.arch != format!("{arch}") {
            return Err(SignatureDbError::InvalidDatabase("noncanonical architecture"));
        }
        let mut db = Self::empty(arch, strict.scheme);
        db.entries = strict.entries;
        db.exact = strict.exact;
        db.calls = strict.calls;
        db.ambiguous = strict.ambiguous;
        db.ambiguous_exact = strict.ambiguous_exact;
        db.ambiguous_calls = strict.ambiguous_calls;
        db.validate_compressed()?;
        Ok(db)
    }

    /// Writes deterministic JSON (ordered maps/sets) in one gzip member with mtime zero and no filename.
    /// Uses the same schema and size limits as [`Self::from_gzip`]. In-memory fallback evidence is not saved.
    pub fn to_gzip(&self) -> Result<Vec<u8>, SignatureDbError> {
        self.validate_compressed()?;
        let mut json = BoundedWriter { bytes: Vec::new(), limit: MAX_JSON_BYTES, exceeded: false };
        if serde_json::to_writer(&mut json, self).is_err() {
            return Err(if json.exceeded {
                SignatureDbError::LimitExceeded("uncompressed bytes")
            } else {
                SignatureDbError::InvalidJson
            });
        }
        let output = BoundedWriter { bytes: Vec::new(), limit: MAX_COMPRESSED_BYTES, exceeded: false };
        let mut encoder = GzBuilder::new().mtime(0).operating_system(255).write(output, Compression::best());
        if encoder.write_all(&json.bytes).and_then(|_| encoder.try_finish()).is_err() {
            return Err(if encoder.get_ref().exceeded {
                SignatureDbError::LimitExceeded("compressed bytes")
            } else {
                SignatureDbError::CompressionFailed
            });
        }
        let output = encoder.finish().map_err(|_| SignatureDbError::CompressionFailed)?;
        Ok(output.bytes)
    }

    /// Collision-safe union for library corpora, unlike the user-priority overlay [`Self::merge`].
    /// Ambiguity is permanent in every key space. Architecture/scheme mismatches leave `self` unchanged.
    /// Retains available in-memory fallback evidence but cannot recover evidence omitted by serialization.
    pub fn combine(&mut self, other: &SignatureDb) -> Result<(), CombineError> {
        if self.arch != other.arch {
            return Err(CombineError::ArchitectureMismatch);
        }
        if self.scheme != other.scheme {
            return Err(CombineError::SchemeMismatch);
        }

        let mut incoming = other.clone();
        let mut ambiguous = self.ambiguous.union(&other.ambiguous).cloned().collect::<BTreeSet<_>>();
        for (key, name) in &self.entries {
            if other.entries.get(key).is_some_and(|other_name| other_name != name) {
                ambiguous.insert(key.clone());
            }
        }

        // Check latent fallback keys as well: a conflict discovered before a masked collision must
        // remain ambiguous even if that collision only occurs in a later combine.
        let mut exact_names = BTreeMap::new();
        let mut call_names = BTreeMap::new();
        let mut ambiguous_exact = self.ambiguous_exact.union(&other.ambiguous_exact).cloned().collect();
        let mut ambiguous_calls = self.ambiguous_calls.union(&other.ambiguous_calls).cloned().collect();
        for db in [&*self, other] {
            for (key, name) in &db.exact {
                add_unambiguous(&mut exact_names, &mut ambiguous_exact, key.clone(), name.clone());
            }
            for (key, name) in &db.calls {
                add_unambiguous(&mut call_names, &mut ambiguous_calls, key.clone(), name.clone());
            }
            for (hash, name) in &db.entries {
                for key in db.entry_exact.get(hash).into_iter().flatten() {
                    add_unambiguous(&mut exact_names, &mut ambiguous_exact, key.clone(), name.clone());
                }
                for key in db.entry_calls.get(hash).into_iter().flatten() {
                    add_unambiguous(&mut call_names, &mut ambiguous_calls, key.clone(), name.clone());
                }
            }
        }
        self.ambiguous_exact = ambiguous_exact;
        self.ambiguous_calls = ambiguous_calls;
        for hash in ambiguous {
            self.make_ambiguous(hash.clone());
            incoming.make_ambiguous(hash);
        }
        union_answers(&mut self.exact, &mut self.ambiguous_exact, &incoming.exact, &incoming.ambiguous_exact);
        union_answers(&mut self.calls, &mut self.ambiguous_calls, &incoming.calls, &incoming.ambiguous_calls);
        self.entries.extend(incoming.entries);
        for (hash, keys) in incoming.entry_exact {
            self.entry_exact.entry(hash).or_default().extend(keys);
        }
        for (hash, keys) in incoming.entry_calls {
            let stored = self.entry_calls.entry(hash).or_default();
            stored.extend(keys);
            stored.sort();
            stored.dedup();
        }
        Ok(())
    }

    /// Withholds existing answers contradicted by raw names in full native training-reference databases.
    /// Pass the complete reference set in ONE batch after corpus combination and before serialization. Every
    /// reference is checked against the intact candidate, including latent exact/callee evidence, before any
    /// rejected entry or cache is discarded. Splitting references across calls is not equivalent: discarded
    /// evidence is unavailable to later batches. Rebuild from the original combined candidate to add references.
    /// Use original producer names, not synthetic negative labels or held-out target truth. Reference names are
    /// evidence, not publisher authentication. Serialized references lack latent evidence; use native databases.
    /// Same-key different names and reference ambiguity reject an answer; same names or absent keys do not.
    /// No reference answer is imported. Conflicting exported and latent keys persist as tombstones through gzip
    /// reload and collision-safe [`Self::combine`]; uncontradicted qualified fallbacks remain available.
    /// Returns exported answer keys removed across masked, exact and callee maps, not unique functions or latent
    /// keys. All architecture/scheme checks precede mutation; an empty reference set leaves the candidate intact.
    pub fn reject_reference_conflicts_from<'a>(
        &mut self,
        references: impl IntoIterator<Item = &'a SignatureDb>,
    ) -> Result<usize, CombineError> {
        let references: Vec<_> = references.into_iter().collect();
        for reference in &references {
            if self.arch != reference.arch {
                return Err(CombineError::ArchitectureMismatch);
            }
            if self.scheme != reference.scheme {
                return Err(CombineError::SchemeMismatch);
            }
        }
        if references.is_empty() {
            return Ok(0);
        }
        let mut rejected = self.ambiguous.clone();
        let mut rejected_exact = self.ambiguous_exact.clone();
        let mut rejected_calls = self.ambiguous_calls.clone();
        for reference in references {
            let mut exact = reference.exact.clone();
            let mut calls = reference.calls.clone();
            let mut ambiguous_exact = reference.ambiguous_exact.clone();
            let mut ambiguous_calls = reference.ambiguous_calls.clone();
            for (hash, name) in &reference.entries {
                for key in reference.entry_exact.get(hash).into_iter().flatten() {
                    add_unambiguous(&mut exact, &mut ambiguous_exact, key.clone(), name.clone());
                }
                for key in reference.entry_calls.get(hash).into_iter().flatten() {
                    add_unambiguous(&mut calls, &mut ambiguous_calls, key.clone(), name.clone());
                }
            }
            collect_reference_conflicts(&self.entries, &mut rejected, &reference.entries, &reference.ambiguous);
            collect_reference_conflicts(&self.exact, &mut rejected_exact, &exact, &ambiguous_exact);
            collect_reference_conflicts(&self.calls, &mut rejected_calls, &calls, &ambiguous_calls);
            for (hash, keys) in &self.entry_exact {
                if let Some(name) = self.entries.get(hash) {
                    for key in keys {
                        if reference_conflicts(key, name, &exact, &ambiguous_exact) {
                            rejected_exact.insert(key.clone());
                        }
                    }
                }
            }
            for (hash, keys) in &self.entry_calls {
                if let Some(name) = self.entries.get(hash) {
                    for key in keys {
                        if reference_conflicts(key, name, &calls, &ambiguous_calls) {
                            rejected_calls.insert(key.clone());
                        }
                    }
                }
            }
        }
        let before = self.entries.len() + self.exact.len() + self.calls.len();
        self.ambiguous = rejected;
        self.ambiguous_exact = rejected_exact;
        self.ambiguous_calls = rejected_calls;
        self.entries.retain(|key, _| !self.ambiguous.contains(key));
        self.exact.retain(|key, _| !self.ambiguous_exact.contains(key));
        self.calls.retain(|key, _| !self.ambiguous_calls.contains(key));
        self.entry_exact.retain(|hash, keys| {
            keys.retain(|key| !self.ambiguous_exact.contains(key));
            self.entries.contains_key(hash) && !keys.is_empty()
        });
        self.entry_calls.retain(|hash, keys| {
            keys.retain(|key| !self.ambiguous_calls.contains(key));
            self.entries.contains_key(hash) && !keys.is_empty()
        });
        Ok(before - self.entries.len() - self.exact.len() - self.calls.len())
    }

    fn validate_compressed(&self) -> Result<(), SignatureDbError> {
        if ![LEGACY_SCHEME, CURRENT_SCHEME].contains(&self.scheme) {
            return Err(SignatureDbError::InvalidDatabase("unknown hash scheme"));
        }
        let total = self.entries.len()
            + self.exact.len()
            + self.calls.len()
            + self.ambiguous.len()
            + self.ambiguous_exact.len()
            + self.ambiguous_calls.len();
        if total > MAX_ENTRIES {
            return Err(SignatureDbError::LimitExceeded("entries"));
        }
        for (map, ambiguous) in [
            (&self.entries, &self.ambiguous),
            (&self.exact, &self.ambiguous_exact),
            (&self.calls, &self.ambiguous_calls),
        ] {
            if map.keys().chain(ambiguous).any(|key| !valid_hash(key)) {
                return Err(SignatureDbError::InvalidDatabase("noncanonical hash"));
            }
            if map.values().any(|name| !valid_name(name)) {
                return Err(SignatureDbError::InvalidDatabase("invalid function name"));
            }
            if map.keys().any(|key| ambiguous.contains(key)) {
                return Err(SignatureDbError::InvalidDatabase("ambiguous key also has an answer"));
            }
        }
        Ok(())
    }
}

fn reference_conflicts(
    key: &str,
    name: &str,
    reference: &BTreeMap<String, String>,
    ambiguous: &BTreeSet<String>,
) -> bool {
    ambiguous.contains(key) || reference.get(key).is_some_and(|raw_name| raw_name != name)
}

fn collect_reference_conflicts(
    answers: &BTreeMap<String, String>,
    rejected: &mut BTreeSet<String>,
    reference: &BTreeMap<String, String>,
    ambiguous: &BTreeSet<String>,
) {
    for (key, name) in answers {
        if reference_conflicts(key, name, reference, ambiguous) {
            rejected.insert(key.clone());
        }
    }
}

fn union_answers(
    answers: &mut BTreeMap<String, String>,
    ambiguous: &mut BTreeSet<String>,
    incoming: &BTreeMap<String, String>,
    incoming_ambiguous: &BTreeSet<String>,
) {
    ambiguous.extend(incoming_ambiguous.iter().cloned());
    answers.retain(|key, _| !ambiguous.contains(key));
    for (key, name) in incoming {
        add_unambiguous(answers, ambiguous, key.clone(), name.clone());
    }
}

pub(super) fn decode_gzip(bytes: &[u8]) -> Result<Vec<u8>, SignatureDbError> {
    decode_gzip_bounded(bytes, MAX_COMPRESSED_BYTES, MAX_JSON_BYTES)
}

fn decode_gzip_bounded(bytes: &[u8], compressed_limit: usize, json_limit: usize) -> Result<Vec<u8>, SignatureDbError> {
    if bytes.len() > compressed_limit {
        return Err(SignatureDbError::LimitExceeded("compressed bytes"));
    }
    let mut decoder = GzDecoder::new(bytes);
    let mut json = Vec::new();
    decoder.by_ref().take(json_limit as u64 + 1).read_to_end(&mut json).map_err(|_| SignatureDbError::InvalidGzip)?;
    if json.len() > json_limit {
        return Err(SignatureDbError::LimitExceeded("uncompressed bytes"));
    }
    if !decoder.into_inner().is_empty() {
        return Err(SignatureDbError::TrailingData);
    }
    Ok(json)
}

// Bound allocation-driving tokens before serde allocates decoded strings or tree nodes. An escaped
// Unicode scalar takes at most six raw bytes per UTF-8 byte. Structural validation stays with serde.
fn preflight_json(bytes: &[u8]) -> Result<(), SignatureDbError> {
    preflight_json_bounded(bytes, MAX_ENTRIES)
}

fn preflight_json_bounded(bytes: &[u8], entry_limit: usize) -> Result<(), SignatureDbError> {
    let mut string_start = None;
    let mut escaped = false;
    let mut strings = 0usize;
    let mut depth = 0usize;
    let mut previous = 0u8;
    let mut entries = 0usize;
    for (index, &byte) in bytes.iter().enumerate() {
        if let Some(start) = string_start {
            if index - start > MAX_NAME_BYTES * 6 {
                return Err(SignatureDbError::LimitExceeded("JSON string bytes"));
            }
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                string_start = None;
            }
        } else if byte == b'"' {
            strings += 1;
            if strings > entry_limit * 2 + 16 {
                return Err(SignatureDbError::LimitExceeded("JSON strings"));
            }
            // The schema is flat: at depth two a string is a map key or a set element,
            // except immediately after a colon, where it is a function name.
            if depth == 2 && previous != b':' {
                entries += 1;
                if entries > entry_limit {
                    return Err(SignatureDbError::LimitExceeded("entries"));
                }
            }
            string_start = Some(index + 1);
            previous = b'"';
        } else if !byte.is_ascii_whitespace() {
            match byte {
                b'{' | b'[' => depth = depth.saturating_add(1),
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
            previous = byte;
        }
    }
    Ok(())
}

fn valid_hash(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME_BYTES && !name.contains('\0')
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictDb {
    arch: String,
    #[serde(default = "crate::legacy_scheme")]
    scheme: u32,
    #[serde(deserialize_with = "hash_map")]
    entries: BTreeMap<String, String>,
    #[serde(default, deserialize_with = "hash_map")]
    exact: BTreeMap<String, String>,
    #[serde(default, deserialize_with = "hash_map")]
    calls: BTreeMap<String, String>,
    #[serde(default, deserialize_with = "hash_set")]
    ambiguous: BTreeSet<String>,
    #[serde(default, deserialize_with = "hash_set")]
    ambiguous_exact: BTreeSet<String>,
    #[serde(default, deserialize_with = "hash_set")]
    ambiguous_calls: BTreeSet<String>,
}

fn hash_map<'de, D: Deserializer<'de>>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error> {
    struct HashMapVisitor;
    impl<'de> Visitor<'de> for HashMapVisitor {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded map of canonical hashes to names")
        }

        fn visit_map<M: MapAccess<'de>>(self, mut access: M) -> Result<Self::Value, M::Error> {
            let mut map = BTreeMap::new();
            while let Some(key) = access.next_key::<String>()? {
                if map.len() == MAX_ENTRIES || !valid_hash(&key) || map.contains_key(&key) {
                    return Err(serde::de::Error::custom("invalid, duplicate or excessive signature key"));
                }
                let name = access.next_value::<String>()?;
                if !valid_name(&name) {
                    return Err(serde::de::Error::custom("invalid signature name"));
                }
                map.insert(key, name);
            }
            Ok(map)
        }
    }
    deserializer.deserialize_map(HashMapVisitor)
}

fn hash_set<'de, D: Deserializer<'de>>(deserializer: D) -> Result<BTreeSet<String>, D::Error> {
    struct HashSetVisitor;
    impl<'de> Visitor<'de> for HashSetVisitor {
        type Value = BTreeSet<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded set of canonical hashes")
        }

        fn visit_seq<S: SeqAccess<'de>>(self, mut access: S) -> Result<Self::Value, S::Error> {
            let mut set = BTreeSet::new();
            while let Some(key) = access.next_element::<String>()? {
                if set.len() == MAX_ENTRIES || !valid_hash(&key) || !set.insert(key) {
                    return Err(serde::de::Error::custom("invalid, duplicate or excessive ambiguous key"));
                }
            }
            Ok(set)
        }
    }
    deserializer.deserialize_seq(HashSetVisitor)
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            self.exceeded = true;
            return Err(std::io::Error::other("signature database byte limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rampage_arch::Arch;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzBuilder::new().mtime(0).write(Vec::new(), Compression::best());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn key(byte: u8) -> String {
        crate::hex(&[byte; 32])
    }

    fn db() -> SignatureDb {
        SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME)
    }

    #[test]
    fn compressed_output_is_deterministic_and_preserves_all_serialized_evidence() {
        let mut first = db();
        first.add([2; 32], Some([12; 32]), Some([22; 32]), "second");
        first.add([1; 32], Some([11; 32]), Some([21; 32]), "first");
        first.add([1; 32], Some([13; 32]), Some([23; 32]), "conflict");
        let mut second = db();
        second.add([1; 32], Some([13; 32]), Some([23; 32]), "conflict");
        second.add([1; 32], Some([11; 32]), Some([21; 32]), "first");
        second.add([2; 32], Some([12; 32]), Some([22; 32]), "second");
        let output = first.to_gzip().unwrap();
        assert_eq!(output, second.to_gzip().unwrap());
        assert_eq!(&output[4..8], &[0; 4]);
        assert_eq!(decode_gzip(&output).unwrap(), first.to_json().as_bytes());
        let loaded = SignatureDb::from_gzip(&output).unwrap();
        assert_eq!(loaded.to_json(), first.to_json());
        assert!(loaded.entry_exact.is_empty());
        assert!(loaded.entry_calls.is_empty());
    }

    #[test]
    fn compressed_loading_preserves_native_architecture_context_and_confidence_gates() {
        let target = rampage_arch::Target::new(Arch::X86_64);
        let image = crate::MaskContext::new(std::iter::once(0x40_0000..0x50_0000));
        // mov rax, [0x401000]; add eax, 0x1234; xor eax, 0x22; ret.
        let body =
            [0x48, 0x8b, 0x04, 0x25, 0x00, 0x10, 0x40, 0x00, 0x05, 0x34, 0x12, 0x00, 0x00, 0x83, 0xf0, 0x22, 0xc3];
        let mut reference = db();
        let hash = crate::function_hash_in(&target, &image, &body, 0x1000).unwrap();
        reference.add(hash, crate::function_hash(&target, &body, 0x1000), None, "native-function");
        let loaded = SignatureDb::from_gzip(&reference.to_gzip().unwrap()).unwrap();
        assert_eq!(loaded.identify_in(&target, &image, &body, 0x1000), Some("native-function"));
        assert_eq!(loaded.identify(&target, &body, 0x1000), None);
        let wrong_arch = rampage_arch::Target::new(Arch::X86);
        assert_eq!(loaded.identify_in(&wrong_arch, &image, &body, 0x1000), None);
        assert_eq!(loaded.identify_in(&target, &image, &[0xc3], 0x1000), None);
    }

    #[test]
    fn gzip_requires_a_complete_single_member_and_valid_checksums() {
        let valid = db().to_gzip().unwrap();
        for end in 0..valid.len() {
            assert!(matches!(SignatureDb::from_gzip(&valid[..end]), Err(SignatureDbError::InvalidGzip)));
        }
        for offset in [valid.len() - 8, valid.len() - 4] {
            let mut corrupt = valid.clone();
            corrupt[offset] ^= 1;
            assert!(matches!(SignatureDb::from_gzip(&corrupt), Err(SignatureDbError::InvalidGzip)));
        }
        for suffix in [b"trailing".as_slice(), valid.as_slice(), &[0]] {
            let mut trailing = valid.clone();
            trailing.extend_from_slice(suffix);
            assert!(matches!(SignatureDb::from_gzip(&trailing), Err(SignatureDbError::TrailingData)));
        }
        assert!(matches!(SignatureDb::from_gzip(&gzip(b"")), Err(SignatureDbError::InvalidJson)));
        assert!(SignatureDb::from_gzip(&valid).unwrap().is_empty());
    }

    #[test]
    fn strict_compressed_schema_does_not_change_legacy_json_loading() {
        let hash = key(0xab);
        for json in [
            format!(r#"{{"arch":"x86_64","entries":{{"{}":"name"}}}}"#, hash.to_uppercase()),
            r#"{"arch":"x86_64","entries":{"not-a-hash":"name"}}"#.to_owned(),
            format!(r#"{{"arch":"x86_64","entries":{{"{hash}":""}}}}"#),
            format!(r#"{{"arch":"x86_64","entries":{{"{hash}":"a","{hash}":"b"}}}}"#),
            r#"{"arch":"x86_64","entries":{},"unknown":true}"#.to_owned(),
            r#"{"arch":"X86_64","entries":{}}"#.to_owned(),
            r#"{"arch":"amd64","entries":{}}"#.to_owned(),
        ] {
            assert!(SignatureDb::from_json(&json).is_ok(), "legacy JSON rejected {json}");
            assert!(SignatureDb::from_gzip(&gzip(json.as_bytes())).is_err(), "strict gzip accepted {json}");
        }
        for json in [
            r#"{"arch":"x86_64","scheme":99,"entries":{}}"#.to_owned(),
            r#"{"arch":"not-an-arch","entries":{}}"#.to_owned(),
            r#"{"arch":"x86_64"}"#.to_owned(),
            r#"{"arch":"x86_64","entries":{}} {}"#.to_owned(),
            format!(r#"{{"arch":"x86_64","entries":{{"{hash}":"a"}},"ambiguous":["{hash}"]}}"#),
            format!(r#"{{"arch":"x86_64","entries":{{}},"ambiguous":["{hash}","{hash}"]}}"#),
            format!(r#"{{"arch":"x86_64","entries":{{"{hash}":"{}"}}}}"#, "n".repeat(MAX_NAME_BYTES + 1)),
        ] {
            assert!(SignatureDb::from_gzip(&gzip(json.as_bytes())).is_err());
        }
        let legacy = SignatureDb::from_gzip(&gzip(br#"{"arch":"x86_64","entries":{}}"#)).unwrap();
        assert_eq!(legacy.scheme(), LEGACY_SCHEME);
    }

    #[test]
    fn compressed_and_expanded_byte_limits_are_enforced_before_parsing() {
        let bytes = gzip(&[b'a'; 1024]);
        assert!(matches!(
            decode_gzip_bounded(&bytes, bytes.len() - 1, 1024),
            Err(SignatureDbError::LimitExceeded("compressed bytes"))
        ));
        assert!(matches!(
            decode_gzip_bounded(&bytes, bytes.len(), 1023),
            Err(SignatureDbError::LimitExceeded("uncompressed bytes"))
        ));
        assert_eq!(decode_gzip_bounded(&bytes, bytes.len(), 1024).unwrap().len(), 1024);
        let oversized_token = format!("\"{}\"", "n".repeat(MAX_NAME_BYTES * 6 + 1));
        assert!(matches!(
            preflight_json(oversized_token.as_bytes()),
            Err(SignatureDbError::LimitExceeded("JSON string bytes"))
        ));
        let mut writer = BoundedWriter { bytes: Vec::new(), limit: 3, exceeded: false };
        writer.write_all(b"abc").unwrap();
        assert!(writer.write_all(b"d").is_err());
        assert_eq!(writer.bytes, b"abc");
    }

    #[test]
    fn entry_preflight_counts_all_key_spaces_but_not_names_or_escaped_delimiters() {
        let json = format!(
            r#"{{"arch":"x86_64","entries":{{"{}":"name,\"{{["}},"exact":{{"{}":"exact"}},"ambiguous_calls":["{}"]}}"#,
            key(1),
            key(2),
            key(3)
        );
        assert!(preflight_json_bounded(json.as_bytes(), 3).is_ok());
        assert!(matches!(preflight_json_bounded(json.as_bytes(), 2), Err(SignatureDbError::LimitExceeded("entries"))));
    }

    #[test]
    fn compressed_writer_rejects_invalid_in_memory_databases() {
        let mut invalid = db();
        invalid.entries.insert("AB".repeat(32), "name".into());
        assert!(matches!(invalid.to_gzip(), Err(SignatureDbError::InvalidDatabase("noncanonical hash"))));
        invalid.entries.clear();
        invalid.scheme = 999;
        assert!(matches!(invalid.to_gzip(), Err(SignatureDbError::InvalidDatabase("unknown hash scheme"))));
    }

    fn corpus_sources() -> [SignatureDb; 3] {
        let mut a = db();
        a.add([1; 32], Some([10; 32]), Some([20; 32]), "alpha");
        a.add([2; 32], Some([12; 32]), Some([22; 32]), "stable");
        a.exact.insert(key(30), "first".into());
        a.calls.insert(key(31), "first".into());
        let mut b = db();
        b.add([1; 32], Some([11; 32]), Some([21; 32]), "beta");
        b.add([3; 32], Some([12; 32]), Some([22; 32]), "latent-conflict");
        b.add([4; 32], Some([14; 32]), Some([24; 32]), "gamma");
        let mut c = db();
        c.add([1; 32], Some([10; 32]), Some([20; 32]), "alpha");
        c.add([4; 32], Some([15; 32]), Some([25; 32]), "delta");
        c.exact.insert(key(30), "second".into());
        c.calls.insert(key(31), "second".into());
        [a, b, c]
    }

    fn assert_same_evidence(left: &SignatureDb, right: &SignatureDb) {
        assert_eq!(left.to_json(), right.to_json());
        assert_eq!(left.entry_exact, right.entry_exact);
        assert_eq!(left.entry_calls, right.entry_calls);
    }

    #[test]
    fn corpus_union_is_order_independent_and_associative_for_every_permutation() {
        let sources = corpus_sources();
        let mut expected = db();
        for source in &sources {
            expected.combine(source).unwrap();
        }
        assert_eq!(expected.ambiguous, BTreeSet::from([key(1), key(4)]));
        assert!(expected.ambiguous_exact.contains(&key(12)));
        assert!(expected.ambiguous_exact.contains(&key(30)));
        assert!(expected.ambiguous_calls.contains(&key(22)));
        assert!(expected.ambiguous_calls.contains(&key(31)));
        assert_eq!(expected.exact.get(&key(10)).map(String::as_str), Some("alpha"));
        assert_eq!(expected.calls.get(&key(21)).map(String::as_str), Some("beta"));
        for [a, b, c] in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
            let mut left = sources[a].clone();
            left.combine(&sources[b]).unwrap();
            left.combine(&sources[c]).unwrap();
            let mut right = sources[b].clone();
            right.combine(&sources[c]).unwrap();
            let mut grouped = sources[a].clone();
            grouped.combine(&right).unwrap();
            assert_same_evidence(&left, &expected);
            assert_same_evidence(&grouped, &expected);
            left.combine(&left.clone()).unwrap();
            assert_same_evidence(&left, &expected);
        }
    }

    #[test]
    fn corpus_ambiguities_never_resurrect_but_user_overlay_still_wins() {
        let mut ambiguous = db();
        ambiguous.ambiguous.insert(key(1));
        ambiguous.ambiguous_exact.insert(key(2));
        ambiguous.ambiguous_calls.insert(key(3));
        let mut answer = db();
        answer.entries.insert(key(1), "answer".into());
        answer.exact.insert(key(2), "answer".into());
        answer.calls.insert(key(3), "answer".into());
        let mut first = ambiguous.clone();
        first.combine(&answer).unwrap();
        let mut second = answer.clone();
        second.combine(&ambiguous).unwrap();
        assert_same_evidence(&first, &second);
        first.combine(&answer).unwrap();
        assert!(first.is_empty());
        assert_same_evidence(&first, &ambiguous);

        ambiguous.merge(&answer);
        assert_eq!(ambiguous.to_json(), answer.to_json());
        let mut priority = answer.clone();
        let mut user = answer;
        user.entries.insert(key(1), "user-priority".into());
        priority.merge(&user);
        assert_eq!(priority.entries.get(&key(1)).map(String::as_str), Some("user-priority"));
    }

    #[test]
    fn combine_mismatches_are_atomic_including_ephemeral_evidence() {
        let mut current = corpus_sources()[0].clone();
        let before = current.clone();
        let mut other = db();
        other.arch = Arch::Aarch64;
        assert_eq!(current.combine(&other), Err(CombineError::ArchitectureMismatch));
        assert_same_evidence(&current, &before);
        other.arch = current.arch;
        other.scheme = LEGACY_SCHEME;
        assert_eq!(current.combine(&other), Err(CombineError::SchemeMismatch));
        assert_same_evidence(&current, &before);
    }

    #[test]
    fn combine_preserves_multiple_known_fallbacks_without_inventing_serialized_ones() {
        let mut a = db();
        a.add([1; 32], Some([10; 32]), Some([20; 32]), "alpha");
        let loaded = SignatureDb::from_json(&a.to_json()).unwrap();
        let mut b = db();
        b.add([1; 32], Some([11; 32]), Some([21; 32]), "alpha");
        let mut c = db();
        c.add([1; 32], Some([12; 32]), Some([22; 32]), "beta");
        a.combine(&b).unwrap();
        a.combine(&c).unwrap();
        for exact in [10, 11] {
            assert_eq!(a.exact.get(&key(exact)).map(String::as_str), Some("alpha"));
        }
        for call in [20, 21] {
            assert_eq!(a.calls.get(&key(call)).map(String::as_str), Some("alpha"));
        }
        let mut without_evidence = loaded;
        without_evidence.combine(&c).unwrap();
        assert!(!without_evidence.exact.contains_key(&key(10)));
        assert!(!without_evidence.calls.contains_key(&key(20)));
        assert_eq!(without_evidence.exact.get(&key(12)).map(String::as_str), Some("beta"));
    }

    #[test]
    fn retaining_owned_names_removes_negative_answers_without_erasing_collision_evidence() {
        let mut reference = db();
        reference.add([1; 32], Some([11; 32]), Some([21; 32]), "owned");
        reference.add([1; 32], Some([12; 32]), Some([22; 32]), "nonlibrary");
        reference.add([2; 32], Some([13; 32]), Some([23; 32]), "nonlibrary");
        reference.add([3; 32], Some([14; 32]), Some([24; 32]), "owned");
        reference.ambiguous_exact.insert(key(90));
        reference.ambiguous_calls.insert(key(91));
        let ambiguous = reference.ambiguous.clone();
        let ambiguous_exact = reference.ambiguous_exact.clone();
        let ambiguous_calls = reference.ambiguous_calls.clone();

        reference.retain_names(&BTreeSet::from(["owned".to_owned()]));

        assert!(!reference.entries.contains_key(&key(1)));
        assert!(!reference.entries.contains_key(&key(2)));
        assert!(!reference.exact.contains_key(&key(12)));
        assert!(!reference.calls.contains_key(&key(22)));
        assert!(!reference.entry_exact.contains_key(&key(2)));
        assert!(!reference.entry_calls.contains_key(&key(2)));
        assert_eq!(reference.entries.get(&key(3)).map(String::as_str), Some("owned"));
        assert_eq!(reference.exact.get(&key(11)).map(String::as_str), Some("owned"));
        assert_eq!(reference.calls.get(&key(21)).map(String::as_str), Some("owned"));
        assert_eq!(reference.entry_exact.get(&key(3)), Some(&BTreeSet::from([key(14)])));
        assert_eq!(reference.entry_calls.get(&key(3)), Some(&vec![key(24)]));
        assert_eq!(reference.ambiguous, ambiguous);
        assert_eq!(reference.ambiguous_exact, ambiguous_exact);
        assert_eq!(reference.ambiguous_calls, ambiguous_calls);

        let mut owned_again = db();
        owned_again.add([1; 32], Some([11; 32]), Some([21; 32]), "owned");
        reference.combine(&owned_again).unwrap();
        assert!(!reference.entries.contains_key(&key(1)));
        assert_eq!(reference.ambiguous, ambiguous);
        assert_eq!(reference.ambiguous_exact, ambiguous_exact);
        assert_eq!(reference.ambiguous_calls, ambiguous_calls);

        let mut explicit_overlay = reference.clone();
        explicit_overlay.merge(&owned_again);
        assert_eq!(explicit_overlay.entries.get(&key(1)).map(String::as_str), Some("owned"));

        reference.retain_names(&BTreeSet::new());
        assert!(reference.is_empty());
        assert!(reference.entry_exact.is_empty());
        assert!(reference.entry_calls.is_empty());
        assert_eq!(reference.ambiguous, ambiguous);
        assert_eq!(reference.ambiguous_exact, ambiguous_exact);
        assert_eq!(reference.ambiguous_calls, ambiguous_calls);
    }

    #[test]
    fn raw_reference_negatives_reject_later_exports_without_blacklisting_consistent_musl() {
        let mut reference = db();
        reference.add([1; 32], Some([11; 32]), Some([21; 32]), "malloc");
        reference.add([2; 32], Some([12; 32]), Some([22; 32]), "pairscont");
        reference.add([3; 32], Some([13; 32]), Some([23; 32]), "iter_auxlax");
        let before = reference.clone();
        let mut candidate = reference.clone();
        candidate.retain_names(&BTreeSet::from(["malloc".to_owned()]));
        let mut later = db();
        later.add([2; 32], Some([12; 32]), Some([22; 32]), "ZSTD_defaultCLevel");
        candidate.combine(&later).unwrap();
        assert_eq!(candidate.entries.get(&key(2)).map(String::as_str), Some("ZSTD_defaultCLevel"));

        assert_eq!(candidate.reject_reference_conflicts_from([&reference]), Ok(1));
        assert_same_evidence(&reference, &before);
        assert_eq!(candidate.entries.get(&key(1)).map(String::as_str), Some("malloc"));
        assert!(!candidate.entries.contains_key(&key(2)));
        assert!(!candidate.entries.contains_key(&key(3)));
        assert!(!candidate.ambiguous.contains(&key(1)));
        assert!(!candidate.ambiguous.contains(&key(3)));
        assert!(candidate.ambiguous.contains(&key(2)));
        assert!(!candidate.entry_exact.contains_key(&key(2)));
        assert!(!candidate.entry_calls.contains_key(&key(2)));

        let mut loaded = SignatureDb::from_gzip(&candidate.to_gzip().unwrap()).unwrap();
        loaded.combine(&later).unwrap();
        assert!(!loaded.entries.contains_key(&key(2)));
        assert!(!loaded.exact.contains_key(&key(12)));
        assert!(!loaded.calls.contains_key(&key(22)));
        assert_eq!(loaded.entries.get(&key(1)).map(String::as_str), Some("malloc"));
        assert_eq!(loaded.reject_reference_conflicts_from([&reference]), Ok(0));
    }

    #[test]
    fn raw_reference_filter_handles_all_key_spaces_and_never_imports_reference_names() {
        let mut candidate = db();
        let mut reference = db();
        for (answers, raw, tombstones, base) in [
            (&mut candidate.entries, &mut reference.entries, &mut reference.ambiguous, 0),
            (&mut candidate.exact, &mut reference.exact, &mut reference.ambiguous_exact, 10),
            (&mut candidate.calls, &mut reference.calls, &mut reference.ambiguous_calls, 20),
        ] {
            answers.insert(key(base + 1), "exported".into());
            raw.insert(key(base + 1), "local_function".into());
            answers.insert(key(base + 2), "consistent".into());
            raw.insert(key(base + 2), "consistent".into());
            answers.insert(key(base + 3), "unseen".into());
            answers.insert(key(base + 4), "ambiguous".into());
            tombstones.insert(key(base + 4));
            raw.insert(key(base + 5), "reference_only".into());
        }
        let original = candidate.clone();
        assert_eq!(candidate.reject_reference_conflicts_from([&reference]), Ok(6));
        for (answers, tombstones, base) in [
            (&candidate.entries, &candidate.ambiguous, 0),
            (&candidate.exact, &candidate.ambiguous_exact, 10),
            (&candidate.calls, &candidate.ambiguous_calls, 20),
        ] {
            assert_eq!(answers.get(&key(base + 2)).map(String::as_str), Some("consistent"));
            assert_eq!(answers.get(&key(base + 3)).map(String::as_str), Some("unseen"));
            assert_eq!(answers.len(), 2);
            assert_eq!(tombstones, &BTreeSet::from([key(base + 1), key(base + 4)]));
        }
        let mut loaded = SignatureDb::from_gzip(&candidate.to_gzip().unwrap()).unwrap();
        loaded.combine(&original).unwrap();
        assert_eq!(loaded.to_json(), candidate.to_json());
    }

    #[test]
    fn reference_rejections_remove_latent_fallbacks_before_later_masked_collisions() {
        let mut candidate = db();
        candidate.add([1; 32], Some([11; 32]), Some([21; 32]), "exported");
        candidate.add([2; 32], Some([12; 32]), Some([22; 32]), "malloc");
        candidate.exact.insert(key(11), "exported".into());
        candidate.calls.insert(key(21), "exported".into());
        let original = candidate.clone();
        let mut reference = db();
        reference.add([3; 32], Some([11; 32]), Some([21; 32]), "local_function");
        reference.add([2; 32], Some([12; 32]), Some([22; 32]), "malloc");

        assert_eq!(candidate.reject_reference_conflicts_from([&reference]), Ok(2));
        assert_eq!(candidate.entries.get(&key(1)).map(String::as_str), Some("exported"));
        assert!(!candidate.entry_exact.contains_key(&key(1)));
        assert!(!candidate.entry_calls.contains_key(&key(1)));
        assert_eq!(candidate.entry_exact.get(&key(2)), Some(&BTreeSet::from([key(12)])));
        assert_eq!(candidate.entry_calls.get(&key(2)), Some(&vec![key(22)]));
        let mut later = db();
        later.add([1; 32], Some([13; 32]), Some([23; 32]), "different_masked_name");
        candidate.combine(&later).unwrap();
        assert!(!candidate.exact.contains_key(&key(11)));
        assert!(!candidate.calls.contains_key(&key(21)));
        let mut loaded = SignatureDb::from_gzip(&candidate.to_gzip().unwrap()).unwrap();
        loaded.combine(&original).unwrap();
        assert!(!loaded.entries.contains_key(&key(1)));
        assert!(!loaded.exact.contains_key(&key(11)));
        assert!(!loaded.calls.contains_key(&key(21)));
        assert!(loaded.ambiguous_exact.contains(&key(11)));
        assert!(loaded.ambiguous_calls.contains(&key(21)));
        assert_eq!(loaded.entries.get(&key(2)).map(String::as_str), Some("malloc"));
    }

    #[test]
    fn masked_rejections_preserve_existing_uncontradicted_qualified_answers() {
        let mut candidate = db();
        candidate.add([1; 32], Some([11; 32]), Some([21; 32]), "exported");
        candidate.exact.insert(key(11), "exported".into());
        candidate.calls.insert(key(21), "exported".into());
        let original = candidate.clone();
        let mut reference = db();
        reference.add([1; 32], Some([11; 32]), Some([23; 32]), "local_function");
        assert_eq!(candidate.reject_reference_conflicts_from([&reference]), Ok(2));
        assert!(candidate.ambiguous.contains(&key(1)));
        assert!(candidate.ambiguous_exact.contains(&key(11)));
        assert!(!candidate.ambiguous_calls.contains(&key(21)));
        assert_eq!(candidate.calls.get(&key(21)).map(String::as_str), Some("exported"));
        assert!(!candidate.entry_exact.contains_key(&key(1)));
        assert!(!candidate.entry_calls.contains_key(&key(1)));
        candidate.combine(&original).unwrap();
        assert!(!candidate.entries.contains_key(&key(1)));
        assert!(!candidate.exact.contains_key(&key(11)));
        assert_eq!(candidate.calls.get(&key(21)).map(String::as_str), Some("exported"));
        assert!(!candidate.calls.contains_key(&key(23)));
    }

    #[test]
    fn reference_latent_ambiguity_rejects_candidate_fallbacks_but_does_not_count_latent_keys() {
        let mut candidate = db();
        candidate.add([1; 32], Some([11; 32]), Some([21; 32]), "exported");
        let mut reference = db();
        reference.add([3; 32], Some([11; 32]), Some([21; 32]), "exported");
        reference.add([4; 32], Some([11; 32]), Some([21; 32]), "different_raw_name");
        assert_eq!(candidate.reject_reference_conflicts_from([&reference]), Ok(0));
        assert_eq!(candidate.entries.get(&key(1)).map(String::as_str), Some("exported"));
        assert!(candidate.ambiguous_exact.contains(&key(11)));
        assert!(candidate.ambiguous_calls.contains(&key(21)));
        assert!(candidate.entry_exact.is_empty());
        assert!(candidate.entry_calls.is_empty());
        assert_eq!(candidate.reject_reference_conflicts_from([&reference]), Ok(0));
    }

    #[test]
    fn reference_batch_checks_intact_latent_evidence_in_every_order_before_pruning() {
        let mut original = db();
        original.add([1; 32], Some([11; 32]), Some([21; 32]), "exported");
        original.add([2; 32], Some([12; 32]), Some([22; 32]), "malloc");
        let mut masked_conflict = db();
        masked_conflict.add([1; 32], Some([13; 32]), Some([23; 32]), "different_masked_name");
        masked_conflict.add([2; 32], Some([12; 32]), Some([22; 32]), "malloc");
        masked_conflict.add([5; 32], Some([15; 32]), Some([25; 32]), "reference_only");
        let mut latent_conflict = db();
        latent_conflict.add([3; 32], Some([11; 32]), Some([21; 32]), "different_latent_name");
        latent_conflict.add([2; 32], Some([12; 32]), Some([22; 32]), "malloc");
        let mut expected = None;
        for references in [
            vec![&masked_conflict, &latent_conflict],
            vec![&latent_conflict, &masked_conflict],
            vec![&masked_conflict, &latent_conflict, &masked_conflict],
        ] {
            let mut candidate = original.clone();
            assert_eq!(candidate.reject_reference_conflicts_from(references), Ok(1));
            assert!(candidate.ambiguous.contains(&key(1)));
            assert!(candidate.ambiguous_exact.contains(&key(11)));
            assert!(candidate.ambiguous_calls.contains(&key(21)));
            assert!(!candidate.entry_exact.contains_key(&key(1)));
            assert!(!candidate.entry_calls.contains_key(&key(1)));
            assert_eq!(candidate.entry_exact.get(&key(2)), Some(&BTreeSet::from([key(12)])));
            assert_eq!(candidate.entry_calls.get(&key(2)), Some(&vec![key(22)]));
            assert_eq!(candidate.entries, BTreeMap::from([(key(2), "malloc".to_owned())]));
            assert_eq!(candidate.ambiguous, BTreeSet::from([key(1)]));
            assert_eq!(candidate.ambiguous_exact, BTreeSet::from([key(11)]));
            assert_eq!(candidate.ambiguous_calls, BTreeSet::from([key(21)]));
            let output = candidate.to_gzip().unwrap();
            if let Some(previous) = &expected {
                assert_eq!(&output, previous);
            } else {
                expected = Some(output.clone());
            }
            let mut loaded = SignatureDb::from_gzip(&output).unwrap();
            loaded.combine(&original).unwrap();
            assert!(!loaded.entries.contains_key(&key(1)));
            assert!(!loaded.exact.contains_key(&key(11)));
            assert!(!loaded.calls.contains_key(&key(21)));
            assert_eq!(loaded.to_json(), candidate.to_json());
        }
    }

    #[test]
    fn empty_reference_batch_preserves_all_candidate_evidence() {
        let mut candidate = corpus_sources()[0].clone();
        let before = candidate.clone();
        assert_eq!(candidate.reject_reference_conflicts_from(std::iter::empty::<&SignatureDb>()), Ok(0));
        assert_same_evidence(&candidate, &before);
    }

    #[test]
    fn reference_filter_mismatches_are_atomic_including_ephemeral_evidence() {
        let mut candidate = corpus_sources()[0].clone();
        let before = candidate.clone();
        let mut conflicting = db();
        conflicting.add([1; 32], Some([10; 32]), Some([20; 32]), "different_raw_name");
        let mut reference = before.clone();
        reference.arch = Arch::Aarch64;
        assert_eq!(
            candidate.reject_reference_conflicts_from([&conflicting, &reference]),
            Err(CombineError::ArchitectureMismatch)
        );
        assert_same_evidence(&candidate, &before);
        reference.arch = candidate.arch;
        reference.scheme = LEGACY_SCHEME;
        assert_eq!(
            candidate.reject_reference_conflicts_from([&conflicting, &reference]),
            Err(CombineError::SchemeMismatch)
        );
        assert_same_evidence(&candidate, &before);
    }
}
