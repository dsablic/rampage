//! Candidate signature rows: a function byte pattern with wildcards, a name and an optional library tag, stored as a
//! FLIRT PAT record in the existing signature pack format. A candidate is data only; it is evaluated as a scratch
//! data pack and never applied elsewhere.
//!
//! What a row can express is what rampage's PAT matcher supports (`rampage_signatures::PatternDb`):
//! - whole-byte wildcards (`..`) anywhere: a changed constant, displacement, register choice (a ModRM, REX or
//!   instruction-word byte) or call target; there are no nibble or bit wildcards;
//! - an exact module length: a body matches only at exactly that many bytes;
//! - a pattern shorter than the module (`length` above the pattern's own length): the bytes past the pattern are
//!   unconstrained, as a PAT tail that ends early leaves them.
//!
//! The PAT format's CRC16 field is not used (explicit bytes are stronger), and its references (`^`) and dumpsig
//! tuples are unsupported by the matcher. Ghidra FID records are hashes needing a semantic adapter, not byte
//! patterns, so they cannot be proposed as rows.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use rampage_arch::Arch;
use rampage_signatures::{PatternDb, SignatureDb};
use serde::{Deserialize, Serialize};

use super::engine::Layer;
use super::{FlywheelError, sha256_text, write_atomic};

/// Most rows in one candidate.
pub const MAX_ROWS: usize = 256;
/// The longest pattern: PAT's 32-byte prefix and a tail of at most 2048 bytes (one 4096-character field).
pub const MAX_PATTERN_BYTES: usize = 32 + 2048;
/// The longest module a row may name.
pub const MAX_MODULE_BYTES: usize = 0xffff;
const MAX_NAME_CHARS: usize = 255;
const MAX_LIBRARY_CHARS: usize = 64;

/// One signature row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub arch: String,
    /// The function name a match gives.
    pub name: String,
    /// The library the function belongs to, recorded as provenance; matching ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    /// The body from its first byte: two lowercase hex digits per fixed byte, `..` per wildcard.
    pub pattern: String,
    /// The module length a body must have, when longer than the pattern: bytes past the pattern are unconstrained.
    /// Absent, a body matches only at exactly the pattern's length.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<usize>,
    /// The training failure the row was made from, when it was made from one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<RowSource>,
}

/// The training case behind a row: provenance only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowSource {
    pub case: String,
    pub binary: String,
    pub address: String,
}

impl Row {
    /// The PAT record: the first 32 bytes (wildcard-padded when shorter), no CRC, the module length, the name at
    /// offset zero, and the rest of the body as the contiguous tail.
    pub fn pat_line(&self) -> Result<String, FlywheelError> {
        let bytes = parse_pattern(&self.pattern).map_err(FlywheelError::Invalid)?;
        let length = self.module_length(&bytes)?;
        let pat = |bytes: &[Option<u8>]| -> String {
            bytes.iter().map(|byte| byte.map_or("..".to_owned(), |byte| format!("{byte:02X}"))).collect()
        };
        let mut prefix: Vec<Option<u8>> = bytes.iter().copied().take(32).collect();
        prefix.resize(32, None);
        let mut line = format!("{} 00 0000 {length:04X} :0000 {}", pat(&prefix), self.name);
        if bytes.len() > 32 {
            line.push(' ');
            line.push_str(&pat(&bytes[32..]));
        }
        Ok(line)
    }

    /// The module length a body must have: `length`, or the pattern's own length.
    fn module_length(&self, bytes: &[Option<u8>]) -> Result<usize, FlywheelError> {
        match self.length {
            None => Ok(bytes.len()),
            Some(length) if length >= bytes.len() && length <= MAX_MODULE_BYTES => Ok(length),
            Some(length) => Err(FlywheelError::Invalid(format!(
                "length {length} must be at least the pattern's {} bytes and at most {MAX_MODULE_BYTES}",
                bytes.len()
            ))),
        }
    }

    /// The pattern as matching sees it: the pattern's bytes, then a wildcard for every byte up to `length`.
    pub fn matcher(&self) -> Result<Vec<Option<u8>>, FlywheelError> {
        let mut bytes = parse_pattern(&self.pattern).map_err(FlywheelError::Invalid)?;
        let length = self.module_length(&bytes)?;
        bytes.resize(length, None);
        Ok(bytes)
    }

    /// Checks the row's fields, that its pattern is at least `min_bytes` long, and that it carries enough fixed
    /// content to ever answer.
    pub fn validate(&self, arches: &BTreeSet<String>, min_bytes: usize) -> Result<(), FlywheelError> {
        let invalid = |message: String| Err(FlywheelError::Invalid(message));
        if !arches.contains(&self.arch) {
            let known: Vec<&str> = arches.iter().map(String::as_str).collect();
            return invalid(format!("arch `{}` is not in the corpus ({})", self.arch, known.join(", ")));
        }
        let name = &self.name;
        if name.is_empty()
            || name.chars().count() > MAX_NAME_CHARS
            || name == "?"
            || name.starts_with([':', '^', '('])
            || name.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return invalid(format!(
                "name {name:?} must be 1 to {MAX_NAME_CHARS} characters without whitespace, not `?` and not \
                 starting with `:`, `^` or `(`"
            ));
        }
        if let Some(library) = &self.library
            && (library.is_empty()
                || library.len() > MAX_LIBRARY_CHARS
                || !library.chars().all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c)))
        {
            return invalid(format!("library {library:?} must be 1 to {MAX_LIBRARY_CHARS} of A-Z a-z 0-9 . _ + -"));
        }
        let bytes = parse_pattern(&self.pattern).map_err(FlywheelError::Invalid)?;
        if bytes.len() > MAX_PATTERN_BYTES {
            return invalid(format!("pattern is {} bytes; at most {MAX_PATTERN_BYTES}", bytes.len()));
        }
        // The minimum applies to the explicit pattern, not only to the module: a short pattern on a long module
        // constrains no more than a short body does.
        if bytes.len() < min_bytes {
            return invalid(format!(
                "pattern is {} bytes; the gate needs at least {min_bytes}: shorter bodies collide with unrelated code",
                bytes.len()
            ));
        }
        self.module_length(&bytes)?;
        if self.length.is_some_and(|length| length > bytes.len()) && bytes.last().is_some_and(Option::is_none) {
            return invalid("a pattern shorter than `length` must end with a fixed byte".to_owned());
        }
        let arch: Arch = self.arch.parse().map_err(FlywheelError::Invalid)?;
        let line = self.pat_line()?;
        let database = PatternDb::parse(arch, format!("{line}\n---\n").as_bytes())
            .map_err(|error| FlywheelError::Invalid(format!("pattern does not form a PAT record: {error}")))?;
        if !database.records().iter().all(|record| record.has_discriminating_pattern()) {
            return invalid(
                "pattern has too few fixed bytes to ever answer: at least 6, and at least half of its positions"
                    .to_owned(),
            );
        }
        Ok(())
    }

    /// The fields that make a row the heuristic it is, for hashing: provenance excluded.
    fn identity(&self) -> (String, String, String, String) {
        // What matching sees: `length` equal to the pattern's own is the same row as no `length`.
        let pattern = self.matcher().map(|bytes| format_pattern(&bytes)).unwrap_or_default();
        (self.arch.clone(), self.name.clone(), self.library.clone().unwrap_or_default(), pattern)
    }
}

/// Parses a pattern: pairs of hex digits for fixed bytes and `..` (or `??`) for wildcards; whitespace is ignored.
pub fn parse_pattern(text: &str) -> Result<Vec<Option<u8>>, String> {
    let compact: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() || !compact.len().is_multiple_of(2) {
        return Err("pattern must be pairs of hex digits or `..`, at least one byte".to_owned());
    }
    compact
        .chunks(2)
        .map(|pair| match pair {
            ['.', '.'] | ['?', '?'] => Ok(None),
            [high, low] => match (high.to_digit(16), low.to_digit(16)) {
                (Some(high), Some(low)) => Ok(Some((high * 16 + low) as u8)),
                _ => Err(format!("`{high}{low}` is neither a hex byte nor `..`")),
            },
            _ => unreachable!("chunks of two"),
        })
        .collect()
}

/// The canonical spelling of a pattern: lowercase hex pairs and `..`, no spaces.
pub fn format_pattern(bytes: &[Option<u8>]) -> String {
    bytes.iter().map(|byte| byte.map_or("..".to_owned(), |byte| format!("{byte:02x}"))).collect()
}

/// One signature database per architecture holding `rows` as PAT records.
pub fn databases(rows: &[Row]) -> Result<BTreeMap<String, SignatureDb>, FlywheelError> {
    let mut lines: BTreeMap<&str, String> = BTreeMap::new();
    for row in rows {
        let text = lines.entry(row.arch.as_str()).or_default();
        text.push_str(&row.pat_line()?);
        text.push('\n');
    }
    let mut databases = BTreeMap::new();
    for (arch, mut text) in lines {
        text.push_str("---\n");
        let parsed: Arch = arch.parse().map_err(FlywheelError::Invalid)?;
        let database = SignatureDb::from_pat(parsed, text.as_bytes())
            .map_err(|error| FlywheelError::Invalid(format!("{arch} rows: {error}")))?;
        databases.insert(arch.to_owned(), database);
    }
    Ok(databases)
}

/// The evaluation layer for `rows`, `None` when there are none.
pub fn layer(name: &str, rows: &[Row]) -> Result<Option<Layer>, FlywheelError> {
    if rows.is_empty() {
        return Ok(None);
    }
    let mut patterns = Vec::new();
    for row in rows {
        let arch: Arch = row.arch.parse().map_err(FlywheelError::Invalid)?;
        patterns.push((arch, row.matcher()?));
    }
    Ok(Some(Layer {
        name: name.to_owned(),
        databases: databases(rows)?.into_values().collect(),
        patterns: Some(patterns),
    }))
}

/// The SHA-256 identifying a set of rows, independent of their order and provenance.
pub fn rows_hash(rows: &[Row]) -> String {
    let mut identities: Vec<_> = rows.iter().map(Row::identity).collect();
    identities.sort();
    identities.dedup();
    sha256_text(&serde_json::to_string(&identities).unwrap_or_default())
}

/// A candidate: rows proposed together, evaluated and promoted as one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub id: String,
    pub family: String,
    pub created_unix_ms: u64,
    /// The proposer run that made it, when the server was started for one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    pub rows: Vec<Row>,
}

impl Candidate {
    pub fn hash(&self) -> String {
        rows_hash(&self.rows)
    }
}

/// The candidate file inside its scratch pack directory.
pub const CANDIDATE_FILE: &str = "candidate.json";

/// Writes a data pack holding `rows` to `directory`: the manifest, one signatures content per architecture,
/// and nothing else of `rampage-pack.toml`'s kinds. Stale architecture files are removed.
pub fn write_pack(
    directory: &Path,
    name: &str,
    version: &str,
    license: &str,
    source: &str,
    description: &str,
    rows: &[Row],
) -> Result<(), FlywheelError> {
    let databases = databases(rows)?;
    let sigs = directory.join("sigs");
    if sigs.is_dir() {
        for entry in std::fs::read_dir(&sigs).map_err(|error| FlywheelError::io(&sigs, error))? {
            let path = entry.map_err(|error| FlywheelError::io(&sigs, error))?.path();
            if path.extension().is_some_and(|extension| extension == "json") {
                std::fs::remove_file(&path).map_err(|error| FlywheelError::io(&path, error))?;
            }
        }
    }
    let mut manifest = format!(
        "name = {}\nversion = {}\nlicense = {}\nsource = {}\ndescription = {}\n",
        toml_string(name),
        toml_string(version),
        toml_string(license),
        toml_string(source),
        toml_string(description)
    );
    if databases.is_empty() {
        manifest.push_str("contents = []\n");
    }
    for (arch, database) in &databases {
        write_atomic(&sigs.join(format!("{arch}.json")), database.to_json().as_bytes())?;
        manifest.push_str(&format!(
            "\n[[contents]]\nkind = \"signatures\"\npath = \"sigs/{arch}.json\"\narch = \"{arch}\"\n"
        ));
    }
    write_atomic(&directory.join(crate::packs::MANIFEST_FILE), manifest.as_bytes())
}

fn toml_string(text: &str) -> String {
    serde_json::Value::from(text).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pattern: &str) -> Row {
        Row {
            arch: "x86_64".to_owned(),
            name: "inflate".to_owned(),
            library: Some("zlib".to_owned()),
            pattern: pattern.to_owned(),
            length: None,
            source: None,
        }
    }

    fn arches() -> BTreeSet<String> {
        BTreeSet::from(["x86_64".to_owned()])
    }

    #[test]
    fn patterns_parse_canonically_and_reject_nibble_wildcards() {
        assert_eq!(
            parse_pattern("55 48 ..89 ?? E5").unwrap(),
            [Some(0x55), Some(0x48), None, Some(0x89), None, Some(0xe5)]
        );
        assert_eq!(format_pattern(&parse_pattern("55 48 .. E5").unwrap()), "5548..e5");
        assert!(parse_pattern("5").is_err());
        assert!(parse_pattern("5.").is_err());
        assert!(parse_pattern("").is_err());
    }

    #[test]
    fn a_row_becomes_a_pat_record_that_the_signature_database_matches() {
        // push rbp; mov rbp, rsp; call rel32 (wildcarded); mov eax, 0x1234; pop rbp; ret, padded past 32 bytes.
        let body: Vec<u8> = [0x55, 0x48, 0x89, 0xe5, 0xe8, 1, 2, 3, 4, 0xb8, 0x34, 0x12, 0, 0, 0x5d, 0xc3]
            .into_iter()
            .chain(std::iter::repeat_n(0x90, 24))
            .collect();
        let mut pattern: Vec<Option<u8>> = body.iter().map(|&byte| Some(byte)).collect();
        pattern[5..9].fill(None);
        let row = row(&format_pattern(&pattern));
        row.validate(&arches(), 0).unwrap();
        let databases = databases(std::slice::from_ref(&row)).unwrap();
        let database = &databases["x86_64"];
        let target = rampage_arch::Target {
            arch: Arch::X86_64,
            big_endian: false,
            data_big_endian: false,
            thumb: std::sync::Arc::new([]),
            global_pointer: None,
            got: None,
        };
        let image = rampage_signatures::MaskContext::default();
        assert_eq!(database.identify_in(&target, &image, &body, 0x401000), Some("inflate"));
        let mut relinked = body.clone();
        relinked[5..9].copy_from_slice(&[9, 9, 9, 9]);
        assert_eq!(database.identify_in(&target, &image, &relinked, 0x402000), Some("inflate"), "wildcards");
        let mut other = body.clone();
        other[10] = 0x35;
        assert_eq!(database.identify_in(&target, &image, &other, 0x401000), None, "a fixed byte differs");
        assert_eq!(database.identify_in(&target, &image, &body[..body.len() - 1], 0x401000), None, "length");
    }

    #[test]
    fn rows_are_schema_checked() {
        let good = "554889e5b834120000005dc3";
        assert!(row(good).validate(&arches(), 0).is_ok());
        assert!(Row { arch: "mips".to_owned(), ..row(good) }.validate(&arches(), 0).is_err());
        assert!(Row { name: "two words".to_owned(), ..row(good) }.validate(&arches(), 0).is_err());
        assert!(Row { name: "?".to_owned(), ..row(good) }.validate(&arches(), 0).is_err());
        assert!(Row { library: Some("zlib 1".to_owned()), ..row(good) }.validate(&arches(), 0).is_err());
        assert!(row("55 .. .. .. .. .. .. .. .. .. c3").validate(&arches(), 0).is_err(), "too few fixed bytes");
        assert!(row(&"90".repeat(MAX_PATTERN_BYTES + 1)).validate(&arches(), 0).is_err());
        let error = row(good).validate(&arches(), 32).unwrap_err();
        assert!(error.message().contains("at least 32"), "{error}");
    }

    #[test]
    fn the_rows_hash_ignores_order_spelling_and_provenance() {
        let a = row("554889e5b834120000005dc3");
        let b = Row { name: "deflate".to_owned(), ..row("554889e5b835120000005dc3") };
        let spelled = Row {
            pattern: "55 48 89 E5 B8 34 12 00 00 00 5D C3".to_owned(),
            source: Some(RowSource { case: "f1".to_owned(), binary: "x".to_owned(), address: "0x1".to_owned() }),
            ..a.clone()
        };
        assert_eq!(rows_hash(&[a.clone(), b.clone()]), rows_hash(&[b.clone(), spelled]));
        assert_ne!(rows_hash(std::slice::from_ref(&a)), rows_hash(&[a, b]));
    }

    fn target() -> rampage_arch::Target {
        rampage_arch::Target {
            arch: Arch::X86_64,
            big_endian: false,
            data_big_endian: false,
            thumb: std::sync::Arc::new([]),
            global_pointer: None,
            got: None,
        }
    }

    /// push rbp; mov rbp, rsp; mov eax, imm32; add eax, imm32; imul eax, eax, imm32; ... a 64-byte body whose
    /// constants a new version could change.
    fn versioned(constant: u8, tail: u8) -> Vec<u8> {
        let mut body =
            vec![0x55, 0x48, 0x89, 0xe5, 0xb8, constant, 0, 0, 0, 0x05, 0x34, 0x12, 0, 0, 0x69, 0xc0, 7, 0, 0, 0];
        while body.len() < 62 {
            body.extend([0x01, 0xc8]);
        }
        body.extend([0x5d, 0xc3]);
        let at = body.len() - 4;
        body[at] = tail;
        body
    }

    #[test]
    fn wildcards_generalise_a_row_across_a_changed_constant_and_the_schema_keeps_it_long_and_fixed() {
        let old = versioned(1, 0x01);
        let new = versioned(7, 0x01);
        let exact = Row { pattern: format_pattern(&old.iter().map(|&b| Some(b)).collect::<Vec<_>>()), ..row("") };
        let mut wildcarded: Vec<Option<u8>> = old.iter().map(|&b| Some(b)).collect();
        wildcarded[5] = None;
        let general = Row { pattern: format_pattern(&wildcarded), ..row("") };
        general.validate(&arches(), 32).unwrap();
        let image = rampage_signatures::MaskContext::default();
        let exact_db = &databases(std::slice::from_ref(&exact)).unwrap()["x86_64"];
        let general_db = &databases(std::slice::from_ref(&general)).unwrap()["x86_64"];
        assert_eq!(exact_db.identify_in(&target(), &image, &old, 0x1000), Some("inflate"));
        assert_eq!(exact_db.identify_in(&target(), &image, &new, 0x1000), None, "an exact row misses the new version");
        assert_eq!(general_db.identify_in(&target(), &image, &new, 0x1000), Some("inflate"), "the wildcard carries");
        assert!(pattern_matches_row(&general, &new));
    }

    fn pattern_matches_row(row: &Row, body: &[u8]) -> bool {
        super::super::engine::pattern_matches(&row.matcher().unwrap(), body)
    }

    #[test]
    fn a_pattern_shorter_than_its_module_leaves_the_rest_unconstrained_but_keeps_the_length() {
        let old = versioned(1, 0x01);
        let changed_tail = versioned(1, 0x29);
        let prefix: Vec<Option<u8>> = old[..40].iter().map(|&b| Some(b)).collect();
        let prefixed = Row { pattern: format_pattern(&prefix), length: Some(old.len()), ..row("") };
        prefixed.validate(&arches(), 32).unwrap();
        let line = prefixed.pat_line().unwrap();
        assert!(line.contains(&format!(" 00 0000 {:04X} :0000 inflate ", old.len())), "{line}");
        let tail = line.rsplit(' ').next().unwrap();
        assert_eq!(tail.len(), 2 * 8, "the PAT tail ends where the pattern does: {line}");
        assert_eq!(prefixed.matcher().unwrap().len(), old.len());
        let database = &databases(std::slice::from_ref(&prefixed)).unwrap()["x86_64"];
        let image = rampage_signatures::MaskContext::default();
        assert_eq!(database.identify_in(&target(), &image, &changed_tail, 0x1000), Some("inflate"));
        let mut longer = old.clone();
        longer.insert(60, 0x90);
        assert_eq!(database.identify_in(&target(), &image, &longer, 0x1000), None, "the module length still binds");

        // The schema: the explicit pattern meets the minimum, `length` covers it, and it ends in a fixed byte.
        assert!(
            Row { length: Some(39), ..prefixed.clone() }.validate(&arches(), 32).is_err(),
            "length below the pattern"
        );
        let short: Vec<Option<u8>> = old[..24].iter().map(|&b| Some(b)).collect();
        let error = Row { pattern: format_pattern(&short), ..prefixed.clone() }.validate(&arches(), 32).unwrap_err();
        assert!(error.message().contains("at least 32"), "{error}");
        let mut trailing = prefix.clone();
        trailing[39] = None;
        assert!(Row { pattern: format_pattern(&trailing), ..prefixed.clone() }.validate(&arches(), 32).is_err());
        assert!(Row { length: Some(MAX_MODULE_BYTES + 1), ..prefixed.clone() }.validate(&arches(), 32).is_err());
        let half: Vec<Option<u8>> = old[..40].iter().enumerate().map(|(i, &b)| (i % 3 == 0).then_some(b)).collect();
        assert!(
            Row { pattern: format_pattern(&half), ..prefixed.clone() }.validate(&arches(), 32).is_err(),
            "too few fixed"
        );

        // A length equal to the pattern's own is the same row as none.
        let whole = Row { pattern: format_pattern(&old.iter().map(|&b| Some(b)).collect::<Vec<_>>()), ..row("") };
        assert_eq!(
            rows_hash(std::slice::from_ref(&whole)),
            rows_hash(&[Row { length: Some(old.len()), ..whole.clone() }])
        );
        assert_ne!(rows_hash(std::slice::from_ref(&whole)), rows_hash(std::slice::from_ref(&prefixed)));
    }
}
