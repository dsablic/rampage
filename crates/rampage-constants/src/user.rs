//! User constants: a JSON database of constants to look for beside the bundled ones, as data packs supply it.
//!
//! ```json
//! { "constants": [
//!   { "name": "Acme cipher S-box", "algorithm": "Acme", "kind": "block_cipher", "bytes": "63 7c 77 7b ...",
//!     "min_len": 64 },
//!   { "name": "Acme hash IV", "algorithm": "Acme", "kind": "hash", "u32": [1732584193, "0xefcdab89", ...],
//!     "endian": "both" }
//! ] }
//! ```
//!
//! Each constant has exactly one of `bytes` (hex, whitespace allowed between bytes), `u32` or `u64` (numbers, or
//! hex strings `0x...`); word tables need `endian`: `little`, `big` or `both`. `min_len` (bytes, default the
//! whole pattern) is how much of the head must match. Every constant passes the bundled ones' information guards
//! (see [`ConstantSignature::validate`]), names are unique and distinct from the bundled names, and sizes are
//! capped. Any invalid constant rejects the whole file, naming it.
//!
//! The file may declare `format_version` (absent means 1). This build reads format 1 and refuses a higher one. Within
//! format 1 a later rampage may add fields and constant kinds: fields this build does not know are ignored and a
//! constant of a kind it does not know is skipped, each with a warning ([`UserConstants::warnings`]).

use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};

use serde::Deserialize;

use crate::{ConstantDb, ConstantSignature, Endian, Kind, Pattern};

/// The most constants one file may hold.
pub const MAX_USER_CONSTANTS: usize = 4096;
/// The longest pattern one user constant may have, in bytes; the largest bundled table (a CRC-64 table) has 2048.
pub const MAX_USER_CONSTANT_BYTES: usize = 4096;
const MAX_NAME_CHARS: usize = 128;
const MAX_ALGORITHM_CHARS: usize = 64;
const MAX_SOURCE_CHARS: usize = 512;
/// The constants-file format this build reads; a file without `format_version` is format 1.
pub const CONSTANTS_FORMAT_VERSION: u64 = 1;
/// Warnings named for one file; the rest are counted.
const MAX_WARNINGS: usize = 8;

#[derive(Deserialize)]
struct File {
    #[serde(default)]
    format_version: Option<u64>,
    constants: Vec<Entry>,
    #[serde(flatten)]
    unknown: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct Entry {
    name: String,
    algorithm: String,
    kind: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    bytes: Option<String>,
    #[serde(default)]
    u32: Option<Vec<Word>>,
    #[serde(default)]
    u64: Option<Vec<Word>>,
    #[serde(default)]
    endian: Option<Order>,
    #[serde(default)]
    min_len: Option<usize>,
    #[serde(flatten)]
    unknown: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Word {
    Number(u64),
    Hex(String),
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Order {
    Little,
    Big,
    Both,
}

/// Validated user constants, ready to add to the bundled database with [`ConstantDb::bundled_with`].
#[derive(Debug, Clone, Default)]
pub struct UserConstants {
    signatures: Vec<ConstantSignature>,
    warnings: Vec<String>,
}

impl UserConstants {
    /// Parses and validates a constants file. `origin` (a pack, say) is recorded as the source of constants that
    /// name none.
    pub fn parse(text: &str, origin: &str) -> Result<Self, String> {
        let file: File = serde_json::from_str(text).map_err(|error| format!("invalid constants JSON: {error}"))?;
        let version = file.format_version.unwrap_or(CONSTANTS_FORMAT_VERSION);
        if version > CONSTANTS_FORMAT_VERSION {
            return Err(format!(
                "constants format_version {version} is newer than this rampage reads ({CONSTANTS_FORMAT_VERSION}); \
                 use a newer rampage"
            ));
        }
        let mut warnings = Vec::new();
        if !file.unknown.is_empty() {
            let keys: Vec<&str> = file.unknown.keys().map(String::as_str).collect();
            warnings.push(format!("fields this rampage does not know were ignored: {}", keys.join(", ")));
        }
        if file.constants.is_empty() {
            return Err("`constants` is empty".to_owned());
        }
        if file.constants.len() > MAX_USER_CONSTANTS {
            return Err(format!("more than {MAX_USER_CONSTANTS} constants"));
        }
        let bundled: HashSet<&str> = ConstantDb::bundled().signatures().iter().map(|s| &*s.what).collect();
        let mut names = HashSet::new();
        let mut signatures = Vec::with_capacity(file.constants.len());
        for (index, entry) in file.constants.into_iter().enumerate() {
            let label = format!("constant {index} ({:?})", entry.name.chars().take(MAX_NAME_CHARS).collect::<String>());
            if !entry.unknown.is_empty() {
                let keys: Vec<&str> = entry.unknown.keys().map(String::as_str).collect();
                warnings.push(format!("{label}: fields this rampage does not know were ignored: {}", keys.join(", ")));
            }
            let Ok(kind) = serde_json::from_value::<Kind>(serde_json::Value::String(entry.kind.clone())) else {
                warnings.push(format!("{label}: kind {:?} is not one this rampage knows; skipped", entry.kind));
                continue;
            };
            let signature = signature(entry, kind, origin).map_err(|reason| format!("{label}: {reason}"))?;
            if bundled.contains(&*signature.what) {
                return Err(format!("{label}: the name is taken by a bundled constant"));
            }
            if !names.insert(signature.what.clone()) {
                return Err(format!("{label}: the name is used twice"));
            }
            signature.validate().map_err(|error| format!("{label}: {}", error.reason))?;
            signatures.push(signature);
        }
        if signatures.is_empty() {
            return Err("no constant of a kind this rampage knows".to_owned());
        }
        if warnings.len() > MAX_WARNINGS {
            let more = warnings.len() - MAX_WARNINGS;
            warnings.truncate(MAX_WARNINGS);
            warnings.push(format!("and {more} more"));
        }
        Ok(Self { signatures, warnings })
    }

    /// What the file holds that this build ignored or skipped: unknown fields and constants of unknown kinds.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn signatures(&self) -> &[ConstantSignature] {
        &self.signatures
    }

    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
}

fn text_field(name: &str, value: String, max: usize) -> Result<String, String> {
    if value.trim().is_empty() {
        return Err(format!("`{name}` is empty"));
    }
    if value.chars().count() > max {
        return Err(format!("`{name}` is longer than {max} characters"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("`{name}` contains a control character"));
    }
    Ok(value)
}

fn signature(entry: Entry, kind: Kind, origin: &str) -> Result<ConstantSignature, String> {
    let what = text_field("name", entry.name, MAX_NAME_CHARS)?;
    let algorithm = text_field("algorithm", entry.algorithm, MAX_ALGORITHM_CHARS)?;
    let source = match entry.source {
        Some(source) => text_field("source", source, MAX_SOURCE_CHARS)?,
        None => origin.to_owned(),
    };
    let (pattern, byte_order) = match (entry.bytes, entry.u32, entry.u64) {
        (Some(hex), None, None) => {
            if entry.endian.is_some() {
                return Err("`endian` applies only to `u32` and `u64` tables".to_owned());
            }
            (Pattern::Bytes(parse_hex(&hex)?), None)
        }
        (None, Some(words), None) => {
            let words = words_of(&words, u64::from(u32::MAX))?;
            let words = words.into_iter().map(|word| word as u32).collect();
            (Pattern::U32(words), order(entry.endian)?)
        }
        (None, None, Some(words)) => (Pattern::U64(words_of(&words, u64::MAX)?), order(entry.endian)?),
        _ => return Err("give exactly one of `bytes`, `u32` and `u64`".to_owned()),
    };
    let len = pattern.byte_len();
    if len > MAX_USER_CONSTANT_BYTES {
        return Err(format!("the pattern's {len} bytes exceed {MAX_USER_CONSTANT_BYTES}"));
    }
    let min_len = entry.min_len.unwrap_or(len);
    Ok(ConstantSignature {
        algorithm: Cow::Owned(algorithm),
        kind,
        what: Cow::Owned(what),
        source: Cow::Owned(source),
        pattern,
        min_len,
        byte_order,
    })
}

fn order(endian: Option<Order>) -> Result<Option<Endian>, String> {
    match endian {
        None => Err("a word table needs `endian`: little, big or both".to_owned()),
        Some(Order::Little) => Ok(Some(Endian::Little)),
        Some(Order::Big) => Ok(Some(Endian::Big)),
        Some(Order::Both) => Ok(None),
    }
}

fn words_of(words: &[Word], max: u64) -> Result<Vec<u64>, String> {
    if words.len() > MAX_USER_CONSTANT_BYTES {
        return Err(format!("more than {MAX_USER_CONSTANT_BYTES} words"));
    }
    words
        .iter()
        .enumerate()
        .map(|(index, word)| {
            let value = match word {
                Word::Number(value) => *value,
                Word::Hex(text) => text
                    .strip_prefix("0x")
                    .or_else(|| text.strip_prefix("0X"))
                    .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                    .ok_or_else(|| format!("word {index} {text:?} is not a number or 0x-prefixed hex"))?,
            };
            if value > max {
                return Err(format!("word {index} ({value:#x}) does not fit the table's width"));
            }
            Ok(value)
        })
        .collect()
}

fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = text.bytes().filter(|byte| !byte.is_ascii_whitespace()).collect();
    if digits.len() > 2 * MAX_USER_CONSTANT_BYTES {
        return Err(format!("`bytes` holds more than {MAX_USER_CONSTANT_BYTES} bytes"));
    }
    if !digits.len().is_multiple_of(2) {
        return Err("`bytes` has an odd number of hex digits".to_owned());
    }
    digits
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok().filter(|pair| pair.bytes().all(|b| b.is_ascii_hexdigit()));
            pair.and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| "`bytes` is not hex: use digits 0-9 and a-f, two per byte".to_owned())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{scan, scan_binary};

    const ACME_SBOX: &str = "6b 2f 91 0c d4 37 e8 5a a2 1d 7f c6 03 b9 48 f5 \
                             8e 22 5d 9b 14 e1 76 c0 3a ad 69 07 f2 58 bc 81";

    fn parse(constants: &str) -> Result<UserConstants, String> {
        UserConstants::parse(&format!("{{\"constants\": [{constants}]}}"), "pack test")
    }

    fn acme(extra: &str) -> String {
        format!(
            "{{\"name\": \"Acme S-box\", \"algorithm\": \"Acme\", \"kind\": \"block_cipher\", \
             \"bytes\": \"{ACME_SBOX}\"{extra}}}"
        )
    }

    #[test]
    fn byte_and_word_constants_are_found_beside_the_bundled_ones() {
        let words = "{\"name\": \"Acme IV\", \"algorithm\": \"Acme\", \"kind\": \"hash\", \"endian\": \"big\", \
                     \"u32\": [\"0x9e3779b9\", 2654435769, \"0x7f4a7c15\", \"0xf39cc060\", \"0x5cedc834\"]}";
        let user = parse(&format!("{},{words}", acme(""))).unwrap();
        assert_eq!(user.len(), 2);
        assert_eq!(user.signatures()[0].source, "pack test");
        let db = ConstantDb::bundled_with(&[&user]);
        assert_eq!(db.signatures().len(), ConstantDb::bundled().signatures().len() + 2);

        let sbox = parse_hex(ACME_SBOX).unwrap();
        let iv: Vec<u8> = [0x9e37_79b9u32, 0x9e37_79b9, 0x7f4a_7c15, 0xf39c_c060, 0x5ced_c834]
            .iter()
            .flat_map(|word| word.to_be_bytes())
            .collect();
        let little: Vec<u8> = iv.chunks(4).flat_map(|word| word.iter().rev().copied()).collect();
        let mut buffer = vec![0x11u8; 256];
        buffer[16..48].copy_from_slice(&sbox);
        buffer[64..84].copy_from_slice(&iv);
        buffer[128..148].copy_from_slice(&little);
        buffer[192..208].copy_from_slice(b"expand 32-byte k");
        let hits: Vec<_> =
            scan(&buffer, 0x1000, &db).into_iter().map(|hit| (hit.address, hit.what, hit.endian)).collect();
        assert_eq!(
            hits,
            [
                (0x1010, "Acme S-box".into(), None),
                // Only big-endian was asked for, so the little-endian copy at 0x1080 is not reported.
                (0x1040, "Acme IV".into(), Some(Endian::Big)),
                (0x10c0, "\"expand 32-byte k\" constant".into(), None),
            ]
        );
        assert!(scan(&buffer, 0, ConstantDb::bundled()).iter().all(|hit| hit.algorithm != "Acme"));
    }

    #[test]
    fn a_pack_constant_is_found_in_a_binary() {
        // The fixture's own bytes stand in for an embedded table: 32 bytes from the middle of its text.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
        let binary = rampage_loaders::Binary::open(&path).unwrap();
        let text = binary.sections.iter().find(|section| section.name == ".text").unwrap();
        let bytes = binary.section_file_bytes(text).unwrap();
        let table = &bytes[bytes.len() / 2..bytes.len() / 2 + 32];
        let hex: String = table.iter().map(|byte| format!("{byte:02x}")).collect();
        let user = parse(&format!(
            "{{\"name\": \"Fixture table\", \"algorithm\": \"Fixture\", \"kind\": \"checksum\", \"bytes\": \"{hex}\"}}"
        ));
        let user = user.unwrap();
        let hits = scan_binary(&binary, &ConstantDb::bundled_with(&[&user]));
        let address = text.address + (bytes.len() / 2) as u64;
        assert!(hits.iter().any(|hit| hit.what == "Fixture table" && hit.address == address), "{hits:?}");
    }

    #[test]
    fn malformed_entries_reject_the_file_naming_the_constant() {
        let cases = [
            (acme(", \"u32\": [1]"), "exactly one of"),
            (acme(", \"endian\": \"big\""), "`endian` applies only"),
            (acme(", \"min_len\": 64"), "exceeds the pattern's 32 bytes"),
            (acme("").replace("block_cipher", "rot13"), "no constant of a kind this rampage knows"),
            (acme("").replace("6b 2f", "6g 2f"), "not hex"),
            (acme("").replace("6b 2f", "6b 2"), "odd number"),
            (acme("").replace("Acme S-box", " "), "`name` is empty"),
            (acme("").replace("Acme S-box", "AES forward S-box"), "taken by a bundled constant"),
            (format!("{},{}", acme(""), acme("")), "used twice"),
            (
                "{\"name\": \"w\", \"algorithm\": \"a\", \"kind\": \"hash\", \"u32\": [1, 2, 3, 4]}".to_owned(),
                "needs `endian`",
            ),
            (
                "{\"name\": \"w\", \"algorithm\": \"a\", \"kind\": \"hash\", \"endian\": \"both\", \
                 \"u32\": [4294967296, 2, 3, 4]}"
                    .to_owned(),
                "does not fit",
            ),
        ];
        for (constants, expected) in cases {
            let error = parse(&constants).unwrap_err();
            assert!(error.contains(expected), "{constants}: {error}");
        }
        let error = parse(&format!("{},{}", acme(""), acme("").replace("S-box", "table").replace("6b", "zz")));
        assert!(error.unwrap_err().starts_with("constant 1 (\"Acme table\")"));
        assert!(UserConstants::parse("{\"constants\": []}", "p").unwrap_err().contains("empty"));
        assert!(UserConstants::parse("[]", "p").is_err());
        let huge = format!("\"{}\"", "ab".repeat(MAX_USER_CONSTANT_BYTES + 1));
        let error = parse(&acme("").replace(&format!("\"{ACME_SBOX}\""), &huge)).unwrap_err();
        assert!(error.contains("more than 4096 bytes"), "{error}");
    }

    #[test]
    fn later_fields_and_kinds_are_skipped_with_warnings_and_a_newer_format_is_refused() {
        let plain = parse(&acme("")).unwrap();
        assert!(plain.warnings().is_empty());
        let versioned = UserConstants::parse(&format!("{{\"format_version\": 1, \"constants\": [{}]}}", acme("")), "p");
        assert!(versioned.unwrap().warnings().is_empty());

        let later = acme(", \"colour\": 1").replace("Acme S-box", "Acme later");
        let rot13 = acme("").replace("block_cipher", "rot13").replace("Acme S-box", "Acme rot13");
        let text = format!("{{\"constants\": [{}, {later}, {rot13}], \"origin\": \"x\"}}", acme(""));
        let user = UserConstants::parse(&text, "p").unwrap();
        assert_eq!(user.len(), 2);
        let warnings = user.warnings().join("\n");
        assert!(warnings.contains("ignored: origin"), "{warnings}");
        assert!(
            warnings.contains("constant 1 (\"Acme later\"): fields this rampage does not know were ignored: colour")
        );
        assert!(warnings.contains("constant 2 (\"Acme rot13\"): kind \"rot13\" is not one this rampage knows"));

        let newer = UserConstants::parse(&format!("{{\"format_version\": 2, \"constants\": [{}]}}", acme("")), "p");
        let error = newer.unwrap_err();
        assert!(error.contains("format_version 2 is newer than this rampage reads (1)"), "{error}");
    }

    #[test]
    fn low_information_constants_are_rejected() {
        let entry = |bytes: &str| {
            format!("{{\"name\": \"n\", \"algorithm\": \"a\", \"kind\": \"hash\", \"bytes\": \"{bytes}\"}}")
        };
        let zeros = parse(&entry(&"00".repeat(64))).unwrap_err();
        assert!(zeros.contains("distinct byte values"), "{zeros}");
        let short = parse(&entry("0123456789abcdef0123")).unwrap_err();
        assert!(short.contains("below 16"), "{short}");
        let ramp: String = (0..64).map(|i| format!("{:02x}", [0xff, 0xff, 0, 1][i % 4])).collect();
        assert!(parse(&entry(&ramp)).unwrap_err().contains("distinct"));
        // A table whose head alone is required must carry the information there.
        assert!(parse(&acme(", \"min_len\": 8")).unwrap_err().contains("below 16"));
        let words = "{\"name\": \"w\", \"algorithm\": \"a\", \"kind\": \"hash\", \"endian\": \"little\", \
                     \"u64\": [0, 0, 0, 0]}";
        assert!(parse(words).unwrap_err().contains("distinct"));
    }
}
