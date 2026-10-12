//! A parser for the public PeID `userdb.txt` signature format, so users can bring their own database. We ship
//! only the parser, never a vendored PeID file, because PeID's bundled database has an unclear license.
//!
//! The format is a flat list of entries:
//!
//! ```text
//! [Packer or compiler name]
//! signature = 60 E8 ?? ?? ?? ??
//! ep_only = true
//! ```
//!
//! A `[name]` line opens an entry; the `signature` line is a hex pattern with `??` byte wildcards; `ep_only`
//! says whether the pattern is anchored at the entry point. Blank lines, `;` comments (whole-line or trailing a
//! value) and a leading byte-order mark are ignored, as are keys we do not model (such as `section_start`). PeID
//! does not categorize its entries, so every parsed signature gets [`Kind::Unknown`]; the entry name usually
//! carries the real tool and version.
//!
//! Real-world databases are hand-edited and rarely clean, so one bad entry never rejects the file: it is
//! skipped and reported as a [`PeidWarning`].

use crate::model::{Condition, Kind, Signature};
use crate::pattern::{BytePattern, PatternError};

/// A problem with one line or entry of a PeID database; the offending entry or line was skipped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeidWarning {
    /// A `signature`/`ep_only` line appeared before any `[name]` header.
    #[error("line {line}: field outside any [name] section, ignored")]
    OrphanField { line: usize },
    /// A `signature` value was not a usable hex pattern, so its entry was dropped.
    #[error("line {line}: bad signature in [{entry}], entry skipped: {source}")]
    BadSignature { line: usize, entry: String, source: PatternError },
    /// An entry gave `signature` more than once; the last one is used.
    #[error("line {line}: [{entry}] repeats its signature; the later one is used")]
    DuplicateSignature { line: usize, entry: String },
    /// An entry's `[ ]` header had no name, so the entry was dropped.
    #[error("line {line}: entry with an empty name skipped")]
    EmptyName { line: usize },
}

/// Why a PeID database could not be used at all: it had problems and not one usable signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeidError {
    #[error(
        "no usable signatures ({} problems; first: {})",
        .warnings.len(),
        .warnings.first().map_or_else(String::new, ToString::to_string)
    )]
    NoUsableSignatures { warnings: Vec<PeidWarning> },
}

/// The signatures parsed from a PeID database and the problems skipped on the way.
#[derive(Debug, Default)]
pub(crate) struct Parsed {
    pub signatures: Vec<Signature>,
    pub warnings: Vec<PeidWarning>,
}

/// An entry being assembled from consecutive lines.
struct Pending {
    name: String,
    line: usize,
    signature: Option<BytePattern>,
    ep_only: bool,
    broken: bool,
}

impl Parsed {
    /// Turns a completed entry into a signature, dropping entries that are broken, unnamed or never supplied a
    /// pattern.
    fn finish(&mut self, entry: Pending) {
        if entry.broken {
            return;
        }
        let name = entry.name.trim();
        if name.is_empty() {
            self.warnings.push(PeidWarning::EmptyName { line: entry.line });
            return;
        }
        let Some(pattern) = entry.signature else { return };
        let condition = Condition::Entry { pattern, ep_only: entry.ep_only };
        self.signatures.push(Signature::new(name, Kind::Unknown, vec![condition]).with_note("PeID userdb entry"));
    }
}

/// Parses PeID `userdb.txt` text into signatures, skipping and reporting what it cannot use.
pub(crate) fn parse(text: &str) -> Parsed {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut parsed = Parsed::default();
    let mut pending: Option<Pending> = None;
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }
        if let Some(name) = section_header(trimmed) {
            if let Some(entry) = pending.take() {
                parsed.finish(entry);
            }
            pending = Some(Pending { name: name.to_owned(), line, signature: None, ep_only: false, broken: false });
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.split(';').next().unwrap_or_default().trim();
        let Some(entry) = pending.as_mut() else {
            parsed.warnings.push(PeidWarning::OrphanField { line });
            continue;
        };
        match key.as_str() {
            "signature" => {
                if entry.signature.is_some() {
                    parsed.warnings.push(PeidWarning::DuplicateSignature { line, entry: entry.name.clone() });
                }
                match BytePattern::parse(value) {
                    Ok(pattern) => entry.signature = Some(pattern),
                    Err(source) => {
                        entry.broken = true;
                        parsed.warnings.push(PeidWarning::BadSignature { line, entry: entry.name.clone(), source });
                    }
                }
            }
            "ep_only" => entry.ep_only = value.eq_ignore_ascii_case("true"),
            _ => {}
        }
    }
    if let Some(entry) = pending {
        parsed.finish(entry);
    }
    parsed
}

/// The name inside a `[ ... ]` header line, or `None` when the line is not a header.
fn section_header(line: &str) -> Option<&str> {
    line.strip_prefix('[')?.strip_suffix(']')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::MAX_PATTERN_BYTES;

    const SAMPLE: &str = "; a tiny sample, authored here, not from PeID\n\
        [UPX 3.x -> Markus & Laszlo]\n\
        signature = 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ??\n\
        ep_only = true\n\
        \n\
        [Microsoft Visual C++ 8.0]\n\
        signature = 55 8B EC 6A ?? 68\n\
        ep_only = false\n\
        section_start = false\n";

    fn entry_pattern(signature: &Signature) -> (&BytePattern, bool) {
        match &signature.conditions[0] {
            Condition::Entry { pattern, ep_only } => (pattern, *ep_only),
            other => panic!("unexpected condition {other:?}"),
        }
    }

    #[test]
    fn parses_names_patterns_and_ep_flags() {
        let parsed = parse(SAMPLE);
        // The leading comment and the `section_start` key must not create extra signatures or warnings.
        assert_eq!(parsed.signatures.len(), 2);
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        assert_eq!(parsed.signatures[0].name, "UPX 3.x -> Markus & Laszlo");
        assert_eq!(parsed.signatures[0].kind, Kind::Unknown);
        let (pattern, ep_only) = entry_pattern(&parsed.signatures[0]);
        assert_eq!((pattern.len(), ep_only), (12, true));
        assert!(!entry_pattern(&parsed.signatures[1]).1);
    }

    #[test]
    fn a_leading_byte_order_mark_is_ignored() {
        let parsed = parse(&format!("\u{feff}{SAMPLE}"));
        assert_eq!(parsed.signatures.len(), 2);
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let bom_first = parse("\u{feff}[First]\nsignature = 60 E8 00 00\n");
        assert_eq!(bom_first.signatures[0].name, "First");
    }

    #[test]
    fn trailing_comments_are_stripped_from_values() {
        let parsed = parse("[Commented]\nsignature = 60 E8 00 00 ; the stub\nep_only = true ; anchored\n");
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let (pattern, ep_only) = entry_pattern(&parsed.signatures[0]);
        assert_eq!((pattern.len(), ep_only), (4, true));
    }

    #[test]
    fn long_signatures_well_past_256_bytes_parse() {
        let text = format!("[Long]\nsignature = {}\n", "90 ".repeat(1024));
        let parsed = parse(&text);
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        assert_eq!(entry_pattern(&parsed.signatures[0]).0.len(), 1024);
        let too_long = format!("[Huge]\nsignature = {}\n", "90".repeat(MAX_PATTERN_BYTES + 1));
        assert!(matches!(
            parse(&too_long).warnings[..],
            [PeidWarning::BadSignature { source: PatternError::TooLong, .. }]
        ));
    }

    #[test]
    fn a_bad_entry_is_skipped_and_reported_while_the_rest_load() {
        let text = "signature = 90 90\n[Bad]\nsignature = 60 ZZ\nep_only = true\n[]\nsignature = 90 90\n\
                    [Twice]\nsignature = 90 90\nsignature = 60 E8 00 00\n[Good]\nsignature = 60 E8 00 00\n";
        let parsed = parse(text);
        let names: Vec<_> = parsed.signatures.iter().map(|signature| signature.name.as_str()).collect();
        assert_eq!(names, ["Twice", "Good"]);
        assert_eq!(entry_pattern(&parsed.signatures[0]).0.len(), 4);
        assert_eq!(
            parsed.warnings,
            [
                PeidWarning::OrphanField { line: 1 },
                PeidWarning::BadSignature { line: 3, entry: "Bad".to_owned(), source: PatternError::BadChar('Z') },
                PeidWarning::EmptyName { line: 5 },
                PeidWarning::DuplicateSignature { line: 9, entry: "Twice".to_owned() },
            ]
        );
    }

    #[test]
    fn loading_fails_only_when_nothing_is_usable() {
        let mut db = crate::SignatureDb::new();
        assert_eq!(db.load_peid("[Good]\nsignature = 60 E8 00 00\n[Bad]\nsignature = ZZ\n").unwrap().len(), 1);
        assert_eq!(db.len(), 1);
        assert!(matches!(db.load_peid("[Bad]\nsignature = ZZ\n"), Err(PeidError::NoUsableSignatures { .. })));
        assert_eq!(db.len(), 1);
        assert!(db.load_peid("; nothing here\n").unwrap().is_empty());
    }

    #[test]
    fn an_entry_without_a_signature_is_dropped() {
        let parsed = parse("[No signature here]\nep_only = true\n");
        assert!(parsed.signatures.is_empty());
        assert!(parsed.warnings.is_empty());
    }
}
