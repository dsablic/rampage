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
//! says whether the pattern is anchored at the entry point. Blank lines and `;` comments are ignored, as are
//! keys we do not model (such as `section_start`). PeID does not categorize its entries, so every parsed
//! signature gets [`Kind::Unknown`]; the entry name usually carries the real tool and version.

use crate::model::{Condition, Kind, Signature};
use crate::pattern::{BytePattern, PatternError};

/// Why a PeID database could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeidError {
    /// A `signature`/`ep_only` line appeared before any `[name]` header.
    #[error("line {line}: field outside any [name] section")]
    OrphanField { line: usize },
    /// A `signature` value was not a valid hex pattern.
    #[error("line {line}: bad signature: {source}")]
    BadSignature { line: usize, source: PatternError },
}

/// An entry being assembled from consecutive lines.
#[derive(Default)]
struct Pending {
    name: String,
    signature: Option<BytePattern>,
    ep_only: bool,
}

impl Pending {
    /// Turns a completed entry into a signature, dropping entries that never supplied a usable pattern.
    fn finish(self) -> Option<Signature> {
        let pattern = self.signature?;
        let condition = Condition::Entry { pattern, ep_only: self.ep_only };
        Some(Signature::new(self.name.trim(), Kind::Unknown, vec![condition]).with_note("PeID userdb entry"))
    }
}

/// Parses PeID `userdb.txt` text into signatures. Unknown keys and comments are skipped; a malformed `signature`
/// value fails the whole parse so a bad user file is reported rather than silently dropped.
pub(crate) fn parse(text: &str) -> Result<Vec<Signature>, PeidError> {
    let mut signatures = Vec::new();
    let mut pending: Option<Pending> = None;
    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if let Some(name) = section_header(line) {
            if let Some(entry) = pending.take().and_then(Pending::finish) {
                signatures.push(entry);
            }
            pending = Some(Pending { name: name.to_owned(), ..Pending::default() });
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim().to_ascii_lowercase(), value.trim());
        let entry = pending.as_mut().ok_or(PeidError::OrphanField { line: line_no })?;
        match key.as_str() {
            "signature" => {
                let pattern =
                    BytePattern::parse(value).map_err(|source| PeidError::BadSignature { line: line_no, source })?;
                entry.signature = Some(pattern);
            }
            "ep_only" => entry.ep_only = value.eq_ignore_ascii_case("true"),
            _ => {}
        }
    }
    if let Some(entry) = pending.and_then(Pending::finish) {
        signatures.push(entry);
    }
    Ok(signatures)
}

/// The name inside a `[ ... ]` header line, or `None` when the line is not a header.
fn section_header(line: &str) -> Option<&str> {
    line.strip_prefix('[')?.strip_suffix(']')
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "; a tiny sample, authored here, not from PeID\n\
        [UPX 3.x -> Markus & Laszlo]\n\
        signature = 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ??\n\
        ep_only = true\n\
        \n\
        [Microsoft Visual C++ 8.0]\n\
        signature = 55 8B EC 6A ?? 68\n\
        ep_only = false\n\
        section_start = false\n";

    #[test]
    fn parses_names_patterns_and_ep_flags() {
        let signatures = parse(SAMPLE).unwrap();
        assert_eq!(signatures.len(), 2);
        assert_eq!(signatures[0].name, "UPX 3.x -> Markus & Laszlo");
        assert_eq!(signatures[0].kind, Kind::Unknown);
        match &signatures[0].conditions[0] {
            Condition::Entry { pattern, ep_only } => {
                assert_eq!(pattern.len(), 12);
                assert!(*ep_only);
            }
            other => panic!("unexpected condition {other:?}"),
        }
        match &signatures[1].conditions[0] {
            Condition::Entry { ep_only, .. } => assert!(!*ep_only),
            other => panic!("unexpected condition {other:?}"),
        }
    }

    #[test]
    fn skips_comments_blank_lines_and_unknown_keys() {
        let signatures = parse(SAMPLE).unwrap();
        // The `section_start` key and the leading comment must not create extra signatures.
        assert_eq!(signatures.len(), 2);
    }

    #[test]
    fn a_field_before_any_header_is_an_error() {
        let error = parse("signature = 90 90\n").unwrap_err();
        assert_eq!(error, PeidError::OrphanField { line: 1 });
    }

    #[test]
    fn a_bad_signature_is_reported_with_its_line() {
        let text = "[Bad]\nsignature = 60 ZZ\n";
        assert!(matches!(parse(text), Err(PeidError::BadSignature { line: 2, .. })));
    }

    #[test]
    fn an_entry_without_a_signature_is_dropped() {
        let signatures = parse("[No signature here]\nep_only = true\n").unwrap();
        assert!(signatures.is_empty());
    }
}
