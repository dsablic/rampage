//! Toolchain build metadata that compilers embed in the image: Go's build info (`go version -m`) and Rust's
//! cargo-auditable dependency list. Both are self-reported by the build, readable without analysis, and survive
//! symbol stripping. Each reader is bounded and never panics; a blob that is found but cannot be decoded is
//! reported as unreadable with a reason rather than dropped, so "absent" is never confused with "broken".

use serde::Serialize;

use crate::Binary;

pub mod go;
pub mod rust;

/// Whether a blob that was found could be decoded. Absent blobs are `None` at the call site, not a status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobStatus {
    /// Decoded; the record may still carry warnings about individual entries.
    Present,
    /// Found (the magic or section is there) but not decodable; `reason` says why.
    Unreadable,
}

/// Where a blob was found: its section and virtual address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlobLocation {
    pub section: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
}

/// Longest text kept from one embedded field (a module path, a setting value, a crate name); longer text is cut
/// on a character boundary and the record says so in a warning.
pub const MAX_FIELD_BYTES: usize = 4096;

/// `text` cut to [`MAX_FIELD_BYTES`], and whether it was cut.
pub(crate) fn clip(text: &str) -> (String, bool) {
    let (text, truncated) = crate::text::clip(text, MAX_FIELD_BYTES);
    (text.to_owned(), truncated)
}

/// The image's sections named one of `names`, in section order.
pub(crate) fn sections_named<'a>(
    binary: &'a Binary,
    names: &'a [&str],
) -> impl Iterator<Item = &'a crate::Section> + 'a {
    binary.sections.iter().filter(move |section| names.contains(&section.name.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_keeps_short_text_and_cuts_long_text_on_a_character_boundary() {
        assert_eq!(clip("short"), ("short".to_owned(), false));
        let long = format!("{}é", "a".repeat(MAX_FIELD_BYTES - 1));
        let (cut, truncated) = clip(&long);
        assert!(truncated);
        assert_eq!(cut.len(), MAX_FIELD_BYTES - 1);
    }
}
