//! Side-by-side manifests: the text, capped, and a bounded textual scan for the requested execution level and the
//! dependent assemblies' names. This is not an XML parser; comments and CDATA are not recognized.

use serde::Serialize;

/// Bytes of manifest text returned.
pub const MAX_MANIFEST_TEXT: usize = 16 * 1024;
/// Bytes of the manifest scanned for the execution level and dependencies.
pub const MAX_MANIFEST_SCAN: usize = 64 * 1024;
/// Dependent assembly names retained.
pub const MAX_MANIFEST_DEPENDENCIES: usize = 32;
const MAX_ATTRIBUTE_BYTES: usize = 256;
const MAX_PREFIX_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Manifest {
    /// The manifest decoded as UTF-8 (lossily, without a byte-order mark), cut at [`MAX_MANIFEST_TEXT`] bytes.
    pub text: String,
    pub size: usize,
    /// Whether `text` is shorter than the manifest.
    pub text_truncated: bool,
    pub requested_execution_level: Option<RequestedExecutionLevel>,
    /// `name` of each `assemblyIdentity` inside a `dependentAssembly`.
    pub dependent_assemblies: Vec<String>,
    /// Whether the scan stopped at [`MAX_MANIFEST_SCAN`] bytes or [`MAX_MANIFEST_DEPENDENCIES`] names.
    pub scan_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestedExecutionLevel {
    /// asInvoker, highestAvailable or requireAdministrator as written.
    pub level: Option<String>,
    pub ui_access: Option<String>,
}

pub(super) fn parse(bytes: &[u8]) -> Manifest {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let mut text_end = bytes.len().min(MAX_MANIFEST_TEXT);
    // Cut on a character boundary where the text is valid UTF-8.
    while text_end > 0 && text_end < bytes.len() && (bytes[text_end] & 0xc0) == 0x80 {
        text_end -= 1;
    }
    let scan = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_MANIFEST_SCAN)]);
    let requested_execution_level = tag(&scan, "requestedExecutionLevel", 0).map(|(element, _)| {
        RequestedExecutionLevel { level: attribute(element, "level"), ui_access: attribute(element, "uiAccess") }
    });
    let mut dependent_assemblies = Vec::new();
    let mut scan_truncated = bytes.len() > MAX_MANIFEST_SCAN;
    let mut at = 0;
    while let Some((_, end)) = tag(&scan, "dependentAssembly", at) {
        let close = scan[end..].find("dependentAssembly>").map_or(scan.len(), |offset| end + offset);
        if let Some((identity, _)) = tag(&scan[..close], "assemblyIdentity", end)
            && let Some(name) = attribute(identity, "name")
        {
            if dependent_assemblies.len() >= MAX_MANIFEST_DEPENDENCIES {
                scan_truncated = true;
                break;
            }
            dependent_assemblies.push(name);
        }
        at = close.max(end);
    }
    Manifest {
        text: String::from_utf8_lossy(&bytes[..text_end]).into_owned(),
        size: bytes.len(),
        text_truncated: text_end < bytes.len(),
        requested_execution_level,
        dependent_assemblies,
        scan_truncated,
    }
}

/// The first start tag named `name` (with any namespace prefix) at or after `from`: its text between the name and
/// `>`, and the offset just past it.
fn tag<'a>(text: &'a str, name: &str, from: usize) -> Option<(&'a str, usize)> {
    let mut at = from;
    loop {
        let found = at + text.get(at..)?.find(name)?;
        let after = found + name.len();
        // A namespace prefix is short, so the `<` is looked for only just before the name.
        let window = found.saturating_sub(MAX_PREFIX_BYTES);
        let opens = text.as_bytes()[window..found].iter().rposition(|&byte| byte == b'<').is_some_and(|open| {
            let prefix = &text.as_bytes()[window + open + 1..found];
            prefix.is_empty()
                || (prefix.ends_with(b":") && prefix[..prefix.len() - 1].iter().copied().all(is_name_byte))
        });
        let delimited = text[after..].starts_with(|c: char| c.is_ascii_whitespace() || c == '>' || c == '/');
        if opens && delimited {
            let end = text[after..].find('>').map_or(text.len(), |offset| after + offset + 1);
            return Some((&text[after..end], end));
        }
        at = after;
    }
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

/// The value of `name="…"` or `name='…'` in a start tag's text, capped at [`MAX_ATTRIBUTE_BYTES`].
fn attribute(element: &str, name: &str) -> Option<String> {
    let mut at = 0;
    while let Some(offset) = element[at..].find(name) {
        let start = at + offset;
        at = start + name.len();
        let boundary = start == 0 || element.as_bytes()[start - 1].is_ascii_whitespace();
        let rest = element[at..].trim_start();
        let Some(rest) = rest.strip_prefix('=').map(str::trim_start) else { continue };
        let Some(quote) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') else { continue };
        if !boundary {
            continue;
        }
        let value = &rest[1..];
        let value = &value[..value.find(quote).unwrap_or(value.len())];
        return Some(crate::text::clip(value, MAX_ATTRIBUTE_BYTES).0.to_owned());
    }
    None
}
