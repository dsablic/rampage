//! Go string headers in static data. Go string data is not NUL-terminated: literals sit back to back in one
//! blob, and a literal's bounds come from whatever references it. Code references give starts; a static
//! `{ptr, len}` header in data (a package-level string, a string field of a composite literal, a slice of
//! strings) gives a start and an exact length, even for a literal no instruction references.

use rampage_analysis::discover::{Program, XrefKind};
use rampage_analysis::strings::{Encoding, FoundString};
use rampage_loaders::{Binary, SectionKind};

/// Data bytes scanned for headers, across all sections.
const MAX_SCAN_BYTES: usize = 256 << 20;
/// Headers kept; a larger count stops the scan with what was found.
const MAX_HEADERS: usize = 1 << 20;
/// The longest literal a header may describe.
const MAX_LENGTH: u64 = 64 << 10;

/// One literal start that static headers point at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GoStringHeader {
    pub start: u64,
    /// The longest length a header gives for `start` (shorter headers at the same start are prefixes).
    pub length: u64,
    /// How many headers point at `start`.
    pub references: usize,
}

/// The static string headers of a Go image, sorted by start.
#[derive(Debug, Default)]
pub(crate) struct GoStrings {
    headers: Vec<GoStringHeader>,
}

impl GoStrings {
    pub(crate) fn header(&self, start: u64) -> Option<&GoStringHeader> {
        self.headers.binary_search_by_key(&start, |header| header.start).ok().map(|index| &self.headers[index])
    }

    /// Headers whose start lies in `low..high`.
    pub(crate) fn in_range(&self, low: u64, high: u64) -> &[GoStringHeader] {
        let first = self.headers.partition_point(|header| header.start < low);
        let last = self.headers.partition_point(|header| header.start < high);
        &self.headers[first..last.max(first)]
    }

    /// The first header start after `address`.
    pub(crate) fn next_after(&self, address: u64) -> Option<u64> {
        let index = self.headers.partition_point(|header| header.start <= address);
        self.headers.get(index).map(|header| header.start)
    }
}

/// Reads the `{ptr, len}` headers in a Go image's non-code sections. Conservative: the pointer must land on
/// printable text inside the Go string blob (the span of printable runs where code references several literal
/// starts), and the length must keep the literal inside that span, at most [`MAX_LENGTH`], valid UTF-8 and
/// free of NUL bytes. Only call this for images recognised as Go.
pub(crate) fn read(binary: &Binary, program: &Program, strings: &[FoundString]) -> GoStrings {
    let Some(pointer) = binary.arch.pointer_size().filter(|size| matches!(size, 4 | 8)).map(usize::from) else {
        return GoStrings::default();
    };
    let mut runs: Vec<(u64, u64)> = strings
        .iter()
        .filter(|string| string.encoding == Encoding::Ascii)
        .map(|string| (string.address, string.address + string.text.len() as u64))
        .collect();
    runs.sort_unstable();
    let mut targets: Vec<u64> =
        program.xrefs.iter().filter(|xref| xref.kind == XrefKind::Data).map(|xref| xref.to).collect();
    targets.dedup();
    // The blob spans the printable runs that join several code-referenced literals.
    let mut span: Option<(u64, u64)> = None;
    for &(start, end) in &runs {
        let first = targets.partition_point(|&target| target < start);
        let last = targets.partition_point(|&target| target < end);
        if last - first >= 2 {
            span = Some(span.map_or((start, end), |(low, high)| (low.min(start), high.max(end))));
        }
    }
    let Some((low, high)) = span else { return GoStrings::default() };
    let in_run = |address: u64| {
        let index = runs.partition_point(|&(start, _)| start <= address);
        index > 0 && address < runs[index - 1].1
    };
    let word = |bytes: &[u8]| -> u64 {
        let mut value = 0u64;
        for (index, &byte) in bytes.iter().enumerate() {
            let shift = if binary.big_endian { (bytes.len() - 1 - index) * 8 } else { index * 8 };
            value |= u64::from(byte) << shift;
        }
        value
    };

    let mut found = Vec::new();
    let mut scanned = 0usize;
    'sections: for section in &binary.sections {
        if !matches!(section.kind, SectionKind::Data | SectionKind::ReadOnlyData | SectionKind::Other) {
            continue;
        }
        let Some(bytes) = binary.section_file_bytes(section) else { continue };
        if binary.is_code(section.address) {
            continue;
        }
        // Headers are pointer-aligned: skip to the first aligned address.
        let skip = (section.address.wrapping_neg() % pointer as u64) as usize;
        let Some(bytes) = bytes.get(skip..) else { continue };
        let base = section.address + skip as u64;
        for (index, pair) in bytes.windows(pointer * 2).step_by(pointer).enumerate() {
            scanned += pointer;
            if scanned > MAX_SCAN_BYTES || found.len() >= MAX_HEADERS {
                break 'sections;
            }
            let at = base + (index * pointer) as u64;
            let start = binary.rebase_target(at).unwrap_or_else(|| word(&pair[..pointer]));
            if start < low || start >= high {
                continue;
            }
            let length = word(&pair[pointer..]);
            if length == 0 || length > MAX_LENGTH || length > high - start || !in_run(start) {
                continue;
            }
            let Some(text) = binary.read(start, length) else { continue };
            if text.contains(&0) || std::str::from_utf8(text).is_err() {
                continue;
            }
            found.push((start, length));
        }
    }
    found.sort_unstable();
    let mut headers: Vec<GoStringHeader> = Vec::new();
    for (start, length) in found {
        match headers.last_mut() {
            Some(last) if last.start == start => {
                last.length = length;
                last.references += 1;
            }
            _ => headers.push(GoStringHeader { start, length, references: 1 }),
        }
    }
    GoStrings { headers }
}

/// Where the Go literal at `target` ends: at its header length when a static header gives one, else at the
/// next literal start that code or a header references.
pub(crate) fn literal_end(program: &Program, headers: &GoStrings, target: u64) -> Option<u64> {
    if let Some(header) = headers.header(target) {
        return Some(target + header.length);
    }
    let after = program.xrefs.partition_point(|xref| xref.to <= target);
    let code = program.xrefs[after..].iter().find(|xref| xref.kind == XrefKind::Data).map(|xref| xref.to);
    match (code, headers.next_after(target)) {
        (Some(code), Some(header)) => Some(code.min(header)),
        (code, header) => code.or(header),
    }
}
