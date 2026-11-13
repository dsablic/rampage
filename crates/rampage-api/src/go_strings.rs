//! Go string headers in static data. Go string data is not NUL-terminated: literals sit back to back in one
//! blob, and a literal's bounds come from whatever references it. Code references give starts; a static
//! `{ptr, len}` header in data (a package-level string, a string field of a composite literal, a slice of
//! strings) gives a start and a length, even for a literal no instruction references.
//!
//! Inside the blob there are no separators, so almost any `{V, n}` pair with `V` on a literal start passes the
//! byte checks. Code references are therefore trusted over headers: a header may not run across a
//! code-referenced start, nor start strictly inside a literal a code reference and a header length bound.

use rampage_analysis::discover::{Program, XrefKind};
use rampage_analysis::strings::{Encoding, FoundString};
use rampage_loaders::{Binary, SectionKind};

/// Data bytes scanned for headers, across all sections.
const MAX_SCAN_BYTES: usize = 256 << 20;
/// Header candidates kept; a larger count stops the scan with what was found and marks it truncated.
const MAX_HEADERS: usize = 1 << 20;
/// The longest literal a header may describe.
const MAX_LENGTH: u64 = 64 << 10;
/// The most non-printable bytes (`\n`, non-ASCII text) between two printable runs of one blob region.
const MAX_GAP: u64 = 16;

/// One literal start that static headers point at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GoStringHeader {
    pub start: u64,
    /// The literal's length, when the headers at `start` agree on one or one of them ends exactly at the next
    /// known literal start. `None` when they disagree: then only the start is evidence.
    pub length: Option<u64>,
    /// How many headers point at `start`.
    pub references: usize,
}

/// The static string headers of a Go image, sorted by start.
#[derive(Debug, Default)]
pub(crate) struct GoStrings {
    headers: Vec<GoStringHeader>,
    /// The scan stopped at its byte or header cap, so later headers are missing.
    pub truncated: bool,
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

/// The printable regions of the Go string blob: chains of printable runs separated by at most [`MAX_GAP`]
/// bytes, kept when one of their runs joins several code-referenced literals. Separate regions are never
/// bridged, so unrelated read-only data between them (C strings, type links, pclntab) stays out.
fn blob_regions(runs: &[(u64, u64)], targets: &[u64]) -> Vec<(u64, u64)> {
    let qualifies = |&(start, end): &(u64, u64)| {
        targets.partition_point(|&target| target < end) - targets.partition_point(|&target| target < start) >= 2
    };
    let mut regions = Vec::new();
    let mut current: Option<(u64, u64, bool)> = None;
    for run in runs {
        current = match current {
            Some((start, end, blob)) if run.0 >= end && run.0 - end <= MAX_GAP => {
                Some((start, end.max(run.1), blob || qualifies(run)))
            }
            previous => {
                if let Some((start, end, true)) = previous {
                    regions.push((start, end));
                }
                Some((run.0, run.1, qualifies(run)))
            }
        };
    }
    if let Some((start, end, true)) = current {
        regions.push((start, end));
    }
    regions
}

/// Reads the `{ptr, len}` headers in a Go image's non-code sections. Conservative: the pointer must land on
/// printable text inside one Go string blob region, and the literal must stay inside that region, be at most
/// [`MAX_LENGTH`] bytes, valid UTF-8, free of NUL bytes, and must not run across a code-referenced start. Only
/// call this for images recognised as Go.
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
    targets.sort_unstable();
    targets.dedup();
    let regions = blob_regions(&runs, &targets);
    let (Some(&(low, _)), Some(&(_, high))) = (regions.first(), regions.last()) else {
        return GoStrings::default();
    };
    let region_end = |address: u64| {
        let index = regions.partition_point(|&(start, _)| start <= address);
        index.checked_sub(1).map(|index| regions[index]).filter(|&(_, end)| address < end).map(|(_, end)| end)
    };
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
    let mut truncated = false;
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
                truncated = true;
                break 'sections;
            }
            let at = base + (index * pointer) as u64;
            let start = binary.rebase_target(at).unwrap_or_else(|| word(&pair[..pointer]));
            if start < low || start >= high {
                continue;
            }
            let length = word(&pair[pointer..]);
            if length == 0 || length > MAX_LENGTH || !in_run(start) {
                continue;
            }
            if !region_end(start).is_some_and(|end| length <= end - start) {
                continue;
            }
            let Some(text) = binary.read(start, length) else { continue };
            if text.contains(&0) || std::str::from_utf8(text).is_err() {
                continue;
            }
            found.push((start, length));
        }
    }
    GoStrings { headers: resolve(found, &targets), truncated }
}

/// Turns header candidates into literal starts and lengths, trusting code references (sorted `targets`) over
/// headers: a candidate running across a code-referenced start is dropped; of several lengths at one start, the
/// shortest ending exactly at another known start wins, else a length is kept only when all agree; and a header
/// start strictly inside a literal a code reference starts and a kept length ends is dropped.
fn resolve(mut found: Vec<(u64, u64)>, targets: &[u64]) -> Vec<GoStringHeader> {
    let next_target = |address: u64| targets.get(targets.partition_point(|&target| target <= address)).copied();
    // A code-referenced start inside the literal means the pair is not this literal's header.
    found.retain(|&(start, length)| !next_target(start).is_some_and(|target| target < start + length));
    found.sort_unstable();
    let starts: Vec<u64> = {
        let mut starts: Vec<u64> = found.iter().map(|&(start, _)| start).collect();
        starts.dedup();
        starts
    };
    let known = |address: u64| starts.binary_search(&address).is_ok() || targets.binary_search(&address).is_ok();
    let mut headers: Vec<GoStringHeader> = Vec::new();
    for group in found.chunk_by(|left, right| left.0 == right.0) {
        let start = group[0].0;
        // Prefer the shortest length ending exactly at another known start (where the next literal begins); else
        // keep one only when all headers agree. Never simply the longest.
        let length = group
            .iter()
            .map(|&(_, length)| length)
            .find(|&length| known(start + length))
            .or_else(|| group.iter().all(|&(_, length)| length == group[0].1).then_some(group[0].1));
        headers.push(GoStringHeader { start, length, references: group.len() });
    }
    // A header start strictly inside a literal that a code reference starts and a header length ends splits
    // nothing: it is a coincidental pair.
    let mut covered_until = 0;
    headers.retain(|header| {
        if header.start < covered_until && targets.binary_search(&header.start).is_err() {
            return false;
        }
        if targets.binary_search(&header.start).is_ok()
            && let Some(length) = header.length
        {
            covered_until = covered_until.max(header.start + length);
        }
        true
    });
    headers
}

/// Where the Go literal at `target` ends: at its header length when static headers give one, else at the next
/// literal start that code or a header references.
pub(crate) fn literal_end(program: &Program, headers: &GoStrings, target: u64) -> Option<u64> {
    if let Some(length) = headers.header(target).and_then(|header| header.length) {
        return Some(target + length);
    }
    let after = program.xrefs.partition_point(|xref| xref.to <= target);
    let code = program.xrefs[after..].iter().find(|xref| xref.kind == XrefKind::Data).map(|xref| xref.to);
    match (code, headers.next_after(target)) {
        (Some(code), Some(header)) => Some(code.min(header)),
        (code, header) => code.or(header),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_regions_chain_close_runs_and_never_bridge_unrelated_data() {
        // Two qualifying runs 8 bytes apart form one region; a qualifying run far away is its own region; a
        // non-qualifying chain between them is left out.
        let runs = [(0x100, 0x140), (0x148, 0x180), (0x400, 0x420), (0x800, 0x840)];
        let targets = [0x100, 0x110, 0x810, 0x820];
        assert_eq!(blob_regions(&runs, &targets), [(0x100, 0x180), (0x800, 0x840)]);
    }

    #[test]
    fn code_references_win_over_coincidental_headers() {
        // Code references literals at 0x100 and 0x110.
        let targets = [0x100, 0x110];
        let headers = resolve(
            vec![
                // Runs across the code-referenced 0x110: not a header of 0x100.
                (0x100, 0x20),
                // Two lengths at 0x110: 0x10 ends at the header start 0x120, so it wins over the longer 0x18.
                (0x110, 0x18),
                (0x110, 0x10),
                // Strictly inside 0x110..0x120: a coincidental pair, dropped.
                (0x114, 0x4),
                // Disagreeing lengths, neither ending at a known start: start only.
                (0x120, 0x3),
                (0x120, 0x5),
                // A single header-only literal keeps its length.
                (0x130, 0x6),
            ],
            &targets,
        );
        let summary: Vec<(u64, Option<u64>, usize)> =
            headers.iter().map(|header| (header.start, header.length, header.references)).collect();
        assert_eq!(summary, [(0x110, Some(0x10), 2), (0x120, None, 2), (0x130, Some(6), 1)]);
        let strings = GoStrings { headers, truncated: false };
        let program = Program {
            xrefs: targets
                .iter()
                .map(|&to| rampage_analysis::discover::Xref { to, from: 0x10, kind: XrefKind::Data })
                .collect(),
            ..Default::default()
        };
        // 0x100 ends at the code-referenced 0x110, 0x110 at its length, 0x120 (no agreed length) at 0x130.
        assert_eq!(literal_end(&program, &strings, 0x100), Some(0x110));
        assert_eq!(literal_end(&program, &strings, 0x110), Some(0x120));
        assert_eq!(literal_end(&program, &strings, 0x120), Some(0x130));
        assert_eq!(literal_end(&program, &strings, 0x130), Some(0x136));
    }
}
