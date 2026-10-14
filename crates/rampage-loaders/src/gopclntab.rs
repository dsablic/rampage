//! Recovers function names from a Go program-counter line table (the `gopclntab`), so stripped Go binaries
//! gain real names the way IDA and Ghidra do. The table maps code addresses to function names and survives
//! `-ldflags "-s -w"`, which removes the Go symbol table and DWARF but not the pclntab.
//!
//! This is a bounded reader of an untrusted blob: it never panics, caps what it collects, validates every
//! offset against the blob length, and turns any inconsistency into "no symbols" rather than a failure. It
//! mirrors `pdb.rs`: additive enrichment that returns a report rather than mutating anything.
//!
//! Supported header magics (little- or big-endian per the image):
//!   - `0xFFFFFFFB` go1.2
//!   - `0xFFFFFFFA` go1.16
//!   - `0xFFFFFFF0` go1.18
//!   - `0xFFFFFFF1` go1.20 and later
//!
//! The header is `magic(4), pad(2), minLC(1), ptrSize(1)` followed by version-dependent pointer-wide fields.
//! The functab yields each function's entry PC and the offset of its `_func`, whose name offset indexes the
//! funcname table; the name is read NUL-terminated. Addresses are the image's virtual addresses.

use rampage_arch::bytes::read_uint;
use serde::Serialize;

use crate::warnings::CappedWarnings;

/// Caps for an untrusted blob: generous for real programs, bounded against a hostile or corrupt table.
const MAX_FUNCTIONS: usize = 1_000_000;
const MAX_NAME_BYTES: usize = 4096;
const WARNINGS: CappedWarnings = CappedWarnings::new(1024, "gopclntab");

const MAGIC_GO12: u32 = 0xFFFF_FFFB;
const MAGIC_GO116: u32 = 0xFFFF_FFFA;
const MAGIC_GO118: u32 = 0xFFFF_FFF0;
const MAGIC_GO120: u32 = 0xFFFF_FFF1;

#[derive(Debug, Default, Serialize)]
pub struct GoReport {
    pub functions: Vec<GoFunction>,
    pub warnings: Vec<String>,
    /// The table's header version, once its magic is recognized.
    pub version: Option<GoTableVersion>,
}

/// A pclntab header version. Each names the first Go release using that layout; a layout spans every release
/// until the next one, so `Go116` covers go1.16 and go1.17.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoTableVersion {
    Go12,
    Go116,
    Go118,
    Go120,
}

impl GoTableVersion {
    fn from_magic(magic: u32) -> Option<Self> {
        match magic {
            MAGIC_GO12 => Some(Self::Go12),
            MAGIC_GO116 => Some(Self::Go116),
            MAGIC_GO118 => Some(Self::Go118),
            MAGIC_GO120 => Some(Self::Go120),
            _ => None,
        }
    }
}

/// A function recovered from the pclntab. Being a `GoFunction` rather than a loader `Symbol` is the source
/// marker: everything here came from the Go table, never from a real symbol table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GoFunction {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
}

impl GoReport {
    pub(crate) fn warn(&mut self, warning: String) {
        WARNINGS.push(&mut self.warnings, warning);
    }
}

/// Where each version keeps its tables, resolved once from the header.
struct Layout {
    /// Width of a functab field: 4 (go1.18+) or `ptr_size` (older), which also strides the functab.
    functab_field: usize,
    /// Width of the `_func` struct's first field before its name offset: 4 (go1.18+) or `ptr_size`.
    first_field: usize,
    /// go1.18+ stores entry PCs as offsets from the text base; older versions store absolute PCs.
    add_text_base: bool,
    /// Absolute offset of the funcname table within the blob.
    funcname_base: usize,
    /// Absolute offset of the functab within the blob.
    functab_base: usize,
    /// Absolute offset the `_func` structs are measured from (the blob start for go1.2, else the functab).
    funcdata_base: usize,
}

/// Parses a Go pclntab blob and returns the `(address, name)` pairs it describes. `pointer_size` is the
/// image's pointer width in bytes and must agree with the table's own `ptrSize`; anything inconsistent or
/// out of range yields an empty (or partial) report with a warning, never a panic.
pub fn parse(pclntab: &[u8], text_base: u64, pointer_size: u8, big_endian: bool) -> GoReport {
    let mut report = GoReport::default();

    // The header is magic(4), pad(2), minLC(1), ptrSize(1), then pointer-wide fields.
    let Some(magic) = read_uint(pclntab, 0, 4, big_endian).map(|value| value as u32) else {
        report.warn("gopclntab too small for a header".to_owned());
        return report;
    };
    let Some(version) = GoTableVersion::from_magic(magic) else {
        report.warn(format!("not a gopclntab: unknown magic {magic:#010x}"));
        return report;
    };
    report.version = Some(version);
    if pclntab.get(4) != Some(&0) || pclntab.get(5) != Some(&0) {
        report.warn("gopclntab header padding is not zero".to_owned());
        return report;
    }
    let ptr_size = match pclntab.get(7).copied() {
        Some(size @ (4 | 8)) => usize::from(size),
        other => {
            report.warn(format!("gopclntab ptrSize {other:?} is not 4 or 8"));
            return report;
        }
    };
    if ptr_size != usize::from(pointer_size) {
        report.warn(format!("gopclntab ptrSize {ptr_size} disagrees with image pointer size {pointer_size}"));
        return report;
    }

    let Some(layout) = resolve_layout(pclntab, magic, ptr_size, big_endian) else {
        report.warn("gopclntab table offsets are out of range".to_owned());
        return report;
    };
    if layout.funcname_base >= pclntab.len() || layout.functab_base >= pclntab.len() {
        report.warn("gopclntab funcname or functab table lies outside the blob".to_owned());
        return report;
    }

    let Some(nfunc) = read_uint(pclntab, 8, ptr_size, big_endian) else {
        report.warn("gopclntab function count is unreadable".to_owned());
        return report;
    };
    let nfunc = match usize::try_from(nfunc) {
        Ok(count) if count <= MAX_FUNCTIONS => count,
        _ => {
            report.warn(format!("gopclntab function count {nfunc} exceeds the cap; truncating"));
            MAX_FUNCTIONS
        }
    };

    collect(pclntab, text_base, big_endian, &layout, nfunc, &mut report);
    report
}

/// A scanned candidate must yield at least this many functions to be trusted. A real Go program has thousands;
/// this rejects stray bytes that merely begin with the magic.
const MIN_SCANNED_FUNCTIONS: usize = 16;
/// Caps the number of header-shaped positions fully parsed per blob, bounding scan cost on hostile data.
const MAX_SCAN_CANDIDATES: usize = 64;

/// Scans a read-only data blob for an embedded pclntab, for images whose table is in an unnamed or renamed
/// section. Each pointer-aligned position whose bytes form a `pcHeader` prefix (a known magic, the two zero
/// pad bytes, a plausible `minLC`, and a `ptrSize` matching the image) is parsed; the first candidate that
/// yields at least [`MIN_SCANNED_FUNCTIONS`] functions with no warnings is returned. The number of positions
/// fully parsed is capped, so a blob full of magic-shaped noise cannot make this run away. The caller still
/// confirms the recovered addresses are code before trusting the result.
pub fn scan_blob(blob: &[u8], text_base: u64, pointer_size: u8, big_endian: bool) -> Option<GoReport> {
    let stride = usize::from(pointer_size);
    let mut candidates = 0;
    let mut offset = 0usize;
    while offset.checked_add(8).is_some_and(|end| end <= blob.len()) {
        if header_shaped(&blob[offset..], pointer_size, big_endian) {
            let report = parse(&blob[offset..], text_base, pointer_size, big_endian);
            if report.warnings.is_empty() && report.functions.len() >= MIN_SCANNED_FUNCTIONS {
                return Some(report);
            }
            candidates += 1;
            if candidates >= MAX_SCAN_CANDIDATES {
                break;
            }
        }
        offset += stride;
    }
    None
}

/// Whether the bytes begin with a `pcHeader` prefix: a known magic, two zero pad bytes, a `minLC` of 1, 2 or
/// 4, and a `ptrSize` equal to the image's.
fn header_shaped(bytes: &[u8], pointer_size: u8, big_endian: bool) -> bool {
    let Some(magic) = read_uint(bytes, 0, 4, big_endian).map(|value| value as u32) else {
        return false;
    };
    matches!(magic, MAGIC_GO12 | MAGIC_GO116 | MAGIC_GO118 | MAGIC_GO120)
        && bytes.get(4) == Some(&0)
        && bytes.get(5) == Some(&0)
        && matches!(bytes.get(6), Some(1 | 2 | 4))
        && bytes.get(7) == Some(&pointer_size)
}

/// Reads each functab entry into an `(address, name)` pair, skipping any entry whose offsets fall outside
/// the blob rather than aborting the whole table.
fn collect(blob: &[u8], text_base: u64, big_endian: bool, layout: &Layout, nfunc: usize, report: &mut GoReport) {
    let stride = layout.functab_field * 2;
    for index in 0..nfunc {
        let Some(entry) = index.checked_mul(stride).and_then(|offset| layout.functab_base.checked_add(offset)) else {
            break;
        };
        let pc = read_uint(blob, entry, layout.functab_field, big_endian);
        let funcoff = read_uint(blob, entry + layout.functab_field, layout.functab_field, big_endian);
        let (Some(pc), Some(funcoff)) = (pc, funcoff) else {
            report.warn("gopclntab functab entry is out of range".to_owned());
            break;
        };
        let address = if layout.add_text_base {
            match text_base.checked_add(pc) {
                Some(address) => address,
                None => continue,
            }
        } else {
            pc
        };

        // The `_func` begins with its entry field, then a 32-bit name offset into the funcname table.
        let Some(name_field) = usize::try_from(funcoff)
            .ok()
            .and_then(|funcoff| layout.funcdata_base.checked_add(funcoff))
            .and_then(|base| base.checked_add(layout.first_field))
        else {
            report.warn("gopclntab _func offset is out of range".to_owned());
            continue;
        };
        let Some(name_off) = read_uint(blob, name_field, 4, big_endian) else {
            report.warn("gopclntab name offset is unreadable".to_owned());
            continue;
        };
        let Some(name) = usize::try_from(name_off)
            .ok()
            .and_then(|name_off| layout.funcname_base.checked_add(name_off))
            .and_then(|start| read_name(blob, start))
        else {
            report.warn("gopclntab function name is out of range or too long".to_owned());
            continue;
        };
        if !name.is_empty() {
            report.functions.push(GoFunction { address, name });
        }
    }
}

/// Resolves the table offsets for a known magic. The field positions follow Go's `runtime.pcHeader`.
fn resolve_layout(blob: &[u8], magic: u32, ptr: usize, big_endian: bool) -> Option<Layout> {
    let field = |index: usize| read_uint(blob, 8 + index * ptr, ptr, big_endian).and_then(|v| usize::try_from(v).ok());
    match magic {
        // go1.2: funcname table and `_func` structs are measured from the blob start; the functab follows the
        // function count directly, and entries hold absolute PCs.
        MAGIC_GO12 => Some(Layout {
            functab_field: ptr,
            first_field: ptr,
            add_text_base: false,
            funcname_base: 0,
            functab_base: 8 + ptr,
            funcdata_base: 0,
        }),
        // go1.16: pointer-wide functab fields holding absolute PCs; funcname at field 2, functab at field 6.
        MAGIC_GO116 => {
            let funcname_base = field(2)?;
            let functab_base = field(6)?;
            Some(Layout {
                functab_field: ptr,
                first_field: ptr,
                add_text_base: false,
                funcname_base,
                functab_base,
                funcdata_base: functab_base,
            })
        }
        // go1.18 and go1.20+: 32-bit functab fields holding text-relative PCs; the field after the count is a
        // text base this reader ignores in favor of the caller's, funcname at field 3, functab at field 7.
        MAGIC_GO118 | MAGIC_GO120 => {
            let funcname_base = field(3)?;
            let functab_base = field(7)?;
            Some(Layout {
                functab_field: 4,
                first_field: 4,
                add_text_base: true,
                funcname_base,
                functab_base,
                funcdata_base: functab_base,
            })
        }
        _ => None,
    }
}

/// Reads a NUL-terminated name at `offset`, bounded by `MAX_NAME_BYTES`. Returns `None` when `offset` is out
/// of range or no terminator appears within the cap.
fn read_name(bytes: &[u8], offset: usize) -> Option<String> {
    let tail = bytes.get(offset..)?;
    let end = tail.iter().take(MAX_NAME_BYTES).position(|&byte| byte == 0)?;
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal little-endian go1.20 pclntab (ptrSize 8) with two functions, returning the blob.
    fn synthetic_go120() -> Vec<u8> {
        let ptr = 8usize;
        let header_len = 8 + 8 * ptr; // fields at 8,16,24,32,40,48,56,64 -> ends at 72
        let funcname_base = header_len;
        // funcname table: a reserved empty name at offset 0, then the two names.
        let mut names = vec![0u8];
        let main_off = names.len();
        names.extend_from_slice(b"main.main\0");
        let greet_off = names.len();
        names.extend_from_slice(b"main.greet\0");

        let functab_base = funcname_base + names.len();
        // Two functab entries (entryoff u32, funcoff u32) plus a sentinel entry.
        let functab_len = (2 * 2 + 1) * 4;
        let funcs_base = functab_base + functab_len;
        // _func0 then _func1: each is entryOff(u32) then nameOff(u32).
        let func0_off = funcs_base - functab_base;
        let func1_off = func0_off + 8;

        let mut blob = vec![0u8; funcs_base + 16];
        blob[0..4].copy_from_slice(&MAGIC_GO120.to_le_bytes());
        blob[6] = 1; // minLC
        blob[7] = 8; // ptrSize
        blob[8..16].copy_from_slice(&2u64.to_le_bytes()); // nfunc
        blob[32..40].copy_from_slice(&(funcname_base as u64).to_le_bytes()); // funcname offset (field 3)
        blob[64..72].copy_from_slice(&(functab_base as u64).to_le_bytes()); // functab offset (field 7)
        blob[funcname_base..funcname_base + names.len()].copy_from_slice(&names);

        let put_u32 = |blob: &mut [u8], at: usize, value: u32| blob[at..at + 4].copy_from_slice(&value.to_le_bytes());
        put_u32(&mut blob, functab_base, 0x10); // entry0 entryoff
        put_u32(&mut blob, functab_base + 4, func0_off as u32);
        put_u32(&mut blob, functab_base + 8, 0x40); // entry1 entryoff
        put_u32(&mut blob, functab_base + 12, func1_off as u32);
        put_u32(&mut blob, functab_base + 16, 0x80); // sentinel entryoff (text end)
        // _func0: entryOff then nameOff into funcname table.
        put_u32(&mut blob, funcs_base, 0x10);
        put_u32(&mut blob, funcs_base + 4, main_off as u32);
        put_u32(&mut blob, funcs_base + 8, 0x40);
        put_u32(&mut blob, funcs_base + 12, greet_off as u32);
        blob
    }

    /// Builds a little-endian go1.20 pclntab (ptrSize 8) with one function per name, each at PC `0x10 + i*0x10`.
    fn synthetic_go120_named(names: &[&str]) -> Vec<u8> {
        let ptr = 8usize;
        let header_len = 8 + 8 * ptr;
        let funcname_base = header_len;
        let mut nametab = vec![0u8]; // reserved empty name at offset 0
        let mut name_offs = Vec::new();
        for name in names {
            name_offs.push(nametab.len());
            nametab.extend_from_slice(name.as_bytes());
            nametab.push(0);
        }
        let functab_base = funcname_base + nametab.len();
        let functab_len = (names.len() * 2 + 1) * 4;
        let funcs_base = functab_base + functab_len;
        let mut blob = vec![0u8; funcs_base + names.len() * 8];
        blob[0..4].copy_from_slice(&MAGIC_GO120.to_le_bytes());
        blob[6] = 1; // minLC
        blob[7] = 8; // ptrSize
        blob[8..16].copy_from_slice(&(names.len() as u64).to_le_bytes());
        blob[32..40].copy_from_slice(&(funcname_base as u64).to_le_bytes());
        blob[64..72].copy_from_slice(&(functab_base as u64).to_le_bytes());
        blob[funcname_base..funcname_base + nametab.len()].copy_from_slice(&nametab);
        let put = |blob: &mut [u8], at: usize, value: u32| blob[at..at + 4].copy_from_slice(&value.to_le_bytes());
        for (index, &name_off) in name_offs.iter().enumerate() {
            let entry_pc = 0x10 + index as u32 * 0x10;
            let func_off = (funcs_base - functab_base) + index * 8;
            put(&mut blob, functab_base + index * 8, entry_pc);
            put(&mut blob, functab_base + index * 8 + 4, func_off as u32);
            put(&mut blob, funcs_base + index * 8, entry_pc);
            put(&mut blob, funcs_base + index * 8 + 4, name_off as u32);
        }
        put(&mut blob, functab_base + names.len() * 8, 0x10 + names.len() as u32 * 0x10); // sentinel
        blob
    }

    #[test]
    fn scan_finds_an_embedded_table_amid_noise() {
        let names: Vec<String> = (0..20).map(|index| format!("pkg.fn{index}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let table = synthetic_go120_named(&refs);
        // Pointer-aligned noise before and after; neither looks like a header.
        let mut blob = vec![0xAAu8; 32];
        blob.extend_from_slice(&table);
        blob.extend_from_slice(&[0x55u8; 40]);
        let report = scan_blob(&blob, 0x401000, 8, false).expect("scan finds the table");
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(report.functions.len(), 20);
        assert_eq!(report.functions[0].name, "pkg.fn0");
        assert_eq!(report.functions[0].address, 0x401000 + 0x10);
    }

    #[test]
    fn scan_declines_magic_shaped_noise_and_too_small_tables() {
        // A valid header prefix over garbage parses to nothing useful, so it is declined.
        let mut blob = vec![0u8; 256];
        blob[0..4].copy_from_slice(&MAGIC_GO120.to_le_bytes());
        blob[6] = 1;
        blob[7] = 8;
        blob[8] = 5;
        assert!(scan_blob(&blob, 0x401000, 8, false).is_none());
        // A clean table with too few functions is below the scan's trust threshold.
        let small = synthetic_go120_named(&["main.main", "main.greet"]);
        assert!(scan_blob(&small, 0x401000, 8, false).is_none());
        // No header anywhere: nothing found, no panic on any truncation.
        let plain = b"not a go table, just some read-only strings and data".to_vec();
        assert!(scan_blob(&plain, 0x401000, 8, false).is_none());
        for end in 0..small.len() {
            let _ = scan_blob(&small[..end], 0x401000, 8, false);
        }
    }

    #[test]
    fn parses_synthetic_go120_table() {
        let blob = synthetic_go120();
        let report = parse(&blob, 0x401000, 8, false);
        assert!(report.warnings.is_empty(), "unexpected warnings: {:?}", report.warnings);
        assert_eq!(
            report.functions,
            vec![
                GoFunction { address: 0x401010, name: "main.main".to_owned() },
                GoFunction { address: 0x401040, name: "main.greet".to_owned() },
            ]
        );
    }

    #[test]
    fn non_pclntab_bytes_yield_no_functions_and_no_panic() {
        let report = parse(b"this is not a go pclntab at all, just text", 0x1000, 8, false);
        assert!(report.functions.is_empty());
        assert_eq!(report.warnings.len(), 1);
    }

    #[test]
    fn empty_input_is_handled_cleanly() {
        let report = parse(&[], 0, 8, false);
        assert!(report.functions.is_empty());
    }

    #[test]
    fn wrong_pointer_size_bails_cleanly() {
        let blob = synthetic_go120();
        // The blob is a ptrSize-8 table; claiming a 4-byte image must be rejected, not misread.
        let report = parse(&blob, 0x401000, 4, false);
        assert!(report.functions.is_empty());
        assert_eq!(report.warnings.len(), 1);
    }

    #[test]
    fn wrong_endianness_is_not_mistaken_for_a_table() {
        let blob = synthetic_go120();
        let report = parse(&blob, 0x401000, 8, true);
        assert!(report.functions.is_empty());
    }

    #[test]
    fn truncated_table_recovers_nothing_without_panicking() {
        let blob = synthetic_go120();
        for end in 0..blob.len() {
            let _ = parse(&blob[..end], 0x401000, 8, false);
        }
    }
}
