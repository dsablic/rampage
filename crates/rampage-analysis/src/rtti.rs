//! Recover C++ class names and base-class edges from RTTI data in stripped binaries.
//!
//! This complements the symbol-driven path in [`crate::classes`]: when a binary carries no named vtable or
//! typeinfo symbols, the compiler-emitted RTTI structures in its data still name the classes and spell out the
//! inheritance graph. The core is a pure function over a mapped image (byte ranges with virtual addresses,
//! pointer width and endianness), so it is unit-testable with hand-built little-endian 32- and 64-bit blobs.
//! [`recover`] adapts a loaded [`Binary`] to that core, returning a checked limitation when its format,
//! pointer width or ABI cannot be inspected. An unsupported source is not an examined zero-class result.
//!
//! The scan is deliberately conservative to avoid naming non-C++ data: every followed pointer must land in a
//! mapped range, every type name must demangle through the project's existing demanglers, and the work is
//! bounded by fixed caps.

use std::collections::BTreeMap;

use rampage_loaders::{Binary, Format, SectionKind};
use serde::Serialize;

/// Largest file-backed span taken from any one section.
const MAX_SECTION_BYTES: u64 = 64 * 1024 * 1024;
/// Upper bound on emitted classes.
const MAX_RECORDS: usize = 65_536;
/// Upper bound on pointer-aligned positions probed in one range. Per range, so a large leading range cannot starve
/// the ones after it; the total stays bounded by the file-backed bytes.
const MAX_SCAN_POSITIONS: usize = 8_000_000;
/// Upper bound on base entries considered for one class.
const MAX_BASES: usize = 1024;
/// Upper bound on a mangled type-name string.
const MAX_NAME_BYTES: usize = 4096;
/// A candidate vtable pointer shared by at least this many Itanium records is treated as a typeinfo category
/// vtable even when it cannot be dereferenced (its target is an unresolved external in a stripped image).
const MIN_SHARED_VTABLE: usize = 3;

/// Why the top-level native RTTI adapter did not inspect a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RttiLimitation {
    UnknownPointerWidth,
    UnsupportedPointerWidth(u8),
    UnsupportedFormat(Format),
    UnsupportedMips64N32Abi,
}

impl std::fmt::Display for RttiLimitation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPointerWidth => formatter.write_str("RTTI pointer width is unknown"),
            Self::UnsupportedPointerWidth(width) => {
                write!(formatter, "RTTI pointer width {width} bytes is unsupported; expected 4 or 8")
            }
            Self::UnsupportedFormat(format) => {
                write!(formatter, "RTTI recovery is unsupported for {format:?} images")
            }
            Self::UnsupportedMips64N32Abi => formatter.write_str("unsupported MIPS64 ELFCLASS32/N32 RTTI pointer ABI"),
        }
    }
}

impl std::error::Error for RttiLimitation {}

/// A recovered class: its demangled name, the raw RTTI name, and the demangled direct base-class edges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RttiClass {
    pub name: String,
    /// The raw type name found in the image (an Itanium mangled fragment, or an MSVC `.?A...` name).
    pub mangled: String,
    pub abi: &'static str,
    /// Virtual address of the record the name was read from (Itanium typeinfo, or MSVC TypeDescriptor).
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub type_info: u64,
    pub bases: Vec<String>,
    pub source: &'static str,
}

/// A read-only mapped byte range at a virtual address.
pub struct MappedRange<'a> {
    pub vaddr: u64,
    pub bytes: &'a [u8],
}

/// A mapped image presented to the parsers: byte ranges plus the ABI's pointer width and endianness.
pub struct Image<'a> {
    /// Sorted by start address.
    ranges: Vec<MappedRange<'a>>,
    pointer_size: u8,
    big_endian: bool,
}

impl<'a> Image<'a> {
    pub fn new(mut ranges: Vec<MappedRange<'a>>, pointer_size: u8, big_endian: bool) -> Self {
        ranges.sort_by_key(|range| range.vaddr);
        Image { ranges, pointer_size, big_endian }
    }

    /// The range holding `va` and the offset into it. With overlapping ranges, the latest-starting one wins.
    fn locate(&self, va: u64) -> Option<(&MappedRange<'a>, usize)> {
        let index = self.ranges.partition_point(|range| range.vaddr <= va).checked_sub(1)?;
        let range = &self.ranges[index];
        let delta = va - range.vaddr;
        (delta < range.bytes.len() as u64).then_some((range, delta as usize))
    }

    fn read(&self, va: u64, len: usize) -> Option<&'a [u8]> {
        let (range, offset) = self.locate(va)?;
        range.bytes.get(offset..offset.checked_add(len)?)
    }

    fn mapped(&self, va: u64) -> bool {
        self.locate(va).is_some()
    }

    fn read_u32(&self, va: u64) -> Option<u32> {
        let bytes: [u8; 4] = self.read(va, 4)?.try_into().ok()?;
        Some(if self.big_endian { u32::from_be_bytes(bytes) } else { u32::from_le_bytes(bytes) })
    }

    fn read_pointer(&self, va: u64) -> Option<u64> {
        let bytes = self.read(va, usize::from(self.pointer_size))?;
        let fold = |value: u64, &byte: &u8| value << 8 | u64::from(byte);
        Some(if self.big_endian { bytes.iter().fold(0, fold) } else { bytes.iter().rev().fold(0, fold) })
    }

    /// NUL-terminated bytes at `va`, excluding the NUL, searching at most `max` bytes.
    fn read_cstr(&self, va: u64, max: usize) -> Option<&'a [u8]> {
        let (range, offset) = self.locate(va)?;
        let slice = &range.bytes[offset..];
        let end = slice.iter().take(max).position(|&byte| byte == 0)?;
        Some(&slice[..end])
    }

    fn pointer_width(&self) -> u64 {
        u64::from(self.pointer_size)
    }

    /// Visits each pointer-aligned position in every range, honouring a per-range probe budget.
    fn for_each_aligned(&self, stride: u64, min_len: u64, mut visit: impl FnMut(u64)) {
        for range in &self.ranges {
            let len = range.bytes.len() as u64;
            if len < min_len {
                continue;
            }
            let start = (stride - range.vaddr % stride) % stride;
            let mut offset = start;
            let mut budget = MAX_SCAN_POSITIONS;
            while offset + min_len <= len {
                if budget == 0 {
                    break;
                }
                budget -= 1;
                visit(range.vaddr + offset);
                offset += stride;
            }
        }
    }
}

/// A virtual address `delta` bytes past `base`, or `None` on overflow. Record offsets are applied to
/// cross-referenced addresses read out of the image, so a crafted binary must not be able to wrap them.
fn va_at(base: u64, delta: u64) -> Option<u64> {
    base.checked_add(delta)
}

#[derive(Clone)]
struct ItaniumCandidate {
    vtable: u64,
    mangled: String,
    name: String,
}

/// Reads and validates the name string of an Itanium typeinfo record.
fn itanium_name(image: &Image, name_va: u64) -> Option<(String, String)> {
    let raw = image.read_cstr(name_va, MAX_NAME_BYTES)?;
    let raw = std::str::from_utf8(raw).ok()?;
    // GCC prefixes an internal-linkage type's name with `*` (compare by address); it is not part of the mangling.
    let raw = raw.strip_prefix('*').unwrap_or(raw);
    // Cheap pre-filter before demangling: a class typeinfo name is a length-prefixed (`4Base`), nested (`N...E`),
    // `std::` (`St9exception`) or local (`Z4mainE5Local`) mangling.
    let first = *raw.as_bytes().first()?;
    let shaped = first.is_ascii_digit() || first == b'N' || first == b'Z' || raw.starts_with("St");
    if !shaped || !raw.bytes().all(|byte| byte.is_ascii_graphic()) {
        return None;
    }
    let demangled = crate::language::demangle(&format!("_ZTS{raw}"))?;
    let name = demangled.strip_prefix("typeinfo name for ")?;
    (!name.is_empty()).then(|| (raw.to_owned(), name.to_owned()))
}

/// Collects positions shaped like an Itanium typeinfo header `[vtable_ptr, name_ptr]`.
fn itanium_candidates(image: &Image) -> BTreeMap<u64, ItaniumCandidate> {
    let width = image.pointer_width();
    let mut candidates = BTreeMap::new();
    image.for_each_aligned(width, 2 * width, |address| {
        if candidates.len() >= MAX_RECORDS {
            return;
        }
        let Some(name_slot) = va_at(address, width) else {
            return;
        };
        let (Some(vtable), Some(name_raw)) = (image.read_pointer(address), image.read_pointer(name_slot)) else {
            return;
        };
        // 64-bit Darwin sets bit 63 of the typeinfo name pointer to flag a non-unique type name. The flagged
        // form is tried only after the plain one, since 32-bit images may genuinely live above 0x8000_0000.
        let non_unique = 1u64 << 63;
        let name = itanium_name(image, name_raw).or_else(|| {
            (image.pointer_size == 8 && name_raw & non_unique != 0)
                .then(|| itanium_name(image, name_raw & !non_unique))
                .flatten()
        });
        if let Some((mangled, name)) = name {
            candidates.insert(address, ItaniumCandidate { vtable, mangled, name });
        }
    });
    candidates
}

/// Whether `va` holds C string data: at least four printable ASCII bytes before a NUL. A vtable address point holds
/// code pointers, whose bytes never read that way (their high bytes are zero or non-printable).
fn is_string_data(image: &Image, va: u64) -> bool {
    image
        .read_cstr(va, MAX_NAME_BYTES)
        .is_some_and(|text| text.len() >= 4 && text.iter().all(|&byte| byte == b' ' || byte.is_ascii_graphic()))
}

/// Keeps candidates whose vtable pointer is an aligned, mapped address that is not string data, or is shared by
/// enough records to be a category vtable.
fn accept_itanium(image: &Image, candidates: BTreeMap<u64, ItaniumCandidate>) -> BTreeMap<u64, ItaniumCandidate> {
    let mut frequency: BTreeMap<u64, usize> = BTreeMap::new();
    for candidate in candidates.values() {
        *frequency.entry(candidate.vtable).or_default() += 1;
    }
    candidates
        .into_iter()
        .filter(|(_, candidate)| {
            let vtable = candidate.vtable;
            // A genuine typeinfo vtable pointer targets a vtable, never string data: a table of string pointers
            // (`{"des-ede3-cbc", "3des"}`) otherwise reads as `[vtable, name]` whenever the second name demangles.
            if vtable != 0 && (itanium_name(image, vtable).is_some() || is_string_data(image, vtable)) {
                return false;
            }
            (vtable != 0 && vtable.is_multiple_of(image.pointer_width()) && image.mapped(vtable))
                || frequency.get(&vtable).copied().unwrap_or(0) >= MIN_SHARED_VTABLE
        })
        .collect()
}

/// Base edges from a `__vmi_class_type_info` record, or `None` when the layout does not fully validate.
fn itanium_vmi_bases(image: &Image, address: u64, accepted: &BTreeMap<u64, ItaniumCandidate>) -> Option<Vec<String>> {
    let width = image.pointer_width();
    let count = image.read_u32(va_at(address, 2 * width + 4)?)?;
    if count == 0 || count as usize > MAX_BASES {
        return None;
    }
    let array = va_at(address, 2 * width + 8)?;
    let mut bases = Vec::with_capacity(count as usize);
    for index in 0..u64::from(count) {
        let entry = array.checked_add(index.checked_mul(2 * width)?)?;
        let base_ti = image.read_pointer(entry)?;
        bases.push(accepted.get(&base_ti)?.name.clone());
    }
    Some(bases)
}

/// Direct base-class names for an Itanium record, from its `__si`/`__vmi` inheritance variant.
fn itanium_bases(image: &Image, address: u64, accepted: &BTreeMap<u64, ItaniumCandidate>, own: &str) -> Vec<String> {
    let width = image.pointer_width();
    let single = va_at(address, 2 * width).and_then(|va| image.read_pointer(va)).and_then(|base| accepted.get(&base));
    if let Some(single) = single {
        return dedup_bases(vec![single.name.clone()], own);
    }
    match itanium_vmi_bases(image, address, accepted) {
        Some(bases) => dedup_bases(bases, own),
        None => Vec::new(),
    }
}

/// Recovers Itanium (ELF/Mach-O) classes from a mapped image.
pub fn recover_itanium(image: &Image) -> Vec<RttiClass> {
    let accepted = accept_itanium(image, itanium_candidates(image));
    let mut classes = Vec::new();
    for (&address, candidate) in &accepted {
        let bases = itanium_bases(image, address, &accepted, &candidate.name);
        classes.push(RttiClass {
            name: candidate.name.clone(),
            mangled: candidate.mangled.clone(),
            abi: "itanium",
            type_info: address,
            bases,
            source: "rtti_scan",
        });
        if classes.len() >= MAX_RECORDS {
            break;
        }
    }
    classes
}

/// Resolves an MSVC RTTI cross-reference: a full pointer for 32-bit (signature 0), an image-relative RVA for
/// 64-bit (signature 1).
fn msvc_resolve(signature: u32, image_base: u64, field: u32) -> u64 {
    // A wrapped address lands outside every mapped range, so the later read fails cleanly; never panics.
    if signature == 1 { image_base.saturating_add(u64::from(field)) } else { u64::from(field) }
}

/// Reads an MSVC `TypeDescriptor` and returns its raw `.?A...` name and the demangled class name.
fn msvc_type_descriptor(image: &Image, address: u64) -> Option<(String, String)> {
    let vftable = image.read_pointer(address)?;
    if vftable == 0 || !image.mapped(vftable) {
        return None;
    }
    let name_va = va_at(address, 2 * image.pointer_width())?;
    let raw = image.read_cstr(name_va, MAX_NAME_BYTES)?;
    let raw = std::str::from_utf8(raw).ok()?;
    if !raw.starts_with(".?A") || !raw.bytes().all(|byte| byte.is_ascii_graphic()) {
        return None;
    }
    // The RTTI type descriptor name demangles once reframed as a `??_R0` type-descriptor symbol.
    let demangled = crate::language::demangle(&format!("??_R0{}@8", &raw[1..]))?;
    let name = demangled.strip_suffix("::`RTTI Type Descriptor'")?;
    let name = strip_msvc_keyword(name);
    (!name.is_empty()).then(|| (raw.to_owned(), name.to_owned()))
}

fn strip_msvc_keyword(name: &str) -> &str {
    for keyword in ["class ", "struct ", "union ", "enum ", "coclass ", "cointerface "] {
        if let Some(rest) = name.strip_prefix(keyword) {
            return rest;
        }
    }
    name
}

/// Direct base-class names from an MSVC `ClassHierarchyDescriptor`, or `None` when the hierarchy does not
/// validate.
///
/// The base class array flattens the whole hierarchy in pre-order: entry 0 is the class itself and each
/// `BaseClassDescriptor` is followed by its own `numContainedBases` bases. Direct bases are therefore the entries
/// reached from index 1 by skipping each entry's contained subtree.
fn msvc_bases(image: &Image, chd: u64, signature: u32, image_base: u64, own: &str) -> Option<Vec<String>> {
    let count = image.read_u32(va_at(chd, 8)?)?;
    if count == 0 || count as usize > MAX_BASES {
        return None;
    }
    let array = msvc_resolve(signature, image_base, image.read_u32(va_at(chd, 12)?)?);
    let mut bases = Vec::new();
    let mut index = 1;
    while index < count {
        let slot = array.checked_add(u64::from(index).checked_mul(4)?)?;
        let descriptor = msvc_resolve(signature, image_base, image.read_u32(slot)?);
        let type_descriptor = msvc_resolve(signature, image_base, image.read_u32(descriptor)?);
        let contained = image.read_u32(va_at(descriptor, 4)?)?;
        if contained >= count - index {
            return None;
        }
        let (_, name) = msvc_type_descriptor(image, type_descriptor)?;
        bases.push(name);
        index += 1 + contained;
    }
    Some(dedup_bases(bases, own))
}

/// Parses a Complete Object Locator at `address`, returning the class it describes.
fn msvc_complete_object_locator(image: &Image, address: u64) -> Option<RttiClass> {
    let signature = image.read_u32(address)?;
    // x86 locators hold absolute pointers (signature 0) and x64 ones image-relative RVAs (signature 1).
    if signature != u32::from(image.pointer_size == 8) {
        return None;
    }
    let image_base = if signature == 1 {
        // The self RVA in a 64-bit locator recovers the image base without any external knowledge; a PE image
        // base is always 64 KiB aligned, which rejects most chance matches.
        let base = address.checked_sub(u64::from(image.read_u32(va_at(address, 20)?)?))?;
        if !base.is_multiple_of(0x1_0000) {
            return None;
        }
        base
    } else {
        0
    };
    let type_descriptor = msvc_resolve(signature, image_base, image.read_u32(va_at(address, 12)?)?);
    let hierarchy = msvc_resolve(signature, image_base, image.read_u32(va_at(address, 16)?)?);
    let (mangled, name) = msvc_type_descriptor(image, type_descriptor)?;
    let bases = msvc_bases(image, hierarchy, signature, image_base, &name)?;
    Some(RttiClass { name, mangled, abi: "msvc", type_info: type_descriptor, bases, source: "rtti_scan" })
}

/// Recovers MSVC (PE) classes from a mapped image.
pub fn recover_msvc(image: &Image) -> Vec<RttiClass> {
    let mut classes = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    // A 32-bit locator spans five dwords (signature..pClassDescriptor); a 64-bit one adds the self RVA.
    let locator_len = if image.pointer_size == 8 { 24 } else { 20 };
    image.for_each_aligned(4, locator_len, |address| {
        if classes.len() >= MAX_RECORDS {
            return;
        }
        if let Some(class) = msvc_complete_object_locator(image, address)
            && seen.insert(class.type_info)
        {
            classes.push(class);
        }
    });
    classes
}

fn dedup_bases(bases: Vec<String>, own: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    bases.into_iter().filter(|base| base != own && seen.insert(base.clone())).collect()
}

/// Builds a mapped image from a binary's file-backed data sections. RTTI records, type names and the vtables they
/// point to are data; code and other sections are left out, so they neither cost scan budget nor validate a
/// pointer.
fn build_image(binary: &Binary, pointer_size: u8) -> Image<'_> {
    let mut ranges = Vec::new();
    for section in &binary.sections {
        if !matches!(section.kind, SectionKind::Data | SectionKind::ReadOnlyData) || section.file_offset.is_none() {
            continue;
        }
        let len = section.file_size.min(section.size).min(MAX_SECTION_BYTES);
        if len == 0 || section.address.checked_add(len).is_none() {
            continue;
        }
        if let Some(bytes) = binary.read(section.address, len) {
            ranges.push(MappedRange { vaddr: section.address, bytes });
        }
    }
    // PE is always little-endian; Itanium images follow the loaded byte order.
    Image::new(ranges, pointer_size, binary.big_endian && binary.format != Format::Pe)
}

fn checked_pointer_size(format: Format, pointer_size: Option<u8>, mips64_n32: bool) -> Result<u8, RttiLimitation> {
    if !matches!(format, Format::Elf | Format::MachO | Format::Pe) {
        return Err(RttiLimitation::UnsupportedFormat(format));
    }
    let pointer_size = match pointer_size {
        None => return Err(RttiLimitation::UnknownPointerWidth),
        Some(width @ (4 | 8)) => width,
        Some(width) => return Err(RttiLimitation::UnsupportedPointerWidth(width)),
    };
    if mips64_n32 {
        return Err(RttiLimitation::UnsupportedMips64N32Abi);
    }
    Ok(pointer_size)
}

/// Recovers classes from bounded, file-backed RTTI data, independent of symbols.
///
/// `Err` means the source was not admitted for inspection. `Ok`, including an empty vector, is a result
/// over the existing bounded mapped-data view, not completeness or source/layout proof. No eligible ranges
/// is an empty scan. Existing malformed-record skips and scan budgets are unchanged.
pub fn recover(binary: &Binary) -> Result<Vec<RttiClass>, RttiLimitation> {
    let pointer_size =
        checked_pointer_size(binary.format, binary.arch.default_pointer_size(), crate::classes::is_mips64_n32(binary))?;
    let image = build_image(binary, pointer_size);
    Ok(if binary.format == Format::Pe { recover_msvc(&image) } else { recover_itanium(&image) })
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn unknown_pointer_width_cannot_inherit_a_machine_address_width() {
        assert_eq!(checked_pointer_size(Format::Elf, None, false), Err(RttiLimitation::UnknownPointerWidth));
        for width in [0, 1, 2, 16] {
            assert_eq!(
                checked_pointer_size(Format::Elf, Some(width), false),
                Err(RttiLimitation::UnsupportedPointerWidth(width)),
            );
        }
        assert_eq!(checked_pointer_size(Format::Elf, Some(4), false), Ok(4));
        assert_eq!(checked_pointer_size(Format::MachO, Some(8), false), Ok(8));
        assert_eq!(checked_pointer_size(Format::Pe, Some(4), false), Ok(4));
    }

    #[test]
    fn unsupported_format_and_abi_are_distinct_from_an_empty_scan() {
        assert_eq!(
            checked_pointer_size(Format::Snapshot, Some(8), false),
            Err(RttiLimitation::UnsupportedFormat(Format::Snapshot)),
        );
        assert_eq!(checked_pointer_size(Format::Elf, Some(8), true), Err(RttiLimitation::UnsupportedMips64N32Abi),);
    }
}
