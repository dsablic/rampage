//! Bounded EHABI range-start candidates, not proof of function boundaries: fragments and coalesced ranges
//! cannot be distinguished here. This deliberately does not interpret unwind instructions or change ARM mode.

use object::read::elf::{FileHeader, SectionHeader};
use object::{Object, elf};
use rampage_arch::bytes::read_uint;

use crate::Binary;

const MAX_SECTION_HEADERS: usize = 65_536;
const MAX_TABLES: usize = 64;
const MAX_RECORDS: usize = 1_048_576;
const MAX_WARNINGS: usize = 16;

pub(crate) struct ArmExidxTables {
    tables: Vec<Table>,
    storage: Vec<Storage>,
}

struct Table {
    storage: Storage,
    code: Storage,
}

struct Storage {
    address: u64,
    size: u64,
    file_offset: u64,
}

/// Retain the native section type, flags and linked code backing before dropping the parsed ELF object.
/// Names are intentionally not involved in admission, and relocatable/unlinked images are not supported.
pub(crate) fn arm_exidx_tables(parsed: &object::File, warnings: &mut Vec<String>) -> Option<ArmExidxTables> {
    let object::File::Elf32(file) = parsed else { return None };
    let endian = file.endian();
    if parsed.architecture() != object::Architecture::Arm
        || !matches!(file.elf_header().e_type(endian), elf::ET_EXEC | elf::ET_DYN)
    {
        return None;
    }
    let sections = file.elf_section_table();
    let mut tables = Vec::new();
    let mut storage = Vec::new();
    let mut issues = Vec::new();
    if sections.len() > MAX_SECTION_HEADERS {
        warn(&mut issues, "section-header budget exhausted; later sections ignored".into());
    }
    for section in sections.iter().take(MAX_SECTION_HEADERS) {
        let flags = section.sh_flags(endian);
        if flags.contains(elf::SHF_COMPRESSED) || !flags.contains(elf::SHF_ALLOC) {
            if section.sh_type(endian) == elf::SHT_ARM_EXIDX {
                warn(&mut issues, "table is not allocated uncompressed storage; ignored".into());
            }
            continue;
        }
        let area = Storage {
            address: u64::from(section.sh_addr(endian)),
            size: u64::from(section.sh_size(endian)),
            file_offset: u64::from(section.sh_offset(endian)),
        };
        if section.sh_type(endian) == elf::SHT_PROGBITS && !flags.contains(elf::SHF_EXECINSTR) {
            storage.push(area);
            continue;
        }
        if section.sh_type(endian) != elf::SHT_ARM_EXIDX {
            continue;
        }
        if !flags.contains(elf::SHF_ALLOC | elf::SHF_LINK_ORDER) {
            warn(&mut issues, "table lacks allocated link-order flags; ignored".into());
            continue;
        }
        if tables.len() == MAX_TABLES {
            warn(&mut issues, "table budget exhausted; later tables ignored".into());
            continue;
        }
        let linked = sections.section(object::SectionIndex(section.sh_link(endian) as usize));
        let code = linked.ok().filter(|linked| {
            linked.sh_type(endian) == elf::SHT_PROGBITS
                && linked.sh_flags(endian).contains(elf::SHF_ALLOC | elf::SHF_EXECINSTR)
                && !linked.sh_flags(endian).contains(elf::SHF_COMPRESSED)
        });
        let Some(code) = code else {
            warn(&mut issues, "table has no linked allocated executable section; ignored".into());
            continue;
        };
        let code = Storage {
            address: u64::from(code.sh_addr(endian)),
            size: u64::from(code.sh_size(endian)),
            file_offset: u64::from(code.sh_offset(endian)),
        };
        if !area.address.is_multiple_of(4)
            || !area.file_offset.is_multiple_of(4)
            || section.sh_addralign(endian) < 4
            || !section.sh_addralign(endian).is_power_of_two()
            || !area.size.is_multiple_of(8)
            || !matches!(section.sh_entsize(endian), 0 | 8)
            || !elf32_range(area.address, area.size)
            || code.size == 0
            || !elf32_range(code.address, code.size)
        {
            warn(&mut issues, "table layout or linked code range is malformed; ignored".into());
            continue;
        }
        tables.push(Table { storage: area, code });
    }
    storage.sort_unstable_by_key(|area| area.address);
    warnings.extend(issues);
    Some(ArmExidxTables { tables, storage })
}

/// Decode only the compact forms whose complete storage is bounded here. Unsupported forms remain warnings;
/// address corruption stops that table at its valid prefix, just like the `.eh_frame` reader.
pub(crate) fn arm_exidx(binary: &Binary, tables: &ArmExidxTables) -> (Vec<u64>, Vec<String>) {
    read_tables(binary, tables, MAX_RECORDS)
}

fn read_tables(binary: &Binary, tables: &ArmExidxTables, mut remaining: usize) -> (Vec<u64>, Vec<String>) {
    let mut starts = Vec::new();
    let mut warnings = Vec::new();
    for table in &tables.tables {
        let Some(bytes) = mapped_storage(binary, &table.storage, table.storage.address, table.storage.size) else {
            warn(
                &mut warnings,
                "table is not fully readable/file-backed with matching VA/file mapping; ignored".into(),
            );
            continue;
        };
        let mut previous = None;
        for (index, record) in bytes.as_chunks::<8>().0.iter().take(remaining).enumerate() {
            remaining -= 1;
            let field = table.storage.address + index as u64 * 8;
            let raw = word(record, binary.big_endian);
            let Some(address) = (raw & 0x8000_0000 == 0).then(|| prel31(raw, field)).flatten() else {
                warn(&mut warnings, format!("malformed code PREL31 at {field:#x}; later entries ignored"));
                break;
            };
            let address = address & !1;
            if previous.is_some_and(|previous| address <= previous) {
                warn(&mut warnings, format!("non-increasing code address at {field:#x}; later entries ignored"));
                break;
            }
            previous = Some(address);
            let unwind = word(&record[4..], binary.big_endian);
            if unwind == 1 {
                continue;
            }
            // The linked section's end is commonly an EHABI sentinel, never an instruction address.
            let mode_index = binary.thumb.partition_point(|range| range.end <= address);
            let thumb = binary.thumb.get(mode_index).is_some_and(|range| range.contains(&address));
            let alignment = if thumb { 2 } else { 4 };
            if address % alignment != 0
                || !binary.is_code(address)
                || !binary.segment_containing(address).is_some_and(|segment| segment.perms.execute)
                || mapped_storage(binary, &table.code, address, 1).is_none()
            {
                warn(
                    &mut warnings,
                    format!("code candidate {address:#x} is outside readable linked code or misaligned"),
                );
                continue;
            }
            if unwind >> 24 == 0x80 {
                starts.push(address);
            } else if unwind & 0x8000_0000 == 0 {
                if supported_extab(binary, tables, unwind, field + 4) {
                    starts.push(address);
                } else {
                    warn(&mut warnings, format!("unsupported or unreadable extab descriptor at {:#x}", field + 4));
                }
            } else {
                warn(&mut warnings, format!("unsupported inline unwind descriptor at {:#x}", field + 4));
            }
        }
        if remaining == 0 {
            warn(&mut warnings, "record budget exhausted; later entries ignored".into());
            break;
        }
    }
    if !starts.is_empty() {
        warnings.truncate(MAX_WARNINGS - 1);
        warnings.insert(
            0,
            "ARM EHABI: range starts are candidates, not proven function boundaries; \
            fragments and coalesced ranges are possible"
                .into(),
        );
    }
    (starts, warnings)
}

fn supported_extab(binary: &Binary, tables: &ArmExidxTables, unwind: u32, field: u64) -> bool {
    let Some(address) = prel31(unwind, field).filter(|address| address % 4 == 0) else { return false };
    let index = tables.storage.partition_point(|area| area.address <= address);
    let Some(area) = index.checked_sub(1).and_then(|index| tables.storage.get(index)) else { return false };
    let Some(header) = mapped_storage(binary, area, address, 4) else { return false };
    let header = word(header, binary.big_endian);
    let size = match header >> 24 {
        0x80 => 4,
        0x81 => 4 * (1 + u64::from((header >> 16) & 0xff)),
        _ => return false,
    };
    mapped_storage(binary, area, address, size).is_some()
}

fn word(bytes: &[u8], big_endian: bool) -> u32 {
    read_uint(bytes, 0, 4, big_endian).unwrap() as u32
}

/// PREL31 is signed in bit 30, relative to this word (not its record), without ELF32 wraparound.
fn prel31(value: u32, field: u64) -> Option<u64> {
    let field = u32::try_from(field).ok()?;
    let delta = ((value << 1) as i32 >> 1) as i64;
    u32::try_from(i64::from(field) + delta).ok().map(u64::from)
}

fn elf32_range(address: u64, size: u64) -> bool {
    address <= u64::from(u32::MAX) && address.checked_add(size).is_some_and(|end| end <= u64::from(u32::MAX) + 1)
}

fn readable(binary: &Binary, address: u64, size: u64) -> bool {
    binary.segment_containing(address).is_some_and(|segment| segment.perms.read)
        && elf32_range(address, size)
        && binary.read(address, size).is_some()
}

fn mapped_storage<'a>(binary: &'a Binary, area: &Storage, address: u64, size: u64) -> Option<&'a [u8]> {
    let offset = address.checked_sub(area.address)?;
    if offset.checked_add(size)? > area.size || !readable(binary, address, size) {
        return None;
    }
    let segment = binary.segment_containing(address)?;
    if segment.file_offset.checked_add(address - segment.address)? != area.file_offset.checked_add(offset)? {
        return None;
    }
    binary.read(address, size)
}

fn warn(warnings: &mut Vec<String>, message: String) {
    if warnings.len() < MAX_WARNINGS {
        warnings.push(format!("ARM EHABI: {message}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Perms, Section, SectionKind, Segment};
    use rampage_arch::Arch;

    fn encoded(target: u64, field: u64) -> u32 {
        ((target as i64 - field as i64) as u32) & 0x7fff_ffff
    }

    fn put_word(bytes: &mut [u8], offset: usize, value: u32, big_endian: bool) {
        let value = if big_endian { value.to_be_bytes() } else { value.to_le_bytes() };
        bytes[offset..offset + 4].copy_from_slice(&value);
    }

    fn fixture(records: &[(u64, u32)], extab: &[u32], big_endian: bool, thumb: bool) -> (Binary, ArmExidxTables) {
        fixture_with_data(records, extab, big_endian, thumb, |_| {})
    }

    fn fixture_with_data(
        records: &[(u64, u32)],
        extab: &[u32],
        big_endian: bool,
        thumb: bool,
        edit: impl FnOnce(&mut [u8]),
    ) -> (Binary, ArmExidxTables) {
        let mut data = vec![0; 0x200];
        for (index, &(address, unwind)) in records.iter().enumerate() {
            let offset = 0x80 + index * 8;
            put_word(&mut data, offset, encoded(address, 0x1000 + offset as u64), big_endian);
            put_word(&mut data, offset + 4, unwind, big_endian);
        }
        for (index, &value) in extab.iter().enumerate() {
            put_word(&mut data, 0x100 + index * 4, value, big_endian);
        }
        edit(&mut data);
        let binary = Binary::from_snapshot(
            Arch::Arm,
            false,
            big_endian,
            "EHABI unit test".into(),
            data,
            Vec::new(),
            vec![Segment {
                name: String::new(),
                address: 0x1000,
                size: 0x200,
                file_offset: 0,
                file_size: 0x200,
                perms: Perms { read: true, write: false, execute: true },
            }],
            vec![Section {
                name: ".text".into(),
                address: 0x1000,
                size: 0x40,
                kind: SectionKind::Code,
                file_offset: Some(0),
                file_size: 0x40,
            }],
            if thumb { std::iter::once(0x1000..0x1040).collect() } else { Vec::new() },
            Vec::new(),
            None,
        )
        .unwrap();
        let tables = ArmExidxTables {
            tables: vec![Table {
                storage: Storage { address: 0x1080, size: records.len() as u64 * 8, file_offset: 0x80 },
                code: Storage { address: 0x1000, size: 0x40, file_offset: 0 },
            }],
            storage: vec![Storage { address: 0x1100, size: extab.len() as u64 * 4, file_offset: 0x100 }],
        };
        (binary, tables)
    }

    #[test]
    fn prel31_is_signed_field_relative_and_never_wraps_elf32() {
        assert_eq!(prel31(0x7fff_fff0, 0x1000), Some(0xff0));
        assert_eq!(prel31(0x4000_0000, 0x4000_0000), Some(0));
        assert_eq!(prel31(0x3fff_ffff, 0), Some(0x3fff_ffff));
        assert_eq!(prel31(0x7fff_ffff, 0), None);
        assert_eq!(prel31(4, u64::from(u32::MAX) - 3), None);
        assert_eq!(prel31(0, u64::from(u32::MAX) + 1), None);
    }

    #[test]
    fn compact_forms_use_data_endian_and_each_fields_own_base() {
        for big_endian in [false, true] {
            let records = [(0x1001, 0x80b0_b0b0), (0x1003, encoded(0x1100, 0x108c)), (0x1005, encoded(0x1104, 0x1094))];
            let (binary, tables) = fixture(&records, &[0x80b0_b0b0, 0x8101_b0b0, 0xb0b0_b0b0], big_endian, true);
            let (starts, warnings) = arm_exidx(&binary, &tables);
            assert_eq!(starts, [0x1000, 0x1002, 0x1004]);
            assert_eq!(warnings.len(), 1);
            assert!(warnings[0].contains("not proven function boundaries"));
            assert!(!binary.target().big_endian);
            assert_eq!(binary.big_endian, big_endian);
        }
    }

    #[test]
    fn extab_prel31_can_point_backwards_from_its_own_word() {
        for big_endian in [false, true] {
            let records = [(0x1000, encoded(0x1060, 0x1084))];
            let (binary, mut tables) = fixture_with_data(&records, &[], big_endian, true, |data| {
                put_word(data, 0x60, 0x80b0_b0b0, big_endian);
            });
            tables.storage = vec![Storage { address: 0x1060, size: 4, file_offset: 0x60 }];
            assert_eq!(arm_exidx(&binary, &tables).0, [0x1000]);
        }
    }

    #[test]
    fn cantunwind_and_section_end_do_not_become_starts() {
        let (binary, tables) = fixture(&[(0x1000, 1), (0x1004, 0x80b0_b0b0), (0x1040, 0x80b0_b0b0)], &[], false, true);
        let (starts, _) = arm_exidx(&binary, &tables);
        assert_eq!(starts, [0x1004]);
    }

    #[test]
    fn unsupported_forms_skip_without_hiding_later_ordered_candidates() {
        let descriptors = [0x8100_0000, 0x8200_0000, 0xff00_0000, encoded(0x1100, 0x109c)];
        let mut records: Vec<_> =
            descriptors.iter().enumerate().map(|(i, &word)| (0x1000 + i as u64 * 4, word)).collect();
        records.push((0x1010, 0x80b0_b0b0));
        for extab in [0x8200_0000, 0x0000_0000, 0xff00_0000] {
            let (binary, tables) = fixture(&records, &[extab], false, false);
            let (starts, warnings) = arm_exidx(&binary, &tables);
            assert_eq!(starts, [0x1010]);
            assert_eq!(warnings.len(), 5);
        }
    }

    #[test]
    fn duplicates_after_thumb_normalization_and_descents_stop_at_valid_prefix() {
        for next in [0x1005, 0x1000] {
            let records = [(0x1004, 0x80b0_b0b0), (next, 0x80b0_b0b0), (0x1008, 0x80b0_b0b0)];
            let (binary, tables) = fixture(&records, &[], false, true);
            let (starts, warnings) = arm_exidx(&binary, &tables);
            assert_eq!(starts, [0x1004]);
            assert!(warnings.iter().any(|warning| warning.contains("later entries ignored")));
        }
    }

    #[test]
    fn rejects_reserved_code_pointer_and_preserves_existing_thumb_mode() {
        let (binary, tables) = fixture_with_data(&[(0x1000, 0x80b0_b0b0)], &[], false, true, |data| {
            put_word(data, 0x80, 0xffff_ff80, false);
        });
        let (starts, warnings) = arm_exidx(&binary, &tables);
        assert!(starts.is_empty());
        assert!(warnings.iter().any(|warning| warning.contains("malformed code PREL31")));
        let (mut binary, tables) = fixture(&[(0x1003, 0x80b0_b0b0)], &[], false, false);
        assert!(arm_exidx(&binary, &tables).0.is_empty());
        binary.thumb.push(0x1000..0x1040);
        let before = binary.thumb.clone();
        assert_eq!(arm_exidx(&binary, &tables).0, [0x1002]);
        assert_eq!(binary.thumb, before);
        let (mut binary, tables) = fixture(&[(0x1000, 0x80b0_b0b0)], &[], false, true);
        binary.segments[0].perms.read = false;
        assert!(arm_exidx(&binary, &tables).0.is_empty());
    }

    #[test]
    fn overflowing_code_pointer_stops_at_the_valid_prefix() {
        let records = [(0x1000, 0x80b0_b0b0), (0x1004, 0x80b0_b0b0), (0x1008, 0x80b0_b0b0)];
        let (binary, tables) = fixture_with_data(&records, &[], false, true, |data| {
            put_word(data, 0x88, 0x4000_0000, false);
        });
        let (starts, warnings) = arm_exidx(&binary, &tables);
        assert_eq!(starts, [0x1000]);
        assert!(warnings.iter().any(|warning| warning.contains("malformed code PREL31")));
    }

    #[test]
    fn thumb_lookup_preserves_sorted_range_boundaries_and_arm_gaps() {
        let records: Vec<_> = (0..6).map(|index| (0x1000 + index * 2, 0x80b0_b0b0)).collect();
        let (mut binary, tables) = fixture(&records, &[], false, false);
        binary.thumb = vec![0x1000..0x1002, 0x1004..0x1006];
        let (starts, _) = arm_exidx(&binary, &tables);
        assert_eq!(starts, [0x1000, 0x1004, 0x1008]);
        assert_eq!(binary.thumb, [0x1000..0x1002, 0x1004..0x1006]);
    }

    #[test]
    fn truncated_or_mismapped_tables_are_not_partially_admitted() {
        let (mut binary, mut tables) = fixture(&[(0x1000, 0x80b0_b0b0), (0x1004, 0x80b0_b0b0)], &[], false, true);
        binary.segments[0].file_size = 0x8f;
        assert!(arm_exidx(&binary, &tables).0.is_empty());
        binary.segments[0].file_size = 0x200;
        tables.tables[0].storage.file_offset += 4;
        assert!(arm_exidx(&binary, &tables).0.is_empty());
    }

    #[test]
    fn extab_requires_alignment_matching_mapping_and_complete_continuations() {
        let records = [(0x1000, encoded(0x1100, 0x1084))];
        for extab in [&[][..], &[0x8101_b0b0][..], &[0x81ff_b0b0, 0][..]] {
            let (binary, tables) = fixture(&records, extab, false, true);
            assert!(arm_exidx(&binary, &tables).0.is_empty());
        }
        let (mut binary, mut tables) = fixture(&records, &[0x80b0_b0b0], false, true);
        binary.segments[0].file_size = 0x103;
        assert!(arm_exidx(&binary, &tables).0.is_empty());
        binary.segments[0].file_size = 0x200;
        tables.storage[0].file_offset += 4;
        assert!(arm_exidx(&binary, &tables).0.is_empty());
        let records = [(0x1000, encoded(0x1101, 0x1084))];
        let (binary, tables) = fixture(&records, &[0x80b0_b0b0, 0], false, true);
        assert!(arm_exidx(&binary, &tables).0.is_empty());
    }

    #[test]
    fn record_and_warning_budgets_are_bounded() {
        let (binary, tables) = fixture(&[(0x1000, 0x80b0_b0b0), (0x1004, 0x80b0_b0b0)], &[], false, true);
        let (starts, warnings) = read_tables(&binary, &tables, 1);
        assert_eq!(starts, [0x1000]);
        assert!(warnings.iter().any(|warning| warning.contains("budget exhausted")));
        assert!(read_tables(&binary, &tables, 0).0.is_empty());
        let mut warnings = Vec::new();
        for _ in 0..MAX_WARNINGS + 1 {
            warn(&mut warnings, "unsupported".into());
        }
        assert_eq!(warnings.len(), MAX_WARNINGS);
    }

    #[test]
    fn malformed_prefix_charges_only_visited_records_and_preserves_later_tables() {
        let records = [(0x1000, 0x80b0_b0b0), (0x1004, 0x80b0_b0b0), (0x1008, 0x80b0_b0b0), (0x100c, 0x80b0_b0b0)];
        let (binary, mut tables) = fixture_with_data(&records, &[], false, true, |data| {
            put_word(data, 0x80, 0xffff_ff80, false);
        });
        tables.tables.push(Table {
            storage: Storage { address: 0x1088, size: 8, file_offset: 0x88 },
            code: Storage { address: 0x1000, size: 0x40, file_offset: 0 },
        });
        tables.tables.push(Table {
            storage: Storage { address: 0x1090, size: 8, file_offset: 0x90 },
            code: Storage { address: 0x1000, size: 0x40, file_offset: 0 },
        });
        let (starts, warnings) = read_tables(&binary, &tables, 2);
        assert_eq!(starts, [0x1004]);
        assert!(warnings.iter().any(|warning| warning.contains("malformed code PREL31")));
        assert!(warnings.iter().any(|warning| warning.contains("record budget exhausted")));
    }

    fn elf32_headers(big_endian: bool) -> Vec<u8> {
        let mut data = vec![0; 0x240];
        data[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 1, if big_endian { 2 } else { 1 }, 1]);
        let half = |data: &mut [u8], offset: usize, value: u16| {
            let value = if big_endian { value.to_be_bytes() } else { value.to_le_bytes() };
            data[offset..offset + 2].copy_from_slice(&value);
        };
        half(&mut data, 16, 2);
        half(&mut data, 18, 40);
        put_word(&mut data, 20, 1, big_endian);
        put_word(&mut data, 32, 0x100, big_endian);
        half(&mut data, 40, 52);
        half(&mut data, 46, 40);
        half(&mut data, 48, 5);
        half(&mut data, 50, 4);
        let mut section = |index: usize, fields: [u32; 10]| {
            for (field, value) in fields.into_iter().enumerate() {
                put_word(&mut data, 0x100 + index * 40 + field * 4, value, big_endian);
            }
        };
        section(1, [0, elf::SHT_PROGBITS.0, 6, 0x1000, 0x40, 0x40, 0, 0, 4, 0]);
        section(2, [1, elf::SHT_ARM_EXIDX.0, 0x82, 0x1080, 0x80, 8, 1, 0, 4, 0]);
        section(3, [0, elf::SHT_PROGBITS.0, 2, 0x1100, 0x90, 4, 0, 0, 4, 0]);
        section(4, [0, elf::SHT_STRTAB.0, 0, 0, 0x200, 12, 0, 0, 1, 0]);
        data[0x200..0x20c].copy_from_slice(b"\0.ARM.exidx\0");
        data
    }

    fn collected(data: &[u8]) -> (Option<ArmExidxTables>, Vec<String>) {
        let parsed = object::File::parse(data).unwrap();
        let mut warnings = Vec::new();
        let tables = arm_exidx_tables(&parsed, &mut warnings);
        (tables, warnings)
    }

    #[test]
    fn native_elf_type_link_and_flags_admit_tables_without_names() {
        for big_endian in [false, true] {
            for entsize in [0, 8] {
                let mut data = elf32_headers(big_endian);
                put_word(&mut data, 0x150, 0, big_endian);
                put_word(&mut data, 0x174, entsize, big_endian);
                let (tables, warnings) = collected(&data);
                assert_eq!(tables.unwrap().tables.len(), 1);
                assert!(warnings.is_empty());
            }
        }
        let mut data = elf32_headers(false);
        data[16..18].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(collected(&data).0.unwrap().tables.len(), 1);
        data[16..18].copy_from_slice(&1u16.to_le_bytes());
        assert!(collected(&data).0.is_none());
        data[16..18].copy_from_slice(&2u16.to_le_bytes());
        data[18..20].copy_from_slice(&3u16.to_le_bytes());
        assert!(collected(&data).0.is_none());
    }

    #[test]
    fn linked_code_section_file_mapping_is_required_even_when_segment_code_is_readable() {
        let (binary, _) = fixture(&[(0x1000, 0x80b0_b0b0)], &[], false, true);
        assert!(binary.is_code(0x1000));
        assert!(binary.read(0x1000, 1).is_some());
        for file_offset in [0, 1, 0x200, 0xffff_fffc] {
            let mut headers = elf32_headers(false);
            put_word(&mut headers, 0x128 + 16, file_offset, false);
            let (tables, _) = collected(&headers);
            let (starts, warnings) = arm_exidx(&binary, &tables.unwrap());
            if file_offset == 0 {
                assert_eq!(starts, [0x1000]);
            } else {
                assert!(starts.is_empty(), "linked file offset {file_offset:#x}");
                assert!(warnings.iter().any(|warning| warning.contains("outside readable linked code")));
            }
        }
    }

    #[test]
    fn section_name_impostors_bad_links_and_unallocated_tables_are_ignored() {
        let table = 0x150;
        let code = 0x128;
        for (offset, value) in [
            (table + 4, elf::SHT_PROGBITS.0),
            (table + 24, 0),
            (table + 24, 99),
            (table + 24, 3),
            (table + 8, 0),
            (table + 8, elf::SHF_ALLOC.0 as u32),
            (table + 8, (elf::SHF_ALLOC | elf::SHF_COMPRESSED).0 as u32),
            (code + 8, elf::SHF_ALLOC.0 as u32),
            (code + 8, elf::SHF_EXECINSTR.0 as u32),
            (code + 4, elf::SHT_NOBITS.0),
        ] {
            let mut data = elf32_headers(false);
            put_word(&mut data, offset, value, false);
            assert!(collected(&data).0.unwrap().tables.is_empty(), "offset {offset:#x}, value {value:#x}");
        }
    }

    #[test]
    fn native_table_stride_alignment_and_entry_size_are_checked() {
        let table = 0x150;
        for (offset, value) in [
            (table + 12, 0x1082),
            (table + 16, 0x82),
            (table + 20, 7),
            (table + 20, 9),
            (table + 32, 0),
            (table + 32, 2),
            (table + 32, 6),
            (table + 36, 4),
            (table + 36, 16),
            (table + 12, 0xffff_fffc),
            (0x128 + 20, 0xffff_ffff),
        ] {
            let mut data = elf32_headers(false);
            put_word(&mut data, offset, value, false);
            let (tables, warnings) = collected(&data);
            assert!(tables.unwrap().tables.is_empty(), "offset {offset:#x}, value {value:#x}");
            assert!(!warnings.is_empty());
        }
    }

    #[test]
    fn native_table_count_budget_does_not_grow_with_hostile_sections() {
        let mut data = elf32_headers(false);
        let count = MAX_TABLES + 8;
        let header: [u8; 40] = data[0x150..0x178].try_into().unwrap();
        let strings_header: [u8; 40] = data[0x1a0..0x1c8].try_into().unwrap();
        let strings: [u8; 12] = data[0x200..0x20c].try_into().unwrap();
        let strings_index = count - 1;
        let strings_offset = 0x100 + count * 40;
        data.resize(strings_offset + strings.len(), 0);
        data[48..50].copy_from_slice(&u16::try_from(count).unwrap().to_le_bytes());
        data[50..52].copy_from_slice(&u16::try_from(strings_index).unwrap().to_le_bytes());
        for index in 2..strings_index {
            data[0x100 + index * 40..0x100 + (index + 1) * 40].copy_from_slice(&header);
        }
        let strings_header_offset = 0x100 + strings_index * 40;
        data[strings_header_offset..strings_header_offset + 40].copy_from_slice(&strings_header);
        put_word(&mut data, strings_header_offset + 16, u32::try_from(strings_offset).unwrap(), false);
        data[strings_offset..].copy_from_slice(&strings);
        let (tables, warnings) = collected(&data);
        assert_eq!(tables.unwrap().tables.len(), MAX_TABLES);
        assert!(warnings.iter().any(|warning| warning.contains("table budget exhausted")));
        assert!(warnings.len() <= MAX_WARNINGS);
    }
}
