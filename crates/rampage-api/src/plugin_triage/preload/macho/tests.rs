use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_loaders::{Binary, Format, ImageAt, LoadError, SectionKind};

use super::*;
use crate::Project;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name);
    std::fs::read(path).unwrap()
}

fn hello() -> Vec<u8> {
    fixture("hello-x64.macho")
}

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn command(bytes: &[u8], kind: u32) -> usize {
    let mut at = 32;
    for _ in 0..u32_at(bytes, 16).unwrap() {
        if u32_at(bytes, at).unwrap() == kind {
            return at;
        }
        at += u32_at(bytes, at + 4).unwrap() as usize;
    }
    panic!("missing command {kind:x}")
}

fn segment(bytes: &[u8], index: usize) -> usize {
    let mut at = 32;
    let mut found = 0;
    for _ in 0..u32_at(bytes, 16).unwrap() {
        if u32_at(bytes, at).unwrap() == 0x19 {
            if found == index {
                return at;
            }
            found += 1;
        }
        at += u32_at(bytes, at + 4).unwrap() as usize;
    }
    panic!("missing segment {index}")
}

fn section(bytes: &[u8], index: usize) -> usize {
    if index < 4 { segment(bytes, 1) + 72 + index * 80 } else { segment(bytes, 2) + 72 }
}

fn table_fields(bytes: &[u8]) -> [(usize, usize); 6] {
    [
        (command(bytes, 0x8000_0034) + 8, 1),
        (command(bytes, 0x8000_0033) + 8, 1),
        (command(bytes, 0x26) + 8, 1),
        (command(bytes, 2) + 8, 16),
        (command(bytes, 0xb) + 56, 4),
        (command(bytes, 2) + 16, 1),
    ]
}

fn linkedit(bytes: &[u8]) -> [Vec<u8>; 6] {
    table_fields(bytes).map(|(field, width)| {
        let offset = u32_at(bytes, field).unwrap() as usize;
        let count = u32_at(bytes, field + 4).unwrap() as usize;
        bytes[offset..offset + count * width].to_vec()
    })
}

fn repack(bytes: &mut Vec<u8>, tables: &[Vec<u8>; 6]) {
    let fields = table_fields(bytes);
    let segment = segment(bytes, 3);
    let start = usize_at(bytes, segment + 40).unwrap();
    bytes.truncate(start);
    for ((field, width), data) in fields.into_iter().zip(tables) {
        bytes.resize(bytes.len().div_ceil(8) * 8, 0);
        let at = bytes.len();
        put32(bytes, field, at as u32);
        put32(bytes, field + 4, (data.len() / width) as u32);
        bytes.extend(data);
    }
    let end = bytes.len();
    let size = end - start;
    put64(bytes, segment + 48, size as u64);
    put64(bytes, segment + 32, (size.div_ceil(4096) * 4096) as u64);
    let empty = command(bytes, 0x29);
    put32(bytes, empty + 8, end as u32);
}

fn refused(bytes: &[u8], reason: &str) {
    let error = super::super::admit_before_load(bytes, None).unwrap_err();
    assert!(error.to_string().contains(reason), "{error}: expected {reason}");
}

struct Source(PathBuf);

impl Source {
    fn new(bytes: &[u8]) -> Self {
        use std::io::Write;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-macho-admission-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        let source = Self(path);
        file.write_all(bytes).unwrap();
        source
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn loaded(bytes: &[u8]) -> (Source, Project) {
    let source = Source::new(bytes);
    let callback = Cell::new(false);
    let binary = Binary::open_image_checked_admitted(&source.0, None, None, MAX_PLUGIN_TRIAGE_SOURCE_BYTES, |actual| {
        callback.set(true);
        assert_eq!(actual, bytes);
        super::super::admit_before_load(actual, None).map_err(|error| LoadError::Unsupported(error.to_string()))
    })
    .unwrap();
    assert!(callback.get());
    (source, Project::new(binary))
}

#[test]
fn unchanged_owned_hello_images_reach_native_starts_imports_exports_and_constructor_names() {
    for stripped in [false, true] {
        let name = if stripped { "hello-x64-stripped.macho" } else { "hello-x64.macho" };
        let bytes = fixture(name);
        let (_source, project) = loaded(&bytes);
        let binary = &project.binary;
        assert_eq!(binary.format, Format::MachO);
        assert_eq!(binary.arch, rampage_arch::Arch::X86_64);
        assert!(!binary.big_endian);
        assert_eq!(binary.entry, Some(BASE + 0x480));
        assert_eq!(binary.function_starts, [BASE + 0x470, BASE + 0x480]);
        assert_eq!(binary.imports.len(), 1);
        assert_eq!(binary.imports[0].name, "_puts");
        assert_eq!(binary.imports[0].library.as_deref(), Some("/usr/lib/libSystem.B.dylib"));
        assert_eq!(binary.import_slots.len(), 1);
        let slot = &binary.import_slots[0];
        assert_eq!(slot.address, BASE + 0x1000);
        assert_eq!(slot.name, "_puts");
        assert_eq!(slot.library.as_deref(), Some("/usr/lib/libSystem.B.dylib"));
        let mut exports: Vec<_> = binary.exports.iter().map(|export| (export.name.as_str(), export.address)).collect();
        exports.sort_unstable();
        let mut expected = vec![("__mh_execute_header", BASE)];
        if !stripped {
            expected.extend([("_add", BASE + 0x470), ("_main", BASE + 0x480)]);
        }
        assert_eq!(exports, expected);
        assert_eq!(binary.sections[0].kind, SectionKind::Code);
        assert_eq!(binary.sections[1].kind, SectionKind::Code);
        assert_eq!(binary.segments[0].size, BASE);
        assert_eq!(binary.segments[0].file_size, 0);
        assert!(!binary.segments[0].perms.read);
        assert!(binary.read(0, 1).is_none());
        assert!(binary.code_from(BASE).is_none());
        assert_eq!(binary.read(slot.address, 8).unwrap(), &bytes[4096..4104]);
        assert!(binary.inventory_source_context().2.is_empty());
        assert!(binary.warnings.is_empty(), "{:?}", binary.warnings);
        assert_eq!(project.name_at(BASE + 0x498).as_deref(), Some("_puts"));
        assert_eq!(project.name_at(slot.address).as_deref(), Some("__imp__puts"));
        assert_eq!(project.name_at(BASE).as_deref(), Some("__mh_execute_header"));
        if stripped {
            assert!(binary.symbol_by_name("_add").is_none());
            assert!(binary.symbol_by_name("_main").is_none());
            assert!(project.name_at(BASE + 0x470).is_none());
            assert_eq!(project.name_at(BASE + 0x480).as_deref(), Some("entry"));
        } else {
            assert_eq!(project.name_at(BASE + 0x470).as_deref(), Some("_add"));
            assert_eq!(project.name_at(BASE + 0x480).as_deref(), Some("_main"));
        }
        binary.validate_backing_source().unwrap();
    }
}

#[test]
fn compact_unwind_is_backed_but_opaque_to_opening_and_constructor() {
    let mut bytes = hello();
    let header = section(&bytes, 3);
    let at = u32_at(&bytes, header + 48).unwrap() as usize;
    let size = usize_at(&bytes, header + 40).unwrap();
    bytes[at..at + size].fill(0xff);
    let (_source, project) = loaded(&bytes);
    assert!(project.binary.warnings.is_empty());
    assert_eq!(project.binary.function_starts, [BASE + 0x470, BASE + 0x480]);
}

#[test]
fn public_dispatch_refuses_unearned_architectures_containers_and_runtime_metadata() {
    for name in
        ["hello-arm64.macho", "hello-universal.macho", "hello-x64.dylib", "debug-x64.macho", "objc-x64-stripped.macho"]
    {
        assert!(super::super::admit_before_load(&fixture(name), None).is_err(), "{name}");
    }
    let bytes = hello();
    for image in [ImageAt::new(0, Some(bytes.len() as u64)), ImageAt::new(1, None)] {
        assert!(super::super::admit_before_load(&bytes, Some(image)).is_err());
    }
    super::super::admit_before_load(&bytes, Some(ImageAt::new(0, None))).unwrap();
    for (offset, value) in [(4, 0x0100_000c), (8, 0x8000_0003), (12, 6), (12, 8), (24, 0x85), (28, 1)] {
        let mut changed = bytes.clone();
        put32(&mut changed, offset, value);
        refused(&changed, "ordinary little-endian x86_64");
    }
    for kind in [0x8000_0022, 0x22, 0x1d, 0x8000_001c, 0x5, 0x8000_0035] {
        let mut changed = bytes.clone();
        let at = command(&changed, 0x2a);
        put32(&mut changed, at, kind);
        refused(&changed, "unsupported load command");
    }
}

#[test]
fn command_counts_sizes_and_singletons_are_admitted_before_object_parsing() {
    let bytes = hello();
    let mut changed = bytes.clone();
    put32(&mut changed, 16, MAX_COMMANDS as u32 + 1);
    refused(&changed, "load-command count/bytes");
    let mut changed = bytes.clone();
    put32(&mut changed, 20, u32::MAX);
    refused(&changed, "load-command count/bytes");
    for size in [0, 7, u32::MAX - 7] {
        let mut changed = bytes.clone();
        put32(&mut changed, 36, size);
        assert!(admit(&changed).is_err());
    }
    let mut changed = bytes.clone();
    let at = command(&changed, 0x2a);
    put32(&mut changed, at, 0x1b);
    refused(&changed, "duplicate singleton");
    let mut changed = bytes.clone();
    let size = u32_at(&changed, 20).unwrap();
    put32(&mut changed, 20, size + 8);
    refused(&changed, "exhaust");
}

#[test]
fn guard_and_native_va_reads_cannot_hide_in_other_raw_bytes_or_zero_fill() {
    let bytes = hello();
    for (index, field, value) in [
        (0, 48, 8),
        (0, 32, BASE - 1),
        (1, 48, 1200),
        (1, 32, 8192),
        (2, 40, u64::MAX),
        (2, 24, BASE + 0x800),
        (3, 48, u64::MAX),
    ] {
        let mut changed = bytes.clone();
        let at = segment(&changed, index);
        put64(&mut changed, at + field, value);
        assert!(admit(&changed).is_err(), "segment {index} field {field}");
    }
    for (field, value) in [(32, BASE + 0x600), (40, u64::MAX), (48, 0x600)] {
        let mut changed = bytes.clone();
        let at = section(&changed, 3);
        if field == 48 {
            put32(&mut changed, at + field, value as u32);
        } else {
            put64(&mut changed, at + field, value);
        }
        assert!(admit(&changed).is_err(), "section field {field}");
    }
    let mut changed = bytes.clone();
    let at = section(&changed, 1);
    let text = section(&changed, 0);
    put32(&mut changed, at + 48, u32_at(&bytes, text + 48).unwrap());
    put64(&mut changed, at + 32, u64_at(&bytes, text + 32).unwrap());
    refused(&changed, "overlap");
    let mut changed = bytes;
    let at = section(&changed, 4);
    put64(&mut changed, at + 32, BASE + 0x2000);
    refused(&changed, "file backing");
}

#[test]
fn section_aliases_types_relocations_and_hidden_go_never_start_recovery() {
    let bytes = hello();
    for name in [b"__eh_frame".as_slice(), b".eh_frame", b"__objc_classlist", b"__swift5_types", b"__gopclntab"] {
        let mut changed = bytes.clone();
        let at = section(&changed, 3);
        changed[at..at + 16].fill(0);
        changed[at..at + name.len()].copy_from_slice(name);
        refused(&changed, "section name/type/relocations");
    }
    for (field, value) in [(56, 1), (60, 1), (64, 0x8000_0400), (64, 1), (76, 1)] {
        let mut changed = bytes.clone();
        let at = section(&changed, 3);
        put32(&mut changed, at + field, value);
        refused(&changed, "section name/type/relocations");
    }
    let mut changed = bytes;
    changed[0x600..0x608].copy_from_slice(&[0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 8]);
    refused(&changed, "hidden Go");
}

#[test]
fn nlist_names_and_dysymtab_references_cannot_escape_the_admitted_table() {
    let bytes = hello();
    let original = linkedit(&bytes);
    for name in ["_Z1fv", "___Z1fv_block_invoke", "_RNvC1a1b", "_GLOBAL__I_a", "?f@@YAXXZ", "i", "ZN1aE", "_$s1a"] {
        let mut changed = bytes.clone();
        let mut tables = original.clone();
        tables[5] = [b"\0".as_slice(), name.as_bytes(), b"\0"].concat();
        put32(&mut tables[3], 0, 1);
        repack(&mut changed, &tables);
        refused(&changed, "mangled/non-C");
    }
    for (field, value) in [(8, 1), (12, u32::MAX), (32, 1), (36, 1), (64, 1), (68, 1)] {
        let mut changed = bytes.clone();
        let at = command(&changed, 0xb);
        put32(&mut changed, at + field, value);
        assert!(admit(&changed).is_err());
    }
    for value in [u32::MAX, 0x8000_0000, 0] {
        let mut changed = bytes.clone();
        let mut tables = original.clone();
        put32(&mut tables[4], 0, value);
        repack(&mut changed, &tables);
        refused(&changed, "indirect row");
    }
    let mut changed = bytes.clone();
    let at = command(&changed, 2);
    put32(&mut changed, at + 12, u32::MAX);
    refused(&changed, "link-edit tables");
    let mut changed = bytes;
    let at = command(&changed, 0x8000_0033);
    put32(&mut changed, at + 8, 8192);
    refused(&changed, "tables overlap");
}

#[test]
fn repeated_nlist_text_is_charged_per_reference_not_unique_string_offset() {
    let mut bytes = hello();
    let mut tables = linkedit(&bytes);
    let count = 240;
    let mut undefined = tables[3][48..64].to_vec();
    put32(&mut undefined, 0, 1);
    tables[3] = undefined.repeat(count);
    tables[4] = vec![0; 8];
    tables[5] = vec![b'a'; MAX_NAME + 2];
    tables[5][0] = 0;
    tables[5][1] = b'_';
    tables[5][MAX_NAME + 1] = 0;
    let at = command(&bytes, 0xb);
    for field in [8, 12, 16, 20, 24] {
        put32(&mut bytes, at + field, 0);
    }
    put32(&mut bytes, at + 28, count as u32);
    repack(&mut bytes, &tables);
    refused(&bytes, "repeated names");
}

#[test]
fn chained_headers_imports_and_pointer_walks_are_all_checked_before_native_iteration() {
    let bytes = hello();
    let original = linkedit(&bytes);
    for (offset, value) in [(0, 1), (4, u32::MAX), (8, 4), (12, 4), (16, u32::MAX), (20, 2), (24, 1), (32, 5)] {
        let mut changed = bytes.clone();
        let mut tables = original.clone();
        put32(&mut tables[0], offset, value);
        repack(&mut changed, &tables);
        assert!(admit(&changed).is_err(), "fixup field {offset}");
    }
    for (offset, value) in [(60, 0), (62, 2), (76, 2), (78, 0x8000), (78, 0xfff), (78, 8)] {
        let mut changed = bytes.clone();
        let mut tables = original.clone();
        put16(&mut tables[0], offset, value);
        repack(&mut changed, &tables);
        assert!(admit(&changed).is_err(), "segment fixup field {offset}");
    }
    for value in [0, 0x100, 9, 0xff, 0xffff_fe01] {
        let mut changed = bytes.clone();
        let mut tables = original.clone();
        put32(&mut tables[0], 80, value);
        repack(&mut changed, &tables);
        assert!(admit(&changed).is_err(), "import {value:x}");
    }
    for pointer in
        [0, 1 << 63 | 1, 1 << 63 | 1 << 24, 1 << 63 | 1 << 32, 1 << 63 | 1 << 50, 1 << 63 | 1 << 51, 1 << 63 | 2 << 51]
    {
        let mut changed = bytes.clone();
        put64(&mut changed, 4096, pointer);
        assert!(admit(&changed).is_err(), "pointer {pointer:x}");
    }
}

#[test]
fn admitted_multi_page_chains_preserve_nonzero_starts_skipped_pages_and_exact_native_slots() {
    let mut bytes = hello();
    let mut tables = linkedit(&bytes);
    let data = segment(&bytes, 2);
    let linkedit = segment(&bytes, 3);
    let got = section(&bytes, 4);
    put64(&mut bytes, data + 32, 0x3000);
    put64(&mut bytes, data + 48, 0x3000);
    put64(&mut bytes, linkedit + 24, BASE + 0x4000);
    put64(&mut bytes, linkedit + 40, 0x4000);
    put64(&mut bytes, got + 40, 0x3000);
    tables[4] = 3u32.to_le_bytes().repeat(0x3000 / 8 + 1);
    bytes.resize(0x4000, 0);
    bytes[0x1000..].fill(0);

    // Segment metadata starts at offset 56. Three page starts extend it to 84, followed by two imports.
    tables[0].truncate(78);
    put32(&mut tables[0], 56, 28);
    put16(&mut tables[0], 76, 3);
    for start in [8u16, 0xffff, 16] {
        tables[0].extend(start.to_le_bytes());
    }
    put32(&mut tables[0], 8, 84);
    put32(&mut tables[0], 12, 92);
    put32(&mut tables[0], 16, 2);
    tables[0].extend(0x201u32.to_le_bytes());
    tables[0].extend((1u32 | 7 << 9).to_le_bytes());
    tables[0].extend(b"\0_puts\0_second\0");
    put64(&mut bytes, 0x1008, 1 << 63);
    put64(&mut bytes, 0x3010, 1 << 63 | 2 << 51 | 1);
    put64(&mut bytes, 0x3018, 1 << 63);
    // These valid-looking encodings are not chain starts: the middle page is NONE and other pages start later.
    for offset in [0x1000, 0x2000, 0x3000] {
        put64(&mut bytes, offset, 1 << 63 | 1);
    }
    let stubs = section(&bytes, 1);
    let stub = u32_at(&bytes, stubs + 48).unwrap() as usize;
    put32(&mut bytes, stub + 2, (0x1008i32 - (stub + 6) as i32) as u32);
    repack(&mut bytes, &tables);

    let (_source, project) = loaded(&bytes);
    let binary = &project.binary;
    let library = Some("/usr/lib/libSystem.B.dylib");
    let imports: Vec<_> =
        binary.imports.iter().map(|import| (import.name.as_str(), import.library.as_deref())).collect();
    assert_eq!(imports, [("_puts", library), ("_second", library)]);
    let slots: Vec<_> =
        binary.import_slots.iter().map(|slot| (slot.address, slot.name.as_str(), slot.library.as_deref())).collect();
    assert_eq!(
        slots,
        [(BASE + 0x1008, "_puts", library), (BASE + 0x3010, "_second", library), (BASE + 0x3018, "_puts", library)]
    );
    for (offset, name) in [(0x1008, "__imp__puts"), (0x3010, "__imp__second"), (0x3018, "__imp__puts")] {
        assert_eq!(project.name_at(BASE + offset).as_deref(), Some(name));
        assert_eq!(binary.read(BASE + offset, 8).unwrap(), &bytes[offset as usize..offset as usize + 8]);
    }
    for offset in [0x1000, 0x2000, 0x3000] {
        assert!(binary.import_slot(BASE + offset).is_none());
        assert!(project.name_at(BASE + offset).is_none());
    }
    assert_eq!(project.name_at(BASE + stub as u64).as_deref(), Some("_puts"));
    assert!(binary.inventory_source_context().2.is_empty());
    assert!(binary.warnings.is_empty(), "{:?}", binary.warnings);
    binary.validate_backing_source().unwrap();
}

fn long_chain_name(fixups: &mut Vec<u8>) {
    fixups.truncate(85);
    fixups.extend(std::iter::repeat_n(b'a', MAX_NAME));
    fixups[85] = b'_';
    fixups.push(0);
}

#[test]
fn reused_chain_import_strings_and_per_pointer_library_clones_are_funded_before_collection() {
    let mut bytes = hello();
    let mut tables = linkedit(&bytes);
    long_chain_name(&mut tables[0]);
    let count = 200;
    let got = section(&bytes, 4);
    put64(&mut bytes, got + 40, (count * 8) as u64);
    tables[4] = 3u32.to_le_bytes().repeat(count + 1);
    for index in 0..count {
        let next = if index + 1 == count { 0 } else { 2u64 << 51 };
        put64(&mut bytes, 4096 + index * 8, 1 << 63 | next);
    }
    repack(&mut bytes, &tables);
    refused(&bytes, "repeated names");

    let mut bytes = hello();
    let mut tables = linkedit(&bytes);
    let count = 200;
    tables[0].truncate(80);
    tables[0].extend(0x201u32.to_le_bytes().repeat(count));
    let strings = tables[0].len();
    tables[0].push(0);
    tables[0].push(b'_');
    tables[0].extend(std::iter::repeat_n(b'a', MAX_NAME - 1));
    tables[0].push(0);
    put32(&mut tables[0], 12, strings as u32);
    put32(&mut tables[0], 16, count as u32);
    repack(&mut bytes, &tables);
    refused(&bytes, "repeated names");
}

#[test]
fn export_tree_allows_backward_edges_but_refuses_dag_replay_cycles_and_special_terminals() {
    let mut bytes = hello();
    let mut tables = linkedit(&bytes);
    tables[1] = vec![0, 1, b'_', 0, 10, 3, 0, 0xf0, 8, 0, 0, 1, b'a', 0, 5];
    repack(&mut bytes, &tables);
    let (_source, project) = loaded(&bytes);
    assert_eq!(project.binary.exports.len(), 1);
    assert_eq!(project.binary.exports[0].name, "_a");
    assert_eq!(project.binary.exports[0].address, BASE + 0x470);
    for trie in [
        vec![0, 1, b'_', 0, 0],
        vec![0, 2, b'_', b'a', 0, 10, b'_', b'b', 0, 10, 3, 0, 0xf0, 8, 0],
        vec![0, 1, b'_', 0, 2],
    ] {
        let mut changed = hello();
        let mut tables = linkedit(&changed);
        tables[1] = trie;
        repack(&mut changed, &tables);
        assert!(admit(&changed).is_err());
    }
    for flags in [1, 2, 4, 8, 0x10] {
        let mut changed = bytes.clone();
        let mut tables = linkedit(&changed);
        tables[1][6] = flags;
        repack(&mut changed, &tables);
        refused(&changed, "export flags");
    }
}

fn append_uleb(bytes: &mut Vec<u8>, mut value: usize) {
    loop {
        let next = value & 0x7f;
        value >>= 7;
        bytes.push(next as u8 | if value == 0 { 0 } else { 0x80 });
        if value == 0 {
            break;
        }
    }
}

#[test]
fn full_export_prefix_work_is_charged_even_when_each_terminal_is_a_tiny_record() {
    let mut bytes = hello();
    let mut tables = linkedit(&bytes);
    let count = 128;
    let length = 250;
    let root_size = 2 + count * (length + 1 + 3);
    let mut trie = vec![0, count as u8];
    for index in 0..count {
        let mut name = vec![b'a'; length];
        name[0] = b'_';
        let suffix = format!("{index:03}");
        name[length - 3..].copy_from_slice(suffix.as_bytes());
        trie.extend(name);
        trie.push(0);
        append_uleb(&mut trie, root_size + index * 4);
    }
    assert_eq!(trie.len(), root_size);
    trie.extend([2, 0, 0, 0].repeat(count));
    tables[1] = trie;
    repack(&mut bytes, &tables);
    refused(&bytes, "repeated names");
}

#[test]
fn start_ulebs_targets_termination_and_pre_filter_record_work_are_bounded() {
    let bytes = hello();
    for starts in [vec![0x80; 10], vec![0xff; 10], vec![0x80, 0], vec![0, 1], vec![0x80, 0x20, 0]] {
        let mut changed = bytes.clone();
        let mut tables = linkedit(&changed);
        tables[2] = starts;
        repack(&mut changed, &tables);
        assert!(admit(&changed).is_err());
    }
    let mut changed = bytes;
    let mut tables = linkedit(&changed);
    tables[2] = vec![0xf0, 8, 16];
    repack(&mut changed, &tables);
    refused(&changed, "unterminated");

    let mut changed = many_real_stubs(1);
    let mut tables = linkedit(&changed);
    let stubs = section(&changed, 1);
    let old = u32_at(&changed, stubs + 48).unwrap() as usize;
    changed.copy_within(old..old + 6, 3500);
    put32(&mut changed, stubs + 48, 3500);
    put64(&mut changed, stubs + 32, BASE + 3500);
    let text = section(&changed, 0);
    put64(&mut changed, text + 40, 2300);
    tables[2] = vec![0xf0, 8];
    tables[2].extend(std::iter::repeat_n(1, 2050));
    tables[2].push(0);
    repack(&mut changed, &tables);
    refused(&changed, "producer records");
}

fn many_real_stubs(count: usize) -> Vec<u8> {
    let mut bytes = hello();
    let mut tables = linkedit(&bytes);
    for (index, destination) in [(2, 0xe00), (3, 0xe20)] {
        let header = section(&bytes, index);
        let at = u32_at(&bytes, header + 48).unwrap() as usize;
        let size = usize_at(&bytes, header + 40).unwrap();
        bytes.copy_within(at..at + size, destination);
        put32(&mut bytes, header + 48, destination as u32);
        put64(&mut bytes, header + 32, BASE + destination as u64);
    }
    let stubs = section(&bytes, 1);
    let start = u32_at(&bytes, stubs + 48).unwrap() as usize;
    put64(&mut bytes, stubs + 40, (count * 6) as u64);
    for index in 0..count {
        let at = start + index * 6;
        bytes[at..at + 2].copy_from_slice(&[0xff, 0x25]);
        let displacement = (4096i64 - (at + 6) as i64) as i32;
        bytes[at + 2..at + 6].copy_from_slice(&displacement.to_le_bytes());
    }
    let got = section(&bytes, 4);
    put32(&mut bytes, got + 68, count as u32);
    tables[4] = 3u32.to_le_bytes().repeat(count + 1);
    repack(&mut bytes, &tables);
    bytes
}

#[test]
fn actual_checked_mapping_refuses_stub_work_before_native_producers_and_names() {
    let records = many_real_stubs(350);
    let mut repeated = many_real_stubs(200);
    let mut tables = linkedit(&repeated);
    long_chain_name(&mut tables[0]);
    repack(&mut repeated, &tables);
    for (bytes, reason) in [(records, "producer records"), (repeated, "repeated names")] {
        refused(&bytes, reason);
        let source = Source::new(&bytes);
        let callback = Cell::new(false);
        let constructed = Cell::new(false);
        let refusal = "raw Mach-O gate refused constructor amplification";
        let result =
            Binary::open_image_checked_admitted(&source.0, None, None, MAX_PLUGIN_TRIAGE_SOURCE_BYTES, |actual| {
                callback.set(true);
                assert_eq!(actual, bytes);
                let error = super::super::admit_before_load(actual, None).unwrap_err();
                assert!(error.to_string().contains(reason));
                Err(LoadError::Unsupported(refusal.into()))
            })
            .map(|binary| {
                constructed.set(true);
                Project::new(binary)
            });
        assert!(callback.get());
        assert!(!constructed.get());
        assert!(matches!(result, Err(LoadError::Unsupported(message)) if message == refusal));
    }

    let control = many_real_stubs(2);
    let (_source, project) = loaded(&control);
    for offset in [0x498, 0x49e] {
        assert_eq!(project.name_at(BASE + offset).as_deref(), Some("_puts"));
    }
}

#[test]
fn every_fixture_truncation_is_refused_without_unchecked_reads() {
    let bytes = hello();
    for length in 0..bytes.len() {
        assert!(admit(&bytes[..length]).is_err(), "truncation at {length}");
    }
}
