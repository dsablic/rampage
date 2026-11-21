use std::path::Path;

use super::*;
use crate::Binary;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)).unwrap()
}

/// `data` with its section headers gone, as `sstrip` leaves a file: `e_shoff`, `e_shnum` and `e_shstrndx` zero.
fn sectionless(mut data: Vec<u8>) -> Vec<u8> {
    let (shoff, shnum, shstrndx) = if data[4] == 2 { (40..48, 60..62, 62..64) } else { (32..36, 48..50, 50..52) };
    for range in [shoff, shnum, shstrndx] {
        data[range].fill(0);
    }
    data
}

fn load(data: Vec<u8>) -> Binary {
    let arch = Binary::from_owned_native_bytes(data.clone(), rampage_arch::Arch::X86_64)
        .err()
        .and_then(|error| {
            let text = error.to_string();
            rampage_arch::Arch::ALL.into_iter().find(|arch| text.ends_with(&format!("contains {arch}")))
        })
        .unwrap_or(rampage_arch::Arch::X86_64);
    Binary::from_owned_native_bytes(data, arch).unwrap()
}

fn sorted<T: Ord + Clone>(items: &[T]) -> Vec<T> {
    let mut items = items.to_vec();
    items.sort();
    items
}

const DYNAMIC_FIXTURES: &[&str] = &[
    "bin/hello-mipsel.elf",
    "bin/hello-x64-dyn.elf",
    "bin/libhelper-x64.so",
    "bin/libhelper-x86.so",
    "bin/hello-arm.elf",
    "bin/switch-scheduled-arm64.so",
    "bin/switch-pic-i386.so",
    "bin/hello-ppc64le.elf",
    "bin/hello-riscv64.elf",
    "mips/router-gnu-mips.elf",
    "mips/router-gnu-mipsel.elf",
    "mips/router-mipsel.elf",
    "mips/router-mips64.elf",
];

fn names<T>(items: &[T], name: impl Fn(&T) -> (&str, u64)) -> Vec<(String, u64)> {
    let mut found: Vec<(String, u64)> = items.iter().map(name).map(|(n, a)| (n.to_owned(), a)).collect();
    found.sort();
    found
}

/// Removing the section headers loses nothing the dynamic linker uses: the same exports, imports and import slots,
/// and the dynamic function symbols, are read through PT_DYNAMIC.
#[test]
fn a_sectionless_file_keeps_its_dynamic_symbols_on_every_architecture() {
    for name in DYNAMIC_FIXTURES {
        let original = load(fixture(name));
        let stripped = load(sectionless(fixture(name)));
        assert!(stripped.sections.is_empty(), "{name}");
        assert!(!original.exports.is_empty() || !original.imports.is_empty(), "{name}");
        assert_eq!(
            names(&stripped.exports, |export| (&export.name, export.address)),
            names(&original.exports, |export| (&export.name, export.address)),
            "{name}: exports"
        );
        let imports =
            |binary: &Binary| sorted(&binary.imports.iter().map(|import| import.name.clone()).collect::<Vec<_>>());
        assert_eq!(imports(&stripped), imports(&original), "{name}: imports");
        // 64-bit MIPS relocations are not read; its GOT gives the slots.
        assert_eq!(
            names(&stripped.import_slots, |slot| (&slot.name, slot.address)),
            names(&original.import_slots, |slot| (&slot.name, slot.address)),
            "{name}: import slots"
        );
        assert_eq!(stripped.got_functions, original.got_functions, "{name}: GOT functions");
        let got = |binary: &Binary| binary.target().got.map(|got| (got.address, got.entries.len(), got.local_entries));
        // Only MIPS describes its GOT in the dynamic section; elsewhere the `.got` section is gone with the rest.
        if matches!(original.arch, rampage_arch::Arch::Mips | rampage_arch::Arch::Mips64) {
            assert_eq!(got(&stripped), got(&original), "{name}: GOT");
        }
        for symbol in stripped.symbols.iter().filter(|symbol| symbol.kind == crate::SymbolKind::Function) {
            assert!(original.symbols.contains(symbol), "{name}: {symbol:?} is not in the section-backed symbols");
        }
        assert!(
            stripped.warnings.iter().all(|warning| !warning.contains("PT_DYNAMIC")),
            "{name}: {:?}",
            stripped.warnings
        );
    }
}

/// The dynamic entries of `data`, as (file offset of the entry, tag, value).
fn entries(data: &[u8]) -> Vec<(usize, u64, u64)> {
    let image = Image::parse(data).unwrap();
    let is_64 = data[4] == 2;
    let (phoff, phentsize, phnum) = if is_64 {
        (image.uint(32, 8).unwrap(), image.uint(54, 2).unwrap(), image.uint(56, 2).unwrap())
    } else {
        (image.uint(28, 4).unwrap(), image.uint(42, 2).unwrap(), image.uint(44, 2).unwrap())
    };
    let dynamic = (0..phnum)
        .map(|index| (phoff + index * phentsize) as usize)
        .find(|&at| image.uint(at, 4) == Some(u64::from(PT_DYNAMIC)))
        .map(|at| if is_64 { image.uint(at + 8, 8).unwrap() } else { image.uint(at + 4, 4).unwrap() })
        .unwrap() as usize;
    let size = if is_64 { 16 } else { 8 };
    image.entries.iter().enumerate().map(|(index, &(tag, value))| (dynamic + index * size, tag, value)).collect()
}

fn put(data: &mut [u8], at: usize, size: usize, value: u64) {
    let big = data[5] == 2;
    for index in 0..size {
        let shift = 8 * if big { size - 1 - index } else { index };
        data[at + index] = (value >> shift) as u8;
    }
}

/// Retags every entry with `tag` as `DT_DEBUG`, which nothing reads.
fn without_tag(mut data: Vec<u8>, tag: u64) -> Vec<u8> {
    let half = if data[4] == 2 { 8 } else { 4 };
    for (at, found, _) in entries(&data) {
        if found == tag {
            put(&mut data, at, half, 21);
        }
    }
    data
}

#[test]
fn the_gnu_hash_table_alone_gives_the_symbol_count() {
    for name in ["bin/hello-x64-dyn.elf", "bin/libhelper-x86.so", "bin/hello-arm.elf", "bin/hello-riscv64.elf"] {
        let gnu_only = without_tag(sectionless(fixture(name)), DT_HASH);
        let image = Image::parse(&gnu_only).unwrap();
        assert!(image.value(DT_HASH).is_none() && image.value(DT_GNU_HASH).is_some(), "{name}");
        let classic = Image::parse(&fixture(name)).map(|image| symbol_count(&image).unwrap()).unwrap();
        assert_eq!(symbol_count(&image).unwrap(), classic, "{name}");
        let original = load(fixture(name));
        let stripped = load(gnu_only);
        assert_eq!(
            names(&stripped.exports, |export| (&export.name, export.address)),
            names(&original.exports, |export| (&export.name, export.address)),
            "{name}"
        );
    }
}

#[test]
fn without_a_count_the_table_is_not_guessed() {
    let mut data = sectionless(fixture("bin/hello-mipsel.elf"));
    for tag in [DT_HASH, DT_GNU_HASH, DT_MIPS_SYMTABNO] {
        data = without_tag(data, tag);
    }
    let binary = load(data);
    assert!(binary.exports.is_empty() && binary.imports.is_empty());
    assert!(binary.warnings.iter().any(|warning| warning.contains("gives its length")), "{:?}", binary.warnings);
}

#[test]
fn constructors_and_destructors_seed_functions() {
    let data = fixture("mips/router-gnu-mips.elf");
    let dynamic = read(&data, false).unwrap();
    assert_eq!(dynamic.constructors, [0x740, 0xea0, 0xa90, 0xa24]);
    for binary in [load(data.clone()), load(sectionless(data))] {
        for start in [0x740, 0xea0, 0xa90, 0xa24] {
            assert!(binary.function_starts.contains(&start), "{start:#x}: {:?}", binary.function_starts);
        }
    }
}

/// A small ELF64 little-endian image: one PT_LOAD over the whole file at address 0 and a PT_DYNAMIC with
/// `dynamic`'s entries at 0x100; `extra` is copied to 0x200.
fn image64(dynamic: &[(u64, u64)], extra: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 0x200 + extra.len()];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 2;
    data[5] = 1;
    put(&mut data, 18, 2, 62);
    put(&mut data, 32, 8, 0x40);
    put(&mut data, 54, 2, 56);
    put(&mut data, 56, 2, 2);
    let length = data.len() as u64;
    for (index, (kind, offset, size)) in [(PT_LOAD, 0, length), (PT_DYNAMIC, 0x100, 0x100)].into_iter().enumerate() {
        let at = 0x40 + index * 56;
        put(&mut data, at, 4, u64::from(kind));
        put(&mut data, at + 8, 8, offset);
        put(&mut data, at + 16, 8, offset);
        put(&mut data, at + 32, 8, size);
        put(&mut data, at + 40, 8, size);
    }
    for (index, &(tag, value)) in dynamic.iter().enumerate() {
        put(&mut data, 0x100 + index * 16, 8, tag);
        put(&mut data, 0x108 + index * 16, 8, value);
    }
    data[0x200..].copy_from_slice(extra);
    data
}

#[test]
fn a_rela_relative_relocation_supplies_a_zero_init_array_slot() {
    // The init array at 0x200 holds 0 and 0x5000; a R_X86_64_RELATIVE relocation at 0x210 fills the first.
    let mut extra = vec![0u8; 0x30];
    extra[8..16].copy_from_slice(&0x5000u64.to_le_bytes());
    extra[0x10..0x18].copy_from_slice(&0x200u64.to_le_bytes());
    extra[0x18..0x20].copy_from_slice(&8u64.to_le_bytes());
    extra[0x20..0x28].copy_from_slice(&0x4321u64.to_le_bytes());
    let data = image64(
        &[(DT_INIT_ARRAY, 0x200), (DT_INIT_ARRAYSZ, 16), (DT_RELA, 0x210), (DT_RELASZ, 24), (DT_RELAENT, 24)],
        &extra,
    );
    assert_eq!(read(&data, true).unwrap().constructors, [0x4321, 0x5000]);
}

#[test]
fn a_gnu_hash_chain_that_never_ends_is_refused() {
    // One bucket naming symbol 1, no Bloom words, and chain words that never set the low bit up to the file's end.
    let mut extra = vec![0u8; 0x40];
    extra[..16].copy_from_slice(&[1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    extra[16..20].copy_from_slice(&1u32.to_le_bytes());
    let data = image64(&[(DT_GNU_HASH, 0x200), (DT_SYMTAB, 0x200), (DT_STRTAB, 0x200), (DT_STRSZ, 1)], &extra);
    let image = Image::parse(&data).unwrap();
    assert!(symbol_count(&image).is_err());
    let dynamic = read(&data, true).unwrap();
    assert!(dynamic.symbols.is_empty());
    assert!(dynamic.warnings.iter().any(|warning| warning.contains("chain")), "{:?}", dynamic.warnings);
}

#[test]
fn implausible_counts_and_tables_outside_the_file_read_nothing() {
    for (tag, value) in [(DT_MIPS_SYMTABNO, u64::from(u32::MAX)), (DT_HASH, u64::MAX - 2), (DT_HASH, 0x10_0000)] {
        let data = image64(&[(tag, value), (DT_SYMTAB, 0x200), (DT_STRTAB, 0x200), (DT_STRSZ, 1)], &[0; 16]);
        let dynamic = read(&data, true).unwrap();
        assert!(dynamic.symbols.is_empty(), "{tag:#x}");
        assert!(!dynamic.warnings.is_empty(), "{tag:#x}");
    }
    // Relocation and constructor tables whose sizes run past every segment read nothing either.
    let data = image64(
        &[
            (DT_RELA, 0x200),
            (DT_RELASZ, 24 << 40),
            (DT_RELAENT, 24),
            (DT_INIT_ARRAY, u64::MAX - 7),
            (DT_INIT_ARRAYSZ, 64),
        ],
        &[0; 16],
    );
    let dynamic = read(&data, true).unwrap();
    assert!(dynamic.relocations.is_empty() && dynamic.constructors.is_empty());
}

/// Corrupting any byte of a section-less file's headers, dynamic section, hash and symbol tables, or truncating it,
/// never panics the loader.
#[test]
fn hostile_dynamic_sections_never_panic() {
    for name in ["mips/router-gnu-mips.elf", "bin/hello-x64-dyn.elf", "bin/libhelper-x86.so"] {
        let original = sectionless(fixture(name));
        let arch = load(original.clone()).arch;
        let image = Image::parse(&original).unwrap();
        let mut offsets: Vec<usize> = (0..0x200.min(original.len())).collect();
        for tag in [DT_HASH, DT_GNU_HASH, DT_SYMTAB, DT_STRTAB, DT_REL, DT_RELA, DT_JMPREL, DT_INIT_ARRAY] {
            if let Some(start) = image.value(tag).and_then(|address| image.offset_of(address, 1)) {
                offsets.extend(start..(start + 64).min(original.len()));
            }
        }
        offsets.extend(entries(&original).iter().flat_map(|&(at, ..)| at..at + 16));
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for &offset in &offsets {
            for value in [0x00, 0xff, 0x7f, 0x80] {
                let mut data = original.clone();
                if offset >= data.len() {
                    continue;
                }
                data[offset] = value;
                let _ = read(&data, true);
                let _ = Binary::from_owned_native_bytes(data, arch);
            }
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let length = (state as usize) % original.len();
            let _ = read(&original[..length], true);
        }
    }
}
