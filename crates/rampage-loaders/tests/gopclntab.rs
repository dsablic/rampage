use std::path::PathBuf;

use rampage_loaders::{Binary, SymbolKind};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

#[test]
fn recovers_function_names_from_a_stripped_go_binary() {
    // The fixture is built with `-ldflags "-s -w"`, so there is no real symbol table: every Function symbol
    // below is recovered from the pclntab, which `Binary::open` does automatically.
    let binary = Binary::open(fixture("hello-go-x64.elf")).unwrap();

    let attached =
        |name: &str| binary.symbols.iter().find(|symbol| symbol.name == name && symbol.kind == SymbolKind::Function);
    let main = attached("main.main").expect("main.main recovered at load");
    let greet = attached("main.greet").expect("main.greet recovered at load");
    assert!(main.address > 0x400000, "main.main at implausible address {:#x}", main.address);
    assert!(greet.address > 0x400000, "main.greet at implausible address {:#x}", greet.address);
    assert_ne!(main.address, greet.address);

    // Recovery pulls in the wider Go runtime too, not just package main.
    assert!(binary.symbols.len() > 100, "expected many recovered functions, got {}", binary.symbols.len());
    assert!(binary.symbols.iter().any(|symbol| symbol.name.starts_with("runtime.")));
}

#[test]
fn recovers_function_names_from_a_stripped_arm64_go_binary() {
    let mut binary = Binary::open(fixture("hello-go-arm64.elf")).unwrap();
    let report = binary.recover_go_symbols();
    assert!(report.warnings.is_empty(), "unexpected warnings: {:?}", report.warnings);
    assert!(report.functions.iter().any(|function| function.name == "main.main"), "main.main recovered");
    assert!(report.functions.iter().any(|function| function.name == "main.greet"), "main.greet recovered");
}

#[test]
fn magic_scan_recovers_names_when_the_section_is_renamed() {
    // Rename every `.gopclntab` so the named lookup misses and the bounded magic scan must find the table in
    // the read-only data by its header. The section keeps its read-only flags, so its bytes are still scanned.
    let mut bytes = std::fs::read(fixture("hello-go-x64.elf")).unwrap();
    let needle = b".gopclntab";
    let mut cursor = 0;
    let mut renamed = 0;
    while let Some(rel) = bytes[cursor..].windows(needle.len()).position(|window| window == needle) {
        let at = cursor + rel;
        bytes[at + 1] = b'z'; // ".zopclntab" matches no known pclntab section name
        cursor = at + needle.len();
        renamed += 1;
    }
    assert!(renamed >= 1, "fixture has no .gopclntab to rename");

    let path = std::env::temp_dir().join(format!("rampage-go-scan-{}.elf", std::process::id()));
    std::fs::write(&path, &bytes).unwrap();
    let binary = Binary::open(&path).unwrap();
    std::fs::remove_file(&path).unwrap();

    assert!(binary.sections.iter().all(|section| section.name != ".gopclntab"), "rename did not take");
    let attached = |name: &str| binary.symbols.iter().any(|s| s.name == name && s.kind == SymbolKind::Function);
    assert!(attached("main.main"), "main.main recovered via scan");
    assert!(attached("main.greet"), "main.greet recovered via scan");
    assert!(binary.symbols.iter().any(|symbol| symbol.name.starts_with("runtime.")), "runtime names via scan");
}

#[test]
fn magic_scan_reaches_a_pclntab_merged_into_writable_relro_data() {
    // An externally linked PIE merges the pclntab into `.data.rel.ro`, which is writable data, not rodata.
    // Rebuild that shape: name the `.gopclntab` header `.data.rel.ro` (reusing the longer `.note.gnu.build-id`
    // string's bytes) and set SHF_WRITE on it.
    let mut bytes = std::fs::read(fixture("hello-go-x64.elf")).unwrap();
    let u16_at = |bytes: &[u8], at: usize| usize::from(u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap()));
    let u32_at = |bytes: &[u8], at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let u64_at = |bytes: &[u8], at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()) as usize;
    let (shoff, shentsize, shnum, shstrndx) =
        (u64_at(&bytes, 0x28), u16_at(&bytes, 0x3A), u16_at(&bytes, 0x3C), u16_at(&bytes, 0x3E));
    let header = |index: usize| shoff + index * shentsize;
    let strtab = u64_at(&bytes, header(shstrndx) + 0x18);
    let name_of = |bytes: &[u8], index: usize| {
        let start = strtab + u32_at(bytes, header(index)) as usize;
        let end = start + bytes[start..].iter().position(|&byte| byte == 0).unwrap();
        bytes[start..end].to_vec()
    };
    let find = |bytes: &[u8], name: &[u8]| (0..shnum).find(|&index| name_of(bytes, index) == name).unwrap();
    let (pclntab, note) = (find(&bytes, b".gopclntab"), find(&bytes, b".note.gnu.build-id"));
    let note_name = u32_at(&bytes, header(note));
    let start = strtab + note_name as usize;
    bytes[start..start + 13].copy_from_slice(b".data.rel.ro\0");
    bytes[header(pclntab)..header(pclntab) + 4].copy_from_slice(&note_name.to_le_bytes());
    bytes[header(pclntab) + 8] |= 0x1;

    let path = std::env::temp_dir().join(format!("rampage-go-relro-{}.elf", std::process::id()));
    std::fs::write(&path, &bytes).unwrap();
    let binary = Binary::open(&path).unwrap();
    std::fs::remove_file(&path).unwrap();

    let relro = |section: &rampage_loaders::Section| {
        section.name == ".data.rel.ro" && section.kind == rampage_loaders::SectionKind::Data
    };
    assert!(binary.sections.iter().any(relro), "the pclntab section is now writable relro data");
    let attached = |name: &str| binary.symbols.iter().any(|s| s.name == name && s.kind == SymbolKind::Function);
    assert!(attached("main.main"), "main.main recovered from relro data");
}

#[test]
fn recovery_on_a_non_go_binary_is_a_clean_no_op() {
    let mut binary = Binary::open(fixture("hello-x64.elf")).unwrap();
    let before = binary.symbols.len();
    let report = binary.recover_go_symbols();
    assert!(report.functions.is_empty(), "a C binary has no gopclntab");
    assert_eq!(binary.symbols.len(), before, "recovery must not touch symbols when there is no table");
}
