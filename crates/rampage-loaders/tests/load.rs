use std::path::PathBuf;

use rampage_arch::Arch;
use rampage_loaders::{Binary, Format, SymbolKind};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

const GREETING: &[u8] = b"rampage fixture greeting";

fn check_x64_fixture(name: &str, format: Format, add_symbol: &str) {
    let binary = Binary::open(fixture(name)).unwrap();
    assert_eq!(binary.format, format);
    assert_eq!(binary.arch, Arch::X86_64);

    let entry_segment = binary.segment_containing(binary.entry).expect("entry inside a segment");
    assert!(entry_segment.perms.execute, "entry segment {:?} not executable", entry_segment.name);
    assert_eq!(binary.read(binary.entry, 16).map(<[u8]>::len), Some(16));

    let add_address = match binary.symbol_by_name(add_symbol) {
        Some(symbol) => {
            assert_eq!(symbol.kind, SymbolKind::Function);
            symbol.address
        }
        None => binary.exports.iter().find(|export| export.name == add_symbol).expect("add symbol or export").address,
    };
    assert!(binary.segment_containing(add_address).unwrap().perms.execute);

    let found = binary.segments.iter().any(|segment| {
        binary
            .read(segment.address, segment.file_size)
            .is_some_and(|bytes| bytes.windows(GREETING.len()).any(|w| w == GREETING))
    });
    assert!(found, "greeting not readable through segments");
}

#[test]
fn loads_elf() {
    check_x64_fixture("hello-x64.elf", Format::Elf, "add");
}

#[test]
fn loads_pe() {
    check_x64_fixture("hello-x64.exe", Format::Pe, "add");
}

#[test]
fn loads_macho() {
    check_x64_fixture("hello-x64.macho", Format::MachO, "_add");
}

#[test]
fn loads_arm64_macho_metadata() {
    let binary = Binary::open(fixture("hello-arm64.macho")).unwrap();
    assert_eq!(binary.arch, Arch::Aarch64);
    assert!(binary.imports.iter().any(|import| import.name == "_puts"));
}

#[test]
fn reads_never_cross_past_file_backed_bytes() {
    let binary = Binary::open(fixture("hello-x64.elf")).unwrap();
    let segment = binary.segments.iter().find(|segment| segment.file_size > 0).unwrap();
    assert!(binary.read(segment.address + segment.file_size - 1, 1).is_some());
    assert!(binary.read(segment.address + segment.file_size - 1, 2).is_none());
    assert!(binary.read(u64::MAX - 4, 8).is_none());
}

#[test]
fn rejects_non_binaries() {
    let error = Binary::open(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap_err();
    assert!(matches!(error, rampage_loaders::LoadError::Parse(_)), "{error:?}");
}

#[test]
fn universal_binary_defaults_to_x86_64_slice() {
    let binary = Binary::open(fixture("hello-universal.macho")).unwrap();
    assert_eq!(binary.arch, Arch::X86_64);
    assert_eq!(binary.slices, [Arch::X86_64, Arch::Aarch64]);
    let main = binary.symbol_by_name("_main").unwrap();
    assert_eq!(binary.entry, main.address);
    assert_eq!(binary.read(binary.entry, 1), Some(&[0x55][..]), "push rbp");
}

#[test]
fn universal_binary_slice_can_be_selected() {
    let binary = Binary::open_with(fixture("hello-universal.macho"), Some(Arch::Aarch64)).unwrap();
    assert_eq!(binary.arch, Arch::Aarch64);
    assert!(binary.imports.iter().any(|import| import.name == "_puts"));
    let thin = Binary::open(fixture("hello-arm64.macho")).unwrap();
    assert_eq!(binary.read(binary.entry, 16), thin.read(thin.entry, 16));
}

#[test]
fn missing_slice_is_an_error() {
    let error = Binary::open_with(fixture("hello-universal.macho"), Some(Arch::X86)).unwrap_err();
    assert!(error.to_string().contains("x86_64"), "{error}");
}

#[test]
fn thin_binary_reports_itself_as_only_slice_and_rejects_other_arch() {
    let binary = Binary::open(fixture("hello-x64.elf")).unwrap();
    assert_eq!(binary.slices, [Arch::X86_64]);
    assert!(Binary::open_with(fixture("hello-x64.elf"), Some(Arch::Aarch64)).is_err());
}
