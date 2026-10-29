use std::path::PathBuf;

use rampage_loaders::Binary;
use rampage_loaders::buildinfo::{BlobStatus, go, rust};
use rampage_loaders::gopclntab::GoTableVersion;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

#[test]
fn reads_go_build_info_from_elf_macho_and_pe() {
    for (name, section, goos, goarch) in [
        ("buildinfo-go-x64.elf", ".go.buildinfo", "linux", "amd64"),
        ("buildinfo-go-arm64.macho", "__go_buildinfo", "darwin", "arm64"),
        ("buildinfo-go-x64.exe", ".data", "windows", "amd64"),
    ] {
        let binary = Binary::open(fixture(name)).unwrap();
        let info = go::read(&binary).unwrap_or_else(|| panic!("{name}: no build info"));
        assert_eq!(info.status, BlobStatus::Present, "{name}: {info:?}");
        assert_eq!(info.location.section, section, "{name}");
        assert_eq!(info.location.address % 16, 0, "{name}");
        assert_eq!(info.layout, go::GoLayout::Inline, "{name}");
        let version = info.go_version.as_deref().unwrap();
        assert!(version.starts_with("go1."), "{name}: {version}");
        assert_eq!(go::expected_table(version), Some(GoTableVersion::Go120), "{name}");
        assert_eq!(info.path.as_deref(), Some("example.com/buildinfo"), "{name}");
        let main = info.main.as_ref().unwrap();
        assert_eq!((main.path.as_str(), main.version.as_str(), &main.sum), ("example.com/buildinfo", "(devel)", &None));
        assert_eq!(info.deps.len(), 1, "{name}");
        let dep = &info.deps[0];
        assert_eq!((dep.path.as_str(), dep.version.as_str()), ("example.com/greet", "v0.1.0"), "{name}");
        let replace = dep.replace.as_ref().unwrap();
        assert_eq!((replace.path.as_str(), replace.version.as_str()), ("./greet", "(devel)"), "{name}");
        let setting =
            |key: &str| info.settings.iter().find(|setting| setting.key == key).map(|setting| &*setting.value);
        assert_eq!(setting("-compiler"), Some("gc"), "{name}");
        assert_eq!(setting("-trimpath"), Some("true"), "{name}");
        assert_eq!(setting("CGO_ENABLED"), Some("0"), "{name}");
        assert_eq!(setting("GOOS"), Some(goos), "{name}");
        assert_eq!(setting("GOARCH"), Some(goarch), "{name}");
        assert!(info.warnings.is_empty(), "{name}: {:?}", info.warnings);
        assert!(rust::read(&binary).is_none(), "{name}");
    }
}

#[test]
fn reads_cargo_auditable_data_from_elf_macho_and_pe() {
    for name in ["auditable-x64.elf", "auditable-arm64.macho", "auditable-x64.exe"] {
        let binary = Binary::open(fixture(name)).unwrap();
        let audit = rust::read(&binary).unwrap_or_else(|| panic!("{name}: no .dep-v0"));
        assert_eq!(audit.status, BlobStatus::Present, "{name}: {audit:?}");
        assert_eq!(audit.location.section, ".dep-v0", "{name}");
        assert_eq!(audit.roots, [0], "{name}");
        let names: Vec<(&str, &str, &str)> =
            audit.packages.iter().map(|package| (&*package.name, &*package.source, &*package.kind)).collect();
        assert_eq!(
            names,
            [
                ("auditable-fixture", "local", "runtime"),
                ("serde", "crates.io", "runtime"),
                ("cc", "crates.io", "build"),
                ("serde_derive", "crates.io", "runtime"),
            ],
            "{name}"
        );
        assert_eq!(audit.packages[0].dependencies, [1, 2], "{name}");
        assert!(audit.warnings.is_empty(), "{name}: {:?}", audit.warnings);
        assert!(go::read(&binary).is_none(), "{name}");
    }
}

#[test]
fn ordinary_binaries_have_neither_record() {
    for name in ["hello-x64.elf", "hello-x64.exe", "hello-arm64.macho"] {
        let binary = Binary::open(fixture(name)).unwrap();
        assert!(go::read(&binary).is_none(), "{name}");
        assert!(rust::read(&binary).is_none(), "{name}");
    }
}

#[test]
fn a_corrupted_dep_v0_section_is_unreadable_not_absent() {
    let path = fixture("auditable-x64.elf");
    let mut bytes = std::fs::read(&path).unwrap();
    let binary = Binary::open(&path).unwrap();
    let section = binary.sections.iter().find(|section| section.name == rust::SECTION).unwrap();
    let start = section.file_offset.unwrap() as usize;
    bytes[start..start + 4].copy_from_slice(b"junk");
    let binary = Binary::from_owned_native_bytes(bytes, binary.arch).unwrap();
    let audit = rust::read(&binary).unwrap();
    assert_eq!(audit.status, BlobStatus::Unreadable);
    assert!(audit.reason.unwrap().contains("zlib"));
}

#[test]
fn a_corrupted_go_header_is_unreadable_not_absent() {
    let path = fixture("buildinfo-go-x64.elf");
    let binary = Binary::open(&path).unwrap();
    let location = go::read(&binary).unwrap().location;
    let section = binary.sections.iter().find(|section| section.name == location.section).unwrap();
    let start = (section.file_offset.unwrap() + location.address - section.address) as usize;
    let mut bytes = std::fs::read(&path).unwrap();
    // The inline version length becomes an unterminated uvarint.
    bytes[start + 32..start + 48].fill(0xff);
    let binary = Binary::from_owned_native_bytes(bytes, binary.arch).unwrap();
    let info = go::read(&binary).unwrap();
    assert_eq!(info.status, BlobStatus::Unreadable);
    assert!(info.reason.as_deref().unwrap().contains("version string"), "{info:?}");
}
