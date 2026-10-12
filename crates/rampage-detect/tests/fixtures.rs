//! Tests against the shared real fixtures. These cover the compiler/linker/Go paths on genuine binaries and
//! confirm an ordinary unpacked binary is not misreported as packed. No UPX binary is installed, so the packer
//! path is exercised only by the synthetic tests in `synthetic.rs`.

use rampage_detect::{identify, Kind, SignatureDb};
use rampage_loaders::Binary;

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn detect(name: &str) -> Vec<rampage_detect::Detection> {
    let binary = Binary::open(fixture(name)).expect("fixture loads");
    identify(&binary, &SignatureDb::bundled())
}

fn named(detections: &[rampage_detect::Detection], name: &str) -> bool {
    detections.iter().any(|d| d.name == name)
}

#[test]
fn go_binary_is_detected_by_its_pclntab() {
    let detections = detect("hello-go-x64.elf");
    let go = detections.iter().find(|d| d.name == "Go").expect("Go detected");
    assert_eq!(go.kind, Kind::Compiler);
    assert!(!go.evidence.is_empty());
}

#[test]
fn clang_static_elf_reports_clang_and_lld() {
    // hello-x64.elf is a static binary whose .comment records "Homebrew clang version ..." and "Linker: ... LLD".
    let detections = detect("hello-x64.elf");
    assert!(named(&detections, "Clang/LLVM"), "expected Clang/LLVM in {detections:?}");
    assert!(named(&detections, "LLD"), "expected LLD linker in {detections:?}");
}

#[test]
fn mingw_pe_is_detected() {
    // hello-x64.exe is built with MinGW-w64; its runtime banner is embedded in read-only data.
    let detections = detect("hello-x64.exe");
    assert!(named(&detections, "MinGW/GCC"), "expected MinGW/GCC in {detections:?}");
}

#[test]
fn ordinary_binaries_are_not_misreported_as_packed_or_protected() {
    for name in ["hello-x64.elf", "hello-go-x64.elf", "hello-x64.exe"] {
        let detections = detect(name);
        let bad: Vec<_> = detections
            .iter()
            .filter(|d| matches!(d.kind, Kind::Packer | Kind::Protector))
            .map(|d| d.name.clone())
            .collect();
        assert!(bad.is_empty(), "{name} wrongly flagged as packed/protected: {bad:?}");
    }
}

#[test]
fn identify_is_panic_free_across_every_fixture() {
    let db = SignatureDb::bundled();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin");
    for entry in std::fs::read_dir(dir).expect("fixtures dir") {
        let path = entry.expect("dir entry").path();
        if let Ok(binary) = Binary::open(&path) {
            // The result is unused; the point is that no malformed or exotic fixture makes identify panic.
            let _ = identify(&binary, &db);
        }
    }
}
