//! Tests against the shared real fixtures. These cover the compiler/linker/Go paths on genuine binaries and
//! confirm an ordinary unpacked binary is not misreported as packed. No UPX binary is installed, so the packer
//! path is exercised only by the crafted-image unit tests in `src/matcher.rs`.

use rampage_detect::{Confidence, Kind, SignatureDb, identify};
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
    // .gopclntab is emitted only by the Go toolchain, so it is distinctive on its own.
    assert_eq!(go.confidence, Confidence::Strong);
}

#[test]
fn clang_static_elf_reports_clang_and_lld() {
    // hello-x64.elf is a static binary whose .comment records "Homebrew clang version ..." and "Linker: ... LLD".
    let detections = detect("hello-x64.elf");
    assert!(named(&detections, "Clang/LLVM"), "expected Clang/LLVM in {detections:?}");
    assert!(named(&detections, "LLD"), "expected LLD linker in {detections:?}");
}

fn find<'a>(detections: &'a [rampage_detect::Detection], name: &str) -> Option<&'a rampage_detect::Detection> {
    detections.iter().find(|d| d.name == name)
}

#[test]
fn mingw_w64_crt_is_a_runtime_not_a_gcc_compiler() {
    // hello-x64.exe is `zig cc -target x86_64-windows-gnu`: Clang against the MinGW-w64 CRT, whose runtime-failure
    // banner sits in read-only data. That banner names the C runtime; nothing GCC-specific is in the image.
    let detections = detect("hello-x64.exe");
    let mingw = find(&detections, "MinGW-w64").expect("MinGW-w64 runtime");
    assert_eq!((mingw.kind, mingw.confidence), (Kind::Runtime, Confidence::Strong));
    assert!(!named(&detections, "GCC"), "no GCC producer string in a Clang-built PE: {detections:?}");
    assert!(!detections.iter().any(|d| d.kind == Kind::Compiler && d.name.contains("MinGW")), "{detections:?}");
}

#[test]
fn mingw_w64_runtime_is_not_reported_on_msvc_elf_or_macho_fixtures() {
    for name in ["Microsoft.Bcl.HashCode.dll", "hello-x64.elf", "hello-x64-dyn.elf", "hello-x64.macho"] {
        let detections = detect(name);
        assert!(!named(&detections, "MinGW-w64"), "{name}: {detections:?}");
    }
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
