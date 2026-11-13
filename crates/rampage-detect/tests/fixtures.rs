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
fn lld_link_is_named_by_its_codeview_build_id_record_when_one_is_present() {
    let detections = detect("hello-x64.exe");
    let lld = find(&detections, "LLD").expect("LLD from the debug directory");
    assert_eq!((lld.kind, lld.confidence), (Kind::Linker, Confidence::Strong));
    // Microsoft's link.exe writes an RSDS record too, without lld's brand.
    assert!(!named(&detect("Microsoft.Bcl.HashCode.dll"), "LLD"));
    // persist-x64.exe is linked with -s, which drops the debug directory: nothing is left to key on.
    let stripped = Binary::open(fixture("../../../crates/rampage-api/tests/fixtures/persist-x64.exe")).unwrap();
    assert!(!named(&identify(&stripped, &SignatureDb::bundled()), "LLD"));
}

#[test]
fn apple_ld_is_named_by_the_build_version_tool_it_records() {
    for name in ["hello-x64.macho", "hello-arm64.macho", "hello-x64.dylib", "hello-x64-stripped.macho"] {
        let detections = detect(name);
        let ld = find(&detections, "Apple ld").unwrap_or_else(|| panic!("{name}: {detections:?}"));
        assert_eq!((ld.kind, ld.confidence), (Kind::Linker, Confidence::Strong));
        assert!(ld.evidence[0].starts_with("LC_BUILD_VERSION records ld "), "{:?}", ld.evidence);
        assert!(!named(&detections, "LLD"), "{name}");
    }
    // ld64.lld records itself as tool 4; an object, never linked, records no tool; ELF and PE have none.
    assert!(named(&detect("debug-x64.macho"), "LLD"));
    assert!(!named(&detect("debug-x64.macho"), "Apple ld"));
    for name in ["hello-x64.o", "hello-x64.elf", "hello-x64.exe"] {
        assert!(!named(&detect(name), "Apple ld"), "{name}");
    }
}

fn api_fixture(name: &str) -> Vec<rampage_detect::Detection> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../rampage-api/tests/fixtures").join(name);
    identify(&Binary::open(path).expect("fixture loads"), &SignatureDb::bundled())
}

#[test]
fn zig_is_named_by_its_compiler_rt_symbols_or_tentatively_by_its_libc_tree() {
    for name in ["hello-x64.elf", "hello-thumb.elf", "hello-ppc.elf", "hello-arm.elf"] {
        let detections = detect(name);
        let zig = find(&detections, "Zig").unwrap_or_else(|| panic!("{name}: {detections:?}"));
        assert_eq!((zig.kind, zig.confidence), (Kind::Compiler, Confidence::Strong), "{name}");
        assert!(zig.evidence.iter().any(|line| line.contains("(prefix compiler_rt.)")), "{:?}", zig.evidence);
    }
    // net-client-x64.elf keeps debug info for the glibc start files zig compiled, but no compiler_rt symbol.
    let debug = api_fixture("net-client-x64.elf");
    let zig = find(&debug, "Zig").expect("Zig from the libc source path");
    assert_eq!(zig.confidence, Confidence::Tentative);
    // Its stripped twin keeps neither: no general marker is left, so Zig stays unreported.
    assert!(!named(&api_fixture("net-client-x64-stripped.elf"), "Zig"));
}

#[test]
fn zig_is_not_reported_for_other_toolchains_or_unlinked_objects() {
    for name in ["hello-go-x64.elf", "hello-x64.macho", "hello-x64.o", "hello-x64-elf.o", "Microsoft.Bcl.HashCode.dll"]
    {
        assert!(!named(&detect(name), "Zig"), "{name}");
    }
}

#[test]
fn mingw_w64_runtime_is_not_reported_on_msvc_elf_or_macho_fixtures() {
    for name in ["Microsoft.Bcl.HashCode.dll", "hello-x64.elf", "hello-x64-dyn.elf", "hello-x64.macho"] {
        let detections = detect(name);
        assert!(!named(&detections, "MinGW-w64"), "{name}: {detections:?}");
    }
}

fn runtimes(detections: &[rampage_detect::Detection]) -> Vec<&str> {
    detections.iter().filter(|d| d.kind == Kind::Runtime).map(|d| d.name.as_str()).collect()
}

#[test]
fn dynamic_glibc_programs_report_glibc_from_their_version_needs() {
    // zig cc -target *-linux-gnu: dynamically linked against glibc, so .dynstr names GLIBC_2.x and libc.so.6.
    for name in ["hello-x64-dyn.elf", "hello-arm64.elf", "hello-mips.elf", "hello-s390x.elf"] {
        let detections = detect(name);
        let glibc = find(&detections, "glibc").unwrap_or_else(|| panic!("{name}: {detections:?}"));
        assert_eq!((glibc.kind, glibc.confidence), (Kind::Runtime, Confidence::Strong));
        assert!(glibc.evidence.iter().any(|line| line.contains("GLIBC_2.")), "{name}: {:?}", glibc.evidence);
        assert_eq!(runtimes(&detections), ["glibc"], "{name}");
    }
}

#[test]
fn static_musl_programs_report_musl_with_or_without_symbols() {
    // hello-x64.elf keeps its symbol table; musl-static-x86_64.elf is stripped, leaving musl's strerror table.
    let symbols = detect("hello-x64.elf");
    let musl = find(&symbols, "musl").expect("musl from symbols");
    assert!(musl.evidence.contains(&"symbol __init_tp present".to_owned()), "{:?}", musl.evidence);
    let stripped = detect("musl-static-x86_64.elf");
    let musl = find(&stripped, "musl").expect("musl from strerror");
    assert_eq!((musl.kind, musl.confidence), (Kind::Runtime, Confidence::Strong));
    assert!(musl.evidence[0].contains("No error information"), "{:?}", musl.evidence);
    for detections in [&symbols, &stripped] {
        assert_eq!(runtimes(detections), ["musl"]);
    }
}

#[test]
fn no_libc_runtime_is_claimed_without_libc_evidence() {
    // Go links no libc; objects are not linked; Mach-O programs use libSystem, which no signature names.
    for name in ["hello-go-x64.elf", "hello-x64-elf.o", "hello-x64.macho", "Microsoft.Bcl.HashCode.dll"] {
        let detections = detect(name);
        assert!(runtimes(&detections).is_empty(), "{name}: {detections:?}");
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

/// A minimal arm64 Mach-O executable with one segment per `(segment, section)` pair, each holding 0x100 bytes.
fn macho_with_sections(sections: &[(&str, &str)]) -> Vec<u8> {
    let name = |text: &str| {
        let mut field = [0u8; 16];
        field[..text.len()].copy_from_slice(text.as_bytes());
        field
    };
    let commands = sections.len() as u32;
    let mut out = Vec::new();
    for word in [0xfeed_facf_u32, 0x0100_000c, 0, 2, commands, commands * (72 + 80), 0, 0] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    for (index, (segment, section)) in sections.iter().enumerate() {
        let offset = 0x1000 * (index as u64 + 1);
        out.extend_from_slice(&0x19u32.to_le_bytes());
        out.extend_from_slice(&(72u32 + 80).to_le_bytes());
        out.extend_from_slice(&name(segment));
        for word in [0x1_0000_0000 + offset, 0x1000, offset, 0x1000] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        for word in [5u32, 5, 1, 0] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.extend_from_slice(&name(section));
        out.extend_from_slice(&name(segment));
        for word in [0x1_0000_0000 + offset, 0x100] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        for word in [offset as u32, 2, 0, 0, 0, 0, 0, 0] {
            out.extend_from_slice(&word.to_le_bytes());
        }
    }
    out.resize(0x1000 * (sections.len() + 1), 0);
    out
}

fn detect_bytes(name: &str, bytes: &[u8]) -> Vec<rampage_detect::Detection> {
    let path = std::env::temp_dir().join(format!("rampage-detect-{name}-{}", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let binary = Binary::open(&path).expect("synthetic image loads");
    std::fs::remove_file(&path).unwrap();
    identify(&binary, &SignatureDb::bundled())
}

#[test]
fn pace_wrapper_is_named_by_its_mach_o_sections() {
    let wrapped = macho_with_sections(&[
        ("__TEXT", "__text"),
        ("__DATA", "__pbootstrap"),
        ("__POVERTEXT", "__povertext"),
        ("__POVERDDATA", "__poverdata"),
    ]);
    let detections = detect_bytes("pace", &wrapped);
    let pace = find(&detections, "PACE (Eden/Fusion)").expect("protector detected");
    assert_eq!((pace.kind, pace.confidence), (Kind::Protector, Confidence::Strong), "{detections:?}");
    let plain = detect_bytes("pace-plain", &macho_with_sections(&[("__TEXT", "__text"), ("__DATA", "__data")]));
    assert!(plain.iter().all(|d| d.kind != Kind::Protector), "{plain:?}");
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

/// `host` with each of `payloads` appended, written to a fresh temporary file and loaded.
fn with_appended(name: &str, host: &str, payloads: &[&str]) -> Vec<rampage_detect::Detection> {
    let mut bytes = std::fs::read(fixture(host)).unwrap();
    for payload in payloads {
        bytes.extend(std::fs::read(fixture(payload)).unwrap());
    }
    let path = std::env::temp_dir().join(format!("rampage-detect-{name}-{}", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let binary = Binary::open(&path).expect("host still loads");
    std::fs::remove_file(&path).unwrap();
    identify(&binary, &SignatureDb::bundled())
}

fn summary(detections: &[rampage_detect::Detection]) -> Vec<String> {
    let mut names: Vec<String> = detections.iter().map(|d| format!("{} {:?}", d.name, d.confidence)).collect();
    names.sort();
    names
}

#[test]
fn appended_programs_lend_the_host_none_of_their_tools() {
    let carrier = with_appended("carrier", "hello-x64.macho", &["hello-x64.exe", "musl-static-x86_64.elf"]);
    assert_eq!(summary(&carrier), summary(&detect("hello-x64.macho")), "{carrier:?}");
    // The appended PE and ELF on their own still report what the host must not.
    assert!(named(&detect("hello-x64.exe"), "LLD") && named(&detect("hello-x64.exe"), "MinGW-w64"));
    assert!(named(&detect("musl-static-x86_64.elf"), "musl"));

    let carrier = with_appended("pe-carrier", "hello-x64.exe", &["musl-static-x86_64.elf", "hello-x64.macho"]);
    assert_eq!(summary(&carrier), summary(&detect("hello-x64.exe")), "{carrier:?}");
}

#[test]
fn the_detector_does_not_detect_the_signature_strings_it_links() {
    // This test program links rampage-detect, so its read-only data holds every bundled needle.
    let binary = Binary::open(std::env::current_exe().unwrap()).expect("the test binary loads");
    let detections = identify(&binary, &SignatureDb::bundled());
    // Only a glibc build's own glibc is a fact about this program; the rest would come from the signature table.
    let borrowed: Vec<_> = detections
        .iter()
        .filter(|d| d.name != "glibc")
        .filter(|d| {
            matches!(d.kind, Kind::Runtime | Kind::Installer | Kind::Packer | Kind::Protector)
                || matches!(d.name.as_str(), "Zig" | "Go" | "Delphi/Borland")
                || (d.name == "LLD" && binary.format == rampage_loaders::Format::Pe)
        })
        .collect();
    assert!(borrowed.is_empty(), "{borrowed:?}");
}
