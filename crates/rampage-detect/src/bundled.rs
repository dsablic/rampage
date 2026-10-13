//! The starter signature database, authored here from public, well-known reverse-engineering knowledge (section
//! layouts, embedded toolchain strings, import conventions). None of it is copied from PeID's `userdb.txt`.
//!
//! Each signature is deliberately conservative: it keys off fingerprints that are cheap to read and rarely
//! collide, and it reports evidence rather than a verdict. The rules are plain [`Signature`] builder calls that
//! [`bundled`] collects, so there is no file to parse and no runtime format to trust.

use crate::model::{Condition, Kind, Signature, SignatureDb};
use crate::pattern::BytePattern;

/// Builds the bundled database. Any entry-point pattern here is a string constant validated by a unit test, so a
/// typo cannot ship silently.
pub(crate) fn bundled() -> SignatureDb {
    let mut db = SignatureDb::new();
    db.extend(packers());
    db.extend(protectors());
    db.extend(compilers());
    db.extend(linkers());
    db.extend(runtimes());
    db.extend(installers());
    db
}

/// Parses an entry-point pattern that is a crate constant. Panicking here is correct: a bad constant is a bug in
/// this file, caught by [`tests::bundled_patterns_parse`], never a runtime input.
fn ep(pattern: &str) -> Condition {
    Condition::Entry { pattern: BytePattern::parse(pattern).expect("bundled pattern parses"), ep_only: true }
}

/// A byte pattern that may sit anywhere in the image, also a crate constant.
fn anywhere(pattern: &str) -> Condition {
    Condition::Entry { pattern: BytePattern::parse(pattern).expect("bundled pattern parses"), ep_only: false }
}

fn section(name: &str) -> Condition {
    Condition::SectionName(name.to_owned())
}

fn any_section(names: &[&str]) -> Condition {
    Condition::AnySectionName(names.iter().map(|name| (*name).to_owned()).collect())
}

/// Section names that carry the tool's own brand, so only that tool emits them (distinctive on their own).
fn unique_section(names: &[&str]) -> Condition {
    Condition::UniqueSectionName(names.iter().map(|name| (*name).to_owned()).collect())
}

fn contains(needle: &str) -> Condition {
    Condition::SectionContains { section: None, needle: needle.as_bytes().to_vec() }
}

fn section_contains(name: &str, needle: &str) -> Condition {
    Condition::SectionContains { section: Some(name.to_owned()), needle: needle.as_bytes().to_vec() }
}

fn symbol(name: &str) -> Condition {
    Condition::Symbol(name.to_owned())
}

fn versioned_import(prefix: &str) -> Condition {
    Condition::VersionedImportLibrary(prefix.to_owned())
}

fn packers() -> Vec<Signature> {
    vec![
        // UPX renames the first two sections UPX0 (unpacked) and UPX1 (packed); both present is a reliable tell.
        Signature::new("UPX", Kind::Packer, vec![section("UPX0"), section("UPX1")]).with_note("UPX0 and UPX1 sections"),
        // The classic 32-bit UPX stub: pushad, then a pointer load into esi/edi.
        Signature::new("UPX", Kind::Packer, vec![ep("60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ??")])
            .with_note("pushad + lea esi/edi entry stub"),
        Signature::new("ASPack", Kind::Packer, vec![unique_section(&[".aspack"])]).with_note("ASPack section name"),
        // ASProtect also emits .adata, so on its own it only suggests ASPack.
        Signature::new("ASPack", Kind::Packer, vec![section(".adata")]).with_note("ASPack/ASProtect .adata section"),
        Signature::new("MPRESS", Kind::Packer, vec![unique_section(&[".MPRESS1", ".MPRESS2"])])
            .with_note("MPRESS section names"),
        Signature::new("PECompact", Kind::Packer, vec![any_section(&["pec1", "PEC2", ".pec"])])
            .with_note("PECompact section names"),
        Signature::new("Petite", Kind::Packer, vec![unique_section(&[".petite"])]).with_note("Petite section name"),
        Signature::new("NsPack", Kind::Packer, vec![unique_section(&[".nsp0", ".nsp1", ".nsp2"])])
            .with_note("NsPack section names"),
        Signature::new("FSG", Kind::Packer, vec![ep("87 25 ?? ?? ?? ?? 61 94")]).with_note("FSG entry stub"),
    ]
}

fn protectors() -> Vec<Signature> {
    vec![
        Signature::new("VMProtect", Kind::Protector, vec![unique_section(&[".vmp0", ".vmp1", ".vmp2"])])
            .with_note("VMProtect section names"),
        Signature::new("Themida/WinLicense", Kind::Protector, vec![unique_section(&[".themida", ".winlice"])])
            .with_note("Themida/WinLicense section names"),
        Signature::new("Enigma", Kind::Protector, vec![unique_section(&[".enigma1", ".enigma2"])])
            .with_note("Enigma Protector section names"),
    ]
}

fn compilers() -> Vec<Signature> {
    vec![
        // Go keeps its program-counter line table in a dedicated section under either platform's spelling.
        Signature::new("Go", Kind::Compiler, vec![unique_section(&[".gopclntab", "__gopclntab"])])
            .with_note("Go pclntab section"),
        Signature::new("Go", Kind::Compiler, vec![contains("Go build ID:")]).with_note("Go build ID string"),
        // .NET assemblies run through the CLR shim; native code and a CLI header both betray them.
        Signature::new(".NET", Kind::Compiler, vec![Condition::ImportFunction("_CorExeMain".to_owned())])
            .with_note("mscoree _CorExeMain import"),
        Signature::new(".NET", Kind::Compiler, vec![Condition::ImportFunction("_CorDllMain".to_owned())])
            .with_note("mscoree _CorDllMain import (managed DLL)"),
        Signature::new(".NET", Kind::Compiler, vec![Condition::ImportLibrary("mscoree".to_owned())])
            .with_note("mscoree.dll import"),
        Signature::new(".NET", Kind::Compiler, vec![section(".cormeta")]).with_note(".cormeta CLR metadata"),
        // MSVC links against a versioned C/C++ runtime. The unversioned msvcrt.dll is the system runtime that
        // MinGW and Rust's gnu targets use, so it says nothing about MSVC.
        Signature::new("MSVC", Kind::Compiler, vec![versioned_import("vcruntime")]).with_note("VCRUNTIME import"),
        Signature::new("MSVC", Kind::Compiler, vec![versioned_import("msvcr")]).with_note("MSVCR runtime import"),
        Signature::new("MSVC", Kind::Compiler, vec![versioned_import("msvcp")]).with_note("MSVCP C++ runtime import"),
        // GCC and Clang stamp a producer string into .comment. "GCC:" alone is weak: glibc's crt1.o/crti.o and
        // libgcc's crtbegin.o carry it too, so Clang- and Rust-built glibc programs show it as well.
        Signature::new("GCC", Kind::Compiler, vec![section_contains(".comment", "GCC:")])
            .with_note(".comment GCC producer (also stamped by glibc/libgcc startup objects)")
            .corroborating(),
        // A PE has no .comment: GNU ld folds GCC's .rdata$zzz producer strings into .rdata. A GCC-built
        // MinGW-w64 CRT brings its own, so a Clang build against that CRT shows them too.
        Signature::new("GCC", Kind::Compiler, vec![section_contains(".rdata", "GCC: (")])
            .with_note(".rdata GCC producer (also stamped by GCC-built MinGW-w64 CRT objects)")
            .corroborating(),
        Signature::new("Clang/LLVM", Kind::Compiler, vec![section_contains(".comment", "clang")])
            .with_note(".comment clang producer"),
        Signature::new("Rust", Kind::Compiler, vec![contains("rustc version")]).with_note("rustc version string"),
        Signature::new("Rust", Kind::Compiler, vec![section_contains(".comment", "rustc")])
            .with_note(".comment rustc producer"),
        Signature::new("Zig", Kind::Compiler, vec![section_contains(".comment", "zig")])
            .with_note(".comment zig producer"),
        // Delphi/Borland name their code and data segments in upper case and tag the toolchain vendor.
        Signature::new("Delphi/Borland", Kind::Compiler, vec![contains("Embarcadero Delphi")])
            .with_note("Embarcadero banner"),
        Signature::new("Delphi/Borland", Kind::Compiler, vec![section("CODE"), section("DATA")])
            .with_note("upper-case CODE and DATA sections"),
    ]
}

fn linkers() -> Vec<Signature> {
    vec![
        Signature::new("LLD", Kind::Linker, vec![section_contains(".comment", "LLD")])
            .with_note(".comment LLD linker tag"),
        // lld-link brands the CodeView record of a build-id debug directory (RSDS, then a GUID whose second half
        // is "LLD PDB."). An image linked without a debug directory (-s) has no such record.
        Signature::new(
            "LLD",
            Kind::Linker,
            vec![anywhere("52 53 44 53 ?? ?? ?? ?? ?? ?? ?? ?? 4C 4C 44 20 50 44 42 2E")],
        )
        .with_note("lld-link CodeView build-id record"),
        // GNU ld (BFD) writes no tag at all. mold's tag reads "mold x.y (...; compatible with GNU ld)", so it
        // must be matched by its own name, not by "GNU ld".
        Signature::new("mold", Kind::Linker, vec![section_contains(".comment", "mold ")])
            .with_note(".comment mold linker tag"),
        Signature::new("GNU gold", Kind::Linker, vec![unique_section(&[".note.gnu.gold-version"])])
            .with_note("gold version note"),
    ]
}

fn runtimes() -> Vec<Signature> {
    vec![
        // The MinGW-w64 CRT's runtime-failure banner. It names the C runtime, not the compiler: GCC and Clang
        // (zig cc, llvm-mingw) both link it.
        Signature::new("MinGW-w64", Kind::Runtime, vec![contains("Mingw-w64 runtime failure")])
            .with_note("MinGW-w64 CRT runtime-failure banner"),
        // Only glibc versions its symbols GLIBC_x.y, and only glibc's soname is libc.so.6 (musl's is libc.so,
        // uClibc's libc.so.0, Bionic's libc.so); .dynstr holds the version needs and DT_NEEDED names.
        Signature::new("glibc", Kind::Runtime, vec![section_contains(".dynstr", "GLIBC_2.")])
            .with_note("GLIBC_2.x symbol-version need"),
        Signature::new("glibc", Kind::Runtime, vec![section_contains(".dynstr", "libc.so.6")])
            .with_note("libc.so.6 (glibc soname) needed"),
        // The head of musl's strerror table (src/errno/__strerror.h); glibc and Bionic say "Success" for 0.
        Signature::new(
            "musl",
            Kind::Runtime,
            vec![contains("No error information\0Illegal byte sequence\0Domain error\0")],
        )
        .with_note("musl strerror message table"),
        // musl's static TLS setup (src/env/__init_tls.c), linked into every static musl program.
        Signature::new("musl", Kind::Runtime, vec![symbol("__init_tp"), symbol("__copy_tls")])
            .with_note("musl TLS initialization symbols"),
        Signature::new("musl", Kind::Runtime, vec![section_contains(".interp", "/ld-musl-")])
            .with_note("musl dynamic loader interpreter"),
    ]
}

fn installers() -> Vec<Signature> {
    vec![
        Signature::new("NSIS", Kind::Installer, vec![contains("NullsoftInst")]).with_note("NSIS overlay signature"),
        Signature::new("NSIS", Kind::Installer, vec![section(".ndata")]).with_note("NSIS .ndata section"),
        Signature::new("Inno Setup", Kind::Installer, vec![contains("Inno Setup")]).with_note("Inno Setup banner"),
    ]
}

#[cfg(test)]
mod tests {
    use crate::model::Condition;

    #[test]
    fn bundled_patterns_parse() {
        // Building the database runs every `ep(...)` constant through the parser; a bad constant would panic.
        let db = super::bundled();
        assert!(db.len() >= 20);
        for signature in &db.signatures {
            assert!(!signature.conditions.is_empty(), "{} has no conditions", signature.name);
            for condition in &signature.conditions {
                if let Condition::Entry { .. } = condition {
                    assert!(
                        condition.is_distinctive(),
                        "{}: entry pattern too short to be distinctive",
                        signature.name
                    );
                }
            }
        }
    }
}
