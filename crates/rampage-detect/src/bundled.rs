//! The starter signature database, authored here from public, well-known reverse-engineering knowledge (section
//! layouts, embedded toolchain strings, import conventions). None of it is copied from PeID's `userdb.txt`.
//!
//! Each signature is deliberately conservative: it keys off fingerprints that are cheap to read and rarely
//! collide, and it reports evidence rather than a verdict. The data lives as a `const` table of tuples that
//! [`bundled`] turns into [`Signature`]s, so there is no file to parse and no runtime format to trust.

use crate::model::{Condition, Kind, Signature, SignatureDb};
use crate::pattern::BytePattern;

/// Builds the bundled database. Any entry-point pattern here is a string constant validated by a unit test, so a
/// typo cannot ship silently.
pub fn bundled() -> SignatureDb {
    let mut db = SignatureDb::new();
    db.extend(packers());
    db.extend(protectors());
    db.extend(compilers());
    db.extend(linkers());
    db.extend(installers());
    db
}

/// Parses an entry-point pattern that is a crate constant. Panicking here is correct: a bad constant is a bug in
/// this file, caught by [`tests::bundled_patterns_parse`], never a runtime input.
fn ep(pattern: &str) -> Condition {
    Condition::Entry { pattern: BytePattern::parse(pattern).expect("bundled pattern parses"), ep_only: true }
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

fn packers() -> Vec<Signature> {
    vec![
        // UPX renames the first two sections UPX0 (unpacked) and UPX1 (packed); both present is a reliable tell.
        Signature::new("UPX", Kind::Packer, vec![section("UPX0"), section("UPX1")])
            .with_note("UPX0 and UPX1 sections"),
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
        Signature::new("FSG", Kind::Packer, vec![ep("87 25 ?? ?? ?? ?? 61 94")])
            .with_note("FSG entry stub"),
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
        Signature::new(".NET", Kind::Compiler, vec![Condition::ImportLibrary("mscoree".to_owned())])
            .with_note("mscoree.dll import"),
        Signature::new(".NET", Kind::Compiler, vec![section(".cormeta")]).with_note(".cormeta CLR metadata"),
        // MSVC links against a versioned C/C++ runtime import library.
        Signature::new("MSVC", Kind::Compiler, vec![Condition::ImportLibrary("vcruntime".to_owned())])
            .with_note("VCRUNTIME import"),
        Signature::new("MSVC", Kind::Compiler, vec![Condition::ImportLibrary("msvcr".to_owned())])
            .with_note("MSVCR runtime import"),
        // MinGW embeds its runtime-failure banner in read-only data.
        Signature::new("MinGW/GCC", Kind::Compiler, vec![contains("Mingw-w64")]).with_note("Mingw-w64 banner"),
        // GCC and Clang stamp a producer string into .comment.
        Signature::new("GCC", Kind::Compiler, vec![section_contains(".comment", "GCC:")])
            .with_note(".comment GCC producer"),
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
        Signature::new("GNU ld", Kind::Linker, vec![section_contains(".comment", "GNU ld")])
            .with_note(".comment GNU ld tag"),
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
                if let Condition::Entry { pattern, .. } = condition {
                    assert!(!pattern.is_empty());
                }
            }
        }
    }
}
