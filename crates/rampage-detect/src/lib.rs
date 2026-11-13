//! Packer, compiler, protector, installer, linker and runtime identification from heuristic signatures: the
//! DIE/PeID niche. Given a loaded [`rampage_loaders::Binary`], [`identify`] reports which tools likely produced it,
//! each with the evidence that fired and a confidence that is a signal, not a proof.
//!
//! # What a signature is
//!
//! A [`Signature`] names one tool, carries a [`Kind`] (packer, compiler, protector, cryptor, installer, SFX, joiner,
//! linker or runtime), and holds a list of [`Condition`]s that must all hold (logical AND) for it to match. Conditions test:
//!
//! - the container format (PE, ELF, Mach-O), which narrows the others but is no evidence itself,
//! - an entry-point byte pattern (hex with `?` nibble and `??` byte wildcards; see [`BytePattern`]),
//! - a required section name, or any of a set of names,
//! - a byte needle contained in a section (or anywhere in the image but its overlay), which covers toolchain
//!   banners and unloaded sections such as `.comment`; in a DWARF debug section; or in the overlay,
//! - the GUID of a PE's CodeView debug record,
//! - a required imported library or function, or a symbol-table name,
//! - a Mach-O `LC_BUILD_VERSION` tool entry (the linker that wrote the image),
//! - the presence of an overlay,
//! - a minimum image or section entropy.
//!
//! A search of bytes the image need not own (anywhere in it, or its overlay) can only make a detection strong
//! in a signature that also names its format: files carry other programs, and a detector carries its own
//! signature strings.
//!
//! # The bundled database
//!
//! [`SignatureDb::bundled`] returns a starter database authored here from public knowledge (section layouts,
//! embedded producer strings, import conventions), never copied from PeID's `userdb.txt`. It covers UPX, ASPack,
//! MPRESS, PECompact, Petite, NsPack and FSG (packers); VMProtect, Themida/WinLicense and Enigma (protectors);
//! Go, .NET, MSVC, GCC, Clang/LLVM, Rust, Zig and Delphi/Borland (compilers); LLD, Apple ld, mold and GNU gold
//! (linkers; GNU ld leaves no mark to key on); MinGW-w64, glibc and musl (runtimes); and NSIS and Inno Setup
//! (installers).
//!
//! # Signatures from Detect It Easy
//!
//! The bundled database also carries signatures converted from the [Detect It Easy] (DIE) database by
//! `tools/die_signatures.py`, stored as data in `data/die-signatures.json` with the pinned DIE commit they came
//! from. DIE is MIT-licensed (Copyright (c) 2012-2026 hors and the DIE contributors; the licence is in
//! `data/LICENSE.detect-it-easy` and THIRD-PARTY-NOTICES). Each such [`Signature`] has [`Source::DetectItEasy`],
//! keeps DIE's name and version strings (`version`, options in parentheses), and names its DIE script and that
//! script's authors in `origin`, which prefixes its evidence lines. A [`Detection`] lists every source that fired
//! in `sources` and the versions the matching rules name in `versions`.
//!
//! The converter reads DIE's scripts without running them and keeps only what rampage tests exactly as DIE does:
//! entry-point patterns, including DIE's relative jumps (see [`JumpPattern`]) and compares at an offset; bytes at
//! a file offset or at the start of the overlay; section names; linked library names; imported functions;
//! exports; overlay presence; and PE32/PE32+ pointer width. A converted signature is never broader than DIE's own
//! condition; scripts that need more (loops, helper functions, string searches, .NET metadata, ...) are skipped
//! and counted in the converter's report. DIE's library, tool, game-engine and format types describe content, not
//! the producing tool, and stay out; so do entry patterns identical to an entry of the PeID `userdb.txt` files
//! DIE carries, and scripts that matched clean binaries in the false-positive sweep. When several branches of one
//! DIE script match, every branch's version is listed, where DIE would report the first.
//!
//! [Detect It Easy]: https://github.com/horsicq/Detect-It-Easy
//!
//! # User-supplied databases
//!
//! [`SignatureDb::load_peid`] parses the public PeID `userdb.txt` format so users can bring their own
//! signatures. We ship the parser, not a database.

mod bundled;
mod die;
mod matcher;
mod model;
mod pattern;
mod peid;

pub use matcher::identify;
pub use model::{Condition, Confidence, Detection, Kind, Signature, SignatureDb, Source};
pub use pattern::{BytePattern, JumpPattern, JumpPiece, MAX_PATTERN_BYTES, MIN_DISTINCTIVE_NIBBLES, PatternError};
pub use peid::{PeidError, PeidWarning};

impl SignatureDb {
    /// The bundled starter database (see the [crate] docs for coverage).
    pub fn bundled() -> Self {
        bundled::bundled()
    }

    /// Adds every usable signature parsed from PeID `userdb.txt` text to this database, returning the entries
    /// and lines it skipped. Fails, adding nothing, only when there were problems and not one usable signature.
    pub fn load_peid(&mut self, text: &str) -> Result<Vec<PeidWarning>, PeidError> {
        let parsed = peid::parse(text);
        if parsed.signatures.is_empty() && !parsed.warnings.is_empty() {
            return Err(PeidError::NoUsableSignatures { warnings: parsed.warnings });
        }
        self.signatures.extend(parsed.signatures);
        Ok(parsed.warnings)
    }
}
