//! Packer, compiler, protector, installer and linker identification from heuristic signatures: the DIE/PeID
//! niche. Given a loaded [`rampage_loaders::Binary`], [`identify`] reports which tools likely produced it, each
//! with the evidence that fired and a confidence that is a signal, not a proof.
//!
//! # What a signature is
//!
//! A [`Signature`] names one tool, carries a [`Kind`] (packer, compiler, protector, installer or linker), and
//! holds a list of [`Condition`]s that must all hold (logical AND) for it to match. Conditions test:
//!
//! - an entry-point byte pattern (hex with `?` nibble and `??` byte wildcards; see [`BytePattern`]),
//! - a required section name, or any of a set of names,
//! - a byte needle contained in a section (or anywhere in the image), which covers toolchain banners and
//!   unloaded sections such as `.comment`,
//! - a required imported library or function,
//! - the presence of an overlay,
//! - a minimum image or section entropy.
//!
//! # The bundled database
//!
//! [`SignatureDb::bundled`] returns a starter database authored here from public knowledge (section layouts,
//! embedded producer strings, import conventions), never copied from PeID's `userdb.txt`. It covers UPX, ASPack,
//! MPRESS, PECompact, Petite, NsPack and FSG (packers); VMProtect, Themida/WinLicense and Enigma (protectors);
//! Go, .NET, MSVC, MinGW/GCC, GCC, Clang/LLVM, Rust, Zig and Delphi/Borland (compilers); LLD and GNU ld
//! (linkers); and NSIS and Inno Setup (installers).
//!
//! # User-supplied databases
//!
//! [`SignatureDb::load_peid`] parses the public PeID `userdb.txt` format so users can bring their own
//! signatures. We ship the parser, not a database.

mod bundled;
mod matcher;
mod model;
mod pattern;
mod peid;

pub use matcher::identify;
pub use model::{Condition, Confidence, Detection, Kind, Signature, SignatureDb};
pub use pattern::{BytePattern, MAX_PATTERN_BYTES, PatternError};
pub use peid::PeidError;

impl SignatureDb {
    /// The bundled starter database (see the [crate] docs for coverage).
    pub fn bundled() -> Self {
        bundled::bundled()
    }

    /// Adds every signature parsed from PeID `userdb.txt` text to this database.
    pub fn load_peid(&mut self, text: &str) -> Result<(), PeidError> {
        self.signatures.extend(peid::parse(text)?);
        Ok(())
    }
}
