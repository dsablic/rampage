//! The signature model: what a signature is, the conditions it can test, and what a match reports.

use rampage_loaders::Format;
use serde::Serialize;

use crate::pattern::{BytePattern, JumpPattern, MIN_DISTINCTIVE_NIBBLES};

/// The category of tool a signature identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Packer,
    Compiler,
    Protector,
    Installer,
    Linker,
    /// A crypter: encrypts the image and decrypts it at run time, as a packer compresses it.
    Cryptor,
    /// A joiner (binder): glues several programs into one.
    Joiner,
    /// A self-extracting archive stub.
    Sfx,
    /// A C or language runtime linked into the image (musl, glibc, the MinGW-w64 CRT): it says which libc the
    /// program uses, not which compiler built it.
    Runtime,
    /// A user-supplied signature we cannot categorize, such as a parsed PeID entry.
    Unknown,
}

/// How much weight the evidence carries. These are heuristics, never proof: a `Strong` detection rests on a
/// distinctive pattern (an entry-point stub, an embedded toolchain string) or on several corroborating
/// conditions or signatures, while a `Tentative` one rests on a single generic signal like a lone section name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Tentative,
    Strong,
}

/// One testable condition. A [`Signature`] fires only when every one of its conditions holds (logical AND), so
/// each condition can only tighten a match. "Any of these names" is expressed with [`Condition::AnySectionName`].
///
/// Some conditions search bytes the image's own code and data need not account for: an un-anchored
/// [`Condition::Entry`], a [`Condition::SectionContains`] without a section, and [`Condition::OverlayContains`].
/// Such bytes include programs and strings a file merely carries (an embedded installer, appended data, a
/// detector's own signature table), so none of them makes a match `Strong` unless the signature also pins the
/// [`Condition::Format`] it is written for.
#[derive(Debug, Clone)]
pub enum Condition {
    /// The image is in this container format. It narrows other conditions; it is no evidence on its own.
    Format(Format),
    /// The entry-point bytes match this pattern. When `ep_only` is false the pattern may appear anywhere in the
    /// image except its overlay, which mirrors PeID's `ep_only = false`.
    Entry { pattern: BytePattern, ep_only: bool },
    /// Following relative jumps from the entry point matches this pattern (see [`JumpPattern`]).
    EntryJumps(JumpPattern),
    /// The file's bytes at this offset match this pattern; offset 0 is the start of the file.
    FileBytes { offset: u64, pattern: BytePattern },
    /// The overlay's first bytes match this pattern.
    OverlayBytes(BytePattern),
    /// A library with exactly this name is linked: a PE import library (ignoring case), an ELF `DT_NEEDED` entry,
    /// or the file name of a Mach-O dylib load command.
    Library(String),
    /// An imported function with exactly this name (case-sensitive) is present, from the named library (ignoring
    /// case) when one is given.
    ImportedFunction { library: Option<String>, name: String },
    /// An exported name exactly equal to this one is present.
    Export(String),
    /// The image's architecture has pointers this many bits wide (a PE32 image is 32, a PE32+ image 64).
    PointerBits(u8),
    /// A section with exactly this name is present.
    SectionName(String),
    /// At least one section whose name is in this list is present.
    AnySectionName(Vec<String>),
    /// At least one section with one of these tool-branded names (such as `.gopclntab` or `.vmp0`) is present.
    /// Unlike [`Condition::AnySectionName`], only one tool emits these names, so a match is distinctive on its
    /// own. It is still evidence, not proof: a section can be renamed or a name planted.
    UniqueSectionName(Vec<String>),
    /// A section (a named one, or anywhere in the image but its overlay when `section` is `None`) contains this
    /// byte needle. This reads the section's file-backed bytes, which also covers unloaded sections such as
    /// `.comment`.
    SectionContains { section: Option<String>, needle: Vec<u8> },
    /// A DWARF debug section (`.debug_*` in ELF and PE, `__debug_*` in Mach-O, or their compressed `z` forms)
    /// contains this byte needle.
    DebugContains(Vec<u8>),
    /// The overlay (data appended past everything the image's structures describe) contains this byte needle:
    /// where installers keep their payload.
    OverlayContains(Vec<u8>),
    /// The PE debug directory's CodeView (RSDS) record has a GUID matching this pattern.
    CodeViewGuid(BytePattern),
    /// An import from a library whose name contains this text (case-insensitive) is present.
    ImportLibrary(String),
    /// An import from a library named this prefix and then a version number (case-insensitive), such as
    /// `msvcr` matching `MSVCR120.dll` but not the unversioned system `msvcrt.dll` that MinGW also links.
    VersionedImportLibrary(String),
    /// An imported function with this exact name (case-insensitive) is present.
    ImportFunction(String),
    /// A symbol (from the symbol table, so a stripped image has none) with exactly this name is present. Names
    /// are as the source spells them: a Mach-O symbol's one leading underscore is not part of the name.
    Symbol(String),
    /// A symbol whose name starts with this prefix (and goes on past it) is present.
    SymbolPrefix(String),
    /// A Mach-O `LC_BUILD_VERSION` lists this tool (`ld`, `lld`, `clang`, `swift`), as the loader names it.
    BuildTool(String),
    /// The image has an overlay (data appended past everything its structures describe).
    OverlayPresent,
    /// The whole image's Shannon entropy is at least this many bits per byte.
    MinImageEntropy(f64),
    /// A section's entropy is at least this many bits per byte. `None` means the highest-entropy section.
    MinSectionEntropy { section: Option<String>, min: f64 },
}

impl Condition {
    /// Whether satisfying this condition on its own justifies a `Strong` reading. Distinctive conditions do;
    /// generic ones (a bare section name, an overlay, an entropy floor, a byte pattern with too few fixed nibbles)
    /// only corroborate.
    pub(crate) fn is_distinctive(&self) -> bool {
        match self {
            Self::Entry { pattern, .. } | Self::FileBytes { pattern, .. } | Self::OverlayBytes(pattern) => {
                pattern.fixed_nibbles() >= MIN_DISTINCTIVE_NIBBLES
            }
            Self::EntryJumps(pattern) => pattern.fixed_nibbles() >= MIN_DISTINCTIVE_NIBBLES,
            Self::SectionContains { .. }
            | Self::DebugContains(_)
            | Self::OverlayContains(_)
            | Self::CodeViewGuid(_)
            | Self::ImportFunction(_)
            | Self::ImportedFunction { .. }
            | Self::Export(_)
            | Self::UniqueSectionName(_)
            | Self::Symbol(_)
            | Self::SymbolPrefix(_)
            | Self::BuildTool(_) => true,
            _ => false,
        }
    }

    /// Whether this condition searches bytes that need not be the image's own (see [`Condition`]).
    pub(crate) fn is_unscoped(&self) -> bool {
        matches!(
            self,
            Self::Entry { ep_only: false, .. }
                | Self::SectionContains { section: None, .. }
                | Self::OverlayContains(_)
                | Self::OverlayBytes(_)
        )
    }
}

/// Where a signature comes from, so a report can tell rampage's own rules from imported ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Authored in this crate, or supplied by the user (a PeID database, a data pack).
    Rampage,
    /// Converted from the Detect It Easy signature database (MIT); see the crate docs.
    DetectItEasy,
}

/// A named rule that identifies one tool from a conjunction of conditions.
#[derive(Debug, Clone)]
pub struct Signature {
    pub name: String,
    pub kind: Kind,
    pub conditions: Vec<Condition>,
    /// The version (and any variant notes) the rule identifies, as its source words it.
    pub version: Option<String>,
    pub source: Source,
    /// For an imported rule, where it came from (such as the Detect It Easy script path) and who wrote it.
    pub origin: Option<String>,
    /// A short human note on what the signature keys off, for documentation and output.
    pub note: Option<String>,
    /// Whether a match is only `Tentative` on its own, however distinctive its conditions: the evidence also
    /// turns up in builds by other tools. Another signature for the same tool can still corroborate it.
    pub corroborating: bool,
}

impl Signature {
    pub fn new(name: &str, kind: Kind, conditions: Vec<Condition>) -> Self {
        Self {
            name: name.to_owned(),
            kind,
            conditions,
            version: None,
            source: Source::Rampage,
            origin: None,
            note: None,
            corroborating: false,
        }
    }

    pub fn with_note(mut self, note: &str) -> Self {
        self.note = Some(note.to_owned());
        self
    }

    /// Marks the signature [`Signature::corroborating`].
    pub fn corroborating(mut self) -> Self {
        self.corroborating = true;
        self
    }
}

/// A match: the tool identified, its category, the evidence that fired, and how much to trust it.
#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub name: String,
    pub kind: Kind,
    pub confidence: Confidence,
    /// One human-readable line per condition that matched.
    pub evidence: Vec<String>,
    /// Every signature source that fired, in order: `rampage` for this crate's own rules, `detect_it_easy` for
    /// rules converted from Detect It Easy.
    pub sources: Vec<Source>,
    /// The versions the matching signatures name, when they name one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<String>,
}

/// A collection of signatures, bundled or user-supplied, applied together.
#[derive(Debug, Clone, Default)]
pub struct SignatureDb {
    pub signatures: Vec<Signature>,
}

impl SignatureDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_signatures(signatures: Vec<Signature>) -> Self {
        Self { signatures }
    }

    /// Adds every signature from `other` to this database.
    pub fn extend(&mut self, other: impl IntoIterator<Item = Signature>) {
        self.signatures.extend(other);
    }

    pub fn push(&mut self, signature: Signature) {
        self.signatures.push(signature);
    }

    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
}
