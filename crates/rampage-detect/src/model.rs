//! The signature model: what a signature is, the conditions it can test, and what a match reports.

use serde::Serialize;

use crate::pattern::{BytePattern, MIN_DISTINCTIVE_NIBBLES};

/// The category of tool a signature identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Packer,
    Compiler,
    Protector,
    Installer,
    Linker,
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
#[derive(Debug, Clone)]
pub enum Condition {
    /// The entry-point bytes match this pattern. When `ep_only` is false the pattern may appear anywhere in the
    /// image, which mirrors PeID's `ep_only = false`.
    Entry { pattern: BytePattern, ep_only: bool },
    /// A section with exactly this name is present.
    SectionName(String),
    /// At least one section whose name is in this list is present.
    AnySectionName(Vec<String>),
    /// At least one section with one of these tool-branded names (such as `.gopclntab` or `.vmp0`) is present.
    /// Unlike [`Condition::AnySectionName`], only one tool emits these names, so a match is distinctive on its
    /// own. It is still evidence, not proof: a section can be renamed or a name planted.
    UniqueSectionName(Vec<String>),
    /// A section (a named one, or any when `section` is `None`) contains this byte needle. This reads the
    /// section's file-backed bytes, which also covers unloaded sections such as `.comment`.
    SectionContains { section: Option<String>, needle: Vec<u8> },
    /// An import from a library whose name contains this text (case-insensitive) is present.
    ImportLibrary(String),
    /// An import from a library named this prefix and then a version number (case-insensitive), such as
    /// `msvcr` matching `MSVCR120.dll` but not the unversioned system `msvcrt.dll` that MinGW also links.
    VersionedImportLibrary(String),
    /// An imported function with this exact name (case-insensitive) is present.
    ImportFunction(String),
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
            Self::Entry { pattern, .. } => pattern.fixed_nibbles() >= MIN_DISTINCTIVE_NIBBLES,
            Self::SectionContains { .. } | Self::ImportFunction(_) | Self::UniqueSectionName(_) => true,
            _ => false,
        }
    }
}

/// A named rule that identifies one tool from a conjunction of conditions.
#[derive(Debug, Clone)]
pub struct Signature {
    pub name: String,
    pub kind: Kind,
    pub conditions: Vec<Condition>,
    /// A short human note on what the signature keys off, for documentation and output.
    pub note: Option<String>,
    /// Whether a match is only `Tentative` on its own, however distinctive its conditions: the evidence also
    /// turns up in builds by other tools. Another signature for the same tool can still corroborate it.
    pub corroborating: bool,
}

impl Signature {
    pub fn new(name: &str, kind: Kind, conditions: Vec<Condition>) -> Self {
        Self { name: name.to_owned(), kind, conditions, note: None, corroborating: false }
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
