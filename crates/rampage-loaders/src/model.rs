use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Elf,
    Pe,
    MachO,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Segment {
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub perms: Perms,
}

impl Segment {
    pub fn contains(&self, address: u64) -> bool {
        address >= self.address && address - self.address < self.size
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionKind {
    Code,
    Data,
    ReadOnlyData,
    UninitializedData,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Section {
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub size: u64,
    pub kind: SectionKind,
    /// Where the section's contents lie in the image, when they are stored in the file (not zero-fill).
    pub file_offset: Option<u64>,
    pub file_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SymbolKind {
    Function,
    Data,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Symbol {
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub size: u64,
    pub kind: SymbolKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Import {
    pub library: Option<String>,
    pub name: String,
}

/// A location the dynamic loader fills with an import's address (a GOT entry, a Mach-O symbol pointer, or a PE
/// import address table entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportSlot {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
    /// The library the import is bound to, when the format records it per slot (PE, Mach-O).
    pub library: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Export {
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
}
