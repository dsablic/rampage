pub mod carve;
pub mod container;
mod details;
mod entropy;
pub mod linkage;
mod load;
mod macho;
mod model;
mod raw;
pub mod raw_vectors;
mod slots;
pub mod snapshot;
mod starts;
mod text;
mod warnings;

pub use details::{
    BuildTool, CodeView, Details, ElfDetails, MAX_BUILD_TOOLS, MAX_CODEVIEW_PATH, MachODetails, Overlay, PeDetails,
    RichEntry,
};
pub use entropy::shannon_entropy;
pub use linkage::{
    LinkageCoverage, LinkageCoverageStatus, LinkageExport, LinkageExportTarget, LinkageImport, LinkageImportProvenance,
    LinkageLimitation, LinkageLimits, LinkageMetadata, LinkageStatus, LinkageSymbol, linkage_metadata,
};
pub use load::{Binary, Embedded, ImageAt, InventorySourceContext, LoadError};
pub use model::{Export, Format, Import, ImportSlot, Perms, Section, SectionKind, Segment, Symbol, SymbolKind};
pub use raw::{
    MAX_RAW_BYTES, MAX_RAW_NATIVE_BYTES, MAX_RAW_SEEDS, RawCodeImage, RawCodeOptions, RawCodeSpace,
    RawInterpretationIdentity, RawProfile,
};
pub mod buildinfo;
mod checked_snapshot;
pub mod debug;
pub mod debug_types;
pub mod dotnet;
pub mod gopclntab;
pub mod objc;
pub mod pdb;
pub mod pe_load_config;
pub mod pe_resources;
#[cfg(test)]
mod pe_test_image;
pub mod pyinstaller;
pub mod wasm;
