//! Embedded toolchain build metadata, from `rampage_loaders::buildinfo`: Go's build info (the `go version -m`
//! record) and Rust's cargo-auditable dependency list, each absent (`None`), present, or present but unreadable.
//! One `offset`/`limit` pair pages both long lists: Go dependency modules and Rust packages.

use rampage_loaders::buildinfo::go::{self, GoLayout, GoModule, GoSetting};
use rampage_loaders::buildinfo::rust::{self, RustPackage};
use rampage_loaders::buildinfo::{BlobLocation, BlobStatus};
use rampage_loaders::gopclntab::GoTableVersion;
use serde::Serialize;

use crate::{Page, Project};

const LIMITATIONS: &[&str] = &[
    "Both records are self-reported by the toolchain at build time: not verified against the code, and removable \
     or forgeable by obfuscators.",
    "Go: GOPATH-mode builds carry no modinfo; pre-1.18 version/modinfo pointers resolve only through file-backed \
     segments.",
    "Rust: only cargo-auditable's .dep-v0 section; plain cargo builds embed no dependency list, and the Mach-O \
     segment name is not checked.",
    "offset/limit page go.deps and rust.packages independently; build settings are returned whole (at most 1024).",
];

#[derive(Debug, Default, Clone)]
pub struct BuildInfoQuery {
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct BuildInfo {
    /// `None` when the image holds no Go build info.
    pub go: Option<GoBuildInfo>,
    /// `None` when the image has no `.dep-v0` section.
    pub rust: Option<RustAudit>,
    pub limitations: &'static [&'static str],
}

#[derive(Debug, Serialize)]
pub struct GoBuildInfo {
    pub status: BlobStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub location: BlobLocation,
    pub layout: GoLayout,
    pub pointer_size: u8,
    pub big_endian: bool,
    pub go_version: Option<String>,
    pub modinfo: bool,
    pub path: Option<String>,
    pub main: Option<GoModule>,
    /// One page of the dependency modules, in modinfo order.
    pub deps: Page<GoModule>,
    /// Whether modinfo listed more modules than were retained (65536).
    pub deps_truncated: bool,
    pub settings: Vec<GoSetting>,
    pub settings_truncated: bool,
    pub pclntab: PclntabCheck,
    pub warnings: Vec<String>,
}

/// The build info's toolchain version against the pclntab layout the loader found (`gopclntab.rs`), two
/// independent records of the same build.
#[derive(Debug, Serialize)]
pub struct PclntabCheck {
    /// The pclntab layout the loader recognized, if any.
    pub table: Option<GoTableVersion>,
    /// The layout `go_version` implies; `None` for a devel or unrecognized version.
    pub expected: Option<GoTableVersion>,
    /// Whether the two agree; `None` when either is unknown.
    pub consistent: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct RustAudit {
    pub status: BlobStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub location: BlobLocation,
    pub compressed_bytes: usize,
    pub decompressed_bytes: usize,
    pub format: u32,
    /// The root package(s), whichever page they fall on.
    pub roots: Vec<RustPackage>,
    /// One page of every package, in embedded order (`index` is the position `dependencies` refer to).
    pub packages: Page<RustPackage>,
    pub warnings: Vec<String>,
}

impl Project {
    /// The image's embedded Go build info and cargo-auditable dependency list.
    pub fn build_info(&self, query: &BuildInfoQuery) -> BuildInfo {
        let go = go::read(&self.binary).map(|info| {
            let expected = info.go_version.as_deref().and_then(go::expected_table);
            let table = self.binary.go_table;
            let consistent = table.zip(expected).map(|(table, expected)| table == expected);
            GoBuildInfo {
                status: info.status,
                reason: info.reason,
                location: info.location,
                layout: info.layout,
                pointer_size: info.pointer_size,
                big_endian: info.big_endian,
                go_version: info.go_version,
                modinfo: info.modinfo,
                path: info.path,
                main: info.main,
                deps: Page::of(info.deps, query.offset, query.limit),
                deps_truncated: info.deps_truncated,
                settings: info.settings,
                settings_truncated: info.settings_truncated,
                pclntab: PclntabCheck { table, expected, consistent },
                warnings: info.warnings,
            }
        });
        let rust = rust::read(&self.binary).map(|audit| RustAudit {
            status: audit.status,
            reason: audit.reason,
            location: audit.location,
            compressed_bytes: audit.compressed_bytes,
            decompressed_bytes: audit.decompressed_bytes,
            format: audit.format,
            roots: audit.roots.iter().filter_map(|&index| audit.packages.get(index).cloned()).collect(),
            packages: Page::of(audit.packages, query.offset, query.limit),
            warnings: audit.warnings,
        });
        BuildInfo { go, rust, limitations: LIMITATIONS }
    }
}
