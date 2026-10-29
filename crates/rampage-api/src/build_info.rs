//! Embedded toolchain build metadata, from `rampage_loaders::buildinfo`: Go's build info (the `go version -m`
//! record) and Rust's cargo-auditable dependency list, each absent (`None`), present, or present but unreadable.
//! One `offset`/`limit` pair pages both long lists: Go dependency modules and Rust packages. The result is fitted
//! to the tool-result JSON budget: build settings and Rust roots get fixed shares, the two pages the rest.

use rampage_loaders::buildinfo::go::{self, GoLayout, GoModule, GoSetting};
use rampage_loaders::buildinfo::rust::{self, RustPackage};
use rampage_loaders::buildinfo::{BlobLocation, BlobStatus};
use rampage_loaders::gopclntab::GoTableVersion;
use serde::Serialize;

use crate::rows::{FittedPage, Window, fit_window, item_budget};
use crate::{ApiError, Project};

/// Root packages listed; `roots_total` counts them all.
pub const MAX_ROOTS_LISTED: usize = 16;
/// JSON bytes the listed build settings may take; `settings_byte_capped` says when they were cut.
const MAX_SETTINGS_BYTES: usize = 16_000;
/// JSON bytes the listed root packages may take.
const MAX_ROOTS_BYTES: usize = 8_000;

const LIMITATIONS: &[&str] = &[
    "Both records are self-reported by the toolchain at build time: not verified against the code, and removable \
     or forgeable by obfuscators.",
    "Go: GOPATH-mode builds carry no modinfo; pre-1.18 version/modinfo pointers resolve only through file-backed \
     segments.",
    "Rust: only cargo-auditable's .dep-v0 section; plain cargo builds embed no dependency list, and the Mach-O \
     segment name is not checked.",
    "offset/limit page go.deps and rust.packages independently, each also cut to fit the result's JSON budget \
     (next_offset, byte_capped); build settings and Rust roots are listed only up to a byte share, not paged.",
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
    pub deps: FittedPage<GoModule>,
    /// Whether modinfo listed more modules than were retained (65536).
    pub deps_truncated: bool,
    /// The build settings, in order, as many as fit their byte share.
    pub settings: Vec<GoSetting>,
    /// Settings retained (up to 1024); more than `settings` holds when `settings_byte_capped`.
    pub settings_total: usize,
    pub settings_byte_capped: bool,
    /// Whether modinfo listed more settings than were retained (1024).
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
    /// The root package(s), whichever page they fall on: at most 16, and fewer when they overrun their byte share.
    pub roots: Vec<RustPackage>,
    pub roots_total: usize,
    /// One page of every package, in embedded order (`index` is the position `dependencies` refer to).
    pub packages: FittedPage<RustPackage>,
    pub warnings: Vec<String>,
}

impl Project {
    /// The image's embedded Go build info and cargo-auditable dependency list.
    pub fn build_info(&self, query: &BuildInfoQuery) -> Result<BuildInfo, ApiError> {
        let mut deps = Vec::new();
        let go = go::read(&self.binary).map(|mut info| {
            deps = std::mem::take(&mut info.deps);
            let expected = info.go_version.as_deref().and_then(go::expected_table);
            let table = self.binary.go_table;
            let consistent = table.zip(expected).map(|(table, expected)| table == expected);
            let settings_total = info.settings.len();
            let settings = byte_share(info.settings, usize::MAX, MAX_SETTINGS_BYTES);
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
                deps: FittedPage::empty(),
                deps_truncated: info.deps_truncated,
                settings: settings.items,
                settings_total,
                settings_byte_capped: settings.byte_capped,
                settings_truncated: info.settings_truncated,
                pclntab: PclntabCheck { table, expected, consistent },
                warnings: info.warnings,
            }
        });
        let mut packages = Vec::new();
        let rust = rust::read(&self.binary).map(|mut audit| {
            packages = std::mem::take(&mut audit.packages);
            let roots = audit.roots.iter().filter_map(|&index| packages.get(index).cloned());
            RustAudit {
                status: audit.status,
                reason: audit.reason,
                location: audit.location,
                compressed_bytes: audit.compressed_bytes,
                decompressed_bytes: audit.decompressed_bytes,
                format: audit.format,
                roots: byte_share(roots, MAX_ROOTS_LISTED, MAX_ROOTS_BYTES).items,
                roots_total: audit.roots.len(),
                packages: FittedPage::empty(),
                warnings: audit.warnings,
            }
        });
        let mut info = BuildInfo { go, rust, limitations: LIMITATIONS };
        let budget = item_budget(&info)?;
        // Both lists share the rest; a binary rarely carries both records.
        let share = if info.go.is_some() && info.rust.is_some() { budget / 2 } else { budget };
        if let Some(go) = &mut info.go {
            go.deps = FittedPage::of(deps, query.offset, query.limit, share)?;
        }
        if let Some(rust) = &mut info.rust {
            rust.packages = FittedPage::of(packages, query.offset, query.limit, share)?;
        }
        Ok(info)
    }
}

/// The leading `items` (at most `limit`) that fit `budget` JSON bytes; possibly none, since these lists are not
/// paged and an outsized first item must not fail the whole result.
fn byte_share<T: serde::Serialize>(items: impl IntoIterator<Item = T>, limit: usize, budget: usize) -> Window<T> {
    fit_window(items, limit, budget).unwrap_or(Window { items: Vec::new(), byte_capped: true })
}
