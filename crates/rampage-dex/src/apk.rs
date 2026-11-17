//! An APK (or AAB) as a ZIP archive read through `rampage-unpack`: its DEX files in multidex order, the binary
//! `AndroidManifest.xml`, the native libraries per ABI and the `resources.arsc` string pool size. Member reads are
//! bounded by `rampage-unpack`'s per-file and total limits and its compression-ratio meter.

use std::path::Path;

use serde::Serialize;

use crate::axml;
use crate::dex::{Dex, Limits as DexLimits};
use crate::error::{DexError, Result};
use crate::manifest::Manifest;
use crate::read::{u16_at, u32_at};

/// Caps on reading one APK.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// DEX files read, in multidex order; later ones are listed but not parsed.
    pub max_dex_files: usize,
    pub dex: DexLimits,
    /// Bytes of one native library read for its exports; larger ones are listed only.
    pub max_native_bytes: u64,
    /// Bytes of all members read.
    pub max_total_bytes: u64,
    /// Whether native libraries are read at all.
    pub read_native: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_dex_files: 16,
            dex: DexLimits::default(),
            max_native_bytes: 64 << 20,
            max_total_bytes: 384 << 20,
            read_native: true,
        }
    }
}

const MAX_MANIFEST_BYTES: u64 = 16 << 20;
const MAX_ARSC_BYTES: u64 = 32 << 20;

/// One DEX file of the APK: its entry path and the parsed file or why it could not be.
pub struct DexEntry {
    pub path: String,
    pub size: u64,
    pub dex: std::result::Result<Dex, String>,
}

/// A native library: `lib/<abi>/<name>.so`, with its bytes when they were read.
#[derive(Serialize)]
pub struct NativeLib {
    pub path: String,
    pub abi: String,
    pub size: u64,
    #[serde(skip)]
    pub bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceTable {
    pub size: u64,
    pub packages: u32,
    /// Strings in the global value string pool.
    pub strings: u32,
}

pub struct Apk {
    pub entries: usize,
    pub manifest: Option<Manifest>,
    /// Why the manifest could not be read, when it could not.
    pub manifest_error: Option<String>,
    pub dex: Vec<DexEntry>,
    pub native_libs: Vec<NativeLib>,
    pub resources: Option<ResourceTable>,
    pub warnings: Vec<String>,
}

/// The DEX file number of `classes.dex` (1), `classes2.dex` (2), ...; `None` for any other name.
fn dex_number(path: &str) -> Option<u32> {
    let name = path.strip_prefix("base/dex/").unwrap_or(path);
    let middle = name.strip_prefix("classes")?.strip_suffix(".dex")?;
    if middle.is_empty() {
        return Some(1);
    }
    middle.parse().ok().filter(|number| *number >= 2)
}

/// `(abi, file name)` of a native library path.
fn native_lib(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("lib/").or_else(|| path.strip_prefix("base/lib/"))?;
    let (abi, name) = rest.split_once('/')?;
    (name.ends_with(".so") && !name.contains('/')).then_some((abi, name))
}

/// The manifest of an APK, or of an AAB's base module (stored as protobuf there).
fn manifest_path(path: &str) -> bool {
    path == "AndroidManifest.xml" || path == "base/manifest/AndroidManifest.xml"
}

/// The package count and global string count of a `resources.arsc`, from its first chunks only.
pub fn resource_table(data: &[u8]) -> Option<ResourceTable> {
    if u16_at(data, 0)? != 0x0002 {
        return None;
    }
    let header = usize::from(u16_at(data, 2)?);
    let packages = u32_at(data, 8)?;
    let strings = if u16_at(data, header)? == 0x0001 { u32_at(data, header + 8)? } else { 0 };
    Some(ResourceTable { size: data.len() as u64, packages, strings })
}

impl Apk {
    pub fn open(path: &Path, limits: Limits) -> Result<Self> {
        let unpack = rampage_unpack::Limits {
            max_total_bytes: limits.max_total_bytes,
            max_file_bytes: (limits.dex.max_file_bytes as u64).max(limits.max_native_bytes).max(MAX_ARSC_BYTES),
            ..rampage_unpack::Limits::default()
        };
        // DEX files in multidex order (classes.dex, classes2.dex, ...), then the first manifest, the resource
        // table and the native libraries.
        let mut choose = |entries: &[rampage_unpack::Entry]| -> Vec<usize> {
            let mut dex: Vec<(u32, usize)> = entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.size <= limits.dex.max_file_bytes as u64)
                .filter_map(|(index, entry)| dex_number(&entry.path).map(|number| (number, index)))
                .collect();
            dex.sort();
            let mut chosen: Vec<usize> = dex.into_iter().take(limits.max_dex_files).map(|(_, index)| index).collect();
            chosen.extend(
                entries
                    .iter()
                    .position(|entry| manifest_path(&entry.path))
                    .filter(|&index| entries[index].size <= MAX_MANIFEST_BYTES),
            );
            chosen.extend(
                entries.iter().position(|entry| entry.path == "resources.arsc" && entry.size <= MAX_ARSC_BYTES),
            );
            if limits.read_native {
                chosen.extend(entries.iter().enumerate().filter_map(|(index, entry)| {
                    (native_lib(&entry.path).is_some() && entry.size <= limits.max_native_bytes).then_some(index)
                }));
            }
            chosen
        };
        let selected = rampage_unpack::read_chosen(path, rampage_unpack::At::default(), &[], unpack, &mut choose)
            .map_err(|error| match error {
                rampage_unpack::UnpackError::Limit(text) => DexError::Limit(text),
                rampage_unpack::UnpackError::Unsupported(text) => DexError::Unsupported(text),
                other => DexError::Malformed(other.to_string()),
            })?;
        if selected.layers.first().map(|layer| layer.format) != Some(rampage_unpack::Format::Zip) {
            return Err(DexError::Unsupported("not a ZIP archive (APK, AAB or JAR)".to_owned()));
        }
        let mut contents: std::collections::HashMap<usize, Vec<u8>> = selected.contents.into_iter().collect();
        let mut apk = Apk {
            entries: selected.entries.len(),
            manifest: None,
            manifest_error: None,
            dex: Vec::new(),
            native_libs: Vec::new(),
            resources: None,
            warnings: selected.layers.iter().flat_map(|layer| layer.notes.clone()).collect(),
        };
        let mut dex_files: Vec<(u32, usize)> = selected
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| dex_number(&entry.path).map(|number| (number, index)))
            .collect();
        dex_files.sort();
        for (_, index) in dex_files {
            let entry = &selected.entries[index];
            let dex = match contents.remove(&index) {
                Some(bytes) => Dex::parse_with(bytes, limits.dex).map_err(|error| error.to_string()),
                None => {
                    Err(format!("not read: {} bytes, or past the first {} DEX files", entry.size, limits.max_dex_files))
                }
            };
            apk.dex.push(DexEntry { path: entry.path.clone(), size: entry.size, dex });
        }
        let mut manifests = 0usize;
        for (index, entry) in selected.entries.iter().enumerate() {
            if manifest_path(&entry.path) {
                manifests += 1;
                if manifests > 1 {
                    continue;
                }
                let aab = entry.path.starts_with("base/");
                match contents.remove(&index) {
                    Some(bytes) if axml::is_axml(&bytes) => match axml::parse(&bytes) {
                        Ok(document) => apk.manifest = Some(Manifest::from_document(&document)),
                        Err(error) => apk.manifest_error = Some(error.to_string()),
                    },
                    Some(_) if aab => {
                        apk.manifest_error = Some(
                            "base/manifest/AndroidManifest.xml is an AAB manifest in protobuf (aapt2 proto) form, \
                             which is not read yet; dex_metadata still reads the DEX files and native libraries"
                                .to_owned(),
                        )
                    }
                    Some(_) => apk.manifest_error = Some(format!("{} is not binary XML", entry.path)),
                    None => apk.manifest_error = Some(format!("{} of {} bytes not read", entry.path, entry.size)),
                }
            } else if entry.path == "resources.arsc" {
                apk.resources = contents.remove(&index).as_deref().and_then(resource_table);
            } else if let Some((abi, _)) = native_lib(&entry.path) {
                apk.native_libs.push(NativeLib {
                    path: entry.path.clone(),
                    abi: abi.to_owned(),
                    size: entry.size,
                    bytes: contents.remove(&index),
                });
            }
        }
        if manifests > 1 {
            apk.warnings.push(format!(
                "{manifests} AndroidManifest.xml entries: the first is read, as the platform's installer reads one; \
                 the others may hide components or permissions from tools"
            ));
        }
        if apk.manifest.is_none() && apk.manifest_error.is_none() {
            apk.manifest_error = Some("no AndroidManifest.xml".to_owned());
        }
        Ok(apk)
    }
}
