//! Rust dependency lists embedded by cargo-auditable: a `.dep-v0` section (in the `__DATA` segment on Mach-O)
//! holding zlib-compressed JSON, `{"packages":[{"name","version","source","kind"?,"dependencies"?,"root"?}],
//! "format"?}`, where `dependencies` are indices into `packages`, `kind` defaults to `runtime` and `root` marks
//! the crate that was built. Format and limits follow cargo-auditable's `PARSING.md` and
//! `cargo-auditable.schema.json`, including its 8 MiB decompression cap against zip bombs.

use std::io::Read;

use serde::{Deserialize, Serialize};

use super::{BlobLocation, BlobStatus, clip};
use crate::Binary;
use crate::warnings::CappedWarnings;

pub const SECTION: &str = ".dep-v0";
/// cargo-auditable's recommended limit: "8 MiB should be more than enough to hold any legitimate audit data".
pub const MAX_DECOMPRESSED_BYTES: usize = 8 << 20;
/// Dependency indices listed per package; `dependencies_total` keeps the full count.
pub const MAX_DEPENDENCIES_LISTED: usize = 256;
const WARNINGS: CappedWarnings = CappedWarnings::new(64, "cargo-auditable");

/// The cargo-auditable record of an image; `status` says whether it could be decoded at all.
#[derive(Debug, Clone, Serialize)]
pub struct RustAudit {
    pub status: BlobStatus,
    /// Why an unreadable record could not be decoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub location: BlobLocation,
    /// The zlib stream's length (bytes the decompressor consumed), excluding any section padding after it.
    pub compressed_bytes: usize,
    pub decompressed_bytes: usize,
    /// The schema's `format` field; absent means format 0.
    pub format: u32,
    /// Indices of the root packages (normally exactly one).
    pub roots: Vec<usize>,
    pub packages: Vec<RustPackage>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RustPackage {
    /// The package's index in the embedded list, which `dependencies` refer to.
    pub index: usize,
    pub name: String,
    pub version: String,
    /// `crates.io`, `git`, `local`, `registry`, or another source as the JSON recorded it.
    pub source: String,
    /// `runtime` or `build`.
    pub kind: String,
    pub root: bool,
    /// Indices of the packages this one depends on, up to [`MAX_DEPENDENCIES_LISTED`].
    pub dependencies: Vec<usize>,
    pub dependencies_total: usize,
}

#[derive(Deserialize)]
struct RawAudit {
    packages: Vec<RawPackage>,
    #[serde(default)]
    format: Option<u32>,
}

#[derive(Deserialize)]
struct RawPackage {
    name: String,
    version: String,
    source: serde_json::Value,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    dependencies: Vec<usize>,
    #[serde(default)]
    root: bool,
}

/// The image's cargo-auditable record, or `None` when it has no `.dep-v0` section.
pub fn read(binary: &Binary) -> Option<RustAudit> {
    let mut sections = super::sections_named(binary, &[SECTION]);
    let section = sections.next()?;
    let location = BlobLocation { section: section.name.clone(), address: section.address };
    let mut audit = match binary.section_file_bytes(section) {
        Some(bytes) => decode(bytes, location),
        None => unreadable(location, 0, "the .dep-v0 section has no file bytes".to_owned()),
    };
    if sections.next().is_some() {
        WARNINGS.push(&mut audit.warnings, "more than one .dep-v0 section; only the first was read".to_owned());
    }
    Some(audit)
}

fn unreadable(location: BlobLocation, compressed_bytes: usize, reason: String) -> RustAudit {
    RustAudit {
        status: BlobStatus::Unreadable,
        reason: Some(reason),
        location,
        compressed_bytes,
        decompressed_bytes: 0,
        format: 0,
        roots: Vec::new(),
        packages: Vec::new(),
        warnings: Vec::new(),
    }
}

/// Decompresses and parses the section contents.
pub fn decode(compressed: &[u8], location: BlobLocation) -> RustAudit {
    let mut json = Vec::new();
    let limit = MAX_DECOMPRESSED_BYTES as u64 + 1;
    let mut decoder = flate2::read::ZlibDecoder::new(compressed);
    let inflated = decoder.by_ref().take(limit).read_to_end(&mut json);
    // The zlib stream's own length: the section is usually padded past it.
    let stream_bytes = usize::try_from(decoder.total_in()).unwrap_or(compressed.len());
    if let Err(error) = inflated {
        return unreadable(location, stream_bytes, format!("zlib decompression failed: {error}"));
    }
    if json.len() > MAX_DECOMPRESSED_BYTES {
        let reason = format!("the decompressed JSON exceeds the {MAX_DECOMPRESSED_BYTES}-byte cap");
        return unreadable(location, stream_bytes, reason);
    }
    let raw: RawAudit = match serde_json::from_slice(&json) {
        Ok(raw) => raw,
        Err(error) => {
            let mut audit = unreadable(location, stream_bytes, format!("the JSON is malformed: {error}"));
            audit.decompressed_bytes = json.len();
            return audit;
        }
    };
    let mut warnings = Vec::new();
    let mut warn = |text: String| WARNINGS.push(&mut warnings, text);
    let count = raw.packages.len();
    let mut packages = Vec::with_capacity(count);
    for (index, package) in raw.packages.into_iter().enumerate() {
        let mut text = |value: &str, what: &str| {
            let (value, truncated) = clip(value);
            if truncated {
                warn(format!("package {index}: {what} over {} bytes was truncated", super::MAX_FIELD_BYTES));
            }
            value
        };
        let source = match &package.source {
            serde_json::Value::String(source) => text(source, "source"),
            other => text(&other.to_string(), "source"),
        };
        let kind = text(package.kind.as_deref().unwrap_or("runtime"), "kind");
        let (name, version) = (text(&package.name, "name"), text(&package.version, "version"));
        let dependencies_total = package.dependencies.len();
        let dangling = package.dependencies.iter().filter(|&&dependency| dependency >= count).count();
        if dangling > 0 {
            warn(format!(
                "package {index} ({}): {dangling} dependency indices are out of range",
                crate::text::clip(&name, 64).0
            ));
        }
        let mut dependencies = package.dependencies;
        dependencies.truncate(MAX_DEPENDENCIES_LISTED);
        packages.push(RustPackage {
            index,
            name,
            version,
            source,
            kind,
            root: package.root,
            dependencies,
            dependencies_total,
        });
    }
    let roots: Vec<usize> = packages.iter().filter(|package| package.root).map(|package| package.index).collect();
    match roots.len() {
        0 if count > 0 => warn("no package is marked as the root".to_owned()),
        0 | 1 => {}
        many => warn(format!("{many} packages are marked as the root; the format expects one")),
    }
    RustAudit {
        status: BlobStatus::Present,
        reason: None,
        location,
        compressed_bytes: stream_bytes,
        decompressed_bytes: json.len(),
        format: raw.format.unwrap_or(0),
        roots,
        packages,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn location() -> BlobLocation {
        BlobLocation { section: SECTION.to_owned(), address: 0x4000 }
    }

    fn zlib(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn decodes_packages_roots_kinds_and_sources() {
        let json = r#"{"packages":[
            {"name":"app","version":"0.1.0","source":"local","dependencies":[1,2],"root":true},
            {"name":"serde","version":"1.0.200","source":"crates.io"},
            {"name":"cc","version":"1.0.0","source":"registry","kind":"build"},
            {"name":"odd","version":"0.0.1","source":{"Other":"somewhere"}}
        ],"format":1,"future":true}"#;
        let audit = decode(&zlib(json.as_bytes()), location());
        assert_eq!(audit.status, BlobStatus::Present, "{audit:?}");
        assert_eq!((audit.format, audit.roots.clone()), (1, vec![0]));
        assert_eq!(audit.decompressed_bytes, json.len());
        let summary: Vec<(&str, &str, &str, &str)> = audit
            .packages
            .iter()
            .map(|package| {
                (package.name.as_str(), package.version.as_str(), package.source.as_str(), package.kind.as_str())
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("app", "0.1.0", "local", "runtime"),
                ("serde", "1.0.200", "crates.io", "runtime"),
                ("cc", "1.0.0", "registry", "build"),
                ("odd", "0.0.1", r#"{"Other":"somewhere"}"#, "runtime"),
            ]
        );
        assert_eq!(audit.packages[0].dependencies, [1, 2]);
        assert!(audit.warnings.is_empty(), "{:?}", audit.warnings);
    }

    #[test]
    fn inconsistent_lists_are_kept_with_warnings() {
        let json = r#"{"packages":[{"name":"a","version":"1","source":"local","dependencies":[7],"root":true},
            {"name":"b","version":"1","source":"local","root":true}]}"#;
        let audit = decode(&zlib(json.as_bytes()), location());
        assert_eq!(audit.status, BlobStatus::Present);
        assert_eq!(audit.format, 0);
        assert_eq!(audit.roots, [0, 1]);
        assert_eq!(audit.warnings.len(), 2, "{:?}", audit.warnings);

        let audit = decode(&zlib(br#"{"packages":[{"name":"a","version":"1","source":"local"}]}"#), location());
        assert_eq!(audit.warnings, ["no package is marked as the root"]);
    }

    #[test]
    fn compressed_bytes_is_the_stream_without_section_padding() {
        let stream = zlib(br#"{"packages":[{"name":"a","version":"1","source":"local","root":true}]}"#);
        let padded = [stream.as_slice(), &[0; 64]].concat();
        let audit = decode(&padded, location());
        assert_eq!(audit.status, BlobStatus::Present);
        assert_eq!(audit.compressed_bytes, stream.len());
    }

    #[test]
    fn long_dependency_lists_are_capped() {
        let dependencies: Vec<String> = (0..=MAX_DEPENDENCIES_LISTED).map(|_| "0".to_owned()).collect();
        let json = format!(
            r#"{{"packages":[{{"name":"a","version":"1","source":"local","root":true,"dependencies":[{}]}}]}}"#,
            dependencies.join(",")
        );
        let audit = decode(&zlib(json.as_bytes()), location());
        let package = &audit.packages[0];
        assert_eq!(package.dependencies.len(), MAX_DEPENDENCIES_LISTED);
        assert_eq!(package.dependencies_total, MAX_DEPENDENCIES_LISTED + 1);
    }

    #[test]
    fn hostile_payloads_are_unreadable_with_reasons() {
        let bomb = zlib(&vec![b' '; MAX_DECOMPRESSED_BYTES + 1]);
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (Vec::new(), "zlib"),
            (b"not zlib at all".to_vec(), "zlib"),
            (zlib(b"{\"packages\":"), "malformed"),
            (zlib(b"{\"packages\":[{\"name\":1}]}"), "malformed"),
            (zlib(b"[]"), "malformed"),
            (bomb, "cap"),
        ];
        for (bytes, reason) in cases {
            let audit = decode(&bytes, location());
            assert_eq!(audit.status, BlobStatus::Unreadable);
            assert!(audit.reason.as_deref().unwrap().contains(reason), "{reason}: {:?}", audit.reason);
        }
        let good = zlib(br#"{"packages":[{"name":"a","version":"1","source":"local","root":true}]}"#);
        for length in 0..good.len() {
            assert_eq!(decode(&good[..length], location()).status, BlobStatus::Unreadable, "{length}");
        }
    }
}
