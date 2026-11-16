//! `dex_metadata` and `dex_code`: Android APKs and DEX files through `rampage-dex`. An APK's manifest
//! (package, versions, SDK levels, permissions with their protection level, components with intent filters and
//! start-at-boot receivers), its native libraries per ABI with their JNI exports, its DEX files, and one page of
//! classes or methods; a directory of them pages by cursor. Dalvik bytecode is listed by `dex_code`, never analysed
//! as native code.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use rampage_dex::apk::{Apk, Limits as ApkLimits, NativeLib, ResourceTable};
use rampage_dex::dex::{ClassDef, Dex, Member, access_names, java_name};
use rampage_dex::manifest::{Component, Manifest};
use serde_json::{Value, json};

/// JSON bytes a page of rows may take, leaving room for the summary within the tool result limit.
const PAGE_BYTES: usize = 36_000;
const DEFAULT_LIMIT: usize = 100;
pub const MAX_DEX_PAGE: usize = 500;
/// Components listed in a summary; `list: "components"` pages the rest.
const SUMMARY_COMPONENTS: usize = 60;
/// Java_ exports listed per native library.
const MAX_JNI_EXPORTS: usize = 100;
/// Files a directory page holds at most, and the files a directory walk visits.
const DEFAULT_FILES: usize = 10;
const MAX_FILES: usize = 50;
const MAX_WALK: usize = 100_000;

pub struct DexMetadataQuery {
    pub path: PathBuf,
    /// `classes` (default), `methods` or `components`.
    pub list: Option<String>,
    /// Only classes whose Java name (or descriptor) starts with this.
    pub prefix: Option<String>,
    /// Only classes in this package or its subpackages.
    pub package: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
    /// Directory paging: the `next_cursor` of the previous page.
    pub cursor: Option<String>,
    pub max_files: Option<usize>,
}

/// One opened APK or DEX file.
pub(crate) struct Opened {
    pub(crate) kind: &'static str,
    pub(crate) apk: Option<Apk>,
    /// `(entry path, parsed file or error, size)` in multidex order; one entry for a bare DEX file.
    pub(crate) dexes: Vec<(String, Result<Dex, String>, u64)>,
}

impl Opened {
    pub(crate) fn parsed(&self) -> impl Iterator<Item = (&str, &Dex)> {
        self.dexes.iter().filter_map(|(path, dex, _)| dex.as_ref().ok().map(|dex| (path.as_str(), dex)))
    }

    pub(crate) fn manifest(&self) -> Option<&Manifest> {
        self.apk.as_ref().and_then(|apk| apk.manifest.as_ref())
    }
}

/// Whether the file at `path` starts as a DEX file or a ZIP archive, by its first bytes.
pub(crate) fn sniff(path: &Path) -> Option<&'static str> {
    use std::io::Read;
    let mut head = [0u8; 8];
    let mut file = std::fs::File::open(path).ok()?;
    let read = file.read(&mut head).ok()?;
    if rampage_dex::is_dex(&head[..read]) {
        Some("dex")
    } else if head[..read].starts_with(b"PK\x03\x04") || head[..read].starts_with(b"PK\x05\x06") {
        Some("apk")
    } else {
        None
    }
}

pub(crate) fn open(path: &Path, read_native: bool) -> Result<Opened, String> {
    let metadata = std::fs::metadata(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    match sniff(path) {
        Some("dex") => {
            let limits = rampage_dex::Limits::default();
            if metadata.len() > limits.max_file_bytes as u64 {
                return Err(format!(
                    "{} bytes is more than the {}-byte DEX limit",
                    metadata.len(),
                    limits.max_file_bytes
                ));
            }
            let bytes = std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            let name =
                path.file_name().map_or_else(|| "classes.dex".to_owned(), |name| name.to_string_lossy().into_owned());
            let dex = Dex::parse(bytes).map_err(|error| error.to_string());
            if let Err(error) = &dex {
                return Err(format!("{}: {error}", path.display()));
            }
            Ok(Opened { kind: "dex", apk: None, dexes: vec![(name, dex, metadata.len())] })
        }
        Some(_) => {
            let mut apk = Apk::open(path, ApkLimits { read_native, ..ApkLimits::default() })
                .map_err(|error| format!("{}: {error}", path.display()))?;
            let dexes =
                std::mem::take(&mut apk.dex).into_iter().map(|entry| (entry.path, entry.dex, entry.size)).collect();
            Ok(Opened { kind: "apk", apk: Some(apk), dexes })
        }
        None => Err(format!(
            "{} is not an APK, AAB, JAR or DEX file (no ZIP or DEX magic); for a native library use the binary tools",
            path.display()
        )),
    }
}

/// `java.lang.Object` for a descriptor, keeping arrays and primitives readable.
fn class_name(descriptor: &str) -> String {
    java_name(descriptor)
}

fn class_matches(name: &str, prefix: Option<&str>, package: Option<&str>) -> bool {
    let prefix_ok = prefix.is_none_or(|prefix| {
        let prefix = match prefix.strip_prefix('L') {
            Some(rest) if rest.contains('/') => rest.trim_end_matches(';').replace('/', "."),
            _ => prefix.to_owned(),
        };
        name.starts_with(&prefix)
    });
    let package_ok = package.is_none_or(|package| {
        let package = package.trim_end_matches('.');
        name.strip_prefix(package).is_some_and(|rest| rest.starts_with('.'))
    });
    prefix_ok && package_ok
}

/// The descriptors of every class the parsed DEX files define.
pub(crate) fn defined_classes(opened: &Opened) -> HashSet<String> {
    let mut set = HashSet::new();
    for (_, dex) in opened.parsed() {
        for index in 0..dex.class_count() {
            if let Ok(class) = dex.class_def(index) {
                set.insert(dex.type_text(class.class_idx));
            }
        }
    }
    set
}

fn class_row(dex_path: &str, dex: &Dex, class: &ClassDef, budget: &mut usize) -> Value {
    let data = dex.class_data(class, budget);
    let (fields, methods, native) = match &data {
        Ok(data) => (
            data.static_fields.len() + data.instance_fields.len(),
            data.methods().count(),
            data.methods().filter(|method| method.access & rampage_dex::dex::ACC_NATIVE != 0).count(),
        ),
        Err(_) => (0, 0, 0),
    };
    let mut row = json!({
        "class": class_name(&dex.type_text(class.class_idx)),
        "dex": dex_path,
        "access": access_names(class.access, Member::Class),
        "fields": fields,
        "methods": methods,
    });
    if class.superclass_idx != rampage_dex::dex::NO_INDEX {
        row["superclass"] = json!(class_name(&dex.type_text(class.superclass_idx)));
    }
    if !class.interfaces.is_empty() {
        row["interfaces"] = json!(
            class.interfaces.iter().map(|index| class_name(&dex.type_text(u32::from(*index)))).collect::<Vec<_>>()
        );
    }
    if native > 0 {
        row["native_methods"] = json!(native);
    }
    if class.source_file_idx != rampage_dex::dex::NO_INDEX {
        row["source_file"] = json!(dex.string_text(class.source_file_idx));
    }
    if let Err(error) = data {
        row["error"] = json!(error.to_string());
    }
    row
}

/// Pages `rows` (produced lazily, already filtered) by offset and limit within [`PAGE_BYTES`].
fn page(rows: impl Iterator<Item = Value>, offset: usize, limit: usize) -> Value {
    let mut items = Vec::new();
    let mut bytes = 0usize;
    let mut total = 0usize;
    let mut byte_capped = false;
    for row in rows {
        total += 1;
        if total <= offset || items.len() >= limit || byte_capped {
            continue;
        }
        let size = row.to_string().len() + 1;
        if bytes + size > PAGE_BYTES && !items.is_empty() {
            byte_capped = true;
            continue;
        }
        bytes += size;
        items.push(row);
    }
    let end = offset + items.len();
    json!({
        "total": total,
        "offset": offset,
        "returned": items.len(),
        "next_offset": (end < total).then_some(end),
        "byte_capped": byte_capped,
        "items": items,
    })
}

fn permission_rows(manifest: &Manifest) -> Vec<Value> {
    let declared: BTreeMap<&str, Option<&str>> = manifest
        .declared_permissions
        .iter()
        .map(|permission| (permission.name.as_str(), permission.protection_level.as_deref()))
        .collect();
    manifest
        .uses_permissions
        .iter()
        .map(|uses| {
            let mut row = json!({"name": uses.name});
            if let Some(platform) = rampage_dex::permissions::lookup(&uses.name) {
                row["protection_level"] = json!(platform.protection_level);
                row["category"] = json!(platform.category);
                row["privacy"] = json!(platform.privacy);
            } else if let Some(level) = declared.get(uses.name.as_str()) {
                row["protection_level"] = json!(level.unwrap_or("normal"));
                row["declared_here"] = json!(true);
            } else {
                row["protection_level"] = json!("unknown");
            }
            if let Some(max) = uses.max_sdk {
                row["max_sdk"] = json!(max);
            }
            row
        })
        .collect()
}

fn component_row(component: &Component, defined: &HashSet<String>) -> Value {
    let mut row = serde_json::to_value(component).unwrap_or(Value::Null);
    if !defined.is_empty() {
        let descriptor = rampage_dex::dex::descriptor_of(&component.name);
        row["in_dex"] = json!(defined.contains(&descriptor));
    }
    row
}

/// The ELF architecture of an ABI directory name.
pub(crate) fn abi_arch(abi: &str) -> Option<rampage_arch::Arch> {
    use rampage_arch::Arch;
    Some(match abi {
        "arm64-v8a" => Arch::Aarch64,
        "armeabi-v7a" | "armeabi" => Arch::Arm,
        "x86" => Arch::X86,
        "x86_64" => Arch::X86_64,
        "mips" => Arch::Mips,
        "mips64" => Arch::Mips64,
        "riscv64" => Arch::Riscv64,
        _ => return None,
    })
}

/// A native library's JNI surface: its `Java_*` exports and whether it has `JNI_OnLoad` (which may register
/// natives by table instead of by name).
pub(crate) struct JniExports {
    pub(crate) java: Vec<String>,
    pub(crate) on_load: bool,
    pub(crate) error: Option<String>,
}

pub(crate) fn jni_exports(lib: &NativeLib) -> JniExports {
    let Some(bytes) = lib.bytes.clone() else {
        return JniExports { java: Vec::new(), on_load: false, error: Some("not read (size limit)".to_owned()) };
    };
    let Some(arch) = abi_arch(&lib.abi) else {
        return JniExports { java: Vec::new(), on_load: false, error: Some(format!("unknown ABI `{}`", lib.abi)) };
    };
    match rampage_loaders::Binary::from_owned_native_bytes(bytes, arch) {
        Ok(binary) => {
            let mut java: Vec<String> = binary
                .exports
                .iter()
                .filter(|export| export.name.starts_with("Java_"))
                .map(|export| export.name.clone())
                .collect();
            java.sort();
            java.dedup();
            JniExports { java, on_load: binary.exports.iter().any(|export| export.name == "JNI_OnLoad"), error: None }
        }
        Err(error) => JniExports { java: Vec::new(), on_load: false, error: Some(error.to_string()) },
    }
}

fn native_rows(apk: &Apk) -> Vec<Value> {
    apk.native_libs
        .iter()
        .map(|lib| {
            let exports = jni_exports(lib);
            let mut row = json!({
                "path": lib.path,
                "abi": lib.abi,
                "size": lib.size,
                "jni_exports": exports.java.iter().take(MAX_JNI_EXPORTS).collect::<Vec<_>>(),
                "jni_export_count": exports.java.len(),
                "jni_onload": exports.on_load,
            });
            if let Some(error) = exports.error {
                row["error"] = json!(error);
            }
            row
        })
        .collect()
}

fn dex_rows(opened: &Opened) -> Vec<Value> {
    opened
        .dexes
        .iter()
        .map(|(path, dex, size)| match dex {
            Ok(dex) => {
                let mut row = json!({
                    "path": path,
                    "size": size,
                    "version": format!("{:03}", dex.header.version),
                    "checksum_valid": dex.header.checksum_valid,
                    "signature_valid": dex.header.signature_valid,
                    "classes": dex.header.classes.count,
                    "method_ids": dex.header.methods.count,
                    "field_ids": dex.header.fields.count,
                    "strings": dex.header.strings.count,
                    "types": dex.header.types.count,
                });
                if !dex.warnings.is_empty() {
                    row["warnings"] = json!(dex.warnings.iter().take(8).collect::<Vec<_>>());
                    row["warnings_total"] = json!(dex.warnings.len() + dex.warnings_dropped);
                }
                row
            }
            Err(error) => json!({"path": path, "size": size, "error": error}),
        })
        .collect()
}

/// Capture APIs listed at most, and methods a reachability walk visits.
const MAX_CAPTURE_ROWS: usize = 50;
const MAX_REACHED: usize = 200_000;
const ACCESSIBILITY_SERVICE: &str = "Landroid/accessibilityservice/AccessibilityService;";

/// The Android capture and personal-data APIs the code invokes, each with its callers, the permissions that guard
/// it (and whether the manifest requests one), and the start-at-boot receivers whose code reaches a caller; plus
/// the classes that extend `AccessibilityService` (which can read the screen's contents).
fn privacy(opened: &Opened) -> Value {
    let mut calls: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
    let mut class_methods: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut accessibility = Vec::new();
    for (_, dex) in opened.parsed() {
        let index = rampage_dex::scan::index(dex);
        for (caller, callees) in index.calls {
            calls.entry(caller).or_default().extend(callees);
        }
        for (class, methods) in index.class_methods {
            class_methods.entry(class).or_default().extend(methods);
        }
        for class_index in 0..dex.class_count() {
            if let Ok(class) = dex.class_def(class_index)
                && dex.superclasses(&class).iter().any(|name| name == ACCESSIBILITY_SERVICE)
            {
                accessibility.push(class_name(&dex.type_text(class.class_idx)));
            }
        }
    }
    let manifest = opened.manifest();
    let requested: HashSet<&str> = manifest
        .map(|manifest| manifest.uses_permissions.iter().map(|permission| permission.name.as_str()).collect())
        .unwrap_or_default();
    let boot: Vec<String> = manifest
        .map(|manifest| {
            manifest
                .components
                .iter()
                .filter(|component| component.start_at_boot)
                .flat_map(|component| {
                    class_methods.get(&rampage_dex::dex::descriptor_of(&component.name)).cloned().unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default();
    let reached = rampage_dex::scan::reachable(&calls, &boot, MAX_REACHED);
    let uses = rampage_dex::scan::capture_uses(&calls);
    let rows: Vec<Value> = uses
        .iter()
        .take(MAX_CAPTURE_ROWS)
        .map(|capture| {
            let mut receivers: Vec<String> = capture
                .callers
                .iter()
                .filter_map(|caller| reached.get(caller))
                .map(|entry| class_name(entry.split("->").next().unwrap_or(entry)))
                .collect();
            receivers.sort();
            receivers.dedup();
            let mut row = serde_json::to_value(capture).unwrap_or(Value::Null);
            if manifest.is_some() && !capture.permissions.is_empty() {
                row["permission_requested"] =
                    json!(capture.permissions.iter().any(|permission| requested.contains(permission)));
            }
            if !receivers.is_empty() {
                row["reached_from_boot"] = json!(receivers);
            }
            row
        })
        .collect();
    let mut media: Vec<&str> = uses.iter().map(|capture| capture.medium).collect();
    media.sort();
    media.dedup();
    json!({
        "media": media,
        "capture_apis": rows,
        "capture_apis_total": uses.len(),
        "accessibility_services": accessibility,
        "note": "invoke sites in DEX code; reflection, native code and dynamically loaded code are not seen",
    })
}

/// The summary of one opened file: manifest, permissions, components (capped), native libraries and DEX files.
fn summary(path: &Path, opened: &Opened, components_limit: usize) -> Value {
    let mut out = json!({"path": path, "kind": opened.kind});
    let defined = defined_classes(opened);
    if let Some(apk) = &opened.apk {
        out["entries"] = json!(apk.entries);
        match &apk.manifest {
            Some(manifest) => {
                out["package"] = json!(manifest.package);
                out["version_code"] = json!(manifest.version_code);
                out["version_name"] = json!(manifest.version_name);
                out["sdk"] = json!(manifest.sdk);
                out["application"] = json!(manifest.application);
                out["permissions"] = json!(permission_rows(manifest));
                if !manifest.declared_permissions.is_empty() {
                    out["declared_permissions"] = json!(manifest.declared_permissions);
                }
                if !manifest.features.is_empty() {
                    out["features"] = json!(manifest.features);
                }
                let boot: Vec<&str> = manifest
                    .components
                    .iter()
                    .filter(|component| component.start_at_boot)
                    .map(|component| component.name.as_str())
                    .collect();
                out["start_at_boot"] = json!(boot);
                out["components_total"] = json!(manifest.components.len());
                out["components"] = json!(
                    manifest
                        .components
                        .iter()
                        .take(components_limit)
                        .map(|component| component_row(component, &defined))
                        .collect::<Vec<_>>()
                );
                if !manifest.warnings.is_empty() {
                    out["manifest_warnings"] = json!(manifest.warnings.iter().take(16).collect::<Vec<_>>());
                }
            }
            None => out["manifest_error"] = json!(apk.manifest_error),
        }
        out["native_libs"] = json!(native_rows(apk));
        if let Some(ResourceTable { size, packages, strings }) = &apk.resources {
            out["resources"] = json!({"size": size, "packages": packages, "strings": strings});
        }
        if !apk.warnings.is_empty() {
            out["warnings"] = json!(apk.warnings);
        }
    }
    out["dex"] = json!(dex_rows(opened));
    out["privacy"] = privacy(opened);
    let totals = opened.parsed().fold((0u64, 0u64, 0u64), |(classes, methods, strings), (_, dex)| {
        (
            classes + u64::from(dex.header.classes.count),
            methods + u64::from(dex.header.methods.count),
            strings + u64::from(dex.header.strings.count),
        )
    });
    out["totals"] = json!({"classes": totals.0, "method_ids": totals.1, "strings": totals.2});
    out
}

fn class_rows<'a>(
    opened: &'a Opened,
    prefix: Option<&'a str>,
    package: Option<&'a str>,
) -> impl Iterator<Item = Value> + 'a {
    let mut budget = rampage_dex::Limits::default().max_members;
    opened.parsed().flat_map(move |(path, dex)| {
        (0..dex.class_count())
            .filter_map(|index| dex.class_def(index).ok())
            .filter(|class| class_matches(&class_name(&dex.type_text(class.class_idx)), prefix, package))
            .map(|class| class_row(path, dex, &class, &mut budget))
            .collect::<Vec<_>>()
    })
}

fn method_rows<'a>(
    opened: &'a Opened,
    prefix: Option<&'a str>,
    package: Option<&'a str>,
) -> impl Iterator<Item = Value> + 'a {
    let mut budget = rampage_dex::Limits::default().max_members;
    opened.parsed().flat_map(move |(path, dex)| {
        let mut rows = Vec::new();
        for index in 0..dex.class_count() {
            let Ok(class) = dex.class_def(index) else { continue };
            if !class_matches(&class_name(&dex.type_text(class.class_idx)), prefix, package) {
                continue;
            }
            let Ok(data) = dex.class_data(&class, &mut budget) else { continue };
            for method in data.methods() {
                let mut row = json!({
                    "method": dex.method_text(method.method_idx),
                    "dex": path,
                    "index": method.method_idx,
                    "access": access_names(method.access, Member::Method),
                });
                if method.code_off != 0
                    && let Ok(code) = dex.code_item(method.code_off)
                {
                    row["code_units"] = json!(code.insns.len());
                    row["registers"] = json!(code.registers);
                }
                rows.push(row);
            }
        }
        rows
    })
}

/// Every APK, AAB, JAR or DEX file under `root`, sorted, without following symlinks.
fn walk(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    let mut stack = vec![(root.to_owned(), 0usize)];
    let mut visited = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|error| format!("cannot list {}: {error}", dir.display()))?;
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_WALK {
                return Err(format!("more than {MAX_WALK} directory entries under {}", root.display()));
            }
            let Ok(kind) = entry.file_type() else { continue };
            let path = entry.path();
            if kind.is_dir() && depth < 32 {
                stack.push((path, depth + 1));
            } else if kind.is_file() {
                let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("").to_ascii_lowercase();
                if matches!(extension.as_str(), "apk" | "aab" | "jar" | "dex" | "apex") || sniff(&path) == Some("dex") {
                    found.push(path);
                }
            }
        }
    }
    found.sort();
    Ok(found)
}

fn directory(query: &DexMetadataQuery) -> Result<Value, String> {
    let files = walk(&query.path)?;
    let start: usize = match &query.cursor {
        Some(cursor) => cursor.parse().map_err(|_| format!("cursor `{cursor}` is not one this tool returned"))?,
        None => 0,
    };
    let max_files = query.max_files.unwrap_or(DEFAULT_FILES).clamp(1, MAX_FILES);
    let mut rows = Vec::new();
    let mut bytes = 0usize;
    let mut next = start;
    for path in files.iter().skip(start).take(max_files) {
        let row = match open(path, true) {
            Ok(opened) => {
                let mut row = summary(path, &opened, 0);
                if let Some(object) = row.as_object_mut() {
                    object.remove("components");
                    object.remove("application");
                    if let Some(privacy) = object.get_mut("privacy").and_then(Value::as_object_mut) {
                        privacy.retain(|key, _| key == "media" || key == "capture_apis_total");
                    }
                }
                row
            }
            Err(error) => json!({"path": path, "error": error}),
        };
        let size = row.to_string().len();
        if bytes + size > PAGE_BYTES + 12_000 && !rows.is_empty() {
            break;
        }
        bytes += size;
        rows.push(row);
        next += 1;
    }
    Ok(json!({
        "path": query.path,
        "files_total": files.len(),
        "files": rows,
        "next_cursor": (next < files.len()).then(|| next.to_string()),
        "hint": "call dex_metadata on one file for its classes, methods and every component",
    }))
}

pub fn dex_metadata(query: &DexMetadataQuery) -> Result<Value, String> {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_DEX_PAGE).contains(&limit) {
        return Err(format!("limit must be in 1..={MAX_DEX_PAGE}"));
    }
    if std::fs::metadata(&query.path).is_ok_and(|metadata| metadata.is_dir()) {
        return directory(query);
    }
    if query.cursor.is_some() {
        return Err("cursor pages a directory; for one file use offset".to_owned());
    }
    let opened = open(&query.path, true)?;
    let list = query.list.as_deref().unwrap_or("classes");
    let offset = query.offset.unwrap_or(0);
    let (prefix, package) = (query.prefix.as_deref(), query.package.as_deref());
    let mut out = summary(&query.path, &opened, if list == "components" { 0 } else { SUMMARY_COMPONENTS });
    let page = match list {
        "classes" => page(class_rows(&opened, prefix, package), offset, limit),
        "methods" => page(method_rows(&opened, prefix, package), offset, limit),
        "components" => {
            let defined = defined_classes(&opened);
            let components = opened.manifest().map(|manifest| manifest.components.clone()).unwrap_or_default();
            page(
                components
                    .iter()
                    .filter(|component| class_matches(&component.name, prefix, package))
                    .map(|component| component_row(component, &defined))
                    .collect::<Vec<_>>()
                    .into_iter(),
                offset,
                limit,
            )
        }
        other => return Err(format!("unknown list `{other}` (expected classes, methods or components)")),
    };
    out["list"] = json!(list);
    out["page"] = page;
    Ok(out)
}
