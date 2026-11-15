//! `endpoint_inventory` and `endpoint_blocklist`: the network endpoints a binary or an extracted firmware tree
//! names (URLs, hosts, IP literals, certificate pins and embedded certificates), with the evidence for each and
//! grouped by registrable domain and by component, and a DNS or firewall blocklist of the chosen ones. An owner can
//! block a device's telemetry at the router without modifying the device.

mod certificate;
mod classify;
mod export;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rampage_analysis::strings::{self, Encoding};
use serde::Serialize;
use serde_json::{Value, json};

use crate::Project;
use crate::workflows::network_api;
pub use certificate::Certificate;
pub use classify::{Candidate, Form, Kind, Noise, extract, registrable};
pub use export::{BlocklistQuery, endpoint_blocklist};

/// Files scanned per call by default and at most, and the default and largest time budget.
const DEFAULT_MAX_FILES: usize = 200;
const MAX_FILES: usize = 5000;
const DEFAULT_TIMEOUT_MS: u64 = 20_000;
const MAX_TIMEOUT_MS: u64 = 120_000;
/// Directory entries walked before a tree is cut, and its deepest level.
const MAX_WALK_ENTRIES: usize = 200_000;
const MAX_WALK_DEPTH: usize = 64;
/// Executables larger than this are skipped, and text files larger than this.
const MAX_EXECUTABLE_BYTES: u64 = 256 << 20;
const MAX_TEXT_BYTES: u64 = 4 << 20;
/// Endpoint rows per result by default and at most, and the JSON bytes the rows and groups may take.
const DEFAULT_ROWS: usize = 100;
const MAX_ROWS: usize = 500;
const RESULT_BYTES: usize = 56_000;
/// Evidence items, groups, hosts and components listed per row or group, noise examples per reason and skipped
/// files listed.
const MAX_ROW_EVIDENCE: usize = 4;
const MAX_GROUPS: usize = 100;
const MAX_GROUP_ITEMS: usize = 10;
const MAX_NOISE_EXAMPLES: usize = 3;
const MAX_SKIPPED: usize = 20;
/// Extensions of the configuration-like text files a tree scan reads (besides scripts with a `#!` line).
const TEXT_EXTENSIONS: [&str; 14] =
    ["sh", "conf", "cfg", "json", "xml", "prop", "properties", "ini", "yaml", "yml", "rc", "service", "env", "lua"];

pub struct InventoryQuery {
    /// An executable or other file, or a directory such as an `fs_extract` output_dir.
    pub path: PathBuf,
    /// Where a directory scan resumes (the `next_cursor` of the previous page).
    pub cursor: Option<String>,
    pub max_files: Option<usize>,
    pub timeout_ms: Option<u64>,
    /// Look up the functions referencing each string (default: on for a file, off for a directory).
    pub xrefs: Option<bool>,
    /// Run candidate string decoders in emulation and read endpoints from their output (default off).
    pub decode: bool,
    /// Only rows of these kinds.
    pub kinds: Option<Vec<String>>,
    pub limit: Option<usize>,
}

/// How strongly code ties a finding to networking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    /// Read from text, or references were not looked up.
    NotTraced,
    /// References were looked up and none were found.
    Unreferenced,
    /// Referenced from code.
    Referenced,
    /// Referenced from a function that also calls a networking API `network_surface` knows.
    NetworkCode,
}

/// Where one occurrence of a finding was read.
#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    /// `string` (a readable string in the image), `decoded` (emulated decoder output), `text` (a line of a text
    /// file), `bytes` (a string in a file no loader opened) or `certificate`.
    pub origin: &'static str,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "rampage_arch::hex::optional_address")]
    pub address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<&'static str>,
    /// The decoding routine whose emulated output held it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_by: Option<String>,
    /// Referencing functions, `name@0xaddress`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<String>,
    /// Networking APIs those functions call.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub network_apis: Vec<String>,
}

/// One endpoint in one component, with every occurrence's evidence (the first few kept).
#[derive(Debug, Clone, Serialize)]
pub struct Row {
    pub kind: Kind,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form: Option<Form>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    pub component: String,
    pub signal: Signal,
    pub occurrences: usize,
    pub evidence: Vec<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Certificate>,
    /// For a pin: the subject of a certificate in the inventory whose public key it pins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pins_certificate: Option<String>,
}

/// Everything one scan collected.
#[derive(Default)]
pub struct Inventory {
    pub rows: BTreeMap<(String, Kind, String), Row>,
    pub noise: BTreeMap<Noise, (usize, Vec<String>)>,
    /// Component path to its format (`elf`, `text`, ...).
    pub components: BTreeMap<String, String>,
    pub limitations: BTreeSet<String>,
    pub files: usize,
    pub executables: usize,
    pub text_files: usize,
    pub bytes: u64,
    pub skipped: Vec<(String, String)>,
    /// Other files passed over (neither executable nor configuration-like text).
    pub ignored: usize,
    pub symlinks: usize,
    pub next_cursor: Option<String>,
    pub stopped: Option<&'static str>,
}

impl Inventory {
    fn add(&mut self, component: &str, candidate: Candidate, evidence: Evidence, signal: Signal) {
        let key = (component.to_owned(), candidate.kind, candidate.value.clone());
        let row = self.rows.entry(key).or_insert_with(|| Row {
            kind: candidate.kind,
            value: candidate.value,
            form: candidate.form,
            host: candidate.host,
            domain: candidate.domain,
            reason: candidate.reason,
            component: component.to_owned(),
            signal,
            occurrences: 0,
            evidence: Vec::new(),
            certificate: None,
            pins_certificate: None,
        });
        row.occurrences += 1;
        row.signal = row.signal.max(signal);
        if row.evidence.len() < MAX_ROW_EVIDENCE {
            row.evidence.push(evidence);
        }
    }

    fn add_text(&mut self, component: &str, text: &str, evidence: &Evidence, signal: Signal) {
        let extracted = extract(text);
        for (noise, example) in extracted.noise {
            let entry = self.noise.entry(noise).or_default();
            entry.0 += 1;
            if entry.1.len() < MAX_NOISE_EXAMPLES && !entry.1.contains(&example) {
                entry.1.push(example);
            }
        }
        for candidate in extracted.found {
            self.add(component, candidate, evidence.clone(), signal);
        }
    }

    fn add_certificate(&mut self, component: &str, certificate: Certificate, evidence: Evidence, signal: Signal) {
        let candidate = Candidate {
            kind: Kind::Certificate,
            value: certificate.subject.clone(),
            form: None,
            host: None,
            domain: None,
            reason: None,
        };
        let key = (component.to_owned(), Kind::Certificate, candidate.value.clone());
        self.add(component, candidate, evidence, signal);
        if let Some(row) = self.rows.get_mut(&key) {
            row.certificate.get_or_insert(certificate);
        }
    }

    /// Links each pin to a certificate in the inventory with the same SPKI pin.
    fn link_pins(&mut self) {
        let pins: BTreeMap<String, String> = self
            .rows
            .values()
            .filter_map(|row| row.certificate.as_ref())
            .map(|certificate| (certificate.spki_pin.clone(), certificate.subject.clone()))
            .collect();
        for row in self.rows.values_mut().filter(|row| row.kind == Kind::Pin) {
            let pin =
                if row.value.starts_with("sha256/") { row.value.clone() } else { format!("sha256/{}", row.value) };
            row.pins_certificate = pins.get(&pin).cloned();
        }
    }

    fn skip(&mut self, path: &str, reason: impl Into<String>) {
        self.skipped.push((path.to_owned(), reason.into()));
    }
}

/// The functions that reference networking APIs, with the APIs each calls; `None` without analysis.
struct NetworkCode {
    functions: BTreeMap<u64, BTreeSet<String>>,
}

impl NetworkCode {
    fn of(project: &Project) -> Option<Self> {
        let analysis = project.analysis().ok()?;
        let program = &analysis.program;
        let mut targets: BTreeMap<u64, String> = BTreeMap::new();
        for import in &project.binary.imports {
            if network_api(&import.name).is_none() {
                continue;
            }
            for slot in project.binary.import_slots.iter().filter(|slot| slot.name == import.name) {
                targets.insert(slot.address, import.name.clone());
            }
            if let Ok(address) = project.resolve(&import.name) {
                targets.insert(address, import.name.clone());
            }
        }
        for symbol in &project.binary.symbols {
            if symbol.kind == rampage_loaders::SymbolKind::Function
                && project.binary.is_code(symbol.address)
                && network_api(&symbol.name).is_some()
            {
                targets.insert(symbol.address, symbol.name.clone());
            }
        }
        let mut functions: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
        for (&target, name) in &targets {
            for xref in program.xrefs_to(target) {
                if let Some(function) = analysis.function_containing(xref.from)
                    && !targets.contains_key(&function)
                {
                    functions.entry(function).or_default().insert(name.clone());
                }
            }
        }
        Some(Self { functions })
    }
}

/// References into `start..end` from discovered functions, and the evidence and signal they give.
fn traced(project: &Project, network: Option<&NetworkCode>, start: u64, end: u64, extra: &[u64]) -> (Evidence, Signal) {
    let mut evidence = Evidence {
        origin: "string",
        address: Some(start),
        offset: None,
        line: None,
        encoding: None,
        decoded_by: None,
        functions: Vec::new(),
        network_apis: Vec::new(),
    };
    let (Some(network), Ok(analysis)) = (network, project.analysis()) else { return (evidence, Signal::NotTraced) };
    let xrefs = &analysis.program.xrefs;
    let first = xrefs.partition_point(|xref| xref.to < start);
    let last = xrefs.partition_point(|xref| xref.to < end.max(start + 1));
    let mut functions: BTreeSet<u64> =
        xrefs[first..last].iter().filter_map(|xref| analysis.function_containing(xref.from)).collect();
    functions.extend(extra);
    let mut apis = BTreeSet::new();
    for function in &functions {
        evidence.functions.push(format!("{}@{function:#x}", project.function_name(*function)));
        if let Some(called) = network.functions.get(function) {
            apis.extend(called.iter().cloned());
        }
    }
    evidence.network_apis = apis.into_iter().collect();
    let signal = if functions.is_empty() {
        Signal::Unreferenced
    } else if evidence.network_apis.is_empty() {
        Signal::Referenced
    } else {
        Signal::NetworkCode
    };
    (evidence, signal)
}

fn encoding_name(encoding: Encoding) -> &'static str {
    match encoding {
        Encoding::Ascii => "ascii",
        Encoding::Utf16Le => "utf16le",
    }
}

/// Scans an opened binary: certificates in its segments, its readable strings (outside those certificates), and
/// with `decode`, the output of its candidate string decoders.
pub fn scan_project(project: &Project, component: &str, xrefs: bool, decode: bool, inventory: &mut Inventory) {
    let binary = &project.binary;
    let network = if xrefs { NetworkCode::of(project) } else { None };
    if xrefs && network.is_none() {
        let error = project.analysis().err().map_or_else(String::new, |error| error.to_string());
        inventory
            .limitations
            .insert(format!("Code references are unavailable for {component} ({error}); its findings are not traced."));
    }
    let mut certificate_ranges = Vec::new();
    for segment in binary.segments.iter().filter(|segment| segment.file_size > 0) {
        let Some(bytes) = binary.read_to_segment_end(segment.address) else { continue };
        let bytes = &bytes[..bytes.len().min(usize::try_from(segment.file_size).unwrap_or(usize::MAX))];
        for certificate in certificate::certificates(bytes) {
            let address = segment.address + certificate.offset as u64;
            let end = address + certificate.length as u64;
            certificate_ranges.push((address, end));
            let (mut evidence, signal) = traced(project, network.as_ref(), address, end, &[]);
            evidence.origin = "certificate";
            evidence.encoding = Some(certificate.encoding);
            inventory.add_certificate(component, certificate, evidence, signal);
        }
    }
    for found in project.scanned_strings() {
        if certificate_ranges.iter().any(|&(start, end)| (start..end).contains(&found.address)) {
            continue;
        }
        let unit = if found.encoding == Encoding::Utf16Le { 2 } else { 1 };
        let end = found.address + (found.text.chars().count() * unit) as u64;
        let (mut evidence, signal) = traced(project, network.as_ref(), found.address, end, &[]);
        evidence.encoding = Some(encoding_name(found.encoding));
        inventory.add_text(component, &found.text, &evidence, signal);
    }
    if decode {
        if project.analysis().is_err() {
            inventory.limitations.insert(format!("Decoders cannot be emulated in {component} without analysis."));
            return;
        }
        for decoded in project.decoded_texts() {
            let callers: Vec<u64> = decoded.callers.iter().map(|(address, _)| *address).collect();
            let (mut evidence, signal) = traced(project, network.as_ref(), decoded.blob, decoded.blob + 1, &callers);
            evidence.origin = "decoded";
            evidence.decoded_by = Some(format!("{}@{:#x}", decoded.routine_name, decoded.routine));
            inventory.add_text(component, &decoded.text, &evidence, signal);
        }
    }
}

/// Scans a file no loader opened, or one too odd to analyse, by its raw bytes: certificates and readable strings
/// (by file offset).
fn scan_bytes(bytes: &[u8], component: &str, inventory: &mut Inventory) {
    let mut ranges = Vec::new();
    for certificate in certificate::certificates(bytes) {
        ranges.push((certificate.offset as u64, (certificate.offset + certificate.length) as u64));
        let evidence = Evidence {
            origin: "certificate",
            address: None,
            offset: Some(certificate.offset as u64),
            line: None,
            encoding: Some(certificate.encoding),
            decoded_by: None,
            functions: Vec::new(),
            network_apis: Vec::new(),
        };
        inventory.add_certificate(component, certificate, evidence, Signal::NotTraced);
    }
    for found in strings::scan_bytes(bytes, 0, 4) {
        if ranges.iter().any(|&(start, end)| (start..end).contains(&found.address)) {
            continue;
        }
        let evidence = Evidence {
            origin: "bytes",
            address: None,
            offset: Some(found.address),
            line: None,
            encoding: Some(encoding_name(found.encoding)),
            decoded_by: None,
            functions: Vec::new(),
            network_apis: Vec::new(),
        };
        inventory.add_text(component, &found.text, &evidence, Signal::NotTraced);
    }
}

/// Scans a text file line by line, plus the certificates in it.
fn scan_text(text: &str, component: &str, inventory: &mut Inventory) {
    for certificate in certificate::certificates(text.as_bytes()) {
        let line = text[..certificate.offset].matches('\n').count() + 1;
        let evidence = Evidence {
            origin: "certificate",
            address: None,
            offset: Some(certificate.offset as u64),
            line: Some(line),
            encoding: Some(certificate.encoding),
            decoded_by: None,
            functions: Vec::new(),
            network_apis: Vec::new(),
        };
        inventory.add_certificate(component, certificate, evidence, Signal::NotTraced);
    }
    for (index, line) in text.lines().enumerate() {
        let evidence = Evidence {
            origin: "text",
            address: None,
            offset: None,
            line: Some(index + 1),
            encoding: None,
            decoded_by: None,
            functions: Vec::new(),
            network_apis: Vec::new(),
        };
        inventory.add_text(component, line, &evidence, Signal::NotTraced);
    }
}

/// What a file is to the scan.
enum FileKind {
    Executable(&'static str),
    Text,
    Other,
}

fn file_kind(path: &Path, head: &[u8]) -> FileKind {
    if let Some(format) = rampage_unpack::executable_format(head) {
        return FileKind::Executable(format);
    }
    let extension = path.extension().and_then(|extension| extension.to_str()).map(str::to_ascii_lowercase);
    if head.starts_with(b"#!") || extension.is_some_and(|extension| TEXT_EXTENSIONS.contains(&extension.as_str())) {
        FileKind::Text
    } else {
        FileKind::Other
    }
}

fn read_head(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut head = Vec::with_capacity(64);
    std::fs::File::open(path)?.take(64).read_to_end(&mut head)?;
    Ok(head)
}

/// Scans one file as its kind says, recording it in `inventory`.
fn scan_file(
    path: &Path,
    component: &str,
    size: u64,
    kind: FileKind,
    xrefs: bool,
    decode: bool,
    inventory: &mut Inventory,
) {
    match kind {
        FileKind::Executable(format) => {
            if size > MAX_EXECUTABLE_BYTES {
                return inventory.skip(component, format!("executable over {} MiB", MAX_EXECUTABLE_BYTES >> 20));
            }
            inventory.files += 1;
            inventory.executables += 1;
            inventory.bytes += size;
            inventory.components.insert(component.to_owned(), format.to_owned());
            match rampage_loaders::Binary::open(path) {
                Ok(binary) => scan_project(&Project::new(binary), component, xrefs, decode, inventory),
                Err(error) => match std::fs::read(path) {
                    Ok(bytes) => {
                        inventory.limitations.insert(format!(
                            "{component} did not load ({error}); its raw bytes were scanned, without addresses or \
                             references."
                        ));
                        scan_bytes(&bytes, component, inventory);
                    }
                    Err(error) => inventory.skip(component, format!("unreadable: {error}")),
                },
            }
        }
        FileKind::Text => {
            if size > MAX_TEXT_BYTES {
                return inventory.skip(component, format!("text file over {} MiB", MAX_TEXT_BYTES >> 20));
            }
            let bytes = match std::fs::read(path) {
                Ok(bytes) => bytes,
                Err(error) => return inventory.skip(component, format!("unreadable: {error}")),
            };
            if bytes[..bytes.len().min(8192)].contains(&0) {
                inventory.ignored += 1;
                return;
            }
            inventory.files += 1;
            inventory.text_files += 1;
            inventory.bytes += size;
            inventory.components.insert(component.to_owned(), "text".to_owned());
            scan_text(&String::from_utf8_lossy(&bytes), component, inventory);
        }
        FileKind::Other => inventory.ignored += 1,
    }
}

/// A regular file in a tree: its path relative to the root (with `/`), its full path and its size.
type TreeFile = (String, PathBuf, u64);

/// The regular files under `root` in path order, never following symlinks, and how many symlinks were passed over;
/// an error when the walk is too large.
fn walk(root: &Path) -> Result<(Vec<TreeFile>, usize), String> {
    let mut files = Vec::new();
    let mut symlinks = 0;
    let mut entries = 0;
    let mut stack = vec![(root.to_path_buf(), String::new(), 0usize)];
    while let Some((directory, relative, depth)) = stack.pop() {
        let listing =
            std::fs::read_dir(&directory).map_err(|error| format!("read {}: {error}", directory.display()))?;
        for entry in listing {
            let entry = entry.map_err(|error| format!("read {}: {error}", directory.display()))?;
            entries += 1;
            if entries > MAX_WALK_ENTRIES {
                return Err(format!(
                    "the tree has more than {MAX_WALK_ENTRIES} entries; scan a subdirectory (such as usr/bin or etc)"
                ));
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            let child = if relative.is_empty() { name } else { format!("{relative}/{name}") };
            let Ok(metadata) = std::fs::symlink_metadata(&path) else { continue };
            if metadata.file_type().is_symlink() {
                symlinks += 1;
            } else if metadata.is_dir() {
                if depth + 1 < MAX_WALK_DEPTH {
                    stack.push((path, child, depth + 1));
                }
            } else if metadata.is_file() {
                files.push((child, path, metadata.len()));
            }
        }
    }
    files.sort();
    Ok((files, symlinks))
}

/// Scans `query.path`: one file whole, or a directory's files in path order from `query.cursor` until the file or
/// time budget runs out (at least one file per call).
pub fn scan(query: &InventoryQuery) -> Result<Inventory, String> {
    let max_files = query.max_files.unwrap_or(DEFAULT_MAX_FILES);
    if !(1..=MAX_FILES).contains(&max_files) {
        return Err(format!("max_files must be in 1..={MAX_FILES}"));
    }
    let timeout = query.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if !(1..=MAX_TIMEOUT_MS).contains(&timeout) {
        return Err(format!("timeout_ms must be in 1..={MAX_TIMEOUT_MS}"));
    }
    let deadline = Instant::now() + Duration::from_millis(timeout);
    let metadata = std::fs::metadata(&query.path).map_err(|error| format!("{}: {error}", query.path.display()))?;
    let mut inventory = Inventory::default();
    if metadata.is_file() {
        if query.cursor.is_some() {
            return Err("cursor applies to a directory scan".to_owned());
        }
        let component = query
            .path
            .file_name()
            .map_or_else(|| query.path.display().to_string(), |name| name.to_string_lossy().into_owned());
        let head = read_head(&query.path).map_err(|error| format!("{}: {error}", query.path.display()))?;
        let kind = file_kind(&query.path, &head);
        let xrefs = query.xrefs.unwrap_or(true);
        scan_file(&query.path, &component, metadata.len(), kind, xrefs, query.decode, &mut inventory);
        if inventory.files == 0 && inventory.skipped.is_empty() {
            // Neither an executable nor configuration-like text: read its strings anyway, since it was asked for.
            if metadata.len() > MAX_EXECUTABLE_BYTES {
                return Err(format!(
                    "{} is over {} MiB and neither an executable nor text; extract it first (fs_extract, carve)",
                    query.path.display(),
                    MAX_EXECUTABLE_BYTES >> 20
                ));
            }
            let bytes = std::fs::read(&query.path).map_err(|error| error.to_string())?;
            inventory.ignored = 0;
            inventory.files = 1;
            inventory.bytes = bytes.len() as u64;
            inventory.components.insert(component.clone(), "data".to_owned());
            scan_bytes(&bytes, &component, &mut inventory);
        }
    } else {
        let (files, symlinks) = walk(&query.path)?;
        inventory.symlinks = symlinks;
        let start = query.cursor.as_ref().map_or(0, |cursor| files.partition_point(|(path, ..)| path < cursor));
        let xrefs = query.xrefs.unwrap_or(false);
        let mut scanned = 0;
        for (relative, path, size) in &files[start..] {
            // Files the scan passes over cost a 64-byte read and never end a page, so a page stops at a file it
            // would scan and the last page is never empty.
            let kind = match read_head(path) {
                Ok(head) => file_kind(path, &head),
                Err(error) => {
                    inventory.skip(relative, format!("unreadable: {error}"));
                    continue;
                }
            };
            if matches!(kind, FileKind::Other) {
                inventory.ignored += 1;
                continue;
            }
            if scanned > 0 && (inventory.files >= max_files || Instant::now() >= deadline) {
                inventory.next_cursor = Some(relative.clone());
                inventory.stopped = Some(if inventory.files >= max_files { "max_files" } else { "timeout_ms" });
                break;
            }
            let before = inventory.files;
            scan_file(path, relative, *size, kind, xrefs, query.decode, &mut inventory);
            scanned += usize::from(inventory.files > before);
        }
    }
    inventory.link_pins();
    Ok(inventory)
}

/// Rows of `kinds` (all when `None`), most notable kind first, then by domain, value and component.
fn ordered<'i>(inventory: &'i Inventory, kinds: Option<&BTreeSet<Kind>>) -> Vec<&'i Row> {
    let mut rows: Vec<&Row> =
        inventory.rows.values().filter(|row| kinds.is_none_or(|kinds| kinds.contains(&row.kind))).collect();
    rows.sort_by(|a, b| (a.kind, &a.domain, &a.value, &a.component).cmp(&(b.kind, &b.domain, &b.value, &b.component)));
    rows
}

fn capped<T: Serialize>(items: impl IntoIterator<Item = T>, limit: usize) -> (Vec<T>, usize) {
    let mut kept = Vec::new();
    let mut total = 0;
    for item in items {
        total += 1;
        if kept.len() < limit {
            kept.push(item);
        }
    }
    (kept, total)
}

/// Registrable domains (and IP addresses) with their hosts and the components naming them, most components first.
fn domain_groups(inventory: &Inventory) -> Vec<Value> {
    #[derive(Default)]
    struct Group {
        hosts: BTreeSet<String>,
        components: BTreeSet<String>,
        kinds: BTreeMap<&'static str, usize>,
        local: bool,
        network_code: bool,
        ip: bool,
    }
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    for row in inventory.rows.values() {
        let Some(host) = &row.host else { continue };
        let ip = row.form == Some(Form::Ip) || host.parse::<std::net::IpAddr>().is_ok();
        let key = if ip { host.clone() } else { row.domain.clone().unwrap_or_else(|| host.clone()) };
        let group = groups.entry(key).or_default();
        group.hosts.insert(host.clone());
        group.components.insert(row.component.clone());
        *group.kinds.entry(row.kind.name()).or_default() += 1;
        group.local |= row.kind == Kind::Local;
        group.network_code |= row.signal == Signal::NetworkCode;
        group.ip |= ip;
    }
    let mut groups: Vec<(String, Group)> = groups.into_iter().collect();
    // Most components first, then non-local, then tied to networking code, then names before addresses.
    groups.sort_by(|a, b| {
        b.1.components
            .len()
            .cmp(&a.1.components.len())
            .then(a.1.local.cmp(&b.1.local))
            .then(b.1.network_code.cmp(&a.1.network_code))
            .then(a.1.ip.cmp(&b.1.ip))
            .then(a.0.cmp(&b.0))
    });
    groups
        .into_iter()
        .map(|(name, group)| {
            let (hosts, hosts_total) = capped(group.hosts, MAX_GROUP_ITEMS);
            let (components, components_total) = capped(group.components, MAX_GROUP_ITEMS);
            json!({
                (if group.ip { "ip" } else { "domain" }): name,
                "hosts": hosts,
                "hosts_total": hosts_total,
                "components": components,
                "components_total": components_total,
                "kinds": group.kinds,
                "local": group.local,
                "network_code": group.network_code,
            })
        })
        .collect()
}

/// Components with their format, endpoint count by kind and the domains they name.
fn component_groups(inventory: &Inventory) -> Vec<Value> {
    let mut groups: BTreeMap<&str, (BTreeMap<&'static str, usize>, BTreeSet<&str>)> = BTreeMap::new();
    for row in inventory.rows.values() {
        let group = groups.entry(&row.component).or_default();
        *group.0.entry(row.kind.name()).or_default() += 1;
        if let Some(domain) = row.domain.as_deref().or(row.host.as_deref())
            && row.kind != Kind::Local
        {
            group.1.insert(domain);
        }
    }
    groups
        .into_iter()
        .map(|(component, (kinds, domains))| {
            let (domains, domains_total) = capped(domains, MAX_GROUP_ITEMS);
            json!({
                "path": component,
                "format": inventory.components.get(component),
                "kinds": kinds,
                "domains": domains,
                "domains_total": domains_total,
            })
        })
        .collect()
}

/// The `endpoint_inventory` result for `query`.
pub fn endpoint_inventory(query: &InventoryQuery) -> Result<Value, String> {
    let kinds = match &query.kinds {
        Some(names) => Some(
            names
                .iter()
                .map(|name| Kind::parse(name).ok_or_else(|| format!("unknown kind `{name}`")))
                .collect::<Result<BTreeSet<Kind>, String>>()?,
        ),
        None => None,
    };
    let limit = query.limit.unwrap_or(DEFAULT_ROWS);
    if !(1..=MAX_ROWS).contains(&limit) {
        return Err(format!("limit must be in 1..={MAX_ROWS}"));
    }
    let inventory = scan(query)?;
    let rows = ordered(&inventory, kinds.as_ref());
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for row in inventory.rows.values() {
        *counts.entry(row.kind.name()).or_default() += 1;
    }
    let noise: BTreeMap<&str, Value> = inventory
        .noise
        .iter()
        .map(|(noise, (count, examples))| (noise.name(), json!({"count": count, "examples": examples})))
        .collect();
    let mut domains = domain_groups(&inventory);
    let domains_total = domains.len();
    domains.truncate(MAX_GROUPS);
    let mut components = component_groups(&inventory);
    let components_total = components.len();
    components.truncate(MAX_GROUPS);
    let (skipped, skipped_total) =
        capped(inventory.skipped.iter().map(|(path, reason)| json!({"path": path, "reason": reason})), MAX_SKIPPED);
    let mut limitations: Vec<String> = inventory.limitations.iter().cloned().collect();
    limitations.push(
        "Endpoints are matched lexically in strings and text: addresses built at run time, encrypted or compressed \
         data, and IPv4 addresses stored as integers in code are not found; decoded strings need decode."
            .to_owned(),
    );
    let rows_total = rows.len();
    let mut rows: Vec<Value> = rows.iter().take(limit).filter_map(|row| serde_json::to_value(row).ok()).collect();
    let mut result = json!({
        "path": query.path,
        "scanned": {
            "files": inventory.files,
            "executables": inventory.executables,
            "text_files": inventory.text_files,
            "bytes": inventory.bytes,
            "ignored": inventory.ignored,
            "symlinks": inventory.symlinks,
        },
        "skipped": skipped,
        "skipped_total": skipped_total,
        "next_cursor": inventory.next_cursor,
        "stopped": inventory.stopped,
        "counts": counts,
        "noise": noise,
        "limitations": limitations,
        "hint": "endpoint_blocklist writes the hosts and IPs as a hosts, dnsmasq, unbound, domain or IP list",
    });
    // Rows and groups go last and shrink until the whole result fits.
    loop {
        result["domains_total"] = json!(domains_total);
        result["components_total"] = json!(components_total);
        result["endpoints_total"] = json!(rows_total);
        result["domains"] = json!(domains);
        result["components"] = json!(components);
        result["endpoints"] = json!(rows);
        result["endpoints_omitted"] = json!(rows_total - rows.len());
        if result.to_string().len() <= RESULT_BYTES {
            break;
        }
        if rows.len() > 1 {
            rows.truncate(rows.len() / 2);
        } else if domains.len() > 1 || components.len() > 1 {
            domains.truncate(domains.len().div_ceil(2));
            components.truncate(components.len().div_ceil(2));
        } else {
            break;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_kinds_follow_magic_extension_and_shebang() {
        assert!(matches!(file_kind(Path::new("x"), b"\x7fELF\x02"), FileKind::Executable("elf")));
        assert!(matches!(file_kind(Path::new("etc/a.conf"), b"key=value"), FileKind::Text));
        assert!(matches!(file_kind(Path::new("etc/init.d/S50x"), b"#!/bin/sh\n"), FileKind::Text));
        assert!(matches!(file_kind(Path::new("usr/share/doc.txt"), b"hello"), FileKind::Other));
    }
}
