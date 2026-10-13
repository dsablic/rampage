//! Data packs: directories that extend the heuristic databases (function signatures, PeID overlays, YARA rules,
//! capa rules) and declare in a `rampage-pack.toml` manifest what they hold, under which licence and from where.
//! A pack is data only: nothing is downloaded or executed. Every path stays inside the pack directory, every file
//! is read once, with a size cap and within running budgets per pack and for all packs together, and a content that
//! fails to load is reported without keeping the others from loading.

use std::collections::HashSet;
use std::fs::File;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use rampage_arch::Arch;
use rampage_capabilities::CapaRuleSet;
use serde::{Deserialize, Serialize};

use crate::files::{MAX_PACK_MANIFEST_BYTES, MAX_PEID_BYTES, MAX_RULE_FILE_BYTES, MAX_SIGNATURE_DB_BYTES};
use crate::files::{read_open_bounded, size_label};

/// The manifest file at the root of every pack directory.
pub const MANIFEST_FILE: &str = "rampage-pack.toml";
/// The environment variable holding pack directories, as a platform path list, loaded after `--pack` ones.
pub const PACKS_VARIABLE: &str = "RAMPAGE_PACKS";
/// The name the bundled databases are listed under; no pack may take it.
pub const BUILTIN_PACK: &str = "rampage-builtin";
/// The YARA namespace user-supplied rules match in; a pack named so would pass its matches off as the user's.
const USER_RULES_NAMESPACE: &str = "default";

const MAX_CONTENTS: usize = 256;
/// Rule files gathered from one directory content.
const MAX_RULE_FILES: usize = 10_000;
/// Subdirectory levels searched below a capa rule directory.
const MAX_RULE_DEPTH: usize = 32;
const MAX_NAME_CHARS: usize = 64;
const MAX_LICENSE_CHARS: usize = 128;
const MAX_SOURCE_CHARS: usize = 2048;
const MAX_DESCRIPTION_CHARS: usize = 4096;
/// PeID problems named in a content's detail; the rest are counted.
const MAX_PEID_WARNINGS: usize = 3;
const MIB: u64 = 1024 * 1024;
/// Packs loaded in one process; directories past these are reported, not read.
const MAX_PACKS: usize = 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    name: String,
    version: String,
    /// An SPDX licence expression.
    license: String,
    /// Where the data comes from: a URL or another statement of provenance.
    source: String,
    description: String,
    contents: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    kind: Kind,
    path: String,
    /// For signatures: the architecture the database must be built for.
    #[serde(default)]
    arch: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Signatures,
    Peid,
    Yara,
    Capa,
    Constants,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Signatures => "signatures",
            Kind::Peid => "peid",
            Kind::Yara => "yara",
            Kind::Capa => "capa",
            Kind::Constants => "constants",
        }
    }
}

/// One pack as loaded: its manifest's declarations and the status of each content.
#[derive(Debug, Clone, Serialize)]
pub struct PackInfo {
    /// The pack directory as given; absent for the built-in pack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory: Option<PathBuf>,
    pub builtin: bool,
    /// The manifest's declarations; absent when the manifest was unreadable or rejected.
    #[serde(flatten)]
    pub manifest: Option<PackManifest>,
    /// Why the whole pack was rejected; none of its contents is then loaded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub contents: Vec<ContentInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackManifest {
    pub name: String,
    pub version: String,
    /// SPDX licence expression.
    pub license: String,
    /// Provenance: where the data comes from.
    pub source: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentInfo {
    /// `signatures`, `peid`, `yara`, `capa` or `constants`; the built-in pack also lists `detect`, its
    /// producing-tool database.
    pub kind: &'static str,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    pub status: ContentStatus,
    /// What loaded, or why it did not.
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentStatus {
    Loaded,
    Error,
    /// Declared validly, but this version cannot use it.
    Unsupported,
}

/// The data packs in effect, in load order, with the databases they contributed. Packs made with [`Packs::lazy`]
/// load on first use, so that a command that never consults them does not pay for reading them.
#[derive(Default)]
pub struct Packs {
    directories: Vec<PathBuf>,
    loaded: OnceLock<Loaded>,
}

#[derive(Default)]
struct Loaded {
    packs: Vec<PackInfo>,
    signatures: Vec<rampage_signatures::SignatureDb>,
    peid: rampage_detect::SignatureDb,
    yara: Vec<rampage_yara::Rules>,
    capa: Vec<CapaRuleSet>,
}

impl Packs {
    /// Loads the packs in `directories`, in order; a directory given again (by any path) is loaded once, where it
    /// first appears. Problems are recorded in each pack's info, never returned.
    pub fn load(directories: &[PathBuf]) -> Self {
        let packs = Self::lazy(directories);
        packs.get();
        packs
    }

    /// The packs in `directories`, loaded as [`Packs::load`] does when first consulted.
    pub fn lazy(directories: &[PathBuf]) -> Self {
        Self { directories: directories.to_vec(), loaded: OnceLock::new() }
    }

    /// The packs in `directories`, then those [`PACKS_VARIABLE`] lists, loaded when first consulted.
    pub fn lazy_with_env(directories: &[PathBuf]) -> Self {
        let mut all = directories.to_vec();
        if let Some(value) = std::env::var_os(PACKS_VARIABLE) {
            all.extend(std::env::split_paths(&value).filter(|path| !path.as_os_str().is_empty()));
        }
        Self::lazy(&all)
    }

    /// Loads one pack on its own, reporting what loads and what does not.
    pub fn check(directory: &Path) -> PackInfo {
        Loaded::load(&[directory.to_owned()], PACK_BUDGET, TOTAL_BUDGET).packs.remove(0)
    }

    /// Whether any pack directory was given, loaded or not.
    pub fn configured(&self) -> bool {
        !self.directories.is_empty()
    }

    /// Whether the packs have been loaded, by [`Packs::load`] or by a first use.
    pub fn is_loaded(&self) -> bool {
        self.loaded.get().is_some()
    }

    fn get(&self) -> &Loaded {
        self.loaded.get_or_init(|| Loaded::load(&self.directories, PACK_BUDGET, TOTAL_BUDGET))
    }

    /// The loaded packs, in load order, without the built-in one.
    pub fn loaded(&self) -> &[PackInfo] {
        &self.get().packs
    }

    /// Every loaded pack, then the built-in one: the order in which they are applied, the first taking precedence.
    pub fn listing(&self) -> Vec<PackInfo> {
        self.loaded().iter().cloned().chain(std::iter::once(builtin())).collect()
    }

    /// One line for each rejected pack and each content that failed or is unsupported.
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        for pack in self.loaded() {
            let directory = pack.directory.as_deref().unwrap_or(Path::new("")).display();
            if let Some(error) = &pack.error {
                problems.push(format!("pack {directory}: {error}"));
            }
            for content in pack.contents.iter().filter(|content| content.status != ContentStatus::Loaded) {
                problems.push(format!("pack {directory}: {} {}: {}", content.kind, content.path, content.detail));
            }
        }
        problems
    }

    /// Signature databases for `arch`, in pack order.
    pub(crate) fn signatures_for(&self, arch: Arch) -> impl Iterator<Item = &rampage_signatures::SignatureDb> {
        self.get().signatures.iter().filter(move |database| database.arch() == arch)
    }

    pub(crate) fn peid(&self) -> &rampage_detect::SignatureDb {
        &self.get().peid
    }

    pub(crate) fn yara(&self) -> &[rampage_yara::Rules] {
        &self.get().yara
    }

    pub(crate) fn capa(&self) -> &[CapaRuleSet] {
        &self.get().capa
    }
}

impl Loaded {
    fn load(directories: &[PathBuf], pack: Budget, total: Budget) -> Self {
        let mut packs = Self::default();
        let mut names = HashSet::from([BUILTIN_PACK.to_owned()]);
        let mut seen = HashSet::new();
        let mut loading = Loading { pack, total, read: HashSet::new() };
        for directory in directories {
            if let Ok(canonical) = directory.canonicalize()
                && !seen.insert(canonical)
            {
                continue;
            }
            if packs.packs.len() >= MAX_PACKS {
                let error = Some(format!("more than {MAX_PACKS} packs are given; this one was not loaded"));
                let given = Some(directory.to_owned());
                packs.packs.push(PackInfo {
                    directory: given,
                    builtin: false,
                    manifest: None,
                    error,
                    contents: vec![],
                });
                continue;
            }
            loading.pack = pack;
            packs.add(directory, &mut names, &mut loading);
        }
        packs
    }

    fn add(&mut self, directory: &Path, names: &mut HashSet<String>, loading: &mut Loading) {
        let given = Some(directory.to_owned());
        let mut info = PackInfo { directory: given, builtin: false, manifest: None, error: None, contents: Vec::new() };
        match open_manifest(directory, names, loading) {
            Err(error) => info.error = Some(error),
            Ok((root, manifest)) => {
                for entry in &manifest.contents {
                    let (status, detail) = match self.load_content(&root, &manifest.name, entry, loading) {
                        Ok(detail) => (ContentStatus::Loaded, detail),
                        Err(problem) => problem,
                    };
                    let (kind, path, arch) = (entry.kind.label(), entry.path.clone(), entry.arch.clone());
                    info.contents.push(ContentInfo { kind, path, arch, status, detail });
                }
                info.manifest = Some(PackManifest {
                    name: manifest.name,
                    version: manifest.version,
                    license: manifest.license,
                    source: manifest.source,
                    description: manifest.description,
                });
            }
        }
        self.packs.push(info);
    }

    /// Loads one content, returning a summary of what it added, or its status and why it added nothing.
    fn load_content(
        &mut self,
        root: &Path,
        pack: &str,
        entry: &Entry,
        loading: &mut Loading,
    ) -> Result<String, (ContentStatus, String)> {
        let error = |text: String| (ContentStatus::Error, text);
        if entry.kind == Kind::Constants {
            return Err((
                ContentStatus::Unsupported,
                "constants packs are not supported in this version: the crypto-constant database takes no user \
                 data yet"
                    .to_owned(),
            ));
        }
        let path = contained(root, &entry.path).map_err(error)?;
        match entry.kind {
            Kind::Signatures => {
                let planned = loading.plan(path, MAX_SIGNATURE_DB_BYTES, "signature database").map_err(error)?;
                let text = read_planned(root, &planned, "signature database").map_err(error)?;
                let database = rampage_signatures::SignatureDb::from_json(&text)
                    .map_err(|problem| error(format!("invalid signature database: {problem}")))?;
                let declared = entry.arch.as_deref().map(str::parse::<Arch>).transpose().map_err(error)?;
                if let Some(declared) = declared
                    && declared != database.arch()
                {
                    return Err(error(format!("declared for {declared}, but the database is for {}", database.arch())));
                }
                let detail = format!(
                    "{} signatures and {} callee keys for {}",
                    database.len(),
                    database.callee_keys(),
                    database.arch()
                );
                self.signatures.push(database);
                Ok(detail)
            }
            Kind::Peid => {
                let planned = loading.plan(path, MAX_PEID_BYTES, "PeID database").map_err(error)?;
                let text = read_planned(root, &planned, "PeID database").map_err(error)?;
                let mut database = rampage_detect::SignatureDb::new();
                let skipped =
                    database.load_peid(&text).map_err(|problem| error(format!("PeID database: {problem}")))?;
                loading.keep_peid(database.signatures.len()).map_err(error)?;
                let mut detail = format!("{} PeID signatures", database.signatures.len());
                if !skipped.is_empty() {
                    let named: Vec<String> = skipped.iter().take(MAX_PEID_WARNINGS).map(ToString::to_string).collect();
                    detail.push_str(&format!("; {} entries or lines skipped: {}", skipped.len(), named.join("; ")));
                }
                self.peid.signatures.extend(database.signatures);
                Ok(detail)
            }
            Kind::Yara => {
                let files = rule_files(root, &path, &["yar", "yara"], false, loading).map_err(error)?;
                let sources = read_rule_files(root, files, "YARA rules", loading).map_err(error)?;
                let origins: Vec<(String, String)> =
                    sources.into_iter().map(|(file, text)| (file.display().to_string(), text)).collect();
                let rules = rampage_yara::compile_sources(Some(pack), &origins)
                    .map_err(|problem| error(format!("YARA rules: {problem}")))?;
                self.yara.push(rules);
                Ok(format!("{} YARA rule files", origins.len()))
            }
            Kind::Capa => {
                let files = rule_files(root, &path, &["yml", "yaml"], true, loading).map_err(error)?;
                let count = files.len();
                let sources = read_rule_files(root, files, "capa rule", loading).map_err(error)?;
                let rules = rampage_capabilities::load_capa_rule_texts(
                    sources.iter().map(|(file, text)| (file.as_path(), text.as_str())),
                )
                .map_err(|problem| error(format!("capa rules: {problem}")))?;
                let detail = format!("{} usable file-scope capa rules from {count} files", rules.len());
                self.capa.push(rules);
                Ok(detail)
            }
            Kind::Constants => unreachable!("handled above"),
        }
    }
}

/// What loading may still read and keep: bytes and files read, directories listed and PeID signatures kept. One
/// budget covers each pack, another every pack together; both are running totals, charged before anything is read
/// or kept.
#[derive(Debug, Clone, Copy)]
struct Budget {
    scope: &'static str,
    bytes: u64,
    files: usize,
    directories: usize,
    peid: usize,
}

const PACK_BUDGET: Budget =
    Budget { scope: "one pack", bytes: 512 * MIB, files: 10_000, directories: 4_096, peid: 100_000 };
const TOTAL_BUDGET: Budget =
    Budget { scope: "all packs together", bytes: 1024 * MIB, files: 50_000, directories: 16_384, peid: 100_000 };

/// Identifies a file however it was reached, so that one file is read once.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FileKey {
    #[cfg(unix)]
    Inode(u64, u64),
    #[cfg(not(unix))]
    Path(PathBuf),
}

fn file_key(_path: &Path, metadata: &std::fs::Metadata) -> FileKey {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        FileKey::Inode(metadata.dev(), metadata.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        FileKey::Path(_path.to_owned())
    }
}

/// A pack file checked and paid for, not yet read.
struct Planned {
    path: PathBuf,
    length: u64,
    key: FileKey,
}

/// The running budgets of one load and the files it has read.
struct Loading {
    pack: Budget,
    total: Budget,
    read: HashSet<FileKey>,
}

impl Loading {
    /// Checks that the canonical `path` is a regular file of at most `max` bytes not read before, and charges it to
    /// both budgets.
    fn plan(&mut self, path: PathBuf, max: u64, what: &str) -> Result<Planned, String> {
        let invalid = |reason: String| format!("cannot read {what} {}: {reason}", path.display());
        let metadata = std::fs::metadata(&path).map_err(|error| invalid(error.to_string()))?;
        if !metadata.is_file() {
            return Err(invalid("not a regular file".to_owned()));
        }
        if metadata.len() > max {
            return Err(invalid(format!("larger than {}", size_label(max))));
        }
        let key = file_key(&path, &metadata);
        if self.read.contains(&key) {
            return Err(format!("{} was already read: each file loads once", path.display()));
        }
        for budget in [&self.pack, &self.total] {
            if budget.files == 0 || metadata.len() > budget.bytes {
                return Err(format!("reading {} would exceed the read budget of {}", path.display(), budget.scope));
            }
        }
        for budget in [&mut self.pack, &mut self.total] {
            budget.files -= 1;
            budget.bytes -= metadata.len();
        }
        self.read.insert(key.clone());
        Ok(Planned { path, length: metadata.len(), key })
    }

    /// Charges listing one directory to both budgets.
    fn keep_peid(&mut self, signatures: usize) -> Result<(), String> {
        for budget in [&self.pack, &self.total] {
            if signatures > budget.peid {
                return Err(format!(
                    "keeping {signatures} PeID signatures would exceed the budget of {}",
                    budget.scope
                ));
            }
        }
        for budget in [&mut self.pack, &mut self.total] {
            budget.peid -= signatures;
        }
        Ok(())
    }

    fn list(&mut self, directory: &Path) -> Result<(), String> {
        for budget in [&self.pack, &self.total] {
            if budget.directories == 0 {
                let path = directory.display();
                return Err(format!("listing {path} would exceed the directory budget of {}", budget.scope));
            }
        }
        for budget in [&mut self.pack, &mut self.total] {
            budget.directories -= 1;
        }
        Ok(())
    }
}

/// The canonical pack directory and its validated manifest.
fn open_manifest(
    directory: &Path,
    names: &mut HashSet<String>,
    loading: &mut Loading,
) -> Result<(PathBuf, Manifest), String> {
    let root = directory.canonicalize().map_err(|error| format!("cannot open pack directory: {error}"))?;
    if !root.is_dir() {
        return Err("not a directory".to_owned());
    }
    let planned = loading.plan(contained(&root, MANIFEST_FILE)?, MAX_PACK_MANIFEST_BYTES, "pack manifest")?;
    let text = read_planned(&root, &planned, "pack manifest")?;
    let manifest: Manifest = toml::from_str(&text).map_err(|error| format!("invalid {MANIFEST_FILE}: {error}"))?;
    validate(&manifest)?;
    if manifest.name == USER_RULES_NAMESPACE {
        return Err(format!(
            "the pack name {USER_RULES_NAMESPACE:?} is reserved: user YARA rules match in that namespace"
        ));
    }
    if !names.insert(manifest.name.clone()) {
        return Err(format!("the pack name {:?} is already taken", manifest.name));
    }
    Ok((root, manifest))
}

fn validate(manifest: &Manifest) -> Result<(), String> {
    let field = |name: &str, value: &str, max: usize, allowed: &dyn Fn(char) -> bool| {
        if value.trim().is_empty() {
            return Err(format!("`{name}` is empty"));
        }
        if value.chars().count() > max {
            return Err(format!("`{name}` is longer than {max} characters"));
        }
        if let Some(bad) = value.chars().find(|&c| !allowed(c)) {
            return Err(format!("`{name}` contains {bad:?}"));
        }
        Ok(())
    };
    let identifier = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    field("name", &manifest.name, MAX_NAME_CHARS, &identifier)?;
    field("version", &manifest.version, MAX_NAME_CHARS, &|c| identifier(c) || c == '+')?;
    // SPDX expressions: identifiers joined by AND, OR and WITH, grouped with parentheses.
    let spdx = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '+' | ':' | '(' | ')' | ' ');
    field("license", &manifest.license, MAX_LICENSE_CHARS, &spdx)?;
    field("source", &manifest.source, MAX_SOURCE_CHARS, &|c| !c.is_control())?;
    field("description", &manifest.description, MAX_DESCRIPTION_CHARS, &|c| !c.is_control() || c == '\n')?;
    if manifest.contents.is_empty() {
        return Err("`contents` is empty".to_owned());
    }
    if manifest.contents.len() > MAX_CONTENTS {
        return Err(format!("more than {MAX_CONTENTS} contents"));
    }
    for entry in &manifest.contents {
        let path = Path::new(&entry.path);
        if entry.path.is_empty() || !path.components().all(|component| matches!(component, Component::Normal(_))) {
            return Err(format!(
                "content path {:?} must be relative and inside the pack, without `.`, `..` or a root",
                entry.path
            ));
        }
        match (&entry.arch, entry.kind) {
            (Some(arch), Kind::Signatures) => {
                arch.parse::<Arch>().map_err(|error| format!("content {:?}: {error}", entry.path))?;
            }
            (Some(_), kind) => {
                let kind = kind.label();
                return Err(format!("content {:?}: `arch` applies only to signatures, not {kind}", entry.path));
            }
            (None, _) => {}
        }
    }
    Ok(())
}

/// The canonical path of `relative` under the canonical `root`, refusing one that resolves outside it (through a
/// symbolic link, say). Open it with [`open_contained`], which makes sure the file opened is the one checked.
fn contained(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let path = root.join(relative).canonicalize().map_err(|error| format!("cannot open {relative}: {error}"))?;
    if !path.starts_with(root) {
        return Err(format!("{relative} resolves outside the pack directory"));
    }
    Ok(path)
}

/// Opens `target`, a canonical path [`contained`] checked, as a regular file. On Unix every component is opened
/// from `root` without following symbolic links, so a link swapped in after the check fails instead of leading out
/// of the pack, and a FIFO is opened without blocking.
fn open_contained(root: &Path, target: &Path) -> Result<File, String> {
    let failure = |error: std::io::Error| format!("cannot open {}: {error}", target.display());
    let outside = || format!("{} is outside the pack directory", target.display());
    let relative = target.strip_prefix(root).map_err(|_| outside())?;
    let file = open_beneath(root, relative).map_err(failure)?;
    if !file.metadata().map_err(failure)?.is_file() {
        return Err(format!("{} is not a regular file", target.display()));
    }
    Ok(file)
}

#[cfg(unix)]
fn open_beneath(root: &Path, relative: &Path) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags, open, openat};
    let directory = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let file = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let mut at = open(root, directory, Mode::empty())?;
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(std::io::Error::other("not a plain relative path"));
        };
        let flags = if components.peek().is_some() { directory } else { file };
        at = openat(&at, name, flags, Mode::empty())?;
    }
    Ok(File::from(at))
}

#[cfg(not(unix))]
fn open_beneath(root: &Path, relative: &Path) -> std::io::Result<File> {
    File::open(root.join(relative))
}

/// Reads a planned file through [`open_contained`], refusing one replaced or grown since it was planned.
fn read_planned(root: &Path, planned: &Planned, what: &str) -> Result<String, String> {
    let file = open_contained(root, &planned.path)?;
    let metadata = file.metadata().map_err(|error| format!("cannot read {}: {error}", planned.path.display()))?;
    if file_key(&planned.path, &metadata) != planned.key {
        return Err(format!("{} changed while the pack was loading", planned.path.display()));
    }
    read_open_bounded(file, &planned.path, planned.length, what).map_err(|error| error.to_string())
}

/// The rule files a content names: the file itself, or the files with one of `extensions` in the directory (and,
/// when `recursive`, its subdirectories), sorted, each as the canonical path checked to be inside the pack and once
/// however many links name it. Symbolic links to files are taken only when they stay inside the pack; linked
/// directories are not followed, which also rules out cycles. Every directory listed is charged to `loading`.
fn rule_files(
    root: &Path,
    path: &Path,
    extensions: &[&str],
    recursive: bool,
    loading: &mut Loading,
) -> Result<Vec<PathBuf>, String> {
    if path.is_file() {
        return Ok(vec![path.to_owned()]);
    }
    if !path.is_dir() {
        return Err(format!("{} is neither a regular file nor a directory", path.display()));
    }
    let wanted = |file: &Path| {
        let extension = file.extension().and_then(|extension| extension.to_str()).unwrap_or("");
        extensions.iter().any(|wanted| extension.eq_ignore_ascii_case(wanted))
    };
    let failure = |at: &Path, error: std::io::Error| format!("cannot read {}: {error}", at.display());
    let mut files = Vec::new();
    let mut pending = vec![(path.to_owned(), 0)];
    while let Some((directory, depth)) = pending.pop() {
        loading.list(&directory)?;
        for entry in std::fs::read_dir(&directory).map_err(|error| failure(&directory, error))? {
            let entry = entry.map_err(|error| failure(&directory, error))?;
            let file = entry.path();
            let file_type = entry.file_type().map_err(|error| failure(&file, error))?;
            if file_type.is_dir() {
                if recursive {
                    if depth >= MAX_RULE_DEPTH {
                        return Err(format!("rule directories nest deeper than {MAX_RULE_DEPTH} levels"));
                    }
                    pending.push((file, depth + 1));
                }
            } else if wanted(&file) && (file_type.is_file() || file_type.is_symlink()) {
                let target = file.canonicalize().map_err(|error| failure(&file, error))?;
                if !target.starts_with(root) {
                    return Err(format!("{} links outside the pack directory", file.display()));
                }
                if !target.is_file() {
                    continue;
                }
                if files.len() >= MAX_RULE_FILES {
                    return Err(format!("more than {MAX_RULE_FILES} rule files"));
                }
                files.push(target);
            }
        }
    }
    if files.is_empty() {
        let names: Vec<String> = extensions.iter().map(|extension| format!(".{extension}")).collect();
        return Err(format!("no {} files in {}", names.join("/"), path.display()));
    }
    files.sort();
    files.dedup();
    Ok(files)
}

/// Reads `files` once all of them are planned, so that a content over budget is refused before any is read.
fn read_rule_files(
    root: &Path,
    files: Vec<PathBuf>,
    what: &str,
    loading: &mut Loading,
) -> Result<Vec<(PathBuf, String)>, String> {
    let planned: Vec<Planned> =
        files.into_iter().map(|file| loading.plan(file, MAX_RULE_FILE_BYTES, what)).collect::<Result<_, _>>()?;
    planned.into_iter().map(|file| Ok((file.path.clone(), read_planned(root, &file, what)?))).collect()
}

/// The databases bundled in rampage, described as a pack.
fn builtin() -> PackInfo {
    let loaded = |kind, path: String, arch: Option<String>, detail| ContentInfo {
        kind,
        path,
        arch,
        status: ContentStatus::Loaded,
        detail,
    };
    let mut contents: Vec<ContentInfo> = Arch::ALL
        .into_iter()
        .filter_map(|arch| {
            let database = rampage_signatures::bundled(arch)?;
            let detail = format!("{} musl libc signatures and {} callee keys", database.len(), database.callee_keys());
            Some(loaded("signatures", format!("bundled:musl-{arch}.json"), Some(arch.to_string()), detail))
        })
        .collect();
    let tools = rampage_detect::SignatureDb::bundled().signatures.len();
    let detail = format!("{tools} producing-tool signatures (packers, compilers, protectors, installers, linkers)");
    contents.push(loaded("detect", "bundled:tools".to_owned(), None, detail));
    let constants = rampage_constants::ConstantDb::bundled().signatures().len();
    contents.push(loaded("constants", "bundled:crypto".to_owned(), None, format!("{constants} crypto constants")));
    PackInfo {
        directory: None,
        builtin: true,
        manifest: Some(PackManifest {
            name: BUILTIN_PACK.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            license: "Apache-2.0".to_owned(),
            source: "bundled with rampage: tool and constant signatures authored from public knowledge; function \
                     signatures generated from a static musl libc build by tools/gen-signatures.sh"
                .to_owned(),
            description: "Starter databases for identify, detect and find_crypto; always applied after user packs."
                .to_owned(),
        }),
        error: None,
        contents,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A canonical temporary directory removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("rampage-packs-unit-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }

        fn write(&self, relative: &str, contents: &str) {
            let path = self.0.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }

        /// A pack named `name` with one content of `kind` at `path`.
        fn pack(name: &str, kind: &str, path: &str) -> Self {
            let pack = Self::new(name);
            pack.write(
                MANIFEST_FILE,
                &format!(
                    "name = \"{name}\"\nversion = \"1\"\nlicense = \"MIT\"\nsource = \"test\"\ndescription = \"test\"\n\
                     [[contents]]\nkind = \"{kind}\"\npath = \"{path}\"\n"
                ),
            );
            pack
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const PEID: &str = "[Unit DOS Header]\nsignature = 4D 5A\nep_only = false\n";

    impl Packs {
        fn within(directories: &[PathBuf], pack: Budget, total: Budget) -> Self {
            let loaded = OnceLock::from(Loaded::load(directories, pack, total));
            Self { directories: directories.to_vec(), loaded }
        }
    }

    fn detail(packs: &Packs, pack: usize) -> (ContentStatus, &str) {
        let content = &packs.loaded()[pack].contents[0];
        (content.status, content.detail.as_str())
    }

    #[test]
    fn a_link_swapped_in_after_the_check_is_not_followed() {
        let outside = Scratch::new("swap-outside");
        outside.write("rules/a.yar", "outside");
        outside.write("b.yar", "outside");
        let pack = Scratch::new("swap");
        pack.write("rules/a.yar", "inside");
        pack.write("b.yar", "inside");

        let nested = contained(&pack.0, "rules/a.yar").unwrap();
        let file = contained(&pack.0, "b.yar").unwrap();
        assert!(open_contained(&pack.0, &nested).is_ok());
        // Between the check and the open, a directory and a file become links out of the pack.
        std::fs::rename(pack.0.join("rules"), pack.0.join("moved")).unwrap();
        std::os::unix::fs::symlink(outside.0.join("rules"), pack.0.join("rules")).unwrap();
        std::fs::remove_file(pack.0.join("b.yar")).unwrap();
        std::os::unix::fs::symlink(outside.0.join("b.yar"), pack.0.join("b.yar")).unwrap();
        assert!(open_contained(&pack.0, &nested).is_err());
        assert!(open_contained(&pack.0, &file).is_err());
    }

    #[test]
    fn a_file_replaced_after_planning_is_not_read() {
        let pack = Scratch::new("replaced");
        pack.write("b.yar", "first");
        let mut loading = Loading { pack: PACK_BUDGET, total: TOTAL_BUDGET, read: HashSet::new() };
        let planned = loading.plan(contained(&pack.0, "b.yar").unwrap(), 64, "rule").unwrap();
        std::fs::remove_file(pack.0.join("b.yar")).unwrap();
        pack.write("b.yar", "a longer replacement");
        let error = read_planned(&pack.0, &planned, "rule").unwrap_err();
        assert!(error.contains("changed while the pack was loading") || error.contains("larger than"), "{error}");
    }

    #[test]
    fn rule_files_are_the_checked_link_targets_once_each() {
        let pack = Scratch::new("targets");
        pack.write("rules/real.yar", "rule");
        std::os::unix::fs::symlink(pack.0.join("rules/real.yar"), pack.0.join("rules/alias.yar")).unwrap();
        let mut loading = Loading { pack: PACK_BUDGET, total: TOTAL_BUDGET, read: HashSet::new() };
        let files = rule_files(&pack.0, &pack.0.join("rules"), &["yar"], false, &mut loading).unwrap();
        assert_eq!(files, [pack.0.join("rules/real.yar")]);
    }

    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let pack = Scratch::new("fifo");
        let fifo = pack.0.join("rules.yar");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        let error = open_contained(&pack.0, &fifo).unwrap_err();
        assert!(error.contains("not a regular file"), "{error}");
    }

    #[test]
    fn directories_listed_are_charged_to_the_budget() {
        let pack = Scratch::pack("deep", "capa", "rules");
        for nested in ["rules/a/b/c", "rules/d", "rules/e"] {
            std::fs::create_dir_all(pack.0.join(nested)).unwrap();
        }
        pack.write("rules/rule.yml", "rule: {}");
        let budget = Budget { directories: 4, ..PACK_BUDGET };
        let packs = Packs::within(std::slice::from_ref(&pack.0), budget, TOTAL_BUDGET);
        let (status, text) = detail(&packs, 0);
        assert_eq!(status, ContentStatus::Error);
        assert!(text.contains("directory budget of one pack"), "{text}");
    }

    #[test]
    fn the_budget_of_all_packs_is_a_running_total() {
        let first = Scratch::pack("first", "peid", "userdb.txt");
        let second = Scratch::pack("second", "peid", "userdb.txt");
        for pack in [&first, &second] {
            pack.write("userdb.txt", PEID);
        }
        let manifest = std::fs::metadata(first.0.join(MANIFEST_FILE)).unwrap().len();
        let one_pack = manifest + PEID.len() as u64;
        let total = Budget { bytes: one_pack * 2 - 1, ..TOTAL_BUDGET };
        let directories = [first.0.clone(), second.0.clone()];
        let packs = Packs::within(&directories, PACK_BUDGET, total);
        assert_eq!(detail(&packs, 0).0, ContentStatus::Loaded);
        let (status, text) = detail(&packs, 1);
        assert_eq!(status, ContentStatus::Error);
        assert!(text.contains("read budget of all packs together"), "{text}");

        let files = Budget { files: 3, ..TOTAL_BUDGET };
        let packs = Packs::within(&directories, PACK_BUDGET, files);
        assert!(packs.loaded()[1].contents[0].detail.contains("all packs together"), "{:?}", packs.loaded());

        let peid = Budget { peid: 1, ..TOTAL_BUDGET };
        let packs = Packs::within(&directories, PACK_BUDGET, peid);
        assert_eq!(detail(&packs, 0).0, ContentStatus::Loaded);
        let (status, text) = detail(&packs, 1);
        assert_eq!(status, ContentStatus::Error);
        assert!(text.contains("PeID signatures would exceed the budget of all packs together"), "{text}");
        assert_eq!(packs.peid().signatures.len(), 1);
    }
}
