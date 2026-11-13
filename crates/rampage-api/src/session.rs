use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rampage_analysis::capture_identity::capture_identity;
use rampage_arch::Arch;
use rampage_loaders::{Binary, Format, ImageAt};
use sha2::{Digest, Sha256};

use crate::annotations::Annotations;
use crate::{ApiError, Packs, Project};

type SourceAdmission<'a> = &'a mut dyn FnMut(&[u8]) -> Result<(), ApiError>;

/// Loaded binaries, with snapshots revalidated on each open to notice changed mappings or capture metadata, and
/// ordinary binaries reloaded when their file's length, modification time or inode changes.
///
/// Binaries are memory-mapped, so replace one by writing the new file elsewhere and renaming it over the old: a
/// rewrite in place that truncates the file can crash (SIGBUS) a call still reading the old mapping. Annotations
/// made on the old binary stay in its log and apply to the new one by address, with a warning when the image differs
/// (see [`Annotations::warnings`]).
#[derive(Default)]
pub struct Session {
    state: Mutex<State>,
    capture_annotations: Option<PathBuf>,
    packs: Arc<Packs>,
    /// The worker every project must decompile in, chosen with [`Session::requiring_decompiler_worker`].
    required_worker: Option<PathBuf>,
    /// The persistent analysis store chosen with [`Session::with_analysis_store`]; `None` keeps each project's
    /// [`crate::AnalysisStore::from_env`] default.
    analysis_store: Option<Option<Arc<crate::AnalysisStore>>>,
}

#[derive(Default)]
struct State {
    /// Projects by canonical path, embedded image location and the architecture of the slice loaded.
    projects: HashMap<(PathBuf, Option<ImageAt>, Arch), Arc<Project>>,
    /// The slice each path and image location opens when no architecture is asked for.
    defaults: HashMap<(PathBuf, Option<ImageAt>), Arch>,
    /// Paths once used for captures remain revalidated even after an ordinary binary replaces them.
    capture_paths: HashSet<PathBuf>,
    /// Freeze hashes for ordinary replacements; their memory maps may reflect later in-place file writes.
    ordinary_sources: HashMap<(PathBuf, Option<ImageAt>, Arch), [u8; 32]>,
    /// The file each ordinary project was loaded from, to notice it being rewritten or replaced while cached.
    stamps: HashMap<(PathBuf, Option<ImageAt>, Arch), FileStamp>,
    /// Raw projects by canonical path and raw interpretation SHA-256, least recently used first.
    raw: Vec<((PathBuf, String), Arc<Project>)>,
}

/// Raw interpretations retained per session; the least recently used is evicted beyond this.
pub const MAX_RAW_PROJECTS: usize = 32;
/// The retained Raw projects' input bytes together, so 4 MiB Cortex-M images cannot pin 128 MiB at once; the least
/// recently used are evicted first, and the newest project is always kept.
pub const MAX_RAW_PROJECT_BYTES: usize = 64 * 1024 * 1024;

/// A cheap stand-in for a file's contents: its length, modification time and, on Unix, device and inode. A rewrite
/// that keeps all of them (same length, within the file system's timestamp granularity) goes unnoticed.
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    length: u64,
    modified: Option<std::time::SystemTime>,
    inode: Option<(u64, u64)>,
}

fn file_stamp(path: &Path) -> Option<FileStamp> {
    let metadata = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        Some((metadata.dev(), metadata.ino()))
    };
    #[cfg(not(unix))]
    let inode = None;
    Some(FileStamp { length: metadata.len(), modified: metadata.modified().ok(), inode })
}

impl Session {
    /// Shares identity-scoped snapshot annotation logs in an explicitly selected, existing directory.
    /// Without this option, snapshots share logs only with captures in the same canonical directory.
    /// Ordinary binaries still use their existing per-path, per-slice sidecars.
    pub fn with_capture_annotations(directory: PathBuf) -> Self {
        Self { capture_annotations: Some(directory), ..Self::default() }
    }

    /// Layers `packs` over the bundled heuristic databases of every project this session opens.
    pub fn with_packs(self, packs: Arc<Packs>) -> Self {
        Self { packs, ..self }
    }

    /// Decompiles every project of this session in the supervised worker at `executable`, never in-process. A
    /// worker that later goes missing or fails makes decompilation fail; nothing falls back to in-process.
    pub fn requiring_decompiler_worker(self, executable: PathBuf) -> Self {
        Self { required_worker: Some(executable), ..self }
    }

    /// Analyses every project this session opens through `store` (`None` disables the persistent store),
    /// instead of the [`crate::AnalysisStore::from_env`] default.
    pub fn with_analysis_store(self, store: Option<Arc<crate::AnalysisStore>>) -> Self {
        Self { analysis_store: Some(store), ..self }
    }

    fn configure(&self, project: &Project) {
        if let Some(store) = &self.analysis_store {
            project.set_analysis_store(store.clone());
        }
    }

    /// The worker chosen with [`Session::requiring_decompiler_worker`], if any.
    pub fn required_decompiler_worker(&self) -> Option<&Path> {
        self.required_worker.as_deref()
    }

    /// The worker a project opened now decompiles in: the required one, else [`find_decompiler_worker`]'s. `None`
    /// means native decompilation runs in-process.
    fn decompiler_worker(&self) -> Option<PathBuf> {
        self.required_worker.clone().or_else(find_decompiler_worker)
    }

    /// The data packs every project of this session uses.
    pub fn packs(&self) -> Arc<Packs> {
        Arc::clone(&self.packs)
    }

    /// The directory chosen with [`Session::with_capture_annotations`], if any.
    pub fn capture_annotations(&self) -> Option<&Path> {
        self.capture_annotations.as_deref()
    }

    /// A session with this one's settings (snapshot annotation directory, packs, required worker) and none of its
    /// projects, for changing a setting of a session that is shared and so cannot be taken apart.
    pub fn unloaded_copy(&self) -> Self {
        Self {
            capture_annotations: self.capture_annotations.clone(),
            packs: self.packs(),
            required_worker: self.required_worker.clone(),
            analysis_store: self.analysis_store.clone(),
            ..Self::default()
        }
    }

    pub fn open(&self, path: &Path, arch: Option<Arch>) -> Result<Arc<Project>, ApiError> {
        self.open_at(path, arch, None)
    }

    /// Opens the binary at `path`, or with an `image` location, the executable embedded there (see
    /// [`Binary::open_at`]). An embedded image is a project of its own, with its own annotation sidecar; a location
    /// that [is the whole file](ImageAt::is_whole_file) is the project [`Session::open`] gives.
    pub fn open_at(&self, path: &Path, arch: Option<Arch>, image: Option<ImageAt>) -> Result<Arc<Project>, ApiError> {
        self.open_at_policy(path, arch, image, false, None)
    }

    /// Workspace restores never reuse ordinary cached projects or resolve a directory as a container.
    pub(crate) fn open_workspace_at(
        &self,
        path: &Path,
        arch: Option<Arch>,
        image: Option<ImageAt>,
    ) -> Result<Arc<Project>, ApiError> {
        self.open_at_policy(path, arch, image, true, None)
    }

    /// Fresh checked annotations plus admission on the actual original mapping before native parsing.
    /// Keeping this separate leaves the existing workspace loader's 128 MiB policy unchanged.
    pub(crate) fn open_plugin_triage_at(
        &self,
        path: &Path,
        arch: Option<Arch>,
        image: Option<ImageAt>,
        admit: &mut dyn FnMut(&[u8]) -> Result<(), ApiError>,
    ) -> Result<Arc<Project>, ApiError> {
        self.unloaded_copy().open_at_policy(path, arch, image, true, Some(admit))
    }

    /// Opens the Raw interpretation `request` asserts over a range of the regular file at `path`. Projects are
    /// cached by canonical path and the raw interpretation identity (bytes, profile, mapping, entry and seeds), so
    /// changed bytes or seeds give a fresh project while the same interpretation keeps its memory-only annotations.
    /// No sidecar or annotation log is read or written.
    pub fn open_raw(&self, path: &Path, request: &crate::RawProjectRequest) -> Result<Arc<Project>, ApiError> {
        let binary = crate::raw_project::open_raw_binary(path, request)?;
        let identity = binary
            .raw_interpretation_identity()
            .map_err(|source| ApiError::Load { path: path.to_owned(), source })?
            .ok_or_else(|| ApiError::Invalid("Raw admission produced no interpretation identity".to_owned()))?;
        let canonical = path.canonicalize().map_err(|source| ApiError::Load {
            path: path.to_owned(),
            source: rampage_loaders::LoadError::Io { path: path.to_owned(), source },
        })?;
        let key = (canonical, identity.sha256);
        let project = {
            let mut state = self.state.lock().expect("session lock");
            if let Some(index) = state.raw.iter().position(|(cached, _)| *cached == key) {
                let entry = state.raw.remove(index);
                let project = Arc::clone(&entry.1);
                state.raw.push(entry);
                project
            } else {
                let project = Project::new(binary);
                project.set_packs(Arc::clone(&self.packs));
                self.configure(&project);
                if let Some(executable) = self.decompiler_worker() {
                    project.set_decompiler_worker(Some(crate::DecompilerWorkerConfig {
                        executable: Some(executable),
                        ..Default::default()
                    }));
                }
                let project = Arc::new(project);
                state.raw.push((key, Arc::clone(&project)));
                let bytes = |raw: &[(_, Arc<Project>)]| -> usize {
                    raw.iter().map(|(_, project)| project.binary.image_bytes().len()).sum()
                };
                while state.raw.len() > MAX_RAW_PROJECTS
                    || (state.raw.len() > 1 && bytes(&state.raw) > MAX_RAW_PROJECT_BYTES)
                {
                    state.raw.remove(0);
                }
                project
            }
        };
        project.effective_snapshot()
    }

    fn open_at_policy(
        &self,
        path: &Path,
        arch: Option<Arch>,
        image: Option<ImageAt>,
        checked: bool,
        admission: Option<SourceAdmission<'_>>,
    ) -> Result<Arc<Project>, ApiError> {
        let image = image.filter(|image| !image.is_whole_file());
        let held_source = checked.then(|| crate::project_workspace::open_source(path)).transpose()?;
        let executable = if checked {
            path.to_owned()
        } else {
            rampage_loaders::container::resolve_executable(path)
                .map_err(|source| ApiError::Load { path: path.to_owned(), source })?
        };
        let path = executable.as_path();
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_owned());
        // Taken before loading, so a write racing the load leaves a stamp the next open finds stale.
        let stamp = file_stamp(path);
        let cached = {
            let state = self.state.lock().expect("session lock");
            let loaded = arch.or_else(|| state.defaults.get(&(canonical.clone(), image)).copied());
            let key = loaded.map(|arch| (canonical.clone(), image, arch));
            if !checked
                && let Some(key) = key
                && let Some(project) = state.projects.get(&key)
                && project.binary.format != Format::Snapshot
                && !state.capture_paths.contains(&canonical)
                && stamp.is_some()
                && state.stamps.get(&key) == stamp.as_ref()
            {
                Some(Arc::clone(project))
            } else {
                None
            }
        };
        if let Some(project) = cached
            && can_reuse_ordinary_input(path)?
        {
            return project.effective_snapshot();
        }
        let mut binary = match admission {
            Some(admit) => {
                let mut rejected = None;
                let binary = Binary::open_image_checked_admitted(
                    path,
                    image,
                    arch,
                    crate::plugin_triage::MAX_PLUGIN_TRIAGE_SOURCE_BYTES,
                    |bytes| {
                        admit(bytes).map_err(|error| {
                            rejected = Some(error);
                            rampage_loaders::LoadError::Unsupported("source profile admission rejected".into())
                        })
                    },
                );
                if let Some(error) = rejected {
                    return Err(error);
                }
                binary
            }
            None if checked => Binary::open_image_checked(path, image, arch),
            None => Binary::open_image(path, image, arch),
        }
        .map_err(|source| ApiError::Load { path: path.to_owned(), source })?;
        let legacy = annotation_path(path, image, &binary);
        let log = if binary.format == Format::Snapshot {
            self.state.lock().expect("session lock").capture_paths.insert(canonical.clone());
            let identity = capture_identity(&binary)
                .ok_or_else(|| ApiError::Invalid("cannot derive validated snapshot capture identity".to_owned()))?;
            if let Some(directory) = &self.capture_annotations {
                let metadata = std::fs::metadata(directory).map_err(|error| {
                    ApiError::Invalid(format!("snapshot annotation directory {}: {error}", directory.display()))
                })?;
                if !metadata.is_dir() {
                    return Err(ApiError::Invalid(format!(
                        "snapshot annotation directory {} is not a directory",
                        directory.display()
                    )));
                }
            }
            let directory = self
                .capture_annotations
                .as_deref()
                .unwrap_or_else(|| canonical.parent().unwrap_or_else(|| Path::new(".")));
            // A distinct suffix keeps capture logs outside the namespace of ordinary binary sidecars.
            let log = directory.join(format!(".{}-{}.jsonl", identity.schema, identity.sha256));
            if std::fs::symlink_metadata(&legacy).is_ok() {
                binary.warnings.push(format!(
                    "legacy snapshot annotations at {} were not loaded: no capture identity; \
                     identity-scoped annotations use {}",
                    legacy.display(),
                    log.display()
                ));
            }
            log
        } else {
            if let Some(image) = image.filter(|image| image.length().is_none()) {
                warn_of_unsuffixed_image_sidecar(path, image, &mut binary, &legacy);
            }
            legacy
        };
        // Snapshots share identity-scoped logs across captures whose bytes differ, so only ordinary images are named.
        let digest = (binary.format != Format::Snapshot).then(|| Sha256::digest(binary.image_bytes()).into());
        let annotations = if checked {
            Annotations::open_for_image_checked(log, digest)
        } else {
            Annotations::open_for_image(log, digest)
        }
        .map_err(ApiError::Invalid)?;
        binary.warnings.extend(annotations.warnings());
        if let Some(source) = &held_source {
            crate::project_workspace::validate_source_file(path, source)?;
            binary.validate_available_backing_source().map_err(|error| ApiError::Invalid(error.to_string()))?;
        }

        let mut state = self.state.lock().expect("session lock");
        if arch.is_none() {
            state.defaults.insert((canonical.clone(), image), binary.arch);
        }
        let revalidate = state.capture_paths.contains(&canonical);
        let key = (canonical, image, binary.arch);
        // A project this open replaces hands its undo history on: same log, same edits to undo.
        let previous = state.projects.get(&key).cloned();
        let ordinary_source: Option<[u8; 32]> =
            (revalidate && binary.format != Format::Snapshot).then(|| Sha256::digest(binary.file_bytes()).into());
        if !checked
            && let Some(project) = state.projects.get(&key)
            && project.binary.format == binary.format
            && project.binary.warnings == binary.warnings
            && (binary.format == Format::Snapshot && project.binary.file_bytes() == binary.file_bytes()
                || ordinary_source.is_some_and(|source| state.ordinary_sources.get(&key) == Some(&source)))
        {
            return project.effective_snapshot();
        }
        // Identity excludes provenance and registers, so projects stay path-specific and compare the full source.
        if revalidate {
            state.projects.remove(&key);
            state.ordinary_sources.remove(&key);
        }
        if let Some(source) = ordinary_source {
            state.ordinary_sources.insert(key.clone(), source);
        }
        if !revalidate && binary.format != Format::Snapshot {
            if stamp.is_none() || state.stamps.get(&key) != stamp.as_ref() {
                state.projects.remove(&key);
            }
            match stamp {
                Some(stamp) => state.stamps.insert(key.clone(), stamp),
                None => state.stamps.remove(&key),
            };
        }
        let worker = self.decompiler_worker();
        if checked {
            state.projects.remove(&key);
        }
        let project = state.projects.entry(key).or_insert_with(|| {
            let mut annotations = annotations;
            if let Some(previous) = previous {
                annotations.inherit_history(&previous.annotations.read().expect("annotations lock"));
            }
            let project = Project::with_annotations(binary, annotations);
            project.set_packs(Arc::clone(&self.packs));
            self.configure(&project);
            if let Some(executable) = worker {
                project.set_decompiler_worker(Some(crate::DecompilerWorkerConfig {
                    executable: Some(executable),
                    ..Default::default()
                }));
            }
            Arc::new(project)
        });
        project.effective_snapshot()
    }
}

/// The supervised decompiler worker: `RAMPAGE_WORKER` when set, else a `rampage-worker` file beside the running
/// executable. `None` means decompilation runs in-process, in the same process as the parsing of the binary.
pub fn find_decompiler_worker() -> Option<PathBuf> {
    std::env::var_os("RAMPAGE_WORKER").map(PathBuf::from).or_else(|| {
        let sibling = std::env::current_exe().ok()?.with_file_name("rampage-worker");
        sibling.is_file().then_some(sibling)
    })
}

fn can_reuse_ordinary_input(path: &Path) -> Result<bool, ApiError> {
    let error = |source| ApiError::Load {
        path: path.to_owned(),
        source: rampage_loaders::LoadError::Io { path: path.to_owned(), source },
    };
    let mut reader = BufReader::new(File::open(path).map_err(error)?);
    loop {
        let bytes = reader.fill_buf().map_err(error)?;
        if let Some(byte) = bytes.iter().find(|byte| !byte.is_ascii_whitespace()) {
            // Match the loader's snapshot recognition before reusing an ordinary binary at this path.
            return Ok(*byte != b'{');
        }
        let length = bytes.len();
        if length == 0 {
            return Ok(false);
        }
        reader.consume(length);
    }
}

/// `<file>.rampage`, with `.<arch>` for one slice of a universal binary. An embedded image's sidecar is
/// `<file>@0x<offset>[+0x<length>][.<arch>].rampage-image`: no plain file's sidecar ends that way, and neither the
/// location nor the architecture can contain the `@` that separates them from the file name.
pub(crate) fn annotation_path(path: &Path, image: Option<ImageAt>, binary: &Binary) -> PathBuf {
    let mut log = path.as_os_str().to_owned();
    if let Some(image) = image {
        log.push(format!("@{:#x}", image.offset()));
        if let Some(length) = image.length() {
            log.push(format!("+{length:#x}"));
        }
    }
    if binary.slices.len() > 1 {
        log.push(format!(".{}", binary.arch));
    }
    log.push(if image.is_some() { ".rampage-image" } else { ".rampage" });
    PathBuf::from(log)
}

/// Embedded images once used `<file>@0x<offset>[.<arch>].rampage`, which is also the sidecar of a file named
/// `<file>@0x<offset>`. Such a log is left alone; when no file of that name exists, it likely holds this image's
/// annotations, so say where they now go.
fn warn_of_unsuffixed_image_sidecar(path: &Path, image: ImageAt, binary: &mut Binary, log: &Path) {
    let mut owner = path.as_os_str().to_owned();
    owner.push(format!("@{:#x}", image.offset()));
    let owner = PathBuf::from(owner);
    let old = annotation_path(&owner, None, binary);
    if std::fs::symlink_metadata(&old).is_ok() && std::fs::symlink_metadata(&owner).is_err() {
        binary.warnings.push(format!(
            "annotations at {} were not loaded: embedded images now keep theirs in {}; move that log there if it \
             belongs to this image",
            old.display(),
            log.display()
        ));
    }
}
