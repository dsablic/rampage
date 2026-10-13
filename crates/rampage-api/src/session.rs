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
}

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

    /// The data packs every project of this session uses.
    pub fn packs(&self) -> Arc<Packs> {
        Arc::clone(&self.packs)
    }

    /// The directory chosen with [`Session::with_capture_annotations`], if any.
    pub fn capture_annotations(&self) -> Option<&Path> {
        self.capture_annotations.as_deref()
    }

    /// A session with this one's settings (snapshot annotation directory, packs) and none of its projects, for
    /// changing a setting of a session that is shared and so cannot be taken apart.
    pub fn unloaded_copy(&self) -> Self {
        Self { capture_annotations: self.capture_annotations.clone(), packs: self.packs(), ..Self::default() }
    }

    pub fn open(&self, path: &Path, arch: Option<Arch>) -> Result<Arc<Project>, ApiError> {
        self.open_at(path, arch, None)
    }

    /// Opens the binary at `path`, or with an `image` location, the executable embedded there (see
    /// [`Binary::open_at`]). An embedded image is a project of its own, with its own annotation sidecar; a location
    /// that [is the whole file](ImageAt::is_whole_file) is the project [`Session::open`] gives.
    pub fn open_at(&self, path: &Path, arch: Option<Arch>, image: Option<ImageAt>) -> Result<Arc<Project>, ApiError> {
        let image = image.filter(|image| !image.is_whole_file());
        let executable = rampage_loaders::container::resolve_executable(path)
            .map_err(|source| ApiError::Load { path: path.to_owned(), source })?;
        let path = executable.as_path();
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_owned());
        // Taken before loading, so a write racing the load leaves a stamp the next open finds stale.
        let stamp = file_stamp(path);
        let cached = {
            let state = self.state.lock().expect("session lock");
            let loaded = arch.or_else(|| state.defaults.get(&(canonical.clone(), image)).copied());
            let key = loaded.map(|arch| (canonical.clone(), image, arch));
            if let Some(key) = key
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
            return Ok(project);
        }
        let mut binary =
            Binary::open_image(path, image, arch).map_err(|source| ApiError::Load { path: path.to_owned(), source })?;
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
        let annotations = Annotations::open_for_image(log, digest).map_err(ApiError::Invalid)?;
        binary.warnings.extend(annotations.warnings());

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
        if let Some(project) = state.projects.get(&key)
            && project.binary.format == binary.format
            && project.binary.warnings == binary.warnings
            && (binary.format == Format::Snapshot && project.binary.file_bytes() == binary.file_bytes()
                || ordinary_source.is_some_and(|source| state.ordinary_sources.get(&key) == Some(&source)))
        {
            project.refresh_annotations()?;
            return Ok(Arc::clone(project));
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
        let worker = std::env::var_os("RAMPAGE_WORKER").map(PathBuf::from).or_else(|| {
            let sibling = std::env::current_exe().ok()?.with_file_name("rampage-worker");
            sibling.is_file().then_some(sibling)
        });
        let project = state.projects.entry(key).or_insert_with(|| {
            let mut annotations = annotations;
            if let Some(previous) = previous {
                annotations.inherit_history(&previous.annotations());
            }
            let project = Project::with_annotations(binary, annotations);
            project.set_packs(Arc::clone(&self.packs));
            if let Some(executable) = worker {
                project.set_decompiler_worker(Some(crate::DecompilerWorkerConfig {
                    executable: Some(executable),
                    ..Default::default()
                }));
            }
            Arc::new(project)
        });
        Ok(Arc::clone(project))
    }
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
fn annotation_path(path: &Path, image: Option<ImageAt>, binary: &Binary) -> PathBuf {
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
