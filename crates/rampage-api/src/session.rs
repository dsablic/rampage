use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rampage_analysis::capture_identity::capture_identity;
use rampage_arch::Arch;
use rampage_loaders::{Binary, Format};
use sha2::{Digest, Sha256};

use crate::annotations::Annotations;
use crate::{ApiError, Project};

/// Loaded binaries, with snapshots revalidated on each open to notice changed mappings or capture metadata.
#[derive(Default)]
pub struct Session {
    state: Mutex<State>,
    capture_annotations: Option<PathBuf>,
}

#[derive(Default)]
struct State {
    /// Projects by canonical path, embedded image offset and the architecture of the slice loaded.
    projects: HashMap<(PathBuf, Option<u64>, Arch), Arc<Project>>,
    /// The slice each path and offset opens when no architecture is asked for.
    defaults: HashMap<(PathBuf, Option<u64>), Arch>,
    /// Paths once used for captures remain revalidated even after an ordinary binary replaces them.
    capture_paths: HashSet<PathBuf>,
    /// Freeze hashes for ordinary replacements; their memory maps may reflect later in-place file writes.
    ordinary_sources: HashMap<(PathBuf, Option<u64>, Arch), [u8; 32]>,
}

impl Session {
    /// Shares identity-scoped snapshot annotation logs in an explicitly selected, existing directory.
    /// Without this option, snapshots share logs only with captures in the same canonical directory.
    /// Ordinary binaries still use their existing per-path, per-slice sidecars.
    pub fn with_capture_annotations(directory: PathBuf) -> Self {
        Self { capture_annotations: Some(directory), ..Self::default() }
    }

    pub fn open(&self, path: &Path, arch: Option<Arch>) -> Result<Arc<Project>, ApiError> {
        self.open_at(path, arch, None)
    }

    /// Opens the binary at `path`, or with an `offset`, the executable embedded there (see
    /// [`Binary::open_at`]). An embedded image is a project of its own, with its own annotation sidecar.
    pub fn open_at(&self, path: &Path, arch: Option<Arch>, offset: Option<u64>) -> Result<Arc<Project>, ApiError> {
        let executable = rampage_loaders::container::resolve_executable(path)
            .map_err(|source| ApiError::Load { path: path.to_owned(), source })?;
        let path = executable.as_path();
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_owned());
        let cached = {
            let state = self.state.lock().expect("session lock");
            let loaded = arch.or_else(|| state.defaults.get(&(canonical.clone(), offset)).copied());
            if let Some(project) = loaded.and_then(|arch| state.projects.get(&(canonical.clone(), offset, arch)))
                && project.binary.format != Format::Snapshot
                && !state.capture_paths.contains(&canonical)
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
        let binary = match offset {
            Some(offset) => Binary::open_at_with(path, offset, None, arch),
            None => Binary::open_with(path, arch),
        };
        let mut binary = binary.map_err(|source| ApiError::Load { path: path.to_owned(), source })?;
        let legacy = annotation_path(path, &binary);
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
            legacy
        };
        let annotations = Annotations::open(log).map_err(ApiError::Invalid)?;

        let mut state = self.state.lock().expect("session lock");
        if arch.is_none() {
            state.defaults.insert((canonical.clone(), offset), binary.arch);
        }
        let revalidate = state.capture_paths.contains(&canonical);
        let key = (canonical, offset, binary.arch);
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
        let worker = std::env::var_os("RAMPAGE_WORKER").map(PathBuf::from).or_else(|| {
            let sibling = std::env::current_exe().ok()?.with_file_name("rampage-worker");
            sibling.is_file().then_some(sibling)
        });
        let project = state.projects.entry(key).or_insert_with(|| {
            let project = Project::with_annotations(binary, annotations);
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

/// `<file>.rampage`, with `@0x<offset>` for an embedded image and `.<arch>` for one slice of a universal binary.
fn annotation_path(path: &Path, binary: &Binary) -> PathBuf {
    let mut log = path.as_os_str().to_owned();
    if let Some(embedded) = binary.embedded {
        log.push(format!("@{:#x}", embedded.offset));
    }
    if binary.slices.len() > 1 {
        log.push(format!(".{}", binary.arch));
    }
    log.push(".rampage");
    PathBuf::from(log)
}
