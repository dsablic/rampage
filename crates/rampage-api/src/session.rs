use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rampage_arch::Arch;
use rampage_loaders::Binary;

use crate::annotations::Annotations;
use crate::{ApiError, Project};

/// Loaded binaries, each analyzed at most once however it is asked for.
#[derive(Default)]
pub struct Session {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// Projects by canonical path and the architecture of the slice loaded.
    projects: HashMap<(PathBuf, Arch), Arc<Project>>,
    /// The slice each path opens when no architecture is asked for.
    defaults: HashMap<PathBuf, Arch>,
}

impl Session {
    pub fn open(&self, path: &Path, arch: Option<Arch>) -> Result<Arc<Project>, ApiError> {
        let executable = rampage_loaders::container::resolve_executable(path)
            .map_err(|source| ApiError::Load { path: path.to_owned(), source })?;
        let path = executable.as_path();
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_owned());
        {
            let state = self.state.lock().expect("session lock");
            let loaded = arch.or_else(|| state.defaults.get(&canonical).copied());
            if let Some(project) = loaded.and_then(|arch| state.projects.get(&(canonical.clone(), arch))) {
                return Ok(Arc::clone(project));
            }
        }
        let binary =
            Binary::open_with(path, arch).map_err(|source| ApiError::Load { path: path.to_owned(), source })?;
        // Annotations are kept beside the binary, per slice of a universal binary.
        let mut log = path.as_os_str().to_owned();
        if binary.slices.len() > 1 {
            log.push(format!(".{}", binary.arch));
        }
        log.push(".rampage");
        let annotations = Annotations::open(PathBuf::from(log)).map_err(ApiError::Invalid)?;

        let mut state = self.state.lock().expect("session lock");
        if arch.is_none() {
            state.defaults.insert(canonical.clone(), binary.arch);
        }
        // Another thread may have loaded the same slice meanwhile; everyone shares the first.
        let key = (canonical, binary.arch);
        let project =
            state.projects.entry(key).or_insert_with(|| Arc::new(Project::with_annotations(binary, annotations)));
        if let Some(executable) = std::env::var_os("RAMPAGE_WORKER") {
            project.set_decompiler_worker(Some(crate::DecompilerWorkerConfig {
                executable: Some(PathBuf::from(executable)),
                ..Default::default()
            }));
        }
        Ok(Arc::clone(project))
    }
}
