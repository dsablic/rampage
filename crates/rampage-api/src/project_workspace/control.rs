use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use serde::Serialize;

use crate::ApiError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectWorkspacePhase {
    CapturingInputs,
    ReadingManifest,
    PreflightingSources,
    LoadingModule,
    ValidatingIdentity,
    ReadingAnnotations,
    PreparingDocument,
    Publishing,
    PublicationStaged,
    ResultValidation,
    CapturingInventory,
    ReadingCache,
    ValidatingCache,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectWorkspaceProgress {
    pub phase: ProjectWorkspacePhase,
    pub module_id: Option<String>,
    pub completed_modules: usize,
    pub total_modules: usize,
    pub elapsed_ms: u64,
}

/// One calling-thread operation scope. Cancellation is cooperative, including during bounded regular-file I/O.
pub struct ProjectWorkspaceTaskControl<'a> {
    cancellation: &'a AtomicBool,
    observer: &'a mut dyn FnMut(ProjectWorkspaceProgress),
    started: Instant,
}

impl<'a> ProjectWorkspaceTaskControl<'a> {
    pub fn new(cancellation: &'a AtomicBool, observer: &'a mut dyn FnMut(ProjectWorkspaceProgress)) -> Self {
        Self { cancellation, observer, started: Instant::now() }
    }

    pub fn check(&self) -> Result<(), ApiError> {
        if self.cancellation.load(Ordering::Relaxed) {
            Err(ApiError::Unavailable("workspace operation cancellation requested".into()))
        } else {
            Ok(())
        }
    }

    pub(crate) fn phase(
        &mut self,
        phase: ProjectWorkspacePhase,
        module_id: Option<&str>,
        completed: usize,
        total: usize,
    ) -> Result<(), ApiError> {
        self.check()?;
        (self.observer)(ProjectWorkspaceProgress {
            phase,
            module_id: module_id.map(str::to_owned),
            completed_modules: completed,
            total_modules: total,
            elapsed_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        });
        self.check()
    }
}

pub(super) fn uncontrolled<T>(
    work: impl FnOnce(&mut ProjectWorkspaceTaskControl<'_>) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    let cancellation = AtomicBool::new(false);
    let mut observer = |_| {};
    work(&mut ProjectWorkspaceTaskControl::new(&cancellation, &mut observer))
}
