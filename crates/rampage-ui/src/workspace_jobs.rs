//! Explicit workspace file operations share one execution lease, including after cancellation or bank changes.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rampage_api::derived_cache::{self, InventoryCacheReadOutcome};
use rampage_api::{
    ApiError, LoadedProjectWorkspace, ProjectWorkspaceModuleInput, ProjectWorkspacePreview, ProjectWorkspaceProgress,
    ProjectWorkspacePublication, ProjectWorkspaceTaskControl, Session,
};

use crate::cached_inventory_ui::CacheBinding;
use crate::workspace::Job;
use crate::workspace_bank::BankBinding;

#[derive(Clone, Default)]
struct ExecutionGate(Arc<AtomicBool>);

impl ExecutionGate {
    fn acquire(&self) -> Option<ExecutionPermit> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| ExecutionPermit(Arc::clone(&self.0)))
    }
}

struct ExecutionPermit(Arc<AtomicBool>);

impl Drop for ExecutionPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(crate) enum WorkspaceInput {
    Save { modules: Vec<ProjectWorkspaceModuleInput>, active: String, session: Session, output: PathBuf },
    Preview { path: PathBuf },
    OpenReviewed { preview: Arc<ProjectWorkspacePreview>, session: Session },
    InventorySave { project: Arc<rampage_api::Project>, output: PathBuf },
    InventoryLoad { project: Arc<rampage_api::Project>, path: PathBuf },
}

pub(crate) enum WorkspaceOutput {
    Save { output: PathBuf, result: Result<ProjectWorkspacePublication, ApiError> },
    Preview(Result<ProjectWorkspacePreview, ApiError>),
    OpenReviewed(Result<Box<LoadedCandidate>, ApiError>),
    InventorySave { output: PathBuf, result: Result<ProjectWorkspacePublication, ApiError> },
    InventoryLoad(Result<InventoryCacheReadOutcome, ApiError>),
}

pub(crate) struct LoadedCandidate {
    pub(crate) loaded: LoadedProjectWorkspace,
    pub(crate) canonical_sources: Vec<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Save,
    Preview,
    OpenReviewed,
    InventorySave,
    InventoryLoad,
}

impl WorkspaceInput {
    fn operation(&self) -> Operation {
        match self {
            Self::Save { .. } => Operation::Save,
            Self::Preview { .. } => Operation::Preview,
            Self::OpenReviewed { .. } => Operation::OpenReviewed,
            Self::InventorySave { .. } => Operation::InventorySave,
            Self::InventoryLoad { .. } => Operation::InventoryLoad,
        }
    }

    fn execute(self, cancellation: &AtomicBool, progress: &mut dyn FnMut(ProjectWorkspaceProgress)) -> WorkspaceOutput {
        let mut control = ProjectWorkspaceTaskControl::new(cancellation, progress);
        match self {
            Self::Save { modules, active, session, output } => {
                let result =
                    rampage_api::capture_project_workspace_controlled(&modules, &active, &session, &mut control)
                        .and_then(|manifest| {
                            rampage_api::publish_project_workspace_controlled(&manifest, &output, &mut control)
                        });
                WorkspaceOutput::Save { output, result }
            }
            Self::Preview { path } => {
                WorkspaceOutput::Preview(rampage_api::preview_project_workspace_controlled(&path, &mut control))
            }
            Self::OpenReviewed { preview, session } => {
                let result = preview.open_reviewed_controlled(&session, &mut control).and_then(|loaded| {
                    let canonical_sources = loaded
                        .modules()
                        .iter()
                        .map(|module| {
                            control.check()?;
                            module
                                .module()
                                .source_path
                                .canonicalize()
                                .map_err(|error| ApiError::Invalid(error.to_string()))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    loaded.validate_metadata()?;
                    control.check()?;
                    Ok(Box::new(LoadedCandidate { loaded, canonical_sources }))
                });
                WorkspaceOutput::OpenReviewed(result)
            }
            Self::InventorySave { project, output } => {
                let result = derived_cache::capture_function_inventory(project, &mut control)
                    .and_then(|prepared| derived_cache::publish_function_inventory(&prepared, &output, &mut control));
                WorkspaceOutput::InventorySave { output, result }
            }
            Self::InventoryLoad { project, path } => {
                WorkspaceOutput::InventoryLoad(derived_cache::read_function_inventory(project, &path, &mut control))
            }
        }
    }
}

pub(crate) enum WorkspaceJobBinding {
    Bank(BankBinding),
    Inventory(CacheBinding),
}

/// Memory-only identity observation. Current never attests physical source metadata or authorizes adoption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BindingState {
    Current,
    Busy,
    Changed,
}

impl WorkspaceJobBinding {
    pub(crate) fn memory_state(&self, app: &crate::App) -> BindingState {
        match self {
            Self::Bank(binding) => {
                if binding.matches(app) {
                    BindingState::Current
                } else {
                    BindingState::Changed
                }
            }
            Self::Inventory(binding) => binding.memory_state(app),
        }
    }
}

pub(crate) struct WorkspaceCompletion {
    pub(crate) binding: WorkspaceJobBinding,
    pub(crate) cancelled: bool,
    pub(crate) output: Result<WorkspaceOutput, String>,
}

pub(crate) struct WorkspaceJobs {
    gate: ExecutionGate,
    job: Job<WorkspaceOutput>,
    binding: Option<WorkspaceJobBinding>,
    cancellation: Arc<AtomicBool>,
    progress: Arc<Mutex<Option<ProjectWorkspaceProgress>>>,
    operation: Option<Operation>,
    status: Option<String>,
    #[cfg(test)]
    pub(crate) before_work: Option<Box<dyn FnOnce() + Send>>,
}

impl Default for WorkspaceJobs {
    fn default() -> Self {
        Self {
            gate: ExecutionGate::default(),
            job: Job::Idle,
            binding: None,
            cancellation: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(Mutex::new(None)),
            operation: None,
            status: None,
            #[cfg(test)]
            before_work: None,
        }
    }
}

impl WorkspaceJobs {
    pub(crate) fn running(&self) -> bool {
        self.operation.is_some() || self.gate.0.load(Ordering::Acquire)
    }

    pub(crate) fn visible(&self) -> bool {
        self.running() || self.status.is_some()
    }

    pub(crate) fn binding(&self) -> Option<&WorkspaceJobBinding> {
        self.binding.as_ref()
    }

    pub(crate) fn defer_inventory_adoption(&self) -> bool {
        self.operation == Some(Operation::InventoryLoad) && !self.cancellation.load(Ordering::Acquire)
    }

    pub(crate) fn cancel(&mut self) {
        if self.running() {
            self.cancellation.store(true, Ordering::Release);
        }
    }

    pub(crate) fn close_review(&mut self) {
        if matches!(self.operation, Some(Operation::Preview | Operation::OpenReviewed)) {
            self.cancel();
        }
    }

    pub(crate) fn bank_changed(&mut self) {
        if matches!(self.binding, Some(WorkspaceJobBinding::Bank(_))) {
            self.cancel();
        }
    }

    pub(crate) fn cancel_inventory(&mut self) {
        if matches!(self.binding, Some(WorkspaceJobBinding::Inventory(_))) {
            self.cancel();
        }
    }

    pub(crate) fn start_inventory(
        &mut self,
        ctx: &egui::Context,
        blocking: bool,
        binding: CacheBinding,
        input: WorkspaceInput,
    ) -> Result<(), String> {
        let operation = input.operation();
        self.start_bound_execution(
            ctx,
            blocking,
            WorkspaceJobBinding::Inventory(binding),
            operation,
            move |cancellation, progress| input.execute(cancellation, progress),
        )
    }

    pub(crate) fn start(
        &mut self,
        ctx: &egui::Context,
        blocking: bool,
        binding: BankBinding,
        input: WorkspaceInput,
    ) -> Result<(), String> {
        let operation = input.operation();
        self.start_execution(ctx, blocking, binding, operation, move |cancellation, progress| {
            input.execute(cancellation, progress)
        })
    }

    fn start_execution(
        &mut self,
        ctx: &egui::Context,
        blocking: bool,
        binding: BankBinding,
        operation: Operation,
        work: impl FnOnce(&AtomicBool, &mut dyn FnMut(ProjectWorkspaceProgress)) -> WorkspaceOutput + Send + 'static,
    ) -> Result<(), String> {
        self.start_bound_execution(ctx, blocking, WorkspaceJobBinding::Bank(binding), operation, work)
    }

    fn start_bound_execution(
        &mut self,
        ctx: &egui::Context,
        blocking: bool,
        binding: WorkspaceJobBinding,
        operation: Operation,
        work: impl FnOnce(&AtomicBool, &mut dyn FnMut(ProjectWorkspaceProgress)) -> WorkspaceOutput + Send + 'static,
    ) -> Result<(), String> {
        if self.running() {
            return Err("A workspace file operation is still finishing. No new operation was started.".to_owned());
        }
        let permit = self.gate.acquire().ok_or_else(|| "A workspace file operation is still finishing.".to_owned())?;
        self.binding = Some(binding);
        self.operation = Some(operation);
        self.status = None;
        self.cancellation = Arc::new(AtomicBool::new(false));
        self.progress = Arc::new(Mutex::new(None));
        let cancellation = Arc::clone(&self.cancellation);
        let progress = Arc::clone(&self.progress);
        let repaint = ctx.clone();
        #[cfg(test)]
        let before_work = self.before_work.take();
        self.job.start(blocking, ctx, move || {
            let _permit = permit;
            #[cfg(test)]
            if let Some(before_work) = before_work {
                before_work();
            }
            let mut update = |phase| {
                if let Ok(mut latest) = progress.try_lock() {
                    *latest = Some(phase);
                }
                repaint.request_repaint();
            };
            Ok(work(&cancellation, &mut update))
        });
        Ok(())
    }

    pub(crate) fn poll(&mut self) -> Option<WorkspaceCompletion> {
        self.job.poll();
        if !matches!(self.job, Job::Done(_)) {
            return None;
        }
        let Job::Done(output) = std::mem::replace(&mut self.job, Job::Idle) else { unreachable!() };
        self.operation = None;
        Some(WorkspaceCompletion {
            binding: self.binding.take()?,
            cancelled: self.cancellation.load(Ordering::Acquire),
            output,
        })
    }

    pub(crate) fn finish(&mut self, status: String) {
        self.status = Some(status);
    }

    pub(crate) fn show(&mut self, ui: &mut egui::Ui) {
        if self.running() {
            ui.horizontal(|ui| {
                ui.spinner();
                let phase = self.progress.try_lock().ok().and_then(|latest| latest.clone());
                if let Some(progress) = phase {
                    ui.label(format!("{:?}", progress.phase));
                    if let Some(module) = progress.module_id {
                        ui.label(module);
                    }
                    if progress.total_modules > 0 {
                        ui.label(format!("{} / {} modules", progress.completed_modules, progress.total_modules));
                    }
                    ui.label(format!("{} ms", progress.elapsed_ms));
                } else {
                    ui.label("Workspace operation queued");
                }
                let requested = self.cancellation.load(Ordering::Acquire);
                if ui.add_enabled(!requested, egui::Button::new("Cancel workspace operation")).clicked() {
                    self.cancel();
                }
                if requested {
                    ui.label("Cancellation requested; waiting for the current operation to finish.");
                }
            });
        } else if let Some(status) = &self.status {
            ui.label(status);
        }
    }
}

impl Drop for WorkspaceJobs {
    fn drop(&mut self) {
        self.cancellation.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests;
