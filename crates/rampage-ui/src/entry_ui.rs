//! Explicit exact-entry execution, independent of the analysis-backed pseudocode panel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rampage_api::{
    DecompileEntryRequest, DecompilerConfigurationRevision, EntryDecompilation, EntryPreparationPhase,
    EntryPreparationProgress, EntryValidation, Project,
};

use crate::theme;
use crate::workspace::{Job, Workspace};

#[derive(Clone, Default)]
pub(crate) struct EntryGate(Arc<AtomicBool>);

impl EntryGate {
    fn is_running(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn try_acquire(&self) -> Option<EntryPermit> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| EntryPermit(Arc::clone(&self.0)))
    }
}

struct EntryPermit(Arc<AtomicBool>);

impl Drop for EntryPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct Binding {
    instance: Arc<()>,
    project: Arc<Project>,
    epoch: Arc<()>,
    revision: Arc<()>,
    request_id: u64,
    address: u64,
    validation: EntryValidation,
    configuration: DecompilerConfigurationRevision,
}

impl Binding {
    fn matches(&self, workspace: &Workspace, entry: &EntryUi) -> bool {
        Arc::ptr_eq(&self.instance, &workspace.instance)
            && Arc::ptr_eq(&self.project, &workspace.project)
            && Arc::ptr_eq(&self.epoch, &workspace.annotations_epoch)
            && Arc::ptr_eq(&self.revision, &entry.revision)
            && self.request_id == entry.request_id
            && self.address == workspace.cursor
            && self.validation == entry.validation
            && workspace.project.decompiler_configuration_revision().is_ok_and(|current| current == self.configuration)
            && workspace.project.binary.validate_available_backing_source().is_ok()
    }
}

pub(crate) struct EntryUi {
    shown: bool,
    validation: EntryValidation,
    gate: EntryGate,
    revision: Arc<()>,
    request_id: u64,
    cancellation: Arc<AtomicBool>,
    progress: Arc<Mutex<Option<EntryPreparationProgress>>>,
    job: Job<EntryDecompilation>,
    binding: Option<Binding>,
    result: Option<EntryDecompilation>,
    error: Option<String>,
}

impl Default for EntryUi {
    fn default() -> Self {
        Self {
            shown: false,
            validation: EntryValidation::MetadataBacked,
            gate: EntryGate::default(),
            revision: Arc::new(()),
            request_id: 0,
            cancellation: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(Mutex::new(None)),
            job: Job::Idle,
            binding: None,
            result: None,
            error: None,
        }
    }
}

impl EntryUi {
    pub(crate) fn show(&mut self) {
        self.shown = true;
    }

    pub(crate) fn set_gate(&mut self, gate: EntryGate) {
        self.invalidate();
        self.gate = gate;
    }

    pub(crate) fn invalidate(&mut self) {
        let had_work = self.binding.is_some() || self.result.is_some();
        self.cancellation.store(true, Ordering::Relaxed);
        self.revision = Arc::new(());
        self.binding = None;
        self.result = None;
        self.progress = Arc::new(Mutex::new(None));
        if had_work {
            self.error = Some("Request invalidated. Run explicitly again when ready.".to_owned());
        }
        if !self.job.is_running() {
            self.job = Job::Idle;
        }
    }

    fn close(&mut self) {
        self.invalidate();
        self.shown = false;
    }

    pub(crate) fn poll(&mut self, workspace: &Workspace) {
        if self.binding.as_ref().is_some_and(|binding| !binding.matches(workspace, self)) {
            self.invalidate();
        }
        if self.job.poll() || matches!(self.job, Job::Done(_)) {
            let job = std::mem::replace(&mut self.job, Job::Idle);
            if let Job::Done(result) = job {
                self.accept_result(workspace, result);
            }
        }
    }

    fn run(&mut self, workspace: &Workspace, ctx: &egui::Context, blocking: bool) {
        self.start_execution(workspace, ctx, blocking, |project, request, cancellation, progress| {
            project
                .decompile_entry_with_progress(request, cancellation, |update| {
                    if let Ok(mut latest) = progress.try_lock() {
                        *latest = Some(update);
                    }
                })
                .map_err(error_text)
        });
    }

    fn start_execution(
        &mut self,
        workspace: &Workspace,
        ctx: &egui::Context,
        blocking: bool,
        work: impl FnOnce(
            &Project,
            &DecompileEntryRequest,
            &AtomicBool,
            &Mutex<Option<EntryPreparationProgress>>,
        ) -> Result<EntryDecompilation, String>
        + Send
        + 'static,
    ) {
        self.poll(workspace);
        if self.job.is_running() || self.gate.is_running() {
            self.error = Some("An exact-entry task is still finishing. No new task was started.".to_owned());
            return;
        }
        self.invalidate();
        let configuration = match workspace.project.decompiler_configuration_revision() {
            Ok(revision) => revision,
            Err(error) => {
                self.error = Some(error.to_string());
                return;
            }
        };
        let Some(request_id) = self.request_id.checked_add(1) else {
            self.error = Some("Request identifiers exhausted; reopen the workspace.".to_owned());
            return;
        };
        let Some(permit) = self.gate.try_acquire() else {
            self.error = Some("An exact-entry task is still finishing.".to_owned());
            return;
        };
        self.request_id = request_id;
        self.error = None;
        self.cancellation = Arc::new(AtomicBool::new(false));
        self.progress = Arc::new(Mutex::new(None));
        self.binding = Some(Binding {
            instance: Arc::clone(&workspace.instance),
            project: Arc::clone(&workspace.project),
            epoch: Arc::clone(&workspace.annotations_epoch),
            revision: Arc::clone(&self.revision),
            request_id,
            address: workspace.cursor,
            validation: self.validation,
            configuration,
        });
        let request = DecompileEntryRequest { address: workspace.cursor, validation: self.validation };
        let project = Arc::clone(&workspace.project);
        let cancellation = Arc::clone(&self.cancellation);
        let progress = Arc::clone(&self.progress);
        self.job.start(blocking, ctx, move || {
            let _permit = permit;
            work(&project, &request, &cancellation, &progress)
        });
        self.poll(workspace);
    }

    fn accept_result(&mut self, workspace: &Workspace, result: Result<EntryDecompilation, String>) {
        let Some(binding) = &self.binding else { return };
        if !binding.matches(workspace, self) || self.cancellation.load(Ordering::Relaxed) {
            self.invalidate();
            return;
        }
        match result {
            Ok(result) if result.context.configuration_revision == binding.configuration => {
                self.result = Some(result);
            }
            Ok(_) => self.invalidate(),
            Err(error) => {
                self.error = Some(error);
                self.binding = None;
            }
        }
    }

    pub(crate) fn window(&mut self, workspace: &Workspace, ctx: &egui::Context, blocking: bool) {
        self.poll(workspace);
        if !self.shown {
            return;
        }
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
            self.close();
            return;
        }
        let mut shown = true;
        egui::Window::new("Exact-entry decompilation")
            .id(egui::Id::new("exact-entry-decompilation"))
            .open(&mut shown)
            .default_size([760.0, 580.0])
            .vscroll(true)
            .show(ctx, |ui| {
                ui.label(format!("Current cursor: {:#x}", workspace.cursor));
                ui.label("Does not start or require global analysis; this session project may already have analysis.");
                let previous = self.validation;
                egui::ComboBox::from_label("Entry validation")
                    .selected_text(validation_label(self.validation))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.validation, EntryValidation::MetadataBacked, "Metadata-backed");
                        ui.selectable_value(&mut self.validation, EntryValidation::AnalystAsserted, "Analyst-asserted");
                    });
                if previous != self.validation {
                    self.invalidate();
                }
                ui.label("No automatic fallback. Neither validation mode proves a complete function boundary.");
                ui.label("Native calls cannot be forcibly interrupted; cancellation is cooperative.");
                ui.horizontal(|ui| {
                    let busy = self.job.is_running() || self.gate.is_running();
                    if ui.add_enabled(!busy, egui::Button::new("Run")).clicked() {
                        self.run(workspace, ctx, blocking);
                    }
                    if ui.add_enabled(self.job.is_running(), egui::Button::new("Cancel")).clicked() {
                        self.invalidate();
                    }
                });
                if self.job.is_running() {
                    ctx.request_repaint_after(Duration::from_millis(50));
                    ui.spinner();
                    if self.cancellation.load(Ordering::Relaxed) {
                        ui.label("Cancellation requested; the executing task still owns its permit.");
                    }
                } else if self.gate.is_running() {
                    ctx.request_repaint_after(Duration::from_millis(50));
                    ui.label("Another exact-entry task is still finishing.");
                }
                if let Ok(latest) = self.progress.try_lock()
                    && let Some(progress) = latest.as_ref()
                {
                    ui.label(format!("Last observed phase: {:?} ({} ms elapsed)", progress.phase, progress.elapsed_ms));
                    if matches!(
                        progress.phase,
                        EntryPreparationPhase::NativeInitialization
                            | EntryPreparationPhase::NativeReplay
                            | EntryPreparationPhase::NativeExecution
                    ) {
                        ui.colored_label(
                            theme::WARNING,
                            "Native FFI is cooperative: Cancel cannot forcibly interrupt an active native call.",
                        );
                    }
                }
                if let Some(error) = &self.error {
                    ui.colored_label(theme::WARNING, error);
                }
                if let Some(result) = &self.result {
                    show_result(ui, result);
                } else if !self.job.is_running() && self.error.is_none() {
                    ui.label("Not started. Choose validation and press Run.");
                }
            });
        if !shown {
            self.close();
        }
    }
}

impl Drop for EntryUi {
    fn drop(&mut self) {
        self.cancellation.store(true, Ordering::Relaxed);
    }
}

fn validation_label(validation: EntryValidation) -> &'static str {
    match validation {
        EntryValidation::MetadataBacked => "Metadata-backed",
        EntryValidation::AnalystAsserted => "Analyst-asserted",
    }
}

fn error_text(error: rampage_api::ApiError) -> String {
    let mut message = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        message.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    message
}

fn show_result(ui: &mut egui::Ui, result: &EntryDecompilation) {
    let decompilation = &result.decompilation;
    ui.separator();
    ui.label(format!("Exact entry {:#x} — {}", decompilation.address, decompilation.language_id));
    ui.colored_label(theme::WARNING, "Bounded local context, not a recovered or verified function boundary.");
    ui.label(format!("Native recovery status: {}", decompilation.recovery_status.label()));
    ui.collapsing("Native recovery diagnostics and warnings", |ui| {
        ui.monospace(format!("{:#?}", decompilation.structure.diagnostics));
    });
    ui.collapsing("Exact-entry context, backing, budgets, typed entry sample and omissions", |ui| {
        ui.monospace(format!("{:#?}", result.context));
    });
    egui::ScrollArea::both().id_salt("exact-entry-code").show(ui, |ui| {
        ui.add(egui::Label::new(egui::RichText::new(&decompilation.code).monospace()).selectable(true));
    });
}

#[cfg(test)]
#[path = "entry_ui_tests.rs"]
mod tests;
