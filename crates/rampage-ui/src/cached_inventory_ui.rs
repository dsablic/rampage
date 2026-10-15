//! Explicit historical inventory hints, isolated from current analysis and function-entry authority.

use std::path::PathBuf;
use std::sync::Arc;

use rampage_api::derived_cache::{CachedFunctionInventory, InventoryCacheReadOutcome};
use rampage_api::{ApiError, DebuggerCapturePublicationStatus, Project, ProjectWorkspacePublication};

use crate::workspace_jobs::{BindingState, WorkspaceInput, WorkspaceOutput};
use crate::{App, ProjectWorkspaceSaveNotice, Workspace, theme};

const DISPLAY_ROWS: usize = 2048;

#[derive(Clone)]
pub(crate) struct CacheBinding {
    module_id: String,
    project: Arc<Project>,
    names_revision: Arc<()>,
}

impl CacheBinding {
    pub(crate) fn capture(app: &App, module_id: &str) -> Result<Self, String> {
        let workspace = app.inventory_module(module_id).ok_or_else(|| "Select an open source module.".to_owned())?;
        Ok(Self {
            module_id: module_id.to_owned(),
            project: Arc::clone(&workspace.project),
            names_revision: workspace.project.names_revision().map_err(|error| error.to_string())?,
        })
    }

    pub(crate) fn memory_state(&self, app: &App) -> BindingState {
        let Some(workspace) = app.inventory_module(&self.module_id) else { return BindingState::Changed };
        if !Arc::ptr_eq(&self.project, &workspace.project) {
            return BindingState::Changed;
        }
        match workspace.project.names_revision() {
            Ok(names) if Arc::ptr_eq(&names, &self.names_revision) => BindingState::Current,
            Ok(_) => BindingState::Changed,
            Err(ApiError::Unavailable(_)) => BindingState::Busy,
            Err(_) => BindingState::Changed,
        }
    }
}

struct InventoryView {
    binding: CacheBinding,
    inventory: CachedFunctionInventory,
    filtered: Vec<usize>,
    selected: Option<usize>,
}

#[derive(Clone, Copy)]
enum PathAction {
    Save,
    Load,
}

struct PathDialog {
    action: PathAction,
    module_id: String,
}

#[derive(Default)]
pub(crate) struct CachedInventoryUi {
    shown: bool,
    module_id: String,
    path: String,
    dialog: Option<PathDialog>,
    filter: String,
    view: Option<InventoryView>,
    pending: Option<(CacheBinding, CachedFunctionInventory)>,
    message: Option<String>,
    #[cfg(test)]
    source_checks: std::cell::Cell<usize>,
}

impl App {
    fn inventory_module(&self, id: &str) -> Option<&Workspace> {
        if self.active_module_id() == Some(id) {
            self.workspace.as_ref()
        } else {
            self.workspace_bank.inactive.iter().find(|module| module.info.id == id).map(|module| &module.workspace)
        }
    }

    /// Opens controls only. No cache path is guessed, scanned, read or published.
    pub fn show_cached_function_inventory(&mut self) {
        self.cached_inventory.shown = true;
        if self.cached_inventory.module_id.is_empty() {
            self.cached_inventory.module_id = self.active_module_id().unwrap_or_default().to_owned();
        }
    }

    /// Explicitly reads one selected cache against an already-open module, without starting discovery.
    pub fn begin_inventory_cache_load(
        &mut self,
        ctx: &egui::Context,
        module_id: &str,
        path: PathBuf,
    ) -> Result<(), String> {
        self.ensure_workspace_io_idle(ctx)?;
        let binding = CacheBinding::capture(self, module_id)?;
        let input = WorkspaceInput::InventoryLoad { project: Arc::clone(&binding.project), path };
        self.workspace_jobs.start_inventory(ctx, self.blocking, binding, input)?;
        self.cached_inventory.view = None;
        self.cached_inventory.pending = None;
        self.cached_inventory.filter.clear();
        self.cached_inventory.message = None;
        self.cached_inventory.shown = true;
        self.cached_inventory.module_id = module_id.to_owned();
        self.error = None;
        self.poll_workspace_jobs(ctx);
        Ok(())
    }

    /// Publishes only completed discovery; capture never starts analysis and publication never opens its result.
    pub fn begin_inventory_cache_save(
        &mut self,
        ctx: &egui::Context,
        module_id: &str,
        output: PathBuf,
    ) -> Result<(), String> {
        self.ensure_workspace_io_idle(ctx)?;
        self.ensure_workspace_publication_clear()?;
        let binding = CacheBinding::capture(self, module_id)?;
        if !binding.project.analysis_cache_status().program {
            return Err("Complete global analysis explicitly before saving its historical inventory.".to_owned());
        }
        let input = WorkspaceInput::InventorySave { project: Arc::clone(&binding.project), output };
        self.workspace_jobs.start_inventory(ctx, self.blocking, binding, input)?;
        self.cached_inventory.message = None;
        self.cached_inventory.shown = true;
        self.cached_inventory.module_id = module_id.to_owned();
        self.error = None;
        self.poll_workspace_jobs(ctx);
        Ok(())
    }

    pub(crate) fn finish_inventory_job(
        &mut self,
        binding: CacheBinding,
        cancelled: bool,
        output: Result<WorkspaceOutput, String>,
    ) -> Result<String, String> {
        let result = (|| match output {
            Ok(WorkspaceOutput::InventorySave { output, result }) => {
                self.record_workspace_publication(output, &result);
                if binding.memory_state(self) == BindingState::Changed {
                    Err("Inventory source changed. Inspect the retained publication notices.".to_owned())
                } else {
                    publication_message(result)
                }
            }
            Ok(WorkspaceOutput::InventoryLoad(result)) => {
                if cancelled || binding.memory_state(self) == BindingState::Changed {
                    Err("Inventory load cancelled or its source changed. No live analysis was adopted.".to_owned())
                } else {
                    match result.map_err(|error| error.to_string())? {
                        InventoryCacheReadOutcome::Hit(inventory) => {
                            self.cached_inventory.pending = Some((binding, inventory));
                            self.adopt_pending_inventory()
                        }
                        InventoryCacheReadOutcome::Miss => Ok("Inventory cache miss. No discovery was started.".into()),
                        InventoryCacheReadOutcome::Rejected => {
                            Err("Inventory cache rejected. No discovery was started.".into())
                        }
                        InventoryCacheReadOutcome::SourceChanged => {
                            Err("Inventory source changed; load refused.".into())
                        }
                    }
                }
            }
            Ok(WorkspaceOutput::Save { output, result }) => {
                self.record_workspace_publication(output, &result);
                Err("Unexpected publication binding. Inspect the retained publication notices.".to_owned())
            }
            Ok(_) => Err("Unexpected inventory operation result. No live analysis was adopted.".to_owned()),
            Err(error) => Err(error),
        })();
        self.cached_inventory.message = Some(match &result {
            Ok(message) | Err(message) => message.clone(),
        });
        result
    }

    pub(crate) fn adopt_pending_inventory(&mut self) -> Result<String, String> {
        let Some((binding, inventory)) = self.cached_inventory.pending.as_ref() else {
            return Ok("No inventory adoption is pending.".to_owned());
        };
        match binding.memory_state(self) {
            BindingState::Busy => return Ok("Inventory names are busy; adoption is deferred.".to_owned()),
            BindingState::Changed => {
                self.cached_inventory.pending = None;
                return Err("Inventory source or names changed before adoption.".to_owned());
            }
            BindingState::Current => {}
        }
        let validation = self.validate_inventory_metadata(inventory, &binding.project);
        if matches!(&validation, Err(ApiError::Unavailable(_))) {
            return Ok("Inventory names are busy; adoption is deferred.".to_owned());
        }
        if let Err(error) = validation {
            self.cached_inventory.pending = None;
            return Err(error.to_string());
        }
        let (binding, inventory) = self.cached_inventory.pending.take().expect("validated pending inventory");
        let filtered = (0..inventory.rows().len().min(DISPLAY_ROWS)).collect();
        self.cached_inventory.view = Some(InventoryView { binding, inventory, filtered, selected: None });
        Ok("Historical inventory loaded; every candidate remains cached and unverified.".to_owned())
    }

    pub(crate) fn poll_pending_inventory(&mut self) {
        // Only a completed load may continue a deferred adoption; idle historical views never probe the source.
        if self.cached_inventory.pending.is_some() {
            let result = self.adopt_pending_inventory();
            self.cached_inventory.message = Some(match result {
                Ok(message) | Err(message) => message,
            });
        }
    }

    pub(crate) fn cancel_pending_inventory(&mut self) {
        if self.cached_inventory.pending.take().is_some() {
            self.cached_inventory.message = Some("Pending inventory adoption cancelled.".to_owned());
        }
    }

    fn inventory_view_memory_state(&self) -> BindingState {
        self.cached_inventory.view.as_ref().map_or(BindingState::Changed, |view| view.binding.memory_state(self))
    }

    fn validate_inventory_metadata(
        &self,
        inventory: &CachedFunctionInventory,
        project: &Arc<Project>,
    ) -> Result<(), ApiError> {
        #[cfg(test)]
        self.cached_inventory.source_checks.set(self.cached_inventory.source_checks.get() + 1);
        inventory.validate_current_metadata(project)
    }

    #[cfg(test)]
    pub(crate) fn inventory_view_current(&self) -> bool {
        self.cached_inventory.view.as_ref().is_some_and(|view| {
            view.binding.memory_state(self) == BindingState::Current
                && self.validate_inventory_metadata(&view.inventory, &view.binding.project).is_ok()
        })
    }

    fn inspect_cached_inventory_address(&mut self) -> Result<(), String> {
        match self.inventory_view_memory_state() {
            BindingState::Busy => {
                return Err("Inventory names are busy. Wait before inspecting a cached raw address.".to_owned());
            }
            BindingState::Changed => {
                self.cached_inventory.view = None;
                return Err(
                    "Historical inventory source changed. Load explicitly again before inspecting an address.".into()
                );
            }
            BindingState::Current => {}
        }
        let view = self.cached_inventory.view.as_ref().expect("validated inventory view");
        match self.validate_inventory_metadata(&view.inventory, &view.binding.project) {
            Ok(()) => {}
            Err(ApiError::Unavailable(_)) => {
                return Err("Inventory names are busy. Wait before inspecting a cached raw address.".to_owned());
            }
            Err(error) => {
                self.cached_inventory.view = None;
                return Err(error.to_string());
            }
        }
        let view = self.cached_inventory.view.as_ref().expect("validated inventory view");
        let row = view
            .selected
            .and_then(|index| view.inventory.rows().get(index))
            .ok_or_else(|| "Select a historical candidate first.".to_owned())?;
        let address = row
            .address
            .strip_prefix("0x")
            .and_then(|digits| u64::from_str_radix(digits, 16).ok())
            .ok_or_else(|| "The cached raw address is not a 64-bit hexadecimal address.".to_owned())?;
        let module_id = view.binding.module_id.clone();
        self.select_module(&module_id)?;
        self.workspace.as_mut().expect("selected inventory owner").goto(address);
        Ok(())
    }

    fn close_cached_inventory(&mut self) {
        self.cached_inventory.shown = false;
        self.cached_inventory.dialog = None;
        self.cached_inventory.view = None;
        self.cached_inventory.pending = None;
        self.workspace_jobs.cancel_inventory();
    }

    pub(crate) fn cached_inventory_window(&mut self, ctx: &egui::Context) {
        if !self.cached_inventory.shown {
            return;
        }
        let view_state = self.inventory_view_memory_state();
        if self.cached_inventory.view.is_some() && view_state == BindingState::Changed {
            self.cached_inventory.view = None;
            self.cached_inventory.message = Some("Historical inventory invalidated by source or name changes.".into());
        }
        let modules = self.modules();
        let ready = self
            .inventory_module(&self.cached_inventory.module_id)
            .is_some_and(|workspace| workspace.project.analysis_cache_status().program);
        let target_names_ready = self
            .inventory_module(&self.cached_inventory.module_id)
            .is_some_and(|workspace| workspace.project.names_revision().is_ok());
        let selected_module_exists = modules.iter().any(|module| module.id == self.cached_inventory.module_id);
        let idle = !self.workspace_io_running();
        let mut shown = true;
        let mut path_action = None;
        let mut inspect = false;
        egui::Window::new("Cached function inventory").open(&mut shown).default_width(750.0).show(ctx, |ui| {
            ui.heading("Cached / unverified historical candidates");
            ui.label(
                "Cache rows are historical hints, not current functions, source proof or decompiler entry authority.",
            );
            ui.label(
                "Loading never starts discovery, restores analysis, renames symbols or runs native decompilation.",
            );
            ui.label("Retained native mapped sources only. Snapshot-owned sources are not supported.");
            ui.label("Physical source metadata is rechecked on load completion and explicit address inspection.");
            if view_state == BindingState::Busy {
                ui.label("Inventory names are busy. Historical rows are retained; address inspection is deferred.");
            }
            egui::ComboBox::from_id_salt("inventory-cache-module")
                .selected_text(&self.cached_inventory.module_id)
                .show_ui(ui, |ui| {
                    for module in &modules {
                        ui.selectable_value(&mut self.cached_inventory.module_id, module.id.clone(), &module.id);
                    }
                });
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        idle && selected_module_exists && target_names_ready,
                        egui::Button::new("Load inventory cache…"),
                    )
                    .clicked()
                {
                    path_action = Some(PathAction::Load);
                }
                if ui
                    .add_enabled(idle && ready && target_names_ready, egui::Button::new("Save completed inventory…"))
                    .clicked()
                {
                    path_action = Some(PathAction::Save);
                }
            });
            if !ready {
                ui.label("Save requires separately completed global analysis. This window never starts it.");
            }
            if let Some(view) = &mut self.cached_inventory.view {
                ui.separator();
                ui.label(format!("Inventory owner module: {}", view.binding.module_id));
                ui.monospace(view.inventory.provenance());
                ui.label(format!(
                    "{} cached rows of {} historical functions; truncated: {}",
                    view.inventory.rows().len(),
                    view.inventory.total_functions(),
                    view.inventory.truncated(),
                ));
                ui.label(format!("This view displays and filters at most {DISPLAY_ROWS} historical rows."));
                let label = ui.label("Filter historical candidates");
                if ui
                    .add(egui::TextEdit::singleline(&mut self.cached_inventory.filter).char_limit(256))
                    .labelled_by(label.id)
                    .changed()
                {
                    view.filtered = view
                        .inventory
                        .rows()
                        .iter()
                        .take(DISPLAY_ROWS)
                        .enumerate()
                        .filter(|(_, row)| {
                            row.name.contains(&self.cached_inventory.filter)
                                || row.address.contains(&self.cached_inventory.filter)
                        })
                        .map(|(index, _)| index)
                        .collect();
                }
                ui.label(format!("{} historical candidates match", view.filtered.len()));
                let height = ui.text_style_height(&egui::TextStyle::Body) + ui.spacing().item_spacing.y;
                egui::ScrollArea::vertical().id_salt("cached-inventory-rows").max_height(300.0).show_rows(
                    ui,
                    height,
                    view.filtered.len(),
                    |ui, range| {
                        for index in range {
                            let row_index = view.filtered[index];
                            let row = &view.inventory.rows()[row_index];
                            ui.horizontal(|ui| {
                                if ui.selectable_label(view.selected == Some(row_index), &row.address).clicked() {
                                    view.selected = Some(row_index);
                                }
                                ui.add(egui::Label::new(&row.name).truncate());
                                ui.label(format!(
                                    "historical: {} bytes, {} blocks, {} instructions",
                                    row.size, row.block_count, row.instruction_count,
                                ));
                            });
                        }
                    },
                );
                inspect = ui
                    .add_enabled(
                        view.selected.is_some() && view_state == BindingState::Current,
                        egui::Button::new("Inspect raw cached address — unverified"),
                    )
                    .clicked();
                egui::CollapsingHeader::new("Dependency key (consistency only, never authentication)").show(ui, |ui| {
                    ui.monospace(format!("{:?}", view.inventory.key()));
                });
            }
            if let Some(message) = &self.cached_inventory.message {
                ui.label(message);
            }
            inventory_publications(ui, self.project_workspace_save_notices());
        });
        self.cached_inventory.shown = shown;
        if !shown {
            self.close_cached_inventory();
        }
        if let Some(action) = path_action {
            self.cached_inventory.dialog =
                Some(PathDialog { action, module_id: self.cached_inventory.module_id.clone() });
            self.cached_inventory.path.clear();
        }
        if inspect && let Err(error) = self.inspect_cached_inventory_address() {
            self.cached_inventory.message = Some(error);
        }
        self.inventory_path_window(ctx);
    }

    fn inventory_path_window(&mut self, ctx: &egui::Context) {
        let Some(dialog) = &self.cached_inventory.dialog else { return };
        let module_id = dialog.module_id.clone();
        let action = dialog.action;
        let (title, button) = match action {
            PathAction::Save => ("Save historical inventory cache", "Publish completed inventory cache"),
            PathAction::Load => ("Load historical inventory cache", "Load selected inventory cache"),
        };
        let mut shown = true;
        let mut submit = false;
        egui::Window::new(title).open(&mut shown).collapsible(false).show(ctx, |ui| {
            ui.label(format!("Current source module: {module_id}"));
            ui.label(
                "Choose an explicit path. Save requires a new filename in a private directory; no files are replaced.",
            );
            let label = ui.label("Inventory cache path");
            ui.add(egui::TextEdit::singleline(&mut self.cached_inventory.path).char_limit(4096)).labelled_by(label.id);
            submit = ui.add_enabled(!self.cached_inventory.path.is_empty(), egui::Button::new(button)).clicked();
        });
        if submit {
            let path = PathBuf::from(&self.cached_inventory.path);
            let result = match action {
                PathAction::Save => self.begin_inventory_cache_save(ctx, &module_id, path),
                PathAction::Load => self.begin_inventory_cache_load(ctx, &module_id, path),
            };
            match result {
                Ok(()) => shown = false,
                Err(error) => self.cached_inventory.message = Some(error),
            }
        }
        if !shown {
            self.cached_inventory.dialog = None;
        }
    }
}

fn publication_message(result: Result<ProjectWorkspacePublication, ApiError>) -> Result<String, String> {
    result.map_err(|error| error.to_string()).map(|publication| match publication.status {
        DebuggerCapturePublicationStatus::Published => "Historical inventory cache published; not loaded.".to_owned(),
        DebuggerCapturePublicationStatus::PublishedUncertain => {
            "Inventory publication uncertain. Inspect every retained destination and staging path.".to_owned()
        }
    })
}

fn inventory_publications(ui: &mut egui::Ui, notices: &[ProjectWorkspaceSaveNotice]) {
    if notices.is_empty() {
        return;
    }
    egui::CollapsingHeader::new("Retained publication notices (workspace and inventory)").default_open(true).show(
        ui,
        |ui| {
            for notice in notices {
                match notice {
                    ProjectWorkspaceSaveNotice::Publication(publication) => {
                        ui.label(format!("{:?}: {}", publication.status, publication.path.display()));
                        ui.monospace(&publication.document_sha256);
                        for warning in &publication.warnings {
                            ui.label(egui::RichText::new(warning).color(theme::WARNING));
                        }
                        for path in &publication.retained_staging_paths {
                            ui.label(format!("Retained staging: {}", path.display()));
                        }
                    }
                    ProjectWorkspaceSaveNotice::Failure { requested, message, retained_paths } => {
                        ui.label(format!("Publication failed: {}", requested.display()));
                        ui.label(message);
                        for path in retained_paths {
                            ui.label(format!("Retained staging: {}", path.display()));
                        }
                    }
                }
            }
            ui.label("Sensitive paths require explicit inspection. Nothing is deleted or retried automatically.");
        },
    );
}

#[cfg(test)]
mod tests;
