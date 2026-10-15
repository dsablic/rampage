//! Explicit module retention. The active workspace remains in App for legacy callers.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use rampage_api::{
    ApiError, DebuggerCapturePublicationStatus, DecompilerConfigurationRevision, LoadedProjectWorkspace,
    ProjectWorkspaceManifest, ProjectWorkspaceModuleInput, ProjectWorkspaceNavigation, ProjectWorkspacePreview,
    ProjectWorkspacePublication, QualifiedProjectAddress,
};
use rampage_arch::Arch;
use rampage_loaders::ImageAt;

use crate::{App, Workspace, debug_layout, theme};

const MAX_MODULES: usize = 8;

#[derive(Clone, Copy, Debug)]
struct EditorIdentity(u64);

impl Default for EditorIdentity {
    fn default() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let identity = NEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| next.checked_add(1))
            .expect("annotation editor identity exhausted");
        Self(identity)
    }
}

fn issued_module_ids() -> &'static Mutex<HashSet<String>> {
    static ISSUED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    ISSUED.get_or_init(|| Mutex::new(HashSet::new()))
}

#[derive(Clone, Debug)]
pub struct ModuleInfo {
    pub id: String,
    pub label: String,
    pub path: PathBuf,
    pub arch: Option<Arch>,
    pub image: Option<ImageAt>,
    /// Deduplication only; persistence still validates the actual project's current source and retained descriptor.
    canonical_source: PathBuf,
    editor_identity: EditorIdentity,
}

impl ModuleInfo {
    fn new(workspace: &Workspace, canonical_source: PathBuf) -> Self {
        static NAMESPACE: OnceLock<String> = OnceLock::new();
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let namespace = NAMESPACE.get_or_init(|| {
            let started = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock before Unix epoch");
            format!("{:x}-{:x}", std::process::id(), started.as_nanos())
        });
        let mut issued = issued_module_ids().lock().expect("module identity registry");
        let id = loop {
            let token = NEXT
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| next.checked_add(1))
                .expect("module identity exhausted");
            let id = format!("module-{namespace}-{token:x}");
            if issued.insert(id.clone()) {
                break id;
            }
        };
        Self {
            label: id.clone(),
            id,
            path: workspace.path.clone(),
            arch: Some(workspace.project.binary.arch),
            image: workspace.image,
            canonical_source,
            editor_identity: EditorIdentity::default(),
        }
    }
}

pub(crate) struct RetainedModule {
    pub(crate) info: ModuleInfo,
    pub(crate) workspace: Workspace,
}

#[derive(Clone, Debug)]
pub enum ProjectWorkspaceSaveNotice {
    Publication(ProjectWorkspacePublication),
    Failure { requested: PathBuf, message: String, retained_paths: Vec<PathBuf> },
}

struct ModuleBinding {
    id: String,
    instance: Arc<()>,
    annotations_epoch: Arc<()>,
    configuration: DecompilerConfigurationRevision,
    navigation: (u64, Vec<u64>, Vec<u64>),
    annotations: Vec<(rampage_api::annotations::Field, u64, String)>,
}

struct BankBinding {
    generation: Arc<()>,
    modules: Vec<ModuleBinding>,
}

struct ReviewedWorkspace {
    preview: ProjectWorkspacePreview,
    binding: BankBinding,
}

#[derive(Clone, Copy)]
pub(crate) enum OpenPathAction {
    ReplaceExact,
    Add,
    AddExact,
    SaveWorkspace,
    PreviewWorkspace,
}

#[derive(Default)]
pub(crate) struct WorkspaceBank {
    pub(crate) active: Option<ModuleInfo>,
    pub(crate) inactive: Vec<RetainedModule>,
    pub(crate) generation: Arc<()>,
    shown: bool,
    open_path: Option<OpenPathAction>,
    path_text: String,
    navigation_module: String,
    navigation_address: String,
    review: Option<ReviewedWorkspace>,
    save_notices: Vec<ProjectWorkspaceSaveNotice>,
    fallback_editor_identity: EditorIdentity,
}

fn annotation_snapshot(workspace: &Workspace) -> Vec<(rampage_api::annotations::Field, u64, String)> {
    use rampage_api::annotations::Field;
    let rows = workspace.project.annotation_list();
    [
        (Field::Name, rows.names),
        (Field::Comment, rows.comments),
        (Field::Signature, rows.signatures),
        (Field::Types, rows.types),
        (Field::Global, rows.globals),
    ]
    .into_iter()
    .flat_map(|(field, rows)| rows.into_iter().map(move |row| (field, row.address, row.text)))
    .collect()
}

fn source_path(workspace: &Workspace) -> Result<PathBuf, String> {
    workspace
        .project
        .binary
        .backing_path()
        .unwrap_or(&workspace.path)
        .canonicalize()
        .map_err(|error| format!("Cannot resolve the module's explicit source: {error}"))
}

impl BankBinding {
    fn capture(app: &App) -> Result<Self, String> {
        let modules = app
            .bank_workspaces()
            .map(|(info, workspace)| {
                Ok(ModuleBinding {
                    id: info.id.clone(),
                    instance: Arc::clone(&workspace.instance),
                    annotations_epoch: Arc::clone(&workspace.annotations_epoch),
                    configuration: workspace.project.decompiler_configuration_revision().map_err(|e| e.to_string())?,
                    navigation: workspace.navigation_snapshot(),
                    annotations: annotation_snapshot(workspace),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self { generation: Arc::clone(&app.workspace_bank.generation), modules })
    }

    fn matches(&self, app: &App) -> bool {
        Arc::ptr_eq(&self.generation, &app.workspace_bank.generation)
            && app.bank_workspaces().count() == self.modules.len()
            && app.bank_workspaces().zip(&self.modules).all(|((info, workspace), binding)| {
                info.id == binding.id
                    && Arc::ptr_eq(&workspace.instance, &binding.instance)
                    && Arc::ptr_eq(&workspace.annotations_epoch, &binding.annotations_epoch)
                    && workspace.navigation_snapshot() == binding.navigation
                    && annotation_snapshot(workspace) == binding.annotations
                    && workspace
                        .project
                        .decompiler_configuration_revision()
                        .is_ok_and(|revision| revision == binding.configuration)
            })
    }
}

impl App {
    pub(crate) fn annotation_editor_scope(&self) -> egui::Id {
        let identity = self
            .workspace_bank
            .active
            .as_ref()
            .map_or(self.workspace_bank.fallback_editor_identity, |module| module.editor_identity);
        egui::Id::new(("annotation-editor", identity.0))
    }

    fn bank_workspaces(&self) -> impl Iterator<Item = (&ModuleInfo, &Workspace)> {
        self.workspace_bank
            .active
            .as_ref()
            .zip(self.workspace.as_ref())
            .into_iter()
            .chain(self.workspace_bank.inactive.iter().map(|module| (&module.info, &module.workspace)))
    }

    fn bank_changed(&mut self) {
        self.workspace_bank.generation = Arc::new(());
        self.workspace_bank.review = None;
    }

    /// Captures source identities and navigation only on an explicit action, never while rendering.
    pub fn capture_project_workspace(&self) -> Result<ProjectWorkspaceManifest, String> {
        self.ensure_bank_replaceable()?;
        let active = self.active_module_id().ok_or_else(|| "No module is open.".to_owned())?;
        let inputs = self
            .bank_workspaces()
            .map(|(info, workspace)| {
                let (cursor, back, forward) = workspace.navigation_snapshot();
                let qualified = |address| QualifiedProjectAddress { module_id: info.id.clone(), address };
                Ok(ProjectWorkspaceModuleInput {
                    id: info.id.clone(),
                    label: info.label.clone(),
                    source_path: source_path(workspace)?,
                    image: workspace.image,
                    project: Arc::clone(&workspace.project),
                    navigation: ProjectWorkspaceNavigation {
                        current: Some(qualified(cursor)),
                        back: back.into_iter().map(&qualified).collect(),
                        forward: forward.into_iter().map(qualified).collect(),
                    },
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        rampage_api::capture_project_workspace_with_session(&inputs, active, &self.session)
            .map_err(|error| error.to_string())
    }

    /// Publishes without clobbering. Receipts disclose resources; they never authorize opening a workspace.
    pub fn save_project_workspace(&mut self, output: PathBuf) -> Result<ProjectWorkspacePublication, String> {
        let binding = BankBinding::capture(self)?;
        let manifest = self.capture_project_workspace()?;
        if !binding.matches(self) {
            return Err("Workspace changed during capture. Nothing was published; capture again.".to_owned());
        }
        let result = rampage_api::publish_project_workspace(&manifest, &output);
        self.finish_workspace_save(&binding, output, result)
    }

    fn finish_workspace_save(
        &mut self,
        binding: &BankBinding,
        output: PathBuf,
        result: Result<ProjectWorkspacePublication, ApiError>,
    ) -> Result<ProjectWorkspacePublication, String> {
        match &result {
            Ok(publication) => {
                self.workspace_bank.save_notices.push(ProjectWorkspaceSaveNotice::Publication(publication.clone()));
            }
            Err(error) => {
                let retained_paths = match error {
                    ApiError::DebuggerCaptureStagingRetained(retention) => retention.paths.clone(),
                    _ => Vec::new(),
                };
                self.workspace_bank.save_notices.push(ProjectWorkspaceSaveNotice::Failure {
                    requested: output,
                    message: error.to_string(),
                    retained_paths,
                });
            }
        }
        if !binding.matches(self) || self.ensure_bank_replaceable().is_err() {
            return Err("Workspace changed during save. Inspect the retained publication notices below.".to_owned());
        }
        result.map_err(|error| error.to_string())
    }

    pub fn project_workspace_save_notices(&self) -> &[ProjectWorkspaceSaveNotice] {
        &self.workspace_bank.save_notices
    }

    /// Reads only the manifest. Sources and recognized annotation logs require separate reviewed approval.
    pub fn preview_project_workspace(&mut self, path: PathBuf) -> Result<(), String> {
        self.workspace_bank.review = None;
        let binding = BankBinding::capture(self)?;
        let preview = rampage_api::preview_project_workspace(&path).map_err(|error| error.to_string())?;
        self.workspace_bank.review = Some(ReviewedWorkspace { preview, binding });
        self.workspace_bank.shown = true;
        self.error = None;
        Ok(())
    }

    pub fn reviewed_project_workspace(&self) -> Option<&ProjectWorkspaceManifest> {
        self.workspace_bank.review.as_ref().map(|review| review.preview.manifest())
    }

    pub fn open_reviewed_project_workspace(&mut self, ctx: &egui::Context) -> Result<(), String> {
        self.ensure_bank_replaceable()?;
        let review = self
            .workspace_bank
            .review
            .take()
            .ok_or_else(|| "Preview a workspace file before approving it.".to_owned())?;
        if !review.binding.matches(self) {
            return Err("The current workspace changed since preview. Preview again before opening.".to_owned());
        }
        let loaded = review.preview.open_reviewed(&self.session).map_err(|error| error.to_string())?;
        self.adopt_project_workspace(ctx, &review.binding, loaded)
    }

    fn adopt_project_workspace(
        &mut self,
        ctx: &egui::Context,
        binding: &BankBinding,
        loaded: LoadedProjectWorkspace,
    ) -> Result<(), String> {
        self.ensure_bank_replaceable()?;
        if !binding.matches(self) {
            return Err("Workspace changed while loading. The original modules remain open.".to_owned());
        }
        loaded.validate().map_err(|error| error.to_string())?;
        let mut staged = Vec::with_capacity(loaded.modules().len());
        for module in loaded.modules() {
            let data = module.module();
            let image = data.image.map(|image| ImageAt::new(image.offset, image.length));
            let mut workspace = Workspace::from_loaded_project(
                data.source_path.clone(),
                image,
                Arc::clone(module.project()),
                ctx,
                self.blocking,
                true,
            );
            let cursor = data.navigation.current.as_ref().map_or(workspace.cursor, |current| current.address);
            workspace.restore_navigation(
                cursor,
                data.navigation.back.iter().map(|address| address.address).collect(),
                data.navigation.forward.iter().map(|address| address.address).collect(),
            );
            self.prepare_workspace(&mut workspace);
            let info = ModuleInfo {
                id: data.id.clone(),
                label: data.label.clone(),
                path: data.source_path.clone(),
                arch: Some(workspace.project.binary.arch),
                image,
                canonical_source: source_path(&workspace)?,
                editor_identity: EditorIdentity::default(),
            };
            staged.push(RetainedModule { info, workspace });
        }
        let active_index = staged
            .iter()
            .position(|module| module.info.id == loaded.active_module_id())
            .ok_or_else(|| "The reviewed active module was not loaded.".to_owned())?;
        loaded.validate().map_err(|error| error.to_string())?;
        self.ensure_bank_replaceable()?;
        if !binding.matches(self) {
            return Err("Workspace changed before adoption. The original modules remain open.".to_owned());
        }
        issued_module_ids()
            .lock()
            .expect("module identity registry")
            .extend(staged.iter().map(|module| module.info.id.clone()));
        let active = staged.remove(active_index);
        let (_, _, session) = loaded.into_parts();
        self.deactivate_bank();
        self.session = session;
        self.workspace = Some(active.workspace);
        self.workspace_bank.active = Some(active.info);
        self.workspace_bank.inactive = staged;
        self.bank_changed();
        self.carve = None;
        self.error = None;
        Ok(())
    }

    pub fn modules(&self) -> Vec<ModuleInfo> {
        self.workspace_bank
            .active
            .iter()
            .chain(self.workspace_bank.inactive.iter().map(|module| &module.info))
            .cloned()
            .collect()
    }

    pub fn active_module_id(&self) -> Option<&str> {
        self.workspace_bank.active.as_ref().map(|module| module.id.as_str())
    }

    pub fn show_project_workspace(&mut self) {
        self.workspace_bank.shown = true;
    }

    pub(crate) fn ensure_bank_replaceable(&self) -> Result<(), String> {
        let editing = self.workspace.as_ref().is_some_and(|workspace| workspace.editing.is_some())
            || self.workspace_bank.inactive.iter().any(|module| module.workspace.editing.is_some());
        if editing {
            return Err("Finish or cancel every module's unsaved editor before replacing the workspace.".to_owned());
        }
        Ok(())
    }

    pub(crate) fn prepare_workspace(&self, workspace: &mut Workspace) {
        workspace.debug_layout = debug_layout::DebugLayouts::with_gate(self.debug_layout_gate.clone());
        workspace.set_entry_gate(self.entry_gate.clone());
    }

    pub(crate) fn deactivate_bank(&mut self) {
        if let Some(workspace) = &mut self.workspace {
            workspace.deactivate();
        }
        for module in &mut self.workspace_bank.inactive {
            module.workspace.deactivate();
        }
        self.debugger.invalidate_workspace();
    }

    pub(crate) fn replace_workspace(&mut self, mut workspace: Workspace) -> Result<(), String> {
        let canonical_source = source_path(&workspace)?;
        self.prepare_workspace(&mut workspace);
        self.deactivate_bank();
        self.workspace_bank.inactive.clear();
        self.workspace_bank.active = Some(ModuleInfo::new(&workspace, canonical_source));
        self.bank_changed();
        self.workspace = Some(workspace);
        Ok(())
    }

    /// Opens only the selected image, without carving or starting global analysis.
    pub fn open_exact_at(
        &mut self,
        ctx: &egui::Context,
        path: PathBuf,
        arch: Option<Arch>,
        image: Option<ImageAt>,
    ) -> Result<(), String> {
        self.ensure_bank_replaceable()?;
        let mut workspace = Workspace::open_exact(&self.session, path, arch, image, ctx, self.blocking)?;
        workspace.show_entry_decompilation();
        self.replace_workspace(workspace)?;
        self.carve = None;
        self.error = None;
        Ok(())
    }

    /// Adds a deferred module and retains the actual current workspace, including unsaved editors.
    pub fn add_module_at(
        &mut self,
        ctx: &egui::Context,
        path: PathBuf,
        arch: Option<Arch>,
        image: Option<ImageAt>,
    ) -> Result<String, String> {
        let image = image.filter(|image| !image.is_whole_file());
        if self.modules().iter().any(|module| {
            module.path == path && arch.is_none_or(|arch| module.arch == Some(arch)) && module.image == image
        }) {
            return Err("That path, architecture and image is already open. Select its module explicitly.".to_owned());
        }
        if self.modules().len() >= MAX_MODULES {
            return Err(
                "A project workspace can contain at most eight modules. Close one before adding another.".into()
            );
        }
        let proposed = path.canonicalize().map_err(|error| error.to_string())?;
        for (info, existing) in self.bank_workspaces() {
            if arch.is_none_or(|arch| existing.project.binary.arch == arch)
                && existing.image == image
                && info.canonical_source == proposed
            {
                return Err("That canonical source, architecture and image is already open. Select its module.".into());
            }
        }
        let mut workspace = Workspace::open_exact(&self.session, path, arch, image, ctx, self.blocking)?;
        let canonical = source_path(&workspace)?;
        for (info, existing) in self.bank_workspaces() {
            if existing.project.binary.arch == workspace.project.binary.arch
                && existing.image == image
                && info.canonical_source == canonical
            {
                return Err("That resolved source, architecture and image is already open. Select its module.".into());
            }
        }
        self.prepare_workspace(&mut workspace);
        let info = ModuleInfo::new(&workspace, canonical);
        let id = info.id.clone();
        if let Some(mut old) = self.workspace.take() {
            old.deactivate();
            let old_info = self.workspace_bank.active.take().expect("active module identity");
            self.workspace_bank.inactive.push(RetainedModule { info: old_info, workspace: old });
        }
        self.debugger.invalidate_workspace();
        self.workspace_bank.active = Some(info);
        self.bank_changed();
        self.workspace = Some(workspace);
        self.carve = None;
        self.error = None;
        Ok(id)
    }

    pub fn add_module_exact_at(
        &mut self,
        ctx: &egui::Context,
        path: PathBuf,
        arch: Option<Arch>,
        image: Option<ImageAt>,
    ) -> Result<String, String> {
        let id = self.add_module_at(ctx, path, arch, image)?;
        self.workspace.as_mut().expect("added workspace").show_entry_decompilation();
        Ok(id)
    }

    /// Switches by stable identity without opening a file or querying analysis.
    pub fn select_module(&mut self, id: &str) -> Result<(), String> {
        if self.active_module_id() == Some(id) {
            return Ok(());
        }
        let index = self
            .workspace_bank
            .inactive
            .iter()
            .position(|module| module.info.id == id)
            .ok_or_else(|| "The selected module is no longer in this workspace.".to_owned())?;
        if let Some(workspace) = &mut self.workspace {
            workspace.deactivate();
        }
        let next = self.workspace_bank.inactive.remove(index);
        if let Some(workspace) = self.workspace.take() {
            let info = self.workspace_bank.active.take().expect("active module identity");
            self.workspace_bank.inactive.push(RetainedModule { info, workspace });
        }
        self.workspace = Some(next.workspace);
        self.workspace_bank.active = Some(next.info);
        self.bank_changed();
        self.debugger.invalidate_workspace();
        self.carve = None;
        Ok(())
    }

    pub fn close_module(&mut self, id: &str) -> Result<(), String> {
        if self.active_module_id() == Some(id) {
            if self.workspace.as_ref().is_some_and(|workspace| workspace.editing.is_some()) {
                return Err("Finish or cancel this module's unsaved editor before closing it.".to_owned());
            }
            if let Some(workspace) = &mut self.workspace {
                workspace.deactivate();
            }
            let next = self.workspace_bank.inactive.pop();
            self.workspace_bank.active = next.as_ref().map(|module| module.info.clone());
            self.workspace = next.map(|module| module.workspace);
            self.debugger.invalidate_workspace();
            self.carve = None;
        } else {
            let index = self
                .workspace_bank
                .inactive
                .iter()
                .position(|module| module.info.id == id)
                .ok_or_else(|| "The selected module is no longer in this workspace.".to_owned())?;
            if self.workspace_bank.inactive[index].workspace.editing.is_some() {
                return Err("Finish or cancel this module's unsaved editor before closing it.".to_owned());
            }
            self.workspace_bank.inactive[index].workspace.deactivate();
            self.workspace_bank.inactive.remove(index);
        }
        self.bank_changed();
        Ok(())
    }

    pub fn close_workspace(&mut self) -> Result<(), String> {
        self.ensure_bank_replaceable()?;
        self.deactivate_bank();
        self.workspace = None;
        self.workspace_bank.active = None;
        self.workspace_bank.inactive.clear();
        self.bank_changed();
        self.carve = None;
        Ok(())
    }

    pub(crate) fn show_open_path(&mut self, action: OpenPathAction) {
        self.workspace_bank.open_path = Some(action);
        self.workspace_bank.path_text.clear();
    }

    pub(crate) fn open_path_window(&mut self, ctx: &egui::Context) {
        let Some(action) = self.workspace_bank.open_path else { return };
        let title = match action {
            OpenPathAction::ReplaceExact => "Open for exact-entry",
            OpenPathAction::Add => "Add module",
            OpenPathAction::AddExact => "Add module for exact-entry",
            OpenPathAction::SaveWorkspace => "Save project workspace",
            OpenPathAction::PreviewWorkspace => "Preview project workspace",
        };
        let (description, label, button) = match action {
            OpenPathAction::SaveWorkspace => (
                "Use a new filename in a private directory. Existing files are never overwritten.",
                "Workspace output path",
                "Save workspace file",
            ),
            OpenPathAction::PreviewWorkspace => (
                "Preview reads the manifest only. Opening its sources requires separate approval.",
                "Workspace manifest path",
                "Preview workspace file",
            ),
            _ => (
                "Source file path (whole image; no carving or global analysis)",
                "Full source path",
                "Open selected path",
            ),
        };
        let mut shown = true;
        let mut open = false;
        egui::Window::new(title).open(&mut shown).collapsible(false).show(ctx, |ui| {
            ui.label(description);
            let label = ui.label(label);
            ui.add(egui::TextEdit::singleline(&mut self.workspace_bank.path_text)).labelled_by(label.id);
            open = ui.add_enabled(!self.workspace_bank.path_text.is_empty(), egui::Button::new(button)).clicked();
        });
        if open {
            let path = PathBuf::from(&self.workspace_bank.path_text);
            let result = match action {
                OpenPathAction::ReplaceExact => self.open_exact_at(ctx, path, None, None),
                OpenPathAction::Add => self.add_module_at(ctx, path, None, None).map(|_| ()),
                OpenPathAction::AddExact => self.add_module_exact_at(ctx, path, None, None).map(|_| ()),
                OpenPathAction::SaveWorkspace => self.save_project_workspace(path).map(|publication| {
                    self.error = match publication.status {
                        DebuggerCapturePublicationStatus::Published => None,
                        DebuggerCapturePublicationStatus::PublishedUncertain => Some(
                            "Publication is uncertain. Inspect every reported destination and staging path.".to_owned(),
                        ),
                    };
                }),
                OpenPathAction::PreviewWorkspace => self.preview_project_workspace(path),
            };
            match result {
                Ok(()) => shown = false,
                Err(error) => self.error = Some(error),
            }
        }
        if !shown {
            self.workspace_bank.open_path = None;
        }
    }

    pub(crate) fn module_selector(&mut self, ui: &mut egui::Ui) {
        let modules = self.modules();
        if modules.len() <= 1 {
            return;
        }
        let active = self.active_module_id().unwrap_or_default().to_owned();
        let mut selected = active.clone();
        egui::ComboBox::from_id_salt("workspace-module-selector").selected_text(&active).show_ui(ui, |ui| {
            for module in modules {
                ui.selectable_value(&mut selected, module.id.clone(), &module.id)
                    .on_hover_text(module.path.display().to_string());
            }
        });
        if selected != active
            && let Err(error) = self.select_module(&selected)
        {
            self.error = Some(error);
        }
    }

    pub(crate) fn project_workspace_window(&mut self, ctx: &egui::Context) {
        if !self.workspace_bank.shown {
            return;
        }
        let mut shown = true;
        let mut select = None;
        let mut close = None;
        let mut close_all = false;
        let mut open_path = None;
        let mut navigate = false;
        let mut open_reviewed = false;
        let active = self.active_module_id().map(str::to_owned);
        let modules = self.modules();
        let replaceable = self.ensure_bank_replaceable().is_ok();
        egui::Window::new("Project workspace").open(&mut shown).show(ctx, |ui| {
            ui.label(format!("{} / {MAX_MODULES} modules", modules.len()));
            ui.label("Module selection retains navigation, filters, annotations and unsaved editors.");
            for module in &modules {
                ui.horizontal(|ui| {
                    if ui.selectable_label(active.as_deref() == Some(module.id.as_str()), &module.id).clicked() {
                        select = Some(module.id.clone());
                    }
                    ui.label(module.path.display().to_string());
                    if let Some(image) = module.image {
                        ui.monospace(format!("image @ {:#x}", image.offset()));
                    }
                    if ui.button(format!("Close {}", module.id)).clicked() {
                        close = Some(module.id.clone());
                    }
                });
            }
            ui.horizontal(|ui| {
                if ui.add_enabled(modules.len() < MAX_MODULES, egui::Button::new("Add module…")).clicked() {
                    open_path = Some(OpenPathAction::Add);
                }
                if ui
                    .add_enabled(modules.len() < MAX_MODULES, egui::Button::new("Add module for exact-entry…"))
                    .clicked()
                {
                    open_path = Some(OpenPathAction::AddExact);
                }
                close_all = ui.add_enabled(!modules.is_empty(), egui::Button::new("Close workspace")).clicked();
            });
            ui.horizontal(|ui| {
                if ui.add_enabled(!modules.is_empty() && replaceable, egui::Button::new("Save workspace…")).clicked()
                {
                    open_path = Some(OpenPathAction::SaveWorkspace);
                }
                if ui.button("Preview workspace file…").clicked() {
                    open_path = Some(OpenPathAction::PreviewWorkspace);
                }
            });
            if let Some(review) = &self.workspace_bank.review {
                ui.separator();
                ui.heading("Reviewed workspace manifest");
                ui.label(format!("Document SHA-256: {}", review.preview.document_sha256()));
                ui.label(format!("Active module: {}", review.preview.manifest().active_module_id));
                egui::ScrollArea::vertical().id_salt("workspace-manifest-review").max_height(260.0).show(ui, |ui| {
                    for module in &review.preview.manifest().modules {
                        ui.group(|ui| {
                            ui.label(format!("Module ID: {}", module.id));
                            ui.label(format!("Label: {}", module.label));
                            ui.label(format!("Source: {}", module.source_path.display()));
                            ui.label(format!("Source SHA-256: {}", module.identity.source_sha256));
                            ui.label(format!("Image SHA-256: {}", module.identity.image_sha256));
                            if let Some(context) = &module.annotation_context_sha256 {
                                ui.label(format!("Annotation context SHA-256: {context}"));
                            }
                            ui.label(format!("{} / {}", module.identity.format, module.identity.architecture));
                            ui.label(format!("Image selection: {:?}", module.image));
                            ui.label(format!("Decompiler options: {:?}", module.options));
                            if let Some(address) = &module.navigation.current {
                                ui.label(format!("Cursor: {} @ {:#x}", address.module_id, address.address));
                            }
                        });
                    }
                });
                ui.label(review.preview.annotation_review());
                open_reviewed = ui
                    .add_enabled(replaceable, egui::Button::new("Open reviewed workspace"))
                    .on_hover_text("Replaces all modules only after every source and recognized annotation log loads")
                    .clicked();
            }
            if !self.workspace_bank.save_notices.is_empty() {
                ui.separator();
                egui::CollapsingHeader::new("Workspace publication notices (retained across module changes)")
                    .default_open(true)
                    .show(ui, |ui| {
                        for notice in &self.workspace_bank.save_notices {
                            match notice {
                                ProjectWorkspaceSaveNotice::Publication(publication) => {
                                    let (status, color) = match publication.status {
                                        DebuggerCapturePublicationStatus::Published => {
                                            ("Published document; not loaded or authorized to open", theme::DIM)
                                        }
                                        DebuggerCapturePublicationStatus::PublishedUncertain => (
                                            "Publication uncertain; destination may exist. Inspect explicitly",
                                            theme::WARNING,
                                        ),
                                    };
                                    ui.label(egui::RichText::new(status).color(color));
                                    ui.label(publication.path.display().to_string());
                                    ui.monospace(&publication.document_sha256);
                                    for warning in &publication.warnings {
                                        ui.label(egui::RichText::new(warning).color(theme::WARNING));
                                    }
                                    retained_paths_ui(ui, &publication.retained_staging_paths);
                                }
                                ProjectWorkspaceSaveNotice::Failure { requested, message, retained_paths } => {
                                    ui.label(format!("Publication failed: {}", requested.display()));
                                    ui.label(egui::RichText::new(message).color(theme::WARNING));
                                    retained_paths_ui(ui, retained_paths);
                                }
                            }
                        }
                    });
            }
            ui.separator();
            ui.label("Qualified navigation (explicit module ID and hexadecimal address)");
            let label = ui.label("Navigation module ID");
            ui.add(egui::TextEdit::singleline(&mut self.workspace_bank.navigation_module)).labelled_by(label.id);
            let label = ui.label("Navigation hex address");
            ui.add(egui::TextEdit::singleline(&mut self.workspace_bank.navigation_address)).labelled_by(label.id);
            navigate = ui.button("Go to module address").clicked();
            if let Some(error) = &self.error {
                ui.label(egui::RichText::new(error).color(theme::WARNING));
            }
        });
        self.workspace_bank.shown = shown;
        let result = if let Some(id) = select {
            self.select_module(&id)
        } else if let Some(id) = close {
            self.close_module(&id)
        } else if close_all {
            self.close_workspace()
        } else if navigate {
            self.navigate_module_address()
        } else if open_reviewed {
            self.open_reviewed_project_workspace(ctx)
        } else {
            Ok(())
        };
        if let Err(error) = result {
            self.error = Some(error);
        }
        if let Some(action) = open_path {
            self.show_open_path(action);
        }
    }

    fn navigate_module_address(&mut self) -> Result<(), String> {
        let text = self.workspace_bank.navigation_address.trim();
        let address = u64::from_str_radix(text.strip_prefix("0x").unwrap_or(text), 16)
            .map_err(|_| "Enter a hexadecimal address; names do not cross module boundaries.".to_owned())?;
        let id = self.workspace_bank.navigation_module.trim().to_owned();
        self.select_module(&id)?;
        self.workspace.as_mut().expect("selected workspace").goto(address);
        Ok(())
    }
}

fn retained_paths_ui(ui: &mut egui::Ui, paths: &[PathBuf]) {
    for path in paths {
        ui.label(egui::RichText::new(format!("Retained staging: {}", path.display())).color(theme::WARNING));
    }
    if !paths.is_empty() {
        ui.label("Sensitive paths require explicit operator inspection. No file will be deleted automatically.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Sources(PathBuf);

    impl Sources {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let token = NEXT.fetch_add(1, Ordering::Relaxed);
            let directory =
                std::env::temp_dir().join(format!("rampage-ui-bank-lifecycle-{}-{token}", std::process::id()));
            std::fs::create_dir(&directory).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
            for name in ["a.elf", "b.elf"] {
                std::fs::copy(&source, directory.join(name)).unwrap();
            }
            Self(directory)
        }
    }

    impl Drop for Sources {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn same_frame_aba_switch_rotates_activation_and_bank_review_tokens() {
        let sources = Sources::new();
        let ctx = egui::Context::default();
        let mut app = App::blocking();
        let a = app.add_module_at(&ctx, sources.0.join("a.elf"), None, None).unwrap();
        let a_instance = Arc::clone(&app.workspace.as_ref().unwrap().instance);
        let a_project = Arc::clone(&app.workspace.as_ref().unwrap().project);
        let b = app.add_module_at(&ctx, sources.0.join("b.elf"), None, None).unwrap();
        let b_instance = Arc::clone(&app.workspace.as_ref().unwrap().instance);
        let review_generation = Arc::clone(&app.workspace_bank.generation);
        app.select_module(&a).unwrap();
        app.select_module(&b).unwrap();
        assert!(!Arc::ptr_eq(&review_generation, &app.workspace_bank.generation));
        assert!(!Arc::ptr_eq(&b_instance, &app.workspace.as_ref().unwrap().instance));
        app.select_module(&a).unwrap();
        let workspace = app.workspace.as_ref().unwrap();
        assert!(!Arc::ptr_eq(&a_instance, &workspace.instance));
        assert!(Arc::ptr_eq(&a_project, &workspace.project));
        assert!(workspace.analysis_deferred());
        assert!(matches!(workspace.functions, crate::workspace::Job::Idle));
        assert!(workspace.listing.is_none());
        assert!(workspace.xrefs.is_none());
    }

    #[test]
    fn replacement_and_close_invalidate_bank_review_tokens() {
        let sources = Sources::new();
        let ctx = egui::Context::default();
        let mut app = App::blocking();
        app.add_module_at(&ctx, sources.0.join("a.elf"), None, None).unwrap();
        let old_generation = Arc::clone(&app.workspace_bank.generation);
        app.open_exact_at(&ctx, sources.0.join("b.elf"), None, None).unwrap();
        assert!(!Arc::ptr_eq(&old_generation, &app.workspace_bank.generation));
        let old_generation = Arc::clone(&app.workspace_bank.generation);
        app.close_workspace().unwrap();
        assert!(!Arc::ptr_eq(&old_generation, &app.workspace_bank.generation));
        assert!(app.workspace.is_none());
    }

    #[test]
    fn adoption_uses_exact_loaded_arcs_and_rejects_an_aba_stale_candidate() {
        let sources = Sources::new();
        let ctx = egui::Context::default();
        let mut app = App::blocking();
        let a = app.add_module_at(&ctx, sources.0.join("a.elf"), None, None).unwrap();
        let b = app.add_module_at(&ctx, sources.0.join("b.elf"), None, None).unwrap();
        let output = sources.0.join("project-workspace.json");
        app.save_project_workspace(output.clone()).unwrap();
        let preview = rampage_api::preview_project_workspace(&output).unwrap();
        let loaded = preview.open_reviewed(&app.session).unwrap();
        let expected = loaded
            .modules()
            .iter()
            .map(|module| (module.module().id.clone(), Arc::clone(module.project())))
            .collect::<Vec<_>>();
        let binding = BankBinding::capture(&app).unwrap();
        app.adopt_project_workspace(&ctx, &binding, loaded).unwrap();
        for (id, project) in expected {
            app.select_module(&id).unwrap();
            assert!(Arc::ptr_eq(&project, &app.workspace.as_ref().unwrap().project));
            assert!(app.workspace.as_ref().unwrap().analysis_deferred());
        }

        app.select_module(&b).unwrap();
        let binding = BankBinding::capture(&app).unwrap();
        let loaded = preview.open_reviewed(&app.session).unwrap();
        let old_project = Arc::clone(&app.workspace.as_ref().unwrap().project);
        app.select_module(&a).unwrap();
        app.select_module(&b).unwrap();
        assert!(app.adopt_project_workspace(&ctx, &binding, loaded).is_err());
        assert!(Arc::ptr_eq(&old_project, &app.workspace.as_ref().unwrap().project));

        let binding = BankBinding::capture(&app).unwrap();
        let loaded = preview.open_reviewed(&app.session).unwrap();
        let replacement = sources.0.join("byte-identical-replacement.elf");
        std::fs::copy(sources.0.join("a.elf"), &replacement).unwrap();
        std::fs::rename(&replacement, sources.0.join("a.elf")).unwrap();
        assert!(app.adopt_project_workspace(&ctx, &binding, loaded).is_err());
        assert!(Arc::ptr_eq(&old_project, &app.workspace.as_ref().unwrap().project));
    }

    #[test]
    fn stale_uncertain_and_prelink_retention_notices_survive_bank_replacement_and_close() {
        let sources = Sources::new();
        let ctx = egui::Context::default();
        let mut app = App::blocking();
        let a = app.add_module_at(&ctx, sources.0.join("a.elf"), None, None).unwrap();
        let b = app.add_module_at(&ctx, sources.0.join("b.elf"), None, None).unwrap();
        let binding = BankBinding::capture(&app).unwrap();
        app.select_module(&a).unwrap();
        app.select_module(&b).unwrap();
        let destination = sources.0.join("uncertain-workspace.json");
        let staging = sources.0.join("retained-sensitive-stage");
        std::fs::write(&destination, b"destination remains untouched").unwrap();
        std::fs::write(&staging, b"staging remains untouched").unwrap();
        let receipt = ProjectWorkspacePublication {
            path: destination.clone(),
            document_sha256: "a".repeat(64),
            status: DebuggerCapturePublicationStatus::PublishedUncertain,
            warnings: vec!["post-publication validation was uncertain".to_owned()],
            retained_staging_paths: vec![staging.clone()],
        };
        assert!(app.finish_workspace_save(&binding, destination.clone(), Ok(receipt)).is_err());
        let error = ApiError::DebuggerCaptureStagingRetained(rampage_api::DebuggerCaptureStagingRetention {
            paths: vec![staging.clone()],
            message: "pre-link publication failed".to_owned(),
        });
        assert!(app.finish_workspace_save(&binding, destination.clone(), Err(error)).is_err());
        app.open_exact_at(&ctx, sources.0.join("a.elf"), None, None).unwrap();
        app.close_workspace().unwrap();
        assert_eq!(app.project_workspace_save_notices().len(), 2);
        match &app.project_workspace_save_notices()[0] {
            ProjectWorkspaceSaveNotice::Publication(publication) => {
                assert_eq!(publication.path, destination);
                assert_eq!(publication.status, DebuggerCapturePublicationStatus::PublishedUncertain);
                assert_eq!(publication.retained_staging_paths, vec![staging.clone()]);
            }
            _ => panic!("uncertain receipt was lost"),
        }
        match &app.project_workspace_save_notices()[1] {
            ProjectWorkspaceSaveNotice::Failure { retained_paths, .. } => {
                assert_eq!(retained_paths, &vec![staging.clone()]);
            }
            _ => panic!("pre-link retention notice was lost"),
        }
        assert!(app.reviewed_project_workspace().is_none());
        assert_eq!(std::fs::read(&destination).unwrap(), b"destination remains untouched");
        assert_eq!(std::fs::read(&staging).unwrap(), b"staging remains untouched");

        use egui_kittest::kittest::Queryable;
        app.show_project_workspace();
        let mut harness = egui_kittest::Harness::builder()
            .with_size(egui::vec2(1500.0, 1000.0))
            .build_ui_state(|ui, app: &mut App| app.show(ui), app);
        harness.run();
        harness.get_by_label("Publication uncertain; destination may exist. Inspect explicitly");
        assert!(harness.query_by_label("Open reviewed workspace").is_none());
    }

    #[test]
    fn snapshot_workspace_round_trip_keeps_custom_session_annotation_directory_and_refuses_changed_settings() {
        let sources = Sources::new();
        let logs = sources.0.join("capture-annotations");
        std::fs::create_dir(&logs).unwrap();
        let document = sources.0.join("owned-capture.json");
        let snapshot = serde_json::json!({
            "format": "rampage-snapshot-v1",
            "arch": "x86_64",
            "provenance": "owned UI workspace fixture",
            "regions": [{"name": "code", "address": "0x1000", "permissions": "r-x", "bytes": "90c3"}],
            "entry": "0x1000",
        });
        std::fs::write(&document, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        let mut app = App::blocking();
        app.session = rampage_api::Session::with_capture_annotations(logs.clone());
        let ctx = egui::Context::default();
        let id = app.add_module_at(&ctx, document.clone(), None, None).unwrap();
        let packs = app.session.packs();
        app.workspace.as_ref().unwrap().project.comment(0x1000, Some("custom-directory analyst state")).unwrap();
        let manifest = app.capture_project_workspace().unwrap();
        assert!(manifest.modules[0].annotation_context_sha256.is_some());
        assert!(!serde_json::to_string(&manifest).unwrap().contains("capture-annotations"));
        let output = sources.0.join("custom-session-workspace.json");
        app.save_project_workspace(output.clone()).unwrap();
        app.preview_project_workspace(output.clone()).unwrap();
        app.open_reviewed_project_workspace(&ctx).unwrap();
        assert_eq!(app.active_module_id(), Some(id.as_str()));
        assert_eq!(app.session.capture_annotations(), Some(logs.as_path()));
        assert!(Arc::ptr_eq(&packs, &app.session.packs()));
        assert!(Arc::ptr_eq(&packs, &app.workspace.as_ref().unwrap().project.packs()));
        assert_eq!(
            app.workspace.as_ref().unwrap().project.comment_at(0x1000).as_deref(),
            Some("custom-directory analyst state"),
        );
        assert!(app.workspace.as_ref().unwrap().analysis_deferred());
        let old_project = Arc::clone(&app.workspace.as_ref().unwrap().project);
        let other_logs = sources.0.join("different-capture-annotations");
        std::fs::create_dir(&other_logs).unwrap();
        app.session = rampage_api::Session::with_capture_annotations(other_logs);
        app.preview_project_workspace(output).unwrap();
        assert!(app.open_reviewed_project_workspace(&ctx).is_err());
        assert!(Arc::ptr_eq(&old_project, &app.workspace.as_ref().unwrap().project));
        assert_eq!(
            app.workspace.as_ref().unwrap().project.comment_at(0x1000).as_deref(),
            Some("custom-directory analyst state"),
        );
    }
}
