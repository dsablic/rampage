//! Explicit, local-only debugger observations, kept apart from the loaded project and assistant.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use egui::{RichText, TextBuffer, TextEdit, Ui};
use rampage_api::{
    DebuggerAddress, DebuggerCapturePreview, DebuggerCapturePublication, DebuggerCapturePublicationStatus,
    DebuggerCaptureRequest, DebuggerPermissions, DebuggerRequest, DebuggerResponse, DebuggerToken,
    MAX_DEBUGGER_REQUEST_BYTES, Project,
};
use rampage_arch::Arch;
use rampage_loaders::{Binary, Details, Format};

use crate::theme;
use crate::workspace::{Job, Workspace};

const TIMEOUT_MS: u64 = 3000;
const OPERATIONS: [&str; 6] =
    ["describe_session", "list_modules", "list_threads", "read_registers", "read_memory", "resolve_module_address"];

pub(crate) struct Debugger {
    pub shown: bool,
    socket: String,
    request: String,
    request_rejected: bool,
    template: usize,
    job: Job<QueryReply>,
    error: Option<String>,
    submitted: Option<(String, String)>,
    input_revision: Arc<()>,
    click_context: Option<ClickContext>,
    navigation_notice: Option<String>,
    gate: WorkGate,
    workflow: Workflow,
    was_shown: bool,
}

impl Default for Debugger {
    fn default() -> Self {
        Self {
            shown: false,
            socket: String::new(),
            request: template(0),
            request_rejected: false,
            template: 0,
            job: Job::Idle,
            error: None,
            submitted: None,
            input_revision: Arc::new(()),
            click_context: None,
            navigation_notice: None,
            gate: WorkGate::default(),
            workflow: Workflow::default(),
            was_shown: false,
        }
    }
}

impl Debugger {
    #[cfg(test)]
    fn show(&mut self, ctx: &egui::Context, workspace: Option<&mut Workspace>) {
        let _ = self.show_action(ctx, workspace);
    }

    pub fn show_action(&mut self, ctx: &egui::Context, workspace: Option<&mut Workspace>) -> Option<OpenSnapshot> {
        if self.was_shown && !self.shown {
            self.close();
        }
        self.was_shown = self.shown;
        let raw_arrived = self.job.poll();
        if raw_arrived
            && (self.job.error().is_some()
                || self.job.ready().is_some_and(|reply| reply.resolution.as_ref().is_some_and(Result::is_err)))
        {
            self.workflow.refresh_required = true;
            self.workflow.invalidate_form();
        }
        self.check_context(workspace.as_deref());
        self.workflow.poll(&self.socket, workspace.as_deref());
        if !self.shown {
            return None;
        }
        let mut shown = self.shown;
        let mut action = None;
        egui::Window::new("Read-only debugger")
            .open(&mut shown)
            .collapsible(false)
            .default_size(egui::vec2(820.0, 760.0))
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 60.0))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().id_salt("debugger-workspace").show(ui, |ui| {
                    action = self.contents(ui, workspace);
                });
            });
        if !shown {
            self.close();
            action = None;
        }
        self.shown = shown;
        self.was_shown = shown;
        action
    }

    fn contents(&mut self, ui: &mut Ui, workspace: Option<&mut Workspace>) -> Option<OpenSnapshot> {
        ui.label(RichText::new("Local runtime observation only").strong());
        ui.label(
            "Socket paths, requests and results stay in this window; they are never sent to an assistant or provider.",
        );
        ui.label(
            RichText::new(
                "Start the read-only LLDB endpoint yourself while stopped. Opening this window does not connect. \
                 Only explicit buttons connect; nothing is attached, resumed, evaluated or written to the target.",
            )
            .color(theme::DIM)
            .small(),
        );
        ui.add_space(6.0);
        ui.label("Explicit Unix socket path");
        let socket_edit = ui.add(
            TextEdit::singleline(&mut self.socket)
                .id(egui::Id::new("debugger-socket"))
                .hint_text("/absolute/private-directory/operator.sock")
                .char_limit(1024)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace),
        );
        if socket_edit.changed() {
            self.invalidate_navigation();
            self.workflow.reset_stop();
            self.workflow.socket = self.socket.clone();
        }
        let action = self.workflow.ui(ui, &self.socket, workspace.as_deref(), &self.gate, self.job.is_running());
        if self.workflow.form_changed {
            self.invalidate_raw_navigation();
            self.workflow.form_changed = false;
        }
        let mut open = None;
        match action {
            Some(WorkflowAction::Resolve(request)) => {
                self.request = request;
                self.request_rejected = false;
                self.query(ui.ctx(), workspace.as_deref());
            }
            Some(WorkflowAction::Open(action)) => open = Some(action),
            None => {}
        }
        egui::CollapsingHeader::new("Advanced: raw requests and JSON responses")
            .id_salt("debugger-advanced")
            .show(ui, |ui| self.advanced_ui(ui, workspace.as_deref()));
        if open.is_some() && self.workflow.validate_preview(&self.socket, workspace.as_deref()).is_err() {
            open = None;
        }
        self.navigation_ui(ui, workspace);
        open
    }

    fn advanced_ui(&mut self, ui: &mut Ui, workspace: Option<&Workspace>) {
        ui.horizontal(|ui| {
            ui.label("Template");
            let previous_template = self.template;
            egui::ComboBox::from_id_salt("debugger-operation").selected_text(OPERATIONS[self.template]).show_ui(
                ui,
                |ui| {
                    for (index, operation) in OPERATIONS.iter().enumerate() {
                        ui.selectable_value(&mut self.template, index, *operation);
                    }
                },
            );
            if self.template != previous_template {
                self.invalidate_navigation();
            }
            if ui.button("Insert template").clicked() {
                self.invalidate_navigation();
                self.request = template(self.template);
                self.request_rejected = false;
            }
        });
        ui.label("Request JSON (at most 16 KiB)");
        self.edit_request(ui);
        if self.request_rejected {
            ui.label(RichText::new(REJECTED_INPUT).color(theme::WARNING));
        }
        ui.label(
            RichText::new(
                "Run describe_session explicitly, then copy its returned token into expected_token for follow-ups. \
                 Replace template placeholders. Stale tokens are not retried or refreshed automatically.",
            )
            .color(theme::DIM)
            .small(),
        );
        if self.template == 5 {
            ui.label(
                RichText::new(
                    "Select a unique module UUID from list_modules and supply its LLDB file virtual address, \
                     not a file offset. Resolution is raw SDK mapping evidence, not proven flow or layout.",
                )
                .color(theme::DIM)
                .small(),
            );
        }
        ui.horizontal(|ui| {
            if ui.add_enabled(!self.busy(), egui::Button::new("Query")).clicked() {
                self.workflow.reset_stop();
                self.query(ui.ctx(), workspace);
            }
            if ui.add_enabled(!self.busy(), egui::Button::new("Clear local data")).clicked() {
                self.clear(ui.ctx());
            }
            ui.label(RichText::new(format!("Client deadline: {TIMEOUT_MS} ms")).color(theme::DIM).small());
            if self.job.is_running() {
                ui.spinner();
                ui.label("Querying");
            }
        });
        if let Some(error) = self.error.as_deref().or_else(|| self.job.error()) {
            ui.label(RichText::new(error).color(theme::WARNING));
        }
        ui.separator();
        ui.label(RichText::new("Raw response to the last explicit query").strong());
        ui.label(
            RichText::new(
                "Includes backend ok:false errors, token and observation.atomic_snapshot:false metadata. \
                 Runtime addresses are not project addresses. Results never change navigation automatically.",
            )
            .color(theme::DIM)
            .small(),
        );
        ui.label(
            RichText::new("Shared tool response limits apply; reduce page or memory size if a query is refused.")
                .color(theme::DIM)
                .small(),
        );
        egui::ScrollArea::vertical().id_salt("debugger-results").max_height(260.0).show(ui, |ui| {
            if let Some((socket, request)) = &self.submitted {
                ui.label(RichText::new(format!("Queried socket: {socket}")).monospace().small());
                ui.collapsing("Submitted request", |ui| {
                    ui.add(egui::Label::new(RichText::new(request).monospace()).selectable(true));
                });
            }
            if let Some(response) = self.job.ready() {
                ui.add(egui::Label::new(RichText::new(&response.raw).monospace()).selectable(true));
            } else if !self.job.is_running() && self.error.is_none() && self.job.error().is_none() {
                ui.label(RichText::new("No query has been sent.").color(theme::DIM));
            }
        });
    }

    fn edit_request(&mut self, ui: &mut Ui) {
        let id = egui::Id::new("debugger-request");
        let previous_request = self.request.clone();
        let mut previous_state = egui::text_edit::TextEditState::load(ui.ctx(), id).unwrap_or_default();
        // TextEditState clones share an undoer; keep an independent snapshot for a rejected edit frame.
        let previous_undo = previous_state.undoer();
        let mut rejected = false;
        let mut edited = false;
        let mut editor = RequestEditor { text: &mut self.request, rejected: &mut rejected, edited: &mut edited };
        ui.add(
            TextEdit::multiline(&mut editor)
                .id(id)
                .desired_width(f32::INFINITY)
                .desired_rows(7)
                .font(egui::TextStyle::Monospace),
        );
        if edited || rejected {
            self.invalidate_navigation();
        }
        if rejected {
            self.request = previous_request;
            previous_state.set_undoer(previous_undo);
            previous_state.store(ui.ctx(), id);
            self.request_rejected = true;
            ui.ctx().request_repaint();
        }
    }

    fn clear(&mut self, ctx: &egui::Context) {
        if self.busy() {
            return;
        }
        let shown = self.shown;
        let gate = self.gate.clone();
        *self = Self { shown, gate, request: String::new(), ..Self::default() };
        for field in [
            "debugger-socket",
            "debugger-request",
            "debugger-memory-address",
            "debugger-file-address",
            "debugger-capture-output",
        ] {
            egui::text_edit::TextEditState::default().store(ctx, egui::Id::new(field));
        }
    }

    fn query(&mut self, ctx: &egui::Context, workspace: Option<&Workspace>) {
        if self.busy() {
            return;
        }
        self.job = Job::Idle;
        self.invalidate_navigation();
        self.navigation_notice = None;
        self.error = None;
        self.submitted = None;
        if self.socket.is_empty() {
            self.error = Some("Enter an explicit absolute Unix socket path before querying.".to_owned());
            return;
        }
        if self.request_rejected {
            self.error = Some(REJECTED_INPUT.to_owned());
            return;
        }
        let request_typed = match DebuggerRequest::from_json(&self.request) {
            Ok(request) => request,
            Err(error) => {
                self.error = Some(error.to_string());
                return;
            }
        };
        let socket = PathBuf::from(&self.socket);
        let deadline = Instant::now() + Duration::from_millis(TIMEOUT_MS);
        let request = self.request.clone();
        self.submitted = Some((self.socket.clone(), self.request.clone()));
        let binding = workspace.map(|workspace| WorkspaceBinding::capture(workspace, &request_typed));
        self.click_context = Some(ClickContext {
            request: request_typed,
            revision: Arc::clone(&self.input_revision),
            workspace: binding,
        });
        let revision = Arc::clone(&self.input_revision);
        let Some(permit) = self.gate.acquire() else { return };
        self.job.start(false, ctx, move || {
            let _permit = permit;
            run_query(socket, request, deadline, revision)
        });
    }

    fn busy(&self) -> bool {
        self.gate.busy() || self.job.is_running() || self.workflow.job.is_running()
    }

    fn close(&mut self) {
        self.invalidate_navigation();
        self.workflow.reset_stop();
    }

    pub(crate) fn invalidate_workspace(&mut self) {
        self.invalidate_navigation();
        self.workflow.reset_stop();
    }

    pub(crate) fn invalidate_navigation(&mut self) {
        self.workflow.invalidate_form();
        self.invalidate_raw_navigation();
    }

    fn invalidate_raw_navigation(&mut self) {
        self.input_revision = Arc::new(());
        self.click_context = None;
        if self.submitted.is_some() {
            self.navigation_notice =
                Some("Navigation invalidated; submit a new explicit query for this workspace.".into());
        }
    }

    fn check_context(&mut self, workspace: Option<&Workspace>) {
        if let Some(context) = &self.click_context {
            let unchanged = self
                .submitted
                .as_ref()
                .is_some_and(|(socket, request)| socket == &self.socket && request == &self.request)
                && Arc::ptr_eq(&context.revision, &self.input_revision)
                && match (&context.workspace, workspace) {
                    (Some(binding), Some(workspace)) => binding.validate_current(workspace).is_ok(),
                    (None, None) => true,
                    _ => false,
                };
            if !unchanged {
                self.invalidate_navigation();
            }
        }
    }

    fn destination(&self, workspace: Option<&Workspace>) -> Result<u64, String> {
        let context = self.click_context.as_ref().ok_or("No current navigation binding; query again.")?;
        if !Arc::ptr_eq(&context.revision, &self.input_revision)
            || !self
                .submitted
                .as_ref()
                .is_some_and(|(socket, request)| socket == &self.socket && request == &self.request)
        {
            return Err("Inputs changed; query again.".into());
        }
        let binding =
            context.workspace.as_ref().ok_or("No workspace was open at submission; open one and query again.")?;
        let workspace = workspace.ok_or("The submitted workspace was closed; query again.")?;
        binding.validate_current(workspace)?;
        let reply = self.job.ready().ok_or("No completed successful resolution.")?;
        if !Arc::ptr_eq(&reply.revision, &context.revision) {
            return Err("Response belongs to an obsolete query; query again.".into());
        }
        let resolution = reply
            .resolution
            .as_ref()
            .ok_or("This response is raw-only.")?
            .as_ref()
            .map_err(|reason| format!("Raw-only resolution: {reason}"))?;
        resolution.matches_request(&context.request)?;
        let destination = binding.destination.as_ref().map_err(|error| error.to_owned())?;
        resolution.destination_cached(&workspace.project.binary, destination)
    }

    fn navigate(&mut self, workspace: Option<&mut Workspace>) {
        match self.destination_on_click(workspace.as_deref()) {
            Ok(address) => {
                if let Some(workspace) = workspace {
                    workspace.goto(address);
                }
            }
            Err(error) => self.navigation_notice = Some(error),
        }
    }

    fn destination_on_click(&self, workspace: Option<&Workspace>) -> Result<u64, String> {
        let address = self.destination(workspace)?;
        let workspace = workspace.ok_or("The submitted workspace was closed; query again.")?;
        StaticDestination::capture(&workspace.project.binary, address)?;
        self.destination(Some(workspace))
    }

    fn navigation_ui(&mut self, ui: &mut Ui, workspace: Option<&mut Workspace>) {
        if self.job.ready().is_some_and(|reply| reply.resolution.is_some()) {
            ui.label(RichText::new(NAVIGATION_LIMITATION).color(theme::WARNING).strong());
            match self.destination(workspace.as_deref()) {
                Ok(address) => {
                    ui.label(format!("Static file virtual address: {address:#x} (not the runtime load address)"));
                    if ui.button("Go to matching static image address").clicked() {
                        self.navigate(workspace);
                    }
                }
                Err(reason) => {
                    ui.label(RichText::new(reason).color(theme::WARNING));
                }
            }
        }
        if let Some(notice) = &self.navigation_notice {
            ui.label(RichText::new(notice).color(theme::WARNING));
        }
    }
}

#[derive(Clone, Default)]
struct WorkGate(Arc<AtomicBool>);

impl WorkGate {
    fn busy(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn acquire(&self) -> Option<WorkPermit> {
        self.0.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).ok()?;
        Some(WorkPermit(Arc::clone(&self.0)))
    }
}

struct WorkPermit(Arc<AtomicBool>);

impl Drop for WorkPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Clone)]
struct SourceIdentity {
    instance: Arc<()>,
    project: Arc<Project>,
    path: PathBuf,
    image: Option<rampage_loaders::ImageAt>,
}

struct CaptureSourceMetadata<'a> {
    format: Format,
    architecture: Arch,
    big_endian: bool,
    uuid: Option<&'a str>,
}

impl<'a> CaptureSourceMetadata<'a> {
    fn from_cached(binary: &'a Binary) -> Self {
        Self {
            format: binary.format,
            architecture: binary.arch,
            big_endian: binary.big_endian,
            uuid: match &binary.details {
                Details::MachO(details) => details.uuid.as_deref(),
                _ => None,
            },
        }
    }

    fn supports_capture_family(&self) -> bool {
        // The loader does not retain CPU subtypes; this is button eligibility, never capture authority.
        self.format == Format::MachO && self.architecture == Arch::X86_64 && !self.big_endian
    }
}

impl SourceIdentity {
    fn capture(workspace: &Workspace) -> Self {
        Self {
            instance: Arc::clone(&workspace.instance),
            project: Arc::clone(&workspace.project),
            path: workspace.path.clone(),
            image: workspace.image,
        }
    }

    fn matches(&self, workspace: &Workspace) -> bool {
        Arc::ptr_eq(&self.instance, &workspace.instance)
            && Arc::ptr_eq(&self.project, &workspace.project)
            && self.path == workspace.path
            && self.image == workspace.image
    }

    fn validate(&self, workspace: &Workspace) -> Result<(), String> {
        if !self.matches(workspace) {
            return Err("Original workspace was replaced; explicitly refresh and prepare again.".into());
        }
        self.project.binary.validate_backing_source().map_err(|error| error.to_string())
    }
}

fn same_source(source: Option<&SourceIdentity>, workspace: Option<&Workspace>) -> bool {
    match (source, workspace) {
        (Some(source), Some(workspace)) => source.matches(workspace),
        (None, None) => true,
        _ => false,
    }
}

#[derive(Clone)]
struct WorkBinding {
    revision: Arc<()>,
    stop: Arc<()>,
    output: Option<Arc<()>>,
    socket: String,
    source: Option<SourceIdentity>,
}

impl WorkBinding {
    fn validate(&self, workflow: &Workflow, socket: &str, workspace: Option<&Workspace>) -> Result<(), String> {
        if !Arc::ptr_eq(&self.revision, &workflow.revision)
            || !Arc::ptr_eq(&self.stop, &workflow.stop)
            || self.output.as_ref().is_some_and(|output| !Arc::ptr_eq(output, &workflow.output_revision))
            || self.socket != socket
            || !same_source(self.source.as_ref(), workspace)
        {
            return Err(
                "Obsolete debugger result refused. Use an explicit Refresh or Prepare; nothing was retried.".into()
            );
        }
        if let (Some(source), Some(workspace)) = (&self.source, workspace)
            && source.project.binary.format != Format::Snapshot
        {
            source.validate(workspace)?;
        }
        Ok(())
    }
}

pub(crate) struct OpenSnapshot {
    pub path: PathBuf,
    pub document_sha256: String,
    publication_status: DebuggerCapturePublicationStatus,
    source: SourceIdentity,
}

impl OpenSnapshot {
    pub fn validate_source(&self, workspace: Option<&Workspace>) -> Result<(), String> {
        if self.publication_status != DebuggerCapturePublicationStatus::Published {
            return Err(
                "Uncertain publication cannot authorize opening a snapshot; inspect its output explicitly.".into()
            );
        }
        let workspace = workspace.ok_or("The original workspace was closed.")?;
        self.source.validate(workspace)?;
        if workspace.editing.is_some() {
            return Err("Finish or cancel the unsaved annotation editor before opening a saved capture.".into());
        }
        Ok(())
    }
}

enum WorkflowAction {
    Resolve(String),
    Open(OpenSnapshot),
}

struct SessionView {
    token: DebuggerToken,
    token_json: String,
    triple: String,
    width: u64,
    data_order: String,
}

#[derive(Clone, PartialEq, Eq)]
struct ModuleRow {
    index: usize,
    name: String,
    uuid: String,
    triple: String,
    width: u64,
    object_order: String,
}

struct ThreadRow {
    id: u64,
    reason: u64,
    stopped: bool,
}

struct Page<T> {
    items: Vec<T>,
    offset: usize,
    total: usize,
    next: Option<usize>,
}

struct RegisterView {
    thread: u64,
    order: String,
    rows: Vec<(String, String)>,
}

struct MemoryView {
    address: u64,
    size: usize,
    order: String,
    bytes: String,
}

#[derive(Clone, Copy)]
enum WorkKind {
    Query,
    Prepare,
    Save,
    Compare,
}

enum WorkResult {
    Query(DebuggerRequest, Box<DebuggerResponse>),
    Prepared(Arc<DebuggerCapturePreview>),
    Saved { requested: PathBuf, publication: DebuggerCapturePublication },
    SaveFailed { requested: PathBuf, document_sha256: String, error: rampage_api::ApiError },
    Compared(rampage_api::RuntimeComparison),
}

enum SaveResourceNotice {
    Publication(DebuggerCapturePublication),
    Failure {
        requested: PathBuf,
        document_sha256: String,
        message: String,
        retention: Option<rampage_api::DebuggerCaptureStagingRetention>,
    },
}

struct Workflow {
    revision: Arc<()>,
    stop: Arc<()>,
    output_revision: Arc<()>,
    cancellation: Arc<AtomicBool>,
    job: Job<WorkResult>,
    job_kind: WorkKind,
    binding: Option<WorkBinding>,
    source: Option<SourceIdentity>,
    socket: String,
    session: Option<SessionView>,
    refresh_required: bool,
    modules: Option<Page<ModuleRow>>,
    threads: Option<Page<ThreadRow>>,
    module_offset: usize,
    thread_offset: usize,
    module: Option<ModuleRow>,
    thread: Option<u64>,
    registers: Option<RegisterView>,
    memory: Option<MemoryView>,
    memory_address: String,
    file_address: String,
    size: usize,
    permissions: usize,
    preview: Option<Arc<DebuggerCapturePreview>>,
    preview_binding: Option<WorkBinding>,
    output: String,
    saved: Option<DebuggerCapturePublication>,
    save_resources: Vec<SaveResourceNotice>,
    comparison: Option<rampage_api::RuntimeComparison>,
    response: Option<DebuggerResponse>,
    error: Option<String>,
    form_changed: bool,
}

impl Default for Workflow {
    fn default() -> Self {
        Self {
            revision: Arc::new(()),
            stop: Arc::new(()),
            output_revision: Arc::new(()),
            cancellation: Arc::new(AtomicBool::new(false)),
            job: Job::Idle,
            job_kind: WorkKind::Query,
            binding: None,
            source: None,
            socket: String::new(),
            session: None,
            refresh_required: false,
            modules: None,
            threads: None,
            module_offset: 0,
            thread_offset: 0,
            module: None,
            thread: None,
            registers: None,
            memory: None,
            memory_address: String::new(),
            file_address: String::new(),
            size: 64,
            permissions: 0,
            preview: None,
            preview_binding: None,
            output: String::new(),
            saved: None,
            save_resources: Vec::new(),
            comparison: None,
            response: None,
            error: None,
            form_changed: false,
        }
    }
}

impl Workflow {
    fn retain_save_resources(&mut self, result: &WorkResult) {
        match result {
            WorkResult::Saved { publication, .. } => {
                self.save_resources.push(SaveResourceNotice::Publication(publication.clone()));
            }
            WorkResult::SaveFailed { requested, document_sha256, error } => {
                let retention = match error {
                    rampage_api::ApiError::DebuggerCaptureStagingRetained(retention) => Some(retention.clone()),
                    _ => None,
                };
                self.save_resources.push(SaveResourceNotice::Failure {
                    requested: requested.clone(),
                    document_sha256: document_sha256.clone(),
                    message: error.to_string(),
                    retention,
                });
            }
            _ => {}
        }
    }

    #[cfg(test)]
    fn latest_publication_notice(&self) -> Option<&DebuggerCapturePublication> {
        self.save_resources.iter().rev().find_map(|notice| match notice {
            SaveResourceNotice::Publication(publication) => Some(publication),
            SaveResourceNotice::Failure { .. } => None,
        })
    }

    fn published_destination(&self, output: &std::path::Path) -> bool {
        self.save_resources.iter().any(|notice| match notice {
            SaveResourceNotice::Publication(publication) => publication.path.as_path() == output,
            SaveResourceNotice::Failure { .. } => false,
        })
    }

    fn invalidate_form(&mut self) {
        self.revision = Arc::new(());
        self.cancellation.store(true, Ordering::Release);
        self.preview = None;
        self.preview_binding = None;
        self.saved = None;
        self.comparison = None;
    }

    fn reset_stop(&mut self) {
        self.invalidate_form();
        self.stop = Arc::new(());
        self.session = None;
        self.modules = None;
        self.threads = None;
        self.module = None;
        self.thread = None;
        self.registers = None;
        self.memory = None;
        self.response = None;
        self.module_offset = 0;
        self.thread_offset = 0;
        self.refresh_required = false;
    }

    fn edited(&mut self) {
        self.invalidate_form();
        self.form_changed = true;
    }

    fn poll(&mut self, socket: &str, workspace: Option<&Workspace>) {
        if self.socket != socket || !same_source(self.source.as_ref(), workspace) {
            self.reset_stop();
            self.socket = socket.to_owned();
            self.source = workspace.map(SourceIdentity::capture);
        }
        self.job.poll();
        if matches!(self.job, Job::Done(_)) {
            let Job::Done(result) = std::mem::replace(&mut self.job, Job::Idle) else { unreachable!() };
            if let Ok(result) = &result {
                self.retain_save_resources(result);
            }
            let result = (|| {
                let binding = self.binding.take().ok_or("Missing debugger job binding.")?;
                binding.validate(self, socket, workspace)?;
                match result? {
                    WorkResult::Query(request, response) => self.accept_response(&request, *response)?,
                    WorkResult::Prepared(preview) => {
                        let source = binding.source.as_ref().ok_or("Capture requires an original static source.")?;
                        if !Arc::ptr_eq(preview.source_project(), &source.project) {
                            return Err("Prepared capture belongs to a different source project.".into());
                        }
                        self.preview = Some(preview);
                        self.preview_binding = Some(binding);
                    }
                    WorkResult::Saved { requested, publication } => {
                        let preview = self.preview.as_ref().ok_or("Prepared capture was invalidated.")?;
                        if requested.as_path() != std::path::Path::new(&self.output)
                            || publication.path != requested
                            || publication.document_sha256 != preview.summary().document_sha256
                        {
                            return Err("Publication does not match the explicit destination and preview.".into());
                        }
                        if publication.status == DebuggerCapturePublicationStatus::Published {
                            self.saved = Some(publication);
                        } else {
                            self.saved = None;
                            self.error = Some(
                                concat!(
                                    "Publication is uncertain: output may exist. Inspect the reported path; ",
                                    "no open, retry, overwrite or cleanup was performed.",
                                )
                                .into(),
                            );
                        }
                    }
                    WorkResult::SaveFailed { error, .. } => return Err(error.to_string()),
                    WorkResult::Compared(comparison) => self.comparison = Some(comparison),
                }
                Ok::<_, String>(())
            })();
            if let Err(error) = result {
                self.form_changed = true;
                if matches!(self.job_kind, WorkKind::Query | WorkKind::Prepare) {
                    self.refresh_required = true;
                    self.registers = None;
                    self.memory = None;
                    self.preview = None;
                    self.preview_binding = None;
                }
                self.error = Some(error);
            }
        }
        if let Some(binding) = &self.preview_binding
            && let Err(error) = binding.validate(self, socket, workspace)
        {
            self.invalidate_form();
            self.error = Some(error);
        }
    }

    fn start(
        &mut self,
        ui: &Ui,
        socket: &str,
        workspace: Option<&Workspace>,
        gate: &WorkGate,
        kind: WorkKind,
        work: impl FnOnce() -> Result<WorkResult, String> + Send + 'static,
    ) {
        if self.job.is_running() {
            return;
        }
        let Some(permit) = gate.acquire() else { return };
        self.binding = Some(WorkBinding {
            revision: Arc::clone(&self.revision),
            stop: Arc::clone(&self.stop),
            output: matches!(kind, WorkKind::Save).then(|| Arc::clone(&self.output_revision)),
            source: workspace.map(SourceIdentity::capture),
            socket: socket.to_owned(),
        });
        self.job_kind = kind;
        self.error = None;
        self.job.start(false, ui.ctx(), move || {
            let _permit = permit;
            work()
        });
    }

    fn query(
        &mut self,
        ui: &Ui,
        socket: &str,
        workspace: Option<&Workspace>,
        gate: &WorkGate,
        request: DebuggerRequest,
    ) {
        if gate.busy() || self.job.is_running() {
            return;
        }
        self.invalidate_form();
        self.form_changed = true;
        match &request {
            DebuggerRequest::ReadRegisters { .. } => self.registers = None,
            DebuggerRequest::ReadMemory { .. } => self.memory = None,
            _ => {}
        }
        if !PathBuf::from(socket).is_absolute() {
            self.error = Some("Enter an explicit absolute Unix socket path before querying.".into());
            return;
        }
        self.response = None;
        let socket_path = PathBuf::from(socket);
        let deadline = Instant::now() + Duration::from_millis(TIMEOUT_MS);
        self.start(ui, socket, workspace, gate, WorkKind::Query, move || {
            let response =
                rampage_api::query_debugger(&socket_path, &request, deadline).map_err(|error| error.to_string())?;
            Ok(WorkResult::Query(request, Box::new(response)))
        });
    }

    fn accept_response(&mut self, request: &DebuggerRequest, response: DebuggerResponse) -> Result<(), String> {
        let result = self.read_response(request, &response);
        self.response = Some(response);
        result
    }

    fn read_response(&mut self, request: &DebuggerRequest, response: &DebuggerResponse) -> Result<(), String> {
        if !response.ok {
            let error = response.error.as_ref().ok_or("Debugger returned an unspecified refusal.")?;
            return Err(format!("{}: {}. Explicit Refresh is required; no retry was sent.", error.code, error.message));
        }
        if response.operation.as_deref() != Some(request.operation()) {
            return Err("Debugger operation does not match the explicit request.".into());
        }
        let token = response.token.as_ref().ok_or("Missing stopped-session token.")?;
        let expected = match request {
            DebuggerRequest::DescribeSession { expected_token, .. } => expected_token.as_ref(),
            DebuggerRequest::ListModules { expected_token, .. }
            | DebuggerRequest::ListThreads { expected_token, .. }
            | DebuggerRequest::ReadRegisters { expected_token, .. }
            | DebuggerRequest::ReadMemory { expected_token, .. }
            | DebuggerRequest::ResolveModuleAddress { expected_token, .. } => Some(expected_token),
        };
        if expected.is_some_and(|expected| expected != token) {
            return Err("Debugger stop token changed. Explicit Refresh is required.".into());
        }
        let data = response.data.as_ref().ok_or("Missing debugger observation data.")?;
        let order = data
            .get("data_byte_order")
            .and_then(|value| value.get("order"))
            .and_then(|value| value.as_str())
            .filter(|order| matches!(*order, "little" | "big"))
            .unwrap_or("unknown")
            .to_owned();
        match request {
            DebuggerRequest::DescribeSession { .. } => {
                if data.get("state").and_then(|value| value.as_str()) != Some("stopped") {
                    return Err("The endpoint did not describe a stopped session. Explicit Refresh is required.".into());
                }
                let mut encoded = data.clone();
                let fields = encoded.as_object_mut().ok_or("Invalid stopped-session observation.")?;
                fields.clear();
                fields.insert("backend".into(), "lldb-sb".into());
                fields.insert("session_id".into(), token.session_id.clone().into());
                fields.insert("process_unique_id".into(), token.process_unique_id.into());
                fields.insert("stop_id".into(), token.stop_id.into());
                fields.insert("target_index".into(), token.target_index.into());
                self.session = Some(SessionView {
                    token: token.clone(),
                    token_json: encoded.to_string(),
                    triple: data.get("triple").and_then(|value| value.as_str()).unwrap_or("unknown").into(),
                    width: data.get("address_byte_size").and_then(|value| value.as_u64()).unwrap_or(0),
                    data_order: order,
                });
                self.refresh_required = false;
            }
            DebuggerRequest::ListModules { offset, limit, .. } | DebuggerRequest::ListThreads { offset, limit, .. } => {
                let offset = offset.unwrap_or(0);
                let items = data.get("items").and_then(|value| value.as_array()).ok_or("Missing page items.")?;
                let total = data.get("total").and_then(|value| value.as_u64()).ok_or("Missing page total.")?;
                let next = data.get("next_offset").ok_or("Missing page boundary.")?;
                let end = offset.checked_add(items.len()).ok_or("Page boundary overflow.")?;
                if total > 4096
                    || items.len() > 32
                    || items.len() > limit.unwrap_or(32)
                    || end > total as usize
                    || data.get("offset").and_then(|value| value.as_u64()) != Some(offset as u64)
                    || if end < total as usize { next.as_u64() != Some(end as u64) } else { !next.is_null() }
                {
                    return Err("Enumeration page does not match the requested bounded range.".into());
                }
                let next = next.as_u64().map(|value| value as usize);
                if matches!(request, DebuggerRequest::ListModules { .. }) {
                    let mut rows = Vec::new();
                    for (relative, row) in items.iter().enumerate() {
                        let index = row.get("index").and_then(|value| value.as_u64()).ok_or("Missing module index.")?;
                        if index != (offset + relative) as u64 {
                            return Err("Module page index mismatch.".into());
                        }
                        rows.push(ModuleRow {
                            index: index as usize,
                            name: row.get("name").and_then(|value| value.as_str()).unwrap_or("unnamed").into(),
                            uuid: row.get("uuid").and_then(|value| value.as_str()).unwrap_or("").into(),
                            triple: row.get("triple").and_then(|value| value.as_str()).unwrap_or("unknown").into(),
                            width: row.get("address_byte_size").and_then(|value| value.as_u64()).unwrap_or(0),
                            object_order: row
                                .get("target_byte_order")
                                .and_then(|value| value.as_str())
                                .unwrap_or("unknown")
                                .into(),
                        });
                    }
                    self.modules = Some(Page { items: rows, offset, total: total as usize, next });
                } else {
                    let mut rows = Vec::new();
                    for row in items {
                        let id = address_value(
                            row.get("thread_id").and_then(|value| value.as_str()).ok_or("Missing thread identity.")?,
                        )?;
                        if id == 0 || rows.iter().any(|row: &ThreadRow| row.id == id) {
                            return Err("Duplicate or invalid thread identity.".into());
                        }
                        rows.push(ThreadRow {
                            id,
                            reason: row.get("stop_reason").and_then(|value| value.as_u64()).unwrap_or(0),
                            stopped: row.get("is_stopped").and_then(|value| value.as_bool()).unwrap_or(false),
                        });
                    }
                    self.threads = Some(Page { items: rows, offset, total: total as usize, next });
                }
            }
            DebuggerRequest::ReadRegisters { thread_id, .. } => {
                let thread = request_address(thread_id)?;
                let observed = data.get("thread_id").and_then(|value| value.as_str()).map(address_value).transpose()?;
                if observed != Some(thread) {
                    return Err("Register observation belongs to another thread.".into());
                }
                let values = data
                    .get("context")
                    .and_then(|value| value.get("registers"))
                    .and_then(|value| value.as_object())
                    .ok_or("Missing raw register values.")?;
                if values.is_empty() || values.len() > 34 {
                    return Err("Register observation exceeds the bounded view.".into());
                }
                let rows = values
                    .iter()
                    .map(|(name, value)| {
                        let text = value.as_str().ok_or("Invalid raw register value.")?;
                        let digits = text.strip_prefix("0x").ok_or("Register is not raw hexadecimal.")?;
                        if digits.is_empty()
                            || digits.len() > 16
                            || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
                        {
                            return Err("Invalid raw register hexadecimal value.".to_owned());
                        }
                        Ok((name.clone(), text.to_owned()))
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                self.registers = Some(RegisterView { thread, order, rows });
            }
            DebuggerRequest::ReadMemory { address, size, permissions, thread_id, .. } => {
                let address = request_address(address)?;
                let bytes =
                    data.get("bytes_hex").and_then(|value| value.as_str()).ok_or("Missing raw memory bytes.")?;
                let observed_address =
                    data.get("address").and_then(|value| value.as_str()).map(address_value).transpose()?;
                let observed_thread = data.get("thread_id").and_then(|value| {
                    value.as_u64().or_else(|| value.as_str().and_then(|text| address_value(text).ok()))
                });
                if !(1..=4096).contains(size)
                    || address.checked_add(*size as u64).is_none()
                    || bytes.len() != *size * 2
                    || !bytes.bytes().all(|byte| byte.is_ascii_hexdigit())
                    || observed_address != Some(address)
                    || observed_thread != thread_id.as_ref().map(request_address).transpose()?
                    || data.get("size").and_then(|value| value.as_u64()) != Some(*size as u64)
                    || data.get("permissions").and_then(|value| value.as_str()) != Some(permission_name(permissions))
                    || data.get("interpretation").and_then(|value| value.as_str()) != Some("raw-bytes-only")
                {
                    return Err("Memory observation does not match the complete requested raw-byte range.".into());
                }
                self.memory = Some(MemoryView { address, size: *size, order, bytes: bytes.to_owned() });
            }
            DebuggerRequest::ResolveModuleAddress { .. } => {
                return Err("Use the guarded static-resolution view.".into());
            }
        }
        Ok(())
    }

    fn token(&self) -> Option<DebuggerToken> {
        self.session.as_ref().filter(|_| !self.refresh_required).map(|session| session.token.clone())
    }

    fn capture_request(&self, workspace: Option<&Workspace>) -> Result<DebuggerCaptureRequest, String> {
        let token = self.token().ok_or("Connect or explicitly Refresh the stopped session first.")?;
        let session = self.session.as_ref().ok_or("No retained stopped session.")?;
        let workspace =
            workspace.ok_or("Inspection works without a source; capture requires the original static image.")?;
        let source = self.source.as_ref().ok_or("Explicitly Refresh after opening the original image.")?;
        source.validate(workspace)?;
        let metadata = CaptureSourceMetadata::from_cached(&source.project.binary);
        let module = self.module.as_ref().ok_or("Explicitly list and select a module.")?;
        let thread_id = self.thread.ok_or("Explicitly list and select a thread.")?;
        if !metadata.supports_capture_family()
            || module_arch(&module.triple) != Ok(Arch::X86_64)
            || module_arch(&session.triple) != Ok(Arch::X86_64)
            || module.width != 8
            || session.width != 8
            || module.object_order != "little"
            || session.data_order != "little"
        {
            return Err(concat!(
                "Capture supports ordinary little-endian x86_64 Mach-O only. ",
                "ARM64 data order remains unknown.",
            )
            .into());
        }
        if metadata.uuid.map(macho_uuid).transpose()? != Some(macho_uuid(&module.uuid)?) {
            return Err("Selected module UUID does not exactly match the retained original image.".into());
        }
        let file_address = address_value(&self.file_address)?;
        if !(1..=4096).contains(&self.size) || file_address.checked_add(self.size as u64).is_none() {
            return Err("Capture requires one non-overflowing file-VA range of 1..4096 bytes.".into());
        }
        Ok(DebuggerCaptureRequest {
            expected_token: token,
            module_index: module.index,
            module_uuid: module.uuid.clone(),
            thread_id,
            file_address,
            size: self.size as u64,
            permissions: selected_permissions(self.permissions),
        })
    }

    fn validate_preview(&self, socket: &str, workspace: Option<&Workspace>) -> Result<(), String> {
        let binding = self.preview_binding.as_ref().ok_or("Prepare a new capture first.")?;
        binding.validate(self, socket, workspace)?;
        let preview = self.preview.as_ref().ok_or("Prepare a new capture first.")?;
        let source = binding.source.as_ref().ok_or("Missing retained source identity.")?;
        if !Arc::ptr_eq(preview.source_project(), &source.project) {
            return Err("Prepared capture source identity changed.".into());
        }
        Ok(())
    }

    fn ui(
        &mut self,
        ui: &mut Ui,
        socket: &str,
        workspace: Option<&Workspace>,
        gate: &WorkGate,
        other_running: bool,
    ) -> Option<WorkflowAction> {
        let busy = other_running || gate.busy() || self.job.is_running();
        ui.horizontal(|ui| {
            for label in ["Connect stopped session", "Refresh stopped session"] {
                if ui.add_enabled(!busy, egui::Button::new(label)).clicked() {
                    self.reset_stop();
                    self.query(
                        ui,
                        socket,
                        workspace,
                        gate,
                        DebuggerRequest::DescribeSession { version: 1, expected_token: None, response_budget: None },
                    );
                    self.form_changed = true;
                }
            }
            if busy {
                ui.spinner();
                ui.label("One bounded local job is pending; closing this window does not release its permit.");
            }
        });
        ui.label("Each inspection button sends one query. No automatic refresh, retry, navigation or target control.");
        ui.label(concat!(
            "Historical, revalidated non-atomic observations: a token does not prove the current stop, ",
            "target authenticity, control flow or layout.",
        ));
        if let Some(session) = &self.session {
            ui.label(format!(
                "Retained stop {} · process {} · target {} · {}",
                session.token.stop_id, session.token.process_unique_id, session.token.target_index, session.triple
            ));
            ui.label(format!("Runtime data byte order: {} (no scalar interpretation)", session.data_order));
        } else {
            ui.label("Not connected. No query has been sent by opening this window.");
        }
        if self.refresh_required {
            ui.colored_label(
                theme::WARNING,
                "Observation refused. Explicit Refresh is required; no recovery was attempted.",
            );
        }
        if let Some(error) = &self.error {
            ui.colored_label(theme::WARNING, error);
        }
        self.selectors(ui, socket, workspace, gate, busy);
        let mut memory_changed = false;
        ui.horizontal(|ui| {
            ui.label("Raw runtime load address (0x)");
            memory_changed |= ui
                .add(
                    TextEdit::singleline(&mut self.memory_address)
                        .id(egui::Id::new("debugger-memory-address"))
                        .char_limit(18)
                        .desired_width(180.0),
                )
                .changed();
            ui.label("Bytes");
            memory_changed |= ui.add(egui::DragValue::new(&mut self.size).range(1..=4096)).changed();
        });
        let mut file_changed = false;
        ui.horizontal(|ui| {
            ui.label("Exact mapping permissions");
            let previous = self.permissions;
            egui::ComboBox::from_id_salt("debugger-permissions")
                .selected_text(PERMISSION_NAMES[self.permissions])
                .show_ui(ui, |ui| {
                    for (index, name) in PERMISSION_NAMES.iter().enumerate() {
                        ui.selectable_value(&mut self.permissions, index, *name);
                    }
                });
            memory_changed |= previous != self.permissions;
            ui.label("File virtual address (0x), not a file offset");
            file_changed |= ui
                .add(
                    TextEdit::singleline(&mut self.file_address)
                        .id(egui::Id::new("debugger-file-address"))
                        .char_limit(18)
                        .desired_width(180.0),
                )
                .changed();
        });
        if memory_changed || file_changed {
            self.edited();
        }
        if memory_changed {
            self.memory = None;
        }
        let token = self.token();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !busy && token.is_some() && self.thread.is_some(),
                    egui::Button::new("Read selected thread registers"),
                )
                .clicked()
            {
                self.query(
                    ui,
                    socket,
                    workspace,
                    gate,
                    DebuggerRequest::ReadRegisters {
                        version: 1,
                        expected_token: token.clone().unwrap(),
                        response_budget: None,
                        thread_id: DebuggerAddress::Integer(self.thread.unwrap()),
                        registers: None,
                    },
                );
            }
            let address = address_value(&self.memory_address);
            if ui
                .add_enabled(!busy && token.is_some() && address.is_ok(), egui::Button::new("Read raw memory"))
                .clicked()
            {
                self.query(
                    ui,
                    socket,
                    workspace,
                    gate,
                    DebuggerRequest::ReadMemory {
                        version: 1,
                        expected_token: token.clone().unwrap(),
                        response_budget: None,
                        address: DebuggerAddress::Integer(address.unwrap()),
                        size: self.size,
                        permissions: selected_permissions(self.permissions),
                        thread_id: self.thread.map(DebuggerAddress::Integer),
                    },
                );
            }
        });
        if let Some(registers) = &self.registers {
            ui.label(RichText::new(format!("Raw registers · thread {:#x}", registers.thread)).strong());
            ui.label(format!("Runtime data byte order: {}", registers.order));
            egui::Grid::new("debugger-register-values").num_columns(2).show(ui, |ui| {
                for (name, value) in &registers.rows {
                    ui.monospace(name);
                    ui.monospace(value);
                    ui.end_row();
                }
            });
        }
        if let Some(memory) = &self.memory {
            ui.label(RichText::new(format!("Raw memory · {:#x} · {} bytes", memory.address, memory.size)).strong());
            ui.label(format!("Runtime data byte order: {}. Hex bytes only; no scalar interpretation.", memory.order));
            ui.label("LLDB ReadMemory may normalize software-breakpoint trap bytes.");
            egui::ScrollArea::vertical().id_salt("debugger-hex").max_height(180.0).show(ui, |ui| {
                for (index, chunk) in memory.bytes.as_bytes().chunks(32).enumerate() {
                    let bytes =
                        chunk.chunks(2).map(|pair| std::str::from_utf8(pair).unwrap()).collect::<Vec<_>>().join(" ");
                    ui.monospace(format!("{:016x}  {bytes}", memory.address + (index * 16) as u64));
                }
            });
        }
        let mut action = None;
        let can_resolve = token.is_some() && self.module.is_some() && address_value(&self.file_address).is_ok();
        if ui.add_enabled(!busy && can_resolve, egui::Button::new("Resolve selected file address")).clicked() {
            let module = self.module.as_ref().unwrap();
            if macho_uuid(&module.uuid).is_ok() {
                action = Some(WorkflowAction::Resolve(format!(
                    "{{\"version\":1,\"operation\":\"resolve_module_address\",\"expected_token\":{},\
                    \"module_uuid\":\"{}\",\"file_address\":\"{}\"}}",
                    self.session.as_ref().unwrap().token_json,
                    module.uuid,
                    self.file_address,
                )));
            } else {
                self.error = Some("Static navigation requires an exact Mach-O module UUID.".into());
            }
        }
        ui.label("Resolution never navigates automatically. Go to uses only the matching already-open static image.");
        ui.separator();
        if let Some(open) = self.capture_ui(ui, socket, workspace, gate, busy) {
            action = Some(WorkflowAction::Open(open));
        }
        ui.collapsing("Advanced: last structured observation JSON", |ui| {
            if let Some(response) = &self.response {
                ui.monospace(format!("operation: {:?}; token: {:?}", response.operation, response.token));
                if let Some(data) = &response.data {
                    ui.add(egui::Label::new(RichText::new(format!("{data:#}")).monospace()).selectable(true));
                }
                if let Some(error) = &response.error {
                    ui.monospace(format!("{}: {}", error.code, error.message));
                }
                ui.monospace(format!("observation: {:?}", response.observation));
            }
        });
        action
    }

    fn selectors(&mut self, ui: &mut Ui, socket: &str, workspace: Option<&Workspace>, gate: &WorkGate, busy: bool) {
        let token = self.token();
        for modules in [true, false] {
            let mut offset = if modules { self.module_offset } else { self.thread_offset };
            let name = if modules { "modules" } else { "threads" };
            let mut query = false;
            ui.horizontal(|ui| {
                ui.label(format!("{name} page offset (32 rows maximum)"));
                if ui.add(egui::DragValue::new(&mut offset).range(0..=4096)).changed() {
                    self.edited();
                }
                query |=
                    ui.add_enabled(!busy && token.is_some(), egui::Button::new(format!("List {name} page"))).clicked();
                let next = if modules {
                    self.modules.as_ref().and_then(|page| page.next)
                } else {
                    self.threads.as_ref().and_then(|page| page.next)
                };
                let previous = if modules {
                    self.modules.as_ref().map(|page| page.offset)
                } else {
                    self.threads.as_ref().map(|page| page.offset)
                };
                if ui
                    .add_enabled(
                        !busy && token.is_some() && previous.is_some_and(|offset| offset > 0),
                        egui::Button::new(format!("Previous {name} page")),
                    )
                    .clicked()
                {
                    offset = previous.unwrap().saturating_sub(32);
                    query = true;
                    self.edited();
                }
                if ui
                    .add_enabled(
                        !busy && token.is_some() && next.is_some(),
                        egui::Button::new(format!("Next {name} page")),
                    )
                    .clicked()
                {
                    offset = next.unwrap();
                    query = true;
                    self.edited();
                }
            });
            if modules {
                self.module_offset = offset;
            } else {
                self.thread_offset = offset;
            }
            if query {
                let expected_token = token.clone().unwrap();
                let request = if modules {
                    DebuggerRequest::ListModules {
                        version: 1,
                        expected_token,
                        response_budget: None,
                        offset: Some(offset),
                        limit: Some(32),
                    }
                } else {
                    DebuggerRequest::ListThreads {
                        version: 1,
                        expected_token,
                        response_budget: None,
                        offset: Some(offset),
                        limit: Some(32),
                    }
                };
                self.query(ui, socket, workspace, gate, request);
            }
        }
        let mut module = None;
        if let Some(page) = &self.modules {
            ui.label(format!(
                "Modules {}..{} of {} · select explicitly",
                page.offset,
                page.offset + page.items.len(),
                page.total
            ));
            for row in &page.items {
                let selected = self.module.as_ref().is_some_and(|module| module.index == row.index);
                if ui
                    .selectable_label(
                        selected,
                        format!("Module {} · {} · {} · {}", row.index, row.name, row.uuid, row.triple),
                    )
                    .clicked()
                {
                    module = Some(row.clone());
                }
            }
        }
        if let Some(module) = module
            && self.module.as_ref() != Some(&module)
        {
            self.edited();
            self.registers = None;
            self.memory = None;
            self.module = Some(module);
        }
        let mut thread = None;
        if let Some(page) = &self.threads {
            ui.label(format!(
                "Threads {}..{} of {} · select explicitly",
                page.offset,
                page.offset + page.items.len(),
                page.total
            ));
            for row in &page.items {
                if ui
                    .selectable_label(
                        self.thread == Some(row.id),
                        format!("Thread {:#x} · stop reason {} · SDK is_stopped {}", row.id, row.reason, row.stopped),
                    )
                    .clicked()
                {
                    thread = Some(row.id);
                }
            }
        }
        if let Some(thread) = thread
            && self.thread != Some(thread)
        {
            self.edited();
            self.registers = None;
            self.memory = None;
            self.thread = Some(thread);
        }
    }

    fn capture_ui(
        &mut self,
        ui: &mut Ui,
        socket: &str,
        workspace: Option<&Workspace>,
        gate: &WorkGate,
        busy: bool,
    ) -> Option<OpenSnapshot> {
        ui.label(RichText::new("Client-local capture preview → Compare / Save → Open saved snapshot").strong());
        ui.label("Prepare authorizes nine fixed token-bound queries under one deadline, with no retry or publication.");
        ui.label(concat!(
            "Button availability uses cached metadata, not CPU subtype/header proof. ",
            "Explicit Prepare validates the exact source header before any query.",
        ));
        ui.label(
            "Historical observations, not the current stop or an atomic transaction. No proven C++ layout or flow.",
        );
        let request = self.capture_request(workspace);
        if let Err(reason) = &request {
            ui.colored_label(theme::DIM, reason);
        }
        if ui.add_enabled(!busy && request.is_ok(), egui::Button::new("Prepare capture preview (9 queries)")).clicked()
        {
            self.invalidate_form();
            self.form_changed = true;
            let request = request.unwrap();
            let source = Arc::clone(&workspace.unwrap().project);
            let socket_path = PathBuf::from(socket);
            self.cancellation = Arc::new(AtomicBool::new(false));
            let cancellation = Arc::clone(&self.cancellation);
            self.start(ui, socket, workspace, gate, WorkKind::Prepare, move || {
                rampage_api::prepare_debugger_capture(
                    source,
                    &socket_path,
                    &request,
                    Duration::from_millis(TIMEOUT_MS),
                    &cancellation,
                )
                .map(|preview| WorkResult::Prepared(Arc::new(preview)))
                .map_err(|error| error.to_string())
            });
        }
        let current = self.validate_preview(socket, workspace).is_ok();
        if let Some(preview) = &self.preview {
            let summary = preview.summary();
            ui.label(format!(
                "Module {} · thread {:#x} · file VA {:#x} → load VA {:#x} · {} bytes",
                summary.module_uuid, summary.thread_id, summary.file_address, summary.load_address, summary.size
            ));
            ui.label(format!(
                "Prepared token: process {} · stop {} · target {}",
                summary.token.process_unique_id, summary.token.stop_id, summary.token.target_index
            ));
            ui.label(format!("Exact captured mapping permissions: {}", permission_name(&summary.permissions)));
            ui.monospace(format!("Bytes SHA-256: {}", summary.bytes_sha256));
            ui.monospace(format!("Document SHA-256: {}", summary.document_sha256));
            for limitation in &summary.limitations {
                ui.colored_label(theme::WARNING, limitation);
            }
            for path in &summary.retained_staging_paths {
                ui.colored_label(
                    theme::WARNING,
                    format!("Prepared capture staging requires operator inspection/cleanup: {}", path.display(),),
                );
            }
        }
        if ui.add_enabled(!busy && current, egui::Button::new("Compare prepared capture with original")).clicked() {
            let preview = Arc::clone(self.preview.as_ref().unwrap());
            self.comparison = None;
            self.start(ui, socket, workspace, gate, WorkKind::Compare, move || {
                preview.compare_original().map(WorkResult::Compared).map_err(|error| error.to_string())
            });
        }
        if let Some(comparison) = &self.comparison {
            ui.label(format!(
                "Prepared capture comparison: {} equal · {} changed · {} unavailable bytes",
                comparison.equal_bytes, comparison.changed_bytes, comparison.unavailable_bytes
            ));
            ui.label("This compares the prepared observations with the retained original, not the saved file.");
            for span in &comparison.spans {
                ui.monospace(format!(
                    "{:#x} → {:#x} · {} bytes · {:?}",
                    span.runtime_address, span.image_address, span.size, span.status
                ));
            }
            for limitation in &comparison.limitations {
                ui.colored_label(theme::WARNING, limitation);
            }
        }
        ui.label("Explicit client-local output path in an existing private 0700 directory; never overwrites a file.");
        ui.label(concat!(
            "An authorized Save may finish after inputs change or this window closes; ",
            "it never opens the file automatically.",
        ));
        if ui
            .add(
                TextEdit::singleline(&mut self.output)
                    .id(egui::Id::new("debugger-capture-output"))
                    .char_limit(1024)
                    .desired_width(f32::INFINITY),
            )
            .changed()
        {
            self.output_revision = Arc::new(());
            self.saved = None;
        }
        let published_output = self.published_destination(&PathBuf::from(&self.output));
        if ui
            .add_enabled(
                !busy && current && !published_output && PathBuf::from(&self.output).is_absolute(),
                egui::Button::new("Save prepared capture"),
            )
            .clicked()
        {
            // Revalidate at the click, not only when deciding whether to draw an enabled button.
            if let Err(error) = self.validate_preview(socket, workspace) {
                self.error = Some(error);
            } else {
                let preview = Arc::clone(self.preview.as_ref().unwrap());
                let path = PathBuf::from(&self.output);
                let document_sha256 = preview.summary().document_sha256.clone();
                self.saved = None;
                self.start(ui, socket, workspace, gate, WorkKind::Save, move || {
                    Ok(match preview.publish(&path) {
                        Ok(publication) => WorkResult::Saved { requested: path, publication },
                        Err(error) => WorkResult::SaveFailed { requested: path, document_sha256, error },
                    })
                });
            }
        }
        if let Some(saved) = &self.saved {
            ui.label(format!("Saved locally: {}. The original workspace is still open.", saved.path.display()));
        }
        self.save_resources_ui(ui);
        let editing = workspace.is_some_and(|workspace| workspace.editing.is_some());
        if editing {
            ui.label("Finish or cancel the unsaved annotation editor before opening a saved capture.");
        }
        let published =
            self.saved.as_ref().is_some_and(|saved| saved.status == DebuggerCapturePublicationStatus::Published);
        if ui
            .add_enabled(
                !busy && current && !editing && published && self.comparison.is_some(),
                egui::Button::new("Open saved snapshot"),
            )
            .clicked()
        {
            if let Err(error) = self.validate_preview(socket, workspace) {
                self.error = Some(error);
                return None;
            }
            let saved = self.saved.as_ref().unwrap();
            return Some(OpenSnapshot {
                path: saved.path.clone(),
                document_sha256: saved.document_sha256.clone(),
                publication_status: saved.status,
                source: SourceIdentity::capture(workspace.unwrap()),
            });
        }
        None
    }

    fn save_resources_ui(&self, ui: &mut Ui) {
        if !self.save_resources.is_empty() {
            ui.label(
                "Save resource notices survive input/workspace changes; they authorize neither opening nor cleanup.",
            );
        }
        for notice in &self.save_resources {
            match notice {
                SaveResourceNotice::Publication(publication) => Self::publication_notice_ui(ui, publication),
                SaveResourceNotice::Failure { requested, document_sha256, message, retention } => {
                    ui.colored_label(
                        theme::WARNING,
                        format!(
                            "Save refusal retained for inspection (not publication authority): {}",
                            requested.display(),
                        ),
                    );
                    ui.monospace(format!("Expected publication document SHA-256: {document_sha256}"));
                    ui.colored_label(theme::WARNING, message);
                    if let Some(retention) = retention {
                        Self::retained_paths_ui(ui, &retention.paths);
                    }
                }
            }
        }
    }

    fn retained_paths_ui(ui: &mut Ui, paths: &[PathBuf]) {
        for path in paths {
            ui.colored_label(
                theme::WARNING,
                format!(
                    "Retained staging requires operator inspection/cleanup (not automatic deletion): {}",
                    path.display(),
                ),
            );
        }
    }

    fn publication_notice_ui(ui: &mut Ui, publication: &DebuggerCapturePublication) {
        let status = match publication.status {
            DebuggerCapturePublicationStatus::Published => "Published by an explicit Save",
            DebuggerCapturePublicationStatus::PublishedUncertain => "Publication uncertain; output may exist",
        };
        ui.colored_label(theme::WARNING, format!("{status}: {}", publication.path.display()));
        ui.monospace(format!("Expected publication document SHA-256: {}", publication.document_sha256));
        for warning in &publication.warnings {
            ui.colored_label(theme::WARNING, warning);
        }
        Self::retained_paths_ui(ui, &publication.retained_staging_paths);
    }
}

const PERMISSION_NAMES: [&str; 4] = ["r--", "rw-", "r-x", "rwx"];

fn permission_name(permissions: &DebuggerPermissions) -> &'static str {
    match permissions {
        DebuggerPermissions::Read => "r--",
        DebuggerPermissions::ReadWrite => "rw-",
        DebuggerPermissions::ReadExecute => "r-x",
        DebuggerPermissions::ReadWriteExecute => "rwx",
    }
}

fn selected_permissions(index: usize) -> DebuggerPermissions {
    match index {
        1 => DebuggerPermissions::ReadWrite,
        2 => DebuggerPermissions::ReadExecute,
        3 => DebuggerPermissions::ReadWriteExecute,
        _ => DebuggerPermissions::Read,
    }
}

fn run_query(socket: PathBuf, request: String, deadline: Instant, revision: Arc<()>) -> Result<QueryReply, String> {
    let submitted = DebuggerRequest::from_json(&request).map_err(|error| error.to_string())?;
    let tool = rampage_api::tools::file_tools()
        .into_iter()
        .find(|tool| tool.name == "query_debugger")
        .ok_or_else(|| "The shared debugger query tool is unavailable.".to_owned())?;
    let mut input = tool.input_schema.clone();
    let fields = input.as_object_mut().ok_or_else(|| "Invalid debugger tool schema.".to_owned())?;
    fields.clear();
    fields.insert("socket".to_owned(), socket.to_string_lossy().as_ref().into());
    // The shared typed parser already refused duplicate and unknown fields before this conversion to a tool value.
    match request.parse() {
        Ok(request) => fields.insert("request".to_owned(), request),
        Err(error) => return Err(format!("invalid debugger request: {error}")),
    };
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .map(|remaining| remaining.as_millis().min(TIMEOUT_MS as u128) as u64)
        .filter(|timeout| *timeout > 0)
        .ok_or_else(|| "Debugger query deadline exceeded.".to_owned())?;
    fields.insert("timeout_ms".to_owned(), timeout.into());
    let response = tool.call(&rampage_api::Packs::default(), input)?;
    if Instant::now() >= deadline {
        return Err("Debugger query deadline exceeded.".to_owned());
    }
    let resolution = if let DebuggerRequest::ResolveModuleAddress { expected_token, .. } = &submitted {
        Some((|| {
            let data = response.get("data").ok_or("Missing resolution data")?;
            let token = response.get("token").ok_or("Missing response token")?;
            if response.get("ok").and_then(|value| value.as_bool()) != Some(true)
                || response.get("operation").and_then(|value| value.as_str()) != Some("resolve_module_address")
                || token.get("backend").and_then(|value| value.as_str()) != Some("lldb-sb")
                || token.get("session_id").and_then(|value| value.as_str()) != Some(&expected_token.session_id)
                || token.get("process_unique_id").and_then(|value| value.as_u64())
                    != Some(expected_token.process_unique_id)
                || token.get("stop_id").and_then(|value| value.as_u64()) != Some(expected_token.stop_id)
                || token.get("target_index").and_then(|value| value.as_u64())
                    != Some(u64::from(expected_token.target_index))
            {
                return Err("Unsuccessful response or submitted token mismatch".into());
            }
            if data.get("interpretation").and_then(|value| value.as_str()) != Some("raw-addresses-only")
                || data.get("proven_flow").and_then(|value| value.as_bool()) != Some(false)
                || data.get("proven_layout").and_then(|value| value.as_bool()) != Some(false)
                || data.get("address_semantics").and_then(|value| value.as_str())
                    != Some("LLDB file virtual address, not a file byte offset")
            {
                return Err("Missing raw SDK address qualifications".into());
            }
            let context = data.get("module_context").ok_or("Missing selected module context")?;
            let section = data.get("section").ok_or("Missing section evidence")?;
            let mut chain = section
                .get("ancestors")
                .and_then(|value| value.as_array())
                .ok_or("Missing ancestor evidence")?
                .iter()
                .collect::<Vec<_>>();
            if chain.len() >= 32 {
                return Err("Section ancestry exceeds UI bound".into());
            }
            chain.push(section);
            let mut sections = Vec::new();
            for row in chain {
                let address = |key| -> Result<u64, String> {
                    address_value(row.get(key).and_then(|value| value.as_str()).ok_or("Missing section address")?)
                };
                let path = row
                    .get("index_path")
                    .and_then(|value| value.as_array())
                    .ok_or("Missing section path")?
                    .iter()
                    .map(|value| value.as_u64().ok_or_else(|| "Invalid section path".to_owned()))
                    .collect::<Result<Vec<_>, _>>()?;
                sections.push(SectionEvidence {
                    path,
                    file_base: address("file_base")?,
                    file_end: address("file_end")?,
                    load_base: address("load_base")?,
                    load_end: address("load_end")?,
                });
            }
            let mapping = data.get("mapping").ok_or("Missing readable runtime mapping")?;
            let result = ResolutionReply {
                token: expected_token.clone(),
                uuid: macho_uuid(data.get("module_uuid").and_then(|value| value.as_str()).ok_or("Missing UUID")?)?,
                file_address: address_value(
                    data.get("file_address").and_then(|value| value.as_str()).ok_or("Missing file address")?,
                )?,
                load_address: address_value(
                    data.get("load_address").and_then(|value| value.as_str()).ok_or("Missing load address")?,
                )?,
                architecture: module_arch(
                    context.get("triple").and_then(|value| value.as_str()).ok_or("Missing module triple")?,
                )?,
                address_bytes: context
                    .get("address_byte_size")
                    .and_then(|value| value.as_u64())
                    .ok_or("Missing module address width")?,
                byte_order: context
                    .get("object_byte_order")
                    .and_then(|value| value.as_str())
                    .ok_or("Missing module object byte order")?
                    .to_owned(),
                section_offset: address_value(
                    section.get("offset").and_then(|value| value.as_str()).ok_or("Missing section offset")?,
                )?,
                sections,
                mapping_base: address_value(
                    mapping.get("base").and_then(|value| value.as_str()).ok_or("Missing mapping base")?,
                )?,
                mapping_end: address_value(
                    mapping.get("end").and_then(|value| value.as_str()).ok_or("Missing mapping end")?,
                )?,
                mapping_permissions: mapping
                    .get("permissions")
                    .and_then(|value| value.as_str())
                    .ok_or("Missing mapping permissions")?
                    .to_owned(),
            };
            let module = data.get("module").ok_or("Missing selected module evidence")?;
            if module.get("uuid").and_then(|value| value.as_str()).map(macho_uuid).transpose()? != Some(result.uuid)
                || module.get("triple") != context.get("triple")
                || module.get("address_byte_size") != context.get("address_byte_size")
                || module.get("target_byte_order") != context.get("object_byte_order")
                || context.get("data_byte_order").and_then(|value| value.get("order")).and_then(|value| value.as_str())
                    != Some("unknown")
            {
                return Err("Inconsistent selected module evidence".into());
            }
            result.matches_request(&submitted)?;
            result.validate()?;
            Ok(result)
        })())
    } else {
        None
    };
    Ok(QueryReply { raw: format!("{response:#}"), resolution, revision })
}

const NAVIGATION_LIMITATION: &str = "UUID correlation does not prove equal runtime/static bytes, the current stop, \
    control flow or layout. Navigation uses only the already-open static image; it does not query or refresh LLDB. \
    Backing metadata checks are not atomic with external file changes.";

#[derive(Debug)]
struct QueryReply {
    raw: String,
    resolution: Option<Result<ResolutionReply, String>>,
    revision: Arc<()>,
}

#[cfg(test)]
impl From<String> for QueryReply {
    fn from(raw: String) -> Self {
        Self { raw, resolution: None, revision: Arc::new(()) }
    }
}

struct WorkspaceBinding {
    instance: Arc<()>,
    project: Weak<Project>,
    path: PathBuf,
    image: Option<rampage_loaders::ImageAt>,
    destination: Result<StaticDestination, String>,
}

impl WorkspaceBinding {
    fn capture(workspace: &Workspace, request: &DebuggerRequest) -> Self {
        let destination = match request {
            DebuggerRequest::ResolveModuleAddress { file_address, .. } => request_address(file_address)
                .and_then(|address| StaticDestination::capture(&workspace.project.binary, address)),
            _ => Err("Only a submitted resolve_module_address can navigate".into()),
        };
        Self {
            instance: Arc::clone(&workspace.instance),
            project: Arc::downgrade(&workspace.project),
            path: workspace.path.clone(),
            image: workspace.image,
            destination,
        }
    }

    fn matches(&self, workspace: &Workspace) -> bool {
        Arc::ptr_eq(&self.instance, &workspace.instance)
            && self.project.ptr_eq(&Arc::downgrade(&workspace.project))
            && self.path == workspace.path
            && self.image == workspace.image
    }

    fn validate_current(&self, workspace: &Workspace) -> Result<(), String> {
        if !self.matches(workspace) {
            return Err("The submitted workspace was replaced; query again.".into());
        }
        workspace.project.binary.validate_backing_source().map_err(|error| {
            format!("Static backing source changed or cannot be verified: {error}; reopen and query again.")
        })
    }
}

struct StaticDestination {
    address: u64,
    uuid: [u8; 16],
    architecture: Arch,
    big_endian: bool,
}

impl StaticDestination {
    fn capture(binary: &Binary, address: u64) -> Result<Self, String> {
        binary.validate_backing_source().map_err(|error| format!("Cannot verify original static backing: {error}"))?;
        let Details::MachO(details) = &binary.details else {
            return Err("The selected static image is not Mach-O".into());
        };
        let uuid = macho_uuid(details.uuid.as_deref().ok_or("The selected static Mach-O has no UUID")?)?;
        if binary.format != Format::MachO || !read_supported_static_variant(binary) {
            return Err("Unsupported selected static architecture or variant".into());
        }
        validate_static_span(binary, address)?;
        let span = instruction_span(binary.arch);
        binary
            .validate_backing_source()
            .map_err(|error| format!("Static backing changed before span validation: {error}"))?;
        if binary.read(address, span).is_none() || binary.decoder().is_err() {
            return Err("Static destination lacks a byte-backed instruction span".into());
        }
        binary
            .validate_backing_source()
            .map_err(|error| format!("Static backing changed during validation: {error}"))?;
        Ok(Self { address, uuid, architecture: binary.arch, big_endian: binary.big_endian })
    }
}

fn instruction_span(arch: Arch) -> u64 {
    if arch == Arch::Aarch64 { 4 } else { 1 }
}

fn validate_static_span(binary: &Binary, address: u64) -> Result<(), String> {
    let span = instruction_span(binary.arch);
    if !address.is_multiple_of(span) {
        return Err("Static destination is not instruction-aligned".into());
    }
    let segment = binary.segment_containing(address).ok_or("Static destination is not mapped")?;
    let end = address.checked_add(span).ok_or("Static destination overflows")?;
    let offset = address.checked_sub(segment.address).ok_or("Static destination precedes segment")?;
    if !segment.perms.read
        || segment.address.checked_add(segment.size).is_none_or(|bound| end > bound)
        || offset.checked_add(span).is_none_or(|end| end > segment.file_size)
    {
        return Err("Static destination lacks a readable, byte-backed instruction span".into());
    }
    Ok(())
}

struct ClickContext {
    request: DebuggerRequest,
    revision: Arc<()>,
    workspace: Option<WorkspaceBinding>,
}

#[derive(Debug)]
struct SectionEvidence {
    path: Vec<u64>,
    file_base: u64,
    file_end: u64,
    load_base: u64,
    load_end: u64,
}

#[derive(Debug)]
struct ResolutionReply {
    token: DebuggerToken,
    uuid: [u8; 16],
    file_address: u64,
    load_address: u64,
    architecture: Arch,
    address_bytes: u64,
    byte_order: String,
    sections: Vec<SectionEvidence>,
    section_offset: u64,
    mapping_base: u64,
    mapping_end: u64,
    mapping_permissions: String,
}

fn native_sdk_width_matches(width: Option<u8>, address_bytes: u64) -> bool {
    width.filter(|width| matches!(width, 4 | 8)).map(u64::from) == Some(address_bytes)
}

impl ResolutionReply {
    fn matches_request(&self, request: &DebuggerRequest) -> Result<(), String> {
        let DebuggerRequest::ResolveModuleAddress { expected_token, module_uuid, file_address, .. } = request else {
            return Err("Only a submitted resolve_module_address can navigate".into());
        };
        let address = request_address(file_address)?;
        if expected_token != &self.token || macho_uuid(module_uuid)? != self.uuid || address != self.file_address {
            return Err("Resolution does not correspond to the submitted token, UUID and file address".into());
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        if !native_sdk_width_matches(self.architecture.default_pointer_size(), self.address_bytes)
            || !matches!(self.byte_order.as_str(), "little" | "big")
        {
            return Err("Unsupported module address width or object byte order".into());
        }
        let limit = if self.address_bytes == 4 { 1u64 << 32 } else { u64::MAX };
        if self.file_address >= limit
            || self.load_address >= limit
            || self.mapping_base >= limit
            || self.mapping_end > limit
            || self.mapping_base >= self.mapping_end
        {
            return Err("SDK addresses or mapping exceed the selected module address width".into());
        }
        let mut parent: Option<&SectionEvidence> = None;
        for section in &self.sections {
            let size = section
                .file_end
                .checked_sub(section.file_base)
                .filter(|size| *size > 0)
                .ok_or("Invalid SDK file section range")?;
            if section.file_base >= limit
                || section.file_end > limit
                || section.load_base >= limit
                || section.load_end > limit
                || section.load_end == u64::MAX
                || section.load_base.checked_add(size) != Some(section.load_end)
                || !(section.file_base..section.file_end).contains(&self.file_address)
                || !(section.load_base..section.load_end).contains(&self.load_address)
                || section.path.len() != parent.map_or(1, |parent| parent.path.len() + 1)
                || section.path.iter().any(|index| *index >= 4096)
            {
                return Err("Inconsistent SDK section range or index path".into());
            }
            if let Some(parent) = parent {
                let relative = section.file_base.checked_sub(parent.file_base).ok_or("Child before ancestor")?;
                if !section.path.starts_with(&parent.path)
                    || section.file_end > parent.file_end
                    || section.load_end > parent.load_end
                    || parent.load_base.checked_add(relative) != Some(section.load_base)
                {
                    return Err("Inconsistent SDK ancestor mapping".into());
                }
            }
            parent = Some(section);
        }
        let leaf = parent.ok_or("Missing SDK leaf section")?;
        if leaf.file_base.checked_add(self.section_offset) != Some(self.file_address)
            || leaf.load_base.checked_add(self.section_offset) != Some(self.load_address)
            || !(self.mapping_base..self.mapping_end).contains(&self.load_address)
            || !matches!(self.mapping_permissions.as_str(), "r--" | "rw-" | "r-x" | "rwx")
        {
            return Err("Inconsistent SDK offset or unreadable runtime mapping".into());
        }
        Ok(())
    }

    fn destination_cached(&self, binary: &Binary, destination: &StaticDestination) -> Result<u64, String> {
        self.validate()?;
        let Details::MachO(details) = &binary.details else {
            return Err("The selected static image is not Mach-O".into());
        };
        if binary.format != Format::MachO || details.uuid.as_deref().map(macho_uuid).transpose()? != Some(self.uuid) {
            return Err("Selected static Mach-O UUID does not match".into());
        }
        if binary.arch != self.architecture
            || !native_sdk_width_matches(binary.arch.default_pointer_size(), self.address_bytes)
            || binary.big_endian != (self.byte_order == "big")
            || destination.architecture != binary.arch
            || destination.big_endian != binary.big_endian
            || destination.uuid != self.uuid
            || destination.address != self.file_address
        {
            return Err("Selected static architecture, variant, width or byte order does not match".into());
        }
        validate_static_span(binary, self.file_address)?;
        Ok(self.file_address)
    }

    #[cfg(test)]
    fn destination(&self, binary: &Binary) -> Result<u64, String> {
        let destination = StaticDestination::capture(binary, self.file_address)?;
        self.destination_cached(binary, &destination)
    }
}

fn request_address(address: &DebuggerAddress) -> Result<u64, String> {
    match address {
        DebuggerAddress::Integer(value) => Ok(*value),
        DebuggerAddress::Hex(value) => address_value(value),
    }
}

fn address_value(text: &str) -> Result<u64, String> {
    let digits = text
        .strip_prefix("0x")
        .filter(|digits| {
            !digits.is_empty() && digits.len() <= 16 && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .ok_or("Invalid hexadecimal SDK address")?;
    u64::from_str_radix(digits, 16).ok().filter(|value| *value != u64::MAX).ok_or_else(|| "Invalid SDK address".into())
}

fn macho_uuid(text: &str) -> Result<[u8; 16], String> {
    let digits = text.replace('-', "");
    if digits.len() != 32
        || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
        || text.len() != 32 && (text.len() != 36 || [8, 13, 18, 23].iter().any(|index| text.as_bytes()[*index] != b'-'))
    {
        return Err("Navigation requires an exact 16-byte Mach-O UUID".into());
    }
    let mut uuid = [0; 16];
    for (index, byte) in uuid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16).map_err(|_| "Invalid Mach-O UUID")?;
    }
    Ok(uuid)
}

fn module_arch(triple: &str) -> Result<Arch, String> {
    match triple.split('-').next() {
        Some("arm64" | "aarch64") => Ok(Arch::Aarch64),
        Some("x86_64") => Ok(Arch::X86_64),
        Some("i386") => Ok(Arch::X86),
        _ => Err("Unsupported selected module architecture or variant".into()),
    }
}

#[cfg(test)]
std::thread_local! {
    static STATIC_HEADER_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn read_supported_static_variant(binary: &Binary) -> bool {
    // Mapped-byte validation belongs to explicit query/navigation actions, not paint-time eligibility.
    #[cfg(test)]
    STATIC_HEADER_READS.with(|reads| reads.set(reads.get() + 1));
    let bytes = binary.image_bytes();
    let Some(header) = bytes.get(..12) else { return false };
    if !matches!(&header[..4], [0xcf, 0xfa, 0xed, 0xfe] | [0xce, 0xfa, 0xed, 0xfe]) {
        return false;
    }
    let cpu = u32::from_le_bytes(header[4..8].try_into().unwrap());
    let subtype = u32::from_le_bytes(header[8..12].try_into().unwrap());
    matches!(
        (binary.arch, header[0], cpu, subtype),
        (Arch::Aarch64, 0xcf, 0x0100_000c, 0) | (Arch::X86_64, 0xcf, 0x0100_0007, 3) | (Arch::X86, 0xce, 7, 3)
    )
}

const REJECTED_INPUT: &str = "Input exceeded 16 KiB and was rejected, not truncated. \
                            Insert a template or Clear local data before querying.";

struct RequestEditor<'a> {
    text: &'a mut String,
    rejected: &'a mut bool,
    edited: &'a mut bool,
}

impl TextBuffer for RequestEditor<'_> {
    fn is_mutable(&self) -> bool {
        true
    }

    fn as_str(&self) -> &str {
        self.text
    }

    fn insert_text(&mut self, text: &str, char_index: egui::text::CharIndex) -> usize {
        *self.edited = true;
        if text.len() > MAX_DEBUGGER_REQUEST_BYTES.saturating_sub(self.text.len()) {
            *self.rejected = true;
            return 0;
        }
        self.text.insert_text(text, char_index)
    }

    fn delete_char_range(&mut self, char_range: std::ops::Range<egui::text::CharIndex>) {
        *self.edited = true;
        self.text.delete_char_range(char_range);
    }

    fn replace_with(&mut self, text: &str) {
        *self.edited = true;
        if text.len() > MAX_DEBUGGER_REQUEST_BYTES {
            *self.rejected = true;
            return;
        }
        self.text.replace_with(text);
    }

    fn type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<RequestEditor<'static>>()
    }
}

fn template(index: usize) -> String {
    if index == 0 {
        return "{\n  \"version\": 1,\n  \"operation\": \"describe_session\"\n}".to_owned();
    }
    let fields = match index {
        1 | 2 => ",\n  \"offset\": 0,\n  \"limit\": 32",
        3 => ",\n  \"thread_id\": \"REPLACE_THREAD_ID\"",
        5 => ",\n  \"module_uuid\": \"REPLACE_MODULE_UUID\",\n  \"file_address\": \"REPLACE_FILE_ADDRESS\"",
        _ => ",\n  \"address\": \"REPLACE_ADDRESS\",\n  \"size\": 64,\n  \"permissions\": \"r--\"",
    };
    format!(
        "{{\n  \"version\": 1,\n  \"operation\": \"{}\",\n  \
         \"expected_token\": \"REPLACE_WITH_RETURNED_TOKEN_OBJECT\"{fields}\n}}",
        OPERATIONS[index],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui_kittest::Harness;
    use egui_kittest::kittest::{NodeT, Queryable};

    const TEST_UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const FILE_BASE: u64 = 0x1_0000_0000;
    const FILE_ADDRESS: u64 = FILE_BASE + 0x204;

    #[test]
    fn native_sdk_width_does_not_admit_unknown_or_non_native_slot_sizes() {
        assert!(!native_sdk_width_matches(None, 8));
        assert!(!native_sdk_width_matches(None, 4));
        assert!(!native_sdk_width_matches(Some(2), 2));
        assert!(!native_sdk_width_matches(Some(4), 8));
        assert!(native_sdk_width_matches(Some(4), 4));
        assert!(native_sdk_width_matches(Some(8), 8));
    }

    fn open_advanced<T>(harness: &mut Harness<'_, T>) {
        harness.get_by_label("Advanced: raw requests and JSON responses").click_accesskit();
        harness.run();
    }

    struct StaticFixture {
        directory: PathBuf,
        path: PathBuf,
    }

    impl StaticFixture {
        fn new(bytes: &[u8]) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "rampage-ui-static-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir(&directory).unwrap();
            let path = directory.join("image.macho");
            std::fs::write(&path, bytes).unwrap();
            Self { directory, path }
        }

        fn workspace(&self) -> Workspace {
            Workspace::open(
                &rampage_api::Session::default(),
                self.path.clone(),
                None,
                None,
                &egui::Context::default(),
                true,
            )
            .unwrap()
        }
    }

    impl Drop for StaticFixture {
        fn drop(&mut self) {
            // This fixture owns its freshly created directory; production never cleans publication paths.
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn thin_macho(arch: Arch, uuid: &str) -> Vec<u8> {
        let mut bytes = vec![0; 0x1000];
        let (cpu, subtype) = match arch {
            Arch::Aarch64 => (0x0100_000c, 0),
            Arch::X86_64 => (0x0100_0007, 3),
            _ => panic!("fixture architecture unsupported"),
        };
        for (offset, value) in [
            (0, 0xfeed_facfu32),
            (4, cpu),
            (8, subtype),
            (12, 2),
            (16, 2),
            (20, 176),
            (32, 0x19),
            (36, 152),
            (88, 7),
            (92, 5),
            (96, 1),
            (152, 0x200),
            (156, 2),
            (168, 0x8000_0400),
            (184, 0x1b),
            (188, 24),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(56, FILE_BASE), (64, 0x1000), (80, 0x1000), (136, FILE_BASE + 0x200), (144, 0x100)] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[40..46].copy_from_slice(b"__TEXT");
        bytes[104..110].copy_from_slice(b"__text");
        bytes[120..126].copy_from_slice(b"__TEXT");
        bytes[192..208].copy_from_slice(&macho_uuid(uuid).unwrap());
        if arch == Arch::Aarch64 {
            for word in bytes[0x200..0x300].as_chunks_mut::<4>().0 {
                word.copy_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
            }
        } else {
            bytes[0x200..0x300].fill(0xc3);
        }
        bytes
    }

    fn test_token() -> DebuggerToken {
        DebuggerToken {
            backend: rampage_api::DebuggerBackend::LldbSb,
            session_id: "ui-local-session".into(),
            process_unique_id: 17,
            stop_id: 4,
            target_index: 0,
        }
    }

    fn test_resolution() -> ResolutionReply {
        ResolutionReply {
            token: test_token(),
            uuid: macho_uuid(TEST_UUID).unwrap(),
            file_address: FILE_ADDRESS,
            load_address: 0x1804,
            architecture: Arch::Aarch64,
            address_bytes: 8,
            byte_order: "little".into(),
            sections: vec![
                SectionEvidence {
                    path: vec![0],
                    file_base: FILE_BASE,
                    file_end: FILE_BASE + 0x1000,
                    load_base: 0x1600,
                    load_end: 0x2600,
                },
                SectionEvidence {
                    path: vec![0, 0],
                    file_base: FILE_BASE + 0x200,
                    file_end: FILE_BASE + 0x300,
                    load_base: 0x1800,
                    load_end: 0x1900,
                },
            ],
            section_offset: 4,
            mapping_base: 0x1000,
            mapping_end: 0x3000,
            mapping_permissions: "r-x".into(),
        }
    }

    fn resolution_request() -> String {
        serde_json::json!({"version":1,"operation":"resolve_module_address", "expected_token":test_token(),
            "module_uuid":TEST_UUID.to_uppercase(),"file_address":format!("{FILE_ADDRESS:#x}")})
        .to_string()
    }

    #[cfg(unix)]
    #[test]
    fn static_destination_requires_exact_uuid_architecture_width_endian_permissions_and_backing() {
        let fixture = StaticFixture::new(&thin_macho(Arch::Aarch64, TEST_UUID));
        let binary = Binary::open(&fixture.path).unwrap();
        assert_eq!(test_resolution().destination(&binary).unwrap(), FILE_ADDRESS);
        for change in [
            "uuid",
            "missing-uuid",
            "architecture",
            "width",
            "endian",
            "permission",
            "backing",
            "partial-instruction",
            "unmapped",
            "segment-overflow",
            "unaligned",
        ] {
            let mut binary = Binary::open(&fixture.path).unwrap();
            let mut reply = test_resolution();
            match change {
                "uuid" => reply.uuid[0] ^= 1,
                "missing-uuid" => {
                    let Details::MachO(details) = &mut binary.details else { unreachable!() };
                    details.uuid = None;
                }
                "architecture" => reply.architecture = Arch::X86_64,
                "width" => reply.address_bytes = 4,
                "endian" => reply.byte_order = "big".into(),
                "permission" => binary.segments[0].perms.read = false,
                "backing" => binary.segments[0].file_size = 0x204,
                "partial-instruction" => binary.segments[0].file_size = 0x206,
                "unmapped" => binary.segments.clear(),
                "segment-overflow" => binary.segments[0].size = u64::MAX,
                "unaligned" => {
                    reply.file_address += 1;
                    reply.load_address += 1;
                    reply.section_offset += 1;
                }
                _ => unreachable!(),
            }
            assert!(reply.destination(&binary).is_err(), "accepted {change}");
        }
        let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
        let mut reply = test_resolution();
        reply.architecture = Arch::X86_64;
        assert_eq!(reply.destination(&Binary::open(&fixture.path).unwrap()).unwrap(), FILE_ADDRESS);
    }

    #[test]
    fn returned_resolution_must_correspond_to_the_submitted_operation_uuid_address_and_stop_token() {
        for change in ["operation", "uuid", "address", "session", "process", "stop", "target"] {
            let mut request = DebuggerRequest::from_json(&resolution_request()).unwrap();
            if change == "operation" {
                request = DebuggerRequest::from_json(&template(0)).unwrap();
            } else {
                let DebuggerRequest::ResolveModuleAddress { expected_token, module_uuid, file_address, .. } =
                    &mut request
                else {
                    unreachable!()
                };
                match change {
                    "uuid" => *module_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
                    "address" => *file_address = DebuggerAddress::Integer(FILE_ADDRESS + 4),
                    "session" => expected_token.session_id.push('x'),
                    "process" => expected_token.process_unique_id += 1,
                    "stop" => expected_token.stop_id += 1,
                    "target" => expected_token.target_index += 1,
                    _ => unreachable!(),
                }
            }
            assert!(test_resolution().matches_request(&request).is_err(), "accepted {change}");
        }
        let mut request = DebuggerRequest::from_json(&resolution_request()).unwrap();
        let DebuggerRequest::ResolveModuleAddress { file_address, .. } = &mut request else { unreachable!() };
        *file_address = DebuggerAddress::Integer(FILE_ADDRESS);
        assert!(test_resolution().matches_request(&request).is_ok());
    }

    #[test]
    fn sdk_section_and_ancestor_mapping_must_be_internally_consistent() {
        for change in [
            "file-end",
            "load-end",
            "offset",
            "file-address",
            "load-address",
            "ancestor-file",
            "ancestor-load",
            "ancestor-path",
            "missing-ancestor",
            "empty-chain",
            "mapping-gap",
            "mapping-permission",
        ] {
            let mut reply = test_resolution();
            match change {
                "file-end" => reply.sections[1].file_end = reply.sections[1].file_base,
                "load-end" => reply.sections[1].load_end += 1,
                "offset" => reply.section_offset += 1,
                "file-address" => reply.file_address = u64::MAX,
                "load-address" => reply.load_address += 1,
                "ancestor-file" => reply.sections[0].file_end = FILE_BASE + 0x208,
                "ancestor-load" => {
                    reply.sections[0].load_base += 1;
                    reply.sections[0].load_end += 1;
                }
                "ancestor-path" => reply.sections[1].path[0] = 1,
                "missing-ancestor" => {
                    reply.sections.remove(0);
                }
                "empty-chain" => reply.sections.clear(),
                "mapping-gap" => reply.mapping_base = 0x1805,
                "mapping-permission" => reply.mapping_permissions = "--x".into(),
                _ => unreachable!(),
            }
            assert!(reply.validate().is_err(), "accepted {change}");
        }
    }

    #[test]
    fn sdk_load_addresses_and_mapping_bounds_must_fit_the_explicit_address_width() {
        let mut narrow = test_resolution();
        narrow.architecture = Arch::X86;
        narrow.address_bytes = 4;
        narrow.file_address = 0x1204;
        narrow.load_address = 0x1204;
        narrow.section_offset = 0x204;
        narrow.sections = vec![SectionEvidence {
            path: vec![0],
            file_base: 0x1000,
            file_end: 0x2000,
            load_base: 0x1000,
            load_end: 0x2000,
        }];
        narrow.mapping_base = 0x1000;
        narrow.mapping_end = 0x2000;
        assert!(narrow.validate().is_ok());
        let high = 1u64 << 32;
        narrow.load_address += high;
        narrow.sections[0].load_base += high;
        narrow.sections[0].load_end += high;
        narrow.mapping_base += high;
        narrow.mapping_end += high;
        assert!(narrow.validate().is_err());

        for (arch, width, end) in [(Arch::X86, 4, 1u64 << 32), (Arch::X86_64, 8, u64::MAX - 1)] {
            let mut reply = test_resolution();
            reply.architecture = arch;
            reply.address_bytes = width;
            reply.file_address = end - 4;
            reply.load_address = end - 4;
            reply.section_offset = 12;
            reply.sections = vec![SectionEvidence {
                path: vec![0],
                file_base: end - 16,
                file_end: end,
                load_base: end - 16,
                load_end: end,
            }];
            reply.mapping_base = end - 16;
            reply.mapping_end = end;
            assert!(reply.validate().is_ok(), "rejected {width}-byte boundary");
            reply.mapping_end = end + 1;
            if width == 4 {
                assert!(reply.validate().is_err());
            }
            reply.mapping_end = end;
            reply.sections[0].load_base = u64::MAX - 7;
            assert!(reply.validate().is_err(), "accepted overflowing section");
        }
        for width in [0, 1, 2, 3, 5, 6, 7, 9, u64::MAX] {
            let mut reply = test_resolution();
            reply.address_bytes = width;
            assert!(reply.validate().is_err(), "accepted malformed address width {width}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn static_variants_are_not_guessed_from_the_architecture_family() {
        for (arch, subtype) in [(Arch::Aarch64, 2u32), (Arch::X86_64, 8)] {
            let mut bytes = thin_macho(arch, TEST_UUID);
            bytes[8..12].copy_from_slice(&subtype.to_le_bytes());
            let fixture = StaticFixture::new(&bytes);
            let binary = Binary::open(&fixture.path).unwrap();
            let mut reply = test_resolution();
            reply.architecture = arch;
            assert!(reply.destination(&binary).is_err());
        }
        for triple in ["arm64e-apple-macosx", "x86_64h-apple-macosx", "armv7-apple-ios", "unknown"] {
            assert!(module_arch(triple).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn only_the_selected_universal_or_embedded_image_uuid_is_used() {
        let other_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let x86 = thin_macho(Arch::X86_64, other_uuid);
        let arm = thin_macho(Arch::Aarch64, TEST_UUID);
        let mut fat = vec![0; 0x3000];
        for (offset, value) in [
            (0, 0xcafe_babeu32),
            (4, 2),
            (8, 0x0100_0007),
            (12, 3),
            (16, 0x1000),
            (20, 0x1000),
            (24, 12),
            (28, 0x0100_000c),
            (36, 0x2000),
            (40, 0x1000),
            (44, 12),
        ] {
            fat[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        fat[0x1000..0x2000].copy_from_slice(&x86);
        fat[0x2000..].copy_from_slice(&arm);
        for embedded in [false, true] {
            let mut bytes = if embedded { vec![0x55; 0x1000] } else { Vec::new() };
            bytes.extend_from_slice(&fat);
            let fixture = StaticFixture::new(&bytes);
            let image = embedded.then_some(rampage_loaders::ImageAt::new(0x1000, Some(fat.len() as u64)));
            let selected = Binary::open_image(&fixture.path, image, Some(Arch::Aarch64)).unwrap();
            assert_eq!(test_resolution().destination(&selected).unwrap(), FILE_ADDRESS);
            let other = Binary::open_image(&fixture.path, image, Some(Arch::X86_64)).unwrap();
            assert!(test_resolution().destination(&other).is_err());
        }
    }

    fn bound_debugger(workspace: Option<&Workspace>) -> Debugger {
        let mut debugger = Debugger {
            shown: true,
            socket: "/private/operator.sock".into(),
            request: resolution_request(),
            ..Default::default()
        };
        debugger.submitted = Some((debugger.socket.clone(), debugger.request.clone()));
        debugger.click_context = Some(ClickContext {
            request: DebuggerRequest::from_json(&debugger.request).unwrap(),
            revision: Arc::clone(&debugger.input_revision),
            workspace: workspace.map(|workspace| {
                WorkspaceBinding::capture(workspace, &DebuggerRequest::from_json(&debugger.request).unwrap())
            }),
        });
        debugger.job = Job::Done(Ok(QueryReply {
            raw: "raw local evidence".into(),
            resolution: Some(Ok(test_resolution())),
            revision: Arc::clone(&debugger.input_revision),
        }));
        debugger
    }

    fn capture_ready_workflow(workspace: &Workspace) -> Workflow {
        let mut workflow = stopped_workflow("x86_64", "little", Some(workspace));
        workflow.module = Some(ModuleRow {
            index: 0,
            name: "controlled image".into(),
            uuid: TEST_UUID.into(),
            triple: "x86_64-apple-macosx".into(),
            width: 8,
            object_order: "little".into(),
        });
        workflow.thread = Some(7);
        workflow.file_address = format!("{FILE_ADDRESS:#x}");
        workflow.size = 4;
        workflow.permissions = 2;
        workflow
    }

    fn x64_bound_debugger(workspace: &Workspace) -> Debugger {
        let mut debugger = bound_debugger(Some(workspace));
        let Job::Done(Ok(reply)) = &mut debugger.job else { panic!("missing controlled resolution") };
        let Some(Ok(resolution)) = &mut reply.resolution else { panic!("missing controlled resolution") };
        resolution.architecture = Arch::X86_64;
        debugger.workflow = capture_ready_workflow(workspace);
        debugger.workflow.socket = debugger.socket.clone();
        debugger
    }

    #[cfg(unix)]
    #[test]
    fn debugger_paint_never_reads_mapped_headers_before_or_after_source_mutation_or_truncation() {
        use std::io::Write;

        for truncate in [false, true] {
            let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
            let workspace = fixture.workspace();
            let project = Arc::clone(&workspace.project);
            let metadata = CaptureSourceMetadata::from_cached(&project.binary);
            let debugger = x64_bound_debugger(&workspace);
            let initial_reads = STATIC_HEADER_READS.with(std::cell::Cell::get);
            let mut harness = Harness::builder().with_size(egui::vec2(1500.0, 1300.0)).build_ui_state(
                |ui, state: &mut (Debugger, Workspace)| state.0.show(ui.ctx(), Some(&mut state.1)),
                (debugger, workspace),
            );
            harness.run();
            assert!(!harness.get_by_label("Prepare capture preview (9 queries)").accesskit_node().is_disabled());
            harness.get_by_label("Go to matching static image address");
            assert_eq!(STATIC_HEADER_READS.with(std::cell::Cell::get), initial_reads);
            if truncate {
                std::fs::OpenOptions::new().write(true).open(&fixture.path).unwrap().set_len(0).unwrap();
            } else {
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&fixture.path)
                    .unwrap()
                    .write_all(b"observable backing mutation before paint")
                    .unwrap();
            }
            assert!(project.binary.validate_backing_source().is_err());
            assert!(metadata.supports_capture_family(), "cached family is not proof of current backing");
            assert_eq!(metadata.uuid.map(macho_uuid).transpose().unwrap(), Some(macho_uuid(TEST_UUID).unwrap()));
            for _ in 0..3 {
                harness.run();
                assert!(harness.get_by_label("Prepare capture preview (9 queries)").accesskit_node().is_disabled());
                assert!(harness.query_by_label("Go to matching static image address").is_none());
                assert!(harness.state().0.click_context.is_none());
                assert_eq!(harness.state().1.cursor, 0);
                assert_eq!(STATIC_HEADER_READS.with(std::cell::Cell::get), initial_reads);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn explicit_goto_revalidates_the_static_header_but_paint_uses_only_cached_navigation_facts() {
        let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
        let workspace = fixture.workspace();
        let debugger = x64_bound_debugger(&workspace);
        let initial_reads = STATIC_HEADER_READS.with(std::cell::Cell::get);
        let mut harness = Harness::builder().with_size(egui::vec2(1500.0, 1300.0)).build_ui_state(
            |ui, state: &mut (Debugger, Workspace)| state.0.show(ui.ctx(), Some(&mut state.1)),
            (debugger, workspace),
        );
        harness.run();
        assert_eq!(STATIC_HEADER_READS.with(std::cell::Cell::get), initial_reads);
        assert_eq!(harness.state().1.cursor, 0);
        harness.get_by_label("Go to matching static image address").click_accesskit();
        harness.run();
        assert_eq!(STATIC_HEADER_READS.with(std::cell::Cell::get), initial_reads + 1);
        assert_eq!(harness.state().1.cursor, FILE_ADDRESS);
        assert!(harness.state().1.can_go_back());
        for _ in 0..3 {
            harness.run();
            assert_eq!(STATIC_HEADER_READS.with(std::cell::Cell::get), initial_reads + 1);
            assert!(!harness.state().0.busy());
        }
    }

    #[cfg(unix)]
    #[test]
    fn cached_capture_eligibility_disables_known_unsupported_sdk_variants_without_reading_the_image() {
        for triple in ["x86_64h-apple-macosx", "arm64e-apple-macosx", "unknown"] {
            let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
            let workspace = fixture.workspace();
            let mut workflow = capture_ready_workflow(&workspace);
            workflow.module.as_mut().unwrap().triple = triple.into();
            let debugger = Debugger { shown: true, socket: workflow.socket.clone(), workflow, ..Default::default() };
            let initial_reads = STATIC_HEADER_READS.with(std::cell::Cell::get);
            let mut harness = Harness::builder().with_size(egui::vec2(1500.0, 1300.0)).build_ui_state(
                |ui, state: &mut (Debugger, Workspace)| state.0.show(ui.ctx(), Some(&mut state.1)),
                (debugger, workspace),
            );
            harness.run();
            assert!(harness.get_by_label("Prepare capture preview (9 queries)").accesskit_node().is_disabled());
            harness.get_by_label(concat!(
                "Button availability uses cached metadata, not CPU subtype/header proof. ",
                "Explicit Prepare validates the exact source header before any query.",
            ));
            assert!(harness.state().0.workflow.token().is_some(), "inspection remains independent of capture scope");
            assert_eq!(STATIC_HEADER_READS.with(std::cell::Cell::get), initial_reads);
            assert!(!harness.state().0.busy());
        }
    }

    #[cfg(unix)]
    #[test]
    fn workspace_instance_project_replacement_and_missing_submission_workspace_refuse_navigation() {
        let fixture = StaticFixture::new(&thin_macho(Arch::Aarch64, TEST_UUID));
        let mut workspace = fixture.workspace();
        let mut debugger = bound_debugger(Some(&workspace));
        assert_eq!(debugger.destination(Some(&workspace)).unwrap(), FILE_ADDRESS);
        let reopened = fixture.workspace();
        assert!(debugger.destination(Some(&reopened)).is_err());
        workspace.project = Arc::clone(&reopened.project);
        assert!(debugger.destination(Some(&workspace)).is_err());
        debugger.check_context(Some(&workspace));
        assert!(debugger.click_context.is_none());
        let debugger = bound_debugger(None);
        assert!(debugger.destination(Some(&reopened)).is_err());
        assert!(debugger.destination(None).unwrap_err().contains("No workspace was open"));
    }

    #[cfg(unix)]
    #[test]
    fn source_overwrite_replacement_and_truncation_refuse_before_debugger_paint_or_click() {
        use std::fs::{File, FileTimes};
        use std::io::{Seek, SeekFrom, Write};
        use std::time::Duration;

        for change in ["uuid", "replace", "truncate"] {
            let fixture = StaticFixture::new(&thin_macho(Arch::Aarch64, TEST_UUID));
            let workspace = fixture.workspace();
            let debugger = bound_debugger(Some(&workspace));
            let mut harness = Harness::builder().with_size(egui::vec2(1400.0, 1100.0)).build_ui_state(
                |ui, state: &mut (Debugger, Workspace)| state.0.show(ui.ctx(), Some(&mut state.1)),
                (debugger, workspace),
            );
            harness.run();
            harness.get_by_label("Go to matching static image address");
            match change {
                "uuid" => {
                    let mut file = File::options().write(true).open(&fixture.path).unwrap();
                    let modified = file.metadata().unwrap().modified().unwrap();
                    file.seek(SeekFrom::Start(192)).unwrap();
                    file.write_all(&[0xaa; 16]).unwrap();
                    file.set_times(FileTimes::new().set_modified(modified + Duration::from_secs(1))).unwrap();
                }
                "replace" => {
                    let replacement = fixture.directory.join("replacement");
                    std::fs::write(&replacement, thin_macho(Arch::Aarch64, TEST_UUID)).unwrap();
                    std::fs::rename(replacement, &fixture.path).unwrap();
                }
                "truncate" => File::options().write(true).open(&fixture.path).unwrap().set_len(0).unwrap(),
                _ => unreachable!(),
            }
            let (debugger, workspace) = harness.state_mut();
            assert!(workspace.project.binary.validate_backing_source().is_err());
            debugger.navigate(Some(&mut *workspace));
            assert_eq!(workspace.cursor, 0, "navigated after {change}");
            harness.run();
            assert!(harness.state().0.click_context.is_none());
            assert!(harness.query_by_label("Go to matching static image address").is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_cached_project_cannot_adopt_a_later_source_stamp_at_workspace_or_query_creation() {
        use std::fs::{File, FileTimes};
        use std::io::{Seek, SeekFrom, Write};

        let fixture = StaticFixture::new(&thin_macho(Arch::Aarch64, TEST_UUID));
        let session = rampage_api::Session::default();
        let ctx = egui::Context::default();
        let original = Workspace::open(&session, fixture.path.clone(), None, None, &ctx, true).unwrap();
        let mut file = File::options().write(true).open(&fixture.path).unwrap();
        let modified = file.metadata().unwrap().modified().unwrap();
        file.seek(SeekFrom::Start(192)).unwrap();
        file.write_all(&[0xaa; 16]).unwrap();
        file.set_times(FileTimes::new().set_modified(modified)).unwrap();
        assert!(original.project.binary.validate_backing_source().is_err());
        let cached = Workspace::open(&session, fixture.path.clone(), None, None, &ctx, true).unwrap();
        assert!(Arc::ptr_eq(&original.project, &cached.project));
        let debugger = bound_debugger(Some(&cached));
        assert!(debugger.click_context.as_ref().unwrap().workspace.as_ref().unwrap().destination.is_err());
        assert!(debugger.destination(Some(&cached)).is_err());
        assert_eq!(cached.cursor, 0);
    }

    #[cfg(unix)]
    #[test]
    fn invalidation_and_response_epoch_prevent_late_completion_and_aba_navigation() {
        let fixture = StaticFixture::new(&thin_macho(Arch::Aarch64, TEST_UUID));
        let workspace = fixture.workspace();
        let mut debugger = bound_debugger(Some(&workspace));
        let old_reply = std::mem::replace(&mut debugger.job, Job::Idle);
        debugger.invalidate_navigation();
        debugger.job = old_reply;
        assert!(debugger.destination(Some(&workspace)).is_err());
        debugger.click_context = Some(ClickContext {
            request: DebuggerRequest::from_json(&debugger.request).unwrap(),
            revision: Arc::clone(&debugger.input_revision),
            workspace: Some(WorkspaceBinding::capture(
                &workspace,
                &DebuggerRequest::from_json(&debugger.request).unwrap(),
            )),
        });
        assert!(debugger.destination(Some(&workspace)).unwrap_err().contains("obsolete query"));
    }

    #[cfg(unix)]
    #[test]
    fn request_edit_roundtrip_and_rejected_paste_invalidate_even_when_text_is_unchanged() {
        for rejected_paste in [false, true] {
            let fixture = StaticFixture::new(&thin_macho(Arch::Aarch64, TEST_UUID));
            let workspace = fixture.workspace();
            let debugger = bound_debugger(Some(&workspace));
            let original = debugger.request.clone();
            let mut harness = Harness::builder().with_size(egui::vec2(1400.0, 1100.0)).build_ui_state(
                |ui, state: &mut (Debugger, Workspace)| {
                    state.0.show(ui.ctx(), Some(&mut state.1));
                },
                (debugger, workspace),
            );
            harness.run();
            open_advanced(&mut harness);
            let id = egui::Id::new("debugger-request");
            harness.ctx.memory_mut(|memory| memory.request_focus(id));
            harness.run();
            harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
            harness.run();
            if rejected_paste {
                harness.event(egui::Event::Paste("x".repeat(MAX_DEBUGGER_REQUEST_BYTES + 1)));
            } else {
                harness.input_mut().events.extend([
                    egui::Event::Paste(format!("{original} ")),
                    egui::Event::Key {
                        key: egui::Key::Backspace,
                        physical_key: None,
                        pressed: true,
                        repeat: false,
                        modifiers: egui::Modifiers::NONE,
                    },
                ]);
            }
            harness.run();
            assert_eq!(harness.state().0.request, original);
            assert!(harness.state().0.click_context.is_none());
            assert!(harness.query_by_label("Go to matching static image address").is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    fn socket_template_and_clear_edits_remove_the_navigation_offer() {
        for action in ["socket", "template", "insert-template", "clear"] {
            let fixture = StaticFixture::new(&thin_macho(Arch::Aarch64, TEST_UUID));
            let workspace = fixture.workspace();
            let debugger = bound_debugger(Some(&workspace));
            let mut harness = Harness::builder().with_size(egui::vec2(1400.0, 1100.0)).build_ui_state(
                |ui, state: &mut (Debugger, Workspace)| state.0.show(ui.ctx(), Some(&mut state.1)),
                (debugger, workspace),
            );
            harness.run();
            assert!(harness.query_by_label("Request JSON (at most 16 KiB)").is_none());
            open_advanced(&mut harness);
            harness.get_by_label("Request JSON (at most 16 KiB)");
            harness.get_by_label("Go to matching static image address");
            match action {
                "socket" => {
                    harness.ctx.memory_mut(|memory| memory.request_focus(egui::Id::new("debugger-socket")));
                    harness.run();
                    harness.event(egui::Event::Paste("changed".into()));
                }
                "template" => {
                    harness.get_by_value("describe_session").click_accesskit();
                    harness.run();
                    harness.get_by_label("list_modules").click_accesskit();
                }
                "insert-template" => harness.get_by_label("Insert template").click_accesskit(),
                "clear" => harness.get_by_label("Clear local data").click_accesskit(),
                _ => unreachable!(),
            }
            harness.run();
            assert!(harness.state().0.click_context.is_none(), "kept binding after {action}");
            assert!(harness.query_by_label("Go to matching static image address").is_none());
            assert_eq!(harness.state().1.cursor, 0);
        }
    }

    #[test]
    fn a_new_refused_query_invalidates_a_previous_actionable_result() {
        let fixture = StaticFixture::new(&thin_macho(Arch::Aarch64, TEST_UUID));
        let workspace = fixture.workspace();
        let mut debugger = bound_debugger(Some(&workspace));
        debugger.socket.clear();
        debugger.query(&egui::Context::default(), Some(&workspace));
        assert!(debugger.click_context.is_none());
        assert!(debugger.job.ready().is_none());
        assert!(debugger.destination(Some(&workspace)).is_err());
    }

    fn key_event(key: egui::Key, modifiers: egui::Modifiers) -> egui::Event {
        egui::Event::Key { key, physical_key: None, pressed: true, repeat: false, modifiers }
    }

    #[test]
    fn oversized_paste_events_preserve_select_all_and_partial_selection() {
        let original = concat!(
            r#"{"version":1,"operation":"describe_session","expected_token":{"backend":"lldb-sb","#,
            r#""session_id":"private-é","process_unique_id":17,"stop_id":4,"target_index":0}}"#,
        );
        for select_all in [true, false] {
            let debugger = Debugger {
                shown: true,
                socket: "/private/operator.sock".to_owned(),
                request: original.to_owned(),
                ..Default::default()
            };
            let mut harness = Harness::builder()
                .with_size(egui::vec2(1400.0, 860.0))
                .build_ui_state(|ui, debugger: &mut Debugger| debugger.show(ui.ctx(), None), debugger);
            harness.run();
            open_advanced(&mut harness);
            let id = egui::Id::new("debugger-request");
            harness.ctx.memory_mut(|memory| memory.request_focus(id));
            harness.run();
            if select_all {
                harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
                harness.run();
            } else {
                let start = original[..original.find("private-é").unwrap()].chars().count();
                let end = start + "private-é".chars().count();
                let mut state = egui::text_edit::TextEditState::load(&harness.ctx, id).unwrap();
                state.cursor.set_char_range(Some(egui::text::CCursorRange::two(
                    egui::text::CCursor::new(start),
                    egui::text::CCursor::new(end),
                )));
                state.store(&harness.ctx, id);
                harness.run();
            }
            let selection =
                egui::text_edit::TextEditState::load(&harness.ctx, id).unwrap().cursor.char_range().unwrap();
            let selected_bytes = selection.slice_str(original).len();
            assert_eq!(selected_bytes, if select_all { original.len() } else { "private-é".len() });
            let paste_bytes = MAX_DEBUGGER_REQUEST_BYTES - (original.len() - selected_bytes) + 1;
            harness.event(egui::Event::Paste("x".repeat(paste_bytes)));
            harness.run();
            assert_eq!(harness.state().request, original);
            assert!(harness.state().request_rejected);
            let after = egui::text_edit::TextEditState::load(&harness.ctx, id).unwrap().cursor.char_range().unwrap();
            assert_eq!(after, selection);
            harness.get_by_label(REJECTED_INPUT);
            let ctx = harness.ctx.clone();
            harness.state_mut().query(&ctx, None);
            assert!(!harness.state().job.is_running());
            assert!(harness.state().error.is_some());
        }
    }

    #[test]
    fn same_frame_select_all_and_paste_uses_the_effective_selection() {
        for character in ["x", "é"] {
            let original = character.repeat(MAX_DEBUGGER_REQUEST_BYTES / character.len());
            let debugger = Debugger { shown: true, request: original.clone(), ..Default::default() };
            let mut harness = Harness::builder()
                .with_size(egui::vec2(1400.0, 860.0))
                .build_ui_state(|ui, debugger: &mut Debugger| debugger.show(ui.ctx(), None), debugger);
            harness.run();
            open_advanced(&mut harness);
            let id = egui::Id::new("debugger-request");
            harness.ctx.memory_mut(|memory| memory.request_focus(id));
            harness.run();
            let mut state = egui::text_edit::TextEditState::load(&harness.ctx, id).unwrap();
            state.cursor.set_char_range(Some(egui::text::CCursorRange::one(egui::text::CCursor::new(
                original.chars().count(),
            ))));
            state.store(&harness.ctx, id);
            let replacement = template(0);
            // Harness::event runs each queued event in a separate frame; RawInput preserves this batch.
            harness
                .input_mut()
                .events
                .extend([key_event(egui::Key::A, egui::Modifiers::COMMAND), egui::Event::Paste(replacement.clone())]);
            harness.run();
            assert_eq!(harness.state().request, replacement);
            assert!(!harness.state().request_rejected);
        }
    }

    #[test]
    fn same_frame_selection_change_and_oversized_paste_rolls_back_text_cursor_and_undo() {
        for (character, paste) in [("x", "ab"), ("é", "abc")] {
            let original = format!("{character}{}", "x".repeat(MAX_DEBUGGER_REQUEST_BYTES - character.len()));
            let debugger = Debugger {
                shown: true,
                socket: "/private/operator.sock".to_owned(),
                request: original.clone(),
                ..Default::default()
            };
            let mut harness = Harness::builder()
                .with_size(egui::vec2(1400.0, 860.0))
                .build_ui_state(|ui, debugger: &mut Debugger| debugger.show(ui.ctx(), None), debugger);
            harness.run();
            open_advanced(&mut harness);
            let id = egui::Id::new("debugger-request");
            harness.ctx.memory_mut(|memory| memory.request_focus(id));
            harness.run();
            harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
            harness.run();
            let mut state = egui::text_edit::TextEditState::load(&harness.ctx, id).unwrap();
            let selection = state.cursor.char_range().unwrap();
            assert_eq!(selection.slice_str(&original), original);
            let baseline = (selection, original.clone());
            let mut undo = egui::text_edit::TextEditState::default().undoer();
            undo.add_undo(&(selection, "earlier private request".to_owned()));
            undo.add_undo(&baseline);
            let future = (selection, "later private request".to_owned());
            undo.add_undo(&future);
            assert_eq!(undo.undo(&future), Some(&baseline));
            let previous_undo = undo.clone().undo(&baseline).cloned();
            let previous_redo = undo.clone().redo(&baseline).cloned();
            assert!(previous_undo.is_some());
            assert!(previous_redo.is_some());
            state.set_undoer(undo);
            state.store(&harness.ctx, id);
            harness.input_mut().events.extend([
                key_event(egui::Key::ArrowLeft, egui::Modifiers::NONE),
                key_event(egui::Key::ArrowRight, egui::Modifiers::SHIFT),
                egui::Event::Paste(paste.to_owned()),
            ]);
            harness.run();
            assert_eq!(harness.state().request, original);
            assert!(harness.state().request_rejected);
            let after = egui::text_edit::TextEditState::load(&harness.ctx, id).unwrap();
            assert_eq!(after.cursor.char_range(), Some(selection));
            assert_eq!(after.undoer().undo(&baseline).cloned(), previous_undo);
            assert_eq!(after.undoer().redo(&baseline).cloned(), previous_redo);
            harness.get_by_label(REJECTED_INPUT);
            let ctx = harness.ctx.clone();
            harness.state_mut().query(&ctx, None);
            assert!(!harness.state().job.is_running());
            assert!(harness.state().error.is_some());
        }
    }

    #[test]
    fn request_editor_rejects_whole_insertions_without_truncating_utf8_or_json() {
        let mut request = "a".repeat(MAX_DEBUGGER_REQUEST_BYTES - 1);
        let mut rejected = false;
        let mut edited = false;
        let mut editor = RequestEditor { text: &mut request, rejected: &mut rejected, edited: &mut edited };
        assert_eq!(editor.insert_text("é", egui::text::CharIndex(0)), 0);
        assert_eq!(editor.as_str().len(), MAX_DEBUGGER_REQUEST_BYTES - 1);
        assert!(rejected);

        let mut request = String::new();
        let mut rejected = false;
        let mut editor = RequestEditor { text: &mut request, rejected: &mut rejected, edited: &mut edited };
        let oversized = format!("{}{}", template(0), " ".repeat(MAX_DEBUGGER_REQUEST_BYTES));
        assert_eq!(editor.insert_text(&oversized, egui::text::CharIndex(0)), 0);
        assert!(editor.as_str().is_empty());
        assert!(rejected);
    }

    #[test]
    fn a_refused_query_drops_the_previous_observation() {
        let mut debugger = Debugger {
            job: Job::Done(Ok("previous runtime bytes".to_owned().into())),
            submitted: Some(("previous socket".to_owned(), "previous request".to_owned())),
            ..Default::default()
        };
        debugger.query(&egui::Context::default(), None);
        assert!(debugger.error.is_some());
        assert!(debugger.job.ready().is_none());
        assert!(debugger.submitted.is_none());
        assert!(!debugger.job.is_running());
    }

    #[test]
    fn resolution_template_requires_manual_uuid_address_and_token_replacement() {
        let original = template(5);
        assert!(DebuggerRequest::from_json(&original).is_err());
        let request = original
            .replace(
                "\"REPLACE_WITH_RETURNED_TOKEN_OBJECT\"",
                concat!(
                    "{\"backend\":\"lldb-sb\",\"session_id\":\"ui-local-session\",",
                    "\"process_unique_id\":17,\"stop_id\":4,\"target_index\":0}",
                ),
            )
            .replace("REPLACE_MODULE_UUID", "01234567-89ab-cdef-0123-456789abcdef")
            .replace("REPLACE_FILE_ADDRESS", "0x100000004");
        assert_eq!(DebuggerRequest::from_json(&request).unwrap().operation(), "resolve_module_address");
        let mut debugger = Debugger { template: 5, request, ..Default::default() };
        debugger.query(&egui::Context::default(), None);
        assert!(!debugger.job.is_running());
        assert!(debugger.submitted.is_none());
        assert!(debugger.error.as_ref().unwrap().contains("explicit absolute"));
    }

    #[test]
    fn clear_removes_local_inputs_results_and_editor_undo_history() {
        let ctx = egui::Context::default();
        let cursor = egui::text::CCursorRange::default();
        for field in ["debugger-socket", "debugger-request"] {
            let mut state = egui::text_edit::TextEditState::default();
            let mut undo = state.undoer();
            undo.feed_state(0.0, &(cursor, "private data".to_owned()));
            state.set_undoer(undo);
            state.store(&ctx, egui::Id::new(field));
        }
        let mut debugger = Debugger {
            shown: true,
            socket: "private socket".to_owned(),
            job: Job::Done(Ok("private runtime bytes".to_owned().into())),
            submitted: Some(("private socket".to_owned(), "private request".to_owned())),
            ..Default::default()
        };
        debugger.clear(&ctx);
        assert!(debugger.shown);
        assert!(debugger.socket.is_empty());
        assert!(debugger.request.is_empty());
        assert!(debugger.job.ready().is_none());
        assert!(debugger.submitted.is_none());
        for field in ["debugger-socket", "debugger-request"] {
            let state = egui::text_edit::TextEditState::load(&ctx, egui::Id::new(field)).unwrap();
            assert!(!state.undoer().has_undo(&(cursor, String::new())));
        }
    }

    fn controlled_response(operation: &str, data: serde_json::Value) -> DebuggerResponse {
        serde_json::from_value(serde_json::json!({
            "protocol":"rampage-lldb-query-v1", "ok":true, "operation":operation, "token":test_token(),
            "data":data, "observation":{"content_sha256":"a".repeat(64), "consistency":"revalidated-non-atomic",
                "atomic_snapshot":false, "identity_scope":"controlled session/process/stop"},
        }))
        .unwrap()
    }

    fn work_binding(workflow: &Workflow, workspace: Option<&Workspace>) -> WorkBinding {
        WorkBinding {
            revision: Arc::clone(&workflow.revision),
            stop: Arc::clone(&workflow.stop),
            output: None,
            socket: workflow.socket.clone(),
            source: workspace.map(SourceIdentity::capture),
        }
    }

    fn complete_observation(
        workflow: &mut Workflow,
        workspace: Option<&Workspace>,
        request: DebuggerRequest,
        response: DebuggerResponse,
    ) {
        workflow.binding = Some(work_binding(workflow, workspace));
        workflow.job_kind = WorkKind::Query;
        workflow.job = Job::Done(Ok(WorkResult::Query(request, Box::new(response))));
        let socket = workflow.socket.clone();
        workflow.poll(&socket, workspace);
    }

    fn stopped_workflow(arch: &str, order: &str, workspace: Option<&Workspace>) -> Workflow {
        let mut workflow = Workflow::default();
        workflow.poll("/operator/chosen.sock", workspace);
        complete_observation(
            &mut workflow,
            workspace,
            DebuggerRequest::DescribeSession { version: 1, expected_token: None, response_budget: None },
            controlled_response(
                "describe_session",
                serde_json::json!({
                    "state":"stopped", "triple":format!("{arch}-apple-macosx"), "address_byte_size":8,
                    "data_byte_order":{"order":order,"source":"controlled runtime data order"},
                }),
            ),
        );
        workflow
    }

    #[test]
    fn structured_pages_retain_the_token_but_never_select_or_fetch_the_next_page_automatically() {
        let mut workflow = stopped_workflow("arm64", "unknown", None);
        let token = workflow.token().unwrap();
        complete_observation(
            &mut workflow,
            None,
            DebuggerRequest::ListModules {
                version: 1,
                expected_token: token.clone(),
                response_budget: None,
                offset: Some(0),
                limit: Some(1),
            },
            controlled_response(
                "list_modules",
                serde_json::json!({
                    "offset":0,"total":2,"next_offset":1,"items":[{
                        "index":0,"name":"controlled image","uuid":TEST_UUID,"triple":"arm64-apple-macosx",
                        "address_byte_size":8,"target_byte_order":"little",
                    }],
                }),
            ),
        );
        complete_observation(
            &mut workflow,
            None,
            DebuggerRequest::ListThreads {
                version: 1,
                expected_token: token.clone(),
                response_budget: None,
                offset: Some(0),
                limit: Some(32),
            },
            controlled_response(
                "list_threads",
                serde_json::json!({
                    "offset":0,"total":1,"next_offset":null,
                    "items":[{"thread_id":"0x7","stop_reason":3,"is_stopped":false}],
                }),
            ),
        );
        assert_eq!(workflow.token().unwrap(), token);
        assert_eq!(workflow.modules.as_ref().unwrap().next, Some(1));
        assert!(workflow.module.is_none() && workflow.thread.is_none());
        assert!(matches!(workflow.job, Job::Idle));
        assert!(workflow.memory.is_none() && workflow.registers.is_none() && workflow.preview.is_none());
        assert_eq!(workflow.modules.as_ref().unwrap().items[0].uuid, TEST_UUID);
        assert_eq!(workflow.threads.as_ref().unwrap().items[0].id, 7);
    }

    #[test]
    fn mismatched_and_oversized_pages_refuse_without_retaining_a_partial_selection() {
        for change in ["offset", "next", "count", "index"] {
            let mut workflow = stopped_workflow("x86_64", "little", None);
            let mut page = serde_json::json!({"offset":0,"total":1,"next_offset":null,
                "items":[{"index":0,"name":"image","uuid":TEST_UUID}]});
            match change {
                "offset" => page["offset"] = 1.into(),
                "next" => page["next_offset"] = 1.into(),
                "count" => {
                    page["total"] = 33.into();
                    page["items"] = serde_json::json!(vec![page["items"][0].clone(); 33]);
                }
                "index" => page["items"][0]["index"] = 1.into(),
                _ => unreachable!(),
            }
            complete_observation(
                &mut workflow,
                None,
                DebuggerRequest::ListModules {
                    version: 1,
                    expected_token: test_token(),
                    response_budget: None,
                    offset: Some(0),
                    limit: Some(32),
                },
                controlled_response("list_modules", page),
            );
            assert!(workflow.modules.is_none(), "accepted {change}");
            assert!(workflow.refresh_required && workflow.token().is_none());
            assert!(workflow.module.is_none());
        }
    }

    #[test]
    fn raw_memory_and_register_views_keep_unknown_data_order_and_never_interpret_scalars() {
        let mut workflow = stopped_workflow("arm64", "unknown", None);
        complete_observation(
            &mut workflow,
            None,
            DebuggerRequest::ReadRegisters {
                version: 1,
                expected_token: test_token(),
                response_budget: None,
                thread_id: DebuggerAddress::Integer(7),
                registers: None,
            },
            controlled_response(
                "read_registers",
                serde_json::json!({
                    "thread_id":"0x7","context":{"registers":{"pc":"0x1000","x0":"0xffffffffffffffff"}},
                    "data_byte_order":{"order":"unknown"},
                }),
            ),
        );
        complete_observation(
            &mut workflow,
            None,
            DebuggerRequest::ReadMemory {
                version: 1,
                expected_token: test_token(),
                response_budget: None,
                address: DebuggerAddress::Integer(0x1000),
                size: 4,
                permissions: DebuggerPermissions::Read,
                thread_id: Some(DebuggerAddress::Integer(7)),
            },
            controlled_response(
                "read_memory",
                serde_json::json!({
                    "address":"0x1000","size":4,"permissions":"r--","bytes_hex":"0102ff00","thread_id":7,
                    "interpretation":"raw-bytes-only","data_byte_order":{"order":"unknown"},
                }),
            ),
        );
        let mut harness = Harness::builder().with_size(egui::vec2(1500.0, 1300.0)).build_ui_state(
            |ui, workflow: &mut Workflow| {
                let _ = workflow.ui(ui, "/operator/chosen.sock", None, &WorkGate::default(), false);
            },
            workflow,
        );
        harness.run();
        harness.get_by_label("Raw registers · thread 0x7");
        harness.get_by_label("0xffffffffffffffff");
        harness.get_by_label("Runtime data byte order: unknown. Hex bytes only; no scalar interpretation.");
        harness.get_by_label("0000000000001000  01 02 ff 00");
        assert!(harness.state().preview.is_none() && harness.state().saved.is_none());
        assert!(matches!(harness.state().job, Job::Idle));
    }

    #[test]
    fn stale_token_retains_historical_identity_but_refuses_followups_until_explicit_refresh() {
        let mut workflow = stopped_workflow("x86_64", "little", None);
        let refusal = serde_json::from_value(serde_json::json!({
            "protocol":"rampage-lldb-query-v1","ok":false,"operation":"list_threads",
            "error":{"code":"stale_token","message":"controlled stop changed"},
        }))
        .unwrap();
        complete_observation(
            &mut workflow,
            None,
            DebuggerRequest::ListThreads {
                version: 1,
                expected_token: test_token(),
                response_budget: None,
                offset: Some(0),
                limit: Some(32),
            },
            refusal,
        );
        assert_eq!(workflow.session.as_ref().unwrap().token, test_token());
        assert!(workflow.token().is_none() && workflow.refresh_required);
        assert!(workflow.error.as_deref().unwrap().contains("stale_token"));
        assert!(matches!(workflow.job, Job::Idle));
        for _ in 0..3 {
            workflow.poll("/operator/chosen.sock", None);
            assert!(matches!(workflow.job, Job::Idle));
            assert!(workflow.token().is_none());
        }
    }

    #[test]
    fn a_success_response_from_another_stop_cannot_replace_the_retained_token() {
        let mut workflow = stopped_workflow("x86_64", "little", None);
        let mut response = controlled_response(
            "list_threads",
            serde_json::json!({
                "offset":0,"total":0,"next_offset":null,"items":[],
            }),
        );
        response.token.as_mut().unwrap().stop_id += 1;
        complete_observation(
            &mut workflow,
            None,
            DebuggerRequest::ListThreads {
                version: 1,
                expected_token: test_token(),
                response_budget: None,
                offset: Some(0),
                limit: Some(32),
            },
            response,
        );
        assert_eq!(workflow.session.as_ref().unwrap().token, test_token());
        assert!(workflow.refresh_required && workflow.token().is_none());
        assert!(workflow.threads.is_none());
    }

    #[test]
    fn socket_form_stop_and_output_epochs_refuse_late_completions_and_text_aba() {
        for change in ["socket", "form-aba", "stop", "output"] {
            let mut workflow = stopped_workflow("x86_64", "little", None);
            let mut binding = work_binding(&workflow, None);
            if change == "output" {
                binding.output = Some(Arc::clone(&workflow.output_revision));
            }
            match change {
                "socket" => {
                    workflow.poll("/operator/other.sock", None);
                    workflow.poll("/operator/chosen.sock", None);
                }
                "form-aba" => {
                    workflow.memory_address.push('x');
                    workflow.edited();
                    workflow.memory_address.pop();
                    workflow.edited();
                }
                "stop" => workflow.reset_stop(),
                "output" => workflow.output_revision = Arc::new(()),
                _ => unreachable!(),
            }
            workflow.binding = Some(binding);
            workflow.job = Job::Done(Ok(WorkResult::Query(
                DebuggerRequest::DescribeSession { version: 1, expected_token: None, response_budget: None },
                Box::new(controlled_response("describe_session", serde_json::json!({"state":"stopped"}))),
            )));
            workflow.poll("/operator/chosen.sock", None);
            assert!(workflow.error.as_deref().unwrap().contains("Obsolete"), "accepted {change}");
            assert!(workflow.token().is_none());
        }
    }

    #[test]
    fn close_clear_and_reopen_never_release_or_replace_a_pending_job_permit() {
        let mut debugger = Debugger { shown: true, ..Default::default() };
        let gate = debugger.gate.clone();
        let permit = gate.acquire().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        debugger.workflow.job = Job::Running(receiver);
        let cancellation = Arc::clone(&debugger.workflow.cancellation);
        debugger.close();
        debugger.shown = false;
        debugger.clear(&egui::Context::default());
        assert!(gate.busy() && debugger.workflow.job.is_running());
        assert!(cancellation.load(Ordering::Acquire));
        debugger.shown = true;
        debugger.query(&egui::Context::default(), None);
        assert!(matches!(debugger.job, Job::Idle));
        assert!(gate.acquire().is_none());
        drop(permit);
        assert!(debugger.busy(), "uncollected old receiver still blocks replacement");
        drop(sender);
        debugger.workflow.poll("", None);
        assert!(!debugger.busy());
        let next = gate.acquire().unwrap();
        assert!(gate.acquire().is_none());
        drop(next);
        assert!(!gate.busy());
    }

    #[cfg(unix)]
    #[test]
    fn capture_selection_requires_exact_source_and_disables_arm64_without_guessing_data_order() {
        for arch in [Arch::X86_64, Arch::Aarch64] {
            let fixture = StaticFixture::new(&thin_macho(arch, TEST_UUID));
            let workspace = fixture.workspace();
            let machine = if arch == Arch::X86_64 { "x86_64" } else { "arm64" };
            let order = if arch == Arch::X86_64 { "little" } else { "unknown" };
            let mut workflow = stopped_workflow(machine, order, Some(&workspace));
            workflow.module = Some(ModuleRow {
                index: 0,
                name: "controlled image".into(),
                uuid: TEST_UUID.into(),
                triple: format!("{machine}-apple-macosx"),
                width: 8,
                object_order: "little".into(),
            });
            workflow.thread = Some(7);
            workflow.file_address = format!("{FILE_ADDRESS:#x}");
            workflow.size = 4;
            let request = workflow.capture_request(Some(&workspace));
            if arch == Arch::X86_64 {
                let request = request.unwrap();
                assert_eq!(request.expected_token, test_token());
                assert_eq!(request.file_address, FILE_ADDRESS);
                let reopened = fixture.workspace();
                assert!(workflow.capture_request(Some(&reopened)).is_err());
                assert!(
                    work_binding(&workflow, Some(&workspace))
                        .validate(&workflow, "/operator/chosen.sock", Some(&reopened))
                        .is_err()
                );
            } else {
                assert!(request.unwrap_err().contains("ARM64 data order remains unknown"));
                assert_eq!(workflow.session.as_ref().unwrap().data_order, "unknown");
                assert!(workflow.token().is_some(), "inspection still works on ARM64");
            }
            assert!(workflow.preview.is_none() && workflow.saved.is_none());
        }
    }

    #[cfg(unix)]
    mod local_socket {
        use super::*;
        use std::fs::DirBuilder;
        use std::io::{Read, Write};
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicU64, Ordering};

        struct MockSocket {
            directory: PathBuf,
            path: PathBuf,
            listener: UnixListener,
        }

        impl MockSocket {
            fn new() -> Self {
                static NEXT: AtomicU64 = AtomicU64::new(0);
                let root = std::env::temp_dir().canonicalize().unwrap();
                let directory =
                    root.join(format!("ru-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
                DirBuilder::new().mode(0o700).create(&directory).unwrap();
                let path = directory.join("s");
                let listener = UnixListener::bind(&path).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
                listener.set_nonblocking(true).unwrap();
                Self { directory, path, listener }
            }

            fn assert_no_connection(&self) {
                assert_eq!(self.listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            }

            fn respond(&self, response: serde_json::Value) -> serde_json::Value {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match self.listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "explicit UI query never connected");
                            std::thread::yield_now();
                        }
                        Err(error) => panic!("mock socket accept failed: {error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut request = Vec::new();
                stream.read_to_end(&mut request).unwrap();
                assert_eq!(request.pop(), Some(b'\n'));
                assert!(!request.contains(&b'\n'));
                stream.write_all(format!("{response}\n").as_bytes()).unwrap();
                serde_json::from_slice(&request).unwrap()
            }
        }

        impl Drop for MockSocket {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.path);
                let _ = std::fs::remove_dir(&self.directory);
            }
        }

        fn finish(debugger: &mut Debugger) {
            let Job::Running(receiver) = &debugger.job else { panic!("UI query was not a background job") };
            let response = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
            debugger.job = Job::Done(response);
            assert!(debugger.job.error().is_none(), "{:?}", debugger.job.error());
        }

        fn session_response() -> serde_json::Value {
            serde_json::json!({
                "protocol": "rampage-lldb-query-v1",
                "ok": true,
                "operation": "describe_session",
                "token": {
                    "backend": "lldb-sb",
                    "session_id": "ui-local-session",
                    "process_unique_id": 17,
                    "stop_id": 4,
                    "target_index": 0
                },
                "data": {"architecture": "arm64", "runtime_address": "0x12340000"},
                "observation": {
                    "content_sha256": "a".repeat(64),
                    "consistency": "revalidated-non-atomic",
                    "atomic_snapshot": false,
                    "identity_scope": "session/process/stop"
                }
            })
        }

        fn resolution_response() -> serde_json::Value {
            let mut response = session_response();
            response["operation"] = "resolve_module_address".into();
            response["data"] = serde_json::json!({
                "module_uuid": TEST_UUID,
                "module": {"index":1,"name":"image","path":"/not/a/static/source/image",
                    "uuid":TEST_UUID.to_uppercase(),"triple":"arm64-apple-macosx",
                    "target_byte_order":"little","lldb_byte_order":4,"address_byte_size":8},
                "module_context": {"triple":"arm64-apple-macosx","object_byte_order":"little",
                    "address_byte_size":8,"data_byte_order":{"order":"unknown",
                        "source":"no runtime data interpretation"}},
                "file_address":format!("{FILE_ADDRESS:#x}"),"load_address":"0x1804",
                "section": {"index_path":[0,0],"name":"__text",
                    "file_base":format!("{:#x}",FILE_BASE + 0x200),
                    "file_end":format!("{:#x}",FILE_BASE + 0x300),
                    "load_base":"0x1800","load_end":"0x1900","offset":"0x4",
                    "ancestors":[{"index_path":[0],"name":"__TEXT","file_base":format!("{FILE_BASE:#x}"),
                        "file_end":format!("{:#x}",FILE_BASE + 0x1000),
                        "load_base":"0x1600","load_end":"0x2600"}]},
                "mapping":{"base":"0x1000","end":"0x3000","permissions":"r-x"},
                "interpretation":"raw-addresses-only",
                "address_semantics":"LLDB file virtual address, not a file byte offset",
                "proven_flow":false,"proven_layout":false
            });
            response
        }

        fn capture_replies(size: usize) -> [serde_json::Value; 9] {
            let mut session = session_response();
            let order = serde_json::json!({"order":"little","source":"LLDB target byte order"});
            session["data"] = serde_json::json!({
                "pid":42,"state":"stopped","triple":"x86_64-apple-macosx","architecture":"x86_64",
                "target_byte_order":"little","data_byte_order":order,"address_byte_size":8,
                "module_count":2,"thread_count":2,"operations":OPERATIONS,
                "limits":{"request_bytes":16384,"response_bytes":262144,"memory_bytes":65536,"page_items":128,
                    "modules":4096,"threads":4096,"resolution_work":16384,"module_sections":4096,
                    "section_depth":32,"module_uuid_bytes":64},
            });
            let mut resolution = resolution_response();
            resolution["data"]["module"]["triple"] = "x86_64-apple-macosx".into();
            resolution["data"]["module_context"]["triple"] = "x86_64-apple-macosx".into();
            let mut module = resolution["data"]["module"].clone();
            module["image_base"] = format!("{FILE_BASE:#x}").into();
            module["runtime_base"] = "0x1600".into();
            let mut modules = session_response();
            modules["operation"] = "list_modules".into();
            modules["data"] = serde_json::json!({"items":[module],"offset":1,"total":2,"next_offset":null});
            let stop = serde_json::json!({
                "source":"SBThread.GetStopReason/current-process-stop","is_stopped":false,"stop_reason":3,
            });
            let mut registers = session_response();
            registers["operation"] = "read_registers".into();
            registers["data"] = serde_json::json!({
                "thread_id":"0x7","required_registers":["rflags","rip","rsp"],"data_byte_order":order,
                "context":{"stop_evidence":stop,"frame_id":0,"pc":"0x1804","sp":"0x4000",
                    "registers":{"rip":"0x1804","rsp":"0x4000","rflags":"0x202"}},
            });
            let mut memory = session_response();
            memory["operation"] = "read_memory".into();
            memory["data"] = serde_json::json!({
                "address":"0x1804","size":size,"permissions":"r-x","bytes_hex":"c3".repeat(size),
                "data_byte_order":order,"stop_evidence":stop,"thread_id":7,"interpretation":"raw-bytes-only",
                "read_semantics":"LLDB ReadMemory may normalize software-breakpoint trap bytes",
            });
            [
                session.clone(),
                modules.clone(),
                resolution.clone(),
                registers.clone(),
                memory,
                registers,
                resolution,
                modules,
                session,
            ]
        }

        fn controlled_capture_preview(workspace: &Workspace) -> DebuggerCapturePreview {
            let mock = MockSocket::new();
            let source = Arc::clone(&workspace.project);
            let socket = mock.path.clone();
            let worker = std::thread::spawn(move || {
                rampage_api::prepare_debugger_capture(
                    source,
                    &socket,
                    &DebuggerCaptureRequest {
                        expected_token: test_token(),
                        module_index: 1,
                        module_uuid: TEST_UUID.into(),
                        thread_id: 7,
                        file_address: FILE_ADDRESS,
                        size: 4,
                        permissions: DebuggerPermissions::ReadExecute,
                    },
                    Duration::from_secs(5),
                    &AtomicBool::new(false),
                )
            });
            let replies = capture_replies(4);
            for (index, response) in replies.into_iter().enumerate() {
                let operation = response["operation"].clone();
                let request = mock.respond(response);
                assert_eq!(request["operation"], operation, "capture query {index}");
                assert_eq!(request["expected_token"], serde_json::to_value(test_token()).unwrap());
            }
            let preview = worker.join().unwrap().unwrap();
            mock.assert_no_connection();
            preview
        }

        fn finish_workflow(workflow: &mut Workflow) {
            let Job::Running(receiver) = &workflow.job else { panic!("explicit action did not start a local job") };
            workflow.job = Job::Done(receiver.recv_timeout(Duration::from_secs(5)).unwrap());
        }

        #[test]
        fn explicit_prepare_refuses_an_uncached_static_cpu_subtype_before_any_debugger_query() {
            let mut bytes = thin_macho(Arch::X86_64, TEST_UUID);
            bytes[8..12].copy_from_slice(&8u32.to_le_bytes());
            let fixture = StaticFixture::new(&bytes);
            let workspace = fixture.workspace();
            let workflow = capture_ready_workflow(&workspace);
            let initial_reads = STATIC_HEADER_READS.with(std::cell::Cell::get);
            let request = workflow.capture_request(Some(&workspace)).unwrap();
            assert_eq!(STATIC_HEADER_READS.with(std::cell::Cell::get), initial_reads);
            let mock = MockSocket::new();
            let error = rampage_api::prepare_debugger_capture(
                Arc::clone(&workspace.project),
                &mock.path,
                &request,
                Duration::from_secs(5),
                &AtomicBool::new(false),
            )
            .unwrap_err();
            assert!(error.to_string().contains("subtype"), "{error}");
            assert!(workflow.preview.is_none() && workflow.saved.is_none());
            mock.assert_no_connection();
        }

        fn replace_input(harness: &mut Harness<'_, crate::App>, id: &str, text: &str) {
            harness.ctx.memory_mut(|memory| memory.request_focus(egui::Id::new(id)));
            harness.step();
            harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
            harness.step();
            harness.event(egui::Event::Paste(text.to_owned()));
            harness.step();
        }

        fn settle_input_undo(harness: &mut Harness<'_, crate::App>) {
            let time = harness.ctx.input(|input| input.time);
            harness.input_mut().time = Some(time + 2.0);
            harness.step();
        }

        fn undo_input(harness: &mut Harness<'_, crate::App>) {
            harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::Z);
            harness.step();
        }

        fn inspection_harness(fixture: &StaticFixture, mock: &MockSocket) -> Harness<'static, crate::App> {
            let mut app = crate::App::blocking();
            app.open(&egui::Context::default(), fixture.path.clone(), None);
            app.show_debugger();
            let mut harness = Harness::builder()
                .with_size(egui::vec2(1700.0, 1500.0))
                .build_ui_state(|ui, app: &mut crate::App| app.show(ui), app);
            harness.run();
            replace_input(&mut harness, "debugger-socket", mock.path.to_str().unwrap());
            mock.assert_no_connection();
            let replies = capture_replies(64);
            harness.get_by_label("Connect stopped session").click_accesskit();
            harness.step();
            let request = mock.respond(replies[0].clone());
            assert_eq!(request["operation"], "describe_session");
            assert!(request.get("expected_token").is_none());
            finish_workflow(&mut harness.state_mut().debugger.workflow);
            harness.run();
            let mut modules = replies[1].clone();
            let target = modules["data"]["items"][0].clone();
            let mut other = target.clone();
            other["index"] = 0.into();
            other["name"] = "other".into();
            other["uuid"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into();
            modules["data"] = serde_json::json!({"items":[other,target],"offset":0,"total":2,"next_offset":null});
            harness.get_by_label("List modules page").click_accesskit();
            harness.step();
            let request = mock.respond(modules);
            assert_eq!(request["operation"], "list_modules");
            assert_eq!(request["limit"], 32);
            assert_eq!(request["expected_token"], serde_json::to_value(test_token()).unwrap());
            finish_workflow(&mut harness.state_mut().debugger.workflow);
            harness.run();
            assert!(harness.state().debugger.workflow.module.is_none());
            harness
                .get_by_label(&format!("Module 1 · image · {} · x86_64-apple-macosx", TEST_UUID.to_uppercase()))
                .click_accesskit();
            harness.run();
            let threads = controlled_response(
                "list_threads",
                serde_json::json!({
                    "offset":0,"total":2,"next_offset":null,"items":[
                        {"thread_id":"0x7","stop_reason":3,"is_stopped":false},
                        {"thread_id":"0x8","stop_reason":3,"is_stopped":false},
                    ],
                }),
            );
            harness.get_by_label("List threads page").click_accesskit();
            harness.step();
            let request = mock.respond(serde_json::to_value(threads).unwrap());
            assert_eq!(request["operation"], "list_threads");
            assert_eq!(request["limit"], 32);
            assert_eq!(request["expected_token"], serde_json::to_value(test_token()).unwrap());
            finish_workflow(&mut harness.state_mut().debugger.workflow);
            harness.run();
            assert!(harness.state().debugger.workflow.thread.is_none());
            harness.get_by_label("Thread 0x7 · stop reason 3 · SDK is_stopped false").click_accesskit();
            harness.run();
            replace_input(&mut harness, "debugger-file-address", &format!("{FILE_ADDRESS:#x}"));
            replace_input(&mut harness, "debugger-memory-address", "0x1804");
            replace_input(
                &mut harness,
                "debugger-capture-output",
                fixture.directory.join("operator.capture.json").to_str().unwrap(),
            );
            harness.get_by_role(egui::accesskit::Role::ComboBox).click_accesskit();
            harness.run();
            harness.get_by_label("r-x").click_accesskit();
            harness.run();
            mock.assert_no_connection();
            assert_eq!(harness.state().debugger.workflow.thread, Some(7));
            assert_eq!(harness.state().debugger.workflow.module.as_ref().unwrap().index, 1);
            assert!(harness.state().debugger.workflow.preview.is_none());
            harness
        }

        fn click_prepare(harness: &mut Harness<'_, crate::App>, mock: &MockSocket) {
            harness.get_by_label("Prepare capture preview (9 queries)").click_accesskit();
            harness.step();
            assert!(harness.state().debugger.workflow.job.is_running());
            assert!(!harness.state().debugger.workflow.cancellation.load(Ordering::Acquire));
            let operations = [
                "describe_session",
                "list_modules",
                "resolve_module_address",
                "read_registers",
                "read_memory",
                "read_registers",
                "resolve_module_address",
                "list_modules",
                "describe_session",
            ];
            for (index, response) in capture_replies(64).into_iter().enumerate() {
                let request = mock.respond(response);
                assert_eq!(request["operation"], operations[index]);
                assert_eq!(request["version"], 1);
                assert_eq!(request["expected_token"], serde_json::to_value(test_token()).unwrap());
                assert!(request["response_budget"].as_u64().unwrap() <= 65536);
                assert!(request.get("output").is_none() && request.get("path").is_none());
                match operations[index] {
                    "list_modules" => {
                        assert_eq!(request["offset"], 1);
                        assert_eq!(request["limit"], 1);
                    }
                    "read_registers" => {
                        assert_eq!(request["thread_id"], 7);
                        assert_eq!(request["registers"], serde_json::json!(["rip", "rsp", "rflags"]));
                    }
                    "read_memory" => {
                        assert_eq!(request["thread_id"], 7);
                        assert_eq!(request["size"], 64);
                        assert_eq!(request["address"], 0x1804);
                        assert_eq!(request["permissions"], "r-x");
                    }
                    "resolve_module_address" => {
                        assert_eq!(request["module_uuid"], TEST_UUID.to_uppercase());
                        assert_eq!(request["file_address"], FILE_ADDRESS);
                    }
                    _ => {}
                }
            }
            assert!(!harness.state().debugger.workflow.cancellation.load(Ordering::Acquire));
        }

        fn hold_completed_work(
            workflow: &mut Workflow,
        ) -> (std::sync::mpsc::Sender<Result<WorkResult, String>>, Result<WorkResult, String>) {
            let Job::Running(receiver) = &workflow.job else { panic!("expected an explicitly started job") };
            let result = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
            let (sender, receiver) = std::sync::mpsc::channel();
            workflow.job = Job::Running(receiver);
            (sender, result)
        }

        fn resolve_navigation(harness: &mut Harness<'_, crate::App>, mock: &MockSocket) {
            harness.get_by_label("Resolve selected file address").click_accesskit();
            harness.step();
            let request = mock.respond(capture_replies(64)[2].clone());
            assert_eq!(request["operation"], "resolve_module_address");
            finish(&mut harness.state_mut().debugger);
            harness.run();
            harness.get_by_label("Go to matching static image address");
            assert!(harness.state().debugger.destination(harness.state().workspace.as_ref()).is_ok());
        }

        #[test]
        fn app_prepare_button_runs_nine_token_queries_without_self_cancellation_or_followup_actions() {
            let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
            let mock = MockSocket::new();
            let mut harness = inspection_harness(&fixture, &mock);
            let original = Arc::clone(&harness.state().workspace.as_ref().unwrap().project);
            let annotations = serde_json::to_string(&original.annotation_list()).unwrap();
            click_prepare(&mut harness, &mock);
            finish_workflow(&mut harness.state_mut().debugger.workflow);
            harness.run();
            let preview = harness.state().debugger.workflow.preview.as_ref().unwrap();
            assert!(Arc::ptr_eq(preview.source_project(), &original));
            assert_eq!(preview.summary().size, 64);
            for _ in 0..3 {
                harness.run();
                let app = harness.state();
                assert!(app.debugger.workflow.saved.is_none() && app.debugger.workflow.comparison.is_none());
                assert!(!fixture.directory.join("operator.capture.json").exists());
                assert!(Arc::ptr_eq(&app.workspace.as_ref().unwrap().project, &original));
                assert_eq!(app.workspace.as_ref().unwrap().cursor, 0);
                assert!(app.debugger.click_context.is_none());
                mock.assert_no_connection();
            }
            assert_eq!(serde_json::to_string(&original.annotation_list()).unwrap(), annotations);
        }

        #[test]
        fn successive_register_and_memory_buttons_preserve_compatible_views_but_selection_changes_clear_them() {
            let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
            let mock = MockSocket::new();
            let mut harness = inspection_harness(&fixture, &mock);
            let replies = capture_replies(64);
            harness.get_by_label("Read selected thread registers").click_accesskit();
            harness.step();
            let request = mock.respond(replies[3].clone());
            assert_eq!(request["operation"], "read_registers");
            finish_workflow(&mut harness.state_mut().debugger.workflow);
            harness.run();
            harness.get_by_label("Raw registers · thread 0x7");
            harness.get_by_label("Read raw memory").click_accesskit();
            harness.step();
            assert!(harness.state().debugger.workflow.registers.is_some());
            let request = mock.respond(replies[4].clone());
            assert_eq!(request["operation"], "read_memory");
            finish_workflow(&mut harness.state_mut().debugger.workflow);
            harness.run();
            harness.get_by_label("Raw registers · thread 0x7");
            harness.get_by_label("Raw memory · 0x1804 · 64 bytes");
            assert_eq!(harness.state().debugger.workflow.memory.as_ref().unwrap().bytes, "c3".repeat(64));
            harness.get_by_label("Thread 0x7 · stop reason 3 · SDK is_stopped false").click_accesskit();
            harness.run();
            assert!(harness.state().debugger.workflow.memory.is_some());
            assert!(harness.state().debugger.workflow.registers.is_some());
            replace_input(&mut harness, "debugger-memory-address", "0x1810");
            assert!(harness.state().debugger.workflow.memory.is_none());
            assert!(harness.state().debugger.workflow.registers.is_some());
            harness.get_by_label("Thread 0x8 · stop reason 3 · SDK is_stopped false").click_accesskit();
            harness.run();
            assert!(harness.state().debugger.workflow.registers.is_none());
            assert!(harness.state().debugger.workflow.memory.is_none());
            assert_eq!(harness.state().debugger.workflow.token().unwrap(), test_token());
            mock.assert_no_connection();
        }

        #[test]
        fn an_egui_form_edit_then_undo_cannot_reauthorize_a_held_real_prepare_or_compare_result() {
            for compare in [false, true] {
                let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
                let mock = MockSocket::new();
                let mut harness = inspection_harness(&fixture, &mock);
                let original = Arc::clone(&harness.state().workspace.as_ref().unwrap().project);
                let initial_address = harness.state().debugger.workflow.file_address.clone();
                resolve_navigation(&mut harness, &mock);
                settle_input_undo(&mut harness);
                click_prepare(&mut harness, &mock);
                if compare {
                    finish_workflow(&mut harness.state_mut().debugger.workflow);
                    harness.run();
                    harness.get_by_label("Compare prepared capture with original").click_accesskit();
                    harness.step();
                }
                let (release, result) = hold_completed_work(&mut harness.state_mut().debugger.workflow);
                assert!(result.is_ok());
                if compare {
                    assert!(matches!(&result, Ok(WorkResult::Compared(_))));
                } else {
                    let Ok(WorkResult::Prepared(preview)) = &result else { panic!("expected opaque real preview") };
                    assert!(Arc::ptr_eq(preview.source_project(), &original));
                }
                replace_input(&mut harness, "debugger-file-address", &format!("{:#x}", FILE_ADDRESS + 4));
                assert_ne!(harness.state().debugger.workflow.file_address, initial_address);
                assert!(harness.state().debugger.workflow.cancellation.load(Ordering::Acquire));
                undo_input(&mut harness);
                assert_eq!(harness.state().debugger.workflow.file_address, initial_address);
                assert!(release.send(result).is_ok());
                harness.run();
                let app = harness.state();
                assert!(app.debugger.workflow.preview.is_none() && app.debugger.workflow.comparison.is_none());
                assert!(app.debugger.workflow.saved.is_none() && app.debugger.click_context.is_none());
                assert!(Arc::ptr_eq(&app.workspace.as_ref().unwrap().project, &original));
                assert_eq!(app.workspace.as_ref().unwrap().cursor, 0);
                assert!(harness.get_by_label("Save prepared capture").accesskit_node().is_disabled());
                assert!(harness.get_by_label("Open saved snapshot").accesskit_node().is_disabled());
                assert!(harness.query_by_label("Go to matching static image address").is_none());
                assert!(!fixture.directory.join("operator.capture.json").exists());
                mock.assert_no_connection();
            }
        }

        #[test]
        fn an_egui_output_path_aba_refuses_late_save_authority_but_reports_the_actual_publication() {
            let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
            std::fs::set_permissions(&fixture.directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let mock = MockSocket::new();
            let mut harness = inspection_harness(&fixture, &mock);
            let original = Arc::clone(&harness.state().workspace.as_ref().unwrap().project);
            let output = fixture.directory.join("operator.capture.json");
            resolve_navigation(&mut harness, &mock);
            settle_input_undo(&mut harness);
            click_prepare(&mut harness, &mock);
            finish_workflow(&mut harness.state_mut().debugger.workflow);
            harness.run();
            harness.get_by_label("Compare prepared capture with original").click_accesskit();
            harness.step();
            finish_workflow(&mut harness.state_mut().debugger.workflow);
            harness.run();
            harness.get_by_label("Save prepared capture").click_accesskit();
            harness.step();
            let (release, result) = hold_completed_work(&mut harness.state_mut().debugger.workflow);
            assert!(matches!(&result, Ok(WorkResult::Saved { .. })));
            assert!(output.exists());
            replace_input(
                &mut harness,
                "debugger-capture-output",
                fixture.directory.join("not-authorized.json").to_str().unwrap(),
            );
            undo_input(&mut harness);
            assert_eq!(PathBuf::from(&harness.state().debugger.workflow.output), output);
            assert!(release.send(result).is_ok());
            harness.run();
            let workflow = &harness.state().debugger.workflow;
            assert!(workflow.saved.is_none());
            assert_eq!(workflow.latest_publication_notice().unwrap().path, output);
            assert!(workflow.error.as_deref().unwrap().contains("Obsolete"));
            assert!(harness.get_by_label("Save prepared capture").accesskit_node().is_disabled());
            assert!(harness.get_by_label("Open saved snapshot").accesskit_node().is_disabled());
            assert!(harness.query_by_label("Go to matching static image address").is_none());
            assert!(Arc::ptr_eq(&harness.state().workspace.as_ref().unwrap().project, &original));
            assert!(output.exists(), "stale completion must not delete the authorized output");
            assert!(!fixture.directory.join("not-authorized.json").exists());
            mock.assert_no_connection();
        }

        #[test]
        fn uncertain_publication_is_reported_without_open_retry_overwrite_or_staging_cleanup() {
            let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
            std::fs::set_permissions(&fixture.directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let mock = MockSocket::new();
            let mut harness = inspection_harness(&fixture, &mock);
            let original = Arc::clone(&harness.state().workspace.as_ref().unwrap().project);
            click_prepare(&mut harness, &mock);
            finish_workflow(&mut harness.state_mut().debugger.workflow);
            harness.run();
            harness.get_by_label("Compare prepared capture with original").click_accesskit();
            harness.step();
            finish_workflow(&mut harness.state_mut().debugger.workflow);
            harness.run();
            let workspace = harness.state_mut().workspace.as_mut().unwrap();
            workspace.begin_comment();
            workspace.editing.as_mut().unwrap().text = "keep unsaved annotation".into();
            harness.step();
            harness.get_by_label("Save prepared capture").click_accesskit();
            harness.step();
            let (release, mut result) = hold_completed_work(&mut harness.state_mut().debugger.workflow);
            let Ok(WorkResult::Saved { publication, .. }) = &mut result else { panic!("expected actual Save result") };
            publication.status = DebuggerCapturePublicationStatus::PublishedUncertain;
            publication.warnings.push("controlled post-publication namespace uncertainty".into());
            let retained = fixture.directory.join("retained.staging");
            std::fs::write(&retained, b"must not be removed automatically").unwrap();
            publication.retained_staging_paths.push(retained.clone());
            let output = publication.path.clone();
            let document = std::fs::read(&output).unwrap();
            assert!(release.send(result).is_ok());
            harness.run();
            assert!(harness.state().debugger.workflow.saved.is_none());
            harness.get_by_label(&format!("Publication uncertain; output may exist: {}", output.display()));
            harness.get_by_label("controlled post-publication namespace uncertainty");
            harness.get_by_label(&format!(
                "Retained staging requires operator inspection/cleanup (not automatic deletion): {}",
                retained.display(),
            ));
            let receipt = harness.state().debugger.workflow.latest_publication_notice().unwrap();
            harness.get_by_label(&format!("Expected publication document SHA-256: {}", receipt.document_sha256));
            assert!(
                harness
                    .query_by_label(&format!(
                        "Saved locally: {}. The original workspace is still open.",
                        output.display(),
                    ))
                    .is_none()
            );
            let workspace = harness.state().workspace.as_ref().unwrap();
            assert!(Arc::ptr_eq(&workspace.project, &original));
            assert_eq!(workspace.editing.as_ref().unwrap().text, "keep unsaved annotation");
            harness.state_mut().workspace.as_mut().unwrap().editing = None;
            for _ in 0..3 {
                harness.run();
                assert!(harness.get_by_label("Save prepared capture").accesskit_node().is_disabled());
                assert!(harness.get_by_label("Open saved snapshot").accesskit_node().is_disabled());
                assert_eq!(std::fs::read(&output).unwrap(), document);
                assert_eq!(std::fs::read(&retained).unwrap(), b"must not be removed automatically");
                mock.assert_no_connection();
            }
            let receipt = harness.state().debugger.workflow.latest_publication_notice().unwrap().clone();
            let action = OpenSnapshot {
                path: receipt.path,
                document_sha256: receipt.document_sha256,
                publication_status: receipt.status,
                source: SourceIdentity::capture(harness.state().workspace.as_ref().unwrap()),
            };
            let ctx = harness.ctx.clone();
            harness.state_mut().open_debugger_snapshot(&ctx, action);
            assert!(harness.state().error.as_deref().unwrap().contains("Uncertain publication"));
            assert!(Arc::ptr_eq(&harness.state().workspace.as_ref().unwrap().project, &original));
            assert_eq!(std::fs::read(&output).unwrap(), document);
        }

        #[test]
        fn uncertain_destination_and_resources_survive_a_later_publication_and_return_to_the_old_path() {
            let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
            std::fs::set_permissions(&fixture.directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let mock = MockSocket::new();
            let mut harness = inspection_harness(&fixture, &mock);
            let original = Arc::clone(&harness.state().workspace.as_ref().unwrap().project);
            let first = fixture.directory.join("operator.capture.json");
            let second = fixture.directory.join("second.capture.json");
            click_prepare(&mut harness, &mock);
            finish_workflow(&mut harness.state_mut().debugger.workflow);
            harness.run();
            harness.get_by_label("Save prepared capture").click_accesskit();
            harness.step();
            let (release, mut result) = hold_completed_work(&mut harness.state_mut().debugger.workflow);
            let Ok(WorkResult::Saved { publication, .. }) = &mut result else { panic!("expected actual publication") };
            publication.status = DebuggerCapturePublicationStatus::PublishedUncertain;
            publication.warnings.push("first destination still requires inspection".into());
            let first_receipt = publication.clone();
            let first_document = std::fs::read(&first).unwrap();
            assert!(!first_receipt.retained_staging_paths.is_empty());
            assert!(release.send(result).is_ok());
            harness.run();
            assert!(harness.get_by_label("Save prepared capture").accesskit_node().is_disabled());
            replace_input(&mut harness, "debugger-capture-output", second.to_str().unwrap());
            assert!(!harness.get_by_label("Save prepared capture").accesskit_node().is_disabled());
            harness.get_by_label("Save prepared capture").click_accesskit();
            harness.step();
            finish_workflow(&mut harness.state_mut().debugger.workflow);
            harness.run();
            let second_receipt = harness.state().debugger.workflow.saved.as_ref().unwrap().clone();
            assert_eq!(second_receipt.path, second);
            assert_eq!(second_receipt.status, DebuggerCapturePublicationStatus::Published);
            assert_eq!(harness.state().debugger.workflow.latest_publication_notice().unwrap().path, second);
            replace_input(&mut harness, "debugger-capture-output", first.to_str().unwrap());
            let app = harness.state();
            let workflow = &app.debugger.workflow;
            assert!(workflow.validate_preview(mock.path.to_str().unwrap(), app.workspace.as_ref()).is_ok());
            assert!(workflow.saved.is_none());
            assert_eq!(workflow.save_resources.len(), 2);
            assert!(workflow.published_destination(&first));
            let SaveResourceNotice::Publication(retained_first) = &workflow.save_resources[0] else {
                panic!("first publication was forgotten")
            };
            assert_eq!(retained_first.status, DebuggerCapturePublicationStatus::PublishedUncertain);
            assert_eq!(retained_first.document_sha256, first_receipt.document_sha256);
            assert_eq!(retained_first.warnings, first_receipt.warnings);
            assert_eq!(retained_first.retained_staging_paths, first_receipt.retained_staging_paths);
            assert!(harness.get_by_label("Save prepared capture").accesskit_node().is_disabled());
            assert!(harness.get_by_label("Open saved snapshot").accesskit_node().is_disabled());
            harness.get_by_label(&format!("Publication uncertain; output may exist: {}", first.display()));
            harness.get_by_label(&format!("Published by an explicit Save: {}", second.display()));
            harness.get_by_label("first destination still requires inspection");
            replace_input(&mut harness, "debugger-file-address", &format!("{:#x}", FILE_ADDRESS + 4));
            harness.state_mut().debugger.invalidate_workspace();
            for _ in 0..3 {
                harness.run();
                assert_eq!(harness.state().debugger.workflow.save_resources.len(), 2);
                harness.get_by_label(&format!("Publication uncertain; output may exist: {}", first.display()));
                harness.get_by_label("first destination still requires inspection");
                for path in first_receipt.retained_staging_paths.iter().chain(&second_receipt.retained_staging_paths) {
                    harness.get_by_label(&format!(
                        "Retained staging requires operator inspection/cleanup (not automatic deletion): {}",
                        path.display(),
                    ));
                    assert_eq!(std::fs::read(path).unwrap(), first_document);
                }
                assert_eq!(std::fs::read(&first).unwrap(), first_document);
                assert_eq!(std::fs::read(&second).unwrap(), first_document);
                assert!(Arc::ptr_eq(&harness.state().workspace.as_ref().unwrap().project, &original));
                mock.assert_no_connection();
            }
        }

        #[test]
        fn genuine_save_resource_paths_survive_source_backing_change_without_restoring_authority() {
            let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
            std::fs::set_permissions(&fixture.directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let mock = MockSocket::new();
            let mut harness = inspection_harness(&fixture, &mock);
            let original = Arc::clone(&harness.state().workspace.as_ref().unwrap().project);
            click_prepare(&mut harness, &mock);
            finish_workflow(&mut harness.state_mut().debugger.workflow);
            harness.run();
            harness.get_by_label("Save prepared capture").click_accesskit();
            harness.step();
            let (release, result) = hold_completed_work(&mut harness.state_mut().debugger.workflow);
            let Ok(WorkResult::Saved { publication, .. }) = &result else { panic!("expected genuine Save result") };
            let receipt = publication.clone();
            assert!(!receipt.retained_staging_paths.is_empty());
            let document = std::fs::read(&receipt.path).unwrap();
            let workspace = harness.state_mut().workspace.as_mut().unwrap();
            workspace.begin_comment();
            workspace.editing.as_mut().unwrap().text = "keep editor across obsolete Save".into();
            std::fs::OpenOptions::new()
                .append(true)
                .open(&fixture.path)
                .unwrap()
                .write_all(b"changed backing after publication")
                .unwrap();
            assert!(original.binary.validate_backing_source().is_err());
            assert!(release.send(result).is_ok());
            harness.run();
            let app = harness.state();
            assert!(app.debugger.workflow.saved.is_none() && app.debugger.workflow.preview.is_none());
            assert!(app.debugger.click_context.is_none());
            assert!(Arc::ptr_eq(&app.workspace.as_ref().unwrap().project, &original));
            assert_eq!(
                app.workspace.as_ref().unwrap().editing.as_ref().unwrap().text,
                "keep editor across obsolete Save"
            );
            assert_eq!(app.debugger.workflow.latest_publication_notice().unwrap().path, receipt.path);
            harness.state_mut().debugger.invalidate_workspace();
            for _ in 0..3 {
                harness.run();
                assert_eq!(harness.state().debugger.workflow.save_resources.len(), 1);
                assert!(harness.get_by_label("Open saved snapshot").accesskit_node().is_disabled());
                for path in &receipt.retained_staging_paths {
                    harness.get_by_label(&format!(
                        "Retained staging requires operator inspection/cleanup (not automatic deletion): {}",
                        path.display(),
                    ));
                    assert_eq!(std::fs::read(path).unwrap(), document);
                }
                assert_eq!(std::fs::read(&receipt.path).unwrap(), document);
                mock.assert_no_connection();
            }
        }

        #[test]
        fn typed_retention_error_with_real_staging_paths_survives_an_obsolete_binding() {
            let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
            std::fs::set_permissions(&fixture.directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let mock = MockSocket::new();
            let mut harness = inspection_harness(&fixture, &mock);
            click_prepare(&mut harness, &mock);
            finish_workflow(&mut harness.state_mut().debugger.workflow);
            harness.run();
            harness.get_by_label("Save prepared capture").click_accesskit();
            harness.step();
            let (release, result) = hold_completed_work(&mut harness.state_mut().debugger.workflow);
            let Ok(WorkResult::Saved { requested, publication }) = result else {
                panic!("expected real staging files")
            };
            let document = std::fs::read(&publication.path).unwrap();
            assert!(!publication.retained_staging_paths.is_empty());
            let retention = rampage_api::DebuggerCaptureStagingRetention {
                paths: publication.retained_staging_paths,
                message: "controlled typed retained-stage refusal".into(),
            };
            let error = rampage_api::ApiError::DebuggerCaptureStagingRetained(retention.clone());
            let displayed_error = error.to_string();
            let failed = WorkResult::SaveFailed {
                requested: requested.clone(),
                document_sha256: publication.document_sha256.clone(),
                error,
            };
            replace_input(&mut harness, "debugger-file-address", &format!("{:#x}", FILE_ADDRESS + 4));
            assert!(release.send(Ok(failed)).is_ok());
            harness.run();
            let workflow = &harness.state().debugger.workflow;
            assert!(workflow.saved.is_none() && workflow.preview.is_none());
            assert!(workflow.error.as_deref().unwrap().contains("Obsolete"));
            let [
                SaveResourceNotice::Failure {
                    requested: retained_request,
                    document_sha256,
                    message,
                    retention: Some(retained),
                },
            ] = workflow.save_resources.as_slice()
            else {
                panic!("typed resource details were discarded with the stale authorization")
            };
            assert_eq!(retained_request, &requested);
            assert_eq!(document_sha256, &publication.document_sha256);
            assert_eq!(message, &displayed_error);
            assert_eq!(retained.paths, retention.paths);
            assert_eq!(retained.message, retention.message);
            harness.get_by_label(&displayed_error);
            harness.state_mut().debugger.invalidate_workspace();
            for _ in 0..3 {
                harness.run();
                assert_eq!(harness.state().debugger.workflow.save_resources.len(), 1);
                harness.get_by_label(&displayed_error);
                assert!(harness.get_by_label("Open saved snapshot").accesskit_node().is_disabled());
                assert!(harness.get_by_label("Save prepared capture").accesskit_node().is_disabled());
                for path in &retention.paths {
                    harness.get_by_label(&format!(
                        "Retained staging requires operator inspection/cleanup (not automatic deletion): {}",
                        path.display(),
                    ));
                    assert_eq!(std::fs::read(path).unwrap(), document);
                }
                mock.assert_no_connection();
            }
        }

        #[test]
        fn genuine_save_refusal_remains_typed_until_resources_are_recorded_despite_obsolete_binding() {
            let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
            std::fs::set_permissions(&fixture.directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let mock = MockSocket::new();
            let mut harness = inspection_harness(&fixture, &mock);
            click_prepare(&mut harness, &mock);
            finish_workflow(&mut harness.state_mut().debugger.workflow);
            harness.run();
            let output = fixture.directory.join("operator.capture.json");
            let document_sha256 =
                harness.state().debugger.workflow.preview.as_ref().unwrap().summary().document_sha256.clone();
            std::fs::write(&output, b"preexisting output must remain unchanged").unwrap();
            harness.get_by_label("Save prepared capture").click_accesskit();
            harness.step();
            let (release, result) = hold_completed_work(&mut harness.state_mut().debugger.workflow);
            let Ok(WorkResult::SaveFailed { requested, document_sha256: returned_hash, error }) = &result else {
                panic!("genuine API error was flattened into an unbound string")
            };
            assert_eq!(requested, &output);
            assert_eq!(returned_hash, &document_sha256);
            assert!(matches!(error, rampage_api::ApiError::Invalid(_)));
            let displayed_error = error.to_string();
            assert!(displayed_error.contains("already exists"));
            replace_input(&mut harness, "debugger-file-address", &format!("{:#x}", FILE_ADDRESS + 4));
            assert!(release.send(result).is_ok());
            harness.run();
            let workflow = &harness.state().debugger.workflow;
            assert!(workflow.saved.is_none() && workflow.preview.is_none());
            assert!(workflow.error.as_deref().unwrap().contains("Obsolete"));
            let [SaveResourceNotice::Failure { requested, document_sha256: retained_hash, message, retention: None }] =
                workflow.save_resources.as_slice()
            else {
                panic!("genuine Save failure resources were discarded")
            };
            assert_eq!(requested, &output);
            assert_eq!(retained_hash, &document_sha256);
            assert_eq!(message, &displayed_error);
            harness.get_by_label(&displayed_error);
            assert!(harness.get_by_label("Open saved snapshot").accesskit_node().is_disabled());
            assert_eq!(std::fs::read(&output).unwrap(), b"preexisting output must remain unchanged");
            mock.assert_no_connection();
        }

        #[test]
        fn normal_session_document_mismatch_refuses_at_the_second_check_and_preserves_original_editor() {
            let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
            std::fs::set_permissions(&fixture.directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let workspace = fixture.workspace();
            let preview = controlled_capture_preview(&workspace);
            let publication = preview.publish(&fixture.directory.join("operator.capture.json")).unwrap();
            let action = OpenSnapshot {
                path: publication.path.clone(),
                document_sha256: publication.document_sha256.clone(),
                publication_status: publication.status,
                source: SourceIdentity::capture(&workspace),
            };
            action.validate_source(Some(&workspace)).unwrap();
            let verified =
                rampage_api::read_debugger_capture_publication(&action.path, &action.document_sha256).unwrap();
            let mut changed = verified.clone();
            changed.push(b'\n');
            std::fs::write(&action.path, &changed).unwrap();
            let candidate = Workspace::open(
                &rampage_api::Session::default(),
                action.path.clone(),
                None,
                None,
                &egui::Context::default(),
                true,
            )
            .unwrap();
            assert_eq!(candidate.project.binary.format, Format::Snapshot);
            assert_eq!(candidate.project.binary.file_bytes(), changed.as_slice());
            let original = Arc::clone(&workspace.project);
            let annotations = serde_json::to_string(&original.annotation_list()).unwrap();
            let mut app = crate::App::blocking();
            app.workspace = Some(workspace);
            let workspace = app.workspace.as_mut().unwrap();
            workspace.goto(FILE_ADDRESS + 1);
            workspace.begin_comment();
            workspace.editing.as_mut().unwrap().text = "editor remains unsaved".into();
            let error = app.finish_debugger_snapshot_open(&action, &verified, candidate).unwrap_err();
            assert_eq!(error, "Saved capture changed while opening; the original workspace remains open.");
            let workspace = app.workspace.as_ref().unwrap();
            assert!(Arc::ptr_eq(&workspace.project, &original));
            assert_eq!(workspace.cursor, FILE_ADDRESS + 1);
            assert!(workspace.can_go_back());
            assert_eq!(workspace.editing.as_ref().unwrap().text, "editor remains unsaved");
            assert_eq!(serde_json::to_string(&original.annotation_list()).unwrap(), annotations);
            assert_eq!(std::fs::read(&action.path).unwrap(), changed);
        }

        #[test]
        fn prepared_capture_compare_save_and_verified_open_are_separate_actions_without_annotation_writes() {
            let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
            std::fs::set_permissions(&fixture.directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let mut workspace = fixture.workspace();
            let original = Arc::clone(&workspace.project);
            let annotations = serde_json::to_string(&original.annotation_list()).unwrap();
            let preview = Arc::new(controlled_capture_preview(&workspace));
            assert!(Arc::ptr_eq(preview.source_project(), &original));
            let output = fixture.directory.join("operator.capture.json");
            let mut workflow = stopped_workflow("x86_64", "little", Some(&workspace));
            workflow.module = Some(ModuleRow {
                index: 1,
                name: "image".into(),
                uuid: TEST_UUID.into(),
                triple: "x86_64-apple-macosx".into(),
                width: 8,
                object_order: "little".into(),
            });
            workflow.thread = Some(7);
            workflow.file_address = format!("{FILE_ADDRESS:#x}");
            workflow.size = 4;
            workflow.permissions = 2;
            workflow.output = output.to_str().unwrap().into();
            workflow.preview_binding = Some(work_binding(&workflow, Some(&workspace)));
            workflow.preview = Some(preview);
            workspace.goto(FILE_ADDRESS + 1);
            workspace.begin_comment();
            workspace.editing.as_mut().unwrap().text = "unsaved operator annotation".into();
            let cursor = workspace.cursor;
            let mut harness = Harness::builder().with_size(egui::vec2(1600.0, 1500.0)).build_ui_state(
                |ui, state: &mut (Workflow, Workspace, WorkGate, Option<OpenSnapshot>)| {
                    state.0.poll("/operator/chosen.sock", Some(&state.1));
                    let busy = state.2.busy() || state.0.job.is_running();
                    let action = state.0.capture_ui(ui, "/operator/chosen.sock", Some(&state.1), &state.2, busy);
                    if let Some(action) = action {
                        state.3 = Some(action);
                    }
                },
                (workflow, workspace, WorkGate::default(), None),
            );
            for _ in 0..3 {
                harness.run();
                assert!(!output.exists());
                assert!(harness.state().0.saved.is_none() && harness.state().0.comparison.is_none());
                assert!(harness.state().3.is_none());
            }
            harness.get_by_label("Compare prepared capture with original").click_accesskit();
            harness.step();
            finish_workflow(&mut harness.state_mut().0);
            harness.run();
            assert_eq!(harness.state().0.comparison.as_ref().unwrap().equal_bytes, 4);
            assert!(!output.exists() && harness.state().3.is_none());
            harness.get_by_label("Save prepared capture").click_accesskit();
            harness.step();
            finish_workflow(&mut harness.state_mut().0);
            harness.run();
            assert_eq!(harness.state().0.saved.as_ref().unwrap().path, output);
            let receipt = harness.state().0.saved.as_ref().unwrap();
            for path in &receipt.retained_staging_paths {
                harness.get_by_label(&format!(
                    "Retained staging requires operator inspection/cleanup (not automatic deletion): {}",
                    path.display(),
                ));
            }
            assert!(output.exists() && harness.state().3.is_none());
            assert!(harness.get_by_label("Open saved snapshot").accesskit_node().is_disabled());
            let workspace = &harness.state().1;
            assert!(Arc::ptr_eq(&workspace.project, &original));
            assert_eq!(workspace.cursor, cursor);
            assert!(workspace.can_go_back());
            assert_eq!(workspace.editing.as_ref().unwrap().text, "unsaved operator annotation");
            assert_eq!(serde_json::to_string(&original.annotation_list()).unwrap(), annotations);
            harness.state_mut().1.editing = None;
            harness.run();
            harness.get_by_label("Open saved snapshot").click_accesskit();
            harness.run();
            let (workflow, workspace, _, action) = harness.into_state();
            let mut app = crate::App::blocking();
            app.workspace = Some(workspace);
            let document = std::fs::read(&output).unwrap();
            let mut changed = document.clone();
            changed.push(b'\n');
            std::fs::write(&output, changed).unwrap();
            app.open_debugger_snapshot(&egui::Context::default(), action.unwrap());
            assert!(app.error.is_some());
            assert!(Arc::ptr_eq(&app.workspace.as_ref().unwrap().project, &original));
            assert_eq!(app.workspace.as_ref().unwrap().cursor, cursor);
            std::fs::write(&output, document).unwrap();
            let saved = workflow.saved.as_ref().unwrap();
            let action = OpenSnapshot {
                path: saved.path.clone(),
                document_sha256: saved.document_sha256.clone(),
                publication_status: saved.status,
                source: SourceIdentity::capture(app.workspace.as_ref().unwrap()),
            };
            app.open_debugger_snapshot(&egui::Context::default(), action);
            assert!(app.error.is_none(), "{:?}", app.error);
            let snapshot = app.workspace.as_ref().unwrap();
            assert_eq!(snapshot.path, output);
            assert_eq!(snapshot.project.binary.format, Format::Snapshot);
            assert_eq!(snapshot.cursor, 0, "register PC must not authorize automatic navigation");
            assert!(snapshot.project.binary.entry.is_none());
            assert!(snapshot.project.binary.function_starts.is_empty());
            assert_eq!(snapshot.project.binary.snapshot_registers.len(), 3);
            assert_eq!(serde_json::to_string(&original.annotation_list()).unwrap(), annotations);
            assert!(
                std::fs::read_dir(&fixture.directory)
                    .unwrap()
                    .all(|entry| { entry.unwrap().path().extension().is_none_or(|extension| extension != "jsonl") })
            );
            drop(app);
            std::fs::remove_file(output).unwrap();
        }

        #[test]
        fn an_opaque_prepared_reply_cannot_adopt_a_reopened_workspace_even_with_the_same_project_arc() {
            let fixture = StaticFixture::new(&thin_macho(Arch::X86_64, TEST_UUID));
            let workspace = fixture.workspace();
            let preview = Arc::new(controlled_capture_preview(&workspace));
            for change in ["instance", "project", "close-reopen"] {
                let mut workflow = stopped_workflow("x86_64", "little", Some(&workspace));
                let binding = work_binding(&workflow, Some(&workspace));
                let mut replacement = fixture.workspace();
                if change == "instance" {
                    replacement.project = Arc::clone(&workspace.project);
                }
                if change == "close-reopen" {
                    workflow.reset_stop();
                }
                workflow.binding = Some(binding);
                workflow.job_kind = WorkKind::Prepare;
                workflow.job = Job::Done(Ok(WorkResult::Prepared(Arc::clone(&preview))));
                let current = if change == "close-reopen" { &workspace } else { &replacement };
                workflow.poll("/operator/chosen.sock", Some(current));
                assert!(workflow.preview.is_none() && workflow.saved.is_none(), "accepted {change}");
                assert!(workflow.validate_preview("/operator/chosen.sock", Some(current)).is_err());
            }
        }

        #[test]
        fn explicit_resolution_click_uses_file_address_and_existing_navigation_history_without_connecting() {
            let fixture = StaticFixture::new(&thin_macho(Arch::Aarch64, TEST_UUID));
            let mock = MockSocket::new();
            let ctx = egui::Context::default();
            let mut app = crate::App::blocking();
            app.open(&ctx, fixture.path.clone(), None);
            app.show_debugger();
            app.debugger.socket = mock.path.to_str().unwrap().into();
            app.debugger.request = resolution_request();
            let initial = app.workspace.as_ref().unwrap().cursor;
            let mut harness = Harness::builder()
                .with_size(egui::vec2(1500.0, 1200.0))
                .build_ui_state(|ui, app: &mut crate::App| app.show(ui), app);
            harness.run();
            open_advanced(&mut harness);
            mock.assert_no_connection();
            assert!(harness.query_by_label("Go to matching static image address").is_none());
            harness.get_by_label("Query").click_accesskit();
            harness.step();
            assert!(harness.state().debugger.job.is_running());
            assert_eq!(harness.state().workspace.as_ref().unwrap().cursor, initial);
            let sent = mock.respond(resolution_response());
            assert_eq!(sent["file_address"], format!("{FILE_ADDRESS:#x}"));
            finish(&mut harness.state_mut().debugger);
            harness.run();
            harness.get_by_label(NAVIGATION_LIMITATION);
            assert_eq!(harness.state().workspace.as_ref().unwrap().cursor, initial);
            assert!(!harness.state().workspace.as_ref().unwrap().can_go_back());
            mock.assert_no_connection();
            harness.get_by_label("Go to matching static image address").click_accesskit();
            harness.run();
            let workspace = harness.state_mut().workspace_mut().unwrap();
            assert_eq!(workspace.path, fixture.path);
            assert_eq!(workspace.cursor, FILE_ADDRESS);
            assert_ne!(workspace.cursor, 0x1804);
            assert!(workspace.can_go_back());
            workspace.go_back();
            assert_eq!(workspace.cursor, initial);
            workspace.go_forward();
            assert_eq!(workspace.cursor, FILE_ADDRESS);
            mock.assert_no_connection();
        }

        #[test]
        fn incomplete_and_contradictory_success_evidence_stays_raw_only() {
            let fixture = StaticFixture::new(&thin_macho(Arch::Aarch64, TEST_UUID));
            let workspace = fixture.workspace();
            let changes = [
                ("/data/module_context", serde_json::Value::Null),
                ("/data/module_context/triple", "arm64e-apple-macosx".into()),
                ("/data/module_context/triple", "x86_64h-apple-macosx".into()),
                ("/data/module_context/address_byte_size", 4.into()),
                ("/data/module_context/object_byte_order", "unknown".into()),
                ("/data/module_context/data_byte_order/order", "little".into()),
                ("/data/module/uuid", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into()),
                ("/data/module_uuid", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into()),
                ("/data/module_uuid", "01234567-89ab-cdef-0123-456789abcdef-01234567".into()),
                ("/data/file_address", "0x100000208".into()),
                ("/data/file_address", "0xffffffffffffffff".into()),
                ("/data/file_address", "0x10000000000000000".into()),
                ("/data/file_address", "4096".into()),
                ("/data/load_address", "0x1805".into()),
                ("/data/section/file_end", "0x100000200".into()),
                ("/data/section/load_end", "0x1901".into()),
                ("/data/section/offset", "0x5".into()),
                ("/data/section/ancestors", serde_json::Value::Null),
                ("/data/section/ancestors/0/file_end", "0x100000208".into()),
                ("/data/section/ancestors/0/load_base", "0x1601".into()),
                ("/data/section/index_path", serde_json::json!([1, 0])),
                ("/data/mapping", serde_json::Value::Null),
                ("/data/mapping/base", "0x1805".into()),
                ("/data/mapping/permissions", "--x".into()),
                ("/data/interpretation", serde_json::Value::Null),
                ("/data/address_semantics", serde_json::Value::Null),
                ("/data/proven_layout", true.into()),
            ];
            for (pointer, replacement) in changes {
                let mock = MockSocket::new();
                let ctx = egui::Context::default();
                let mut debugger = Debugger {
                    socket: mock.path.to_str().unwrap().into(),
                    request: resolution_request(),
                    ..Default::default()
                };
                let mut response = resolution_response();
                *response.pointer_mut(pointer).unwrap() = replacement;
                debugger.query(&ctx, Some(&workspace));
                mock.respond(response.clone());
                finish(&mut debugger);
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&debugger.job.ready().unwrap().raw).unwrap(),
                    response
                );
                assert!(debugger.destination(Some(&workspace)).is_err(), "accepted {pointer}");
                mock.assert_no_connection();
            }
        }

        #[test]
        fn a_narrow_module_cannot_qualify_a_wide_runtime_mapping() {
            let fixture = StaticFixture::new(&thin_macho(Arch::Aarch64, TEST_UUID));
            let workspace = fixture.workspace();
            let mock = MockSocket::new();
            let ctx = egui::Context::default();
            let mut request: serde_json::Value = serde_json::from_str(&resolution_request()).unwrap();
            request["file_address"] = "0x1204".into();
            let mut debugger = Debugger {
                socket: mock.path.to_str().unwrap().into(),
                request: request.to_string(),
                ..Default::default()
            };
            let mut response = resolution_response();
            response["data"]["file_address"] = "0x1204".into();
            response["data"]["load_address"] = "0x100001204".into();
            for field in ["module", "module_context"] {
                response["data"][field]["triple"] = "i386-apple-macosx".into();
                response["data"][field]["address_byte_size"] = 4.into();
            }
            response["data"]["section"] = serde_json::json!({
                "index_path":[0],"file_base":"0x1000","file_end":"0x2000",
                "load_base":"0x100001000","load_end":"0x100002000","offset":"0x204","ancestors":[]
            });
            response["data"]["mapping"] = serde_json::json!({
                "base":"0x100001000","end":"0x100002000","permissions":"r-x"
            });
            debugger.query(&ctx, Some(&workspace));
            mock.respond(response);
            finish(&mut debugger);
            let resolution = debugger.job.ready().unwrap().resolution.as_ref().unwrap();
            assert!(resolution.as_ref().unwrap_err().contains("address width"));
            assert!(debugger.destination(Some(&workspace)).is_err());
            mock.assert_no_connection();
        }

        #[test]
        fn late_success_cannot_rebind_a_reopened_workspace_edited_request_or_changed_source() {
            for change in ["workspace", "request", "source"] {
                let fixture = StaticFixture::new(&thin_macho(Arch::Aarch64, TEST_UUID));
                let mock = MockSocket::new();
                let ctx = egui::Context::default();
                let mut workspace = fixture.workspace();
                let mut debugger = Debugger {
                    shown: true,
                    socket: mock.path.to_str().unwrap().into(),
                    request: resolution_request(),
                    ..Default::default()
                };
                debugger.query(&ctx, Some(&workspace));
                match change {
                    "workspace" => workspace = fixture.workspace(),
                    "request" => debugger.request.push(' '),
                    "source" => std::fs::File::options().write(true).open(&fixture.path).unwrap().set_len(0).unwrap(),
                    _ => unreachable!(),
                }
                let mut output =
                    ctx.run_ui(egui::RawInput::default(), |ui| debugger.show(ui.ctx(), Some(&mut workspace)));
                output.textures_delta.clear();
                assert!(debugger.click_context.is_none());
                if change == "request" {
                    debugger.request.pop();
                }
                mock.respond(resolution_response());
                finish(&mut debugger);
                assert!(debugger.job.ready().unwrap().resolution.as_ref().unwrap().is_ok());
                debugger.navigate(Some(&mut workspace));
                assert_eq!(workspace.cursor, 0);
                assert!(!workspace.can_go_back());
                mock.assert_no_connection();
            }
        }

        #[test]
        fn a_query_without_a_workspace_stays_raw_only_after_a_matching_image_is_opened() {
            let mock = MockSocket::new();
            let ctx = egui::Context::default();
            let mut debugger = Debugger {
                socket: mock.path.to_str().unwrap().into(),
                request: resolution_request(),
                ..Default::default()
            };
            debugger.query(&ctx, None);
            mock.respond(resolution_response());
            finish(&mut debugger);
            let fixture = StaticFixture::new(&thin_macho(Arch::Aarch64, TEST_UUID));
            let mut workspace = fixture.workspace();
            debugger.navigate(Some(&mut workspace));
            assert_eq!(workspace.cursor, 0);
            assert!(debugger.destination(Some(&workspace)).unwrap_err().contains("No workspace was open"));
            mock.assert_no_connection();
        }

        #[test]
        fn opening_and_painting_with_a_socket_does_not_connect_but_query_returns_raw_evidence() {
            let mock = MockSocket::new();
            let ctx = egui::Context::default();
            let mut debugger =
                Debugger { shown: true, socket: mock.path.to_str().unwrap().to_owned(), ..Default::default() };
            for _ in 0..3 {
                let mut output = ctx.run_ui(egui::RawInput::default(), |ui| debugger.show(ui.ctx(), None));
                output.textures_delta.clear();
                mock.assert_no_connection();
                assert!(!debugger.job.is_running());
            }
            debugger.query(&ctx, None);
            debugger.request = r#"{"version":1,"operation":"resume"}"#.to_owned();
            debugger.query(&ctx, None);
            let expected = session_response();
            let request = mock.respond(expected.clone());
            assert_eq!(request["operation"], "describe_session");
            finish(&mut debugger);
            let response: serde_json::Value = serde_json::from_str(&debugger.job.ready().unwrap().raw).unwrap();
            assert_eq!(response, expected);
            assert_eq!(debugger.submitted.as_ref().unwrap().1, template(0));
            mock.assert_no_connection();
        }

        #[test]
        fn an_expired_client_deadline_is_forwarded_without_connecting() {
            let mock = MockSocket::new();
            let request = template(0);
            let error = run_query(mock.path.clone(), request, Instant::now(), Arc::new(())).unwrap_err();
            assert!(error.contains("deadline"), "{error}");
            mock.assert_no_connection();
        }

        #[test]
        fn module_resolution_is_manual_local_only_and_retains_raw_qualified_result() {
            let mock = MockSocket::new();
            let ctx = egui::Context::default();
            let token = session_response()["token"].clone();
            let request = serde_json::json!({"version":1,"operation":"resolve_module_address",
                "expected_token":token,"module_uuid":"01234567-89ab-cdef-0123-456789abcdef",
                "file_address":"0x100000004"});
            let mut debugger = Debugger {
                shown: true,
                socket: mock.path.to_str().unwrap().to_owned(),
                template: 5,
                request: request.to_string(),
                ..Default::default()
            };
            let mut output = ctx.run_ui(egui::RawInput::default(), |ui| debugger.show(ui.ctx(), None));
            output.textures_delta.clear();
            mock.assert_no_connection();
            let mut expected = session_response();
            expected["operation"] = serde_json::json!("resolve_module_address");
            expected["data"] = serde_json::json!({"module_uuid":request["module_uuid"],
                "module":{"index":1,"name":"same","path":"/private/runtime/same"},
                "file_address":"0x100000004","load_address":"0x1804",
                "section":{"index_path":[0,0],"ancestors":[{"index_path":[0],
                    "file_base":"0x100000000","file_end":"0x100004000",
                    "load_base":"0x1800","load_end":"0x5800"}]},
                "interpretation":"raw-addresses-only","proven_flow":false,"proven_layout":false});
            debugger.query(&ctx, None);
            let sent = mock.respond(expected.clone());
            assert_eq!(sent["module_uuid"], request["module_uuid"]);
            assert_eq!(sent["file_address"], request["file_address"]);
            assert_eq!(sent["expected_token"], token);
            finish(&mut debugger);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&debugger.job.ready().unwrap().raw).unwrap(),
                expected
            );
            assert!(debugger.job.ready().unwrap().resolution.as_ref().unwrap().is_err());
            assert!(debugger.destination(None).is_err());
            assert_eq!(debugger.submitted.as_ref().unwrap().1, request.to_string());
            mock.assert_no_connection();
        }

        #[test]
        fn unsafe_duplicate_unknown_and_oversized_requests_refuse_before_connecting() {
            let mock = MockSocket::new();
            let requests = [
                r#"{"version":1,"operation":"resume"}"#.to_owned(),
                r#"{"version":1,"operation":"resume","operation":"describe_session"}"#.to_owned(),
                r#"{"version":1,"operation":"describe_session","command":"continue"}"#.to_owned(),
                format!("{}{}", template(0), " ".repeat(MAX_DEBUGGER_REQUEST_BYTES)),
                format!("{}{}", template(0), "é".repeat(MAX_DEBUGGER_REQUEST_BYTES)),
            ];
            for request in requests {
                let mut debugger = Debugger {
                    socket: mock.path.to_str().unwrap().to_owned(),
                    request,
                    job: Job::Done(Ok("old runtime observation".to_owned().into())),
                    ..Default::default()
                };
                debugger.query(&egui::Context::default(), None);
                assert!(debugger.error.is_some());
                assert!(!debugger.job.is_running());
                assert!(debugger.job.ready().is_none());
                assert!(debugger.submitted.is_none());
                mock.assert_no_connection();
            }
        }

        #[test]
        fn rejected_paste_cannot_dispatch_the_previous_valid_request() {
            let mock = MockSocket::new();
            let mut debugger = Debugger { socket: mock.path.to_str().unwrap().to_owned(), ..Default::default() };
            let original = debugger.request.clone();
            let mut edited = false;
            let mut editor = RequestEditor {
                text: &mut debugger.request,
                rejected: &mut debugger.request_rejected,
                edited: &mut edited,
            };
            editor.replace_with(&format!("{original}{}", " ".repeat(MAX_DEBUGGER_REQUEST_BYTES)));
            assert_eq!(debugger.request, original);
            debugger.query(&egui::Context::default(), None);
            assert!(debugger.error.is_some());
            assert!(!debugger.job.is_running());
            mock.assert_no_connection();
        }

        #[test]
        fn stale_token_keeps_the_backend_error_and_clears_old_data_without_a_retry() {
            let mock = MockSocket::new();
            let ctx = egui::Context::default();
            let mut debugger = Debugger { socket: mock.path.to_str().unwrap().to_owned(), ..Default::default() };
            debugger.query(&ctx, None);
            mock.respond(session_response());
            finish(&mut debugger);
            let previous: serde_json::Value = serde_json::from_str(&debugger.job.ready().unwrap().raw).unwrap();
            debugger.request = serde_json::json!({
                "version": 1,
                "operation": "list_threads",
                "expected_token": previous["token"]
            })
            .to_string();
            debugger.query(&ctx, None);
            assert!(debugger.job.ready().is_none());
            let expected = serde_json::json!({
                "protocol": "rampage-lldb-query-v1",
                "ok": false,
                "operation": "list_threads",
                "error": {"code": "stale_token", "message": "process stop changed"}
            });
            let request = mock.respond(expected.clone());
            assert_eq!(request["operation"], "list_threads");
            assert_eq!(request["expected_token"], previous["token"]);
            finish(&mut debugger);
            let response: serde_json::Value = serde_json::from_str(&debugger.job.ready().unwrap().raw).unwrap();
            assert_eq!(response, expected);
            assert!(response.get("data").is_none());
            mock.assert_no_connection();
        }
    }
}
