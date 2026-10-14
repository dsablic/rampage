//! Explicit, local-only debugger observations, kept apart from the loaded project and assistant.

use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use egui::{RichText, TextBuffer, TextEdit, Ui};
use rampage_api::{DebuggerAddress, DebuggerRequest, DebuggerToken, MAX_DEBUGGER_REQUEST_BYTES, Project};
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
        }
    }
}

impl Debugger {
    pub fn show(&mut self, ctx: &egui::Context, workspace: Option<&mut Workspace>) {
        self.job.poll();
        self.check_context(workspace.as_deref());
        if !self.shown {
            return;
        }
        let mut shown = self.shown;
        egui::Window::new("Read-only debugger")
            .open(&mut shown)
            .collapsible(false)
            .default_size(egui::vec2(720.0, 560.0))
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 60.0))
            .show(ctx, |ui| self.contents(ui, workspace));
        self.shown = shown;
    }

    fn contents(&mut self, ui: &mut Ui, workspace: Option<&mut Workspace>) {
        ui.label(RichText::new("Local runtime observation only").strong());
        ui.label(
            "Socket paths, requests and results stay in this window; they are never sent to an assistant or provider.",
        );
        ui.label(
            RichText::new(
                "Start the read-only LLDB endpoint yourself while stopped. Opening this window does not connect. \
                 Only Query connects; nothing is attached, resumed, evaluated or written.",
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
        }
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
            if ui.add_enabled(!self.job.is_running(), egui::Button::new("Query")).clicked() {
                self.query(ui.ctx(), workspace.as_deref());
            }
            if ui.add_enabled(!self.job.is_running(), egui::Button::new("Clear local data")).clicked() {
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
        self.navigation_ui(ui, workspace);
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
        let shown = self.shown;
        *self = Self { shown, request: String::new(), ..Self::default() };
        for field in ["debugger-socket", "debugger-request"] {
            egui::text_edit::TextEditState::default().store(ctx, egui::Id::new(field));
        }
    }

    fn query(&mut self, ctx: &egui::Context, workspace: Option<&Workspace>) {
        if self.job.is_running() {
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
        self.job.start(false, ctx, move || run_query(socket, request, deadline, revision));
    }

    pub(crate) fn invalidate_navigation(&mut self) {
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
        match self.destination(workspace.as_deref()) {
            Ok(address) => {
                if let Some(workspace) = workspace {
                    workspace.goto(address);
                }
            }
            Err(error) => self.navigation_notice = Some(error),
        }
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
        if binary.format != Format::MachO || !supported_static_variant(binary) {
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
        if self.address_bytes != u64::from(self.architecture.pointer_size())
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
            || self.address_bytes != u64::from(binary.arch.pointer_size())
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

fn supported_static_variant(binary: &Binary) -> bool {
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
    use egui_kittest::kittest::Queryable;

    const TEST_UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const FILE_BASE: u64 = 0x1_0000_0000;
    const FILE_ADDRESS: u64 = FILE_BASE + 0x204;

    struct StaticFixture {
        directory: PathBuf,
        path: PathBuf,
    }

    impl StaticFixture {
        fn new(bytes: &[u8]) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
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
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_dir(&self.directory);
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
            harness.get_by_label("Go to matching static image address");
            match action {
                "socket" => {
                    harness.ctx.memory_mut(|memory| memory.request_focus(egui::Id::new("debugger-socket")));
                    harness.run();
                    harness.event(egui::Event::Paste("changed".into()));
                }
                "template" => {
                    harness.get_by_role(egui::accesskit::Role::ComboBox).click();
                    harness.run();
                    harness.get_by_label("list_modules").click();
                }
                "insert-template" => harness.get_by_label("Insert template").click(),
                "clear" => harness.get_by_label("Clear local data").click(),
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
            mock.assert_no_connection();
            assert!(harness.query_by_label("Go to matching static image address").is_none());
            harness.get_by_label("Query").click();
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
            harness.get_by_label("Go to matching static image address").click();
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
