//! The rampage desktop UI: an egui front end over the same API the CLI and MCP server use.

mod about;
pub mod assistant;
mod band;
mod cached_inventory_ui;
mod carve;
mod debug_layout;
mod debugger;
mod entry_ui;
mod graph;
mod listing;
mod module_references_ui;
mod tabs;
pub mod theme;
mod workspace;
mod workspace_bank;
mod workspace_jobs;

use std::path::PathBuf;
use std::sync::Arc;

use egui::{Key, Modifiers, RichText, TextEdit, Ui};
use egui_dock::{DockArea, DockState, NodeIndex, Style};
use rampage_api::annotations::Field;
use rampage_api::{Packs, Session};
use rampage_arch::Arch;
use rampage_loaders::ImageAt;

pub use tabs::Tab;
pub use workspace::Workspace;
pub use workspace_bank::{ModuleInfo, ProjectWorkspaceSaveNotice};

pub struct App {
    session: Session,
    /// One line per pack or content that did not load, once the packs have loaded.
    pack_problems: Option<Vec<String>>,
    workspace: Option<Workspace>,
    workspace_bank: workspace_bank::WorkspaceBank,
    workspace_jobs: workspace_jobs::WorkspaceJobs,
    cached_inventory: cached_inventory_ui::CachedInventoryUi,
    module_references: module_references_ui::ModuleReferences,
    entry_gate: entry_ui::EntryGate,
    /// Shared with replacement workspaces; dropping a receiver does not stop its preview thread.
    debug_layout_gate: debug_layout::PreviewGate,
    /// The carving of the file last opened, for opening what it embeds.
    carve: Option<carve::Carve>,
    error: Option<String>,
    dock: DockState<Tab>,
    /// Run background work inline, for deterministic tests and snapshots.
    blocking: bool,
    themed: bool,
    /// Whether a text field had keyboard focus last frame. Escape takes focus away before shortcuts run, so this
    /// keeps Escape in a text field from also going back.
    typing: bool,
    about: bool,
    debugger: debugger::Debugger,
}

fn default_layout() -> DockState<Tab> {
    let mut dock = DockState::new(vec![Tab::Disassembly, Tab::Graph, Tab::Pseudocode, Tab::Triage]);
    let surface = dock.main_surface_mut();
    let [center, _] =
        surface.split_left(NodeIndex::root(), 0.20, vec![Tab::Functions, Tab::Strings, Tab::Imports, Tab::Exports]);
    surface.split_right(center, 0.72, vec![Tab::Xrefs, Tab::Assistant]);
    dock
}

impl Default for App {
    fn default() -> Self {
        Self {
            session: Session::default(),
            pack_problems: None,
            workspace: None,
            workspace_bank: workspace_bank::WorkspaceBank::default(),
            workspace_jobs: workspace_jobs::WorkspaceJobs::default(),
            cached_inventory: cached_inventory_ui::CachedInventoryUi::default(),
            module_references: module_references_ui::ModuleReferences::default(),
            entry_gate: entry_ui::EntryGate::default(),
            debug_layout_gate: debug_layout::PreviewGate::default(),
            carve: None,
            error: None,
            dock: default_layout(),
            blocking: false,
            themed: false,
            typing: false,
            about: false,
            debugger: debugger::Debugger::default(),
        }
    }
}

impl App {
    /// An app that computes everything inline, so a single frame shows final results.
    pub fn blocking() -> Self {
        Self { blocking: true, ..Self::default() }
    }

    pub fn open(&mut self, ctx: &egui::Context, path: PathBuf, arch: Option<Arch>) {
        self.open_at(ctx, path, arch, None);
    }

    /// Opens `path`, or the executable embedded at `image` in it, and carves the file for what else it embeds. When
    /// the file cannot be opened, the Carve window shows what it embeds instead.
    pub fn open_at(&mut self, ctx: &egui::Context, path: PathBuf, arch: Option<Arch>, image: Option<ImageAt>) {
        if let Err(error) = self.ensure_bank_replaceable() {
            self.error = Some(error);
            return;
        }
        if self.carve.as_ref().is_none_or(|carve| carve.path != path) {
            self.carve = Some(carve::Carve::start(path.clone(), ctx, self.blocking));
        }
        let opened = Workspace::open(&self.session, path, arch, image, ctx, self.blocking)
            .and_then(|workspace| self.replace_workspace(workspace));
        match opened {
            Ok(()) => {
                self.error = None;
            }
            Err(error) => {
                if let Some(carve) = &mut self.carve {
                    carve.error = image.is_some().then(|| error.clone());
                    carve.shown = true;
                }
                self.error = Some(error);
            }
        }
    }

    /// Shows the Carve window for the file last opened.
    pub fn show_carve(&mut self) {
        if let Some(carve) = &mut self.carve {
            carve.shown = true;
        }
    }

    /// Layers data packs over the bundled databases of every binary opened. They load in the background (inline
    /// for a blocking app), and the About window lists them with their problems.
    pub fn with_packs(self, packs: Arc<Packs>) -> Self {
        if packs.configured() {
            if self.blocking {
                packs.loaded();
            } else {
                let loading = Arc::clone(&packs);
                std::thread::spawn(move || {
                    loading.loaded();
                });
            }
        }
        Self { session: Session::default().with_packs(packs), ..self }
    }

    /// Opens the About window with the version, licence and third-party notices.
    pub fn show_about(&mut self) {
        self.about = true;
    }

    /// Opens the local read-only debugger window without connecting or requiring a loaded binary.
    pub fn show_debugger(&mut self) {
        self.debugger.shown = true;
    }

    /// Opens controls only. Source metadata is queried solely by an explicit Refresh action.
    pub fn show_module_references(&mut self) {
        self.module_references.show();
    }

    /// Opens a fresh checked layout review without importing anything.
    pub fn show_debug_layout_review(&mut self, ctx: &egui::Context) {
        if let Some(workspace) = &mut self.workspace {
            workspace.review_debug_layouts(ctx);
        }
    }

    pub fn workspace_mut(&mut self) -> Option<&mut Workspace> {
        self.workspace.as_mut()
    }

    /// Brings `tab` to the front of its panel.
    pub fn focus_tab(&mut self, tab: Tab) {
        if let Some(workspace) = &mut self.workspace {
            workspace.show_listing = false;
        }
        // A location from find_tab is always valid, so activating it cannot fail.
        if let Some(location) = self.dock.find_tab(&tab) {
            let _ = self.dock.set_active_tab(location);
        }
    }

    pub fn show(&mut self, ui: &mut Ui) {
        self.poll_workspace_jobs(ui.ctx());
        if !self.themed {
            theme::apply(ui.ctx());
            self.themed = true;
        }
        let dropped = ui.ctx().input(|input| input.raw.dropped_files.first().map(|file| file.path().to_path_buf()));
        if let Some(path) = dropped {
            self.open(&ui.ctx().clone(), path, None);
        }
        if let Some(workspace) = &mut self.workspace {
            workspace.poll(ui.ctx());
        }

        egui::Panel::top("top").show(ui, |ui| self.top_bar(ui));
        if self.workspace_jobs.visible() {
            egui::Panel::top("workspace-file-operation").show(ui, |ui| self.workspace_jobs.show(ui));
        }
        egui::Panel::bottom("status").exact_size(22.0).show(ui, |ui| self.status_bar(ui));
        if self.about {
            about::show(&ui.ctx().clone(), &mut self.about, &self.session.packs());
        }
        self.carve_window(&ui.ctx().clone());
        self.project_workspace_window(ui.ctx());
        self.cached_inventory_window(ui.ctx());
        self.open_path_window(ui.ctx());
        let reference_inputs = self.module_reference_inputs();
        if let Some(navigation) =
            module_references_ui::show(ui.ctx(), &mut self.module_references, self.blocking, &reference_inputs)
            && let Err(error) = self.navigate_module_reference(&navigation.inputs, &navigation.address)
        {
            self.module_references.navigation_failed(error);
        }
        let debugger_action = self.debugger.show_action(ui.ctx(), self.workspace.as_mut());
        if let Some(action) = debugger_action {
            self.open_debugger_snapshot(ui.ctx(), action);
        }
        let Some(workspace) = &mut self.workspace else {
            egui::CentralPanel::default().show(ui, |ui| self.empty(ui));
            self.shortcuts(ui.ctx());
            return;
        };
        egui::Panel::top("band").exact_size(18.0).show(ui, |ui| band::show(ui, workspace));
        egui::CentralPanel::default().frame(egui::Frame::NONE).show(ui, |ui| {
            let mut style = Style::from_egui(ui.style());
            style.tab_bar.bg_fill = theme::BACKGROUND;
            DockArea::new(&mut self.dock)
                .style(style)
                .show_close_buttons(false)
                .show_add_buttons(false)
                .show_leaf_collapse_buttons(false)
                .show_leaf_close_all_buttons(false)
                .show_inside(ui, &mut tabs::Viewer { workspace });
        });
        let editor_scope = self.annotation_editor_scope();
        if let Some(workspace) = &mut self.workspace {
            workspace.show_entry_window(ui.ctx());
            debug_layout::show(ui.ctx(), workspace);
            Self::edit_dialog(&ui.ctx().clone(), workspace, editor_scope);
            Self::undo_dialog(&ui.ctx().clone(), workspace);
        }
        self.shortcuts(ui.ctx());
        if self.workspace.as_ref().is_some_and(|workspace| workspace.show_listing) {
            let code_view = if self.graph_in_use(ui.ctx()) { Tab::Graph } else { Tab::Disassembly };
            self.focus_tab(code_view);
        }
    }

    fn carve_window(&mut self, ctx: &egui::Context) {
        let Some(carve) = &mut self.carve else { return };
        carve.job.poll();
        if !carve.shown {
            return;
        }
        let current = self.workspace.as_ref().map(|workspace| workspace.image.map_or(0, ImageAt::offset));
        if let Some(image) = carve::show(ctx, carve, current) {
            let path = carve.path.clone();
            self.open_at(ctx, path, None, Some(image));
        }
    }

    fn open_debugger_snapshot(&mut self, ctx: &egui::Context, action: debugger::OpenSnapshot) {
        let result = (|| {
            self.ensure_bank_replaceable()?;
            action.validate_source(self.workspace.as_ref())?;
            let verified = rampage_api::read_debugger_capture_publication(&action.path, &action.document_sha256)
                .map_err(|error| error.to_string())?;
            let workspace = Workspace::open(&self.session, action.path.clone(), None, None, ctx, self.blocking)?;
            self.finish_debugger_snapshot_open(&action, &verified, workspace)
        })();
        if let Err(error) = result {
            self.error = Some(error);
        }
    }

    fn finish_debugger_snapshot_open(
        &mut self,
        action: &debugger::OpenSnapshot,
        verified: &[u8],
        workspace: Workspace,
    ) -> Result<(), String> {
        if workspace.project.binary.format != rampage_loaders::Format::Snapshot
            || workspace.project.binary.file_bytes() != verified
        {
            return Err("Saved capture changed while opening; the original workspace remains open.".to_owned());
        }
        action.validate_source(self.workspace.as_ref())?;
        self.ensure_bank_replaceable()?;
        self.replace_workspace(workspace)?;
        self.carve = None;
        self.error = None;
        Ok(())
    }

    /// Whether the graph was on screen in this pass or the last, so navigation should stay in it.
    fn graph_in_use(&self, ctx: &egui::Context) -> bool {
        let pass = ctx.cumulative_pass_nr();
        self.workspace
            .as_ref()
            .and_then(|workspace| workspace.graph_shown_pass)
            .is_some_and(|shown| pass.saturating_sub(shown) <= 1)
    }

    fn shortcuts(&mut self, ctx: &egui::Context) {
        // Space switches between the listing and the graph, as in IDA.
        let toggle = !ctx.egui_wants_keyboard_input()
            && self
                .workspace
                .as_ref()
                .is_some_and(|workspace| workspace.editing.is_none() && !workspace.debug_layout.shown())
            && ctx.input_mut(|input| input.consume_key(Modifiers::NONE, Key::Space));
        if toggle {
            let view = if self.graph_in_use(ctx) { Tab::Disassembly } else { Tab::Graph };
            self.focus_tab(view);
        }
        let typing = std::mem::replace(&mut self.typing, ctx.egui_wants_keyboard_input());
        if !typing && !self.typing && ctx.input_mut(|input| input.consume_key(Modifiers::COMMAND, Key::D)) {
            self.show_debugger();
        }
        let Some(workspace) = &mut self.workspace else { return };
        if typing || self.typing || workspace.editing.is_some() || workspace.debug_layout.shown() {
            return;
        }
        // Consuming the keys keeps them from reaching anything else. Matching ignores extra Shift, so Cmd+Shift+Z
        // is checked before Cmd+Z; it also requires Cmd to match, so Cmd+G and Cmd+N do not trigger G and N.
        let (redo, undo, back, forward, goto, rename, comment) = ctx.input_mut(|input| {
            let alt = Modifiers::ALT;
            (
                input.consume_key(Modifiers::COMMAND | Modifiers::SHIFT, Key::Z),
                input.consume_key(Modifiers::COMMAND, Key::Z),
                input.consume_key(Modifiers::NONE, Key::Escape) || input.consume_key(alt, Key::ArrowLeft),
                input.consume_key(alt, Key::ArrowRight),
                input.consume_key(Modifiers::NONE, Key::G),
                input.consume_key(Modifiers::NONE, Key::N),
                input.consume_key(Modifiers::NONE, Key::Semicolon),
            )
        });
        if back {
            workspace.go_back();
        }
        if forward {
            workspace.go_forward();
        }
        if goto {
            ctx.memory_mut(|memory| memory.request_focus(egui::Id::new("goto")));
        }
        if rename {
            workspace.begin_rename();
        }
        if comment {
            workspace.begin_comment();
        }
        if undo {
            workspace.undo();
        }
        if redo {
            workspace.redo();
        }
    }

    /// The rename or comment dialog.
    fn edit_dialog(ctx: &egui::Context, workspace: &mut Workspace, editor_scope: egui::Id) {
        let Some(editing) = &mut workspace.editing else { return };
        let title = match editing.field {
            Field::Name => format!("Rename {:#x}", editing.address),
            Field::Comment => format!("Comment {:#x}", editing.address),
            Field::Signature => format!("Signature {:#x}", editing.address),
            Field::Types => format!("Types {:#x}", editing.address),
            Field::Global => format!("Global {:#x}", editing.address),
            Field::LocalName | Field::LocalType => format!("Local variable {:#x}", editing.address),
            Field::TypeLibrary => "Project type library".to_owned(),
            Field::DataType => format!("Data type {:#x}", editing.address),
            Field::OperandType => format!("Operand type {:#x}", editing.address),
        };
        let mut done = false;
        let mut cancel = false;
        let window_id = editor_scope.with(("window", &title));
        let text_id = editor_scope.with(("text", &title));
        egui::Window::new(title)
            .id(window_id)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 120.0))
            .show(ctx, |ui| {
                // An unfocused TextEdit collapses its saved selection before handling input.
                ui.memory_mut(|memory| {
                    if !memory.has_focus(text_id) {
                        memory.request_focus(text_id);
                    }
                });
                ui.add(
                    TextEdit::singleline(&mut editing.text)
                        .id(text_id)
                        .desired_width(360.0)
                        .font(egui::TextStyle::Monospace),
                );
                ui.label(RichText::new("Enter to save, Escape to cancel, empty to remove").color(theme::DIM).small());
                if let Some(error) = &workspace.edit_error {
                    ui.label(RichText::new(error).color(theme::WARNING));
                }
                done = ui.input_mut(|input| input.consume_key(Modifiers::NONE, Key::Enter));
                cancel = ui.input_mut(|input| input.consume_key(Modifiers::NONE, Key::Escape));
            });
        if cancel {
            workspace.editing = None;
        } else if done {
            workspace.finish_edit();
        }
    }

    /// Offers to discard an undo step another client's edits block. Discarding is never forced, so a step that is
    /// no longer blocked stays undoable.
    fn undo_dialog(ctx: &egui::Context, workspace: &mut Workspace) {
        let Some(reason) = &workspace.blocked_undo else { return };
        let (mut discard, mut keep) = (false, false);
        egui::Window::new("Undo blocked")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 120.0))
            .show(ctx, |ui| {
                ui.set_max_width(460.0);
                ui.label(RichText::new(reason).color(theme::WARNING));
                ui.add_space(4.0);
                ui.label(
                    "Another client changed what this step would revert, so it cannot be undone, and it blocks every \
                     earlier step. Discarding drops it from the undo history: its edits stay in effect and earlier \
                     steps can be undone.",
                );
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    discard = ui.button("Discard step").clicked();
                    keep = ui.button("Keep").clicked();
                });
            });
        if discard {
            workspace.discard_blocked_undo();
        } else if keep {
            workspace.blocked_undo = None;
        }
    }

    fn top_bar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            let brand = ui.add(
                egui::Label::new(RichText::new("rampage").strong().color(theme::LINK)).sense(egui::Sense::click()),
            );
            brand.context_menu(|ui| {
                if ui.button("Project workspace…").clicked() {
                    self.show_project_workspace();
                    ui.close();
                }
                if ui.button("Cached function inventory…").clicked() {
                    self.show_cached_function_inventory();
                    ui.close();
                }
                if ui.button("Module references…").clicked() {
                    self.show_module_references();
                    ui.close();
                }
                if ui.button("Open for exact-entry…").clicked() {
                    self.show_open_path(workspace_bank::OpenPathAction::ReplaceExact);
                    ui.close();
                }
                if ui.add_enabled(self.workspace.is_some(), egui::Button::new("Exact-entry decompilation…")).clicked()
                {
                    if let Some(workspace) = &mut self.workspace {
                        workspace.show_entry_decompilation();
                    }
                    ui.close();
                }
                if ui
                    .add_enabled(self.workspace.is_some(), egui::Button::new("Review checked debug layouts…"))
                    .clicked()
                {
                    self.show_debug_layout_review(ui.ctx());
                    ui.close();
                }
                if ui.button("Read-only debugger (Cmd+D)").clicked() {
                    self.show_debugger();
                    ui.close();
                }
            });
            if brand.on_hover_text("About rampage").clicked() {
                self.about = true;
            }
            self.module_selector(ui);
            let Some(workspace) = &mut self.workspace else { return };
            ui.separator();
            let name = workspace.path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            ui.label(RichText::new(name).strong());
            if let Some(image) = workspace.image {
                ui.label(RichText::new(format!("@ {:#x}", image.offset())).monospace())
                    .on_hover_text("The executable embedded at this file offset");
            }
            ui.label(RichText::new(workspace.project.binary.arch.to_string()).color(theme::DIM));
            ui.separator();
            if ui
                .add_enabled(workspace.can_go_back(), egui::Button::new("◀"))
                .on_hover_text("Back (Esc, Alt+Left)")
                .clicked()
            {
                workspace.go_back();
            }
            if ui
                .add_enabled(workspace.can_go_forward(), egui::Button::new("▶"))
                .on_hover_text("Forward (Alt+Right)")
                .clicked()
            {
                workspace.go_forward();
            }
            let goto = ui.add(
                TextEdit::singleline(&mut workspace.goto_text)
                    .id(egui::Id::new("goto"))
                    .hint_text("Go to address or name (G)")
                    .desired_width(260.0)
                    .font(egui::TextStyle::Monospace),
            );
            if goto.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)) {
                let text = workspace.goto_text.trim().to_owned();
                if !text.is_empty() {
                    workspace.goto_text(&text);
                }
            }
            if let Some(error) = &workspace.goto_error {
                ui.label(RichText::new(error).color(theme::WARNING));
            }
            // Offered only when the file embeds something else, so plain binaries keep a plain toolbar.
            let current = workspace.image.map_or(0, ImageAt::offset);
            if let Some(carve) = &mut self.carve {
                let others = carve.others(current);
                if others > 0 || workspace.image.is_some() {
                    ui.separator();
                    let button = ui.button(format!("Carve {others}"));
                    if button.on_hover_text("Executables and containers embedded in this file").clicked() {
                        carve.shown = !carve.shown;
                    }
                }
            }
        });
    }

    fn status_bar(&mut self, ui: &mut Ui) {
        let packs = self.session.packs();
        if self.pack_problems.is_none() && packs.configured() && packs.is_loaded() {
            self.pack_problems = Some(packs.problems());
        }
        ui.horizontal_centered(|ui| {
            if let Some(problems) = self.pack_problems.as_ref().filter(|problems| !problems.is_empty()) {
                let plural = if problems.len() == 1 { "" } else { "s" };
                let label = ui.add(
                    egui::Label::new(
                        RichText::new(format!("{} data pack problem{plural}", problems.len())).color(theme::WARNING),
                    )
                    .sense(egui::Sense::click()),
                );
                if label.on_hover_text(problems.join("\n")).clicked() {
                    self.about = true;
                }
                ui.separator();
            }
            if let Some(error) = &self.error {
                ui.label(RichText::new(error).color(theme::WARNING));
                ui.separator();
            }
            let Some(workspace) = &self.workspace else { return };
            if let Some(error) = &workspace.notice {
                ui.label(RichText::new(error).color(theme::WARNING));
                ui.separator();
            }
            if workspace.functions.is_running() {
                ui.spinner();
                ui.label(RichText::new("Analyzing").color(theme::DIM));
            } else if let Some(functions) = workspace.functions.ready() {
                ui.label(RichText::new(format!("{} functions", functions.len())).color(theme::DIM));
            } else if let Some(error) = workspace.functions.error() {
                ui.label(RichText::new(error).color(theme::WARNING));
            }
            ui.separator();
            ui.label(RichText::new(format!("cursor {:#x}", workspace.cursor)).color(theme::DIM).monospace());
            let binary = &workspace.project.binary;
            ui.separator();
            ui.label(RichText::new(format!("{:?} {}", binary.format, binary.arch)).color(theme::DIM));
        });
    }

    fn empty(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() * 0.35);
            ui.label(RichText::new("rampage").size(28.0).color(theme::LINK));
            ui.add_space(8.0);
            ui.label(RichText::new("Drop a PE, ELF or Mach-O binary here to open it").color(theme::DIM));
            if let Some(error) = &self.error {
                ui.add_space(8.0);
                ui.label(RichText::new(error).color(theme::WARNING));
                if let Some(carve) = &mut self.carve
                    && !carve.shown
                    && ui.button("Carve for embedded executables").clicked()
                {
                    carve.shown = true;
                }
            }
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
    }
}
