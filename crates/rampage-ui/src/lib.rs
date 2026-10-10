//! The rampage desktop UI: an egui front end over the same API the CLI and MCP server use.

mod band;
mod graph;
mod listing;
mod tabs;
pub mod theme;
mod workspace;

use std::path::PathBuf;

use egui::{Key, Modifiers, RichText, TextEdit, Ui};
use egui_dock::{DockArea, DockState, NodeIndex, Style};
use rampage_api::annotations::Field;
use rampage_arch::Arch;

pub use tabs::Tab;
pub use workspace::Workspace;

pub struct App {
    workspace: Option<Workspace>,
    error: Option<String>,
    dock: DockState<Tab>,
    /// Run background work inline, for deterministic tests and snapshots.
    blocking: bool,
    themed: bool,
    /// Whether a text field had keyboard focus last frame. Escape takes focus away before shortcuts run, so this
    /// keeps Escape in a text field from also going back.
    typing: bool,
}

fn default_layout() -> DockState<Tab> {
    let mut dock = DockState::new(vec![Tab::Disassembly, Tab::Graph, Tab::Triage]);
    let surface = dock.main_surface_mut();
    let [center, _] =
        surface.split_left(NodeIndex::root(), 0.20, vec![Tab::Functions, Tab::Strings, Tab::Imports, Tab::Exports]);
    surface.split_right(center, 0.76, vec![Tab::Xrefs]);
    dock
}

impl Default for App {
    fn default() -> Self {
        Self { workspace: None, error: None, dock: default_layout(), blocking: false, themed: false, typing: false }
    }
}

impl App {
    /// An app that computes everything inline, so a single frame shows final results.
    pub fn blocking() -> Self {
        Self { blocking: true, ..Self::default() }
    }

    pub fn open(&mut self, ctx: &egui::Context, path: PathBuf, arch: Option<Arch>) {
        match Workspace::open(path, arch, ctx, self.blocking) {
            Ok(workspace) => {
                self.workspace = Some(workspace);
                self.error = None;
            }
            Err(error) => self.error = Some(error),
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
        egui::Panel::bottom("status").exact_size(22.0).show(ui, |ui| self.status_bar(ui));
        let Some(workspace) = &mut self.workspace else {
            egui::CentralPanel::default().show(ui, |ui| self.empty(ui));
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
        if let Some(workspace) = &mut self.workspace {
            Self::edit_dialog(&ui.ctx().clone(), workspace);
        }
        self.shortcuts(ui.ctx());
        if self.workspace.as_ref().is_some_and(|workspace| workspace.show_listing) {
            let code_view = if self.graph_in_use(ui.ctx()) { Tab::Graph } else { Tab::Disassembly };
            self.focus_tab(code_view);
        }
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
            && self.workspace.as_ref().is_some_and(|workspace| workspace.editing.is_none())
            && ctx.input_mut(|input| input.consume_key(Modifiers::NONE, Key::Space));
        if toggle {
            let view = if self.graph_in_use(ctx) { Tab::Disassembly } else { Tab::Graph };
            self.focus_tab(view);
        }
        let typing = std::mem::replace(&mut self.typing, ctx.egui_wants_keyboard_input());
        let Some(workspace) = &mut self.workspace else { return };
        if typing || self.typing || workspace.editing.is_some() {
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
    fn edit_dialog(ctx: &egui::Context, workspace: &mut Workspace) {
        let Some(editing) = &mut workspace.editing else { return };
        let title = match editing.field {
            Field::Name => format!("Rename {:#x}", editing.address),
            Field::Comment => format!("Comment {:#x}", editing.address),
        };
        let mut done = false;
        let mut cancel = false;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 120.0))
            .show(ctx, |ui| {
                let field = ui
                    .add(TextEdit::singleline(&mut editing.text).desired_width(360.0).font(egui::TextStyle::Monospace));
                field.request_focus();
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

    fn top_bar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("rampage").strong().color(theme::LINK));
            let Some(workspace) = &mut self.workspace else { return };
            ui.separator();
            let name = workspace.path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            ui.label(RichText::new(name).strong());
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
        });
    }

    fn status_bar(&mut self, ui: &mut Ui) {
        ui.horizontal_centered(|ui| {
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
            }
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
    }
}
