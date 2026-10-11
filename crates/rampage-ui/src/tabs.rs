//! The dockable panels.

use egui::{Color32, RichText, Sense, TextEdit, Ui, WidgetText};
use egui_extras::{Column, TableBuilder};
use rampage_loaders::Details;

use crate::workspace::{Filter, Workspace, matches};
use crate::{graph, listing, theme};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Functions,
    Strings,
    Imports,
    Exports,
    Disassembly,
    Graph,
    Pseudocode,
    Xrefs,
    Assistant,
    Triage,
}

pub struct Viewer<'a> {
    pub workspace: &'a mut Workspace,
}

impl egui_dock::TabViewer for Viewer<'_> {
    type Tab = Tab;

    fn id(&mut self, tab: &mut Tab) -> egui::Id {
        egui::Id::new(*tab as u8)
    }

    fn title(&mut self, tab: &mut Tab) -> WidgetText {
        let workspace = &*self.workspace;
        let count = |n: usize| format!(" {n}");
        let title = match tab {
            Tab::Functions => {
                format!("Functions{}", workspace.functions.ready().map_or(String::new(), |f| count(f.len())))
            }
            Tab::Strings => format!("Strings{}", workspace.strings.ready().map_or(String::new(), |s| count(s.len()))),
            Tab::Imports => format!("Imports{}", count(workspace.imports.len())),
            Tab::Exports => format!("Exports{}", count(workspace.exports.len())),
            Tab::Disassembly => match &workspace.listing {
                Some(Ok(listing)) if !listing.function.name.is_empty() => {
                    format!("Disassembly - {}", listing.function.name)
                }
                None if workspace.analysis_ready() => format!("Hex - {:#x}", workspace.cursor),
                _ => "Disassembly".to_owned(),
            },
            Tab::Graph => "Graph".to_owned(),
            Tab::Pseudocode => "Pseudocode".to_owned(),
            Tab::Xrefs => "Xrefs".to_owned(),
            Tab::Assistant => "Assistant".to_owned(),
            Tab::Triage => "Triage".to_owned(),
        };
        title.into()
    }

    fn ui(&mut self, ui: &mut Ui, tab: &mut Tab) {
        match tab {
            Tab::Functions => functions(ui, self.workspace),
            Tab::Strings => strings(ui, self.workspace),
            Tab::Imports => imports(ui, self.workspace),
            Tab::Exports => exports(ui, self.workspace),
            Tab::Disassembly => listing::show(ui, self.workspace),
            Tab::Graph => {
                self.workspace.graph_shown_pass = Some(ui.ctx().cumulative_pass_nr());
                graph::show(ui, self.workspace);
            }
            Tab::Pseudocode => pseudocode(ui, self.workspace),
            Tab::Xrefs => xrefs(ui, self.workspace),
            Tab::Assistant => {
                if crate::assistant::show(ui, &mut self.workspace.assistant) {
                    let project = std::sync::Arc::clone(&self.workspace.project);
                    self.workspace.assistant.ask(&project, ui.ctx());
                }
            }
            Tab::Triage => triage(ui, self.workspace),
        }
    }

    fn is_closeable(&self, _tab: &Tab) -> bool {
        false
    }
}

fn pseudocode(ui: &mut Ui, workspace: &mut Workspace) {
    workspace.want_pseudocode(ui.ctx());
    if let Some(error) = workspace.pseudocode.error() {
        ui.label(error);
        return;
    }
    let Some(result) = workspace.pseudocode.ready() else {
        ui.spinner();
        return;
    };
    ui.label(&result.language_id);
    let mut target = None;
    egui::ScrollArea::both().show(ui, |ui| {
        ui.label(RichText::new(&result.code).monospace());
        ui.separator();
        ui.label("Address-linked tokens");
        ui.horizontal_wrapped(|ui| {
            for token in &result.tokens {
                if let Some(address) = token.address
                    && ui.link(&token.text).on_hover_text(format!("{address:#x} ({})", token.kind)).clicked()
                {
                    target = Some(address);
                }
            }
        });
    });
    if let Some(address) = target {
        workspace.goto(address);
    }
}

fn filter_box(ui: &mut Ui, filter: &mut Filter, hint: &str) {
    ui.add(TextEdit::singleline(&mut filter.text).hint_text(hint).desired_width(f32::INFINITY));
    ui.add_space(2.0);
}

fn status(ui: &mut Ui, message: &str) {
    ui.centered_and_justified(|ui| ui.label(RichText::new(message).color(theme::DIM)));
}

fn mono(text: impl Into<String>, color: Color32) -> RichText {
    RichText::new(text).color(color).monospace()
}

fn address(address: u64) -> RichText {
    mono(format!("{address:x}"), theme::ADDRESS)
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// One table row: its cells, whether it is the current item, and where clicking it goes.
struct Row {
    cells: Vec<RichText>,
    selected: bool,
    target: Option<u64>,
}

/// A striped, clickable table of `count` rows built on demand by `row_at`, so only visible rows are formatted.
/// Column `wide` takes the remaining width. Returns the target of the clicked row.
fn table(
    ui: &mut Ui,
    header: &[&str],
    columns: usize,
    wide: usize,
    count: usize,
    mut row_at: impl FnMut(usize) -> Row,
) -> Option<u64> {
    let height = ui.text_style_height(&egui::TextStyle::Monospace) + 4.0;
    let mut builder = TableBuilder::new(ui).striped(true).sense(Sense::click());
    for index in 0..columns {
        builder = builder.column(if index == wide { Column::remainder().clip(true) } else { Column::auto() });
    }
    let mut chosen = None;
    let body = |body: egui_extras::TableBody| {
        body.rows(height, count, |mut row| {
            let Row { cells, selected, target } = row_at(row.index());
            row.set_selected(selected);
            for (index, cell) in cells.into_iter().enumerate() {
                // The wide column cuts long text short; the others size to fit theirs.
                let label = egui::Label::new(cell);
                let label = if index == wide { label.truncate() } else { label.extend() };
                row.col(|ui| {
                    ui.add(label);
                });
            }
            if row.response().clicked() {
                chosen = target;
            }
        });
    };
    if header.is_empty() {
        builder.body(body);
    } else {
        builder
            .header(height, |mut row| {
                for title in header {
                    row.col(|ui| {
                        ui.label(RichText::new(*title).color(theme::DIM));
                    });
                }
            })
            .body(body);
    }
    chosen
}

fn functions(ui: &mut Ui, workspace: &mut Workspace) {
    filter_box(ui, &mut workspace.function_filter, "Filter functions");
    let Some(all) = workspace.functions.ready() else {
        status(ui, workspace.functions.error().unwrap_or("Analyzing..."));
        return;
    };
    let current = workspace.listing_address();
    let shown = workspace.function_filter.shown(all.len(), |index, needle| matches(&all[index].name, needle));
    let chosen = table(ui, &["Name", "Address", "Size"], 3, 0, shown.len(), |index| {
        let function = &all[shown[index]];
        Row {
            cells: vec![
                RichText::new(&function.name).monospace(),
                address(function.address),
                mono(function.size.to_string(), theme::DIM),
            ],
            selected: Some(function.address) == current,
            target: Some(function.address),
        }
    });
    if let Some(address) = chosen {
        workspace.goto(address);
    }
}

fn strings(ui: &mut Ui, workspace: &mut Workspace) {
    workspace.want_strings(ui.ctx());
    filter_box(ui, &mut workspace.string_filter, "Filter strings");
    let Some(all) = workspace.strings.ready() else {
        status(ui, workspace.strings.error().unwrap_or("Scanning strings..."));
        return;
    };
    let shown = workspace.string_filter.shown(all.len(), |index, needle| matches(&all[index].text, needle));
    let chosen = table(ui, &[], 2, 1, shown.len(), |index| {
        let string = &all[shown[index]];
        Row {
            cells: vec![address(string.address), mono(&string.text, theme::COMMENT)],
            selected: false,
            target: Some(string.address),
        }
    });
    // Strings are data: going there shows their bytes and who references them.
    if let Some(address) = chosen {
        workspace.goto(address);
    }
}

fn imports(ui: &mut Ui, workspace: &mut Workspace) {
    filter_box(ui, &mut workspace.import_filter, "Filter imports");
    let all = &workspace.imports;
    let shown = workspace.import_filter.shown(all.len(), |index, needle| {
        let import = &all[index];
        matches(&import.name, needle) || import.library.as_deref().is_some_and(|library| matches(library, needle))
    });
    let chosen = table(ui, &[], 2, 0, shown.len(), |index| {
        let import = &all[shown[index]];
        Row {
            cells: vec![
                RichText::new(&import.name).monospace(),
                RichText::new(import.library.as_deref().unwrap_or("")).color(theme::DIM),
            ],
            selected: false,
            target: import.slot,
        }
    });
    if let Some(slot) = chosen {
        workspace.goto(slot);
    }
}

fn exports(ui: &mut Ui, workspace: &mut Workspace) {
    filter_box(ui, &mut workspace.export_filter, "Filter exports");
    let all = &workspace.exports;
    let shown = workspace.export_filter.shown(all.len(), |index, needle| matches(&all[index].name, needle));
    let chosen = table(ui, &[], 2, 0, shown.len(), |index| {
        let export = &all[shown[index]];
        Row {
            cells: vec![RichText::new(&export.name).monospace(), address(export.address)],
            selected: false,
            target: Some(export.address),
        }
    });
    if let Some(address) = chosen {
        workspace.goto(address);
    }
}

fn xrefs(ui: &mut Ui, workspace: &mut Workspace) {
    let Some(panel) = &workspace.xrefs else {
        status(ui, "Analyzing...");
        return;
    };
    ui.label(RichText::new(format!("References to {}", panel.target)).color(theme::DIM));
    let rows = match &panel.rows {
        Ok(rows) if rows.is_empty() => return status(ui, "No references"),
        Ok(rows) => rows,
        Err(error) => {
            ui.colored_label(theme::WARNING, error);
            return;
        }
    };
    let chosen = table(ui, &[], 3, 2, rows.len(), |index| {
        let xref = &rows[index];
        Row {
            cells: vec![
                mono(xref.kind.as_str(), theme::BRANCH),
                address(xref.from),
                RichText::new(xref.from_function.as_deref().unwrap_or("?")).monospace(),
            ],
            selected: false,
            target: Some(xref.from),
        }
    });
    if let Some(address) = chosen {
        workspace.goto(address);
    }
}

/// The triage panel's facts about the format, as (label, value) pairs.
fn facts(details: &Details) -> Vec<(&'static str, String)> {
    let mut facts = Vec::new();
    let mut fact = |label, value: String| {
        if !value.is_empty() {
            facts.push((label, value));
        }
    };
    match details {
        Details::Pe(pe) => {
            fact("Built", format!("{} UTC", pe.timestamp_utc));
            fact("Subsystem", pe.subsystem.to_owned());
            fact("Linker", pe.linker_version.clone());
            fact("Mitigations", pe.characteristics.join(", "));
            fact("Signed", yes_no(pe.signed).to_owned());
            if pe.dotnet {
                fact(".NET", "yes: the code is IL".to_owned());
            }
            if !pe.rich.is_empty() {
                fact("Rich header", format!("{} tool entries", pe.rich.len()));
            }
        }
        Details::Elf(elf) => {
            fact("Kind", format!("{}{}", elf.kind, if elf.pie { " (PIE)" } else { "" }));
            fact("Interpreter", elf.interpreter.clone().unwrap_or_default());
            fact("Needed", elf.needed.join(", "));
            fact("Hardening", format!("NX {}, RELRO {}", yes_no(elf.nx), elf.relro));
            fact("Build ID", elf.build_id.clone().unwrap_or_default());
            fact("Stripped", yes_no(elf.stripped).to_owned());
        }
        Details::MachO(macho) => {
            fact("Type", macho.file_type.to_owned());
            if let (Some(platform), Some(min_os)) = (&macho.platform, &macho.min_os) {
                fact("Platform", format!("{platform} {min_os}"));
            }
            fact("Libraries", macho.dylibs.join(", "));
            fact("Flags", macho.flags.join(", "));
            fact("UUID", macho.uuid.clone().unwrap_or_default());
            fact("Signed", yes_no(macho.code_signature).to_owned());
            if macho.encrypted {
                fact("Encrypted", "yes".to_owned());
            }
        }
        Details::None => {}
    }
    facts
}

fn triage(ui: &mut Ui, workspace: &mut Workspace) {
    let Some(triage) = workspace.triage.ready() else {
        status(ui, workspace.triage.error().unwrap_or("Hashing..."));
        return;
    };
    let overlay = workspace.project.binary.overlay;
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        egui::Grid::new("triage-facts").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
            let mut field = |name: &str, value: &str| {
                ui.label(RichText::new(name).color(theme::DIM));
                ui.add(egui::Label::new(RichText::new(value).monospace()).wrap());
                ui.end_row();
            };
            field("Size", &format!("{} bytes", triage.image_size));
            field("SHA-256", &triage.image_hashes.sha256);
            field("SHA-1", &triage.image_hashes.sha1);
            field("MD5", &triage.image_hashes.md5);
            if let Some(imphash) = &triage.imphash {
                field("Imphash", imphash);
            }
            for (label, value) in facts(&triage.details) {
                field(label, &value);
            }
            if let Some(overlay) = overlay {
                field("Overlay", &format!("{} bytes at file offset {:#x}", overlay.size, overlay.file_offset));
            }
        });
        ui.add_space(10.0);
        ui.label(RichText::new(format!("Entropy {:.2} bits per byte", triage.entropy)).color(theme::DIM));
        entropy_chart(ui, &triage.entropy_profile);
        ui.add_space(10.0);
        if !triage.hints.is_empty() {
            ui.label(RichText::new("Hints").color(theme::DIM));
            for hint in &triage.hints {
                ui.label(RichText::new(format!("•  {hint}")).color(theme::WARNING));
            }
            ui.add_space(10.0);
        }
        ui.label(RichText::new("Sections").color(theme::DIM));
        egui::Grid::new("triage-sections").num_columns(4).striped(true).spacing([16.0, 2.0]).show(ui, |ui| {
            for section in &triage.sections {
                ui.label(RichText::new(&section.name).monospace());
                ui.label(address(section.address));
                ui.label(mono(&section.perms, theme::DIM));
                let color = if section.entropy > 7.2 { theme::WARNING } else { theme::TEXT };
                ui.label(mono(format!("{:.2}", section.entropy), color));
                ui.end_row();
            }
        });
    });
}

/// Bars of entropy across the file, scaled to 8 bits per byte.
fn entropy_chart(ui: &mut Ui, profile: &[f64]) {
    let width = ui.available_width().min(520.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, 56.0), Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 3.0, theme::BACKGROUND);
    let bar = rect.width() / profile.len().max(1) as f32;
    for (index, &bits) in profile.iter().enumerate() {
        let height = rect.height() * (bits as f32 / 8.0);
        let x = rect.left() + index as f32 * bar;
        let color = if bits > 7.2 { theme::WARNING } else { theme::BAND_FUNCTION };
        painter.rect_filled(
            egui::Rect::from_min_max(
                egui::pos2(x + 0.5, rect.bottom() - height),
                egui::pos2(x + bar - 0.5, rect.bottom()),
            ),
            0.0,
            color,
        );
    }
}
