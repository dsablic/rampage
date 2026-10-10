//! The dockable panels.

use egui::{RichText, Sense, TextEdit, Ui, WidgetText};
use egui_extras::{Column, TableBuilder};
use rampage_analysis::discover::XrefKind;
use rampage_loaders::Details;

use crate::workspace::Workspace;
use crate::{listing, theme};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Functions,
    Strings,
    Imports,
    Exports,
    Disassembly,
    Xrefs,
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
                Some(Ok(listing)) if !listing.name.is_empty() => format!("Disassembly - {}", listing.name),
                _ => "Disassembly".to_owned(),
            },
            Tab::Xrefs => "Xrefs".to_owned(),
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
            Tab::Xrefs => xrefs(ui, self.workspace),
            Tab::Triage => triage(ui, self.workspace),
        }
    }

    fn is_closeable(&self, _tab: &Tab) -> bool {
        false
    }
}

fn filter_box(ui: &mut Ui, text: &mut String, hint: &str) {
    ui.add(TextEdit::singleline(text).hint_text(hint).desired_width(f32::INFINITY));
    ui.add_space(2.0);
}

/// Case-insensitive (ASCII) substring test that allocates nothing, for filtering hundreds of thousands of rows.
fn matches(haystack: &str, needle: &str) -> bool {
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    needle.is_empty() || haystack.windows(needle.len()).any(|window| window.eq_ignore_ascii_case(needle))
}

/// Indices of the rows matching a filter, recomputed only when the filter or the row count changes.
#[derive(Default)]
pub struct Filtered {
    needle: String,
    rows: usize,
    indices: Vec<usize>,
    valid: bool,
}

impl Filtered {
    pub fn get(&mut self, needle: &str, rows: usize, keep: impl Fn(usize) -> bool) -> &[usize] {
        if !self.valid || self.needle != needle || self.rows != rows {
            self.indices = (0..rows).filter(|&index| keep(index)).collect();
            self.needle = needle.to_owned();
            self.rows = rows;
            self.valid = true;
        }
        &self.indices
    }
}

fn row_height(ui: &Ui) -> f32 {
    ui.text_style_height(&egui::TextStyle::Monospace) + 4.0
}

fn status(ui: &mut Ui, message: &str) {
    ui.centered_and_justified(|ui| ui.label(RichText::new(message).color(theme::DIM)));
}

fn functions(ui: &mut Ui, workspace: &mut Workspace) {
    filter_box(ui, &mut workspace.function_filter, "Filter functions");
    let Some(all) = workspace.functions.ready() else {
        status(ui, workspace.functions.error().unwrap_or("Analyzing..."));
        return;
    };
    let filter = &workspace.function_filter;
    let shown = workspace.function_rows.get(filter, all.len(), |i| matches(&all[i].name, filter));
    let mut chosen = None;
    let current = match &workspace.listing {
        Some(Ok(listing)) => Some(listing.address),
        _ => None,
    };
    let height = row_height(ui);
    TableBuilder::new(ui)
        .striped(true)
        .sense(Sense::click())
        .column(Column::remainder().clip(true))
        .column(Column::auto())
        .column(Column::auto())
        .header(height, |mut header| {
            header.col(|ui| {
                ui.label(RichText::new("Name").color(theme::DIM));
            });
            header.col(|ui| {
                ui.label(RichText::new("Address").color(theme::DIM));
            });
            header.col(|ui| {
                ui.label(RichText::new("Size").color(theme::DIM));
            });
        })
        .body(|body| {
            body.rows(height, shown.len(), |mut row| {
                let function = &all[shown[row.index()]];
                row.set_selected(Some(function.address) == current);
                row.col(|ui| {
                    ui.label(RichText::new(&function.name).monospace());
                });
                row.col(|ui| {
                    ui.label(RichText::new(format!("{:x}", function.address)).color(theme::ADDRESS).monospace());
                });
                row.col(|ui| {
                    ui.label(RichText::new(function.size.to_string()).color(theme::DIM).monospace());
                });
                if row.response().clicked() {
                    chosen = Some(function.address);
                }
            });
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
    let filter = &workspace.string_filter;
    let shown = workspace.string_rows.get(filter, all.len(), |i| matches(&all[i].text, filter));
    let mut chosen = None;
    let height = row_height(ui);
    TableBuilder::new(ui)
        .striped(true)
        .sense(Sense::click())
        .column(Column::auto())
        .column(Column::remainder().clip(true))
        .body(|body| {
            body.rows(height, shown.len(), |mut row| {
                let string = &all[shown[row.index()]];
                row.col(|ui| {
                    ui.label(RichText::new(format!("{:x}", string.address)).color(theme::ADDRESS).monospace());
                });
                row.col(|ui| {
                    ui.label(RichText::new(&string.text).color(theme::COMMENT).monospace());
                });
                if row.response().clicked() {
                    chosen = Some(string.address);
                }
            });
        });
    // Strings are data: show who references them rather than disassembling them.
    if let Some(address) = chosen {
        workspace.goto(address);
    }
}

fn imports(ui: &mut Ui, workspace: &mut Workspace) {
    filter_box(ui, &mut workspace.import_filter, "Filter imports");
    let filter = workspace.import_filter.clone();
    let shown: Vec<usize> = (0..workspace.imports.len())
        .filter(|&i| {
            let import = &workspace.imports[i];
            matches(&import.name, &filter) || import.library.as_deref().is_some_and(|library| matches(library, &filter))
        })
        .collect();
    let mut chosen = None;
    let height = row_height(ui);
    TableBuilder::new(ui)
        .striped(true)
        .sense(Sense::click())
        .column(Column::remainder().clip(true))
        .column(Column::auto().clip(true))
        .body(|body| {
            body.rows(height, shown.len(), |mut row| {
                let import = &workspace.imports[shown[row.index()]];
                row.col(|ui| {
                    ui.label(RichText::new(&import.name).monospace());
                });
                row.col(|ui| {
                    ui.label(RichText::new(import.library.as_deref().unwrap_or("")).color(theme::DIM));
                });
                if row.response().clicked() {
                    chosen = import.slot;
                }
            });
        });
    if let Some(slot) = chosen {
        workspace.goto(slot);
    }
}

fn exports(ui: &mut Ui, workspace: &mut Workspace) {
    let mut chosen = None;
    let exports = &workspace.exports;
    let height = row_height(ui);
    TableBuilder::new(ui)
        .striped(true)
        .sense(Sense::click())
        .column(Column::remainder().clip(true))
        .column(Column::auto())
        .body(|body| {
            body.rows(height, exports.len(), |mut row| {
                let export = &exports[row.index()];
                row.col(|ui| {
                    ui.label(RichText::new(&export.name).monospace());
                });
                row.col(|ui| {
                    ui.label(RichText::new(format!("{:x}", export.address)).color(theme::ADDRESS).monospace());
                });
                if row.response().clicked() {
                    chosen = Some(export.address);
                }
            });
        });
    if let Some(address) = chosen {
        workspace.goto(address);
    }
}

fn xrefs(ui: &mut Ui, workspace: &mut Workspace) {
    let target = match &workspace.listing {
        Some(Ok(listing)) if !listing.name.is_empty() => listing.name.clone(),
        _ => format!("{:#x}", workspace.cursor),
    };
    ui.label(RichText::new(format!("References to {target}")).color(theme::DIM));
    let rows = match &workspace.xrefs {
        Some(Ok(rows)) => rows.clone(),
        Some(Err(error)) => {
            ui.colored_label(theme::WARNING, error);
            return;
        }
        None => {
            status(ui, "Analyzing...");
            return;
        }
    };
    if rows.is_empty() {
        status(ui, "No references");
        return;
    }
    let mut chosen = None;
    let height = row_height(ui);
    TableBuilder::new(ui)
        .striped(true)
        .sense(Sense::click())
        .column(Column::auto())
        .column(Column::auto())
        .column(Column::remainder().clip(true))
        .body(|body| {
            body.rows(height, rows.len(), |mut row| {
                let xref = &rows[row.index()];
                let kind = match xref.kind {
                    XrefKind::Call => "call",
                    XrefKind::Jump => "jump",
                    XrefKind::Data => "data",
                };
                row.col(|ui| {
                    ui.label(RichText::new(kind).color(theme::BRANCH).monospace());
                });
                row.col(|ui| {
                    ui.label(RichText::new(format!("{:x}", xref.from)).color(theme::ADDRESS).monospace());
                });
                row.col(|ui| {
                    ui.label(RichText::new(xref.from_function.as_deref().unwrap_or("?")).monospace());
                });
                if row.response().clicked() {
                    chosen = Some(xref.from);
                }
            });
        });
    if let Some(address) = chosen {
        workspace.goto(address);
    }
}

fn triage(ui: &mut Ui, workspace: &mut Workspace) {
    let Some(triage) = workspace.triage.ready() else {
        status(ui, workspace.triage.error().unwrap_or("Hashing..."));
        return;
    };
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        let field = |ui: &mut Ui, name: &str, value: &str| {
            ui.label(RichText::new(name).color(theme::DIM));
            ui.label(RichText::new(value).monospace());
            ui.end_row();
        };
        egui::Grid::new("triage-hashes").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
            field(ui, "Size", &format!("{} bytes", triage.image_size));
            field(ui, "SHA-256", &triage.image_hashes.sha256);
            field(ui, "SHA-1", &triage.image_hashes.sha1);
            field(ui, "MD5", &triage.image_hashes.md5);
            if let Some(imphash) = &triage.imphash {
                field(ui, "Imphash", imphash);
            }
            match &triage.details {
                Details::Pe(pe) => {
                    field(ui, "Built", &format!("{} UTC", pe.timestamp_utc));
                    field(ui, "Subsystem", &pe.subsystem);
                    field(ui, "Mitigations", &pe.characteristics.join(", "));
                    field(ui, "Signed", if pe.signed { "yes" } else { "no" });
                }
                Details::Elf(elf) => {
                    field(ui, "Kind", &format!("{}{}", elf.kind, if elf.pie { " (PIE)" } else { "" }));
                    if let Some(interpreter) = &elf.interpreter {
                        field(ui, "Interpreter", interpreter);
                    }
                    field(ui, "Needed", &elf.needed.join(", "));
                    field(ui, "Hardening", &format!("NX {}, RELRO {}", if elf.nx { "yes" } else { "no" }, elf.relro));
                }
                Details::MachO(macho) => {
                    field(ui, "Type", &macho.file_type);
                    if let (Some(platform), Some(min_os)) = (&macho.platform, &macho.min_os) {
                        field(ui, "Platform", &format!("{platform} {min_os}"));
                    }
                    field(ui, "Flags", &macho.flags.join(", "));
                    field(ui, "Signed", if macho.code_signature { "yes" } else { "no" });
                }
                Details::None => {}
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
                ui.label(RichText::new(format!("{:x}", section.address)).color(theme::ADDRESS).monospace());
                ui.label(RichText::new(&section.perms).color(theme::DIM).monospace());
                let color = if section.entropy > 7.2 { theme::WARNING } else { theme::TEXT };
                ui.label(RichText::new(format!("{:.2}", section.entropy)).color(color).monospace());
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
