//! The Carve window: executables and containers embedded in the opened file, with a way to open one as a project of
//! its own, or to open an image at an offset typed by hand.

use std::path::PathBuf;

use egui::{RichText, TextEdit, Ui};
use rampage_loaders::ImageAt;
use rampage_loaders::carve::{Candidate, Carving, Confidence, Kind};

use crate::theme;
use crate::workspace::Job;

/// A carving of the file last opened, and the window's state.
pub struct Carve {
    pub path: PathBuf,
    pub job: Job<Carving>,
    pub shown: bool,
    pub offset_text: String,
    pub length_text: String,
    pub error: Option<String>,
}

impl Carve {
    /// Starts carving `path`, which may name a bundle: the executable it resolves to is carved.
    pub fn start(path: PathBuf, ctx: &egui::Context, blocking: bool) -> Self {
        let mut job = Job::Idle;
        let target = path.clone();
        job.start(blocking, ctx, move || {
            let executable =
                rampage_loaders::container::resolve_executable(&target).map_err(|error| error.to_string())?;
            rampage_api::carve(&executable, None).map_err(|error| error.to_string())
        });
        Self { path, job, shown: false, offset_text: String::new(), length_text: String::new(), error: None }
    }

    /// Candidates other than the image at `current` (the whole file at 0), worth offering to open.
    pub fn others(&self, current: u64) -> usize {
        self.job.ready().map_or(0, |carving| carving.candidates.iter().filter(|c| c.offset != current).count())
    }

    /// The image the hand-typed offset and optional length name.
    fn typed_image(&self) -> Result<ImageAt, String> {
        let offset = rampage_api::parse_file_offset(self.offset_text.trim())
            .map_err(|error| format!("offset {:?}: {error}", self.offset_text.trim()))?;
        let length = self.length_text.trim();
        let length = (!length.is_empty())
            .then(|| rampage_api::parse_file_offset(length).map_err(|error| format!("length {length:?}: {error}")))
            .transpose()?;
        if length == Some(0) {
            return Err("length must not be zero".to_owned());
        }
        Ok(ImageAt::new(offset, length))
    }
}

/// Whether a candidate is an executable whose header checked out, so that it can be opened.
pub fn openable(candidate: &Candidate) -> bool {
    candidate.confidence == Confidence::Validated
        && matches!(candidate.kind, Kind::Elf | Kind::Pe | Kind::MachO | Kind::MachOFat)
}

/// Shows the window; returns the image to open, if one was chosen. `current` is the offset of the open image.
pub fn show(ctx: &egui::Context, carve: &mut Carve, current: Option<u64>) -> Option<ImageAt> {
    let mut chosen = None;
    let mut shown = carve.shown;
    egui::Window::new("Carve")
        .open(&mut shown)
        .collapsible(false)
        .default_size(egui::vec2(720.0, 420.0))
        .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 80.0))
        .show(ctx, |ui| chosen = contents(ui, carve, current));
    carve.shown = shown && chosen.is_none();
    chosen
}

fn contents(ui: &mut Ui, carve: &mut Carve, current: Option<u64>) -> Option<ImageAt> {
    let mut chosen = None;
    let name = carve.path.file_name().map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    ui.label(RichText::new(format!("Executables and containers embedded in {name}")).strong());
    ui.label(
        RichText::new("Found by magic and checked against their headers; nothing is extracted or decompressed.")
            .color(theme::DIM)
            .small(),
    );
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label("Offset");
        ui.add(
            TextEdit::singleline(&mut carve.offset_text)
                .hint_text("0x...")
                .desired_width(120.0)
                .font(egui::TextStyle::Monospace),
        );
        ui.label("Length");
        let hint = "from headers";
        ui.add(
            TextEdit::singleline(&mut carve.length_text)
                .hint_text(hint)
                .desired_width(120.0)
                .font(egui::TextStyle::Monospace),
        );
        if ui.button("Open at offset").clicked() {
            match carve.typed_image() {
                Ok(image) => chosen = Some(image),
                Err(error) => carve.error = Some(error),
            }
        }
    });
    if let Some(error) = &carve.error {
        ui.label(RichText::new(error).color(theme::WARNING));
    }
    ui.separator();
    if carve.job.is_running() {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(RichText::new("Carving").color(theme::DIM));
        });
    }
    if let Some(error) = carve.job.error() {
        ui.label(RichText::new(error).color(theme::WARNING));
    }
    let Some(carving) = carve.job.ready() else { return chosen };
    for limitation in &carving.limitations {
        ui.label(RichText::new(limitation).color(theme::DIM).small());
    }
    if carving.candidates.is_empty() {
        ui.label(RichText::new("No embedded executables or containers were found.").color(theme::DIM));
        return chosen;
    }
    // With nothing open, no candidate is the open image.
    let current = current.unwrap_or(u64::MAX);
    egui::ScrollArea::vertical().auto_shrink([false, true]).show(ui, |ui| {
        egui::Grid::new("carve-candidates").num_columns(6).striped(true).spacing([16.0, 4.0]).show(ui, |ui| {
            for heading in ["Offset", "Kind", "Header", "Architecture", "Extent", ""] {
                ui.label(RichText::new(heading).color(theme::DIM));
            }
            ui.end_row();
            for candidate in &carving.candidates {
                let offset = ui.label(RichText::new(format!("{:#x}", candidate.offset)).monospace());
                if !candidate.notes.is_empty() {
                    offset.on_hover_text(candidate.notes.join("\n"));
                }
                ui.label(candidate.kind.to_string());
                ui.label(RichText::new(candidate.confidence.to_string()).color(theme::DIM));
                let arch = match (&candidate.arch, candidate.bits) {
                    (Some(arch), Some(bits)) => format!("{arch} ({bits}-bit)"),
                    (Some(arch), None) => arch.clone(),
                    _ => String::new(),
                };
                ui.label(arch);
                ui.label(
                    RichText::new(candidate.extent.map_or(String::new(), |extent| format!("{extent:#x}"))).monospace(),
                );
                if candidate.offset == current {
                    ui.label(RichText::new("open").color(theme::DIM));
                } else if openable(candidate) {
                    if ui.button("Open").clicked() {
                        chosen = Some(ImageAt::new(candidate.offset, None));
                    }
                } else {
                    ui.label("");
                }
                ui.end_row();
            }
        });
    });
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(offset: &str, length: &str) -> Result<ImageAt, String> {
        let carve = Carve {
            path: PathBuf::new(),
            job: Job::Idle,
            shown: true,
            offset_text: offset.to_owned(),
            length_text: length.to_owned(),
            error: None,
        };
        carve.typed_image()
    }

    #[test]
    fn typed_offsets_and_lengths_parse_or_explain() {
        assert_eq!(typed(" 0x1000 ", ""), Ok(ImageAt::new(0x1000, None)));
        assert_eq!(typed("4096", "0x200"), Ok(ImageAt::new(0x1000, Some(0x200))));
        assert!(typed("", "").unwrap_err().starts_with("offset"));
        assert!(typed("0xzz", "").unwrap_err().starts_with("offset \"0xzz\""));
        assert!(typed("0x10", "ten").unwrap_err().starts_with("length \"ten\""));
        assert_eq!(typed("0x10", "0"), Err("length must not be zero".to_owned()));
    }
}
