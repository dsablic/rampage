//! The About window: version, licence, the data packs in use, and the notices for everything the binary bundles.

use std::sync::OnceLock;

use egui::{RichText, ScrollArea, Ui};
use rampage_api::{ContentStatus, PackInfo, Packs};

use crate::theme;

const NOTICE: &str = include_str!("../../../NOTICE");
const THIRD_PARTY_NOTICES: &str = include_str!("../../../THIRD-PARTY-NOTICES");

/// A font egui renders with, from the `epaint_default_fonts` crate.
pub struct Font {
    pub name: &'static str,
    pub licence: &'static str,
    pub text: &'static str,
}

/// The licence files are verbatim copies of those shipped beside the fonts in `epaint_default_fonts`.
pub const FONTS: [Font; 4] = [
    Font { name: "Ubuntu Light", licence: "Ubuntu Font Licence 1.0", text: include_str!("../licenses/fonts/UFL.txt") },
    Font {
        name: "Hack Regular",
        licence: "MIT License; Bitstream Vera License",
        text: include_str!("../licenses/fonts/Hack-Regular.txt"),
    },
    Font {
        name: "Noto Emoji Regular",
        licence: "SIL Open Font License 1.1",
        text: include_str!("../licenses/fonts/OFL.txt"),
    },
    Font {
        name: "emoji-icon-font",
        licence: "MIT License",
        text: include_str!("../licenses/fonts/emoji-icon-font-mit-license.txt"),
    },
];

/// The notices split into lines once, so the scroll area lays out only the visible rows of a ~1 MB text.
fn third_party_lines() -> &'static [&'static str] {
    static LINES: OnceLock<Vec<&'static str>> = OnceLock::new();
    LINES.get_or_init(|| THIRD_PARTY_NOTICES.lines().collect())
}

pub fn show(ctx: &egui::Context, open: &mut bool, packs: &Packs) {
    egui::Window::new("About rampage")
        .open(open)
        .collapsible(false)
        .default_size(egui::vec2(760.0, 640.0))
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .show(ctx, |ui| contents(ui, packs));
}

fn contents(ui: &mut Ui, packs: &Packs) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("rampage").size(22.0).color(theme::LINK));
        ui.label(RichText::new(env!("CARGO_PKG_VERSION")).color(theme::DIM).monospace());
    });
    ui.label("Licensed under the Apache License, Version 2.0.");
    ui.add_space(6.0);
    ScrollArea::vertical().id_salt("about").max_height(260.0).show(ui, |ui| {
        // Listed only when packs were given (--pack, RAMPAGE_PACKS), so the built-in databases need no mention.
        if packs.configured() {
            ui.label(RichText::new("Data packs, in precedence order").strong());
            for pack in packs.listing() {
                pack_info(ui, &pack);
            }
            ui.add_space(6.0);
        }
        ui.label(RichText::new("Bundled fonts").strong());
        for font in &FONTS {
            egui::CollapsingHeader::new(format!("{} ({})", font.name, font.licence)).show(ui, |ui| {
                ui.label(RichText::new(font.text).monospace());
            });
        }
        egui::CollapsingHeader::new("NOTICE").default_open(true).show(ui, |ui| {
            ui.label(RichText::new(NOTICE).monospace());
        });
    });
    ui.add_space(6.0);
    ui.label(RichText::new("Third-party notices").strong());
    let lines = third_party_lines();
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
    ScrollArea::both().id_salt("third-party").auto_shrink([false, false]).show_rows(
        ui,
        row_height,
        lines.len(),
        |ui, rows| {
            for line in &lines[rows] {
                ui.add(egui::Label::new(RichText::new(*line).monospace()).extend());
            }
        },
    );
}

fn pack_info(ui: &mut Ui, pack: &PackInfo) {
    let directory = pack.directory.as_ref().map(|directory| directory.display().to_string());
    let title = match (&pack.manifest, &directory) {
        (Some(manifest), _) => format!("{} {} ({})", manifest.name, manifest.version, manifest.license),
        (None, Some(directory)) => directory.clone(),
        (None, None) => "pack".to_owned(),
    };
    let failed = pack.error.is_some() || pack.contents.iter().any(|content| content.status != ContentStatus::Loaded);
    let heading = if failed { RichText::new(title).color(theme::WARNING) } else { RichText::new(title) };
    egui::CollapsingHeader::new(heading).id_salt(&directory).default_open(failed).show(ui, |ui| {
        if let Some(directory) = &directory {
            ui.label(RichText::new(directory).color(theme::DIM).monospace());
        }
        if let Some(manifest) = &pack.manifest {
            ui.label(RichText::new(format!("source: {}", manifest.source)).color(theme::DIM));
        }
        if let Some(error) = &pack.error {
            ui.label(RichText::new(format!("not loaded: {error}")).color(theme::WARNING));
        }
        for content in &pack.contents {
            let status = match content.status {
                ContentStatus::Loaded => "loaded",
                ContentStatus::Error => "error",
                ContentStatus::Unsupported => "unsupported",
            };
            let line = format!("{} {} ({status}): {}", content.kind, content.path, content.detail);
            let colour = if content.status == ContentStatus::Loaded { theme::DIM } else { theme::WARNING };
            ui.label(RichText::new(line).color(colour));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_texts_are_present() {
        assert!(NOTICE.contains("Apache License, Version 2.0"));
        assert!(THIRD_PARTY_NOTICES.contains("epaint_default_fonts"));
        assert!(FONTS[0].text.contains("UBUNTU FONT LICENCE Version 1.0"));
        assert!(FONTS[2].text.contains("SIL OPEN FONT LICENSE Version 1.1"));
        assert!(third_party_lines().len() > 1000);
    }
}
