//! The About window: version, licence, and the notices for everything the binary bundles.

use std::sync::OnceLock;

use egui::{RichText, ScrollArea, Ui};

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

pub fn show(ctx: &egui::Context, open: &mut bool) {
    egui::Window::new("About rampage")
        .open(open)
        .collapsible(false)
        .default_size(egui::vec2(760.0, 640.0))
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .show(ctx, contents);
}

fn contents(ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("rampage").size(22.0).color(theme::LINK));
        ui.label(RichText::new(env!("CARGO_PKG_VERSION")).color(theme::DIM).monospace());
    });
    ui.label("Licensed under the Apache License, Version 2.0.");
    ui.add_space(6.0);
    ScrollArea::vertical().id_salt("about").max_height(260.0).show(ui, |ui| {
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
