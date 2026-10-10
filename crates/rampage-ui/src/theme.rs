//! Colors and text styles: a dark theme tuned for long reading sessions in dense listings.

use egui::{Color32, FontFamily, FontId, TextStyle, Visuals};

pub const BACKGROUND: Color32 = Color32::from_rgb(0x1b, 0x1d, 0x23);
pub const PANEL: Color32 = Color32::from_rgb(0x22, 0x25, 0x2c);
pub const ROW_ALT: Color32 = Color32::from_rgb(0x25, 0x28, 0x30);
pub const SELECTION: Color32 = Color32::from_rgb(0x2f, 0x3e, 0x5a);
pub const TEXT: Color32 = Color32::from_rgb(0xd4, 0xd7, 0xdd);
pub const DIM: Color32 = Color32::from_rgb(0x7a, 0x80, 0x8c);
pub const FAINT: Color32 = Color32::from_rgb(0x54, 0x59, 0x63);
pub const ADDRESS: Color32 = Color32::from_rgb(0x8c, 0x95, 0xa5);
pub const MNEMONIC: Color32 = Color32::from_rgb(0x7a, 0xb8, 0xf5);
pub const BRANCH: Color32 = Color32::from_rgb(0xf0, 0x9a, 0x5c);
pub const REGISTER: Color32 = Color32::from_rgb(0xc6, 0xa0, 0xf6);
pub const NUMBER: Color32 = Color32::from_rgb(0xe5, 0xc0, 0x7b);
pub const LINK: Color32 = Color32::from_rgb(0x6c, 0xd0, 0xc4);
pub const COMMENT: Color32 = Color32::from_rgb(0x8f, 0xb5, 0x73);
pub const LABEL: Color32 = Color32::from_rgb(0xf2, 0xd3, 0x7a);
pub const WARNING: Color32 = Color32::from_rgb(0xf0, 0x80, 0x70);
/// Navigation band: code covered by functions, other code, and data.
pub const BAND_FUNCTION: Color32 = Color32::from_rgb(0x3f, 0x8f, 0xe0);
pub const BAND_CODE: Color32 = Color32::from_rgb(0x2a, 0x4c, 0x70);
pub const BAND_DATA: Color32 = Color32::from_rgb(0x5a, 0x5f, 0x69);

pub const MONO_SIZE: f32 = 13.0;

pub fn mono() -> FontId {
    FontId::new(MONO_SIZE, FontFamily::Monospace)
}

pub fn apply(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();
    visuals.panel_fill = PANEL;
    visuals.window_fill = PANEL;
    visuals.extreme_bg_color = BACKGROUND;
    visuals.faint_bg_color = ROW_ALT;
    visuals.override_text_color = Some(TEXT);
    visuals.selection.bg_fill = SELECTION;
    visuals.hyperlink_color = LINK;
    ctx.set_visuals(visuals);
    ctx.all_styles_mut(|style| {
        style.text_styles.insert(TextStyle::Body, FontId::new(13.5, FontFamily::Proportional));
        style.text_styles.insert(TextStyle::Button, FontId::new(13.5, FontFamily::Proportional));
        style.text_styles.insert(TextStyle::Monospace, mono());
        style.text_styles.insert(TextStyle::Small, FontId::new(11.5, FontFamily::Proportional));
        style.spacing.item_spacing = egui::vec2(8.0, 4.0);
    });
}
