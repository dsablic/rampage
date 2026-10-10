//! The disassembly listing: one function at a time, block by block, with clickable references.

use egui::{Color32, Label, RichText, ScrollArea, Sense, Ui};
use rampage_api::{DisassemblyLine, FunctionListing};
use rampage_arch::Flow;

use crate::theme;
use crate::workspace::Workspace;

enum Action {
    None,
    /// Move the cursor within the listing.
    Select(u64),
    /// Follow a reference, remembering where we came from.
    Follow(u64),
}

/// A function's disassembly and the rows that display it.
pub struct Listing {
    pub function: FunctionListing,
    rows: Vec<Row>,
}

enum Row {
    /// The function's name, or a block's label.
    Label(String),
    /// The line at this index of this block.
    Line(usize, usize),
    /// Space between basic blocks.
    Gap,
}

impl Listing {
    pub fn new(function: FunctionListing) -> Self {
        let mut rows = Vec::new();
        for (block_index, block) in function.blocks.iter().enumerate() {
            if block_index > 0 {
                rows.push(Row::Gap);
            }
            for (line_index, line) in block.iter().enumerate() {
                if let Some(label) = &line.label {
                    rows.push(Row::Label(format!("{label}:")));
                } else if line.address == function.address && !function.name.is_empty() {
                    rows.push(Row::Label(format!("{}:", function.name)));
                }
                rows.push(Row::Line(block_index, line_index));
            }
        }
        Self { function, rows }
    }

    pub fn contains(&self, address: u64) -> bool {
        self.function.blocks.iter().flatten().any(|line| line.address == address)
    }

    fn line(&self, row: &Row) -> Option<&DisassemblyLine> {
        match *row {
            Row::Line(block, line) => Some(&self.function.blocks[block][line]),
            _ => None,
        }
    }
}

/// Splits instruction text into tokens: words, numbers and the punctuation between them.
fn tokens(text: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut start = 0;
    for (index, c) in text.char_indices() {
        let sign = c == '-' && (index == start || text[..index].ends_with('#'));
        let word = c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '#' || sign;
        if !word {
            if start < index {
                tokens.push(&text[start..index]);
            }
            tokens.push(&text[index..index + c.len_utf8()]);
            start = index + c.len_utf8();
        }
    }
    if start < text.len() {
        tokens.push(&text[start..]);
    }
    tokens
}

fn is_register(token: &str) -> bool {
    let token = token.to_ascii_lowercase();
    const NAMED: [&str; 40] = [
        "sp", "xzr", "wzr", "lr", "fp", "pc", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "eax",
        "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "ax", "bx", "cx", "dx", "al", "bl", "cl", "dl", "ah",
        "bh", "ch", "dh", "si", "di", "bp", "wsp",
    ];
    if NAMED.contains(&token.as_str()) {
        return true;
    }
    // r8..r15 with size suffixes, x0..x30, w0..w30, v/q/d/s/h/b/z/p registers, xmm/ymm/zmm.
    let digits = |rest: &str| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    for prefix in ["xmm", "ymm", "zmm", "r", "x", "w", "v", "q", "d", "s", "h", "b", "z", "p"] {
        if let Some(rest) = token.strip_prefix(prefix) {
            let rest = rest.trim_end_matches(['d', 'w', 'b']);
            if digits(rest.split('.').next().unwrap_or("")) {
                return true;
            }
        }
    }
    false
}

/// A token naming a mapped address the user can follow.
fn address_token(workspace: &Workspace, token: &str) -> Option<u64> {
    let hex = token.trim_start_matches('#').strip_prefix("0x")?;
    let address = u64::from_str_radix(hex, 16).ok()?;
    workspace.project.binary.segment_containing(address).is_some().then_some(address)
}

fn line_ui(ui: &mut Ui, workspace: &Workspace, line: &DisassemblyLine, action: &mut Action) {
    let is_cursor = line.address == workspace.cursor;
    let row = ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.label(
            RichText::new(format!("{:0width$x}  ", line.address, width = workspace.address_width))
                .color(theme::ADDRESS)
                .monospace(),
        );
        ui.label(RichText::new(format!("{:<18}", truncate(&line.bytes, 16))).color(theme::FAINT).monospace());
        let branch = !matches!(line.flow, Flow::Next | Flow::Invalid);
        let (mnemonic, operands) = line.text.split_once(' ').unwrap_or((&line.text, ""));
        let color = if branch { theme::BRANCH } else { theme::MNEMONIC };
        ui.label(RichText::new(format!("{mnemonic:<7} ")).color(color).monospace());
        for token in tokens(operands) {
            if let Some(address) = address_token(workspace, token) {
                let label = ui.add(
                    Label::new(RichText::new(token).color(theme::LINK).monospace().underline()).sense(Sense::click()),
                );
                if label.clicked() {
                    *action = Action::Follow(address);
                }
                if let Some(name) = workspace.project.name_at(address) {
                    label.on_hover_text(name);
                }
            } else {
                let color = if is_register(token) {
                    theme::REGISTER
                } else if token.starts_with('#') || token.starts_with(|c: char| c.is_ascii_digit()) {
                    theme::NUMBER
                } else {
                    theme::TEXT
                };
                ui.label(RichText::new(token).color(color).monospace());
            }
        }
        if let Some(note) = &line.note {
            ui.label(RichText::new(format!("    ; {note}")).color(theme::NOTE).monospace());
        }
        if let Some(comment) = &line.comment {
            ui.label(RichText::new(format!("    ; {comment}")).color(theme::COMMENT).monospace());
        }
    });
    let response = row.response.interact(Sense::click());
    if is_cursor {
        ui.painter().rect_filled(response.rect.expand2(egui::vec2(4.0, 1.0)), 2.0, highlight());
    }
    if response.clicked() && matches!(action, Action::None) {
        *action = Action::Select(line.address);
    }
}

fn highlight() -> Color32 {
    Color32::from_rgba_unmultiplied(0x5a, 0x7a, 0xc0, 0x30)
}

fn truncate(text: &str, width: usize) -> String {
    if text.len() <= width { text.to_owned() } else { format!("{}..", &text[..width - 2]) }
}

pub fn show(ui: &mut Ui, workspace: &mut Workspace) {
    let Some(listing) = &workspace.listing else {
        if workspace.analysis_ready() {
            hex(ui, workspace);
        } else {
            ui.centered_and_justified(|ui| ui.label(RichText::new("Analyzing...").color(theme::DIM)));
        }
        return;
    };
    let listing = match listing {
        Ok(listing) => listing,
        Err(error) => {
            ui.colored_label(theme::WARNING, error);
            return;
        }
    };
    let rows = &listing.rows;
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + ui.spacing().item_spacing.y;
    let mut area = ScrollArea::both().auto_shrink([false, false]).id_salt("listing");
    if workspace.scroll_to_cursor {
        let index = rows.iter().position(|row| listing.line(row).is_some_and(|line| line.address == workspace.cursor));
        if let Some(index) = index {
            // Put the cursor a few lines from the top.
            area = area.vertical_scroll_offset((index.saturating_sub(4)) as f32 * row_height);
        }
        workspace.scroll_to_cursor = false;
    }
    let mut action = Action::None;
    area.show_rows(ui, row_height, rows.len(), |ui, range| {
        for row in &rows[range] {
            match row {
                Row::Label(text) => {
                    ui.label(RichText::new(text).color(theme::LABEL).monospace());
                }
                Row::Line(..) => line_ui(ui, workspace, listing.line(row).expect("a line row"), &mut action),
                Row::Gap => {
                    ui.label(RichText::new(" ").monospace());
                }
            }
        }
    });
    match action {
        Action::None => {}
        Action::Select(address) => workspace.select(address),
        Action::Follow(address) => workspace.goto(address),
    }
}

/// Bytes per hex-view row, and rows shown around the cursor.
const HEX_ROW: u64 = 16;
const HEX_ROWS: u64 = 4096;

/// A hex dump of the data around the cursor, within its segment. Rows count from the segment's start, which need
/// not be aligned.
fn hex(ui: &mut Ui, workspace: &mut Workspace) {
    let binary = &workspace.project.binary;
    let base = binary.segment_containing(workspace.cursor).map_or(workspace.cursor, |segment| segment.address);
    let cursor_row = base + (workspace.cursor - base) / HEX_ROW * HEX_ROW;
    let start = cursor_row.saturating_sub(HEX_ROW * HEX_ROWS / 2).max(base);
    let Some(bytes) = binary.read_to_segment_end(start) else {
        ui.colored_label(theme::WARNING, format!("{:#x} is not backed by file data", workspace.cursor));
        return;
    };
    let bytes = &bytes[..bytes.len().min((HEX_ROW * HEX_ROWS) as usize)];
    let rows = bytes.len().div_ceil(HEX_ROW as usize);
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + ui.spacing().item_spacing.y;
    let mut area = ScrollArea::both().auto_shrink([false, false]).id_salt("hex");
    let cursor_index = ((cursor_row - start) / HEX_ROW) as usize;
    if workspace.scroll_to_cursor {
        area = area.vertical_scroll_offset(cursor_index.saturating_sub(4) as f32 * row_height);
        workspace.scroll_to_cursor = false;
    }
    let width = workspace.address_width;
    let cursor = workspace.cursor;
    area.show_rows(ui, row_height, rows, |ui, range| {
        for index in range {
            let address = start + index as u64 * HEX_ROW;
            let chunk = &bytes[index * HEX_ROW as usize..((index + 1) * HEX_ROW as usize).min(bytes.len())];
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                ui.label(RichText::new(format!("{address:0width$x}  ")).color(theme::ADDRESS).monospace());
                for (offset, &byte) in chunk.iter().enumerate() {
                    let at_cursor = address + offset as u64 == cursor;
                    let color = if at_cursor {
                        theme::LABEL
                    } else if byte == 0 {
                        theme::FAINT
                    } else {
                        theme::TEXT
                    };
                    let gap = if offset == 7 { "  " } else { " " };
                    ui.label(RichText::new(format!("{byte:02x}{gap}")).color(color).monospace());
                }
                let ascii: String =
                    chunk.iter().map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }).collect();
                ui.label(RichText::new(format!(" {ascii}")).color(theme::COMMENT).monospace());
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{is_register, tokens};

    #[test]
    fn splits_operands_into_tokens() {
        assert_eq!(
            tokens("x29, x30, [sp, #-16]!"),
            ["x29", ",", " ", "x30", ",", " ", "[", "sp", ",", " ", "#-16", "]", "!"]
        );
        assert_eq!(tokens("qword ptr [rip+0x1000]"), ["qword", " ", "ptr", " ", "[", "rip", "+", "0x1000", "]"]);
    }

    #[test]
    fn recognizes_registers() {
        for register in ["x0", "w30", "sp", "xzr", "v1.16b", "rax", "r8d", "xmm3", "z0.s", "p1"] {
            assert!(is_register(register), "{register}");
        }
        for word in ["qword", "ptr", "lsl", "#16", "add"] {
            assert!(!is_register(word), "{word}");
        }
    }
}
