//! The navigation band: the image's mapped segments laid end to end, colored by what each pixel covers
//! (functions, other code, data), with the cursor marked. Clicking jumps there.

use egui::{Color32, Rect, Sense, Ui, pos2, vec2};

use crate::theme;
use crate::workspace::Workspace;

/// Mapped segments with their place along the band.
struct Layout {
    /// (address, size, offset along the band) for each segment.
    segments: Vec<(u64, u64, u64)>,
    total: u64,
}

fn layout(workspace: &Workspace) -> Layout {
    let mut segments = Vec::new();
    let mut total = 0u64;
    let binary = &workspace.project.binary;
    let mut mapped: Vec<_> = binary
        .segments
        .iter()
        .filter(|segment| segment.size > 0 && (segment.perms.read || segment.perms.execute))
        .collect();
    mapped.sort_by_key(|segment| segment.address);
    for segment in mapped {
        segments.push((segment.address, segment.size, total));
        total = total.saturating_add(segment.size);
    }
    Layout { segments, total }
}

impl Layout {
    fn address_at(&self, fraction: f64) -> Option<u64> {
        let offset = (fraction.clamp(0.0, 1.0) * self.total as f64) as u64;
        let &(address, size, start) = self.segments.iter().rev().find(|&&(_, _, start)| start <= offset)?;
        Some(address + (offset - start).min(size.saturating_sub(1)))
    }

    fn fraction_of(&self, address: u64) -> Option<f64> {
        let &(base, size, start) =
            self.segments.iter().find(|&&(base, size, _)| address >= base && address - base < size)?;
        let _ = size;
        Some((start + (address - base)) as f64 / self.total.max(1) as f64)
    }
}

fn color_at(workspace: &Workspace, address: u64) -> Color32 {
    let in_function = workspace.functions.ready().is_some_and(|functions| {
        let index = functions.partition_point(|function| function.address <= address);
        index > 0 && address < functions[index - 1].address + functions[index - 1].size.max(1)
    });
    if in_function {
        theme::BAND_FUNCTION
    } else if workspace.project.binary.is_code(address) {
        theme::BAND_CODE
    } else {
        theme::BAND_DATA
    }
}

pub fn show(ui: &mut Ui, workspace: &mut Workspace) {
    let layout = layout(workspace);
    let rect = ui.available_rect_before_wrap().shrink2(vec2(4.0, 3.0));
    let response = ui.allocate_rect(rect, Sense::click());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 2.0, theme::BACKGROUND);
    if layout.total == 0 {
        return;
    }
    let columns = rect.width().floor().max(1.0) as usize;
    for column in 0..columns {
        let fraction = (column as f64 + 0.5) / columns as f64;
        let Some(address) = layout.address_at(fraction) else { continue };
        let x = rect.left() + column as f32;
        painter.rect_filled(
            Rect::from_min_max(pos2(x, rect.top()), pos2(x + 1.0, rect.bottom())),
            0.0,
            color_at(workspace, address),
        );
    }
    if let Some(fraction) = layout.fraction_of(workspace.cursor) {
        let x = rect.left() + (fraction as f32) * rect.width();
        painter.rect_filled(
            Rect::from_min_max(pos2(x - 1.0, rect.top()), pos2(x + 1.0, rect.bottom())),
            0.0,
            theme::LABEL,
        );
    }
    if response.clicked()
        && let Some(position) = response.interact_pointer_pos()
        && let Some(address) = layout.address_at(((position.x - rect.left()) / rect.width()) as f64)
    {
        workspace.goto(address);
    }
    if let Some(position) = response.hover_pos()
        && let Some(address) = layout.address_at(((position.x - rect.left()) / rect.width()) as f64)
    {
        response.on_hover_text(format!("{address:#x}"));
    }
}
