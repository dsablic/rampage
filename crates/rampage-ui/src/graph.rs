//! The graph view: a function's basic blocks as boxes of disassembly, laid out in layers from the entry, with
//! branches drawn between them.

use egui::{Align2, Color32, FontId, Pos2, Rect, ScrollArea, Sense, Stroke, Ui, pos2, vec2};
use rampage_api::{EdgeKind, FunctionGraph};
use rampage_arch::Flow;

use crate::theme;
use crate::workspace::Workspace;

const LINE_HEIGHT: f32 = 16.0;
const CHAR_WIDTH: f32 = 7.8;
const PADDING: f32 = 6.0;
const LAYER_GAP: f32 = 48.0;
const BOX_GAP: f32 = 36.0;
const MARGIN: f32 = 48.0;

/// A laid-out graph: each block's rectangle at zoom 1, and the canvas size.
pub struct Layout {
    pub graph: FunctionGraph,
    pub boxes: Vec<Rect>,
    pub size: egui::Vec2,
    /// Edges that go back up the layers (loops), drawn around the side.
    back_edges: Vec<bool>,
    /// Each block's layer.
    layer: Vec<usize>,
}

impl Layout {
    /// The horizontal extent of the boxes in the layers strictly between `from` and `to`.
    fn span_between(&self, from: usize, to: usize) -> Option<(f32, f32)> {
        let boxes = (0..self.boxes.len()).filter(|&block| self.layer[block] > from && self.layer[block] < to);
        boxes
            .map(|block| (self.boxes[block].left(), self.boxes[block].right()))
            .reduce(|a, b| (a.0.min(b.0), a.1.max(b.1)))
    }
}

/// Lays `graph` out in layers: each block one layer below the deepest predecessor reached without looping back,
/// ordered within its layer by its predecessors' positions.
pub fn layout(graph: FunctionGraph) -> Layout {
    let count = graph.blocks.len();
    let entry = graph.entry().unwrap_or(0);
    // Depth-first search from the entry finds the edges that close loops.
    let mut back_edges = vec![false; graph.edges.len()];
    let mut state = vec![0u8; count]; // 0 unseen, 1 on the stack, 2 done
    let successors = |block: usize| {
        graph.edges.iter().enumerate().filter(move |(_, edge)| edge.from == block).map(|(index, edge)| (index, edge.to))
    };
    let mut stack = vec![(entry, false)];
    while let Some((block, leaving)) = stack.pop() {
        if leaving {
            state[block] = 2;
            continue;
        }
        if state[block] != 0 {
            continue;
        }
        state[block] = 1;
        stack.push((block, true));
        for (index, to) in successors(block) {
            match state[to] {
                0 => stack.push((to, false)),
                1 => back_edges[index] = true,
                _ => {}
            }
        }
    }
    // Longest path over the forward edges, in a topological order (repeated relaxation suffices here).
    let mut layer = vec![0usize; count];
    for _ in 0..count {
        let mut changed = false;
        for (index, edge) in graph.edges.iter().enumerate() {
            if !back_edges[index] && edge.from != edge.to && layer[edge.to] < layer[edge.from] + 1 {
                layer[edge.to] = layer[edge.from] + 1;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let layers = layer.iter().copied().max().unwrap_or(0) + 1;
    let mut rows: Vec<Vec<usize>> = vec![Vec::new(); layers];
    for block in 0..count {
        rows[layer[block]].push(block);
    }

    let size_of = |block: usize| {
        let lines = &graph.blocks[block].lines;
        let widest = lines.iter().map(|line| line.text.len() + 10).max().unwrap_or(10);
        vec2(widest as f32 * CHAR_WIDTH + 2.0 * PADDING, lines.len() as f32 * LINE_HEIGHT + 2.0 * PADDING)
    };
    let sizes: Vec<egui::Vec2> = (0..count).map(size_of).collect();
    let mut boxes = vec![Rect::NOTHING; count];
    let mut y = MARGIN;
    let mut width = 0.0f32;
    let mut centers = vec![0.0f32; count];
    for row in &mut rows {
        // Order by the average center of each block's placed predecessors.
        let key = |block: usize| {
            let parents: Vec<f32> = graph
                .edges
                .iter()
                .filter(|edge| edge.to == block && layer[edge.from] < layer[block])
                .map(|edge| centers[edge.from])
                .collect();
            if parents.is_empty() { block as f32 * 1e-3 } else { parents.iter().sum::<f32>() / parents.len() as f32 }
        };
        row.sort_by(|&a, &b| key(a).total_cmp(&key(b)));
        let row_width: f32 =
            row.iter().map(|&block| sizes[block].x).sum::<f32>() + BOX_GAP * row.len().saturating_sub(1) as f32;
        let height = row.iter().map(|&block| sizes[block].y).fold(0.0, f32::max);
        let mut x = MARGIN;
        for &block in row.iter() {
            boxes[block] = Rect::from_min_size(pos2(x, y), sizes[block]);
            centers[block] = x + sizes[block].x / 2.0;
            x += sizes[block].x + BOX_GAP;
        }
        width = width.max(row_width);
        y += height + LAYER_GAP;
    }
    // Center each layer on the widest one.
    for row in &rows {
        let row_width =
            row.iter().map(|&block| boxes[block].width()).sum::<f32>() + BOX_GAP * row.len().saturating_sub(1) as f32;
        let shift = (width - row_width) / 2.0;
        for &block in row {
            boxes[block] = boxes[block].translate(vec2(shift, 0.0));
        }
    }
    let size = vec2(width + 2.0 * MARGIN + 40.0, y + MARGIN);
    Layout { graph, boxes, size, back_edges, layer }
}

fn edge_color(kind: EdgeKind) -> Color32 {
    match kind {
        EdgeKind::Taken => Color32::from_rgb(0x6c, 0xc0, 0x6c),
        EdgeKind::NotTaken => Color32::from_rgb(0xe0, 0x70, 0x70),
        EdgeKind::Unconditional => Color32::from_rgb(0x6c, 0x9c, 0xe0),
    }
}

/// An arrowhead pointing down at `tip`.
fn arrowhead(painter: &egui::Painter, tip: Pos2, color: Color32, scale: f32) {
    let size = 5.0 * scale;
    painter.add(egui::Shape::convex_polygon(
        vec![tip, pos2(tip.x - size, tip.y - size * 1.4), pos2(tip.x + size, tip.y - size * 1.4)],
        color,
        Stroke::NONE,
    ));
}

pub fn show(ui: &mut Ui, workspace: &mut Workspace) {
    workspace.want_graph();
    let Some((_, layout)) = &workspace.graph else {
        ui.centered_and_justified(|ui| ui.label(egui::RichText::new("Analyzing...").color(theme::DIM)));
        return;
    };
    let layout = match layout {
        Ok(layout) => layout,
        Err(error) => {
            ui.colored_label(theme::WARNING, error);
            return;
        }
    };
    // Ctrl or Cmd with the scroll wheel zooms.
    let zoom_delta = ui.input(|input| input.zoom_delta());
    if zoom_delta != 1.0 {
        workspace.graph_zoom = (workspace.graph_zoom * zoom_delta).clamp(0.2, 2.5);
    }
    let zoom = workspace.graph_zoom;
    let cursor = workspace.cursor;
    let mut clicked = None;
    let mut followed = None;
    ScrollArea::both().auto_shrink([false, false]).id_salt("graph").show(ui, |ui| {
        let (canvas, response) = ui.allocate_exact_size(layout.size * zoom, Sense::click());
        let painter = ui.painter_at(canvas);
        let origin = canvas.min.to_vec2();
        let place =
            |rect: Rect| Rect::from_min_size(pos2(rect.min.x * zoom, rect.min.y * zoom) + origin, rect.size() * zoom);

        for (index, edge) in layout.graph.edges.iter().enumerate() {
            let (from, to) = (place(layout.boxes[edge.from]), place(layout.boxes[edge.to]));
            let color = edge_color(edge.kind);
            let stroke = Stroke::new(1.5 * zoom.max(0.6), color);
            let start = pos2(from.center().x, from.bottom());
            let end = pos2(to.center().x, to.top());
            let points = if layout.back_edges[index] || edge.from == edge.to {
                // Loops run out to the right of both boxes and back in from above.
                let side = from.right().max(to.right()) + 16.0 * zoom;
                vec![
                    start,
                    pos2(start.x, start.y + 10.0 * zoom),
                    pos2(side, start.y + 10.0 * zoom),
                    pos2(side, end.y - 10.0 * zoom),
                    pos2(end.x, end.y - 10.0 * zoom),
                    end,
                ]
            } else if let Some((left, right)) = layout.span_between(layout.layer[edge.from], layout.layer[edge.to]) {
                // Edges that skip layers run down a channel beside the boxes in between, on the nearer side.
                let (left, right) = (left * zoom + origin.x, right * zoom + origin.x);
                let lane = 6.0 * zoom * (index % 4) as f32;
                let channel = if start.x - left < right - start.x {
                    left - 14.0 * zoom - lane
                } else {
                    right + 14.0 * zoom + lane
                };
                let (down, up) = (start.y + 10.0 * zoom, end.y - 10.0 * zoom);
                vec![start, pos2(start.x, down), pos2(channel, down), pos2(channel, up), pos2(end.x, up), end]
            } else {
                let middle = (start.y + end.y) / 2.0;
                vec![start, pos2(start.x, middle), pos2(end.x, middle), end]
            };
            painter.add(egui::Shape::line(points, stroke));
            arrowhead(&painter, end, color, zoom.max(0.6));
        }

        let font = FontId::monospace(12.0 * zoom);
        for (index, block) in layout.graph.blocks.iter().enumerate() {
            let rect = place(layout.boxes[index]);
            let is_entry = block.start == layout.graph.address;
            painter.rect_filled(rect, 3.0 * zoom, theme::PANEL);
            let border = if is_entry { theme::LABEL } else { theme::FAINT };
            painter.rect_stroke(rect, 3.0 * zoom, Stroke::new(1.0, border), egui::StrokeKind::Inside);
            for (row, line) in block.lines.iter().enumerate() {
                let top = rect.top() + (PADDING + row as f32 * LINE_HEIGHT) * zoom;
                let line_rect = Rect::from_min_size(pos2(rect.left(), top), vec2(rect.width(), LINE_HEIGHT * zoom));
                if line.address == cursor {
                    painter.rect_filled(line_rect, 0.0, theme::SELECTION);
                }
                let left = rect.left() + PADDING * zoom;
                painter.text(
                    pos2(left, top),
                    Align2::LEFT_TOP,
                    format!("{:x}", line.address & 0xffff_ffff),
                    font.clone(),
                    theme::ADDRESS,
                );
                let branch = !matches!(line.flow, Flow::Next | Flow::Invalid);
                let color = if branch { theme::BRANCH } else { theme::TEXT };
                let mut text = line.text.clone();
                if let Some(comment) = line.note.as_ref().or(line.comment.as_ref()) {
                    text.push_str("  ; ");
                    text.push_str(comment);
                }
                painter.text(pos2(left + 10.0 * CHAR_WIDTH * zoom, top), Align2::LEFT_TOP, text, font.clone(), color);
                if response.hover_pos().is_some_and(|position| line_rect.contains(position)) {
                    if response.double_clicked() {
                        followed = match line.flow {
                            Flow::Jump(target) | Flow::ConditionalJump(target) | Flow::Call(target) => Some(target),
                            _ => line.data_ref,
                        };
                    } else if response.clicked() {
                        clicked = Some(line.address);
                    }
                }
            }
        }
    });
    if let Some(address) = followed {
        workspace.goto(address);
    } else if let Some(address) = clicked {
        workspace.select(address);
    }
}
