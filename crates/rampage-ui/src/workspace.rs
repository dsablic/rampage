//! An open binary: its project, results computed in the background, and the navigation state.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::time::{Duration, Instant};

use rampage_analysis::strings::FoundString;
use rampage_api::annotations::{DISCARD_HINT, Edit, Field};
use rampage_api::{
    ApiError, FunctionListing, FunctionRow, FunctionsQuery, ImportRow, ListQuery, Project, Session, StringsQuery,
    Triage, XrefQuery, XrefRow,
};
use rampage_arch::Arch;
use rampage_loaders::{Export, ImageAt};

use crate::listing::Listing;

/// A result computed on a background thread, or inline when the workspace runs synchronously (in tests).
pub enum Job<T> {
    Idle,
    Running(Receiver<Result<T, String>>),
    Done(Result<T, String>),
}

impl<T: Send + 'static> Job<T> {
    pub(crate) fn start(
        &mut self,
        blocking: bool,
        ctx: &egui::Context,
        work: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) {
        if blocking {
            *self = Job::Done(work());
            return;
        }
        let (sender, receiver) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = sender.send(work());
            ctx.request_repaint();
        });
        *self = Job::Running(receiver);
    }

    /// Collects a finished background result. Returns true when it just arrived.
    pub(crate) fn poll(&mut self) -> bool {
        let Job::Running(receiver) = self else { return false };
        match receiver.try_recv() {
            Ok(result) => {
                *self = Job::Done(result);
                true
            }
            Err(TryRecvError::Empty) => false,
            Err(TryRecvError::Disconnected) => {
                *self = Job::Done(Err("background task failed".to_owned()));
                true
            }
        }
    }

    pub fn ready(&self) -> Option<&T> {
        match self {
            Job::Done(Ok(value)) => Some(value),
            _ => None,
        }
    }

    pub fn error(&self) -> Option<&str> {
        match self {
            Job::Done(Err(error)) => Some(error),
            _ => None,
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self, Job::Running(_))
    }
}

/// Instructions shown when the cursor is outside every function.
const LINEAR_LINES: usize = 400;

/// How often to pick up names and comments other clients (an AI agent over MCP, the CLI) saved.
const ANNOTATION_REFRESH: Duration = Duration::from_secs(1);

/// The error with its causes: a load error alone names only the file.
fn text(error: ApiError) -> String {
    let mut text = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        text.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    text
}

/// Case-insensitive (ASCII) substring test that allocates nothing, for filtering hundreds of thousands of rows.
pub fn matches(haystack: &str, needle: &str) -> bool {
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    needle.is_empty() || haystack.windows(needle.len()).any(|window| window.eq_ignore_ascii_case(needle))
}

/// A list's filter text and the indices of the rows it keeps, recomputed only when the text or the row count
/// changes, or after `invalidate`.
#[derive(Default)]
pub struct Filter {
    pub text: String,
    applied: Option<(String, usize)>,
    indices: Vec<usize>,
}

impl Filter {
    pub fn shown(&mut self, rows: usize, keep: impl Fn(usize, &str) -> bool) -> &[usize] {
        let current = (self.text.as_str(), rows);
        if self.applied.as_ref().is_none_or(|(text, count)| (text.as_str(), *count) != current) {
            self.indices = (0..rows).filter(|&index| keep(index, &self.text)).collect();
            self.applied = Some((self.text.clone(), rows));
        }
        &self.indices
    }

    /// Forces the next `shown` to filter again, after the rows' text changed.
    pub fn invalidate(&mut self) {
        self.applied = None;
    }
}

/// An edit being typed: the field, the address, and the text so far.
pub struct Editing {
    pub field: Field,
    pub address: u64,
    pub text: String,
}

/// The cross-reference panel: what it shows references to, and the references.
pub struct Xrefs {
    pub target: String,
    pub rows: Result<Vec<XrefRow>, String>,
}

pub struct Workspace {
    pub(crate) instance: Arc<()>,
    pub(crate) annotations_epoch: Arc<()>,
    pub(crate) navigation_revision: Arc<()>,
    pub(crate) debug_layout: crate::debug_layout::DebugLayouts,
    entry_ui: crate::entry_ui::EntryUi,
    deferred: bool,
    pub path: PathBuf,
    /// The embedded image opened, when not the whole file.
    pub image: Option<ImageAt>,
    pub project: Arc<Project>,
    blocking: bool,
    pub functions: Job<Vec<FunctionRow>>,
    pub strings: Job<Vec<FoundString>>,
    pub triage: Job<Triage>,
    pub pseudocode: Job<rampage_api::Decompilation>,
    pseudocode_address: Option<u64>,
    pseudocode_cancellation: Arc<std::sync::atomic::AtomicBool>,
    pub imports: Vec<ImportRow>,
    pub exports: Vec<Export>,
    /// The address the listing and the cross-reference panel follow.
    pub cursor: u64,
    back: Vec<u64>,
    forward: Vec<u64>,
    /// The function shown in the listing, for the cursor's address.
    pub listing: Option<Result<Listing, String>>,
    pub xrefs: Option<Xrefs>,
    /// Set when the listing should scroll the cursor into view.
    pub scroll_to_cursor: bool,
    /// Set when navigation should bring the listing to the front.
    pub show_listing: bool,
    pub function_filter: Filter,
    pub string_filter: Filter,
    pub import_filter: Filter,
    pub export_filter: Filter,
    pub goto_text: String,
    pub goto_error: Option<String>,
    /// Hex digits needed for the highest mapped address, so listings drop leading zeros.
    pub address_width: usize,
    /// The rename or comment dialog, when open.
    pub editing: Option<Editing>,
    pub edit_error: Option<String>,
    /// A problem for the status bar: an undo that could not apply, or other clients' edits that cannot be read.
    pub notice: Option<String>,
    /// An undo another client's edits block: the refusal, shown with the offer to discard the step.
    pub blocked_undo: Option<String>,
    pub band: crate::band::Cache,
    /// The graph of the listing's function, keyed by its address.
    pub graph: Option<(u64, Result<crate::graph::Layout, String>)>,
    pub graph_zoom: f32,
    /// The UI pass in which the graph was last shown, to keep navigation in the graph while it is in use.
    pub graph_shown_pass: Option<u64>,
    pub assistant: crate::assistant::Assistant,
    annotations_checked: Instant,
}

impl Workspace {
    #[cfg(test)]
    pub(crate) fn request_annotation_refresh_for_test(&mut self) {
        self.annotations_checked = Instant::now() - ANNOTATION_REFRESH;
    }

    /// Opens `path` in `session`, or the executable embedded at `image`, and starts analysis. With `blocking`,
    /// every background job runs inline instead.
    pub fn open(
        session: &Session,
        path: PathBuf,
        arch: Option<Arch>,
        image: Option<ImageAt>,
        ctx: &egui::Context,
        blocking: bool,
    ) -> Result<Self, String> {
        let image = image.filter(|image| !image.is_whole_file());
        let project = session.open_at(&path, arch, image).map_err(text)?;
        Ok(Self::from_loaded_project(path, image, project, ctx, blocking, false))
    }

    /// Opens the same session project without starting or requiring global analysis.
    pub fn open_exact(
        session: &Session,
        path: PathBuf,
        arch: Option<Arch>,
        image: Option<ImageAt>,
        ctx: &egui::Context,
        blocking: bool,
    ) -> Result<Self, String> {
        let image = image.filter(|image| !image.is_whole_file());
        let project = session.open_at(&path, arch, image).map_err(text)?;
        Ok(Self::from_loaded_project(path, image, project, ctx, blocking, true))
    }

    pub(crate) fn from_loaded_project(
        path: PathBuf,
        image: Option<ImageAt>,
        project: Arc<Project>,
        ctx: &egui::Context,
        blocking: bool,
        deferred: bool,
    ) -> Self {
        let imports = project.imports(&ListQuery::default()).items;
        let exports = project.exports(&ListQuery::default()).items;
        let cursor = project
            .binary
            .entry
            .or_else(|| project.binary.function_starts.first().copied())
            .or_else(|| project.binary.exports.first().map(|export| export.address))
            .unwrap_or(0);
        let highest = project.binary.segments.iter().map(|segment| segment.address + segment.size).max().unwrap_or(0);
        let address_width = (64 - highest.leading_zeros() as usize).div_ceil(4).max(4);
        let mut workspace = Self {
            instance: Arc::new(()),
            annotations_epoch: Arc::new(()),
            navigation_revision: Arc::new(()),
            debug_layout: crate::debug_layout::DebugLayouts::default(),
            entry_ui: crate::entry_ui::EntryUi::default(),
            deferred: true,
            path,
            image,
            project,
            blocking,
            functions: Job::Idle,
            strings: Job::Idle,
            triage: Job::Idle,
            pseudocode: Job::Idle,
            pseudocode_address: None,
            pseudocode_cancellation: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            imports,
            exports,
            cursor,
            back: Vec::new(),
            forward: Vec::new(),
            listing: None,
            xrefs: None,
            scroll_to_cursor: true,
            show_listing: false,
            function_filter: Filter::default(),
            string_filter: Filter::default(),
            import_filter: Filter::default(),
            export_filter: Filter::default(),
            goto_text: String::new(),
            goto_error: None,
            address_width,
            editing: None,
            edit_error: None,
            notice: None,
            blocked_undo: None,
            band: crate::band::Cache::default(),
            graph: None,
            graph_zoom: 1.0,
            graph_shown_pass: None,
            assistant: crate::assistant::Assistant::default(),
            annotations_checked: Instant::now(),
        };
        if !deferred {
            workspace.start_analysis(ctx);
        }
        workspace
    }

    pub fn start_analysis(&mut self, ctx: &egui::Context) {
        if !self.deferred {
            return;
        }
        self.deferred = false;
        let project = Arc::clone(&self.project);
        self.functions.start(self.blocking, ctx, move || {
            project.functions(&FunctionsQuery::default()).map(|page| page.items).map_err(text)
        });
        let project = Arc::clone(&self.project);
        self.triage.start(self.blocking, ctx, move || Ok(project.triage().clone()));
        if self.blocking {
            self.refresh_cursor_views();
        }
    }

    pub fn analysis_deferred(&self) -> bool {
        self.deferred
    }

    pub fn show_entry_decompilation(&mut self) {
        self.entry_ui.show();
    }

    pub(crate) fn show_entry_window(&mut self, ctx: &egui::Context) {
        let mut entry = std::mem::take(&mut self.entry_ui);
        entry.window(self, ctx, self.blocking);
        self.entry_ui = entry;
    }

    pub(crate) fn set_entry_gate(&mut self, gate: crate::entry_ui::EntryGate) {
        self.entry_ui.set_gate(gate);
    }

    pub(crate) fn navigation_snapshot(&self) -> (u64, Vec<u64>, Vec<u64>) {
        (self.cursor, self.back.clone(), self.forward.clone())
    }

    pub(crate) fn bounded_navigation_snapshot(&self) -> Result<(u64, Vec<u64>, Vec<u64>), String> {
        if self.back.len() > 256 || self.forward.len() > 256 {
            return Err("workspace history exceeds the 256-address persistence limit".into());
        }
        Ok(self.navigation_snapshot())
    }

    pub(crate) fn navigation_matches(&self, snapshot: &(u64, Vec<u64>, Vec<u64>)) -> bool {
        self.back.len() <= 256
            && self.forward.len() <= 256
            && self.cursor == snapshot.0
            && self.back == snapshot.1
            && self.forward == snapshot.2
    }

    pub(crate) fn restore_navigation(&mut self, cursor: u64, back: Vec<u64>, forward: Vec<u64>) {
        if self.cursor != cursor || self.back != back || self.forward != forward {
            self.navigation_revision = Arc::new(());
        }
        self.entry_ui.invalidate();
        self.cursor = cursor;
        self.back = back;
        self.forward = forward;
        self.listing = None;
        self.xrefs = None;
        self.graph = None;
        self.scroll_to_cursor = true;
        self.refresh_cursor_views();
    }

    pub(crate) fn deactivate(&mut self) {
        self.entry_ui.invalidate();
        self.instance = Arc::new(());
        self.debug_layout.invalidate();
        self.pseudocode_cancellation.store(true, std::sync::atomic::Ordering::Relaxed);
        self.pseudocode_address = None;
    }

    /// Starts the string scan the first time the strings panel is shown.
    pub fn want_strings(&mut self, ctx: &egui::Context) {
        if self.deferred {
            return;
        }
        if matches!(self.strings, Job::Idle) {
            let project = Arc::clone(&self.project);
            self.strings.start(self.blocking, ctx, move || Ok(project.strings(&StringsQuery::default()).items));
        }
    }

    /// Collects finished background work and edits other clients saved.
    pub fn poll(&mut self, ctx: &egui::Context) {
        let mut entry = std::mem::take(&mut self.entry_ui);
        entry.poll(self);
        self.entry_ui = entry;
        if !self.deferred && self.pseudocode.is_running() {
            let address = self.project.function_containing(self.cursor).ok().flatten().unwrap_or(self.cursor);
            if self.pseudocode_address != Some(address) {
                self.pseudocode_cancellation.store(true, std::sync::atomic::Ordering::Relaxed);
                self.pseudocode_address = None;
            }
        }
        let analyzed = self.functions.poll();
        self.strings.poll();
        self.triage.poll();
        self.pseudocode.poll();
        if analyzed {
            self.refresh_cursor_views();
        }
        let effects = self.assistant.poll();
        if effects.annotations_changed {
            self.annotations_changed(None);
        }
        if let Some(target) = effects.show {
            self.goto_text(&target);
        }
        if !self.blocking {
            if self.annotations_checked.elapsed() >= ANNOTATION_REFRESH {
                self.annotations_checked = Instant::now();
                match self.project.refresh_annotations() {
                    Ok(changed) => {
                        self.notice = None;
                        if changed {
                            self.annotations_changed(None);
                        }
                    }
                    Err(error) => self.notice = Some(error.to_string()),
                }
            }
            ctx.request_repaint_after(ANNOTATION_REFRESH);
        }
        let mut review = std::mem::take(&mut self.debug_layout);
        review.poll(self);
        self.debug_layout = review;
    }

    pub(crate) fn review_debug_layouts(&mut self, ctx: &egui::Context) {
        let mut review = std::mem::take(&mut self.debug_layout);
        review.start(self, ctx, self.blocking);
        self.debug_layout = review;
    }

    pub fn analysis_ready(&self) -> bool {
        self.functions.ready().is_some()
    }

    pub fn want_pseudocode(&mut self, ctx: &egui::Context) {
        if !self.analysis_ready() {
            return;
        }
        if self.pseudocode.is_running() {
            let address = self.project.function_containing(self.cursor).ok().flatten().unwrap_or(self.cursor);
            if self.pseudocode_address != Some(address) {
                self.pseudocode_cancellation.store(true, std::sync::atomic::Ordering::Relaxed);
                self.pseudocode_address = None;
            }
            return;
        }
        let address = self.project.function_containing(self.cursor).ok().flatten().unwrap_or(self.cursor);
        if self.pseudocode_address == Some(address) {
            return;
        }
        self.pseudocode_address = Some(address);
        self.pseudocode_cancellation = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancellation = Arc::clone(&self.pseudocode_cancellation);
        let project = Arc::clone(&self.project);
        self.pseudocode
            .start(self.blocking, ctx, move || project.decompile_cancellable(address, &cancellation).map_err(text));
    }

    /// Lays out the graph of the listing's function, once per function.
    pub fn want_graph(&mut self) {
        if !self.analysis_ready() {
            return;
        }
        // Outside any function (data, or code analysis did not reach) there is no graph to show.
        let Some(address) =
            self.listing_address().filter(|_| self.project.function_containing(self.cursor).ok().flatten().is_some())
        else {
            self.graph = Some((self.cursor, Err(format!("No function contains {:#x}", self.cursor))));
            return;
        };
        if self.graph.as_ref().is_some_and(|(cached, _)| *cached == address) {
            return;
        }
        let width = self.address_width;
        let layout = self.project.function_graph(address).map(|graph| crate::graph::layout(graph, width)).map_err(text);
        self.graph = Some((address, layout));
    }

    /// The listing's function, when one is shown.
    pub fn listing_address(&self) -> Option<u64> {
        match &self.listing {
            Some(Ok(listing)) => Some(listing.function.address),
            _ => None,
        }
    }

    /// Moves the cursor to `address`, remembering where it was.
    pub fn goto(&mut self, address: u64) {
        if address != self.cursor {
            self.navigation_revision = Arc::new(());
            self.entry_ui.invalidate();
            self.back.push(self.cursor);
            self.forward.clear();
        }
        self.cursor = address;
        self.scroll_to_cursor = true;
        self.show_listing = true;
        self.refresh_cursor_views();
    }

    /// Opens the rename dialog for the cursor.
    pub fn begin_rename(&mut self) {
        let text = self.project.name_at(self.cursor).unwrap_or_default();
        self.editing = Some(Editing { field: Field::Name, address: self.cursor, text });
        self.edit_error = None;
    }

    pub fn begin_comment(&mut self) {
        let text = self.project.comment_at(self.cursor).unwrap_or_default();
        self.editing = Some(Editing { field: Field::Comment, address: self.cursor, text });
        self.edit_error = None;
    }

    /// Applies the open dialog; it stays open with an error if the edit is rejected.
    pub fn finish_edit(&mut self) {
        let Some(editing) = &self.editing else { return };
        let text = editing.text.trim();
        let value = (!text.is_empty()).then_some(text);
        let result = match editing.field {
            Field::Name => self.project.rename(editing.address, value),
            Field::Comment => self.project.comment(editing.address, value),
            Field::Signature => self.project.set_signature(editing.address, value),
            Field::Types => self.project.set_types(editing.address, value),
            Field::Global => self.project.set_global(editing.address, value),
            Field::LocalName | Field::LocalType => Err(rampage_api::ApiError::Invalid(
                "local variable edits require a native storage selector through MCP".to_owned(),
            )),
            Field::TypeLibrary => Err(rampage_api::ApiError::Invalid(
                "project type-library edits require the declare_types/delete_type MCP tools".to_owned(),
            )),
            Field::DataType | Field::OperandType => Err(rampage_api::ApiError::Invalid(
                "data and operand type edits require the selector-aware MCP typing tools".to_owned(),
            )),
            Field::TypeHint => Err(rampage_api::ApiError::Invalid(
                "derived type hints require the provenance-aware propagate_types MCP tool".to_owned(),
            )),
            Field::DebugTypes => Err(rampage_api::ApiError::Invalid(
                "checked debug type edits require the reviewed import_debug_types MCP workflow".to_owned(),
            )),
        };
        match result {
            Ok(edit) => {
                self.editing = None;
                self.annotations_changed(Some(edit.address));
            }
            Err(error) => self.edit_error = Some(error.to_string()),
        }
    }

    pub fn undo(&mut self) {
        match self.project.undo() {
            Err(ApiError::Invalid(message)) if message.ends_with(DISCARD_HINT) => {
                let reason = message.trim_end_matches(DISCARD_HINT).to_owned();
                self.notice = Some(format!("Undo blocked: {reason}"));
                self.blocked_undo = Some(reason);
                // The refused undo read the other client's edits; show them.
                self.annotations_changed(None);
            }
            result => self.step_changed(result),
        }
    }

    /// Drops the blocked step from the undo history, keeping its edits, so earlier steps can be undone. Never
    /// forced: if the step is no longer blocked, the refusal is shown and undo can revert it again.
    pub fn discard_blocked_undo(&mut self) {
        self.blocked_undo = None;
        self.notice = match self.project.discard_undo_step(false) {
            Ok(edits) if edits.is_empty() => None,
            Ok(edits) if edits.len() == 1 => {
                Some("Discarded the blocked undo step; its edit stays in effect".to_owned())
            }
            Ok(edits) => Some(format!("Discarded the blocked undo step; its {} edits stay in effect", edits.len())),
            Err(error) => Some(error.to_string()),
        };
    }

    pub fn redo(&mut self) {
        let result = self.project.redo();
        self.step_changed(result);
    }

    /// Refreshes after an undo or redo: just the address one edit touched, or everything after a batch.
    fn step_changed(&mut self, result: Result<Vec<Edit>, ApiError>) {
        match result.as_deref() {
            Ok([]) => {}
            Ok([edit]) => self.annotations_changed(Some(edit.address)),
            Ok(_) => self.annotations_changed(None),
            Err(error) => self.notice = Some(error.to_string()),
        }
    }

    /// Refreshes everything that shows names or comments after an edit at `address`, or anywhere.
    pub(crate) fn annotations_changed(&mut self, address: Option<u64>) {
        self.entry_ui.invalidate();
        self.annotations_epoch = Arc::new(());
        self.debug_layout.invalidate();
        self.pseudocode_address = None;
        self.pseudocode_cancellation.store(true, std::sync::atomic::Ordering::Relaxed);
        if !self.pseudocode.is_running() {
            self.pseudocode = Job::Idle;
        }
        if let Job::Done(Ok(functions)) = &mut self.functions {
            for function in functions.iter_mut().filter(|function| address.is_none_or(|at| at == function.address)) {
                function.name = self.project.function_name(function.address);
            }
            self.function_filter.invalidate();
        }
        self.listing = None;
        self.graph = None;
        self.refresh_cursor_views();
    }

    /// Moves the cursor within the current listing without adding to the history.
    pub fn select(&mut self, address: u64) {
        if address != self.cursor {
            self.navigation_revision = Arc::new(());
            self.entry_ui.invalidate();
        }
        self.cursor = address;
    }

    /// Resolves an address or name typed by the user and goes there.
    pub fn goto_text(&mut self, text: &str) {
        match self.project.resolve(text) {
            Ok(address) => {
                self.goto_error = None;
                self.goto(address);
            }
            Err(error) => self.goto_error = Some(error.to_string()),
        }
    }

    pub fn can_go_back(&self) -> bool {
        !self.back.is_empty()
    }

    pub fn can_go_forward(&self) -> bool {
        !self.forward.is_empty()
    }

    pub fn go_back(&mut self) {
        if let Some(address) = self.back.pop() {
            self.navigation_revision = Arc::new(());
            self.forward.push(self.cursor);
            self.revisit(address);
        }
    }

    pub fn go_forward(&mut self) {
        if let Some(address) = self.forward.pop() {
            self.navigation_revision = Arc::new(());
            self.back.push(self.cursor);
            self.revisit(address);
        }
    }

    fn revisit(&mut self, address: u64) {
        if address != self.cursor {
            self.entry_ui.invalidate();
        }
        self.cursor = address;
        self.scroll_to_cursor = true;
        self.show_listing = true;
        self.refresh_cursor_views();
    }

    fn refresh_cursor_views(&mut self) {
        if !self.analysis_ready() {
            return;
        }
        let in_current = matches!(&self.listing, Some(Ok(listing)) if listing.contains(self.cursor));
        if !in_current {
            // Outside any function, code analysis did not reach gets a linear disassembly; data gets a hex view.
            self.listing = match self.project.function_listing(self.cursor) {
                Ok(listing) => Some(Ok(Listing::new(listing))),
                Err(_) if self.project.binary.is_code(self.cursor) => {
                    let lines = self.project.disassemble(Some(&format!("{:#x}", self.cursor)), LINEAR_LINES);
                    let listing = lines.map(|lines| {
                        Listing::new(FunctionListing { address: self.cursor, name: String::new(), blocks: vec![lines] })
                    });
                    Some(listing.map_err(text))
                }
                Err(_) => None,
            };
        }
        let (address, target) = match &self.listing {
            Some(Ok(listing)) if !listing.function.name.is_empty() => {
                (listing.function.address, listing.function.name.clone())
            }
            _ => (self.cursor, format!("{:#x}", self.cursor)),
        };
        let rows = self.project.xrefs(XrefQuery::To(address), None, None).map(|page| page.items).map_err(text);
        self.xrefs = Some(Xrefs { target, rows });
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        self.entry_ui.invalidate();
        self.pseudocode_cancellation.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferred_poll_annotation_refresh_does_not_initialize_backend_analysis_caches() {
        for file in ["hello-x64-dyn.elf", "hello-x64.exe", "hello-arm64.macho"] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(file);
            let ctx = egui::Context::default();
            let mut workspace = Workspace::open_exact(&Session::default(), path, None, None, &ctx, false).unwrap();
            assert_eq!(workspace.project.analysis_cache_status(), rampage_api::AnalysisCacheStatus::default());
            let previous_check = Instant::now() - ANNOTATION_REFRESH;
            workspace.annotations_checked = previous_check;
            workspace.poll(&ctx);
            assert!(workspace.annotations_checked > previous_check);
            assert_eq!(workspace.project.analysis_cache_status(), rampage_api::AnalysisCacheStatus::default());
            assert!(matches!(workspace.functions, Job::Idle));
            assert!(matches!(workspace.strings, Job::Idle));
            assert!(matches!(workspace.triage, Job::Idle));
            assert!(matches!(workspace.pseudocode, Job::Idle));
            assert!(workspace.listing.is_none());
            assert!(workspace.xrefs.is_none());
        }
    }

    #[test]
    fn polling_cancels_obsolete_hidden_pseudocode_and_clears_its_cache_key() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
        let ctx = egui::Context::default();
        let mut workspace = Workspace::open(&Session::default(), path, None, None, &ctx, true).unwrap();
        let add = workspace.project.resolve("add").unwrap();
        let main = workspace.project.resolve("main").unwrap();
        let (_sender, receiver) = channel();
        workspace.pseudocode = Job::Running(receiver);
        workspace.pseudocode_address = Some(add);
        workspace.cursor = main;
        workspace.poll(&ctx);
        assert!(workspace.pseudocode_cancellation.load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(workspace.pseudocode_address, None);
        workspace.cursor = add;
        workspace.pseudocode = Job::Done(Err("cancelled".to_owned()));
        workspace.want_pseudocode(&ctx);
        assert!(workspace.pseudocode.ready().unwrap().code.contains("add("));
    }
}
