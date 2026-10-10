//! An open binary: its project, results computed in the background, and the navigation state.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, TryRecvError, channel};

use rampage_api::{
    ApiError, FunctionListing, FunctionRow, FunctionsQuery, ImportRow, ListQuery, Project, Session, StringsQuery,
    Triage, XrefQuery, XrefRow,
};
use rampage_arch::Arch;

/// A result computed on a background thread, or inline when the workspace runs synchronously (in tests).
pub enum Job<T> {
    Idle,
    Running(Receiver<Result<T, String>>),
    Done(Result<T, String>),
}

impl<T: Send + 'static> Job<T> {
    fn start(
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
    fn poll(&mut self) -> bool {
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

fn text(error: ApiError) -> String {
    error.to_string()
}

/// An edit being typed: the field, the address, and the text so far.
pub struct Editing {
    pub field: rampage_api::annotations::Field,
    pub address: u64,
    pub text: String,
}

pub struct Workspace {
    pub path: PathBuf,
    pub project: Arc<Project>,
    blocking: bool,
    pub functions: Job<Vec<FunctionRow>>,
    pub strings: Job<Vec<rampage_analysis::strings::FoundString>>,
    pub triage: Job<Triage>,
    pub imports: Vec<ImportRow>,
    pub exports: Vec<rampage_loaders::Export>,
    /// The address the listing and the cross-reference panel follow.
    pub cursor: u64,
    back: Vec<u64>,
    forward: Vec<u64>,
    /// The function shown in the listing, for the cursor's address.
    pub listing: Option<Result<FunctionListing, String>>,
    /// References to the cursor's function or address.
    pub xrefs: Option<Result<Vec<XrefRow>, String>>,
    /// Set when the listing should scroll the cursor into view.
    pub scroll_to_cursor: bool,
    pub function_filter: String,
    pub function_rows: crate::tabs::Filtered,
    pub string_rows: crate::tabs::Filtered,
    pub string_filter: String,
    pub import_filter: String,
    pub goto_text: String,
    pub goto_error: Option<String>,
    /// Hex digits needed for the highest mapped address, so listings drop leading zeros.
    pub address_width: usize,
    /// The rename or comment dialog, when open.
    pub editing: Option<Editing>,
    pub edit_error: Option<String>,
}

impl Workspace {
    /// Opens `path` and starts analysis. With `blocking`, every background job runs inline instead.
    pub fn open(path: PathBuf, arch: Option<Arch>, ctx: &egui::Context, blocking: bool) -> Result<Self, String> {
        let project = Session::default().open(&path, arch).map_err(text)?;
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
            editing: None,
            edit_error: None,
            address_width,
            path,
            project,
            blocking,
            functions: Job::Idle,
            strings: Job::Idle,
            triage: Job::Idle,
            imports,
            exports,
            cursor,
            back: Vec::new(),
            forward: Vec::new(),
            listing: None,
            xrefs: None,
            scroll_to_cursor: true,
            function_filter: String::new(),
            function_rows: Default::default(),
            string_rows: Default::default(),
            string_filter: String::new(),
            import_filter: String::new(),
            goto_text: String::new(),
            goto_error: None,
        };
        let project = Arc::clone(&workspace.project);
        workspace.functions.start(blocking, ctx, move || {
            project.functions(&FunctionsQuery::default()).map(|page| page.items).map_err(text)
        });
        let project = Arc::clone(&workspace.project);
        workspace.triage.start(blocking, ctx, move || Ok(project.triage().clone()));
        if blocking {
            workspace.refresh_cursor_views();
        }
        Ok(workspace)
    }

    /// Starts the string scan the first time the strings panel is shown.
    pub fn want_strings(&mut self, ctx: &egui::Context) {
        if matches!(self.strings, Job::Idle) {
            let project = Arc::clone(&self.project);
            self.strings.start(self.blocking, ctx, move || Ok(project.strings(&StringsQuery::default()).items));
        }
    }

    /// Collects finished background work; returns true when something changed.
    pub fn poll(&mut self) -> bool {
        let analyzed = self.functions.poll();
        let changed = analyzed | self.strings.poll() | self.triage.poll();
        if analyzed {
            self.refresh_cursor_views();
        }
        changed
    }

    pub fn analysis_ready(&self) -> bool {
        self.functions.ready().is_some()
    }

    /// Moves the cursor to `address`, remembering where it was.
    pub fn goto(&mut self, address: u64) {
        if address != self.cursor {
            self.back.push(self.cursor);
            self.forward.clear();
        }
        self.cursor = address;
        self.scroll_to_cursor = true;
        self.refresh_cursor_views();
    }

    /// Opens the rename dialog for the cursor (or the function containing it, from a label line).
    pub fn begin_rename(&mut self) {
        let text = self.project.name_at(self.cursor).unwrap_or_default();
        self.editing = Some(Editing { field: rampage_api::annotations::Field::Name, address: self.cursor, text });
        self.edit_error = None;
    }

    pub fn begin_comment(&mut self) {
        let text = self.project.comment_at(self.cursor).unwrap_or_default();
        self.editing = Some(Editing { field: rampage_api::annotations::Field::Comment, address: self.cursor, text });
        self.edit_error = None;
    }

    /// Applies the open dialog; it stays open with an error if the edit is rejected.
    pub fn finish_edit(&mut self) {
        let Some(editing) = &self.editing else { return };
        let text = editing.text.trim();
        let value = (!text.is_empty()).then_some(text);
        let result = match editing.field {
            rampage_api::annotations::Field::Name => self.project.rename(editing.address, value),
            rampage_api::annotations::Field::Comment => self.project.comment(editing.address, value),
        };
        match result {
            Ok(_) => {
                let address = editing.address;
                self.editing = None;
                self.annotations_changed(address);
            }
            Err(error) => self.edit_error = Some(error.to_string()),
        }
    }

    pub fn undo(&mut self) {
        if let Ok(Some(edit)) = self.project.undo() {
            self.annotations_changed(edit.address);
        }
    }

    pub fn redo(&mut self) {
        if let Ok(Some(edit)) = self.project.redo() {
            self.annotations_changed(edit.address);
        }
    }

    /// Refreshes everything that shows names or comments after an edit at `address`.
    fn annotations_changed(&mut self, address: u64) {
        if let Job::Done(Ok(functions)) = &mut self.functions
            && let Ok(index) = functions.binary_search_by_key(&address, |function| function.address)
        {
            functions[index].name = self.project.function_name(address);
            // Filters match on names, so they must be recomputed.
            self.function_rows = Default::default();
        }
        self.listing = None;
        self.refresh_cursor_views();
    }

    /// Moves the cursor within the current listing without adding to the history.
    pub fn select(&mut self, address: u64) {
        self.cursor = address;
    }

    /// Resolves an address or name typed by the user and goes there.
    pub fn goto_text(&mut self, text: &str) {
        match self.project.resolve(text) {
            Ok(address) => {
                self.goto_error = None;
                self.goto(address);
            }
            Err(error) => self.goto_error = Some(text_of(&error)),
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
            self.forward.push(self.cursor);
            self.cursor = address;
            self.scroll_to_cursor = true;
            self.refresh_cursor_views();
        }
    }

    pub fn go_forward(&mut self) {
        if let Some(address) = self.forward.pop() {
            self.back.push(self.cursor);
            self.cursor = address;
            self.scroll_to_cursor = true;
            self.refresh_cursor_views();
        }
    }

    /// The name of the function at `address`, or a `sub_` name.
    pub fn function_name(&self, address: u64) -> String {
        self.functions
            .ready()
            .and_then(|functions| {
                let index = functions.binary_search_by_key(&address, |function| function.address).ok()?;
                Some(functions[index].name.clone())
            })
            .unwrap_or_else(|| format!("sub_{address:x}"))
    }

    fn refresh_cursor_views(&mut self) {
        if !self.analysis_ready() {
            return;
        }
        let in_current = self
            .listing
            .as_ref()
            .and_then(|listing| listing.as_ref().ok())
            .is_some_and(|listing| listing.blocks.iter().flatten().any(|line| line.address == self.cursor));
        if !in_current {
            // Outside any function, code analysis did not reach gets a linear disassembly; data gets a hex view.
            self.listing = match self.project.function_listing(self.cursor) {
                Ok(listing) => Some(Ok(listing)),
                Err(_) if self.project.binary.is_code(self.cursor) => {
                    let lines = self.project.disassemble(Some(&format!("{:#x}", self.cursor)), LINEAR_LINES);
                    let listing = lines.map(|lines| FunctionListing {
                        address: self.cursor,
                        name: String::new(),
                        blocks: vec![lines],
                    });
                    Some(listing.map_err(text))
                }
                Err(_) => None,
            };
        }
        let target = match &self.listing {
            Some(Ok(listing)) => listing.address,
            _ => self.cursor,
        };
        self.xrefs = Some(self.project.xrefs(&XrefQuery::To(target)).map_err(text));
    }
}

fn text_of(error: &ApiError) -> String {
    error.to_string()
}
