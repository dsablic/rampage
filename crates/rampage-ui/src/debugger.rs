//! Explicit, local-only debugger observations, kept apart from the loaded project and assistant.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use egui::{RichText, TextBuffer, TextEdit, Ui};
use rampage_api::{DebuggerRequest, MAX_DEBUGGER_REQUEST_BYTES};

use crate::theme;
use crate::workspace::Job;

const TIMEOUT_MS: u64 = 3000;
const OPERATIONS: [&str; 5] = ["describe_session", "list_modules", "list_threads", "read_registers", "read_memory"];

pub(crate) struct Debugger {
    pub shown: bool,
    socket: String,
    request: String,
    request_rejected: bool,
    template: usize,
    job: Job<String>,
    error: Option<String>,
    submitted: Option<(String, String)>,
}

impl Default for Debugger {
    fn default() -> Self {
        Self {
            shown: false,
            socket: String::new(),
            request: template(0),
            request_rejected: false,
            template: 0,
            job: Job::Idle,
            error: None,
            submitted: None,
        }
    }
}

impl Debugger {
    pub fn show(&mut self, ctx: &egui::Context) {
        self.job.poll();
        if !self.shown {
            return;
        }
        let mut shown = self.shown;
        egui::Window::new("Read-only debugger")
            .open(&mut shown)
            .collapsible(false)
            .default_size(egui::vec2(720.0, 560.0))
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 60.0))
            .show(ctx, |ui| self.contents(ui));
        self.shown = shown;
    }

    fn contents(&mut self, ui: &mut Ui) {
        ui.label(RichText::new("Local runtime observation only").strong());
        ui.label(
            "Socket paths, requests and results stay in this window; they are never sent to an assistant or provider.",
        );
        ui.label(
            RichText::new(
                "Start the read-only LLDB endpoint yourself while stopped. Opening this window does not connect. \
                 Only Query connects; nothing is attached, resumed, evaluated or written.",
            )
            .color(theme::DIM)
            .small(),
        );
        ui.add_space(6.0);
        ui.label("Explicit Unix socket path");
        ui.add(
            TextEdit::singleline(&mut self.socket)
                .id(egui::Id::new("debugger-socket"))
                .hint_text("/absolute/private-directory/operator.sock")
                .char_limit(1024)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace),
        );
        ui.horizontal(|ui| {
            ui.label("Template");
            egui::ComboBox::from_id_salt("debugger-operation").selected_text(OPERATIONS[self.template]).show_ui(
                ui,
                |ui| {
                    for (index, operation) in OPERATIONS.iter().enumerate() {
                        ui.selectable_value(&mut self.template, index, *operation);
                    }
                },
            );
            if ui.button("Insert template").clicked() {
                self.request = template(self.template);
                self.request_rejected = false;
            }
        });
        ui.label("Request JSON (at most 16 KiB)");
        self.edit_request(ui);
        if self.request_rejected {
            ui.label(RichText::new(REJECTED_INPUT).color(theme::WARNING));
        }
        ui.label(
            RichText::new(
                "Run describe_session explicitly, then copy its returned token into expected_token for follow-ups. \
                 Replace template placeholders. Stale tokens are not retried or refreshed automatically.",
            )
            .color(theme::DIM)
            .small(),
        );
        ui.horizontal(|ui| {
            if ui.add_enabled(!self.job.is_running(), egui::Button::new("Query")).clicked() {
                self.query(ui.ctx());
            }
            if ui.add_enabled(!self.job.is_running(), egui::Button::new("Clear local data")).clicked() {
                self.clear(ui.ctx());
            }
            ui.label(RichText::new(format!("Client deadline: {TIMEOUT_MS} ms")).color(theme::DIM).small());
            if self.job.is_running() {
                ui.spinner();
                ui.label("Querying");
            }
        });
        if let Some(error) = self.error.as_deref().or_else(|| self.job.error()) {
            ui.label(RichText::new(error).color(theme::WARNING));
        }
        ui.separator();
        ui.label(RichText::new("Raw response to the last explicit query").strong());
        ui.label(
            RichText::new(
                "Includes backend ok:false errors, token and observation.atomic_snapshot:false metadata. \
                 Runtime addresses are not project addresses; no result is applied to the loaded binary or navigation.",
            )
            .color(theme::DIM)
            .small(),
        );
        ui.label(
            RichText::new("Shared tool response limits apply; reduce page or memory size if a query is refused.")
                .color(theme::DIM)
                .small(),
        );
        egui::ScrollArea::vertical().id_salt("debugger-results").max_height(260.0).show(ui, |ui| {
            if let Some((socket, request)) = &self.submitted {
                ui.label(RichText::new(format!("Queried socket: {socket}")).monospace().small());
                ui.collapsing("Submitted request", |ui| {
                    ui.add(egui::Label::new(RichText::new(request).monospace()).selectable(true));
                });
            }
            if let Some(response) = self.job.ready() {
                ui.add(egui::Label::new(RichText::new(response).monospace()).selectable(true));
            } else if !self.job.is_running() && self.error.is_none() && self.job.error().is_none() {
                ui.label(RichText::new("No query has been sent.").color(theme::DIM));
            }
        });
    }

    fn edit_request(&mut self, ui: &mut Ui) {
        let id = egui::Id::new("debugger-request");
        let previous_request = self.request.clone();
        let mut previous_state = egui::text_edit::TextEditState::load(ui.ctx(), id).unwrap_or_default();
        // TextEditState clones share an undoer; keep an independent snapshot for a rejected edit frame.
        let previous_undo = previous_state.undoer();
        let mut rejected = false;
        let mut editor = RequestEditor { text: &mut self.request, rejected: &mut rejected };
        ui.add(
            TextEdit::multiline(&mut editor)
                .id(id)
                .desired_width(f32::INFINITY)
                .desired_rows(7)
                .font(egui::TextStyle::Monospace),
        );
        if rejected {
            self.request = previous_request;
            previous_state.set_undoer(previous_undo);
            previous_state.store(ui.ctx(), id);
            self.request_rejected = true;
            ui.ctx().request_repaint();
        }
    }

    fn clear(&mut self, ctx: &egui::Context) {
        let shown = self.shown;
        *self = Self { shown, request: String::new(), ..Self::default() };
        for field in ["debugger-socket", "debugger-request"] {
            egui::text_edit::TextEditState::default().store(ctx, egui::Id::new(field));
        }
    }

    fn query(&mut self, ctx: &egui::Context) {
        if self.job.is_running() {
            return;
        }
        self.job = Job::Idle;
        self.error = None;
        self.submitted = None;
        if self.socket.is_empty() {
            self.error = Some("Enter an explicit absolute Unix socket path before querying.".to_owned());
            return;
        }
        if self.request_rejected {
            self.error = Some(REJECTED_INPUT.to_owned());
            return;
        }
        if let Err(error) = DebuggerRequest::from_json(&self.request) {
            self.error = Some(error.to_string());
            return;
        }
        let socket = PathBuf::from(&self.socket);
        let deadline = Instant::now() + Duration::from_millis(TIMEOUT_MS);
        let request = self.request.clone();
        self.submitted = Some((self.socket.clone(), self.request.clone()));
        self.job.start(false, ctx, move || run_query(socket, request, deadline));
    }
}

fn run_query(socket: PathBuf, request: String, deadline: Instant) -> Result<String, String> {
    DebuggerRequest::from_json(&request).map_err(|error| error.to_string())?;
    let tool = rampage_api::tools::file_tools()
        .into_iter()
        .find(|tool| tool.name == "query_debugger")
        .ok_or_else(|| "The shared debugger query tool is unavailable.".to_owned())?;
    let mut input = tool.input_schema.clone();
    let fields = input.as_object_mut().ok_or_else(|| "Invalid debugger tool schema.".to_owned())?;
    fields.clear();
    fields.insert("socket".to_owned(), socket.to_string_lossy().as_ref().into());
    // The shared typed parser already refused duplicate and unknown fields before this conversion to a tool value.
    match request.parse() {
        Ok(request) => fields.insert("request".to_owned(), request),
        Err(error) => return Err(format!("invalid debugger request: {error}")),
    };
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .map(|remaining| remaining.as_millis().min(TIMEOUT_MS as u128) as u64)
        .filter(|timeout| *timeout > 0)
        .ok_or_else(|| "Debugger query deadline exceeded.".to_owned())?;
    fields.insert("timeout_ms".to_owned(), timeout.into());
    let response = tool.call(&rampage_api::Packs::default(), input)?;
    if Instant::now() >= deadline {
        return Err("Debugger query deadline exceeded.".to_owned());
    }
    Ok(format!("{response:#}"))
}

const REJECTED_INPUT: &str = "Input exceeded 16 KiB and was rejected, not truncated. \
                            Insert a template or Clear local data before querying.";

struct RequestEditor<'a> {
    text: &'a mut String,
    rejected: &'a mut bool,
}

impl TextBuffer for RequestEditor<'_> {
    fn is_mutable(&self) -> bool {
        true
    }

    fn as_str(&self) -> &str {
        self.text
    }

    fn insert_text(&mut self, text: &str, char_index: egui::text::CharIndex) -> usize {
        if text.len() > MAX_DEBUGGER_REQUEST_BYTES.saturating_sub(self.text.len()) {
            *self.rejected = true;
            return 0;
        }
        self.text.insert_text(text, char_index)
    }

    fn delete_char_range(&mut self, char_range: std::ops::Range<egui::text::CharIndex>) {
        self.text.delete_char_range(char_range);
    }

    fn replace_with(&mut self, text: &str) {
        if text.len() > MAX_DEBUGGER_REQUEST_BYTES {
            *self.rejected = true;
            return;
        }
        self.text.replace_with(text);
    }

    fn type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<RequestEditor<'static>>()
    }
}

fn template(index: usize) -> String {
    if index == 0 {
        return "{\n  \"version\": 1,\n  \"operation\": \"describe_session\"\n}".to_owned();
    }
    let fields = match index {
        1 | 2 => ",\n  \"offset\": 0,\n  \"limit\": 32",
        3 => ",\n  \"thread_id\": \"REPLACE_THREAD_ID\"",
        _ => ",\n  \"address\": \"REPLACE_ADDRESS\",\n  \"size\": 64,\n  \"permissions\": \"r--\"",
    };
    format!(
        "{{\n  \"version\": 1,\n  \"operation\": \"{}\",\n  \
         \"expected_token\": \"REPLACE_WITH_RETURNED_TOKEN_OBJECT\"{fields}\n}}",
        OPERATIONS[index],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    fn key_event(key: egui::Key, modifiers: egui::Modifiers) -> egui::Event {
        egui::Event::Key { key, physical_key: None, pressed: true, repeat: false, modifiers }
    }

    #[test]
    fn oversized_paste_events_preserve_select_all_and_partial_selection() {
        let original = concat!(
            r#"{"version":1,"operation":"describe_session","expected_token":{"backend":"lldb-sb","#,
            r#""session_id":"private-é","process_unique_id":17,"stop_id":4,"target_index":0}}"#,
        );
        for select_all in [true, false] {
            let debugger = Debugger {
                shown: true,
                socket: "/private/operator.sock".to_owned(),
                request: original.to_owned(),
                ..Default::default()
            };
            let mut harness = Harness::builder()
                .with_size(egui::vec2(1400.0, 860.0))
                .build_ui_state(|ui, debugger: &mut Debugger| debugger.show(ui.ctx()), debugger);
            harness.run();
            let id = egui::Id::new("debugger-request");
            harness.ctx.memory_mut(|memory| memory.request_focus(id));
            harness.run();
            if select_all {
                harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
                harness.run();
            } else {
                let start = original[..original.find("private-é").unwrap()].chars().count();
                let end = start + "private-é".chars().count();
                let mut state = egui::text_edit::TextEditState::load(&harness.ctx, id).unwrap();
                state.cursor.set_char_range(Some(egui::text::CCursorRange::two(
                    egui::text::CCursor::new(start),
                    egui::text::CCursor::new(end),
                )));
                state.store(&harness.ctx, id);
                harness.run();
            }
            let selection =
                egui::text_edit::TextEditState::load(&harness.ctx, id).unwrap().cursor.char_range().unwrap();
            let selected_bytes = selection.slice_str(original).len();
            assert_eq!(selected_bytes, if select_all { original.len() } else { "private-é".len() });
            let paste_bytes = MAX_DEBUGGER_REQUEST_BYTES - (original.len() - selected_bytes) + 1;
            harness.event(egui::Event::Paste("x".repeat(paste_bytes)));
            harness.run();
            assert_eq!(harness.state().request, original);
            assert!(harness.state().request_rejected);
            let after = egui::text_edit::TextEditState::load(&harness.ctx, id).unwrap().cursor.char_range().unwrap();
            assert_eq!(after, selection);
            harness.get_by_label(REJECTED_INPUT);
            let ctx = harness.ctx.clone();
            harness.state_mut().query(&ctx);
            assert!(!harness.state().job.is_running());
            assert!(harness.state().error.is_some());
        }
    }

    #[test]
    fn same_frame_select_all_and_paste_uses_the_effective_selection() {
        for character in ["x", "é"] {
            let original = character.repeat(MAX_DEBUGGER_REQUEST_BYTES / character.len());
            let debugger = Debugger { shown: true, request: original.clone(), ..Default::default() };
            let mut harness = Harness::builder()
                .with_size(egui::vec2(1400.0, 860.0))
                .build_ui_state(|ui, debugger: &mut Debugger| debugger.show(ui.ctx()), debugger);
            harness.run();
            let id = egui::Id::new("debugger-request");
            harness.ctx.memory_mut(|memory| memory.request_focus(id));
            harness.run();
            let mut state = egui::text_edit::TextEditState::load(&harness.ctx, id).unwrap();
            state.cursor.set_char_range(Some(egui::text::CCursorRange::one(egui::text::CCursor::new(
                original.chars().count(),
            ))));
            state.store(&harness.ctx, id);
            let replacement = template(0);
            // Harness::event runs each queued event in a separate frame; RawInput preserves this batch.
            harness
                .input_mut()
                .events
                .extend([key_event(egui::Key::A, egui::Modifiers::COMMAND), egui::Event::Paste(replacement.clone())]);
            harness.run();
            assert_eq!(harness.state().request, replacement);
            assert!(!harness.state().request_rejected);
        }
    }

    #[test]
    fn same_frame_selection_change_and_oversized_paste_rolls_back_text_cursor_and_undo() {
        for (character, paste) in [("x", "ab"), ("é", "abc")] {
            let original = format!("{character}{}", "x".repeat(MAX_DEBUGGER_REQUEST_BYTES - character.len()));
            let debugger = Debugger {
                shown: true,
                socket: "/private/operator.sock".to_owned(),
                request: original.clone(),
                ..Default::default()
            };
            let mut harness = Harness::builder()
                .with_size(egui::vec2(1400.0, 860.0))
                .build_ui_state(|ui, debugger: &mut Debugger| debugger.show(ui.ctx()), debugger);
            harness.run();
            let id = egui::Id::new("debugger-request");
            harness.ctx.memory_mut(|memory| memory.request_focus(id));
            harness.run();
            harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
            harness.run();
            let mut state = egui::text_edit::TextEditState::load(&harness.ctx, id).unwrap();
            let selection = state.cursor.char_range().unwrap();
            assert_eq!(selection.slice_str(&original), original);
            let baseline = (selection, original.clone());
            let mut undo = egui::text_edit::TextEditState::default().undoer();
            undo.add_undo(&(selection, "earlier private request".to_owned()));
            undo.add_undo(&baseline);
            let future = (selection, "later private request".to_owned());
            undo.add_undo(&future);
            assert_eq!(undo.undo(&future), Some(&baseline));
            let previous_undo = undo.clone().undo(&baseline).cloned();
            let previous_redo = undo.clone().redo(&baseline).cloned();
            assert!(previous_undo.is_some());
            assert!(previous_redo.is_some());
            state.set_undoer(undo);
            state.store(&harness.ctx, id);
            harness.input_mut().events.extend([
                key_event(egui::Key::ArrowLeft, egui::Modifiers::NONE),
                key_event(egui::Key::ArrowRight, egui::Modifiers::SHIFT),
                egui::Event::Paste(paste.to_owned()),
            ]);
            harness.run();
            assert_eq!(harness.state().request, original);
            assert!(harness.state().request_rejected);
            let after = egui::text_edit::TextEditState::load(&harness.ctx, id).unwrap();
            assert_eq!(after.cursor.char_range(), Some(selection));
            assert_eq!(after.undoer().undo(&baseline).cloned(), previous_undo);
            assert_eq!(after.undoer().redo(&baseline).cloned(), previous_redo);
            harness.get_by_label(REJECTED_INPUT);
            let ctx = harness.ctx.clone();
            harness.state_mut().query(&ctx);
            assert!(!harness.state().job.is_running());
            assert!(harness.state().error.is_some());
        }
    }

    #[test]
    fn request_editor_rejects_whole_insertions_without_truncating_utf8_or_json() {
        let mut request = "a".repeat(MAX_DEBUGGER_REQUEST_BYTES - 1);
        let mut rejected = false;
        let mut editor = RequestEditor { text: &mut request, rejected: &mut rejected };
        assert_eq!(editor.insert_text("é", egui::text::CharIndex(0)), 0);
        assert_eq!(editor.as_str().len(), MAX_DEBUGGER_REQUEST_BYTES - 1);
        assert!(rejected);

        let mut request = String::new();
        let mut rejected = false;
        let mut editor = RequestEditor { text: &mut request, rejected: &mut rejected };
        let oversized = format!("{}{}", template(0), " ".repeat(MAX_DEBUGGER_REQUEST_BYTES));
        assert_eq!(editor.insert_text(&oversized, egui::text::CharIndex(0)), 0);
        assert!(editor.as_str().is_empty());
        assert!(rejected);
    }

    #[test]
    fn a_refused_query_drops_the_previous_observation() {
        let mut debugger = Debugger {
            job: Job::Done(Ok("previous runtime bytes".to_owned())),
            submitted: Some(("previous socket".to_owned(), "previous request".to_owned())),
            ..Default::default()
        };
        debugger.query(&egui::Context::default());
        assert!(debugger.error.is_some());
        assert!(debugger.job.ready().is_none());
        assert!(debugger.submitted.is_none());
        assert!(!debugger.job.is_running());
    }

    #[test]
    fn clear_removes_local_inputs_results_and_editor_undo_history() {
        let ctx = egui::Context::default();
        let cursor = egui::text::CCursorRange::default();
        for field in ["debugger-socket", "debugger-request"] {
            let mut state = egui::text_edit::TextEditState::default();
            let mut undo = state.undoer();
            undo.feed_state(0.0, &(cursor, "private data".to_owned()));
            state.set_undoer(undo);
            state.store(&ctx, egui::Id::new(field));
        }
        let mut debugger = Debugger {
            shown: true,
            socket: "private socket".to_owned(),
            job: Job::Done(Ok("private runtime bytes".to_owned())),
            submitted: Some(("private socket".to_owned(), "private request".to_owned())),
            ..Default::default()
        };
        debugger.clear(&ctx);
        assert!(debugger.shown);
        assert!(debugger.socket.is_empty());
        assert!(debugger.request.is_empty());
        assert!(debugger.job.ready().is_none());
        assert!(debugger.submitted.is_none());
        for field in ["debugger-socket", "debugger-request"] {
            let state = egui::text_edit::TextEditState::load(&ctx, egui::Id::new(field)).unwrap();
            assert!(!state.undoer().has_undo(&(cursor, String::new())));
        }
    }

    #[cfg(unix)]
    mod local_socket {
        use super::*;
        use std::fs::DirBuilder;
        use std::io::{Read, Write};
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicU64, Ordering};

        struct MockSocket {
            directory: PathBuf,
            path: PathBuf,
            listener: UnixListener,
        }

        impl MockSocket {
            fn new() -> Self {
                static NEXT: AtomicU64 = AtomicU64::new(0);
                let root = std::env::temp_dir().canonicalize().unwrap();
                let directory =
                    root.join(format!("ru-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
                DirBuilder::new().mode(0o700).create(&directory).unwrap();
                let path = directory.join("s");
                let listener = UnixListener::bind(&path).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
                listener.set_nonblocking(true).unwrap();
                Self { directory, path, listener }
            }

            fn assert_no_connection(&self) {
                assert_eq!(self.listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
            }

            fn respond(&self, response: serde_json::Value) -> serde_json::Value {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match self.listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "explicit UI query never connected");
                            std::thread::yield_now();
                        }
                        Err(error) => panic!("mock socket accept failed: {error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut request = Vec::new();
                stream.read_to_end(&mut request).unwrap();
                assert_eq!(request.pop(), Some(b'\n'));
                assert!(!request.contains(&b'\n'));
                stream.write_all(format!("{response}\n").as_bytes()).unwrap();
                serde_json::from_slice(&request).unwrap()
            }
        }

        impl Drop for MockSocket {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.path);
                let _ = std::fs::remove_dir(&self.directory);
            }
        }

        fn finish(debugger: &mut Debugger) {
            let Job::Running(receiver) = &debugger.job else { panic!("UI query was not a background job") };
            let response = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
            debugger.job = Job::Done(response);
            assert!(debugger.job.error().is_none(), "{:?}", debugger.job.error());
        }

        fn session_response() -> serde_json::Value {
            serde_json::json!({
                "protocol": "rampage-lldb-query-v1",
                "ok": true,
                "operation": "describe_session",
                "token": {
                    "backend": "lldb-sb",
                    "session_id": "ui-local-session",
                    "process_unique_id": 17,
                    "stop_id": 4,
                    "target_index": 0
                },
                "data": {"architecture": "arm64", "runtime_address": "0x12340000"},
                "observation": {
                    "content_sha256": "a".repeat(64),
                    "consistency": "revalidated-non-atomic",
                    "atomic_snapshot": false,
                    "identity_scope": "session/process/stop"
                }
            })
        }

        #[test]
        fn opening_and_painting_with_a_socket_does_not_connect_but_query_returns_raw_evidence() {
            let mock = MockSocket::new();
            let ctx = egui::Context::default();
            let mut debugger =
                Debugger { shown: true, socket: mock.path.to_str().unwrap().to_owned(), ..Default::default() };
            for _ in 0..3 {
                let mut output = ctx.run_ui(egui::RawInput::default(), |ui| debugger.show(ui.ctx()));
                output.textures_delta.clear();
                mock.assert_no_connection();
                assert!(!debugger.job.is_running());
            }
            debugger.query(&ctx);
            debugger.request = r#"{"version":1,"operation":"resume"}"#.to_owned();
            debugger.query(&ctx);
            let expected = session_response();
            let request = mock.respond(expected.clone());
            assert_eq!(request["operation"], "describe_session");
            finish(&mut debugger);
            let response: serde_json::Value = serde_json::from_str(debugger.job.ready().unwrap()).unwrap();
            assert_eq!(response, expected);
            assert_eq!(debugger.submitted.as_ref().unwrap().1, template(0));
            mock.assert_no_connection();
        }

        #[test]
        fn an_expired_client_deadline_is_forwarded_without_connecting() {
            let mock = MockSocket::new();
            let request = template(0);
            let error = run_query(mock.path.clone(), request, Instant::now()).unwrap_err();
            assert!(error.contains("deadline"), "{error}");
            mock.assert_no_connection();
        }

        #[test]
        fn unsafe_duplicate_unknown_and_oversized_requests_refuse_before_connecting() {
            let mock = MockSocket::new();
            let requests = [
                r#"{"version":1,"operation":"resume"}"#.to_owned(),
                r#"{"version":1,"operation":"resume","operation":"describe_session"}"#.to_owned(),
                r#"{"version":1,"operation":"describe_session","command":"continue"}"#.to_owned(),
                format!("{}{}", template(0), " ".repeat(MAX_DEBUGGER_REQUEST_BYTES)),
                format!("{}{}", template(0), "é".repeat(MAX_DEBUGGER_REQUEST_BYTES)),
            ];
            for request in requests {
                let mut debugger = Debugger {
                    socket: mock.path.to_str().unwrap().to_owned(),
                    request,
                    job: Job::Done(Ok("old runtime observation".to_owned())),
                    ..Default::default()
                };
                debugger.query(&egui::Context::default());
                assert!(debugger.error.is_some());
                assert!(!debugger.job.is_running());
                assert!(debugger.job.ready().is_none());
                assert!(debugger.submitted.is_none());
                mock.assert_no_connection();
            }
        }

        #[test]
        fn rejected_paste_cannot_dispatch_the_previous_valid_request() {
            let mock = MockSocket::new();
            let mut debugger = Debugger { socket: mock.path.to_str().unwrap().to_owned(), ..Default::default() };
            let original = debugger.request.clone();
            let mut editor = RequestEditor { text: &mut debugger.request, rejected: &mut debugger.request_rejected };
            editor.replace_with(&format!("{original}{}", " ".repeat(MAX_DEBUGGER_REQUEST_BYTES)));
            assert_eq!(debugger.request, original);
            debugger.query(&egui::Context::default());
            assert!(debugger.error.is_some());
            assert!(!debugger.job.is_running());
            mock.assert_no_connection();
        }

        #[test]
        fn stale_token_keeps_the_backend_error_and_clears_old_data_without_a_retry() {
            let mock = MockSocket::new();
            let ctx = egui::Context::default();
            let mut debugger = Debugger { socket: mock.path.to_str().unwrap().to_owned(), ..Default::default() };
            debugger.query(&ctx);
            mock.respond(session_response());
            finish(&mut debugger);
            let previous: serde_json::Value = serde_json::from_str(debugger.job.ready().unwrap()).unwrap();
            debugger.request = serde_json::json!({
                "version": 1,
                "operation": "list_threads",
                "expected_token": previous["token"]
            })
            .to_string();
            debugger.query(&ctx);
            assert!(debugger.job.ready().is_none());
            let expected = serde_json::json!({
                "protocol": "rampage-lldb-query-v1",
                "ok": false,
                "operation": "list_threads",
                "error": {"code": "stale_token", "message": "process stop changed"}
            });
            let request = mock.respond(expected.clone());
            assert_eq!(request["operation"], "list_threads");
            assert_eq!(request["expected_token"], previous["token"]);
            finish(&mut debugger);
            let response: serde_json::Value = serde_json::from_str(debugger.job.ready().unwrap()).unwrap();
            assert_eq!(response, expected);
            assert!(response.get("data").is_none());
            mock.assert_no_connection();
        }
    }
}
