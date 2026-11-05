//! The assistant panel: a conversation with a Claude model about the open binary. The model reads the project
//! through rampage's analysis tools on a background thread; its renames and comments land in the listing, and
//! `show_address` moves the cursor.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};

use egui::{Key, Modifiers, RichText, ScrollArea, TextEdit, Ui};
use rampage_agent::{Agent, Anthropic, Event, RunToken, Transport};
use rampage_api::Project;

use crate::theme;

#[cfg(test)]
mod tests {
    use super::*;
    use rampage_api::tools::Effect;
    use serde_json::{Value, json};
    use std::sync::Mutex;
    use std::time::Duration;

    struct Pending {
        requested: Sender<()>,
        response: Mutex<Receiver<Value>>,
        stopped: Sender<()>,
    }

    impl Transport for Pending {
        fn send(&self, _: &Value) -> Result<Value, String> {
            self.requested.send(()).unwrap();
            self.response.lock().unwrap().recv_timeout(Duration::from_secs(10)).map_err(|error| error.to_string())
        }
    }

    impl Drop for Pending {
        fn drop(&mut self) {
            let _ = self.stopped.send(());
        }
    }

    fn pending() -> (Pending, Receiver<()>, Sender<Value>, Receiver<()>) {
        let (requested, requests) = channel();
        let (response, responses) = channel();
        let (stopped, stops) = channel();
        (Pending { requested, response: Mutex::new(responses), stopped }, requests, response, stops)
    }

    fn project() -> Arc<Project> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
        Arc::new(Project::new(rampage_loaders::Binary::open(path).unwrap()))
    }

    #[test]
    fn tool_effects_drive_refresh_and_navigation_without_name_matching() {
        for (effect, failed, annotations, show) in [
            (Effect::Annotations, false, true, None),
            (Effect::ShowAddress, false, false, Some("0x1000")),
            (Effect::Annotations, true, false, None),
            (Effect::ShowAddress, true, false, None),
            (Effect::None, false, false, None),
            (Effect::FileWrite, false, false, None),
        ] {
            let (sender, receiver) = channel();
            let generation = Arc::new(());
            sender
                .send(RunMessage {
                    generation: Arc::clone(&generation),
                    message: Message::Event(Event::Tool {
                        name: "arbitrary_tool_name".to_owned(),
                        input: serde_json::json!({"at": "0x1000"}),
                        failed,
                        effect,
                    }),
                })
                .unwrap();
            let mut assistant = Assistant {
                running: Some(Running { receiver, token: RunToken::for_project(&project()) }),
                generation,
                ..Default::default()
            };
            let effects = assistant.poll();
            assert_eq!(effects.annotations_changed, annotations);
            assert_eq!(effects.show.as_deref(), show);
            assert_eq!(assistant.transcript.len(), 1);
        }
    }

    #[test]
    fn workspace_snapshot_replacement_cancels_pending_model_and_drops_old_text_navigation_and_conversation() {
        let project = project();
        let ctx = egui::Context::default();
        let mut workspace = crate::workspace::Workspace::from_loaded_project(
            std::path::PathBuf::from("owned.elf"),
            None,
            Arc::clone(&project),
            &ctx,
            true,
            true,
        );
        let (transport, requests, response, stopped) = pending();
        workspace.assistant.start_question(&project, &ctx, "pending A".into(), transport);
        requests.recv_timeout(Duration::from_secs(10)).unwrap();
        let token = workspace.assistant.running.as_ref().unwrap().token.clone();
        let cursor = workspace.cursor;
        project.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap();
        workspace.poll(&ctx);
        assert!(token.is_cancelled());
        assert_eq!(workspace.project.list_patches().unwrap().len(), 1);
        response
            .send(json!({ "content": [
                {"type":"text","text":"stale answer A"},
                {"type":"tool_use","id":"nav","name":"show_address","input":{"at":"0x100191e"}},
                {"type":"tool_use","id":"edit","name":"rename","input":{"at":"main","name":"stale_name"}}
            ]}))
            .unwrap();
        stopped.recv_timeout(Duration::from_secs(10)).unwrap();
        workspace.poll(&ctx);
        assert_eq!(workspace.cursor, cursor);
        assert_eq!(workspace.assistant.transcript.len(), 1);
        assert!(workspace.assistant.agent.is_none());
        assert!(!workspace.assistant.is_running());
        assert!(workspace.project.resolve("stale_name").is_err());
    }

    #[test]
    fn own_patch_and_rename_advance_workspace_without_cancelling_run_or_losing_receipts_and_conversation() {
        let root = project();
        let receipt = root.patch_receipt().unwrap();
        let project = root.effective_snapshot().unwrap();
        let ctx = egui::Context::default();
        let mut workspace = crate::workspace::Workspace::from_loaded_project(
            std::path::PathBuf::from("owned.elf"),
            None,
            Arc::clone(&project),
            &ctx,
            true,
            true,
        );
        let (transport, requests, response, stopped) = pending();
        workspace.assistant.start_question(&project, &ctx, "own patch".into(), transport);
        requests.recv_timeout(Duration::from_secs(10)).unwrap();
        let token = workspace.assistant.running.as_ref().unwrap().token.clone();
        response
            .send(json!({"content":[
                {"type":"tool_use","id":"patch","name":"patch_bytes","input":{
                    "at":"0x100191e","original_hex":"b805000000","replacement_hex":"b807000000",
                    "allow_data":false,"source_sha256":receipt.source_sha256,"expected_revision":receipt.revision_sha256
                }},
                {"type":"tool_use","id":"rename","name":"rename","input":{"at":"main","name":"owned_main"}}
            ]}))
            .unwrap();
        requests.recv_timeout(Duration::from_secs(10)).unwrap();
        workspace.poll(&ctx);
        assert!(!token.is_cancelled(), "own transition must not look external");
        assert!(workspace.assistant.is_running());
        assert!(workspace.project.resolve("owned_main").is_ok());
        assert_eq!(workspace.project.list_patches().unwrap().len(), 1);
        let receipts = workspace
            .assistant
            .transcript
            .iter()
            .filter(|entry| matches!(entry, Entry::Receipt { failed: false, .. }))
            .count();
        assert_eq!(receipts, 2);
        response.send(json!({"content":[{"type":"text","text":"completed on my new revision"}]})).unwrap();
        stopped.recv_timeout(Duration::from_secs(10)).unwrap();
        workspace.poll(&ctx);
        assert!(workspace.assistant.agent.is_some());
        assert!(workspace.assistant.transcript.iter().any(|entry| matches!(entry,
            Entry::Answer(text) if text == "completed on my new revision")));
        assert_eq!(
            workspace.assistant.transcript.iter().filter(|entry| matches!(entry, Entry::Receipt { .. })).count(),
            2
        );
    }

    #[test]
    fn own_live_root_rename_does_not_authorize_a_later_external_annotation_revision() {
        let project = project();
        let ctx = egui::Context::default();
        let mut assistant = Assistant::default();
        let (transport, requests, response, stopped) = pending();
        assistant.start_question(&project, &ctx, "rename on live original".into(), transport);
        requests.recv_timeout(Duration::from_secs(10)).unwrap();
        response
            .send(json!({"content":[
                {"type":"tool_use","id":"rename","name":"rename","input":{"at":"main","name":"own_name"}}
            ]}))
            .unwrap();
        requests.recv_timeout(Duration::from_secs(10)).unwrap();
        assistant.poll();
        assert!(assistant.is_running());
        project.comment(project.resolve("own_name").unwrap(), Some("external annotation")).unwrap();
        response
            .send(json!({"content":[
                {"type":"text","text":"stale after external comment"},
                {"type":"tool_use","id":"late","name":"rename","input":{"at":"own_name","name":"must_not_run"}}
            ]}))
            .unwrap();
        stopped.recv_timeout(Duration::from_secs(10)).unwrap();
        let effects = assistant.poll();
        assert!(effects.show.is_none());
        assert!(assistant.agent.is_none());
        assert!(project.resolve("must_not_run").is_err());
        assert!(!assistant.transcript.iter().any(|entry| matches!(entry,
            Entry::Answer(text) if text == "stale after external comment")));
        assert_eq!(assistant.transcript.iter().filter(|entry| matches!(entry, Entry::Receipt { .. })).count(), 1);
    }

    #[test]
    fn cancellation_discards_model_channel_but_drains_completed_mutation_evidence_once() {
        let project = project();
        let ctx = egui::Context::default();
        let mut assistant = Assistant::default();
        let (transport, requests, response, stopped) = pending();
        assistant.start_question(&project, &ctx, "retain commit evidence".into(), transport);
        requests.recv_timeout(Duration::from_secs(10)).unwrap();
        response
            .send(json!({"content":[
                {"type":"tool_use","id":"rename","name":"rename","input":{"at":"main","name":"committed_before_cancel"}}
            ]}))
            .unwrap();
        requests.recv_timeout(Duration::from_secs(10)).unwrap();
        assistant.cancel();
        assistant.poll();
        response.send(json!({"content":[
            {"type":"text","text":"cancelled text"},
            {"type":"tool_use","id":"late","name":"rename","input":{"at":"committed_before_cancel","name":"too_late"}}
        ]})).unwrap();
        stopped.recv_timeout(Duration::from_secs(10)).unwrap();
        assistant.poll();
        assert!(assistant.agent.is_none());
        assert!(!assistant.is_running());
        assert!(project.resolve("committed_before_cancel").is_ok());
        assert!(project.resolve("too_late").is_err());
        let receipts = assistant
            .transcript
            .iter()
            .filter(|entry| {
                matches!(entry,
            Entry::Receipt { name, output, failed: false }
                if name == "rename" && output.contains("committed_before_cancel"))
            })
            .count();
        assert_eq!(receipts, 1);
        assert!(!assistant.transcript.iter().any(|entry| matches!(entry, Entry::Answer(_))));
    }

    #[test]
    fn closing_workspace_while_model_is_pending_stops_following_rename_patch_and_export_admission() {
        let project = project();
        let receipt = project.patch_receipt().unwrap();
        let project = project.effective_snapshot().unwrap();
        let ctx = egui::Context::default();
        let mut workspace = crate::workspace::Workspace::from_loaded_project(
            std::path::PathBuf::from("owned.elf"),
            None,
            Arc::clone(&project),
            &ctx,
            true,
            true,
        );
        let (transport, requests, response, stopped) = pending();
        workspace.assistant.start_question(&project, &ctx, "close pending A".into(), transport);
        requests.recv_timeout(Duration::from_secs(10)).unwrap();
        let token = workspace.assistant.running.as_ref().unwrap().token.clone();
        drop(workspace);
        assert!(token.is_cancelled());
        response
            .send(json!({"content":[
                {"type":"tool_use","id":"rename","name":"rename","input":{"at":"main","name":"closed_name"}},
                {"type":"tool_use","id":"patch","name":"patch_bytes","input":{
                    "at":"0x100191e","original_hex":"b805000000","replacement_hex":"b807000000",
                    "allow_data":false,"source_sha256":receipt.source_sha256,"expected_revision":receipt.revision_sha256
                }},
                {"type":"tool_use","id":"export","name":"export_patched","input":{}}
            ]}))
            .unwrap();
        stopped.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(project.resolve("closed_name").is_err());
        assert!(project.list_patches().unwrap().is_empty());
    }

    #[test]
    fn dropping_run_receiver_and_event_send_failure_both_cancel_the_executor_token() {
        let (sender, receiver) = channel();
        let token = RunToken::for_project(&project());
        let running = Running { receiver, token: token.clone() };
        drop(running);
        assert!(token.is_cancelled());
        let (sender2, receiver2) = channel();
        drop(receiver2);
        let token2 = RunToken::default();
        assert!(!send(&sender2, &token2, &Arc::new(()), Message::Event(Event::Text("orphan".into()))));
        assert!(token2.is_cancelled());
        drop(sender);
    }

    #[test]
    fn stale_generation_messages_cannot_publish_navigation_or_restore_conversation() {
        let (sender, receiver) = channel();
        let project = project();
        let stale = Arc::new(());
        for message in [
            Message::Event(Event::Text("stale".into())),
            Message::Event(Event::Tool {
                name: "show_address".into(),
                input: json!({"at":"main"}),
                failed: false,
                effect: Effect::ShowAddress,
            }),
            Message::Finished(Box::new(Agent::new(&project)), Ok(())),
        ] {
            sender.send(RunMessage { generation: Arc::clone(&stale), message }).unwrap();
        }
        let mut assistant = Assistant {
            running: Some(Running { receiver, token: RunToken::for_project(&project) }),
            ..Default::default()
        };
        let effects = assistant.poll();
        assert!(effects.show.is_none());
        assert!(assistant.transcript.is_empty());
        assert!(assistant.agent.is_none());
    }
}

pub enum Entry {
    Question(String),
    Answer(String),
    /// A tool call, summarized: its name and main argument.
    Tool {
        summary: String,
        failed: bool,
    },
    Error(String),
    Receipt {
        name: String,
        output: String,
        failed: bool,
    },
}

enum Message {
    Event(Event),
    Finished(Box<Agent>, Result<(), String>),
}

struct RunMessage {
    generation: Arc<()>,
    message: Message,
}

struct Running {
    receiver: Receiver<RunMessage>,
    token: RunToken,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

fn send(sender: &Sender<RunMessage>, token: &RunToken, generation: &Arc<()>, message: Message) -> bool {
    if token.is_cancelled() {
        return false;
    }
    if sender.send(RunMessage { generation: Arc::clone(generation), message }).is_err() {
        token.cancel();
        return false;
    }
    !token.is_cancelled()
}

#[derive(Default)]
pub struct Assistant {
    pub transcript: Vec<Entry>,
    pub input: String,
    agent: Option<Box<Agent>>,
    running: Option<Running>,
    generation: Arc<()>,
    retired: Vec<RunToken>,
    pending_effects: Effects,
}

/// What the workspace should do after the model's tools ran.
#[derive(Default)]
pub struct Effects {
    pub annotations_changed: bool,
    pub show: Option<String>,
    pub project: Option<Arc<Project>>,
    pub pending: bool,
    pub stale: bool,
}

impl Assistant {
    /// Stops future work but retains in-flight completion evidence for this panel. Closing the panel's owner
    /// discards that UI handoff; it does not undo an already-admitted tool or claim its receipt was delivered.
    pub(crate) fn cancel(&mut self) {
        if let Some(running) = self.running.take() {
            running.token.cancel();
            self.retired.push(running.token.clone());
        }
        self.agent = None;
        self.generation = Arc::new(());
        self.pending_effects = Effects::default();
    }

    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }

    /// Sends the typed question to the model on a background thread.
    pub fn ask(&mut self, project: &Arc<Project>, ctx: &egui::Context) {
        let question = self.input.trim().to_owned();
        if question.is_empty() || self.is_running() {
            return;
        }
        let Some(transport) = Anthropic::from_environment() else {
            self.transcript.push(Entry::Error("Set ANTHROPIC_API_KEY to use the assistant.".to_owned()));
            return;
        };
        self.start_question(project, ctx, question, transport);
    }

    fn start_question(
        &mut self,
        project: &Arc<Project>,
        ctx: &egui::Context,
        question: String,
        transport: impl Transport + 'static,
    ) {
        self.input.clear();
        self.transcript.push(Entry::Question(question.clone()));
        let mut agent = self.agent.take().unwrap_or_else(|| Box::new(Agent::new(project)));
        let project = Arc::clone(project);
        let (sender, receiver) = channel();
        let ctx = ctx.clone();
        let token = RunToken::for_project(&project);
        let run_token = token.clone();
        let generation = Arc::clone(&self.generation);
        std::thread::spawn(move || {
            let events = sender.clone();
            let repaint = ctx.clone();
            let result = agent.ask_shared_cancellable(&transport, &project, &question, &run_token, &mut |event| {
                let sent = send(&events, &run_token, &generation, Message::Event(event));
                if sent {
                    repaint.request_repaint();
                }
                sent
            });
            let _ = send(&sender, &run_token, &generation, Message::Finished(agent, result));
            ctx.request_repaint();
        });
        self.running = Some(Running { receiver, token });
    }

    /// Collects progress from the background conversation.
    pub fn poll(&mut self) -> Effects {
        let retired_annotations = self.collect_outcomes();
        let mut effects = std::mem::take(&mut self.pending_effects);
        let Some(running) = &self.running else {
            effects.stale |= retired_annotations;
            return effects;
        };
        let view = running.token.inspect_project(|project, revision_matches| {
            project
                .effective_snapshot()
                .ok()
                .filter(|current| revision_matches && rampage_api::tools::same_effective_revision(current, project))
        });
        if view.is_none() && !running.token.is_cancelled() {
            self.pending_effects = effects;
            return Effects { pending: true, ..Default::default() };
        }
        if running.token.is_cancelled() || view.as_ref().is_some_and(Option::is_none) {
            self.cancel();
            self.collect_outcomes();
            return Effects { stale: true, ..Default::default() };
        }
        effects.project = view.flatten();
        loop {
            let view = running.token.inspect_project(|project, revision_matches| {
                project
                    .effective_snapshot()
                    .ok()
                    .filter(|current| revision_matches && rampage_api::tools::same_effective_revision(current, project))
            });
            if view.is_none() && !running.token.is_cancelled() {
                effects.pending = true;
                break;
            }
            if running.token.is_cancelled() || view.as_ref().is_some_and(Option::is_none) {
                self.cancel();
                self.collect_outcomes();
                return Effects { stale: true, ..Default::default() };
            }
            effects.project = view.flatten();
            let message = match running.receiver.try_recv() {
                Ok(message) if Arc::ptr_eq(&message.generation, &self.generation) && !running.token.is_cancelled() => {
                    message.message
                }
                Ok(_) => continue,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.transcript.push(Entry::Error("the assistant stopped unexpectedly".to_owned()));
                    self.retired.push(running.token.clone());
                    self.running = None;
                    break;
                }
            };
            match message {
                Message::Event(Event::Text(text)) => self.transcript.push(Entry::Answer(text)),
                Message::Event(Event::Tool { name, input, failed, effect }) => {
                    let argument = ["at", "to", "from", "name_contains", "contains"]
                        .iter()
                        .find_map(|key| input[key].as_str())
                        .unwrap_or("");
                    if !failed {
                        match effect {
                            rampage_api::tools::Effect::Annotations => effects.annotations_changed = true,
                            rampage_api::tools::Effect::ShowAddress => effects.show = Some(argument.to_owned()),
                            // The assistant is not offered debug tools; nothing else has an execution effect.
                            rampage_api::tools::Effect::None
                            | rampage_api::tools::Effect::FileWrite
                            | rampage_api::tools::Effect::Execution => {}
                        }
                    }
                    self.transcript.push(Entry::Tool { summary: format!("{name} {argument}"), failed });
                }
                Message::Finished(agent, result) => {
                    self.agent = Some(agent);
                    if let Err(error) = result {
                        self.transcript.push(Entry::Error(error));
                    }
                    self.retired.push(running.token.clone());
                    self.running = None;
                    break;
                }
            }
        }
        let retired_annotations = self.collect_outcomes();
        effects.stale |= retired_annotations && effects.project.is_none();
        if effects.pending {
            effects.pending = false;
            self.pending_effects = effects;
            Effects { pending: true, ..Default::default() }
        } else {
            effects
        }
    }

    fn collect_outcomes(&mut self) -> bool {
        let transcript = &mut self.transcript;
        let mut annotations = false;
        self.retired.retain(|token| {
            let (outcomes, pending) = token.drain_tool_outcomes();
            for outcome in outcomes {
                annotations |= !outcome.failed && outcome.effect == rampage_api::tools::Effect::Annotations;
                if outcome.unattributable {
                    transcript.push(Entry::Error(
                        "Run stopped: unattributable annotation transition. The completed tool result was not rolled back.".to_owned(),
                    ));
                }
                transcript.push(Entry::Receipt { name: outcome.name, output: outcome.output, failed: outcome.failed });
            }
            pending
        });
        if let Some(running) = &self.running {
            for outcome in running.token.take_tool_outcomes() {
                if outcome.unattributable {
                    transcript.push(Entry::Error(
                        "Run stopped: unattributable annotation transition. The completed tool result was not rolled back.".to_owned(),
                    ));
                }
                transcript.push(Entry::Receipt { name: outcome.name, output: outcome.output, failed: outcome.failed });
            }
        }
        annotations
    }
}

/// The panel: the conversation, and a box to ask in below it. Returns whether a question was submitted.
pub fn show(ui: &mut Ui, assistant: &mut Assistant) -> bool {
    const INPUT_HEIGHT: f32 = 96.0;
    ScrollArea::vertical()
        .auto_shrink([false, false])
        .stick_to_bottom(true)
        .max_height((ui.available_height() - INPUT_HEIGHT).max(40.0))
        .show(ui, |ui| {
            if assistant.transcript.is_empty() {
                ui.label(
                    RichText::new(
                        "Ask about the binary: what a function does, where a string is used, what to rename.",
                    )
                    .color(theme::DIM),
                );
            }
            for entry in &assistant.transcript {
                match entry {
                    Entry::Question(text) => {
                        ui.add_space(6.0);
                        ui.label(RichText::new(text).strong().color(theme::LINK));
                    }
                    Entry::Answer(text) => {
                        ui.label(text);
                    }
                    Entry::Tool { summary, failed } => {
                        let color = if *failed { theme::WARNING } else { theme::FAINT };
                        ui.label(RichText::new(format!("> {summary}")).monospace().small().color(color));
                    }
                    Entry::Error(text) => {
                        ui.label(RichText::new(text).color(theme::WARNING));
                    }
                    Entry::Receipt { name, output, failed } => {
                        ui.collapsing(
                            format!("{name}: {}", if *failed { "tool error" } else { "completed result" }),
                            |ui| {
                                ui.monospace(output);
                            },
                        );
                    }
                }
            }
        });
    ui.separator();
    let input = ui.add(
        TextEdit::multiline(&mut assistant.input)
            .hint_text("Ask about this binary (Enter to send)")
            .desired_rows(2)
            .desired_width(f32::INFINITY),
    );
    // Enter sends; Shift+Enter starts a new line.
    let mut submit = input.has_focus() && ui.input_mut(|input| input.consume_key(Modifiers::NONE, Key::Enter));
    ui.horizontal(|ui| {
        let busy = assistant.is_running();
        submit |= ui.add_enabled(!busy, egui::Button::new("Ask")).clicked();
        if busy {
            ui.spinner();
        }
    });
    ui.label(RichText::new("Questions and the code the model reads go to Anthropic's API.").small().color(theme::DIM));
    submit
}
