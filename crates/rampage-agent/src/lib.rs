//! An AI assistant for an open binary: a conversation with a Claude model that answers by calling rampage's
//! analysis tools on the project, through the Anthropic Messages API.

use rampage_api::Project;
use rampage_api::tools::{self, Effect, Tool};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Cancels future model requests, event publication and tool admission. A synchronous tool already admitted
/// is not interrupted or rolled back; cancellation after its completion returns its actual result.
#[derive(Clone, Default)]
pub struct RunToken {
    cancelled: Arc<AtomicBool>,
    state: Arc<Mutex<RunState>>,
}

#[derive(Default)]
struct RunState {
    project: Option<Arc<Project>>,
    revision: Option<Arc<()>>,
    admitted: bool,
    outcomes: Vec<ToolOutcome>,
    unattributable: bool,
}

/// Evidence from an admitted mutating tool, available exactly once even if cancellation raced its completion.
#[derive(Clone)]
pub struct ToolOutcome {
    pub name: String,
    pub output: String,
    pub failed: bool,
    pub effect: Effect,
    pub unattributable: bool,
}

impl RunToken {
    pub fn for_project(project: &Arc<Project>) -> Self {
        let token = Self::default();
        token.bind(project);
        token
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    fn cancel_unattributable(&self) {
        self.state.lock().expect("run state").unattributable = true;
        self.cancel();
    }

    fn unattributable(&self) -> bool {
        self.state.lock().expect("run state").unattributable
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn check(&self) -> Result<(), String> {
        if self.is_cancelled() { Err("assistant run cancelled".to_owned()) } else { Ok(()) }
    }

    fn bind(&self, project: &Arc<Project>) {
        let mut state = self.state.lock().expect("run state");
        if state.project.is_none() {
            state.project = Some(Arc::clone(project));
            state.revision = project.annotation_revision().ok();
        }
    }

    /// Inspects the run-owned view while preventing new tool admission. None means a tool is still in flight.
    pub fn inspect_project<R>(&self, inspect: impl FnOnce(&Arc<Project>, bool) -> R) -> Option<R> {
        let state = self.state.lock().expect("run state");
        if state.admitted {
            return None;
        }
        state.project.as_ref().map(|project| {
            let matches = state.revision.as_ref().is_some_and(|expected| {
                project.annotation_revision().is_ok_and(|current| Arc::ptr_eq(&current, expected))
            });
            inspect(project, matches)
        })
    }

    /// Drains admitted mutation/export results, including completion after cancellation. Dropping every token
    /// discards undelivered evidence; this is an in-memory handoff, not a durable audit log.
    pub fn take_tool_outcomes(&self) -> Vec<ToolOutcome> {
        self.drain_tool_outcomes().0
    }

    pub fn drain_tool_outcomes(&self) -> (Vec<ToolOutcome>, bool) {
        let mut state = self.state.lock().expect("run state");
        (std::mem::take(&mut state.outcomes), state.admitted)
    }

    fn admit(&self) -> Result<(), String> {
        let mut state = self.state.lock().expect("run state");
        self.check()?;
        if state.admitted {
            return Err("assistant run already has an admitted tool".to_owned());
        }
        state.admitted = true;
        Ok(())
    }

    fn advance(&self, project: &Arc<Project>, revision: Arc<()>) {
        let mut state = self.state.lock().expect("run state");
        state.project = Some(Arc::clone(project));
        state.revision = Some(revision);
    }

    fn complete(&self, outcome: ToolOutcome) {
        let mut state = self.state.lock().expect("run state");
        if matches!(outcome.effect, Effect::Annotations | Effect::FileWrite) {
            state.outcomes.push(outcome);
        }
        state.admitted = false;
    }
}

fn publish(token: &RunToken, on_event: &mut dyn FnMut(Event) -> bool, event: Event) -> Result<(), String> {
    token.check()?;
    if !on_event(event) {
        token.cancel();
    }
    token.check()
}

/// The model used unless `RAMPAGE_MODEL` names another.
pub const DEFAULT_MODEL: &str = "claude-opus-5-5";
const MAX_TOKENS: u32 = 4096;
/// Model turns allowed for one question, so that a confused loop of tool calls ends.
const MAX_TURNS: usize = 30;

/// Sends a Messages API request and returns the response.
pub trait Transport: Send {
    fn send(&self, request: &Value) -> Result<Value, String>;
}

/// The Anthropic API over HTTPS.
pub struct Anthropic {
    api_key: String,
    url: String,
}

impl Anthropic {
    /// Reads the key from `ANTHROPIC_API_KEY`.
    pub fn from_environment() -> Option<Self> {
        let api_key = std::env::var("ANTHROPIC_API_KEY").ok().filter(|key| !key.is_empty())?;
        Some(Self { api_key, url: "https://api.anthropic.com/v1/messages".to_owned() })
    }
}

impl Transport for Anthropic {
    fn send(&self, request: &Value) -> Result<Value, String> {
        let response = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(15))
            .timeout_read(std::time::Duration::from_secs(300))
            .build()
            .post(&self.url)
            .set("x-api-key", &self.api_key)
            .set("anthropic-version", "2023-06-01")
            .send_json(request);
        match response {
            Ok(response) => response.into_json().map_err(|error| error.to_string()),
            Err(ureq::Error::Status(status, response)) => {
                let body: Value = response.into_json().unwrap_or_default();
                let message = body["error"]["message"].as_str().unwrap_or("request failed").to_owned();
                Err(format!("Anthropic API error {status}: {message}"))
            }
            Err(error) => Err(error.to_string()),
        }
    }
}

/// Something that happened while answering, for the user to watch.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// Text the model wrote.
    Text(String),
    /// A tool the model called, with its input and whether it failed.
    Tool { name: String, input: Value, failed: bool, effect: Effect },
}

/// A conversation about one binary.
pub struct Agent {
    model: String,
    system: String,
    messages: Vec<Value>,
    tools: Vec<Tool>,
}

type ToolDispatcher<'a> = dyn FnMut(&[Tool], &str, Value) -> (String, bool) + 'a;

impl Agent {
    pub fn new(project: &Project) -> Self {
        let summary = project.summary();
        let system = format!(
            "You are a reverse engineer working in rampage, an interactive disassembler, with the user. The open \
             binary is a {:?} {} image with {} symbols, {} imports and {} exports. Answer from evidence: use the \
             tools to read functions, strings, imports and cross-references, and cite addresses (as 0x...). When you \
             work out what a function or address is, rename it or comment it so that the user's listing shows it. \
             Use show_address to point the user at code you discuss. Be concise.",
            summary.format, summary.arch, summary.symbols, summary.imports, summary.exports
        );
        let model = std::env::var("RAMPAGE_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_owned());
        Self { model, system, messages: Vec::new(), tools: tools::tools() }
    }

    /// Asks `question`, running the tools the model calls until it answers. Reports progress to `on_event`. On
    /// failure the conversation returns to where it was before the question, so it stays valid for the API.
    pub fn ask(
        &mut self,
        transport: &dyn Transport,
        project: &Project,
        question: &str,
        on_event: &mut dyn FnMut(Event),
    ) -> Result<(), String> {
        let checkpoint = self.messages.len();
        let token = RunToken::default();
        let result = self.answer(
            transport,
            question,
            &token,
            &mut |event| {
                on_event(event);
                true
            },
            &mut || Ok(()),
            &mut |tools, name, input| match tools::check_tool_arguments(tools, name, &input) {
                Ok(()) => tools::call(tools, project, name, input),
                Err(error) => (error, true),
            },
        );
        if result.is_err() {
            self.messages.truncate(checkpoint);
        }
        result
    }

    /// Asks using shared immutable effective snapshots, including after patch and annotation mutations.
    pub fn ask_shared(
        &mut self,
        transport: &dyn Transport,
        project: &std::sync::Arc<Project>,
        question: &str,
        on_event: &mut dyn FnMut(Event),
    ) -> Result<(), String> {
        self.ask_shared_cancellable(transport, project, question, &RunToken::default(), &mut |event| {
            on_event(event);
            true
        })
    }

    /// Stops a run when cancelled, its held snapshot changes, or its event receiver disappears.
    /// Returning false from `on_event` cancels before any following tool dispatch.
    pub fn ask_shared_cancellable(
        &mut self,
        transport: &dyn Transport,
        project: &Arc<Project>,
        question: &str,
        token: &RunToken,
        on_event: &mut dyn FnMut(Event) -> bool,
    ) -> Result<(), String> {
        let checkpoint = self.messages.len();
        token.bind(project);
        let revision = std::cell::RefCell::new(token.state.lock().expect("run state").revision.clone());
        let project = std::cell::RefCell::new(Arc::clone(project));
        let result = self.answer(
            transport,
            question,
            token,
            on_event,
            &mut || {
                token.check()?;
                let held = project.borrow();
                let current = held.effective_snapshot().map_err(|error| error.to_string())?;
                let matches = revision
                    .borrow()
                    .as_ref()
                    .is_some_and(|expected| held.annotation_revision().is_ok_and(|now| Arc::ptr_eq(&now, expected)));
                if !tools::same_effective_revision(&held, &current) || !matches {
                    token.cancel();
                    return Err("assistant snapshot changed; run cancelled".to_owned());
                }
                drop(held);
                if let Some(stamp) = revision.borrow().as_ref() {
                    token.advance(&current, Arc::clone(stamp));
                }
                *project.borrow_mut() = current;
                Ok(())
            },
            &mut |tools, name, input| {
                // Unknown or missing arguments are refused, naming the tool's arguments, before admission.
                if let Err(error) = tools::check_tool_arguments(tools, name, &input) {
                    return (error, true);
                }
                let (result, stamp) = tools::call_shared_bound_revision(
                    tools,
                    &mut project.borrow_mut(),
                    name,
                    input,
                    revision.borrow().as_ref(),
                );
                let annotates = tools.iter().any(|tool| tool.name == name && tool.effect == Effect::Annotations);
                if !result.1 && annotates {
                    if let Some(stamp) = stamp {
                        token.advance(&project.borrow(), Arc::clone(&stamp));
                        *revision.borrow_mut() = Some(stamp);
                    } else {
                        token.cancel_unattributable();
                    }
                }
                result
            },
        );
        if result.is_err() {
            self.messages.truncate(checkpoint);
        }
        result
    }

    fn answer(
        &mut self,
        transport: &dyn Transport,
        question: &str,
        token: &RunToken,
        on_event: &mut dyn FnMut(Event) -> bool,
        current: &mut dyn FnMut() -> Result<(), String>,
        call: &mut ToolDispatcher<'_>,
    ) -> Result<(), String> {
        self.messages.push(json!({ "role": "user", "content": question }));
        let definitions: Vec<Value> = self.tools.iter().map(Tool::definition).collect();
        for _ in 0..MAX_TURNS {
            token.check()?;
            current()?;
            self.elide_old_results();
            let request = json!({
                "model": self.model,
                "max_tokens": MAX_TOKENS,
                "system": self.system,
                "tools": definitions,
                "messages": self.messages,
            });
            let response = transport.send(&request)?;
            token.check()?;
            current()?;
            let content = match response["content"].as_array() {
                Some(content) if !content.is_empty() => content.clone(),
                _ => return Err("the model returned an empty reply".to_owned()),
            };
            self.messages.push(json!({ "role": "assistant", "content": content }));
            let mut results = Vec::new();
            for block in &content {
                token.check()?;
                current()?;
                match block["type"].as_str() {
                    Some("text") => {
                        publish(token, on_event, Event::Text(block["text"].as_str().unwrap_or("").to_owned()))?
                    }
                    Some("tool_use") => {
                        let name = block["name"].as_str().unwrap_or("");
                        let input = block["input"].clone();
                        token.check()?;
                        current()?;
                        token.admit()?;
                        let (output, failed) = call(&self.tools, name, input.clone());
                        let effect =
                            self.tools.iter().find(|tool| tool.name == name).map_or(Effect::None, |tool| tool.effect);
                        token.complete(ToolOutcome {
                            name: name.to_owned(),
                            output: output.clone(),
                            failed,
                            effect,
                            unattributable: token.unattributable(),
                        });
                        if token.is_cancelled() {
                            let status = if token.unattributable() {
                                "assistant run terminated: unattributable annotation transition"
                            } else {
                                "assistant run cancelled"
                            };
                            return Err(format!(
                                "{status} after tool {name} completed; failed={failed}; \
                                 tool result (not rolled back): {output}"
                            ));
                        }
                        if let Err(error) = current().and_then(|()| {
                            publish(token, on_event, Event::Tool { name: name.to_owned(), input, failed, effect })
                        }) {
                            return Err(format!(
                                "{error}; tool {name} completed; failed={failed}; \
                                tool result (not rolled back): {output}"
                            ));
                        }
                        results.push(json!({
                            "type": "tool_result",
                            "tool_use_id": block["id"],
                            "content": output,
                            "is_error": failed,
                        }));
                    }
                    _ => {}
                }
            }
            // Every tool call needs its result before the conversation goes on, whatever made the reply stop.
            if results.is_empty() {
                if response["stop_reason"] == "max_tokens" {
                    publish(token, on_event, Event::Text("(The answer was cut off at the length limit.)".to_owned()))?;
                }
                return Ok(());
            }
            self.messages.push(json!({ "role": "user", "content": results }));
        }
        Err(format!("stopped after {MAX_TURNS} model turns"))
    }

    /// Keeps the conversation within budget by replacing the oldest tool results with a note: the model has
    /// already read them, and its answers carry what it learned.
    fn elide_old_results(&mut self) {
        let size = |messages: &[Value]| messages.iter().map(|message| message.to_string().len()).sum::<usize>();
        let mut total = size(&self.messages);
        for message in &mut self.messages {
            if total <= MAX_CONVERSATION_CHARS {
                break;
            }
            let Some(blocks) = message["content"].as_array_mut() else { continue };
            for block in blocks.iter_mut().filter(|block| block["type"] == "tool_result") {
                let before = block["content"].to_string().len();
                if before > ELIDED.len() {
                    block["content"] = json!(ELIDED);
                    total -= before - ELIDED.len();
                }
            }
        }
    }
}

/// The conversation size, in characters of JSON, beyond which old tool results are dropped.
const MAX_CONVERSATION_CHARS: usize = 300_000;
const ELIDED: &str = "(earlier result elided to save space; call the tool again if needed)";

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Mutex;

    use rampage_loaders::Binary;

    use super::*;

    /// Replies with scripted responses and records the requests.
    struct Script {
        responses: Mutex<Vec<Value>>,
        requests: Mutex<Vec<Value>>,
    }

    impl Transport for Script {
        fn send(&self, request: &Value) -> Result<Value, String> {
            self.requests.lock().unwrap().push(request.clone());
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() { Err("no more responses".to_owned()) } else { Ok(responses.remove(0)) }
        }
    }

    /// A project whose annotations stay in memory, so tests leave the fixtures alone.
    fn project(name: &str) -> Project {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name);
        Project::new(Binary::open(path).unwrap())
    }

    #[test]
    fn disconnected_event_sink_stops_executor_before_any_following_tool_dispatch() {
        let project = Arc::new(project("hello-x64.elf"));
        let script = Script {
            responses: Mutex::new(vec![json!({"content":[
                {"type":"text","text":"receiver disappeared"},
                {"type":"tool_use","id":"rename","name":"rename","input":{"at":"main","name":"orphan"}},
                {"type":"tool_use","id":"patch","name":"patch_bytes","input":{}},
                {"type":"tool_use","id":"export","name":"export_patched","input":{}}
            ]})]),
            requests: Mutex::new(Vec::new()),
        };
        let token = RunToken::default();
        let mut agent = Agent::new(&project);
        let result = agent.ask_shared_cancellable(&script, &project, "orphan run", &token, &mut |_| false);
        assert!(result.unwrap_err().contains("cancelled"));
        assert!(token.is_cancelled());
        assert!(project.resolve("orphan").is_err());
        assert!(project.list_patches().unwrap().is_empty());
        assert_eq!(script.requests.lock().unwrap().len(), 1);
        assert!(agent.messages.is_empty());
    }

    #[test]
    fn event_delivery_failure_admits_no_following_rename_patch_or_export_handler() {
        let project = project("hello-x64.elf");
        let script = Script {
            responses: Mutex::new(vec![json!({"content":[
                {"type":"text","text":"undeliverable"},
                {"type":"tool_use","id":"rename","name":"rename","input":{}},
                {"type":"tool_use","id":"patch","name":"patch_bytes","input":{}},
                {"type":"tool_use","id":"export","name":"export_patched","input":{}}
            ]})]),
            requests: Mutex::new(Vec::new()),
        };
        let mut calls = Vec::new();
        let token = RunToken::default();
        let error = Agent::new(&project)
            .answer(&script, "disconnected receiver", &token, &mut |_| false, &mut || Ok(()), &mut |_, name, _| {
                calls.push(name.to_owned());
                ("{}".into(), false)
            })
            .unwrap_err();
        assert!(error.contains("cancelled"));
        assert!(calls.is_empty(), "no tool may be admitted after delivery failure");
    }

    #[test]
    fn executor_rejects_model_reply_if_its_project_snapshot_changed_while_transport_was_pending() {
        struct Changing(Arc<Project>);
        impl Transport for Changing {
            fn send(&self, _: &Value) -> Result<Value, String> {
                self.0.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap();
                Ok(json!({"content":[
                    {"type":"text","text":"old snapshot answer"},
                    {"type":"tool_use","id":"rename","name":"rename","input":{"at":"main","name":"stale"}}
                ]}))
            }
        }
        let project = Arc::new(project("hello-x64.elf"));
        let token = RunToken::default();
        let mut events = Vec::new();
        let mut agent = Agent::new(&project);
        let error = agent
            .ask_shared_cancellable(&Changing(Arc::clone(&project)), &project, "snapshot A", &token, &mut |event| {
                events.push(event);
                true
            })
            .unwrap_err();
        assert!(error.contains("snapshot changed"), "{error}");
        assert!(events.is_empty());
        assert!(token.is_cancelled());
        assert!(project.effective_snapshot().unwrap().resolve("stale").is_err());
        assert!(agent.messages.is_empty());
    }

    #[test]
    fn cancellation_during_an_admitted_mutation_reports_actual_commit_and_stops_next_dispatch() {
        let project = Arc::new(project("hello-x64.elf"));
        let script = Script {
            responses: Mutex::new(vec![json!({"content":[
                {"type":"tool_use","id":"first","name":"rename","input":{}},
                {"type":"tool_use","id":"second","name":"export_patched","input":{}}
            ]})]),
            requests: Mutex::new(Vec::new()),
        };
        let token = RunToken::for_project(&project);
        assert!(token.inspect_project(|_, matches| matches).unwrap());
        let cancel = token.clone();
        let (admitted, admission) = std::sync::mpsc::channel();
        let (cancelled, cancellation) = std::sync::mpsc::channel();
        let canceller = std::thread::spawn(move || {
            admission.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            assert!(cancel.inspect_project(|_, _| ()).is_none(), "UI must defer during an admitted tool");
            cancel.cancel();
            cancelled.send(()).unwrap();
        });
        let mut dispatched = Vec::new();
        let mut agent = Agent::new(&project);
        let error = agent
            .answer(
                &script,
                "admitted mutation",
                &token,
                &mut |_| panic!("stale publication"),
                &mut || Ok(()),
                &mut |_, name, _| {
                    dispatched.push(name.to_owned());
                    admitted.send(()).unwrap();
                    cancellation.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
                    let edit = project.rename(project.resolve("main").unwrap(), Some("committed_name")).unwrap();
                    (serde_json::to_string(&edit).unwrap(), false)
                },
            )
            .unwrap_err();
        canceller.join().unwrap();
        assert_eq!(dispatched, ["rename"]);
        let outcomes = token.take_tool_outcomes();
        assert_eq!(outcomes.len(), 1);
        assert!(!outcomes[0].failed);
        assert!(outcomes[0].output.contains("committed_name"));
        assert!(token.take_tool_outcomes().is_empty(), "terminal evidence is delivered exactly once");
        assert!(project.resolve("committed_name").is_ok());
        assert!(
            error.contains("not rolled back") && error.contains("committed_name") && error.contains("failed=false"),
            "{error}"
        );
    }

    #[test]
    fn unattributable_admitted_patch_retains_completion_once_and_stops_later_tools_including_noop() {
        for noop in [false, true] {
            let mut project = Arc::new(project("hello-x64.elf"));
            if noop {
                project =
                    project.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap().project;
            }
            let review = project.patch_receipt().unwrap();
            project = project.effective_snapshot().unwrap();
            let expected = project.annotation_revision().unwrap();
            let main = project.resolve("main").unwrap();
            let external = Arc::clone(&project);
            let (entered, admission) = std::sync::mpsc::channel();
            let (updated, external_revision) = std::sync::mpsc::channel();
            let writer = std::thread::spawn(move || {
                admission.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
                external.comment(main, Some("external metadata after admission")).unwrap();
                updated.send(external.effective_snapshot().unwrap().annotation_revision().unwrap()).unwrap();
            });
            let script = Script {
                responses: Mutex::new(vec![json!({"content":[
                    {"type":"tool_use","id":"patch","name":"patch_bytes","input":{}},
                    {"type":"tool_use","id":"rename","name":"rename","input":{}},
                    {"type":"tool_use","id":"export","name":"export_patched","input":{}},
                    {"type":"text","text":"must not publish"}
                ]})]),
                requests: Mutex::new(Vec::new()),
            };
            let token = RunToken::for_project(&project);
            let mut dispatched = Vec::new();
            let error = Agent::new(&project)
                .answer(
                    &script,
                    "admitted patch",
                    &token,
                    &mut |_| panic!("unattributable result must not publish model events"),
                    &mut || Ok(()),
                    &mut |_, name, _| {
                        dispatched.push(name.to_owned());
                        assert!(Arc::ptr_eq(&expected, &project.annotation_revision().unwrap()));
                        entered.send(()).unwrap();
                        let before = external_revision.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
                        let outcome = project
                            .patch_bytes_reviewed(
                                0x100191e,
                                &[0xb8, 5, 0, 0, 0],
                                &[0xb8, 7, 0, 0, 0],
                                false,
                                &review.source_sha256,
                                &review.revision_sha256,
                            )
                            .unwrap();
                        assert!(Arc::ptr_eq(&before, &outcome.before_annotation_revision));
                        assert!(Arc::ptr_eq(
                            &outcome.after_annotation_revision,
                            &outcome.project.annotation_revision().unwrap()
                        ));
                        assert!(!Arc::ptr_eq(&expected, &outcome.before_annotation_revision));
                        token.cancel_unattributable();
                        (json!({ "changed":outcome.changed, "receipt":outcome.receipt }).to_string(), false)
                    },
                )
                .unwrap_err();
            writer.join().unwrap();
            assert_eq!(dispatched, ["patch_bytes"]);
            assert!(error.contains("unattributable") && error.contains("not rolled back"), "{error}");
            let outcomes = token.take_tool_outcomes();
            assert_eq!(outcomes.len(), 1);
            assert!(!outcomes[0].failed);
            assert!(outcomes[0].unattributable);
            let result: Value = serde_json::from_str(&outcomes[0].output).unwrap();
            assert_eq!(result["changed"], !noop);
            assert_eq!(result["receipt"]["active_ranges"], 1);
            assert!(token.take_tool_outcomes().is_empty());
            let current = project.effective_snapshot().unwrap();
            assert_eq!(current.list_patches().unwrap().len(), 1);
            assert_eq!(current.comment_at(main).as_deref(), Some("external metadata after admission"));
        }
    }

    #[test]
    fn answers_by_calling_tools_on_the_project() {
        let project = project("hello-x64.elf");
        let script = Script {
            responses: Mutex::new(vec![
                json!({
                    "stop_reason": "tool_use",
                    "content": [
                        { "type": "text", "text": "Looking at main." },
                        {
                            "type": "tool_use", "id": "t1", "name": "disassemble",
                            "input": { "at": "main", "count": 3 }
                        },
                        {
                            "type": "tool_use", "id": "t2", "name": "set_comment",
                            "input": { "at": "main", "text": "prints" }
                        },
                    ]
                }),
                json!({
                    "stop_reason": "end_turn",
                    "content": [{ "type": "text", "text": "main prints a greeting." }]
                }),
            ]),
            requests: Mutex::new(Vec::new()),
        };
        let mut agent = Agent::new(&project);
        let mut events = Vec::new();
        agent.ask(&script, &project, "What does main do?", &mut |event| events.push(event)).unwrap();

        assert_eq!(events.first(), Some(&Event::Text("Looking at main.".to_owned())));
        assert!(matches!(&events[1], Event::Tool { name, failed: false, .. } if name == "disassemble"));
        assert!(matches!(&events[2], Event::Tool { effect: Effect::Annotations, .. }));
        assert_eq!(events.last(), Some(&Event::Text("main prints a greeting.".to_owned())));
        // The comment reached the project, and the tool results went back to the model.
        let main = project.resolve("main").unwrap();
        assert_eq!(project.comment_at(main).as_deref(), Some("prints"));
        let requests = script.requests.lock().unwrap();
        let results = &requests[1]["messages"][2]["content"];
        assert_eq!(results[0]["tool_use_id"], "t1");
        assert!(results[0]["content"].as_str().unwrap().contains("push"));
        assert!(requests[0]["tools"].as_array().unwrap().iter().all(|tool| tool["input_schema"]["type"] == "object"));
    }

    /// Benchmark v2: a call with `address`/`length` instead of `at`/`count` disassembled the entry point. The
    /// assistant paths (ask, and ask_shared_cancellable, which the desktop UI uses) refuse it like MCP does.
    #[test]
    fn unknown_arguments_are_refused_on_both_assistant_paths() {
        let script = || Script {
            responses: Mutex::new(vec![
                json!({
                    "stop_reason": "tool_use",
                    "content": [{
                        "type": "tool_use", "id": "t1", "name": "disassemble",
                        "input": { "address": "main", "length": 3 }
                    }]
                }),
                json!({ "stop_reason": "end_turn", "content": [{ "type": "text", "text": "done" }] }),
            ]),
            requests: Mutex::new(Vec::new()),
        };
        let check = |script: &Script, events: &[Event]| {
            assert!(matches!(&events[0], Event::Tool { name, failed: true, .. } if name == "disassemble"));
            let requests = script.requests.lock().unwrap();
            let result = requests[1]["messages"][2]["content"][0]["content"].as_str().unwrap().to_owned();
            assert!(result.contains("unknown fields `address` (did you mean `at`?)"), "{result}");
            assert!(result.contains("Arguments of disassemble:"), "{result}");
        };
        let project = project("hello-x64.elf");
        let (borrowed, mut events) = (script(), Vec::new());
        Agent::new(&project).ask(&borrowed, &project, "main?", &mut |event| events.push(event)).unwrap();
        check(&borrowed, &events);
        let shared = Arc::new(project);
        let (script, mut events) = (script(), Vec::new());
        Agent::new(&shared).ask_shared(&script, &shared, "main?", &mut |event| events.push(event)).unwrap();
        check(&script, &events);
    }

    #[test]
    fn failed_requests_leave_the_conversation_usable() {
        let project = project("hello-x64.elf");
        let script = Script { responses: Mutex::new(Vec::new()), requests: Mutex::new(Vec::new()) };
        let mut agent = Agent::new(&project);
        assert!(agent.ask(&script, &project, "hello", &mut |_| {}).is_err());
        assert!(agent.messages.is_empty());
    }

    #[test]
    fn a_failure_after_tool_calls_rolls_the_conversation_back() {
        let project = project("hello-x64.elf");
        let tool_turn = json!({
            "stop_reason": "max_tokens",
            "content": [{ "type": "tool_use", "id": "t1", "name": "binary_info", "input": {} }]
        });
        // The tool turn is followed by an error: nothing of the question may stay behind.
        let script = Script { responses: Mutex::new(vec![tool_turn]), requests: Mutex::new(Vec::new()) };
        let mut agent = Agent::new(&project);
        assert!(agent.ask(&script, &project, "hello", &mut |_| {}).is_err());
        assert!(agent.messages.is_empty());
        // A reply cut off with a tool call still gets its result and goes on.
        let script = Script {
            responses: Mutex::new(vec![
                json!({
                    "stop_reason": "max_tokens",
                    "content": [{ "type": "tool_use", "id": "t1", "name": "binary_info", "input": {} }]
                }),
                json!({ "stop_reason": "end_turn", "content": [{ "type": "text", "text": "done" }] }),
            ]),
            requests: Mutex::new(Vec::new()),
        };
        agent.ask(&script, &project, "hello", &mut |_| {}).unwrap();
        let roles: Vec<&str> = agent.messages.iter().map(|message| message["role"].as_str().unwrap()).collect();
        assert_eq!(roles, ["user", "assistant", "user", "assistant"]);
        // An empty reply is an error, not an empty turn.
        let script = Script {
            responses: Mutex::new(vec![json!({ "stop_reason": "end_turn", "content": [] })]),
            requests: Mutex::new(Vec::new()),
        };
        assert!(agent.ask(&script, &project, "again", &mut |_| {}).is_err());
        assert_eq!(agent.messages.len(), 4);
    }

    #[test]
    fn old_tool_results_are_elided_to_fit_the_budget() {
        let project = project("hello-x64.elf");
        let mut agent = Agent::new(&project);
        let big = "x".repeat(200_000);
        for id in 0..3 {
            agent.messages.push(json!({ "role": "user", "content": [
                { "type": "tool_result", "tool_use_id": format!("t{id}"), "content": big }
            ]}));
        }
        agent.elide_old_results();
        let kept: Vec<bool> = agent
            .messages
            .iter()
            .map(|message| message["content"][0]["content"].as_str() == Some(big.as_str()))
            .collect();
        assert_eq!(kept, [false, false, true]);
    }

    #[test]
    fn tool_errors_are_reported_to_the_model() {
        let project = project("hello-x64.elf");
        let tools = tools::tools();
        let (text, failed) = tools::call(&tools, &project, "disassemble", json!({ "at": "no_such_name" }));
        assert!(failed && text.contains("no_such_name"));
        let (_, failed) = tools::call(&tools, &project, "nonexistent", json!({}));
        assert!(failed);
    }

    #[test]
    fn undo_redo_and_navigation_report_the_registry_effect() {
        let project = project("hello-x64.elf");
        let script = Script {
            responses: Mutex::new(vec![
                json!({ "content": [
                    { "type": "tool_use", "id": "1", "name": "rename", "input": {"at": "main", "name": "greet"} },
                    { "type": "tool_use", "id": "2", "name": "undo", "input": {} },
                    { "type": "tool_use", "id": "3", "name": "redo", "input": {} },
                    { "type": "tool_use", "id": "4", "name": "show_address", "input": {"at": "greet"} },
                    { "type": "tool_use", "id": "5", "name": "show_address", "input": {"at": "missing"} },
                ] }),
                json!({ "content": [{ "type": "text", "text": "done" }] }),
            ]),
            requests: Mutex::new(Vec::new()),
        };
        let mut events = Vec::new();
        Agent::new(&project).ask(&script, &project, "rename", &mut |event| events.push(event)).unwrap();
        let effects: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::Tool { effect, failed, .. } => Some((*effect, *failed)),
                _ => None,
            })
            .collect();
        assert_eq!(
            effects,
            [
                (Effect::Annotations, false),
                (Effect::Annotations, false),
                (Effect::Annotations, false),
                (Effect::ShowAddress, false),
                (Effect::ShowAddress, true),
            ]
        );
        assert_eq!(project.resolve("greet").unwrap(), project.resolve("main").unwrap());
    }
}
