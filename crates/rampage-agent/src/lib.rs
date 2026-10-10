//! An AI assistant for an open binary: a conversation with a Claude model that answers by calling rampage's
//! analysis tools on the project, through the Anthropic Messages API.

pub mod tools;

use rampage_api::Project;
use serde_json::{Value, json};

pub use tools::Tool;

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
        let response = ureq::post(&self.url)
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
    Tool { name: String, input: Value, failed: bool },
}

/// A conversation about one binary.
pub struct Agent {
    model: String,
    system: String,
    messages: Vec<Value>,
    tools: Vec<Tool>,
}

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

    /// Asks `question`, running the tools the model calls until it answers. Reports progress to `on_event`.
    pub fn ask(
        &mut self,
        transport: &dyn Transport,
        project: &Project,
        question: &str,
        on_event: &mut dyn FnMut(Event),
    ) -> Result<(), String> {
        self.messages.push(json!({ "role": "user", "content": question }));
        let definitions: Vec<Value> = self.tools.iter().map(Tool::definition).collect();
        for _ in 0..MAX_TURNS {
            let request = json!({
                "model": self.model,
                "max_tokens": MAX_TOKENS,
                "system": self.system,
                "tools": definitions,
                "messages": self.messages,
            });
            let response = match transport.send(&request) {
                Ok(response) => response,
                Err(error) => {
                    // Forget the unanswered question so that the conversation can go on.
                    self.messages.pop_if(|message| message["role"] == "user");
                    return Err(error);
                }
            };
            let content = response["content"].clone();
            self.messages.push(json!({ "role": "assistant", "content": content }));
            let mut results = Vec::new();
            for block in content.as_array().into_iter().flatten() {
                match block["type"].as_str() {
                    Some("text") => on_event(Event::Text(block["text"].as_str().unwrap_or("").to_owned())),
                    Some("tool_use") => {
                        let name = block["name"].as_str().unwrap_or("");
                        let input = block["input"].clone();
                        let (output, failed) = tools::call(&self.tools, project, name, input.clone());
                        on_event(Event::Tool { name: name.to_owned(), input, failed });
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
            if response["stop_reason"] != "tool_use" || results.is_empty() {
                return Ok(());
            }
            self.messages.push(json!({ "role": "user", "content": results }));
        }
        Err(format!("stopped after {MAX_TURNS} model turns"))
    }
}

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

    #[test]
    fn failed_requests_leave_the_conversation_usable() {
        let project = project("hello-x64.elf");
        let script = Script { responses: Mutex::new(Vec::new()), requests: Mutex::new(Vec::new()) };
        let mut agent = Agent::new(&project);
        assert!(agent.ask(&script, &project, "hello", &mut |_| {}).is_err());
        assert!(agent.messages.is_empty());
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
}
