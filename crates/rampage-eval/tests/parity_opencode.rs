//! Recorded V2 contracts and real in-process MCP plumbing; never live OpenCode generation.

use rampage_eval::parity_opencode as adapter;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use adapter::{
    AGENT_ID, ApiError, GenerationDriver, GenerationResponse, MAX_BODY_BYTES, MODEL, MODEL_VARIANT, OpenCodeTransport,
    PROTOCOL, SessionApi, SessionDriver, SessionOperation,
};
use rampage_agent::Transport;
use rampage_eval::parity_agent::{AgentConfig, AgentDisposition, ModelSource, run_task};
use rampage_eval::parity_tasks::{ParityTask, TaskAttempt};
use rampage_mcp::RampageServer;
use rmcp::model::ClientConfig;
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

type Captured = Arc<Mutex<Vec<(SessionOperation, Option<Value>)>>>;

struct RecordedApi {
    responses: Mutex<VecDeque<(SessionOperation, Result<Value, ApiError>)>>,
    captured: Captured,
    session_id: String,
}

impl SessionApi for RecordedApi {
    fn call(&self, operation: SessionOperation, body: Option<&Value>) -> Result<Value, ApiError> {
        self.captured.lock().unwrap().push((operation.clone(), body.cloned()));
        let (expected, response) = self.responses.lock().unwrap().pop_front().expect("unexpected API call");
        assert_eq!(operation, expected);
        response
    }

    fn allocate_session_id(&self) -> Result<String, String> {
        Ok(self.session_id.clone())
    }
}

fn recorded_api(responses: Vec<(SessionOperation, Result<Value, ApiError>)>) -> (RecordedApi, Captured) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let session_id = responses
        .first()
        .and_then(|(_, result)| result.as_ref().ok())
        .and_then(|response| response["data"]["id"].as_str())
        .filter(|id| !id.contains('/'))
        .unwrap_or("ses_owned")
        .to_owned();
    (RecordedApi { responses: Mutex::new(responses.into()), captured: Arc::clone(&captured), session_id }, captured)
}

fn request() -> Value {
    json!({
        "model": MODEL, "max_tokens": 4096, "system": "MCP-only test instructions",
        "messages": [{ "role": "user", "content": "task-only prompt" }],
        "tools": [{ "name": "enable_tools", "input_schema": { "type": "object" } }],
    })
}

fn intent(content: Value, stop_reason: &str) -> String {
    json!({ "protocol": PROTOCOL, "content": content, "stop_reason": stop_reason }).to_string()
}

fn answer_text() -> String {
    intent(json!([{ "type": "text", "text": "{\"status\":\"unknown\",\"reason\":\"recorded\"}" }]), "end_turn")
}

/// Minimal fields used from the live Session.Message.Assistant schema. Token fields are numbers.
fn assistant(text: String) -> Value {
    json!({
        "id": "msg_assistant", "type": "assistant", "agent": AGENT_ID,
        "time": { "created": 1, "completed": 2 },
        "model": { "id": "gpt-6.1-sol", "providerID": "github-copilot", "variant": "default" },
        "finish": "stop", "rawFinish": "stop",
        "tokens": { "input": 101, "output": 23, "reasoning": 7, "cache": { "read": 11, "write": 0 } },
        "content": [{ "type": "text", "text": text }],
    })
}

fn created(id: &str) -> Value {
    json!({ "data": {
        "id": id, "projectID": "isolated-project", "cost": 0, "agent": AGENT_ID,
        "tokens": { "input": 0, "output": 0, "reasoning": 0, "cache": { "read": 0, "write": 0 } },
        "time": { "created": 1, "updated": 1 },
        "model": { "id": "gpt-6.1-sol", "providerID": "github-copilot", "variant": "default" },
        "location": { "directory": "/isolated-owned-benchmark" },
        "permissions": [{ "action": "*", "resource": "*", "effect": "deny" }],
    } })
}

fn admitted(id: &str, text: &Value) -> Value {
    json!({ "data": {
        "id": "msg_prompt", "sessionID": id, "type": "user", "time": { "created": 1 },
        "payload": { "text": text }, "delivery": "queue",
    } })
}

fn projected(text: &Value, assistant: Value) -> Value {
    json!({
        "data": [
            { "type": "user", "id": "msg_prompt", "text": text, "time": { "created": 1 } },
            assistant,
        ],
        "cursor": { "previous": null, "next": null },
    })
}

struct RecordedGeneration {
    responses: Mutex<VecDeque<Value>>,
    bodies: Arc<Mutex<Vec<Value>>>,
}

impl GenerationDriver for RecordedGeneration {
    fn generate(&self, body: &Value) -> Result<GenerationResponse, String> {
        self.bodies.lock().unwrap().push(body.clone());
        let assistant = self.responses.lock().unwrap().pop_front().expect("unexpected generation");
        Ok(GenerationResponse {
            session_id: "ses_owned".into(),
            prompt_message_id: "msg_prompt".into(),
            messages: vec![assistant.clone()],
            message_pages: Vec::new(),
            validation_error: None,
            assistant,
        })
    }
}

fn recorded(responses: Vec<Value>) -> (OpenCodeTransport<RecordedGeneration>, Arc<Mutex<Vec<Value>>>) {
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let driver = RecordedGeneration { responses: Mutex::new(responses.into()), bodies: Arc::clone(&bodies) };
    (OpenCodeTransport::with_driver(driver), bodies)
}

#[test]
fn session_lifecycle_uses_fixed_model_isolated_location_denies_host_tools_and_deletes_only_owned_id() {
    let body = json!({ "text": "approved benchmark-only prompt" });
    let id = "ses_owned";
    let (api, captured) = recorded_api(vec![
        (SessionOperation::Create, Ok(created(id))),
        (SessionOperation::Prompt(id.into()), Ok(admitted(id, &body["text"]))),
        (SessionOperation::Wait(id.into()), Ok(Value::Null)),
        (SessionOperation::Messages(id.into()), Ok(projected(&body["text"], assistant(answer_text())))),
        (SessionOperation::Delete(id.into()), Ok(Value::Null)),
    ]);
    let driver = SessionDriver::with_api(PathBuf::from("/isolated-owned-benchmark"), api).unwrap();
    let generated = driver.generate(&body).unwrap();
    assert_eq!(generated.session_id, id);
    assert_eq!(generated.prompt_message_id, "msg_prompt");
    let captured = captured.lock().unwrap();
    let create = captured[0].1.as_ref().unwrap();
    assert_eq!(create["model"], json!({ "id": "gpt-6.1-sol", "providerID": "github-copilot", "variant": "default" }));
    assert_eq!(create["permissions"], json!([{ "action": "*", "resource": "*", "effect": "deny" }]));
    assert_eq!(create["location"]["directory"], "/isolated-owned-benchmark");
    assert_eq!(create["agent"], AGENT_ID);
    assert!(create.get("parentID").is_none());
    assert_eq!(create["id"], id);
    assert_eq!(captured[1].1.as_ref().unwrap(), &body);
}

#[test]
fn unreadable_committed_create_cleans_up_only_preallocated_id_and_conflict_touches_nothing() {
    let (api, captured) = recorded_api(vec![
        (SessionOperation::Create, Err("recorded committed create with unreadable CLI JSON".into())),
        (SessionOperation::Delete("ses_owned".into()), Ok(Value::Null)),
    ]);
    let driver = SessionDriver::with_api(PathBuf::from("/isolated-owned-benchmark"), api).unwrap();
    assert!(driver.generate(&json!({ "text": "benchmark" })).is_err());
    let captured = captured.lock().unwrap();
    assert_eq!(captured[0].1.as_ref().unwrap()["id"], "ses_owned");
    assert_eq!(captured[1].0, SessionOperation::Delete("ses_owned".into()));
    drop(captured);

    let (api, captured) = recorded_api(vec![(SessionOperation::Create, Err(ApiError::Conflict))]);
    let driver = SessionDriver::with_api(PathBuf::from("/isolated-owned-benchmark"), api).unwrap();
    assert!(driver.generate(&json!({ "text": "benchmark" })).unwrap_err().contains("conflict"));
    assert_eq!(captured.lock().unwrap().len(), 1);
}

#[test]
fn production_id_allocator_uses_fresh_128_bit_nonces_without_contacting_api() {
    struct NoCalls;
    impl SessionApi for NoCalls {
        fn call(&self, _operation: SessionOperation, _body: Option<&Value>) -> Result<Value, ApiError> {
            panic!("ID allocation must not contact OpenCode")
        }
    }
    let first = NoCalls.allocate_session_id().unwrap();
    let second = NoCalls.allocate_session_id().unwrap();
    assert_ne!(first, second);
    for id in [first, second] {
        let nonce = id.strip_prefix("ses_parity_").unwrap();
        assert_eq!(nonce.len(), 32);
        assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}

#[test]
fn every_generation_creates_a_new_owned_session_and_cleans_up_on_each_lifecycle_failure() {
    let body = json!({ "text": "benchmark" });
    for fail_at in 1..=3 {
        let id = format!("ses_failure_{fail_at}");
        let mut script = vec![(SessionOperation::Create, Ok(created(&id)))];
        let steps = [
            (SessionOperation::Prompt(id.clone()), admitted(&id, &body["text"])),
            (SessionOperation::Wait(id.clone()), Value::Null),
            (SessionOperation::Messages(id.clone()), projected(&body["text"], assistant(answer_text()))),
        ];
        for (index, (operation, response)) in steps.into_iter().enumerate().take(fail_at) {
            script.push((operation, if index + 1 == fail_at { Err("recorded failure".into()) } else { Ok(response) }));
        }
        if fail_at <= 2 {
            script.push((SessionOperation::Interrupt(id.clone()), Ok(json!({ "interrupted": true }))));
        }
        script.push((SessionOperation::Delete(id.clone()), Ok(Value::Null)));
        let (api, captured) = recorded_api(script);
        let driver = SessionDriver::with_api(PathBuf::from("/isolated-owned-benchmark"), api).unwrap();
        if fail_at == 3 {
            assert!(driver.generate(&body).unwrap().validation_error.is_some());
        } else {
            assert!(driver.generate(&body).is_err());
        }
        assert_eq!(captured.lock().unwrap().last().unwrap().0, SessionOperation::Delete(id));
    }
}

#[test]
fn two_ascending_pages_follow_opaque_next_cursor_and_keep_nonnull_previous_and_raw_evidence() {
    let body = json!({ "text": "benchmark" });
    let cursor = "opaque+/=?&cursor:page-2";
    let first = json!({
        "data": [{ "type": "user", "id": "msg_prompt", "text": body["text"], "time": { "created": 1 } }],
        "cursor": { "previous": "server-start-boundary", "next": cursor },
    });
    let last = json!({
        "data": [assistant(answer_text())],
        "cursor": { "previous": "backward-cursor-is-not-missing-evidence", "next": null },
    });
    let (api, captured) = recorded_api(vec![
        (SessionOperation::Create, Ok(created("ses_owned"))),
        (SessionOperation::Prompt("ses_owned".into()), Ok(admitted("ses_owned", &body["text"]))),
        (SessionOperation::Wait("ses_owned".into()), Ok(Value::Null)),
        (SessionOperation::Messages("ses_owned".into()), Ok(first.clone())),
        (SessionOperation::MessagesAfter { session_id: "ses_owned".into(), cursor: cursor.into() }, Ok(last.clone())),
        (SessionOperation::Delete("ses_owned".into()), Ok(Value::Null)),
    ]);
    let driver = SessionDriver::with_api(PathBuf::from("/isolated-owned-benchmark"), api).unwrap();
    let generated = driver.generate(&body).unwrap();
    assert!(generated.validation_error.is_none(), "{:?}", generated.validation_error);
    assert_eq!(generated.message_pages, vec![first, last]);
    assert_eq!(generated.messages.len(), 2);
    assert_eq!(generated.assistant["tokens"]["reasoning"], 7);
    let calls = captured.lock().unwrap();
    assert_eq!(calls[3].0, SessionOperation::Messages("ses_owned".into()));
    assert_eq!(calls[4].0, SessionOperation::MessagesAfter { session_id: "ses_owned".into(), cursor: cursor.into() });
}

#[test]
fn repeating_cursor_stops_acquisition_and_keeps_acquired_assistant_metering_before_cleanup() {
    let body = json!({ "text": "benchmark" });
    let mut first = projected(&body["text"], assistant(answer_text()));
    first["data"].as_array_mut().unwrap().pop();
    first["cursor"]["next"] = json!("same-cursor");
    let second = json!({
        "data": [assistant(answer_text())], "cursor": { "previous": "backward", "next": "same-cursor" },
    });
    let (api, captured) = recorded_api(vec![
        (SessionOperation::Create, Ok(created("ses_owned"))),
        (SessionOperation::Prompt("ses_owned".into()), Ok(admitted("ses_owned", &body["text"]))),
        (SessionOperation::Wait("ses_owned".into()), Ok(Value::Null)),
        (SessionOperation::Messages("ses_owned".into()), Ok(first)),
        (SessionOperation::MessagesAfter { session_id: "ses_owned".into(), cursor: "same-cursor".into() }, Ok(second)),
        (SessionOperation::Delete("ses_owned".into()), Ok(Value::Null)),
    ]);
    let driver = SessionDriver::with_api(PathBuf::from("/isolated-owned-benchmark"), api).unwrap();
    let generated = driver.generate(&body).unwrap();
    assert!(generated.validation_error.as_deref().unwrap().contains("repeated"));
    assert_eq!(generated.message_pages.len(), 2);
    assert_eq!(generated.messages.len(), 2);
    assert_eq!(generated.assistant["tokens"]["input"], 101);
    assert_eq!(captured.lock().unwrap().len(), 6);
}

#[test]
fn recorded_server_default_variant_is_sent_explicitly_in_create_and_retained_in_evidence() {
    // Minimal model evidence from phase0-completion/create-contract-response.json; no live call.
    let observed: Value = serde_json::from_str(
        r#"{
        "data": { "model": { "id": "gpt-6.1-sol", "providerID": "github-copilot", "variant": "default" } }
    }"#,
    )
    .unwrap();
    let (transport, _) = recorded(vec![assistant(answer_text())]);
    let response = transport.send(&request()).unwrap();
    assert_eq!(response["opencode_assistant"]["model"], observed["data"]["model"]);
    assert_eq!(response["adapter"]["requested_variant"], MODEL_VARIANT);
    assert_eq!(response["adapter"]["returned_variant"], "default");
    assert_eq!(response["adapter"]["returned_agent"], AGENT_ID);
    let body = json!({ "text": "benchmark" });
    let mut observed_create = created("ses_owned");
    observed_create["data"]["model"] = observed["data"]["model"].clone();
    observed_create["data"].as_object_mut().unwrap().remove("agent");
    let (api, captured) = recorded_api(vec![
        (SessionOperation::Create, Ok(observed_create)),
        (SessionOperation::Prompt("ses_owned".into()), Ok(admitted("ses_owned", &body["text"]))),
        (SessionOperation::Wait("ses_owned".into()), Ok(Value::Null)),
        (SessionOperation::Messages("ses_owned".into()), Ok(projected(&body["text"], assistant(answer_text())))),
        (SessionOperation::Delete("ses_owned".into()), Ok(Value::Null)),
    ]);
    let driver = SessionDriver::with_api(PathBuf::from("/isolated-owned-benchmark"), api).unwrap();
    assert!(driver.generate(&body).unwrap().validation_error.is_none());
    assert_eq!(captured.lock().unwrap()[0].1.as_ref().unwrap()["model"], observed["data"]["model"]);
}

#[test]
fn failed_delete_is_not_retried_unboundedly_and_response_is_not_accepted() {
    let body = json!({ "text": "benchmark" });
    let (api, captured) = recorded_api(vec![
        (SessionOperation::Create, Ok(created("ses_owned"))),
        (SessionOperation::Prompt("ses_owned".into()), Ok(admitted("ses_owned", &body["text"]))),
        (SessionOperation::Wait("ses_owned".into()), Ok(Value::Null)),
        (SessionOperation::Messages("ses_owned".into()), Ok(projected(&body["text"], assistant(answer_text())))),
        (SessionOperation::Delete("ses_owned".into()), Err("cleanup error".into())),
    ]);
    let driver = SessionDriver::with_api(PathBuf::from("/isolated-owned-benchmark"), api).unwrap();
    assert!(driver.generate(&body).unwrap_err().contains("cleanup failed"));
    assert_eq!(captured.lock().unwrap().len(), 5);
}

#[test]
fn owned_session_drop_deletes_exact_id_during_unwind() {
    struct PanicAtWait(Captured);

    impl SessionApi for PanicAtWait {
        fn call(&self, operation: SessionOperation, body: Option<&Value>) -> Result<Value, ApiError> {
            self.0.lock().unwrap().push((operation.clone(), body.cloned()));
            match operation {
                SessionOperation::Create => Ok(created("ses_owned")),
                SessionOperation::Prompt(_) => Ok(admitted("ses_owned", &body.unwrap()["text"])),
                SessionOperation::Wait(_) => panic!("recorded worker panic"),
                SessionOperation::Interrupt(_) => Ok(json!({ "interrupted": true })),
                SessionOperation::Delete(_) => Ok(Value::Null),
                SessionOperation::Messages(_) | SessionOperation::MessagesAfter { .. } => {
                    panic!("unexpected message request")
                }
            }
        }

        fn allocate_session_id(&self) -> Result<String, String> {
            Ok("ses_owned".into())
        }
    }

    let captured = Arc::new(Mutex::new(Vec::new()));
    let driver =
        SessionDriver::with_api(PathBuf::from("/isolated-owned-benchmark"), PanicAtWait(Arc::clone(&captured)))
            .unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { driver.generate(&json!({ "text": "benchmark" })) }))
            .is_err()
    );
    assert_eq!(captured.lock().unwrap().last().unwrap().0, SessionOperation::Delete("ses_owned".into()));
}

#[test]
fn partial_or_extra_session_messages_and_projected_host_tools_are_rejected_and_cleaned_up() {
    let body = json!({ "text": "benchmark" });
    let base = projected(&body["text"], assistant(answer_text()));
    let mut pages = Vec::new();
    let mut extra = base.clone();
    extra["data"].as_array_mut().unwrap().push(assistant(answer_text()));
    extra["data"][2]["id"] = json!("msg_extra_assistant");
    pages.push(extra);
    let mut host = base.clone();
    host["data"][1]["content"].as_array_mut().unwrap().push(json!({ "type": "tool", "name": "read" }));
    pages.push(host);
    let mut failed = base.clone();
    failed["data"].as_array_mut().unwrap().push(json!({ "type": "idle", "outcome": "failed" }));
    pages.push(failed);
    let mut wrong_user = base;
    wrong_user["data"][0]["id"] = json!("msg_unowned");
    pages.push(wrong_user);
    for page in pages {
        let (api, captured) = recorded_api(vec![
            (SessionOperation::Create, Ok(created("ses_owned"))),
            (SessionOperation::Prompt("ses_owned".into()), Ok(admitted("ses_owned", &body["text"]))),
            (SessionOperation::Wait("ses_owned".into()), Ok(Value::Null)),
            (SessionOperation::Messages("ses_owned".into()), Ok(page)),
            (SessionOperation::Delete("ses_owned".into()), Ok(Value::Null)),
        ]);
        let driver = SessionDriver::with_api(PathBuf::from("/isolated-owned-benchmark"), api).unwrap();
        let generated = driver.generate(&body).unwrap();
        assert!(generated.validation_error.is_some());
        assert!(!generated.messages.is_empty());
        assert_eq!(generated.message_pages.len(), 1);
        assert_eq!(captured.lock().unwrap().last().unwrap().0, SessionOperation::Delete("ses_owned".into()));
    }
}

#[test]
fn permission_model_location_mismatch_is_rejected_before_prompt_and_cleaned_up() {
    for field in ["permissions", "model", "location"] {
        let mut response = created("ses_owned");
        response["data"][field] = Value::Null;
        let (api, captured) = recorded_api(vec![
            (SessionOperation::Create, Ok(response)),
            (SessionOperation::Delete("ses_owned".into()), Ok(Value::Null)),
        ]);
        let driver = SessionDriver::with_api(PathBuf::from("/isolated-owned-benchmark"), api).unwrap();
        assert!(driver.generate(&json!({ "text": "benchmark" })).is_err());
        assert_eq!(captured.lock().unwrap().len(), 2);
    }
}

#[test]
fn metered_normalization_preserves_real_message_identity_finish_usage_and_raw_assistant() {
    let original = assistant(answer_text());
    let (transport, _) = recorded(vec![original.clone()]);
    let translated = transport.send(&request()).unwrap();
    assert_eq!(translated["opencode_assistant"], original);
    assert_eq!(translated["model"], MODEL);
    assert_eq!(
        translated["usage"],
        json!({
        "input_tokens": 101, "output_tokens": 23, "reasoning_tokens": 7,
            "cache_read_input_tokens": 11, "cache_creation_input_tokens": 0,
        })
    );
    assert_eq!(translated["adapter"]["reasoning_tokens"], 7);
    assert_eq!(translated["adapter"]["session_id"], "ses_owned");
    assert_eq!(translated["adapter"]["assistant_message_id"], "msg_assistant");
    assert_eq!(translated["adapter"]["provider_stop_reason"], "stop");
    assert_eq!(translated["adapter"]["provider_raw_finish"], "stop");
    assert_eq!(translated["adapter"]["stop_reason_source"], "model_generated_json_intent");
    assert_eq!(translated["adapter"]["native_tool_use"], false);
    assert!(translated["adapter"]["enforced_max_tokens"].is_null());
}

#[test]
fn missing_usage_stays_null_and_numeric_schema_integer_floats_are_supported() {
    let mut response = assistant(answer_text());
    response.as_object_mut().unwrap().remove("tokens");
    let mut float_response = assistant(answer_text());
    float_response["tokens"]["input"] = json!(101.0);
    let (transport, _) = recorded(vec![response, float_response]);
    let translated = transport.send(&request()).unwrap();
    assert!(translated["usage"].as_object().unwrap().values().all(Value::is_null));
    assert_eq!(transport.send(&request()).unwrap()["usage"]["input_tokens"], 101);
}

#[test]
fn host_tool_attempts_wrong_identity_errors_and_unfinished_states_cannot_be_normalized() {
    let original = assistant(answer_text());
    let mut invalid = Vec::new();
    for (pointer, value) in [
        ("/agent", json!("build")),
        ("/model/id", json!("another-model")),
        ("/model/providerID", json!("another-provider")),
        ("/finish", json!("tool-calls")),
        ("/finish", json!("length")),
        ("/finish", Value::Null),
        ("/time/completed", Value::Null),
        ("/tokens/input", json!(-1)),
        ("/tokens/output", json!(1.5)),
    ] {
        let mut response = original.clone();
        *response.pointer_mut(pointer).unwrap() = value;
        invalid.push(response);
    }
    let mut variant = original.clone();
    variant["model"]["variant"] = json!("high");
    invalid.push(variant);
    let mut host = original.clone();
    host["content"].as_array_mut().unwrap().push(json!({ "type": "tool", "name": "read", "state": {} }));
    invalid.push(host);
    let mut error = original;
    error["error"] = json!({ "type": "recorded-error", "message": "SECRET_CANARY" });
    invalid.push(error);
    for response in invalid {
        let (transport, _) = recorded(vec![response]);
        let response = transport.send(&request()).unwrap();
        assert_eq!(response["stop_reason"], "adapter_error");
        assert_eq!(response["content"], json!([]));
        assert!(!response["adapter"]["parse_error"].as_str().unwrap().contains("SECRET_CANARY"));
    }
}

#[test]
fn wrong_request_models_and_oversized_escaped_bodies_fail_before_generation() {
    for model in [Value::Null, json!(""), json!("gpt-6.1-sol"), json!(format!("{MODEL}#high"))] {
        let (transport, bodies) = recorded(Vec::new());
        let mut input = request();
        input["model"] = model;
        assert!(transport.send(&input).is_err());
        assert!(bodies.lock().unwrap().is_empty());
    }
    let (transport, bodies) = recorded(Vec::new());
    let mut input = request();
    input["messages"][0]["content"] = json!("\"".repeat(MAX_BODY_BYTES));
    assert!(transport.send(&input).unwrap_err().contains("64 KiB"));
    assert!(bodies.lock().unwrap().is_empty());
}

#[test]
fn isolated_directory_is_mandatory_and_bad_ids_cannot_become_cli_paths() {
    let (api, _) = recorded_api(Vec::new());
    assert!(SessionDriver::with_api(PathBuf::from("relative"), api).is_err());
    let (api, captured) = recorded_api(vec![
        (SessionOperation::Create, Ok(created("ses_/../unowned"))),
        (SessionOperation::Delete("ses_owned".into()), Ok(Value::Null)),
    ]);
    let driver = SessionDriver::with_api(PathBuf::from("/isolated-owned-benchmark"), api).unwrap();
    assert!(driver.generate(&json!({ "text": "benchmark" })).is_err());
    assert_eq!(captured.lock().unwrap().len(), 2);
    assert_eq!(captured.lock().unwrap().last().unwrap().0, SessionOperation::Delete("ses_owned".into()));
}

#[test]
fn history_is_supplied_only_in_one_prompt_and_never_carried_between_generations() {
    let (transport, bodies) = recorded(vec![assistant(answer_text()), assistant(answer_text())]);
    let first = request();
    transport.send(&first).unwrap();
    let mut second = request();
    second["messages"] = json!([{ "role": "user", "content": "fresh unrelated task" }]);
    transport.send(&second).unwrap();
    let bodies = bodies.lock().unwrap();
    assert_eq!(bodies[0].as_object().unwrap().len(), 1);
    let prompt = bodies[0]["text"].as_str().unwrap();
    let embedded = prompt.split("Supplied conversation request (JSON):\n").nth(1).unwrap();
    assert_eq!(serde_json::from_str::<Value>(embedded).unwrap(), first);
    assert!(!bodies[1]["text"].as_str().unwrap().contains("task-only prompt"));
}

#[test]
fn generated_provider_claims_duplicate_ids_and_inconsistent_intents_are_rejected_without_repair() {
    let tool = json!({ "type": "tool_use", "id": "model-call", "name": "enable_tools", "input": {} });
    for text in [
        intent(json!([tool.clone()]), "end_turn"),
        intent(json!([tool.clone(), tool]), "tool_use"),
        intent(json!([{ "type": "tool_use", "id": "call", "name": "enable_tools", "input": "{}" }]), "tool_use"),
        intent(json!([]), "end_turn"),
        json!({ "protocol": PROTOCOL, "stop_reason": "end_turn", "content": [], "usage": { "input": 999 } })
            .to_string(),
        "SECRET_CANARY".into(),
    ] {
        let (transport, _) = recorded(vec![assistant(text)]);
        let response = transport.send(&request()).unwrap();
        assert_eq!(response["stop_reason"], "adapter_error");
        assert_eq!(response["content"], json!([]));
        assert_eq!(response["usage"]["input_tokens"], 101);
        assert!(!response["adapter"]["parse_error"].as_str().unwrap().contains("SECRET_CANARY"));
    }
}

#[derive(Default)]
struct TestClient;

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

#[tokio::test]
async fn recorded_intents_use_existing_actual_mcp_loop_and_refresh_without_truth_leakage() {
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server_io).await.unwrap().waiting().await.unwrap();
    });
    let client = TestClient.serve(client_io).await.unwrap();
    let (transport, bodies) = recorded(vec![
        assistant(intent(
            json!([{
                "type": "tool_use", "id": "model-emitted-id", "name": "enable_tools", "input": { "groups": ["all"] },
            }]),
            "tool_use",
        )),
        assistant(answer_text()),
    ]);
    let mut task = ParityTask::from_toml(include_str!("../tasks/arithmetic-arm64-elf.toml")).unwrap();
    task.truth_reference = "PRIVATE_EVALUATOR_CANARY".into();
    task.fixture.source = PathBuf::from("PRIVATE_EVALUATOR_CANARY");
    task.answer = rampage_eval::parity_tasks::AnswerContract::Exact {
        fields: [("PRIVATE_EVALUATOR_CANARY".into(), json!(999))].into(),
    };
    let fixture = PathBuf::from("/fixture-not-read-by-enable-tools");
    let run =
        run_task(&client, Some(transport), ModelSource::Scripted, &task, &fixture, &AgentConfig::new(MODEL)).await;
    assert!(matches!(run.disposition, AgentDisposition::Unknown { .. }), "{run:?}");
    assert_eq!((run.model_turns, run.tool_calls, run.catalog_requests), (2, 1, 2));
    assert!(run.calls[0].invoked);
    assert_eq!(run.calls[0].tool_use_id, "model-emitted-id");
    assert_eq!(run.usage.input_tokens, Some(202));
    assert_eq!(run.usage.output_tokens, Some(46));
    assert_eq!(run.usage.reasoning_tokens, Some(14));
    assert!(run.turns.iter().all(|turn| turn.usage.reasoning_tokens == Some(7)));
    assert!(run.turns.iter().all(|turn| turn.returned_model.as_deref() == Some(MODEL)));
    assert_eq!(run.task_attempt(), TaskAttempt::Unmeasured);
    let bodies = bodies.lock().unwrap();
    assert!(!serde_json::to_string(&*bodies).unwrap().contains("PRIVATE_EVALUATOR_CANARY"));
    let prompt = bodies[1]["text"].as_str().unwrap();
    let request: Value =
        serde_json::from_str(prompt.split("Supplied conversation request (JSON):\n").nth(1).unwrap()).unwrap();
    assert_eq!(request["messages"][2]["content"][0]["tool_use_id"], "model-emitted-id");
    assert_eq!(request["messages"][2]["content"][0]["is_error"], false);
    assert!(request["tools"].as_array().unwrap().iter().any(|tool| tool["name"] == "language_metadata"));
}

#[tokio::test]
async fn billed_malformed_intent_is_retained_as_failed_turn_before_any_mcp_invocation() {
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server_io).await.unwrap().waiting().await.unwrap();
    });
    let client = TestClient.serve(client_io).await.unwrap();
    let original = assistant("not valid JSON intent".into());
    let (transport, _) = recorded(vec![original.clone()]);
    let task = ParityTask::from_toml(include_str!("../tasks/arithmetic-arm64-elf.toml")).unwrap();
    let fixture = PathBuf::from("/fixture-never-opened");
    let run =
        run_task(&client, Some(transport), ModelSource::Scripted, &task, &fixture, &AgentConfig::new(MODEL)).await;
    assert!(matches!(run.disposition, AgentDisposition::Failed { .. }));
    assert_eq!((run.model_turns, run.model_errors, run.tool_requests, run.tool_calls), (1, 0, 0, 0));
    assert_eq!(run.usage.input_tokens, Some(101));
    assert_eq!(run.usage.output_tokens, Some(23));
    assert_eq!(run.usage.reasoning_tokens, Some(7));
    assert_eq!(run.usage.cache_read_input_tokens, Some(11));
    assert_eq!(run.usage.cache_creation_input_tokens, Some(0));
    assert_eq!(run.turns[0].returned_model.as_deref(), Some(MODEL));
    let retained: Value = serde_json::from_str(&run.turns[0].response.as_ref().unwrap().text).unwrap();
    assert_eq!(retained["stop_reason"], "adapter_error");
    assert_eq!(retained["content"], json!([]));
    assert_eq!(retained["opencode_assistant"], original);
    assert!(retained["adapter"]["parse_error"].is_string());
    assert_eq!(retained["adapter"]["stop_reason_source"], "adapter_validation_error");
    assert_eq!(retained["adapter"]["provider_stop_reason"], "stop");
    assert!(run.calls.is_empty());
}
