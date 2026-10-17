//! Scripted-model MCP plumbing tests, not AI task-success measurements. No network or target execution.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rampage_agent::Transport;
use rampage_eval::parity_agent::{AgentConfig, AgentDisposition, AgentRun, ModelSource, ProviderUsage, run_task};
use rampage_eval::parity_tasks::{ParityTask, TaskAttempt, TaskOutcome};
use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::service::{RoleClient, RunningService};
use rmcp::{ClientHandler, ServiceExt};
use serde_json::{Value, json};

#[derive(Default)]
struct TestClient;

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

async fn connect() -> RunningService<RoleClient, TestClient> {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        RampageServer::default().serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    TestClient.serve(client_transport).await.unwrap()
}

struct Script {
    replies: Mutex<VecDeque<Result<Value, String>>>,
    requests: Arc<Mutex<Vec<Value>>>,
}

impl Script {
    fn new(replies: Vec<Value>) -> (Self, Arc<Mutex<Vec<Value>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let script =
            Self { replies: Mutex::new(replies.into_iter().map(Ok).collect()), requests: Arc::clone(&requests) };
        (script, requests)
    }
}

impl Transport for Script {
    fn send(&self, request: &Value) -> Result<Value, String> {
        self.requests.lock().unwrap().push(request.clone());
        self.replies.lock().unwrap().pop_front().unwrap_or_else(|| Err("script exhausted".into()))
    }
}

fn task() -> ParityTask {
    ParityTask::from_toml(include_str!("../tasks/arithmetic-arm64-elf.toml")).unwrap()
}

fn missing_capability_task() -> ParityTask {
    ParityTask::from_toml(include_str!("../tasks/capability-patch-export.toml")).unwrap()
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-arm64.elf")
}

fn config() -> AgentConfig {
    AgentConfig::new("explicit-script-requested-model")
}

fn tool(name: &str, input: Value) -> Value {
    json!({
        "model": "script-returned-model", "stop_reason": "tool_use",
        "content": [{ "type": "tool_use", "id": "call-1", "name": name, "input": input }],
    })
}

fn final_answer(answer: Value) -> Value {
    json!({
        "model": "script-returned-model", "stop_reason": "end_turn",
        "content": [{ "type": "text", "text": answer.to_string() }],
    })
}

fn offered(request: &Value, name: &str) -> bool {
    request["tools"].as_array().unwrap().iter().any(|tool| tool["name"] == name)
}

#[test]
fn without_provider_needs_no_peer_and_preserves_explicit_model_with_null_metrics() {
    let config = config();
    let run = AgentRun::without_provider(&config);
    assert_eq!(run.requested_model, config.model);
    assert!(matches!(run.disposition, AgentDisposition::Unrun { .. }));
    assert_eq!(run.task_attempt(), TaskAttempt::Unmeasured);
    assert_eq!(run.model_source, None);
    assert_eq!(run.wall_time_ms, None);
    assert_eq!(run.usage, ProviderUsage::default());
    assert_eq!(
        (run.model_turns, run.model_errors, run.tool_requests, run.tool_calls, run.tool_errors, run.catalog_requests),
        (0, 0, 0, 0, 0, 0),
    );
    assert!(run.turns.is_empty() && run.calls.is_empty() && run.catalogs.is_empty());
    assert!(run.catalog_tool_names.is_empty());
    let serialized = serde_json::to_value(&run).unwrap();
    assert_eq!(serialized["wall_time_ms"], Value::Null);
    assert_eq!(serialized["usage"]["input_tokens"], Value::Null);
    assert_eq!(serialized["usage"]["output_tokens"], Value::Null);
    assert_eq!(serialized["usage"]["cache_read_input_tokens"], Value::Null);
    assert_eq!(serialized["usage"]["cache_creation_input_tokens"], Value::Null);
}

#[test]
fn without_provider_rejects_invalid_model_and_limits_without_measuring_anything() {
    let mut invalid_limits = config();
    invalid_limits.max_turns = 0;
    for config in [AgentConfig::new(" "), invalid_limits] {
        let run = AgentRun::without_provider(&config);
        assert_eq!(run.requested_model, config.model);
        assert!(matches!(run.disposition, AgentDisposition::Failed { .. }));
        assert!(matches!(run.task_attempt(), TaskAttempt::Failed { .. }));
        assert_eq!(run.model_source, None);
        assert_eq!(run.wall_time_ms, None);
        assert_eq!(run.usage, ProviderUsage::default());
        assert_eq!((run.model_turns, run.tool_calls, run.catalog_requests), (0, 0, 0));
        assert!(run.turns.is_empty() && run.calls.is_empty() && run.catalogs.is_empty());
    }
}

#[test]
fn older_agent_runs_default_to_no_compact_catalog_inventory() {
    let mut serialized = serde_json::to_value(AgentRun::without_provider(&config())).unwrap();
    serialized.as_object_mut().unwrap().remove("catalog_tool_names");
    let run: AgentRun = serde_json::from_value(serialized).unwrap();
    assert!(run.catalog_tool_names.is_empty());
}

#[tokio::test]
async fn scripted_transport_uses_actual_mcp_and_keeps_truth_out_of_model_requests() {
    let client = connect().await;
    let path = fixture();
    let mut task = task();
    task.truth_reference = "EVALUATOR_ONLY_TRUTH".into();
    task.capability_evidence = "EVALUATOR_ONLY_INVENTORY".into();
    task.fixture.source = PathBuf::from("EVALUATOR_ONLY_SOURCE");
    task.fixture.build = PathBuf::from("EVALUATOR_ONLY_BUILD");
    task.fixture.sha256 = "EVALUATOR_ONLY_DIGEST".into();
    task.fixture.path = PathBuf::from("EVALUATOR_ONLY_MANIFEST_PATH");
    task.required_capabilities = vec!["EVALUATOR_ONLY_REQUIRED_CAPABILITY".into()];
    task.answer = rampage_eval::parity_tasks::AnswerContract::Exact {
        fields: [("EVALUATOR_ONLY_EXPECTED".into(), json!("secret"))].into(),
    };
    let mut first = tool("disassemble", json!({ "path": path, "at": "0x1010518", "count": 2 }));
    first["usage"] = json!({ "input_tokens": 10, "output_tokens": 4, "cache_read_input_tokens": 0 });
    let mut second = final_answer(json!({ "return_value": 18 }));
    second["usage"] = json!({ "input_tokens": 20, "output_tokens": 6 });
    let (script, requests) = Script::new(vec![first, second]);
    let run = run_task(&client, Some(script), ModelSource::Scripted, &task, &path, &config()).await;
    assert!(matches!(run.disposition, AgentDisposition::Answer { .. }), "{run:?}");
    assert_eq!(run.model_source, Some(ModelSource::Scripted));
    assert_eq!(run.task_attempt(), TaskAttempt::Unmeasured);
    assert_eq!(run.contract_attempt(), TaskAttempt::Answer(json!({ "return_value": 18 })));
    assert_eq!(run.requested_model, config().model);
    assert_eq!(run.turns[0].returned_model.as_deref(), Some("script-returned-model"));
    assert_eq!((run.model_turns, run.tool_requests, run.tool_calls), (2, 1, 1));
    assert_eq!(run.tool_errors, 0);
    assert!(run.wall_time_ms.is_some());
    assert!(run.calls[0].invoked);
    assert!(run.calls[0].output.text.contains("add"), "{run:?}");
    assert_eq!(run.usage.input_tokens, Some(30));
    assert_eq!(run.usage.output_tokens, Some(10));
    assert_eq!(run.turns[0].usage.cache_read_input_tokens, Some(0));
    assert_eq!(run.usage.cache_read_input_tokens, None);
    assert_eq!(run.usage.cache_creation_input_tokens, None);
    let requests = requests.lock().unwrap();
    assert_eq!(requests[0]["messages"][0]["content"], task.agent_prompt(&path));
    assert_eq!(requests[0]["model"], config().model);
    assert!(requests[1]["messages"][2]["content"][0]["content"].as_str().unwrap().contains("add"));
    assert!(!serde_json::to_string(&*requests).unwrap().contains("EVALUATOR_ONLY"));
    assert!(!offered(&requests[0], "rename"));
    assert!(!offered(&requests[0], "query_debugger"));
}

#[tokio::test]
async fn scripted_group_enable_refreshes_real_catalog_before_next_model_turn() {
    for allow_variable_edits in [false, true] {
        let client = connect().await;
        let initial_names: Vec<_> =
            client.list_all_tools().await.unwrap().into_iter().map(|tool| tool.name.into_owned()).collect();
        let path = fixture();
        let (script, requests) = Script::new(vec![
            tool("enable_tools", json!({ "groups": ["types"] })),
            tool("language_metadata", json!({ "path": path })),
            final_answer(json!({ "status": "unknown", "reason": "scripted inventory only" })),
        ]);
        let mut bounds = config();
        bounds.allow_variable_edits = allow_variable_edits;
        let run = run_task(&client, Some(script), ModelSource::Scripted, &task(), &path, &bounds).await;
        assert!(matches!(run.disposition, AgentDisposition::Unknown { .. }), "{run:?}");
        assert_eq!(run.catalog_requests, 2);
        assert_eq!(run.catalogs.len(), 2);
        assert_eq!(run.tool_calls, 2);
        let refreshed_names: Vec<_> =
            client.list_all_tools().await.unwrap().into_iter().map(|tool| tool.name.into_owned()).collect();
        assert!(!initial_names.iter().any(|name| name == "edit_variable" || name == "set_types"));
        for name in ["edit_variable", "set_types", "set_signature"] {
            assert!(refreshed_names.iter().any(|actual| actual == name));
        }
        assert_eq!(run.catalog_tool_names, vec![initial_names, refreshed_names]);
        {
            let requests = requests.lock().unwrap();
            assert!(!offered(&requests[0], "language_metadata"));
            assert!(offered(&requests[1], "language_metadata"));
            assert!(!offered(&requests[0], "edit_variable"));
            assert!(!offered(&requests[0], "set_types"));
            assert_eq!(offered(&requests[1], "edit_variable"), allow_variable_edits);
            assert_eq!(offered(&requests[1], "set_types"), allow_variable_edits);
            assert!(!offered(&requests[1], "set_signature"));
        }
        client.cancel().await.unwrap();
    }
}

#[tokio::test]
async fn scripted_policy_violations_are_not_sent_to_mcp_or_reclassified_as_unsupported() {
    for (name, input) in [
        ("binary_info", json!({ "path": "/outside/scope" })),
        ("binary_info", json!({ "path": fixture(), "command": "anything" })),
        ("rename", json!({ "path": fixture(), "at": "main", "name": "changed" })),
        ("query_debugger", json!({ "socket": "/outside/socket" })),
        ("build_signatures", json!({ "path": fixture(), "output": "/outside/output" })),
    ] {
        let client = connect().await;
        let (script, requests) = Script::new(vec![tool(name, input)]);
        let run = run_task(&client, Some(script), ModelSource::Scripted, &task(), &fixture(), &config()).await;
        assert!(matches!(run.disposition, AgentDisposition::Failed { .. }), "{name}: {run:?}");
        assert_eq!((run.tool_requests, run.tool_calls, run.tool_errors), (1, 0, 1));
        assert!(!run.calls[0].invoked);
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn scripted_preview_cannot_apply_annotations_or_read_a_second_path() {
    for input in [
        json!({ "path": fixture(), "apply": true }),
        json!({ "path": fixture(), "database": "/outside/database", "apply": false }),
    ] {
        let client = connect().await;
        let (script, _) = Script::new(vec![
            tool("enable_tools", json!({ "groups": ["detection"] })),
            tool("identify_functions", input),
        ]);
        let run = run_task(&client, Some(script), ModelSource::Scripted, &task(), &fixture(), &config()).await;
        assert!(matches!(run.disposition, AgentDisposition::Failed { .. }), "{run:?}");
        assert_eq!(run.tool_calls, 1);
        assert!(!run.calls[1].invoked);
    }
}

#[tokio::test]
async fn scripted_bad_address_can_be_repaired_using_matching_mcp_error_feedback() {
    let client = connect().await;
    let mut bad = tool("disassemble", json!({ "path": fixture(), "at": "definitely_not_a_symbol" }));
    bad["content"][0]["id"] = json!("bad-address");
    let mut corrected = tool("disassemble", json!({ "path": fixture(), "at": "0x1010518", "count": 2 }));
    corrected["content"][0]["id"] = json!("corrected-address");
    let (script, requests) = Script::new(vec![bad, corrected, final_answer(json!({ "return_value": 18 }))]);
    let task = task();
    let run = run_task(&client, Some(script), ModelSource::Scripted, &task, &fixture(), &config()).await;
    assert!(matches!(run.disposition, AgentDisposition::Answer { .. }), "{run:?}");
    assert_eq!((run.tool_calls, run.tool_errors, run.model_turns), (2, 1, 3));
    assert!(run.calls[0].invoked && run.calls[0].is_error);
    assert!(run.calls[1].invoked && !run.calls[1].is_error);
    assert!(run.calls[1].output.text.contains("add"));
    assert_eq!(task.check(&run.contract_attempt()).outcome, TaskOutcome::AnswerMatches);
    assert_eq!(task.check(&run.task_attempt()).outcome, TaskOutcome::Unmeasured);
    let requests = requests.lock().unwrap();
    let error_result = &requests[1]["messages"][2]["content"][0];
    assert_eq!(error_result["type"], "tool_result");
    assert_eq!(error_result["tool_use_id"], "bad-address");
    assert_eq!(error_result["is_error"], true);
    assert!(error_result["content"].as_str().unwrap().contains("definitely_not_a_symbol"));
    let repaired_result = &requests[2]["messages"][4]["content"][0];
    assert_eq!(repaired_result["tool_use_id"], "corrected-address");
    assert_eq!(repaired_result["is_error"], false);
}

#[tokio::test]
async fn actual_mcp_tool_error_cannot_be_reclassified_as_unsupported_even_after_full_discovery() {
    let client = connect().await;
    let (script, _) = Script::new(vec![
        tool("disassemble", json!({ "path": fixture(), "at": "definitely_not_a_symbol" })),
        tool("enable_tools", json!({ "groups": ["all"] })),
        final_answer(json!({ "status": "unsupported", "reason": "scripted runtime misclassification" })),
    ]);
    let run =
        run_task(&client, Some(script), ModelSource::Scripted, &missing_capability_task(), &fixture(), &config()).await;
    assert!(matches!(run.disposition, AgentDisposition::Failed { .. }), "{run:?}");
    assert_eq!((run.tool_calls, run.tool_errors, run.model_turns), (2, 1, 3));
    assert_eq!(run.catalog_requests, 2);
    assert!(run.calls[0].invoked && run.calls[0].is_error);
}

#[tokio::test]
async fn malformed_stop_reason_with_tool_use_never_invokes_mcp() {
    for stop_reason in [None, Some("end_turn"), Some("unknown"), Some("max_tokens")] {
        let client = connect().await;
        let mut response = tool("enable_tools", json!({ "groups": ["all"] }));
        if let Some(reason) = stop_reason {
            response["stop_reason"] = json!(reason);
        } else {
            response.as_object_mut().unwrap().remove("stop_reason");
        }
        let (script, requests) = Script::new(vec![response]);
        let run = run_task(&client, Some(script), ModelSource::Scripted, &task(), &fixture(), &config()).await;
        assert!(matches!(run.disposition, AgentDisposition::Failed { .. }), "{stop_reason:?}: {run:?}");
        assert_eq!((run.model_turns, run.tool_requests, run.tool_calls), (1, 1, 0));
        assert_eq!(run.catalog_requests, 1);
        assert!(run.calls.is_empty());
        assert_eq!(requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn no_provider_is_unmeasured_without_any_mcp_or_model_request() {
    let client = connect().await;
    let run = run_task::<Script>(&client, None, ModelSource::Provider, &task(), &fixture(), &config()).await;
    assert!(matches!(run.disposition, AgentDisposition::Unrun { .. }));
    assert_eq!(run.task_attempt(), TaskAttempt::Unmeasured);
    assert_eq!((run.model_turns, run.tool_calls, run.catalog_requests), (0, 0, 0));
    assert_eq!(run.model_source, None);
    assert_eq!(run.wall_time_ms, None);
    assert_eq!(run.usage, ProviderUsage::default());
}

#[tokio::test]
async fn blank_model_never_falls_back_or_sends_a_request() {
    let client = connect().await;
    let (script, requests) = Script::new(Vec::new());
    let run = run_task(&client, Some(script), ModelSource::Scripted, &task(), &fixture(), &AgentConfig::new(" ")).await;
    assert!(matches!(run.disposition, AgentDisposition::Failed { .. }));
    assert_eq!(run.catalog_requests, 0);
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn scripted_exhaustion_records_actual_transport_error_and_null_usage() {
    let client = connect().await;
    let (script, _) = Script::new(Vec::new());
    let run = run_task(&client, Some(script), ModelSource::Scripted, &task(), &fixture(), &config()).await;
    assert!(matches!(run.disposition, AgentDisposition::Failed { .. }));
    assert_eq!((run.model_turns, run.model_errors), (1, 1));
    assert!(run.turns[0].error.as_ref().unwrap().text.contains("script exhausted"));
    assert_eq!(run.turns[0].returned_model, None);
    assert_eq!(run.usage, ProviderUsage::default());
    assert_eq!(run.task_attempt(), TaskAttempt::Unmeasured);
    assert!(matches!(run.contract_attempt(), TaskAttempt::Failed { .. }));
}

#[tokio::test]
async fn scripted_turn_and_tool_bounds_stop_without_inventing_calls() {
    let client = connect().await;
    let mut bounds = config();
    bounds.max_turns = 1;
    let (script, _) = Script::new(vec![tool("enable_tools", json!({}))]);
    let run = run_task(&client, Some(script), ModelSource::Scripted, &task(), &fixture(), &bounds).await;
    assert!(matches!(run.disposition, AgentDisposition::Failed { .. }));
    assert_eq!((run.model_turns, run.tool_calls), (1, 1));

    bounds.max_tool_calls = 1;
    let mut reply = tool("enable_tools", json!({}));
    reply["content"].as_array_mut().unwrap().push(json!({
        "type": "tool_use", "id": "call-2", "name": "enable_tools", "input": {},
    }));
    let (script, _) = Script::new(vec![reply]);
    let run = run_task(&client, Some(script), ModelSource::Scripted, &task(), &fixture(), &bounds).await;
    assert!(matches!(run.disposition, AgentDisposition::Failed { .. }));
    assert_eq!((run.tool_requests, run.tool_calls), (2, 0));
}

#[tokio::test]
async fn scripted_retention_is_bounded_and_truncation_is_visible_to_model_and_evaluator() {
    let client = connect().await;
    let actual_names: Vec<_> =
        client.list_all_tools().await.unwrap().into_iter().map(|tool| tool.name.into_owned()).collect();
    let mut bounds = config();
    bounds.max_record_bytes = 256;
    bounds.max_retained_bytes = 256;
    let (script, requests) = Script::new(vec![
        tool("enable_tools", json!({})),
        final_answer(json!({ "status": "unknown", "reason": "scripted truncation check" })),
    ]);
    let run = run_task(&client, Some(script), ModelSource::Scripted, &task(), &fixture(), &bounds).await;
    assert!(matches!(run.disposition, AgentDisposition::Unknown { .. }), "{run:?}");
    assert!(run.catalogs[0].truncated);
    assert_eq!(run.catalog_tool_names, vec![actual_names.clone(), actual_names]);
    assert_eq!(run.catalog_tool_names.len(), run.catalogs.len());
    assert!(run.catalogs[1].truncated && run.catalogs[1].text.is_empty());
    assert!(run.calls[0].output.truncated);
    assert!(run.calls[0].output.original_bytes > run.calls[0].output.text.len());
    let retained: usize = run.catalogs.iter().map(|entry| entry.text.len()).sum::<usize>()
        + run.calls.iter().map(|call| call.input.text.len() + call.output.text.len()).sum::<usize>()
        + run.turns.iter().filter_map(|turn| turn.response.as_ref()).map(|entry| entry.text.len()).sum::<usize>();
    assert!(retained <= bounds.max_retained_bytes);
    let requests = requests.lock().unwrap();
    assert!(requests[1]["messages"][2]["content"][0]["content"].as_str().unwrap().contains("TRUNCATED"));
}

#[tokio::test]
async fn scripted_unsupported_requires_successful_all_group_discovery_and_catalog_refresh() {
    let unsupported = final_answer(json!({ "status": "unsupported", "reason": "scripted missing capability" }));
    let client = connect().await;
    let (script, _) = Script::new(vec![unsupported.clone()]);
    let task = missing_capability_task();
    let run = run_task(&client, Some(script), ModelSource::Scripted, &task, &fixture(), &config()).await;
    assert!(matches!(run.disposition, AgentDisposition::Failed { .. }));

    for groups in [json!({}), json!({ "groups": [] }), json!({ "groups": ["types"] })] {
        let client = connect().await;
        let (script, _) = Script::new(vec![tool("enable_tools", groups), unsupported.clone()]);
        let run = run_task(&client, Some(script), ModelSource::Scripted, &task, &fixture(), &config()).await;
        assert!(matches!(run.disposition, AgentDisposition::Failed { .. }), "{run:?}");
        assert_eq!(run.tool_errors, 0);
        assert_eq!(run.catalog_requests, 2);
    }

    let (script, _) = Script::new(vec![tool("enable_tools", json!({ "groups": ["all"] })), unsupported]);
    let run = run_task(&client, Some(script), ModelSource::Scripted, &task, &fixture(), &config()).await;
    assert!(matches!(run.disposition, AgentDisposition::Unsupported { .. }), "{run:?}");
    assert_eq!(run.catalog_requests, 2);
    assert_eq!(run.task_attempt(), TaskAttempt::Unmeasured);
    assert!(matches!(run.contract_attempt(), TaskAttempt::Unsupported { .. }));
}

#[tokio::test]
async fn scripted_unsupported_is_rejected_when_all_required_names_are_in_actual_catalog() {
    let client = connect().await;
    let mut task = task();
    // set_signature is present after full discovery even though benchmark policy will not invoke it.
    task.required_capabilities = vec!["disassemble".into(), "set_signature".into()];
    let (script, _) = Script::new(vec![
        tool("enable_tools", json!({ "groups": ["all"] })),
        final_answer(json!({ "status": "unsupported", "reason": "scripted false absence" })),
    ]);
    let run = run_task(&client, Some(script), ModelSource::Scripted, &task, &fixture(), &config()).await;
    assert!(
        matches!(&run.disposition, AgentDisposition::Failed { reason }
        if reason.contains("all required tool names are present")),
        "{run:?}"
    );
    assert_eq!(run.tool_errors, 0);
    assert_eq!(run.catalog_requests, 2);
}

#[tokio::test]
async fn scripted_provider_truncation_is_not_an_answer() {
    let client = connect().await;
    let mut cut_off = final_answer(json!({ "return_value": 18 }));
    cut_off["stop_reason"] = json!("max_tokens");
    let (script, _) = Script::new(vec![cut_off]);
    let run = run_task(&client, Some(script), ModelSource::Scripted, &task(), &fixture(), &config()).await;
    assert!(matches!(run.disposition, AgentDisposition::Failed { .. }));
}

struct LocalFixture {
    directory: PathBuf,
    path: PathBuf,
}

impl LocalFixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-eval-local-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let fixture = Self { path: directory.join("fixture.snapshot.json"), directory };
        std::fs::copy(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/local-variables-x64.snapshot.json"),
            &fixture.path,
        )
        .unwrap();
        fixture
    }
}

impl Drop for LocalFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

async fn native_decompilation(client: &RunningService<RoleClient, TestClient>, path: &std::path::Path) -> Value {
    let result = client
        .call_tool(
            CallToolRequestParams::new("decompile")
                .with_arguments(json!({"path": path, "at": "0x4000ae"}).as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    let text = &result.content.first().unwrap().as_text().unwrap().text;
    assert_ne!(result.is_error, Some(true), "{text}");
    serde_json::from_str(text).unwrap()
}

#[tokio::test]
async fn default_policy_hides_and_blocks_both_variable_annotation_writes() {
    for (name, edits) in [
        ("set_types", json!({"text": "struct PhaseState { int4 gain; int4 bias; };"})),
        ("edit_variable", json!({"variable": "piStack_10", "name": "state"})),
    ] {
        let owned = LocalFixture::new();
        let client = connect().await;
        let mut input = edits;
        input["path"] = json!(owned.path);
        input["at"] = json!("0x4000ae");
        let (script, requests) = Script::new(vec![tool("enable_tools", json!({"groups": ["all"]})), tool(name, input)]);
        let run = run_task(&client, Some(script), ModelSource::Scripted, &task(), &owned.path, &config()).await;
        assert!(matches!(run.disposition, AgentDisposition::Failed { .. }), "{run:?}");
        assert_eq!(run.tool_calls, 1);
        assert!(!run.calls[1].invoked);
        {
            let requests = requests.lock().unwrap();
            assert!(!offered(&requests[1], "set_types"));
            assert!(!offered(&requests[1], "edit_variable"));
            assert!(requests[1]["system"].as_str().unwrap().contains("restricted to read-only"));
        }
        let binary = rampage_loaders::Binary::open(&owned.path).unwrap();
        let identity = rampage_analysis::capture_identity::capture_identity(&binary).unwrap();
        let sidecar = owned.path.parent().unwrap().join(format!(".{}-{}.jsonl", identity.schema, identity.sha256));
        assert!(!sidecar.exists());
        client.cancel().await.unwrap();
    }
}

#[tokio::test]
async fn opt_in_executes_only_owned_fixture_type_and_variable_edits_with_native_refresh() {
    for by_storage in [false, true] {
        let owned = LocalFixture::new();
        let client = connect().await;
        let before = native_decompilation(&client, &owned.path).await;
        let local = before["variables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variable| {
                variable["editable"] == true
                    && variable["kind"] == "local"
                    && variable["storage"]["kind"] == "spacebase"
                    && variable["storage"]["space"] == "stack"
                    && variable["storage"]["size"] == 8
            })
            .expect("owned fixture stack local");
        let mut edit = json!({
            "path": owned.path, "at": "0x4000ae", "name": "state", "data_type": "struct PhaseState *",
        });
        if by_storage {
            edit["storage"] = local["storage"].clone();
        } else {
            edit["variable"] = local["name"].clone();
        }
        let (script, requests) = Script::new(vec![
            tool("enable_tools", json!({"groups": ["types"]})),
            tool(
                "set_types",
                json!({
                    "path": owned.path, "at": "0x4000ae", "text": "struct PhaseState { int4 gain; int4 bias; };",
                }),
            ),
            tool("edit_variable", edit),
            final_answer(json!({"local_name": "state", "local_type": "struct PhaseState *"})),
        ]);
        let mut bounds = config();
        bounds.allow_variable_edits = true;
        let run = run_task(&client, Some(script), ModelSource::Scripted, &task(), &owned.path, &bounds).await;
        assert!(matches!(run.disposition, AgentDisposition::Answer { .. }), "{run:?}");
        assert_eq!((run.tool_calls, run.tool_errors), (3, 0));
        assert!(run.calls.iter().all(|call| call.invoked && !call.is_error));
        assert_eq!(run.task_attempt(), TaskAttempt::Unmeasured);
        {
            let requests = requests.lock().unwrap();
            assert!(offered(&requests[1], "set_types"));
            assert!(offered(&requests[1], "edit_variable"));
            assert!(!offered(&requests[1], "set_signature"));
            assert!(!offered(&requests[1], "set_global"));
            assert!(requests[1]["system"].as_str().unwrap().contains("same owned fixture"));
        }
        let after = native_decompilation(&client, &owned.path).await;
        let updated =
            after["variables"].as_array().unwrap().iter().find(|variable| variable["name"] == "state").unwrap();
        assert_eq!(updated["kind"], "local");
        assert_eq!(updated["editable"], true);
        assert_eq!(updated["storage"], local["storage"]);
        assert_eq!(updated["key"], local["key"]);
        let code = after["code"].as_str().unwrap();
        assert!(code.contains("state->gain") && code.contains("state->bias"), "{code}");
        client.cancel().await.unwrap();
    }
}

#[tokio::test]
async fn opt_in_does_not_admit_other_writes_secondary_paths_or_unchecked_nested_inputs() {
    for (name, input) in [
        ("set_signature", json!({"at": "0x4000ae", "text": "int changed(void)"})),
        ("set_global", json!({"at": "0x4000ae", "text": "int changed"})),
        ("rename", json!({"at": "0x4000ae", "name": "changed"})),
        ("set_comment", json!({"at": "0x4000ae", "text": "changed"})),
        ("undo", json!({})),
        ("patch", json!({"at": "0x4000ae", "bytes": "90"})),
        ("query_debugger", json!({"socket": "/outside/socket"})),
        ("set_types", json!({"path": "/outside/fixture", "at": "0x4000ae", "text": "struct X {};"})),
        ("edit_variable", json!({"path": "/outside/fixture", "at": "0x4000ae", "name": "state"})),
        ("set_types", json!({"at": "0x4000ae", "text": "struct X {};", "image_offset": "0x10"})),
        ("edit_variable", json!({"at": "0x4000ae", "storage": {"command": "injected"}, "name": "state"})),
        ("edit_variable", json!({"at": "0x4000ae", "variable": {"name": "injected"}, "name": "state"})),
        (
            "edit_variable",
            json!({"at": "0x4000ae", "storage": {
            "kind": "spacebase", "space": "stack", "address": "0xfffffffffffffff0", "size": 8,
            "use_ranges": [{"space": "ram", "start": "0x4000ae", "end": "0x4000b0",
                "other": "/outside/fixture"}],
        }, "name": "state"}),
        ),
        ("binary_info", json!({"path": "/outside/fixture"})),
        ("import_debug_layouts", json!({"apply": true})),
    ] {
        let owned = LocalFixture::new();
        let client = connect().await;
        let mut input = input;
        if input.get("path").is_none() {
            input["path"] = json!(owned.path);
        }
        let (script, _) = Script::new(vec![tool("enable_tools", json!({"groups": ["all"]})), tool(name, input)]);
        let mut bounds = config();
        bounds.allow_variable_edits = true;
        let run = run_task(&client, Some(script), ModelSource::Scripted, &task(), &owned.path, &bounds).await;
        assert!(matches!(run.disposition, AgentDisposition::Failed { .. }), "{name}: {run:?}");
        assert_eq!((run.tool_calls, run.tool_errors), (1, 1), "{name}: {run:?}");
        assert!(!run.calls[1].invoked, "{name}: {run:?}");
        client.cancel().await.unwrap();
    }
}
