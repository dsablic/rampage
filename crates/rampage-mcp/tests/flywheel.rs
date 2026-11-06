//! The flywheel's `improve` group over a tiny synthetic version-split corpus (tests/fixtures/flywheel): an owned
//! library's version 1 in two training programs, its version 2 (one function changed, every function moved) in the
//! same programs held out, and a negative program holding a copy of one library function under another name.
//! The tests check that a corpus server serves only the improve group and reads no corpus file, that no tool
//! reveals held-out binaries or truth, that the held-out budget spans servers, and run a scripted (non-model)
//! proposer that the negatives gate stops once, that promotes rows which carry across versions, and reverts.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rampage_api::flywheel::{
    CorpusManifest, GateConfig, Improve, ImproveOptions, Paths, PromotedSet, Split, evaluate_split, promoted_layer,
    revert, sha256_file,
};
use rampage_api::tools::Group;
use rampage_mcp::RampageServer;
use rmcp::model::{CallToolRequestParams, CallToolResult, ClientConfig};
use rmcp::service::RunningService;
use rmcp::{ClientHandler, RoleClient, ServiceExt};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct TestClient;

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

type Client = RunningService<RoleClient, TestClient>;

async fn connect(server: RampageServer) -> Client {
    let (server_transport, client_transport) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        server.serve(server_transport).await.unwrap().waiting().await.unwrap();
    });
    TestClient.serve(client_transport).await.unwrap()
}

async fn call(client: &Client, tool: &str, arguments: Value) -> CallToolResult {
    let arguments = arguments.as_object().unwrap().clone();
    client.call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments)).await.unwrap()
}

fn text(result: &CallToolResult) -> &str {
    result.content.first().and_then(|content| content.as_text()).map(|text| text.text.as_str()).unwrap()
}

fn json_of(result: &CallToolResult) -> Value {
    assert_ne!(result.is_error, Some(true), "{}", text(result));
    serde_json::from_str(text(result)).unwrap()
}

async fn tool_names(client: &Client) -> Vec<String> {
    let mut names: Vec<String> =
        client.list_all_tools().await.unwrap().into_iter().map(|tool| tool.name.into_owned()).collect();
    names.sort();
    names
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/flywheel")
}

/// A synthetic corpus in a fresh directory (`<root>/corpus/<version>`).
struct Synthetic {
    root: PathBuf,
    corpus: PathBuf,
}

impl Drop for Synthetic {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn synthetic(name: &str) -> Synthetic {
    let root = std::env::temp_dir().join(format!("rampage-flywheel-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let corpus = root.join("corpus").join("synthetic-1");
    std::fs::create_dir_all(&corpus).unwrap();
    for entry in std::fs::read_dir(fixtures()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|extension| extension == "elf" || extension == "o") {
            std::fs::copy(&path, corpus.join(path.file_name().unwrap())).unwrap();
        }
    }
    let digest = |file: &str| sha256_file(&corpus.join(file)).unwrap();
    let mut binaries = Vec::new();
    for (version, split) in [("1", "train"), ("2", "heldout")] {
        for program in ["a", "b"] {
            let id = format!("v{version}-{program}");
            binaries.push(json!({
                "id": id, "program": format!("minilib/{program}"), "library": "minilib",
                "library_version": version, "split": split,
                "arch": "x86_64", "compiler": "zig", "opt": "O2",
                "stripped": format!("{id}.elf"), "twin": format!("{id}.twin.elf"),
                "program_object": format!("prog-{program}.o"), "library_object": format!("minilib-v{version}.o"),
                "stripped_sha256": digest(&format!("{id}.elf")), "twin_sha256": digest(&format!("{id}.twin.elf")),
                "program_object_sha256": digest(&format!("prog-{program}.o")),
                "library_object_sha256": digest(&format!("minilib-v{version}.o")),
            }));
        }
    }
    binaries.push(json!({
        "id": "negative", "program": "owned/negative", "library": "owned", "library_version": "1",
        "split": "negative", "arch": "x86_64", "compiler": "zig", "opt": "O2",
        "stripped": "negative.elf", "twin": "negative.twin.elf", "program_object": "negative.o",
        "stripped_sha256": digest("negative.elf"), "twin_sha256": digest("negative.twin.elf"),
        "program_object_sha256": digest("negative.o"),
    }));
    let manifest: CorpusManifest = serde_json::from_value(json!({
        "schema_version": 2, "family": "libid", "name": "synthetic", "version": "synthetic-1",
        "libraries": [{"name": "minilib", "license": "Apache-2.0", "role": "target"}],
        // Most minilib functions are unchanged between versions by design: the limit is lifted for this corpus.
        "split": {"rule": "version", "fast_programs_per_library": 1, "max_heldout_overlap": 1.0, "refuse_heldout_overlap": 1.0},
        "binaries": binaries,
    }))
    .unwrap();
    std::fs::write(corpus.join("manifest.json"), serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
    Synthetic { root, corpus }
}

fn improve_with(synthetic: &Synthetic, run: Option<&str>, gate: GateConfig) -> Arc<Improve> {
    let options = ImproveOptions {
        corpus: synthetic.corpus.clone(),
        flywheel_dir: None,
        gate,
        workers: 2,
        run: run.map(str::to_owned),
    };
    Arc::new(Improve::open(options).unwrap())
}

fn improve(synthetic: &Synthetic, run: Option<&str>) -> Arc<Improve> {
    improve_with(synthetic, run, GateConfig::default())
}

#[tokio::test]
async fn a_corpus_server_serves_only_the_improve_group_and_reads_no_corpus_file() {
    let plain = connect(RampageServer::with_groups(Group::ALL)).await;
    let listing = json_of(&call(&plain, "enable_tools", json!({})).await);
    let groups: Vec<&str> =
        listing["groups"].as_array().unwrap().iter().map(|group| group["name"].as_str().unwrap()).collect();
    assert!(!groups.contains(&"improve"));
    assert!(!tool_names(&plain).await.iter().any(|name| name == "corpus_failures"));
    assert_eq!(call(&plain, "enable_tools", json!({"groups": ["improve"]})).await.is_error, Some(true));

    let synthetic = synthetic("group");
    let client = connect(RampageServer::with_groups(Group::ALL).with_improve(improve(&synthetic, None))).await;
    let expected = ["corpus_failures", "enable_tools", "evaluate_candidate", "promote_candidate", "propose_heuristic"];
    assert_eq!(tool_names(&client).await, expected, "only the improve tools, whatever groups were asked for");
    let listing = json_of(&call(&client, "enable_tools", json!({"groups": ["all"]})).await);
    let groups: Vec<&str> =
        listing["groups"].as_array().unwrap().iter().map(|group| group["name"].as_str().unwrap()).collect();
    assert_eq!(groups, ["improve"]);
    assert_eq!(tool_names(&client).await, expected, "enabling `all` adds nothing");
    let refused = call(&client, "enable_tools", json!({"groups": ["detection"]})).await;
    assert_eq!(refused.is_error, Some(true), "{}", text(&refused));

    // Neither a held-out binary nor its symbolized twin can be opened, by any tool, under any spelling.
    let corpus = synthetic.corpus.clone();
    for (tool, path) in [
        ("binary_info", corpus.join("v2-a.elf")),
        ("disassemble", corpus.join("v2-a.twin.elf")),
        ("identify_functions", corpus.join("v2-b.twin.elf")),
        ("list_functions", corpus.join("..").join("synthetic-1").join("v2-b.elf")),
        ("report_observation", corpus.join("v1-a.elf")),
    ] {
        let result = call(&client, tool, json!({"path": path, "at": "0x1000"})).await;
        assert_eq!(result.is_error, Some(true), "{tool}");
        assert!(!text(&result).contains("ml_"), "{tool} revealed a symbol: {}", text(&result));
    }
    let outside = call(&client, "binary_info", json!({"path": fixtures().join("../bin/hello-x64.elf")})).await;
    assert!(text(&outside).contains("serves only the improve group"), "{}", text(&outside));
    let inside = call(&client, "binary_info", json!({"path": corpus.join("v2-a.twin.elf")})).await;
    assert!(text(&inside).contains("inside the flywheel corpus"), "{}", text(&inside));
    let instructions = client.peer_info().unwrap().instructions.clone().unwrap_or_default();
    assert!(instructions.contains("serves only the improve group") && !instructions.contains("decompile"));
}

#[tokio::test]
async fn no_improve_tool_reveals_heldout_binaries_functions_or_truth() {
    let synthetic = synthetic("leak");
    let improve = improve(&synthetic, None);
    let client = connect(RampageServer::default().with_improve(Arc::clone(&improve))).await;
    let mut outputs = Vec::new();
    let failures = json_of(&call(&client, "corpus_failures", json!({"limit": 200})).await);
    assert_eq!(failures["split"], "train");
    for group in failures["groups"].as_array().unwrap() {
        assert!(group["example"]["binary"].as_str().unwrap().starts_with("v1-"), "{group}");
    }
    outputs.push(failures.to_string());
    let rows: Vec<Value> = failures["groups"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|group| group["proposable"] == true && group["truth_names"].as_array().unwrap().len() == 1)
        .map(|group| json!({"case": group["case"], "name": group["truth_names"][0]}))
        .collect();
    let proposal = json_of(&call(&client, "propose_heuristic", json!({"rows": rows})).await);
    outputs.push(proposal.to_string());
    let candidate = proposal["candidate"].as_str().unwrap();
    let fast = json_of(&call(&client, "evaluate_candidate", json!({"candidate": candidate})).await);
    outputs.push(fast.to_string());
    let heldout =
        json_of(&call(&client, "evaluate_candidate", json!({"candidate": candidate, "stage": "heldout"})).await);
    outputs.push(heldout.to_string());
    if heldout["heldout"]["status"] == "run" {
        let keys: Vec<&String> = heldout["heldout"].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["checks", "elapsed_ms", "overall_delta", "passed", "status"], "verdict and delta only");
    }
    for output in &outputs {
        for secret in ["v2-a", "v2-b", "ml_extra", "minilib-v2"] {
            assert!(!output.contains(secret), "held-out {secret} appears in {output}");
        }
    }
}

#[tokio::test]
async fn the_heldout_budget_spans_servers() {
    let synthetic = synthetic("budget");
    let gate = GateConfig { max_heldout_evaluations: 1, ..GateConfig::default() };
    let mut candidates = Vec::new();
    for round in 0..2 {
        let client = connect(RampageServer::default().with_improve(improve_with(&synthetic, None, gate.clone()))).await;
        let failures = json_of(&call(&client, "corpus_failures", json!({"limit": 200})).await);
        let group = failures["groups"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|group| group["proposable"] == true && group["truth_names"].as_array().unwrap().len() == 1)
            .nth(round)
            .unwrap()
            .clone();
        let proposal = json_of(
            &call(
                &client,
                "propose_heuristic",
                json!({"rows": [{"case": group["case"], "name": group["truth_names"][0]}]}),
            )
            .await,
        );
        candidates.push(proposal["candidate"].as_str().unwrap().to_owned());
        let result =
            call(&client, "evaluate_candidate", json!({"candidate": candidates[round], "stage": "heldout"})).await;
        if round == 0 {
            let value = json_of(&result);
            assert_eq!(value["heldout_evaluations_left"], 0, "{value}");
        } else {
            assert_eq!(result.is_error, Some(true), "a new server has no fresh budget: {}", text(&result));
            assert!(text(&result).contains("used up"), "{}", text(&result));
        }
    }
}

#[tokio::test]
async fn a_scripted_proposer_is_stopped_by_negatives_then_promotes_rows_that_carry_across_versions() {
    let synthetic = synthetic("e2e");
    let improve = improve(&synthetic, Some("scripted/round-1"));
    let paths = Paths::for_corpus(&synthetic.corpus).unwrap();
    let client = connect(RampageServer::default().with_improve(Arc::clone(&improve))).await;
    let baseline = heldout_counts(&improve);
    assert_eq!(baseline.0, 0, "the bundled databases know nothing of minilib");

    // Every training failure with one truth name, long enough for a row.
    let failures = json_of(&call(&client, "corpus_failures", json!({"outcome": "missed", "limit": 200})).await);
    let rows: Vec<Value> = failures["groups"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|group| group["proposable"] == true && group["truth_names"].as_array().unwrap().len() == 1)
        .map(|group| json!({"case": group["case"], "name": group["truth_names"][0], "library": "minilib"}))
        .collect();
    let names: Vec<&str> = rows.iter().map(|row| row["name"].as_str().unwrap()).collect();
    for name in ["ml_checksum", "ml_sum_squares", "ml_mix"] {
        assert!(names.contains(&name), "{name} is a training failure: {names:?}");
    }

    // The negatives gate refuses the ml_sum_squares row: the negative program holds the same body.
    let first = json_of(&call(&client, "propose_heuristic", json!({"rows": rows})).await);
    let first_id = first["candidate"].as_str().unwrap();
    let fast = json_of(&call(&client, "evaluate_candidate", json!({"candidate": first_id})).await);
    assert_eq!(fast["fast"]["passed"], false, "{fast}");
    let negative =
        fast["fast"]["checks"].as_array().unwrap().iter().find(|check| check["rule"] == "negative_matches").unwrap();
    assert_eq!(negative["passed"], false);
    let flagged: Vec<String> = fast["fast"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["binary"] == "negative")
        .filter_map(|case| case["after"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(flagged, ["ml_sum_squares"]);
    let refused = call(&client, "promote_candidate", json!({"candidate": first_id})).await;
    assert_eq!(refused.is_error, Some(true));

    // Without it the candidate passes both gates. ml_checksum changed in version 2, so its row gains nothing
    // held out: only the functions that carry across versions do.
    let clean: Vec<Value> =
        rows.iter().filter(|row| !flagged.iter().any(|name| row["name"] == name.as_str())).cloned().collect();
    let second = json_of(&call(&client, "propose_heuristic", json!({"rows": clean})).await);
    let candidate = second["candidate"].as_str().unwrap();
    assert_eq!(
        json_of(&call(&client, "evaluate_candidate", json!({"candidate": candidate})).await)["fast"]["passed"],
        true
    );
    let gated =
        json_of(&call(&client, "evaluate_candidate", json!({"candidate": candidate, "stage": "heldout"})).await);
    assert_eq!(gated["heldout"]["passed"], true, "{gated}");
    assert_eq!(gated["heldout"]["overall_delta"]["fp"], 0);

    let promoted = json_of(&call(&client, "promote_candidate", json!({"candidate": candidate})).await);
    let revert_id = promoted["revert_id"].as_str().unwrap().to_owned();
    let entry = &PromotedSet::load(&paths, "libid").unwrap().entries[0];
    assert_eq!(entry.revert_id, revert_id);
    assert_eq!(entry.proposer_run.as_deref(), Some("scripted/round-1"));
    assert!(entry.rows.iter().all(|row| row.name != "ml_sum_squares"));

    let gained = heldout_names(&improve);
    assert!(gained.contains("ml_mix") && gained.contains("ml_reverse"), "{gained:?}");
    assert!(!gained.contains("ml_checksum"), "a row memorising version 1's ml_checksum gains nothing: {gained:?}");
    let after = heldout_counts(&improve);
    assert!(after.0 > baseline.0 && after.1 == baseline.1, "{after:?} against {baseline:?}");

    revert(&paths, "libid", &revert_id).unwrap();
    assert_eq!(heldout_counts(&improve), baseline, "reverting restores the baseline exactly");
}

/// The held-out split's gated (TP, FP, FN) under the promoted pack, measured directly by the evaluator.
fn heldout_counts(improve: &Improve) -> (u64, u64, u64) {
    let set = PromotedSet::load(improve.paths(), "libid").unwrap();
    let layers: Vec<_> = promoted_layer(&set).unwrap().into_iter().collect();
    let evaluation = evaluate_split(improve.engine(), Split::Heldout, &layers, &[]).unwrap();
    let all = evaluation.candidate["all"];
    (all.tp(), all.fp(), all.fn_())
}

/// The truth names the promoted pack newly names correctly in the held-out split.
fn heldout_names(improve: &Improve) -> std::collections::BTreeSet<String> {
    let set = PromotedSet::load(improve.paths(), "libid").unwrap();
    let layers: Vec<_> = promoted_layer(&set).unwrap().into_iter().collect();
    let evaluation = evaluate_split(improve.engine(), Split::Heldout, &layers, &[]).unwrap();
    assert!(evaluation.cases.is_empty(), "held-out evaluations keep no cases");
    let engine = improve.engine();
    let mut names = std::collections::BTreeSet::new();
    for index in engine.corpus.indices(Split::Heldout) {
        let loaded = engine.get(index).unwrap();
        let proposals = engine.propose(&[index], &layers).unwrap();
        for (address, name) in &proposals.names[&index] {
            if loaded.truth.get(address).is_some_and(|truth| &truth.name == name)
                && !loaded.baseline.contains_key(address)
            {
                names.insert(name.clone());
            }
        }
    }
    names
}
