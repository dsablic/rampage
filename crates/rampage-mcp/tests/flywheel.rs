//! The flywheel's `improve` group over a tiny synthetic corpus built from committed fixtures: two programs (the
//! eval signature corpus and target, both static musl) on x86-64 and AArch64, one of them held out. The tests
//! check that the group exists only with a corpus, that no tool reveals held-out binaries, functions or truth,
//! and run a scripted (non-model) proposer that promotes a known-good signature and reverts it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rampage_api::flywheel::{
    Corpus, CorpusManifest, Improve, ImproveOptions, ObservationStore, Paths, PromotedSet, Split, revert, sha256_file,
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
    client.list_all_tools().await.unwrap().into_iter().map(|tool| tool.name.into_owned()).collect()
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin")
}

/// A synthetic corpus in a fresh directory (`<root>/corpus/<version>`), with the target program held out.
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
    // The version keys the split; pick the first whose held-out program is the target, for a stable scenario.
    let version = (0..64)
        .map(|n| format!("synthetic-{n}"))
        .find(|version| {
            let manifest = manifest(version, &PathBuf::new(), false);
            let corpus = Corpus::from_manifest(PathBuf::from("/"), manifest).unwrap();
            corpus.heldout_programs().contains("musl/target")
        })
        .unwrap();
    let corpus = root.join("corpus").join(&version);
    std::fs::create_dir_all(&corpus).unwrap();
    for arch in ["x86_64", "aarch64"] {
        for (from, to) in [
            (format!("eval-twin-{arch}.elf"), format!("corpus-{arch}.elf")),
            (format!("eval-ref-{arch}.elf"), format!("corpus-{arch}.twin.elf")),
            (format!("eval-program-corpus-{arch}.o"), format!("corpus-{arch}.o")),
            (format!("eval-target-{arch}.elf"), format!("target-{arch}.elf")),
            (format!("eval-target-sym-{arch}.elf"), format!("target-{arch}.twin.elf")),
            (format!("eval-program-target-{arch}.o"), format!("target-{arch}.o")),
        ] {
            std::fs::copy(fixtures().join(from), corpus.join(to)).unwrap();
        }
    }
    let manifest = manifest(&version, &corpus, true);
    std::fs::write(corpus.join("manifest.json"), serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
    Synthetic { root, corpus }
}

fn manifest(version: &str, corpus: &Path, hashed: bool) -> CorpusManifest {
    let digest = |file: &str| if hashed { sha256_file(&corpus.join(file)).unwrap() } else { String::new() };
    let mut binaries = Vec::new();
    for program in ["corpus", "target"] {
        for arch in ["x86_64", "aarch64"] {
            binaries.push(json!({
                "id": format!("{program}-{arch}"),
                "program": format!("musl/{program}"),
                "library": "musl",
                "arch": arch,
                "compiler": "zig",
                "opt": "O1",
                "stripped": format!("{program}-{arch}.elf"),
                "twin": format!("{program}-{arch}.twin.elf"),
                "program_object": format!("{program}-{arch}.o"),
                "stripped_sha256": digest(&format!("{program}-{arch}.elf")),
                "twin_sha256": digest(&format!("{program}-{arch}.twin.elf")),
                "program_object_sha256": if hashed { Some(digest(&format!("{program}-{arch}.o"))) } else { None },
            }));
        }
    }
    serde_json::from_value(json!({
        "schema_version": 1,
        "family": "libid",
        "name": "synthetic",
        "version": version,
        "libraries": [{"name": "musl", "license": "MIT"}],
        "split": {"heldout_fraction": 0.5, "fast_programs_per_library": 1},
        "binaries": binaries,
    }))
    .unwrap()
}

fn improve(synthetic: &Synthetic, run: Option<&str>) -> Arc<Improve> {
    let options = ImproveOptions {
        corpus: synthetic.corpus.clone(),
        flywheel_dir: None,
        gate: Default::default(),
        workers: 2,
        run: run.map(str::to_owned),
    };
    Arc::new(Improve::open(options).unwrap())
}

#[tokio::test]
async fn the_improve_group_exists_only_with_a_corpus() {
    let plain = connect(RampageServer::with_groups(Group::ALL)).await;
    let listing = json_of(&call(&plain, "enable_tools", json!({})).await);
    let groups: Vec<&str> =
        listing["groups"].as_array().unwrap().iter().map(|group| group["name"].as_str().unwrap()).collect();
    assert!(!groups.contains(&"improve"));
    let names = tool_names(&plain).await;
    for tool in
        ["corpus_failures", "propose_heuristic", "evaluate_candidate", "promote_candidate", "report_observation"]
    {
        assert!(!names.iter().any(|name| name == tool), "{tool} is served without a corpus");
    }
    let refused = call(&plain, "corpus_failures", json!({})).await;
    assert_eq!(refused.is_error, Some(true));
    let refused = call(&plain, "enable_tools", json!({"groups": ["improve"]})).await;
    assert_eq!(refused.is_error, Some(true), "{}", text(&refused));
    let info = plain.peer_info().unwrap();
    let instructions = info.instructions.as_deref().unwrap_or("");
    assert!(!instructions.contains("corpus_failures") && !instructions.contains("report_observation"));

    let synthetic = synthetic("group");
    let store = Arc::new(ObservationStore::new(synthetic.root.join("observations")));
    let server = RampageServer::default().with_improve(improve(&synthetic, None)).with_observations(store);
    let client = connect(server).await;
    let before = tool_names(&client).await;
    assert!(before.iter().any(|name| name == "report_observation"), "report_observation is in core");
    assert!(!before.iter().any(|name| name == "corpus_failures"), "improve is enabled on request");
    let listing = json_of(&call(&client, "enable_tools", json!({"groups": ["improve"]})).await);
    assert_eq!(listing["newly_enabled"], json!(["improve"]));
    let after = tool_names(&client).await;
    for tool in ["corpus_failures", "propose_heuristic", "evaluate_candidate", "promote_candidate"] {
        assert!(after.iter().any(|name| name == tool), "{tool}");
    }
    let instructions = client.peer_info().unwrap().instructions.clone().unwrap_or_default();
    assert!(instructions.contains("- improve: ") && instructions.contains("held-out binaries are never shown"));
    // Arguments are checked against the schemas like every other tool's.
    let unknown = call(&client, "corpus_failures", json!({"bogus": 1})).await;
    assert_eq!(unknown.is_error, Some(true));
    assert!(text(&unknown).contains("unknown field"), "{}", text(&unknown));
}

/// Every name, address and binary id that only the held-out split has.
fn heldout_secrets(improve: &Improve) -> (Vec<String>, Vec<String>) {
    let engine = improve.engine();
    let corpus = engine.corpus.clone();
    let mut train_names = std::collections::BTreeSet::new();
    for index in corpus.indices(Split::Train) {
        train_names.extend(engine.get(index).unwrap().truth.values().map(|truth| truth.name.clone()));
    }
    let mut ids = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for index in corpus.indices(Split::Heldout) {
        ids.push(engine.binary(index).id.clone());
        let loaded = engine.get(index).unwrap();
        names.extend(loaded.truth.values().map(|truth| truth.name.clone()).filter(|name| !train_names.contains(name)));
    }
    (ids, names.into_iter().collect())
}

#[tokio::test]
async fn no_improve_tool_reveals_heldout_binaries_functions_or_truth() {
    let synthetic = synthetic("leak");
    let improve = improve(&synthetic, None);
    let client =
        connect(RampageServer::with_groups([Group::Core, Group::Improve]).with_improve(Arc::clone(&improve))).await;
    let mut outputs = Vec::new();
    let mut offset = 0;
    loop {
        let page = json_of(&call(&client, "corpus_failures", json!({"offset": offset, "limit": 200})).await);
        assert_eq!(page["split"], "train");
        outputs.push(page.to_string());
        for group in page["groups"].as_array().unwrap() {
            let binary = group["example"]["binary"].as_str().unwrap();
            assert!(binary.starts_with("corpus-"), "a failure example from {binary}");
        }
        match page["next_offset"].as_u64() {
            Some(next) => offset = next as usize,
            None => break,
        }
    }
    let (ids, names) = heldout_secrets(&improve);
    assert!(!ids.is_empty() && !names.is_empty(), "the scenario has held-out-only functions");

    // A candidate from the first failure, evaluated through both gates.
    let failures = json_of(&call(&client, "corpus_failures", json!({"outcome": "missed", "limit": 1})).await);
    let group = &failures["groups"][0];
    let name = group["truth_names"][0].as_str().unwrap();
    let proposal =
        json_of(&call(&client, "propose_heuristic", json!({"rows": [{"case": group["case"], "name": name}]})).await);
    outputs.push(proposal.to_string());
    let candidate = proposal["candidate"].as_str().unwrap();
    let fast = json_of(&call(&client, "evaluate_candidate", json!({"candidate": candidate})).await);
    outputs.push(fast.to_string());
    let heldout = call(&client, "evaluate_candidate", json!({"candidate": candidate, "stage": "heldout"})).await;
    outputs.push(text(&heldout).to_owned());
    let heldout = json_of(&heldout);
    assert!(heldout["heldout"].get("cases").is_none(), "held-out results carry no cases");

    for output in &outputs {
        for id in &ids {
            assert!(!output.contains(id.as_str()), "held-out binary {id} appears in {output}");
        }
        for name in &names {
            assert!(!output.contains(&format!("\"{name}\"")), "held-out-only function {name} appears in {output}");
        }
    }
}

#[tokio::test]
async fn a_scripted_proposer_promotes_a_known_good_signature_and_reverting_restores_the_baseline() {
    let synthetic = synthetic("e2e");
    let improve = improve(&synthetic, Some("scripted/round-1"));
    let paths = Paths::for_corpus(&synthetic.corpus).unwrap();
    let client =
        connect(RampageServer::with_groups([Group::Core, Group::Improve]).with_improve(Arc::clone(&improve))).await;

    // The scripted proposer: training failures that are missed in every training binary of their architecture
    // under one truth name, whose row's training preview names nothing else.
    let failures = json_of(
        &call(&client, "corpus_failures", json!({"outcome": "missed", "origin": "runtime", "limit": 200})).await,
    );
    let mut rows = Vec::new();
    for group in failures["groups"].as_array().unwrap() {
        let single = group["truth_names"].as_array().unwrap().len() == 1;
        if !single || group["wrong"] != 0 || group["spurious"] != 0 || group["proposable"] != true {
            continue;
        }
        rows.push(json!({"case": group["case"], "name": group["truth_names"][0], "library": "musl"}));
    }
    assert!(!rows.is_empty(), "the synthetic corpus has missed training functions");
    let mut candidate: Option<String> = None;
    let mut kept = 0;
    for row in rows.into_iter().take(64) {
        let mut arguments = json!({"rows": [row]});
        if let Some(id) = &candidate {
            arguments["candidate"] = json!(id);
        }
        // Rows whose preview matches another name stay out: propose each into a probe candidate first.
        let probe = json_of(&call(&client, "propose_heuristic", json!({"rows": arguments["rows"].clone()})).await);
        let preview = &probe["added"][0]["train_preview"];
        if preview["truth_is_another_name"] != 0 || preview["not_library_code"] != 0 {
            continue;
        }
        let added = json_of(&call(&client, "propose_heuristic", arguments).await);
        candidate = Some(added["candidate"].as_str().unwrap().to_owned());
        kept += 1;
    }
    let candidate = candidate.expect("at least one clean row");
    assert!(kept > 0);

    // Promotion is refused before a held-out result.
    let early = call(&client, "promote_candidate", json!({"candidate": candidate})).await;
    assert_eq!(early.is_error, Some(true));
    assert!(text(&early).contains("\"error\":\"refused\""), "{}", text(&early));

    let fast = json_of(&call(&client, "evaluate_candidate", json!({"candidate": candidate})).await);
    assert_eq!(fast["fast"]["passed"], true, "{fast}");
    assert_eq!(fast["heldout"]["status"], "not_run");
    let gated =
        json_of(&call(&client, "evaluate_candidate", json!({"candidate": candidate, "stage": "heldout"})).await);
    assert_eq!(gated["heldout"]["passed"], true, "{gated}");
    assert!(gated["heldout"]["deltas"]["all"]["tp"].as_i64().unwrap() > 0);
    assert_eq!(gated["heldout"]["deltas"]["all"]["fp"], 0);
    // The same request again comes from the cache.
    let again =
        json_of(&call(&client, "evaluate_candidate", json!({"candidate": candidate, "stage": "heldout"})).await);
    assert_eq!(again["cached"], true);

    let baseline = improve_heldout(&improve);
    let promoted = json_of(&call(&client, "promote_candidate", json!({"candidate": candidate})).await);
    let revert_id = promoted["revert_id"].as_str().unwrap().to_owned();
    let set = PromotedSet::load(&paths, "libid").unwrap();
    assert_eq!(set.entries.len(), 1);
    let entry = &set.entries[0];
    assert_eq!(entry.revert_id, revert_id);
    assert_eq!(entry.corpus_version, improve.corpus().version());
    assert_eq!(entry.split, "heldout");
    assert!(entry.heldout.passed && entry.fast.passed);
    assert_eq!(entry.driving_cases.len(), entry.rows.len());
    assert_eq!(entry.proposer_run.as_deref(), Some("scripted/round-1"));
    assert!(paths.promoted("libid").join("rampage-pack.toml").is_file());
    let after = improve_heldout(&improve);
    assert!(after.0 > baseline.0, "the promoted pack adds held-out true positives");
    assert_eq!(after.1, baseline.1, "and no false positives");

    // The promoted pack is an ordinary data pack: it loads and identifies through the API path.
    let packs = rampage_api::Packs::check(&paths.promoted("libid"));
    assert!(packs.error.is_none(), "{:?}", packs.error);

    // A second promotion of the same candidate is refused: the baseline moved.
    let twice = call(&client, "promote_candidate", json!({"candidate": candidate})).await;
    assert_eq!(twice.is_error, Some(true));

    let events = std::fs::read_to_string(paths.runs().join("scripted/round-1/events.jsonl")).unwrap();
    assert!(events.contains("\"promote_candidate\"") && events.contains(&revert_id));

    revert(&paths, "libid", &revert_id).unwrap();
    assert!(PromotedSet::load(&paths, "libid").unwrap().entries.is_empty());
    assert_eq!(improve_heldout(&improve), baseline, "reverting restores the baseline metrics exactly");
    assert!(revert(&paths, "libid", &revert_id).is_err(), "a revert id works once");
}

/// The held-out split's (TP, FP, FN) under the promoted pack, measured directly by the evaluator.
fn improve_heldout(improve: &Improve) -> (u64, u64, u64) {
    let set = PromotedSet::load(improve.paths(), "libid").unwrap();
    let layers: Vec<_> = rampage_api::flywheel::promoted_layer(&set).unwrap().into_iter().collect();
    let evaluation = rampage_api::flywheel::evaluate_split(improve.engine(), Split::Heldout, &layers, &[]).unwrap();
    let all = evaluation.candidate["all"];
    (all.tp(), all.fp(), all.fn_())
}
