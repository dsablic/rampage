use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::Command;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn eval() -> Command {
    Command::cargo_bin("rampage-eval").unwrap()
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-parity-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        Self(directory)
    }

    fn manifest(&self) -> PathBuf {
        let path = self.0.join("manifest.json");
        std::fs::write(
            &path,
            json!({"slices":{"pilot-discovery":{
                "family":"discovery", "target":root().join("tests/fixtures/bin/eval-twin-x86_64.elf"),
                "truth":root().join("tests/fixtures/data/eval-truth-twin-x86_64.json")
            }}})
            .to_string(),
        )
        .unwrap();
        path
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn artifact_info_observes_headers_symbols_and_debug_metadata_in_both_twins() {
    for (file, stripped) in [("eval-types-sym-aarch64.elf", false), ("eval-types-aarch64.elf", true)] {
        let output = eval().arg("artifact-info").arg(root().join("tests/fixtures/bin").join(file)).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let info: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(info["format"], "elf");
        assert_eq!(info["arch"], "aarch64");
        assert_eq!(info["endianness"], "little");
        assert_eq!(info["static_function_symbols"] == 0, stripped);
        assert_eq!(info["debug_sections"].as_array().unwrap().is_empty(), stripped);
    }
}

#[test]
fn macho_header_marker_is_not_counted_as_a_function_bearing_analysis_truth() {
    let output = eval().arg("artifact-info").arg(root().join("tests/fixtures/bin/hello-arm64.macho")).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let info: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(info["static_function_symbols"], 2, "only owned hello.c add and main lie in the text section");
    assert_eq!(info["static_text_symbols_outside_section"], 1);
}

#[test]
fn explicit_dwarf_truth_checks_ranges_instead_of_requiring_sized_function_symbols() {
    let output = eval()
        .arg("truth")
        .arg(root().join("tests/fixtures/bin/eval-types-sym-aarch64.elf"))
        .arg("--dwarf")
        .arg("--stripped")
        .arg(root().join("tests/fixtures/bin/eval-types-aarch64.elf"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let truth: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(truth.as_object().unwrap().values().any(|name| name == "t_i8"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("DWARF"));
}

#[test]
fn parity_route_combines_real_static_scores_with_explicitly_unmeasured_tasks() {
    let scratch = Scratch::new();
    let output = eval().args(["run", "--suite", "parity", "--manifest"]).arg(scratch.manifest()).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["suite"], "parity");
    assert_eq!(report["phase0_complete"], false);
    assert_eq!(report["static_metric_status"]["function_starts"], "scored");
    assert_eq!(report["static_metric_status"]["library_names"], "not_run");
    assert_eq!(report["static_metric_status"]["parameter_counts"], "not_run");
    assert!(report["static_evaluation"]["slices"]["pilot-discovery"]["correct"].as_u64().unwrap() > 0);
    assert_eq!(report["agent_tasks"]["measured_analysis_tasks"], 0);
    assert_eq!(report["agent_tasks"]["transport"], "not_connected");
    assert_eq!(report["agent_tasks"]["fixture_failures"], 0);
    let roster = &report["processor_roster"];
    assert_eq!(roster["rows"].as_array().unwrap().len(), 16);
    assert_eq!(roster["totals"]["manual"], json!({"retained": 32, "exact_extents": 23}));
    assert_eq!(roster["totals"]["call_only"], json!({"retained": 27, "exact_extents": 20}));
    let unmeasured = report["unmeasured"].as_array().unwrap();
    assert!(unmeasured.iter().any(|category| category == "autonomous Ghidra discovery recall per processor"));
    assert_eq!(report["agent_tasks"]["tasks"].as_array().unwrap().len(), 20);
    for task in report["agent_tasks"]["tasks"].as_array().unwrap() {
        assert_eq!(task["check"]["outcome"], "unmeasured");
        assert!(task["mcp_tool_calls"].is_null() && task["input_tokens"].is_null() && task["wall_time_ms"].is_null());
    }
}

#[test]
fn empty_static_baselines_are_not_vacuous_passes() {
    let scratch = Scratch::new();
    let path = scratch.0.join("empty.json");
    std::fs::write(&path, "{\"slices\":{}}").unwrap();
    let output =
        eval().args(["run", "--suite", "parity", "--skip-processor-roster", "--manifest"]).arg(path).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("nonempty"));
}

#[test]
fn completion_gate_rejects_a_valid_but_partial_static_run() {
    let scratch = Scratch::new();
    let output = eval()
        .args(["run", "--suite", "parity", "--skip-processor-roster", "--require-complete", "--manifest"])
        .arg(scratch.manifest())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["phase0_complete"], false);
    assert!(
        report["acceptance"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| { check["criterion"] == "complete_fixed_model_mcp_task_run" && check["met"] == false })
    );
}

#[test]
fn empty_type_truth_retains_zero_coverage_without_reporting_measured_health() {
    let scratch = Scratch::new();
    let truth = scratch.0.join("truth.json");
    std::fs::write(&truth, "{}").unwrap();
    let path = scratch.0.join("manifest.json");
    std::fs::write(
        &path,
        json!({"slices":{"empty-types":{
            "family":"types", "target":root().join("tests/fixtures/bin/eval-types-aarch64.elf"),
            "truth":truth
        }}})
        .to_string(),
    )
    .unwrap();
    let output =
        eval().args(["run", "--suite", "parity", "--skip-processor-roster", "--manifest"]).arg(path).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["decompiler_health"]["status"], "not_run");
    assert_eq!(report["decompiler_health"]["attempted"], 0);
    assert_eq!(report["decompiler_health"]["targets"][0]["attempted"], 0);
}

#[test]
fn health_sampling_measures_discovery_only_targets_with_a_bounded_explicit_sample() {
    let scratch = Scratch::new();
    let output = eval()
        .args(["run", "--suite", "parity", "--skip-processor-roster", "--manifest"])
        .arg(scratch.manifest())
        .args(["--health-sample", "2"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["decompiler_health"]["status"], "measured");
    assert_eq!(report["decompiler_health"]["attempted"], 2);
    assert_eq!(report["decompiler_health"]["targets"][0]["sample_kind"], "address_sorted_function_truth");
    assert_eq!(report["decompiler_health"]["targets"][0]["functions"].as_array().unwrap().len(), 2);
}

#[test]
fn health_sample_is_shared_across_path_aliases_without_losing_source_paths() {
    let scratch = Scratch::new();
    let truth = root().join("tests/fixtures/data/eval-truth-twin-x86_64.json");
    let manifest = scratch.0.join("aliases.json");
    std::fs::write(
        &manifest,
        json!({"slices":{
            "direct":{"family":"discovery","target":root().join("tests/fixtures/bin/eval-twin-x86_64.elf"),
                "truth":truth},
            "alias":{"family":"discovery","target":root().join("tests/fixtures/data/../bin/eval-twin-x86_64.elf"),
                "truth":truth}
        }})
        .to_string(),
    )
    .unwrap();
    let output = eval()
        .args(["run", "--suite", "parity", "--skip-processor-roster", "--manifest"])
        .arg(manifest)
        .args(["--health-sample", "2"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["decompiler_health"]["attempted"], 2);
    assert_eq!(report["decompiler_health"]["targets"].as_array().unwrap().len(), 1);
    assert_eq!(report["decompiler_health"]["targets"][0]["source_paths"].as_array().unwrap().len(), 2);
}

#[test]
fn multiple_corpora_share_one_scorecard_without_silently_overwriting_slices() {
    let scratch = Scratch::new();
    let first = scratch.manifest();
    let second = scratch.0.join("second.json");
    let input = std::fs::read_to_string(&first).unwrap();
    std::fs::write(&second, input.replace("pilot-discovery", "second-discovery")).unwrap();
    let run = || {
        eval()
            .args(["run", "--suite", "parity", "--skip-processor-roster", "--manifest"])
            .arg(&first)
            .arg("--manifest")
            .arg(&second)
            .output()
            .unwrap()
    };
    let output = run();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["static_evaluation"]["slices"].as_object().unwrap().len(), 2);
    assert_eq!(report["static_manifests"].as_array().unwrap().len(), 2);
    std::fs::write(&second, input).unwrap();
    let refused = run();
    assert_eq!(refused.status.code(), Some(2));
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("duplicate slice"));
}

#[test]
fn fixture_preflight_failure_is_not_presented_as_an_agent_attempt() {
    let scratch = Scratch::new();
    let directory = scratch.0.join("tasks");
    std::fs::create_dir(&directory).unwrap();
    let task = include_str!("../tasks/arithmetic-arm64-elf.toml").replace("b47331c6", "a47331c6");
    std::fs::write(directory.join("task.toml"), task).unwrap();
    let output = eval()
        .args(["run", "--suite", "parity", "--skip-processor-roster", "--manifest"])
        .arg(scratch.manifest())
        .arg("--tasks")
        .arg(directory)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let task = &report["agent_tasks"]["tasks"][0];
    assert_eq!(task["fixture_status"], "mismatch");
    assert_eq!(task["run_kind"], "not_run");
    assert_eq!(task["check"]["outcome"], "unmeasured");
    assert!(task["mcp_tool_calls"].is_null());
}

#[test]
fn explicit_live_request_without_credentials_stays_unmeasured_and_does_not_call_a_model() {
    let scratch = Scratch::new();
    let output = eval()
        .env_remove("ANTHROPIC_API_KEY")
        .args(["run", "--suite", "parity", "--skip-processor-roster", "--manifest"])
        .arg(scratch.manifest())
        .args(["--agent-model", "explicit-pinned-test-model", "--agent-task", "arithmetic-arm64-elf"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["agent_tasks"]["transport"], "not_connected");
    assert_eq!(report["agent_tasks"]["configured_transport"], "in_memory_mcp_jsonrpc");
    assert_eq!(report["agent_tasks"]["measured_analysis_tasks"], 0);
    let task = report["agent_tasks"]["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|task| task["task_id"] == "arithmetic-arm64-elf")
        .unwrap();
    assert_eq!(task["requested_model"], "explicit-pinned-test-model");
    assert_eq!(task["agent_run"]["disposition"]["status"], "unrun");
    assert_eq!(task["agent_run"]["model_turns"], 0);
    assert_eq!(task["agent_run"]["catalog_requests"], 0);
    assert_eq!(task["check"]["outcome"], "unmeasured");
    assert!(task["input_tokens"].is_null() && task["mcp_tool_calls"].is_null());
}

#[test]
fn graph_exports_are_bound_before_the_scorecard_attaches_their_agreement() {
    let scratch = Scratch::new();
    let rampage = scratch.0.join("rampage.json");
    let ghidra = scratch.0.join("ghidra.json");
    let request = scratch.0.join("request.json");
    let r = r#"[{"address":"0x1000","blocks":["0x1000"],"edges":[],"references":[]}]"#;
    let g = concat!(
        r#"{"functions":[{"address":"0x1000","noreturn":false,"blocks":["#,
        r#"{"start":"0x1000","end":"0x1004","successors":[]}],"calls":[]}]}"#,
    );
    let binding = |tool: &str, text: &str| {
        json!({
            "image": {"image_sha256":"a".repeat(64),"architecture":"arm","address_bits":32,
                "address_space":"toy_static","image_base":"0x1000","image_offset":0,"image_length":null},
            "tool":tool,"version":"scripted-vector","exporter":"owned-test-vector",
            "exporter_sha256":"b".repeat(64), "export_sha256":rampage_arch::hex::bytes(&Sha256::digest(text.as_bytes()))
        })
    };
    std::fs::write(&rampage, r).unwrap();
    std::fs::write(&ghidra, g).unwrap();
    std::fs::write(
        &request,
        json!({"rampage":binding("rampage",r),"ghidra":binding("ghidra",g),
        "max_details":2})
        .to_string(),
    )
    .unwrap();
    let run = || {
        eval()
            .args(["run", "--suite", "parity", "--skip-processor-roster", "--manifest"])
            .arg(scratch.manifest())
            .arg("--graph-request")
            .arg(&request)
            .arg("--rampage-graph")
            .arg(&rampage)
            .arg("--ghidra-graph")
            .arg(&ghidra)
            .output()
            .unwrap()
    };
    let output = run();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["graph_agreement"]["functions"]["common"], 1);
    assert_eq!(report["graph_agreement"]["reference_is_truth"], false);
    assert!(report["graph_agreement"]["calls"]["precision"].is_null());
    std::fs::write(&ghidra, format!("{g}\n")).unwrap();
    let refused = run();
    assert_eq!(refused.status.code(), Some(2));
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("SHA-256"));
}
