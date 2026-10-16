use std::path::PathBuf;
use std::process::{Command, Output};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rampage"))
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rampage-api/tests/fixtures/net-client-x64.elf")
}

fn error(output: &Output) -> String {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn ordinary_report_keeps_its_native_json_shape() {
    let output = command().args(["--json", "report", "triage-report"]).arg(fixture()).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["workflow"], "triage_report");
    assert!(value.get("provenance").is_none());
    assert!(value["sections"].as_array().unwrap().iter().any(|section| section["title"] == "Imports by library"));
}

#[test]
fn component_only_options_and_unsupported_workflows_fail_before_file_io() {
    let output =
        command().args(["report", "find-main", "missing-source", "--component", "missing-component"]).output().unwrap();
    assert!(error(&output).contains("supported only"));
    for option in ["--prepare-analysis", "--component-worker"] {
        let mut request = command();
        request.args(["report", "triage-report", "missing-source", option]);
        if option == "--component-worker" {
            request.arg("missing-worker");
        }
        assert!(error(&request.output().unwrap()).contains("--component"));
    }
}

#[test]
#[ignore = "requires the owned component/worker recipe; targets are never executed"]
fn explicit_component_route_is_labelled_bounded_and_never_falls_back() {
    let component = PathBuf::from(std::env::var_os("RAMPAGE_TRIAGE_COMPONENT").expect("owned component"));
    let worker = PathBuf::from(std::env::var_os("RAMPAGE_PLUGIN_WORKER").expect("trusted component worker"));
    let output = command()
        .args(["--json", "report", "triage-report"])
        .arg(fixture())
        .arg("--component")
        .arg(&component)
        .arg("--component-worker")
        .arg(&worker)
        .arg("--prepare-analysis")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stdout.len() <= rampage_api::MAX_PLUGIN_TRIAGE_REPORT_BYTES);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["report"]["workflow"], "triage_report");
    assert_eq!(value["provenance"]["content_authority"], "plugin_claims");
    assert_eq!(value["provenance"]["interface"], "rampage:workflow/triage@0.0.1");
    assert_eq!(value["provenance"]["component_sha256"].as_str().unwrap().len(), 64);

    let cold = command()
        .args(["report", "triage-report"])
        .arg(fixture())
        .arg("--component")
        .arg(&component)
        .arg("--component-worker")
        .arg(&worker)
        .output()
        .unwrap();
    assert!(error(&cold).contains("explicitly completed"));

    let pe = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.exe");
    let refused = command()
        .args(["report", "triage-report"])
        .arg(pe)
        .arg("--component")
        .arg(&component)
        .arg("--component-worker")
        .arg(&worker)
        .arg("--prepare-analysis")
        .output()
        .unwrap();
    assert!(error(&refused).contains("ELF"));
}
