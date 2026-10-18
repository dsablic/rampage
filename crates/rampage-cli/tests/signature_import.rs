use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::Command;
use predicates::str::contains;
use serde_json::{Value, json};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-cli-signature-import-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let prefix = "554889E5B82A00000083C00783C00783C00783C00783C00783C00783C0075D90";
        let snapshot = json!({
            "format":"rampage-snapshot-v1", "arch":"x86_64", "data_big_endian":false,
            "provenance":"owned hand-authored CLI PAT integration body", "seeds":["0x1000"],
            "regions":[{"name":"code", "address":"0x1000", "permissions":"r-x",
                "bytes":format!("{prefix}83C0019090C3")}]
        });
        std::fs::write(directory.join("owned.snapshot.json"), serde_json::to_vec(&snapshot).unwrap()).unwrap();
        std::fs::write(directory.join("owned.pat"), format!("{prefix} 06 2FCD 0026 :0000 owned_cli_pat\n---\n"))
            .unwrap();
        Self(directory)
    }

    fn identify(&self, database: &str, apply: bool) -> assert_cmd::assert::Assert {
        let mut command = Command::cargo_bin("rampage").unwrap();
        command.args(["--json", "identify", "--no-bundled", "--db"]).arg(self.0.join(database));
        if apply {
            command.arg("--apply");
        }
        command.arg(self.0.join("owned.snapshot.json")).assert()
    }

    fn assert_no_annotations(&self) {
        for entry in std::fs::read_dir(&self.0).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(
                !name.ends_with(".jsonl") && !name.ends_with(".rampage") && !name.ends_with(".lock"),
                "unexpected annotation file: {name}"
            );
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn identify_accepts_pat_directly_and_preview_does_not_save_names() {
    let fixture = Fixture::new();
    let before = std::fs::read(fixture.0.join("owned.pat")).unwrap();
    for _ in 0..2 {
        let result = fixture.identify("owned.pat", false).success();
        let value: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
        assert_eq!(value["matched"], 1);
        assert_eq!(value["applied"], 0);
        assert_eq!(value["matches"][0]["name"], "owned_cli_pat");
        assert_eq!(value["matches"][0]["unnamed"], true);
        assert_eq!(value["matches"][0]["source"], "user database");
    }
    assert_eq!(std::fs::read(fixture.0.join("owned.pat")).unwrap(), before);
    assert!(!fixture.0.join("owned.snapshot.json.rampage").exists());
    fixture.assert_no_annotations();
}

#[test]
fn identify_keeps_extensionless_json_and_rejects_fid_or_unknown_extensions_explicitly() {
    let fixture = Fixture::new();
    let empty = r#"{"arch":"x86_64","scheme":2,"entries":{}}"#;
    std::fs::write(fixture.0.join("native"), empty).unwrap();
    let result = fixture.identify("native", false).success();
    let value: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(value["matched"], 0);
    for (name, expected) in
        [("untrusted.fidbf", "explicitly configured trusted JVM/Ghidra"), ("unknown.db", "unsupported extension")]
    {
        std::fs::write(fixture.0.join(name), empty).unwrap();
        fixture.identify(name, true).failure().stderr(contains(expected));
    }
    std::fs::write(fixture.0.join("invalid.pat"), "{}\n").unwrap();
    fixture.identify("invalid.pat", true).failure().stderr(contains("PAT line"));
    assert!(!fixture.0.join("owned.snapshot.json.rampage").exists());
    fixture.assert_no_annotations();
}

#[test]
fn fuzzy_cli_candidates_never_count_as_exact_or_apply_names() {
    let fixture = Fixture::new();
    let body = "554889E5B82A00000083C00783C00783C00783C00783C00783C00783C00783FF03740383C00535785634125DC3";
    let snapshot = json!({
        "format":"rampage-snapshot-v1", "arch":"x86_64", "data_big_endian":false,
        "provenance":"owned branching CLI fuzzy body", "seeds":["0x1000"],
        "regions":[{"name":"code", "address":"0x1000", "permissions":"r-x", "bytes":body}]
    });
    let bytes = serde_json::to_vec(&snapshot).unwrap();
    let mut target_snapshot = snapshot.clone();
    target_snapshot["regions"][0]["bytes"] = json!(body.replacen("B82A000000", "B82B000000", 1));
    assert_ne!(target_snapshot["regions"][0]["bytes"], snapshot["regions"][0]["bytes"]);
    std::fs::write(fixture.0.join("fuzzy-target.json"), serde_json::to_vec(&target_snapshot).unwrap()).unwrap();
    let mut identical_snapshot = snapshot.clone();
    identical_snapshot["provenance"] = json!("different metadata and cohort, identical owned executable code");
    std::fs::write(fixture.0.join("identical-target.json"), serde_json::to_vec(&identical_snapshot).unwrap()).unwrap();
    let mut binary = rampage_loaders::Binary::from_snapshot_bytes(bytes).unwrap();
    binary.symbols.push(rampage_loaders::Symbol {
        name: "owned_cli_fuzzy".to_owned(),
        address: 4096,
        size: (body.len() / 2) as u64,
        kind: rampage_loaders::SymbolKind::Function,
    });
    let source = rampage_api::Project::new(binary);
    let build_request: rampage_api::FuzzyBuildRequest = serde_json::from_value(json!({
        "owned_names":["owned_cli_fuzzy"],
        "provenance":{"library":"owned", "source":"hand-authored CLI body", "cohort":"source"}
    }))
    .unwrap();
    let report = source.build_fuzzy_signatures(&build_request).unwrap();
    std::fs::write(fixture.0.join("fuzzy.json"), report.database.unwrap().save_json().unwrap()).unwrap();
    let request = fixture.0.join("query.json");
    std::fs::write(
        &request,
        json!({
            "cohort":"held-out-query", "addresses":[4096], "candidates_per_function":2
        })
        .to_string(),
    )
    .unwrap();
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["identify", "--apply", "--fuzzy-db"])
        .arg(fixture.0.join("fuzzy.json"))
        .arg("--fuzzy-request")
        .arg(&request)
        .arg(fixture.0.join("identical-target.json"))
        .assert()
        .failure()
        .stderr(contains("executable code duplicates"));
    fixture.assert_no_annotations();
    for apply in [false, true] {
        let mut command = Command::cargo_bin("rampage").unwrap();
        command
            .args(["--json", "identify", "--fuzzy-db"])
            .arg(fixture.0.join("fuzzy.json"))
            .arg("--fuzzy-request")
            .arg(&request);
        if apply {
            command.arg("--apply");
        }
        let result = command.arg(fixture.0.join("fuzzy-target.json")).assert().success();
        let value: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
        assert_eq!(value["matched"], 0);
        assert_eq!(value["applied"], 0);
        assert_eq!(value["fuzzy"]["read_only"], true);
        assert_eq!(value["fuzzy"]["suggestions"][0]["status"], "candidate_evidence");
        assert_eq!(value["fuzzy"]["suggestions"][0]["report"]["candidates"][0]["name"], "owned_cli_fuzzy");
    }
    let mut exact_binary =
        rampage_loaders::Binary::from_snapshot_bytes(serde_json::to_vec(&target_snapshot).unwrap()).unwrap();
    exact_binary.symbols.push(rampage_loaders::Symbol {
        name: "owned_cli_exact".to_owned(),
        address: 4096,
        size: (body.len() / 2) as u64,
        kind: rampage_loaders::SymbolKind::Function,
    });
    let exact_source = rampage_api::Project::new(exact_binary);
    std::fs::write(fixture.0.join("exact.json"), exact_source.build_signatures().to_json()).unwrap();
    std::fs::write(&request, "{}").unwrap();
    Command::cargo_bin("rampage")
        .unwrap()
        .args(["identify", "--apply", "--db"])
        .arg(fixture.0.join("exact.json"))
        .arg("--fuzzy-db")
        .arg(fixture.0.join("fuzzy.json"))
        .arg("--fuzzy-request")
        .arg(&request)
        .arg(fixture.0.join("fuzzy-target.json"))
        .assert()
        .failure();
    assert!(!fixture.0.join("fuzzy-target.json.rampage").exists());
    fixture.assert_no_annotations();
}
