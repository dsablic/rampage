use std::path::PathBuf;

use rampage_api::{DetectionKind, Session};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

#[test]
fn detect_tools_names_the_producing_toolchain() {
    let go = Session::default().open(&fixture("hello-go-x64.elf"), None).unwrap();
    let detections = go.detect_tools(None).unwrap();
    assert!(detections.iter().any(|d| d.name == "Go" && d.kind == DetectionKind::Compiler), "{detections:?}");

    let elf = Session::default().open(&fixture("hello-x64.elf"), None).unwrap();
    let detections = elf.detect_tools(None).unwrap();
    assert!(detections.iter().any(|d| d.name == "Clang/LLVM"), "{detections:?}");
    // An ordinary unpacked binary is not reported as packed.
    assert!(detections.iter().all(|d| d.kind != DetectionKind::Packer), "{detections:?}");
}

#[test]
fn detect_tools_reports_a_malformed_peid_database() {
    let project = Session::default().open(&fixture("hello-x64.elf"), None).unwrap();
    let error = project.detect_tools(Some("[Broken]\nsignature = ZZ ZZ\nep_only = true\n"));
    assert!(error.is_err());
}

#[test]
fn yara_scan_runs_user_rules_and_rejects_malformed_ones() {
    let project = Session::default().open(&fixture("hello-x64.exe"), None).unwrap();
    let rules = r#"
        rule pe_header : format { strings: $mz = "MZ" condition: $mz at 0 }
        rule absent { strings: $x = "not-in-this-binary-0123456789" condition: $x }
    "#;
    let matches = project.yara_scan(rules).unwrap();
    let names: Vec<&str> = matches.iter().map(|m| m.identifier.as_str()).collect();
    assert_eq!(names, ["pe_header"]);
    assert_eq!(matches[0].tags, ["format"]);
    assert!(project.yara_scan("rule broken {").is_err());
}

#[test]
fn detect_capa_evaluates_a_rule_directory() {
    let dir = std::env::temp_dir().join(format!("rampage-capa-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("console.yml"),
        "rule:\n  meta:\n    name: write output to console\n    namespace: host-interaction/console\n    \
         scopes:\n      static: file\n  features:\n    - or:\n      - import: puts\n      - import: printf\n",
    )
    .unwrap();
    let project = Session::default().open(&fixture("hello-x64.exe"), None).unwrap();
    let result = project.detect_capa(&dir);
    std::fs::remove_dir_all(&dir).unwrap();
    let capabilities = result.unwrap();
    let console = capabilities.iter().find(|c| c.name == "write output to console").expect("capa rule matched");
    assert_eq!(console.category, "host-interaction");
}
