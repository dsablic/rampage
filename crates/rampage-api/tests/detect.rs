use std::path::PathBuf;

use rampage_api::{DetectionKind, Session};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

#[test]
fn detect_tools_names_the_producing_toolchain() {
    let go = Session::default().open(&fixture("hello-go-x64.elf"), None).unwrap();
    let detections = go.detect_tools(None).unwrap().detections;
    assert!(detections.iter().any(|d| d.name == "Go" && d.kind == DetectionKind::Compiler), "{detections:?}");

    let elf = Session::default().open(&fixture("hello-x64.elf"), None).unwrap();
    let detections = elf.detect_tools(None).unwrap().detections;
    assert!(detections.iter().any(|d| d.name == "Clang/LLVM"), "{detections:?}");
    // An ordinary unpacked binary is not reported as packed.
    assert!(detections.iter().all(|d| d.kind != DetectionKind::Packer), "{detections:?}");
}

#[test]
fn detect_tools_reports_a_malformed_peid_database() {
    let project = Session::default().open(&fixture("hello-x64.elf"), None).unwrap();
    let error = project.detect_tools(Some("[Broken]\nsignature = ZZ ZZ\nep_only = true\n"));
    assert!(error.is_err());

    // A database with some usable entries loads them and reports the rest.
    let partial = "[Broken]\nsignature = ZZ ZZ\nep_only = true\n[Fine]\nsignature = 4D 5A\nep_only = false\n";
    let found = project.detect_tools(Some(partial)).unwrap();
    assert_eq!(found.warnings.len(), 1, "{:?}", found.warnings);
    assert!(found.warnings[0].contains("[Broken]"), "{:?}", found.warnings);

    // A database with many broken entries reports the first few and counts the rest.
    let many =
        "[Broken]\nsignature = ZZ ZZ\nep_only = true\n".repeat(1000) + "[Fine]\nsignature = 4D 5A\nep_only = false\n";
    let found = project.detect_tools(Some(&many)).unwrap();
    assert_eq!(found.warnings.len(), 21, "{:?}", found.warnings);
    assert_eq!(found.warnings[20], "PeID database: ... and 980 more problems skipped");
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

#[test]
fn detect_capa_evaluates_export_features() {
    let dir = std::env::temp_dir().join(format!("rampage-capa-export-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let rule = |file: &str, name: &str, features: &str| {
        let text = format!(
            "rule:\n  meta:\n    name: {name}\n    namespace: test/exports\n    scopes:\n      static: file\n  \
             features:\n{features}"
        );
        std::fs::write(dir.join(file), text).unwrap();
    };
    rule("export.yml", "exports add", "    - export: add\n");
    rule("both.yml", "exports add and imports puts", "    - and:\n      - export: add\n      - import: puts\n");
    rule("absent.yml", "exports sub and imports puts", "    - and:\n      - export: sub\n      - import: puts\n");
    // The dylib exports `_add` and `_main` and imports `_puts`.
    let project = Session::default().open(&fixture("hello-x64.dylib"), None).unwrap();
    let result = project.detect_capa(&dir);
    std::fs::remove_dir_all(&dir).unwrap();
    let mut names: Vec<String> = result.unwrap().into_iter().map(|capability| capability.name.into()).collect();
    names.sort();
    assert_eq!(names, ["exports add", "exports add and imports puts"]);
}
