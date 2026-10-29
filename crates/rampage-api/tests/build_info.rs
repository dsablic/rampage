use std::path::PathBuf;

use rampage_api::{BuildInfoQuery, ReportLimits, Session};
use serde_json::json;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn build_info(name: &str, offset: usize, limit: usize) -> serde_json::Value {
    let project = Session::default().open(&fixture(name), None).unwrap();
    let query = BuildInfoQuery { offset: Some(offset), limit: Some(limit) };
    serde_json::to_value(project.build_info(&query).unwrap()).unwrap()
}

#[test]
fn go_build_info_pages_deps_and_cross_checks_the_pclntab() {
    let info = build_info("buildinfo-go-x64.elf", 0, 10);
    assert_eq!(info["rust"], json!(null));
    let go = &info["go"];
    assert_eq!(go["status"], "present");
    assert_eq!(go["layout"], "inline");
    assert_eq!(go["path"], "example.com/buildinfo");
    assert_eq!(go["main"], json!({ "path": "example.com/buildinfo", "version": "(devel)" }));
    assert_eq!(
        go["deps"],
        json!({
            "total": 1,
            "offset": 0,
            "items": [{
                "path": "example.com/greet",
                "version": "v0.1.0",
                "replace": { "path": "./greet", "version": "(devel)" },
            }],
            "next_offset": null,
            "byte_capped": false,
        })
    );
    let settings = go["settings"].as_array().unwrap();
    assert_eq!(
        (go["settings_total"].as_u64(), go["settings_byte_capped"].as_bool()),
        (Some(settings.len() as u64), Some(false))
    );
    assert_eq!(go["pclntab"], json!({ "table": "go120", "expected": "go120", "consistent": true }));
    assert!(go["settings"].as_array().unwrap().contains(&json!({ "key": "GOARCH", "value": "amd64" })));
    assert!(!info["limitations"].as_array().unwrap().is_empty());

    let past = build_info("buildinfo-go-x64.elf", 5, 10);
    assert_eq!(
        past["go"]["deps"],
        json!({ "total": 1, "offset": 1, "items": [], "next_offset": null, "byte_capped": false })
    );
}

#[test]
fn rust_audit_data_pages_packages_and_keeps_the_root() {
    let info = build_info("auditable-x64.exe", 1, 2);
    assert_eq!(info["go"], json!(null));
    let rust = &info["rust"];
    assert_eq!(rust["status"], "present");
    assert_eq!(rust["roots"][0]["name"], "auditable-fixture");
    assert_eq!(rust["roots_total"], 1);
    let packages = &rust["packages"];
    assert_eq!((packages["total"].as_u64(), packages["offset"].as_u64()), (Some(4), Some(1)));
    let names: Vec<&str> =
        packages["items"].as_array().unwrap().iter().map(|item| item["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["serde", "cc"]);
    assert_eq!((packages["next_offset"].as_u64(), packages["byte_capped"].as_bool()), (Some(3), Some(false)));
    assert_eq!(packages["items"][1]["kind"], "build");
}

#[test]
fn ordinary_binaries_report_both_records_absent() {
    let info = build_info("hello-x64.elf", 0, 100);
    assert_eq!((&info["go"], &info["rust"]), (&json!(null), &json!(null)));
}

#[test]
fn triage_report_suggests_build_info_only_when_a_record_is_present() {
    for (name, expected) in [("buildinfo-go-x64.elf", true), ("auditable-x64.elf", true), ("hello-x64.elf", false)] {
        let project = Session::default().open(&fixture(name), None).unwrap();
        let report = project.triage_report(ReportLimits::default()).unwrap();
        let suggested = report.next_steps.iter().any(|step| step.tool == "build_info");
        assert_eq!(suggested, expected, "{name}: {:?}", report.next_steps);
    }
}
