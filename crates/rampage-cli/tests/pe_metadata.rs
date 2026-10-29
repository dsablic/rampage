use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn rampage(arguments: &[&str], file: &str) -> String {
    let mut command = Command::cargo_bin("rampage").unwrap();
    command.env_remove("RAMPAGE_PACKS").env("NO_COLOR", "1").write_stdin("");
    let output = command.args(arguments).arg(fixture(file)).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn binary_pe_resources_lists_and_decodes() {
    let text = rampage(&["binary", "pe-resources"], "pe-metadata-x64.exe");
    assert!(text.contains("types      BLOB 1, RT_STRING 1, RT_VERSION 1, RT_MANIFEST 1"), "{text}");
    assert!(text.contains("040904B0   CompanyName = Rampage Fixtures"), "{text}");
    assert!(text.contains("level      requireAdministrator (uiAccess false)"), "{text}");
    let page = rampage(&["binary", "pe-resources", "--type", "string", "--json"], "pe-metadata-x86.exe");
    let page: Value = serde_json::from_str(&page).unwrap();
    assert_eq!(page["resources"]["total"], 1);
    assert_eq!(page["resources"]["items"][0]["type_name"], "RT_STRING");
    assert_eq!(rampage(&["binary", "pe-resources", "--json"], "hello-x64.elf").trim(), "null");
    assert_eq!(rampage(&["binary", "pe-resources"], "hello-x64.elf").trim(), "not a PE image");
}

#[test]
fn binary_pe_load_config_reports_tables_and_findings() {
    let text = rampage(&["binary", "pe-load-config"], "pe-metadata-x86.exe");
    assert!(text.contains("config    RVA 0x36000, size 92 (92 read)"), "{text}");
    assert!(text.contains("safeseh   2 at "), "{text}");
    assert!(text.contains("finding: the load config is CF_INSTRUMENTED"), "{text}");
    let report: Value =
        serde_json::from_str(&rampage(&["binary", "pe-load-config", "--json"], "pe-metadata-x64.exe")).unwrap();
    assert_eq!(report["load_config"]["eh_continuations"]["count"], 2);
    assert_eq!(rampage(&["binary", "pe-load-config", "--json"], "hello-x64.elf").trim(), "null");
}
