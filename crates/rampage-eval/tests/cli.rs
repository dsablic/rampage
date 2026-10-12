use std::path::PathBuf;

use assert_cmd::Command;
use rampage_eval::Truth;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn eval() -> Command {
    Command::cargo_bin("rampage-eval").unwrap()
}

#[test]
fn truth_prints_the_symbol_table_as_json() {
    let output = eval().arg("truth").arg(fixture("hello-x64.elf")).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let truth = Truth::from_json(&String::from_utf8(output.stdout).unwrap()).unwrap();
    assert!(truth.0.values().any(|name| name == "main"));
}

#[test]
fn truth_rejects_a_stripped_twin_with_different_code() {
    let output = eval()
        .arg("truth")
        .arg(fixture("hello-x64.elf"))
        .arg("--stripped")
        .arg(fixture("musl-static-x86_64.elf"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a twin"), "{output:?}");
}
