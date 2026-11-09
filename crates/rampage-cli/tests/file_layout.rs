use std::path::PathBuf;

use assert_cmd::Command;
use predicates::str::contains;
use serde_json::Value;

use crate::contract_support::layout_fixture;

struct Input(PathBuf);

impl Input {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("rampage-cli-file-layout-{name}-{}.bin", std::process::id()));
        std::fs::write(&path, layout_fixture()).unwrap();
        Self(path)
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn rampage() -> Command {
    let mut command = Command::cargo_bin("rampage").unwrap();
    command.env_remove("RAMPAGE_PACKS");
    command
}

#[test]
fn binary_layout_json_matches_the_mcp_report_and_text_lists_the_map() {
    let input = Input::new("json");
    let output =
        rampage().args(["--json", "binary", "layout"]).arg(&input.0).args(["--length", "0x100"]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let cli: Value = serde_json::from_slice(&output.stdout).unwrap();
    let request = rampage_api::FileLayoutRequest {
        length: Some(rampage_api::FileOffset(0x100)),
        utf16: Some(false),
        hints: Some(true),
        ..Default::default()
    };
    let api = serde_json::to_value(rampage_api::file_layout(&input.0, &request).unwrap()).unwrap();
    assert_eq!(cli, api, "the CLI prints the same report as the MCP tool");
    assert_eq!(cli["hints"][0]["kind"], "cortex_m_vector_table_candidate");

    rampage()
        .args(["binary", "layout"])
        .arg(&input.0)
        .args(["--block-size", "256", "--block-limit", "2"])
        .assert()
        .success()
        .stdout(contains("regions:"))
        .stdout(contains("fill 0xff"))
        .stdout(contains("cortex_m_vector_table_candidate: initial SP 0x20002000, reset 0x101"))
        .stdout(contains("\"rampage layout fixture\""))
        .stdout(contains("suggested --block-size 2048"))
        .stdout(contains("continue with --offset 0x200 --length"));
}

#[test]
fn binary_layout_refuses_empty_ranges_and_image_selectors() {
    let input = Input::new("refuse");
    rampage()
        .args(["binary", "layout"])
        .arg(&input.0)
        .args(["--length", "0"])
        .assert()
        .failure()
        .stderr(contains("non-empty"));
    rampage()
        .args(["--arch", "arm", "binary", "layout"])
        .arg(&input.0)
        .assert()
        .failure()
        .stderr(contains("binary layout does not accept --arch"));
}
