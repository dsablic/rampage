//! The `--json` output of the main CLI commands (docs/stability.md: the same rules as MCP result fields), pinned as
//! the field paths each prints on committed fixtures in `tests/contract/cli-json.json`. Command routes and flags
//! are pinned by `contract_tests` in the binary. `tests/contract/support.rs` classifies the differences.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use assert_cmd::Command;

use crate::contract_support as contract;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

/// A copy of the ELF fixture in a fresh directory, so annotation commands write beside the copy.
struct Copy(PathBuf);

impl Copy {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!("rampage-cli-contract-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("hello-x64.elf");
        std::fs::copy(fixture("hello-x64.elf"), &path).unwrap();
        Self(path)
    }
}

impl Drop for Copy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
    }
}

#[test]
fn contract_cli_json_fields() {
    let copy = Copy::new();
    let elf = copy.0.to_str().unwrap().to_owned();
    let exe = fixture("hello-x64.exe").to_str().unwrap().to_owned();
    let firmware = copy.0.with_file_name("firmware.bin");
    std::fs::write(&firmware, contract::layout_fixture()).unwrap();
    let firmware = firmware.to_str().unwrap().to_owned();
    let commands: Vec<Vec<&str>> = vec![
        vec!["binary", "layout", &firmware, "--block-size", "512", "--block-limit", "2", "--utf16"],
        vec!["binary", "inspect", &elf],
        vec!["binary", "triage", &elf],
        vec!["binary", "detect", &exe],
        vec!["binary", "capabilities", &exe],
        vec!["binary", "list-imports", &exe],
        vec!["binary", "audit", &elf],
        vec!["function", "list", &elf],
        vec!["function", "disassemble", &elf, "--at", "main", "--count", "4"],
        vec!["function", "decompile", &elf, "--at", "main"],
        vec!["function", "xrefs", &elf, "--from", "main"],
        vec!["string", "list", &elf],
        vec!["annotation", "rename", &elf, "main", "compat_main"],
        vec!["annotation", "comment", &elf, "compat_main", "entry"],
        vec!["annotation", "list", &elf],
        vec!["annotation", "record-finding", &elf, "--kind", "finding", "--text", "main calls add"],
        vec!["annotation", "list-findings", &elf],
        vec!["pack", "list"],
    ];
    let mut observed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for arguments in commands {
        let route = arguments.iter().take(2).copied().collect::<Vec<_>>().join(" ");
        let output = Command::cargo_bin("rampage")
            .unwrap()
            .env_remove("RAMPAGE_PACKS")
            .arg("--json")
            .args(&arguments)
            .output()
            .unwrap();
        assert!(output.status.success(), "{route}: {}", String::from_utf8_lossy(&output.stderr));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{route}: {error}: {}", String::from_utf8_lossy(&output.stdout)));
        observed.entry(route).or_default().extend(contract::field_paths(&value));
    }
    contract::check("cli-json.json", &contract::field_snapshot(&observed), contract::compare_fields);
}
