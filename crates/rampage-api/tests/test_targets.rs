use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Crates that set `autotests = false` compile only the test files their `tests/integration.rs` declares, so a new
/// `tests/*.rs` without a `mod` line there would never build or run.
#[test]
fn every_workspace_test_file_belongs_to_a_test_target() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut checked = 0;
    for entry in fs::read_dir(&crates).unwrap() {
        let root = entry.unwrap().path();
        let Ok(manifest) = fs::read_to_string(root.join("Cargo.toml")) else { continue };
        if !manifest.lines().any(|line| line.trim() == "autotests = false") {
            continue;
        }
        let integration = fs::read_to_string(root.join("tests/integration.rs")).unwrap();
        let declared: BTreeSet<String> = integration
            .lines()
            .filter_map(|line| line.strip_prefix("mod ")?.strip_suffix(';'))
            .map(|name| format!("{name}.rs"))
            .collect();
        let missing: Vec<String> = fs::read_dir(root.join("tests"))
            .unwrap()
            .map(|file| file.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.ends_with(".rs") && name != "integration.rs")
            .filter(|name| !declared.contains(name) && !manifest.contains(&format!("path = \"tests/{name}\"")))
            .collect();
        assert!(missing.is_empty(), "{}: add `mod` lines to tests/integration.rs for {missing:?}", root.display());
        checked += 1;
    }
    assert!(checked > 0, "no crate under {} sets autotests = false", crates.display());
}
