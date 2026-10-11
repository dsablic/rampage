use std::path::PathBuf;

#[test]
fn relocated_executable_uses_embedded_specs_with_an_empty_home_and_no_ghidra() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!("rampage-relocated-{}", std::process::id()));
    assert!(!root.exists());
    std::fs::create_dir(&root).unwrap();
    let result = (|| {
        let executable = root.join("rampage");
        std::fs::copy(assert_cmd::cargo::cargo_bin("rampage"), &executable)?;
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
        let output = std::process::Command::new(executable)
            .args(["decompile", "--at", "add"])
            .arg(fixture)
            .env("HOME", &root)
            .env("PATH", "")
            .env_remove("GHIDRA_INSTALL_DIR")
            .output()?;
        if !output.status.success() || !String::from_utf8_lossy(&output.stdout).contains("add(") {
            return Err(std::io::Error::other(String::from_utf8_lossy(&output.stderr).into_owned()));
        }
        let cache = root.join(".cache/rampage");
        let materialized = std::fs::read_dir(cache)?
            .filter_map(Result::ok)
            .any(|entry| entry.path().join("Ghidra/Processors/x86/data/languages/x86-64.sla").is_file());
        if !materialized {
            return Err(std::io::Error::other("embedded specifications were not materialized"));
        }
        Ok::<_, std::io::Error>(())
    })();
    std::fs::remove_dir_all(root).unwrap();
    result.unwrap();
}
