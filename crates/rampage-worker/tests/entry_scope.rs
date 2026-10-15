#![cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]

use std::path::{Path, PathBuf};
use std::process::Command;

use rampage_api::{DecompileEntryRequest, DecompilerWorkerConfig, EntryDecompilation, EntryValidation, Project};
use rampage_loaders::Binary;
use serde_json::Value;

fn fixture(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests").join(relative)
}

fn worker() -> DecompilerWorkerConfig {
    DecompilerWorkerConfig { executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()), ..Default::default() }
}

fn stable_context(result: &EntryDecompilation) -> Value {
    let mut context = serde_json::to_value(&result.context).unwrap();
    let fields = context.as_object_mut().unwrap();
    fields.remove("execution");
    fields.remove("timings");
    context
}

fn assert_parity(native: &EntryDecompilation, isolated: &EntryDecompilation) {
    assert_eq!(native.context.execution, "in_process_native");
    assert_eq!(isolated.context.execution, "supervised_worker");
    let native_output = &native.decompilation;
    let worker_output = &isolated.decompilation;
    assert_eq!(worker_output.address, native_output.address);
    assert_eq!(worker_output.name, native_output.name);
    assert_eq!(worker_output.code, native_output.code);
    assert_eq!(worker_output.language_id, native_output.language_id);
    assert_eq!(worker_output.structure, native_output.structure);
    assert_eq!(worker_output.recovery_status, native_output.recovery_status);
    assert!(!native_output.tokens.is_empty());
    assert_eq!(
        serde_json::to_value(&worker_output.tokens).unwrap(),
        serde_json::to_value(&native_output.tokens).unwrap()
    );
    assert_eq!(stable_context(isolated), stable_context(native));
}

#[test]
fn exact_entry_actual_subprocess_matches_native_imports_tokens_structure_and_local_context() {
    for name in ["hello-x64-dyn.elf", "hello-arm64.elf"] {
        let project = Project::new(Binary::open(fixture(&format!("fixtures/bin/{name}"))).unwrap());
        let request = DecompileEntryRequest {
            address: project.resolve("main").unwrap(),
            validation: EntryValidation::MetadataBacked,
        };
        let native = project.decompile_entry(&request).unwrap();
        project.set_decompiler_worker(Some(worker()));
        let isolated = project.decompile_entry(&request).unwrap();
        assert_parity(&native, &isolated);
        assert!(isolated.decompilation.code.contains("return 5;"), "{name}: {}", isolated.decompilation.code);
        if name == "hello-x64-dyn.elf" {
            assert!(
                isolated.decompilation.code.contains("puts@plt(\"rampage fixture greeting\")"),
                "{}",
                isolated.decompilation.code
            );
        }
    }
}

#[test]
fn exact_entry_actual_subprocess_preserves_native_incomplete_recovery_warnings() {
    let project = Project::new(Binary::open(fixture("data/runtime-x64-bad-code.snapshot.json")).unwrap());
    let request = DecompileEntryRequest { address: 0x1000, validation: EntryValidation::AnalystAsserted };
    let native = project.decompile_entry(&request).unwrap();
    project.set_decompiler_worker(Some(worker()));
    let isolated = project.decompile_entry(&request).unwrap();
    assert_parity(&native, &isolated);
    assert_eq!(isolated.decompilation.recovery_status, rampage_api::RecoveryStatus::Incomplete);
    let diagnostics = isolated.decompilation.structure.diagnostics.as_ref().expect("native recovery diagnostics");
    assert!(diagnostics.bad_data);
    assert!(
        diagnostics
            .warnings
            .iter()
            .any(|warning| { warning.address == Some(0x1000) && warning.message.contains("Bad instruction") })
    );
}

#[test]
fn exact_entry_bad_worker_path_and_non_worker_protocol_fail_without_inline_fallback() {
    let project = Project::new(Binary::open(fixture("data/runtime-x64-bad-code.snapshot.json")).unwrap());
    let request = DecompileEntryRequest { address: 0x1000, validation: EntryValidation::AnalystAsserted };
    let missing = Path::new(env!("CARGO_MANIFEST_DIR")).join("entry-scope-missing-worker");
    assert!(!missing.exists());
    for (executable, expected) in [(missing, "spawn"), (PathBuf::from("/bin/cat"), "invalid worker protocol")] {
        project.set_decompiler_worker(Some(DecompilerWorkerConfig { executable: Some(executable), ..worker() }));
        let error = project.decompile_entry(&request).unwrap_err().to_string();
        assert!(error.contains("exact-entry worker"), "{error}");
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
#[ignore = "requires RAMPAGE_TEST_CLI pointing to the CLI executable"]
fn both_cli_spellings_dispatch_exact_entry_to_the_explicit_worker() {
    let executable = std::env::var_os("RAMPAGE_TEST_CLI")
        .expect("set RAMPAGE_TEST_CLI to the centrally built CLI before selecting this ignored test");
    for command in [&["function", "decompile"][..], &["decompile"][..]] {
        let output = Command::new(&executable)
            .arg("--json")
            .args(command)
            .arg(fixture("fixtures/bin/hello-x64-dyn.elf"))
            .args(["--at", "main", "--exact-entry", "--isolated"])
            .env("RAMPAGE_WORKER", env!("CARGO_BIN_EXE_rampage-worker"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["context"]["scope"], "exact_entry");
        assert_eq!(result["context"]["validation"], "analyst_asserted");
        assert_eq!(result["context"]["execution"], "supervised_worker");
        let code = result["code"].as_str().unwrap();
        assert!(code.contains("puts@plt(\"rampage fixture greeting\")"), "{code}");
        assert!(code.contains("return 5;"), "{code}");
    }
}
