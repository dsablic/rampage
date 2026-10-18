use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::{Project, Session, tools};
use serde_json::{Value, json};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-api-patch-frontends-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::copy(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf"),
            directory.join("source.elf"),
        )
        .unwrap();
        Self(directory)
    }

    fn project(&self) -> Arc<Project> {
        let project = Session::default().open(&self.0.join("source.elf"), None).unwrap();
        project.set_decompiler_worker(None);
        project
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn call(project: &mut Arc<Project>, name: &str, input: Value) -> Value {
    let (text, failed) = tools::call_shared(&tools::tools(), project, name, input);
    assert!(!failed, "{name}: {text}");
    assert!(text.len() <= 60000);
    serde_json::from_str(&text).expect("complete bounded JSON")
}

fn patch(receipt: &Value) -> Value {
    json!({
        "at": "0x100191e", "original_hex": "b805000000", "replacement_hex": "b807000000",
        "allow_data": false, "source_sha256": receipt["source_sha256"],
        "expected_revision": receipt["revision_sha256"],
    })
}

fn assert_return(project: &mut Arc<Project>, value: u8) {
    let output = call(project, "decompile", json!({"at":"main", "view":"code"}));
    assert!(output["code"].as_str().unwrap().contains(&format!("return {value};")), "{output}");
}

#[test]
fn shared_dispatch_keeps_native_reads_history_and_export_on_the_effective_revision() {
    let fixture = Fixture::new();
    let original = std::fs::read(fixture.0.join("source.elf")).unwrap();
    let mut project = fixture.project();
    let held = Arc::clone(&project);
    assert_return(&mut project, 5);
    let review = call(&mut project, "list_patches", json!({}));
    let result = call(&mut project, "patch_bytes", patch(&review["receipt"]));
    assert_eq!(result["changed"], true);
    assert!(!Arc::ptr_eq(&held, &project));
    assert_return(&mut project, 7);
    assert!(held.decompile(held.resolve("main").unwrap()).unwrap().code.contains("return 5;"));
    call(&mut project, "undo", json!({}));
    assert_return(&mut project, 5);
    call(&mut project, "redo", json!({}));
    assert_return(&mut project, 7);
    let review = call(&mut project, "list_patches", json!({}));
    let destination = fixture.0.join("export.elf");
    call(
        &mut project,
        "export_patched",
        json!({
            "destination": destination, "source_sha256": review["receipt"]["source_sha256"],
            "expected_revision": review["receipt"]["revision_sha256"],
        }),
    );
    let mut exported = Session::default().open(&destination, None).unwrap();
    exported.set_decompiler_worker(None);
    assert_return(&mut exported, 7);
    assert_eq!(std::fs::read(fixture.0.join("source.elf")).unwrap(), original);
    assert!(!fixture.0.join("export.elf.rampage").exists());
    call(
        &mut project,
        "revert_patch",
        json!({
            "at": "0x100191e", "source_sha256": review["receipt"]["source_sha256"],
            "expected_revision": review["receipt"]["revision_sha256"],
        }),
    );
    assert_return(&mut project, 5);
}

#[test]
fn invalid_inputs_and_borrowed_dispatch_cannot_silently_patch_or_truncate_receipts() {
    let fixture = Fixture::new();
    let mut project = fixture.project();
    let review = call(&mut project, "list_patches", json!({}));
    let request = patch(&review["receipt"]);
    let (text, failed) = tools::call(&tools::tools(), &project, "patch_bytes", request.clone());
    assert!(failed && text.contains("call_shared"), "{text}");
    for (field, value) in [
        ("original_hex", json!("b807000000")),
        ("original_hex", json!("B805000000")),
        ("replacement_hex", json!("b8")),
        ("replacement_hex", json!("1")),
        ("replacement_hex", json!("00".repeat(4097))),
        ("expected_revision", json!("0".repeat(64))),
        ("source_sha256", json!("0".repeat(64))),
    ] {
        let mut invalid = request.clone();
        invalid[field] = value;
        let (text, failed) = tools::call_shared(&tools::tools(), &mut project, "patch_bytes", invalid);
        assert!(failed, "{field}: {text}");
        assert!(project.list_patches().unwrap().is_empty());
    }
    let mut missing_consent = request;
    missing_consent.as_object_mut().unwrap().remove("allow_data");
    assert!(tools::call_shared(&tools::tools(), &mut project, "patch_bytes", missing_consent).1);
    assert_eq!(call(&mut project, "list_patches", json!({}))["receipt"], review["receipt"]);
    let tool = tools::tools().into_iter().find(|tool| tool.name == "export_patched").unwrap();
    assert_eq!(tool.effect, tools::Effect::FileWrite);
}
