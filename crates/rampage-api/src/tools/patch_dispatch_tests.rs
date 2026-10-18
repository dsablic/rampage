use super::*;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::channel;
use std::time::Duration;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-dispatch-race-{}-{}",
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
        Arc::new(Project::new(rampage_loaders::Binary::open(self.0.join("source.elf")).unwrap()))
    }

    fn writer(
        &self,
    ) -> (std::sync::mpsc::Sender<()>, Mutex<std::sync::mpsc::Receiver<()>>, std::thread::JoinHandle<()>) {
        let source = self.0.join("source.elf");
        let (start, started) = channel();
        let (done, finished) = channel();
        let writer = std::thread::spawn(move || {
            started.recv_timeout(Duration::from_secs(10)).unwrap();
            let mut bytes = std::fs::read(&source).unwrap();
            bytes[0x91f] = 9;
            std::fs::write(source, bytes).unwrap();
            done.send(()).unwrap();
        });
        (start, Mutex::new(finished), writer)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn test_tool(handler: Handler) -> Tool {
    Tool {
        group: Group::Core,
        name: "commit_then_source_race",
        description: "owned test",
        input_schema: schema::<Nothing>(),
        interactive: false,
        effect: Effect::Annotations,
        reads_annotations: true,
        handler,
    }
}

#[test]
fn bound_dispatch_checks_run_revision_even_when_live_original_arc_did_not_change() {
    let fixture = Fixture::new();
    let mut project = fixture.project();
    let expected = project.annotation_revision().unwrap();
    let main = project.resolve("main").unwrap();
    project.comment(main, Some("external edit after executor preflight")).unwrap();
    let ((text, failed), stamp) = call_shared_bound_revision(
        &tools(),
        &mut project,
        "rename",
        serde_json::json!({"at":"main","name":"must_not_dispatch"}),
        Some(&expected),
    );
    assert!(failed && text.contains("no tool dispatched"), "{text}");
    assert!(stamp.is_none());
    assert!(project.resolve("must_not_dispatch").is_err());
}

fn shared_patch_transition_case(external_metadata: bool, noop: bool) {
    let fixture = Fixture::new();
    let mut project = fixture.project();
    if noop {
        project = project.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap().project;
    }
    let receipt = project.patch_receipt().unwrap();
    project = project.effective_snapshot().unwrap();
    let expected = project.annotation_revision().unwrap();
    let external = Arc::clone(&project);
    let main = external.resolve("main").unwrap();
    let (entered, handler_entered) = channel();
    let (changed, metadata_changed) = channel();
    let writer = std::thread::spawn(move || {
        handler_entered.recv_timeout(Duration::from_secs(10)).unwrap();
        if external_metadata {
            external.comment(main, Some("metadata between bound precheck and patch transaction")).unwrap();
        }
        changed.send(()).unwrap();
    });
    let mut tool = tools().into_iter().find(|tool| tool.name == "patch_bytes").unwrap();
    let Handler::Shared(original) = tool.handler else {
        panic!("patch tool must use shared dispatch");
    };
    let metadata_changed = Mutex::new(metadata_changed);
    tool.handler = Handler::Shared(Box::new(move |project, input| {
        entered.send(()).unwrap();
        metadata_changed.lock().unwrap().recv_timeout(Duration::from_secs(10)).unwrap();
        original(project, input)
    }));
    let ((text, failed), revision) = call_shared_bound_revision(
        &[tool],
        &mut project,
        "patch_bytes",
        serde_json::json!({
            "at":"0x100191e", "original_hex":"b805000000", "replacement_hex":"b807000000",
            "allow_data":false, "source_sha256":receipt.source_sha256, "expected_revision":receipt.revision_sha256,
        }),
        Some(&expected),
    );
    writer.join().unwrap();
    assert!(!failed, "admitted patch completion must remain successful: {text}");
    let result: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(result["changed"], !noop);
    assert_eq!(result["receipt"]["active_ranges"], 1);
    assert_eq!(project.list_patches().unwrap().len(), 1);
    assert!(result.get("before_annotation_revision").is_none());
    assert!(result.get("after_annotation_revision").is_none());
    if external_metadata {
        assert!(revision.is_none(), "external before-witness must not be attributed to the run");
        assert_eq!(project.comment_at(main).as_deref(), Some("metadata between bound precheck and patch transaction"));
    } else {
        assert!(Arc::ptr_eq(&revision.unwrap(), &project.annotation_revision().unwrap()));
    }
}

#[test]
fn atomic_patch_witness_rejects_external_metadata_between_bound_precheck_and_transaction_including_noop() {
    for noop in [false, true] {
        shared_patch_transition_case(true, noop);
    }
}

#[test]
fn atomic_patch_witness_accepts_own_transition_including_noop_without_serializing_witness() {
    for noop in [false, true] {
        shared_patch_transition_case(false, noop);
    }
}

#[test]
fn bound_shared_patch_requires_after_witness_to_match_installed_frozen_project() {
    let fixture = Fixture::new();
    let mut project = fixture.project();
    let review = project.patch_receipt().unwrap();
    project = project.effective_snapshot().unwrap();
    let expected = project.annotation_revision().unwrap();
    let tool = test_tool(Handler::Shared(Box::new(move |project, _| {
        let outcome = project
            .patch_bytes_reviewed(
                0x100191e,
                &[0xb8, 5, 0, 0, 0],
                &[0xb8, 7, 0, 0, 0],
                false,
                &review.source_sha256,
                &review.revision_sha256,
            )
            .map_err(|error| error_chain(&error))?;
        let mut result =
            SharedResult::patch(serde_json::json!({"changed":outcome.changed,"receipt":outcome.receipt}), &outcome);
        result.transition.as_mut().unwrap().after = Arc::new(());
        *project = outcome.project;
        Ok(result)
    })));
    let ((text, failed), revision) = call_shared_bound_revision(
        &[tool],
        &mut project,
        "commit_then_source_race",
        serde_json::json!({}),
        Some(&expected),
    );
    assert!(!failed, "{text}");
    assert!(revision.is_none());
    assert_eq!(serde_json::from_str::<Value>(&text).unwrap()["changed"], true);
    assert_eq!(project.list_patches().unwrap().len(), 1);
}

#[test]
fn committed_shared_patch_receipt_survives_source_change_after_outcome_installation() {
    let fixture = Fixture::new();
    let mut project = fixture.project();
    let (start, finished, writer) = fixture.writer();
    let tool = test_tool(Handler::Shared(Box::new(move |project, _| {
        let outcome = project
            .patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false)
            .map_err(|error| error_chain(&error))?;
        let result = SharedResult::patch(
            serde_json::json!({ "changed": outcome.changed, "receipt": outcome.receipt }),
            &outcome,
        );
        *project = outcome.project;
        start.send(()).unwrap();
        finished.lock().unwrap().recv_timeout(Duration::from_secs(10)).unwrap();
        Ok(result)
    })));
    let (text, failed) = call_shared(&[tool], &mut project, "commit_then_source_race", serde_json::json!({}));
    writer.join().unwrap();
    assert!(!failed, "committed patch must not be relabeled as failure: {text}");
    let result: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(result["changed"], true);
    assert_eq!(result["receipt"]["active_ranges"], 1);
    assert_eq!(project.list_patches().unwrap().len(), 1);
    assert!(project.effective_snapshot().is_err(), "the redundant refresh would have failed");
}

#[test]
fn committed_borrowed_annotation_retains_receipt_and_success_when_post_commit_refresh_fails() {
    let fixture = Fixture::new();
    let root = fixture.project();
    let mut project = root.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap().project;
    let (start, finished, writer) = fixture.writer();
    let tool = test_tool(Handler::Borrowed(Box::new(move |project, _| {
        let receipt =
            project.comment(0x100191e, Some("committed before source race")).map_err(|error| error_chain(&error))?;
        start.send(()).unwrap();
        finished.lock().unwrap().recv_timeout(Duration::from_secs(10)).unwrap();
        Ok(serde_json::to_value(receipt).unwrap())
    })));
    let (text, failed) = call_shared(&[tool], &mut project, "commit_then_source_race", serde_json::json!({}));
    writer.join().unwrap();
    assert!(!failed, "annotation commit must remain a successful tool effect: {text}");
    assert!(text.len() <= MAX_RESULT_CHARS);
    let result: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(result["post_commit_refresh"]["status"], "unavailable");
    assert_eq!(result["post_commit_refresh"]["handler_succeeded"], true);
    assert_eq!(result["post_commit_refresh"]["rollback_performed"], false);
    assert_eq!(result["result"]["value"], "committed before source race");
    assert!(project.effective_snapshot().is_err());
}

#[test]
fn near_limit_comment_commit_and_failed_refresh_return_complete_explicitly_compacted_evidence() {
    let fixture = Fixture::new();
    let root = fixture.project();
    let mut project = root.patch_bytes(0x100191e, &[0xb8, 5, 0, 0, 0], &[0xb8, 7, 0, 0, 0], false).unwrap().project;
    let empty = serde_json::json!({ "address":"0x100191e", "field":"comment", "value":"", "changed":true });
    let comment = "x".repeat(MAX_RESULT_CHARS - 10 - empty.to_string().len());
    let expected = serde_json::json!({ "address":"0x100191e", "field":"comment", "value":comment, "changed":true });
    assert_eq!(expected.to_string().len(), MAX_RESULT_CHARS - 10);
    let (start, finished, writer) = fixture.writer();
    let text = comment.clone();
    let authority = Arc::clone(&project);
    let tool = test_tool(Handler::Borrowed(Box::new(move |project, _| {
        let receipt = project.comment(0x100191e, Some(&text)).map_err(|error| error_chain(&error))?;
        assert_eq!(authority.effective_snapshot().unwrap().comment_at(0x100191e).as_deref(), Some(text.as_str()));
        start.send(()).unwrap();
        finished.lock().unwrap().recv_timeout(Duration::from_secs(10)).unwrap();
        Ok(serde_json::to_value(receipt).unwrap())
    })));
    let (text, failed) = call_shared(&[tool], &mut project, "commit_then_source_race", serde_json::json!({}));
    writer.join().unwrap();
    assert!(!failed, "{text}");
    assert!(text.len() <= MAX_RESULT_CHARS);
    let result: Value = serde_json::from_str(&text).expect("committed receipts must never become truncated text");
    assert_eq!(result["post_commit_refresh"]["status"], "unavailable");
    assert_eq!(result["handler_succeeded"], true);
    assert_eq!(result["rollback_performed"], false);
    assert_eq!(result["full_result_omitted"], true);
    assert_eq!(result["full_result_json_bytes"], MAX_RESULT_CHARS - 10);
    assert_eq!(result["full_result_sha256"], result_digest(expected.to_string().as_bytes()));
    assert_eq!(result["commit_evidence"]["changed"], true);
    assert_eq!(result["commit_evidence"]["field"], "comment");
    assert_eq!(result["commit_evidence"]["value"]["omitted"], true);
    assert_eq!(
        result["commit_evidence"]["value"]["sha256"],
        result_digest(serde_json::to_string(&comment).unwrap().as_bytes())
    );
    assert!(project.effective_snapshot().is_err(), "source modification must keep the old mapping invalid");
}
