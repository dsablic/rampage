use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::time::Duration;

use rampage_api::{ModuleReferenceMetadataStatus, Project};
use rampage_loaders::Binary;

use super::*;

mod fixtures;

fn inputs() -> Vec<ModuleReferenceInput> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
    ["first", "second"]
        .into_iter()
        .map(|id| ModuleReferenceInput {
            module_id: id.into(),
            project: Arc::new(Project::new(Binary::open(&path).unwrap())),
        })
        .collect()
}

fn collect(state: &mut ModuleReferences, inputs: &[ModuleReferenceInput]) {
    let Some(Job::Running(receiver)) = &state.job else { panic!("expected background query") };
    let result = receiver.recv_timeout(Duration::from_secs(10)).unwrap();
    state.job = Some(Job::Done(result));
    state.poll(inputs);
}

#[test]
fn opening_and_repainting_never_start_a_query() {
    let ctx = egui::Context::default();
    let inputs = inputs();
    let mut state = ModuleReferences::default();
    state.show();
    for _ in 0..3 {
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            assert!(show(ui.ctx(), &mut state, true, &inputs).is_none());
        });
        output.textures_delta.clear();
    }
    assert!(state.job.is_none());
    assert!(state.view.is_none());
    assert!(!state.running());
}

#[test]
fn invalid_typed_queries_are_rejected_before_starting_work() {
    let ctx = egui::Context::default();
    let inputs = inputs();
    let mut state = ModuleReferences::default();
    for page in ["0", "257", "-1", "184467440737095516160", "invalid"] {
        state.draft.page_size = page.into();
        state.apply(&ctx, true, &inputs);
        assert!(state.error.is_some());
        assert!(state.job.is_none());
        assert!(state.view.is_none());
        assert!(state.binding.is_empty());
    }
    state.draft.page_size.clear();
    state.draft.filter = "é".repeat(129);
    state.apply(&ctx, true, &inputs);
    assert!(state.binding.is_empty());
    state.draft.filter.clear();
    state.draft.slot = "0xffffffffffffffff0".into();
    state.apply(&ctx, true, &inputs);
    assert!(state.binding.is_empty());
    state.draft.slot = "0xffffffffffffffff".into();
    assert_eq!(state.draft.query(&inputs).unwrap().source_slot, Some(u64::MAX));
}

#[test]
fn real_elf_query_keeps_unsupported_coverage_and_whole_bank_membership() {
    let ctx = egui::Context::default();
    let mut inputs = inputs();
    let mut state = ModuleReferences::default();
    state.apply(&ctx, true, &inputs);
    let view = state.view.as_ref().unwrap();
    assert_eq!(view.report().coverage.len(), 2);
    assert!(view.report().coverage.iter().all(|coverage| {
        coverage.metadata_status == ModuleReferenceMetadataStatus::Unsupported && !coverage.omissions.is_empty()
    }));
    assert!(view.report().rows.is_empty());
    assert!(!view.report().proven_runtime_flow);
    assert!(!view.report().proven_layout);
    inputs[0].project.comment(0, Some("unrelated annotation")).unwrap();
    inputs.reverse();
    state.poll(&inputs);
    assert!(state.authority, "active selection/order and annotations are not query inputs");
    inputs.pop();
    state.poll(&inputs);
    assert!(!state.authority);
    assert!(state.view.is_some(), "coverage remains visible as historical observations");
}

#[test]
fn cancelled_closed_and_replaced_queries_hold_the_real_execution_lease() {
    let ctx = egui::Context::default();
    let original = inputs();
    let replacement = inputs();
    let mut state = ModuleReferences::default();
    let (started, wait_started) = channel();
    let (release, wait_release) = channel();
    state.start_execution(&ctx, false, &original, move |inputs| {
        started.send(()).unwrap();
        wait_release.recv_timeout(Duration::from_secs(10)).unwrap();
        prepare_module_reference_view(inputs, &ModuleReferenceQuery::default()).map_err(|error| error.to_string())
    });
    wait_started.recv_timeout(Duration::from_secs(10)).unwrap();
    for inputs in [&original, &replacement] {
        state.invalidate();
        state.close();
        state.show();
        state.poll(inputs);
        assert!(state.running());
        state.start_execution(&ctx, true, inputs, |_| panic!("must not spawn a second operation"));
        assert!(state.gate.0.load(Ordering::Acquire));
    }
    release.send(()).unwrap();
    collect(&mut state, &replacement);
    assert!(!state.running());
    assert!(state.view.is_none());
    state.apply(&ctx, true, &replacement);
    assert!(state.authority);
}

#[test]
fn changing_filters_cancels_inflight_results_without_an_automatic_retry() {
    let ctx = egui::Context::default();
    let inputs = inputs();
    let mut state = ModuleReferences::default();
    let (started, wait_started) = channel();
    let (release, wait_release) = channel();
    state.start_execution(&ctx, false, &inputs, move |inputs| {
        started.send(()).unwrap();
        wait_release.recv_timeout(Duration::from_secs(10)).unwrap();
        prepare_module_reference_view(inputs, &ModuleReferenceQuery::default()).map_err(|error| error.to_string())
    });
    wait_started.recv_timeout(Duration::from_secs(10)).unwrap();
    state.draft.filter = "changed".into();
    state.invalidate();
    release.send(()).unwrap();
    collect(&mut state, &inputs);
    assert!(!state.running());
    assert!(state.view.is_none());
    state.poll(&inputs);
    assert!(state.job.is_none());
}

#[test]
fn same_id_different_arc_is_a_replacement_not_a_selection_change() {
    let first = inputs();
    let replacement = inputs();
    assert!(!same_inputs(&first, &replacement));
    assert!(same_inputs(&first, &[first[1].clone(), first[0].clone()]));
}

#[test]
fn dropping_the_actual_receiver_does_not_release_the_worker_execution_lease() {
    let ctx = egui::Context::default();
    let inputs = inputs();
    let mut original = ModuleReferences::default();
    let (started, wait_started) = channel();
    let (release, wait_release) = channel();
    original.start_execution(&ctx, false, &inputs, move |inputs| {
        started.send(()).unwrap();
        wait_release.recv_timeout(Duration::from_secs(10)).unwrap();
        prepare_module_reference_view(inputs, &Default::default()).map_err(|error| error.to_string())
    });
    wait_started.recv_timeout(Duration::from_secs(10)).unwrap();
    let gate = ExecutionGate(Arc::clone(&original.gate.0));
    drop(original);
    let mut replacement = ModuleReferences::default();
    replacement.gate = gate;
    replacement.start_execution(&ctx, true, &inputs, |_| panic!("orphaned execution still owns its permit"));
    assert!(replacement.running());
    assert!(replacement.job.is_none());
    release.send(()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while replacement.gate.0.load(Ordering::Acquire) {
        assert!(std::time::Instant::now() < deadline, "orphaned worker did not release its execution lease");
        std::thread::yield_now();
    }
    replacement.apply(&ctx, true, &inputs);
    assert!(replacement.authority);
}

#[test]
fn exhausted_matching_budget_remains_visible_even_when_the_real_report_has_no_rows() {
    use egui_kittest::kittest::Queryable;

    let source = fixtures::ExportSource::new();
    let inputs = [source.input()];
    let query = ModuleReferenceQuery { matching_work_limit: Some(0), ..Default::default() };
    let view = prepare_module_reference_view(&inputs, &query).unwrap();
    assert!(view.report().rows.is_empty());
    assert!(view.report().matching_work_exhausted);
    assert!(!view.report().complete);
    assert_eq!(view.report().coverage[0].metadata_status, ModuleReferenceMetadataStatus::Complete);
    assert!(view.report().coverage[0].metadata_lookup_work > 0);
    let mut harness = egui_kittest::Harness::builder().build_ui_state(
        |ui, view: &mut ModuleReferenceView| {
            render_report(ui, view, false, &mut None);
        },
        view,
    );
    harness.run();
    harness.get_by_label("Matching work: exhausted=true; used=0; limit=0 (separate from loader work)");
    harness.get_by_label("All observed rows (not only successful declarations)");
}
