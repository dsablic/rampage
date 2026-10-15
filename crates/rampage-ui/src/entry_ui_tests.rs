use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::{SyncSender, sync_channel};

use super::*;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use rampage_api::Session;
use rampage_loaders::Binary;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn workspace(name: &str) -> Workspace {
    let path = fixture(name);
    let project = Arc::new(Project::new(Binary::open(&path).unwrap()));
    Workspace::from_loaded_project(path, None, project, &egui::Context::default(), true, true)
}

fn assert_ui_jobs_idle(workspace: &Workspace) {
    let status = workspace.project.analysis_cache_status();
    assert!(!status.program && !status.strings && !status.triage, "backend caches initialized: {status:?}");
    assert!(matches!(workspace.functions, Job::Idle));
    assert!(matches!(workspace.triage, Job::Idle));
    assert!(matches!(workspace.strings, Job::Idle));
    assert!(matches!(workspace.pseudocode, Job::Idle));
    assert!(workspace.listing.is_none());
    assert!(workspace.xrefs.is_none());
    assert!(workspace.graph.is_none());
}

fn binding(workspace: &Workspace, entry: &EntryUi) -> Binding {
    Binding {
        instance: Arc::clone(&workspace.instance),
        project: Arc::clone(&workspace.project),
        epoch: Arc::clone(&workspace.annotations_epoch),
        revision: Arc::clone(&entry.revision),
        request_id: entry.request_id,
        address: workspace.cursor,
        validation: entry.validation,
        configuration: workspace.project.decompiler_configuration_revision().unwrap(),
    }
}

#[derive(Default)]
struct ExecutionCounts {
    active: AtomicUsize,
    maximum: AtomicUsize,
    started: AtomicUsize,
}

struct ActiveExecution(Arc<ExecutionCounts>);

impl Drop for ActiveExecution {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

struct HeldExecution {
    release: SyncSender<Result<EntryDecompilation, String>>,
    counts: Arc<ExecutionCounts>,
}

impl HeldExecution {
    fn finish_job(self, job: &mut Job<EntryDecompilation>, result: Result<EntryDecompilation, String>) {
        self.release.send(result).unwrap();
        let Job::Running(receiver) = std::mem::replace(job, Job::Idle) else {
            panic!("controlled execution must use the production asynchronous job");
        };
        *job = Job::Done(receiver.recv_timeout(Duration::from_secs(10)).unwrap());
        assert_eq!(self.counts.active.load(Ordering::SeqCst), 0);
        assert_eq!(self.counts.maximum.load(Ordering::SeqCst), 1);
    }

    fn finish(self, entry: &mut EntryUi, workspace: &Workspace, result: Result<EntryDecompilation, String>) {
        self.finish_job(&mut entry.job, result);
        entry.poll(workspace);
    }
}

fn start_held(entry: &mut EntryUi, workspace: &Workspace, counts: Arc<ExecutionCounts>) -> HeldExecution {
    let (release, released) = sync_channel(1);
    let (started, entered) = sync_channel(1);
    let execution_counts = Arc::clone(&counts);
    entry.start_execution(workspace, &egui::Context::default(), false, move |_, _, _, progress| {
        let active = execution_counts.active.fetch_add(1, Ordering::SeqCst) + 1;
        execution_counts.maximum.fetch_max(active, Ordering::SeqCst);
        execution_counts.started.fetch_add(1, Ordering::SeqCst);
        let _active = ActiveExecution(execution_counts);
        started.send(()).map_err(|error| error.to_string())?;
        let result = released.recv_timeout(Duration::from_secs(10)).map_err(|error| error.to_string())?;
        *progress.lock().unwrap() =
            Some(EntryPreparationProgress { phase: EntryPreparationPhase::ResultValidation, elapsed_ms: 10 });
        result
    });
    entered.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(entry.gate.is_running(), "the production wrapper must own its permit while work is held");
    HeldExecution { release, counts }
}

fn pending(workspace: &Workspace) -> (EntryUi, HeldExecution) {
    let mut entry = EntryUi::default();
    entry.shown = true;
    let execution = start_held(&mut entry, workspace, Arc::new(ExecutionCounts::default()));
    (entry, execution)
}

fn assert_start_refused(entry: &mut EntryUi, workspace: &Workspace, counts: &Arc<ExecutionCounts>) {
    let request_id = entry.request_id;
    let counts = Arc::clone(counts);
    entry.start_execution(workspace, &egui::Context::default(), false, move |_, _, _, _| {
        let active = counts.active.fetch_add(1, Ordering::SeqCst) + 1;
        counts.maximum.fetch_max(active, Ordering::SeqCst);
        counts.started.fetch_add(1, Ordering::SeqCst);
        let _active = ActiveExecution(counts);
        Err("another execution must not start while the shared permit is held".to_owned())
    });
    assert_eq!(entry.request_id, request_id);
}

fn window_harness(mut workspace: Workspace) -> Harness<'static, Workspace> {
    workspace.show_entry_decompilation();
    let mut harness = Harness::builder().with_size(egui::vec2(1100.0, 800.0)).build_ui_state(
        |ui, workspace: &mut Workspace| {
            workspace.poll(ui.ctx());
            workspace.show_entry_window(ui.ctx());
        },
        workspace,
    );
    harness.run();
    harness
}

#[test]
fn exact_open_navigation_and_every_panel_leave_genuine_backend_caches_uninitialized() {
    for (file, symbol) in [("hello-x64-dyn.elf", "main"), ("hello-x64.exe", "add"), ("hello-arm64.macho", "_main")] {
        let session = Session::default();
        let ctx = egui::Context::default();
        let path = fixture(file);
        let project = session.open_at(&path, None, None).unwrap();
        assert_eq!(project.analysis_cache_status(), rampage_api::AnalysisCacheStatus::default());
        let mut workspace = Workspace::open_exact(&session, path, None, None, &ctx, true).unwrap();
        assert!(Arc::ptr_eq(&workspace.project, &project));
        assert_ui_jobs_idle(&workspace);
        let address = workspace.project.resolve(symbol).unwrap();
        workspace.goto(address);
        workspace.select(address + 1);
        workspace.select(address);
        workspace.go_back();
        workspace.go_forward();
        workspace.project.refresh_annotations().unwrap();
        workspace.annotations_changed(None);
        assert_ui_jobs_idle(&workspace);
        let gate = EntryGate::default();
        workspace.set_entry_gate(gate.clone());
        workspace.show_entry_decompilation();
        for _ in 0..3 {
            let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                let ctx = ui.ctx().clone();
                workspace.poll(&ctx);
                egui::CentralPanel::default().show(ui, |ui| {
                    for mut tab in [
                        crate::tabs::Tab::Functions,
                        crate::tabs::Tab::Strings,
                        crate::tabs::Tab::Imports,
                        crate::tabs::Tab::Exports,
                        crate::tabs::Tab::Disassembly,
                        crate::tabs::Tab::Graph,
                        crate::tabs::Tab::Pseudocode,
                        crate::tabs::Tab::Xrefs,
                        crate::tabs::Tab::Assistant,
                        crate::tabs::Tab::Triage,
                    ] {
                        ui.push_id(tab as u8, |ui| {
                            let mut viewer = crate::tabs::Viewer { workspace: &mut workspace };
                            egui_dock::TabViewer::ui(&mut viewer, ui, &mut tab);
                        });
                        assert_ui_jobs_idle(&workspace);
                    }
                });
                workspace.show_entry_window(&ctx);
            });
            output.textures_delta.clear();
            assert!(workspace.analysis_deferred());
            assert_ui_jobs_idle(&workspace);
            assert!(!gate.is_running());
        }
    }
}

#[test]
fn exact_loaded_project_keeps_identity_and_navigation_without_reopening_or_analysis() {
    let mut workspace = workspace("hello-x64-dyn.elf");
    let project = Arc::clone(&workspace.project);
    let entry = workspace.cursor;
    let main = project.resolve("main").unwrap();
    workspace.goto(main);
    let snapshot = workspace.navigation_snapshot();
    workspace.restore_navigation(snapshot.0, snapshot.1, snapshot.2);
    assert_eq!(workspace.cursor, main);
    assert!(Arc::ptr_eq(&workspace.project, &project));
    assert!(workspace.can_go_back());
    workspace.go_back();
    assert_eq!(workspace.cursor, entry);
    workspace.go_forward();
    assert_eq!(workspace.cursor, main);
    assert_ui_jobs_idle(&workspace);
}

#[test]
fn analysis_is_only_started_explicitly_and_start_is_idempotent() {
    let mut workspace = workspace("hello-arm64.macho");
    let ctx = egui::Context::default();
    workspace.want_strings(&ctx);
    workspace.want_pseudocode(&ctx);
    workspace.want_graph();
    assert_ui_jobs_idle(&workspace);
    workspace.start_analysis(&ctx);
    assert!(!workspace.analysis_deferred());
    assert!(workspace.analysis_ready());
    assert!(workspace.triage.ready().is_some());
    let functions = workspace.functions.ready().unwrap().as_ptr();
    workspace.start_analysis(&ctx);
    assert_eq!(workspace.functions.ready().unwrap().as_ptr(), functions);
}

#[test]
fn exact_run_uses_the_requested_entry_and_preserves_source_level_fixture_behavior() {
    for (file, symbol) in [("hello-x64-dyn.elf", "main"), ("hello-x64.exe", "add"), ("hello-arm64.macho", "_main")] {
        let mut workspace = workspace(file);
        let address = workspace.project.resolve(symbol).unwrap();
        workspace.goto(address);
        let mut entry = EntryUi::default();
        entry.show();
        entry.run(&workspace, &egui::Context::default(), true);
        let result = entry.result.as_ref().unwrap_or_else(|| panic!("{file}: {:?}", entry.error));
        let code = &result.decompilation.code;
        assert_eq!(result.decompilation.address, address);
        assert_eq!(result.context.validation, EntryValidation::MetadataBacked);
        assert!(result.context.full_image_mapping);
        assert!(result.context.mapped_backing_checked);
        assert!(!result.context.omissions.is_empty());
        if symbol == "add" {
            assert!(code.contains('+') && code.contains("return"), "{code}");
            assert_eq!(result.decompilation.structure.signature.parameters.len(), 2);
        } else {
            assert!(code.contains("puts") && code.contains("rampage fixture greeting"), "{code}");
            assert!(code.contains("return 5;"), "{code}");
        }
        assert_ui_jobs_idle(&workspace);
        assert!(!entry.gate.is_running());
    }
}

#[test]
fn invalid_metadata_request_never_silently_retries_as_an_analyst_assertion() {
    let mut workspace = workspace("hello-x64-dyn.elf");
    let main = workspace.project.resolve("main").unwrap();
    workspace.goto(main + 1);
    let mut entry = EntryUi::default();
    entry.run(&workspace, &egui::Context::default(), true);
    assert!(entry.result.is_none());
    assert!(entry.error.is_some());
    assert_eq!(entry.validation, EntryValidation::MetadataBacked);
    assert_eq!(entry.request_id, 1);
    for _ in 0..3 {
        entry.poll(&workspace);
    }
    assert_eq!(entry.request_id, 1);
    assert_ui_jobs_idle(&workspace);
}

#[test]
fn cancel_close_and_reopen_keep_the_execution_permit_and_ignore_late_progress_and_errors() {
    let workspace = workspace("hello-x64-dyn.elf");
    let (mut entry, execution) = pending(&workspace);
    let gate = entry.gate.clone();
    let old_progress = Arc::clone(&entry.progress);
    entry.invalidate();
    let cancelled = Arc::clone(&entry.cancellation);
    assert!(cancelled.load(Ordering::Relaxed));
    entry.close();
    entry.show();
    assert!(entry.result.is_none());
    assert!(entry.binding.is_none());
    assert!(entry.job.is_running());
    assert!(gate.try_acquire().is_none());
    *old_progress.lock().unwrap() =
        Some(EntryPreparationProgress { phase: EntryPreparationPhase::NativeExecution, elapsed_ms: 10 });
    assert!(entry.progress.lock().unwrap().is_none());
    entry.run(&workspace, &egui::Context::default(), false);
    assert_eq!(entry.request_id, 1);
    execution.finish(&mut entry, &workspace, Err("obsolete execution failure".to_owned()));
    assert!(!entry.job.is_running());
    assert!(entry.result.is_none());
    assert_ne!(entry.error.as_deref(), Some("obsolete execution failure"));
    assert!(!gate.is_running());
}

#[test]
fn dropping_a_window_or_workspace_cannot_release_an_execution_owned_app_permit() {
    let workspace = workspace("hello-x64-dyn.elf");
    let (mut entry, execution) = pending(&workspace);
    let gate = entry.gate.clone();
    let cancellation = Arc::clone(&entry.cancellation);
    let mut job = std::mem::replace(&mut entry.job, Job::Idle);
    drop(entry);
    drop(workspace);
    assert!(cancellation.load(Ordering::Relaxed));
    assert!(gate.try_acquire().is_none());
    execution.finish_job(&mut job, Err("dropped execution".to_owned()));
    assert!(gate.try_acquire().is_some());
}

#[test]
fn production_async_owner_bounds_cancel_close_deactivate_and_replacement_until_work_returns() {
    for action in ["cancel", "close", "deactivate", "replace"] {
        let mut workspace = workspace("hello-x64-dyn.elf");
        workspace.goto(workspace.project.resolve("main").unwrap());
        let result = workspace
            .project
            .decompile_entry(&DecompileEntryRequest {
                address: workspace.cursor,
                validation: EntryValidation::MetadataBacked,
            })
            .unwrap();
        let gate = EntryGate::default();
        let counts = Arc::new(ExecutionCounts::default());
        let mut entry = EntryUi::default();
        entry.set_gate(gate.clone());
        entry.show();
        let execution = start_held(&mut entry, &workspace, Arc::clone(&counts));
        match action {
            "cancel" => entry.invalidate(),
            "close" => {
                entry.close();
                entry.show();
            }
            "deactivate" => {
                workspace.deactivate();
                entry.poll(&workspace);
            }
            "replace" => {
                workspace = self::workspace("hello-arm64.macho");
                entry.poll(&workspace);
            }
            _ => unreachable!(),
        }
        assert!(entry.cancellation.load(Ordering::Relaxed), "{action}");
        assert!(gate.is_running(), "{action} must not release the execution's permit");
        assert_eq!(counts.active.load(Ordering::SeqCst), 1);
        assert_start_refused(&mut entry, &workspace, &counts);
        let mut replacement = EntryUi::default();
        replacement.set_gate(gate.clone());
        replacement.show();
        assert_start_refused(&mut replacement, &workspace, &counts);
        assert!(matches!(replacement.job, Job::Idle));
        assert_eq!(counts.started.load(Ordering::SeqCst), 1);
        execution.finish(&mut entry, &workspace, Ok(result));
        assert!(!gate.is_running());
        assert!(entry.result.is_none(), "{action} must reject even a successful late completion");
        assert!(entry.binding.is_none());
        assert!(entry.progress.lock().unwrap().is_none());
        assert!(replacement.result.is_none());
        let next = start_held(&mut replacement, &workspace, Arc::clone(&counts));
        assert_eq!(counts.started.load(Ordering::SeqCst), 2);
        next.finish(&mut replacement, &workspace, Err("controlled second execution".to_owned()));
        assert_eq!(counts.maximum.load(Ordering::SeqCst), 1);
        assert!(!gate.is_running());
    }
}

#[test]
fn deactivation_rejects_module_aba_even_without_an_intermediate_paint() {
    let mut workspace = workspace("hello-x64-dyn.elf");
    let (mut entry, execution) = pending(&workspace);
    let old_instance = Arc::clone(&workspace.instance);
    let project = Arc::clone(&workspace.project);
    workspace.deactivate();
    assert!(!Arc::ptr_eq(&workspace.instance, &old_instance));
    assert!(Arc::ptr_eq(&workspace.project, &project));
    execution.finish(&mut entry, &workspace, Err("obsolete module failure".to_owned()));
    assert!(entry.binding.is_none());
    assert!(entry.cancellation.load(Ordering::Relaxed));
    assert!(entry.result.is_none());
    assert_ne!(entry.error.as_deref(), Some("obsolete module failure"));
    assert_ui_jobs_idle(&workspace);
}

#[test]
fn configuration_setter_aba_is_rejected_without_starting_another_request() {
    let workspace = workspace("hello-x64-dyn.elf");
    let (mut entry, execution) = pending(&workspace);
    workspace.project.set_decompiler_options(None);
    workspace.project.set_decompiler_options(None);
    execution.finish(&mut entry, &workspace, Err("obsolete configuration failure".to_owned()));
    assert!(entry.binding.is_none());
    assert!(entry.result.is_none());
    assert!(entry.cancellation.load(Ordering::Relaxed));
    assert_eq!(entry.request_id, 1);
    assert_ne!(entry.error.as_deref(), Some("obsolete configuration failure"));
}

#[test]
fn result_must_match_the_configuration_captured_before_run_not_only_current_settings() {
    let mut workspace = workspace("hello-x64-dyn.elf");
    let main = workspace.project.resolve("main").unwrap();
    workspace.goto(main);
    let mut entry = EntryUi::default();
    entry.run(&workspace, &egui::Context::default(), true);
    let result = entry.result.take().unwrap();
    workspace.project.set_decompiler_options(None);
    entry.binding = Some(binding(&workspace, &entry));
    assert!(entry.binding.as_ref().unwrap().matches(&workspace, &entry));
    entry.accept_result(&workspace, Ok(result));
    assert!(entry.result.is_none());
    assert!(entry.binding.is_none());
    assert!(entry.cancellation.load(Ordering::Relaxed));
    assert_ui_jobs_idle(&workspace);
}

#[test]
fn annotation_change_and_undo_cannot_restore_an_obsolete_request_binding() {
    let mut workspace = workspace("hello-x64-dyn.elf");
    let (mut entry, execution) = pending(&workspace);
    workspace.project.rename(workspace.cursor, Some("entry_reviewed_name")).unwrap();
    workspace.annotations_changed(None);
    workspace.undo();
    execution.finish(&mut entry, &workspace, Err("obsolete annotation failure".to_owned()));
    assert!(entry.binding.is_none());
    assert!(entry.result.is_none());
    assert_eq!(entry.request_id, 1);
    assert_ne!(entry.error.as_deref(), Some("obsolete annotation failure"));
    assert_ui_jobs_idle(&workspace);
}

#[test]
fn rendered_result_does_not_survive_cursor_aba_without_an_intermediate_frame() {
    let mut workspace = workspace("hello-x64-dyn.elf");
    let main = workspace.project.resolve("main").unwrap();
    workspace.goto(main);
    let mut harness = window_harness(workspace);
    harness.get_by_label("Run").click();
    harness.run();
    let result_warning = "Bounded local context, not a recovered or verified function boundary.";
    harness.get_by_label(result_warning);
    harness.state_mut().select(main + 1);
    harness.state_mut().select(main);
    for _ in 0..3 {
        harness.run();
        assert!(harness.query_by_label(result_warning).is_none());
        harness.get_by_label("Request invalidated. Run explicitly again when ready.");
        assert_ui_jobs_idle(harness.state());
    }
}

#[test]
fn closing_and_reopening_a_rendered_result_never_runs_again_or_revives_it() {
    let mut workspace = workspace("hello-x64-dyn.elf");
    let main = workspace.project.resolve("main").unwrap();
    workspace.goto(main);
    let mut harness = window_harness(workspace);
    harness.get_by_label("Run").click();
    harness.run();
    let result_warning = "Bounded local context, not a recovered or verified function boundary.";
    harness.get_by_label(result_warning);
    harness.key_press(egui::Key::Escape);
    harness.run();
    assert!(harness.query_by_label("Exact-entry decompilation").is_none());
    assert_eq!(harness.state().cursor, main);
    harness.state_mut().show_entry_decompilation();
    for _ in 0..3 {
        harness.run();
        harness.get_by_label("Exact-entry decompilation");
        assert!(harness.query_by_label(result_warning).is_none());
        assert_ui_jobs_idle(harness.state());
    }
}

#[test]
fn selecting_analyst_validation_does_not_start_execution() {
    let mut harness = window_harness(workspace("hello-x64-dyn.elf"));
    harness.get_by_role(egui::accesskit::Role::ComboBox).click_accesskit();
    harness.run();
    harness.get_by_label("Analyst-asserted").click_accesskit();
    harness.run();
    harness.get_by_label("Not started. Choose validation and press Run.");
    assert!(harness.query_by_label("Bounded local context, not a recovered or verified function boundary.").is_none());
    assert_ui_jobs_idle(harness.state());
}

struct SourceCopy(PathBuf);

impl SourceCopy {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rampage-entry-ui-{}-{index}.elf", std::process::id()));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        let source = Self(path);
        std::io::Write::write_all(&mut file, &std::fs::read(fixture("hello-x64-dyn.elf")).unwrap()).unwrap();
        source
    }
}

impl Drop for SourceCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn changed_backing_source_cancels_and_discards_late_work_without_mapped_reads() {
    let source = SourceCopy::new();
    let project = Arc::new(Project::new(Binary::open(&source.0).unwrap()));
    let workspace =
        Workspace::from_loaded_project(source.0.clone(), None, project, &egui::Context::default(), true, true);
    let (mut entry, execution) = pending(&workspace);
    let mut file = std::fs::OpenOptions::new().append(true).open(&source.0).unwrap();
    std::io::Write::write_all(&mut file, &[0]).unwrap();
    execution.finish(&mut entry, &workspace, Err("obsolete source failure".to_owned()));
    assert!(entry.binding.is_none());
    assert!(entry.result.is_none());
    assert!(entry.cancellation.load(Ordering::Relaxed));
    assert_ne!(entry.error.as_deref(), Some("obsolete source failure"));
    assert_ui_jobs_idle(&workspace);
}
