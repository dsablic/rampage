use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use egui_kittest::kittest::{NodeT, Queryable};

use super::*;
use crate::{App, ProjectWorkspaceSaveNotice};

struct Sources(PathBuf);

impl Sources {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let token = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!("rampage-workspace-jobs-{}-{token}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
        for name in ["a.elf", "b.elf"] {
            std::fs::copy(&fixture, directory.join(name)).unwrap();
        }
        Self(directory)
    }

    fn app(&self, ctx: &egui::Context) -> App {
        let mut app = App::blocking();
        app.add_module_at(ctx, self.0.join("a.elf"), None, None).unwrap();
        app.add_module_at(ctx, self.0.join("b.elf"), None, None).unwrap();
        app.blocking = false;
        app
    }
}

impl Drop for Sources {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn hold_next(app: &mut App) -> (Receiver<()>, Sender<()>) {
    let (started, wait_started) = channel();
    let (release, wait_release) = channel();
    app.workspace_jobs.before_work = Some(Box::new(move || {
        started.send(()).unwrap();
        wait_release.recv_timeout(Duration::from_secs(10)).unwrap();
    }));
    (wait_started, release)
}

fn receive(app: &mut App) {
    let Job::Running(receiver) = &app.workspace_jobs.job else { panic!("expected asynchronous operation") };
    let result = receiver.recv_timeout(Duration::from_secs(10)).unwrap();
    app.workspace_jobs.job = Job::Done(result);
}

fn collect(app: &mut App, ctx: &egui::Context) {
    receive(app);
    app.poll_workspace_jobs(ctx);
    assert!(!app.workspace_io_running());
}

#[test]
fn actual_default_save_button_releases_the_ui_and_cancel_keeps_its_execution_lease() {
    let sources = Sources::new();
    let ctx = egui::Context::default();
    let mut app = sources.app(&ctx);
    app.show_project_workspace();
    let (started, release) = hold_next(&mut app);
    let mut harness = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1500.0, 1000.0))
        .build_ui_state(|ui, app: &mut App| app.show(ui), app);
    harness.run();
    harness.get_by_label("Save workspace…").click();
    harness.run();
    harness.get_by_label("Workspace output path").focus();
    harness.run();
    let output = sources.0.join("button-save.json");
    harness.get_by_label("Workspace output path").type_text(output.to_str().unwrap());
    harness.run();
    harness.get_by_label("Save workspace file").click();
    harness.step();
    started.recv_timeout(Duration::from_secs(10)).unwrap();
    harness.step();
    assert!(harness.state().workspace_io_running());
    assert!(!output.exists());
    harness.get_by_label("Navigation hex address").focus();
    harness.step();
    harness.get_by_label("Navigation hex address").type_text("1234");
    harness.step();
    assert!(!harness.get_by_label("Cancel workspace operation").accesskit_node().is_disabled());
    harness.get_by_label("Cancel workspace operation").click_accesskit();
    harness.step();
    harness.step();
    harness.get_by_label("Cancellation requested; waiting for the current operation to finish.");
    let app = harness.state_mut();
    for _ in 0..4 {
        app.cancel_workspace_io();
        app.close_workspace().unwrap();
        app.open_exact_at(&ctx, sources.0.join("a.elf"), None, None).unwrap();
        app.show_project_workspace();
        assert!(app.begin_workspace_preview(&ctx, output.clone()).is_err());
        assert!(app.workspace_io_running());
    }
    release.send(()).unwrap();
    collect(harness.state_mut(), &ctx);
    assert!(!output.exists());
    assert!(harness.state().reviewed_project_workspace().is_none());
}

#[test]
fn real_save_annotation_io_releases_live_annotations_before_a_due_ui_refresh_and_cancel() {
    let sources = Sources::new();
    let ctx = egui::Context::default();
    let mut app = App::default();
    let id = app.add_module_at(&ctx, sources.0.join("a.elf"), None, None).unwrap();
    let workspace = app.workspace.as_ref().unwrap();
    workspace.project.comment(workspace.cursor, Some("persisted annotation for detached save IO")).unwrap();
    let original = Arc::clone(&workspace.project);
    // Recording a local edit leaves its log entry unread; settle that real replay before binding the save.
    app.workspace.as_mut().unwrap().request_annotation_refresh_for_test();
    app.show_project_workspace();
    let mut harness = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1500.0, 1000.0))
        .build_ui_state(|ui, app: &mut App| app.show(ui), app);
    harness.run();

    let output = sources.0.join("cancelled-during-annotation-io.json");
    let ctx = harness.ctx.clone();
    let app = harness.state_mut();
    let info = app.modules().pop().unwrap();
    let workspace = app.workspace.as_ref().unwrap();
    let (cursor, back, forward) = workspace.bounded_navigation_snapshot().unwrap();
    let qualified = |address| rampage_api::QualifiedProjectAddress { module_id: id.clone(), address };
    let input = WorkspaceInput::Save {
        modules: vec![ProjectWorkspaceModuleInput {
            id: info.id,
            label: info.label,
            source_path: info.path,
            image: workspace.image,
            project: Arc::clone(&workspace.project),
            navigation: rampage_api::ProjectWorkspaceNavigation {
                current: Some(qualified(cursor)),
                back: back.into_iter().map(&qualified).collect(),
                forward: forward.into_iter().map(qualified).collect(),
            },
        }],
        active: id.clone(),
        session: app.session.unloaded_copy(),
        output: output.clone(),
    };
    let binding = BankBinding::capture(app).unwrap();
    let (paused, wait_paused) = channel();
    let (release, wait_release) = channel();
    let held_module = id.clone();
    app.workspace_jobs
        .start_execution(&ctx, false, binding, Operation::Save, move |cancellation, progress| {
            let mut held_once = false;
            input.execute(cancellation, &mut |update| {
                let reading_annotations = update.phase == rampage_api::ProjectWorkspacePhase::ReadingAnnotations;
                let module_id = update.module_id.clone();
                progress(update);
                if reading_annotations && !held_once {
                    held_once = true;
                    assert_eq!(module_id.as_deref(), Some(held_module.as_str()));
                    paused.send(()).unwrap();
                    wait_release.recv_timeout(Duration::from_secs(10)).unwrap();
                }
            })
        })
        .unwrap();
    wait_paused.recv_timeout(Duration::from_secs(10)).unwrap();

    let bank_generation = Arc::clone(&harness.state().workspace_bank.generation);
    let workspace = harness.state_mut().workspace.as_mut().unwrap();
    let annotations_epoch = Arc::clone(&workspace.annotations_epoch);
    let annotation_revision = workspace.project.annotation_revision().unwrap();
    let navigation = workspace.bounded_navigation_snapshot().unwrap();
    workspace.notice = Some("annotation refresh has not run".to_owned());
    workspace.request_annotation_refresh_for_test();
    harness.step();
    assert!(harness.state().workspace.as_ref().unwrap().notice.is_none());
    let workspace = harness.state().workspace.as_ref().unwrap();
    assert!(Arc::ptr_eq(&annotations_epoch, &workspace.annotations_epoch));
    assert!(Arc::ptr_eq(&annotation_revision, &workspace.project.annotation_revision().unwrap()));
    assert!(Arc::ptr_eq(&bank_generation, &harness.state().workspace_bank.generation));
    assert!(!harness.state().workspace_jobs.cancellation.load(Ordering::Acquire));
    assert!(harness.state().workspace_io_running());
    assert!(Arc::ptr_eq(&original, &harness.state().workspace.as_ref().unwrap().project));
    harness.get_by_label("Project workspace");
    harness.get_by_label("ReadingAnnotations");
    harness.get_by_label("Navigation hex address").focus();
    harness.step();
    harness.get_by_label("Navigation hex address").type_text("1234");
    harness.step();
    assert!(harness.state().workspace.as_ref().unwrap().navigation_matches(&navigation));
    assert!(Arc::ptr_eq(&bank_generation, &harness.state().workspace_bank.generation));
    assert!(!harness.state().workspace_jobs.cancellation.load(Ordering::Acquire));
    assert!(!harness.get_by_label("Cancel workspace operation").accesskit_node().is_disabled());
    harness.get_by_label("Cancel workspace operation").click_accesskit();
    harness.step();
    harness.step();
    harness.get_by_label("Cancellation requested; waiting for the current operation to finish.");
    assert!(harness.state().workspace_jobs.cancellation.load(Ordering::Acquire));
    assert!(harness.state().workspace_io_running());
    assert!(!output.exists());
    release.send(()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while harness.state().workspace_io_running() && std::time::Instant::now() < deadline {
        harness.step();
        std::thread::yield_now();
    }
    assert!(!harness.state().workspace_io_running());
    assert!(!output.exists());
    assert_eq!(harness.state().active_module_id(), Some(id.as_str()));
    assert!(Arc::ptr_eq(&original, &harness.state().workspace.as_ref().unwrap().project));
    assert!(harness.state().reviewed_project_workspace().is_none());
}

#[test]
fn actual_preview_and_open_actions_do_not_chain_and_reject_same_frame_aba() {
    let sources = Sources::new();
    let ctx = egui::Context::default();
    let mut app = sources.app(&ctx);
    let output = sources.0.join("workspace.json");
    app.save_project_workspace(output.clone()).unwrap();
    let original = Arc::clone(&app.workspace.as_ref().unwrap().project);
    let ids = app.modules().into_iter().map(|module| module.id).collect::<Vec<_>>();
    let (started, release) = hold_next(&mut app);
    app.begin_workspace_preview(&ctx, output.clone()).unwrap();
    started.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(app.reviewed_project_workspace().is_none());
    release.send(()).unwrap();
    collect(&mut app, &ctx);
    assert!(app.reviewed_project_workspace().is_some());
    assert!(Arc::ptr_eq(&original, &app.workspace.as_ref().unwrap().project));
    let (started, release) = hold_next(&mut app);
    app.begin_workspace_open_reviewed(&ctx).unwrap();
    started.recv_timeout(Duration::from_secs(10)).unwrap();
    app.select_module(&ids[1]).unwrap();
    app.select_module(&ids[0]).unwrap();
    release.send(()).unwrap();
    collect(&mut app, &ctx);
    assert!(Arc::ptr_eq(&original, &app.workspace.as_ref().unwrap().project));
    assert!(app.reviewed_project_workspace().is_none());
    assert!(app.workspace.as_ref().unwrap().analysis_deferred());
}

#[test]
fn actual_default_preview_and_open_buttons_are_async_and_preview_never_reads_missing_modules() {
    let sources = Sources::new();
    let ctx = egui::Context::default();
    let mut app = sources.app(&ctx);
    let output = sources.0.join("workspace.json");
    app.save_project_workspace(output.clone()).unwrap();
    std::fs::rename(sources.0.join("a.elf"), sources.0.join("unavailable.elf")).unwrap();
    let original = Arc::clone(&app.workspace.as_ref().unwrap().project);
    app.show_project_workspace();
    let (started, release) = hold_next(&mut app);
    let mut harness = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1500.0, 1000.0))
        .build_ui_state(|ui, app: &mut App| app.show(ui), app);
    harness.run();
    harness.get_by_label("Preview workspace file…").click();
    harness.run();
    harness.get_by_label("Workspace manifest path").focus();
    harness.run();
    harness.get_by_label("Workspace manifest path").type_text(output.to_str().unwrap());
    harness.run();
    harness.get_by_label("Preview workspace file").click();
    harness.step();
    started.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(harness.state().workspace_io_running());
    assert!(harness.state().reviewed_project_workspace().is_none());
    release.send(()).unwrap();
    collect(harness.state_mut(), &ctx);
    assert!(harness.state().reviewed_project_workspace().is_some());
    assert!(Arc::ptr_eq(&original, &harness.state_mut().workspace.as_ref().unwrap().project));
    harness.step();
    let (started, release) = hold_next(harness.state_mut());
    let review_window = harness.get_by_role_and_label(egui::accesskit::Role::Window, "Project workspace");
    let open_reviewed = review_window.get_by_label("Open reviewed workspace");
    assert!(!open_reviewed.accesskit_node().is_disabled());
    open_reviewed.click_accesskit();
    harness.step();
    started.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(harness.state().workspace_io_running());
    harness.step();
    harness.get_by_label("Navigation hex address").focus();
    harness.step();
    harness.get_by_label("Navigation hex address").type_text("5678");
    harness.step();
    release.send(()).unwrap();
    collect(harness.state_mut(), &ctx);
    assert!(harness.state().error.is_some());
    assert_eq!(harness.state().modules().len(), 2);
    assert!(Arc::ptr_eq(&original, &harness.state_mut().workspace.as_ref().unwrap().project));
    assert!(harness.state().reviewed_project_workspace().is_none());
}

#[test]
fn completion_retains_uncertain_receipts_and_typed_staging_errors_before_cancel_and_stale_checks() {
    let sources = Sources::new();
    let ctx = egui::Context::default();
    let mut app = sources.app(&ctx);
    let output = sources.0.join("uncertain.json");
    let staging = sources.0.join("sensitive-stage");
    for typed_error in [false, true] {
        let binding = BankBinding::capture(&app).unwrap();
        let (started, release) = hold_next(&mut app);
        let destination = output.clone();
        let retained = staging.clone();
        app.workspace_jobs
            .start_execution(&ctx, false, binding, Operation::Save, move |_, _| {
                let result = if typed_error {
                    Err(ApiError::DebuggerCaptureStagingRetained(rampage_api::DebuggerCaptureStagingRetention {
                        paths: vec![retained],
                        message: "injected pre-link failure".into(),
                    }))
                } else {
                    Ok(ProjectWorkspacePublication {
                        path: destination.clone(),
                        document_sha256: "a".repeat(64),
                        status: rampage_api::DebuggerCapturePublicationStatus::PublishedUncertain,
                        warnings: vec!["injected post-link uncertainty".into()],
                        retained_staging_paths: vec![retained],
                    })
                };
                WorkspaceOutput::Save { output: destination, result }
            })
            .unwrap();
        started.recv_timeout(Duration::from_secs(10)).unwrap();
        app.cancel_workspace_io();
        app.close_workspace().unwrap();
        release.send(()).unwrap();
        collect(&mut app, &ctx);
    }
    let notices = app.project_workspace_save_notices();
    assert_eq!(notices.len(), 2);
    assert!(matches!(&notices[0], ProjectWorkspaceSaveNotice::Publication(receipt)
        if receipt.path == output && receipt.retained_staging_paths == vec![staging.clone()]));
    assert!(matches!(&notices[1], ProjectWorkspaceSaveNotice::Failure { retained_paths, .. }
        if retained_paths == &vec![staging]));
    app.add_module_at(&ctx, sources.0.join("a.elf"), None, None).unwrap();
    assert!(app.begin_workspace_save(&ctx, sources.0.join("never-retry.json")).is_err());
    assert!(app.reviewed_project_workspace().is_none());
}

#[test]
fn dropping_receiver_does_not_release_the_production_execution_permit() {
    let sources = Sources::new();
    let ctx = egui::Context::default();
    let mut app = sources.app(&ctx);
    let (started, release) = hold_next(&mut app);
    let gate = app.workspace_jobs.gate.clone();
    app.begin_workspace_preview(&ctx, sources.0.join("missing.json")).unwrap();
    started.recv_timeout(Duration::from_secs(10)).unwrap();
    let old = std::mem::take(&mut app.workspace_jobs);
    drop(old);
    assert!(gate.acquire().is_none());
    app.workspace_jobs.gate = gate.clone();
    assert!(app.begin_workspace_preview(&ctx, sources.0.join("missing.json")).is_err());
    release.send(()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while gate.0.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(gate.acquire().is_some());
}

#[test]
fn metadata_guard_refuses_a_source_replaced_after_background_validation() {
    let sources = Sources::new();
    let ctx = egui::Context::default();
    let mut app = sources.app(&ctx);
    let output = sources.0.join("workspace.json");
    app.save_project_workspace(output.clone()).unwrap();
    app.preview_project_workspace(output).unwrap();
    let original = Arc::clone(&app.workspace.as_ref().unwrap().project);
    app.begin_workspace_open_reviewed(&ctx).unwrap();
    receive(&mut app);
    assert!(matches!(&app.workspace_jobs.job, Job::Done(Ok(WorkspaceOutput::OpenReviewed(Ok(_))))));
    let progress = app.workspace_jobs.progress.lock().unwrap().clone().unwrap();
    assert_eq!(progress.phase, rampage_api::ProjectWorkspacePhase::ResultValidation);
    assert_eq!(progress.total_modules, app.modules().len());
    assert!(progress.completed_modules <= progress.total_modules);
    let replacement = sources.0.join("replacement.elf");
    std::fs::copy(sources.0.join("a.elf"), &replacement).unwrap();
    std::fs::rename(replacement, sources.0.join("a.elf")).unwrap();
    app.poll_workspace_jobs(&ctx);
    assert!(!app.workspace_io_running());
    assert!(app.error.is_some());
    assert_eq!(app.modules().len(), 2);
    assert!(Arc::ptr_eq(&original, &app.workspace.as_ref().unwrap().project));
}

#[test]
fn inactive_editor_opened_after_worker_validation_prevents_every_module_swap() {
    let sources = Sources::new();
    let ctx = egui::Context::default();
    let mut app = sources.app(&ctx);
    let output = sources.0.join("workspace.json");
    app.save_project_workspace(output.clone()).unwrap();
    app.preview_project_workspace(output).unwrap();
    let original = Arc::clone(&app.workspace.as_ref().unwrap().project);
    app.begin_workspace_open_reviewed(&ctx).unwrap();
    receive(&mut app);
    assert!(matches!(&app.workspace_jobs.job, Job::Done(Ok(WorkspaceOutput::OpenReviewed(Ok(_))))));
    let inactive = &mut app.workspace_bank.inactive[0].workspace;
    inactive.begin_comment();
    inactive.editing.as_mut().unwrap().text = "keep this inactive draft".to_owned();
    app.poll_workspace_jobs(&ctx);
    assert!(app.error.is_some());
    assert!(Arc::ptr_eq(&original, &app.workspace.as_ref().unwrap().project));
    assert_eq!(app.workspace_bank.inactive[0].workspace.editing.as_ref().unwrap().text, "keep this inactive draft",);
}

#[test]
fn direct_annotation_aba_and_configuration_revision_changes_revoke_inflight_preview() {
    let sources = Sources::new();
    let ctx = egui::Context::default();
    let mut app = sources.app(&ctx);
    let output = sources.0.join("workspace.json");
    app.save_project_workspace(output.clone()).unwrap();
    let original = Arc::clone(&app.workspace.as_ref().unwrap().project);
    for annotation_change in [true, false] {
        let (started, release) = hold_next(&mut app);
        app.begin_workspace_preview(&ctx, output.clone()).unwrap();
        started.recv_timeout(Duration::from_secs(10)).unwrap();
        let workspace = app.workspace.as_ref().unwrap();
        if annotation_change {
            workspace.project.comment(workspace.cursor, Some("temporary annotation")).unwrap();
            workspace.project.comment(workspace.cursor, None).unwrap();
        } else {
            workspace.project.set_decompiler_options(None);
        }
        release.send(()).unwrap();
        collect(&mut app, &ctx);
        assert!(app.reviewed_project_workspace().is_none());
        assert!(Arc::ptr_eq(&original, &app.workspace.as_ref().unwrap().project));
    }
}
