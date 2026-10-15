use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use rampage_ui::App;

struct Sources {
    directory: PathBuf,
    paths: Vec<PathBuf>,
}

impl Sources {
    fn new(count: usize) -> Self {
        Self::with_fixture(count, "debug-x64.elf")
    }

    fn with_fixture(count: usize, fixture: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let token = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!("rampage-ui-module-bank-{}-{token}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(fixture);
        let paths = (0..count)
            .map(|index| {
                let module = directory.join(index.to_string());
                std::fs::create_dir(&module).unwrap();
                let path = module.join("same-name.elf");
                std::fs::copy(&source, &path).unwrap();
                path
            })
            .collect();
        Self { directory, paths }
    }
}

impl Drop for Sources {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn harness(app: App) -> Harness<'static, App> {
    let mut harness =
        Harness::builder().with_size(egui::vec2(1500.0, 1000.0)).build_ui_state(|ui, app: &mut App| app.show(ui), app);
    harness.run();
    harness
}

#[test]
fn selection_keeps_owned_projects_filters_history_and_unsaved_editors() {
    let sources = Sources::new(2);
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    let first = app.add_module_at(&ctx, sources.paths[0].clone(), None, None).unwrap();
    let workspace = app.workspace_mut().unwrap();
    let initial_cursor = workspace.cursor;
    workspace.goto(initial_cursor + 1);
    workspace.function_filter.text = "first module filter".to_owned();
    workspace.begin_comment();
    workspace.editing.as_mut().unwrap().text = "unsaved first module".to_owned();
    let first_project = Arc::clone(&workspace.project);

    let second = app.add_module_at(&ctx, sources.paths[1].clone(), None, None).unwrap();
    let workspace = app.workspace_mut().unwrap();
    assert_eq!(workspace.cursor, initial_cursor);
    assert!(!workspace.can_go_back());
    assert!(workspace.editing.is_none());
    assert!(!Arc::ptr_eq(&first_project, &workspace.project));
    workspace.project.comment(initial_cursor, Some("second module annotation")).unwrap();
    assert!(first_project.annotation_list().comments.is_empty());

    let mut harness = harness(app);
    assert!(harness.query_by_label("Project workspace").is_none());
    harness.get_by_label("rampage").click_secondary();
    harness.run();
    harness.get_by_label("Project workspace…").click();
    harness.run();
    harness.get_by_label(&first).click();
    harness.run();
    let workspace = harness.state_mut().workspace_mut().unwrap();
    assert!(Arc::ptr_eq(&first_project, &workspace.project));
    assert_eq!(workspace.function_filter.text, "first module filter");
    assert_eq!(workspace.editing.as_ref().unwrap().text, "unsaved first module");
    assert_eq!(workspace.cursor, initial_cursor + 1);
    workspace.go_back();
    assert_eq!(workspace.cursor, initial_cursor);
    harness.state_mut().select_module(&second).unwrap();
    assert!(harness.state_mut().workspace_mut().unwrap().editing.is_none());
}

#[test]
fn inactive_editor_blocks_every_destructive_replacement_and_close() {
    let sources = Sources::new(3);
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    let first = app.add_module_at(&ctx, sources.paths[0].clone(), None, None).unwrap();
    app.workspace_mut().unwrap().begin_rename();
    app.workspace_mut().unwrap().editing.as_mut().unwrap().text = "unfinished".to_owned();
    let second = app.add_module_at(&ctx, sources.paths[1].clone(), None, None).unwrap();
    let project = Arc::clone(&app.workspace_mut().unwrap().project);

    app.open(&ctx, sources.paths[2].clone(), None);
    assert_eq!(app.active_module_id(), Some(second.as_str()));
    assert!(Arc::ptr_eq(&project, &app.workspace_mut().unwrap().project));
    assert!(app.open_exact_at(&ctx, sources.paths[2].clone(), None, None).is_err());
    assert!(app.close_module(&first).is_err());
    assert!(app.close_workspace().is_err());
    assert_eq!(app.modules().len(), 2);

    app.select_module(&first).unwrap();
    assert_eq!(app.workspace_mut().unwrap().editing.as_ref().unwrap().text, "unfinished");
    app.workspace_mut().unwrap().editing = None;
    app.open(&ctx, sources.paths[2].clone(), None);
    assert_eq!(app.modules().len(), 1);
    assert_eq!(app.workspace_mut().unwrap().path, sources.paths[2]);
    assert_ne!(app.active_module_id(), Some(first.as_str()));
    assert_ne!(app.active_module_id(), Some(second.as_str()));
}

#[test]
fn ninth_module_fails_before_source_io_and_failed_add_keeps_the_bank() {
    let sources = Sources::new(8);
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    let missing = sources.directory.join("does-not-exist.elf");
    let first = app.add_module_at(&ctx, sources.paths[0].clone(), None, None).unwrap();
    assert!(app.add_module_at(&ctx, missing.clone(), None, None).is_err());
    assert_eq!(app.modules().len(), 1);
    assert_eq!(app.active_module_id(), Some(first.as_str()));
    assert!(app.add_module_at(&ctx, sources.paths[0].clone(), None, None).is_err());
    for path in sources.paths.iter().skip(1) {
        app.add_module_at(&ctx, path.clone(), None, None).unwrap();
    }
    let active = app.active_module_id().unwrap().to_owned();
    let error = app.add_module_at(&ctx, missing, None, None).unwrap_err();
    assert!(error.contains("eight modules"), "{error}");
    assert_eq!(app.modules().len(), 8);
    assert_eq!(app.active_module_id(), Some(active.as_str()));
    app.select_module(&first).unwrap();
    assert_eq!(app.workspace_mut().unwrap().path, sources.paths[0]);
}

#[test]
fn actual_exact_open_and_explicit_run_keep_global_caches_idle_and_return_source_level_c() {
    let sources = Sources::with_fixture(1, "hello-x64-dyn.elf");
    let mut harness = harness(App::blocking());
    harness.get_all_by_label("rampage").next().unwrap().click_secondary();
    harness.run();
    harness.get_by_label("Open for exact-entry…").click();
    harness.run();
    harness.get_by_label("Full source path").focus();
    harness.run();
    harness.get_by_label("Full source path").type_text(sources.paths[0].to_str().unwrap());
    harness.run();
    harness.get_by_label("Open selected path").click();
    harness.run();
    for tab in [rampage_ui::Tab::Strings, rampage_ui::Tab::Pseudocode, rampage_ui::Tab::Triage] {
        harness.state_mut().focus_tab(tab);
        harness.run();
        let workspace = harness.state_mut().workspace_mut().unwrap();
        assert!(workspace.analysis_deferred());
        assert!(!workspace.functions.is_running());
        assert!(workspace.functions.ready().is_none());
        assert!(workspace.strings.ready().is_none());
        assert!(workspace.triage.ready().is_none());
        assert!(workspace.pseudocode.ready().is_none());
        assert!(workspace.listing.is_none());
        assert!(workspace.xrefs.is_none());
        let caches = workspace.project.analysis_cache_status();
        assert!(!caches.program && !caches.strings && !caches.triage, "{caches:?}");
    }
    let workspace = harness.state_mut().workspace_mut().unwrap();
    let address = workspace.project.resolve("main").unwrap();
    workspace.goto(address);
    harness.run();
    harness.run();
    let caches = harness.state_mut().workspace_mut().unwrap().project.analysis_cache_status();
    assert!(!caches.program && !caches.strings && !caches.triage, "{caches:?}");
    harness.get_by_label("Not started. Choose validation and press Run.");
    harness.get_by_label("Run").click();
    harness.run();
    harness.get_by_label_contains(&format!("Exact entry {address:#x} —"));
    harness.get_by_label_contains("puts");
    harness.get_by_label_contains("rampage fixture greeting");
    harness.get_by_label_contains("return 5;");
    harness.get_by_label("Exact-entry context, backing, budgets, typed entry sample and omissions").click();
    harness.run();
    harness.get_by_label_contains("validation: MetadataBacked");
    harness.get_by_label_contains("full_image_mapping: true");
    harness.get_by_label_contains("mapped_backing_checked: true");
    let caches = harness.state_mut().workspace_mut().unwrap().project.analysis_cache_status();
    assert!(!caches.program && !caches.strings && !caches.triage, "{caches:?}");
}

#[test]
fn qualified_navigation_uses_module_identity_with_identical_names_and_virtual_addresses() {
    let sources = Sources::new(2);
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    let first = app.add_module_at(&ctx, sources.paths[0].clone(), None, None).unwrap();
    let address = app.workspace_mut().unwrap().cursor + 1;
    let first_project = Arc::clone(&app.workspace_mut().unwrap().project);
    let second = app.add_module_at(&ctx, sources.paths[1].clone(), None, None).unwrap();
    app.show_project_workspace();
    let mut harness = harness(app);
    harness.get_by_label("Navigation module ID").focus();
    harness.run();
    harness.get_by_label("Navigation module ID").type_text(&first);
    harness.run();
    harness.get_by_label("Navigation hex address").focus();
    harness.run();
    harness.get_by_label("Navigation hex address").type_text(&format!("{address:x}"));
    harness.run();
    harness.get_by_label("Go to module address").click();
    harness.run();
    assert_eq!(harness.state().active_module_id(), Some(first.as_str()));
    let workspace = harness.state_mut().workspace_mut().unwrap();
    assert_eq!(workspace.cursor, address);
    assert!(Arc::ptr_eq(&first_project, &workspace.project));
    assert!(workspace.analysis_deferred());
    assert!(workspace.listing.is_none());
    assert!(workspace.xrefs.is_none());
    harness.state_mut().select_module(&second).unwrap();
    assert_ne!(harness.state_mut().workspace_mut().unwrap().cursor, address);
}

#[test]
fn explicit_save_preview_and_reviewed_open_restore_two_modules_without_analysis() {
    let sources = Sources::new(2);
    let output = sources.directory.join("project-workspace.json");
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    let first = app.add_module_at(&ctx, sources.paths[0].clone(), None, None).unwrap();
    let workspace = app.workspace_mut().unwrap();
    let cursor = workspace.cursor;
    workspace.goto(cursor + 1);
    workspace.goto(cursor + 2);
    workspace.go_back();
    workspace.project.comment(cursor, Some("first module only")).unwrap();
    let first_project = Arc::clone(&workspace.project);
    let second = app.add_module_at(&ctx, sources.paths[1].clone(), None, None).unwrap();
    app.workspace_mut().unwrap().goto(cursor + 4);
    app.workspace_mut().unwrap().project.comment(cursor, Some("second module only")).unwrap();
    let second_project = Arc::clone(&app.workspace_mut().unwrap().project);
    app.show_project_workspace();
    let mut harness = harness(app);

    harness.get_by_label("Save workspace…").click();
    harness.run();
    harness.get_by_label("Workspace output path").focus();
    harness.run();
    harness.get_by_label("Workspace output path").type_text(output.to_str().unwrap());
    harness.run();
    harness.get_by_label("Save workspace file").click();
    harness.run();
    assert!(output.is_file());
    assert!(harness.state().reviewed_project_workspace().is_none());
    assert_eq!(harness.state().project_workspace_save_notices().len(), 1);
    assert!(Arc::ptr_eq(&second_project, &harness.state_mut().workspace_mut().unwrap().project));

    harness.get_by_label("Preview workspace file…").click();
    harness.run();
    harness.get_by_label("Workspace manifest path").focus();
    harness.run();
    harness.get_by_label("Workspace manifest path").type_text(output.to_str().unwrap());
    harness.run();
    harness.get_by_label("Preview workspace file").click();
    harness.run();
    let reviewed = harness.state().reviewed_project_workspace().unwrap().clone();
    assert_eq!(reviewed.active_module_id, second);
    assert_eq!(reviewed.modules.len(), 2);
    assert!(Arc::ptr_eq(&second_project, &harness.state_mut().workspace_mut().unwrap().project));
    harness.get_by_label("Open reviewed workspace").click();
    harness.run();
    assert!(harness.state().reviewed_project_workspace().is_none());
    assert_eq!(harness.state().active_module_id(), Some(second.as_str()));
    let workspace = harness.state_mut().workspace_mut().unwrap();
    assert!(!Arc::ptr_eq(&second_project, &workspace.project));
    assert_eq!(workspace.cursor, cursor + 4);
    assert!(workspace.analysis_deferred());
    assert!(workspace.project.annotation_list().comments.iter().any(|row| row.text == "second module only"));
    assert_eq!(harness.state().capture_project_workspace().unwrap(), reviewed);

    harness.state_mut().select_module(&first).unwrap();
    let workspace = harness.state_mut().workspace_mut().unwrap();
    assert!(!Arc::ptr_eq(&first_project, &workspace.project));
    assert_eq!(workspace.cursor, cursor + 1);
    assert!(workspace.can_go_back());
    assert!(workspace.can_go_forward());
    assert!(workspace.project.annotation_list().comments.iter().any(|row| row.text == "first module only"));
    workspace.go_forward();
    assert_eq!(workspace.cursor, cursor + 2);
    assert!(workspace.analysis_deferred());
    harness.run();
    assert!(harness.state_mut().workspace_mut().unwrap().functions.ready().is_none());
}

#[test]
fn missing_nth_source_is_not_opened_by_preview_and_cannot_replace_the_current_bank() {
    let sources = Sources::new(3);
    let output = sources.directory.join("missing-source-workspace.json");
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    app.add_module_at(&ctx, sources.paths[0].clone(), None, None).unwrap();
    app.add_module_at(&ctx, sources.paths[1].clone(), None, None).unwrap();
    app.save_project_workspace(output.clone()).unwrap();
    app.open_exact_at(&ctx, sources.paths[2].clone(), None, None).unwrap();
    let old_id = app.active_module_id().unwrap().to_owned();
    let old_project = Arc::clone(&app.workspace_mut().unwrap().project);
    let old_cursor = app.workspace_mut().unwrap().cursor;
    app.workspace_mut().unwrap().goto(old_cursor + 1);
    std::fs::rename(&sources.paths[0], sources.directory.join("temporarily-unavailable.elf")).unwrap();

    app.preview_project_workspace(output).unwrap();
    assert!(app.reviewed_project_workspace().is_some());
    app.workspace_mut().unwrap().begin_comment();
    app.workspace_mut().unwrap().editing.as_mut().unwrap().text = "preserve this draft".to_owned();
    assert!(app.open_reviewed_project_workspace(&ctx).is_err());
    assert_eq!(app.workspace_mut().unwrap().editing.as_ref().unwrap().text, "preserve this draft");
    assert!(Arc::ptr_eq(&old_project, &app.workspace_mut().unwrap().project));
    app.workspace_mut().unwrap().editing = None;
    assert!(app.open_reviewed_project_workspace(&ctx).is_err());
    assert_eq!(app.active_module_id(), Some(old_id.as_str()));
    assert_eq!(app.modules().len(), 1);
    assert_eq!(app.workspace_mut().unwrap().cursor, old_cursor + 1);
    assert!(app.workspace_mut().unwrap().can_go_back());
    assert!(Arc::ptr_eq(&old_project, &app.workspace_mut().unwrap().project));
}

#[test]
fn navigation_annotation_and_bank_aba_changes_revoke_reviewed_open_authority() {
    let sources = Sources::new(2);
    let output = sources.directory.join("bound-workspace.json");
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    let first = app.add_module_at(&ctx, sources.paths[0].clone(), None, None).unwrap();
    let second = app.add_module_at(&ctx, sources.paths[1].clone(), None, None).unwrap();
    app.save_project_workspace(output.clone()).unwrap();
    let old_project = Arc::clone(&app.workspace_mut().unwrap().project);
    app.preview_project_workspace(output.clone()).unwrap();
    let cursor = app.workspace_mut().unwrap().cursor;
    app.workspace_mut().unwrap().goto(cursor + 1);
    assert!(app.open_reviewed_project_workspace(&ctx).is_err());
    assert!(Arc::ptr_eq(&old_project, &app.workspace_mut().unwrap().project));

    app.preview_project_workspace(output.clone()).unwrap();
    app.workspace_mut().unwrap().project.comment(cursor, Some("new analyst edit")).unwrap();
    assert!(app.open_reviewed_project_workspace(&ctx).is_err());
    assert!(Arc::ptr_eq(&old_project, &app.workspace_mut().unwrap().project));

    app.preview_project_workspace(output).unwrap();
    app.select_module(&first).unwrap();
    app.select_module(&second).unwrap();
    assert!(app.open_reviewed_project_workspace(&ctx).is_err());
    assert!(Arc::ptr_eq(&old_project, &app.workspace_mut().unwrap().project));
}

#[cfg(unix)]
#[test]
fn canonical_source_alias_is_rejected_without_activating_or_merging_a_module() {
    let sources = Sources::new(1);
    let alias = sources.directory.join("alias.elf");
    std::os::unix::fs::symlink(&sources.paths[0], &alias).unwrap();
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    let first = app.add_module_at(&ctx, sources.paths[0].clone(), None, None).unwrap();
    let old_project = Arc::clone(&app.workspace_mut().unwrap().project);
    app.workspace_mut().unwrap().begin_comment();
    assert!(app.add_module_at(&ctx, alias, None, None).is_err());
    assert_eq!(app.modules().len(), 1);
    assert_eq!(app.active_module_id(), Some(first.as_str()));
    assert!(Arc::ptr_eq(&old_project, &app.workspace_mut().unwrap().project));
    assert!(app.workspace_mut().unwrap().editing.is_some());
}

#[test]
fn changed_source_hash_and_changed_manifest_leave_the_original_workspace_untouched() {
    let sources = Sources::new(3);
    let output = sources.directory.join("changed-workspace.json");
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    app.add_module_at(&ctx, sources.paths[0].clone(), None, None).unwrap();
    app.add_module_at(&ctx, sources.paths[1].clone(), None, None).unwrap();
    app.save_project_workspace(output.clone()).unwrap();
    app.open_exact_at(&ctx, sources.paths[2].clone(), None, None).unwrap();
    let old_id = app.active_module_id().unwrap().to_owned();
    let old_project = Arc::clone(&app.workspace_mut().unwrap().project);

    app.preview_project_workspace(output.clone()).unwrap();
    let mut changed = std::fs::read(&sources.paths[0]).unwrap();
    changed[0] ^= 1;
    let replacement = sources.directory.join("replacement.elf");
    std::fs::write(&replacement, changed).unwrap();
    std::fs::rename(&replacement, &sources.paths[0]).unwrap();
    assert!(app.open_reviewed_project_workspace(&ctx).is_err());
    assert_eq!(app.active_module_id(), Some(old_id.as_str()));
    assert!(Arc::ptr_eq(&old_project, &app.workspace_mut().unwrap().project));

    app.preview_project_workspace(output.clone()).unwrap();
    let replacement = sources.directory.join("replacement-workspace.json");
    let mut changed = std::fs::read(&output).unwrap();
    changed.push(b' ');
    std::fs::write(&replacement, changed).unwrap();
    std::fs::rename(&replacement, &output).unwrap();
    assert!(app.open_reviewed_project_workspace(&ctx).is_err());
    assert_eq!(app.active_module_id(), Some(old_id.as_str()));
    assert!(Arc::ptr_eq(&old_project, &app.workspace_mut().unwrap().project));
    assert_eq!(app.modules().len(), 1);
}

#[test]
fn bundle_capture_persists_the_resolved_native_backing_file_not_the_bundle_directory() {
    let sources = Sources::new(1);
    let bundle = sources.directory.join("Owned.app");
    let binaries = bundle.join("Contents/MacOS");
    std::fs::create_dir_all(&binaries).unwrap();
    let executable = binaries.join("Owned");
    std::fs::copy(&sources.paths[0], &executable).unwrap();
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    let id = app.add_module_at(&ctx, bundle.clone(), None, None).unwrap();
    assert_eq!(app.workspace_mut().unwrap().path, bundle);
    let manifest = app.capture_project_workspace().unwrap();
    assert_eq!(manifest.modules[0].source_path, executable.canonicalize().unwrap());
    assert!(app.add_module_at(&ctx, executable.clone(), None, None).is_err());
    assert_eq!(app.active_module_id(), Some(id.as_str()));
    let output = sources.directory.join("bundle-workspace.json");
    app.save_project_workspace(output.clone()).unwrap();
    app.preview_project_workspace(output).unwrap();
    app.open_reviewed_project_workspace(&ctx).unwrap();
    assert_eq!(app.active_module_id(), Some(id.as_str()));
    assert_eq!(app.workspace_mut().unwrap().path, executable.canonicalize().unwrap());
    assert!(app.workspace_mut().unwrap().analysis_deferred());
}

#[test]
fn annotation_editor_undo_and_selection_are_scoped_to_the_retained_module() {
    fn selection(ctx: &egui::Context, editor: egui::Id) -> (usize, usize) {
        let state = egui::text_edit::TextEditState::load(ctx, editor).expect("rendered editor state");
        let range = state.cursor.char_range().expect("rendered editor cursor");
        (range.primary.index.0, range.secondary.index.0)
    }

    let sources = Sources::new(2);
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    let first = app.add_module_at(&ctx, sources.paths[0].clone(), None, None).unwrap();
    let cursor = app.workspace_mut().unwrap().cursor;
    app.workspace_mut().unwrap().begin_comment();
    let title = format!("Comment {cursor:#x}");
    let mut harness = harness(app);
    let first_editor = harness.ctx.memory(|memory| memory.focused()).expect("first editor focus");
    harness
        .get_by_role_and_label(egui::accesskit::Role::Window, &title)
        .get_by_role(egui::accesskit::Role::TextInput)
        .type_text("alpha draft");
    harness.run();
    harness.key_press(egui::Key::Home);
    harness.run();
    harness.key_combination_modifiers(egui::Modifiers::SHIFT, &[egui::Key::ArrowRight]);
    harness.run();
    assert_eq!(selection(&harness.ctx, first_editor), (1, 0));
    let stable_time = egui::util::undoer::Settings::default().stable_time;
    let stable_at = harness.ctx.input(|input| input.time) + f64::from(stable_time) + 0.1;
    harness.input_mut().time = Some(stable_at);
    harness.step();
    harness.input_mut().time = None;
    assert_eq!(selection(&harness.ctx, first_editor), (1, 0));
    assert!(
        !egui::text_edit::TextEditState::load(&harness.ctx, first_editor).unwrap().undoer().is_in_flux(),
        "the selected alpha draft must have a stable undo checkpoint",
    );
    let ctx = harness.ctx.clone();
    let second = harness.state_mut().add_module_at(&ctx, sources.paths[1].clone(), None, None).unwrap();
    assert_eq!(harness.state_mut().workspace_mut().unwrap().cursor, cursor);
    harness.state_mut().workspace_mut().unwrap().begin_comment();
    harness.run();
    let second_editor = harness.ctx.memory(|memory| memory.focused()).expect("second editor focus");
    assert_ne!(first_editor, second_editor);
    assert_eq!(selection(&harness.ctx, first_editor), (1, 0));
    assert_eq!(selection(&harness.ctx, second_editor), (0, 0));
    harness.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::Z]);
    harness.run();
    assert_eq!(harness.state_mut().workspace_mut().unwrap().editing.as_ref().unwrap().text, "");
    harness
        .get_by_role_and_label(egui::accesskit::Role::Window, &title)
        .get_by_role(egui::accesskit::Role::TextInput)
        .type_text("beta draft");
    harness.run();
    assert_eq!(harness.state_mut().workspace_mut().unwrap().editing.as_ref().unwrap().text, "beta draft");
    assert_eq!(selection(&harness.ctx, second_editor), (10, 10));
    harness.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::Z]);
    harness.run();
    assert_eq!(harness.state_mut().workspace_mut().unwrap().editing.as_ref().unwrap().text, "");
    harness.key_combination_modifiers(egui::Modifiers::COMMAND | egui::Modifiers::SHIFT, &[egui::Key::Z]);
    harness.run();
    assert_eq!(harness.state_mut().workspace_mut().unwrap().editing.as_ref().unwrap().text, "beta draft");

    harness.state_mut().select_module(&first).unwrap();
    harness.run();
    assert_eq!(harness.state_mut().workspace_mut().unwrap().editing.as_ref().unwrap().text, "alpha draft");
    assert_eq!(harness.ctx.memory(|memory| memory.focused()), Some(first_editor));
    assert_eq!(selection(&harness.ctx, first_editor), (1, 0));
    assert_eq!(selection(&harness.ctx, second_editor), (10, 10));
    harness
        .get_by_role_and_label(egui::accesskit::Role::Window, &title)
        .get_by_role(egui::accesskit::Role::TextInput)
        .type_text("A");
    harness.run();
    assert_eq!(harness.state_mut().workspace_mut().unwrap().editing.as_ref().unwrap().text, "Alpha draft");
    harness.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::Z]);
    harness.run();
    assert_eq!(harness.state_mut().workspace_mut().unwrap().editing.as_ref().unwrap().text, "alpha draft");
    assert_eq!(selection(&harness.ctx, first_editor), (1, 0));
    harness.key_combination_modifiers(egui::Modifiers::COMMAND | egui::Modifiers::SHIFT, &[egui::Key::Z]);
    harness.run();
    assert_eq!(harness.state_mut().workspace_mut().unwrap().editing.as_ref().unwrap().text, "Alpha draft");
    harness.state_mut().select_module(&second).unwrap();
    harness.run();
    assert_eq!(harness.state_mut().workspace_mut().unwrap().editing.as_ref().unwrap().text, "beta draft");
    assert_eq!(harness.ctx.memory(|memory| memory.focused()), Some(second_editor));
    assert_eq!(selection(&harness.ctx, second_editor), (10, 10));
}

#[test]
fn missing_retained_source_does_not_block_add_or_lose_its_editor_and_navigation() {
    let sources = Sources::new(2);
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    let first = app.add_module_at(&ctx, sources.paths[0].clone(), None, None).unwrap();
    let cursor = app.workspace_mut().unwrap().cursor;
    app.workspace_mut().unwrap().goto(cursor + 1);
    app.workspace_mut().unwrap().begin_comment();
    app.workspace_mut().unwrap().editing.as_mut().unwrap().text = "keep missing module draft".to_owned();
    let first_project = Arc::clone(&app.workspace_mut().unwrap().project);
    std::fs::rename(&sources.paths[0], sources.directory.join("retained-original.elf")).unwrap();
    let second = app.add_module_at(&ctx, sources.paths[1].clone(), None, None).unwrap();
    assert_eq!(app.modules().len(), 2);
    app.select_module(&first).unwrap();
    let workspace = app.workspace_mut().unwrap();
    assert!(Arc::ptr_eq(&first_project, &workspace.project));
    assert_eq!(workspace.cursor, cursor + 1);
    assert!(workspace.can_go_back());
    assert_eq!(workspace.editing.as_ref().unwrap().text, "keep missing module draft");
    let draft = workspace.editing.take().unwrap();
    let output = sources.directory.join("cannot-save-missing-source.json");
    let error = app.save_project_workspace(output.clone()).unwrap_err();
    assert!(error.contains("Cannot resolve"), "{error}");
    assert!(!output.exists());
    app.workspace_mut().unwrap().editing = Some(draft);
    app.select_module(&second).unwrap();
    let alias = sources.paths[1].parent().unwrap().join("../1/same-name.elf");
    let error = app.add_module_at(&ctx, alias, None, None).unwrap_err();
    assert!(error.contains("canonical source"), "{error}");
    assert_eq!(app.active_module_id(), Some(second.as_str()));
    app.select_module(&first).unwrap();
    assert_eq!(app.workspace_mut().unwrap().editing.as_ref().unwrap().text, "keep missing module draft");
    app.workspace_mut().unwrap().go_back();
    assert_eq!(app.workspace_mut().unwrap().cursor, cursor);
}

#[test]
fn bad_nth_annotation_log_cannot_partially_adopt_or_lose_an_inactive_editor_and_history() {
    let sources = Sources::new(4);
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    let poisoned = app.add_module_at(&ctx, sources.paths[0].clone(), None, None).unwrap();
    app.workspace_mut().unwrap().project.comment(0x1000, Some("recognized log fixture")).unwrap();
    let mut annotation_log = sources.paths[0].as_os_str().to_owned();
    annotation_log.push(".rampage");
    let annotation_log = PathBuf::from(annotation_log);
    assert!(std::fs::read_to_string(&annotation_log).unwrap().contains("recognized log fixture"));
    app.add_module_at(&ctx, sources.paths[1].clone(), None, None).unwrap();
    let output = sources.directory.join("bad-annotation-workspace.json");
    app.save_project_workspace(output.clone()).unwrap();
    let manifest = app.capture_project_workspace().unwrap();
    let poisoned_index = manifest.modules.iter().position(|module| module.id == poisoned).unwrap();
    assert!(poisoned_index > 0, "a valid earlier module must be staged before the poisoned annotation log");
    app.open_exact_at(&ctx, sources.paths[2].clone(), None, None).unwrap();
    let retained = app.active_module_id().unwrap().to_owned();
    let cursor = app.workspace_mut().unwrap().cursor;
    app.workspace_mut().unwrap().goto(cursor + 1);
    app.workspace_mut().unwrap().begin_comment();
    app.workspace_mut().unwrap().editing.as_mut().unwrap().text = "unrelated inactive draft".to_owned();
    let retained_project = Arc::clone(&app.workspace_mut().unwrap().project);
    let active = app.add_module_at(&ctx, sources.paths[3].clone(), None, None).unwrap();
    let active_project = Arc::clone(&app.workspace_mut().unwrap().project);
    std::fs::write(annotation_log, b"not a recognized annotation record\n").unwrap();
    app.preview_project_workspace(output.clone()).unwrap();
    let editor_error = app.open_reviewed_project_workspace(&ctx).unwrap_err();
    assert!(editor_error.contains("unsaved editor"), "{editor_error}");
    assert_eq!(app.active_module_id(), Some(active.as_str()));
    app.select_module(&retained).unwrap();
    let draft = app.workspace_mut().unwrap().editing.take().unwrap();
    assert_eq!(draft.text, "unrelated inactive draft");
    app.select_module(&active).unwrap();
    app.preview_project_workspace(output).unwrap();
    let annotation_error = app.open_reviewed_project_workspace(&ctx).unwrap_err();
    assert!(annotation_error.contains("annotation"), "{annotation_error}");
    assert_eq!(app.modules().len(), 2);
    assert!(Arc::ptr_eq(&active_project, &app.workspace_mut().unwrap().project));
    app.select_module(&retained).unwrap();
    let workspace = app.workspace_mut().unwrap();
    workspace.editing = Some(draft);
    assert!(Arc::ptr_eq(&retained_project, &workspace.project));
    assert_eq!(workspace.cursor, cursor + 1);
    assert!(workspace.can_go_back());
    assert_eq!(workspace.editing.as_ref().unwrap().text, "unrelated inactive draft");
}
