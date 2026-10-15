use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use rampage_ui::App;

struct SourceCopy {
    directory: PathBuf,
    path: PathBuf,
}

impl SourceCopy {
    fn new(source: &Path) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!("rampage-ui-debug-layout-{}-{index}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let copy = Self { path: directory.join("image.elf"), directory };
        std::fs::copy(source, &copy.path).unwrap();
        copy
    }
}

impl Drop for SourceCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn generated(variant: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("RAMPAGE_DEBUG_LAYOUT_FIXTURES").expect("requires centrally compiled fixtures"))
        .join(variant)
        .join("flat.debug.elf")
}

fn harness(path: &Path) -> Harness<'static, App> {
    let mut app = App::blocking();
    app.open(&egui::Context::default(), path.to_owned(), None);
    let mut harness =
        Harness::builder().with_size(egui::vec2(1500.0, 1000.0)).build_ui_state(|ui, app: &mut App| app.show(ui), app);
    harness.run();
    assert!(harness.state_mut().workspace_mut().is_some());
    harness
}

fn annotations(harness: &mut Harness<'_, App>) -> String {
    serde_json::to_string(&harness.state_mut().workspace_mut().unwrap().project.annotation_list()).unwrap()
}

fn open_review(harness: &mut Harness<'_, App>) {
    let ctx = harness.ctx.clone();
    harness.state_mut().show_debug_layout_review(&ctx);
    harness.run();
    harness.get_by_label("Checked debug layout review");
}

#[test]
fn committed_preview_only_fixture_never_imports_and_escape_does_not_navigate() {
    let source = SourceCopy::new(&fixture("debug-x64.elf"));
    let mut harness = harness(&source.path);
    assert!(harness.query_by_label("Checked debug layout review").is_none());
    let before = annotations(&mut harness);
    let workspace = harness.state_mut().workspace_mut().unwrap();
    let target = workspace
        .functions
        .ready()
        .unwrap()
        .iter()
        .find(|function| function.address != workspace.cursor)
        .unwrap()
        .address;
    workspace.goto(target);
    assert!(workspace.can_go_back());

    harness.get_by_label("rampage").click_secondary();
    harness.run();
    harness.get_by_label("Review checked debug layouts…").click();
    harness.run();
    harness.get_by_label("Checked debug layout review");
    harness.get_by_label("No approved changes. Apply is disabled; producer facts below are preview-only.");
    assert!(harness.get_by_label("Apply reviewed changes").accesskit_node().is_disabled());
    assert_eq!(annotations(&mut harness), before);
    let project = &harness.state_mut().workspace_mut().unwrap().project;
    let review = project.review_debug_layouts().unwrap();
    assert!(review.approved.is_empty());
    let layout = review
        .producer_report
        .as_ref()
        .unwrap()
        .layouts
        .iter()
        .find(|layout| layout.original_name.as_deref() == Some("debug_pair"))
        .unwrap();
    assert!(layout.producer_alignment.is_none());
    assert!(project.undo().unwrap().is_empty());
    harness.get_by_label(&format!("Producer layout: {}", layout.emitted_name)).click_accesskit();
    harness.run();
    harness.get_by_label(&format!("Size {}; producer struct alignment: unknown (not inferred)", layout.byte_size,));

    harness.key_press(egui::Key::Escape);
    harness.run();
    assert!(harness.query_by_label("Checked debug layout review").is_none());
    assert_eq!(harness.state_mut().workspace_mut().unwrap().cursor, target);
    open_review(&mut harness);
    assert!(harness.get_by_label("Apply reviewed changes").accesskit_node().is_disabled());
    assert_eq!(annotations(&mut harness), before);
}

#[test]
fn unsupported_image_explains_the_scope_and_cannot_apply() {
    let source = SourceCopy::new(&fixture("hello-arm64.macho"));
    let mut harness = harness(&source.path);
    let before = annotations(&mut harness);
    open_review(&mut harness);
    harness.get_by_label("This image is outside the supported checked layout scope.");
    assert!(harness.get_by_label("Apply reviewed changes").accesskit_node().is_disabled());
    assert_eq!(annotations(&mut harness), before);
    assert!(harness.state_mut().workspace_mut().unwrap().project.undo().unwrap().is_empty());
}

#[test]
#[ignore = "requires RAMPAGE_DEBUG_LAYOUT_FIXTURES from the central owned-source fixture recipe"]
fn explicit_apply_is_one_undo_step_and_preserves_analyst_edits() {
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let source = SourceCopy::new(&generated(variant));
        let mut harness = harness(&source.path);
        let project = &harness.state_mut().workspace_mut().unwrap().project;
        let preserved = project.resolve("debug_flat_read_first").unwrap();
        let imported = project.resolve("debug_flat_read_interior").unwrap();
        project.rename(preserved, Some("analyst_kept")).unwrap();
        project.comment(preserved, Some("analyst explanation")).unwrap();
        project.set_signature(preserved, Some("int4 analyst_kept(void);")).unwrap();
        let review = project.review_debug_layouts().unwrap();
        assert!(!review.approved.is_empty());
        assert!(review.approved.contains(&imported));
        assert!(review.preserved.contains(&preserved));
        assert!(!review.approved.contains(&preserved));
        let before = annotations(&mut harness);

        open_review(&mut harness);
        assert_eq!(annotations(&mut harness), before);
        assert!(!harness.get_by_label("Apply reviewed changes").accesskit_node().is_disabled());
        harness.get_by_label("Apply reviewed changes").click();
        harness.run();
        harness.get_by_label(&format!(
            "Applied {} functions; preserved {} functions; imported 1 types. Undo uses the existing undo command.",
            review.approved.len(),
            review.preserved.len(),
        ));
        assert!(harness.get_by_label("Apply reviewed changes").accesskit_node().is_disabled());
        let workspace = harness.state_mut().workspace_mut().unwrap();
        let result = workspace.project.annotation_list();
        assert!(result.signatures.iter().any(|signature| signature.address == imported));
        assert!(
            result
                .signatures
                .iter()
                .any(|signature| { signature.address == preserved && signature.text == "int4 analyst_kept(void);" })
        );
        assert_eq!(workspace.project.name_at(preserved).as_deref(), Some("analyst_kept"));
        assert_eq!(workspace.project.comment_at(preserved).as_deref(), Some("analyst explanation"));
        assert!(!result.types.is_empty());
        workspace.undo();
        assert_eq!(annotations(&mut harness), before, "one undo must restore the entire pre-import state");
        harness.run();
        assert!(harness.get_by_label("Apply reviewed changes").accesskit_node().is_disabled());
    }
}

#[test]
#[ignore = "requires RAMPAGE_DEBUG_LAYOUT_FIXTURES from the central owned-source fixture recipe"]
fn annotation_change_then_undo_cannot_restore_old_approval() {
    let source = SourceCopy::new(&generated("dwarf4-o1"));
    let mut harness = harness(&source.path);
    open_review(&mut harness);
    assert!(!harness.get_by_label("Apply reviewed changes").accesskit_node().is_disabled());
    let before = annotations(&mut harness);
    let workspace = harness.state_mut().workspace_mut().unwrap();
    workspace.begin_comment();
    workspace.editing.as_mut().unwrap().text = "intervening annotation".to_owned();
    workspace.finish_edit();
    workspace.undo();
    assert_eq!(annotations(&mut harness), before);
    harness.run();
    harness.get_by_label("Review is no longer current. Preview again and review the changes before applying.");
    assert!(harness.get_by_label("Apply reviewed changes").accesskit_node().is_disabled());
    harness.get_by_label("Preview again").click();
    harness.run();
    assert!(!harness.get_by_label("Apply reviewed changes").accesskit_node().is_disabled());
    assert_eq!(annotations(&mut harness), before, "an explicit fresh preview still must not import");
}

#[test]
#[ignore = "requires RAMPAGE_DEBUG_LAYOUT_FIXTURES from the central owned-source fixture recipe"]
fn final_core_recheck_refuses_changed_content_without_automatic_preview_or_apply() {
    let source = SourceCopy::new(&generated("dwarf5-o2"));
    let mut harness = harness(&source.path);
    open_review(&mut harness);
    let project = &harness.state_mut().workspace_mut().unwrap().project;
    let address = project.resolve("debug_flat_read_first").unwrap();
    // Bypass the UI epoch deliberately: the final core recheck must still reject the changed approved set.
    project.set_signature(address, Some("int4 debug_flat_read_first(void);")).unwrap();
    let before_apply = annotations(&mut harness);
    harness.get_by_label("Apply reviewed changes").click();
    harness.run();
    assert!(harness.get_by_label("Apply reviewed changes").accesskit_node().is_disabled());
    assert_eq!(annotations(&mut harness), before_apply);
    assert!(harness.state_mut().workspace_mut().unwrap().project.annotation_list().types.is_empty());
    harness.run();
    assert_eq!(annotations(&mut harness), before_apply);
    assert!(harness.get_by_label("Apply reviewed changes").accesskit_node().is_disabled());
}
