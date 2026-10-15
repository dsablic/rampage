use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use rampage_ui::App;

fn harness(shown: bool) -> Harness<'static, App> {
    let mut app = App::blocking();
    if shown {
        app.show_debugger();
    }
    let mut harness =
        Harness::builder().with_size(egui::vec2(1500.0, 1100.0)).build_ui_state(|ui, app: &mut App| app.show(ui), app);
    harness.run();
    harness
}

#[test]
fn ordinary_app_has_no_debugger_window_or_implicit_workspace() {
    let mut harness = harness(false);
    assert!(harness.query_by_label("Read-only debugger").is_none());
    assert!(harness.query_by_label("Connect stopped session").is_none());
    assert!(harness.state_mut().workspace_mut().is_none());
}

#[test]
fn opening_inspection_keeps_capture_and_target_actions_unavailable_without_a_source_or_connection() {
    let mut harness = harness(true);
    harness.get_by_label("Not connected. No query has been sent by opening this window.");
    for label in [
        "List modules page",
        "List threads page",
        "Read selected thread registers",
        "Read raw memory",
        "Resolve selected file address",
        "Prepare capture preview (9 queries)",
        "Compare prepared capture with original",
        "Save prepared capture",
        "Open saved snapshot",
    ] {
        assert!(harness.get_by_label(label).accesskit_node().is_disabled(), "enabled {label}");
    }
    assert!(harness.query_by_label("Request JSON (at most 16 KiB)").is_none());
    assert!(harness.query_by_label("Go to matching static image address").is_none());
    assert!(harness.state_mut().workspace_mut().is_none());
}

#[test]
fn explicit_connection_refusal_does_not_create_a_workspace_or_enable_capture() {
    let mut harness = harness(true);
    harness.get_by_label("Connect stopped session").click_accesskit();
    harness.run();
    harness.get_by_label("Enter an explicit absolute Unix socket path before querying.");
    assert!(harness.state_mut().workspace_mut().is_none());
    assert!(harness.get_by_label("Save prepared capture").accesskit_node().is_disabled());
    assert!(harness.get_by_label("Open saved snapshot").accesskit_node().is_disabled());
    for _ in 0..3 {
        harness.run();
        harness.get_by_label("Not connected. No query has been sent by opening this window.");
        assert!(harness.state_mut().workspace_mut().is_none());
    }
}
