use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use rampage_ui::App;

#[test]
fn debugger_window_opens_without_a_binary_and_waits_for_an_explicit_query() {
    let mut app = App::blocking();
    app.show_debugger();
    let mut harness =
        Harness::builder().with_size(egui::vec2(1400.0, 860.0)).build_ui_state(|ui, app: &mut App| app.show(ui), app);
    harness.run();
    harness.get_by_label("Read-only debugger");
    harness.get_by_label("No query has been sent.");
    assert!(harness.state_mut().workspace_mut().is_none());
    harness.get_by_label("Query").click();
    harness.run();
    harness.get_by_label("Enter an explicit absolute Unix socket path before querying.");
    assert!(harness.state_mut().workspace_mut().is_none());
}
