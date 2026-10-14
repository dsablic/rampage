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
    assert!(harness.query_by_label("Go to matching static image address").is_none());
    assert!(harness.state_mut().workspace_mut().is_none());
    harness.get_by_label("Query").click();
    harness.run();
    harness.get_by_label("Enter an explicit absolute Unix socket path before querying.");
    assert!(harness.state_mut().workspace_mut().is_none());
}

#[test]
fn resolution_template_does_not_open_a_project_or_issue_an_automatic_query() {
    let mut app = App::blocking();
    app.show_debugger();
    let mut harness =
        Harness::builder().with_size(egui::vec2(1400.0, 1000.0)).build_ui_state(|ui, app: &mut App| app.show(ui), app);
    harness.run();
    harness.get_by_role(egui::accesskit::Role::ComboBox).click();
    harness.run();
    harness.get_by_label("resolve_module_address").click();
    harness.run();
    harness.get_by_label("Insert template").click();
    harness.run();
    harness.get_by_label("No query has been sent.");
    assert!(harness.query_by_label("Go to matching static image address").is_none());
    harness.get_by_label(
        "Select a unique module UUID from list_modules and supply its LLDB file virtual address, \
         not a file offset. Resolution is raw SDK mapping evidence, not proven flow or layout.",
    );
    assert!(harness.state_mut().workspace_mut().is_none());
    harness.get_by_label("Query").click();
    harness.run();
    harness.get_by_label("Enter an explicit absolute Unix socket path before querying.");
    assert!(harness.state_mut().workspace_mut().is_none());
}
