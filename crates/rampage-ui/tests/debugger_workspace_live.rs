use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use rampage_loaders::Format;
use rampage_ui::App;
use serde_json::Value;

fn replace_input(harness: &mut Harness<'_, App>, id: &str, text: &str) {
    harness.ctx.memory_mut(|memory| memory.request_focus(egui::Id::new(id)));
    harness.step();
    harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
    harness.step();
    harness.event(egui::Event::Paste(text.to_owned()));
    harness.step();
}

fn wait_for(harness: &mut Harness<'_, App>, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        harness.step();
        if harness.query_by_label(label).is_some() {
            return;
        }
        assert!(Instant::now() < deadline, "real SDK UI did not display {label:?}");
        std::thread::yield_now();
    }
}

fn click(harness: &mut Harness<'_, App>, label: &str) {
    assert!(!harness.get_by_label(label).accesskit_node().is_disabled(), "disabled control: {label}");
    harness.get_by_label(label).click_accesskit();
    harness.step();
}

fn address(metadata: &Value, field: &str) -> u64 {
    u64::from_str_radix(metadata[field].as_str().unwrap().strip_prefix("0x").unwrap(), 16).unwrap()
}

#[test]
#[ignore = "requires the opt-in Python runner's owned stopped x86_64 LLDB fixture"]
fn owned_lldb_workspace_connect_inspect_prepare_compare_save_open() {
    assert_eq!(std::env::var("RAMPAGE_LLDB_WORKSPACE_LIVE").as_deref(), Ok("1"));
    let metadata: Value = serde_json::from_str(&std::env::var("RAMPAGE_LLDB_WORKSPACE_METADATA").unwrap()).unwrap();
    let source = PathBuf::from(metadata["source"].as_str().unwrap());
    let source_bytes = std::fs::read(&source).unwrap();
    let output = PathBuf::from(metadata["output"].as_str().unwrap());
    assert!(!output.exists());
    let mut app = App::blocking();
    app.open(&egui::Context::default(), source.clone(), None);
    app.show_debugger();
    let original = Arc::clone(&app.workspace_mut().expect("owned Mach-O must open").project);
    assert_eq!(original.binary.format, Format::MachO);
    let annotations = serde_json::to_string(&original.annotation_list()).unwrap();
    let mut harness =
        Harness::builder().with_size(egui::vec2(1900.0, 2400.0)).build_ui_state(|ui, app: &mut App| app.show(ui), app);
    harness.run();
    harness.get_by_label("Not connected. No query has been sent by opening this window.");
    let cursor = harness.state_mut().workspace_mut().unwrap().cursor;
    replace_input(&mut harness, "debugger-socket", metadata["socket"].as_str().unwrap());
    click(&mut harness, "Connect stopped session");
    wait_for(&mut harness, "Runtime data byte order: little (no scalar interpretation)");
    click(&mut harness, "List modules page");
    let module_label = format!(
        "Module {} · {} · {} · {}",
        metadata["module_index"].as_u64().unwrap(),
        metadata["module_name"].as_str().unwrap(),
        metadata["module_uuid"].as_str().unwrap(),
        metadata["module_triple"].as_str().unwrap(),
    );
    wait_for(&mut harness, &module_label);
    click(&mut harness, &module_label);
    click(&mut harness, "List threads page");
    let thread_id = metadata["thread_id"].as_u64().unwrap();
    let thread_label = format!(
        "Thread {thread_id:#x} · stop reason {} · SDK is_stopped {}",
        metadata["stop_reason"].as_u64().unwrap(),
        metadata["is_stopped"].as_bool().unwrap(),
    );
    wait_for(&mut harness, &thread_label);
    click(&mut harness, &thread_label);
    replace_input(&mut harness, "debugger-memory-address", metadata["load_address"].as_str().unwrap());
    replace_input(&mut harness, "debugger-file-address", metadata["file_address"].as_str().unwrap());
    replace_input(&mut harness, "debugger-capture-output", output.to_str().unwrap());
    let (target_node, target_tree) = harness.get_by_value("64").accesskit_node().locate();
    harness.event(egui::Event::AccessKitActionRequest(egui::accesskit::ActionRequest {
        target_node,
        target_tree,
        action: egui::accesskit::Action::SetValue,
        data: Some(egui::accesskit::ActionData::NumericValue(4.0)),
    }));
    harness.step();
    harness.get_by_role(egui::accesskit::Role::ComboBox).click_accesskit();
    harness.run();
    click(&mut harness, "r-x");
    click(&mut harness, "Read selected thread registers");
    wait_for(&mut harness, &format!("Raw registers · thread {thread_id:#x}"));
    click(&mut harness, "Read raw memory");
    wait_for(&mut harness, &format!("Raw memory · {:#x} · 4 bytes", address(&metadata, "load_address")));
    click(&mut harness, "Resolve selected file address");
    wait_for(&mut harness, "Go to matching static image address");
    assert_eq!(harness.state_mut().workspace_mut().unwrap().cursor, cursor, "inspection navigated implicitly");
    click(&mut harness, "Go to matching static image address");
    assert_eq!(harness.state_mut().workspace_mut().unwrap().cursor, address(&metadata, "file_address"));
    click(&mut harness, "Prepare capture preview (9 queries)");
    wait_for(&mut harness, "Exact captured mapping permissions: r-x");
    harness.get_by_label(
        "Nine revalidated observations are non-atomic; matching tokens and fresh checks are not an atomic snapshot.",
    );
    harness.get_by_label(
        "Entry is null and seeds are empty; registers do not authorize automatic PC navigation or discovery.",
    );
    assert!(!output.exists(), "Prepare published without Save");
    click(&mut harness, "Compare prepared capture with original");
    wait_for(&mut harness, "Prepared capture comparison: 4 equal · 0 changed · 0 unavailable bytes");
    assert!(!output.exists(), "Compare published without Save");
    click(&mut harness, "Save prepared capture");
    wait_for(&mut harness, &format!("Saved locally: {}. The original workspace is still open.", output.display()));
    let workspace = harness.state_mut().workspace_mut().unwrap();
    assert_eq!(workspace.path, source);
    assert!(Arc::ptr_eq(&workspace.project, &original));
    assert_eq!(workspace.cursor, address(&metadata, "file_address"));
    assert!(workspace.can_go_back());
    let document = std::fs::read(&output).unwrap();
    let snapshot: Value = serde_json::from_slice(&document).unwrap();
    assert_eq!(snapshot["arch"], "x86_64");
    assert_eq!(snapshot["regions"][0]["bytes"], metadata["bytes_hex"]);
    assert_eq!(snapshot["regions"][0]["address"], metadata["load_address"]);
    assert_eq!(snapshot["regions"][0]["permissions"], "r-x");
    assert_eq!(snapshot["modules"][0]["runtime_base"], metadata["runtime_base"]);
    assert_eq!(snapshot["modules"][0]["image_base"], metadata["image_base"]);
    assert_eq!(snapshot["modules"][0]["path"], metadata["source"]);
    assert_eq!(
        snapshot["modules"][0]["uuid"],
        rampage_loaders::snapshot::canonical_module_identity(metadata["module_uuid"].as_str().unwrap()),
    );
    assert_eq!(snapshot["target"]["platform"], "darwin");
    assert!(snapshot["target"].get("compiler").is_none());
    let provenance: Value = serde_json::from_str(snapshot["provenance"].as_str().unwrap()).unwrap();
    assert_eq!(provenance["atomic_snapshot"], false);
    assert_eq!(provenance["historical_token"]["stop_id"], metadata["stop_id"]);
    assert_eq!(provenance["thread_id"], metadata["thread_id"]);
    assert_eq!(provenance["observations"].as_array().unwrap().len(), 9);
    assert!(snapshot["seeds"].as_array().unwrap().is_empty());
    assert_eq!(snapshot["registers"].as_array().unwrap().len(), 3);
    click(&mut harness, "Open saved snapshot");
    harness.run();
    let workspace = harness.state_mut().workspace_mut().unwrap();
    assert_eq!(workspace.path, output);
    assert_eq!(workspace.project.binary.format, Format::Snapshot);
    assert_eq!(workspace.project.binary.file_bytes(), document.as_slice());
    assert_eq!(workspace.cursor, 0, "register PC must not authorize navigation");
    assert!(workspace.project.binary.entry.is_none());
    assert!(workspace.project.binary.function_starts.is_empty());
    assert_eq!(serde_json::to_string(&original.annotation_list()).unwrap(), annotations);
    assert_eq!(std::fs::read(&source).unwrap(), source_bytes);
    original.binary.validate_backing_source().unwrap();
}
