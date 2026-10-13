//! Renders the UI offscreen. Run with UPDATE_SNAPSHOTS=1 to refresh the images in tests/snapshots.

use std::path::PathBuf;

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use rampage_ui::App;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn harness(app: App) -> Harness<'static, App> {
    Harness::builder().with_size(egui::vec2(1400.0, 860.0)).build_ui_state(|ui, app: &mut App| app.show(ui), app)
}

#[test]
fn empty_window() {
    let mut harness = harness(App::blocking());
    harness.run();
    harness.snapshot("empty");
}

#[test]
fn runtime_snapshot_opens_in_the_existing_ui() {
    let mut harness = harness(App::blocking());
    harness.run();
    let ctx = harness.ctx.clone();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json");
    harness.state_mut().open(&ctx, path, None);
    harness.state_mut().workspace_mut().unwrap().goto_text("0x1000");
    harness.run();
    harness.state_mut().focus_tab(rampage_ui::Tab::Graph);
    harness.run();
    assert!(harness.state_mut().workspace_mut().is_some());
}

#[test]
fn pseudocode_panel_loads_decompilation_and_address_links() {
    let mut harness = harness(App::blocking());
    harness.run();
    let ctx = harness.ctx.clone();
    harness.state_mut().open(&ctx, fixture("hello-x64-dyn.elf"), None);
    harness.state_mut().workspace_mut().unwrap().goto_text("main");
    harness.state_mut().focus_tab(rampage_ui::Tab::Pseudocode);
    harness.run();
    let result = harness.state_mut().workspace_mut().unwrap().pseudocode.ready().unwrap();
    assert!(result.code.contains("puts@plt(\"rampage fixture greeting\")"), "{}", result.code);
    assert!(result.tokens.iter().any(|token| token.address.is_some()));
    harness.snapshot("pseudocode");
}

#[test]
fn main_window_with_a_binary() {
    let mut harness = harness(App::blocking());
    harness.run();
    let ctx = harness.ctx.clone();
    harness.state_mut().open(&ctx, fixture("hello-x64-dyn.elf"), None);
    harness.run();
    harness.run();
    harness.run();
    harness.snapshot("main-elf");
}

#[test]
fn arm64_main_with_triage() {
    let mut harness = harness(App::blocking());
    harness.run();
    let ctx = harness.ctx.clone();
    let app = harness.state_mut();
    app.open(&ctx, fixture("hello-arm64.macho"), None);
    app.workspace_mut().unwrap().goto_text("_main");
    app.focus_tab(rampage_ui::Tab::Triage);
    harness.run();
    harness.snapshot("arm64-triage");
}

#[test]
fn strings_panel() {
    let mut harness = harness(App::blocking());
    harness.run();
    let ctx = harness.ctx.clone();
    let app = harness.state_mut();
    app.open(&ctx, fixture("hello-x64.exe"), None);
    app.focus_tab(rampage_ui::Tab::Strings);
    // Following a string shows its bytes and who references it.
    app.workspace_mut().unwrap().goto(0x1_4002_9000);
    harness.run();
    harness.snapshot("pe-strings");
}

/// Frame times with a very large binary. Run with `cargo test -p rampage-ui --release -- --ignored large`.
#[test]
#[ignore = "needs Google Chrome installed; measures performance"]
fn large_binary_frames_stay_fast() {
    let chrome = PathBuf::from(concat!(
        "/Applications/Google Chrome.app/Contents/Frameworks/",
        "Google Chrome Framework.framework/Versions/Current/Google Chrome Framework",
    ));
    if !chrome.exists() {
        return;
    }
    let mut harness = harness(App::blocking());
    harness.run();
    let ctx = harness.ctx.clone();
    let started = std::time::Instant::now();
    harness.state_mut().open(&ctx, chrome, Some(rampage_arch::Arch::Aarch64));
    println!("open and analyze: {:?}", started.elapsed());
    let started = std::time::Instant::now();
    harness.run();
    println!("first frame: {:?}", started.elapsed());
    for tab in [rampage_ui::Tab::Functions, rampage_ui::Tab::Strings, rampage_ui::Tab::Imports, rampage_ui::Tab::Triage]
    {
        harness.state_mut().focus_tab(tab);
        let started = std::time::Instant::now();
        harness.run();
        println!("{tab:?} frame: {:?}", started.elapsed());
        let started = std::time::Instant::now();
        harness.run();
        println!("{tab:?} next frame: {:?}", started.elapsed());
    }
}

#[test]
fn rename_dialog_and_user_comments() {
    let directory = std::env::temp_dir().join(format!("rampage-ui-annotate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("hello-arm64.macho");
    std::fs::copy(fixture("hello-arm64.macho"), &path).unwrap();

    let mut harness = harness(App::blocking());
    harness.run();
    let ctx = harness.ctx.clone();
    let app = harness.state_mut();
    app.open(&ctx, path, None);
    let workspace = app.workspace_mut().unwrap();
    workspace.goto_text("_main");
    workspace.select(0x1_0000_0474);
    workspace.begin_comment();
    workspace.editing.as_mut().unwrap().text = "builds the greeting pointer".into();
    workspace.finish_edit();
    workspace.select(0x1_0000_0468);
    workspace.begin_rename();
    workspace.editing.as_mut().unwrap().text = "say_hello".into();
    workspace.finish_edit();
    workspace.begin_rename();
    workspace.editing.as_mut().unwrap().text = "two words".into();
    workspace.finish_edit();
    harness.run();
    harness.snapshot("annotations");
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn function_graph() {
    let mut harness = harness(App::blocking());
    harness.run();
    let ctx = harness.ctx.clone();
    let app = harness.state_mut();
    app.open(&ctx, fixture("hello-x64.elf"), None);
    let workspace = app.workspace_mut().unwrap();
    // A function with a few branches.
    let function = workspace
        .functions
        .ready()
        .unwrap()
        .iter()
        .filter(|function| (6..=10).contains(&function.blocks))
        .min_by_key(|function| function.size)
        .map(|function| function.address)
        .unwrap();
    workspace.goto(function);
    app.focus_tab(rampage_ui::Tab::Graph);
    harness.run();
    harness.run();
    harness.snapshot("graph");
}

#[test]
fn assistant_panel() {
    use rampage_ui::assistant::Entry;
    let mut harness = harness(App::blocking());
    harness.run();
    let ctx = harness.ctx.clone();
    let app = harness.state_mut();
    app.open(&ctx, fixture("hello-x64-dyn.elf"), None);
    app.focus_tab(rampage_ui::Tab::Assistant);
    let assistant = &mut app.workspace_mut().unwrap().assistant;
    assistant.transcript.push(Entry::Question("What does main do?".to_owned()));
    assistant.transcript.push(Entry::Tool { summary: "disassemble main".to_owned(), failed: false });
    assistant.transcript.push(Entry::Answer("main passes the greeting to puts and returns 5.".to_owned()));
    harness.run();
    harness.snapshot("assistant");
}

#[test]
fn about_window() {
    let mut app = App::blocking();
    app.show_about();
    let mut harness = harness(app);
    harness.run();
    harness.get_by_label("NOTICE");
    harness.get_by_label("Ubuntu Light (Ubuntu Font Licence 1.0)");
    harness.snapshot("about");
}

#[test]
fn clicking_the_brand_opens_about() {
    let mut harness = harness(App::blocking());
    harness.run();
    let ctx = harness.ctx.clone();
    harness.state_mut().open(&ctx, fixture("hello-x64-dyn.elf"), None);
    harness.run();
    assert!(harness.query_by_label("Third-party notices").is_none());
    harness.get_by_label("rampage").click();
    harness.run();
    harness.get_by_label("Third-party notices");
}

/// A copy of `name` in a fresh temporary directory, so its annotation sidecar starts empty.
fn scratch_copy(test: &str, name: &str) -> (PathBuf, PathBuf) {
    let directory = std::env::temp_dir().join(format!("rampage-ui-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(name);
    std::fs::copy(fixture(name), &path).unwrap();
    (directory, path)
}

fn comment(workspace: &mut rampage_ui::Workspace, address: u64, text: &str) {
    workspace.select(address);
    workspace.begin_comment();
    workspace.editing.as_mut().unwrap().text = text.into();
    workspace.finish_edit();
}

#[test]
fn an_undo_another_client_blocks_offers_to_discard_the_step() {
    let (directory, path) = scratch_copy("undo-blocked", "hello-arm64.macho");
    let mut harness = harness(App::blocking());
    harness.run();
    let ctx = harness.ctx.clone();
    let app = harness.state_mut();
    app.open(&ctx, path.clone(), None);
    let workspace = app.workspace_mut().unwrap();
    workspace.goto_text("_main");
    comment(workspace, 0x1_0000_0474, "earlier step");
    comment(workspace, 0x1_0000_0468, "blocked step");
    // Another client, such as an agent over MCP, comments the same address.
    let agent = rampage_api::Session::default().open(&path, None).unwrap();
    agent.comment(0x1_0000_0468, Some("the agent's comment")).unwrap();
    workspace.undo();
    assert!(workspace.blocked_undo.as_deref().unwrap().contains("edited by another client"));
    harness.run();
    harness.snapshot("undo-blocked");

    harness.get_by_label("Discard step").click();
    harness.run();
    let workspace = harness.state_mut().workspace_mut().unwrap();
    assert!(workspace.blocked_undo.is_none());
    assert!(workspace.notice.as_deref().unwrap().contains("its edit stays in effect"), "{:?}", workspace.notice);
    assert_eq!(workspace.project.comment_at(0x1_0000_0468).as_deref(), Some("the agent's comment"));
    // The earlier step is no longer stuck behind the blocked one.
    workspace.undo();
    assert!(workspace.blocked_undo.is_none());
    assert_eq!(workspace.project.comment_at(0x1_0000_0474), None);
    std::fs::remove_dir_all(&directory).unwrap();
}

/// A file the loaders cannot open whole: `prefix` bytes of padding, then the ELF fixture.
/// The directory is relative to the package, under the target directory, so that snapshots showing the path match
/// on every machine.
fn padded_elf(test: &str, prefix: usize) -> (PathBuf, PathBuf) {
    let directory = PathBuf::from("../../target/rampage-ui-tests").join(test);
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("firmware.bin");
    let mut bytes = b"FIRMWARE".repeat(prefix / 8);
    bytes.extend(std::fs::read(fixture("hello-x64.elf")).unwrap());
    std::fs::write(&path, bytes).unwrap();
    (directory, path)
}

#[test]
fn carve_window_opens_an_embedded_executable() {
    let (directory, path) = padded_elf("carve", 0x1000);
    let mut harness = harness(App::blocking());
    harness.run();
    let ctx = harness.ctx.clone();
    harness.state_mut().open(&ctx, path.clone(), None);
    assert!(harness.state_mut().workspace_mut().is_none());
    harness.run();
    assert!(harness.get_all_by_label_contains("cannot parse binary").count() > 0);
    // The file does not open whole, so the Carve window lists what it embeds.
    harness.get_by_label("0x1000");
    harness.snapshot("carve");

    harness.get_by_label("Open").click();
    harness.run();
    let workspace = harness.state_mut().workspace_mut().unwrap();
    assert_eq!(workspace.image.map(rampage_loaders::ImageAt::offset), Some(0x1000));
    assert_eq!(workspace.project.binary.format, rampage_loaders::Format::Elf);
    assert!(workspace.project.resolve("main").is_ok());
    harness.run();
    // The open image is marked rather than offered again, and the toolbar names its offset.
    harness.get_by_label("@ 0x1000");
    harness.get_by_label("Carve 0").click();
    harness.run();
    assert!(harness.query_by_label("Open").is_none());
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn an_image_offset_and_length_open_from_the_open_flow() {
    let (directory, path) = padded_elf("image-offset", 0x800);
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    let length = std::fs::metadata(fixture("hello-x64.elf")).unwrap().len();
    let image = rampage_loaders::ImageAt::new(0x800, Some(length));
    app.open_at(&ctx, path.clone(), None, Some(image));
    let workspace = app.workspace_mut().unwrap();
    assert_eq!(workspace.image, Some(image));
    assert!(workspace.project.resolve("main").is_ok());
    // An offset with nothing there fails with the loader's reason, keeping the open project.
    app.open_at(&ctx, path, None, Some(rampage_loaders::ImageAt::new(0x10, None)));
    assert_eq!(app.workspace_mut().unwrap().image, Some(image));
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn data_packs_apply_to_opened_binaries_and_list_their_problems() {
    // Relative to the package, so the snapshot shows the same directory on every machine.
    let directory = PathBuf::from("../../target/rampage-ui-tests/pack");
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("rampage-pack.toml"),
        "name = \"ui-pack\"\nversion = \"1.0\"\nlicense = \"MIT\"\nsource = \"https://example.com/ui-pack\"\n\
         description = \"UI test pack\"\n[[contents]]\nkind = \"peid\"\npath = \"userdb.txt\"\n\
         [[contents]]\nkind = \"yara\"\npath = \"missing.yar\"\n",
    )
    .unwrap();
    std::fs::write(directory.join("userdb.txt"), "[UI Pack DOS Header]\nsignature = 4D 5A\nep_only = false\n").unwrap();
    let packs = std::sync::Arc::new(rampage_api::Packs::lazy(std::slice::from_ref(&directory)));

    let mut harness = harness(App::blocking().with_packs(std::sync::Arc::clone(&packs)));
    harness.run();
    let ctx = harness.ctx.clone();
    harness.state_mut().open(&ctx, fixture("hello-x64.exe"), None);
    let project = &harness.state_mut().workspace_mut().unwrap().project;
    assert!(std::sync::Arc::ptr_eq(&project.packs(), &packs));
    let detections = project.detect_tools(None).unwrap().detections;
    assert!(detections.iter().any(|detection| detection.name == "UI Pack DOS Header"), "{detections:?}");
    harness.run();
    harness.get_by_label("1 data pack problem").click();
    harness.run();
    harness.get_by_label("ui-pack 1.0 (MIT)");
    harness.get_by_label("peid userdb.txt (loaded): 1 PeID signatures");
    assert!(harness.get_all_by_label_contains("yara missing.yar (error): cannot open missing.yar").count() > 0);
    harness.snapshot("about-packs");
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn discarding_never_forces_away_a_step_undo_can_revert() {
    let (directory, path) = scratch_copy("undo-unblocked", "hello-arm64.macho");
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    app.open(&ctx, path, None);
    let workspace = app.workspace_mut().unwrap();
    comment(workspace, 0x1_0000_0474, "still undoable");
    workspace.blocked_undo = Some("stale".to_owned());
    workspace.discard_blocked_undo();
    assert!(workspace.notice.as_deref().unwrap().contains("force"), "{:?}", workspace.notice);
    workspace.undo();
    assert_eq!(workspace.project.comment_at(0x1_0000_0474), None);
    std::fs::remove_dir_all(&directory).unwrap();
}
