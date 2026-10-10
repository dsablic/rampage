//! Renders the UI offscreen. Run with UPDATE_SNAPSHOTS=1 to refresh the images in tests/snapshots.

use std::path::PathBuf;

use egui_kittest::Harness;
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
fn main_window_with_a_binary() {
    let mut harness = harness(App::blocking());
    harness.run();
    let ctx = harness.ctx.clone();
    harness.state_mut().open(&ctx, fixture("hello-x64-dyn.elf"), None);
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
    let chrome = PathBuf::from(
        "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/Current/Google Chrome Framework",
    );
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
