use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};

use egui_kittest::kittest::{NodeT, Queryable};
use rampage_api::derived_cache::{capture_function_inventory, publish_function_inventory, read_function_inventory};
use rampage_api::{FunctionsQuery, ProjectWorkspacePhase, ProjectWorkspaceTaskControl, Session};

use super::*;

struct Sources(PathBuf);

impl Sources {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let token = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("rampage-cached-inventory-ui-{}-{token}", std::process::id()));
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

    fn publish(&self) -> PathBuf {
        let project = Session::default().open(&self.0.join("a.elf"), None).unwrap();
        project.functions(&FunctionsQuery::default()).unwrap();
        let cancellation = AtomicBool::new(false);
        let mut observer = |_| {};
        let mut control = ProjectWorkspaceTaskControl::new(&cancellation, &mut observer);
        let prepared = capture_function_inventory(project, &mut control).unwrap();
        assert!(!prepared.rows().is_empty());
        let output = self.0.join("inventory.json");
        publish_function_inventory(&prepared, &output, &mut control).unwrap();
        output
    }

    fn app(&self, ctx: &egui::Context) -> (App, String) {
        let mut app = App::blocking();
        app.open_exact_at(ctx, self.0.join("a.elf"), None, None).unwrap();
        let id = app.active_module_id().unwrap().to_owned();
        (app, id)
    }
}

impl Drop for Sources {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_cold(app: &App, id: &str) {
    let workspace = app.inventory_module(id).unwrap();
    let status = workspace.project.analysis_cache_status();
    assert!(!status.program && !status.strings && !status.triage, "{status:?}");
    assert!(workspace.analysis_deferred());
    assert!(!workspace.analysis_ready());
    assert!(workspace.functions.ready().is_none());
    assert!(workspace.pseudocode.ready().is_none());
    assert!(workspace.listing.is_none());
    assert!(workspace.xrefs.is_none());
}

fn drain(app: &mut App, ctx: &egui::Context) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while app.workspace_io_running() && Instant::now() < deadline {
        app.poll_workspace_jobs(ctx);
        std::thread::yield_now();
    }
    assert!(!app.workspace_io_running());
}

struct HeldCommentWriter {
    lock: Option<std::fs::File>,
    done: std::sync::mpsc::Receiver<Result<(), String>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl HeldCommentWriter {
    fn new(project: Arc<Project>, source: &std::path::Path, address: u64) -> Self {
        let mut path = source.as_os_str().to_owned();
        path.push(".rampage.lock");
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(PathBuf::from(path))
            .unwrap();
        lock.lock().unwrap();
        let (done, receive_done) = channel();
        let writer = Arc::clone(&project);
        let thread = std::thread::spawn(move || {
            let result = writer
                .comment(address, Some("held comment-only writer"))
                .map(|_| ())
                .map_err(|error| error.to_string());
            let _ = done.send(result);
        });
        let held = Self { lock: Some(lock), done: receive_done, thread: Some(thread) };
        let deadline = Instant::now() + Duration::from_secs(10);
        while project.names_revision().is_ok() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(matches!(project.names_revision(), Err(ApiError::Unavailable(_))));
        held
    }

    fn release(mut self) {
        drop(self.lock.take());
        self.done.recv_timeout(Duration::from_secs(10)).unwrap().unwrap();
        self.thread.take().unwrap().join().unwrap();
    }
}

impl Drop for HeldCommentWriter {
    fn drop(&mut self) {
        drop(self.lock.take());
        if let Some(thread) = self.thread.take()
            && self.done.recv_timeout(Duration::from_secs(10)).is_ok()
        {
            let _ = thread.join();
        }
    }
}

#[test]
fn historical_paint_and_inflight_idle_polling_do_not_revalidate_physical_sources() {
    let sources = Sources::new();
    let output = sources.publish();
    let ctx = egui::Context::default();
    let (mut app, id) = sources.app(&ctx);
    app.begin_inventory_cache_load(&ctx, &id, output.clone()).unwrap();
    app.cached_inventory.view.as_mut().unwrap().selected = Some(0);
    app.cached_inventory.source_checks.set(0);
    std::fs::rename(sources.0.join("a.elf"), sources.0.join("moved.elf")).unwrap();
    let mut harness = egui_kittest::Harness::builder().with_size(egui::vec2(1600.0, 1100.0)).build_ui_state(
        |ui, app: &mut App| {
            app.poll_workspace_jobs(ui.ctx());
            app.workspace_jobs.show(ui);
            app.cached_inventory_window(ui.ctx());
        },
        app,
    );
    for _ in 0..3 {
        harness.step();
        assert!(harness.state().cached_inventory.view.is_some());
        assert_eq!(harness.state().cached_inventory.source_checks.get(), 0);
    }
    assert!(harness.state_mut().inspect_cached_inventory_address().is_err());
    assert!(harness.state().cached_inventory.view.is_none());
    assert_eq!(harness.state().cached_inventory.source_checks.get(), 1);

    let app = harness.state_mut();
    app.blocking = false;
    app.cached_inventory.source_checks.set(0);
    let (started, wait_started) = channel();
    let (release, wait_release) = channel();
    app.workspace_jobs.before_work = Some(Box::new(move || {
        started.send(()).unwrap();
        wait_release.recv_timeout(Duration::from_secs(10)).unwrap();
    }));
    app.begin_inventory_cache_load(&ctx, &id, output).unwrap();
    wait_started.recv_timeout(Duration::from_secs(10)).unwrap();
    for _ in 0..3 {
        harness.step();
        assert!(harness.state().workspace_io_running());
        assert_eq!(harness.state().cached_inventory.source_checks.get(), 0);
        assert!(
            harness.query_by_label("Cancellation requested; waiting for the current operation to finish.").is_none()
        );
    }
    release.send(()).unwrap();
    drain(harness.state_mut(), &ctx);
    assert!(harness.state().cached_inventory.view.is_none());
}

#[test]
fn a_real_comment_writer_keeps_busy_rows_and_defers_adoption_and_navigation_without_source_checks() {
    let sources = Sources::new();
    let output = sources.publish();
    let ctx = egui::Context::default();
    let (mut app, id) = sources.app(&ctx);
    app.begin_inventory_cache_load(&ctx, &id, output.clone()).unwrap();
    app.cached_inventory.view.as_mut().unwrap().selected = Some(0);
    let project = Arc::clone(&app.workspace.as_ref().unwrap().project);
    let names = project.names_revision().unwrap();
    let cursor = app.workspace.as_ref().unwrap().cursor;
    let binding = CacheBinding::capture(&app, &id).unwrap();
    let cancellation = AtomicBool::new(false);
    let mut observer = |_| {};
    let mut control = ProjectWorkspaceTaskControl::new(&cancellation, &mut observer);
    let outcome = read_function_inventory(Arc::clone(&project), &output, &mut control).unwrap();
    assert!(matches!(&outcome, InventoryCacheReadOutcome::Hit(_)));
    let writer = HeldCommentWriter::new(Arc::clone(&project), &sources.0.join("a.elf"), cursor);
    app.cached_inventory.source_checks.set(0);
    assert_eq!(binding.memory_state(&app), BindingState::Busy);
    app.finish_inventory_job(binding, false, Ok(WorkspaceOutput::InventoryLoad(Ok(outcome)))).unwrap();
    assert!(app.cached_inventory.pending.is_some());
    assert!(app.inspect_cached_inventory_address().is_err());
    assert_eq!(app.workspace.as_ref().unwrap().cursor, cursor);
    let mut harness = egui_kittest::Harness::builder().with_size(egui::vec2(1600.0, 1100.0)).build_ui_state(
        |ui, app: &mut App| {
            app.poll_workspace_jobs(ui.ctx());
            app.cached_inventory_window(ui.ctx());
        },
        app,
    );
    harness.step();
    harness.get_by_label("Inventory names are busy. Historical rows are retained; address inspection is deferred.");
    assert!(harness.get_by_label("Inspect raw cached address — unverified").accesskit_node().is_disabled());
    assert!(harness.get_by_label("Load inventory cache…").accesskit_node().is_disabled());
    assert!(harness.state().cached_inventory.view.is_some());
    assert!(harness.state().cached_inventory.pending.is_some());
    assert_eq!(harness.state().cached_inventory.source_checks.get(), 0);
    writer.release();
    project.refresh_annotations().unwrap();
    assert!(Arc::ptr_eq(&names, &project.names_revision().unwrap()));
    harness.step();
    assert!(harness.state().cached_inventory.pending.is_none());
    assert!(harness.state().cached_inventory.view.is_some());
    assert_eq!(harness.state().cached_inventory.source_checks.get(), 1);
    assert_cold(harness.state(), &id);
}

#[test]
fn comment_writer_contention_does_not_cancel_an_executing_inventory_request() {
    let sources = Sources::new();
    let output = sources.publish();
    let ctx = egui::Context::default();
    let (mut app, id) = sources.app(&ctx);
    let project = Arc::clone(&app.workspace.as_ref().unwrap().project);
    let cursor = app.workspace.as_ref().unwrap().cursor;
    app.blocking = false;
    let (started, wait_started) = channel();
    let (release, wait_release) = channel();
    app.workspace_jobs.before_work = Some(Box::new(move || {
        started.send(()).unwrap();
        wait_release.recv_timeout(Duration::from_secs(10)).unwrap();
    }));
    app.begin_inventory_cache_load(&ctx, &id, output.clone()).unwrap();
    wait_started.recv_timeout(Duration::from_secs(10)).unwrap();
    let writer = HeldCommentWriter::new(project, &sources.0.join("a.elf"), cursor);
    for _ in 0..3 {
        app.poll_workspace_jobs(&ctx);
        assert!(app.workspace_io_running());
        assert!(app.begin_workspace_preview(&ctx, output.clone()).is_err());
    }
    writer.release();
    release.send(()).unwrap();
    drain(&mut app, &ctx);
    assert!(app.cached_inventory.view.is_some(), "{:?}", app.cached_inventory.message);
    assert_cold(&app, &id);
}

#[test]
fn actual_load_controls_display_historical_rows_without_discovery_even_after_filter_and_raw_navigation() {
    let sources = Sources::new();
    let output = sources.publish();
    let ctx = egui::Context::default();
    let mut app = App::default();
    app.open_exact_at(&ctx, sources.0.join("a.elf"), None, None).unwrap();
    let id = app.active_module_id().unwrap().to_owned();
    let (started, wait_started) = channel();
    let (release, wait_release) = channel();
    app.workspace_jobs.before_work = Some(Box::new(move || {
        started.send(()).unwrap();
        wait_release.recv_timeout(Duration::from_secs(10)).unwrap();
    }));
    let mut harness = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1600.0, 1100.0))
        .build_ui_state(|ui, app: &mut App| app.show(ui), app);
    harness.run();
    assert!(harness.query_by_label("Cached function inventory").is_none());
    harness.get_by_label("Close window").click_accesskit();
    harness.run();
    harness.get_all_by_label("rampage").next().unwrap().click_secondary();
    harness.run();
    harness.get_by_label("Cached function inventory…").click_accesskit();
    harness.run();
    assert!(!harness.state().workspace_io_running());
    assert_eq!(harness.state().cached_inventory.source_checks.get(), 0);
    assert_cold(harness.state(), &id);
    assert!(harness.get_by_label("Save completed inventory…").accesskit_node().is_disabled());
    harness.get_by_label("Load inventory cache…").click_accesskit();
    harness.run();
    harness.get_by_label("Inventory cache path").focus();
    harness.run();
    harness.get_by_label("Inventory cache path").type_text(output.to_str().unwrap());
    harness.run();
    harness.get_by_label("Load selected inventory cache").click_accesskit();
    harness.step();
    wait_started.recv_timeout(Duration::from_secs(10)).unwrap();
    harness.step();
    assert!(harness.state().workspace_io_running());
    assert_cold(harness.state(), &id);
    assert!(harness.state().cached_inventory.view.is_none());
    release.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while harness.state().workspace_io_running() && Instant::now() < deadline {
        harness.step();
        std::thread::yield_now();
    }
    assert!(!harness.state().workspace_io_running());
    harness.run();
    harness.get_by_label("Cached / unverified historical candidates");
    harness.get_by_label("cached_unverified_historical");
    let row = harness.state().cached_inventory.view.as_ref().unwrap().inventory.rows()[0].clone();
    harness.get_by_label("Filter historical candidates").focus();
    harness.run();
    harness.get_by_label("Filter historical candidates").type_text(&row.address);
    harness.run();
    let window = harness.get_by_role_and_label(egui::accesskit::Role::Window, "Cached function inventory");
    window.get_by_label(&row.address).click_accesskit();
    harness.run();
    assert!(!harness.get_by_label("Inspect raw cached address — unverified").accesskit_node().is_disabled());
    harness.get_by_label("Inspect raw cached address — unverified").click_accesskit();
    harness.run();
    assert_eq!(
        harness.state().workspace.as_ref().unwrap().cursor,
        u64::from_str_radix(row.address.strip_prefix("0x").unwrap(), 16).unwrap()
    );
    assert_cold(harness.state(), &id);
    assert!(harness.state().cached_inventory.view.is_some());
}

#[test]
fn saving_completed_inventory_through_its_controls_never_loads_or_restores_the_result() {
    let sources = Sources::new();
    let ctx = egui::Context::default();
    let (mut app, _) = sources.app(&ctx);
    app.workspace.as_ref().unwrap().project.functions(&FunctionsQuery::default()).unwrap();
    app.show_cached_function_inventory();
    let mut harness = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1600.0, 1100.0))
        .build_ui_state(|ui, app: &mut App| app.show(ui), app);
    harness.run();
    assert!(!harness.get_by_label("Save completed inventory…").accesskit_node().is_disabled());
    harness.get_by_label("Save completed inventory…").click_accesskit();
    harness.run();
    harness.get_by_label("Inventory cache path").focus();
    harness.run();
    let output = sources.0.join("saved-through-ui.json");
    harness.get_by_label("Inventory cache path").type_text(output.to_str().unwrap());
    harness.run();
    harness.get_by_label("Publish completed inventory cache").click_accesskit();
    harness.run();
    assert!(output.exists());
    assert_eq!(harness.state().project_workspace_save_notices().len(), 1);
    assert!(harness.state().cached_inventory.view.is_none());
    assert!(harness.state().reviewed_project_workspace().is_none());
    assert!(harness.state().workspace.as_ref().unwrap().functions.ready().is_none());
}

#[test]
fn cold_capture_is_refused_and_explicit_miss_and_rejection_never_start_analysis() {
    let sources = Sources::new();
    let ctx = egui::Context::default();
    let (mut app, id) = sources.app(&ctx);
    assert!(app.begin_inventory_cache_save(&ctx, &id, sources.0.join("never-created.json")).is_err());
    assert!(!sources.0.join("never-created.json").exists());
    app.begin_inventory_cache_load(&ctx, &id, sources.0.join("missing.json")).unwrap();
    assert!(app.cached_inventory.view.is_none());
    assert!(app.cached_inventory.message.as_ref().unwrap().contains("miss"));
    let malformed = sources.0.join("malformed.json");
    std::fs::write(&malformed, b"not an inventory cache").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&malformed, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    app.begin_inventory_cache_load(&ctx, &id, malformed).unwrap();
    assert!(app.cached_inventory.view.is_none());
    assert!(app.cached_inventory.message.as_ref().unwrap().contains("rejected"));
    assert_cold(&app, &id);
}

#[test]
fn comments_options_and_module_switches_keep_hints_but_a_name_aba_revokes_them() {
    let sources = Sources::new();
    let output = sources.publish();
    let ctx = egui::Context::default();
    let (mut app, id) = sources.app(&ctx);
    app.begin_inventory_cache_load(&ctx, &id, output).unwrap();
    let project = Arc::clone(&app.inventory_module(&id).unwrap().project);
    let names = project.names_revision().unwrap();
    let address = app.inventory_module(&id).unwrap().cursor;
    project.comment(address, Some("comment is not an inventory naming dependency")).unwrap();
    project.refresh_annotations().unwrap();
    project.refresh_annotations().unwrap();
    project.set_decompiler_options(None);
    assert!(Arc::ptr_eq(&names, &project.names_revision().unwrap()));
    assert!(app.inventory_view_current());
    let other = app.add_module_at(&ctx, sources.0.join("b.elf"), None, None).unwrap();
    app.workspace.as_mut().unwrap().goto(address + 1);
    assert!(app.inventory_view_current());
    assert_eq!(app.cached_inventory.view.as_ref().unwrap().binding.module_id, id);
    app.select_module(&id).unwrap();
    app.select_module(&other).unwrap();
    assert!(app.inventory_view_current());
    app.cached_inventory.view.as_mut().unwrap().selected = Some(0);
    app.inspect_cached_inventory_address().unwrap();
    assert_eq!(app.active_module_id(), Some(id.as_str()));
    assert!(app.inventory_view_current());
    project.rename(address, Some("temporary_inventory_name")).unwrap();
    project.rename(address, None).unwrap();
    assert!(!app.inventory_view_current());
    app.cached_inventory.view.as_mut().unwrap().selected = Some(0);
    assert!(app.inspect_cached_inventory_address().is_err());
    assert_cold(&app, &id);
    assert_cold(&app, &other);
}

#[test]
fn a_byte_identical_source_replacement_refuses_both_candidate_adoption_and_later_raw_inspection() {
    let sources = Sources::new();
    let output = sources.publish();
    let ctx = egui::Context::default();
    let (mut app, id) = sources.app(&ctx);
    app.begin_inventory_cache_load(&ctx, &id, output.clone()).unwrap();
    app.cached_inventory.view.as_mut().unwrap().selected = Some(0);
    let binding = CacheBinding::capture(&app, &id).unwrap();
    let cancellation = AtomicBool::new(false);
    let mut observer = |_| {};
    let mut control = ProjectWorkspaceTaskControl::new(&cancellation, &mut observer);
    let outcome = read_function_inventory(Arc::clone(&binding.project), &output, &mut control).unwrap();
    assert!(matches!(&outcome, InventoryCacheReadOutcome::Hit(_)));
    let replacement = sources.0.join("replacement.elf");
    std::fs::copy(sources.0.join("a.elf"), &replacement).unwrap();
    std::fs::rename(replacement, sources.0.join("a.elf")).unwrap();
    assert!(app.inspect_cached_inventory_address().is_err());
    app.cached_inventory.view = None;
    assert!(app.finish_inventory_job(binding, false, Ok(WorkspaceOutput::InventoryLoad(Ok(outcome)))).is_err());
    assert!(app.cached_inventory.view.is_none());
    assert_cold(&app, &id);
}

#[test]
fn inventory_uses_the_same_execution_gate_and_switching_to_another_module_does_not_cancel_its_owner() {
    let sources = Sources::new();
    let output = sources.publish();
    let ctx = egui::Context::default();
    let (mut app, id) = sources.app(&ctx);
    let other = app.add_module_at(&ctx, sources.0.join("b.elf"), None, None).unwrap();
    app.blocking = false;
    let (started, wait_started) = channel();
    let (release, wait_release) = channel();
    app.workspace_jobs.before_work = Some(Box::new(move || {
        started.send(()).unwrap();
        wait_release.recv_timeout(Duration::from_secs(10)).unwrap();
    }));
    app.begin_inventory_cache_load(&ctx, &id, output).unwrap();
    wait_started.recv_timeout(Duration::from_secs(10)).unwrap();
    let source = app.inventory_module(&id).unwrap();
    source.project.comment(source.cursor, Some("in-flight comment is not a naming dependency")).unwrap();
    source.project.refresh_annotations().unwrap();
    source.project.set_decompiler_options(None);
    app.select_module(&id).unwrap();
    app.select_module(&other).unwrap();
    app.poll_workspace_jobs(&ctx);
    assert!(app.begin_workspace_preview(&ctx, sources.0.join("missing.json")).is_err());
    assert!(app.begin_workspace_save(&ctx, sources.0.join("not-published.json")).is_err());
    release.send(()).unwrap();
    drain(&mut app, &ctx);
    assert!(app.cached_inventory.view.is_some(), "{:?}", app.cached_inventory.message);
    assert_eq!(app.cached_inventory.view.as_ref().unwrap().binding.module_id, id);
    assert_eq!(app.active_module_id(), Some(other.as_str()));
    assert_cold(&app, &id);
    assert_cold(&app, &other);
}

#[test]
fn closing_inventory_and_replacing_the_bank_cannot_admit_another_file_job_until_work_returns() {
    let sources = Sources::new();
    let output = sources.publish();
    let ctx = egui::Context::default();
    let (mut app, id) = sources.app(&ctx);
    app.blocking = false;
    let (started, wait_started) = channel();
    let (release, wait_release) = channel();
    app.workspace_jobs.before_work = Some(Box::new(move || {
        started.send(()).unwrap();
        wait_release.recv_timeout(Duration::from_secs(10)).unwrap();
    }));
    app.begin_inventory_cache_load(&ctx, &id, output.clone()).unwrap();
    wait_started.recv_timeout(Duration::from_secs(10)).unwrap();
    for _ in 0..3 {
        app.close_cached_inventory();
        app.close_workspace().unwrap();
        app.open_exact_at(&ctx, sources.0.join("b.elf"), None, None).unwrap();
        let current = app.active_module_id().unwrap().to_owned();
        assert!(app.begin_inventory_cache_load(&ctx, &current, output.clone()).is_err());
        assert!(app.begin_workspace_preview(&ctx, output.clone()).is_err());
        assert!(app.workspace_io_running());
    }
    release.send(()).unwrap();
    drain(&mut app, &ctx);
    assert!(app.cached_inventory.view.is_none());
}

fn forged_payload_digest(document: &serde_json::Value) -> String {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"FunctionInventoryCacheV0.payload\0");
    for field in ["source_sha256", "image_sha256", "context_sha256", "names_sha256", "decoder", "discovery", "naming"] {
        let value = document["key"][field].as_str().unwrap();
        bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&document["total_functions"].as_u64().unwrap().to_le_bytes());
    bytes.push(u8::from(document["truncated"].as_bool().unwrap()));
    let rows = document["rows"].as_array().unwrap();
    bytes.extend_from_slice(&(rows.len() as u64).to_le_bytes());
    for row in rows {
        for field in ["address", "name"] {
            let value = row[field].as_str().unwrap();
            bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        for field in ["size", "block_count", "instruction_count"] {
            bytes.extend_from_slice(&row[field].as_u64().unwrap().to_le_bytes());
        }
    }
    let mut child = Command::new("shasum")
        .args(["-a", "256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let text = std::str::from_utf8(&output.stdout).unwrap();
    let digest = text.split_whitespace().next().unwrap();
    assert!(digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    digest.to_owned()
}

#[test]
#[ignore = "explicit forgery acceptance requires the host shasum tool; API forgery tests run by default"]
fn a_forged_valid_checksum_never_upgrades_historical_rows_to_current_entry_authority() {
    let sources = Sources::new();
    let output = sources.publish();
    let mut document: serde_json::Value = serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    let mut row = document["rows"][0].clone();
    row["name"] = "forged historical display name".into();
    row["address"] = "0xffffffffffffffff".into();
    document["rows"] = serde_json::json!([row]);
    document["truncated"] = serde_json::json!(document["total_functions"].as_u64().unwrap() > 1);
    document["payload_sha256"] = forged_payload_digest(&document).into();
    std::fs::write(&output, serde_json::to_vec(&document).unwrap()).unwrap();
    let ctx = egui::Context::default();
    let (mut app, id) = sources.app(&ctx);
    app.begin_inventory_cache_load(&ctx, &id, output).unwrap();
    let view = app.cached_inventory.view.as_mut().unwrap();
    assert_eq!(view.inventory.provenance(), "cached_unverified_historical");
    assert_eq!(view.inventory.rows()[0].name, "forged historical display name");
    view.selected = Some(0);
    app.inspect_cached_inventory_address().unwrap();
    assert_eq!(app.workspace.as_ref().unwrap().cursor, u64::MAX);
    assert!(app.workspace.as_ref().unwrap().project.name_at(u64::MAX).is_none());
    assert_cold(&app, &id);
    let mut harness = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1600.0, 1100.0))
        .build_ui_state(|ui, app: &mut App| app.show(ui), app);
    harness.run();
    harness.get_by_label("Cached / unverified historical candidates");
    harness.get_by_label("cached_unverified_historical");
    harness.get_by_label("forged historical display name");
    assert_cold(harness.state(), &id);
}

#[test]
fn a_real_late_cancelled_inventory_publication_keeps_receipts_and_blocks_later_workspace_writes() {
    let sources = Sources::new();
    let ctx = egui::Context::default();
    let (mut app, id) = sources.app(&ctx);
    let project = Arc::clone(&app.workspace.as_ref().unwrap().project);
    project.functions(&FunctionsQuery::default()).unwrap();
    let binding = CacheBinding::capture(&app, &id).unwrap();
    let cancellation = AtomicBool::new(false);
    let mut staged = false;
    let mut observer = |progress: rampage_api::ProjectWorkspaceProgress| {
        if progress.phase == ProjectWorkspacePhase::PublicationStaged {
            staged = true;
        }
        if staged && progress.phase == ProjectWorkspacePhase::ValidatingCache {
            cancellation.store(true, Ordering::Release);
        }
    };
    let mut control = ProjectWorkspaceTaskControl::new(&cancellation, &mut observer);
    let prepared = capture_function_inventory(project, &mut control).unwrap();
    let output = sources.0.join("late-cancel.json");
    let result = publish_function_inventory(&prepared, &output, &mut control);
    assert_eq!(result.as_ref().unwrap().status, DebuggerCapturePublicationStatus::PublishedUncertain);
    app.close_workspace().unwrap();
    assert!(
        app.finish_inventory_job(binding, true, Ok(WorkspaceOutput::InventorySave { output: output.clone(), result }))
            .is_err()
    );
    assert!(matches!(&app.project_workspace_save_notices()[0], ProjectWorkspaceSaveNotice::Publication(receipt)
        if receipt.path == output && receipt.status == DebuggerCapturePublicationStatus::PublishedUncertain));
    app.open_exact_at(&ctx, sources.0.join("b.elf"), None, None).unwrap();
    assert!(app.begin_workspace_save(&ctx, sources.0.join("never-published.json")).is_err());
    app.workspace.as_ref().unwrap().project.functions(&FunctionsQuery::default()).unwrap();
    let current = app.active_module_id().unwrap().to_owned();
    assert!(app.begin_inventory_cache_save(&ctx, &current, sources.0.join("never-cached.json")).is_err());
    assert!(!sources.0.join("never-cached.json").exists());
    assert!(output.exists());
}
