use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use rampage_ui::App;

struct Sources(PathBuf);

impl Sources {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "module-reference-ui-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
        for name in ["first.elf", "second.elf"] {
            std::fs::copy(&fixture, path.join(name)).unwrap();
        }
        Self(path)
    }
}

impl Drop for Sources {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn harness(app: App) -> Harness<'static, App> {
    let mut harness =
        Harness::builder().with_size(egui::vec2(1500.0, 1100.0)).build_ui_state(|ui, app: &mut App| app.show(ui), app);
    harness.run();
    harness
}

#[test]
fn window_is_explicit_and_unsupported_coverage_survives_active_selection_changes() {
    let sources = Sources::new();
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    let first = app.add_module_at(&ctx, sources.0.join("first.elf"), None, None).unwrap();
    let first_project = Arc::clone(&app.workspace_mut().unwrap().project);
    let second = app.add_module_at(&ctx, sources.0.join("second.elf"), None, None).unwrap();
    let second_project = Arc::clone(&app.workspace_mut().unwrap().project);
    let first_bytes = std::fs::read(sources.0.join("first.elf")).unwrap();
    let second_bytes = std::fs::read(sources.0.join("second.elf")).unwrap();
    let mut harness = harness(app);
    assert!(harness.query_by_label("Module references").is_none());
    harness.get_by_label("rampage").click_secondary();
    harness.run();
    harness.get_by_label("Module references…").click();
    harness.run();
    harness.get_by_label("No query has run. Opening this window and editing filters do not read source files.");
    harness.get_by_label("Apply / Refresh").click();
    harness.run();
    harness.get_by_label("Metadata coverage (including unavailable modules)");
    let coverage = format!("{first}: Elf · Unsupported · origin None");
    harness.get_by_label(&coverage);
    harness.state_mut().select_module(&first).unwrap();
    harness.state_mut().workspace_mut().unwrap().goto(0x1234);
    harness.run();
    harness.get_by_label(&coverage);
    assert!(
        harness
            .query_by_label("Historical rows only: navigation and paging disabled. Apply again explicitly.")
            .is_none()
    );
    harness.state_mut().select_module(&second).unwrap();
    assert!(Arc::ptr_eq(&second_project, &harness.state_mut().workspace_mut().unwrap().project));
    assert!(first_project.annotation_list().comments.is_empty());
    assert!(second_project.annotation_list().comments.is_empty());
    assert_eq!(std::fs::read(sources.0.join("first.elf")).unwrap(), first_bytes);
    assert_eq!(std::fs::read(sources.0.join("second.elf")).unwrap(), second_bytes);
}

#[test]
fn changed_original_source_is_not_checked_by_opening_or_repainting_the_window() {
    let sources = Sources::new();
    let path = sources.0.join("first.elf");
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    app.add_module_at(&ctx, path.clone(), None, None).unwrap();
    let project = Arc::clone(&app.workspace_mut().unwrap().project);
    app.show_module_references();
    let mut harness = harness(app);
    harness.get_by_label("Apply / Refresh").click();
    harness.run();
    std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(&[0]).unwrap();
    for _ in 0..3 {
        harness.run();
    }
    assert!(
        harness
            .query_by_label("Historical rows only: navigation and paging disabled. Apply again explicitly.")
            .is_none()
    );
    assert!(project.binary.validate_available_backing_source().is_err(), "the retained descriptor really is stale");
    harness.get_by_label("Apply / Refresh").click();
    harness.run();
    harness.get_by_label("Historical rows only: navigation and paging disabled. Apply again explicitly.");
    assert!(project.annotation_list().comments.is_empty());
}

#[test]
#[ignore = "requires the owned consumer.exe and renamed-provider.bin PE fixtures"]
fn owned_pe_pair_navigates_only_after_explicit_source_and_target_clicks() {
    let directory = PathBuf::from(
        std::env::var_os("RAMPAGE_MODULE_LINKAGE_FIXTURES")
            .expect("set RAMPAGE_MODULE_LINKAGE_FIXTURES to the owned PE pair directory"),
    );
    let consumer = directory.join("consumer.exe");
    let provider = directory.join("renamed-provider.bin");
    assert!(consumer.is_file() && provider.is_file(), "both owned PE fixture files are required");
    let expected_source = PeImage(std::fs::read(&consumer).unwrap()).import_slot(b"owned-provider.dll", b"add");
    let expected_target = PeImage(std::fs::read(&provider).unwrap()).export_address(b"add");
    let sources = Sources::new();
    let copied_consumer = sources.0.join("consumer.exe");
    let copied_provider = sources.0.join("renamed-provider.bin");
    std::fs::copy(consumer, &copied_consumer).unwrap();
    std::fs::copy(provider, &copied_provider).unwrap();
    let ctx = egui::Context::default();
    let mut app = App::blocking();
    let source_id = app.add_module_at(&ctx, copied_consumer.clone(), None, None).unwrap();
    let source_project = Arc::clone(&app.workspace_mut().unwrap().project);
    let target_id = app.add_module_at(&ctx, copied_provider, None, None).unwrap();
    let target_project = Arc::clone(&app.workspace_mut().unwrap().project);
    let inputs = [
        rampage_api::ModuleReferenceInput { module_id: source_id.clone(), project: source_project },
        rampage_api::ModuleReferenceInput { module_id: target_id.clone(), project: target_project },
    ];
    let view = rampage_api::prepare_module_reference_view(&inputs, &Default::default()).unwrap();
    let row = view
        .report()
        .rows
        .iter()
        .find(|row| {
            row.status == rampage_api::ModuleReferenceStatus::DeclaredLink
                && row.import_name.as_ref().is_some_and(|name| name.display.as_deref() == Some("add"))
        })
        .expect("real parser must prove a named add declaration despite the provider basename mismatch");
    assert_eq!(row.import_library.display.as_deref(), Some("owned-provider.dll"));
    let source_slot = row.source_slot;
    assert_eq!(source_slot, expected_source, "independent PE import-directory address");
    let candidate = &row.candidates[0];
    assert_eq!(candidate.module_id, target_id);
    let target_address = candidate.address.expect("direct export address");
    assert_eq!(target_address, expected_target, "independent PE export-directory address");
    app.show_module_references();
    let mut harness = harness(app);
    harness.get_by_label("Apply / Refresh").click();
    harness.run();
    assert_eq!(harness.state().active_module_id(), Some(target_id.as_str()));
    harness.get_by_label("Inspect source slot").scroll_to_me();
    harness.run();
    assert!(!harness.get_by_label("Inspect source slot").accesskit_node().is_disabled());
    assert!(harness.query_by_label("Module reference error").is_none());
    harness.get_by_label("Inspect source slot").click_accesskit();
    harness.run();
    assert!(harness.query_by_label("Module reference error").is_none(), "source navigation was rejected");
    assert_eq!(harness.state().active_module_id(), Some(source_id.as_str()));
    assert_eq!(harness.state_mut().workspace_mut().unwrap().cursor, source_slot);
    assert!(Arc::ptr_eq(&inputs[0].project, &harness.state_mut().workspace_mut().unwrap().project));
    harness.get_by_label("Inspect direct target").scroll_to_me();
    harness.run();
    assert!(!harness.get_by_label("Inspect direct target").accesskit_node().is_disabled());
    harness.get_by_label("Inspect direct target").click_accesskit();
    harness.run();
    assert!(harness.query_by_label("Module reference error").is_none(), "target navigation was rejected");
    assert_eq!(harness.state().active_module_id(), Some(target_id.as_str()));
    assert_eq!(harness.state_mut().workspace_mut().unwrap().cursor, target_address);
    assert!(Arc::ptr_eq(&inputs[1].project, &harness.state_mut().workspace_mut().unwrap().project));
    assert!(harness.state_mut().workspace_mut().unwrap().analysis_deferred());
    std::fs::OpenOptions::new().append(true).open(copied_consumer).unwrap().write_all(&[0]).unwrap();
    harness.run();
    assert!(
        harness
            .query_by_label("Historical rows only: navigation and paging disabled. Apply again explicitly.")
            .is_none(),
        "paint does not inspect original descriptors"
    );
    harness.get_by_label("Inspect source slot").scroll_to_me();
    harness.run();
    assert!(!harness.get_by_label("Inspect source slot").accesskit_node().is_disabled());
    harness.get_by_label("Inspect source slot").click_accesskit();
    harness.run();
    assert_eq!(harness.state().active_module_id(), Some(target_id.as_str()));
    assert_eq!(harness.state_mut().workspace_mut().unwrap().cursor, target_address);
    harness.get_by_label("Module reference error");
    harness.get_by_label("Historical rows only: navigation and paging disabled. Apply again explicitly.");
    assert!(harness.get_by_label("Inspect source slot").accesskit_node().is_disabled());
    assert!(harness.get_by_label("Inspect direct target").accesskit_node().is_disabled());
    assert!(Arc::ptr_eq(&inputs[1].project, &harness.state_mut().workspace_mut().unwrap().project));
}

// Independent fixture expectations: read PE64 directory fields without the production linkage parser.
struct PeImage(Vec<u8>);

impl PeImage {
    fn word(&self, at: usize) -> u16 {
        u16::from_le_bytes(self.0[at..at + 2].try_into().unwrap())
    }

    fn dword(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.0[at..at + 4].try_into().unwrap())
    }

    fn qword(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.0[at..at + 8].try_into().unwrap())
    }

    fn nt(&self) -> usize {
        let nt = self.dword(0x3c) as usize;
        assert_eq!(&self.0[nt..nt + 4], b"PE\0\0");
        assert_eq!(self.word(nt + 24), 0x20b, "owned fixture must be PE64");
        nt
    }

    fn base(&self) -> u64 {
        self.qword(self.nt() + 24 + 24)
    }

    fn offset(&self, rva: u32) -> usize {
        let nt = self.nt();
        let sections = nt + 24 + usize::from(self.word(nt + 20));
        for index in 0..usize::from(self.word(nt + 6)) {
            let section = sections + index * 40;
            let start = self.dword(section + 12);
            let size = self.dword(section + 16);
            if rva >= start && rva - start < size {
                return (self.dword(section + 20) + rva - start) as usize;
            }
        }
        panic!("fixture RVA {rva:#x} has no raw section backing");
    }

    fn name(&self, rva: u32) -> &[u8] {
        let bytes = &self.0[self.offset(rva)..];
        &bytes[..bytes.iter().position(|byte| *byte == 0).unwrap()]
    }

    fn import_slot(&self, library: &[u8], name: &[u8]) -> u64 {
        let directory = self.nt() + 24 + 112 + 8;
        let mut descriptor = self.offset(self.dword(directory));
        for _ in 0..64 {
            let lookup = self.dword(descriptor);
            assert_ne!(lookup, 0, "fixture import not found before end of descriptors");
            if self.name(self.dword(descriptor + 12)).eq_ignore_ascii_case(library) {
                for index in 0..256 {
                    let thunk = self.qword(self.offset(lookup) + index * 8);
                    assert_ne!(thunk, 0, "named fixture import not found");
                    if thunk >> 63 == 0 && self.name(u32::try_from(thunk).unwrap() + 2) == name {
                        return self.base() + u64::from(self.dword(descriptor + 16)) + index as u64 * 8;
                    }
                }
            }
            descriptor += 20;
        }
        panic!("fixture import directory exceeds expectation bound");
    }

    fn export_address(&self, name: &[u8]) -> u64 {
        let directory = self.nt() + 24 + 112;
        let export_rva = self.dword(directory);
        let exports = self.offset(export_rva);
        assert_eq!(self.name(self.dword(exports + 12)), b"owned-provider.dll");
        let names = self.offset(self.dword(exports + 32));
        let ordinals = self.offset(self.dword(exports + 36));
        let addresses = self.offset(self.dword(exports + 28));
        for index in 0..self.dword(exports + 24) as usize {
            if self.name(self.dword(names + index * 4)) == name {
                let ordinal = usize::from(self.word(ordinals + index * 2));
                let target = self.dword(addresses + ordinal * 4);
                assert!(!(export_rva..export_rva + self.dword(directory + 4)).contains(&target));
                return self.base() + u64::from(target);
            }
        }
        panic!("fixture named export missing");
    }
}
