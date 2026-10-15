use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use rampage_analysis::classes::HeaderClassification;
use rampage_api::{DebugLayoutProjection, DebugLayoutReview};
use rampage_ui::App;

struct SourceCopy {
    directory: PathBuf,
    path: PathBuf,
}

impl SourceCopy {
    fn new(variant: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root =
            std::env::var_os("RAMPAGE_DEBUG_CPP_VIRTUAL_FIXTURES").expect("requires centrally compiled fixtures");
        let source = PathBuf::from(root).join(variant).join("records.debug.elf");
        let directory = std::env::temp_dir().join(format!(
            "rampage-ui-debug-virtual-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
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

fn optional_fact(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown (not inferred)".to_owned(), |value| format!("{value} bytes (explicit)"))
}

fn assert_expanded_contents(harness: &mut Harness<'_, App>, review: &DebugLayoutReview) {
    let ty = review
        .report
        .types
        .iter()
        .find(|ty| {
            !ty.projections.is_empty()
                && review.report.functions.iter().any(|function| {
                    review.approved.contains(&function.address) && function.dependencies.contains(&ty.layout.name)
                })
        })
        .unwrap();
    let checked_title = format!("Checked consumer layout: {}", ty.layout.name);
    harness.get_by_label(&checked_title).click_accesskit();
    harness.run();
    harness.get_by_label("Projected opaque consumer storage below; not an exact producer void pointer type.");
    let field = &ty.layout.fields[0];
    assert_eq!(field.name, "rampage_vptr");
    harness.get_by_label(&format!(
        "{}: offset {}, size {}; consumer type/alignment: {:?}",
        field.name, field.offset, field.size, field.ty,
    ));
    harness.get_by_label(&checked_title).click_accesskit();
    harness.run();

    let title = "Opaque consumer storage projections (read-only)";
    harness.get_by_label(title).click_accesskit();
    harness.run();
    harness
        .get_by_label_contains("Producer roles establish pointer -> pointer -> subroutine, not an exact callback ABI.");
    let mut projections = 0;
    let mut unknowns = 0;
    for ty in &review.report.types {
        for projection in &ty.projections {
            projections += 1;
            let DebugLayoutProjection::OpaqueVptr {
                field_index,
                record_id,
                member_id,
                record_byte_size,
                record_alignment,
                member_offset,
                member_byte_size,
                member_alignment,
                pointer_id,
                pointer_byte_size,
                pointer_alignment,
                pointee_pointer_id,
                pointee_pointer_byte_size,
                pointee_pointer_alignment,
                subroutine_id,
                ..
            } = projection;
            harness.get_by_label(&format!("{}: opaque_vptr, field {field_index}", ty.layout.name));
            harness.get_by_label(&format!(
                "Record unit {:#x}, DIE {:#x}: size {record_byte_size}, alignment {record_alignment}",
                record_id.unit_offset, record_id.die_offset,
            ));
            harness.get_by_label(&format!(
                "Member unit {:#x}, DIE {:#x}: offset {member_offset}, declared size {}, alignment {}",
                member_id.unit_offset,
                member_id.die_offset,
                optional_fact(*member_byte_size),
                optional_fact(*member_alignment),
            ));
            for (role, id, size, alignment) in [
                ("Pointer", pointer_id, pointer_byte_size, pointer_alignment),
                ("Pointee pointer", pointee_pointer_id, pointee_pointer_byte_size, pointee_pointer_alignment),
            ] {
                let label = format!(
                    "{role} unit {:#x}, DIE {:#x}: declared size {}, alignment {}",
                    id.unit_offset,
                    id.die_offset,
                    optional_fact(*size),
                    optional_fact(*alignment),
                );
                assert!(harness.query_all_by_label(&label).count() > 0, "{label}");
            }
            let label = format!(
                "Subroutine role: unit {:#x}, DIE {:#x} (not an exact callback type)",
                subroutine_id.unit_offset, subroutine_id.die_offset,
            );
            assert!(harness.query_all_by_label(&label).count() > 0, "{label}");
            unknowns += [
                member_byte_size,
                member_alignment,
                pointer_byte_size,
                pointer_alignment,
                pointee_pointer_byte_size,
                pointee_pointer_alignment,
            ]
            .into_iter()
            .filter(|fact| fact.is_none())
            .count();
        }
    }
    assert!(projections > 0 && unknowns > 0, "expanded assertions must include actual absent producer facts");
    harness.get_by_label(title).click_accesskit();
    harness.run();

    let title = "Raw named tables / header confidence";
    harness.get_by_label(title).click_accesskit();
    harness.run();
    assert!(!review.virtual_evidence.tables.is_empty());
    for table in &review.virtual_evidence.tables {
        let raw = &table.raw;
        assert_eq!(raw.header, HeaderClassification::UnverifiedPrefix);
        assert_eq!(raw.offset_to_top, None);
        let label = format!(
            "Header: UnverifiedPrefix; pointer size {}; raw offset word {:#x}; offset-to-top unknown (not inferred)",
            raw.pointer_size, raw.raw_offset_word,
        );
        assert!(harness.query_all_by_label(&label).count() > 0, "{label}");
        harness
            .get_by_label(
                &format!("Display name: {}; source {}; confidence {}", raw.name, raw.source, raw.confidence,),
            );
    }
    harness.get_by_label(title).click_accesskit();
    harness.run();

    let title = "Raw table slots (candidate positions)";
    harness.get_by_label(title).click_accesskit();
    harness.run();
    let mut slots = 0;
    for table in &review.virtual_evidence.tables {
        for slot in &table.raw.slots {
            slots += 1;
            harness.get_by_label(&format!(
                "Table {:#x}, candidate slot {} at {:#x}: raw {:#x}, {:?}, target {}",
                table.raw.address,
                slot.index,
                slot.address,
                slot.raw_value,
                slot.classification,
                slot.target.map_or_else(|| "unknown".to_owned(), |address| format!("{address:#x}")),
            ));
        }
    }
    assert!(slots > 0, "expanded slot assertions must exercise retained raw evidence");
    harness.get_by_label(title).click_accesskit();
    harness.run();
}

#[test]
#[ignore = "requires RAMPAGE_DEBUG_CPP_VIRTUAL_FIXTURES from the central owned-source fixture recipe"]
fn virtual_review_navigation_is_explicit_exact_read_only_and_stale_binding_disables_it() {
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let source = SourceCopy::new(variant);
        let mut harness = harness(&source.path);
        let review = harness.state_mut().workspace_mut().unwrap().project.review_debug_layouts().unwrap();
        let method = review.virtual_evidence.tables.iter().flat_map(|table| &table.methods).next().unwrap();
        let target = method.method_address;
        let button = format!("Go to exact method entry {target:#x}");
        let before = annotations(&mut harness);
        let cursor = harness.state_mut().workspace_mut().unwrap().cursor;
        open_review(&mut harness);
        assert_eq!(harness.state_mut().workspace_mut().unwrap().cursor, cursor, "preview must not navigate");
        assert_expanded_contents(&mut harness, &review);
        assert_eq!(harness.state_mut().workspace_mut().unwrap().cursor, cursor, "expansion must not navigate");
        harness.get_by_label("Exact method entry associations (source evidence only)").click_accesskit();
        harness.run();
        assert!(!harness.get_by_label(&button).accesskit_node().is_disabled());
        harness.get_by_label(&button).click_accesskit();
        harness.run();
        harness.get_by_label("Checked debug layout review");
        assert_eq!(harness.state_mut().workspace_mut().unwrap().cursor, target);
        assert_eq!(annotations(&mut harness), before);
        let workspace = harness.state_mut().workspace_mut().unwrap();
        assert!(workspace.project.undo().unwrap().is_empty(), "navigation creates no annotation step");
        workspace.begin_comment();
        workspace.editing.as_mut().unwrap().text = "intervening annotation".to_owned();
        workspace.finish_edit();
        workspace.undo();
        harness.run();
        assert_eq!(annotations(&mut harness), before);
        assert!(harness.get_by_label(&button).accesskit_node().is_disabled());
        assert!(harness.get_by_label("Apply reviewed changes").accesskit_node().is_disabled());
        harness.get_by_label("Review is no longer current. Preview again and review the changes before applying.");
        harness.key_press(egui::Key::Escape);
        harness.run();
        assert_eq!(harness.state_mut().workspace_mut().unwrap().cursor, target);
    }
}
