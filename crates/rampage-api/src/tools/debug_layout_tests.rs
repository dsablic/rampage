//! Synthetic rows test transport only; native source closure is exercised by the ignored compiled-fixture test.

use super::*;
use rampage_decompiler::layout::{
    LayoutField, LayoutOrganization, LayoutScalar, LayoutType, PlainStructLayout, ScalarKind,
};

fn receipt_evidence() -> crate::DebugLayoutReview {
    crate::DebugLayoutReview {
        review_sha256: "a".repeat(64),
        image_sha256: "b".repeat(64),
        compiler_spec_sha256: "c".repeat(64),
        report: crate::DebugLayoutReport {
            types: Vec::new(),
            functions: (0..128)
                .map(|index| crate::DebugLayoutFunction {
                    address: 0x400000 + index * 16,
                    original_name: format!("receipt_function_{index}"),
                    unit_offset: 0,
                    die_offset: index,
                    declaration: "\0\"\\λ".repeat(500),
                    dependencies: Vec::new(),
                })
                .collect(),
            warnings: (0..128).map(|index| format!("checked refusal {index}: {}", "\0λ".repeat(200))).collect(),
        },
        producer_report: Some(rampage_loaders::debug::DebugLayoutReport {
            warnings: (0..128).map(|index| format!("producer refusal {index}: {}", "\n\"λ".repeat(200))).collect(),
            ..Default::default()
        }),
        virtual_evidence: Default::default(),
        approved: (0..64).map(|index| 0x400000 + index * 16).collect(),
        preserved: (64..128).map(|index| 0x400000 + index * 16).collect(),
        imported: Some(crate::DebugLayoutImport {
            applied: (0..64).map(|index| 0x400000 + index * 16).collect(),
            preserved: (64..128).map(|index| 0x400000 + index * 16).collect(),
            imported_types: vec!["receipt_type".to_owned()],
        }),
    }
}

#[test]
fn receipt_only_escaped_evidence_pages_keep_whole_rows_counts_hashes_and_progress_under_the_byte_cap() {
    let evidence = receipt_evidence();
    let expected = debug_layout_rows(&evidence).unwrap();
    let mut returned = Vec::new();
    let mut offset = 0;
    let mut byte_capped = false;
    loop {
        let mut page = debug_layout_page(&evidence, offset, 1000).unwrap();
        let preview_rows = page["details"].as_array().unwrap().clone();
        debug_layout_applied_receipt(&mut page, &evidence);
        let text = page.to_string();
        assert!(text.len() <= MAX_RESULT_CHARS, "{} bytes", text.len());
        let result: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["status"], "applied");
        assert_eq!(result["whole_apply_succeeded"], true);
        assert_eq!(result["review_sha256"], evidence.review_sha256);
        assert_eq!(result["image_sha256"], evidence.image_sha256);
        assert_eq!(result["compiler_spec_sha256"], evidence.compiler_spec_sha256);
        assert_eq!(result["applied_total"], evidence.imported.as_ref().unwrap().applied.len());
        assert_eq!(result["preserved_total"], evidence.preserved.len());
        assert_eq!(result["warnings_total"], evidence.report.warnings.len());
        assert_eq!(result["producer_warnings_total"], evidence.producer_report.as_ref().unwrap().warnings.len());
        assert_eq!(result["details_total"], expected.len());
        for row in result["details"].as_array().unwrap() {
            if row["kind"] == "function" {
                let address = row["data"]["address"].as_str().unwrap().strip_prefix("0x").unwrap();
                let address = u64::from_str_radix(address, 16).unwrap();
                let expected_status = if evidence.approved.contains(&address) { "applied" } else { "preserved" };
                assert_eq!(row["status"], expected_status);
            }
        }
        returned.extend(preview_rows);
        byte_capped |= result["byte_capped"] == true;
        if result["more"] == false {
            assert!(result["next_offset"].is_null());
            break;
        }
        let next = result["next_offset"].as_u64().unwrap() as usize;
        assert!(next > offset, "every accepted whole row fits at the start of its next page");
        offset = next;
    }
    assert!(byte_capped);
    assert_eq!(returned, expected, "no omitted or partial field/function/warning/refusal rows");
    let mut empty = debug_layout_page(&evidence, usize::MAX, 1).unwrap();
    debug_layout_applied_receipt(&mut empty, &evidence);
    assert_eq!(empty["details"], serde_json::json!([]));
    assert_eq!(empty["whole_apply_succeeded"], true);
    assert_eq!(empty["applied_total"], evidence.approved.len());
}

#[test]
fn receipt_only_oversize_evidence_is_rejected_instead_of_cutting_json_or_creating_a_nonprogressing_page() {
    let mut evidence = receipt_evidence();
    evidence.report.warnings.push("\0".repeat(MAX_RESULT_CHARS));
    let error = debug_layout_page(&evidence, usize::MAX, 1).unwrap_err().to_string();
    assert!(error.contains("output capacity"), "{error}");
    assert!(error.contains("nothing imported"), "{error}");
}

fn receipt_type(name: &str, die_offset: u64) -> crate::DebugLayoutType {
    crate::DebugLayoutType {
        original_name: name.to_owned(),
        unit_offset: 0,
        die_offset,
        projections: Vec::new(),
        layout: PlainStructLayout {
            name: name.to_owned(),
            size: 4,
            alignment: 4,
            organization: LayoutOrganization {
                pointer_size: 8,
                int_size: 4,
                long_size: 8,
                scalar_alignments: [1, 2, 4, 8],
            },
            fields: vec![LayoutField {
                name: "value".to_owned(),
                offset: 0,
                size: 4,
                ty: LayoutType::Scalar {
                    scalar: LayoutScalar {
                        name: "int4".to_owned(),
                        kind: ScalarKind::SignedInteger,
                        size: 4,
                        alignment: 4,
                    },
                },
            }],
        },
    }
}

fn type_receipt_evidence() -> crate::DebugLayoutReview {
    let mut evidence = receipt_evidence();
    evidence.report.types = vec![receipt_type("necessary", 1), receipt_type("unused", 2)];
    evidence.report.functions.truncate(2);
    evidence.report.functions[0].dependencies = vec!["necessary".to_owned()];
    evidence.report.functions[1].dependencies = vec!["unused".to_owned()];
    evidence.report.warnings.clear();
    evidence.producer_report = None;
    evidence.approved = vec![evidence.report.functions[0].address];
    evidence.preserved = vec![evidence.report.functions[1].address];
    evidence.imported = None;
    evidence
}

#[test]
fn receipt_only_unused_types_and_fields_are_unverified_even_when_other_functions_are_approved_and_applied() {
    let mut evidence = type_receipt_evidence();
    let mut page = debug_layout_page(&evidence, 0, 1000).unwrap();
    let rows = page["details"].as_array().unwrap();
    assert_eq!(rows[0]["kind"], "type");
    assert_eq!(rows[0]["data"]["layout"]["name"], "necessary");
    assert_eq!(rows[0]["status"], "verified");
    assert_eq!(rows[1]["kind"], "field");
    assert_eq!(rows[1]["status"], "verified");
    assert_eq!(rows[2]["kind"], "type");
    assert_eq!(rows[2]["data"]["layout"]["name"], "unused");
    assert_eq!(rows[2]["status"], "unverified");
    assert_eq!(rows[3]["kind"], "field");
    assert_eq!(rows[3]["status"], "unverified");
    evidence.imported = Some(crate::DebugLayoutImport {
        applied: evidence.approved.clone(),
        preserved: evidence.preserved.clone(),
        imported_types: vec!["necessary".to_owned()],
    });
    debug_layout_applied_receipt(&mut page, &evidence);
    assert_eq!(page["details"][0]["status"], "applied");
    assert_eq!(page["details"][1]["status"], "applied");
    assert_eq!(page["details"][2]["status"], "unverified");
    assert_eq!(page["details"][3]["status"], "unverified");
    assert_eq!(page["imported_types_total"], 1);
}

#[test]
fn receipt_only_all_preserved_functions_leave_all_types_and_fields_unverified_and_unchanged() {
    let mut evidence = type_receipt_evidence();
    evidence.approved.clear();
    evidence.preserved = evidence.report.functions.iter().map(|function| function.address).collect();
    let mut page = debug_layout_page(&evidence, 0, 1000).unwrap();
    evidence.imported = Some(crate::DebugLayoutImport {
        applied: Vec::new(),
        preserved: evidence.preserved.clone(),
        imported_types: Vec::new(),
    });
    debug_layout_applied_receipt(&mut page, &evidence);
    let rows = page["details"].as_array().unwrap();
    assert_eq!(rows.iter().filter(|row| row["kind"] == "type" || row["kind"] == "field").count(), 4);
    for row in rows {
        let expected = if row["kind"] == "function" { "preserved" } else { "unverified" };
        assert_eq!(row["status"], expected);
    }
    assert_eq!(page["approved_total"], 0);
    assert_eq!(page["applied_total"], 0);
    assert_eq!(page["imported_types_total"], 0);
    assert_eq!(page["preserved_total"], evidence.report.functions.len());
}

fn source_id(die_offset: u64) -> rampage_loaders::debug::DebugLayoutTypeId {
    rampage_loaders::debug::DebugLayoutTypeId { unit_offset: 0, die_offset }
}

fn virtual_receipt_evidence() -> crate::DebugLayoutReview {
    use rampage_analysis::classes::{
        ClassEvidence, HeaderClassification, RttiClassification, RttiEvidence, ScanStop, SlotClassification, VtableSlot,
    };

    let mut review = type_receipt_evidence();
    let ty = &mut review.report.types[0];
    ty.layout.size = 16;
    ty.layout.alignment = 8;
    ty.layout.fields = vec![LayoutField {
        name: "rampage_vptr".to_owned(),
        offset: 0,
        size: 8,
        ty: LayoutType::Pointer {
            name: String::new(),
            size: 8,
            alignment: 8,
            pointee: LayoutScalar { name: "void".to_owned(), kind: ScalarKind::Void, size: 0, alignment: 1 },
        },
    }];
    ty.projections = vec![crate::DebugLayoutProjection::OpaqueVptr {
        field_index: 0,
        record_id: source_id(1),
        member_id: source_id(2),
        source: rampage_loaders::debug::DebugLayoutSource {
            unit_offset: 0,
            language: 4,
            dwarf_version: 5,
            address_size: 8,
        },
        record_byte_size: 16,
        record_alignment: 8,
        member_offset: 0,
        member_byte_size: None,
        member_alignment: None,
        pointer_id: source_id(3),
        pointer_byte_size: None,
        pointer_alignment: None,
        pointee_pointer_id: source_id(4),
        pointee_pointer_byte_size: Some(8),
        pointee_pointer_alignment: None,
        subroutine_id: source_id(5),
    }];
    for index in 0..32u64 {
        let address = 0x800000 + index * 0x1000;
        review.virtual_evidence.tables.push(crate::DebugLayoutVtableEvidence {
            raw: ClassEvidence {
                name: "raw\0\"λ".repeat(16),
                vtable_symbol: format!("_ZTV{index}"),
                address,
                source: "named_itanium_vtable_symbol",
                confidence: "raw_named_vtable_evidence",
                pointer_size: 8,
                header: HeaderClassification::UnverifiedPrefix,
                raw_offset_word: u64::MAX - 7,
                offset_to_top: None,
                rtti_candidate: RttiEvidence { address: 0, classification: RttiClassification::Null, symbol: None },
                bound: "symbol_size",
                scan_limit: address + 16 + 64 * 8,
                scan_end: address + 16 + 64 * 8,
                slots: (0..64)
                    .map(|slot| VtableSlot {
                        index: slot,
                        address: address + 16 + slot * 8,
                        raw_value: 0x400000 + slot * 16,
                        classification: SlotClassification::Function,
                        target: Some(0x400000 + slot * 16),
                    })
                    .collect(),
                stop: ScanStop::SlotLimit,
            },
            methods: (0..8)
                .map(|slot| crate::DebugLayoutVirtualMethodEvidence {
                    slot_index: slot,
                    declared_virtual_slot_index: slot,
                    method_address: 0x400000 + slot * 16,
                    definition_id: source_id(100 + slot * 3),
                    record_id: source_id(1),
                    declaration_id: source_id(101 + slot * 3),
                    object_pointer_id: source_id(102 + slot * 3),
                    linkage_name: "\0\"\\λ".repeat(60),
                    layout_name: "necessary".to_owned(),
                    verification: "native_checked_source_evidence",
                })
                .collect(),
        });
    }
    review.virtual_evidence.warnings.push("raw warning\0\"λ".to_owned());
    review.virtual_evidence.limitations.push("not applied types or virtual-call targets\0\"λ".to_owned());
    review
}

#[test]
fn projection_rows_preserve_role_identities_unknown_facts_and_distinguish_opaque_consumer_storage() {
    let evidence = virtual_receipt_evidence();
    let rows = debug_layout_rows(&evidence).unwrap();
    let projection = rows.iter().find(|row| row["kind"] == "projection").unwrap();
    assert_eq!(projection["data"], debug_layout_value(&evidence.report.types[0].projections[0]).unwrap());
    assert_eq!(projection["data"]["kind"], "opaque_vptr");
    for fact in ["member_byte_size", "member_alignment", "pointer_byte_size", "pointer_alignment"] {
        assert!(projection["data"][fact].is_null(), "{fact}");
    }
    assert_eq!(projection["data"]["pointee_pointer_byte_size"], 8);
    assert_eq!(projection["data"]["pointer_id"]["die_offset"], 3);
    assert_eq!(projection["data"]["pointee_pointer_id"]["die_offset"], 4);
    assert_eq!(projection["data"]["subroutine_id"]["die_offset"], 5);
    let field = rows.iter().find(|row| row["kind"] == "field").unwrap();
    assert_eq!(field["storage_role"], "opaque_projection_storage_not_exact_producer_type");
    assert_eq!(field["data"]["ty"]["kind"], "pointer");
    assert_eq!(field["data"]["ty"]["pointee"]["kind"], "void");
    let unused = rows.iter().find(|row| row["kind"] == "field" && row["type_name"] == "unused").unwrap();
    assert_eq!(unused["status"], "unverified");
    assert!(unused.get("storage_role").is_none());
}

#[test]
fn bounded_virtual_rows_page_without_promoting_raw_confidence_or_read_only_status_after_whole_apply() {
    let mut evidence = virtual_receipt_evidence();
    let projection_count = evidence.report.types.iter().map(|ty| ty.projections.len()).sum::<usize>();
    let slot_count = evidence.virtual_evidence.tables.iter().map(|table| table.raw.slots.len()).sum::<usize>();
    let method_count = evidence.virtual_evidence.tables.iter().map(|table| table.methods.len()).sum::<usize>();
    let retained_total = evidence.report.types.len()
        + evidence.report.types.iter().map(|ty| ty.layout.fields.len()).sum::<usize>()
        + evidence.report.functions.len()
        + evidence.report.warnings.len()
        + projection_count
        + evidence.virtual_evidence.tables.len()
        + slot_count
        + method_count
        + evidence.virtual_evidence.warnings.len()
        + evidence.virtual_evidence.limitations.len();
    assert!(evidence.producer_report.is_none());
    let expected = debug_layout_rows(&evidence).unwrap();
    let mut raw = debug_layout_value(&evidence.virtual_evidence.tables[0].raw).unwrap();
    raw.as_object_mut().unwrap().remove("slots");
    let first_table = expected.iter().find(|row| row["kind"] == "vtable").unwrap();
    assert_eq!(first_table["data"], raw, "only slots move to independent linked rows");
    assert_eq!(first_table["data"]["header"], "unverified_prefix");
    assert!(first_table["data"]["offset_to_top"].is_null());
    assert!(first_table["data"].get("slots").is_none());
    evidence.imported = Some(crate::DebugLayoutImport {
        applied: evidence.approved.clone(),
        preserved: evidence.preserved.clone(),
        imported_types: vec!["necessary".to_owned()],
    });
    let mut returned = Vec::new();
    let mut offset = 0;
    let mut capped = false;
    loop {
        let mut page = debug_layout_page(&evidence, offset, 1000).unwrap();
        returned.extend(page["details"].as_array().unwrap().clone());
        debug_layout_applied_receipt(&mut page, &evidence);
        assert!(page.to_string().len() <= MAX_RESULT_CHARS);
        assert_eq!(page["review_sha256"], evidence.review_sha256);
        assert_eq!(page["details_total"], retained_total);
        assert_eq!(page["projections_total"], projection_count);
        assert_eq!(page["vtables_total"], evidence.virtual_evidence.tables.len());
        assert_eq!(page["vtable_slots_total"], slot_count);
        assert_eq!(page["virtual_methods_total"], method_count);
        assert_eq!(page["virtual_warnings_total"], evidence.virtual_evidence.warnings.len());
        assert_eq!(page["virtual_limitations_total"], evidence.virtual_evidence.limitations.len());
        assert_eq!(page["whole_apply_succeeded"], true);
        for row in page["details"].as_array().unwrap().iter().filter(|row| {
            row["source"] == "virtual_evidence"
                || matches!(row["kind"].as_str(), Some("projection" | "vtable" | "vtable_slot" | "virtual_method"))
        }) {
            assert_eq!(row["source"], "virtual_evidence");
            assert_eq!(row["status"], "read_only");
            if row["kind"] == "vtable_slot" || row["kind"] == "virtual_method" {
                assert!(row["table_address"].as_str().unwrap().starts_with("0x"));
            }
            if row["kind"] == "virtual_method" {
                assert_eq!(row["slot_index"], row["data"]["declared_virtual_slot_index"]);
                assert!(row["data"]["method_address"].as_str().unwrap().starts_with("0x"));
            }
        }
        capped |= page["byte_capped"] == true;
        if page["more"] == false {
            break;
        }
        let next = page["next_offset"].as_u64().unwrap() as usize;
        assert!(next > offset);
        offset = next;
    }
    assert!(capped);
    assert_eq!(returned, expected);
    assert_eq!(returned.len(), retained_total);
    for (kind, retained_count) in [
        ("projection", projection_count),
        ("vtable", evidence.virtual_evidence.tables.len()),
        ("vtable_slot", slot_count),
        ("virtual_method", method_count),
    ] {
        assert!(retained_count > 0, "the {kind} payload loop must be exercised");
        assert_eq!(returned.iter().filter(|row| row["kind"] == kind).count(), retained_count, "{kind}");
    }
    for ty in &evidence.report.types {
        let projections: Vec<_> =
            returned.iter().filter(|row| row["kind"] == "projection" && row["type_name"] == ty.layout.name).collect();
        assert_eq!(projections.len(), ty.projections.len());
        for (row, projection) in projections.iter().zip(&ty.projections) {
            assert_eq!(row["data"], serde_json::to_value(projection).unwrap());
        }
    }
    for table in &evidence.virtual_evidence.tables {
        let address = format!("{:#x}", table.raw.address);
        let table_rows: Vec<_> =
            returned.iter().filter(|row| row["kind"] == "vtable" && row["table_address"] == address).collect();
        assert_eq!(table_rows.len(), 1);
        let mut raw = serde_json::to_value(&table.raw).unwrap();
        raw.as_object_mut().unwrap().remove("slots");
        assert_eq!(table_rows[0]["data"], raw);
        let slots: Vec<_> =
            returned.iter().filter(|row| row["kind"] == "vtable_slot" && row["table_address"] == address).collect();
        assert_eq!(slots.len(), table.raw.slots.len());
        for (row, slot) in slots.iter().zip(&table.raw.slots) {
            assert_eq!(row["table_address"], address);
            assert_eq!(row["data"]["index"], slot.index);
            assert_eq!(row["data"], serde_json::to_value(slot).unwrap());
        }
        let methods: Vec<_> =
            returned.iter().filter(|row| row["kind"] == "virtual_method" && row["table_address"] == address).collect();
        assert_eq!(methods.len(), table.methods.len());
        for (row, method) in methods.iter().zip(&table.methods) {
            assert_eq!(row["table_address"], address);
            assert_eq!(row["slot_index"], method.slot_index);
            assert_eq!(row["data"]["slot_index"], method.slot_index);
            assert_eq!(row["data"], serde_json::to_value(method).unwrap());
        }
    }
}

#[test]
fn virtual_row_capacity_preflight_checks_unpaged_rows_and_preserves_rejection_totals_shape() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
    let source = VirtualFixtureCopy::from_source(&fixture);
    let project = crate::Session::default().open(&source.path(), None).unwrap();
    project.binary.validate_backing_source().unwrap();
    let before = serde_json::to_value(project.annotation_list()).unwrap();
    let log = source.path().with_file_name("image.elf.rampage");
    let log_before = std::fs::read(&log).ok();
    let apply_calls = std::cell::Cell::new(0);
    for kind in ["vtable", "virtual_method", "warning", "limitation"] {
        let mut evidence = virtual_receipt_evidence();
        let args = DebugLayoutImportArgs {
            apply: true,
            review_sha256: Some(evidence.review_sha256.clone()),
            offset: Some(0),
            limit: Some(1),
        };
        args.validate().unwrap();
        let first_page = debug_layout_page(&evidence, 0, 1).unwrap();
        assert_eq!(first_page["details"][0]["kind"], "type", "oversize virtual evidence is off-page");
        let oversize = "\0λ".repeat(MAX_RESULT_CHARS);
        match kind {
            "vtable" => evidence.virtual_evidence.tables[0].raw.name = oversize,
            "virtual_method" => evidence.virtual_evidence.tables[0].methods[0].linkage_name = oversize,
            "warning" => evidence.virtual_evidence.warnings.push(oversize),
            _ => evidence.virtual_evidence.limitations.push(oversize),
        }
        let error = debug_layout_page_before_apply(&evidence, &args, |digest| {
            apply_calls.set(apply_calls.get() + 1);
            project.apply_reviewed_debug_layouts(digest)
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("output capacity"), "{kind}: {error}");
        assert!(error.contains("nothing imported"), "{kind}: {error}");
        assert_eq!(apply_calls.get(), 0, "preflight must precede even core fingerprint/proof work");
        assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), before);
        assert_eq!(std::fs::read(&log).ok(), log_before);
        assert!(project.undo().unwrap().is_empty());
        let receipt: Value = serde_json::from_str(&debug_layout_import_error(&error, Some(true))).unwrap();
        assert_eq!(receipt["whole_apply_succeeded"], false);
        for count in ["projections_total", "vtables_total", "vtable_slots_total", "virtual_methods_total"] {
            assert!(receipt.get(count).unwrap().is_null());
        }
    }
    let bounded = virtual_receipt_evidence();
    let args = DebugLayoutImportArgs {
        apply: true,
        review_sha256: Some(bounded.review_sha256.clone()),
        offset: Some(0),
        limit: Some(1),
    };
    let error = debug_layout_page_before_apply(&bounded, &args, |digest| {
        apply_calls.set(apply_calls.get() + 1);
        assert_eq!(digest, bounded.review_sha256);
        Err(ApiError::Invalid("bounded page reached apply boundary".to_owned()))
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("bounded page reached apply boundary"));
    assert_eq!(apply_calls.get(), 1, "the spy is reachable when all rows fit");
    assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), before);
    assert_eq!(std::fs::read(&log).ok(), log_before);
    assert!(project.undo().unwrap().is_empty());
}

#[test]
fn ordinary_receipts_keep_legacy_rows_without_projection_storage_labels() {
    let evidence = type_receipt_evidence();
    let page = debug_layout_page(&evidence, 0, 1000).unwrap();
    assert_eq!(page["projections_total"], 0);
    assert_eq!(page["vtables_total"], 0);
    assert_eq!(page["virtual_methods_total"], 0);
    assert!(page["details"].as_array().unwrap().iter().all(|row| {
        row["source"] == "checked" && row.get("storage_role").is_none() && row["data"].get("projections").is_none()
    }));
}

struct VirtualFixtureCopy(std::path::PathBuf);

impl VirtualFixtureCopy {
    fn new(variant: &str) -> Self {
        let root =
            std::env::var_os("RAMPAGE_DEBUG_CPP_VIRTUAL_FIXTURES").expect("requires centrally compiled fixtures");
        let source = std::path::PathBuf::from(root).join(variant).join("records.debug.elf");
        Self::from_source(&source)
    }

    fn from_source(source: &std::path::Path) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-virtual-surface-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&directory).unwrap();
        let copy = Self(directory);
        std::fs::copy(source, copy.path()).unwrap();
        copy
    }

    fn path(&self) -> std::path::PathBuf {
        self.0.join("image.elf")
    }
}

impl Drop for VirtualFixtureCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn virtual_fixture_page(project: &Project, arguments: Value) -> Value {
    let (text, failed) = call(&tools(), project, "import_debug_layouts", arguments);
    assert!(!failed, "{text}");
    assert!(text.len() <= MAX_RESULT_CHARS);
    serde_json::from_str(&text).unwrap()
}

#[test]
#[ignore = "requires RAMPAGE_DEBUG_CPP_VIRTUAL_FIXTURES from the central owned-source fixture recipe"]
fn compiled_virtual_surfaces_keep_full_review_identity_and_read_only_associations_through_paged_apply_and_reopen() {
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let source = VirtualFixtureCopy::new(variant);
        let project = crate::Session::default().open(&source.path(), None).unwrap();
        let initial = project.review_debug_layouts().unwrap();
        let exact_address = initial.virtual_evidence.tables.iter().flat_map(|table| &table.methods).next().unwrap();
        let exact_address = exact_address.method_address;
        project.set_signature(exact_address, Some("int4 analyst_kept(void);")).unwrap();
        let review = project.review_debug_layouts().unwrap();
        assert!(review.preserved.contains(&exact_address));
        assert!(!review.approved.is_empty());
        let before = debug_layout_value(project.annotation_list()).unwrap();
        let expected = debug_layout_rows(&review).unwrap();
        assert!(expected.iter().any(|row| row["kind"] == "projection"));
        let method_offset = expected.iter().position(|row| row["kind"] == "virtual_method").unwrap();
        let mut offset = 0;
        let mut returned = Vec::new();
        loop {
            let page = virtual_fixture_page(&project, serde_json::json!({ "offset": offset, "limit": 1000 }));
            assert_eq!(page["review_sha256"], review.review_sha256);
            assert_eq!(page["details_total"], expected.len());
            assert_eq!(page["vtables_total"], review.virtual_evidence.tables.len());
            assert_eq!(page["whole_apply_succeeded"], false);
            returned.extend(page["details"].as_array().unwrap().clone());
            if page["more"] == false {
                break;
            }
            let next = page["next_offset"].as_u64().unwrap() as usize;
            assert!(next > offset);
            offset = next;
        }
        assert_eq!(returned, expected);
        assert_eq!(debug_layout_value(project.annotation_list()).unwrap(), before);
        let page = virtual_fixture_page(
            &project,
            serde_json::json!({
                "apply": true, "review_sha256": review.review_sha256, "offset": method_offset, "limit": 1,
            }),
        );
        assert_eq!(page["whole_apply_succeeded"], true);
        assert_eq!(page["review_sha256"], review.review_sha256);
        assert!(page["applied_total"].as_u64().unwrap() > 0, "paging never selects the write batch");
        assert_eq!(page["details"][0]["kind"], "virtual_method");
        assert_eq!(page["details"][0]["status"], "read_only");
        assert_eq!(page["details"][0]["data"]["verification"], "native_checked_source_evidence");
        assert!(
            project.annotation_list().signatures.iter().any(|signature| {
                signature.address == exact_address && signature.text == "int4 analyst_kept(void);"
            })
        );
        let reopened = crate::Session::default().open(&source.path(), None).unwrap();
        let reopened_review = reopened.review_debug_layouts().unwrap();
        assert_eq!(
            debug_layout_value(&reopened_review.virtual_evidence).unwrap(),
            debug_layout_value(&review.virtual_evidence).unwrap(),
            "preserved analyst signatures do not erase or authorize source-only associations",
        );
        let rows = debug_layout_rows(&reopened_review).unwrap();
        assert!(rows.iter().filter(|row| row["source"] == "virtual_evidence").all(|row| row["status"] == "read_only"));
    }
}
