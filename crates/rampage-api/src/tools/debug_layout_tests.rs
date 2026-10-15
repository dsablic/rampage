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
