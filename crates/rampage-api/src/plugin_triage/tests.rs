use std::sync::atomic::AtomicBool;

use super::*;

fn with_prepared(work: impl FnOnce(&PreparedPluginTriage, &ProjectWorkspaceTaskControl<'_>)) {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/net-client-x64.elf");
    let project = crate::Session::default().open(&path, None).unwrap();
    let cancellation = AtomicBool::new(false);
    let mut observer = |_| {};
    let control = ProjectWorkspaceTaskControl::new(&cancellation, &mut observer);
    let prepared = prepare_plugin_triage_with_analysis(project, ReportLimits::default(), &control).unwrap();
    work(&prepared, &control);
}

fn body(prepared: &PreparedPluginTriage) -> contract::ReportBody {
    let mut sections = ["Binary", "Toolchain", "Capabilities", "Imports by library", "Notable strings", "Functions"]
        .into_iter()
        .map(|title| contract::Section { title: title.to_owned(), findings: Vec::new(), total: 0, truncated: false })
        .collect::<Vec<_>>();
    sections[0].findings.push(contract::Finding {
        observation: "plugin says this is observed".into(),
        evidence: vec!["plugin evidence".into()],
        source: contract::Source::BinaryInfo,
        confidence: contract::Confidence::Observed,
        address: None,
        fact_refs: vec![prepared.facts.binary.id],
    });
    sections[0].total = 1;
    contract::ReportBody {
        summary: vec!["plugin summary".into()],
        limitations: vec!["plugin limitation".into()],
        next_steps: vec![contract::NextStep {
            action: contract::Action::FindMain,
            reason: "plugin suggestion".into(),
            fact_refs: vec![prepared.facts.binary.id],
        }],
        next_steps_omitted: 0,
        sections,
    }
}

fn response(body: contract::ReportBody) -> contract::GuestResponse {
    contract::GuestResponse {
        schema_version: contract::SCHEMA_VERSION,
        outcome: contract::GuestOutcome::Report { body },
    }
}

#[test]
fn adopted_observed_and_suggestions_remain_plugin_claims_and_do_not_edit_names() {
    with_prepared(|prepared, control| {
        let before = prepared.project.names_revision().unwrap();
        let report = conversion::adopt(prepared, response(body(prepared)), "a".repeat(64)).unwrap();
        assert_eq!(report.provenance.content_authority, "plugin_claims");
        assert!(report.provenance.confidence_interpretation.contains("not_host_observation"));
        assert_eq!(report.report.sections[0].findings[0].confidence, crate::FindingConfidence::Observed);
        assert_eq!(report.report.next_steps[0].tool, "find_main");
        assert!(Arc::ptr_eq(&before, &prepared.project.names_revision().unwrap()));
        prepared.revalidate(control).unwrap();
    });
}

#[test]
fn report_rejects_foreign_refs_wrong_source_and_unbacked_addresses() {
    with_prepared(|prepared, _| {
        for mutation in 0..3 {
            let mut body = body(prepared);
            let finding = &mut body.sections[0].findings[0];
            match mutation {
                0 => finding.fact_refs = vec![u32::MAX],
                1 => finding.source = contract::Source::ListImports,
                _ => finding.address = Some(0xdead_beef),
            }
            assert!(conversion::adopt(prepared, response(body), "a".repeat(64)).is_err());
        }
    });
}

#[test]
fn envelope_overhead_and_escaping_cannot_bypass_final_byte_limit() {
    with_prepared(|prepared, _| {
        let mut body = body(prepared);
        // Valid contract text, but escaping alone makes this exceed the final 60k envelope budget.
        body.summary = vec!["\u{0000}".repeat(MAX_PLUGIN_TRIAGE_REPORT_BYTES / 5)];
        contract::validate_report(&prepared.facts, &body).unwrap();
        assert!(conversion::adopt(prepared, response(body), "a".repeat(64)).is_err());
    });
}

#[test]
fn preflight_refuses_large_individual_metadata_before_serialized_copy() {
    let large = "x".repeat(contract::MAX_TEXT_BYTES + 1);
    assert!(bounds::serialized_preflight(&vec![large]).is_err());
    assert!(bounds::serialize_bounded(&"\u{0000}".repeat(100), 100).is_err());
}

#[test]
fn preparation_uses_current_primitive_rows_not_historical_inventory_or_reports() {
    with_prepared(|prepared, _| {
        let rows = match &prepared.facts.functions {
            contract::FunctionFacts::Available { rows } => rows,
            _ => panic!("completed analysis must supply current function facts"),
        };
        let expected = prepared.project.functions(&crate::FunctionsQuery::default()).unwrap();
        assert_eq!(rows.len(), expected.total);
        for (actual, expected) in rows.iter().zip(expected.items) {
            assert_eq!((actual.address, &actual.name), (expected.address, &expected.name));
        }
        let identified = prepared.project.apply_signatures_default(None, false).unwrap();
        assert!(identified.warnings.is_empty());
        assert_eq!(prepared.facts.signature_matches.len(), identified.matches.len());
        for (actual, expected) in prepared.facts.signature_matches.iter().zip(identified.matches) {
            assert_eq!(
                (actual.address, &actual.name, actual.unnamed),
                (expected.address, &expected.name, expected.unnamed)
            );
        }
        contract::validate_facts(&prepared.facts).unwrap();
        assert!(prepared.input.len() <= contract::MAX_INPUT_BYTES);
    });
}
