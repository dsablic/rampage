//! Synthetic methods exercise correlation only, not producer proof or native validation.

use super::*;
use rampage_analysis::classes::{HeaderClassification, RttiClassification, RttiEvidence, ScanStop, VtableSlot};

fn id(offset: u64) -> DebugLayoutTypeId {
    DebugLayoutTypeId { unit_offset: 0, die_offset: offset }
}

fn method(index: u64, address: u64) -> VerifiedVirtualMethod {
    VerifiedVirtualMethod {
        virtual_slot_index: index,
        method_address: address,
        definition_id: id(100 + index * 4),
        record_id: id(1),
        declaration_id: id(101 + index * 4),
        object_pointer_id: id(102 + index * 4),
        linkage_name: "_ZN9Unrelated6methodEv".to_owned(),
        layout_name: "different_source_record".to_owned(),
    }
}

fn table(header: HeaderClassification, targets: &[u64]) -> ClassEvidence {
    ClassEvidence {
        name: "MisleadingDisplayName".to_owned(),
        vtable_symbol: "_ZTV21MisleadingDisplayName".to_owned(),
        address: 0x3000,
        source: "named_itanium_vtable_symbol",
        confidence: "raw_named_vtable_evidence",
        pointer_size: 8,
        header,
        raw_offset_word: u64::MAX - 7,
        offset_to_top: (header == HeaderClassification::KnownRtti).then_some(-8),
        rtti_candidate: RttiEvidence {
            address: if header == HeaderClassification::KnownRtti { 0x4000 } else { 0 },
            classification: if header == HeaderClassification::KnownRtti {
                RttiClassification::KnownSymbol
            } else {
                RttiClassification::Null
            },
            symbol: (header == HeaderClassification::KnownRtti).then(|| "_ZTI21MisleadingDisplayName".to_owned()),
        },
        bound: "symbol_size",
        scan_limit: 0x3010 + targets.len() as u64 * 8,
        scan_end: 0x3010 + targets.len() as u64 * 8,
        slots: targets
            .iter()
            .enumerate()
            .map(|(index, &target)| VtableSlot {
                index: index as u64,
                address: 0x3010 + index as u64 * 8,
                raw_value: target,
                classification: SlotClassification::Function,
                target: Some(target),
            })
            .collect(),
        stop: ScanStop::Bound,
    }
}

fn recovery(tables: Vec<ClassEvidence>) -> ClassRecovery {
    ClassRecovery {
        classes: tables,
        rtti_classes: Vec::new(),
        vftables: Vec::new(),
        vftables_total: 0,
        vftables_offset: 0,
        vftables_next_offset: None,
        warnings: Vec::new(),
        limitations: Vec::new(),
    }
}

#[test]
fn exact_entry_and_index_association_never_promotes_raw_header_confidence() {
    for header in [HeaderClassification::KnownRtti, HeaderClassification::UnverifiedPrefix] {
        let raw = table(header, &[0x1000]);
        let before = serde_json::to_value(&raw).unwrap();
        let evidence = correlate(recovery(vec![raw]), &[method(0, 0x1000)], &BTreeSet::from([0x1000])).unwrap();
        assert_eq!(serde_json::to_value(&evidence.tables[0].raw).unwrap(), before);
        let associated = &evidence.tables[0].methods[0];
        assert_eq!(associated.slot_index, 0);
        assert_eq!(associated.declared_virtual_slot_index, 0);
        assert_eq!(associated.linkage_name, "_ZN9Unrelated6methodEv");
        assert_eq!(associated.layout_name, "different_source_record");
        let json = serde_json::to_value(associated).unwrap();
        assert_eq!(json["method_address"], "0x1000");
        assert_eq!(json["verification"], "native_checked_source_evidence");
        if header == HeaderClassification::UnverifiedPrefix {
            assert_eq!(evidence.tables[0].raw.offset_to_top, None);
        }
    }
}

#[test]
fn misleading_names_interior_targets_and_wrong_indices_do_not_associate() {
    for (target, declared_index, entries) in [
        (0x1001, 0, BTreeSet::from([0x1000])),
        (0x1000, 1, BTreeSet::from([0x1000])),
        (0x1000, 0, BTreeSet::from([0x0ff0])),
    ] {
        let mut source = method(declared_index, 0x1000);
        source.layout_name = "MisleadingDisplayName".to_owned();
        source.linkage_name = "MisleadingDisplayName".to_owned();
        let raw = table(HeaderClassification::UnverifiedPrefix, &[target]);
        let before = serde_json::to_value(&raw).unwrap();
        let evidence = correlate(recovery(vec![raw]), &[source], &entries).unwrap();
        assert!(evidence.tables[0].methods.is_empty());
        assert!(!evidence.warnings.is_empty());
        assert_eq!(serde_json::to_value(&evidence.tables[0].raw).unwrap(), before);
    }
}

#[test]
fn duplicate_targets_and_independent_identity_ambiguities_block_association() {
    for duplicate in 0..4 {
        let first = method(0, 0x1000);
        let mut second = method(1, 0x1008);
        match duplicate {
            0 => second.method_address = first.method_address,
            1 => second.definition_id = first.definition_id,
            2 => second.declaration_id = first.declaration_id,
            _ => second.object_pointer_id = first.object_pointer_id,
        }
        let evidence = correlate(
            recovery(vec![table(HeaderClassification::UnverifiedPrefix, &[0x1000, 0x1008])]),
            &[first, second],
            &BTreeSet::from([0x1000, 0x1008]),
        )
        .unwrap();
        assert!(evidence.tables[0].methods.is_empty());
        assert!(evidence.warnings.iter().any(|warning| warning.contains("Duplicate")));
    }
}

#[test]
fn raw_target_disagreement_and_nonfunction_slots_never_associate() {
    for case in 0..3 {
        let mut raw = table(HeaderClassification::UnverifiedPrefix, &[0x1000]);
        match case {
            0 => raw.slots[0].raw_value = 0x1001,
            1 => raw.slots[0].target = None,
            _ => raw.slots[0].classification = SlotClassification::Unresolved,
        }
        let evidence = correlate(recovery(vec![raw]), &[method(0, 0x1000)], &BTreeSet::from([0x1000])).unwrap();
        assert!(evidence.tables[0].methods.is_empty());
    }
}

#[test]
fn cumulative_association_cap_preserves_every_bounded_raw_slot() {
    let methods: Vec<_> = (0..9).map(|index| method(index, 0x1000 + 16 * index)).collect();
    let targets: Vec<_> = methods.iter().map(|method| method.method_address).collect();
    let tables = (0..MAX_TABLES).map(|_| table(HeaderClassification::UnverifiedPrefix, &targets)).collect();
    let evidence = correlate(recovery(tables), &methods, &targets.into_iter().collect()).unwrap();
    assert_eq!(evidence.tables.iter().map(|table| table.methods.len()).sum::<usize>(), MAX_ASSOCIATIONS);
    assert_eq!(evidence.tables.iter().map(|table| table.raw.slots.len()).sum::<usize>(), MAX_TABLES * 9);
    assert!(evidence.warnings.iter().any(|warning| warning.contains("count/text budget")));
    assert!(evidence.warnings.len() < 8);
}

#[test]
fn names_counts_and_cumulative_text_are_checked_before_association_clones() {
    let mut oversized = method(0, 0x1000);
    oversized.linkage_name = "x".repeat(MAX_NAME_BYTES + 1);
    assert!(validate_methods(&[oversized]).is_err());
    let too_many: Vec<_> = (0..=MAX_ASSOCIATIONS).map(|index| method(index as u64, 0x1000)).collect();
    assert!(validate_methods(&too_many).is_err());
    let methods: Vec<_> = (0..16)
        .map(|index| {
            let mut method = method(index, 0x1000);
            method.layout_name = "x".repeat(MAX_NAME_BYTES);
            method.linkage_name = "y".repeat(MAX_NAME_BYTES);
            method
        })
        .collect();
    assert!(validate_methods(&methods).is_err());

    let mut source = method(0, 0x1000);
    source.layout_name = "x".repeat(MAX_NAME_BYTES);
    source.linkage_name = "y".repeat(MAX_NAME_BYTES);
    let tables = (0..MAX_TABLES).map(|_| table(HeaderClassification::UnverifiedPrefix, &[0x1000])).collect();
    let evidence = correlate(recovery(tables), &[source], &BTreeSet::from([0x1000])).unwrap();
    assert!(evidence.tables.iter().map(|table| table.methods.len()).sum::<usize>() < MAX_TABLES);
    assert!(evidence.warnings.iter().any(|warning| warning.contains("count/text budget")));
}

#[test]
fn oversized_raw_table_or_slot_counts_are_refused_before_association() {
    let too_many_tables = (0..=MAX_TABLES).map(|_| table(HeaderClassification::UnverifiedPrefix, &[0x1000])).collect();
    let too_many_slots = table(HeaderClassification::UnverifiedPrefix, &vec![0x1000; MAX_SLOTS as usize + 1]);
    for raw in [recovery(too_many_tables), recovery(vec![too_many_slots])] {
        assert!(correlate(raw, &[method(0, 0x1000)], &BTreeSet::from([0x1000])).is_err());
    }
}

#[test]
fn ordinary_preview_without_verified_methods_does_no_scan_or_annotation_work() {
    let project = Project::new(crate::debug_layout_import::tests::binary());
    let before = serde_json::to_value(project.annotation_list()).unwrap();
    let evidence = collect_virtual_evidence(&project, &[]).unwrap();
    assert!(evidence.tables.is_empty());
    assert!(project.cached_analysis().is_none());
    assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), before);
    assert!(project.undo().unwrap().is_empty());
}

#[test]
fn collecting_nonempty_source_associations_does_not_apply_types_or_undo_edits() {
    let project = Project::new(crate::debug_layout_import::tests::binary());
    let address = project.resolve("debug_mix").unwrap();
    project.set_types(0, Some("typedef int4 analyst_record;")).unwrap();
    let before = serde_json::to_value(project.annotation_list()).unwrap();
    collect_virtual_evidence(&project, &[method(0, address)]).unwrap();
    assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), before);
    let undone = project.undo().unwrap();
    assert!(!undone.is_empty());
    assert!(project.annotation_list().types.is_empty());
    assert!(project.undo().unwrap().is_empty());
}
