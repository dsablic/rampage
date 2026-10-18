use super::*;
use rampage_loaders::debug_types::*;

fn ty(id: &str, size: Option<u64>, kind: DebugTypeKind) -> DebugType {
    DebugType {
        id: id.to_owned(),
        original_name: Some(id.to_owned()),
        emitted_name: None,
        byte_size: size,
        alignment: None,
        kind,
        origin: DebugTypeOrigin { source: DebugSourceKind::Dwarf, unit: Some("unit:1".into()), index: 1 },
        unsupported: Vec::new(),
    }
}

fn report(types: Vec<DebugType>) -> DebugTypeReport {
    DebugTypeReport {
        types,
        signatures: Vec::new(),
        provenance: DebugTypeProvenance {
            source: DebugSourceKind::Dwarf,
            source_sha256: "a".repeat(64),
            pdb_guid: None,
            pdb_age: None,
        },
        warnings: Vec::new(),
        limits: DebugTypeLimits::default(),
    }
}

fn member(name: &str, id: &str, offset: u64) -> DebugMember {
    DebugMember {
        name: Some(name.into()),
        type_id: id.into(),
        byte_offset: offset,
        bitfield: None,
        unsupported: Vec::new(),
    }
}

fn int() -> DebugType {
    ty("I32", Some(4), DebugTypeKind::Scalar { encoding: DebugScalarEncoding::Signed, c_name: None })
}

#[test]
fn bitfield_record_and_its_dependents_are_not_rendered_as_truncated_structs() {
    let mut bits = member("value", "I32", 0);
    bits.bitfield = Some(DebugBitfield { bit_size: 3, bit_offset: 0 });
    let facts = report(vec![
        int(),
        ty("Bits", Some(4), DebugTypeKind::Struct { members: vec![bits] }),
        ty("Outer", Some(4), DebugTypeKind::Struct { members: vec![member("bits", "Bits", 0)] }),
        ty("Independent", Some(4), DebugTypeKind::Struct { members: vec![member("value", "I32", 0)] }),
    ]);
    let plan = graph::prepare(&facts).unwrap();
    assert_eq!(plan.names, ["Independent"]);
    assert!(!plan.declarations.contains("struct Bits"));
    assert!(plan.reasons["Bits"].iter().any(|reason| reason.contains("bitfield")));
    assert!(matches!(&facts.types[1].kind, DebugTypeKind::Struct { members }
        if members.len() == 1 && members[0].bitfield.is_some()));
}

#[test]
fn by_value_cycles_are_refused_but_self_pointer_and_callback_cycles_have_complete_declarations() {
    let direct =
        report(vec![ty("Cycle", Some(8), DebugTypeKind::Struct { members: vec![member("again", "Cycle", 0)] })]);
    let refused = graph::prepare(&direct).unwrap();
    assert!(refused.names.is_empty());
    assert!(refused.reasons["Cycle"].iter().any(|reason| reason.contains("cycle")));

    let recursive = report(vec![
        int(),
        ty(
            "Record",
            Some(16),
            DebugTypeKind::Struct { members: vec![member("next", "PRecord", 0), member("callback", "PCallback", 8)] },
        ),
        ty("PRecord", Some(8), DebugTypeKind::Pointer { target: "Record".into() }),
        ty(
            "Callback",
            None,
            DebugTypeKind::Function {
                convention: "normal".into(),
                parameters: vec!["PRecord".into()],
                return_type: "I32".into(),
                variadic: false,
            },
        ),
        ty("PCallback", Some(8), DebugTypeKind::Pointer { target: "Callback".into() }),
    ]);
    let plan = graph::prepare(&recursive).unwrap();
    let forward = plan.declarations.find("struct Record;").unwrap();
    let callback = plan.declarations.find("typedef int4 Callback").unwrap();
    let complete = plan.declarations.find("struct Record {").unwrap();
    assert!(forward < callback && callback < complete);
    assert!(plan.declarations.contains("Callback *callback"));
    assert!(plan.declarations.contains("struct Record *next"));
}

#[test]
fn source_identity_is_not_joined_by_display_name_and_missing_dependencies_stay_preview_only() {
    let mut left = ty("source:left", Some(4), DebugTypeKind::Struct { members: vec![member("v", "I32", 0)] });
    left.original_name = Some("SameName".into());
    let mut right = left.clone();
    right.id = "source:right".into();
    assert!(graph::prepare(&report(vec![int(), left, right])).is_err());
    let missing = report(vec![ty(
        "Missing",
        Some(4),
        DebugTypeKind::Struct { members: vec![member("v", "not-in-this-source", 0)] },
    )]);
    let plan = graph::prepare(&missing).unwrap();
    assert!(plan.names.is_empty());
    assert!(
        plan.reasons["Missing"]
            .iter()
            .any(|reason| { reason.contains("missing producer dependency") && reason.contains("not-in-this-source") }),
        "the refusal must identify the absent producer source ID: {:?}",
        plan.reasons["Missing"]
    );
}

#[test]
fn array_stride_is_checked_without_promoting_implicit_stride_or_unknown_alignment_to_producer_facts() {
    let facts = report(vec![
        int(),
        ty("Array", Some(12), DebugTypeKind::Array { element: "I32".into(), count: Some(3), stride: None }),
        ty("Record", Some(12), DebugTypeKind::Struct { members: vec![member("values", "Array", 0)] }),
    ]);
    let plan = graph::prepare(&facts).unwrap();
    assert!(plan.declarations.contains("int4 values[3]"));
    assert!(facts.types.iter().all(|ty| ty.alignment.is_none()));
    assert!(matches!(&facts.types[1].kind, DebugTypeKind::Array { stride: None, .. }));
    let mut invalid = facts;
    invalid.types[1].kind = DebugTypeKind::Array { element: "I32".into(), count: Some(3), stride: Some(8) };
    let plan = graph::prepare(&invalid).unwrap();
    assert!(!plan.names.contains(&"Record".to_owned()));
}

#[test]
fn aggregate_by_value_callbacks_do_not_gain_abi_approval_from_a_successful_declaration_render() {
    let facts = report(vec![
        int(),
        ty("Record", Some(4), DebugTypeKind::Struct { members: vec![member("v", "I32", 0)] }),
        ty(
            "Callback",
            None,
            DebugTypeKind::Function {
                convention: "normal".into(),
                parameters: vec!["Record".into()],
                return_type: "I32".into(),
                variadic: false,
            },
        ),
    ]);
    let plan = graph::prepare(&facts).unwrap();
    assert!(!plan.accepted.contains("Callback"));
    assert!(graph::signature(&facts, &plan, "Callback").is_err());
    assert!(plan.names.contains(&"Record".to_owned()));
}

#[test]
fn enum_values_must_fit_resolved_producer_signedness_width_and_native_literal_range() {
    for (encoding, width, value, enum_size, admitted) in [
        (DebugScalarEncoding::Unsigned, 1, "-1", 1, false),
        (DebugScalarEncoding::Unsigned, 1, "256", 1, false),
        (DebugScalarEncoding::Unsigned, 1, "255", 1, true),
        (DebugScalarEncoding::Signed, 1, "-129", 1, false),
        (DebugScalarEncoding::Signed, 1, "128", 1, false),
        (DebugScalarEncoding::Signed, 1, "-128", 1, true),
        (DebugScalarEncoding::Unsigned, 1, "1", 2, false),
        (DebugScalarEncoding::Unsigned, 8, "18446744073709551615", 8, false),
    ] {
        let facts = report(vec![
            ty("Integer", Some(width), DebugTypeKind::Scalar { encoding, c_name: None }),
            ty(
                "Underlying",
                None,
                DebugTypeKind::Typedef { target: "Integer".into(), constant: false, volatile: false },
            ),
            ty(
                "Enumeration",
                Some(enum_size),
                DebugTypeKind::Enum {
                    underlying: "Underlying".into(),
                    values: vec![DebugEnumerator { name: "Value".into(), value: value.into() }],
                },
            ),
            ty(
                "Dependent",
                Some(enum_size),
                DebugTypeKind::Struct { members: vec![member("value", "Enumeration", 0)] },
            ),
        ]);
        let plan = graph::prepare(&facts).unwrap();
        assert_eq!(plan.accepted.contains("Enumeration"), admitted, "{encoding:?}/{width}/{value}/{enum_size}");
        assert_eq!(plan.accepted.contains("Dependent"), admitted, "dependent of {value}");
        if !admitted {
            assert!(!plan.declarations.contains("enum Enumeration"));
            assert!(!plan.reasons["Enumeration"].is_empty());
        }
    }
}

#[test]
fn consumer_rechecks_struct_storage_overlap_and_bounds_without_rejecting_union_overlap() {
    let facts = report(vec![
        int(),
        ty(
            "Overlap",
            Some(8),
            DebugTypeKind::Struct { members: vec![member("left", "I32", 0), member("right", "I32", 2)] },
        ),
        ty("Outside", Some(4), DebugTypeKind::Struct { members: vec![member("value", "I32", 2)] }),
        ty(
            "Adjacent",
            Some(8),
            DebugTypeKind::Struct { members: vec![member("left", "I32", 0), member("right", "I32", 4)] },
        ),
        ty(
            "Alternatives",
            Some(4),
            DebugTypeKind::Union { members: vec![member("left", "I32", 0), member("right", "I32", 0)] },
        ),
    ]);
    let plan = graph::prepare(&facts).unwrap();
    assert!(!plan.accepted.contains("Overlap"));
    assert!(!plan.accepted.contains("Outside"));
    assert!(plan.accepted.contains("Adjacent"));
    assert!(plan.accepted.contains("Alternatives"));
    assert!(plan.reasons["Overlap"].iter().any(|reason| reason.contains("overlaps")));
}

#[test]
fn known_codeview_near_conventions_have_explicit_spelling_mappings_but_unknown_conventions_do_not() {
    for (source, expected) in [("near_c", "__cdecl"), ("near_stdcall", "__stdcall"), ("near_fastcall", "__fastcall")] {
        let facts = report(vec![
            int(),
            ty(
                "Callback",
                None,
                DebugTypeKind::Function {
                    convention: source.into(),
                    parameters: vec!["I32".into()],
                    return_type: "I32".into(),
                    variadic: false,
                },
            ),
        ]);
        let plan = graph::prepare(&facts).unwrap();
        assert!(plan.declarations.contains(expected), "{source}");
    }
    let facts = report(vec![
        int(),
        ty(
            "Callback",
            None,
            DebugTypeKind::Function {
                convention: "unrecognized_codeview_model".into(),
                parameters: vec!["I32".into()],
                return_type: "I32".into(),
                variadic: false,
            },
        ),
    ]);
    let plan = graph::prepare(&facts).unwrap();
    assert!(!plan.accepted.contains("Callback"));
}

#[test]
fn standalone_bitfield_facts_remain_explicit_and_never_become_an_ordinary_alias() {
    let facts = report(vec![
        int(),
        ty("FieldBits", Some(4), DebugTypeKind::Bitfield { target: "I32".into(), bit_size: 3, bit_offset: 5 }),
        ty("Record", Some(4), DebugTypeKind::Struct { members: vec![member("bits", "FieldBits", 0)] }),
    ]);
    let plan = graph::prepare(&facts).unwrap();
    assert!(!plan.accepted.contains("FieldBits"));
    assert!(!plan.accepted.contains("Record"));
    assert!(!plan.declarations.contains("FieldBits"));
    let retained = serde_json::to_value(&facts.types[1]).unwrap();
    assert_eq!(retained["kind"]["kind"], "bitfield");
    assert_eq!(retained["kind"]["bit_size"], 3);
    assert_eq!(retained["kind"]["bit_offset"], 5);
    assert_eq!(retained["kind"]["target"], "I32");
}

#[test]
fn rendered_callback_graph_is_measured_by_the_selected_native_model_before_it_is_approved() {
    use rampage_arch::Arch;
    use rampage_decompiler::{Decompiler, DecompilerOptions, MemoryRegion, Platform};

    fn engine(arch: Arch, platform: Platform) -> Decompiler {
        Decompiler::open_with_options(
            arch,
            false,
            &[MemoryRegion {
                base: 0x1000,
                bytes: &[0; 4],
                size: 4,
                readable: true,
                writable: false,
                executable: true,
            }],
            &DecompilerOptions { platform, ..Default::default() },
        )
        .unwrap()
    }

    for (arch, platform, source_model, pointer_size) in [
        (Arch::X86_64, Platform::Default, "normal", 8),
        (Arch::X86_64, Platform::Windows, "normal", 8),
        (Arch::Aarch64, Platform::Default, "normal", 8),
        (Arch::X86, Platform::Windows, "near_c", 4),
        (Arch::X86, Platform::Windows, "near_stdcall", 4),
        (Arch::X86, Platform::Windows, "near_fastcall", 4),
    ] {
        let mut probe_engine = engine(arch, platform);
        let measured_probe =
            probe_engine.parse_type_library("typedef int4 (*IndependentDefaultProbe)(void);", None).unwrap();
        let default_model = measured_probe[0].callback.as_ref().unwrap().calling_convention.as_ref().unwrap();
        let facts = report(vec![
            int(),
            ty(
                "Record",
                Some(pointer_size * 2),
                DebugTypeKind::Struct {
                    members: vec![member("next", "PRecord", 0), member("callback", "PCallback", pointer_size)],
                },
            ),
            ty("PRecord", Some(pointer_size), DebugTypeKind::Pointer { target: "Record".into() }),
            ty(
                "Callback",
                None,
                DebugTypeKind::Function {
                    convention: source_model.into(),
                    parameters: vec!["PRecord".into()],
                    return_type: "I32".into(),
                    variadic: false,
                },
            ),
            ty("PCallback", Some(pointer_size), DebugTypeKind::Pointer { target: "Callback".into() }),
        ]);
        let plan = graph::prepare(&facts).unwrap();
        let mut native = engine(arch, platform);
        let actual = native
            .parse_type_library(&plan.declarations, None)
            .unwrap_or_else(|error| panic!("{arch}/{platform:?}/{source_model}: {error}\n{}", plan.declarations));
        graph::compare(&facts, &plan, &actual, default_model)
            .unwrap_or_else(|error| panic!("{arch}/{platform:?}/{source_model}: {error}\n{actual:#?}"));
        let callback = actual.iter().find(|ty| ty.name == "Callback").unwrap();
        let observed = callback.callback.as_ref().unwrap().calling_convention.as_deref().unwrap();
        if source_model == "normal" {
            assert_eq!(observed, default_model);
            assert!(!plan.declarations.contains("__cdecl"));
            assert!(!plan.declarations.contains("__stdcall"));
            assert!(!plan.declarations.contains("__fastcall"));
        }
        let wrong_model = format!("{observed}_not_the_selected_default");
        if source_model == "normal" {
            assert!(graph::compare(&facts, &plan, &actual, &wrong_model).is_err());
        }
        let expected = actual.iter().find(|ty| ty.name == "Record").unwrap();
        assert_eq!(expected.fields[1].name, "callback");
        assert_eq!(expected.fields[1].offset, pointer_size);
    }
}

#[test]
fn signed_enum_native_wire_values_are_compared_at_the_resolved_producer_width() {
    use rampage_arch::Arch;
    use rampage_decompiler::{Decompiler, DecompilerOptions, MemoryRegion, Platform};

    let facts = report(vec![
        int(),
        ty(
            "Enumeration",
            Some(4),
            DebugTypeKind::Enum {
                underlying: "I32".into(),
                values: vec![
                    DebugEnumerator { name: "Negative".into(), value: "-3".into() },
                    DebugEnumerator { name: "Positive".into(), value: "7".into() },
                ],
            },
        ),
    ]);
    let plan = graph::prepare(&facts).unwrap();
    for (arch, platform) in
        [(Arch::X86_64, Platform::Default), (Arch::X86_64, Platform::Windows), (Arch::Aarch64, Platform::Default)]
    {
        let mut engine = Decompiler::open_with_options(
            arch,
            false,
            &[MemoryRegion {
                base: 0x1000,
                bytes: &[0; 4],
                size: 4,
                readable: true,
                writable: false,
                executable: true,
            }],
            &DecompilerOptions { platform, ..Default::default() },
        )
        .unwrap();
        let probe = engine.parse_type_library("typedef int4 (*DefaultProbe)(void);", None).unwrap();
        let default_model = probe[0].callback.as_ref().unwrap().calling_convention.as_ref().unwrap();
        let native = engine.parse_type_library(&plan.declarations, None).unwrap();
        assert_eq!(native[0].enum_values.iter().find(|value| value.name == "Negative").unwrap().value, "-3");
        graph::compare(&facts, &plan, &native, default_model).unwrap();
        let mut carrier = native.clone();
        let negative = carrier[0].identity.as_mut().unwrap()["enum_values"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["name"] == "Negative")
            .unwrap();
        negative["value"] = serde_json::json!("18446744073709551613");
        graph::compare(&facts, &plan, &carrier, default_model).unwrap();
        let mut wrong_bits = native.clone();
        let negative = wrong_bits[0].identity.as_mut().unwrap()["enum_values"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["name"] == "Negative")
            .unwrap();
        negative["value"] = serde_json::json!("4294967294");
        assert!(graph::compare(&facts, &plan, &wrong_bits, default_model).is_err());
        let mut contradictory_source = facts.clone();
        contradictory_source.types[0].kind =
            DebugTypeKind::Scalar { encoding: DebugScalarEncoding::Unsigned, c_name: None };
        assert!(!graph::prepare(&contradictory_source).unwrap().accepted.contains("Enumeration"));
    }
}

#[test]
fn explicit_scalar_alignment_never_borrows_indirect_record_or_typedef_alignment_as_its_proof() {
    for alignment in [4, 8] {
        let mut scalar = int();
        scalar.alignment = Some(alignment);
        let facts = report(vec![
            scalar,
            ty("Alias", Some(4), DebugTypeKind::Typedef { target: "I32".into(), constant: false, volatile: false }),
            ty("Record", Some(4), DebugTypeKind::Struct { members: vec![member("value", "Alias", 0)] }),
        ]);
        let plan = graph::prepare(&facts).unwrap();
        assert!(plan.names.is_empty());
        assert!(!plan.accepted.contains("I32"));
        assert!(plan.reasons["I32"].iter().any(|reason| reason.contains("core-type measurement")));
        assert_eq!(facts.types[0].alignment, Some(alignment));
    }
}

#[test]
fn qualified_pointer_layers_and_their_dependents_remain_preview_only_without_native_qualifier_identity() {
    for (constant, volatile) in [(true, false), (false, true)] {
        let facts = report(vec![
            int(),
            ty("Pointer", Some(8), DebugTypeKind::Pointer { target: "I32".into() }),
            ty("QualifiedPointer", Some(8), DebugTypeKind::Typedef { target: "Pointer".into(), constant, volatile }),
            ty(
                "QualifiedRecord",
                Some(8),
                DebugTypeKind::Struct { members: vec![member("value", "QualifiedPointer", 0)] },
            ),
            ty("PlainRecord", Some(8), DebugTypeKind::Struct { members: vec![member("value", "Pointer", 0)] }),
        ]);
        let plan = graph::prepare(&facts).unwrap();
        assert!(!plan.accepted.contains("QualifiedPointer"));
        assert!(!plan.accepted.contains("QualifiedRecord"));
        assert!(plan.accepted.contains("PlainRecord"));
        assert!(!plan.declarations.contains("QualifiedPointer"));
        assert!(plan.reasons["QualifiedPointer"].iter().any(|reason| reason.contains("qualifier identity")));
    }
}

#[test]
fn producer_sha_origin_source_and_pdb_identity_shapes_are_cross_bound_without_sidecar_reads() {
    let mut facts = report(vec![int()]);
    validate_provenance(&facts, &"a".repeat(64)).unwrap();
    assert!(validate_provenance(&facts, &"b".repeat(64)).is_err());
    facts.types[0].origin.source = DebugSourceKind::Pdb;
    assert!(validate_provenance(&facts, &"a".repeat(64)).is_err());
    facts.provenance.source = DebugSourceKind::Pdb;
    facts.provenance.pdb_guid = Some("c".repeat(32));
    facts.provenance.pdb_age = Some(1);
    validate_provenance(&facts, &"b".repeat(64)).unwrap();
    facts.provenance.pdb_age = Some(0);
    assert!(validate_provenance(&facts, &"b".repeat(64)).is_err());
    facts.provenance.pdb_age = Some(1);
    facts.provenance.pdb_guid = Some("g".repeat(32));
    assert!(validate_provenance(&facts, &"b".repeat(64)).is_err());
    facts.provenance.pdb_guid = Some("c".repeat(32));
    facts.provenance.source_sha256 = "a".repeat(63);
    assert!(validate_provenance(&facts, &"b".repeat(64)).is_err());
}

fn measured_manifest() -> DebugTypesManifest {
    use rampage_decompiler::{Decompiler, DecompilerOptions, MemoryRegion};
    let mut engine = Decompiler::open_with_options(
        rampage_arch::Arch::X86_64,
        false,
        &[MemoryRegion { base: 0x1000, bytes: &[0; 4], size: 4, readable: true, writable: false, executable: true }],
        &DecompilerOptions::default(),
    )
    .unwrap();
    let probe = engine.parse_type_library("typedef int4 (*DefaultProbe)(void);", None).unwrap();
    let default_model = probe[0].callback.as_ref().unwrap().calling_convention.clone().unwrap();
    let mut facts = report(vec![
        int(),
        ty(
            "Record",
            Some(16),
            DebugTypeKind::Struct { members: vec![member("next", "PRecord", 0), member("callback", "PCallback", 8)] },
        ),
        ty("PRecord", Some(8), DebugTypeKind::Pointer { target: "Record".into() }),
        ty(
            "Callback",
            None,
            DebugTypeKind::Function {
                convention: "normal".into(),
                parameters: vec!["PRecord".into()],
                return_type: "I32".into(),
                variadic: false,
            },
        ),
        ty("PCallback", Some(8), DebugTypeKind::Pointer { target: "Callback".into() }),
    ]);
    facts.signatures.push(DebugSignature {
        address: 0x1000,
        name: Some("example".into()),
        type_id: "Callback".into(),
        origin: facts.types[3].origin.clone(),
        unsupported: Vec::new(),
    });
    let plan = graph::prepare(&facts).unwrap();
    let actual = engine.parse_type_library(&plan.declarations, None).unwrap();
    graph::compare(&facts, &plan, &actual, &default_model).unwrap();
    let signature = graph::signature(&facts, &plan, "Callback").unwrap();
    let mut manifest = DebugTypesManifest {
        id: String::new(),
        review_sha256: String::new(),
        image_sha256: facts.provenance.source_sha256.clone(),
        specification_sha256: "b".repeat(64),
        options: option_identity(&DecompilerOptions::default()),
        language_id: engine.language_id().to_owned(),
        organization: engine.data_organization(),
        default_calling_convention: default_model,
        producer: serde_json::to_value(&facts).unwrap(),
        library_names: plan.names,
        declarations_sha256: digest(plan.declarations.as_bytes()),
        declarations: plan.declarations,
        expected_native_named_types: actual,
        signatures: vec![DebugTypesSignature {
            address: 0x1000,
            declaration: signature,
            producer_type_id: "Callback".into(),
        }],
    };
    manifest.id = manifest_identity(&manifest).unwrap();
    manifest.review_sha256 = "c".repeat(64);
    manifest
}

#[test]
fn nested_proof_facts_are_framed_without_relaxing_the_annotation_envelope_depth_budget() {
    let manifest = measured_manifest();
    check_manifest(&manifest).unwrap();
    let mut raw = serde_json::to_value(Proofs { version: 1, imports: vec![manifest.clone()] }).unwrap();
    raw["imports"][0]["producer"] = manifest.producer.clone();
    raw["imports"][0]["expected_native_named_types"] =
        serde_json::to_value(&manifest.expected_native_named_types).unwrap();
    assert!(crate::annotations::encode_debug_types(&raw).is_err(), "the existing depth-8 boundary must stay enforced");
    let encoded = proof_value(vec![manifest.clone()]).unwrap().unwrap();
    crate::annotations::parse_debug_types(&encoded).unwrap();
    let retained: Proofs = serde_json::from_str(&encoded).unwrap();
    assert_eq!(retained.imports[0].producer, manifest.producer);
    assert_eq!(retained.imports[0].expected_native_named_types, manifest.expected_native_named_types);
    check_manifest(&retained.imports[0]).unwrap();
    let mut nul = manifest.clone();
    nul.producer["warnings"] = serde_json::json!(["forbidden\u{0}text"]);
    assert!(proof_value(vec![nul]).unwrap_err().to_string().contains("NUL"));
    let mut deep = manifest;
    let mut nested = serde_json::json!(0);
    for _ in 0..49 {
        nested = serde_json::json!({"child": nested});
    }
    deep.producer = nested;
    assert!(proof_value(vec![deep]).unwrap_err().to_string().contains("depth/node"));
}

#[test]
fn rehashed_manifests_cannot_seal_producer_addresses_that_original_admission_suppressed_as_duplicates() {
    let mut manifest = measured_manifest();
    let mut producer: DebugTypeReport = serde_json::from_value(manifest.producer.clone()).unwrap();
    producer.signatures.push(producer.signatures[0].clone());
    manifest.producer = serde_json::to_value(producer).unwrap();
    manifest.id = manifest_identity(&manifest).unwrap();
    assert!(check_manifest(&manifest).is_err());
}

#[test]
fn owned_selected_pe_identity_and_entry_witnesses_are_rechecked_without_initializing_global_analysis() {
    let Some(root) = std::env::var_os("RAMPAGE_DEBUG_TYPE_FIXTURES") else { return };
    let binary = rampage_loaders::Binary::open(std::path::PathBuf::from(root).join("debug-types-cpp.exe")).unwrap();
    let identity = rampage_loaders::pdb::selected_image_identity(&binary).unwrap();
    let mut facts = report(Vec::new());
    facts.provenance.source = DebugSourceKind::Pdb;
    facts.provenance.pdb_guid = Some(rampage_arch::hex::bytes(&identity.guid));
    facts.provenance.pdb_age = Some(identity.age);
    validate_selected_pdb_identity(&binary, &facts).unwrap();
    facts.provenance.pdb_age = identity.age.checked_add(1);
    assert!(validate_selected_pdb_identity(&binary, &facts).is_err());
    let project = Project::new(binary);
    assert!(!project.analysis_cache_status().program);
    let witnesses = signature_entry_witnesses(&project).unwrap();
    let entry = witnesses.iter().copied().find(|address| project.binary.is_code(*address)).unwrap();
    validate_signature_entry(&project, entry, &witnesses).unwrap();
    let interior = (1..64)
        .filter_map(|offset| entry.checked_add(offset))
        .find(|address| {
            !witnesses.contains(address)
                && project.binary.is_code(*address)
                && project.binary.read(*address, 1).is_some()
        })
        .unwrap();
    assert!(validate_signature_entry(&project, interior, &witnesses).is_err());
    assert!(!project.analysis_cache_status().program);
}

#[test]
fn colliding_forward_alias_names_require_an_exact_source_id_edge_and_keep_both_native_identities() {
    use rampage_decompiler::{Decompiler, DecompilerOptions, MemoryRegion};
    let measured = measured_manifest();
    let mut facts: DebugTypeReport = serde_json::from_value(measured.producer).unwrap();
    let mut forward =
        ty("Forward", Some(16), DebugTypeKind::Typedef { target: "Record".into(), constant: false, volatile: false });
    forward.original_name = Some("Record".into());
    facts.types.insert(0, forward);
    let plan = graph::prepare(&facts).unwrap();
    assert_eq!(plan.emitted["Record"], "Record");
    assert_ne!(plan.emitted["Forward"], plan.emitted["Record"]);
    assert!(plan.emitted["Forward"].starts_with("debug_alias_"));
    assert!(plan.accepted.contains("Forward"));
    let mut engine = Decompiler::open_with_options(
        rampage_arch::Arch::X86_64,
        false,
        &[MemoryRegion { base: 0x1000, bytes: &[0; 4], size: 4, readable: true, writable: false, executable: true }],
        &DecompilerOptions::default(),
    )
    .unwrap();
    let native = engine.parse_type_library(&plan.declarations, None).unwrap();
    graph::compare(&facts, &plan, &native, &measured.default_calling_convention).unwrap();
    let alias = native.iter().find(|ty| ty.name == plan.emitted["Forward"]).unwrap();
    assert_eq!(alias.target.as_deref(), Some("Record"));
    let alias_index = facts.types.iter().position(|ty| ty.id == "Forward").unwrap();
    facts.types[alias_index].byte_size = Some(4);
    facts.types[alias_index].kind =
        DebugTypeKind::Typedef { target: "OtherRecord".into(), constant: false, volatile: false };
    facts.types.push(ty("OtherRecord", Some(4), DebugTypeKind::Struct { members: vec![member("value", "I32", 0)] }));
    assert!(graph::prepare(&facts).is_err(), "same display name must not join unrelated source-ID anchors");
}

#[test]
fn unsupported_raw_record_evidence_exposes_member_bit_facts_without_inventing_missing_offsets() {
    let raw = serde_json::json!({"kind":"record", "record_kind":"struct", "members":[{
        "original_name":"flags", "emitted_name":"member_1", "ty":{"unit_offset":0,"die_offset":1},
        "byte_offset":null, "producer_alignment":null,
        "bitfield":{"bit_size":3,"data_bit_offset":13,"legacy_bit_offset":null,
            "raw_storage_byte_size":null,"underlying_type_byte_size":4,
            "native_unsupported_reason":"native bitfield unsupported"}
    }]});
    let bits = ty("Bits", Some(4), DebugTypeKind::Unsupported { description: raw.to_string() });
    let facts = report(vec![bits.clone()]);
    let plan = graph::prepare(&facts).unwrap();
    assert!(!plan.accepted.contains("Bits"));
    let evidence = producer_evidence(&bits).unwrap().unwrap();
    assert_eq!(evidence["members"][0]["bitfield"]["bit_size"], 3);
    assert_eq!(evidence["members"][0]["bitfield"]["data_bit_offset"], 13);
    assert_eq!(evidence["members"][0]["bitfield"]["underlying_type_byte_size"], 4);
    assert!(evidence["members"][0]["byte_offset"].is_null());
    assert!(evidence["members"][0]["bitfield"]["raw_storage_byte_size"].is_null());
    assert!(matches!(&facts.types[0].kind, DebugTypeKind::Unsupported { description }
        if serde_json::from_str::<Value>(description).unwrap() == raw));
}

#[test]
fn owned_discovered_only_entries_do_not_gain_import_approval_from_a_warm_analysis_cache() {
    let Some(root) = std::env::var_os("RAMPAGE_DEBUG_TYPE_FIXTURES") else { return };
    let path = std::path::PathBuf::from(root).join("debug-types-x64.elf");
    let original = rampage_loaders::Binary::open(&path).unwrap();
    let producer = rampage_loaders::debug::type_graph(&original).unwrap();
    let target = producer
        .signatures
        .iter()
        .find(|signature| signature.name.as_deref() == Some("debug_types_query"))
        .unwrap()
        .address;
    assert_ne!(original.entry, Some(target));
    let open_stripped = || {
        let mut binary = rampage_loaders::Binary::open(&path).unwrap();
        binary.symbols.retain(|symbol| symbol.address != target);
        binary.exports.retain(|export| export.address != target);
        binary.function_starts.retain(|address| *address != target);
        binary
    };
    let warm = Project::new(open_stripped());
    let cold_witnesses = signature_entry_witnesses(&warm).unwrap();
    assert!(!cold_witnesses.contains(&target));
    assert!(!warm.analysis_cache_status().program);
    assert!(warm.analysis().unwrap().program.functions.iter().any(|function| function.address == target));
    assert_eq!(signature_entry_witnesses(&warm).unwrap(), cold_witnesses);
    let mut request = DebugTypesRequest { limit: 256, ..Default::default() };
    let preview = warm.import_debug_types(&request).unwrap();
    assert!(preview.preserved_signatures > 0);
    assert!(
        preview.warnings.iter().any(|warning| warning.contains(&format!("{target:#x}"))
            && warning.contains("cold-image metadata entry witness"))
    );
    request.apply = true;
    request.review_sha256 = Some(preview.review_sha256);
    warm.import_debug_types(&request).unwrap();
    assert!(!warm.annotations().signatures().contains_key(&target));
    let snapshot = warm.annotations().snapshot();
    let name = crate::type_library::stored_declarations(&snapshot).unwrap()[0].names[0].clone();
    let reopened = Project::with_annotations(open_stripped(), snapshot);
    assert!(!reopened.analysis_cache_status().program);
    validate_replay_source(&reopened, &reopened.annotations()).unwrap();
    assert!(!reopened.analysis_cache_status().program);
    reopened.get_type(&name).unwrap();
}

#[test]
fn pdb_legacy_conventions_project_only_for_the_measured_windows_x64_unified_context() {
    use rampage_arch::Arch;
    use rampage_decompiler::{DataOrganization, Decompiler, DecompilerOptions, MemoryRegion, Platform};

    for arch in [Arch::X86_64, Arch::X86] {
        for (raw, explicit) in [("near_c", "__cdecl"), ("near_stdcall", "__stdcall"), ("near_fastcall", "__fastcall")] {
            let mut engine = Decompiler::open_with_options(
                arch,
                false,
                &[MemoryRegion {
                    base: 0x1000,
                    bytes: &[0; 4],
                    size: 4,
                    readable: true,
                    writable: false,
                    executable: true,
                }],
                &DecompilerOptions { platform: Platform::Windows, ..Default::default() },
            )
            .unwrap();
            let probe = engine.parse_type_library("typedef int4 (*DefaultProbe)(void);", None).unwrap();
            let default_model = probe[0].callback.as_ref().unwrap().calling_convention.as_ref().unwrap();
            let pointer = u64::from(engine.data_organization().pointer);
            let mut facts = report(vec![
                int(),
                ty(
                    "Record",
                    Some(pointer * 2),
                    DebugTypeKind::Struct {
                        members: vec![member("next", "PRecord", 0), member("callback", "PCallback", pointer)],
                    },
                ),
                ty("PRecord", Some(pointer), DebugTypeKind::Pointer { target: "Record".into() }),
                ty(
                    "Callback",
                    None,
                    DebugTypeKind::Function {
                        convention: raw.into(),
                        parameters: vec!["PRecord".into(), "I32".into()],
                        return_type: "PRecord".into(),
                        variadic: false,
                    },
                ),
                ty("PCallback", Some(pointer), DebugTypeKind::Pointer { target: "Callback".into() }),
            ]);
            facts.provenance.source = DebugSourceKind::Pdb;
            facts.provenance.pdb_guid = Some("a".repeat(32));
            facts.provenance.pdb_age = Some(1);
            for ty in &mut facts.types {
                ty.origin.source = DebugSourceKind::Pdb;
            }
            let plan = graph::prepare_for_target(&facts, engine.language_id(), engine.data_organization()).unwrap();
            let native = engine
                .parse_type_library(&plan.declarations, None)
                .unwrap_or_else(|error| panic!("{arch}/{raw}: {error}\n{}", plan.declarations));
            graph::compare(&facts, &plan, &native, default_model).unwrap();
            let callback_type = native.iter().find(|ty| ty.name == "Callback").unwrap();
            let callback = callback_type.callback.as_ref().unwrap();
            let observed = callback.calling_convention.as_deref().unwrap();
            let signature = &callback_type.identity.as_ref().unwrap()["typedef"];
            assert_eq!(signature["return_type"]["kind"], 9);
            assert_eq!(signature["return_type"]["size"], pointer);
            assert_eq!(signature["return_type"]["target"]["reference"], "Record");
            assert_eq!(signature["parameters"][0]["type"]["kind"], 9);
            assert_eq!(signature["parameters"][0]["type"]["size"], pointer);
            assert_eq!(signature["parameters"][0]["type"]["target"]["reference"], "Record");
            let record = native.iter().find(|ty| ty.name == "Record").unwrap();
            assert_eq!(record.fields[0].size, Some(pointer));
            if arch == Arch::X86_64 {
                assert_eq!(observed, default_model);
                assert!(!plan.declarations.contains(explicit));
            } else {
                assert_eq!(observed, explicit);
                assert!(plan.declarations.contains(&format!("typedef {explicit} struct Record *Callback(")));
                assert!(
                    graph::signature(&facts, &plan, "Callback")
                        .unwrap()
                        .starts_with(&format!("{explicit} struct Record *debug_signature("))
                );
            }
            assert!(matches!(&facts.types[3].kind, DebugTypeKind::Function { convention, .. } if convention == raw));
            let lp64 = graph::prepare_for_target(
                &facts,
                "x86:LE:64:default:gcc",
                DataOrganization { pointer: 8, int: 4, long: 8 },
            )
            .unwrap();
            assert!(lp64.declarations.contains(explicit), "non-Windows models must not inherit the unified policy");
            let mismatched_organization = graph::prepare_for_target(
                &facts,
                "x86:LE:64:default:windows",
                DataOrganization { pointer: 8, int: 4, long: 8 },
            )
            .unwrap();
            assert!(mismatched_organization.declarations.contains(explicit));
            facts.types[3].kind = DebugTypeKind::Function {
                convention: "unknown_codeview_model".into(),
                parameters: vec!["PRecord".into()],
                return_type: "PRecord".into(),
                variadic: false,
            };
            let unknown = graph::prepare_for_target(&facts, engine.language_id(), engine.data_organization()).unwrap();
            assert!(!unknown.accepted.contains("Callback"));
            assert!(!unknown.accepted.contains("Record"));
        }
    }
}
