use std::collections::BTreeMap;
use std::path::PathBuf;

use object::{Object, ObjectSection};
use rampage_loaders::{Binary, debug};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

#[test]
fn legacy_aggregate_pointer_fixture_remains_refused_by_scalar_import_and_preview_only_by_layout_import() {
    let source = include_str!("../../../tests/fixtures/debug.c");
    assert!(source.contains("int debug_aggregate_pointer(struct debug_pair *pair)"));
    let binary = Binary::open(fixture("debug-x64.elf")).unwrap();
    let legacy = debug::signatures(&binary).unwrap();
    assert!(!legacy.signatures.iter().any(|signature| signature.name == "debug_aggregate_pointer"));
    let report = debug::layout_signatures(&binary).unwrap();
    let signature = report
        .signatures
        .iter()
        .find(|signature| signature.original_name == "debug_aggregate_pointer")
        .unwrap_or_else(|| panic!("missing explicit layout preview: {report:?}"));
    let layout = report.layouts.iter().find(|layout| signature.dependencies.contains(&layout.id)).unwrap();
    assert_eq!(layout.original_name.as_deref(), Some("debug_pair"));
    assert_eq!(layout.byte_size, 8);
    assert_eq!(layout.producer_alignment, None);
    assert!(!layout.strictly_applicable);
    assert!(!signature.strictly_applicable);
    assert_eq!(signature.address, binary.symbol_by_name("debug_aggregate_pointer").unwrap().address);
    let extents: Vec<_> = layout.fields.iter().map(|field| (field.offset, field.byte_size)).collect();
    assert_eq!(extents, [(0, 4), (4, 4)]);
    for unsupported in ["debug_aggregate", "debug_callback", "debug_nested_pointer", "debug_extended_float"] {
        assert!(!report.signatures.iter().any(|signature| signature.original_name == unsupported), "{report:?}");
    }
}

#[test]
fn unsupported_containers_and_relocatable_addresses_do_not_supply_layouts() {
    for name in ["debug-x64.macho", "hello-x64-elf.o", "hello-x64-dyn.elf"] {
        let report = debug::layout_signatures(&Binary::open(fixture(name)).unwrap()).unwrap();
        assert!(report.layouts.is_empty(), "{name}: {report:?}");
        assert!(report.signatures.is_empty(), "{name}: {report:?}");
        assert!(!report.warnings.is_empty(), "{name}: {report:?}");
    }
}

fn generated_root() -> PathBuf {
    std::env::var_os("RAMPAGE_DEBUG_LAYOUT_FIXTURES")
        .map(PathBuf::from)
        .expect("compiled debug-layout controls required; run the owned fixture build --check wrapper")
}

fn alignment_evidence(binary: &Binary) -> BTreeMap<debug::DebugLayoutTypeId, Option<u64>> {
    let object = object::File::parse(binary.image_bytes()).unwrap();
    let dwarf = gimli::Dwarf::load(|id| -> Result<_, object::Error> {
        let section = object.section_by_name(id.name()).map(|section| section.data()).transpose()?;
        Ok(gimli::EndianSlice::new(section.unwrap_or_default(), gimli::LittleEndian))
    })
    .unwrap();
    let mut result = BTreeMap::new();
    let mut headers = dwarf.units();
    while let Some(header) = headers.next().unwrap() {
        let unit_offset = header.offset().to_debug_info_offset(&header).unwrap().0 as u64;
        let unit = dwarf.unit(header).unwrap();
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs().unwrap() {
            let id = debug::DebugLayoutTypeId {
                unit_offset,
                die_offset: entry.offset().to_debug_info_offset(&unit.header).unwrap().0 as u64,
            };
            let alignment = entry
                .attr_value(gimli::DW_AT_alignment)
                .map(|value| value.udata_value().expect("owned fixture alignment must be a constant"));
            assert!(result.insert(id, alignment).is_none());
        }
    }
    result
}

fn check_known_alignment(producer: Option<u64>, measured: u64) {
    if let Some(producer) = producer {
        assert_eq!(producer, measured);
    }
}

fn leaf_proof(leaf: &debug::DebugLayoutLeaf) -> bool {
    match leaf {
        debug::DebugLayoutLeaf::Scalar { scalar } => scalar.producer_alignment.is_some(),
        debug::DebugLayoutLeaf::Pointer { producer_alignment, pointee, .. } => {
            producer_alignment.is_some() && pointee.as_ref().is_none_or(|scalar| scalar.producer_alignment.is_some())
        }
    }
}

fn value_proof(value: &debug::DebugLayoutValue) -> bool {
    match value {
        debug::DebugLayoutValue::Void => true,
        debug::DebugLayoutValue::Leaf { leaf } => leaf_proof(leaf),
        debug::DebugLayoutValue::StructPointer { producer_alignment, .. } => producer_alignment.is_some(),
    }
}

#[test]
#[ignore = "requires centrally compiled owned DWARF fixtures through the --check wrapper"]
fn independent_compiler_constants_match_exact_flat_layouts_in_dwarf4_and_dwarf5() {
    let root = generated_root();
    let oracle: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/debug-layouts/oracle.json")).unwrap();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let binary = Binary::open(root.join(variant).join("flat.debug.elf")).unwrap();
        let object = object::File::parse(binary.image_bytes()).unwrap();
        let constants = object.section_by_name(".rampage_debug_layout").unwrap().data().unwrap();
        let (chunks, remainder) = constants.as_chunks::<8>();
        assert!(remainder.is_empty());
        let words: Vec<_> = chunks.iter().map(|bytes| u64::from_le_bytes(*bytes)).collect();
        assert_eq!(words.len(), 25);
        let report = debug::layout_signatures(&binary).unwrap();
        let evidence = alignment_evidence(&binary);
        let layout = report
            .layouts
            .iter()
            .find(|layout| layout.original_name.as_deref() == oracle["flat"]["tag"].as_str())
            .unwrap_or_else(|| panic!("missing flat layout in {variant}: {report:?}"));
        assert_eq!(layout.byte_size, oracle["flat"]["size"].as_u64().unwrap());
        assert_eq!(layout.byte_size, words[4]);
        assert_eq!(layout.producer_alignment, oracle["flat"]["alignment"].as_u64());
        assert!(layout.eligible_for_native_verification);
        assert_eq!(layout.producer_alignment, evidence[&layout.id]);
        let complete_alignment_proof =
            layout.fields.iter().all(|field| field.producer_alignment.is_some() && leaf_proof(&field.leaf));
        assert_eq!(layout.strictly_applicable, complete_alignment_proof);
        assert_eq!(layout.producer_alignment, Some(words[5]));
        let expected_fields = oracle["flat"]["fields"].as_array().unwrap();
        assert_eq!(layout.fields.len(), expected_fields.len());
        for (index, (field, expected)) in layout.fields.iter().zip(expected_fields).enumerate() {
            assert_eq!(field.original_name.as_deref(), expected["name"].as_str());
            assert_eq!(field.offset, expected["offset"].as_u64().unwrap());
            assert_eq!(field.byte_size, expected["size"].as_u64().unwrap());
            assert_eq!((field.offset, field.byte_size), (words[7 + index * 3], words[8 + index * 3]));
            let measured_alignment = words[9 + index * 3];
            assert_eq!(measured_alignment, expected["alignment"].as_u64().unwrap());
            assert_eq!(field.producer_alignment, evidence[&field.id]);
            check_known_alignment(field.producer_alignment, measured_alignment);
            match (&field.leaf, expected["kind"].as_str().unwrap()) {
                (debug::DebugLayoutLeaf::Scalar { scalar }, kind) => {
                    let (expected_kind, encoding) = match (kind, expected["ctype"].as_str().unwrap()) {
                        ("signed", "signed char") => {
                            (debug::DebugLayoutScalarKind::SignedInteger, gimli::DW_ATE_signed_char.0)
                        }
                        ("signed", _) => (debug::DebugLayoutScalarKind::SignedInteger, gimli::DW_ATE_signed.0),
                        ("unsigned", "unsigned char") => {
                            (debug::DebugLayoutScalarKind::UnsignedInteger, gimli::DW_ATE_unsigned_char.0)
                        }
                        ("unsigned", _) => (debug::DebugLayoutScalarKind::UnsignedInteger, gimli::DW_ATE_unsigned.0),
                        ("float", _) => (debug::DebugLayoutScalarKind::Float, gimli::DW_ATE_float.0),
                        _ => panic!("unexpected scalar oracle kind {kind}"),
                    };
                    assert_eq!((scalar.kind, scalar.encoding), (expected_kind, encoding));
                    assert_eq!(scalar.producer_alignment, evidence[&scalar.id]);
                    check_known_alignment(scalar.producer_alignment, measured_alignment);
                }
                (debug::DebugLayoutLeaf::Pointer { id, producer_alignment, pointee, byte_size }, "pointer") => {
                    assert_eq!(*byte_size, words[2]);
                    assert_eq!(*producer_alignment, evidence[id]);
                    check_known_alignment(*producer_alignment, measured_alignment);
                    let scalar = pointee.as_ref().expect("int pointer must preserve its exact scalar pointee");
                    assert_eq!(
                        (scalar.kind, scalar.encoding, scalar.byte_size),
                        (debug::DebugLayoutScalarKind::SignedInteger, gimli::DW_ATE_signed.0, 4)
                    );
                    assert_eq!(scalar.producer_alignment, evidence[&scalar.id]);
                    check_known_alignment(scalar.producer_alignment, words[12]);
                }
                _ => panic!("producer leaf disagrees with the independent source oracle"),
            }
        }
        for expected in oracle["flat"]["functions"].as_array().unwrap() {
            let name = expected["symbol"].as_str().unwrap();
            let signature = report
                .signatures
                .iter()
                .find(|signature| signature.original_name == name)
                .unwrap_or_else(|| panic!("missing {name} in {variant}: {report:?}"));
            assert_eq!(signature.address, binary.symbol_by_name(name).unwrap().address);
            assert_eq!(signature.dependencies, [layout.id]);
            assert!(signature.eligible_for_native_verification);
            assert_eq!(
                signature.strictly_applicable,
                layout.strictly_applicable
                    && value_proof(&signature.return_type)
                    && signature.parameters.iter().all(|parameter| value_proof(&parameter.ty))
            );
            for parameter in &signature.parameters {
                if let debug::DebugLayoutValue::StructPointer { pointer_id, producer_alignment, .. } = &parameter.ty {
                    assert_eq!(*producer_alignment, evidence[pointer_id]);
                    check_known_alignment(*producer_alignment, words[21]);
                }
            }
        }
        let symbols_only = Binary::open(root.join(variant).join("flat.symbols.elf")).unwrap();
        let empty = debug::layout_signatures(&symbols_only).unwrap();
        assert!(empty.layouts.is_empty());
        assert!(empty.signatures.is_empty());
    }
}

#[test]
#[ignore = "requires centrally compiled owned DWARF fixtures through the --check wrapper"]
fn independent_duplicate_cu_names_and_sanitization_collisions_remain_refused() {
    let root = generated_root();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        for group in ["identity-compatible", "identity-incompatible", "collisions"] {
            let binary = Binary::open(root.join(variant).join(format!("{group}.debug.elf"))).unwrap();
            let report = debug::layout_signatures(&binary).unwrap();
            assert!(report.signatures.is_empty(), "{variant}/{group}: {report:?}");
            assert!(report.layouts.is_empty(), "{variant}/{group}: {report:?}");
            assert!(
                report.warnings.iter().any(|warning| warning.contains("distinct DIE identities")),
                "{variant}/{group}: {report:?}"
            );
        }
    }
}

#[test]
#[ignore = "requires centrally compiled owned DWARF fixtures through the --check wrapper"]
fn independent_refusal_controls_do_not_become_strictly_applicable() {
    let root = generated_root();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let binary = Binary::open(root.join(variant).join("refusals.debug.elf")).unwrap();
        let report = debug::layout_signatures(&binary).unwrap();
        let missing = report
            .signatures
            .iter()
            .find(|signature| signature.original_name == "debug_missing_alignment_read")
            .unwrap_or_else(|| panic!("missing unknown-alignment preview in {variant}: {report:?}"));
        assert!(!missing.strictly_applicable);
        assert!(!missing.eligible_for_native_verification);
        let layout = report.layouts.iter().find(|layout| missing.dependencies.contains(&layout.id)).unwrap();
        let evidence = alignment_evidence(&binary);
        assert_eq!(evidence[&layout.id], None, "negative must actually lack DW_AT_alignment");
        assert_eq!(layout.producer_alignment, None);
        assert!(!layout.eligible_for_native_verification);
        for name in [
            "debug_packed_read",
            "debug_overaligned_read",
            "debug_union_read",
            "debug_bitfields_read",
            "debug_nested_read",
            "debug_recursive_read",
            "debug_array_read",
            "debug_flexible_read",
            "debug_unknown_pointer",
            "debug_by_value_argument",
            "debug_by_value_return",
        ] {
            assert!(
                !report.signatures.iter().any(|signature| signature.original_name == name),
                "{variant}/{name}: {report:?}"
            );
        }
        let inheritance = root.join(variant).join("inheritance.debug.elf");
        if std::env::var_os("DEBUG_LAYOUT_CPP").is_some_and(|value| value == "1") {
            assert!(inheritance.is_file(), "required C++ refusal fixture missing: {}", inheritance.display());
        }
        if inheritance.exists() {
            let report = debug::layout_signatures(&Binary::open(inheritance).unwrap()).unwrap();
            assert!(report.layouts.is_empty(), "{variant}/inheritance: {report:?}");
            assert!(report.signatures.is_empty(), "{variant}/inheritance: {report:?}");
        }
    }
}
