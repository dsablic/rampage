use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use gimli::AttributeValue;
use object::{Object, ObjectSection};
use rampage_loaders::{Binary, debug};

type FixtureReader<'a> = gimli::EndianSlice<'a, gimli::LittleEndian>;

fn fixture_inputs() -> (PathBuf, serde_json::Value) {
    let root = std::env::var_os("RAMPAGE_DEBUG_CPP_LAYOUT_FIXTURES")
        .map(PathBuf::from)
        .expect("run the owned debug-cpp-layouts build.sh --check wrapper");
    let oracle = std::env::var_os("RAMPAGE_DEBUG_CPP_LAYOUT_ORACLE")
        .map(PathBuf::from)
        .expect("the compiled fixture wrapper must supply its source oracle");
    let oracle = serde_json::from_slice(&std::fs::read(oracle).unwrap()).unwrap();
    (root, oracle)
}

#[derive(Debug)]
struct Evidence {
    id: debug::DebugLayoutTypeId,
    tag: gimli::DwTag,
    parent: Option<u64>,
    children: Vec<u64>,
    target: Option<u64>,
    specification: Option<u64>,
    object_pointer: Option<u64>,
    name: Option<String>,
    linkage_name: Option<String>,
    alignment: Option<u64>,
    declaration: bool,
    artificial: bool,
}

fn reference(value: Option<AttributeValue<FixtureReader<'_>>>, unit: &gimli::Unit<FixtureReader<'_>>) -> Option<u64> {
    match value? {
        AttributeValue::UnitRef(offset) => Some(offset.to_debug_info_offset(&unit.header).unwrap().0 as u64),
        AttributeValue::DebugInfoRef(offset) => Some(offset.0 as u64),
        _ => panic!("owned method identity evidence must be a DIE reference"),
    }
}

fn evidence(binary: &Binary) -> BTreeMap<u64, Evidence> {
    let object = object::File::parse(binary.image_bytes()).unwrap();
    let dwarf = gimli::Dwarf::load(|id| -> Result<_, object::Error> {
        let bytes = object.section_by_name(id.name()).map(|section| section.data()).transpose()?.unwrap_or_default();
        Ok(gimli::EndianSlice::new(bytes, gimli::LittleEndian))
    })
    .unwrap();
    let mut result: BTreeMap<u64, Evidence> = BTreeMap::new();
    let mut headers = dwarf.units();
    while let Some(header) = headers.next().unwrap() {
        let unit_offset = header.offset().to_debug_info_offset(&header).unwrap().0 as u64;
        let unit = dwarf.unit(header).unwrap();
        let mut entries = unit.entries();
        let mut parents = Vec::new();
        while let Some(entry) = entries.next_dfs().unwrap() {
            parents.truncate(entry.depth() as usize);
            let offset = entry.offset().to_debug_info_offset(&unit.header).unwrap().0 as u64;
            let name = |attribute| {
                entry
                    .attr_value(attribute)
                    .map(|value| dwarf.attr_string(&unit, value).unwrap().to_string_lossy().into_owned())
            };
            let node = Evidence {
                id: debug::DebugLayoutTypeId { unit_offset, die_offset: offset },
                tag: entry.tag(),
                parent: parents.last().copied(),
                children: Vec::new(),
                target: reference(entry.attr_value(gimli::DW_AT_type), &unit),
                specification: reference(entry.attr_value(gimli::DW_AT_specification), &unit),
                object_pointer: reference(entry.attr_value(gimli::DW_AT_object_pointer), &unit),
                name: name(gimli::DW_AT_name),
                linkage_name: name(gimli::DW_AT_linkage_name).or_else(|| name(gimli::DW_AT_MIPS_linkage_name)),
                alignment: entry.attr_value(gimli::DW_AT_alignment).map(|value| value.udata_value().unwrap()),
                declaration: matches!(entry.attr_value(gimli::DW_AT_declaration), Some(AttributeValue::Flag(true))),
                artificial: matches!(entry.attr_value(gimli::DW_AT_artificial), Some(AttributeValue::Flag(true))),
            };
            if let Some(parent) = node.parent {
                result.get_mut(&parent).unwrap().children.push(offset);
            }
            assert!(result.insert(offset, node).is_none());
            parents.push(offset);
        }
    }
    result
}

fn alignment(producer: Option<u64>, measured: u64) {
    if let Some(producer) = producer {
        assert_eq!(producer, measured);
    }
}

fn leaf_alignment(leaf: &debug::DebugLayoutLeaf, nodes: &BTreeMap<u64, Evidence>, measured: u64) {
    match leaf {
        debug::DebugLayoutLeaf::Scalar { scalar } => {
            assert_eq!(scalar.producer_alignment, nodes[&scalar.id.die_offset].alignment);
            alignment(scalar.producer_alignment, measured);
        }
        debug::DebugLayoutLeaf::Pointer { id, producer_alignment, pointee, .. } => {
            assert_eq!(*producer_alignment, nodes[&id.die_offset].alignment);
            alignment(*producer_alignment, measured);
            if let Some(scalar) = pointee {
                assert_eq!(scalar.producer_alignment, nodes[&scalar.id.die_offset].alignment);
                alignment(scalar.producer_alignment, scalar.byte_size);
            }
        }
        debug::DebugLayoutLeaf::OpaqueVptr { .. } => {
            panic!("non-polymorphic fixtures must retain exact leaf categories")
        }
    }
}

fn first_formal(nodes: &BTreeMap<u64, Evidence>, parent: u64) -> u64 {
    nodes[&parent]
        .children
        .iter()
        .copied()
        .find(|child| nodes[child].tag == gimli::DW_TAG_formal_parameter)
        .expect("method must have a producer-described object formal")
}

#[test]
#[ignore = "requires centrally compiled C++ controls through debug-cpp-layouts/build.sh --check"]
fn compiled_methods_preserve_exact_record_declaration_and_actual_object_parameter_evidence() {
    let (root, oracle) = fixture_inputs();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let binary = Binary::open(root.join(variant).join("records.debug.elf")).unwrap();
        let object = object::File::parse(binary.image_bytes()).unwrap();
        let nodes = evidence(&binary);
        let report = debug::layout_signatures(&binary).unwrap();
        let expected_methods = oracle["groups"]["records"]["methods"].as_array().unwrap();
        assert_eq!(
            report.signatures.iter().filter(|signature| signature.method.is_some()).count(),
            expected_methods.len(),
            "{variant}: {report:?}",
        );
        for key in ["checked", "companion"] {
            let record = &oracle["records"][key];
            let constants = object.section_by_name(record["section"].as_str().unwrap()).unwrap().data().unwrap();
            let (chunks, remainder) = constants.as_chunks::<8>();
            assert!(remainder.is_empty());
            let words: Vec<_> = chunks.iter().map(|bytes| u64::from_le_bytes(*bytes)).collect();
            assert_eq!(words.len(), 25);
            let layout = report
                .layouts
                .iter()
                .find(|layout| layout.original_name.as_deref() == record["tag"].as_str())
                .unwrap_or_else(|| panic!("missing {key} in {variant}: {report:?}"));
            assert_eq!(layout.byte_size, oracle["layout"]["size"].as_u64().unwrap());
            assert_eq!(layout.byte_size, words[4]);
            assert_eq!(layout.producer_alignment, oracle["layout"]["alignment"].as_u64());
            assert_eq!(layout.producer_alignment, Some(words[5]));
            assert_eq!(layout.producer_alignment, nodes[&layout.id.die_offset].alignment);
            assert!(layout.eligible_for_native_verification);
            assert_eq!(
                nodes[&layout.id.die_offset].tag,
                if key == "checked" { gimli::DW_TAG_class_type } else { gimli::DW_TAG_structure_type },
            );
            let expected_fields = oracle["layout"]["fields"].as_array().unwrap();
            assert_eq!(layout.fields.len(), expected_fields.len());
            for (index, (field, expected)) in layout.fields.iter().zip(expected_fields).enumerate() {
                assert_eq!(field.original_name.as_deref(), expected["name"].as_str());
                assert_eq!(
                    (field.offset, field.byte_size),
                    (expected["offset"].as_u64().unwrap(), expected["size"].as_u64().unwrap()),
                );
                assert_eq!((field.offset, field.byte_size), (words[7 + index * 3], words[8 + index * 3]));
                assert_eq!(field.producer_alignment, nodes[&field.id.die_offset].alignment);
                alignment(field.producer_alignment, words[9 + index * 3]);
                leaf_alignment(&field.leaf, &nodes, words[9 + index * 3]);
                assert_eq!(nodes[&field.id.die_offset].tag, gimli::DW_TAG_member);
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
                            ("unsigned", _) => {
                                (debug::DebugLayoutScalarKind::UnsignedInteger, gimli::DW_ATE_unsigned.0)
                            }
                            ("float", _) => (debug::DebugLayoutScalarKind::Float, gimli::DW_ATE_float.0),
                            _ => panic!("unsupported independent scalar oracle kind"),
                        };
                        assert_eq!((scalar.kind, scalar.encoding), (expected_kind, encoding));
                    }
                    (debug::DebugLayoutLeaf::Pointer { pointee: Some(scalar), byte_size, .. }, "pointer") => {
                        assert_eq!(*byte_size, 8);
                        assert_eq!(
                            (scalar.kind, scalar.encoding, scalar.byte_size),
                            (debug::DebugLayoutScalarKind::SignedInteger, gimli::DW_ATE_signed.0, 4),
                        );
                    }
                    _ => panic!("producer leaf does not match the independent source oracle"),
                }
            }
        }
        let mut declarations = BTreeSet::new();
        let mut emitted = BTreeSet::new();
        for expected in expected_methods {
            let symbol = expected["symbol"].as_str().unwrap();
            let signature = report
                .signatures
                .iter()
                .find(|signature| signature.method.as_ref().is_some_and(|method| method.linkage_name == symbol))
                .unwrap_or_else(|| panic!("missing explicit-this method {symbol} in {variant}: {report:?}"));
            let method = signature.method.as_ref().unwrap();
            let definition = &nodes[&signature.id.die_offset];
            let declaration = &nodes[&method.declaration_id.die_offset];
            assert_eq!(definition.id, signature.id);
            assert_eq!(declaration.id, method.declaration_id);
            assert_eq!(nodes[&method.record_id.die_offset].id, method.record_id);
            assert_eq!(nodes[&method.object_pointer_id.die_offset].id, method.object_pointer_id);
            assert_eq!(signature.address, binary.symbol_by_name(symbol).unwrap().address);
            assert_eq!(definition.specification, Some(method.declaration_id.die_offset));
            assert_eq!(definition.object_pointer, Some(method.object_pointer_id.die_offset));
            assert_eq!(declaration.parent, Some(method.record_id.die_offset));
            assert_eq!(declaration.specification, None);
            assert!(declaration.declaration);
            assert_eq!(declaration.name.as_deref(), Some(signature.original_name.as_str()));
            assert_eq!(
                definition.linkage_name.as_ref().or(declaration.linkage_name.as_ref()),
                Some(&method.linkage_name),
            );
            assert_eq!(signature.id.unit_offset, method.declaration_id.unit_offset);
            assert_eq!(signature.id.unit_offset, method.object_pointer_id.unit_offset);
            assert_eq!(signature.id.unit_offset, method.record_id.unit_offset);
            assert!(declarations.insert(method.declaration_id));
            assert!(emitted.insert(&signature.emitted_name));
            assert_eq!(signature.dependencies, [method.record_id]);
            assert!(signature.eligible_for_native_verification);
            assert_eq!(first_formal(&nodes, signature.id.die_offset), method.object_pointer_id.die_offset);
            let declared_object = first_formal(&nodes, method.declaration_id.die_offset);
            if let Some(explicit_object) = declaration.object_pointer {
                assert_eq!(explicit_object, declared_object);
            }
            for (formal, owner) in [
                (method.object_pointer_id.die_offset, signature.id.die_offset),
                (declared_object, method.declaration_id.die_offset),
            ] {
                assert_eq!(nodes[&formal].parent, Some(owner));
                assert!(nodes[&formal].artificial);
                let pointer = &nodes[&nodes[&formal].target.unwrap()];
                assert_eq!(pointer.tag, gimli::DW_TAG_pointer_type);
                assert_eq!(pointer.target, Some(method.record_id.die_offset));
            }
            assert_eq!(signature.parameters[0].id, method.object_pointer_id);
            assert_eq!(signature.parameters[0].emitted_name, "self");
            let debug::DebugLayoutValue::StructPointer { pointer_id, layout_id, producer_alignment, .. } =
                &signature.parameters[0].ty
            else {
                panic!("object must lower to an ordinary record pointer")
            };
            assert_eq!(*layout_id, method.record_id);
            assert_eq!(nodes[&method.object_pointer_id.die_offset].target, Some(pointer_id.die_offset));
            assert_eq!(*producer_alignment, nodes[&pointer_id.die_offset].alignment);
            let record = report.layouts.iter().find(|layout| layout.id == method.record_id).unwrap();
            assert!(signature.declaration.contains(&format!("struct {} * self", record.emitted_name)));
            let setter = expected["access"].as_str() == Some("write");
            assert_eq!(signature.parameters.len(), if setter { 2 } else { 1 });
            assert_eq!(matches!(&signature.return_type, debug::DebugLayoutValue::Void), setter);
            let scalar_value = if setter { &signature.parameters[1].ty } else { &signature.return_type };
            let debug::DebugLayoutValue::Leaf { leaf: debug::DebugLayoutLeaf::Scalar { scalar } } = scalar_value else {
                panic!("supported method ABI values must be ordinary scalar leaves")
            };
            let unsigned = expected["access"].as_str() == Some("read-unsigned");
            assert_eq!(scalar.byte_size, 4);
            assert_eq!(
                scalar.kind,
                if unsigned {
                    debug::DebugLayoutScalarKind::UnsignedInteger
                } else {
                    debug::DebugLayoutScalarKind::SignedInteger
                },
            );
        }
        for symbol in oracle["groups"]["records"]["functions"].as_array().unwrap() {
            let symbol = symbol.as_str().unwrap();
            if !symbol.starts_with("_Z") {
                let address = binary.symbol_by_name(symbol).unwrap().address;
                assert!(
                    !report
                        .signatures
                        .iter()
                        .any(|signature| signature.address == address && signature.method.is_some())
                );
            }
        }
        let stripped = Binary::open(root.join(variant).join("records.symbols.elf")).unwrap();
        let stripped = debug::layout_signatures(&stripped).unwrap();
        assert!(stripped.signatures.is_empty() && stripped.layouts.is_empty());
    }
}

#[test]
#[ignore = "requires centrally compiled C++ controls through debug-cpp-layouts/build.sh --check"]
fn compiled_unsupported_method_shapes_never_gain_this_projection_or_orphan_layouts() {
    let (root, oracle) = fixture_inputs();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        for group in ["unaligned", "const-method", "reference-argument", "byvalue", "inherited", "static-method"] {
            let binary = Binary::open(root.join(variant).join(format!("{group}.debug.elf"))).unwrap();
            if group == "unaligned" {
                let nodes = evidence(&binary);
                let record = nodes
                    .values()
                    .find(|node| node.name.as_deref() == oracle["records"]["unaligned"]["tag"].as_str())
                    .expect("owned negative must contain its record DIE");
                assert_eq!(record.alignment, None, "negative control must actually lack producer alignment");
            }
            let report = debug::layout_signatures(&binary).unwrap();
            for symbol in oracle["groups"][group]["functions"].as_array().unwrap() {
                let symbol = symbol.as_str().unwrap();
                let address = binary.symbol_by_name(symbol).unwrap().address;
                assert!(
                    !report.signatures.iter().any(|signature| signature.address == address),
                    "{variant}/{group}/{symbol}: {report:?}",
                );
            }
            let dependencies: BTreeSet<_> =
                report.signatures.iter().flat_map(|signature| &signature.dependencies).collect();
            assert!(
                report.layouts.iter().all(|layout| dependencies.contains(&layout.id)),
                "{variant}/{group}: {report:?}",
            );
        }
        let binary = Binary::open(root.join(variant).join("overloads.debug.elf")).unwrap();
        let report = debug::layout_signatures(&binary).unwrap();
        let expected_linkages: BTreeSet<_> = oracle["groups"]["overloads"]["functions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|symbol| symbol.as_str().unwrap())
            .filter(|symbol| symbol.starts_with("_Z"))
            .collect();
        assert_eq!(expected_linkages.len(), 2, "owned overload control must describe both method symbols");
        let actual_linkages: BTreeSet<_> = report
            .signatures
            .iter()
            .filter_map(|signature| signature.method.as_ref().map(|method| method.linkage_name.as_str()))
            .collect();
        assert_eq!(report.signatures.len(), expected_linkages.len(), "{variant}/overloads: {report:?}");
        assert_eq!(actual_linkages, expected_linkages, "{variant}/overloads: {report:?}");
        let mut identities = BTreeSet::new();
        let mut names = BTreeSet::new();
        for signature in &report.signatures {
            let method = signature.method.as_ref().expect("C++ wrappers must not be mistaken for object methods");
            assert!(identities.insert((method.declaration_id, method.linkage_name.as_str())));
            assert!(names.insert(signature.emitted_name.as_str()));
            assert_eq!(signature.parameters[0].id, method.object_pointer_id);
            assert_eq!(signature.address, binary.symbol_by_name(&method.linkage_name).unwrap().address);
            assert!(
                oracle["groups"]["overloads"]["functions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|symbol| symbol.as_str() == Some(method.linkage_name.as_str()))
            );
        }
    }
}

#[test]
#[ignore = "requires centrally compiled C++ controls through debug-cpp-layouts/build.sh --check"]
fn former_virtual_refusal_now_exposes_only_explicit_vptr_storage_and_the_declared_slot() {
    let (root, _) = fixture_inputs();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let binary = Binary::open(root.join(variant).join("virtual.debug.elf")).unwrap();
        let entry = binary.symbol_by_name("_ZN13VirtualRecord9readCountEv").unwrap().address;
        let report = debug::layout_signatures(&binary).unwrap();
        assert_eq!(report.signatures.len(), 1, "{variant}: {report:?}");
        let signature = &report.signatures[0];
        assert_eq!(signature.address, entry);
        assert_eq!(signature.method.as_ref().unwrap().virtual_slot, Some(0));
        let record = report.layouts.iter().find(|record| signature.dependencies.contains(&record.id)).unwrap();
        assert_eq!(record.fields[0].emitted_name, "rampage_vptr");
        assert!(matches!(record.fields[0].leaf, debug::DebugLayoutLeaf::OpaqueVptr { byte_size: 8, .. }));
        assert!(!record.strictly_applicable, "opaque storage is not exact producer-pointee equivalence");
    }
}
