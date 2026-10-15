use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use gimli::{AttributeValue, Reader};
use object::{Object, ObjectSection};
use rampage_loaders::{Binary, debug};

type FixtureReader<'a> = gimli::EndianSlice<'a, gimli::LittleEndian>;

fn fixture_inputs() -> (PathBuf, serde_json::Value) {
    let root = std::env::var_os("RAMPAGE_DEBUG_CPP_VIRTUAL_FIXTURES")
        .map(PathBuf::from)
        .expect("run the centrally owned debug-cpp-virtuals/build.sh --check wrapper");
    let oracle = std::env::var_os("RAMPAGE_DEBUG_CPP_VIRTUAL_ORACLE")
        .map(PathBuf::from)
        .expect("the fixture wrapper must supply its source oracle");
    let oracle = serde_json::from_slice(&std::fs::read(oracle).unwrap()).unwrap();
    (root, oracle)
}

#[derive(Debug)]
struct Evidence {
    id: debug::DebugLayoutTypeId,
    dwarf_version: u16,
    tag: gimli::DwTag,
    parent: Option<u64>,
    children: Vec<u64>,
    target: Option<u64>,
    specification: Option<u64>,
    object_pointer: Option<u64>,
    containing_type: Option<u64>,
    name: Option<String>,
    size: Option<u64>,
    alignment: Option<u64>,
    encoding: Option<gimli::DwAte>,
    offset: Option<u64>,
    artificial: bool,
    declaration: bool,
    external: bool,
    location: bool,
    address_evidence: bool,
    virtual_slot: Option<u64>,
}

fn reference(value: Option<AttributeValue<FixtureReader<'_>>>, unit: &gimli::Unit<FixtureReader<'_>>) -> Option<u64> {
    match value? {
        AttributeValue::UnitRef(offset) => Some(offset.to_debug_info_offset(&unit.header).unwrap().0 as u64),
        AttributeValue::DebugInfoRef(offset) => Some(offset.0 as u64),
        _ => panic!("owned virtual identity evidence must be a DIE reference"),
    }
}

fn slot(entry: &gimli::DebuggingInformationEntry<FixtureReader<'_>>) -> Option<u64> {
    let value = entry.attr_value(gimli::DW_AT_vtable_elem_location)?;
    assert!(matches!(
        entry.attr_value(gimli::DW_AT_virtuality),
        Some(AttributeValue::Virtuality(gimli::DW_VIRTUALITY_virtual)),
    ));
    let AttributeValue::Exprloc(expression) = value else { panic!("owned virtual slots require expressions") };
    let mut bytes = expression.0;
    assert_eq!(bytes.read_u8().unwrap(), gimli::DW_OP_constu.0);
    let index = bytes.read_uleb128().unwrap();
    assert!(bytes.is_empty());
    assert!(index < 64);
    Some(index)
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
            let node = Evidence {
                id: debug::DebugLayoutTypeId { unit_offset, die_offset: offset },
                dwarf_version: unit.header.version(),
                tag: entry.tag(),
                parent: parents.last().copied(),
                children: Vec::new(),
                target: reference(entry.attr_value(gimli::DW_AT_type), &unit),
                specification: reference(entry.attr_value(gimli::DW_AT_specification), &unit),
                object_pointer: reference(entry.attr_value(gimli::DW_AT_object_pointer), &unit),
                containing_type: reference(entry.attr_value(gimli::DW_AT_containing_type), &unit),
                name: entry
                    .attr_value(gimli::DW_AT_name)
                    .map(|value| dwarf.attr_string(&unit, value).unwrap().to_string_lossy().into_owned()),
                size: entry.attr_value(gimli::DW_AT_byte_size).map(|value| value.udata_value().unwrap()),
                alignment: entry.attr_value(gimli::DW_AT_alignment).map(|value| value.udata_value().unwrap()),
                encoding: match entry.attr_value(gimli::DW_AT_encoding) {
                    Some(AttributeValue::Encoding(encoding)) => Some(encoding),
                    None => None,
                    _ => panic!("owned producer encoding must use its DWARF encoding value"),
                },
                offset: entry.attr_value(gimli::DW_AT_data_member_location).map(|value| value.udata_value().unwrap()),
                artificial: matches!(entry.attr_value(gimli::DW_AT_artificial), Some(AttributeValue::Flag(true))),
                declaration: matches!(entry.attr_value(gimli::DW_AT_declaration), Some(AttributeValue::Flag(true))),
                external: matches!(entry.attr_value(gimli::DW_AT_external), Some(AttributeValue::Flag(true))),
                location: entry.attr_value(gimli::DW_AT_location).is_some(),
                address_evidence: [
                    gimli::DW_AT_low_pc,
                    gimli::DW_AT_high_pc,
                    gimli::DW_AT_ranges,
                    gimli::DW_AT_entry_pc,
                ]
                .iter()
                .any(|&attribute| entry.attr_value(attribute).is_some()),
                virtual_slot: slot(entry),
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

fn object_formal(nodes: &BTreeMap<u64, Evidence>, owner: u64, record: debug::DebugLayoutTypeId) -> u64 {
    let function = &nodes[&owner];
    let formals: Vec<_> =
        function.children.iter().copied().filter(|child| nodes[child].tag == gimli::DW_TAG_formal_parameter).collect();
    let first = *formals.first().expect("owned instance method must have an object formal");
    if let Some(explicit) = function.object_pointer {
        assert_eq!(explicit, first, "object_pointer must reference the actual first formal");
        assert_eq!(formals.iter().filter(|&&formal| formal == explicit).count(), 1);
    } else {
        assert!(function.declaration, "concrete methods require an explicit object pointer");
    }
    let object = &nodes[&first];
    assert_eq!(object.parent, Some(owner));
    assert_eq!(object.id.unit_offset, record.unit_offset);
    assert!(object.artificial);
    assert!(object.children.is_empty());
    let pointer = &nodes[&object.target.expect("object formal requires its direct pointer DIE")];
    assert_eq!(pointer.tag, gimli::DW_TAG_pointer_type);
    assert_eq!(pointer.target, Some(record.die_offset));
    assert_eq!(pointer.id.unit_offset, record.unit_offset);
    assert!(pointer.children.is_empty());
    first
}

fn artifact_declaration(nodes: &BTreeMap<u64, Evidence>, record: debug::DebugLayoutTypeId) {
    let owner = &nodes[&record.die_offset];
    let artifacts: Vec<_> = owner
        .children
        .iter()
        .map(|child| &nodes[child])
        .filter(|child| child.name.as_deref() == Some("_vtable$"))
        .collect();
    assert_eq!(artifacts.len(), 1);
    let artifact = artifacts[0];
    assert_eq!(
        artifact.tag,
        match owner.dwarf_version {
            4 => gimli::DW_TAG_member,
            5 => gimli::DW_TAG_variable,
            _ => panic!("owned fixture requires DWARF 4 or 5"),
        },
    );
    assert_eq!(artifact.parent, Some(record.die_offset));
    assert_eq!(artifact.id.unit_offset, record.unit_offset);
    assert_eq!(artifact.dwarf_version, owner.dwarf_version);
    assert!(artifact.declaration && artifact.artificial && artifact.external);
    assert!(artifact.children.is_empty());
    assert_eq!(artifact.offset, None);
    assert_eq!(artifact.size, None);
    assert_eq!(artifact.alignment, None);
    assert_eq!(artifact.specification, None);
    assert_eq!(artifact.containing_type, None);
    assert_eq!(artifact.object_pointer, None);
    assert!(!artifact.location && !artifact.address_evidence);
    let pointer = &nodes[&artifact.target.expect("static artifact requires its direct void-pointer DIE")];
    assert_eq!(pointer.tag, gimli::DW_TAG_pointer_type);
    assert_eq!(pointer.target, None);
    assert_eq!(pointer.id.unit_offset, record.unit_offset);
    assert!(pointer.children.is_empty());
    assert!(!pointer.declaration);
}

#[test]
#[ignore = "requires parent-measured DWARF through debug-cpp-virtuals/build.sh --check"]
fn compiled_virtuals_preserve_exact_storage_graph_unknowns_slots_and_record_identity() {
    let (root, oracle) = fixture_inputs();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let binary = Binary::open(root.join(variant).join("records.debug.elf")).unwrap();
        let nodes = evidence(&binary);
        let report = debug::layout_signatures(&binary).unwrap();
        let methods = oracle["groups"]["records"]["methods"].as_array().unwrap();
        assert_eq!(report.signatures.len(), methods.len(), "{variant}: {report:?}");
        assert_eq!(report.layouts.len(), oracle["groups"]["records"]["records"].as_array().unwrap().len());
        let mut identities = BTreeSet::new();
        for key in ["checked", "peer"] {
            let record = &oracle["records"][key];
            let expected = &oracle["layouts"][record["layout"].as_str().unwrap()];
            let layout = report
                .layouts
                .iter()
                .find(|layout| layout.original_name.as_deref() == record["tag"].as_str())
                .unwrap_or_else(|| panic!("missing {key} in {variant}: {report:?}"));
            assert!(identities.insert(layout.id));
            assert!(layout.source.is_cpp());
            assert_eq!(layout.byte_size, expected["size"].as_u64().unwrap());
            assert_eq!(layout.producer_alignment, expected["alignment"].as_u64());
            assert_eq!(layout.producer_alignment, nodes[&layout.id.die_offset].alignment);
            assert_eq!(layout.source.dwarf_version, nodes[&layout.id.die_offset].dwarf_version);
            assert_eq!(nodes[&layout.id.die_offset].containing_type, Some(layout.id.die_offset));
            artifact_declaration(&nodes, layout.id);
            assert!(layout.eligible_for_native_verification);
            assert!(!layout.strictly_applicable);
            let fields = expected["fields"].as_array().unwrap();
            assert_eq!(layout.fields.len(), fields.len() + 1);
            let storage = &layout.fields[0];
            let member = &nodes[&storage.id.die_offset];
            assert_eq!(storage.emitted_name, "rampage_vptr");
            assert_eq!((storage.offset, storage.byte_size), (0, 8));
            assert_eq!(member.parent, Some(layout.id.die_offset));
            assert_eq!(member.offset, Some(0));
            assert!(member.artificial);
            assert_eq!(storage.original_name, member.name);
            assert_eq!(storage.producer_alignment, member.alignment);
            let debug::DebugLayoutLeaf::OpaqueVptr {
                pointer_id,
                pointer_byte_size,
                producer_alignment,
                pointee_pointer_id,
                pointee_pointer_byte_size,
                pointee_pointer_alignment,
                subroutine_id,
                member_byte_size,
                byte_size,
            } = &storage.leaf
            else {
                panic!("compiler vptr must use explicit opaque storage, not an ordinary void pointer")
            };
            assert_eq!(*byte_size, 8);
            assert_eq!(*member_byte_size, member.size);
            assert_eq!(member.target, Some(pointer_id.die_offset));
            for (id, tag) in [
                (pointer_id, gimli::DW_TAG_pointer_type),
                (pointee_pointer_id, gimli::DW_TAG_pointer_type),
                (subroutine_id, gimli::DW_TAG_subroutine_type),
            ] {
                assert_eq!(id.unit_offset, layout.id.unit_offset);
                assert_eq!(nodes[&id.die_offset].id, *id);
                assert_eq!(nodes[&id.die_offset].tag, tag);
                assert!(nodes[&id.die_offset].children.is_empty());
            }
            let pointer = &nodes[&pointer_id.die_offset];
            let pointee = &nodes[&pointee_pointer_id.die_offset];
            assert_eq!(pointer.name, None);
            assert_eq!(pointee.name.as_deref(), Some("__vtbl_ptr_type"));
            assert_eq!(pointer.target, Some(pointee_pointer_id.die_offset));
            assert_eq!(pointee.target, Some(subroutine_id.die_offset));
            let terminal = &nodes[&subroutine_id.die_offset];
            let terminal_result = &nodes[&terminal.target.unwrap()];
            assert_eq!(terminal_result.tag, gimli::DW_TAG_base_type);
            assert_eq!(terminal_result.name.as_deref(), Some("int"));
            assert_eq!(terminal_result.size, Some(4));
            assert_eq!(terminal_result.encoding, Some(gimli::DW_ATE_signed));
            assert_eq!(terminal_result.id.unit_offset, layout.id.unit_offset);
            assert_eq!((*pointer_byte_size, *producer_alignment), (pointer.size, pointer.alignment));
            assert_eq!((*pointee_pointer_byte_size, *pointee_pointer_alignment), (pointee.size, pointee.alignment));
            for (field, expected) in layout.fields[1..].iter().zip(fields) {
                assert_eq!(field.original_name.as_deref(), expected["name"].as_str());
                assert_eq!(field.offset, expected["offset"].as_u64().unwrap());
                assert_eq!(field.byte_size, expected["size"].as_u64().unwrap());
                assert!(matches!(&field.leaf, debug::DebugLayoutLeaf::Scalar { .. }));
            }
        }
        for expected in methods {
            let symbol = expected["symbol"].as_str().unwrap();
            let signature = report
                .signatures
                .iter()
                .find(|signature| signature.method.as_ref().is_some_and(|method| method.linkage_name == symbol))
                .unwrap_or_else(|| panic!("missing {symbol} in {variant}: {report:?}"));
            let method = signature.method.as_ref().unwrap();
            let definition = &nodes[&signature.id.die_offset];
            let declaration = &nodes[&method.declaration_id.die_offset];
            let record = &nodes[&method.record_id.die_offset];
            assert_eq!(definition.tag, gimli::DW_TAG_subprogram);
            assert!(!definition.declaration);
            assert_eq!(declaration.tag, gimli::DW_TAG_subprogram);
            assert!(declaration.declaration);
            assert_eq!(declaration.specification, None);
            assert!(!declaration.address_evidence);
            assert!(matches!(record.tag, gimli::DW_TAG_class_type | gimli::DW_TAG_structure_type));
            assert!(!record.declaration);
            assert_eq!(record.children.iter().filter(|&&child| child == method.declaration_id.die_offset).count(), 1);
            assert_eq!(record.name.as_deref(), oracle["records"][expected["record"].as_str().unwrap()]["tag"].as_str());
            for node in [definition, declaration, record] {
                assert_eq!(node.id.unit_offset, signature.id.unit_offset);
            }
            for parent in [definition.parent.unwrap(), record.parent.unwrap()] {
                assert_eq!(nodes[&parent].tag, gimli::DW_TAG_compile_unit);
                assert_eq!(nodes[&parent].id.unit_offset, signature.id.unit_offset);
            }
            assert_eq!(signature.address, binary.symbol_by_name(symbol).unwrap().address);
            assert_eq!(definition.specification, Some(method.declaration_id.die_offset));
            assert_eq!(definition.object_pointer, Some(method.object_pointer_id.die_offset));
            assert_eq!(declaration.parent, Some(method.record_id.die_offset));
            assert_eq!(
                object_formal(&nodes, signature.id.die_offset, method.record_id),
                method.object_pointer_id.die_offset,
            );
            object_formal(&nodes, method.declaration_id.die_offset, method.record_id);
            if let Some(containing) = declaration.containing_type {
                assert_eq!(containing, method.record_id.die_offset);
            }
            if let Some(containing) = definition.containing_type {
                assert_eq!(containing, method.record_id.die_offset);
            }
            assert_eq!(method.virtual_slot, expected["virtual_slot"].as_u64());
            assert_eq!(method.virtual_slot, declaration.virtual_slot);
            assert_eq!(signature.dependencies, [method.record_id]);
            assert!(signature.eligible_for_native_verification);
            assert!(!signature.strictly_applicable);
        }
        let stripped = Binary::open(root.join(variant).join("records.symbols.elf")).unwrap();
        let stripped = debug::layout_signatures(&stripped).unwrap();
        assert!(stripped.layouts.is_empty() && stripped.signatures.is_empty());
    }
}

#[test]
#[ignore = "requires parent-measured DWARF through debug-cpp-virtuals/build.sh --check"]
fn compiled_unsupported_virtual_controls_never_gain_a_projected_layout_or_method() {
    let (root, oracle) = fixture_inputs();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        for group in ["missing-alignment", "lookalikes", "inherited", "signatures"] {
            let binary = Binary::open(root.join(variant).join(format!("{group}.debug.elf"))).unwrap();
            let report = debug::layout_signatures(&binary).unwrap();
            for symbol in oracle["groups"][group]["functions"].as_array().unwrap() {
                let symbol = symbol.as_str().unwrap();
                if group == "inherited"
                    && ["_ZN10LeftRecord8readLeftEv", "_ZN11RightRecord9readRightEv"].contains(&symbol)
                {
                    continue;
                }
                let address = binary.symbol_by_name(symbol).unwrap().address;
                assert!(
                    !report.signatures.iter().any(|signature| signature.address == address),
                    "{variant}/{group}/{symbol}: {report:?}",
                );
            }
            let rejected_records = oracle["groups"][group]["records"].as_array().unwrap();
            for record in rejected_records {
                let tag = oracle["records"][record.as_str().unwrap()]["tag"].as_str();
                assert!(
                    !report.layouts.iter().any(|layout| layout.original_name.as_deref() == tag),
                    "{variant}/{group}: {report:?}",
                );
            }
            let dependencies: BTreeSet<_> =
                report.signatures.iter().flat_map(|signature| &signature.dependencies).collect();
            assert!(report.layouts.iter().all(|layout| dependencies.contains(&layout.id)));
        }
    }
}
