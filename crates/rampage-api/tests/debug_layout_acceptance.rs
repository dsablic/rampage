use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use rampage_api::{DecompilerOptions, Project};
use rampage_decompiler::layout::{
    LayoutField, LayoutOrganization, LayoutScalar, LayoutType, PlainStructLayout, ScalarKind,
};
use rampage_loaders::{Binary, debug};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Oracle {
    target: Target,
    constant_section: ConstantSection,
    flat: Flat,
    groups: BTreeMap<String, Group>,
}

#[derive(Deserialize)]
struct Target {
    address_size: u32,
    max_binary_bytes: u64,
    max_function_bytes: u64,
}

#[derive(Deserialize)]
struct ConstantSection {
    name: String,
    symbol: String,
    magic: String,
    version: u64,
    byte_order_tag: u64,
    byte_size: u64,
}

#[derive(Deserialize)]
struct Flat {
    tag: String,
    size: u32,
    alignment: u32,
    fields: Vec<ExpectedField>,
    functions: Vec<FieldUse>,
}

#[derive(Deserialize)]
struct ExpectedField {
    name: String,
    offset: u32,
    size: u32,
    alignment: u32,
    kind: String,
}

#[derive(Deserialize)]
struct FieldUse {
    symbol: String,
    field: String,
    access: String,
}

#[derive(Deserialize)]
struct Group {
    functions: Vec<String>,
    extra_constants: BTreeMap<String, Vec<u64>>,
}

fn oracle() -> Oracle {
    serde_json::from_str(include_str!("../../../tests/fixtures/debug-layouts/oracle.json")).unwrap()
}

fn generated_root() -> PathBuf {
    PathBuf::from(
        std::env::var_os("RAMPAGE_DEBUG_LAYOUT_FIXTURES")
            .expect("requires centrally compiled fixtures; run debug-layout-oracle.sh --check"),
    )
}

fn bounded_bytes(path: &Path, maximum: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    std::fs::File::open(path).unwrap().take(maximum.checked_add(1).unwrap()).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() as u64 <= maximum);
    bytes
}

fn words(bytes: &[u8]) -> Vec<u64> {
    assert_eq!(bytes.len() % 8, 0);
    bytes.as_chunks::<8>().0.iter().map(|word| u64::from_le_bytes(*word)).collect()
}

fn source_words(oracle: &Oracle) -> Vec<u64> {
    let section = &oracle.constant_section;
    let mut expected = vec![
        u64::from_str_radix(section.magic.strip_prefix("0x").unwrap(), 16).unwrap(),
        section.version,
        u64::from(oracle.target.address_size),
        section.byte_order_tag,
        u64::from(oracle.flat.size),
        u64::from(oracle.flat.alignment),
        oracle.flat.fields.len() as u64,
    ];
    for field in &oracle.flat.fields {
        expected.extend([u64::from(field.offset), u64::from(field.size), u64::from(field.alignment)]);
    }
    assert_eq!(expected.len() as u64 * 8, section.byte_size);
    expected
}

fn open_generated(root: &Path, variant: &str, group: &str, control: &str, oracle: &Oracle) -> Project {
    let directory = root.join(variant);
    let path = directory.join(format!("{group}.{control}.elf"));
    bounded_bytes(&path, oracle.target.max_binary_bytes);
    let binary = Binary::open(&path).unwrap();
    let constants = bounded_bytes(&directory.join(format!("{group}.constants.bin")), oracle.constant_section.byte_size);
    assert_eq!(constants.len() as u64, oracle.constant_section.byte_size);
    assert_eq!(words(&constants), source_words(oracle));
    let symbol = binary.symbol_by_name(&oracle.constant_section.symbol).expect("constant oracle symbol");
    let section = binary.sections.iter().find(|section| section.name == oracle.constant_section.name).unwrap();
    assert_eq!((symbol.address, symbol.size), (section.address, oracle.constant_section.byte_size));
    let segment = binary.segment_containing(symbol.address).unwrap();
    assert!(segment.perms.read && !segment.perms.write && !segment.perms.execute);
    assert_eq!(binary.read(symbol.address, symbol.size).unwrap(), constants.as_slice());
    for name in &oracle.groups[group].functions {
        let function = binary.symbol_by_name(name).unwrap_or_else(|| panic!("missing {variant}/{group}/{name}"));
        assert!(binary.is_code(function.address));
        assert!(function.size > 0 && function.size <= oracle.target.max_function_bytes);
    }
    Project::new(binary)
}

fn source_field<'a>(oracle: &'a Oracle, name: &str) -> &'a ExpectedField {
    oracle.flat.fields.iter().find(|field| field.name == name).unwrap()
}

fn scalar(field: &ExpectedField) -> LayoutScalar {
    let (prefix, kind) = match field.kind.as_str() {
        "signed" => ("int", ScalarKind::SignedInteger),
        "unsigned" => ("uint", ScalarKind::UnsignedInteger),
        "float" => ("float", ScalarKind::Float),
        kind => panic!("unsupported source scalar category {kind}"),
    };
    LayoutScalar { name: format!("{prefix}{}", field.size), kind, size: field.size, alignment: field.alignment }
}

fn source_layout(oracle: &Oracle) -> PlainStructLayout {
    PlainStructLayout {
        name: oracle.flat.tag.clone(),
        size: oracle.flat.size,
        alignment: oracle.flat.alignment,
        organization: LayoutOrganization {
            pointer_size: oracle.target.address_size,
            int_size: source_field(oracle, "count").size,
            long_size: 8,
            scalar_alignments: ["tag", "flags", "count", "weight"].map(|name| source_field(oracle, name).alignment),
        },
        fields: oracle
            .flat
            .fields
            .iter()
            .map(|field| LayoutField {
                name: field.name.clone(),
                offset: field.offset,
                size: field.size,
                ty: if field.kind == "pointer" {
                    LayoutType::Pointer {
                        name: String::new(),
                        size: field.size,
                        alignment: field.alignment,
                        pointee: scalar(source_field(oracle, "count")),
                    }
                } else {
                    LayoutType::Scalar { scalar: scalar(field) }
                },
            })
            .collect(),
    }
}

fn symbol_address(project: &Project, name: &str) -> u64 {
    project.binary.symbol_by_name(name).expect("real binary function symbol").address
}

fn source_addresses(project: &Project, oracle: &Oracle) -> BTreeSet<u64> {
    oracle.flat.functions.iter().map(|function| symbol_address(project, &function.symbol)).collect()
}

fn annotations(project: &Project) -> serde_json::Value {
    serde_json::to_value(project.annotation_list()).unwrap()
}

fn check_alignment(producer: Option<u64>, measured: u32) {
    if let Some(alignment) = producer {
        assert_eq!(alignment, u64::from(measured));
    }
}

#[test]
#[ignore = "requires centrally compiled owned debug-layout fixtures through the --check wrapper"]
fn consumer_layout_matches_source_and_compiler_constants_without_promoting_producer_unknowns() {
    let root = generated_root();
    let oracle = oracle();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let project = open_generated(&root, variant, "flat", "debug", &oracle);
        let before = annotations(&project);
        let raw = serde_json::to_value(debug::layout_signatures(&project.binary).unwrap()).unwrap();
        let receipt = project.preview_debug_layouts().unwrap();
        let producer = receipt.producer_report().expect("producer evidence retained separately");
        assert_eq!(serde_json::to_value(producer).unwrap(), raw, "native verification must not fill producer Options");
        assert_eq!(receipt.report().types.len(), 1);
        let admitted = &receipt.report().types[0];
        assert_eq!(admitted.original_name, oracle.flat.tag);
        let layout = producer
            .layouts
            .iter()
            .find(|layout| layout.original_name.as_deref() == Some(oracle.flat.tag.as_str()))
            .expect("source-named producer layout");
        let mut expected = source_layout(&oracle);
        expected.name = layout.emitted_name.clone();
        assert_eq!(admitted.layout, expected, "whole native layout, including scalar categories and pointer pointee");
        assert_eq!((admitted.unit_offset, admitted.die_offset), (layout.id.unit_offset, layout.id.die_offset));
        assert_eq!(layout.byte_size, u64::from(expected.size));
        assert_eq!(layout.producer_alignment, Some(u64::from(expected.alignment)));
        assert_eq!(layout.fields.len(), expected.fields.len());
        assert!(
            layout.fields.iter().any(|field| field.producer_alignment.is_none()),
            "exercise unknown member evidence"
        );
        for (field, native) in layout.fields.iter().zip(&expected.fields) {
            assert_eq!(field.original_name.as_deref(), Some(native.name.as_str()));
            assert_eq!((field.offset, field.byte_size), (u64::from(native.offset), u64::from(native.size)));
            match (&field.leaf, &native.ty) {
                (debug::DebugLayoutLeaf::Scalar { scalar: producer }, LayoutType::Scalar { scalar: native }) => {
                    check_alignment(field.producer_alignment, native.alignment);
                    check_alignment(producer.producer_alignment, native.alignment);
                }
                (
                    debug::DebugLayoutLeaf::Pointer { producer_alignment, pointee, .. },
                    LayoutType::Pointer { alignment, pointee: native, .. },
                ) => {
                    check_alignment(field.producer_alignment, *alignment);
                    check_alignment(*producer_alignment, *alignment);
                    check_alignment(pointee.as_ref().unwrap().producer_alignment, native.alignment);
                }
                _ => panic!("producer and consumer leaf categories differ"),
            }
        }
        assert_eq!(receipt.report().functions.len(), oracle.flat.functions.len());
        assert_eq!(receipt.approved().len(), oracle.flat.functions.len());
        assert_eq!(
            receipt.approved().iter().map(|function| function.address).collect::<BTreeSet<_>>(),
            source_addresses(&project, &oracle)
        );
        for function in receipt.approved() {
            let raw = producer.signatures.iter().find(|raw| raw.original_name == function.original_name).unwrap();
            assert_eq!(function.address, symbol_address(&project, &function.original_name));
            assert_eq!((function.unit_offset, function.die_offset), (raw.id.unit_offset, raw.id.die_offset));
            assert_eq!(function.dependencies, [expected.name.clone()]);
            assert_eq!(raw.dependencies, [layout.id]);
            assert!(
                matches!(&raw.parameters[0].ty, debug::DebugLayoutValue::StructPointer { layout_id, byte_size, .. }
                if *layout_id == layout.id && *byte_size == u64::from(oracle.target.address_size))
            );
        }
        let path = root.join(variant).join("flat.debug.elf");
        let digest: [u8; 32] = Sha256::digest(bounded_bytes(&path, oracle.target.max_binary_bytes)).into();
        assert_eq!(receipt.image_sha256(), &digest);
        assert_eq!(annotations(&project), before);
        assert!(project.undo().unwrap().is_empty(), "preview must not add undo history");
    }
}

fn return_type(oracle: &Oracle, function: &FieldUse) -> (String, u32) {
    if function.access == "write" {
        return ("void".to_owned(), 0);
    }
    assert_eq!(function.access, "read");
    let field = source_field(oracle, &function.field);
    match field.kind.as_str() {
        "pointer" => (format!("{} *", scalar(source_field(oracle, "count")).name), field.size),
        "signed" | "unsigned" if field.size < source_field(oracle, "count").size => {
            let prefix = if field.kind == "signed" { "int" } else { "uint" };
            (format!("{prefix}{}", source_field(oracle, "count").size), source_field(oracle, "count").size)
        }
        _ => (scalar(field).name, field.size),
    }
}

fn compact(text: &str) -> String {
    text.chars().filter(|character| !character.is_whitespace()).collect()
}

#[test]
#[ignore = "requires centrally compiled owned debug-layout fixtures through the --check wrapper"]
fn approved_source_prototypes_drive_engine_return_widths_and_actual_scalar_stores() {
    let root = generated_root();
    let oracle = oracle();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let project = open_generated(&root, variant, "flat", "debug", &oracle);
        let receipt = project.preview_debug_layouts().unwrap();
        project.apply_debug_layouts(&receipt).unwrap();
        for source in &oracle.flat.functions {
            let function = receipt.approved().iter().find(|function| function.original_name == source.symbol).unwrap();
            let (expected_return, size) = return_type(&oracle, source);
            let prefix = function.declaration.split_once(source.symbol.as_str()).unwrap().0;
            assert_eq!(compact(prefix), compact(&expected_return), "{} source return category", source.symbol);
            let result = project.decompile(symbol_address(&project, &source.symbol)).unwrap();
            let signature = &result.structure.signature;
            assert_eq!(signature.return_type.size, size, "{} source return width", source.symbol);
            assert!(!signature.variadic);
            let item = &signature.parameters[0];
            assert_eq!(item.name, "item");
            assert_eq!(item.data_type.size, oracle.target.address_size);
            if source.access == "write" {
                assert_eq!(signature.parameters.len(), 2);
                let replacement = &signature.parameters[1];
                assert_eq!(replacement.name, "replacement");
                let field = source_field(&oracle, &source.field);
                assert_eq!(replacement.data_type.size, field.size, "{} store width", source.symbol);
                let declaration = function.declaration.split_once(',').unwrap().1.trim_end_matches(";");
                assert_eq!(compact(declaration), format!("{}replacement)", scalar(field).name));
                let code = compact(&result.code);
                let assignment = format!("->{}=", source.field);
                let right = code.split_once(assignment.as_str()).expect("field is the actual store destination").1;
                assert!(!right.starts_with('='), "comparison is not a store: {}", result.code);
                let right = right.split(';').next().unwrap();
                assert!(
                    right
                        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                        .any(|identifier| identifier == "replacement"),
                    "{}",
                    result.code
                );
            } else {
                assert_eq!(signature.parameters.len(), 1);
            }
        }
    }
}

#[test]
#[ignore = "requires centrally compiled owned debug-layout fixtures through the --check wrapper"]
fn consent_preserves_analyst_signatures_before_and_after_preview_and_undo_keeps_them() {
    let root = generated_root();
    let oracle = oracle();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let project = open_generated(&root, variant, "flat", "debug", &oracle);
        let first = symbol_address(&project, "debug_flat_read_first");
        let final_field = symbol_address(&project, "debug_flat_read_final");
        let entry = symbol_address(&project, "entry");
        project.set_types(entry, Some("typedef uint4 analyst_word;")).unwrap();
        project.set_signature(first, Some("int4 analyst_first(void *opaque);")).unwrap();
        let before_preview = annotations(&project);
        let receipt = project.preview_debug_layouts().unwrap();
        assert_eq!(annotations(&project), before_preview);
        assert!(receipt.preserved().contains(&first));
        assert!(!receipt.approved().iter().any(|function| function.address == first));
        assert!(receipt.approved().iter().any(|function| function.address == final_field));
        project.set_signature(final_field, Some("uint4 analyst_final(void *opaque);")).unwrap();
        let before_apply = annotations(&project);
        let analyst_signatures = project.annotation_list().signatures;
        let imported = project.apply_debug_layouts(&receipt).unwrap();
        let mut expected = source_addresses(&project, &oracle);
        expected.remove(&first);
        expected.remove(&final_field);
        assert_eq!(imported.applied.iter().copied().collect::<BTreeSet<_>>(), expected);
        assert_eq!(imported.preserved.iter().copied().collect::<BTreeSet<_>>(), BTreeSet::from([first, final_field]));
        let producer_type = receipt
            .producer_report()
            .unwrap()
            .layouts
            .iter()
            .find(|layout| layout.original_name.as_deref() == Some(oracle.flat.tag.as_str()))
            .unwrap();
        assert_eq!(imported.imported_types.as_slice(), std::slice::from_ref(&producer_type.emitted_name));
        let after = project.annotation_list();
        for address in [first, final_field] {
            let annotation =
                after.signatures.iter().find(|row| row.address == address).expect("analyst signature retained");
            let previous = analyst_signatures.iter().find(|row| row.address == address).unwrap();
            assert_eq!(annotation.text, previous.text);
        }
        let after_apply = annotations(&project);
        let repeated = project.apply_debug_layouts(&receipt).unwrap();
        assert!(repeated.applied.is_empty() && repeated.imported_types.is_empty());
        assert_eq!(annotations(&project), after_apply);
        assert!(!project.undo().unwrap().is_empty());
        assert_eq!(annotations(&project), before_apply, "one import undo retains both analyst edits and their types");
    }
}

#[test]
#[ignore = "requires centrally compiled owned debug-layout fixtures through the --check wrapper"]
fn rejected_checked_options_do_not_invalidate_consent_or_the_active_engine() {
    let root = generated_root();
    let oracle = oracle();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let project = open_generated(&root, variant, "flat", "debug", &oracle);
        let address = symbol_address(&project, "debug_flat_read_interior");
        let active = project.decompile(address).unwrap();
        let receipt = project.preview_debug_layouts().unwrap();
        let before = annotations(&project);
        assert!(
            project
                .try_set_decompiler_options(Some(DecompilerOptions {
                    compiler: Some("rampage_missing_debug_layout_compiler".to_owned()),
                    ..DecompilerOptions::default()
                }))
                .is_err()
        );
        assert_eq!(annotations(&project), before);
        let retained = project.decompile(address).unwrap();
        assert_eq!(retained.language_id, active.language_id);
        assert_eq!(retained.code, active.code);
        assert_eq!(retained.structure.signature, active.structure.signature);
        let repeated = project.preview_debug_layouts().unwrap();
        assert_eq!(receipt.compiler_spec_sha256(), repeated.compiler_spec_sha256());
        let imported = project.apply_debug_layouts(&receipt).unwrap();
        assert_eq!(imported.applied.iter().copied().collect::<BTreeSet<_>>(), source_addresses(&project, &oracle));
        let result = project.decompile(address).unwrap();
        assert_eq!(result.structure.signature.return_type.size, source_field(&oracle, "count").size);
    }
}

fn assert_no_import(project: &Project) {
    let before = annotations(project);
    let receipt = project.preview_debug_layouts().unwrap();
    assert!(receipt.report().types.is_empty(), "{:?}", receipt.report());
    assert!(receipt.report().functions.is_empty(), "{:?}", receipt.report());
    assert!(receipt.approved().is_empty());
    assert_eq!(annotations(project), before);
    let imported = project.apply_debug_layouts(&receipt).unwrap();
    assert!(imported.applied.is_empty() && imported.imported_types.is_empty());
    assert_eq!(
        imported.preserved.iter().copied().collect::<BTreeSet<_>>(),
        receipt.preserved().iter().copied().collect::<BTreeSet<_>>()
    );
    assert_eq!(annotations(project), before);
    assert!(project.undo().unwrap().is_empty(), "refused candidates must not create undo history");
}

#[test]
#[ignore = "requires centrally compiled owned debug-layout fixtures through the --check wrapper"]
fn same_name_cus_and_sanitization_collisions_cannot_attach_layouts_by_name() {
    let root = generated_root();
    let oracle = oracle();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        for group in ["identity-compatible", "identity-incompatible", "collisions"] {
            let project = open_generated(&root, variant, group, "debug", &oracle);
            for (name, expected) in &oracle.groups[group].extra_constants {
                let symbol = format!("debug_{}_constants", name.strip_prefix(".rampage_").unwrap());
                let symbol = project.binary.symbol_by_name(&symbol).unwrap();
                assert_eq!(symbol.size, expected.len() as u64 * 8);
                assert_eq!(words(project.binary.read(symbol.address, symbol.size).unwrap()), *expected);
            }
            assert_no_import(&project);
        }
        assert_no_import(&open_generated(&root, variant, "flat", "symbols", &oracle));
    }
}

#[test]
#[ignore = "requires centrally compiled owned debug-layout fixtures through the --check wrapper"]
fn unsupported_layouts_remain_unimported_and_missing_alignment_remains_visible_only_in_producer_preview() {
    let root = generated_root();
    let oracle = oracle();
    let cpp = match std::env::var("DEBUG_LAYOUT_CPP") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => "0".to_owned(),
        Err(error) => panic!("invalid DEBUG_LAYOUT_CPP: {error}"),
    };
    assert!(matches!(cpp.as_str(), "0" | "1"), "DEBUG_LAYOUT_CPP must be 0 or 1");
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let project = open_generated(&root, variant, "refusals", "debug", &oracle);
        let receipt = project.preview_debug_layouts().unwrap();
        let producer = receipt.producer_report().unwrap();
        let missing = producer
            .signatures
            .iter()
            .find(|function| function.original_name == "debug_missing_alignment_read")
            .expect("preview-only signature");
        assert_eq!(missing.address, symbol_address(&project, "debug_missing_alignment_read"));
        let layout = producer.layouts.iter().find(|layout| missing.dependencies.contains(&layout.id)).unwrap();
        assert_eq!(layout.producer_alignment, None);
        assert_eq!(layout.byte_size, u64::from(oracle.flat.size));
        assert_eq!(layout.fields.len(), oracle.flat.fields.len());
        for (field, expected) in layout.fields.iter().zip(&oracle.flat.fields) {
            assert_eq!((field.offset, field.byte_size), (u64::from(expected.offset), u64::from(expected.size)));
        }
        assert!(receipt.preserved().contains(&missing.address));
        for name in &oracle.groups["refusals"].functions {
            let address = symbol_address(&project, name);
            assert!(!receipt.approved().iter().any(|function| function.address == address), "{name}");
        }
        assert_no_import(&project);
        if cpp == "1" {
            assert_no_import(&open_generated(&root, variant, "inheritance", "debug", &oracle));
        }
    }
    if cpp == "0" {
        eprintln!("C++ inheritance gate not exercised: DEBUG_LAYOUT_CPP=0");
    }
}
