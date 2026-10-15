use super::*;
use rampage_loaders::debug::{DebugLayoutSource, DebugLayoutTypeId};

fn id(die_offset: u64) -> DebugLayoutTypeId {
    DebugLayoutTypeId { unit_offset: 16, die_offset }
}

pub(super) fn projected_type() -> DebugLayoutType {
    DebugLayoutType {
        original_name: "Record".to_owned(),
        unit_offset: 16,
        die_offset: 32,
        layout: PlainStructLayout {
            name: "debug_layout_10_20_Record".to_owned(),
            size: 16,
            alignment: 8,
            organization: LayoutOrganization {
                pointer_size: 8,
                int_size: 4,
                long_size: 8,
                scalar_alignments: [1, 2, 4, 8],
            },
            fields: vec![
                LayoutField {
                    name: "rampage_vptr".to_owned(),
                    offset: 0,
                    size: 8,
                    ty: LayoutType::Pointer {
                        name: String::new(),
                        size: 8,
                        alignment: 8,
                        pointee: LayoutScalar {
                            name: "void".to_owned(),
                            kind: ScalarKind::Void,
                            size: 0,
                            alignment: 1,
                        },
                    },
                },
                LayoutField {
                    name: "count".to_owned(),
                    offset: 8,
                    size: 4,
                    ty: LayoutType::Scalar {
                        scalar: LayoutScalar {
                            name: "int4".to_owned(),
                            kind: ScalarKind::SignedInteger,
                            size: 4,
                            alignment: 4,
                        },
                    },
                },
            ],
        },
        projections: vec![DebugLayoutProjection::OpaqueVptr {
            field_index: 0,
            record_id: id(32),
            member_id: id(40),
            source: DebugLayoutSource { unit_offset: 16, language: 0x21, dwarf_version: 5, address_size: 8 },
            record_byte_size: 16,
            record_alignment: 8,
            member_offset: 0,
            member_byte_size: None,
            member_alignment: None,
            pointer_id: id(48),
            pointer_byte_size: None,
            pointer_alignment: None,
            pointee_pointer_id: id(56),
            pointee_pointer_byte_size: None,
            pointee_pointer_alignment: None,
            subroutine_id: id(64),
        }],
    }
}

fn projected_text() -> String {
    let ty = projected_type();
    LayoutBundle::encode_types(&[7; 32], &[&ty]).unwrap()
}

#[test]
fn projected_origin_has_a_distinct_seal_and_unknown_facts_survive_the_v2_envelope() {
    let ty = projected_type();
    let v2 = projected_text();
    let v1 = LayoutBundle::encode(&[7; 32], std::slice::from_ref(&ty.layout)).unwrap();
    assert!(v1.starts_with(TYPE_MAGIC));
    assert!(v2.starts_with(TYPE_MAGIC_V2));
    let exact = LayoutBundle::decode(&v1).unwrap().unwrap();
    let projected = LayoutBundle::decode(&v2).unwrap().unwrap();
    assert_eq!(projected.layouts[0].layout, exact.layouts[0].layout);
    assert_eq!(projected.layouts[0].projections, ty.projections);
    assert!(exact.layouts[0].projections.is_empty());
    assert_ne!(projected.layouts[0].digest, exact.layouts[0].digest);
    let image = rampage_arch::hex::bytes(&[7; 32]);
    let canonical = serde_json::to_string(&ty.layout).unwrap();
    let expected =
        digest_text(format!("{TYPE_MAGIC}{image}\n{LANGUAGE}\n{}\n{canonical}", exact.specifications).as_bytes());
    assert_eq!(exact.layouts[0].digest, expected, "historical v1 digest remains unchanged");
    let mut known = ty.clone();
    let DebugLayoutProjection::OpaqueVptr { pointer_alignment, .. } = &mut known.projections[0];
    *pointer_alignment = Some(8);
    let changed = LayoutBundle::encode_types(&[7; 32], &[&known]).unwrap();
    assert_ne!(LayoutBundle::decode(&changed).unwrap().unwrap().layouts[0].digest, projected.layouts[0].digest);
    let sealed = seal_signature("int4 method(debug_layout_10_20_Record *self);", &[&projected.layouts[0]]).unwrap();
    let right = BTreeMap::from([(ty.layout.name.clone(), projected.layouts[0].digest.clone())]);
    let wrong = BTreeMap::from([(ty.layout.name.clone(), exact.layouts[0].digest.clone())]);
    assert!(signature(&sealed, &right).is_ok());
    assert!(signature(&sealed, &wrong).is_err());
}

#[test]
fn all_projection_metadata_is_preflighted_before_any_native_layout_json_decoding() {
    let specifications = current_specification_digest().unwrap();
    let image = rampage_arch::hex::bytes(&[7; 32]);
    let text =
        format!("{TYPE_MAGIC_V2}{image}\n{LANGUAGE}\n{specifications}\n{{\"bad\":true}}\np0\n{{}}\np1 unknown\n");
    let error = match LayoutBundle::decode(&text) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("malformed projection metadata was accepted"),
    };
    assert!(error.contains("unknown projection kind"), "{error}");
}

#[test]
fn projected_pair_framing_missing_extra_unknown_and_projection_free_v2_are_refused() {
    let original = projected_text();
    let lines: Vec<_> = original.lines().collect();
    let header = lines[..4].join("\n");
    let layout = lines[4];
    for bad in [
        format!("{header}\n{layout}\n"),
        format!("{header}\n{layout}\np0\n"),
        format!("{original}p0\n"),
        format!("{header}\n{layout}\np2 opaque_vptr\n"),
        original.replace('\n', "\r\n"),
        original.replace(TYPE_MAGIC_V2, "!rampage-plain-layout-v3\n"),
        format!("{TYPE_MAGIC_V2}{}", " ".repeat(MAX_BUNDLE_BYTES)),
    ] {
        assert!(LayoutBundle::decode(&bad).is_err());
    }
}

#[test]
fn v2_overwrite_dependencies_and_atomic_removal_have_the_same_protection_as_v1() {
    let text = projected_text();
    let bundle = LayoutBundle::decode(&text).unwrap().unwrap();
    let sealed = seal_signature("int4 method(debug_layout_10_20_Record *self);", &[&bundle.layouts[0]]).unwrap();
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Types, 1, Some(text)).unwrap();
    annotations.set(Field::Signature, 2, Some(sealed)).unwrap();
    assert!(annotations.set(Field::Types, 1, Some(declaration(&projected_type().layout))).is_err());
    assert!(annotations.set(Field::Types, 1, None).is_err());
    annotations.set_batch_validated(&[(Field::Signature, 2, None), (Field::Types, 1, None)], |_| Ok(())).unwrap();
    assert!(annotations.types().is_empty() && annotations.signatures().is_empty());
}

#[test]
fn bad_projection_storage_is_refused_before_an_invalid_compiler_can_initialize_native_state() {
    let text = projected_text().replace("\"name\":\"rampage_vptr\"", "\"name\":\"wrong_storage\"");
    let project = Project::new(super::tests::binary());
    project.set_decompiler_options(Some(rampage_decompiler::DecompilerOptions {
        compiler: Some("invalid_projected_compiler".to_owned()),
        ..Default::default()
    }));
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Types, 1, Some(text)).unwrap();
    let error = validate_replay_source(&project, &annotations).unwrap_err().to_string();
    assert!(error.contains("consumer field name"), "{error}");
    assert!(project.annotation_list().types.is_empty());
    assert!(project.undo().unwrap().is_empty());
}
