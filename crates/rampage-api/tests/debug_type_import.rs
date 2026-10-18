use std::path::PathBuf;

use rampage_api::{ApiError, DebugTypesRequest, Project};
use rampage_loaders::Binary;

fn fixtures() -> Option<PathBuf> {
    std::env::var_os("RAMPAGE_DEBUG_TYPE_FIXTURES").map(PathBuf::from)
}

fn snapshot(project: &Project) -> serde_json::Value {
    serde_json::to_value(project.annotation_list()).unwrap()
}

#[test]
fn owned_debug_types_review_covers_the_whole_plan_and_preflight_rolls_back_every_edit() {
    let Some(root) = fixtures() else { return };
    for (image, pdb) in [
        ("debug-types-x64.elf", None),
        ("debug-types-arm64.elf", None),
        ("debug-types-cpp.exe", Some("debug-types-cpp.pdb")),
    ] {
        let project = Project::new(Binary::open(root.join(image)).unwrap());
        let mut request = DebugTypesRequest { pdb: pdb.map(|name| root.join(name)), limit: 1, ..Default::default() };
        let before = snapshot(&project);
        let first = project.import_debug_types(&request).unwrap_or_else(|error| panic!("{image}: preview: {error}"));
        assert!(first.applicable_types > 0, "{image}");
        assert!(first.applicable_signatures > 0, "{image}");
        assert_eq!(first.details.len(), 1);
        assert_eq!(snapshot(&project), before);
        request.offset = first.next_offset.unwrap();
        request.limit = 256;
        let later = project.import_debug_types(&request).unwrap_or_else(|error| panic!("{image}: later page: {error}"));
        assert!(
            later.details.iter().chain(first.details.iter()).any(|detail| {
                detail.producer["kind"]["values"]
                    .as_array()
                    .is_some_and(|values| values.iter().any(|entry| entry["value"] == "-3"))
                    && detail
                        .native
                        .as_ref()
                        .is_some_and(|native| native.enum_values.iter().any(|entry| entry.value == "-3"))
            }),
            "the owned {image} negative enum value must survive producer/native comparison"
        );
        if pdb.is_some() {
            let record = later
                .details
                .iter()
                .chain(first.details.iter())
                .find(|detail| {
                    detail.original_name.as_deref() == Some("DebugRecord")
                        && detail
                            .native
                            .as_ref()
                            .is_some_and(|native| native.kind == rampage_api::NamedTypeKind::Struct)
                })
                .expect("owned PDB complete DebugRecord must retain a native struct counterpart");
            let native = record.native.as_ref().unwrap();
            assert_eq!(native.size, Some(56));
            assert_eq!(
                native.fields.iter().map(|field| (field.name.as_str(), field.offset)).collect::<Vec<_>>(),
                [
                    ("identifier", 0),
                    ("nested", 4),
                    ("taps", 12),
                    ("mode", 28),
                    ("payload", 32),
                    ("next", 40),
                    ("callback", 48),
                ]
            );
            assert!(
                later.details.iter().chain(first.details.iter()).any(|detail| {
                    matches!(detail.producer["kind"]["convention"].as_str(), Some("cdecl" | "near_c" | "__cdecl"))
                        && detail.native.as_ref().and_then(|native| native.callback.as_ref()).is_some()
                }),
                "the raw CodeView convention must remain visible beside its measured native callback"
            );
        }
        assert_eq!(first.review_sha256, later.review_sha256);
        assert_eq!(first.applicable_types, later.applicable_types);
        request.apply = true;
        request.review_sha256 = Some(first.review_sha256.clone());
        let refused = project.import_debug_types_with_preflight(&request, |_| {
            Err(ApiError::Invalid("deliberate response-byte-budget rejection".into()))
        });
        assert!(refused.is_err());
        assert_eq!(snapshot(&project), before);
        assert!(project.undo().unwrap().is_empty());
        let applied = project.import_debug_types(&request).unwrap_or_else(|error| panic!("{image}: apply: {error}"));
        assert!(applied.applied);
        assert_eq!(applied.imported_types, first.applicable_types);
        let after = snapshot(&project);
        assert_eq!(after["debug_types"].as_array().unwrap().len(), 1);
        assert!(!after["type_library"].as_array().unwrap().is_empty());
        assert!(after["types"].as_array().unwrap().is_empty(), "legacy layout bundles must remain untouched");
        assert!(!project.undo().unwrap().is_empty());
        assert_eq!(snapshot(&project), before);
        assert!(!project.redo().unwrap().is_empty());
        assert_eq!(snapshot(&project), after);
    }
}

#[test]
fn owned_debug_types_unknown_alignment_and_bitfield_evidence_survive_preview_without_truncation() {
    let Some(root) = fixtures() else { return };
    let project = Project::new(Binary::open(root.join("debug-types-x64.elf")).unwrap());
    let preview = project.import_debug_types(&DebugTypesRequest { limit: 256, ..Default::default() }).unwrap();
    assert!(preview.details.iter().any(|detail| detail.applicable && detail.producer["alignment"].is_null()));
    let bits: Vec<_> = preview
        .details
        .iter()
        .filter(|detail| detail.original_name.as_deref().is_some_and(|name| name.contains("Bits")))
        .collect();
    assert!(!bits.is_empty());
    assert!(bits.iter().all(|detail| !detail.applicable && !detail.reasons.is_empty()));
    assert!(
        bits.iter().any(|detail| {
            detail
                .producer_evidence
                .as_ref()
                .and_then(|evidence| evidence["members"].as_array())
                .or_else(|| detail.producer["kind"]["members"].as_array())
                .is_some_and(|members| {
                    !members.is_empty()
                        && members.iter().any(|member| {
                            member["bitfield"]["bit_size"].as_u64().is_some()
                                && ["bit_offset", "data_bit_offset", "legacy_bit_offset"]
                                    .iter()
                                    .any(|key| member["bitfield"][*key].as_u64().is_some())
                        })
                })
        }),
        "unsupported bitfield records must expose retained members and raw bit-size/offset facts"
    );
}

#[test]
fn owned_c_pdb_forward_tags_without_unique_identity_remain_preview_only() {
    let Some(root) = fixtures() else { return };
    let project = Project::new(Binary::open(root.join("debug-types.exe")).unwrap());
    let preview = project
        .import_debug_types(&DebugTypesRequest {
            pdb: Some(root.join("debug-types.pdb")),
            limit: 256,
            ..Default::default()
        })
        .unwrap();
    assert!(
        preview.details.iter().any(|detail| {
            detail.original_name.as_deref().is_some_and(|name| name.contains("DebugRecord"))
                && !detail.applicable
                && detail.reasons.iter().any(|reason| reason.contains("forward") || reason.contains("unresolved"))
        }),
        "C tag display names alone must not establish forward/definition identity"
    );
    assert!(project.annotation_list().debug_types.is_empty());
    assert!(project.annotation_list().type_library.is_empty());
}
