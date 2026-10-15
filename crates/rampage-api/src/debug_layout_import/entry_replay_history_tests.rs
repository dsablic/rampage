//! Wire under `project` so this regression can seed private caches without running discovery.

use super::*;
use crate::debug_layout_import::{LayoutBundle, image_digest, validate_entry_replay_source, validate_replay_source};
use rampage_analysis::discover::DiscoveredFunction;
use rampage_decompiler::layout::{
    LayoutField, LayoutOrganization, LayoutScalar, LayoutType, PlainStructLayout, ScalarKind,
};

#[test]
fn entry_source_validation_ignores_oversized_cached_program_and_go_inference_history() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/debug-x64.elf");
    let project = Project::new(Binary::open(fixture).unwrap());
    let layout = PlainStructLayout {
        name: "history_record".to_owned(),
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
    };
    let text = LayoutBundle::encode(&image_digest(&project).unwrap(), &[layout]).unwrap();
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Types, 0, Some(text.clone())).unwrap();
    validate_entry_replay_source(&project, &annotations).unwrap();
    validate_replay_source(&project, &annotations).unwrap();
    let functions = (0..16_385)
        .map(|address| DiscoveredFunction { address, blocks: Vec::new(), instruction_count: 0, switches: Vec::new() })
        .collect();
    project
        .analysis
        .set(Ok(Analysis {
            program: Program { functions, ..Default::default() },
            xrefs_by_source: Vec::new(),
            blocks: Vec::new(),
        }))
        .ok()
        .unwrap();
    project
        .go_prototypes
        .set(crate::decompile::GoPrototypes {
            declarations: std::collections::BTreeMap::from([(1, "void unrelated_cached_go(void);".to_owned())]),
            types: vec!["typedef int4 unrelated_cached_type;".to_owned()],
        })
        .ok()
        .unwrap();
    validate_entry_replay_source(&project, &annotations).unwrap();
    let legacy = validate_replay_source(&project, &annotations).unwrap_err().to_string();
    assert!(legacy.contains("symbol/function resolution"), "{legacy}");
    assert_eq!(annotations.types().get(&0), Some(&text));
    assert!(annotations.signatures().is_empty());
}
