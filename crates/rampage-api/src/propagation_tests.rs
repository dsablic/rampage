use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_decompiler::results::StorageKind;

use super::*;

const SINK: u64 = 0x201160;
const CALLER: u64 = 0x201170;
const WRAPPER: u64 = 0x201180;
const FACTORY: u64 = 0x20118c;
const RETURN_CALLER: u64 = 0x201190;
const TYPES: &str = "struct PropState { int4 gain; int4 bias; }; struct OtherState { int4 first; int4 second; };";

fn new_project(annotations: Annotations) -> Project {
    let binary = rampage_loaders::Binary::from_snapshot_bytes(
        include_bytes!("../../../tests/data/type-propagation-x64.snapshot.json").to_vec(),
    )
    .unwrap();
    Project::with_annotations(binary, annotations)
}

fn request(address: u64, apply: bool) -> PropagationRequest {
    PropagationRequest {
        address,
        apply,
        max_functions: MAX_PROPAGATION_FUNCTIONS,
        max_candidates: MAX_PROPAGATION_CANDIDATES,
    }
}

fn parameter(index: u32) -> TypeHintTarget {
    TypeHintTarget::Parameter {
        index,
        storage: VariableStorage {
            kind: StorageKind::Processor,
            space: "register".into(),
            address: 0x38,
            size: 8,
            use_ranges: Vec::new(),
        },
    }
}

fn pointer(name: &str) -> TypeInfo {
    TypeInfo { name: format!("{name} *"), size: 8 }
}

fn explicit_native_snapshot(project: &Project, address: u64) -> crate::Decompilation {
    let state = project.decompiler.lock().unwrap();
    let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&project.binary));
    let annotations = without_hints(&project.annotations()).unwrap();
    project.decompile_annotation_candidate(&state, &options, &annotations, address).unwrap()
}

#[test]
fn fingerprints_require_reviewed_exact_c_models_and_distinguish_selected_compilers() {
    let project = new_project(Annotations::in_memory());
    let annotations = project.annotations();
    let default = DecompilerOptions::default();
    let windows = DecompilerOptions { compiler: Some("windows".into()), ..Default::default() };
    assert_ne!(
        source_fingerprint(&project, &default, &annotations).unwrap(),
        source_fingerprint(&project, &windows, &annotations).unwrap(),
    );
    let unknown = DecompilerOptions { compiler: Some("unknown".into()), ..Default::default() };
    assert!(matches!(
        source_fingerprint(&project, &unknown, &annotations),
        Err(ApiError::Invalid(message)) if message.contains("reviewed C data organization")
    ));
}

#[test]
fn unavailable_c_model_skips_only_automatic_context_and_withholds_durable_hints() {
    let project = new_project(Annotations::in_memory());
    let options = DecompilerOptions { compiler: Some("golang".into()), ..Default::default() };
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Signature, FACTORY, Some("uint8 owned_factory(uint8 value);".into())).unwrap();
    let payload = TypeHintAnnotation {
        source_fingerprint: "0".repeat(64),
        hints: vec![DerivedTypeHint { target: TypeHintTarget::Return, data_type: "uint8".into(), evidence: vec![] }],
    };
    annotations.set(Field::TypeHint, FACTORY, Some(encode_type_hints(&payload).unwrap())).unwrap();
    let revision = annotations.revision();
    let mut state = project.decompiler.lock().unwrap();
    let (ordinary, limitations) = lazy_context_with_fingerprint(
        &project,
        &mut state,
        &options,
        &annotations,
        FACTORY,
        &std::sync::atomic::AtomicBool::new(false),
        || fingerprint_availability(&project, &options, &annotations),
    )
    .unwrap();
    assert_eq!(ordinary.signatures(), annotations.signatures());
    assert_eq!(ordinary.type_hints(), annotations.type_hints());
    assert!(limitations.iter().any(|reason| reason.contains("durable derived hints withheld")));
    assert!(state.propagation_cache.is_none());
    let (hints, limitations) = replay_hints(&project, &options, &annotations, Some(FACTORY)).unwrap();
    assert!(hints.is_empty());
    assert!(limitations.iter().any(|reason| reason.contains("durable derived hints withheld")));
    assert!(std::sync::Arc::ptr_eq(&revision, &annotations.revision()));
    assert!(source_fingerprint(&project, &options, &annotations).is_err());
}

fn check_go_explicit_typing_without_automatic_c_model(worker: Option<rampage_decompiler::worker::WorkerConfig>) {
    let log = LogFixture::new();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-go-x64.elf");
    let project = Project::with_annotations(rampage_loaders::Binary::open(path).unwrap(), log.annotations());
    project.set_decompiler_worker(worker);
    let greet = project.resolve("main.greet").unwrap();
    project.set_signature(greet, Some("int8 greet(int8 who);")).unwrap();
    let original = project.decompile(greet).unwrap();
    assert!(original.language_id.ends_with(":golang"));
    let storage = VariableStorage::try_from(&original.structure.signature.parameters[0].storage).unwrap();
    project
        .edit_variable(
            greet,
            &crate::VariableEditRequest {
                storage: Some(storage),
                data_type: Some("int8".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let data = project
        .binary
        .segments
        .iter()
        .find(|segment| {
            segment.perms.read
                && segment.perms.write
                && !segment.perms.execute
                && segment.file_size >= 2
                && !project.binary.is_code(segment.address)
        })
        .unwrap()
        .address;
    project.set_global(data, Some("uint1 owned_go_byte;")).unwrap();
    project
        .apply_data_type(
            data + 1,
            &crate::ApplyDataTypeRequest {
                encoding: Some(crate::DataStringEncoding::Ascii),
                byte_length: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
    let annotations = project.annotations();
    assert!(!annotations.signatures().is_empty());
    assert!(!annotations.local_types().is_empty());
    assert!(!annotations.globals().is_empty());
    assert!(!annotations.data_types().is_empty());
    assert!(annotations.type_hints().is_empty());
    drop(annotations);
    let before = log.bytes();
    let revision = project.annotation_revision().unwrap();
    let output = project.decompile(greet).unwrap();
    assert!(output.language_id.ends_with(":golang"));
    assert!(output.code.contains("int8 main.greet(int8 who)"), "{}", output.code);
    assert!(serde_json::to_string(&output.structure).unwrap().contains("automatic type propagation omitted"));
    for apply in [false, true] {
        let error = project
            .propagate_types_with_preflight(&request(greet, apply), |_| {
                panic!("unavailable propagation must refuse before preflight or append")
            })
            .unwrap_err();
        assert!(error.to_string().contains("no reviewed C data organization"), "{error}");
        assert_eq!(log.bytes(), before);
        assert!(project.annotations().type_hints().is_empty());
        assert!(std::sync::Arc::ptr_eq(&revision, &project.annotation_revision().unwrap()));
    }
}

#[test]
fn go_explicit_typing_without_durable_hints_keeps_direct_decompilation() {
    check_go_explicit_typing_without_automatic_c_model(None);
}

#[test]
fn go_explicit_typing_without_durable_hints_keeps_worker_decompilation() {
    let Some(executable) = std::env::var_os("RAMPAGE_TEST_DECOMPILER_WORKER") else { return };
    check_go_explicit_typing_without_automatic_c_model(Some(rampage_decompiler::worker::WorkerConfig {
        executable: Some(PathBuf::from(executable)),
        ..Default::default()
    }));
}

#[test]
fn equal_sources_merge_provenance_and_conflicting_sources_remain_distinct() {
    let mut graph = Graph::default();
    let first = graph.node(0x1000, parameter(0), 8, true).unwrap();
    let second = graph.node(0x2000, parameter(0), 8, true).unwrap();
    let target = graph.node(0x3000, parameter(0), 8, false).unwrap();
    graph.seed(first, &pointer("PropState"), 0x1000, "explicit analyst local type");
    graph.seed(second, &pointer("PropState"), 0x2000, "explicit analyst signature parameter");
    graph.link(first, target, 0x3000, 0x3010, "callee parameter to caller argument");
    graph.link(second, target, 0x3000, 0x3020, "callee parameter to caller argument");
    graph.solve();
    assert_eq!(graph.nodes[target].facts.len(), 1);
    let evidence = &graph.nodes[target].facts["PropState *"];
    assert!(evidence.iter().any(|item| item.function == 0x1000));
    assert!(evidence.iter().any(|item| item.function == 0x2000));
    graph.seed(second, &pointer("OtherState"), 0x2000, "explicit analyst local type");
    graph.solve();
    assert_eq!(graph.nodes[target].facts.len(), 2);
}

#[test]
fn analyst_targets_block_incoming_facts_but_remain_sources() {
    let mut graph = Graph::default();
    let source = graph.node(0x1000, parameter(0), 8, true).unwrap();
    let owner = graph.node(0x2000, parameter(0), 8, true).unwrap();
    let destination = graph.node(0x3000, parameter(0), 8, false).unwrap();
    graph.seed(source, &pointer("PropState"), 0x1000, "explicit analyst signature parameter");
    graph.seed(owner, &pointer("OtherState"), 0x2000, "explicit analyst local type");
    graph.link(source, owner, 0x2000, 0x2010, "callee parameter to caller argument");
    graph.link(owner, destination, 0x3000, 0x3010, "caller argument to callee parameter");
    graph.solve();
    assert!(!graph.nodes[owner].facts.contains_key("PropState *"));
    assert!(graph.nodes[owner].rejected.contains_key("PropState *"));
    assert!(graph.nodes[destination].facts.contains_key("OtherState *"));
    assert!(!graph.nodes[destination].facts.contains_key("PropState *"));
    assert_eq!(graph.skipped.len(), 1);
}

#[test]
fn native_target_budget_fails_closed_before_allocating_unbounded_candidates() {
    let mut graph = Graph::default();
    for address in 0..MAX_PROPAGATION_CANDIDATES {
        graph.node(address as u64, TypeHintTarget::Return, 8, false).unwrap();
    }
    assert!(graph.node(u64::MAX, TypeHintTarget::Return, 8, false).is_err());
}

#[test]
fn matching_widths_and_surviving_storage_do_not_make_an_ignored_hint_successful() {
    let mut structure = StructuredResult::empty();
    structure.signature.return_type = TypeInfo { name: "uint8".into(), size: 8 };
    let hint = DerivedTypeHint { target: TypeHintTarget::Return, data_type: "uint8 *".into(), evidence: Vec::new() };
    let error = validate_hint_targets(&[hint], 0x1000, &structure).unwrap_err();
    assert!(error.to_string().contains("type was not retained"));
}

#[test]
fn automatic_fingerprint_failures_are_fatal_and_do_not_strip_durable_hints_or_publish_cache() {
    let project = new_project(Annotations::in_memory());
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Signature, FACTORY, Some("uint8 owned_factory(uint8 value);".into())).unwrap();
    annotations
        .set(
            Field::TypeHint,
            FACTORY,
            Some(
                encode_type_hints(&TypeHintAnnotation {
                    source_fingerprint: "0".repeat(64),
                    hints: vec![DerivedTypeHint {
                        target: TypeHintTarget::Return,
                        data_type: "int4".into(),
                        evidence: Vec::new(),
                    }],
                })
                .unwrap(),
            ),
        )
        .unwrap();
    let mut state = project.decompiler.lock().unwrap();
    let options = DecompilerOptions { compiler: Some("golang".into()), ..Default::default() };
    let durable = annotations.type_hints().clone();
    let signatures = annotations.signatures().clone();
    for error in [
        ApiError::Invalid("mapped source changed".into()),
        ApiError::Invalid("bundled manifest mismatches retained specification files".into()),
        ApiError::Unavailable("specification attestation unavailable".into()),
    ] {
        let kind = std::mem::discriminant(&error);
        let message = error.to_string();
        let result = lazy_context_with_fingerprint(
            &project,
            &mut state,
            &options,
            &annotations,
            FACTORY,
            &std::sync::atomic::AtomicBool::new(false),
            || Err(error),
        );
        let actual = match result {
            Err(error) => error,
            Ok(_) => panic!("fingerprint failure was downgraded"),
        };
        assert_eq!(std::mem::discriminant(&actual), kind);
        assert_eq!(actual.to_string(), message);
        assert!(state.propagation_cache.is_none());
        assert_eq!(*annotations.type_hints(), durable);
        assert_eq!(*annotations.signatures(), signatures);
    }
}

#[test]
fn configured_external_specifications_skip_only_optional_auto_without_durable_hints() {
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Signature, FACTORY, Some("uint8 owned_factory(uint8 value);".into())).unwrap();
    let mut checked = false;
    let (ordinary, limitations) =
        automatic_specification_gate(&annotations, AutomaticSpecificationContext::ExternalOverride, || {
            checked = true;
            Ok(())
        })
        .unwrap()
        .unwrap();
    assert!(checked);
    assert_eq!(ordinary.signatures(), annotations.signatures());
    assert!(ordinary.type_hints().is_empty());
    assert!(limitations.iter().any(|limitation| limitation.contains("without a bundled fingerprint")));
    assert!(
        automatic_specification_gate(&annotations, AutomaticSpecificationContext::ExternalOverride, || Err(
            ApiError::Invalid("source changed before external-context omission".into())
        ))
        .is_err()
    );
    assert!(
        automatic_specification_gate(&annotations, AutomaticSpecificationContext::Bundled, || panic!(
            "bundled mode must use the strict fingerprint path"
        ))
        .unwrap()
        .is_none()
    );
    annotations
        .set(
            Field::TypeHint,
            FACTORY,
            Some(
                encode_type_hints(&TypeHintAnnotation {
                    source_fingerprint: "0".repeat(64),
                    hints: vec![DerivedTypeHint {
                        target: TypeHintTarget::Return,
                        data_type: "uint8".into(),
                        evidence: Vec::new(),
                    }],
                })
                .unwrap(),
            ),
        )
        .unwrap();
    let stored = annotations.type_hints().clone();
    assert!(
        automatic_specification_gate(&annotations, AutomaticSpecificationContext::ExternalOverride, || panic!(
            "durable hints must use strict attestation, not the external skip"
        ))
        .unwrap()
        .is_none()
    );
    assert_eq!(*annotations.type_hints(), stored);
}

#[test]
fn optional_context_rejection_is_typed_and_never_masks_original_or_transport_errors() {
    let refusal = concat!(
        "Unsupported native callee hint context: ",
        "Unsupported native hint: whole symbol mapping did not survive",
    );
    let original = Annotations::in_memory();
    let candidate = Annotations::in_memory();
    let selector_refusal = concat!(
        "Unsupported native callee hint context: ",
        "Local variable storage selector did not match a recovered symbol",
    );
    assert!(matches!(
        crate::decompile::hint_context_error(selector_refusal),
        Some(ApiError::NativeTypeHintUnsupported(_))
    ));
    assert!(
        crate::decompile::hint_context_error("Local variable storage selector did not match a recovered symbol")
            .is_none()
    );
    let mut calls = 0;
    let limitation = validate_automatic_context(&original, &candidate, |_| {
        calls += 1;
        if calls == 1 { Ok(()) } else { Err(crate::decompile::hint_context_error(refusal).unwrap()) }
    })
    .unwrap();
    assert!(limitation.unwrap().contains("ordinary explicit/durable context retained"));
    for error in [
        ApiError::Unavailable("worker timed out".into()),
        ApiError::Unavailable("decompilation cancelled".into()),
        ApiError::Unavailable(refusal.into()),
        ApiError::Invalid("hard local selector is invalid".into()),
        ApiError::Unavailable("native cleanup failed; poisoned handle".into()),
    ] {
        let mut calls = 0;
        let mut error = Some(error);
        assert!(
            validate_automatic_context(&original, &candidate, |_| {
                calls += 1;
                if calls == 1 { Ok(()) } else { Err(error.take().unwrap()) }
            })
            .is_err()
        );
    }
    let mut calls = 0;
    assert!(
        validate_automatic_context(&original, &candidate, |_| {
            calls += 1;
            Err(crate::decompile::hint_context_error(refusal).unwrap())
        })
        .is_err()
    );
    assert_eq!(calls, 1, "an invalid original durable context is not optional");
    let mut calls = 0;
    let omitted = validate_automatic_context(&original, &candidate, |_| {
        calls += 1;
        if calls == 1 { Ok(()) } else { Err(crate::decompile::hint_context_error(selector_refusal).unwrap()) }
    })
    .unwrap();
    assert!(omitted.unwrap().contains("ordinary explicit/durable context retained"));
    assert!(
        validate_automatic_context(&original, &candidate, |_| Err(crate::decompile::hint_context_error(
            selector_refusal
        )
        .unwrap()))
        .is_err()
    );
    assert!(
        crate::decompile::hint_context_error("Unsupported native callee hint context: memory corruption").is_none()
    );
    let retention = "Unsupported native soft hint: unlocked type was not retained by analysis";
    assert!(matches!(crate::decompile::hint_context_error(retention), Some(ApiError::NativeTypeHintUnsupported(_))));
    assert!(matches!(
        crate::decompile::hint_context_error(&format!(
            "decompiler: Unsupported native callee hint context: {retention}"
        )),
        Some(ApiError::NativeTypeHintUnsupported(_))
    ));
    assert!(crate::decompile::hint_context_error("Unsupported native soft hint: handle corrupted").is_none());
}

#[test]
fn ordinary_wrapper_survives_unsupported_ephemeral_context_and_keeps_hard_types() {
    let project = new_project(Annotations::in_memory());
    project.set_types(SINK, Some(TYPES)).unwrap();
    let before = project.decompile(WRAPPER).unwrap();
    let sink = project.decompile(SINK).unwrap();
    let storage = VariableStorage::try_from(&sink.structure.signature.parameters[0].storage).unwrap();
    project
        .edit_variable(
            SINK,
            &crate::VariableEditRequest {
                storage: Some(storage.clone()),
                data_type: Some("PropState *".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let hard = project.annotations().local_types().clone();
    let wrapper = project.decompile(WRAPPER).unwrap();
    assert_eq!(wrapper.code, before.code);
    assert!(!wrapper.code.contains("PropState"), "{}", wrapper.code);
    assert!(
        wrapper
            .structure
            .diagnostics
            .as_ref()
            .unwrap()
            .warnings
            .iter()
            .any(|warning| warning.message.contains("optional automatic type context omitted")),
        "{wrapper:#?}"
    );
    assert_eq!(*project.annotations().local_types(), hard);
    assert!(project.annotations().type_hints().is_empty());
    assert!(project.decompile(SINK).unwrap().code.contains("->gain"));

    let options = crate::decompile::default_options(&project.binary);
    let fingerprint = source_fingerprint(&project, &options, &project.annotations()).unwrap();
    let invalid = encode_type_hints(&TypeHintAnnotation {
        source_fingerprint: fingerprint,
        hints: vec![DerivedTypeHint {
            target: TypeHintTarget::Local {
                storage: VariableStorage {
                    kind: StorageKind::Processor,
                    space: "register".into(),
                    address: 0x4000,
                    size: 8,
                    use_ranges: Vec::new(),
                },
            },
            data_type: "uint8".into(),
            evidence: Vec::new(),
        }],
    })
    .unwrap();
    project.annotations.write().unwrap().set(Field::TypeHint, WRAPPER, Some(invalid.clone())).unwrap();
    assert!(project.decompile(WRAPPER).is_err(), "a durable invalid hint must still refuse ordinary decompilation");
    assert_eq!(project.annotations().type_hints()[&WRAPPER], invalid);
    assert_eq!(*project.annotations().local_types(), hard);
}

#[test]
fn rejected_candidate_cannot_poison_independent_candidates_or_reenter_bootstrap() {
    let proposals: DerivedHints = [
        (
            SINK,
            vec![DerivedTypeHint {
                target: TypeHintTarget::Return,
                data_type: "RejectedType *".into(),
                evidence: Vec::new(),
            }],
        ),
        (
            FACTORY,
            vec![DerivedTypeHint { target: TypeHintTarget::Return, data_type: "uint8".into(), evidence: Vec::new() }],
        ),
    ]
    .into_iter()
    .collect();
    let selected = select_native_candidates(&Annotations::in_memory(), &"0".repeat(64), &proposals, |candidate, _| {
        if candidate.type_hints().contains_key(&SINK) {
            return Err(ApiError::NativeTypeHintUnsupported("model rejects candidate type".into()));
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(selected.retained, BTreeSet::from([FACTORY]));
    assert!(selected.rejected.contains_key(&SINK));
    let retained: Vec<_> = proposals
        .iter()
        .filter(|(function, _)| selected.retained.contains(*function))
        .flat_map(|(&function, hints)| {
            hints.iter().map(move |hint| PropagationCandidate {
                function,
                target: hint.target.clone(),
                data_type: hint.data_type.clone(),
                evidence: hint.evidence.clone(),
            })
        })
        .collect();
    let bootstrap = candidate_operations(&retained);
    assert_eq!(bootstrap.len(), 1);
    assert!(matches!(bootstrap[0], rampage_decompiler::worker::WorkerOperation::TypeHints { address: FACTORY, .. }));
}

fn fatal_probe_errors() -> Vec<ApiError> {
    vec![
        ApiError::Unavailable("worker transport failed".into()),
        ApiError::Unavailable("worker protocol response invalid".into()),
        ApiError::Unavailable("worker timed out".into()),
        ApiError::Unavailable("decompilation cancelled".into()),
        ApiError::Unavailable("native handle poisoned after corruption".into()),
        ApiError::Invalid("unclassified native failure mapped to Invalid".into()),
        ApiError::Unavailable(
            concat!(
                "Unsupported native callee hint context: ",
                "Local variable storage selector did not match a recovered symbol"
            )
            .into(),
        ),
    ]
}

fn successful_probe_pass() -> NativePassResult {
    let candidates = vec![PropagationCandidate {
        function: FACTORY,
        target: TypeHintTarget::Return,
        data_type: "uint8".into(),
        evidence: Vec::new(),
    }];
    let bootstrap = candidate_operations(&candidates);
    let result = PropagationResult {
        address: FACTORY,
        source_fingerprint: "0".repeat(64),
        apply: false,
        persisted: false,
        hint_edits: Vec::new(),
        candidates,
        applied: Vec::new(),
        skipped: Vec::new(),
        conflicts: Vec::new(),
        limitations: Vec::new(),
        counts: PropagationCounts { functions: 2, candidates: 1, ..Default::default() },
    };
    (result, BTreeSet::from([FACTORY]), bootstrap)
}

#[test]
fn a_good_pass_never_turns_a_later_fatal_failure_into_partial_success() {
    for error in fatal_probe_errors() {
        let kind = std::mem::discriminant(&error);
        let expected = error.to_string();
        let mut error = Some(error);
        let mut calls = 0;
        let result = run_native_passes(2, None, |_| {
            calls += 1;
            if calls == 1 { Ok(successful_probe_pass()) } else { Err(error.take().unwrap()) }
        });
        let actual = result.unwrap_err();
        assert_eq!(std::mem::discriminant(&actual), kind);
        assert_eq!(actual.to_string(), expected);
        assert_eq!(calls, 2);
    }
}

#[test]
fn initial_native_faults_are_fatal_with_or_without_a_cancellation_pointer() {
    let cancellation = std::sync::atomic::AtomicBool::new(false);
    let functions = BTreeSet::from([SINK, FACTORY]);
    for pointer in [None, Some(&cancellation)] {
        for error in fatal_probe_errors() {
            let kind = std::mem::discriminant(&error);
            let expected = error.to_string();
            let mut error = Some(error);
            let mut calls = 0;
            let mut graph = Graph::default();
            let result = analyze_native_context(
                &functions,
                pointer,
                |_| {
                    calls += 1;
                    if calls == 1 { Ok(StructuredResult::empty()) } else { Err(error.take().unwrap()) }
                },
                &mut graph,
            );
            let actual = result.unwrap_err();
            assert_eq!(std::mem::discriminant(&actual), kind);
            assert_eq!(actual.to_string(), expected);
            assert!(graph.skipped.is_empty());
            assert_eq!(calls, 2);
        }
    }
}

#[test]
fn isolated_and_combined_candidate_probes_preserve_fatal_errors_after_a_good_candidate() {
    let proposals: DerivedHints = [SINK, FACTORY]
        .into_iter()
        .map(|function| {
            (
                function,
                vec![DerivedTypeHint {
                    target: TypeHintTarget::Return,
                    data_type: "uint8".into(),
                    evidence: Vec::new(),
                }],
            )
        })
        .collect();
    let annotations = Annotations::in_memory();
    let fingerprint = "0".repeat(64);
    for combined in [false, true] {
        for error in fatal_probe_errors() {
            let kind = std::mem::discriminant(&error);
            let expected = error.to_string();
            let mut error = Some(error);
            let mut calls = 0;
            let mut validate = |_: &Annotations, _: u64| {
                calls += 1;
                if calls == 1 { Ok(()) } else { Err(error.take().unwrap()) }
            };
            let actual = if combined {
                validate_combined_candidates(&annotations, &fingerprint, &mut proposals.clone(), &mut validate)
                    .unwrap_err()
            } else {
                select_native_candidates(&annotations, &fingerprint, &proposals, &mut validate).unwrap_err()
            };
            assert_eq!(std::mem::discriminant(&actual), kind);
            assert_eq!(actual.to_string(), expected);
            assert_eq!(calls, 2);
        }
    }
}

#[test]
fn source_fingerprint_ignores_names_comments_and_old_hints_but_tracks_explicit_typing() {
    let project = new_project(Annotations::in_memory());
    let options = crate::decompile::default_options(&project.binary);
    let mut annotations = Annotations::in_memory();
    let before = source_fingerprint(&project, &options, &annotations).unwrap();
    annotations.set(Field::Name, SINK, Some("renamed_sink".into())).unwrap();
    annotations.set(Field::Comment, SINK, Some("analyst note".into())).unwrap();
    let payload = TypeHintAnnotation {
        source_fingerprint: before.clone(),
        hints: vec![DerivedTypeHint { target: TypeHintTarget::Return, data_type: "int4".into(), evidence: Vec::new() }],
    };
    annotations.set(Field::TypeHint, CALLER, Some(encode_type_hints(&payload).unwrap())).unwrap();
    assert_eq!(before, source_fingerprint(&project, &options, &annotations).unwrap());
    let detached = without_hints(&annotations).unwrap();
    assert!(detached.type_hints().is_empty());
    assert!(!annotations.type_hints().is_empty());
    annotations.set(Field::Signature, SINK, Some("int4 sink(PropState *state, int4 value);".into())).unwrap();
    assert_ne!(before, source_fingerprint(&project, &options, &annotations).unwrap());
    let (hints, limitations) = replay_hints(&project, &options, &annotations, Some(CALLER)).unwrap();
    assert!(hints.is_empty());
    assert!(limitations.iter().any(|limitation| limitation.contains("stale derived type hints")));
}

#[test]
fn owned_snapshot_fingerprint_accepts_retained_bytes_and_tracks_capture_context() {
    let original = new_project(Annotations::in_memory());
    assert!(!original.binary.validate_available_backing_source().unwrap());
    let options = crate::decompile::default_options(&original.binary);
    let annotations = Annotations::in_memory();
    let fingerprint = source_fingerprint(&original, &options, &annotations).unwrap();
    let mut document: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../../tests/data/type-propagation-x64.snapshot.json")).unwrap();
    document["entry"] = serde_json::json!(format!("{WRAPPER:#x}"));
    let changed =
        Project::new(rampage_loaders::Binary::from_snapshot_bytes(serde_json::to_vec(&document).unwrap()).unwrap());
    assert_eq!(original.binary.image_bytes(), changed.binary.image_bytes());
    assert_ne!(fingerprint, source_fingerprint(&changed, &options, &annotations).unwrap());
    document["entry"] = serde_json::json!(format!("{CALLER:#x}"));
    document["provenance"] = serde_json::json!("same capture with a different descriptive note");
    let noted =
        Project::new(rampage_loaders::Binary::from_snapshot_bytes(serde_json::to_vec(&document).unwrap()).unwrap());
    assert_eq!(fingerprint, source_fingerprint(&noted, &options, &annotations).unwrap());
}

struct LogFixture(PathBuf);

impl LogFixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("rampage-propagation-api-{}-{index}.jsonl", std::process::id())))
    }

    fn annotations(&self) -> Annotations {
        Annotations::open_checked(self.0.clone()).unwrap()
    }
    fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.0).unwrap_or_default()
    }
    fn lock(&self) -> PathBuf {
        let mut path = self.0.as_os_str().to_owned();
        path.push(".lock");
        PathBuf::from(path)
    }
}

impl Drop for LogFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.lock());
    }
}

#[test]
fn preview_is_read_only_including_absent_log_and_lock_files() {
    let log = LogFixture::new();
    let project = new_project(log.annotations());
    let preview = project.propagate_types(&request(CALLER, false)).unwrap();
    assert_eq!(preview.counts.applied, 0);
    assert!(!log.0.exists());
    assert!(!log.lock().exists());
}

#[test]
fn preflight_rejection_rolls_back_the_complete_native_candidate() {
    let log = LogFixture::new();
    let project = new_project(log.annotations());
    project.set_types(SINK, Some(TYPES)).unwrap();
    project.set_signature(SINK, Some("int4 sink(PropState *state, int4 value);")).unwrap();
    let before = log.bytes();
    let revision = project.annotation_revision().unwrap();
    let error = project
        .propagate_types_with_preflight(&request(CALLER, true), |result| {
            assert!(!result.candidates.is_empty(), "{result:?}");
            Err(ApiError::Invalid("response refused before append".into()))
        })
        .unwrap_err();
    assert!(error.to_string().contains("response refused"));
    assert_eq!(log.bytes(), before);
    assert!(std::sync::Arc::ptr_eq(&revision, &project.annotation_revision().unwrap()));
    assert!(project.annotations().type_hints().is_empty());
}

fn check_smaller_context_history(worker: Option<rampage_decompiler::worker::WorkerConfig>) {
    let log = LogFixture::new();
    let project = new_project(log.annotations());
    project.set_decompiler_worker(worker);
    project.set_types(SINK, Some(TYPES)).unwrap();
    project.set_signature(SINK, Some("int4 sink(PropState *state, int4 value);")).unwrap();
    let initial = PropagationRequest { max_functions: 2, ..request(CALLER, true) };
    let large = project.propagate_types(&initial).unwrap();
    assert!(large.persisted && !large.hint_edits.is_empty(), "{large:?}");
    assert!(project.annotations().type_hints().contains_key(&CALLER));
    let small = PropagationRequest { max_functions: 1, ..request(CALLER, false) };
    let preview = project.propagate_types(&small).unwrap();
    assert!(preview.candidates.is_empty(), "{preview:?}");
    assert!(!preview.apply && !preview.persisted);
    let planned_edits = preview.hint_edits.len();
    assert!(planned_edits >= 1);
    assert_eq!(preview.counts.planned_hint_edits, planned_edits);
    assert_eq!(preview.counts.planned_hint_clears, planned_edits);
    assert_eq!(preview.counts.persisted_hint_edits, 0);
    let edit = preview.hint_edits.iter().find(|edit| edit.function == CALLER).unwrap();
    assert!(!edit.previous.as_ref().unwrap().hints.is_empty());
    assert!(edit.value.is_none());
    let before = log.bytes();
    let hints = project.annotations().type_hints().clone();
    assert!(!hints.contains_key(&WRAPPER));
    let revision = project.annotation_revision().unwrap();
    let apply = PropagationRequest { apply: true, ..small };
    let refused = project
        .propagate_types_with_preflight(&apply, |receipt| {
            assert_eq!(receipt.hint_edits, preview.hint_edits);
            assert!(receipt.apply && receipt.persisted);
            assert_eq!(receipt.counts.persisted_hint_edits, planned_edits);
            assert!(receipt.applied.is_empty());
            Err(ApiError::Invalid("review refuses payload removal".into()))
        })
        .unwrap_err();
    assert!(refused.to_string().contains("review refuses payload removal"));
    assert_eq!(log.bytes(), before);
    assert_eq!(*project.annotations().type_hints(), hints);
    assert!(std::sync::Arc::ptr_eq(&revision, &project.annotation_revision().unwrap()));
    let removed = project.propagate_types(&apply).unwrap();
    assert_eq!(removed.hint_edits, preview.hint_edits);
    assert!(removed.persisted && removed.applied.is_empty());
    assert_eq!(removed.counts.applied, 0);
    assert_eq!(removed.counts.persisted_hint_edits, planned_edits);
    assert!(!project.annotations().type_hints().contains_key(&CALLER));
    project.undo().unwrap();
    assert_eq!(*project.annotations().type_hints(), hints);
    project.redo().unwrap();
    let unchanged = project.propagate_types(&apply).unwrap();
    assert!(unchanged.hint_edits.is_empty());
    assert!(!unchanged.persisted);
    assert_eq!(unchanged.counts.planned_hint_edits, 0);
    assert_eq!(unchanged.counts.persisted_hint_edits, 0);
}

#[test]
fn smaller_context_reports_zero_candidate_clears_and_removal_preflight_is_atomic() {
    check_smaller_context_history(None);
}

#[test]
fn worker_smaller_context_clear_undo_redo_keeps_dependent_payloads_consistent() {
    let Some(executable) = std::env::var_os("RAMPAGE_TEST_DECOMPILER_WORKER") else { return };
    check_smaller_context_history(Some(rampage_decompiler::worker::WorkerConfig {
        executable: Some(PathBuf::from(executable)),
        ..Default::default()
    }));
}

#[test]
fn cross_context_hint_dependency_refuses_the_initial_clear_before_any_append() {
    let log = LogFixture::new();
    let project = new_project(log.annotations());
    project.set_types(SINK, Some(TYPES)).unwrap();
    project.set_signature(SINK, Some("int4 sink(PropState *state, int4 value);")).unwrap();
    let large = project.propagate_types(&request(CALLER, true)).unwrap();
    let hints = project.annotations().type_hints().clone();
    assert!(hints.contains_key(&CALLER) && hints.contains_key(&WRAPPER), "{large:?}");
    let small = PropagationRequest { max_functions: 1, ..request(CALLER, false) };
    let preview = project.propagate_types(&small).unwrap();
    assert!(preview.candidates.is_empty());
    assert_eq!(preview.hint_edits.len(), 1, "outside-context payloads must not be cascaded away");
    assert_eq!(preview.hint_edits[0].function, CALLER);
    assert!(preview.hint_edits[0].value.is_none());
    let before = log.bytes();
    let revision = project.annotation_revision().unwrap();
    let apply = PropagationRequest { apply: true, ..small };
    let error = project
        .propagate_types_with_preflight(&apply, |_| {
            panic!("unsafe candidate must be refused before response acceptance")
        })
        .unwrap_err();
    assert!(error.to_string().contains("retained hint-context validation"), "{error}");
    assert_eq!(log.bytes(), before);
    assert_eq!(*project.annotations().type_hints(), hints);
    assert!(std::sync::Arc::ptr_eq(&revision, &project.annotation_revision().unwrap()));
    project.undo().unwrap();
    assert!(project.annotations().type_hints().is_empty(), "refused clear must not add an undo step");
    project.redo().unwrap();
    assert_eq!(*project.annotations().type_hints(), hints);
}

#[test]
fn retained_outside_context_hint_is_natively_checked_when_the_budget_is_sufficient() {
    let log = LogFixture::new();
    let project = new_project(log.annotations());
    project.set_types(SINK, Some(TYPES)).unwrap();
    project.set_signature(SINK, Some("int4 sink(PropState *state, int4 value);")).unwrap();
    let native_factory = explicit_native_snapshot(&project, FACTORY);
    let storage = VariableStorage::try_from(&native_factory.structure.signature.parameters[0].storage).unwrap();
    let options = crate::decompile::default_options(&project.binary);
    let fingerprint = source_fingerprint(&project, &options, &project.annotations()).unwrap();
    let invalid = encode_type_hints(&TypeHintAnnotation {
        source_fingerprint: fingerprint,
        hints: vec![DerivedTypeHint {
            target: TypeHintTarget::Parameter { index: 99, storage },
            data_type: "PropState *".into(),
            evidence: Vec::new(),
        }],
    })
    .unwrap();
    project.annotations.write().unwrap().set(Field::TypeHint, FACTORY, Some(invalid)).unwrap();
    let (context, _) = call_context(&project, CALLER, MAX_PROPAGATION_FUNCTIONS).unwrap();
    assert!(!context.contains(&FACTORY));
    assert!(context.len() < MAX_PROPAGATION_FUNCTIONS);
    let before = log.bytes();
    let hints = project.annotations().type_hints().clone();
    let revision = project.annotation_revision().unwrap();
    let mut preflight_called = false;
    let error = project
        .propagate_types_with_preflight(&request(CALLER, true), |_| {
            preflight_called = true;
            Ok(())
        })
        .unwrap_err();
    assert!(!preflight_called);
    assert!(!error.to_string().contains("budget"), "{error}");
    assert!(error.to_string().contains("canonical target identity"), "{error}");
    assert_eq!(log.bytes(), before);
    assert_eq!(*project.annotations().type_hints(), hints);
    assert!(std::sync::Arc::ptr_eq(&revision, &project.annotation_revision().unwrap()));
    let undone = project.undo().unwrap();
    assert_eq!(undone.len(), 1, "refused apply must not create a history step");
    assert_eq!(undone[0].field, Field::TypeHint);
    assert_eq!(undone[0].address, FACTORY);
    assert!(project.annotations().type_hints().is_empty());
}

#[test]
fn payload_receipt_reports_partial_conflict_replacement_and_metadata_only_updates() {
    let project = new_project(Annotations::in_memory());
    project.set_types(SINK, Some(TYPES)).unwrap();
    project.set_signature(SINK, Some("int4 sink(PropState *state, int4 value);")).unwrap();
    project.propagate_types(&request(CALLER, true)).unwrap();
    let caller = explicit_native_snapshot(&project, CALLER);
    let storage = VariableStorage::try_from(&caller.structure.signature.parameters[0].storage).unwrap();
    project
        .edit_variable(
            CALLER,
            &crate::VariableEditRequest {
                storage: Some(storage.clone()),
                data_type: Some("OtherState *".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let partial = project.propagate_types(&request(CALLER, false)).unwrap();
    assert!(!partial.conflicts.is_empty(), "{partial:?}");
    let edit = partial.hint_edits.iter().find(|edit| edit.function == CALLER).unwrap();
    let previous = edit.previous.as_ref().unwrap();
    let next = edit.value.as_ref().unwrap();
    assert!(previous.hints.iter().any(|hint| matches!(&hint.target,
        TypeHintTarget::Parameter { index: 0, storage: old } if *old == storage)));
    assert!(!next.hints.iter().any(|hint| matches!(hint.target, TypeHintTarget::Parameter { index: 0, .. })));
    assert!(!next.hints.is_empty());
    let applied = project.propagate_types(&request(CALLER, true)).unwrap();
    assert_eq!(applied.hint_edits, partial.hint_edits);
    project.set_types(SINK, Some(&format!("{TYPES} typedef uint4 ReceiptTag;"))).unwrap();
    let metadata = project.propagate_types(&request(CALLER, false)).unwrap();
    let edit = metadata.hint_edits.iter().find(|edit| edit.function == CALLER).unwrap();
    let previous = edit.previous.as_ref().unwrap();
    let next = edit.value.as_ref().unwrap();
    assert_ne!(previous.source_fingerprint, next.source_fingerprint);
    assert_eq!(previous.hints, next.hints);
    assert!(metadata.counts.planned_hint_edits > 0);
    assert!(!metadata.persisted);
}

#[test]
fn redo_of_fresh_hint_only_state_validates_native_storage_before_append() {
    let log = LogFixture::new();
    let project = new_project(log.annotations());
    let options = crate::decompile::default_options(&project.binary);
    let fingerprint = source_fingerprint(&project, &options, &project.annotations()).unwrap();
    let value = encode_type_hints(&TypeHintAnnotation {
        source_fingerprint: fingerprint,
        hints: vec![DerivedTypeHint {
            target: TypeHintTarget::Local {
                storage: VariableStorage {
                    kind: StorageKind::Processor,
                    space: "register".into(),
                    address: 0x4000,
                    size: 8,
                    use_ranges: Vec::new(),
                },
            },
            data_type: "uint8".into(),
            evidence: Vec::new(),
        }],
    })
    .unwrap();
    project.annotations.write().unwrap().set(Field::TypeHint, FACTORY, Some(value)).unwrap();
    assert_eq!(project.undo().unwrap().len(), 1);
    assert!(project.annotations().type_hints().is_empty());
    let before = log.bytes();
    assert!(project.redo().is_err(), "a fresh fingerprint does not prove a native storage selector");
    assert_eq!(log.bytes(), before);
    assert!(project.annotations().type_hints().is_empty());
}

#[test]
fn direct_return_source_propagates_to_factory_without_hardening_its_signature() {
    let project = new_project(Annotations::in_memory());
    let before = project.decompile(FACTORY).unwrap();
    assert!(!before.structure.signature.return_type.name.contains("PropState"));
    project.set_types(SINK, Some(TYPES)).unwrap();
    project.set_signature(RETURN_CALLER, Some("PropState *return_caller(PropState *opaque);")).unwrap();
    let raw_caller = explicit_native_snapshot(&project, RETURN_CALLER);
    let raw_factory = explicit_native_snapshot(&project, FACTORY);
    let preview = project.propagate_types(&request(RETURN_CALLER, false)).unwrap();
    assert!(
        preview.candidates.iter().any(|candidate| candidate.function == FACTORY
            && candidate.target == TypeHintTarget::Return
            && candidate.data_type.contains("PropState")),
        "{preview:?}\nexplicit caller: {raw_caller:#?}\nexplicit factory: {raw_factory:#?}"
    );
    let applied = project.propagate_types(&request(RETURN_CALLER, true)).unwrap();
    assert!(applied.counts.applied > 0, "{applied:?}");
    assert!(!project.annotations().signatures().contains_key(&FACTORY));
    let factory = project.decompile(FACTORY).unwrap();
    assert!(factory.structure.signature.return_type.name.contains("PropState"), "{}", factory.code);
    assert!(factory.code.contains("PropState"), "{}", factory.code);
}

#[test]
fn void_pointer_input_and_state_pointer_return_preserve_ordinary_c_at_soft_refinement_boundary() {
    let project = new_project(Annotations::in_memory());
    project.set_types(SINK, Some(TYPES)).unwrap();
    project.set_signature(RETURN_CALLER, Some("PropState *return_caller(void *opaque);")).unwrap();
    let signatures = project.annotations().signatures().clone();
    let preview = project.propagate_types(&request(RETURN_CALLER, false)).unwrap();
    let applied = project.propagate_types(&request(RETURN_CALLER, true)).unwrap();
    assert_eq!(
        preview
            .candidates
            .iter()
            .map(|candidate| (candidate.function, target_key(&candidate.target), candidate.data_type.clone()))
            .collect::<Vec<_>>(),
        applied
            .candidates
            .iter()
            .map(|candidate| (candidate.function, target_key(&candidate.target), candidate.data_type.clone()))
            .collect::<Vec<_>>()
    );
    let caller = project.decompile(RETURN_CALLER).unwrap();
    let factory = project.decompile(FACTORY).unwrap();
    assert!(!caller.code.trim().is_empty() && !factory.code.trim().is_empty());
    assert!(caller.structure.signature.return_type.name.contains("PropState"), "{}", caller.code);
    assert_eq!(caller.structure.signature.parameters[0].data_type.name, "void *");
    assert_eq!(*project.annotations().signatures(), signatures);
    assert!(!project.annotations().signatures().contains_key(&FACTORY));
    assert!(project.annotations().local_types().is_empty());
    let returned = applied.candidates.iter().any(|candidate| {
        candidate.function == FACTORY
            && candidate.target == TypeHintTarget::Return
            && candidate.data_type.contains("PropState")
    });
    if returned {
        assert!(factory.structure.signature.return_type.name.contains("PropState"), "{}", factory.code);
    } else {
        assert!(
            !applied.conflicts.is_empty() || applied.skipped.iter().any(|skip| skip.function == FACTORY),
            "{applied:?}"
        );
        assert!(!applied.limitations.is_empty(), "{applied:?}");
        assert!(caller.structure.diagnostics.as_ref().unwrap().warnings.iter().any(|warning|
            warning.message.contains("native") || warning.message.contains("automatic type context")), "{caller:#?}");
        assert!(factory.structure.diagnostics.as_ref().unwrap().warnings.iter().any(|warning|
            warning.message.contains("native") || warning.message.contains("automatic type context")), "{factory:#?}");
    }
}

#[test]
fn explicit_callee_local_type_bootstraps_missing_caller_arguments_and_forward_wrapper() {
    let project = new_project(Annotations::in_memory());
    project.set_types(SINK, Some(TYPES)).unwrap();
    let sink = project.decompile(SINK).unwrap();
    let caller = project.decompile(CALLER).unwrap();
    assert!(caller.structure.signature.parameters.is_empty(), "{}", caller.code);
    let source = VariableStorage::try_from(&sink.structure.signature.parameters[0].storage).unwrap();
    let edited = project
        .edit_variable(
            SINK,
            &crate::VariableEditRequest {
                storage: Some(source),
                data_type: Some("PropState *".into()),
                name: Some("state".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(edited.decompilation.code.contains("state->gain"), "{}", edited.decompilation.code);
    let preview = project.propagate_types(&request(CALLER, false)).unwrap();
    assert!(
        preview.candidates.iter().any(|candidate| candidate.function == CALLER
            && matches!(candidate.target, TypeHintTarget::Parameter { index: 0, .. })
            && candidate.data_type.contains("PropState")),
        "{preview:?}"
    );
    let wrapper_supported = preview.candidates.iter().any(|candidate| {
        candidate.function == WRAPPER
            && matches!(candidate.target, TypeHintTarget::Parameter { index: 0, .. })
            && candidate.data_type.contains("PropState")
    });
    if !wrapper_supported {
        assert!(preview.skipped.iter().any(|skip| skip.function == WRAPPER), "{preview:?}");
        assert!(preview.limitations.iter().any(|limitation| limitation.contains("native")), "{preview:?}");
    }
    let result = project.propagate_types(&request(CALLER, true)).unwrap();
    assert!(result.counts.applied >= 1, "{result:?}");
    for function in [CALLER, WRAPPER] {
        if function == WRAPPER && !wrapper_supported {
            continue;
        }
        let rendered = project.decompile(function).unwrap();
        assert!(rendered.structure.signature.parameters[0].data_type.name.contains("PropState"), "{}", rendered.code);
        assert!(rendered.code.contains("PropState"), "{}", rendered.code);
        assert!(!project.annotations().signatures().contains_key(&function));
        assert!(!project.annotations().local_types().contains_key(&function));
    }
}

#[test]
fn explicit_caller_argument_changes_callee_fields_without_locking_the_callee_parameter() {
    let project = new_project(Annotations::in_memory());
    project.set_types(SINK, Some(TYPES)).unwrap();
    let sink = project.decompile(SINK).unwrap();
    let scalar = VariableStorage::try_from(&sink.structure.signature.parameters[1].storage).unwrap();
    project
        .edit_variable(
            SINK,
            &crate::VariableEditRequest {
                storage: Some(scalar.clone()),
                data_type: Some("int4".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let caller = project.decompile(CALLER).unwrap();
    let source = VariableStorage::try_from(&caller.structure.signature.parameters[0].storage).unwrap();
    project
        .edit_variable(
            CALLER,
            &crate::VariableEditRequest {
                storage: Some(source),
                data_type: Some("PropState *".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let hard = project.annotations().local_types().clone();
    let ordinary = project.decompile(CALLER).unwrap();
    assert!(ordinary.structure.signature.parameters[0].data_type.name.contains("PropState"), "{}", ordinary.code);
    assert!(
        ordinary
            .structure
            .diagnostics
            .as_ref()
            .unwrap()
            .warnings
            .iter()
            .any(|warning| warning.message.contains("storage selector")
                || warning.message.contains("native type context unavailable")),
        "{ordinary:#?}"
    );
    assert_eq!(*project.annotations().local_types(), hard);
    let applied = project.propagate_types(&request(CALLER, true)).unwrap();
    assert!(
        applied.candidates.iter().any(|candidate| candidate.function == SINK
            && matches!(candidate.target, TypeHintTarget::Parameter { index: 0, .. })
            && candidate.data_type.contains("PropState")),
        "{applied:?}"
    );
    let rendered = project.decompile(SINK).unwrap();
    assert!(rendered.code.contains("->gain") && rendered.code.contains("->bias"), "{}", rendered.code);
    let hard = parse_local_types(&project.annotations().local_types()[&SINK]).unwrap();
    assert_eq!(hard.len(), 1);
    assert_eq!(hard[0].storage, scalar);
    assert!(!project.annotations().signatures().contains_key(&SINK));
}

#[test]
fn explicit_factory_return_reaches_the_call_result_and_direct_return() {
    let project = new_project(Annotations::in_memory());
    let before = project.decompile(RETURN_CALLER).unwrap();
    project.set_types(SINK, Some(TYPES)).unwrap();
    project.set_signature(FACTORY, Some("PropState *factory(void *opaque);")).unwrap();
    let raw_caller = explicit_native_snapshot(&project, RETURN_CALLER);
    let raw_factory = explicit_native_snapshot(&project, FACTORY);
    let result = project.propagate_types(&request(RETURN_CALLER, true)).unwrap();
    assert!(
        result.candidates.iter().any(|candidate| candidate.function == RETURN_CALLER
            && candidate.target == TypeHintTarget::Return
            && candidate.data_type.contains("PropState")),
        "{result:?}\nexplicit caller: {raw_caller:#?}\nexplicit factory: {raw_factory:#?}"
    );
    let after = project.decompile(RETURN_CALLER).unwrap();
    assert_ne!(before.structure.signature.return_type, after.structure.signature.return_type);
    assert!(after.structure.signature.return_type.name.contains("PropState"), "{}", after.code);
    assert!(!project.annotations().signatures().contains_key(&RETURN_CALLER));
}

fn apply_replay_and_preserve(worker: Option<rampage_decompiler::worker::WorkerConfig>) -> serde_json::Value {
    let log = LogFixture::new();
    let project = new_project(log.annotations());
    project.set_decompiler_worker(worker.clone());
    project.set_types(SINK, Some(TYPES)).unwrap();
    project.set_signature(SINK, Some("int4 sink(PropState *state, int4 value);")).unwrap();
    let preview = project.propagate_types(&request(CALLER, false)).unwrap();
    assert!(!preview.candidates.is_empty(), "{preview:?}");
    let applied = project.propagate_types(&request(CALLER, true)).unwrap();
    assert!(applied.counts.applied > 0, "{applied:?}");
    let hints = project.annotations().type_hints().clone();
    let accepted = log.bytes();
    let repeated = project.propagate_types(&request(CALLER, true)).unwrap();
    assert_eq!(repeated.counts.applied, 0, "{repeated:?}");
    assert_eq!(log.bytes(), accepted);
    assert_eq!(serde_json::to_value(&repeated.candidates).unwrap(), serde_json::to_value(&applied.candidates).unwrap());
    assert!(!project.undo().unwrap().is_empty());
    assert!(project.annotations().type_hints().is_empty());
    assert!(!project.redo().unwrap().is_empty());
    assert_eq!(*project.annotations().type_hints(), hints);
    let reopened = new_project(log.annotations());
    reopened.set_decompiler_worker(worker);
    assert_eq!(*reopened.annotations().type_hints(), hints);
    let caller = reopened.decompile(CALLER).unwrap();
    assert!(
        caller.structure.signature.parameters.iter().any(|parameter| parameter.data_type.name.contains("PropState")),
        "{}",
        caller.code
    );
    reopened.set_signature(CALLER, Some("int4 owned_caller(OtherState *owner, int4 value);")).unwrap();
    let preserved = reopened.propagate_types(&request(CALLER, true)).unwrap();
    assert!(preserved.skipped.iter().any(|skip| skip.function == CALLER), "{preserved:?}");
    let caller = reopened.decompile(CALLER).unwrap();
    assert!(caller.structure.signature.parameters[0].data_type.name.contains("OtherState"), "{}", caller.code);
    assert!(!reopened.annotations().local_types().contains_key(&CALLER));
    serde_json::to_value(preview.candidates).unwrap()
}

#[test]
fn apply_rerun_undo_redo_reopen_and_analyst_conflicts_preserve_hard_types() {
    apply_replay_and_preserve(None);
}

#[test]
fn worker_and_native_preview_use_the_same_sources_storage_and_evidence() {
    let Some(executable) = std::env::var_os("RAMPAGE_TEST_DECOMPILER_WORKER") else { return };
    let native = apply_replay_and_preserve(None);
    let worker = apply_replay_and_preserve(Some(rampage_decompiler::worker::WorkerConfig {
        executable: Some(PathBuf::from(executable)),
        ..Default::default()
    }));
    assert_eq!(native, worker);
}

#[test]
fn shared_client_apply_recomputes_from_the_current_locked_source() {
    let log = LogFixture::new();
    let writer = new_project(log.annotations());
    writer.set_types(SINK, Some(TYPES)).unwrap();
    writer.set_signature(SINK, Some("int4 sink(PropState *state, int4 value);")).unwrap();
    let client = new_project(log.annotations());
    let stale = client.propagate_types(&request(CALLER, false)).unwrap();
    writer.set_signature(SINK, Some("int4 sink(OtherState *owner, int4 value);")).unwrap();
    let current = client.propagate_types(&request(CALLER, true)).unwrap();
    assert_ne!(stale.source_fingerprint, current.source_fingerprint);
    assert!(current.candidates.iter().any(|candidate| candidate.data_type.contains("OtherState")), "{current:?}");
    assert!(!current.candidates.iter().any(|candidate| candidate.data_type.contains("PropState")), "{current:?}");
}

#[test]
fn global_value_and_address_require_distinct_native_forms_even_when_all_widths_are_eight() {
    let mut annotations = Annotations::in_memory();
    annotations.set(Field::Global, 0x2000, Some("uint8 g;".into())).unwrap();
    let object = serde_json::json!({ "name": "uint8", "size": 8 });
    let mut value: CallValue = serde_json::from_value(serde_json::json!({
        "status": "global", "data_type": object, "symbol_type": object,
        "storage": null, "raw_storage": null, "display_name": "g", "type_locked": true,
        "global_address": 0x2000, "global_object_type": object, "global_type_locked": true
    }))
    .unwrap();
    assert_eq!(global_source_type(&annotations, &value).unwrap().1.name, "uint8");
    value.status = CallValueStatus::GlobalAddress;
    value.symbol_type = None;
    value.type_locked = false;
    value.data_type = Some(TypeInfo { name: "uint8 *".into(), size: 8 });
    assert_eq!(global_source_type(&annotations, &value).unwrap().1.name, "uint8 *");
    value.status = CallValueStatus::Global;
    value.symbol_type = Some(TypeInfo { name: "uint8".into(), size: 8 });
    value.type_locked = true;
    assert!(
        global_source_type(&annotations, &value).is_none(),
        "same-width transformed scalar is not a pointer source"
    );
    value.status = CallValueStatus::Computed;
    assert!(global_source_type(&annotations, &value).is_none());
}

fn global_value_address_project() -> Project {
    // Original source, analyzed only: consume_value(uint64_t x,int n){return x+n;}
    // consume_address(uint64_t *x,int n){return *x+n;} callers pass g and &g respectively, with n=1.
    let mut code: Vec<u8> = vec![0x48, 0x63, 0xc6, 0x48, 0x01, 0xf8, 0xc3];
    code.resize(0x20, 0x90);
    code.extend_from_slice(&[0x48, 0x63, 0xc6, 0x48, 0x03, 0x07, 0xc3]);
    code.resize(0x40, 0x90);
    code.extend_from_slice(&[0x48, 0x8b, 0x3d, 0xb9, 0x0f, 0, 0, 0xbe, 1, 0, 0, 0, 0xe8, 0xaf, 0xff, 0xff, 0xff, 0xc3]);
    code.resize(0x60, 0x90);
    code.extend_from_slice(&[0x48, 0x8d, 0x3d, 0x99, 0x0f, 0, 0, 0xbe, 1, 0, 0, 0, 0xe8, 0xaf, 0xff, 0xff, 0xff, 0xc3]);
    let code: String = code.iter().map(|byte| format!("{byte:02x}")).collect();
    let snapshot = serde_json::json!({
        "format": "rampage-snapshot-v1", "arch": "x86_64",
        "target": { "platform": "default", "compiler": "gcc" },
        "provenance": "Original scalar global value/address source in propagation_tests.rs; never executed",
        "entry": "0x1040", "seeds": ["0x1000", "0x1020", "0x1040", "0x1060"],
        "regions": [
            { "name": "owned-code", "address": "0x1000", "permissions": "r-x", "bytes": code },
            { "name": "owned-global", "address": "0x2000", "permissions": "rw-", "bytes": "0700000000000000" }
        ]
    });
    Project::new(rampage_loaders::Binary::from_snapshot_bytes(serde_json::to_vec(&snapshot).unwrap()).unwrap())
}

#[test]
fn native_global_value_vs_address_propagates_scalar_vs_pointer_not_just_matching_widths() {
    let project = global_value_address_project();
    for function in [0x1000, 0x1020] {
        let recovered = project.decompile(function).unwrap();
        let marker = VariableStorage::try_from(&recovered.structure.signature.parameters[1].storage).unwrap();
        project
            .edit_variable(
                function,
                &crate::VariableEditRequest {
                    storage: Some(marker),
                    data_type: Some("int4".into()),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    project.set_global(0x2000, Some("uint8 g;")).unwrap();
    for (caller, callee, pointer) in [(0x1040, 0x1000, false), (0x1060, 0x1020, true)] {
        let result = project.propagate_types(&request(caller, true)).unwrap();
        let candidate = result
            .candidates
            .iter()
            .find(|candidate| {
                candidate.function == callee && matches!(candidate.target, TypeHintTarget::Parameter { index: 0, .. })
            })
            .unwrap_or_else(|| panic!("native global source candidate: {result:?}"));
        assert_eq!(candidate.data_type.contains('*'), pointer, "{candidate:?}");
        assert!(candidate.evidence.iter().any(|evidence| evidence.reason.contains("global/data")), "{candidate:?}");
        let native = project.decompile(callee).unwrap();
        assert_eq!(native.structure.signature.parameters[0].data_type.name.contains('*'), pointer, "{}", native.code);
        assert!(!project.annotations().signatures().contains_key(&callee));
    }
}
