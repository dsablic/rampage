#[test]
fn raw_propagation_rejects_implicit_darwin_instead_of_hashing_an_unrelated_default_model() {
    use rampage_decompiler::{DecompilerOptions, Platform};
    for (profile, compiler, bytes) in
        [(RawProfile::Msp430, "default", &[0x30, 0x41][..]), (RawProfile::Avr8, "gcc", &[0x08, 0x95][..])]
    {
        let project = project(profile, bytes, 0x1000, None, vec![0x1000]);
        let annotations = project.annotations();
        let default = DecompilerOptions::default();
        assert!(crate::propagation::source_fingerprint(&project, &default, &annotations).is_ok());
        let implicit = DecompilerOptions { platform: Platform::Darwin, ..Default::default() };
        let error = crate::propagation::source_fingerprint(&project, &implicit, &annotations).unwrap_err();
        assert!(error.to_string().contains("no Darwin compiler default"), "{error}");
        let explicit =
            DecompilerOptions { platform: Platform::Darwin, compiler: Some(compiler.into()), ..Default::default() };
        assert!(crate::propagation::source_fingerprint(&project, &explicit, &annotations).is_ok());
        let unreviewed =
            DecompilerOptions { platform: Platform::Darwin, compiler: Some("unreviewed".into()), ..Default::default() };
        assert!(crate::propagation::source_fingerprint(&project, &unreviewed, &annotations).is_err());
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    let native = Project::new(Binary::open(path).unwrap());
    let darwin = DecompilerOptions { platform: Platform::Darwin, ..Default::default() };
    assert!(crate::propagation::source_fingerprint(&native, &darwin, &native.annotations()).is_ok());
}

#[test]
fn propagation_fingerprints_separate_raw_entry_and_seed_interpretations_without_widening_c_admission() {
    let first = project(RawProfile::Msp430, &[0x30, 0x41], 0x1000, None, vec![0x1000]);
    let second = project(RawProfile::Msp430, &[0x30, 0x41], 0x1000, Some(0x1000), vec![0x1000]);
    let fingerprint = |project: &Project| {
        crate::propagation::source_fingerprint(
            project,
            &crate::decompile::default_options(&project.binary),
            &project.annotations(),
        )
        .unwrap()
    };
    assert_ne!(fingerprint(&first), fingerprint(&second));
    let no_seeds = project(RawProfile::Msp430, &[0x30, 0x41], 0x1000, None, vec![]);
    assert_ne!(fingerprint(&first), fingerprint(&no_seeds));
    let avr = project(RawProfile::Avr8, &[0x08, 0x95], 0x1000, None, vec![0x1000]);
    assert_ne!(fingerprint(&first), fingerprint(&avr));
    let mos6502 = project(RawProfile::Mos6502, &[0x60], 0x1000, None, vec![0x1000]);
    assert!(
        crate::propagation::source_fingerprint(
            &mos6502,
            &crate::decompile::default_options(&mos6502.binary),
            &mos6502.annotations(),
        )
        .is_err()
    );
    let unknown =
        rampage_decompiler::DecompilerOptions { compiler: Some("owned_unknown_alias".into()), ..Default::default() };
    assert!(crate::propagation::source_fingerprint(&first, &unknown, &first.annotations()).is_err());
}

use rampage_arch::{Arch, DecodeGateReason, Flow};
use rampage_decompiler::sleigh_decode::SleighDecoder;
use rampage_loaders::{Binary, RawCodeOptions, RawProfile};

use super::{analysis_binding, decoder_for_project, validate_raw_metadata};
use crate::search_code::{CodeImmediate, CodePattern, CodeReference, CodeSearchKind, CodeSearchQuery, CodeValue};
use crate::{ApiError, Project};

fn project(profile: RawProfile, bytes: &[u8], base: u64, entry: Option<u64>, seeds: Vec<u64>) -> Project {
    Project::new(Binary::from_raw_code(bytes.to_vec(), RawCodeOptions { profile, base, entry, seeds }).unwrap())
}

#[test]
fn actual_native_profile_metadata_matches_raw_admission() {
    let mut matches = Vec::new();
    for profile in RawProfile::ALL {
        let binary =
            Binary::from_raw_code(vec![0; 4], RawCodeOptions { profile, base: 0x1000, entry: None, seeds: vec![] })
                .unwrap();
        let decoder = SleighDecoder::open(profile.language_id()).unwrap();
        let matched = validate_raw_metadata(binary.raw_code_image().unwrap(), decoder.metadata()).is_ok();
        println!(
            "RAW_PROFILE_METADATA {}",
            serde_json::json!({
                "profile": profile.language_id(), "arch": profile.arch(), "admitted": profile.code_space(),
                "big_endian": profile.big_endian(), "code_big_endian": profile.code_big_endian(),
                "parallel_helper": profile.parallel_helper(), "native": decoder.metadata(), "exact_match": matched,
            })
        );
        assert_eq!(decoder.metadata().big_endian, binary.big_endian, "{profile:?}");
        assert_eq!(decoder.metadata().required_parallel_helper.as_deref(), profile.parallel_helper());
        matches.push(matched);
    }
    assert_eq!(matches.len(), RawProfile::ALL.len());
    assert!(matches.into_iter().all(|matched| matched), "all exact profile facts must match");
}

#[test]
fn ordinary_projects_follow_all_six_owned_function_extents_and_match_listing_search_summary() {
    for (profile, bytes, base, main_end, callee_end) in [
        (RawProfile::Msp430, &include_bytes!("../../../tests/fixtures/sleigh/msp430.bin")[..], 0x4400, 10, 20),
        (RawProfile::Avr8, &include_bytes!("../../../tests/fixtures/sleigh/avr8.bin")[..], 0x200, 10, 20),
        (RawProfile::Mos6502, &include_bytes!("../../../tests/fixtures/sleigh/6502.bin")[..], 0x8000, 8, 18),
    ] {
        let project = project(profile, bytes, base, Some(base), vec![]);
        let program = &project.analysis().unwrap().program;
        assert_eq!(program.functions.len(), 2, "{profile:?}");
        for (entry, expected_end) in [(base, base + main_end), (base + 16, base + callee_end)] {
            let function = program.function_at(entry).unwrap();
            assert_eq!(function.blocks.iter().map(|block| block.end).max(), Some(expected_end));
            let listing = project.function_listing(entry).unwrap();
            assert!(listing.blocks.iter().flatten().all(|line| line.decode_gate.is_none()));
            let summary = project.function_summary(entry).unwrap();
            assert!(!summary.graph.blocks.is_empty());
            assert!(summary.ir.is_empty());
            assert!(summary.ssa.is_none());
            assert!(summary.limitations.iter().any(|limit| limit.contains("structural flow only")));
        }
        let query = CodeSearchQuery::new(CodeSearchKind::Instruction {
            mnemonic: CodePattern::new("*").unwrap(),
            operands: None,
        })
        .unwrap();
        let report = project.search_code(&query).unwrap();
        assert!(report.scan_complete, "{report:?}");
        assert!(!report.total_is_lower_bound);
        let mut listing_addresses: Vec<_> = program
            .functions
            .iter()
            .flat_map(|function| {
                project
                    .function_listing(function.address)
                    .unwrap()
                    .blocks
                    .into_iter()
                    .flatten()
                    .map(|line| line.address)
            })
            .collect();
        listing_addresses.sort_unstable();
        listing_addresses.dedup();
        assert_eq!(report.hits.iter().map(|hit| hit.address).collect::<Vec<_>>(), listing_addresses);
        for hit in &report.hits {
            let line = project.disassemble(Some(&format!("{:#x}", hit.site)), 1).unwrap().remove(0);
            assert_eq!(hit.bytes, line.bytes);
            assert_eq!(hit.text, line.text);
            assert_eq!(hit.flow, line.flow);
        }
    }
}

#[test]
fn valid_unknown_seed_and_body_are_retained_without_successor_or_noreturn_claims() {
    for (bytes, gate_at, count) in
        [(&[0x00, 0x10, 0x08, 0x95][..], 0x1000, 1), (&[0x00, 0x00, 0x00, 0x10, 0x08, 0x95][..], 0x1002, 2)]
    {
        let project = project(RawProfile::Avr8, bytes, 0x1000, None, vec![0x1000]);
        let program = &project.analysis().unwrap().program;
        let function = program.function_at(0x1000).unwrap();
        assert_eq!(function.instruction_count, count);
        assert!(!function.contains(gate_at + 2));
        assert!(!program.inferred_noreturn.contains(&0x1000));
        assert!(!program.noreturn.contains(&0x1000));
        let gate = program.decode_gate_at(0x1000, gate_at).unwrap().gate;
        assert_eq!(gate.reason, DecodeGateReason::ContextMediatedFlow);
        let listing = project.disassemble(Some("0x1000"), 99).unwrap();
        assert_eq!(listing.len(), count);
        let last = listing.last().unwrap();
        assert_eq!(last.decode_gate, Some(gate));
        let wire = serde_json::to_value(last).unwrap();
        assert_eq!(wire["flow"]["kind"], "unknown");
        assert_eq!(wire["decode_gate"]["address"], format!("{gate_at:#x}"));
        let projected = crate::tool_views::project_tool_view(
            serde_json::to_value(&listing).unwrap(),
            crate::tool_views::ToolViewKind::Disassemble,
            crate::tool_views::ToolView::Summary,
        )
        .unwrap();
        assert!(projected.to_string().contains("\"decode_gate\""));
        assert!(projected.to_string().contains("\"unknown\""));
        assert!(!last.text.is_empty());
        assert_eq!(last.bytes, "0010");
        assert!(last.noreturn.is_none());
        let graph = project.function_graph(0x1000).unwrap();
        assert!(graph.edges.is_empty());
        let summary = project.function_summary(0x1000).unwrap();
        assert!(summary.limitations.iter().any(|limit| limit.contains("unknown successor flow")));
        let query = CodeSearchQuery::new(CodeSearchKind::Instruction {
            mnemonic: CodePattern::new("cpse").unwrap(),
            operands: None,
        })
        .unwrap();
        let report = project.search_code(&query).unwrap();
        assert_eq!(report.hits.len(), 1);
        assert_eq!(report.hits[0].decode_gate, Some(gate));
        let wire = serde_json::to_value(&report.hits[0]).unwrap();
        assert_eq!(wire["flow"]["kind"], "unknown");
        assert!(!report.scan_complete);
        assert!(report.total_is_lower_bound);
    }
}

#[test]
fn typed_search_refuses_even_when_no_instructions_were_seeded() {
    let value = CodeImmediate {
        value: CodeValue::Unsigned(0),
        width_bits: None,
        include_addresses: false,
        include_displacements: false,
    };
    for (profile, bytes) in [
        (RawProfile::Msp430, &[0x30, 0x41][..]),
        (RawProfile::Avr8, &[0x08, 0x95][..]),
        (RawProfile::Mos6502, &[0x60][..]),
    ] {
        for seeds in [vec![], vec![0x1000]] {
            let project = project(profile, bytes, 0x1000, None, seeds);
            for kind in [
                CodeSearchKind::Immediate(value.clone()),
                CodeSearchKind::FunctionsReferencing(CodeReference::Constant(value.clone())),
            ] {
                let query = CodeSearchQuery::new(kind).unwrap();
                assert!(matches!(project.search_code(&query), Err(ApiError::Unavailable(message))
                    if message.contains("typed operand evidence")));
            }
        }
    }
}

#[test]
fn real_project_code_highest_bytes_do_not_depend_on_a_c_pointer_default() {
    for (profile, bytes, base) in [
        (RawProfile::Msp430, &[0x30, 0x41][..], 0xfffe),
        (RawProfile::Avr8, &[0x08, 0x95][..], 0x1fffe),
        (RawProfile::Mos6502, &[0x60][..], 0xffff),
    ] {
        let project = project(profile, bytes, base, Some(base), vec![base]);
        assert_eq!(project.binary.arch.default_pointer_size(), None);
        let function = project.function_listing(base).unwrap();
        assert_eq!(function.blocks[0][0].flow, Flow::Return);
        assert_eq!(function.blocks[0][0].bytes, rampage_arch::hex::bytes(bytes));
        assert_eq!(project.analysis().unwrap().program.functions[0].blocks[0].end, base + bytes.len() as u64);
        assert!(project.inspect_data(&crate::DataQuery { address: base, size: 1, word_size: Some(4) }).is_err());
    }
}

#[test]
fn direct_and_configured_worker_raw_c_stay_explicitly_refused_before_native_preparation() {
    for (profile, bytes) in [
        (RawProfile::Msp430, &[0x30, 0x41][..]),
        (RawProfile::Avr8, &[0x08, 0x95][..]),
        (RawProfile::Mos6502, &[0x60][..]),
    ] {
        for worker in [None, Some(rampage_decompiler::worker::WorkerConfig::default())] {
            let project = project(profile, bytes, 0x1000, Some(0x1000), vec![0x1000]);
            project.set_decompiler_worker(worker);
            let error = project.decompile(0x1000).unwrap_err();
            assert!(error.to_string().contains("Raw native memory admission"), "{profile:?}: {error}");
        }
    }
}

#[test]
fn matching_profile_does_not_excuse_any_translator_fact_mismatch() {
    let hexagon_helper = RawProfile::Hexagon.parallel_helper().unwrap();
    for profile in RawProfile::ALL {
        let binary =
            Binary::from_raw_code(vec![0; 4], RawCodeOptions { profile, base: 0x1000, entry: None, seeds: vec![] })
                .unwrap();
        let raw = binary.raw_code_image().unwrap();
        let decoder = SleighDecoder::open(profile.language_id()).unwrap();
        let original = decoder.metadata();
        assert!(validate_raw_metadata(raw, original).is_ok());
        for dimension in 0..12 {
            let mut changed = original.clone();
            let code = changed.spaces.iter_mut().find(|space| space.id == changed.code_space).unwrap();
            match dimension {
                0 => code.kind ^= 1,
                1 => code.name.push('_'),
                2 => code.address_size += 1,
                3 => code.word_size += 1,
                4 => code.highest -= 1,
                5 => changed.profile.push('_'),
                6 => changed.alignment_bytes += 1,
                7 => changed.required_parallel_helper = Some("unimplemented helper".into()),
                8 => changed.spaces.clear(),
                9 => changed.big_endian ^= true,
                10 => changed.code_big_endian ^= true,
                // Only the declared helper is admitted: Hexagon without it, or any other profile with it.
                11 if profile.parallel_helper().is_some() => changed.required_parallel_helper = None,
                11 => changed.required_parallel_helper = Some(hexagon_helper.into()),
                _ => unreachable!(),
            }
            assert!(validate_raw_metadata(raw, &changed).is_err(), "{profile:?}/{dimension}");
        }
    }
}

#[test]
fn raw_binding_separates_interpretations_and_cached_analysis_rechecks_drift() {
    let mut original = project(RawProfile::Mos6502, &[0x60, 0x60], 0x1000, None, vec![0x1000]);
    let other = project(RawProfile::Mos6502, &[0x60, 0x60], 0x1000, Some(0x1000), vec![0x1000]);
    assert_ne!(analysis_binding(&original.binary).unwrap(), analysis_binding(&other.binary).unwrap());
    original.analysis().unwrap();
    original.binary.entry = Some(0x1000);
    assert!(original.analysis().is_err());
    assert!(decoder_for_project(&original.binary).is_err());
    assert!(original.disassemble(Some("0x1000"), 1).is_err());
}

#[test]
fn native_fourteen_keep_their_native_selector_and_raw_is_not_inferred_from_an_arch() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    let mut binary = Binary::open(path).unwrap();
    assert_eq!(analysis_binding(&binary).unwrap(), None);
    let mut decoder = decoder_for_project(&binary).unwrap();
    assert_eq!(decoder.decode(&[0xc3], 0x1000).flow, Flow::Return);
    for arch in Arch::ALL.into_iter().skip(14) {
        binary.arch = arch;
        assert!(decoder_for_project(&binary).is_err());
    }
}
