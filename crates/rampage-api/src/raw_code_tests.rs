use super::*;

fn request(arch: Arch, mode: RawCodeMode) -> RawCodeRequest {
    RawCodeRequest {
        arch,
        mode,
        code_big_endian: false,
        data_big_endian: false,
        base_address: 0x1000,
        instruction_limit: 32,
    }
}

#[test]
fn owned_instruction_vectors_preserve_bytes_addresses_and_flow() {
    let vectors: &[(Arch, RawCodeMode, &[u8], &[usize])] = &[
        (Arch::X86, RawCodeMode::Native, &[0x90, 0xc3], &[1, 1]),
        (Arch::X86_64, RawCodeMode::Native, &[0x48, 0x89, 0xe5, 0xc3], &[3, 1]),
        (Arch::Arm, RawCodeMode::Arm, &[0x00, 0x00, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0xe1], &[4, 4]),
        (Arch::Arm, RawCodeMode::Thumb, &[0x00, 0xbf, 0x70, 0x47], &[2, 2]),
        (Arch::Aarch64, RawCodeMode::Native, &[0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6], &[4, 4]),
    ];
    for &(arch, mode, bytes, sizes) in vectors {
        let report = inspect_raw_code(bytes, &request(arch, mode)).unwrap();
        assert_eq!(report.stop_reason, RawCodeStopReason::WindowEnd, "{arch:?} {mode:?}");
        assert_eq!(report.consumed_bytes, bytes.len());
        assert_eq!(report.remaining_bytes, 0);
        assert_eq!(report.rows.last().unwrap().observation.flow, Flow::Return);
        let mut offset = 0;
        for (row, &size) in report.rows.iter().zip(sizes) {
            assert_eq!(row.window_byte_offset, offset);
            assert_eq!(row.observation.address, 0x1000 + offset as u64);
            assert_eq!(usize::from(row.observation.len), size);
            assert_eq!(row.bytes, rampage_arch::hex::bytes(&bytes[offset..offset + size]));
            assert!(!row.text.is_empty());
            offset += size;
        }
        assert_eq!(offset, bytes.len());
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["mapping_validation"], "analyst_asserted");
        assert_eq!(json["facts_interpretation"], "decoder_observations_not_proof");
        assert_eq!(json["rows"][0]["address"], "0x1000");
        assert!(serde_json::to_vec(&report).unwrap().len() <= MAX_RAW_CODE_RESULT_BYTES);
    }
}

#[test]
fn instruction_count_stops_before_decoding_the_next_instruction() {
    let mut limited = request(Arch::Arm, RawCodeMode::Arm);
    limited.instruction_limit = 1;
    let bytes = [0x00, 0x00, 0xa0, 0xe1, 0x00, 0x00, 0x9f, 0xe5];
    let report = inspect_raw_code(&bytes, &limited).unwrap();
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.stop_reason, RawCodeStopReason::InstructionLimit);
    assert_eq!((report.consumed_bytes, report.remaining_bytes), (4, 4));
}

#[test]
fn truncated_and_invalid_instructions_remain_unconsumed_without_cross_window_bytes() {
    let vectors: &[(Arch, RawCodeMode, &[u8], usize)] = &[
        (Arch::X86_64, RawCodeMode::Native, &[0x90, 0xe8, 0x00], 1),
        (Arch::X86_64, RawCodeMode::Native, &[0x0f], 0),
        (Arch::Arm, RawCodeMode::Thumb, &[0x00, 0xbf, 0x00, 0xf0], 2),
        (Arch::Arm, RawCodeMode::Thumb, &[0x00, 0xf0, 0x00], 0),
        (Arch::Arm, RawCodeMode::Thumb, &[0x00], 0),
        (Arch::Arm, RawCodeMode::Arm, &[0x00, 0x00, 0xa0], 0),
        (Arch::Aarch64, RawCodeMode::Native, &[0xff, 0xff, 0xff, 0xff], 0),
        (Arch::Aarch64, RawCodeMode::Native, &[0x1f, 0x20, 0x03], 0),
    ];
    for &(arch, mode, bytes, consumed) in vectors {
        let report = inspect_raw_code(bytes, &request(arch, mode)).unwrap();
        assert_eq!(report.stop_reason, RawCodeStopReason::InvalidOrIncompleteInstruction);
        assert_eq!(report.consumed_bytes, consumed, "{arch:?} {mode:?}");
        assert_eq!(report.remaining_bytes, bytes.len() - consumed);
    }
    // The backing array holds a complete call, but the borrowed window does not.
    let backing = [0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3];
    let report = inspect_raw_code(&backing[..4], &request(Arch::X86_64, RawCodeMode::Native)).unwrap();
    assert!(report.rows.is_empty());
    assert_eq!(report.remaining_bytes, 4);
}

#[test]
fn thumb2_wide_instruction_is_one_row_and_retains_explicit_mode() {
    let bytes = [0x40, 0xf2, 0x34, 0x20, 0x70, 0x47];
    let report = inspect_raw_code(&bytes, &request(Arch::Arm, RawCodeMode::Thumb)).unwrap();
    assert_eq!(report.rows.len(), 2);
    assert_eq!(report.rows[0].observation.len, 4);
    assert_eq!(report.rows[1].window_byte_offset, 4);
    assert_eq!(report.rows[1].observation.flow, Flow::Return);
}

#[test]
fn calls_branches_and_returns_do_not_redirect_the_linear_cursor() {
    let bytes = [0xe8, 0xfb, 0x6f, 0x00, 0x00, 0xeb, 0xf9, 0xc3, 0x90];
    let report = inspect_raw_code(&bytes, &request(Arch::X86_64, RawCodeMode::Native)).unwrap();
    assert_eq!(report.rows.iter().map(|row| row.window_byte_offset).collect::<Vec<_>>(), [0, 5, 7, 8]);
    assert_eq!(report.rows[0].observation.flow, Flow::Call(0x8000));
    assert_eq!(report.rows[1].observation.flow, Flow::Jump(0x1000));
    assert_eq!(report.rows[2].observation.flow, Flow::Return);
    assert_eq!(report.rows[3].observation.flow, Flow::Next);
    assert_eq!(report.consumed_bytes, bytes.len());
}

#[test]
fn calls_to_next_instruction_are_not_reclassified_by_get_pc_lookahead() {
    let report = inspect_raw_code(&[0xe8, 0, 0, 0, 0, 0x58], &request(Arch::X86_64, RawCodeMode::Native)).unwrap();
    assert_eq!(report.rows[0].observation.flow, Flow::Call(0x1005));
    let report = inspect_raw_code(
        &[0x01, 0x00, 0x00, 0x94, 0xe0, 0x03, 0x1e, 0xaa],
        &request(Arch::Aarch64, RawCodeMode::Native),
    )
    .unwrap();
    assert_eq!(report.rows[0].observation.flow, Flow::Call(0x1004));
}

#[test]
fn transfer_discards_aarch64_propagated_address_facts() {
    // ADRP x0, 0x1000; [B next]; ADD x0, x0, #0x20.
    let straight = [0x00, 0x00, 0x00, 0x90, 0x00, 0x80, 0x00, 0x91];
    let branched = [0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x14, 0x00, 0x80, 0x00, 0x91];
    let target = request(Arch::Aarch64, RawCodeMode::Native);
    assert_eq!(inspect_raw_code(&straight, &target).unwrap().rows[1].observation.data_ref, Some(0x1020));
    assert_eq!(inspect_raw_code(&branched, &target).unwrap().rows[2].observation.data_ref, None);
    for transfer in [0x5400_0020u32, 0x9400_0001, 0xd65f_03c0, 0xd61f_0020] {
        let mut bytes = straight[..4].to_vec();
        bytes.extend_from_slice(&transfer.to_le_bytes());
        bytes.extend_from_slice(&straight[4..]);
        let report = inspect_raw_code(&bytes, &target).unwrap();
        assert_eq!(report.rows.len(), 3);
        assert_eq!(report.rows[2].observation.data_ref, None, "{transfer:#x}");
    }
}

#[test]
fn arm_branch_target_mode_hints_cannot_override_the_explicit_mode() {
    // BLX into the following bytes suggests Thumb, but these bytes were explicitly requested as A32.
    let bytes = [0xff, 0xff, 0xff, 0xfa, 0x1e, 0xff, 0x2f, 0xe1];
    let report = inspect_raw_code(&bytes, &request(Arch::Arm, RawCodeMode::Arm)).unwrap();
    assert_eq!(report.rows.len(), 2);
    assert_eq!(report.rows[1].observation.len, 4);
    assert_eq!(report.rows[1].observation.flow, Flow::Return);
}

#[test]
fn observations_include_references_accesses_and_immediates_without_dereference() {
    let bytes = [0x48, 0x8b, 0x05, 0xf9, 0x6f, 0x00, 0x00, 0x48, 0xb8, 0x00, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let report = inspect_raw_code(&bytes, &request(Arch::X86_64, RawCodeMode::Native)).unwrap();
    assert_eq!(report.rows[0].observation.data_ref, Some(0x8000));
    assert!(report.rows[0].observation.accesses);
    assert_eq!(report.rows[1].observation.immediate, Some(0x9000));
    assert_eq!(report.rows[0].observation.immediate, None);
    // AArch64 literal LDR reports its slot but receives no memory reader, even when bytes exist there.
    let report = inspect_raw_code(
        &[0x20, 0x00, 0x00, 0x58, 0xc0, 0x03, 0x5f, 0xd6],
        &request(Arch::Aarch64, RawCodeMode::Native),
    )
    .unwrap();
    assert_eq!(report.rows[0].observation.data_ref, Some(0x1004));
    assert!(report.rows[0].observation.accesses);
    assert_eq!(report.rows[0].observation.immediate, None);
}

#[test]
fn conditional_arm_transfer_is_preserved_as_an_observation() {
    let report = inspect_raw_code(&[0x1e, 0xff, 0x2f, 0x01], &request(Arch::Arm, RawCodeMode::Arm)).unwrap();
    assert!(report.rows[0].observation.conditional);
    assert_eq!(report.rows[0].observation.flow, Flow::Next);
}

#[test]
fn thumb_ite_setup_instructions_retain_both_predicates() {
    // ITE EQ; ADDEQ r0, r0, r1; ADDNE r0, r0, r1; ADDS r0, r0, r1.
    let bytes = [0x0c, 0xbf, 0x40, 0x18, 0x40, 0x18, 0x40, 0x18];
    let report = inspect_raw_code(&bytes, &request(Arch::Arm, RawCodeMode::Thumb)).unwrap();
    assert_eq!(report.rows.len(), 4);
    assert_eq!(report.rows[1].text, "addeq r0, r0, r1");
    assert_eq!(report.rows[2].text, "addne r0, r0, r1");
    assert_eq!(report.rows[3].text, "adds r0, r0, r1");
    assert_eq!(report.stop_reason, RawCodeStopReason::WindowEnd);
}

#[test]
fn conditional_next_joins_facts_without_erasing_thumb_ite_context() {
    // Owned decoder-only ITE vector; this checks predicate preservation, not architectural IT legality.
    let bytes = [0x0c, 0xbf, 0x70, 0x47, 0x70, 0x47, 0x70, 0x47];
    let target = request(Arch::Arm, RawCodeMode::Thumb);
    let report = inspect_raw_code(&bytes, &target).unwrap();
    assert_eq!(report.rows.len(), 4);
    assert_eq!(report.rows[1].text, "bxeq lr");
    assert_eq!(report.rows[2].text, "bxne lr");
    for row in &report.rows[1..3] {
        assert_eq!(row.observation.flow, Flow::Next);
        assert!(row.observation.conditional);
    }
    assert_eq!(report.rows[3].text, "bx lr");
    assert_eq!(report.rows[3].observation.flow, Flow::Return);
    assert!(!report.rows[3].observation.conditional);
    assert_eq!(report.consumed_bytes, bytes.len());

    let mut inside_block = target;
    inside_block.base_address += 2;
    let report = inspect_raw_code(&bytes[2..4], &inside_block).unwrap();
    assert_eq!(report.rows[0].text, "bx lr");
    assert_eq!(report.rows[0].observation.flow, Flow::Return);
    assert!(!report.rows[0].observation.conditional);
    assert!(report.limitations.iter().any(|limitation| limitation.contains("no prior IT state")));
}

#[test]
fn arm_and_thumb_literal_loads_observe_only_provided_complete_words() {
    let vectors: &[(RawCodeMode, &[u8], usize, u64)] = &[
        (RawCodeMode::Arm, &[0x00, 0x00, 0x9f, 0xe5, 0x1e, 0xff, 0x2f, 0xe1, 0x78, 0x56, 0x34, 0x12], 4, 0x1008),
        (RawCodeMode::Thumb, &[0x00, 0x48, 0x70, 0x47, 0x78, 0x56, 0x34, 0x12], 2, 0x1004),
        (RawCodeMode::Thumb, &[0xdf, 0xf8, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12], 4, 0x1004),
    ];
    for &(mode, bytes, instruction_size, slot) in vectors {
        let mut target = request(Arch::Arm, mode);
        target.instruction_limit = 1;
        let report = inspect_raw_code(bytes, &target).unwrap();
        let row = &report.rows[0];
        assert_eq!(row.observation.data_ref, Some(slot));
        assert!(row.observation.accesses);
        assert_eq!(row.observation.immediate, Some(0x1234_5678));
        assert_eq!(row.observation.flow, Flow::Next);
        assert_eq!(row.bytes, rampage_arch::hex::bytes(&bytes[..instruction_size]));
        assert_eq!(report.consumed_bytes, instruction_size);
        assert_eq!(report.remaining_bytes, bytes.len() - instruction_size);
        assert_eq!(report.rows.len(), 1);
        assert_eq!(report.stop_reason, RawCodeStopReason::InstructionLimit);

        // The backing array still has the literal; the selected slice omits at least one of its bytes.
        for length in instruction_size..bytes.len() {
            let report = inspect_raw_code(&bytes[..length], &target).unwrap();
            assert_eq!(report.rows.len(), 1);
            assert_eq!(report.rows[0].observation.data_ref, Some(slot));
            assert!(report.rows[0].observation.accesses);
            assert_eq!(report.rows[0].observation.immediate, None, "{mode:?} length={length}");
            assert_eq!(report.rows[0].observation.flow, Flow::Next);
            assert_eq!(report.consumed_bytes, instruction_size);
            assert_eq!(report.remaining_bytes, length - instruction_size);
        }
    }
}

#[test]
fn zero_literal_is_an_observed_value_not_an_unavailable_literal() {
    let mut target = request(Arch::Arm, RawCodeMode::Thumb);
    target.instruction_limit = 1;
    let report = inspect_raw_code(&[0x00, 0x48, 0x70, 0x47, 0, 0, 0, 0], &target).unwrap();
    assert_eq!(report.rows[0].observation.immediate, Some(0));
    let report = inspect_raw_code(&[0x00, 0x48, 0x70, 0x47, 0, 0, 0], &target).unwrap();
    assert_eq!(report.rows[0].observation.immediate, None);
}

#[test]
fn loaded_arm_pc_is_an_observation_not_a_followed_target_or_inferred_mode() {
    let bytes = [0x00, 0xf0, 0x9f, 0xe5, 0x1e, 0xff, 0x2f, 0xe1, 0x01, 0x80, 0x00, 0x00];
    let mut target = request(Arch::Arm, RawCodeMode::Arm);
    target.instruction_limit = 2;
    let report = inspect_raw_code(&bytes, &target).unwrap();
    assert_eq!(report.rows.len(), 2);
    assert_eq!(report.rows[0].observation.immediate, Some(0x8001));
    assert_eq!(report.rows[0].observation.flow, Flow::Jump(0x8000));
    assert_eq!(report.rows[1].window_byte_offset, 4);
    assert_eq!(report.rows[1].observation.len, 4);
    assert_eq!(report.rows[1].observation.flow, Flow::Return);
    assert_eq!((report.consumed_bytes, report.remaining_bytes), (8, 4));
    let report = inspect_raw_code(&bytes[..11], &target).unwrap();
    assert_eq!(report.rows[0].observation.immediate, None);
    assert_eq!(report.rows[0].observation.flow, Flow::IndirectJump);
}

#[test]
fn backward_arm_literal_remains_unknown_under_the_current_decoder_limitation() {
    // NOP; LDR r0, [pc, #-12]. Its slot is within the supplied window, but before the current instruction.
    let bytes = [0x00, 0x00, 0xa0, 0xe1, 0x0c, 0x00, 0x1f, 0xe5];
    let report = inspect_raw_code(&bytes, &request(Arch::Arm, RawCodeMode::Arm)).unwrap();
    assert_eq!(report.rows[1].observation.data_ref, Some(0x1000));
    assert!(report.rows[1].observation.accesses);
    assert_eq!(report.rows[1].observation.immediate, None);
    assert!(report.limitations.iter().any(|limitation| limitation.contains("Backward ARM literals")));
}

#[test]
fn rejects_empty_oversized_and_out_of_budget_requests() {
    let mut target = request(Arch::X86_64, RawCodeMode::Native);
    assert!(inspect_raw_code(&[], &target).is_err());
    assert!(inspect_raw_code(&vec![0x90; MAX_RAW_CODE_BYTES + 1], &target).is_err());
    for count in [0, MAX_RAW_CODE_INSTRUCTIONS + 1, usize::MAX] {
        target.instruction_limit = count;
        assert!(inspect_raw_code(&[0x90], &target).is_err());
    }
    target.instruction_limit = MAX_RAW_CODE_INSTRUCTIONS;
    let report = inspect_raw_code(&vec![0x90; MAX_RAW_CODE_BYTES], &target);
    match report {
        Ok(report) => {
            assert_eq!(report.rows.len(), MAX_RAW_CODE_INSTRUCTIONS);
            assert_eq!(report.remaining_bytes, MAX_RAW_CODE_BYTES - MAX_RAW_CODE_INSTRUCTIONS);
        }
        Err(error) => assert!(error.to_string().contains("48000 JSON bytes")),
    }
}

#[test]
fn rejects_unsupported_architecture_mode_and_endian_combinations() {
    for arch in Arch::ALL {
        if !matches!(arch, Arch::X86 | Arch::X86_64 | Arch::Arm | Arch::Aarch64) {
            assert!(inspect_raw_code(&[0; 4], &request(arch, RawCodeMode::Native)).is_err());
        }
    }
    assert!(inspect_raw_code(&[0; 4], &request(Arch::Arm, RawCodeMode::Native)).is_err());
    for arch in [Arch::X86, Arch::X86_64, Arch::Aarch64] {
        for mode in [RawCodeMode::Arm, RawCodeMode::Thumb] {
            assert!(inspect_raw_code(&[0; 4], &request(arch, mode)).is_err());
        }
    }
    for (arch, mode) in [
        (Arch::X86, RawCodeMode::Native),
        (Arch::X86_64, RawCodeMode::Native),
        (Arch::Aarch64, RawCodeMode::Native),
        (Arch::Arm, RawCodeMode::Arm),
        (Arch::Arm, RawCodeMode::Thumb),
    ] {
        for (code_big_endian, data_big_endian) in [(true, false), (false, true), (true, true)] {
            let mut target = request(arch, mode);
            target.code_big_endian = code_big_endian;
            target.data_big_endian = data_big_endian;
            assert!(inspect_raw_code(&[0; 4], &target).is_err());
        }
    }
}

#[test]
fn alignment_width_and_overflow_are_checked_without_thumb_bit_normalization() {
    for (arch, mode, base) in [
        (Arch::Arm, RawCodeMode::Arm, 0x1002),
        (Arch::Arm, RawCodeMode::Thumb, 0x1001),
        (Arch::Aarch64, RawCodeMode::Native, 0x1002),
        (Arch::X86, RawCodeMode::Native, 0xffff_ffff),
        (Arch::Arm, RawCodeMode::Arm, 0xffff_fffc),
        (Arch::X86_64, RawCodeMode::Native, u64::MAX),
        (Arch::Aarch64, RawCodeMode::Native, u64::MAX - 3),
    ] {
        let mut target = request(arch, mode);
        target.base_address = base;
        assert!(inspect_raw_code(&[0x90; 8], &target).is_err(), "{arch:?} {mode:?} {base:#x}");
    }
    let mut target = request(Arch::X86, RawCodeMode::Native);
    target.base_address = 0xffff_ffff;
    let report = inspect_raw_code(&[0x90], &target).unwrap();
    assert_eq!(report.end_address_exclusive, 0x1_0000_0000);
    let mut target = request(Arch::X86_64, RawCodeMode::Native);
    target.base_address = 0x1001;
    assert!(inspect_raw_code(&[0x90], &target).is_ok());
    target.base_address = u64::MAX - 1;
    assert!(inspect_raw_code(&[0x90], &target).is_ok());
    target.base_address = 0;
    let report = inspect_raw_code(&[0x90], &target).unwrap();
    assert_eq!(report.rows[0].observation.address, 0);
}

#[test]
fn architecture_selection_controls_decode_width_without_inference() {
    let bytes = [0x48, 0x90];
    let x86 = inspect_raw_code(&bytes, &request(Arch::X86, RawCodeMode::Native)).unwrap();
    let x64 = inspect_raw_code(&bytes, &request(Arch::X86_64, RawCodeMode::Native)).unwrap();
    assert_eq!(x86.rows.len(), 2);
    assert_eq!(x86.rows[0].observation.len, 1);
    assert_eq!(x64.rows.len(), 1);
    assert_eq!(x64.rows[0].observation.len, 2);
}

#[test]
fn oversized_whole_json_is_refused_instead_of_returning_partial_rows() {
    let mut target = request(Arch::X86_64, RawCodeMode::Native);
    target.instruction_limit = MAX_RAW_CODE_INSTRUCTIONS;
    let bytes = [0x48, 0xb8, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01].repeat(MAX_RAW_CODE_INSTRUCTIONS);
    let error = inspect_raw_code(&bytes, &target).unwrap_err();
    assert!(error.to_string().contains("48000 JSON bytes"));
    assert!(error.to_string().contains("narrow"));
    target.instruction_limit = 1;
    let report = inspect_raw_code(&bytes, &target).unwrap();
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.stop_reason, RawCodeStopReason::InstructionLimit);
}
