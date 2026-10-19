//! Conditional-fallthrough recovery proofs over raw p-code, independent of CPU names and assembly text.
use super::*;

fn spaces() -> Vec<Space> {
    [
        (0, "const", 0, 8, u64::MAX),
        (1, "code", 1, 4, u64::from(u32::MAX)),
        (2, "unique", 3, 4, u64::from(u32::MAX)),
        (3, "register", 1, 4, u64::from(u32::MAX)),
        (4, "data", 1, 4, u64::from(u32::MAX)),
    ]
    .into_iter()
    .map(|(id, name, kind, address_size, highest)| Space {
        id,
        name: name.to_owned(),
        kind,
        address_size,
        word_size: 1,
        highest,
    })
    .collect()
}

fn node(spaces: &[Space], id: u32, offset: u64, size: u32) -> Varnode {
    let space = spaces.iter().find(|space| space.id == id).unwrap();
    Varnode {
        space: id,
        size,
        address_size: space.address_size,
        word_size: space.word_size,
        offset: Some(offset),
        selected_space: None,
    }
}

fn pair(spaces: &[Space], address: u64, first: u64, second: u64) -> Vec<PcodeOp> {
    let width = spaces.iter().find(|space| space.id == 1).unwrap().address_size;
    vec![
        PcodeOp {
            opcode: 5,
            name: "CBRANCH".to_owned(),
            address,
            output: None,
            inputs: vec![node(spaces, 1, first, width), node(spaces, 2, 0x80, 1)],
        },
        PcodeOp {
            opcode: 4,
            name: "BRANCH".to_owned(),
            address,
            output: None,
            inputs: vec![node(spaces, 1, second, width)],
        },
    ]
}

#[test]
fn recovers_either_condition_polarity_without_changing_raw_pcode() {
    let spaces = spaces();
    for (first, second) in [(0x1004, 0x2000), (0x2000, 0x1004)] {
        let raw = pair(&spaces, 0x1000, first, second);
        let retained = raw.clone();
        assert_eq!(
            classify(DecodeStatus::Valid, 0x1000, 4, 4, 1, &spaces, &raw),
            InstructionFlow::ConditionalBranch { target: 0x2000 }
        );
        assert_eq!(raw, retained);
    }
}

#[test]
fn fallthrough_is_checked_in_internal_bytes_not_display_words() {
    let mut spaces = spaces();
    spaces[1].address_size = 2;
    spaces[1].word_size = 2;
    spaces[1].highest = 0x1ffff;
    let raw = pair(&spaces, 0x10000, 0x10002, 0x12000);
    assert_eq!(
        classify(DecodeStatus::Valid, 0x10000, 2, 2, 1, &spaces, &raw),
        InstructionFlow::ConditionalBranch { target: 0x12000 }
    );
    let wrong_scaled_next = pair(&spaces, 0x10000, 0x10004, 0x12000);
    assert_eq!(
        classify(DecodeStatus::Valid, 0x10000, 2, 2, 1, &spaces, &wrong_scaled_next),
        InstructionFlow::Unknown { reason: UnknownFlow::MultipleExits }
    );
}

#[test]
fn unsupported_two_exit_shapes_remain_unknown() {
    let spaces = spaces();
    for case in [
        "neither_is_next",
        "both_are_next",
        "reversed_order",
        "internal_branch",
        "other_space",
        "extra_exit",
        "userop",
        "unknown_opcode",
        "unknown_condition_space",
        "wide_condition",
        "constant_condition",
        "missing_condition",
        "selected_condition",
        "condition_offset_missing",
        "condition_out_of_range",
        "condition_metadata",
        "selected_target",
        "target_offset_missing",
        "target_metadata",
        "target_out_of_range",
        "branch_output",
        "wrong_instruction_address",
    ] {
        let mut raw = pair(&spaces, 0x1000, 0x1004, 0x2000);
        match case {
            "neither_is_next" => raw[0].inputs[0].offset = Some(0x3000),
            "both_are_next" => raw[1].inputs[0].offset = Some(0x1004),
            "reversed_order" => raw.reverse(),
            "internal_branch" => raw[0].inputs[0] = node(&spaces, 0, 2, 4),
            "other_space" => raw[0].inputs[0] = node(&spaces, 4, 0x1004, 4),
            "extra_exit" => raw.push(PcodeOp {
                opcode: 10,
                name: "RETURN".to_owned(),
                address: 0x1000,
                output: None,
                inputs: vec![node(&spaces, 3, 0x10, 4)],
            }),
            "userop" => raw.push(PcodeOp {
                opcode: 9,
                name: "CALLOTHER".to_owned(),
                address: 0x1000,
                output: None,
                inputs: vec![node(&spaces, 0, 1, 4)],
            }),
            "unknown_opcode" => raw.push(PcodeOp {
                opcode: u32::MAX,
                name: "unknown".to_owned(),
                address: 0x1000,
                output: None,
                inputs: Vec::new(),
            }),
            "unknown_condition_space" => raw[0].inputs[1].space = 99,
            "wide_condition" => raw[0].inputs[1].size = 2,
            "constant_condition" => raw[0].inputs[1] = node(&spaces, 0, 1, 1),
            "missing_condition" => {
                raw[0].inputs.pop();
            }
            "selected_condition" => raw[0].inputs[1].selected_space = Some(2),
            "condition_offset_missing" => raw[0].inputs[1].offset = None,
            "condition_out_of_range" => raw[0].inputs[1].offset = Some(0x1_0000_0000),
            "condition_metadata" => raw[0].inputs[1].word_size = 2,
            "selected_target" => raw[0].inputs[0].selected_space = Some(1),
            "target_offset_missing" => raw[0].inputs[0].offset = None,
            "target_metadata" => raw[0].inputs[0].address_size = 2,
            "target_out_of_range" => raw[0].inputs[0].offset = Some(0x1_0000_0000),
            "branch_output" => raw[1].output = Some(node(&spaces, 2, 0x90, 1)),
            "wrong_instruction_address" => raw[1].address = 0x1001,
            _ => unreachable!(),
        }
        assert_eq!(
            classify(DecodeStatus::Valid, 0x1000, 4, 4, 1, &spaces, &raw),
            InstructionFlow::Unknown {
                reason: if case == "unknown_opcode" { UnknownFlow::MalformedPcode } else { UnknownFlow::MultipleExits }
            },
            "{case}"
        );
    }
}

#[test]
fn u64_and_native_space_end_overflows_do_not_wrap_into_fallthrough() {
    let mut spaces = spaces();
    spaces[1].address_size = 8;
    spaces[1].highest = u64::MAX;
    let raw = pair(&spaces, u64::MAX - 1, 0, 0x2000);
    assert_eq!(
        classify(DecodeStatus::Valid, u64::MAX - 1, 2, 2, 1, &spaces, &raw),
        InstructionFlow::Unknown { reason: UnknownFlow::MultipleExits }
    );
    spaces[1].address_size = 2;
    spaces[1].highest = 0xffff;
    let raw = pair(&spaces, 0xfffe, 0, 0x2000);
    assert_eq!(
        classify(DecodeStatus::Valid, 0xfffe, 2, 2, 1, &spaces, &raw),
        InstructionFlow::Unknown { reason: UnknownFlow::MultipleExits }
    );
}

#[test]
fn actual_cr16_oracle_recovers_flow_but_context_helper_and_delay_gates_still_win() {
    let oracle: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/sleigh/extended/oracle-current.json")).unwrap();
    let fixture = oracle["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|fixture| fixture["language_id"] == "CR16C:LE:16:default")
        .unwrap();
    let row = fixture["oracle"]["standalone_rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["fixture_offset_bytes"] == 6)
        .unwrap();
    let parse =
        |value: &serde_json::Value| u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let address = parse(&row["address"]["getOffset_bytes"]);
    let target = parse(&row["direct_flow_targets"][0]["getOffset_bytes"]);
    let bytes = include_bytes!("../../../tests/fixtures/sleigh/extended/CR16-v1.bin");
    let offset = row["fixture_offset_bytes"].as_u64().unwrap() as usize;
    let mut decoder = SleighDecoder::open("CR16C:LE:16:default").expect("reviewed bundled CR16");
    let decoded = decoder.decode_instruction(&bytes[offset..], address);
    assert_eq!(decoded.status, DecodeStatus::Valid);
    assert_eq!(decoded.flow, InstructionFlow::ConditionalBranch { target });
    assert_eq!(decoded.length as u64, row["length_bytes"].as_u64().unwrap());
    assert_eq!(decoded.pcode.len(), row["raw_pcode"].as_array().unwrap().len());
    assert!(decoded.unknown_gate.is_none());
    let mut record = Box::<NativeResult>::new_uninit();
    {
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: live owning handle under FFI_LOCK; C initializes the entire fixed-size native record.
        unsafe {
            rampage_sleigh_decode(
                decoder.handle,
                address,
                bytes[offset..].as_ptr(),
                bytes.len() - offset,
                record.as_mut_ptr(),
            );
        }
    }
    let mut record = unsafe { record.assume_init() };
    for (context, helper, extent, reason) in [
        (1, 0, decoded.length, UnknownFlow::ContextMediatedFlow),
        (0, 1, decoded.length, UnknownFlow::ProcessorHelperRequired),
        (1, 1, decoded.length, UnknownFlow::ProcessorHelperRequired),
        (0, 0, decoded.length + 2, UnknownFlow::DelaySlotAggregation),
    ] {
        record.context_mediated_flow = context;
        record.processor_helper_required = helper;
        record.extent = extent;
        let gated = convert(decoder.profile(), address, &record);
        assert_eq!(gated.status, DecodeStatus::Valid);
        assert_eq!(gated.flow, InstructionFlow::Unknown { reason });
        assert_eq!(gated.unknown_gate.as_ref().unwrap().reason, reason);
        assert_eq!(gated.pcode, decoded.pcode);
    }
}

#[test]
fn reserved_opcode_cannot_recover_a_conditional_fallthrough() {
    let spaces = spaces();
    let mut raw = pair(&spaces, 0x1000, 0x1004, 0x2000);
    raw.insert(
        0,
        PcodeOp { opcode: 45, name: "UNUSED1".to_owned(), address: 0x1000, output: None, inputs: Vec::new() },
    );
    let retained = raw.clone();
    assert_eq!(
        classify(DecodeStatus::Valid, 0x1000, 4, 4, 1, &spaces, &raw),
        InstructionFlow::Unknown { reason: UnknownFlow::MalformedPcode }
    );
    assert_eq!(raw, retained);
    assert_eq!(raw[0].opcode, 45);
    assert_eq!(raw[0].name, "UNUSED1");
}

#[test]
fn undefined_opcodes_cannot_claim_next_or_single_exit_flow() {
    let spaces = spaces();
    let exits = pair(&spaces, 0x1000, 0x1004, 0x2000);
    for (opcode, name) in [(0, "BLANK"), (45, "UNUSED1"), (75, "CPUI_MAX"), (u32::MAX, "unknown")] {
        for flow in [Vec::new(), vec![exits[0].clone()], vec![exits[1].clone()]] {
            let mut raw =
                vec![PcodeOp { opcode, name: name.to_owned(), address: 0x1000, output: None, inputs: Vec::new() }];
            raw.extend(flow);
            let retained = raw.clone();
            assert_eq!(
                classify(DecodeStatus::Valid, 0x1000, 4, 4, 1, &spaces, &raw),
                InstructionFlow::Unknown { reason: UnknownFlow::MalformedPcode },
                "opcode {opcode}"
            );
            assert_eq!(raw, retained);
        }
    }
}

#[test]
fn defined_floating_operations_on_either_side_of_the_hole_keep_next_flow() {
    let spaces = spaces();
    for (opcode, name, count) in [(44, "FLOAT_LESSEQUAL", 2), (46, "FLOAT_NAN", 1)] {
        let raw = vec![PcodeOp {
            opcode,
            name: name.to_owned(),
            address: 0x1000,
            output: Some(node(&spaces, 2, 0x80, 1)),
            inputs: vec![node(&spaces, 0, 0, 4); count],
        }];
        assert_eq!(classify(DecodeStatus::Valid, 0x1000, 4, 4, 1, &spaces, &raw), InstructionFlow::Next);
    }
}
