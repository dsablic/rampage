//! Comparisons to captured independent Ghidra Java output; these tests never regenerate the oracle.

use serde_json::Value;

use super::*;

const ORACLE: &str = include_str!("../../../tests/fixtures/sleigh/oracle.json");
const TRUTH: &str = include_str!("../../../tests/fixtures/sleigh/truth.json");
const INPUTS: [(&str, &[u8]); 3] = [
    ("msp430", include_bytes!("../../../tests/fixtures/sleigh/msp430.bin")),
    ("avr8", include_bytes!("../../../tests/fixtures/sleigh/avr8.bin")),
    ("6502", include_bytes!("../../../tests/fixtures/sleigh/6502.bin")),
];

fn hex(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().expect("hexadecimal string").trim_start_matches("0x"), 16)
        .expect("hexadecimal offset")
}

fn operations(row: &Value) -> &[Value] {
    row["raw_pcode"].as_array().expect("raw p-code array")
}

fn opname(name: &str) -> String {
    name.trim_start_matches("CPUI_").to_ascii_uppercase()
}

fn space(decoded: &DecodedInstruction, id: u32) -> &Space {
    decoded.spaces.iter().find(|space| space.id == id).expect("retained native space identity")
}

fn compare_node(decoded: &DecodedInstruction, native: &Varnode, java: &Value, selector: bool, metadata: bool) {
    let address = &java["address"];
    let native_space = space(decoded, native.space);
    assert_eq!(native_space.name, address["space"].as_str().expect("Java space name"), "{decoded:?}");
    assert_eq!(native.word_size as u64, address["addressableUnitSize_bytes"].as_u64().expect("word unit"));
    if selector {
        assert_eq!(native.offset, None, "native pointer-encoded selector must not escape");
        let selected = space(decoded, native.selected_space.expect("sanitized selected space"));
        let expected = if decoded.profile.starts_with("avr8:") { "mem" } else { "RAM" };
        assert_eq!(selected.name, expected, "{decoded:?}");
        assert_eq!(selected.word_size, 1);
    } else {
        assert_eq!(native.size as u64, java["size_bytes"].as_u64().expect("varnode size"), "{decoded:?}");
        assert!(native.selected_space.is_none());
        if !metadata && native_space.name != "unique" {
            assert_eq!(native.offset, Some(hex(&address["getOffset_raw"])), "{decoded:?}");
        }
    }
}

fn compare_pcode(decoded: &DecodedInstruction, row: &Value) {
    let java = operations(row);
    let names: Vec<_> = decoded.pcode.iter().map(|op| opname(&op.name)).collect();
    let java_names: Vec<_> = java.iter().map(|op| opname(op["mnemonic"].as_str().expect("opcode name"))).collect();
    assert_eq!(names, java_names, "{decoded:?}");
    for (native, java) in decoded.pcode.iter().zip(java) {
        assert_eq!(native.address, decoded.address);
        match (&native.output, java["output"].is_null()) {
            (Some(output), false) => compare_node(decoded, output, &java["output"], false, false),
            (None, true) => {}
            _ => panic!("p-code output shape differs: {decoded:?}"),
        }
        let inputs = java["inputs"].as_array().expect("p-code inputs");
        assert_eq!(native.inputs.len(), inputs.len(), "{decoded:?}");
        for (index, (input, java_input)) in native.inputs.iter().zip(inputs).enumerate() {
            let selector = index == 0 && matches!(native.name.as_str(), "LOAD" | "STORE");
            let metadata = index == 0 && native.name == "CALLOTHER";
            // Selector encodings/widths, userop IDs and unique allocations are not cross-engine identities.
            compare_node(decoded, input, java_input, selector, metadata);
        }
    }
}

fn compare_flow(decoded: &DecodedInstruction, row: &Value, fixture_offset: usize) {
    if decoded.profile.starts_with("avr8:") && fixture_offset == 22 {
        assert!(decoded.context_mediated_flow);
        assert_eq!(decoded.flow, InstructionFlow::Unknown { reason: UnknownFlow::ContextMediatedFlow });
        assert!(decoded.unknown_gate.is_some());
        return;
    }
    if decoded.profile.starts_with("avr8:") && fixture_offset == 26 {
        assert!(matches!(decoded.flow, InstructionFlow::Unknown { .. }), "{decoded:?}");
        assert!(decoded.unknown_gate.is_some());
        assert!(decoded.pcode.iter().any(|op| {
            matches!(op.name.as_str(), "BRANCH" | "CBRANCH")
                && op.inputs.first().is_some_and(|input| space(decoded, input.space).name == "const")
        }));
        return;
    }
    let targets = row["direct_flow_targets"].as_array().expect("direct flow targets");
    let target = || {
        assert_eq!(targets.len(), 1);
        let address = &targets[0];
        let code = space(decoded, decoded.code_space);
        assert_eq!(code.name, address["space"].as_str().expect("target space"));
        assert_eq!(code.word_size as u64, address["addressableUnitSize_bytes"].as_u64().expect("target unit"));
        let bytes = hex(&address["getOffset_bytes"]);
        assert_eq!(bytes / u64::from(code.word_size), hex(&address["getAddressableWordOffset_words"]));
        bytes
    };
    let expected = match row["flow"]["name"].as_str().expect("Java flow") {
        "FALL_THROUGH" => InstructionFlow::Next,
        "UNCONDITIONAL_CALL" => InstructionFlow::DirectCall { target: target() },
        "UNCONDITIONAL_JUMP" => InstructionFlow::Branch { target: target() },
        "CONDITIONAL_JUMP" => InstructionFlow::ConditionalBranch { target: target() },
        "COMPUTED_CALL" => InstructionFlow::IndirectCall,
        "COMPUTED_JUMP" => InstructionFlow::IndirectBranch,
        "TERMINATOR" => InstructionFlow::Return,
        flow => panic!("unreviewed oracle flow: {flow}"),
    };
    assert_eq!(decoded.flow, expected, "{decoded:?}");
    assert!(decoded.unknown_gate.is_none());
}

#[test]
fn native_bridge_matches_independent_java_oracle_with_explicit_conservative_gates() {
    let oracle: Value = serde_json::from_str(ORACLE).expect("captured oracle JSON");
    assert_eq!(oracle["ghidra_version"], "12.1.4");
    assert_eq!(oracle["target_execution"], false);
    assert_eq!(oracle["decompilation"], false);
    for fixture in oracle["fixtures"].as_array().expect("oracle fixtures") {
        let name = fixture["name"].as_str().expect("fixture name");
        let bytes = INPUTS.iter().find(|(input, _)| *input == name).expect("owned input bytes").1;
        let profile = fixture["language_id"].as_str().expect("profile");
        let mut decoder = SleighDecoder::open(profile).expect("admitted profile");
        let mut decoded_rows = 0;
        let mut negatives = 0;
        for row in fixture["rows"].as_array().expect("isolated rows") {
            let offset = row["fixture_offset_bytes"].as_u64().expect("fixture byte offset") as usize;
            let address = hex(&row["address"]["getOffset_bytes"]);
            let decoded = decoder.decode_instruction(&bytes[offset..], address);
            match row["status"].as_str().expect("row status") {
                "decoded" => {
                    decoded_rows += 1;
                    assert_eq!(decoded.status, DecodeStatus::Valid, "{decoded:?}");
                    assert_eq!(decoded.length as u64, row["length_bytes"].as_u64().expect("instruction length"));
                    assert_eq!(
                        decoded.mnemonic.to_ascii_lowercase(),
                        row["mnemonic"].as_str().expect("Java mnemonic").to_ascii_lowercase(),
                        "{decoded:?}"
                    );
                    let code = space(&decoded, decoded.code_space);
                    assert_eq!(code.name, row["address"]["space"].as_str().expect("code space name"));
                    assert_eq!(code.word_size as u64, row["address"]["addressableUnitSize_bytes"].as_u64().unwrap());
                    let length = decoded.length as usize;
                    assert_eq!(rampage_arch::hex::bytes(&bytes[offset..offset + length]), row["bytes_hex"]);
                    compare_pcode(&decoded, row);
                    compare_flow(&decoded, row, offset);
                }
                "rejected_unbacked_instruction" => {
                    negatives += 1;
                    assert!(matches!(decoded.status, DecodeStatus::Truncated | DecodeStatus::InvalidOrTruncated));
                    assert_eq!(decoded.length, 0, "a padded prototype is not a backed instruction");
                    assert!(decoded.pcode.is_empty(), "{decoded:?}");
                }
                "decode_error" => {
                    negatives += 1;
                    assert!(matches!(decoded.status, DecodeStatus::Invalid | DecodeStatus::InvalidOrTruncated));
                    assert!(decoded.pcode.is_empty(), "{decoded:?}");
                }
                status => panic!("unreviewed oracle status {status}"),
            }
        }
        assert_eq!(
            (decoded_rows, negatives),
            match name {
                "msp430" => (11, 1),
                "avr8" => (13, 2),
                "6502" => (12, 2),
                _ => unreachable!(),
            }
        );
    }
}

#[test]
fn oracle_avr_word_target_and_flowed_skip_are_not_conflated_with_isolated_context() {
    let oracle: Value = serde_json::from_str(ORACLE).expect("captured oracle JSON");
    let truth: Value = serde_json::from_str(TRUTH).expect("hand-authored truth JSON");
    let fixture = oracle["fixtures"].as_array().unwrap().iter().find(|f| f["name"] == "avr8").unwrap();
    let truth = truth["fixtures"].as_array().unwrap().iter().find(|f| f["name"] == "avr8").unwrap();
    let bytes = INPUTS.iter().find(|(name, _)| *name == "avr8").unwrap().1;
    let base = hex(&truth["base_byte_offset"]);
    let mut decoder = SleighDecoder::open("avr8:LE:16:default").expect("admitted AVR decoder");
    let call = decoder.decode_instruction(bytes, base);
    assert_eq!(call.flow, InstructionFlow::DirectCall { target: 0x210 });
    assert_eq!(hex(&truth["known_call"]["encoded_word_target"]), 0x108);
    assert_eq!(space(&call, call.code_space).word_size, 2);
    let cpse = decoder.decode_instruction(&bytes[22..], base + 22);
    assert_eq!(cpse.flow, InstructionFlow::Unknown { reason: UnknownFlow::ContextMediatedFlow });
    let nop = decoder.decode_instruction(&bytes[24..], base + 24);
    assert_eq!(nop.flow, InstructionFlow::Next);
    assert!(nop.pcode.is_empty());
    let flowed_nop = fixture["program_oracle"]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["fixture_offset_bytes"] == 24)
        .expect("flowed following NOP");
    assert!(operations(flowed_nop).iter().any(|op| op["mnemonic"] == "CBRANCH"));
    assert_ne!(operations(flowed_nop).len(), nop.pcode.len());
    // The prior CPSE gate stops discovery; the fresh NOP decode must not claim the flowed program semantics.
    assert!(cpse.unknown_gate.is_some());
}
