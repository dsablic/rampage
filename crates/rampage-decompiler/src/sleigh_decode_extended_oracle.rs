//! Draft only: immutable independent Java observations versus all thirteen native outcomes.
use super::*;
use serde_json::{Value, json};

const ORACLE: &str = include_str!("../../../tests/fixtures/sleigh/extended/oracle-current.json");
const TRUTH: &str = include_str!("../../../tests/fixtures/sleigh/extended/truth-current.json");
const ADMISSION: &str = include_str!("../specs/processor-admission.json");

fn number(value: &Value) -> u64 {
    u64::from_str_radix(value.as_str().expect("hex string").trim_start_matches("0x"), 16).expect("hex number")
}

fn operation(value: &str) -> String {
    value.trim_start_matches("CPUI_").to_ascii_uppercase()
}

fn native_space(decoded: &DecodedInstruction, id: u32) -> &Space {
    decoded.spaces.iter().find(|space| space.id == id).expect("retained native space")
}

fn compare_node(
    decoded: &DecodedInstruction,
    native: &Varnode,
    java: &Value,
    selector: bool,
    metadata: bool,
    issues: &mut Vec<String>,
) {
    let space = native_space(decoded, native.space);
    let address = &java["address"];
    if address["space"] != space.name || address["addressableUnitSize_bytes"] != space.word_size {
        issues.push(format!("varnode space/unit: native {space:?}, Java {address}"));
    }
    if selector {
        match (native.offset, native.selected_space) {
            (None, Some(id)) => {
                let selected = native_space(decoded, id);
                if selected.word_size == 0 {
                    issues.push("selected space has no addressable unit".to_owned());
                }
            }
            _ => {
                issues.push("LOAD/STORE selector leaked an encoded offset or lost its resolved identity".to_owned());
            }
        }
        // Java exports an engine-local numeric selector, not its resolved name. No ID/width equivalence claim.
        return;
    }
    if java["size_bytes"] != native.size {
        issues.push(format!("varnode size differs: native {}, Java {}", native.size, java["size_bytes"]));
    }
    if !metadata && space.name != "unique" && native.offset != Some(number(&address["getOffset_raw"])) {
        issues.push(format!("varnode offset differs in {}", space.name));
    }
}

fn compare_row(decoded: &DecodedInstruction, java: &Value, issues: &mut Vec<String>) -> String {
    if decoded.status != DecodeStatus::Valid {
        issues.push(format!("native status {:?}: {:?}", decoded.status, decoded.diagnostic));
        return "native_decode_not_supported".to_owned();
    }
    if java["length_bytes"] != decoded.length {
        issues.push(format!("instruction length differs: native {}, Java {}", decoded.length, java["length_bytes"]));
    }
    if !decoded.mnemonic.eq_ignore_ascii_case(java["mnemonic"].as_str().expect("Java mnemonic")) {
        issues.push(format!("mnemonic differs: native {:?}, Java {}", decoded.mnemonic, java["mnemonic"]));
    }
    let code = native_space(decoded, decoded.code_space);
    if java["address"]["space"] != code.name || java["address"]["addressableUnitSize_bytes"] != code.word_size {
        issues.push("default-code-space name/unit differs".to_owned());
    }
    let java_ops = java["raw_pcode"].as_array().expect("Java raw p-code");
    let native_names: Vec<_> = decoded.pcode.iter().map(|op| operation(&op.name)).collect();
    let java_names: Vec<_> = java_ops.iter().map(|op| operation(op["mnemonic"].as_str().unwrap())).collect();
    if native_names != java_names {
        issues.push(format!("complete p-code sequence differs: native {native_names:?}, Java {java_names:?}"));
    }
    for (native, java) in decoded.pcode.iter().zip(java_ops) {
        match (&native.output, java["output"].is_null()) {
            (Some(node), false) => compare_node(decoded, node, &java["output"], false, false, issues),
            (None, true) => {}
            _ => issues.push("p-code output shape differs".to_owned()),
        }
        let java_inputs = java["inputs"].as_array().unwrap();
        if native.inputs.len() != java_inputs.len() {
            issues.push("p-code input count differs".to_owned());
        }
        for (index, (node, expected)) in native.inputs.iter().zip(java_inputs).enumerate() {
            let selector = index == 0 && matches!(native.name.as_str(), "LOAD" | "STORE");
            let metadata = index == 0 && native.name == "CALLOTHER";
            compare_node(decoded, node, expected, selector, metadata, issues);
        }
    }
    let permitted_gate = match decoded.flow {
        InstructionFlow::Unknown { reason: UnknownFlow::ProcessorHelperRequired }
            if decoded.processor_helper_required =>
        {
            Some("unsupported_parallel_helper")
        }
        InstructionFlow::Unknown { reason: UnknownFlow::ContextMediatedFlow } if decoded.context_mediated_flow => {
            Some("conservative_context_commit")
        }
        InstructionFlow::Unknown { reason: UnknownFlow::DelaySlotAggregation }
            if decoded.translated_extent > decoded.length && java["delay_slot_depth"].as_u64().unwrap_or(0) != 0 =>
        {
            Some("conservative_delay_aggregation")
        }
        InstructionFlow::Unknown { reason: UnknownFlow::UserDefinedOperation }
            if decoded.pcode.iter().any(|op| op.name == "CALLOTHER") =>
        {
            Some("conservative_userop")
        }
        InstructionFlow::Unknown { reason: UnknownFlow::InternalPcodeBranch | UnknownFlow::MultipleExits }
            if decoded.pcode.iter().any(|op| {
                matches!(op.name.as_str(), "BRANCH" | "CBRANCH")
                    && op.inputs.first().is_some_and(|node| native_space(decoded, node.space).name == "const")
            }) =>
        {
            Some("conservative_internal_pcode")
        }
        _ => None,
    };
    if let Some(gate) = permitted_gate {
        if decoded.unknown_gate.is_none() {
            issues.push("valid unknown flow lost its structured gate".to_owned());
        }
        return gate.to_owned();
    }
    let targets = java["direct_flow_targets"].as_array().unwrap();
    let direct = || -> Option<u64> {
        if targets.len() != 1 {
            return None;
        }
        let target = &targets[0];
        if target["space"] != code.name || target["addressableUnitSize_bytes"] != code.word_size {
            return None;
        }
        let bytes = number(&target["getOffset_bytes"]);
        if bytes / u64::from(code.word_size) != number(&target["getAddressableWordOffset_words"]) {
            return None;
        }
        Some(bytes)
    };
    let expected = match java["flow"]["name"].as_str().unwrap() {
        "FALL_THROUGH" => Some(InstructionFlow::Next),
        "COMPUTED_CALL" => Some(InstructionFlow::IndirectCall),
        "COMPUTED_JUMP" => Some(InstructionFlow::IndirectBranch),
        "TERMINATOR" => Some(InstructionFlow::Return),
        "UNCONDITIONAL_CALL" => direct().map(|target| InstructionFlow::DirectCall { target }),
        "UNCONDITIONAL_JUMP" => direct().map(|target| InstructionFlow::Branch { target }),
        "CONDITIONAL_JUMP" => direct().map(|target| InstructionFlow::ConditionalBranch { target }),
        _ => None,
    };
    if expected.as_ref() != Some(&decoded.flow) {
        issues.push(format!("flow/target differs: native {:?}, Java {}", decoded.flow, java["flow"]));
    }
    "compared_standalone".to_owned()
}

#[test]
fn thirteen_profiles_preserve_all_native_outcomes_and_compare_unmodified_java_rows() {
    let oracle: Value = serde_json::from_str(ORACLE).expect("audited independent oracle");
    let truth: Value = serde_json::from_str(TRUTH).expect("independent owned ledgers");
    let admission: Value = serde_json::from_str(ADMISSION).expect("closed resource admission");
    let fixtures = oracle["fixtures"].as_array().unwrap();
    assert_eq!(fixtures.len(), 13);
    let mut outcomes = Vec::new();
    let mut total_rows = 0;
    let mut failures = 0;
    for fixture in fixtures {
        let name = fixture["name"].as_str().unwrap();
        let profile = fixture["language_id"].as_str().unwrap();
        let bytes = input(name);
        let java = &fixture["oracle"];
        let rows = java["standalone_rows"].as_array().unwrap();
        let selected = admission["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["language_id"] == profile)
            .expect("exact selected resource profile");
        let owned = truth["fixtures"].as_array().unwrap().iter().find(|item| item["name"] == name).unwrap();
        let mut row_outcomes = Vec::new();
        let mut open_error = None;
        let mut metadata = None;
        match SleighDecoder::open(profile) {
            Err(error) => {
                open_error = Some(error.to_string());
                for row in rows {
                    total_rows += 1;
                    failures += 1;
                    row_outcomes.push(json!({"verdict":"open_failed", "java":row, "native":null,
                        "diagnostic":open_error}));
                }
            }
            Ok(mut decoder) => {
                let observed = decoder.metadata().clone(); // No sample instruction or fake decoding for metadata.
                metadata = Some(serde_json::to_value(&observed).unwrap());
                let code = observed.spaces.iter().find(|space| space.id == observed.code_space).unwrap();
                let expected_code = selected["address_spaces"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|space| space["default"] == true)
                    .unwrap();
                let metadata_matches = expected_code["name"] == code.name
                    && expected_code["address_size_bytes"] == code.address_size
                    && expected_code["word_size_bytes"] == code.word_size;
                let boundary_matches = match profile {
                    "HCS-12:BE:24:default" => code.address_size == 3 && code.highest == 0xffffff,
                    "CR16C:LE:16:default" => code.address_size == 4 && code.highest == 0xffffffff,
                    _ => true,
                };
                let expected_helper = (fixture["family"] == "Hexagon")
                    .then_some("ghidra.app.util.viewer.field.HexagonParallelInstructionHelper");
                let helper_matches = observed.required_parallel_helper.as_deref() == expected_helper;
                for row in rows {
                    total_rows += 1;
                    let offset = row["fixture_offset_bytes"].as_u64().unwrap() as usize;
                    let decoded =
                        decoder.decode_instruction(&bytes[offset..], number(&row["address"]["getOffset_bytes"]));
                    let mut issues = Vec::new();
                    if !metadata_matches {
                        issues.push("native code-space metadata differs from selected source facts".to_owned());
                    }
                    if !boundary_matches || !helper_matches || observed.alignment_bytes == 0 {
                        issues.push("native bounds/alignment/processor-helper metadata differs".to_owned());
                    }
                    if decoded.spaces != observed.spaces || decoded.code_space != observed.code_space {
                        issues.push("metadata identities changed after byte-window binding".to_owned());
                    }
                    let interpretation = compare_row(&decoded, row, &mut issues);
                    if !issues.is_empty() {
                        failures += 1;
                    }
                    row_outcomes.push(json!({"verdict":if issues.is_empty(){"compared"}else{"mismatch"},
                        "interpretation":interpretation,"issues":issues,"java":row,"native":decoded,
                        "standalone_not_flowed":true}));
                }
            }
        }
        outcomes.push(json!({"fixture":name,"profile":profile,"open_error":open_error,"metadata":metadata,
            "expected_rows":rows.len(),"row_outcomes":row_outcomes,
            "manual_function_extents":owned["functions"],"program_flowed_rows":java["program_oracle"]["rows"],
            "native_acceptance_claim":false,"reason":"comparison draft; helper/delay/context limits remain explicit"}));
    }
    let report = json!({"schema_version":1,"phase":"extended_native_comparison_not_acceptance",
        "profile_outcomes":outcomes,"total_rows":total_rows,"failed_rows":failures});
    let encoded = serde_json::to_vec_pretty(&report).unwrap();
    assert!(encoded.len() <= 32 * 1024 * 1024, "bounded native outcome report");
    // The comparison always runs; only publishing the outcome report is opt-in, to a fresh create-only path.
    if let Some(path) = std::env::var_os("SLEIGH_EXTENDED_REPORT") {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(path).expect("new report");
        std::io::Write::write_all(&mut file, &encoded).unwrap();
    }
    assert_eq!(total_rows, 104);
    assert_eq!(report["profile_outcomes"].as_array().unwrap().len(), 13);
    assert_eq!(
        failures, 0,
        "all thirteen outcomes retained; mismatches include Hexagon, never omitted or gold-filtered"
    );
}

fn input(name: &str) -> &'static [u8] {
    match name {
        "8051-v1" => include_bytes!("../../../tests/fixtures/sleigh/extended/8051-v1.bin"),
        "PIC-v1" => include_bytes!("../../../tests/fixtures/sleigh/extended/PIC-v1.bin"),
        "SuperH-v2" => include_bytes!("../../../tests/fixtures/sleigh/extended/SuperH-v2.bin"),
        "V850-v1" => include_bytes!("../../../tests/fixtures/sleigh/extended/V850-v1.bin"),
        "TriCore-v1" => include_bytes!("../../../tests/fixtures/sleigh/extended/TriCore-v1.bin"),
        "Xtensa-v1" => include_bytes!("../../../tests/fixtures/sleigh/extended/Xtensa-v1.bin"),
        "Z80-v1" => include_bytes!("../../../tests/fixtures/sleigh/extended/Z80-v1.bin"),
        "HCS12-v1" => include_bytes!("../../../tests/fixtures/sleigh/extended/HCS12-v1.bin"),
        "6805-v1" => include_bytes!("../../../tests/fixtures/sleigh/extended/6805-v1.bin"),
        "CR16-v1" => include_bytes!("../../../tests/fixtures/sleigh/extended/CR16-v1.bin"),
        "eBPF-v1" => include_bytes!("../../../tests/fixtures/sleigh/extended/eBPF-v1.bin"),
        "Loongarch-v1" => include_bytes!("../../../tests/fixtures/sleigh/extended/Loongarch-v1.bin"),
        "Hexagon-v2" => include_bytes!("../../../tests/fixtures/sleigh/extended/Hexagon-v2.bin"),
        _ => panic!("unreviewed extended fixture {name}"),
    }
}
