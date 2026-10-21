//! Ordinary Raw Project matrix over the selected sixteen-family Sleigh roster.
//! Supplying every truth entry measures retention, not autonomous entry discovery.

use std::collections::BTreeSet;
use std::path::Path;

use rampage_api::FunctionsQuery;
use rampage_api::search_code::{CodePattern, CodeSearchKind, CodeSearchQuery};
use rampage_api::{DisassemblyLine, Project};
use rampage_arch::{DecodeGateReason, Flow};
use rampage_loaders::{Binary, RawCodeOptions, RawProfile};

struct Fixture {
    name: String,
    profile: RawProfile,
    base: u64,
    bytes: Vec<u8>,
    functions: Vec<(u64, u64)>,
}

fn fixtures() -> Vec<Fixture> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sleigh");
    let read = |path: &Path| -> serde_json::Value { serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap() };
    let pilot = read(&root.join("truth.json"));
    let extended = read(&root.join("extended/truth-current.json"));
    let mut all = Vec::new();
    for (is_extended, fixture) in pilot["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| (false, item))
        .chain(extended["fixtures"].as_array().unwrap().iter().map(|item| (true, item)))
    {
        let name = fixture["name"].as_str().unwrap().to_owned();
        let text = fixture["base_byte_offset"].as_str().unwrap();
        let base = u64::from_str_radix(text.trim_start_matches("0x"), 16).unwrap();
        let (start, end) = if is_extended {
            ("start_bytes", "end_exclusive_bytes")
        } else {
            ("entry_offset_bytes", "extent_end_exclusive_bytes")
        };
        let functions = fixture["functions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|function| (base + function[start].as_u64().unwrap(), base + function[end].as_u64().unwrap()))
            .collect();
        let path = if is_extended {
            root.join("extended").join(format!("{name}.bin"))
        } else {
            root.join(fixture["bytes_file"].as_str().unwrap())
        };
        let profile = RawProfile::from_language_id(fixture["language_id"].as_str().unwrap()).unwrap();
        all.push(Fixture { name, profile, base, bytes: std::fs::read(path).unwrap(), functions });
    }
    all
}

fn project(fixture: &Fixture, entry: Option<u64>, seeds: Vec<u64>) -> Project {
    let options = RawCodeOptions { profile: fixture.profile, base: fixture.base, entry, seeds };
    Project::new(Binary::from_raw_code(fixture.bytes.clone(), options).unwrap())
}

fn line_end(line: &DisassemblyLine) -> u64 {
    line.address + line.bytes.len() as u64 / 2
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Outcome {
    retained: usize,
    exact: usize,
}

/// Discovery, function rows, listing, graph and code search must agree; every extent miss needs a gate.
fn measure(fixture: &Fixture, project: &Project, mode: &str) -> (Outcome, Vec<serde_json::Value>) {
    let rows = project.functions(&FunctionsQuery::default()).unwrap();
    let mut listed = BTreeSet::new();
    let mut gates = Vec::new();
    for row in &rows.items {
        let listing = project.function_listing(row.address).unwrap();
        let lines: Vec<_> = listing.blocks.iter().flatten().collect();
        assert_eq!(lines.len(), row.instructions, "{} {mode} {:#x}", fixture.name, row.address);
        assert_eq!(listing.blocks.len(), row.blocks);
        let graph = project.function_graph(row.address).unwrap();
        assert_eq!(graph.blocks.len(), row.blocks);
        for line in lines {
            listed.insert(line.address);
            let wire = serde_json::to_value(line).unwrap();
            if let Some(gate) = line.decode_gate {
                assert_eq!(gate.address, line.address);
                assert_eq!(gate.profile, fixture.profile.language_id());
                assert_eq!(wire["flow"]["kind"], "unknown");
                assert_eq!(wire["decode_gate"]["address"], format!("{:#x}", line.address));
                assert_eq!(line.flow, Flow::Invalid, "Rust STOP sentinel only");
                assert!(line.noreturn.is_none());
                assert!(!line.text.is_empty(), "valid unknown instruction keeps its text");
                gates.push(serde_json::json!({"function": row.address, "gate": gate}));
            } else {
                assert_ne!(wire["flow"]["kind"], "unknown");
            }
        }
    }
    let query =
        CodeSearchQuery::new(CodeSearchKind::Instruction { mnemonic: CodePattern::new("*").unwrap(), operands: None })
            .unwrap();
    let report = project.search_code(&query).unwrap();
    let searched: BTreeSet<_> = report.hits.iter().map(|hit| hit.address).collect();
    assert_eq!(searched, listed, "{} {mode}: search and listing disagree: {:?}", fixture.name, report.limitations);
    assert_eq!(report.scan_complete, gates.is_empty(), "{} {mode}", fixture.name);
    for hit in &report.hits {
        let line = project.disassemble(Some(&format!("{:#x}", hit.site)), 1).unwrap().remove(0);
        assert_eq!(
            (&hit.bytes, &hit.text, hit.flow, hit.decode_gate),
            (&line.bytes, &line.text, line.flow, line.decode_gate)
        );
    }

    let mut outcome = Outcome::default();
    for &(entry, end) in &fixture.functions {
        let Some(row) = rows.items.iter().find(|row| row.address == entry) else { continue };
        outcome.retained += 1;
        let listing = project.function_listing(entry).unwrap();
        let mut covered = BTreeSet::new();
        for line in listing.blocks.iter().flatten() {
            covered.extend(line.address..line_end(line));
        }
        assert_eq!(covered.len() as u64, row.size, "{} {mode} {entry:#x}", fixture.name);
        if covered == (entry..end).collect::<BTreeSet<_>>() {
            outcome.exact += 1;
        } else {
            let gated = listing.blocks.iter().flatten().any(|line| line.decode_gate.is_some());
            assert!(gated, "unexplained extent miss {} {mode} {entry:#x}: {listing:#?}", fixture.name);
        }
    }
    (outcome, gates)
}

/// Measured per-fixture (manual retained, manual exact, call-only retained, call-only exact) and manual-seed
/// gates. Misses are user-defined, context, delay-slot and helper gates, or PIC's computed call.
type ExpectedRow = (&'static str, [usize; 4], &'static [(u64, &'static str)]);

const EXPECTED: &[ExpectedRow] = &[
    ("msp430", [2, 2, 2, 2], &[]),
    ("avr8", [2, 2, 2, 2], &[]),
    ("6502", [2, 2, 2, 2], &[]),
    ("8051-v1", [2, 0, 2, 0], &[(0x1003, "user_defined_operation"), (0x1008, "user_defined_operation")]),
    ("PIC-v1", [2, 1, 1, 0], &[(0x204, "context_mediated_flow")]),
    ("SuperH-v2", [2, 0, 1, 0], &[(0x1000, "delay_slot_aggregation"), (0x1012, "delay_slot_aggregation")]),
    ("V850-v1", [2, 2, 2, 2], &[]),
    ("TriCore-v1", [2, 1, 1, 0], &[(0x1000, "user_defined_operation"), (0x1012, "user_defined_operation")]),
    ("Xtensa-v1", [2, 2, 2, 2], &[]),
    ("Z80-v1", [2, 2, 2, 2], &[]),
    ("HCS12-v1", [2, 1, 1, 0], &[(0x2000, "user_defined_operation"), (0x2009, "user_defined_operation")]),
    ("6805-v1", [2, 2, 2, 2], &[]),
    ("CR16-v1", [2, 2, 2, 2], &[]),
    ("eBPF-v1", [2, 2, 2, 2], &[]),
    ("Loongarch-v1", [2, 2, 2, 2], &[]),
    ("Hexagon-v2", [2, 0, 1, 0], &[(0x1000, "processor_helper_required"), (0x1010, "processor_helper_required")]),
];

#[test]
fn every_roster_fixture_agrees_across_discovery_listing_and_search_with_gates_reported() {
    let mut totals = [0usize; 5];
    let mut matrix = Vec::new();
    let mut measured = Vec::new();
    for fixture in fixtures() {
        let entries: Vec<u64> = fixture.functions.iter().map(|(entry, _)| *entry).collect();
        let manual = project(&fixture, None, entries.clone());
        let (manual_outcome, manual_gates) = measure(&fixture, &manual, "manual");
        assert_eq!(manual_outcome.retained, entries.len(), "{}: every supplied entry is retained", fixture.name);
        let call_only = project(&fixture, Some(fixture.base), vec![]);
        let (call_outcome, call_gates) = measure(&fixture, &call_only, "call_only");
        let row = [manual_outcome.retained, manual_outcome.exact, call_outcome.retained, call_outcome.exact];
        totals[0] += entries.len();
        for (total, value) in totals[1..].iter_mut().zip(row) {
            *total += value;
        }
        let gates: Vec<(u64, String)> = manual_gates
            .iter()
            .map(|gate| {
                let address = gate["gate"]["address"].as_str().unwrap().trim_start_matches("0x");
                (u64::from_str_radix(address, 16).unwrap(), gate["gate"]["reason"].as_str().unwrap().to_owned())
            })
            .collect();
        measured.push((fixture.name.clone(), row, gates));
        matrix.push(serde_json::json!({
            "fixture": fixture.name, "profile": fixture.profile.language_id(), "denominator": entries.len(),
            "manual": row[..2], "call_only": row[2..], "manual_gates": manual_gates, "call_only_gates": call_gates,
        }));
    }
    eprintln!("RAW_ROSTER_MATRIX {}", serde_json::json!({"totals": totals, "outcomes": matrix}));
    assert_eq!(measured.len(), EXPECTED.len());
    for ((name, row, gates), (expected_name, expected_row, expected_gates)) in measured.iter().zip(EXPECTED) {
        assert_eq!(name, expected_name);
        assert_eq!(row, expected_row, "{name}");
        let expected_gates: Vec<_> = expected_gates.iter().map(|(at, reason)| (*at, (*reason).to_owned())).collect();
        assert_eq!(gates, &expected_gates, "{name}");
    }
    // Same denominators and totals as the explicit-window matrix: entries 32/32 manual and 27/32 call-only.
    assert_eq!(totals, [32, 32, 23, 27, 20]);
}

#[test]
fn hexagon_helper_gated_entry_is_a_valid_function_with_unresolved_exit_and_no_noreturn() {
    let fixture = fixtures().into_iter().find(|fixture| fixture.name == "Hexagon-v2").unwrap();
    assert_eq!(
        fixture.profile.parallel_helper(),
        Some("ghidra.app.util.viewer.field.HexagonParallelInstructionHelper")
    );
    let project = project(&fixture, None, vec![0x1000]);
    let listing = project.function_listing(0x1000).unwrap();
    let lines: Vec<_> = listing.blocks.iter().flatten().collect();
    assert_eq!(lines.len(), 1);
    let gate = lines[0].decode_gate.expect("helper-gated entry keeps its gate");
    assert_eq!(gate.address, 0x1000);
    assert_eq!(gate.reason, DecodeGateReason::ProcessorHelperRequired);
    assert!(lines[0].noreturn.is_none());
    let wire = serde_json::to_value(lines[0]).unwrap();
    assert_eq!(wire["flow"]["kind"], "unknown");
    assert_eq!(wire["decode_gate"]["reason"], "processor_helper_required");
    assert!(project.function_graph(0x1000).unwrap().edges.is_empty());
    let summary = project.function_summary(0x1000).unwrap();
    assert!(summary.limitations.iter().any(|limit| limit.contains("unknown successor flow")), "{summary:?}");
    assert!(project.functions(&FunctionsQuery::default()).unwrap().items.iter().all(|row| row.address == 0x1000));
}

#[test]
fn superh_delay_slot_gate_within_a_body_stops_successors_and_serializes_unknown() {
    let fixture = fixtures().into_iter().find(|fixture| fixture.name == "SuperH-v2").unwrap();
    assert!(fixture.profile.big_endian());
    let project = project(&fixture, None, vec![0x1010]);
    let listing = project.function_listing(0x1010).unwrap();
    let lines: Vec<_> = listing.blocks.iter().flatten().collect();
    let gated: Vec<_> = lines.iter().filter(|line| line.decode_gate.is_some()).collect();
    assert_eq!(gated.len(), 1);
    let gate = gated[0].decode_gate.unwrap();
    assert_eq!(gate.address, 0x1012);
    assert_eq!(gate.reason, DecodeGateReason::DelaySlotAggregation);
    assert!(lines.iter().any(|line| line.address == 0x1010 && line.decode_gate.is_none()), "gate is inside the body");
    assert!(lines.iter().all(|line| line.address <= 0x1012), "no successor is discovered past the gate");
    assert!(gated[0].noreturn.is_none());
    let wire = serde_json::to_value(gated[0]).unwrap();
    assert_eq!(wire["flow"]["kind"], "unknown");
    assert_eq!(wire["decode_gate"]["reason"], "delay_slot_aggregation");
    let disassembled = project.disassemble(Some("0x1012"), 1).unwrap();
    assert_eq!(disassembled[0].decode_gate, Some(gate));
    // The delay-slot translation reads bytes past the gated block end; search must decode it as listing does.
    let query =
        CodeSearchQuery::new(CodeSearchKind::Instruction { mnemonic: CodePattern::new("*").unwrap(), operands: None })
            .unwrap();
    let report = project.search_code(&query).unwrap();
    let hit = report.hits.iter().find(|hit| hit.site == 0x1012).expect("gated delay-slot instruction is searched");
    assert_eq!(hit.decode_gate, Some(gate));
    assert_eq!(serde_json::to_value(hit).unwrap()["flow"]["kind"], "unknown");
    assert!(report.total_is_lower_bound && !report.scan_complete);
}

#[test]
fn big_endian_identity_follows_the_profile_and_drift_is_refused() {
    for profile in RawProfile::ALL {
        let options = RawCodeOptions { profile, base: 0x1000, entry: None, seeds: vec![] };
        let binary = Binary::from_raw_code(vec![0; 4], options).unwrap();
        assert_eq!(binary.big_endian, profile.big_endian(), "{profile:?}");
        assert_eq!(binary.arch, profile.arch());
        assert!(binary.raw_interpretation_identity().unwrap().is_some());
        let mut drifted = binary;
        drifted.big_endian = !profile.big_endian();
        assert!(drifted.raw_interpretation_identity().is_err(), "{profile:?}");
        let mut project = Project::new(
            Binary::from_raw_code(vec![0; 4], RawCodeOptions { profile, base: 0x1000, entry: None, seeds: vec![] })
                .unwrap(),
        );
        project.binary.big_endian = !profile.big_endian();
        assert!(project.disassemble(Some("0x1000"), 1).is_err(), "{profile:?}");
    }
}
