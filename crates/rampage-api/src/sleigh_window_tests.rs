use super::*;

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct OwnedFixture {
    path: PathBuf,
    _file: File,
}

impl OwnedFixture {
    fn new(bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rampage-sleigh-window-{}-{}.bin",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        file.write_all(bytes).unwrap();
        Self { path, _file: file }
    }
}

impl Drop for OwnedFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn request(profile: &str, length: usize) -> SleighWindowRequest {
    serde_json::from_value(serde_json::json!({
        "profile": profile,
        "offset": 0,
        "length": length,
        "base_address": "0x1000",
    }))
    .unwrap()
}

// Hand-encoded, repository-owned instructions, not extracted from private firmware or executables.
// MSP430: CALL #0x1008; RET; orphan RET; callee RET.
const MSP430_CALL: &[u8] = &[0xb0, 0x12, 0x08, 0x10, 0x30, 0x41, 0x30, 0x41, 0x30, 0x41];
// AVR8: RCALL +3 words; RET; two orphan RETs; callee RET. All API addresses remain BYTE offsets.
const AVR8_CALL: &[u8] = &[0x03, 0xd0, 0x08, 0x95, 0x08, 0x95, 0x08, 0x95, 0x08, 0x95];
// 6502: JSR $1008; RTS; four orphan NOPs; callee RTS.
const MOS6502_CALL: &[u8] = &[0x20, 0x08, 0x10, 0x60, 0xea, 0xea, 0xea, 0xea, 0x60];

#[test]
fn malformed_requests_fail_before_source_access() {
    let base = serde_json::to_value(serde_json::json!({
        "profile": "6502:LE:16:default", "offset": 0, "length": 1, "base_address": "0x1000"
    }))
    .unwrap();
    for (field, value) in [
        ("profile", serde_json::json!("../../processor.sla")),
        ("profile", serde_json::json!("msp430")),
        ("length", serde_json::json!(0)),
        ("length", serde_json::json!(MAX_SLEIGH_WINDOW_BYTES + 1)),
        ("base_address", serde_json::json!("0xffffffffffffffff")),
        ("offset", serde_json::json!("0xffffffffffffffff")),
        ("instruction_limit", serde_json::json!(0)),
        ("instruction_limit", serde_json::json!(MAX_SLEIGH_WINDOW_INSTRUCTIONS + 1)),
        ("listing_limit", serde_json::json!(0)),
        ("timeout_ms", serde_json::json!(0)),
        ("decode_attempt_limit", serde_json::json!(0)),
        ("decode_attempt_limit", serde_json::json!(MAX_SLEIGH_DECODE_ATTEMPTS + 1)),
        ("handle_open_limit", serde_json::json!(0)),
        ("handle_open_limit", serde_json::json!(MAX_SLEIGH_HANDLE_OPENS + 1)),
        ("stop_limit", serde_json::json!(MAX_SLEIGH_STOP_DIAGNOSTICS + 1)),
        ("discover", serde_json::json!(true)),
        ("seeds", serde_json::json!(["0x1000"])),
    ] {
        let mut input = base.clone();
        input[field] = value;
        let request: SleighWindowRequest = serde_json::from_value(input).unwrap();
        let error = inspect_sleigh_file_range(Path::new("/nonexistent/sleigh-window"), &request).unwrap_err();
        assert!(matches!(error, ApiError::Invalid(_)), "{field}: {error}");
    }
}

#[test]
fn seeds_are_bounded_aligned_and_explicit_not_auto_entries() {
    let mut request = request("TI_MSP430:LE:16:default", 8);
    request.discover = true;
    for seeds in [
        vec![FileOffset(0xffe)],
        vec![FileOffset(0x1008)],
        vec![FileOffset(0x1001)],
        vec![FileOffset(0x1000); MAX_SLEIGH_WINDOW_SEEDS + 1],
    ] {
        request.seeds = seeds;
        let result = validate(&request).and_then(|(_, end, seeds)| {
            let decoder = SleighDecoder::open(&request.profile).unwrap();
            validate_profile_mapping(&request, end, &seeds, decoder.metadata())
        });
        assert!(result.is_err());
    }
    request.seeds = vec![FileOffset(0x1004), FileOffset(0x1000), FileOffset(0x1004)];
    assert_eq!(validate(&request).unwrap().2, vec![0x1000, 0x1004]);
}

#[test]
fn single_code_space_memory_never_exposes_other_bytes_or_data_reads() {
    let memory = CodeWindow { base: 0x1000, bytes: vec![1, 2, 3] };
    assert_eq!(memory.code_from(0x1001), Some(&[2, 3][..]));
    assert!(memory.code_from(0xfff).is_none());
    assert!(memory.code_from(0x1003).is_none());
    assert!(!memory.is_mapped(0x1003));
    assert!(!memory.is_executable(0x1003));
    assert!(!memory.immediates_may_be_addresses());
    assert_eq!(memory.read_pointer(0x1000, 2), None);
    assert_eq!(memory.read_constant(0x1000, 2), None);
}

#[test]
fn factory_failure_is_checked_and_discards_the_whole_program() {
    let memory = CodeWindow { base: 0x1000, bytes: vec![0x60] };
    let request = request("6502:LE:16:default", 1);
    let observations = Arc::new(Mutex::new(Observations::default()));
    let work = Arc::new(WorkCounters::default());
    let error = seeded_discovery(&memory, &request, &[0x1000], &observations, &work, Instant::now(), || {
        Err(rampage_decompiler::Error::Ghidra("injected decoder open failure".into()))
    })
    .unwrap_err();
    assert!(matches!(error, ApiError::Invalid(_)));
    assert!(error.to_string().contains("injected decoder open failure"));
}

#[test]
fn elapsed_deadline_is_checked_even_if_discovery_finishes_without_a_decode() {
    let observations = Arc::new(Mutex::new(Observations::default()));
    let started = Instant::now().checked_sub(Duration::from_secs(20)).unwrap();
    let error = check_completion(&observations, started, 10_000).unwrap_err();
    assert!(error.to_string().contains("deadline"));
}

#[test]
fn expired_deadline_prevents_native_factory_initialization() {
    let memory = CodeWindow { base: 0x1000, bytes: vec![0x60] };
    let request = request("6502:LE:16:default", 1);
    let observations = Arc::new(Mutex::new(Observations::default()));
    let work = Arc::new(WorkCounters::default());
    let opened = AtomicUsize::new(0);
    let started = Instant::now().checked_sub(Duration::from_secs(20)).unwrap();
    let error = seeded_discovery(&memory, &request, &[0x1000], &observations, &work, started, || {
        opened.fetch_add(1, Ordering::Relaxed);
        Err(rampage_decompiler::Error::Ghidra("must not be reached".into()))
    })
    .unwrap_err();
    assert!(error.to_string().contains("deadline"));
    assert_eq!(opened.load(Ordering::Relaxed), 0);
    assert_eq!(work.handle_open_attempts.load(Ordering::Relaxed), 0);
}

#[test]
fn discovery_has_a_smaller_window_cap_independent_of_linear_listing() {
    let mut request = request("6502:LE:16:default", MAX_SLEIGH_DISCOVERY_BYTES + 1);
    assert!(validate(&request).is_ok());
    request.discover = true;
    request.seeds = vec![FileOffset(0x1000)];
    assert!(validate(&request).unwrap_err().to_string().contains("4096"));
}

#[test]
fn exhausted_handle_budget_never_calls_the_native_factory() {
    let memory = CodeWindow { base: 0x1000, bytes: vec![0x60] };
    let mut request = request("6502:LE:16:default", 1);
    request.handle_open_limit = 1;
    let work = Arc::new(WorkCounters::default());
    work.handle_open_attempts.store(1, Ordering::Relaxed);
    let opened = AtomicUsize::new(0);
    let observations = Arc::new(Mutex::new(Observations::default()));
    let error = seeded_discovery(&memory, &request, &[0x1000], &observations, &work, Instant::now(), || {
        opened.fetch_add(1, Ordering::Relaxed);
        Err(rampage_decompiler::Error::Ghidra("must not be reached".into()))
    })
    .unwrap_err();
    assert_eq!(opened.load(Ordering::Relaxed), 0);
    assert_eq!(work.handle_open_attempts.load(Ordering::Relaxed), 1);
    assert_eq!(work.native_decode_attempts.load(Ordering::Relaxed), 0);
    assert_eq!(observations.lock().unwrap().work_stop_status, Some(DecodeStatus::BudgetExceeded));
    assert!(error.to_string().contains("BudgetExceeded"));
    assert!(error.to_string().contains("entire program discarded"));
}

#[test]
fn repeated_cached_decodes_charge_total_work_without_reentering_native_code() {
    let instruction = DecodedInstruction {
        profile: "6502:LE:16:default".into(),
        address: 0x1000,
        status: DecodeStatus::Valid,
        length: 1,
        translated_extent: 1,
        mnemonic: "RTS".into(),
        operand_text: String::new(),
        flow: InstructionFlow::Return,
        code_space: 1,
        spaces: Vec::new(),
        pcode: Vec::new(),
        context_mediated_flow: false,
        processor_helper_required: false,
        unknown_gate: None,
        diagnostic: None,
    };
    let observations = Arc::new(Mutex::new(Observations::default()));
    observations.lock().unwrap().instructions.insert(0x1000, instruction);
    let work = Arc::new(WorkCounters::default());
    let mut decoder = DiscoveryDecoder {
        decoder: None,
        observations: Arc::clone(&observations),
        instruction_limit: 1,
        started: Instant::now(),
        timeout: Duration::from_secs(10),
        retain_pcode: false,
        work: Arc::clone(&work),
        decode_attempt_limit: 2,
        handle_open_limit: 1,
        last_gate: None,
    };
    assert!(decoder.observation(&[0x60], 0x1000).is_some());
    assert!(decoder.observation(&[0x60], 0x1000).is_some());
    assert!(decoder.observation(&[0x60], 0x1000).is_none());
    assert_eq!(work.decode_attempts.load(Ordering::Relaxed), 2);
    assert_eq!(work.native_decode_attempts.load(Ordering::Relaxed), 0);
    assert_eq!(observations.lock().unwrap().work_stop_status, Some(DecodeStatus::BudgetExceeded));
}

#[test]
fn shared_atomic_charges_do_not_overshoot_under_contention() {
    let counter = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let counter = Arc::clone(&counter);
            scope.spawn(move || {
                for _ in 0..50 {
                    charge(&counter, 75);
                }
            });
        }
    });
    assert_eq!(counter.load(Ordering::Relaxed), 75);
}

#[test]
fn factory_admission_serializes_against_cross_decode_budget_failure() {
    let request = request("6502:LE:16:default", 1);
    let observations = Arc::new(Mutex::new(Observations::default()));
    let work = Arc::new(WorkCounters::default());
    work.decode_attempts.store(1, Ordering::Relaxed);
    let entered = std::sync::Barrier::new(2);
    let release = std::sync::Barrier::new(2);
    let decode_waiting = std::sync::Barrier::new(2);
    let started = Instant::now();
    std::thread::scope(|scope| {
        let opener = scope.spawn(|| {
            open_discovery_decoder(&request, &observations, &work, started, || {
                entered.wait();
                release.wait();
                SleighDecoder::open(&request.profile)
            })
        });
        entered.wait();
        let decoder = scope.spawn(|| {
            let mut decoder = DiscoveryDecoder {
                decoder: None,
                observations: Arc::clone(&observations),
                instruction_limit: 1,
                started,
                timeout: Duration::from_secs(10),
                retain_pcode: false,
                work: Arc::clone(&work),
                decode_attempt_limit: 1,
                handle_open_limit: request.handle_open_limit,
                last_gate: None,
            };
            decode_waiting.wait();
            decoder.observation(&[0x60], 0x1000).is_none()
        });
        decode_waiting.wait();
        let admission_holds_failure_guard = observations.try_lock().is_err();
        // Release before asserting so a regressed implementation cannot strand either test thread.
        release.wait();
        assert!(opener.join().unwrap().is_some());
        assert!(decoder.join().unwrap());
        assert!(admission_holds_failure_guard);
    });
    assert_eq!(observations.lock().unwrap().work_stop_status, Some(DecodeStatus::BudgetExceeded));
    let late_opened = AtomicUsize::new(0);
    assert!(
        open_discovery_decoder(&request, &observations, &work, started, || {
            late_opened.fetch_add(1, Ordering::Relaxed);
            Err(rampage_decompiler::Error::Ghidra("must not be reached".into()))
        })
        .is_none()
    );
    assert_eq!(late_opened.load(Ordering::Relaxed), 0);
    assert_eq!(work.handle_open_attempts.load(Ordering::Relaxed), 1);
}

#[test]
fn capped_json_writer_stops_traversal_without_allocating_the_full_serialization() {
    struct ManyRows<'a>(&'a AtomicUsize);
    impl Serialize for ManyRows<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeSeq;
            let mut sequence = serializer.serialize_seq(Some(100_000))?;
            for _ in 0..100_000 {
                self.0.fetch_add(1, Ordering::Relaxed);
                sequence.serialize_element("a repeated row that cannot fit the small output cap")?;
            }
            sequence.end()
        }
    }
    let visited = AtomicUsize::new(0);
    assert!(!fits_json_budget(&ManyRows(&visited), 64));
    assert!(visited.load(Ordering::Relaxed) < 3);
    assert!(fits_json_budget(&"abc", 5));
    assert!(!fits_json_budget(&"abc", 4));
}

#[test]
fn retained_cache_budget_refuses_new_native_observations_without_publishing_partial_records() {
    let observations = Arc::new(Mutex::new(Observations::default()));
    observations.lock().unwrap().retained_bytes = MAX_SLEIGH_CACHE_BYTES;
    let work = Arc::new(WorkCounters::default());
    let mut decoder = DiscoveryDecoder {
        decoder: Some(SleighDecoder::open("6502:LE:16:default").unwrap()),
        observations: Arc::clone(&observations),
        instruction_limit: 1,
        started: Instant::now(),
        timeout: Duration::from_secs(10),
        retain_pcode: true,
        work: Arc::clone(&work),
        decode_attempt_limit: 1,
        handle_open_limit: 1,
        last_gate: None,
    };
    assert!(decoder.observation(&[0x60], 0x1000).is_none());
    let state = observations.lock().unwrap();
    assert!(state.instructions.is_empty());
    assert_eq!(state.work_stop_status, Some(DecodeStatus::BudgetExceeded));
    assert!(state.failure.as_ref().unwrap().contains("retained cache budget"));
    assert_eq!(work.native_decode_attempts.load(Ordering::Relaxed), 1);
}

#[test]
fn three_pilots_use_native_program_discovery_and_do_not_promote_orphan_code() {
    for (profile, bytes) in [
        ("TI_MSP430:LE:16:default", MSP430_CALL),
        ("avr8:LE:16:default", AVR8_CALL),
        ("6502:LE:16:default", MOS6502_CALL),
    ] {
        let file = OwnedFixture::new(bytes);
        let mut request = request(profile, bytes.len());
        request.discover = true;
        request.seeds = vec![FileOffset(0x1000)];
        let report = inspect_sleigh_file_range(&file.path, &request).unwrap();
        assert_eq!(report.completion, SleighWindowCompletion::SeededDiscoveryFinished);
        let program = report.program.as_ref().unwrap();
        assert_eq!(
            program.functions.iter().map(|function| function.address).collect::<Vec<_>>(),
            vec![0x1000, 0x1008],
            "{profile}: {report:#?}"
        );
        assert!(
            program.xrefs.iter().any(|xref| xref.from == 0x1000
                && xref.to == 0x1008
                && xref.kind == rampage_analysis::discover::XrefKind::Call),
            "{profile}: {report:#?}"
        );
        assert_eq!(
            report.rows.iter().map(|row| row.address).collect::<Vec<_>>(),
            if profile.starts_with("TI_") {
                vec![0x1000, 0x1004, 0x1008]
            } else if profile.starts_with("avr") {
                vec![0x1000, 0x1002, 0x1008]
            } else {
                vec![0x1000, 0x1003, 0x1008]
            }
        );
        assert!(report.rows.iter().all(|row| row.status == DecodeStatus::Valid && row.pcode.is_none()));
        assert_eq!(report.profile.language_id, profile);
        assert!(report.profile.abi.contains("unknown"));
        if profile.starts_with("avr") {
            let code = report.profile.spaces.iter().find(|space| space.id == report.profile.code_space).unwrap();
            assert_eq!(code.word_size, 2);
        }
    }
}

#[test]
fn external_direct_target_has_xref_but_is_never_followed() {
    let file = OwnedFixture::new(&[0x20, 0x00, 0x20, 0x60]);
    let mut request = request("6502:LE:16:default", 4);
    request.discover = true;
    request.seeds = vec![FileOffset(0x1000)];
    let report = inspect_sleigh_file_range(&file.path, &request).unwrap();
    let program = report.program.as_ref().unwrap();
    assert_eq!(program.functions.len(), 1);
    assert_eq!(program.xrefs[0].to, 0x2000);
    assert!(report.rows.iter().all(|row| (0x1000..0x1004).contains(&row.address)));
    assert!(report.stops.iter().any(|stop| stop.reason == "direct_target_outside_window_not_followed"));
}

#[test]
fn discovery_instruction_exhaustion_is_not_partial_success() {
    let file = OwnedFixture::new(MOS6502_CALL);
    let mut request = request("6502:LE:16:default", MOS6502_CALL.len());
    request.discover = true;
    request.seeds = vec![FileOffset(0x1000)];
    request.instruction_limit = 1;
    let error = inspect_sleigh_file_range(&file.path, &request).unwrap_err();
    assert!(error.to_string().contains("instruction budget"), "{error}");
}

#[test]
fn linear_pagination_keeps_complete_bounds_source_receipt_and_pcode_opt_in() {
    let file = OwnedFixture::new(&[0xff, 0xff, 0xea, 0x60, 0xea, 0xea, 0xff]);
    let mut request = request("6502:LE:16:default", 4);
    request.offset = FileOffset(2);
    request.listing_offset = 1;
    request.listing_limit = 1;
    let report = inspect_sleigh_file_range(&file.path, &request).unwrap();
    assert_eq!(report.completion, SleighWindowCompletion::LinearWindowEnd);
    assert!(report.program.is_none());
    assert_eq!(report.linear_consumed_bytes, Some(4));
    assert_eq!(report.linear_remaining_bytes, Some(0));
    assert_eq!(report.listing_total, 4);
    assert_eq!(report.decode_attempts, 4);
    assert_eq!(report.native_decode_attempts, 4);
    assert_eq!(report.handle_open_attempts, 1);
    assert_eq!(report.listing_omitted_before, 1);
    assert_eq!(report.listing_omitted_after, 2);
    assert_eq!(report.listing_next_offset, Some(2));
    assert_eq!(report.rows[0].address, 0x1001);
    assert_eq!(report.rows[0].source_byte_offset, 3);
    assert_eq!(report.rows[0].bytes, "60");
    assert_eq!(report.source_size, 7);
    assert_eq!(report.source_range_sha256, rampage_arch::hex::bytes(&Sha256::digest([0xea, 0x60, 0xea, 0xea])));
    assert_eq!(report.source_range_sha256_after, report.source_range_sha256);
    let json = serde_json::to_value(&report).unwrap();
    assert!(json["rows"][0].get("pcode").is_none());
    request.include_pcode = true;
    let pcode = inspect_sleigh_file_range(&file.path, &request).unwrap();
    assert!(!pcode.rows[0].pcode.as_ref().unwrap().is_empty());
    request.listing_offset = 5;
    assert!(inspect_sleigh_file_range(&file.path, &request).is_err());
}

#[test]
fn linear_instruction_limit_is_explicit_not_window_completion() {
    let file = OwnedFixture::new(&[0xea, 0xea, 0x60]);
    let mut request = request("6502:LE:16:default", 3);
    request.instruction_limit = 1;
    let report = inspect_sleigh_file_range(&file.path, &request).unwrap();
    assert_eq!(report.completion, SleighWindowCompletion::LinearInstructionLimit);
    assert_eq!(report.linear_consumed_bytes, Some(1));
    assert_eq!(report.linear_remaining_bytes, Some(2));
    assert_eq!(report.decode_addresses_observed, 1);
}

#[test]
fn incomplete_tail_is_retained_as_a_stop_and_is_not_synthetic_padding_code() {
    let file = OwnedFixture::new(&[0xb0, 0x12, 0x08]);
    let request = request("TI_MSP430:LE:16:default", 3);
    let report = inspect_sleigh_file_range(&file.path, &request).unwrap();
    assert_eq!(report.completion, SleighWindowCompletion::LinearDecodeStopped);
    assert_eq!(report.linear_consumed_bytes, Some(0));
    assert!(matches!(report.rows[0].status, DecodeStatus::Truncated | DecodeStatus::InvalidOrTruncated));
    assert_eq!(report.stops.len(), 1);
}

#[test]
fn valid_but_unknown_pcode_flow_is_not_reported_as_an_invalid_opcode() {
    let file = OwnedFixture::new(&[0x0f, 0xa2, 0xc3]);
    let mut request = request("x86:LE:64:default", 3);
    request.discover = true;
    request.seeds = vec![FileOffset(0x1000)];
    let report = inspect_sleigh_file_range(&file.path, &request).unwrap();
    assert_eq!(report.rows[0].status, DecodeStatus::Valid);
    assert!(matches!(report.rows[0].flow, InstructionFlow::Unknown { .. }));
    assert_eq!(report.stops[0].reason, "conservative_unknown_flow_not_invalid_opcode");
    let program = report.program.as_ref().unwrap();
    assert!(program.function_at(0x1000).unwrap().contains(0x1000));
    assert!(program.decode_gate_at(0x1000, 0x1000).is_some());
    assert!(!program.noreturn.contains(&0x1000));
}

#[test]
fn avr_context_mediated_skip_stops_discovery_instead_of_claiming_fallthrough() {
    // CPSE r0,r0; RET. The skip relies on Sleigh global context at the next instruction.
    let file = OwnedFixture::new(&[0x00, 0x10, 0x08, 0x95]);
    let mut request = request("avr8:LE:16:default", 4);
    request.discover = true;
    request.seeds = vec![FileOffset(0x1000)];
    let report = inspect_sleigh_file_range(&file.path, &request).unwrap();
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.rows[0].address, 0x1000);
    assert_eq!(report.rows[0].status, DecodeStatus::Valid);
    assert!(matches!(report.rows[0].flow, InstructionFlow::Unknown { .. }));
    assert!(report.rows[0].context_mediated_flow);
    assert_eq!(
        report.rows[0].unknown_gate.as_ref().unwrap().reason,
        rampage_decompiler::sleigh_decode::UnknownFlow::ContextMediatedFlow
    );
    assert_eq!(report.stops[0].profile, "avr8:LE:16:default");
    assert_eq!(report.stops[0].address, 0x1000);
    assert_eq!(report.stops[0].reason, "conservative_unknown_flow_not_invalid_opcode");
    assert_eq!(report.stops[0].backed_prefix_hex, "00100895");
    let program = report.program.as_ref().unwrap();
    assert!(program.function_at(0x1000).unwrap().contains(0x1000));
    assert!(program.decode_gate_at(0x1000, 0x1000).is_some());
    assert!(!program.noreturn.contains(&0x1000));
    assert!(report.discovery_coverage.contains("not_complete"));
}

#[test]
fn bounded_stop_diagnostics_count_omissions_independently_of_listing_page() {
    let file = OwnedFixture::new(&[0x0f, 0xa2, 0x0f, 0xa2, 0x0f, 0xa2]);
    let mut request = request("x86:LE:64:default", 6);
    request.stop_limit = 1;
    request.listing_offset = 2;
    request.listing_limit = 1;
    let report = inspect_sleigh_file_range(&file.path, &request).unwrap();
    assert_eq!(report.listing_total, 3);
    assert_eq!(report.rows[0].address, 0x1004);
    assert_eq!(report.stops_total, 3);
    assert_eq!(report.stops.len(), 1);
    assert_eq!(report.stops[0].address, 0x1000);
    assert_eq!(report.stops_omitted, 2);
}

#[test]
fn oversized_pcode_report_fails_instead_of_cutting_strings_or_program() {
    let bytes = [0x48, 0x01, 0xd8].repeat(300);
    let file = OwnedFixture::new(&bytes);
    let mut request = request("x86:LE:64:default", bytes.len());
    request.instruction_limit = 300;
    request.listing_limit = 1;
    request.include_pcode = true;
    let small = inspect_sleigh_file_range(&file.path, &request).unwrap();
    assert!(!small.rows[0].pcode.as_ref().unwrap().is_empty());
    assert!(small.retained_cache_bytes > MAX_SLEIGH_WINDOW_REPORT_BYTES);
    assert!(small.retained_cache_bytes <= small.retained_cache_byte_limit);
    request.listing_limit = 300;
    let error = inspect_sleigh_file_range(&file.path, &request).unwrap_err();
    assert!(error.to_string().contains("60000 JSON bytes"), "{error}");
}

#[test]
fn profile_code_space_bounds_are_not_faked_with_a_native_architecture() {
    let file = OwnedFixture::new(&[0xea, 0x60]);
    let mut request = request("6502:LE:16:default", 2);
    request.base_address = FileOffset(0xffff);
    let error = inspect_sleigh_file_range(&file.path, &request).unwrap_err();
    assert!(error.to_string().contains("code-space byte range"), "{error}");
}

#[test]
fn public_file_range_keeps_sources_read_only_and_rejects_sibling_profile_paths() {
    let source = OwnedFixture::new(&[0xea, 0x60]);
    let sibling_spec = OwnedFixture::new(b"owned non-SLA sibling must never be loaded");
    let mut request = request("6502:LE:16:default", 2);
    let report = inspect_sleigh_file_range(&source.path, &request).unwrap();
    assert_eq!(report.rows.len(), 2);
    assert!(report.rows.iter().all(|row| row.pcode.is_none()));
    assert_eq!(std::fs::read(&source.path).unwrap(), [0xea, 0x60]);
    request.profile = sibling_spec.path.to_str().unwrap().to_owned();
    let error = inspect_sleigh_file_range(&source.path, &request).unwrap_err();
    assert!(matches!(error, ApiError::Invalid(_)));
    assert!(error.to_string().contains("unregistered"));
    assert_eq!(std::fs::read(&sibling_spec.path).unwrap(), b"owned non-SLA sibling must never be loaded");
}

#[test]
fn source_change_and_selected_range_hash_mismatch_refuse_observation() {
    let source_file = OwnedFixture::new(&[0xea, 0x60]);
    let source = RangeSource::open(&source_file.path, 0, 2).unwrap();
    let before = rampage_arch::hex::bytes(&Sha256::digest(source.read().unwrap()));
    assert_eq!(verify_source_after(&source, &before).unwrap(), before);
    let mismatch = verify_source_after(&source, &"0".repeat(64)).unwrap_err();
    assert!(mismatch.to_string().contains("range bytes changed"));
    let mut writer = OpenOptions::new().write(true).truncate(true).open(&source_file.path).unwrap();
    writer.write_all(&[0x60, 0xea, 0xea]).unwrap();
    assert!(verify_source_after(&source, &before).is_err());
}

#[test]
fn independent_oracle_function_recall_uses_the_same_six_function_denominator_for_both_seed_modes() {
    let oracle: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/sleigh/oracle.json")).unwrap();
    let truth: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/sleigh/truth.json")).unwrap();
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sleigh");
    let mut totals = [(0usize, 0usize, 0usize); 2];
    for fixture in oracle["fixtures"].as_array().unwrap() {
        let name = fixture["name"].as_str().unwrap();
        let source_truth = truth["fixtures"].as_array().unwrap().iter().find(|item| item["name"] == name).unwrap();
        let language = fixture["language_id"].as_str().unwrap();
        let base = crate::parse_file_offset(fixture["base"]["getOffset_bytes"].as_str().unwrap()).unwrap();
        let expected: Vec<_> = fixture["program_oracle"]["functions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|function| {
                let entry = crate::parse_file_offset(function["entry"]["getOffset_bytes"].as_str().unwrap()).unwrap();
                let ranges: Vec<_> = function["body_ranges"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|range| {
                        let start =
                            crate::parse_file_offset(range["start"]["getOffset_bytes"].as_str().unwrap()).unwrap();
                        let end = crate::parse_file_offset(range["end_inclusive"]["getOffset_bytes"].as_str().unwrap())
                            .unwrap()
                            + 1;
                        (start, end)
                    })
                    .collect();
                (entry, ranges)
            })
            .collect();
        assert_eq!(expected.len(), source_truth["functions"].as_array().unwrap().len());
        for (mode, manual_seeds) in [true, false].into_iter().enumerate() {
            let mut request = request(language, fixture["byte_length"].as_u64().unwrap() as usize);
            request.base_address = FileOffset(base);
            request.discover = true;
            request.seeds = if manual_seeds {
                expected.iter().map(|(entry, _)| FileOffset(*entry)).collect()
            } else {
                source_truth["entry_seed_offsets_bytes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|offset| FileOffset(base + offset.as_u64().unwrap()))
                    .collect()
            };
            let report =
                inspect_sleigh_file_range(&fixture_root.join(source_truth["bytes_file"].as_str().unwrap()), &request)
                    .unwrap();
            assert_eq!(report.source_range_sha256, fixture["input_sha256"].as_str().unwrap());
            let program = report.program.as_ref().unwrap();
            totals[mode].0 += expected.len();
            for (entry, ranges) in &expected {
                if let Some(function) = program.function_at(*entry) {
                    totals[mode].1 += 1;
                    let mut actual = function.blocks.iter().map(|block| (block.start, block.end)).collect::<Vec<_>>();
                    actual.sort_unstable();
                    let mut merged: Vec<(u64, u64)> = Vec::new();
                    for (start, end) in actual {
                        if let Some(last) = merged.last_mut().filter(|last| start <= last.1) {
                            last.1 = last.1.max(end);
                        } else {
                            merged.push((start, end));
                        }
                    }
                    if &merged == ranges {
                        totals[mode].2 += 1;
                    } else {
                        eprintln!(
                            "oracle extent miss {name} manual={manual_seeds} entry={entry:#x}: \
                            expected={ranges:?} actual={merged:?} stops={:?}",
                            report.stops
                        );
                    }
                } else {
                    eprintln!(
                        "oracle entry miss {name} manual={manual_seeds} entry={entry:#x}: stops={:?}",
                        report.stops
                    );
                }
            }
        }
    }
    eprintln!("oracle recall (denominator, entries, exact extents): manual={:?}, call-only={:?}", totals[0], totals[1]);
    assert_eq!(totals[0].0, 6);
    assert_eq!(totals[1].0, totals[0].0);
    for (denominator, entries, extents) in totals {
        assert_eq!(entries, denominator);
        assert_eq!(extents, denominator);
    }
}

#[test]
fn translator_metadata_validates_word_units_and_unusual_code_space_widths_without_sample_opcodes() {
    for profile in ["avr8:LE:16:default", "PIC-16:LE:16:PIC-16", "HCS-12:BE:24:default", "CR16C:LE:16:default"] {
        let decoder = SleighDecoder::open(profile).unwrap();
        let metadata = decoder.metadata();
        let code = metadata.spaces.iter().find(|space| space.id == metadata.code_space).unwrap();
        if profile.starts_with("avr8") || profile.starts_with("PIC-") {
            assert_eq!(code.word_size, 2);
        }
        if profile.starts_with("HCS-") {
            assert_eq!((code.address_size, code.highest), (3, 0xff_ffff));
        }
        if profile.starts_with("CR16") {
            assert_eq!((code.address_size, code.highest), (4, 0xffff_ffff));
        }
        let mut request = request(profile, 1);
        request.base_address = FileOffset(0);
        let (_, end, seeds) = validate(&request).unwrap();
        validate_profile_mapping(&request, end, &seeds, metadata).unwrap();
        let first_outside = code.highest.checked_add(1).unwrap();
        request.base_address = FileOffset(first_outside);
        let (_, end, seeds) = validate(&request).unwrap();
        assert!(validate_profile_mapping(&request, end, &seeds, metadata).is_err());
        if metadata.alignment_bytes > 1 {
            request.base_address = FileOffset(1);
            let (_, end, seeds) = validate(&request).unwrap();
            assert!(validate_profile_mapping(&request, end, &seeds, metadata).is_err());
        }
    }
}

#[test]
fn full_roster_manual_and_call_only_matrix_retains_unknown_entries_and_reports_extent_misses() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sleigh");
    let truth: serde_json::Value = serde_json::from_slice(&std::fs::read(root.join("truth.json")).unwrap()).unwrap();
    let extended: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("extended/truth-current.json")).unwrap()).unwrap();
    let java: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("extended/oracle-current.json")).unwrap()).unwrap();
    let mut totals = [(0usize, 0usize, 0usize); 2];
    let mut matrix = Vec::new();
    for (extended_fixture, fixture) in truth["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| (false, item))
        .chain(extended["fixtures"].as_array().unwrap().iter().map(|item| (true, item)))
    {
        let name = fixture["name"].as_str().unwrap();
        let language = fixture["language_id"].as_str().unwrap();
        let base = crate::parse_file_offset(fixture["base_byte_offset"].as_str().unwrap()).unwrap();
        let functions = fixture["functions"].as_array().unwrap();
        let expected: Vec<_> = functions
            .iter()
            .map(|function| {
                let start =
                    function[if extended_fixture { "start_bytes" } else { "entry_offset_bytes" }].as_u64().unwrap();
                let end = function[if extended_fixture { "end_exclusive_bytes" } else { "extent_end_exclusive_bytes" }]
                    .as_u64()
                    .unwrap();
                (base + start, base + end)
            })
            .collect();
        if extended_fixture {
            let independent = java["fixtures"].as_array().unwrap().iter().find(|item| item["name"] == name).unwrap();
            let java_functions = independent["oracle"]["program_oracle"]["functions"].as_array().unwrap();
            assert_eq!(java_functions.len(), expected.len());
            for ((entry, end), gold) in expected.iter().zip(java_functions) {
                assert_eq!(
                    *entry,
                    crate::parse_file_offset(gold["entry"]["getOffset_bytes"].as_str().unwrap()).unwrap()
                );
                let ranges = gold["body_ranges"].as_array().unwrap();
                assert_eq!(
                    *end,
                    ranges
                        .iter()
                        .map(|range| crate::parse_file_offset(
                            range["end_inclusive"]["getOffset_bytes"].as_str().unwrap(),
                        )
                        .unwrap()
                            + 1)
                        .max()
                        .unwrap()
                );
            }
        }
        let path = if extended_fixture {
            root.join("extended").join(format!("{name}.bin"))
        } else {
            root.join(fixture["bytes_file"].as_str().unwrap())
        };
        let length = std::fs::metadata(&path).unwrap().len() as usize;
        for (mode, manual) in [true, false].into_iter().enumerate() {
            let mut request = request(language, length);
            request.base_address = FileOffset(base);
            request.discover = true;
            request.seeds = if manual {
                expected.iter().map(|(entry, _)| FileOffset(*entry)).collect()
            } else {
                vec![FileOffset(base)]
            };
            let report = inspect_sleigh_file_range(&path, &request).unwrap();
            if extended_fixture {
                assert_eq!(report.source_range_sha256, fixture["input_sha256"].as_str().unwrap());
                let independent =
                    java["fixtures"].as_array().unwrap().iter().find(|item| item["name"] == name).unwrap();
                let expected_address = &independent["oracle"]["standalone_rows"][0]["address"];
                let code = report.profile.spaces.iter().find(|space| space.id == report.profile.code_space).unwrap();
                assert_eq!(code.name, expected_address["space"].as_str().unwrap());
                assert_eq!(u64::from(code.word_size), expected_address["addressableUnitSize_bytes"].as_u64().unwrap());
            }
            let program = report.program.as_ref().unwrap();
            let mut missing = Vec::new();
            let mut extent_misses = Vec::new();
            totals[mode].0 += expected.len();
            for (entry, end) in &expected {
                if let Some(function) = program.function_at(*entry) {
                    totals[mode].1 += 1;
                    let exact_coverage = function.end() == *end
                        && function.blocks.iter().all(|block| block.start >= *entry && block.end <= *end)
                        && (*entry..*end).all(|address| function.contains(address));
                    if exact_coverage {
                        totals[mode].2 += 1;
                    } else {
                        extent_misses.push(serde_json::json!({"entry":entry,"expected_end":end,
                            "actual_end":function.end(),"blocks":function.blocks}));
                        assert!(
                            report.stops.iter().any(|stop| stop.unknown_gate.is_some()
                                && function.contains(stop.address)
                                && program.decode_gate_at(*entry, stop.address).is_some()),
                            "unexplained extent miss {name} manual={manual}: {report:#?}"
                        );
                    }
                } else {
                    missing.push(*entry);
                    if manual {
                        let row = report.rows.iter().find(|row| row.address == *entry).expect(
                            "every manual seed outcome must be retained, including unsupported decode outcomes",
                        );
                        assert_ne!(
                            row.status,
                            DecodeStatus::Valid,
                            "manual VALID unknown seed was dropped: {name} {entry:#x}"
                        );
                        assert!(report.stops.iter().any(|stop| stop.address == *entry));
                        continue;
                    }
                    assert!(
                        report.stops.iter().any(|stop| stop.unknown_gate.is_some())
                            || report.rows.iter().any(|row| matches!(row.flow, InstructionFlow::IndirectCall)),
                        "unexplained transitive miss {name}: {report:#?}"
                    );
                }
            }
            matrix.push(serde_json::json!({"profile":language,"fixture":name,"manual_seeds":manual,
                "denominator":expected.len(),"missing_entries":missing,"extent_misses":extent_misses,
                "functions":program.functions,"production_gates":program.decode_gates,"stops":report.stops}));
        }
    }
    assert_eq!(totals[0].0, 32);
    assert_eq!(totals[1].0, 32);
    eprintln!(
        "UNFILTERED FULL ROSTER MATRIX: {}",
        serde_json::json!({
            "manual":totals[0],"call_only":totals[1],"outcomes":matrix,
            "limits":"Explicit raw code windows only; missing gated edges are not implemented backend coverage"
        })
    );
    // Do not force either extent total or transitive recall to 32: PIC's computed call and real gates stay visible.
    // Valid unknown entries are enforced per-site above; unsupported native outcomes remain visible as misses.
}

#[test]
fn hexagon_seed_and_superh_body_unknown_gates_are_retained_by_the_production_program() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sleigh/extended");
    for (profile, fixture, seed, gate_address) in [
        ("Hexagon:LE:32:default", "Hexagon-v2.bin", 0x1000, 0x1000),
        ("SuperH:BE:32:SH-2", "SuperH-v2.bin", 0x1010, 0x1012),
    ] {
        let path = root.join(fixture);
        let mut request = request(profile, std::fs::metadata(&path).unwrap().len() as usize);
        request.base_address = FileOffset(0x1000);
        request.discover = true;
        request.seeds = vec![FileOffset(seed)];
        let report = inspect_sleigh_file_range(&path, &request).unwrap();
        let program = report.program.as_ref().unwrap();
        let function = program.function_at(seed).expect("valid unknown seed/body must not be erased as invalid opcode");
        assert!(function.contains(gate_address));
        let production_gate = program
            .decode_gate_at(seed, gate_address)
            .expect("unknown instruction needs a production Program gate, not only a report sidecar");
        assert_eq!(production_gate.gate.profile, profile);
        assert!(production_gate.len > 0);
        assert!(!program.noreturn.contains(&seed));
        let row = report.rows.iter().find(|row| row.address == gate_address).unwrap();
        assert_eq!(row.status, DecodeStatus::Valid);
        assert!(row.unknown_gate.is_some());
        assert_eq!(
            serde_json::to_value(production_gate.gate.reason).unwrap(),
            serde_json::to_value(row.unknown_gate.as_ref().unwrap().reason).unwrap()
        );
        assert!(program.xrefs.iter().all(|xref| xref.from != gate_address));
        assert!(report.rows.iter().all(|row| row.address <= gate_address));
        if profile.starts_with("Hexagon") {
            assert!(row.processor_helper_required);
            assert_eq!(
                row.unknown_gate.as_ref().unwrap().reason,
                rampage_decompiler::sleigh_decode::UnknownFlow::ProcessorHelperRequired
            );
            assert!(report.profile.required_parallel_helper.is_some());
        }
    }
}
