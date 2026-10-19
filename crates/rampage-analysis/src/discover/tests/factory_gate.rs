use std::sync::atomic::{AtomicUsize, Ordering};

use rampage_arch::{DecodeGate, DecodeGateReason, Insn};

use super::super::*;
use crate::memory::FlatMemory;

#[derive(Default)]
struct Decoder {
    gate: Option<DecodeGate>,
}

fn unknown_gate(address: u64) -> DecodeGate {
    DecodeGate { backend: "test", profile: "test:bounded", address, reason: DecodeGateReason::ContextMediatedFlow }
}

impl Disassembler for Decoder {
    fn decode_gate(&self) -> Option<DecodeGate> {
        self.gate
    }

    fn decode(&mut self, bytes: &[u8], address: u64) -> Insn {
        self.gate = None;
        let flow = match bytes.first() {
            Some(1) => {
                self.gate = Some(unknown_gate(address));
                Flow::Invalid
            }
            Some(2) => Flow::ConditionalJump(2),
            Some(3) => Flow::Halt,
            Some(4) => Flow::IndirectJump,
            Some(5) => Flow::Call(0),
            _ => Flow::Return,
        };
        Insn { address, len: 1, flow, data_ref: None, accesses: false, immediate: None, conditional: false }
    }

    fn reset(&mut self) {
        self.gate = None;
    }

    fn format(&mut self, _bytes: &[u8], _address: u64) -> String {
        self.gate = Some(unknown_gate(0xfeed));
        "mock instruction".to_owned()
    }
}

fn factory() -> Result<Box<dyn Disassembler>, &'static str> {
    Ok(Box::<Decoder>::default())
}

#[test]
fn successful_preflight_does_not_mask_a_later_worker_failure() {
    let opens = AtomicUsize::new(0);
    let memory = FlatMemory { base: 0, bytes: vec![0] };
    let result = try_discover(
        &memory,
        || {
            if opens.fetch_add(1, Ordering::SeqCst) == 0 { factory() } else { Err("worker open failed") }
        },
        &[0],
    );
    assert!(matches!(result, Err("worker open failed")));
    assert!(opens.load(Ordering::SeqCst) >= 2);
}

#[test]
fn joined_switch_probe_factory_failure_is_not_an_empty_success() {
    let memory = FlatMemory { base: 0, bytes: vec![4] };
    let known = BTreeSet::from([0]);
    let assumed = Assumed::new();
    let mut decoder = Decoder::default();
    let result = explore(&memory, &mut decoder, &known, None, &BTreeSet::new(), &assumed, 0);
    assert_eq!(result.unresolved_jumps, [0]);
    let results = BTreeMap::from([(0, result)]);
    let fail = || Err::<Box<dyn Disassembler>, _>("joined open failed");
    let resolved = joined_switches::resolve(&memory, &fail, &results, &assumed);
    assert!(matches!(resolved, Err("joined open failed")));
}

#[test]
fn unknown_at_seed_is_a_counted_instruction_and_function_without_fallthrough() {
    let memory = FlatMemory { base: 0, bytes: vec![1, 3] };
    let program = try_discover(&memory, factory, &[0]).unwrap();
    let function = program.function_at(0).unwrap();
    assert_eq!(function.instruction_count, 1);
    assert_eq!(function.blocks, [Block { start: 0, end: 1 }]);
    assert!(!function.contains(1));
    assert_eq!(program.decode_gate_at(0, 0).unwrap().gate, unknown_gate(0));
    assert!(program.inferred_noreturn.is_empty());
}

#[test]
fn an_unknown_exit_blocks_noreturn_even_with_a_terminal_path() {
    let memory = FlatMemory { base: 0, bytes: vec![2, 1, 3, 5, 3] };
    let program = try_discover(&memory, factory, &[0, 3]).unwrap();
    assert!(program.function_at(0).unwrap().contains(2));
    assert!(program.decode_gate_at(0, 1).is_some());
    assert!(!program.inferred_noreturn.contains(&0));
    assert!(!program.is_noreturn_call(3));
}

#[test]
fn the_gate_is_copied_before_format_overwrites_decoder_state() {
    let memory = FlatMemory { base: 0, bytes: vec![1] };
    let program = try_discover(&memory, factory, &[0]).unwrap();
    let retained = program.decode_gate_at(0, 0).unwrap();
    assert_eq!(retained.gate, unknown_gate(0));
    assert_eq!(retained.len, 1);
    assert_eq!(retained.text, "mock instruction");
    assert!(program.decode_gate_at(0, 0xfeed).is_none());
}

#[test]
fn joined_switch_worker_failure_after_a_successful_facts_probe_is_an_error() {
    let memory = FlatMemory { base: 0, bytes: vec![4] };
    let known = BTreeSet::from([0]);
    let assumed = Assumed::new();
    let mut decoder = Decoder::default();
    let result = explore(&memory, &mut decoder, &known, None, &BTreeSet::new(), &assumed, 0);
    assert_eq!(result.unresolved_jumps, [0]);
    let results = BTreeMap::from([(0, result)]);
    let opens = AtomicUsize::new(0);
    let late_failure = || {
        if opens.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(rampage_arch::decoder_for(rampage_arch::Arch::X86_64).unwrap())
        } else {
            Err("joined worker open failed")
        }
    };
    let resolved = joined_switches::resolve(&memory, &late_failure, &results, &assumed);
    assert!(matches!(resolved, Err("joined worker open failed")));
    assert!(opens.load(Ordering::SeqCst) >= 2);
}

struct ObservedDecoder {
    inner: Decoder,
    seed_completed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Disassembler for ObservedDecoder {
    fn decode(&mut self, bytes: &[u8], address: u64) -> Insn {
        let instruction = self.inner.decode(bytes, address);
        if address == 2 && instruction.flow == Flow::Return {
            self.seed_completed.store(true, Ordering::SeqCst);
        }
        instruction
    }

    fn format(&mut self, bytes: &[u8], address: u64) -> String {
        self.inner.format(bytes, address)
    }
}

#[test]
fn a_later_discovery_batch_failure_does_not_return_the_completed_seed_function() {
    let memory = FlatMemory { base: 0, bytes: vec![0, 5, 0] };
    let opens = AtomicUsize::new(0);
    let seed_completed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let result = try_discover(
        &memory,
        || {
            if opens.fetch_add(1, Ordering::SeqCst) >= 2 {
                if !seed_completed.load(Ordering::SeqCst) {
                    return Err("seed was not explored before the failing open");
                }
                return Err("later discovery batch open failed");
            }
            Ok(Box::new(ObservedDecoder {
                inner: Decoder::default(),
                seed_completed: std::sync::Arc::clone(&seed_completed),
            }) as Box<dyn Disassembler>)
        },
        &[1],
    );
    assert!(matches!(result, Err("later discovery batch open failed")));
    assert!(seed_completed.load(Ordering::SeqCst));
}

#[test]
fn empty_seeds_do_not_hide_a_failed_preflight() {
    let memory = FlatMemory { base: 0, bytes: vec![0] };
    let result = try_discover(&memory, || Err::<Box<dyn Disassembler>, _>("preflight failed"), &[]);
    assert!(matches!(result, Err("preflight failed")));
}
