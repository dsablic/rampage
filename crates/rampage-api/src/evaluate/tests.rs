use serde_json::json;

use super::convention::{PairRule, assign, result_pair};
use super::machine::op;
use super::*;

// ----------------------------------------------------------------------------------------------------------------
// Interpreter operations, on hand-built p-code.

const CONSTANT: u32 = 0;
const REGISTER: u32 = 1;
const UNIQUE: u32 = 2;
const RAM: u32 = 3;

struct TestRam {
    base: u64,
    bytes: Vec<u8>,
}

impl Ram for TestRam {
    fn read(&mut self, address: u64, out: &mut [u8]) -> Result<(), Fault> {
        let offset = address.checked_sub(self.base).filter(|offset| offset + out.len() as u64 <= 256);
        let offset = offset.ok_or(Fault::UnmappedRead { address, size: out.len() as u32 })? as usize;
        out.copy_from_slice(&self.bytes[offset..offset + out.len()]);
        Ok(())
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Fault> {
        let offset = address.checked_sub(self.base).filter(|offset| offset + bytes.len() as u64 <= 256);
        let offset = offset.ok_or(Fault::UnmappedWrite { address, size: bytes.len() as u32 })? as usize;
        self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

fn machine(big_endian: bool) -> Machine<TestRam> {
    let ids = SpaceIds { constant: CONSTANT, unique: UNIQUE, register: REGISTER, ram: RAM, address_bytes: 4 };
    Machine::new(ids, big_endian, TestRam { base: 0x1000, bytes: vec![0; 256] })
}

fn node(space: u32, offset: u64, size: u32) -> Varnode {
    Varnode { space, size, address_size: 4, word_size: 1, offset: Some(offset), selected_space: None }
}

fn constant(value: u64, size: u32) -> Varnode {
    node(CONSTANT, value, size)
}

fn register(offset: u64, size: u32) -> Varnode {
    node(REGISTER, offset, size)
}

fn selector(space: u32) -> Varnode {
    Varnode { space: CONSTANT, size: 8, address_size: 8, word_size: 1, offset: None, selected_space: Some(space) }
}

fn pcode(opcode: u32, output: Option<Varnode>, inputs: Vec<Varnode>) -> PcodeOp {
    let name = machine::opcode_name(opcode).unwrap_or("UNKNOWN").to_owned();
    PcodeOp { opcode, name, address: 0, output, inputs }
}

/// Runs `opcode` on constant inputs of `size` bytes and returns its `out_size`-byte output.
fn evaluate(opcode: u32, inputs: &[(u64, u32)], out_size: u32) -> Result<u128, Fault> {
    let mut machine = machine(false);
    let output = register(0x100, out_size);
    let inputs = inputs.iter().map(|&(value, size)| constant(value, size)).collect();
    machine.execute(&[pcode(opcode, Some(output.clone()), inputs)])?;
    machine.read_int(&output)
}

fn value(opcode: u32, inputs: &[(u64, u32)], out_size: u32) -> u128 {
    evaluate(opcode, inputs, out_size).unwrap()
}

#[test]
fn integer_arithmetic_wraps_at_the_operand_width() {
    assert_eq!(value(op::INT_ADD, &[(0xffff_ffff, 4), (2, 4)], 4), 1);
    assert_eq!(value(op::INT_SUB, &[(1, 4), (2, 4)], 4), 0xffff_ffff);
    assert_eq!(value(op::INT_MULT, &[(0x1_0000, 4), (0x1_0001, 4)], 4), 0x1_0000);
    assert_eq!(value(op::INT_MULT, &[(0xffff_ffff, 8), (0xffff_ffff, 8)], 8), 0xffff_fffe_0000_0001);
    assert_eq!(value(op::INT_2COMP, &[(5, 1)], 1), 0xfb);
    assert_eq!(value(op::INT_NEGATE, &[(0x0f, 2)], 2), 0xfff0);
    assert_eq!(value(op::INT_XOR, &[(0xff00, 2), (0x0ff0, 2)], 2), 0xf0f0);
    assert_eq!(value(op::INT_AND, &[(0xff00, 2), (0x0ff0, 2)], 2), 0x0f00);
    assert_eq!(value(op::INT_OR, &[(0xff00, 2), (0x0ff0, 2)], 2), 0xfff0);
}

#[test]
fn carry_and_signed_overflow_flags() {
    assert_eq!(value(op::INT_CARRY, &[(0xffff_ffff, 4), (1, 4)], 1), 1);
    assert_eq!(value(op::INT_CARRY, &[(0xffff_fffe, 4), (1, 4)], 1), 0);
    assert_eq!(value(op::INT_SCARRY, &[(0x7fff_ffff, 4), (1, 4)], 1), 1);
    assert_eq!(value(op::INT_SCARRY, &[(0xffff_ffff, 4), (1, 4)], 1), 0);
    assert_eq!(value(op::INT_SBORROW, &[(0x8000_0000, 4), (1, 4)], 1), 1);
    assert_eq!(value(op::INT_SBORROW, &[(0, 4), (1, 4)], 1), 0);
    assert_eq!(value(op::INT_CARRY, &[(u64::MAX, 8), (1, 8)], 1), 1);
}

#[test]
fn shifts_saturate_past_the_width() {
    assert_eq!(value(op::INT_LEFT, &[(1, 4), (31, 4)], 4), 0x8000_0000);
    assert_eq!(value(op::INT_LEFT, &[(1, 4), (32, 4)], 4), 0);
    assert_eq!(value(op::INT_RIGHT, &[(0x8000_0000, 4), (31, 1)], 4), 1);
    assert_eq!(value(op::INT_RIGHT, &[(0x8000_0000, 4), (40, 1)], 4), 0);
    assert_eq!(value(op::INT_SRIGHT, &[(0x8000_0000, 4), (4, 1)], 4), 0xf800_0000);
    assert_eq!(value(op::INT_SRIGHT, &[(0x8000_0000, 4), (99, 1)], 4), 0xffff_ffff);
    assert_eq!(value(op::INT_SRIGHT, &[(0x4000_0000, 4), (99, 1)], 4), 0);
}

#[test]
fn division_signed_and_unsigned() {
    assert_eq!(value(op::INT_DIV, &[(100, 4), (7, 4)], 4), 14);
    assert_eq!(value(op::INT_REM, &[(100, 4), (7, 4)], 4), 2);
    let minus_100 = (-100i32) as u32 as u64;
    assert_eq!(value(op::INT_SDIV, &[(minus_100, 4), (7, 4)], 4), (-14i32) as u32 as u128);
    assert_eq!(value(op::INT_SREM, &[(minus_100, 4), (7, 4)], 4), (-2i32) as u32 as u128);
    assert_eq!(value(op::INT_SDIV, &[(0x8000_0000, 4), (0xffff_ffff, 4)], 4), 0x8000_0000);
    assert_eq!(evaluate(op::INT_DIV, &[(1, 4), (0, 4)], 4), Err(Fault::DivisionByZero));
    assert_eq!(evaluate(op::INT_SREM, &[(1, 4), (0, 4)], 4), Err(Fault::DivisionByZero));
}

#[test]
fn comparisons_and_booleans() {
    assert_eq!(value(op::INT_LESS, &[(1, 4), (0xffff_ffff, 4)], 1), 1);
    assert_eq!(value(op::INT_SLESS, &[(1, 4), (0xffff_ffff, 4)], 1), 0);
    assert_eq!(value(op::INT_SLESSEQUAL, &[(0xffff_ffff, 4), (0xffff_ffff, 4)], 1), 1);
    assert_eq!(value(op::INT_LESSEQUAL, &[(2, 4), (1, 4)], 1), 0);
    assert_eq!(value(op::INT_EQUAL, &[(2, 2), (2, 2)], 1), 1);
    assert_eq!(value(op::INT_NOTEQUAL, &[(2, 2), (2, 2)], 1), 0);
    assert_eq!(value(op::BOOL_NEGATE, &[(1, 1)], 1), 0);
    assert_eq!(value(op::BOOL_XOR, &[(1, 1), (1, 1)], 1), 0);
    assert_eq!(value(op::BOOL_AND, &[(1, 1), (0, 1)], 1), 0);
    assert_eq!(value(op::BOOL_OR, &[(1, 1), (0, 1)], 1), 1);
}

#[test]
fn extension_pieces_and_bit_counts() {
    assert_eq!(value(op::INT_ZEXT, &[(0x80, 1)], 4), 0x80);
    assert_eq!(value(op::INT_SEXT, &[(0x80, 1)], 4), 0xffff_ff80);
    assert_eq!(value(op::INT_SEXT, &[(0x7f, 1)], 8), 0x7f);
    assert_eq!(value(op::PIECE, &[(0x1234, 2), (0x5678_9abc, 4)], 6), 0x1234_5678_9abc);
    assert_eq!(value(op::SUBPIECE, &[(0x1122_3344_5566_7788, 8), (4, 4)], 4), 0x1122_3344);
    assert_eq!(value(op::SUBPIECE, &[(0x1122_3344_5566_7788, 8), (0, 4)], 2), 0x7788);
    assert_eq!(value(op::POPCOUNT, &[(0xf0f0, 2)], 1), 8);
    assert_eq!(value(op::LZCOUNT, &[(0x0001, 2)], 1), 15);
    assert_eq!(value(op::LZCOUNT, &[(0, 4)], 1), 32);
}

#[test]
fn sixteen_byte_values_multiply_exactly() {
    let mut machine = machine(false);
    let wide = register(0x40, 16);
    let a = register(0x10, 16);
    let b = register(0x20, 16);
    machine.write_int(&a, u128::from(u64::MAX)).unwrap();
    machine.write_int(&b, u128::from(u64::MAX)).unwrap();
    machine.execute(&[pcode(op::INT_MULT, Some(wide.clone()), vec![a, b])]).unwrap();
    assert_eq!(machine.read_int(&wide).unwrap(), u128::from(u64::MAX) * u128::from(u64::MAX));
}

#[test]
fn floats_follow_ieee_semantics() {
    let one_half = 0.5f64.to_bits();
    let two = 2.0f64.to_bits();
    let single = |value: f32| u64::from(value.to_bits());
    assert_eq!(value(op::FLOAT_ADD, &[(one_half, 8), (two, 8)], 8), u128::from(2.5f64.to_bits()));
    assert_eq!(value(op::FLOAT_MULT, &[(single(1.5), 4), (single(2.0), 4)], 4), u128::from(single(3.0)));
    assert_eq!(value(op::FLOAT_LESS, &[(one_half, 8), (two, 8)], 1), 1);
    assert_eq!(value(op::FLOAT_INT2FLOAT, &[((-3i32) as u32 as u64, 4)], 8), u128::from((-3.0f64).to_bits()));
    assert_eq!(value(op::FLOAT_TRUNC, &[((-2.75f64).to_bits(), 8)], 4), (-2i32) as u32 as u128);
    assert_eq!(value(op::FLOAT_FLOAT2FLOAT, &[(single(1.25), 4)], 8), u128::from(1.25f64.to_bits()));
    assert_eq!(value(op::FLOAT_NAN, &[(f64::NAN.to_bits(), 8)], 1), 1);
    assert!(matches!(evaluate(op::FLOAT_ADD, &[(0, 10), (0, 10)], 10), Err(Fault::Unsupported(_))));
}

#[test]
fn loads_and_stores_honour_byte_order() {
    for big_endian in [false, true] {
        let mut machine = machine(big_endian);
        let value = register(0, 4);
        let address = register(8, 4);
        machine.write_int(&value, 0x1122_3344).unwrap();
        machine.write_int(&address, 0x1010).unwrap();
        machine.execute(&[pcode(op::STORE, None, vec![selector(RAM), address.clone(), value])]).unwrap();
        let expected = if big_endian { [0x11, 0x22, 0x33, 0x44] } else { [0x44, 0x33, 0x22, 0x11] };
        assert_eq!(machine.ram.bytes[0x10..0x14], expected);
        let half = register(16, 2);
        machine.write_int(&address, 0x1012).unwrap();
        machine.execute(&[pcode(op::LOAD, Some(half.clone()), vec![selector(RAM), address])]).unwrap();
        assert_eq!(machine.read_int(&half).unwrap(), if big_endian { 0x3344 } else { 0x1122 });
        assert_eq!(machine.read_memory(0x1010, 4).unwrap(), 0x1122_3344);
    }
}

#[test]
fn register_aliases_overlap_in_target_byte_order() {
    // A little-endian 32-bit register's low byte is at its offset; a big-endian one's is at offset + 3.
    let mut little = machine(false);
    little.write_int(&register(0, 4), 0xaabb_ccdd).unwrap();
    assert_eq!(little.read_int(&register(0, 1)).unwrap(), 0xdd);
    let mut big = machine(true);
    big.write_int(&register(0, 4), 0xaabb_ccdd).unwrap();
    assert_eq!(big.read_int(&register(3, 1)).unwrap(), 0xdd);
}

#[test]
fn unmapped_memory_faults_name_the_address() {
    let mut machine = machine(false);
    let address = register(8, 4);
    machine.write_int(&address, 0x9000).unwrap();
    let load = pcode(op::LOAD, Some(register(0, 4)), vec![selector(RAM), address.clone()]);
    assert_eq!(machine.execute(&[load]), Err(Fault::UnmappedRead { address: 0x9000, size: 4 }));
    let store = pcode(op::STORE, None, vec![selector(RAM), address, constant(1, 2)]);
    assert_eq!(machine.execute(&[store]), Err(Fault::UnmappedWrite { address: 0x9000, size: 2 }));
}

#[test]
fn branches_relative_absolute_and_indirect() {
    let mut machine = machine(false);
    let flag = node(UNIQUE, 0, 1);
    let out = register(0, 4);
    // A taken relative CBRANCH skips the next op; falling off the end continues with the next instruction.
    let ops = [
        pcode(op::COPY, Some(flag.clone()), vec![constant(1, 1)]),
        pcode(op::CBRANCH, None, vec![constant(2, 4), flag.clone()]),
        pcode(op::COPY, Some(out.clone()), vec![constant(7, 4)]),
        pcode(op::COPY, Some(register(4, 4)), vec![constant(9, 4)]),
    ];
    assert_eq!(machine.execute(&ops).unwrap(), Flow::Next);
    assert_eq!(machine.read_int(&out).unwrap(), 0);
    assert_eq!(machine.read_int(&register(4, 4)).unwrap(), 9);
    let call = pcode(op::CALL, None, vec![node(RAM, 0x4000, 4)]);
    assert_eq!(machine.execute(&[call]).unwrap(), Flow::Jump { target: 0x4000, call: true });
    machine.write_int(&out, 0x5000).unwrap();
    let ret = pcode(op::RETURN, None, vec![out]);
    assert_eq!(machine.execute(&[ret]).unwrap(), Flow::Jump { target: 0x5000, call: false });
    let not_taken = [
        pcode(op::CBRANCH, None, vec![node(RAM, 0x6000, 4), constant(0, 1)]),
        pcode(op::BRANCH, None, vec![node(RAM, 0x7000, 4)]),
    ];
    assert_eq!(machine.execute(&not_taken).unwrap(), Flow::Jump { target: 0x7000, call: false });
    let backwards_forever = [pcode(op::BRANCH, None, vec![constant(0, 4)])];
    assert!(matches!(machine.execute(&backwards_forever), Err(Fault::Malformed(_))));
}

#[test]
fn user_operations_stop_unless_implemented() {
    let mut machine = machine(false);
    machine.set_user_op(0, UserOp::Other("syscall".into()));
    machine.set_user_op(1, UserOp::Nop("LOCK".into()));
    machine.set_user_op(2, UserOp::Segment { thread_selectors: vec![(REGISTER, 0x80)], thread_base: 0x1000 });
    let call = |index| pcode(op::CALLOTHER, None, vec![constant(index, 4)]);
    assert_eq!(machine.execute(&[call(0)]), Err(Fault::UserOp("syscall".into())));
    assert_eq!(machine.execute(&[call(1)]), Ok(Flow::Next));
    assert_eq!(machine.execute(&[call(3)]), Err(Fault::UserOp("user operation 3".into())));
    let out = register(0, 4);
    let segment = |selector| {
        pcode(op::CALLOTHER, Some(out.clone()), vec![constant(2, 4), register(selector, 2), constant(0x10, 4)])
    };
    machine.execute(&[segment(0x80)]).unwrap();
    assert_eq!(machine.read_int(&out).unwrap(), 0x1010);
    machine.execute(&[segment(0x82)]).unwrap();
    assert_eq!(machine.read_int(&out).unwrap(), 0x10);
}

#[test]
fn unknown_opcodes_are_named() {
    let mut machine = machine(false);
    let mut unknown = pcode(op::INT_ADD, Some(register(0, 4)), vec![constant(1, 4), constant(1, 4)]);
    unknown.opcode = 60;
    unknown.name = "MULTIEQUAL".into();
    let Err(Fault::Unsupported(message)) = machine.execute(&[unknown]) else { panic!("expected unsupported") };
    assert!(message.contains("MULTIEQUAL"), "{message}");
}

// ----------------------------------------------------------------------------------------------------------------
// Calling conventions.

fn abi(arch: Arch, format: rampage_loaders::Format, big_endian: bool, convention: Convention) -> Abi {
    Abi::select(arch, format, big_endian, convention).unwrap()
}

#[test]
fn x86_conventions_place_arguments_on_the_stack_or_in_ecx_edx() {
    use rampage_loaders::Format::{Elf, Pe};
    let cdecl = abi(Arch::X86, Elf, false, Convention::Default);
    assert_eq!(cdecl.convention, Convention::Cdecl);
    assert_eq!(assign(&cdecl, &[4, 8, 4], false), [Place::Stack(0), Place::Stack(4), Place::Stack(12)]);
    let fastcall = abi(Arch::X86, Pe, false, Convention::Fastcall);
    assert_eq!(
        assign(&fastcall, &[8, 4, 4, 4], false),
        [Place::Stack(0), Place::Register("ECX"), Place::Register("EDX"), Place::Stack(8)]
    );
    let thiscall = abi(Arch::X86, Pe, false, Convention::Thiscall);
    assert_eq!(assign(&thiscall, &[4, 4], false), [Place::Register("ECX"), Place::Stack(0)]);
    assert_eq!(result_pair(&cdecl, false), ("EAX", "EDX"));
    assert!(Abi::select(Arch::X86, Elf, false, Convention::Sysv).is_err());
}

#[test]
fn x86_64_picks_sysv_or_win64_from_the_format() {
    use rampage_loaders::Format::{Elf, Pe};
    let sysv = abi(Arch::X86_64, Elf, false, Convention::Default);
    assert_eq!(sysv.convention, Convention::Sysv);
    let places = assign(&sysv, &[8; 7], false);
    assert_eq!(places[5], Place::Register("R9"));
    assert_eq!(places[6], Place::Stack(0));
    let win64 = abi(Arch::X86_64, Pe, false, Convention::Default);
    assert_eq!(win64.convention, Convention::Win64);
    assert_eq!(win64.stack_arguments, 0x20);
    assert_eq!(assign(&win64, &[8; 5], false)[4], Place::Stack(0));
    assert_eq!(abi(Arch::X86_64, Elf, false, Convention::Win64).convention, Convention::Win64);
}

#[test]
fn aapcs_aligns_register_pairs_and_spills_whole_pairs() {
    let arm = abi(Arch::Arm, rampage_loaders::Format::Elf, false, Convention::Default);
    assert_eq!(arm.pair, PairRule::Even);
    assert_eq!(assign(&arm, &[8, 4], false), [Place::Pair("r0", "r1"), Place::Register("r2")]);
    assert_eq!(assign(&arm, &[4, 8], false), [Place::Register("r0"), Place::Pair("r2", "r3")]);
    assert_eq!(
        assign(&arm, &[4, 4, 4, 8, 4], false),
        [Place::Register("r0"), Place::Register("r1"), Place::Register("r2"), Place::Stack(0), Place::Stack(8)]
    );
    // Big-endian AAPCS keeps the high word in the lower-numbered register, for arguments and results.
    assert_eq!(assign(&arm, &[8], true), [Place::Pair("r1", "r0")]);
    assert_eq!(result_pair(&arm, true), ("r1", "r0"));
    assert_eq!(result_pair(&arm, false), ("r0", "r1"));
}

#[test]
fn mips_o32_uses_positional_slots() {
    let o32 = abi(Arch::Mips, rampage_loaders::Format::Elf, true, Convention::Default);
    assert_eq!(assign(&o32, &[4, 8, 4], true), [Place::Register("a0"), Place::Pair("a3", "a2"), Place::Stack(16)]);
    assert_eq!(assign(&o32, &[4, 4, 4, 4, 4], false)[4], Place::Stack(16));
    assert_eq!(o32.entry_registers, ["t9"]);
}

#[test]
fn other_conventions_use_their_register_lists() {
    use rampage_loaders::Format::Elf;
    let n64 = abi(Arch::Mips64, Elf, true, Convention::Default);
    assert_eq!(assign(&n64, &[8; 5], true)[4], Place::Register("t0"));
    let rv32 = abi(Arch::Riscv32, Elf, false, Convention::Default);
    assert_eq!(assign(&rv32, &[4, 8], false), [Place::Register("a0"), Place::Pair("a1", "a2")]);
    let ppc = abi(Arch::PowerPc, Elf, true, Convention::Default);
    assert_eq!(assign(&ppc, &[4, 8], true), [Place::Register("r3"), Place::Pair("r6", "r5")]);
    assert_eq!(result_pair(&ppc, true), ("r4", "r3"));
    let aarch64 = abi(Arch::Aarch64, Elf, false, Convention::Default);
    assert_eq!(assign(&aarch64, &[8; 9], false)[8], Place::Stack(0));
    assert!(Abi::select(Arch::Msp430, Elf, false, Convention::Default).is_err());
}

#[test]
fn arguments_parse_widths_and_buffers() {
    let parse = |value: serde_json::Value, width| prepare(&serde_json::from_value(value).unwrap(), width);
    let integer = |value: serde_json::Value, width| match parse(value, width).unwrap() {
        Prepared::Integer { value, bytes, .. } => (value, bytes),
        Prepared::Buffer(_) => panic!("buffer"),
    };
    assert_eq!(integer(json!(3), 4), (3, 4));
    assert_eq!(integer(json!("0x00F0A500"), 4), (0x00f0_a500, 4));
    assert_eq!(integer(json!("0x0000000100000003"), 4), (0x1_0000_0003, 8));
    assert_eq!(integer(json!("-1"), 4), (u64::MAX, 4));
    assert_eq!(integer(json!({"value": 5, "bits": 64}), 4), (5, 8));
    assert_eq!(integer(json!(5_000_000_000u64), 4), (5_000_000_000, 8));
    assert!(parse(json!({"value": 300, "bits": 8}), 4).is_err());
    assert!(parse(json!("12abc"), 4).is_err());
    let Prepared::Buffer(bytes) = parse(json!({"buffer": {"text": "ab", "size": 4}}), 4).unwrap() else {
        panic!("buffer")
    };
    assert_eq!(bytes, b"ab\0\0");
    let Prepared::Buffer(bytes) = parse(json!({"buffer": {"hex": "0102"}}), 4).unwrap() else { panic!("buffer") };
    assert_eq!(bytes, [1, 2]);
    assert!(parse(json!({"buffer": {"hex": "010203", "size": 2}}), 4).is_err());
    assert!(parse(json!({"value": 1, "buffer": {}}), 4).is_err());
}

#[test]
fn results_report_hex_and_both_signs() {
    let result = result_value(0xffff_fffe, 32, vec!["EAX".into()]);
    assert_eq!(result.hex, "0xfffffffe");
    assert_eq!(result.unsigned, json!(4294967294u64));
    assert_eq!(result.signed, json!(-2));
    let wide = result_value(u128::MAX, 128, vec![]);
    assert_eq!(wide.signed, json!(-1));
    assert_eq!(wide.unsigned, json!(u128::MAX.to_string()));
}

// ----------------------------------------------------------------------------------------------------------------
// Whole functions of committed fixtures, against reference implementations of their C source.

fn fixture(path: &str) -> Project {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(path);
    Project::new(Binary::open(path).unwrap())
}

fn try_run(
    project: &Project,
    at: &str,
    args: serde_json::Value,
    extra: serde_json::Value,
) -> Result<EvaluateReport, ApiError> {
    let mut request = json!({ "at": at, "args": args });
    request.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    project.evaluate_function(&serde_json::from_value(request).unwrap())
}

fn run(project: &Project, at: &str, args: serde_json::Value, extra: serde_json::Value) -> EvaluateReport {
    try_run(project, at, args, extra).unwrap_or_else(|error| panic!("{at}: {error}"))
}

fn returned(report: &EvaluateReport) -> u64 {
    assert_eq!(report.stop, StopReason::Returned, "{}", report.detail);
    report.result.as_ref().unwrap().unsigned.as_u64().unwrap()
}

/// `fold_bytes` of tests/fixtures/bench-v3/src/semantics.c.
fn fold_bytes(mut value: u32, mut rounds: u32) -> u32 {
    let mut acc = 0x85eb_ca6bu32;
    while rounds != 0 && value != 0 {
        acc = acc.rotate_left(7).wrapping_add(value & 0xff);
        value >>= 8;
        rounds -= 1;
    }
    acc ^ (acc >> 13)
}

/// `scale64` of semantics.c.
fn scale64(a: u32, b: u32) -> u64 {
    let mut wide = u64::from(a) * u64::from(b);
    wide = wide.wrapping_add(u64::from(a) << 21);
    wide ^= wide >> 29;
    wide.wrapping_sub(0x1_0000_0001u64.wrapping_mul(u64::from(b & 7)))
}

/// `mix64` of semantics.c.
fn mix64(x: u64, k: u32) -> u64 {
    let k = (k & 31) + 1;
    let y = x.rotate_left(k).wrapping_add(u64::from(k) * 0xffff_ffff);
    y / 7 + ((y % 7) << 40)
}

#[test]
fn x86_cdecl_functions_return_in_eax_and_edx_eax() {
    let project = fixture("bench-v3/twins/semantics-x86.elf");
    for (value, rounds) in [(0x1234_5678u32, 4u32), (0xdead_beef, 2), (0, 9)] {
        let report = run(&project, "fold_bytes", json!([format!("{value:#x}"), rounds]), json!({}));
        assert_eq!(returned(&report), u64::from(fold_bytes(value, rounds)));
        assert_eq!(report.arguments[1].location, "stack+0x8");
    }
    let report = run(&project, "scale64", json!(["0xfffffff1", 13]), json!({"return_bits": 64}));
    assert_eq!(returned(&report), scale64(0xffff_fff1, 13));
    assert_eq!(report.result.as_ref().unwrap().registers, ["EDX", "EAX"]);
}

#[test]
fn arm32_follows_helper_calls_and_returns_register_pairs() {
    let project = fixture("bench-v3/twins/semantics-arm32.elf");
    let report = run(&project, "fold_bytes", json!([0x00c0_ffee, 3]), json!({}));
    assert_eq!(returned(&report), u64::from(fold_bytes(0x00c0_ffee, 3)));
    // The 64-bit division calls the compiler runtime's __aeabi_uldivmod, which the run follows.
    let report = run(&project, "mix64", json!(["0x8000000000000005", 9]), json!({"return_bits": 64}));
    assert_eq!(returned(&report), mix64(0x8000_0000_0000_0005, 9));
    assert_eq!(report.arguments[0].location, "r1:r0");
    assert_eq!(report.result.as_ref().unwrap().registers, ["r1", "r0"]);
    assert!(report.calls.iter().any(|call| call.name.as_deref() == Some("__aeabi_uldivmod")), "{:?}", report.calls);
}

#[test]
fn add_runs_on_every_supported_architecture() {
    for name in [
        "hello-x64.elf",
        "hello-x64.exe",
        "hello-arm64.elf",
        "hello-arm.elf",
        "hello-thumb.elf",
        "hello-mips.elf",
        "hello-mipsel.elf",
        "hello-ppc.elf",
        "hello-ppc64le.elf",
        "hello-riscv64.elf",
    ] {
        let project = fixture(&format!("bin/{name}"));
        let report = run(&project, "add", json!([40, -2]), json!({}));
        assert_eq!(returned(&report), 38, "{name}");
        assert_eq!(report.result.as_ref().unwrap().signed, json!(38), "{name}");
        // `int` is 32 bits on every target: return_bits keeps a 64-bit register's undefined upper half out.
        let report = run(&project, "add", json!([1, -3]), json!({"return_bits": 32}));
        assert_eq!(report.result.as_ref().unwrap().signed, json!(-2), "{name}");
    }
}

#[test]
fn buffers_are_passed_by_pointer_and_returned() {
    // strlen and memset of the statically linked runtime, in Thumb-2 (with IT blocks) and big-endian PowerPC.
    for (name, strlen, memset) in [("hello-thumb.elf", "0x20e8c", "0x20e9e"), ("hello-ppc.elf", "0x21da0", "0x21dd4")] {
        let project = fixture(&format!("bin/{name}"));
        let report = run(&project, strlen, json!([{"buffer": {"text": "evaluate me"}}]), json!({}));
        assert_eq!(returned(&report), 11, "{name}");
        let report = run(&project, memset, json!([{"buffer": {"size": 40}}, 0x41, 33]), json!({}));
        assert_eq!(report.stop, StopReason::Returned, "{name}: {}", report.detail);
        let buffer = &report.buffers[0];
        assert_eq!(buffer.hex, format!("{}{}", "41".repeat(33), "00".repeat(7)), "{name}");
        assert_eq!(buffer.text.as_deref(), Some("A".repeat(33).as_str()));
        assert_eq!(report.arguments[0].buffer, Some(0));
    }
}

#[test]
fn runs_stop_with_named_reasons() {
    let dynamic = fixture("bin/hello-x64-dyn.elf");
    let report = run(&dynamic, "main", json!([]), json!({}));
    assert_eq!(report.stop, StopReason::ExternalCall);
    assert!(report.detail.contains("puts"), "{}", report.detail);
    let report = run(&dynamic, "main", json!([]), json!({"max_steps": 2}));
    assert_eq!((report.stop, report.steps), (StopReason::StepLimit, 2));

    let static_x64 = fixture("bin/hello-x64.elf");
    let report = run(&static_x64, "main", json!([]), json!({}));
    assert_eq!(report.stop, StopReason::UserOp);
    assert!(report.detail.contains("syscall"), "{}", report.detail);
    let stopped = report.stopped_at.as_ref().unwrap();
    assert_eq!(stopped.instruction.as_deref(), Some("SYSCALL"));
    assert!(report.calls.iter().any(|call| call.name.as_deref() == Some("puts")), "{:?}", report.calls);

    let thumb = fixture("bin/hello-thumb.elf");
    let report = run(&thumb, "0x20e8c", json!(["0x10"]), json!({}));
    assert_eq!(report.stop, StopReason::UnmappedRead);
    assert!(report.detail.contains("0x10"), "{}", report.detail);
}

#[test]
fn memory_writes_and_requests_are_validated() {
    let project = fixture("bin/hello-thumb.elf");
    // Copy-on-write: a string written into the image is seen by the function, never by the file.
    let address = project.binary.segments.iter().find(|segment| segment.perms.write).unwrap().address;
    let report = run(
        &project,
        "0x20e8c",
        json!([format!("{address:#x}")]),
        json!({"memory": [{"address": format!("{address:#x}"), "hex": "6162636400"}]}),
    );
    assert_eq!(returned(&report), 4);
    assert!(try_run(&project, "add", json!([]), json!({"convention": "sysv"})).is_err());
    assert!(try_run(&project, "add", json!([]), json!({"max_steps": 0})).is_err());
    assert!(try_run(&project, "add", json!([]), json!({"return_bits": 96})).is_err());
    assert!(try_run(&project, "add", json!([]), json!({"memory": [{"address": "0x10", "hex": "00"}]})).is_err());
    let unsupported = fixture("bin/hello-s390x.elf");
    assert!(try_run(&unsupported, "add", json!([1, 2]), json!({})).is_err());
}

// ----------------------------------------------------------------------------------------------------------------
// Review regressions.

#[test]
fn no_permission_segments_and_the_null_page_are_unmapped() {
    // Mach-O __PAGEZERO covers 4 GiB at 0 with no permissions: a null dereference must stop, not read zero.
    let macho = fixture("bin/hello-x64.macho");
    assert!(macho.binary.segments.iter().any(|segment| segment.address == 0 && segment.size > 0));
    let mut ram = ImageRam::new(&macho.binary, 8);
    let mut word = [0u8; 8];
    assert!(matches!(ram.read(0x10, &mut word), Err(Fault::UnmappedRead { address: 0x10, .. })));
    assert!(matches!(ram.write(0x1_0000, &word), Err(Fault::UnmappedWrite { .. })));
    let elf = fixture("bin/hello-x64.elf");
    let mut ram = ImageRam::new(&elf.binary, 8);
    assert!(matches!(ram.read(0x8, &mut word), Err(Fault::UnmappedRead { .. })));
    // strlen(NULL) stops with unmapped_read.
    let report = run(&fixture("bin/hello-thumb.elf"), "0x20e8c", json!([0]), json!({}));
    assert_eq!(report.stop, StopReason::UnmappedRead, "{}", report.detail);
}

#[test]
fn written_pages_are_capped() {
    let project = fixture("bench-v3/bin/semantics-x86.elf");
    let mut ram = ImageRam::new(&project.binary, 4);
    ram.page_limit = 1;
    let data = project.binary.segments.iter().find(|segment| segment.size > 2 * PAGE).unwrap();
    ram.write(data.address, &[1]).unwrap();
    ram.write(data.address + 1, &[2]).unwrap();
    let next_page = (data.address / PAGE + 1) * PAGE;
    assert_eq!(ram.write(next_page, &[3]), Err(Fault::MemoryLimit { pages: 1 }));
    // A written page that extends past its segment does not map the bytes beyond it.
    let end = data.address + data.size;
    if end % PAGE != 0 && project.binary.segments.iter().all(|segment| !segment.contains(end)) {
        let mut ram = ImageRam::new(&project.binary, 4);
        ram.write(end - 1, &[9]).unwrap();
        assert!(matches!(ram.read(end, &mut [0u8]), Err(Fault::UnmappedRead { .. })));
    }
}

#[test]
fn writes_near_an_import_slot_keep_its_stand_in() {
    let project = fixture("bin/hello-x64-dyn.elf");
    let mut ram = ImageRam::new(&project.binary, 8);
    let slot = project.binary.import_slots[0].address;
    ram.slots.insert(slot, 0x7000_0000);
    ram.stand_ins.insert(0x7000_0000, "puts".into());
    let neighbour = if slot % PAGE >= 8 { slot - 8 } else { slot + 8 };
    ram.write(neighbour, &[0xaa; 8]).unwrap();
    let mut word = [0u8; 8];
    ram.read(slot, &mut word).unwrap();
    assert_eq!(u64::from_le_bytes(word), 0x7000_0000, "a write on the slot's page leaves the stand-in");
    ram.write(slot + 4, &[0x11; 4]).unwrap();
    ram.read(slot, &mut word).unwrap();
    assert_ne!(u64::from_le_bytes(word), 0x7000_0000, "a write to the slot itself is read back");
}

#[test]
fn rv32_splits_a_pair_across_the_last_register_and_the_stack() {
    let rv32 = abi(Arch::Riscv32, rampage_loaders::Format::Elf, false, Convention::Default);
    let places = assign(&rv32, &[4, 4, 4, 4, 4, 4, 4, 8, 4], false);
    assert_eq!(places[6], Place::Register("a6"));
    assert_eq!(places[7], Place::Split("a7", 0));
    assert_eq!(places[8], Place::Stack(4));
}

#[test]
fn apple_arm64_packs_stack_arguments_at_their_size() {
    let darwin = abi(Arch::Aarch64, rampage_loaders::Format::MachO, false, Convention::Default);
    assert_eq!(darwin.name(), "aapcs64_darwin");
    let places = assign(&darwin, &[8, 8, 8, 8, 8, 8, 8, 8, 4, 1, 8, 4], false);
    assert_eq!(places[8..], [Place::Stack(0), Place::Stack(4), Place::Stack(8), Place::Stack(16)]);
    let linux = abi(Arch::Aarch64, rampage_loaders::Format::Elf, false, Convention::Default);
    assert_eq!(assign(&linux, &[8, 8, 8, 8, 8, 8, 8, 8, 4, 1], false)[8..], [Place::Stack(0), Place::Stack(8)]);
}

#[test]
fn int_results_on_64_bit_targets_have_a_low_32_view() {
    let project = fixture("bin/hello-x64.elf");
    let report = run(&project, "add", json!([1, -3]), json!({}));
    let result = report.result.as_ref().unwrap();
    let low = result.low_32.as_ref().unwrap();
    assert_eq!((low.signed.clone(), low.hex.as_str()), (json!(-2), "0xfffffffe"));
    let report = run(&project, "add", json!([1, -3]), json!({"return_bits": 32}));
    assert!(report.result.unwrap().low_32.is_none());
    let report = run(&fixture("bin/hello-arm.elf"), "add", json!([1, 2]), json!({}));
    assert!(report.result.unwrap().low_32.is_none());
}

#[test]
fn negative_arguments_out_of_range_are_refused() {
    let parse = |value: serde_json::Value, width| prepare(&serde_json::from_value(value).unwrap(), width);
    assert!(parse(json!("-18446744073709551615"), 8).is_err());
    assert!(parse(json!({"value": "-18446744073709551615", "bits": 64}), 4).is_err());
    assert!(parse(json!({"value": "-9223372036854775809", "bits": 64}), 8).is_err());
    assert!(parse(json!({"value": "-9223372036854775808", "bits": 64}), 8).is_ok());
    assert!(parse(json!({"value": "-129", "bits": 8}), 4).is_err());
    assert!(parse(json!({"value": "-128", "bits": 8}), 4).is_ok());
}

#[test]
fn scratch_writes_straddling_the_dense_limit_read_back() {
    let mut machine = machine(false);
    let straddling = register(machine::DENSE_LIMIT - 2, 4);
    machine.write_int(&straddling, 0x1122_3344).unwrap();
    assert_eq!(machine.read_int(&straddling).unwrap(), 0x1122_3344);
    assert_eq!(machine.read_int(&register(machine::DENSE_LIMIT, 2)).unwrap(), 0x1122);
}

// ----------------------------------------------------------------------------------------------------------------
// Library stand-ins.

#[test]
fn library_names_map_to_stand_ins_across_platforms() {
    use stubs::{Stub, lookup};
    for (name, stub) in [
        ("memcpy", Stub::Memcpy),
        ("_memcpy", Stub::Memcpy),
        ("__memcpy_chk", Stub::Memcpy),
        ("___memcpy_chk", Stub::Memcpy),
        ("memcpy@GLIBC_2.14", Stub::Memcpy),
        ("__memmove_chk", Stub::Memmove),
        ("__memset_chk", Stub::Memset),
        ("__strcpy_chk", Stub::Strcpy),
        ("__strncpy_chk", Stub::Strncpy),
        ("__strcat_chk", Stub::Strcat),
        ("_strlen", Stub::Strlen),
        ("strnlen", Stub::Strnlen),
        ("_toupper", Stub::Toupper),
        ("___tolower", Stub::Tolower),
        ("abs", Stub::Abs),
        ("_malloc", Stub::Malloc),
        ("calloc", Stub::Calloc),
        ("realloc", Stub::Realloc),
        ("_free", Stub::Free),
    ] {
        assert_eq!(lookup(name), Some(stub), "{name}");
    }
    for name in ["puts", "__stack_chk_fail", "strlen_chk", "_strdup", "memcpy_s", "#12", ""] {
        assert_eq!(lookup(name), None, "{name}");
    }
}

/// An image's memory with a 4 KiB scratch region at 0x7000_0000 and a heap at 0x7100_0000.
fn stub_ram(project: &Project) -> ImageRam<'_> {
    let mut ram = ImageRam::new(&project.binary, 8);
    ram.map(0x7000_0000, vec![0; 4096]);
    ram.heap = Some(stubs::Heap::new(0x7100_0000));
    ram
}

fn put(ram: &mut ImageRam<'_>, address: u64, bytes: &[u8]) {
    ram.write(address, bytes).unwrap();
}

fn get(ram: &mut ImageRam<'_>, address: u64, length: usize) -> Vec<u8> {
    let mut out = vec![0; length];
    ram.read(address, &mut out).unwrap();
    out
}

fn limits(bytes: u64, name: &str) -> stubs::Limits<'_> {
    stubs::Limits { bytes, deadline: Instant::now() + Duration::from_secs(60), name }
}

#[test]
fn long_stand_ins_stream_and_stop_at_memory_and_time_limits() {
    use stubs::Stub;
    let project = fixture("bin/hello-x64.elf");
    let mut ram = stub_ram(&project);
    // A 300 MB memset is refused before it writes: memory cannot take it, whatever the step budget.
    let error =
        stubs::call(Stub::Memset, &[0x7000_0000, 0, 300 << 20], 8, &mut ram, &limits(u64::MAX, "memset")).unwrap_err();
    assert_eq!(error.0, StopReason::MemoryLimit, "{}", error.1);
    // A past deadline stops a long stand-in.
    let mut ram = stub_ram(&project);
    ram.map(0x7200_0000, vec![b'x'; 2 << 20]);
    let late = stubs::Limits { bytes: u64::MAX, deadline: Instant::now(), name: "strlen" };
    let error = stubs::call(Stub::Strlen, &[0x7200_0000], 8, &mut ram, &late).unwrap_err();
    assert_eq!(error.0, StopReason::Timeout, "{}", error.1);
    // Copies stream in chunks, across chunk boundaries and through an overlap in both directions.
    let pattern: Vec<u8> = (0..10_000u32).map(|index| (index % 251) as u8 + 1).collect();
    put(&mut ram, 0x7200_0000, &pattern);
    stub(&mut ram, Stub::Memmove, &[0x7200_0000 + 3000, 0x7200_0000, 10_000]);
    assert_eq!(get(&mut ram, 0x7200_0000 + 3000, 10_000), pattern);
    put(&mut ram, 0x7200_0000 + 3000, &pattern);
    stub(&mut ram, Stub::Memmove, &[0x7200_0000, 0x7200_0000 + 3000, 10_000]);
    assert_eq!(get(&mut ram, 0x7200_0000, 10_000), pattern);
    // A string ending just before unmapped memory: the 4 KiB region's last byte is its NUL.
    let mut ram = stub_ram(&project);
    put(&mut ram, 0x7000_0000 + 4090, b"tail\0");
    assert_eq!(stub(&mut ram, Stub::Strlen, &[0x7000_0000 + 4090]), 4);
    put(&mut ram, 0x7000_0000 + 4091, b"ail\0\0");
    assert_eq!(stub(&mut ram, Stub::Strcmp, &[0x7000_0000 + 4091, 0x7000_0000 + 4091]), 0);
    // calloc touches nothing.
    let outcome = stubs::call(Stub::Calloc, &[1 << 20, 1], 8, &mut ram, &limits(64, "calloc")).unwrap();
    assert_eq!(outcome.bytes, 0);
}

fn stub(ram: &mut ImageRam<'_>, which: stubs::Stub, args: &[u64]) -> u64 {
    stubs::call(which, args, 8, ram, &limits(1 << 20, "test")).unwrap().value
}

#[test]
fn memory_stand_ins_copy_fill_and_compare() {
    use stubs::Stub;
    let project = fixture("bin/hello-x64.elf");
    let mut ram = stub_ram(&project);
    let (a, b) = (0x7000_0000u64, 0x7000_0100u64);
    put(&mut ram, a, b"abcdef\0");
    assert_eq!(stub(&mut ram, Stub::Memcpy, &[b, a, 7]), b);
    assert_eq!(get(&mut ram, b, 7), b"abcdef\0");
    // memmove through an overlap.
    assert_eq!(stub(&mut ram, Stub::Memmove, &[a + 1, a, 3]), a + 1);
    assert_eq!(get(&mut ram, a, 6), b"aabcef");
    assert_eq!(stub(&mut ram, Stub::Memset, &[a, 0x1_2a, 3]), a);
    assert_eq!(get(&mut ram, a, 4), b"***c");
    assert_eq!(stub(&mut ram, Stub::Memcmp, &[a, b, 3]) as i64, i64::from(b'*') - i64::from(b'a'));
    assert_eq!(stub(&mut ram, Stub::Memcmp, &[b, b, 7]), 0);
    // A copy from unmapped memory stops with the first unreadable byte.
    let error = stubs::call(Stub::Memcpy, &[a, 0x10, 4], 8, &mut ram, &limits(1 << 20, "memcpy")).unwrap_err();
    assert_eq!(error.0, StopReason::UnmappedRead, "{}", error.1);
    assert!(error.1.contains("0x10"), "{}", error.1);
    // A length past the step budget stops instead of running on.
    let error = stubs::call(Stub::Memset, &[a, 0, 64], 8, &mut ram, &limits(16, "memset")).unwrap_err();
    assert_eq!(error.0, StopReason::StepLimit);
}

#[test]
fn string_stand_ins_follow_the_c_library() {
    use stubs::Stub;
    let project = fixture("bin/hello-x64.elf");
    let mut ram = stub_ram(&project);
    let (a, b, c) = (0x7000_0000u64, 0x7000_0100u64, 0x7000_0200u64);
    put(&mut ram, a, b"hello, world\0");
    put(&mut ram, c, b"hellp\0");
    assert_eq!(stub(&mut ram, Stub::Strlen, &[a]), 12);
    assert_eq!(stub(&mut ram, Stub::Strnlen, &[a, 5]), 5);
    assert_eq!(stub(&mut ram, Stub::Strnlen, &[a, 50]), 12);
    assert_eq!(stub(&mut ram, Stub::Strcpy, &[b, a]), b);
    assert_eq!(get(&mut ram, b, 13), b"hello, world\0");
    put(&mut ram, b, &[0xff; 8]);
    assert_eq!(stub(&mut ram, Stub::Strncpy, &[b, c, 8]), b);
    assert_eq!(get(&mut ram, b, 8), b"hellp\0\0\0");
    assert_eq!(stub(&mut ram, Stub::Strncpy, &[b, a, 3]), b);
    assert_eq!(get(&mut ram, b, 4), b"hell", "strncpy adds no NUL when the source is longer");
    assert!((stub(&mut ram, Stub::Strcmp, &[a, c]) as i64) < 0);
    assert!((stub(&mut ram, Stub::Strcmp, &[c, a]) as i64) > 0);
    assert_eq!(stub(&mut ram, Stub::Strncmp, &[a, c, 4]), 0);
    assert_eq!(stub(&mut ram, Stub::Strcmp, &[a, a]), 0);
    assert_eq!(stub(&mut ram, Stub::Strchr, &[a, u64::from(b'o')]), a + 4);
    assert_eq!(stub(&mut ram, Stub::Strrchr, &[a, u64::from(b'o')]), a + 8);
    assert_eq!(stub(&mut ram, Stub::Strchr, &[a, u64::from(b'z')]), 0);
    assert_eq!(stub(&mut ram, Stub::Strchr, &[a, 0]), a + 12);
    put(&mut ram, b, b"ab\0");
    assert_eq!(stub(&mut ram, Stub::Strcat, &[b, c]), b);
    assert_eq!(get(&mut ram, b, 8), b"abhellp\0");
    assert_eq!(stub(&mut ram, Stub::Toupper, &[u64::from(b'q')]), u64::from(b'Q'));
    assert_eq!(stub(&mut ram, Stub::Tolower, &[u64::from(b'Q')]), u64::from(b'q'));
    assert_eq!(stub(&mut ram, Stub::Toupper, &[u64::MAX]), u64::MAX, "EOF passes through");
    assert_eq!(stub(&mut ram, Stub::Abs, &[(-7i64) as u64]), 7);
    // An int argument is its low 32 bits.
    assert_eq!(stub(&mut ram, Stub::Abs, &[0x1_ffff_fff9]), 7);
    // 32-bit targets: arguments and results are masked to the register width.
    assert_eq!(stubs::call(Stub::Abs, &[0xffff_fffe], 4, &mut ram, &limits(64, "abs")).unwrap().value, 2);
    assert_eq!(
        stubs::call(Stub::Tolower, &[u64::MAX], 4, &mut ram, &limits(64, "tolower")).unwrap().value,
        0xffff_ffff
    );
}

#[test]
fn heap_stand_ins_allocate_zeroed_blocks_within_the_cap() {
    use stubs::Stub;
    let project = fixture("bin/hello-x64.elf");
    let mut ram = stub_ram(&project);
    let first = stub(&mut ram, Stub::Malloc, &[10]);
    let second = stub(&mut ram, Stub::Calloc, &[4, 4]);
    assert_eq!((first, second), (0x7100_0000, 0x7100_0010));
    assert_eq!(get(&mut ram, second, 16), [0; 16]);
    put(&mut ram, first, b"0123456789");
    let moved = stub(&mut ram, Stub::Realloc, &[first, 32]);
    assert_eq!(get(&mut ram, moved, 10), b"0123456789");
    assert_eq!(stub(&mut ram, Stub::Free, &[moved]), 0);
    assert_eq!(stub(&mut ram, Stub::Calloc, &[u64::MAX, 2]), 0, "an overflowing calloc returns NULL");
    let error = stubs::call(Stub::Realloc, &[0x7000_0000, 8], 8, &mut ram, &limits(64, "realloc")).unwrap_err();
    assert_eq!(error.0, StopReason::UnsupportedOp, "{}", error.1);
    // Heap pages count against the run's page cap, together with written image pages.
    ram.page_limit = ram.heap.as_ref().unwrap().pages() + 1;
    let error = stubs::call(Stub::Malloc, &[2 * PAGE], 8, &mut ram, &limits(64, "malloc")).unwrap_err();
    assert_eq!(error.0, StopReason::MemoryLimit, "{}", error.1);
    assert!(error.1.contains("malloc(8192)"), "{}", error.1);
    stub(&mut ram, Stub::Malloc, &[PAGE]);
    let data = project.binary.segments.iter().find(|segment| segment.perms.write).unwrap().address;
    assert_eq!(ram.write(data, &[1]), Err(Fault::MemoryLimit { pages: ram.page_limit }));
    // And the heap never grows past its reserve.
    let mut ram = stub_ram(&project);
    let error = stubs::call(Stub::Malloc, &[stubs::HEAP_BYTES + 1], 8, &mut ram, &limits(64, "malloc")).unwrap_err();
    assert_eq!(error.0, StopReason::MemoryLimit, "{}", error.1);
}

#[test]
fn imported_library_calls_run_as_stand_ins() {
    // `reveal` copies its input to the heap with strlen, malloc and memcpy, then decodes the copy.
    for name in ["decode-alloc-x64.elf", "decode-alloc-arm64.elf"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
        let project = Project::new(Binary::open(path).unwrap());
        let blob = project.resolve("door").unwrap();
        let request = json!({"at": "reveal", "args": [format!("{blob:#x}")]});
        let request: EvaluateRequest = serde_json::from_value(request).unwrap();
        let (report, probed) = project.evaluate_probed(&request, Some(Probe::default())).unwrap();
        assert_eq!(report.stop, StopReason::Returned, "{name}: {}", report.detail);
        let names: Vec<(&str, u64)> = report.stubbed.iter().map(|row| (row.name.as_str(), row.count)).collect();
        assert_eq!(names, [("strlen", 1), ("malloc", 1), ("memcpy", 1)], "{name}");
        assert_eq!(probed.texts[0].text, "open sesame", "{name}");
        assert_eq!(probed.texts[0].source, "result", "{name}");
        // With stand-ins off, the first import stops the run as before.
        let off = run(&project, "reveal", json!([format!("{blob:#x}")]), json!({"stubs": false}));
        assert_eq!(off.stop, StopReason::ExternalCall, "{name}");
        assert!(off.detail.contains("strlen") && off.stubbed.is_empty(), "{name}: {}", off.detail);
    }
}

fn probed(project: &Project, request: serde_json::Value, probe: Probe) -> (EvaluateReport, Probed) {
    let request: EvaluateRequest = serde_json::from_value(request).unwrap();
    project.evaluate_probed(&request, Some(probe)).unwrap()
}

#[test]
fn probed_text_must_differ_from_the_input_and_from_before_the_run() {
    let project = fixture("bin/hello-x64.elf");
    let mut ram = stub_ram(&project);
    let (blob, copy) = (0x7000_0000u64, 0x7000_0100u64);
    put(&mut ram, blob, b"aGVsbG8sIHdvcmxkIQ==\0");
    let snapshots = vec![(blob, super::snapshot(&mut ram, blob))];
    // A printable blob copied unchanged, or cut short, into a fresh buffer is not decoded text.
    put(&mut ram, copy, b"aGVsbG8sIHdvcmxkIQ==\0");
    assert_eq!(project.probed_text(&mut ram, copy, &snapshots), None);
    put(&mut ram, copy, b"aGVsbG8s\0");
    assert_eq!(project.probed_text(&mut ram, copy, &snapshots), None);
    put(&mut ram, copy, b"hello, world!\0");
    assert_eq!(project.probed_text(&mut ram, copy, &snapshots).as_deref(), Some("hello, world!"));
    // A direct run that leaves a printable buffer argument as it was decodes nothing: memset(buffer, 'A', 0).
    let thumb = fixture("bin/hello-thumb.elf");
    let buffer = json!({"buffer": {"text": "QUJDREVGRw=="}});
    let request = json!({"at": "0x20e9e", "args": [buffer, 0x41, 0]});
    let (report, found) = probed(&thumb, request, Probe::default());
    assert_eq!(report.stop, StopReason::Returned, "{}", report.detail);
    assert!(found.texts.is_empty(), "{:?}", found.texts);
    let request = json!({"at": "0x20e9e", "args": [buffer, 0x41, 4]});
    let (_, found) = probed(&thumb, request, Probe::default());
    assert_eq!(found.texts[0].text, "AAAAREVGRw==");
}

#[test]
fn a_replay_that_never_reaches_its_call_probes_nothing() {
    // main, patched to return its last `reveal` result instead of freeing it: `call free` becomes `mov rax, rbx`
    // and `xor eax, eax` two NOPs.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/decode-alloc-x64.elf");
    let project = Project::new(Binary::open(path).unwrap());
    let main = project.resolve("main").unwrap();
    let main_code = project.binary.read_to_segment_end(main).unwrap();
    assert_eq!(main_code[0x5e..0x65], [0xe8, 0x3d, 0x01, 0x00, 0x00, 0x31, 0xc0], "the fixture's main changed");
    let patch = json!([
        {"address": format!("{:#x}", main + 0x5e), "hex": "4889d89090"},
        {"address": format!("{:#x}", main + 0x63), "hex": "9090"},
    ]);
    let request = json!({"at": "main", "memory": patch});
    // Reached: the third `reveal` call returns the decoded text.
    let (report, found) = probed(&project, request.clone(), Probe { replay: Some((main, main + 0x4b)), input: None });
    assert_eq!(report.stop, StopReason::Returned, "{}", report.detail);
    assert_eq!(found.texts[0].text, "connect: ok");
    // Not reached: main returns the same pointer, but nothing is probed.
    let (report, found) = probed(&project, request, Probe { replay: Some((main, main + 0x6c)), input: None });
    assert_eq!((report.stop, report.detail.as_str()), (StopReason::Returned, "the function returned"));
    assert!(found.arguments.is_none() && found.texts.is_empty(), "{found:?}");
}

#[test]
fn replays_on_32_bit_pe_stop_at_imports_they_cannot_skip() {
    // A replay of `call [slot]` to an import without a model: x86 PE imports may pop their own arguments.
    let project = fixture("bin/pe-metadata-x86.exe");
    let slot = project.binary.import_slots.iter().find(|slot| stubs::lookup(&slot.name).is_none()).unwrap();
    let code = 0x0040_1000u64;
    let call = format!("ff15{}", rampage_arch::hex::bytes(&(slot.address as u32).to_le_bytes()));
    let request = json!({"at": format!("{code:#x}"), "memory": [{"address": format!("{code:#x}"), "hex": call}]});
    let (report, found) = probed(&project, request, Probe { replay: Some((code, code + 0x40)), input: None });
    assert_eq!(report.stop, StopReason::ExternalCall, "{}", report.detail);
    assert!(report.detail.contains("32-bit PE"), "{}", report.detail);
    assert!(found.skipped.is_empty());
}
