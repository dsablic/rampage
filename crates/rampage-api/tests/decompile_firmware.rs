//! Decompiler accuracy on a headerless Cortex-M image opened through the Raw profile: literal-pool globals, callers
//! that keep an argument in a call-clobbered register across a call (interprocedural register allocation), and
//! arguments that are another call's result. tests/fixtures/firmware/raw-cortex-m-decompile.c is the source; its
//! .elf keeps the symbols as the truth.

use rampage_api::Project;
use rampage_loaders::{Binary, RawCodeOptions, RawProfile};

const IMAGE: &[u8] = include_bytes!("../../../tests/fixtures/firmware/raw-cortex-m-decompile.bin");
const ELF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/firmware/raw-cortex-m-decompile.elf");

fn truth(name: &str) -> u64 {
    let elf = Binary::open(ELF).unwrap();
    elf.symbol_by_name(name).unwrap().address & !1
}

/// Raw projects name functions by address, as an analyst sees them before renaming anything.
fn sub(name: &str) -> String {
    format!("sub_{:x}", truth(name))
}

fn project() -> Project {
    let options = RawCodeOptions {
        profile: RawProfile::CortexM,
        base: 0x0800_0000,
        entry: None,
        seeds: vec![],
        vector_table: Some(0x0800_0000),
        pointer_tables: false,
    };
    Project::new(Binary::from_raw_code(IMAGE.to_vec(), options).unwrap())
}

fn decompile(project: &Project, name: &str) -> String {
    project.decompile(truth(name)).unwrap_or_else(|error| panic!("{name}: {error}")).code
}

/// Literal-pool words are read-only code: they fold into the addresses they hold, and globals at those addresses are
/// named by their Cortex-M region rather than as `iRam…`/`pxRam…` variables for the pool words themselves.
#[test]
fn literal_pool_globals_are_named_by_cortex_m_region() {
    let project = project();
    let code = decompile(&project, "advance_cursor");
    assert!(code.contains("ram_20000048 = ram_20000048 + 4;"), "{code}");
    assert!(code.contains("periph_40021004 = periph_40021000 | 0x100;"), "{code}");
    assert!(!code.contains("Ram"), "{code}");
    // The analyst's name for a data address wins over the region name.
    project.rename(0x2000_0048, Some("cursor")).unwrap();
    let code = decompile(&project, "advance_cursor");
    assert!(code.contains("cursor = cursor + 4;"), "{code}");
}

/// verify_image keeps its length in r2 across probe_status, which never writes r2 (LLVM's IPRA relied on that), then
/// moves it to r1 for checksum. checksum_after_quiet keeps it in r1 itself across quiet_leaf, which writes only r3.
#[test]
fn arguments_kept_in_registers_a_callee_never_writes_reach_the_next_call() {
    let project = project();
    let checksum = sub("checksum");
    let code = decompile(&project, "verify_image");
    assert!(code.contains(&format!("ram_20000044 = {checksum}(0x20000004,param_1);")), "{code}");
    assert!(!code.contains("extraout"), "{code}");
    let code = decompile(&project, "checksum_after_quiet");
    assert!(code.contains(&format!("{checksum}(param_1,param_2)")), "{code}");
    assert!(!code.contains("extraout"), "{code}");
}

/// scratch_r1 overwrites r1, so checksum_after_scratch really passes scratch_r1's r1: the call's output, not the
/// caller's parameter. Inference never marks a register the callee writes as preserved.
#[test]
fn a_register_the_callee_writes_still_reads_as_its_output() {
    let project = project();
    let code = decompile(&project, "checksum_after_scratch");
    assert!(code.contains(&format!("{}(param_1,extraout_r1)", sub("checksum"))), "{code}");
}

/// With each callee's prototype committed from its own decompilation, a call's result feeds the next call.
#[test]
fn call_results_feed_the_calls_that_use_them() {
    let project = project();
    let code = decompile(&project, "reset_handler");
    // reset_handler keeps unpack_field's result for a later call too, so it lands in a variable first.
    let call = format!(" = {}(periph_40021000);", sub("unpack_field"));
    let line = code.lines().find(|line| line.contains(&call)).unwrap_or_else(|| panic!("{code}"));
    let variable = line.trim().split(' ').next().unwrap();
    assert!(code.contains(&format!("{}({variable})", sub("verify_image"))), "{code}");
    assert!(!code.contains(&format!("{}()", sub("verify_image"))), "{code}");
    assert!(!code.contains(&format!("{}()", sub("place_field"))), "{code}");
}

/// The shift-and-mask is Ghidra's faithful reading of `ubfx r0, r0, #4, #12`: bits 4..15, written as a 16-bit mask
/// before the shift. Not rewritten; checked so a change to it is noticed.
#[test]
fn bit_field_extracts_read_as_mask_then_shift() {
    let project = project();
    let code = decompile(&project, "unpack_field");
    assert!(code.contains("return (param_1 & 0xffff) >> 4;"), "{code}");
}

/// In every format, a global the binary's data symbols name reads by that name (only the name: no folding, region
/// names or callee inference outside Raw images).
#[test]
fn data_symbols_name_their_globals_in_every_format() {
    for (name, exit) in [("hello-x64.elf", 0x10023ea), ("hello-thumb.elf", 0x20cbc)] {
        let code = fixture(name).decompile(exit).unwrap().code;
        assert!(code.contains("close_file(__stderr_used);"), "{name}: {code}");
        assert!(code.contains("close_file(__stdout_used);"), "{name}: {code}");
    }
}

/// One engine serves every decompilation, and it puts back derived callee prototypes and effects before each one,
/// so a function reads the same whatever was decompiled before it. chain0..chain70 is longer than the 64 callee
/// derivations one request may make: decompiling chain30 first would otherwise leave chain31..chain70 locked, and
/// chain_head's own request would then reach chain0.
#[test]
fn raw_decompilation_does_not_depend_on_history() {
    let reversed = project();
    let project = project();
    let first = decompile(&project, "chain_head");
    assert!(first.contains(&format!("{}()", sub("chain0"))), "{first}");
    let reset = decompile(&project, "reset_handler");
    let others = ["chain30", "chain60", "verify_image", "checksum_after_quiet", "checksum", "unpack_field"];
    for name in others {
        decompile(&project, name);
    }
    assert_eq!(decompile(&project, "chain_head"), first);
    assert_eq!(decompile(&project, "reset_handler"), reset);
    for name in others.iter().rev() {
        decompile(&reversed, name);
    }
    assert_eq!(decompile(&reversed, "reset_handler"), reset);
    assert_eq!(decompile(&reversed, "chain_head"), first);
}

/// depth_probe keeps its argument in r2 across chain54, whose callees the register scan can follow to the end, just
/// after calling chain53, whose callees it cannot. Seeing chain54 too deep below chain53 must not make it unknown.
#[test]
fn a_callee_too_deep_below_another_is_still_scanned_on_its_own() {
    let code = decompile(&project(), "depth_probe");
    assert!(code.contains(&format!("{}(param_1,param_1)", sub("checksum"))), "{code}");
    assert!(!code.contains("extraout"), "{code}");
}

/// An analyst may name any address; a name beyond the 32-bit data space is left out rather than refusing the
/// decompilation.
#[test]
fn names_beyond_the_data_space_are_left_out() {
    let project = project();
    project.rename(0x1_2000_0048, Some("beyond")).unwrap();
    let code = decompile(&project, "advance_cursor");
    assert!(code.contains("ram_20000048 = ram_20000048 + 4;"), "{code}");
}

/// A supervisor-call wrapper hides its parameter from its own decompilation (`mov r1, r0; svc #0`), so its
/// prototype is never derived and the caller's argument stays.
#[test]
fn a_supervisor_call_wrapper_keeps_its_argument() {
    let code = decompile(&project(), "report_length");
    assert!(code.contains(&format!("{}(param_1 * 3 + 1);", sub("sys_report"))), "{code}");
}

/// A thunk (`b.w checksum`) and a conditional tail call (`cmp r0, #0; bne.w checksum`) are never derived from
/// their own flow, which runs into checksum's code.
#[test]
fn tail_call_thunks_keep_their_arguments() {
    let code = decompile(&project(), "sum_through_tail");
    assert!(code.contains(&format!("{}(0x20000004,param_1)", sub("checksum_tail"))), "{code}");
    let code = decompile(&project(), "sum_if_data");
    assert!(code.contains(&format!("{}(0x20000004,param_1)", sub("checksum_if_data"))), "{code}");
}

/// musl's __syscall_ret shape: the input on one path, -1 on the other, after a call to a derived callee. A
/// derived callee return would make Ghidra drop this function's own return.
#[test]
fn a_return_of_input_or_constant_survives_a_derived_callee() {
    let code = decompile(&project(), "syscall_ret");
    assert!(code.contains(&format!("uint4 {}(uint4 param_1)", sub("syscall_ret"))), "{code}");
    assert!(code.contains("return param_1;") && code.contains("return 0xffffffff;"), "{code}");
}

/// checksum_after_probes keeps its length in r2 across probe_twice, which calls probe_status twice; the callee's
/// own calls are followed to see that none of them writes r2.
#[test]
fn arguments_survive_a_callee_whose_callees_leave_them_alone() {
    let code = decompile(&project(), "checksum_after_probes");
    assert!(code.contains(&format!("{}(param_1,param_2)", sub("checksum"))), "{code}");
    assert!(!code.contains("extraout"), "{code}");
}

fn fixture(name: &str) -> Project {
    let path = format!("{}/../../tests/fixtures/bin/{name}", env!("CARGO_MANIFEST_DIR"));
    Project::new(Binary::open(path).unwrap())
}

/// The firmware inference (callee effects and prototypes, read-only folding, region names) is for Raw images only:
/// headered binaries keep Ghidra's defaults.
#[test]
fn headered_binaries_keep_ghidra_defaults() {
    // musl `exit` passes its status in r0 to `_Exit`, whose body is `mov r1, r0; svc #0`.
    let thumb = fixture("hello-thumb.elf");
    let code = thumb.decompile(0x207ec).unwrap().code;
    assert!(code.contains("_Exit(status);"), "{code}");
    // Returns its input on one path and -1 on the other.
    let code = thumb.decompile(0x20b36).unwrap().code;
    assert!(code.contains("uint4 __syscall_ret(uint4 param_1)"), "{code}");
    assert!(code.contains("return param_1;") && code.contains("return 0xffffffff;"), "{code}");
    let arm = fixture("hello-arm.elf");
    let code = arm.decompile(0x202fc).unwrap().code;
    assert!(code.contains("0,0,param_1);"), "{code}");
    // mingw's pseudo-relocator writes `.rdata` at run time: its words stay variables, not constants.
    let exe = fixture("hello-x64.exe");
    let code = exe.decompile(0x1_4000_1fc0).unwrap().code;
    assert!(code.contains("*param_1 ^ uRam00000001400293c0"), "{code}");
}
