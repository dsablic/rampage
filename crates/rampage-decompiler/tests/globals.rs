use rampage_arch::Arch;
use rampage_decompiler::{Decompiler, MemoryRegion};

#[test]
fn named_typed_globals_replace_inferred_memory_symbols_without_constant_folding() {
    let bytes = [0x8b, 5, 0xfa, 0x1f, 0, 0, 0xc3];
    let regions = [
        MemoryRegion {
            base: 0x1000,
            bytes: &bytes,
            size: bytes.len() as u64,
            readable: true,
            writable: false,
            executable: true,
        },
        MemoryRegion {
            base: 0x3000,
            bytes: &[7, 0, 0, 0, 0, 0, 0, 0],
            size: 8,
            readable: true,
            writable: true,
            executable: false,
        },
    ];
    let mut engine = Decompiler::open_regions(Arch::X86_64, false, &regions).unwrap();
    engine.add_global(0x3000, "int4 counter;").unwrap();
    let code = engine.decompile(0x1000, "read_counter", false).unwrap();
    assert!(code.contains("return counter;"), "{code}");
    assert!(engine.add_global(0x3001, "int4 overlap;").is_err());
    assert!(engine.add_global(u64::MAX, "int4 overflow;").is_err());
    assert!(engine.add_global(0x3007, "int4 incomplete;").is_err());
    assert!(engine.add_global(0x3004, "int4 callable(void);").is_err());
    assert!(engine.add_global(0x3004, "volatile int4 another;").is_err());
    assert!(engine.add_global(0x3004, "auto int4 another;").is_err());
    assert!(engine.add_global(0x3004, "int4 restrict(another);").is_err());
    assert!(engine.add_global(0x3004, "int4 counter;").is_err());
}

/// Thumb functions reaching globals through literal pools: `read_ram` loads the word at 0x20000004 and `write_periph`
/// stores its argument to 0x40021000. Each pool word sits in read-only code, so it folds into the address it holds.
const POOLS: [u8; 24] = [
    0x01, 0x48, // ldr r0, [pc, #4]   ; =0x20000004
    0x00, 0x68, // ldr r0, [r0]
    0x70, 0x47, // bx lr
    0x00, 0xbf, // nop
    0x04, 0x00, 0x00, 0x20, // .word 0x20000004
    0x01, 0x49, // ldr r1, [pc, #4]   ; =0x40021000
    0x08, 0x60, // str r0, [r1]
    0x70, 0x47, // bx lr
    0x00, 0xbf, // nop
    0x00, 0x10, 0x02, 0x40, // .word 0x40021000
];

fn pools() -> Decompiler {
    let regions =
        [MemoryRegion { base: 0x1000, bytes: &POOLS, size: 24, readable: true, writable: false, executable: true }];
    let mut engine = Decompiler::open_regions(Arch::Arm, false, &regions).unwrap();
    engine.set_read_only_folding(true).unwrap();
    engine
}

#[test]
fn literal_pool_words_fold_into_the_globals_they_address_only_when_asked() {
    let mut engine = pools();
    let code = engine.decompile(0x1000, "read_ram", true).unwrap();
    // Ghidra's default name for the unnamed global, not a variable for the pool word at 0x1008.
    assert!(code.contains("Ram20000004;"), "{code}");
    assert!(!code.contains("1008"), "{code}");
    // Off by default, as for headered images whose read-only sections may be written at run time.
    engine.set_read_only_folding(false).unwrap();
    let code = engine.decompile(0x1000, "read_ram", true).unwrap();
    assert!(code.contains("Ram00001008"), "{code}");
}

#[test]
fn unnamed_globals_take_a_data_name_or_their_region_prefix() {
    let mut engine = pools();
    engine.add_data_region(0x2000_0000, 0x3fff_ffff, "ram").unwrap();
    engine.add_data_region(0x4000_0000, 0x5fff_ffff, "periph").unwrap();
    let code = engine.decompile(0x1000, "read_ram", true).unwrap();
    assert!(code.contains("return ram_20000004;"), "{code}");
    let code = engine.decompile(0x100c, "write_periph", true).unwrap();
    assert!(code.contains("periph_40021000 = param_1;"), "{code}");

    let mut engine = pools();
    engine.add_data_region(0x2000_0000, 0x3fff_ffff, "ram").unwrap();
    engine.set_data_name(0x2000_0004, "boot_count").unwrap();
    let code = engine.decompile(0x1000, "read_ram", true).unwrap();
    assert!(code.contains("return boot_count;"), "{code}");

    assert!(engine.add_data_region(0x3000_0000, 0x4000_0000, "overlap").is_err());
    assert!(engine.add_data_region(0x1000_0000, 0x2000_0000, "overlap").is_err());
    assert!(engine.add_data_region(0x5000_0000, 0x4000_0000, "reversed").is_err());
    assert!(engine.add_data_region(0x6000_0000, 0x6fff_ffff, "not-an-identifier").is_err());
    assert!(engine.set_data_name(0x2000_0008, "9lives").is_err());
    assert!(engine.set_data_name(0x2000_0008, "").is_err());
    assert!(engine.set_data_name(0x1_0000_0000, "beyond").is_err());
}
