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
