use rampage_arch::Arch;
use rampage_decompiler::{Decompiler, DecompilerOptions, MemoryRegion};

#[test]
fn arm_be8_selects_mixed_endianness_and_decodes_little_endian_instructions() {
    let bytes = [7, 0, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1];
    let regions = [MemoryRegion {
        base: 0x1000,
        bytes: &bytes,
        size: bytes.len() as u64,
        readable: true,
        writable: false,
        executable: true,
    }];
    let options = DecompilerOptions { arm_be8: true, ..Default::default() };
    let mut engine = Decompiler::open_with_options(Arch::Arm, true, &regions, &options).unwrap();
    assert!(engine.language_id().contains(":LEBE:"));
    engine.set_symbol(0x1000, "literal").unwrap();
    engine.apply_prototype(0x1000, false, "int4 literal(void);").unwrap();
    let code = engine.decompile(0x1000, "literal", false).unwrap();
    assert!(code.contains("return 7;"), "{code}");
    assert!(Decompiler::open_with_options(Arch::Arm, false, &regions, &options).is_err());
}
