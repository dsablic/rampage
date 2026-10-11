use rampage_arch::Arch;
use rampage_decompiler::{Decompiler, MemoryRegion};

#[test]
fn indirect_import_slots_have_typed_calls_without_inventing_a_pointer_value() {
    let caller = [0xbf, 0, 0x20, 0, 0, 0xff, 0x15, 0xf5, 0x1f, 0, 0, 0x31, 0xc0, 0xc3];
    let regions = [
        MemoryRegion {
            base: 0x1000,
            bytes: &caller,
            size: caller.len() as u64,
            readable: true,
            writable: false,
            executable: true,
        },
        MemoryRegion {
            base: 0x2000,
            bytes: b"greeting\0",
            size: 9,
            readable: true,
            writable: false,
            executable: false,
        },
        MemoryRegion { base: 0x3000, bytes: &[0; 8], size: 8, readable: true, writable: true, executable: false },
    ];
    let mut engine = Decompiler::open_regions(Arch::X86_64, false, &regions).unwrap();
    engine.add_import(0x3000, None, "puts@got").unwrap();
    assert!(engine.add_import(0x3000, None, "replacement").is_err());
    engine.apply_prototype(0x3000, true, &engine.c_prototype("puts").unwrap()).unwrap();
    let code = engine.decompile(0x1000, "caller", false).unwrap();
    assert!(code.contains("puts@got(\"greeting\")"), "{code}");
    for token in engine.tokens().iter().filter(|token| matches!(token.kind.as_str(), "function" | "call")) {
        assert!(matches!(token.address, Some(0x1000) | Some(0x3000)), "{token:?}");
    }
    assert!(engine.apply_prototype(0x5000, false, "int4 x(void);").is_err());
    assert!(engine.apply_prototype(0x3000, true, "invalid declaration").is_err());
}

#[test]
fn external_symbols_reserve_aligned_ranges_on_fixed_width_architectures() {
    for arch in [Arch::Arm, Arch::Aarch64, Arch::Mips, Arch::PowerPc] {
        let regions = [MemoryRegion {
            base: 0x1000,
            bytes: &[0; 16],
            size: 16,
            readable: true,
            writable: false,
            executable: true,
        }];
        let mut engine = Decompiler::open_regions(arch, false, &regions).unwrap();
        if arch == Arch::Arm {
            engine.set_symbol(0xffff_fffd, "existing").unwrap();
        }
        engine.add_import(0x3000, None, "first").unwrap();
        engine.add_import(0x3010, None, "second").unwrap();
        let first = engine.import_target(0x3000).unwrap();
        let second = engine.import_target(0x3010).unwrap();
        assert_ne!(first, second);
        if arch == Arch::Arm {
            assert!(first < 0xffff_fffd && second < first, "{first:x}/{second:x}");
        }
        engine.apply_prototype(0x3000, true, "int4 first(char *s);").unwrap();
        engine.apply_prototype(0x3010, true, "int4 second(int4 x);").unwrap();
    }
}

#[test]
fn signatures_bind_to_addresses_not_display_names_and_updates_are_visible() {
    let bytes = [0x89, 0xf8, 0xc3];
    let regions =
        [MemoryRegion { base: 0x1000, bytes: &bytes, size: 3, readable: true, writable: false, executable: true }];
    let mut engine = Decompiler::open_regions(Arch::X86_64, false, &regions).unwrap();
    engine.set_symbol(0x1000, "display@name").unwrap();
    engine.add_import(0x3000, Some(0x1000), "display@name").unwrap();
    engine.apply_prototype(0x1000, false, "int4 canonical(int4 value);").unwrap();
    let code = engine.decompile(0x1000, "display@name", false).unwrap();
    assert!(code.contains("display@name(int4 value)"), "{code}");
    assert!(engine.tokens().iter().any(|token| token.kind == "function" && token.address == Some(0x1000)));
    engine.set_symbol(0x1000, "renamed").unwrap();
    let code = engine.decompile(0x1000, "renamed", false).unwrap();
    assert!(code.contains("renamed(int4 value)"), "{code}");
}

#[test]
fn output_limit_errors_clear_tokens_and_allow_a_clean_retry() {
    let bytes = [0x31, 0xc0, 0xc3];
    let regions =
        [MemoryRegion { base: 0x1000, bytes: &bytes, size: 3, readable: true, writable: false, executable: true }];
    let mut engine = Decompiler::open_regions(Arch::X86_64, false, &regions).unwrap();
    engine.set_symbol(0x1000, &"x".repeat(4 * 1024 * 1024 + 1)).unwrap();
    assert!(engine.decompile(0x1000, "fixture", false).is_err());
    assert!(engine.tokens().is_empty());
    engine.set_symbol(0x1000, "recovered").unwrap();
    let code = engine.decompile(0x1000, "recovered", false).unwrap();
    assert!(code.contains("recovered(void)"), "{code}");
    assert_eq!(code.matches("recovered").count(), 1);
}
