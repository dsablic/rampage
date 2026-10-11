use rampage_arch::Arch;
use rampage_decompiler::{DataOrganization, Decompiler, DecompilerOptions, MemoryRegion, Platform};

fn open(arch: Arch, bytes: &[u8], platform: Platform) -> Decompiler {
    Decompiler::open_with_options(
        arch,
        false,
        &[MemoryRegion {
            base: 0x1000,
            bytes,
            size: bytes.len() as u64,
            readable: true,
            writable: false,
            executable: true,
        }],
        &DecompilerOptions { platform, compiler: None, arm_be8: false },
    )
    .unwrap()
}

#[test]
fn windows_x64_uses_two_register_arguments_not_four_system_v_slots() {
    let bytes = [0x89, 0xc8, 0x01, 0xd0, 0xc3];
    let code = open(Arch::X86_64, &bytes, Platform::Windows).decompile(0x1000, "sum", false).unwrap();
    assert!(code.contains("param_1 + param_2") || code.contains("param_2 + param_1"), "{code}");
    assert!(!code.contains("param_3"), "{code}");
}

#[test]
fn runtime_sizes_follow_ilp32_lp64_and_llp64_specs() {
    for (arch, platform, pointer, long) in [
        (Arch::X86, Platform::Default, 4, 4),
        (Arch::X86, Platform::Windows, 4, 4),
        (Arch::X86_64, Platform::Default, 8, 8),
        (Arch::X86_64, Platform::Windows, 8, 4),
        (Arch::Aarch64, Platform::Windows, 8, 4),
    ] {
        let mut decompiler = open(arch, &[0xc3], platform);
        assert_eq!(decompiler.data_organization(), DataOrganization { pointer, int: 4, long });
        for (index, (name, expected)) in [
            ("malloc", format!("uint{pointer} n")),
            ("strlen", format!("uint{pointer} ")),
            ("strtol", format!("int{long} ")),
            ("strtoul", format!("uint{long} ")),
            ("fseek", format!("int{long} off")),
        ]
        .into_iter()
        .enumerate()
        {
            let prototype = decompiler.c_prototype(name).unwrap();
            assert!(prototype.contains(&expected), "{arch}/{platform:?}: {prototype}");
            decompiler.add_symbol(0x1000 + index as u64 * 16, name);
            decompiler.parse_c(&prototype).unwrap();
        }
        assert!(decompiler.c_prototype("time").is_none());
        assert!(decompiler.c_prototype("lseek").is_none());
    }
}

#[test]
fn windows_x86_runtime_prototypes_are_cdecl_not_the_specs_stdcall_default() {
    let mut decompiler = open(Arch::X86, &[0x31, 0xc0, 0xc3], Platform::Windows);
    decompiler.add_symbol(0x1000, "ftell");
    let prototype = decompiler.c_prototype("ftell").unwrap();
    assert_eq!(prototype, "extern __cdecl int4 ftell(void *stream);");
    decompiler.parse_c(&prototype).unwrap();
    let code = decompiler.decompile(0x1000, "ftell", false).unwrap();
    assert!(code.contains("int4 __cdecl ftell("), "{code}");
    assert!(!code.contains("__stdcall"), "{code}");
}

#[test]
fn a_32_bit_malloc_call_uses_one_size_argument() {
    let bytes = [0x6a, 0x20, 0xe8, 9, 0, 0, 0, 0x83, 0xc4, 4, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3];
    let mut decompiler = open(Arch::X86, &bytes, Platform::Default);
    decompiler.add_symbol(0x1010, "malloc");
    decompiler.parse_c(&decompiler.c_prototype("malloc").unwrap()).unwrap();
    let code = decompiler.decompile(0x1000, "caller", false).unwrap();
    assert!(code.contains("malloc(0x20)"), "{code}");
}

#[test]
fn explicit_compiler_ids_override_defaults_and_invalid_ids_are_errors() {
    let regions =
        [MemoryRegion { base: 0x1000, bytes: &[0xc3], size: 1, readable: true, writable: false, executable: true }];
    let options = DecompilerOptions { platform: Platform::Windows, compiler: Some("gcc".to_owned()), arm_be8: false };
    let decompiler = Decompiler::open_with_options(Arch::X86_64, false, &regions, &options).unwrap();
    assert!(decompiler.language_id().ends_with(":gcc"));
    assert_eq!(decompiler.data_organization().long, 8);
    for compiler in ["not_a_spec", "", "gcc:windows", "gcc\0"] {
        let options = DecompilerOptions { compiler: Some(compiler.to_owned()), ..Default::default() };
        assert!(Decompiler::open_with_options(Arch::X86_64, false, &regions, &options).is_err());
    }
}

#[test]
fn default_c_models_cover_all_bundled_targets_and_powerpc_darwin() {
    for (arch, big_endian, platform, width) in [
        (Arch::X86, false, Platform::Default, 4),
        (Arch::X86_64, false, Platform::Default, 8),
        (Arch::Arm, false, Platform::Default, 4),
        (Arch::Aarch64, false, Platform::Default, 8),
        (Arch::Mips, false, Platform::Default, 4),
        (Arch::Mips, true, Platform::Default, 4),
        (Arch::Mips64, false, Platform::Default, 8),
        (Arch::Mips64, true, Platform::Default, 8),
        (Arch::PowerPc, true, Platform::Default, 4),
        (Arch::PowerPc64, true, Platform::Default, 8),
        (Arch::PowerPc, true, Platform::Darwin, 4),
        (Arch::PowerPc64, true, Platform::Darwin, 8),
        (Arch::Riscv32, false, Platform::Default, 4),
        (Arch::Riscv64, false, Platform::Default, 8),
        (Arch::Sparc, true, Platform::Default, 4),
        (Arch::Sparc64, true, Platform::Default, 8),
        (Arch::M68k, true, Platform::Default, 4),
    ] {
        let regions =
            [MemoryRegion { base: 0x1000, bytes: &[0], size: 1, readable: true, writable: false, executable: true }];
        let options = DecompilerOptions { platform, compiler: None, arm_be8: false };
        let decompiler = Decompiler::open_with_options(arch, big_endian, &regions, &options).unwrap();
        assert_eq!(
            decompiler.data_organization(),
            DataOrganization { pointer: width, int: 4, long: width },
            "{arch}/{platform:?}"
        );
        assert!(decompiler.c_prototype("strtol").unwrap().starts_with(&format!("extern int{width} ")));
    }
}

#[test]
fn clang_windows_alias_keeps_crt_types_strings_and_x86_cdecl() {
    let caller = [0xb9, 0, 0x20, 0, 0, 0xe8, 0xf6, 0x1f, 0, 0, 0x31, 0xc0, 0xc3];
    for compiler in ["windows", "clangwindows"] {
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
        ];
        let options = DecompilerOptions { compiler: Some(compiler.to_owned()), ..Default::default() };
        let mut decompiler = Decompiler::open_with_options(Arch::X86_64, false, &regions, &options).unwrap();
        decompiler.add_symbol(0x3000, "puts");
        decompiler.parse_c(&decompiler.c_prototype("puts").unwrap()).unwrap();
        let code = decompiler.decompile(0x1000, "caller", false).unwrap();
        assert!(code.contains("puts(\"greeting\")"), "{compiler}: {code}");
        assert!(decompiler.c_prototype("read").is_none());
        let mut x86 = Decompiler::open_with_options(Arch::X86, false, &regions, &options).unwrap();
        x86.add_symbol(0x3000, "malloc");
        let prototype = x86.c_prototype("malloc").unwrap();
        assert!(prototype.contains("__cdecl"));
        x86.parse_c(&prototype).unwrap();
    }
}
