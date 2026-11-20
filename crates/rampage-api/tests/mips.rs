//! MIPS Linux userland (tests/fixtures/mips, built from router.c): position-independent code reaches its imports,
//! strings and data through the GOT and `$gp`, which LLVM computes from `$t9` and keeps in a callee-saved register,
//! and GCC restores from the stack after each call. Each fixture's -sym copy keeps the symbols as the truth.

use rampage_api::{Project, XrefQuery};
use rampage_loaders::Binary;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/mips/");

/// The o32 userland fixtures: LLVM (lld) big- and little-endian, unoptimised, static musl, and GCC (GNU ld) PIEs
/// with lazy-binding stubs.
const O32: [&str; 6] =
    ["router-mips", "router-mipsel", "router-mipsel-O0", "router-mips-static", "router-gnu-mips", "router-gnu-mipsel"];
const DYNAMIC: [&str; 5] = ["router-mips", "router-mipsel", "router-mipsel-O0", "router-gnu-mips", "router-mips64"];

fn project(name: &str) -> Project {
    Project::new(Binary::open(format!("{DIR}{name}.elf")).unwrap())
}

fn truth(name: &str, symbol: &str) -> u64 {
    let binary = Binary::open(format!("{DIR}{name}-sym.elf")).unwrap();
    binary.symbol_by_name(symbol).unwrap_or_else(|| panic!("{name}: no {symbol}")).address
}

/// The address of the NUL-terminated string `text` in the image.
fn string(project: &Project, text: &str) -> u64 {
    let binary = &project.binary;
    let needle = [text.as_bytes(), &[0]].concat();
    binary
        .segments
        .iter()
        .find_map(|segment| {
            let bytes = binary.read(segment.address, segment.size.min(1 << 20))?;
            let at = bytes.windows(needle.len()).position(|window| window == needle)?;
            Some(segment.address + at as u64)
        })
        .unwrap_or_else(|| panic!("{text:?} not in the image"))
}

fn referencing_functions(project: &Project, address: u64) -> Vec<String> {
    let rows = project.xrefs(XrefQuery::To(address), None, None).unwrap();
    rows.items.into_iter().filter_map(|row| row.from_function).collect()
}

/// `lw $at, %got(page)($gp); addiu $a0, $at, %lo(string)`: the local GOT entry holds the string's page, so the
/// string is referenced from the function that passes it, whether `$gp` lives in `$gp` (GCC), in a callee-saved
/// register computed from `$t9` (LLVM) or in a stack slot (LLVM -O0).
#[test]
fn strings_are_referenced_through_the_got() {
    for name in O32.into_iter().chain(["router-mips64"]) {
        let project = project(name);
        let main = format!("sub_{:x}", truth(name, "main"));
        let request = format!("sub_{:x}", truth(name, "handle_request"));
        for (text, function) in [("ROUTER_USER", &main), ("login ok", &main), ("/cgi-bin/", &request)] {
            let from = referencing_functions(&project, string(&project, text));
            let named = project.function_name(truth(name, if function == &main { "main" } else { "handle_request" }));
            assert!(from.contains(function) || from.contains(&named), "{name}: {text:?} referenced from {from:?}");
        }
    }
}

/// `lw $t9, %call16(getenv)($gp); jalr $t9`: the call goes through the import's GOT entry, so the call site
/// references the import, as x86's `call [slot]` does.
#[test]
fn calls_through_import_got_entries_reference_the_import() {
    for name in ["router-mips", "router-mipsel", "router-mipsel-O0", "router-mips64"] {
        let project = project(name);
        let slot = project.binary.import_slots.iter().find(|slot| slot.name == "getenv").unwrap().address;
        let from = referencing_functions(&project, slot);
        assert!(from.contains(&project.function_name(truth(name, "main"))), "{name}: getenv slot from {from:?}");
    }
}

/// GNU ld's lazy-binding stubs take the name of the import whose GOT entry holds their address.
#[test]
fn lazy_binding_stubs_are_named_after_their_imports() {
    for name in ["router-gnu-mips", "router-gnu-mipsel"] {
        let project = project(name);
        let stubs: Vec<(u64, String)> = rampage_analysis::functions::stub_names(&project.binary);
        let getenv = stubs.iter().find(|(_, stub)| stub == "getenv@plt").unwrap_or_else(|| panic!("{stubs:?}"));
        let stubs_section = project.binary.sections.iter().find(|section| section.name == ".MIPS.stubs").unwrap();
        assert!(getenv.0 >= stubs_section.address && getenv.0 < stubs_section.address + stubs_section.size);
        assert_eq!(project.function_name(getenv.0), "getenv@plt", "{name}");
    }
}

/// With `$t9` the entry address and `$gp` the global pointer at every function's entry, GOT loads fold: imports by
/// name, strings as literals, and no `in_t9` input is left.
#[test]
fn decompiled_pic_code_names_imports_and_strings() {
    for name in DYNAMIC {
        let project = project(name);
        let main = project.decompile(truth(name, "main")).unwrap().code;
        assert!(main.contains("getenv(\"ROUTER_USER\")"), "{name}: {main}");
        assert!(main.contains("puts(\"login ok\")"), "{name}: {main}");
        assert!(!main.contains("in_t9") && !main.contains("code *"), "{name}: {main}");
        let request = project.decompile(truth(name, "handle_request")).unwrap().code;
        assert!(request.contains("strncmp(param_1,\"/cgi-bin/\",9)"), "{name}: {request}");
    }
}

/// Acceptance (zlib's `deflateInit_` decompiled to `(*pcRam000300d4)(...)`): a shared library calls its own exported
/// functions through global GOT entries, and such a call renders by the function's name. The fixture is
/// router-mips.elf with `strlen` made a definition: its dynamic symbol gets a section and a function's address, and
/// its GOT entry a stored value. The dynamic linker fills the entry from the symbol, so a name is bound only when
/// the symbol is a defined function and the stored value agrees with it (review: a file whose bytes and symbol
/// disagree must not show the stored bytes' function).
#[test]
fn calls_through_got_entries_of_defined_functions_render_by_name() {
    let decode_secret = truth("router-mips", "decode_secret") as u32;
    let check_login = truth("router-mips", "check_login") as u32;
    // .dynsym is at file offset 0x1f8 with 16-byte entries; strlen is entry 9 (st_info at +12: binding << 4 | type).
    // .got is at 0x31030 (file 0x1030) and strlen's global entry is at 0x31088.
    let (symbol, entry) = (0x1f8 + 9 * 16, 0x1088);
    let main_with = |value: u32, stored: u32, kind: u8| {
        let mut bytes = std::fs::read(format!("{DIR}router-mips.elf")).unwrap();
        assert_eq!((&bytes[symbol + 4..symbol + 8], &bytes[entry..entry + 4]), (&[0u8; 4][..], &[0u8; 4][..]));
        assert_eq!(&bytes[symbol + 14..symbol + 16], [0; 2]);
        bytes[symbol + 4..symbol + 8].copy_from_slice(&value.to_be_bytes());
        bytes[symbol + 12] = 0x10 | kind;
        bytes[symbol + 14..symbol + 16].copy_from_slice(&12u16.to_be_bytes());
        bytes[entry..entry + 4].copy_from_slice(&stored.to_be_bytes());
        let project = Project::new(Binary::from_owned_native_bytes(bytes, rampage_arch::Arch::Mips).unwrap());
        assert!(project.binary.import_slots.iter().all(|slot| slot.name != "strlen"));
        let secret = project.function_name(u64::from(decode_secret));
        (project.decompile(truth("router-mips", "main")).unwrap().code, secret)
    };
    // Symbol and entry agree: the call names the function.
    let (main, secret) = main_with(decode_secret, decode_secret, 2);
    assert!(main.contains(&format!("{secret}(")), "{main}");
    assert!(!main.contains("code *") && !main.contains("pcRam"), "{main}");
    // The entry's bytes say decode_secret but its symbol says check_login: decode_secret is not shown there.
    let (main, secret) = main_with(check_login, decode_secret, 2);
    assert!(!main.contains(&format!("{secret}(")), "{main}");
    // A data symbol on the slot binds no function name.
    let (main, secret) = main_with(decode_secret, decode_secret, 1);
    assert!(!main.contains(&format!("{secret}(")), "{main}");
}

/// main is the first argument to __libc_start_main: glibc's `__start` loads it from the GOT, and musl's `_start`
/// reaches `_start_c` through a `.gpword`, which passes it in a call's delay slot.
#[test]
fn find_main_follows_the_mips_startup_code() {
    for name in O32.into_iter().chain(["router-mips64"]) {
        let project = project(name);
        let report = project.find_main(rampage_api::ReportLimits::default(), false).unwrap();
        let report = serde_json::to_value(&report).unwrap();
        let candidate = &report["sections"][0]["findings"][0];
        assert_eq!(candidate["address"], format!("{:#x}", truth(name, "main")), "{name}: {report:#}");
        assert!(candidate.to_string().contains("first argument"), "{name}: {candidate:#}");
    }
}

/// A GCC PIE is linked at 0, so its first functions lie in page 0: they run, while loads there still fault.
#[test]
fn evaluation_runs_pie_code_in_page_zero() {
    for name in ["router-gnu-mips", "router-gnu-mipsel", "router-mips", "router-mips64"] {
        let project = project(name);
        let request = serde_json::json!({ "at": format!("{:#x}", truth(name, "scale_add")), "args": [5, 2, 1] });
        let report = project.evaluate_function(&serde_json::from_value(request).unwrap()).unwrap();
        let report = serde_json::to_value(report).unwrap();
        assert_eq!(report["stop"], "returned", "{name}: {report}");
        assert_eq!(report["result"]["unsigned"], 16, "{name}: {report}");
    }
    // A call through a null pointer, or into the headers before the code, still faults.
    let project = project("router-gnu-mips");
    for at in ["0x0", "0x40"] {
        let request = serde_json::json!({ "at": at, "args": [] });
        let report = project.evaluate_function(&serde_json::from_value(request).unwrap()).unwrap();
        let report = serde_json::to_value(report).unwrap();
        assert_eq!(report["stop"], "unmapped_fetch", "{at}: {report}");
    }
}

/// Router firmware often ships binaries without section headers: the dynamic section's DT_PLTGOT and
/// DT_MIPS_LOCAL_GOTNO still give the GOT and the global pointer.
#[test]
fn the_got_is_found_without_section_headers() {
    let mut bytes = std::fs::read(format!("{DIR}router-mips.elf")).unwrap();
    // e_shoff, e_shentsize, e_shnum and e_shstrndx of a big-endian ELF32 header.
    bytes[0x20..0x24].fill(0);
    bytes[0x2e..0x34].fill(0);
    let binary = Binary::from_owned_native_bytes(bytes, rampage_arch::Arch::Mips).unwrap();
    assert!(binary.sections.is_empty());
    let target = binary.target();
    assert_eq!(target.global_pointer, Some(truth("router-mips", "_gp")));
    assert_eq!(target.got.unwrap().local_entries, 14);
    let project = Project::new(binary);
    let main = format!("sub_{:x}", truth("router-mips", "main"));
    let from = referencing_functions(&project, string(&project, "ROUTER_USER"));
    assert!(from.contains(&main), "{from:?}");
}

/// OpenWrt builds most programs as MIPS16e, which rampage does not decode: an ELF header that marks MIPS16e
/// (`EF_MIPS_ARCH_ASE_M16`) or microMIPS makes `binary_info` warn and `list_functions` say so, rather than leaving a
/// short function list to read as the whole program. The fixture is router-mips.elf with only that flag set.
#[test]
fn compressed_instruction_sets_are_reported_as_not_decoded() {
    let plain = project("router-mips");
    assert_eq!(plain.binary.undecoded_isa(), None);
    assert!(plain.functions_page(&rampage_api::FunctionsQuery::default()).unwrap().note.is_none());
    let bytes = std::fs::read(format!("{DIR}router-mips.elf")).unwrap();
    for (flag, isa) in [(0x0400_0000u32, "MIPS16e"), (0x0200_0000, "microMIPS")] {
        let mut flagged = bytes.clone();
        // e_flags of a big-endian ELF32 header.
        let flags = u32::from_be_bytes(flagged[0x24..0x28].try_into().unwrap()) | flag;
        flagged[0x24..0x28].copy_from_slice(&flags.to_be_bytes());
        let project = Project::new(Binary::from_owned_native_bytes(flagged, rampage_arch::Arch::Mips).unwrap());
        assert_eq!(project.binary.undecoded_isa(), Some(isa));
        let warning = format!("marks {isa} code, which rampage does not decode");
        assert!(project.binary.warnings.iter().any(|text| text.contains(&warning)), "{:?}", project.binary.warnings);
        let page = project.functions_page(&rampage_api::FunctionsQuery::default()).unwrap();
        assert!(page.note.as_deref().is_some_and(|note| note.contains(&warning)), "{:?}", page.note);
        // The MIPS32 code is still analysed.
        assert!(page.page.total > 0);
    }
}

/// Review: a MIPS16e or microMIPS function symbol carries the ISA bit (an odd address). It must not seed a function
/// whose bytes are then decoded as MIPS32. The fixture is router-mips-sym.elf with `scale_add`'s symbol made odd.
#[test]
fn odd_mips_symbols_seed_no_function() {
    let mut bytes = std::fs::read(format!("{DIR}router-mips-sym.elf")).unwrap();
    let scale_add = truth("router-mips", "scale_add") as u32;
    // .symtab is at file offset 0x108c with 16-byte entries; scale_add is entry 30, st_value at +4.
    let value = 0x108c + 30 * 16 + 4;
    assert_eq!(&bytes[value..value + 4], scale_add.to_be_bytes());
    bytes[value..value + 4].copy_from_slice(&(scale_add | 1).to_be_bytes());
    let project = Project::new(Binary::from_owned_native_bytes(bytes, rampage_arch::Arch::Mips).unwrap());
    let functions = project.functions(&rampage_api::FunctionsQuery::default()).unwrap();
    let starts: Vec<u64> = functions.items.iter().map(|function| function.address).collect();
    assert!(starts.iter().all(|start| start & 3 == 0), "{starts:x?}");
    // The real, even start is still found from its caller.
    assert!(starts.contains(&u64::from(scale_add)), "{starts:x?}");
}

fn boot_rom() -> Project {
    let image = std::fs::read(format!("{DIR}boot-mips.bin")).unwrap();
    let options = rampage_loaders::RawCodeOptions {
        profile: rampage_loaders::RawProfile::Mips32Be,
        base: 0xbfc0_0000,
        entry: None,
        seeds: vec![],
        vector_table: None,
        pointer_tables: false,
    };
    Project::new(Binary::from_raw_code(image, options).unwrap())
}

fn boot_truth(symbol: &str) -> u64 {
    Binary::open(format!("{DIR}boot-mips.elf")).unwrap().symbol_by_name(symbol).unwrap().address
}

/// A MIPS32 boot ROM mapped at the reset vector: the entry defaults to the base, discovery finds every function
/// from it, find_main follows the reset code's jump to its C entry, and the code decompiles and runs.
#[test]
fn raw_mips_boot_rom_at_the_reset_vector() {
    let project = boot_rom();
    assert_eq!(project.binary.entry, Some(0xbfc0_0000));
    let functions = project.functions(&rampage_api::FunctionsQuery::default()).unwrap();
    let starts: Vec<u64> = functions.items.iter().map(|function| function.address).collect();
    for symbol in ["uart_putc", "uart_puts", "crc32_bitwise", "mix", "boot_fail", "boot_main"] {
        assert!(starts.contains(&boot_truth(symbol)), "{symbol}: {starts:x?}");
    }
    let report = project.find_main(rampage_api::ReportLimits::default(), false).unwrap();
    let report = serde_json::to_value(&report).unwrap();
    assert_eq!(report["sections"][0]["findings"][0]["address"], format!("{:#x}", boot_truth("boot_main")));
    let code = project.decompile(boot_truth("boot_main")).unwrap().code;
    assert!(code.contains("0x27051956"), "{code}");
    let from = referencing_functions(&project, string(&project, "MIPS boot ROM v1.2\r\n"));
    assert_eq!(from, [format!("sub_{:x}", boot_truth("boot_main"))]);
    let request = serde_json::json!({ "at": format!("{:#x}", boot_truth("mix")), "args": [1, 16] });
    let report = serde_json::to_value(project.evaluate_function(&serde_json::from_value(request).unwrap()).unwrap());
    assert_eq!(report.unwrap()["result"]["unsigned"], (1 << 5) + (16 >> 3) + 0x1234);
    // The CRC routines: CRC-32 by its lui/ori polynomial, CRC-16 by `xori 0xa001` in a loop that shifts by one;
    // uart_divisor's `xori 0x1021`, with no such loop, is no CRC.
    let mut project = std::sync::Arc::new(project);
    let report = rampage_api::tools::call_shared(
        &rampage_api::tools::tools(),
        &mut project,
        "integrity_checks",
        serde_json::json!({}),
    );
    assert!(!report.1, "{}", report.0);
    let report: serde_json::Value = serde_json::from_str(&report.0).unwrap();
    let routines: Vec<String> =
        report["routines"].as_array().unwrap().iter().map(|routine| routine["address"].to_string()).collect();
    for (symbol, expected) in [("crc32_bitwise", true), ("crc16_modbus", true), ("uart_divisor", false)] {
        let address = format!("\"{:#x}\"", boot_truth(symbol));
        assert_eq!(routines.contains(&address), expected, "{symbol}: {report:#}");
    }
}

/// The CRC-32 polynomial MIPS code builds with `lui` and `ori` is found by constant search (`loaded_constant`) and
/// names the routine in integrity_checks; a small `addiu` immediate is a typed operand.
#[test]
fn constants_mips_code_builds_are_searchable() {
    let registry = rampage_api::tools::tools();
    for name in ["router-gnu-mips", "router-gnu-mipsel"] {
        let mut project = std::sync::Arc::new(project(name));
        let mode = serde_json::json!({ "kind": "functions_referencing", "reference": { "kind": "constant", "immediate": { "value": { "kind": "unsigned", "value": 0xedb8_8320u32 } } } });
        let (text, failed) =
            rampage_api::tools::call_shared(&registry, &mut project, "search", serde_json::json!({ "mode": mode }));
        assert!(!failed, "{text}");
        let report: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(report["hits"][0]["address"], format!("{:#x}", truth(name, "crc32_init")), "{report:#}");
        let (text, failed) =
            rampage_api::tools::call_shared(&registry, &mut project, "integrity_checks", serde_json::json!({}));
        assert!(!failed && text.contains("polynomial 0xedb88320 formed by lui and ori"), "{text}");
    }
    let mut project = std::sync::Arc::new(project("router-mips"));
    let mode = serde_json::json!({ "kind": "immediate", "immediate": { "value": { "kind": "unsigned", "value": 9 } } });
    let (text, failed) =
        rampage_api::tools::call_shared(&registry, &mut project, "search", serde_json::json!({ "mode": mode }));
    assert!(!failed && text.contains("addiu $a2, $zero, 9"), "{text}");
}

/// Review: per-block runs (search, signatures) on GCC's `deregister_tm_clones` once took the block at `jr $t9` for a
/// function entry, giving a jump to itself and a fake reference.
#[test]
fn block_runs_do_not_assume_t9() {
    let project = project("router-gnu-mipsel");
    let block = 0x9c8;
    let mut decoder = project.binary.decoder().unwrap();
    decoder.begin_run();
    let insn = decoder.decode(project.binary.code_from(block).unwrap(), block);
    assert_eq!(insn.flow, rampage_arch::Flow::IndirectJump);
    let mode =
        serde_json::json!({ "kind": "functions_referencing", "reference": { "kind": "address", "target": block } });
    let registry = rampage_api::tools::tools();
    let mut project = std::sync::Arc::new(project);
    let (text, failed) =
        rampage_api::tools::call_shared(&registry, &mut project, "search", serde_json::json!({ "mode": mode }));
    assert!(!failed, "{text}");
    assert_eq!(serde_json::from_str::<serde_json::Value>(&text).unwrap()["hits"], serde_json::json!([]), "{text}");
}

/// Review: a MIPS boot ROM's first instruction is usually `b reset` over the exception vectors (0x200 and 0x380); that
/// jump is followed, and the C entry is the jump taken after the reset code sets the stack.
#[test]
fn raw_mips_find_main_follows_the_branch_over_the_exception_vectors() {
    let mut image = vec![0u8; 0x600];
    let mut word = |offset: usize, value: u32| image[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    word(0x000, 0x1000_00ff); // b 0xbfc00400
    word(0x380, 0x4200_0018); // eret (the general exception vector)
    word(0x400, 0x3c1d_8001); // lui $sp, 0x8001
    word(0x404, 0x3c08_bfc0); // lui $t0, 0xbfc0
    word(0x408, 0x2508_0500); // addiu $t0, $t0, 0x500
    word(0x40c, 0x0100_0008); // jr $t0
    word(0x500, 0x1000_ffff); // b . (main)
    let options = rampage_loaders::RawCodeOptions {
        profile: rampage_loaders::RawProfile::Mips32Be,
        base: 0xbfc0_0000,
        entry: None,
        seeds: vec![],
        vector_table: None,
        pointer_tables: false,
    };
    let project = Project::new(Binary::from_raw_code(image, options).unwrap());
    let report = project.find_main(rampage_api::ReportLimits::default(), false).unwrap();
    let report = serde_json::to_value(&report).unwrap();
    let candidate = &report["sections"][0]["findings"][0];
    assert_eq!(candidate["address"], "0xbfc00500", "{report:#}");
    assert!(candidate["evidence"].to_string().contains("followed"), "{candidate:#}");
}
