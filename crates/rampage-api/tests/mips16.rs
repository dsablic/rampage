//! MIPS16e userland (tests/fixtures/mips, built by build-mips16.sh): most functions MIPS16e, the `nomips16` ones
//! MIPS32, calls crossing between them through `jalx` and through GOT entries whose low bit names the mode, and a
//! shared library shipped without section headers. Each -sym copy keeps the symbols as the truth.

use std::collections::BTreeMap;
use std::ops::Range;

use object::{Object, ObjectSymbol, SymbolFlags, SymbolKind};
use rampage_api::{Project, XrefQuery};
use rampage_loaders::Binary;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/mips/");

/// Big-endian PIE and little-endian non-PIC programs.
const PROGRAMS: [&str; 2] = ["router16-gnu-mips", "router16-gnu-mipsel"];

fn open(file: &str) -> Project {
    Project::new(Binary::open(format!("{DIR}{file}")).unwrap())
}

/// The truth: each function symbol's code range and whether it is MIPS16e, read with `object` from the -sym copy.
/// GNU tools mark MIPS16e functions with an odd value or with `STO_MIPS16` (0xf0) in `st_other`.
fn truth(file: &str) -> BTreeMap<String, (Range<u64>, bool)> {
    let data = std::fs::read(format!("{DIR}{file}")).unwrap();
    let parsed = object::File::parse(&*data).unwrap();
    let mut functions = BTreeMap::new();
    for symbol in parsed.symbols().filter(|symbol| symbol.kind() == SymbolKind::Text && !symbol.is_undefined()) {
        let flagged = matches!(symbol.flags(), SymbolFlags::Elf { st_other, .. } if st_other.0 & 0xf0 == 0xf0);
        let mips16 = symbol.address() & 1 == 1 || flagged;
        let start = symbol.address() & !1;
        let name = symbol.name().unwrap().to_owned();
        functions.insert(name, (start..start + symbol.size().max(2), mips16));
    }
    functions
}

fn address(truth: &BTreeMap<String, (Range<u64>, bool)>, name: &str) -> u64 {
    truth.get(name).unwrap_or_else(|| panic!("no {name}")).0.start
}

/// Every function of the stripped programs is found, in its own instruction set: each instruction discovery decoded
/// inside a function the truth sizes was decoded in that function's mode, so no MIPS32 decoding is shown as MIPS16e
/// code or the reverse.
#[test]
fn functions_are_found_and_decoded_in_their_own_instruction_set() {
    for name in PROGRAMS {
        let project = open(&format!("{name}.elf"));
        assert!(project.binary.mips16() && project.binary.undecoded_isa().is_none(), "{name}");
        let truth = truth(&format!("{name}-sym.elf"));
        let program = rampage_analysis::functions::analyze(&project.binary).unwrap();
        let starts: Vec<u64> = program.functions.iter().map(|function| function.address).collect();
        for (symbol, (range, _)) in &truth {
            // GNU ld's lazy-binding stubs are listed under their imports' names; register_tm_clones is reached only
            // by frame_dummy's tail jump in the non-PIC build, which discovery keeps inside frame_dummy.
            if symbol == "_MIPS_STUBS_" || symbol == "register_tm_clones" && name.ends_with("el") {
                continue;
            }
            assert!(starts.contains(&range.start), "{name}: {symbol} at {:#x} not found in {starts:x?}", range.start);
        }
        let modes: BTreeMap<u64, bool> = program.code_modes.iter().copied().collect();
        let mut checked = 0;
        for (symbol, (range, mips16)) in truth.iter().filter(|(_, (range, _))| range.end - range.start > 2) {
            for (&at, &mode) in modes.range(range.clone()) {
                let decoded = program
                    .functions
                    .iter()
                    .any(|function| function.blocks.iter().any(|block| block.start <= at && at < block.end));
                if decoded {
                    assert_eq!(mode, *mips16, "{name}: {at:#x} in {symbol} decoded with mips16 = {mode}");
                    checked += 1;
                }
            }
        }
        assert!(checked > 100, "{name}: only {checked} instructions checked");
        // Both instruction sets are present.
        assert!(truth.values().any(|(_, mips16)| *mips16) && truth.values().any(|(_, mips16)| !*mips16));
    }
}

/// Calls cross between the instruction sets in both directions and are cross-referenced: main (MIPS16e) calls
/// crc32_update (MIPS32), and scale_twice (MIPS32) calls scale_add (MIPS16e). The non-PIC build uses `jalx`; the
/// PIE goes through GOT entries holding odd (MIPS16e) or even (MIPS32) addresses.
#[test]
fn calls_between_instruction_sets_are_followed() {
    for name in PROGRAMS {
        let project = open(&format!("{name}.elf"));
        let truth = truth(&format!("{name}-sym.elf"));
        for (caller, callee) in [("main", "crc32_update"), ("main", "crc32_init"), ("scale_twice", "scale_add")] {
            let rows = project.xrefs(XrefQuery::To(address(&truth, callee)), None, None).unwrap();
            let callers: Vec<String> = rows.items.iter().filter_map(|row| row.from_function.clone()).collect();
            let expected = project.function_name(address(&truth, caller));
            assert!(callers.contains(&expected), "{name}: {callee} called from {callers:?}, not {expected}");
        }
    }
}

#[test]
fn mips16e_code_disassembles_with_extended_instructions_and_save() {
    for (name, save) in [("router16-gnu-mips", "save $a0, 80, $ra, $s0-$s1"), ("router16-gnu-mipsel", "save $a0, 64")] {
        let project = open(&format!("{name}.elf"));
        let truth = truth(&format!("{name}-sym.elf"));
        let listing = project.function_listing(address(&truth, "main")).unwrap();
        let lines: Vec<&rampage_api::DisassemblyLine> = listing.blocks.iter().flatten().collect();
        assert!(lines.iter().any(|line| line.text.starts_with(save)), "{name}: {:?}", lines.first());
        assert!(lines.iter().all(|line| line.flow != rampage_arch::Flow::Invalid), "{name}");
        // Two-byte instructions are the common case.
        assert!(lines.iter().filter(|line| line.bytes.len() == 4).count() * 2 > lines.len(), "{name}");
    }
}

#[test]
fn mips16e_functions_decompile() {
    for name in PROGRAMS {
        let project = open(&format!("{name}.elf"));
        let truth = truth(&format!("{name}-sym.elf"));
        let scale_add = project.decompile(address(&truth, "scale_add")).unwrap().code;
        assert!(scale_add.contains("* 3"), "{name}: {scale_add}");
        let crc = project.decompile(address(&truth, "crc32_init")).unwrap().code;
        assert!(crc.contains("0xedb88320"), "{name}: {crc}");
        let request = project.decompile(address(&truth, "handle_request")).unwrap().code;
        for text in ["strncmp", "\"/cgi-bin/\"", "puts"] {
            assert!(request.contains(text), "{name}: {text} in {request}");
        }
    }
}

/// glibc's `__start` (MIPS32) passes main's GOT entry, an odd MIPS16e address, to `__libc_start_main`.
#[test]
fn find_main_reaches_a_mips16e_main() {
    for name in PROGRAMS {
        let project = open(&format!("{name}.elf"));
        let truth = truth(&format!("{name}-sym.elf"));
        let report = project.find_main(rampage_api::ReportLimits::default(), false).unwrap();
        let report = serde_json::to_value(&report).unwrap();
        let candidate = &report["sections"][0]["findings"][0];
        assert_eq!(candidate["address"], format!("{:#x}", address(&truth, "main")), "{name}: {report:#}");
    }
}

/// A MIPS16e shared library without section headers (as OpenWrt's sstrip leaves it): exports and imports come
/// through PT_DYNAMIC, MIPS16e exports are functions at the even address, and the constructor its DT_INIT_ARRAY
/// names, a static MIPS16e function, is found.
#[test]
fn a_sectionless_mips16e_library_lists_its_functions() {
    let project = open("libmips16-gnu-mipsel.so");
    let binary = &project.binary;
    assert!(binary.sections.is_empty() && binary.mips16());
    let truth = truth("libmips16-gnu-mipsel-sym.so");
    for export in ["lib_add", "lib_mul32", "lib_length"] {
        let found = binary.exports.iter().find(|row| row.name == export).unwrap_or_else(|| panic!("{export}"));
        assert_eq!(found.address, address(&truth, export), "{export}");
    }
    assert!(binary.imports.iter().any(|import| import.name == "strlen"), "{:?}", binary.imports);
    let functions = project.functions(&rampage_api::FunctionsQuery::default()).unwrap();
    let starts: Vec<u64> = functions.items.iter().map(|function| function.address).collect();
    for symbol in ["lib_add", "lib_mul32", "lib_length", "library_setup", "frame_dummy", "_init", "_fini"] {
        assert!(starts.contains(&address(&truth, symbol)), "{symbol}: {starts:x?}");
    }
    let page = project.functions_page(&rampage_api::FunctionsQuery::default()).unwrap();
    assert!(page.note.is_none(), "{:?}", page.note);
    // lib_length calls the MIPS32 export and the MIPS16e one through their GOT entries.
    for callee in ["lib_mul32", "lib_add"] {
        let rows = project.xrefs(XrefQuery::To(address(&truth, callee)), None, None).unwrap();
        assert!(rows.items.iter().any(|row| row.from_function.as_deref() == Some("lib_length")), "{callee}");
    }
}

/// evaluate_function runs MIPS16e code, and MIPS32 code that calls into it (scale_twice calls scale_add:
/// (5 * 3 + 5 - 1) * 2).
#[test]
fn mips16e_functions_evaluate() {
    for name in PROGRAMS {
        let project = open(&format!("{name}.elf"));
        let truth = truth(&format!("{name}-sym.elf"));
        for (function, args, result) in [("scale_add", vec![5, 2, 1], 16), ("scale_twice", vec![5], 38)] {
            let request = serde_json::json!({ "at": format!("{:#x}", address(&truth, function)), "args": args });
            let report = project.evaluate_function(&serde_json::from_value(request).unwrap()).unwrap();
            let report = serde_json::to_value(report).unwrap();
            assert_eq!(report["stop"], "returned", "{name} {function}: {report}");
            assert_eq!(report["result"]["unsigned"], result, "{name} {function}: {report}");
        }
    }
}
