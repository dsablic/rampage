use std::path::PathBuf;

use rampage_analysis::{functions, strings};
use rampage_loaders::Binary;

fn open(name: &str) -> Binary {
    Binary::open(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)).unwrap()
}

#[test]
fn finds_greeting_in_every_fixture() {
    for name in ["hello-x64.elf", "hello-x64.exe", "hello-x64.macho", "hello-arm64.macho"] {
        let binary = open(name);
        let found = strings::scan(&binary, 4);
        let greeting = found.iter().find(|string| string.text == "rampage fixture greeting");
        let greeting = greeting.unwrap_or_else(|| panic!("{name}: greeting missing"));
        assert_eq!(binary.read(greeting.address, 7), Some(&b"rampage"[..]), "{name}");
    }
}

#[test]
fn lists_add_main_and_entry_as_functions() {
    for (name, add, main) in
        [("hello-x64.elf", "add", "main"), ("hello-x64.exe", "add", "entry"), ("hello-x64.macho", "_add", "_main")]
    {
        let binary = open(name);
        let found = functions::from_symbols(&binary);
        let names: Vec<_> = found.iter().map(|function| function.name.as_str()).collect();
        assert!(names.contains(&add) && names.contains(&main), "{name}: {names:?}");
        assert!(found.windows(2).all(|pair| pair[0].address < pair[1].address), "{name}: not sorted or duplicated");
        assert!(found.iter().any(|function| Some(function.address) == binary.entry), "{name}: entry missing");
    }
}

fn symbol_address(binary: &Binary, name: &str) -> u64 {
    binary.symbol_by_name(name).unwrap_or_else(|| panic!("no symbol {name}")).address
}

#[test]
fn analysis_finds_calls_from_main_in_static_elf() {
    let binary = open("hello-x64.elf");
    let program = functions::analyze(&binary).unwrap();
    let main = program.function_at(symbol_address(&binary, "main")).expect("main analyzed");
    assert!(main.instruction_count >= 3);
    let puts = symbol_address(&binary, "puts");
    let calls_to_puts = program.xrefs_to(puts);
    assert!(calls_to_puts.iter().any(|xref| main.contains(xref.from)), "{calls_to_puts:?}");
}

#[test]
fn analysis_of_entry_alone_reaches_main_through_code_pointer() {
    let binary = open("hello-x64.elf");
    let entry = binary.entry.unwrap();
    let program =
        rampage_analysis::discover::discover(&binary, || rampage_arch::decoder_for(binary.arch).unwrap(), &[entry]);
    assert!(program.function_at(symbol_address(&binary, "main")).is_some());
}

#[test]
fn analysis_of_stripped_macho_finds_add() {
    let add = symbol_address(&open("hello-x64.macho"), "_add");
    let stripped = open("hello-x64-stripped.macho");
    let program = functions::analyze(&stripped).unwrap();
    assert!(program.function_at(add).is_some());
    assert_eq!(functions::Names::new(&stripped).function_name(add), format!("sub_{add:x}"));
}

#[test]
fn analysis_is_identical_across_thread_counts() {
    let binary = open("hello-x64.elf");
    let analyze_with = |threads| {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
        pool.install(|| functions::analyze(&binary).unwrap())
    };
    let single = analyze_with(1);
    assert!(single.functions.len() >= functions::from_symbols(&binary).len());
    assert_eq!(single, analyze_with(8));
}

#[test]
fn analysis_of_arm64_is_unsupported() {
    assert!(functions::analyze(&open("hello-arm64.macho")).is_err());
}

#[test]
fn names_prefer_symbols_and_fall_back_to_sub() {
    let binary = open("hello-x64.elf");
    let names = functions::Names::new(&binary);
    assert_eq!(names.function_name(symbol_address(&binary, "main")), "main");
    assert_eq!(names.function_name(0x1234), "sub_1234");
}
