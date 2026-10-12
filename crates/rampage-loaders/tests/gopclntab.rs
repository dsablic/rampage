use std::path::PathBuf;

use rampage_loaders::{Binary, SymbolKind};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

#[test]
fn recovers_function_names_from_a_stripped_go_binary() {
    let mut binary = Binary::open(fixture("hello-go-x64.elf")).unwrap();
    // The fixture is built with `-ldflags "-s -w"`, so there is no real symbol table to fall back on.
    assert!(binary.symbols.is_empty(), "fixture should be stripped of real symbols");

    let report = binary.recover_go_symbols();
    assert!(report.warnings.is_empty(), "unexpected warnings: {:?}", report.warnings);

    let find = |name: &str| report.functions.iter().find(|function| function.name == name);
    let main = find("main.main").expect("main.main recovered");
    let greet = find("main.greet").expect("main.greet recovered");
    assert!(main.address > 0x400000, "main.main at implausible address {:#x}", main.address);
    assert!(greet.address > 0x400000, "main.greet at implausible address {:#x}", greet.address);
    assert_ne!(main.address, greet.address);

    // The recovered names are attached to the binary as Function symbols.
    let attached = |name: &str| {
        binary.symbols.iter().find(|symbol| symbol.name == name && symbol.kind == SymbolKind::Function)
    };
    let attached_main = attached("main.main").expect("main.main attached as a Function symbol");
    assert_eq!(attached_main.address, main.address);
    attached("main.greet").expect("main.greet attached as a Function symbol");

    // Recovery pulls in the wider Go runtime too, not just package main.
    assert!(report.functions.len() > 100, "expected many runtime functions, got {}", report.functions.len());
    assert!(report.functions.iter().any(|function| function.name.starts_with("runtime.")));
}

#[test]
fn recovers_function_names_from_a_stripped_arm64_go_binary() {
    let mut binary = Binary::open(fixture("hello-go-arm64.elf")).unwrap();
    let report = binary.recover_go_symbols();
    assert!(report.warnings.is_empty(), "unexpected warnings: {:?}", report.warnings);
    assert!(report.functions.iter().any(|function| function.name == "main.main"), "main.main recovered");
    assert!(report.functions.iter().any(|function| function.name == "main.greet"), "main.greet recovered");
}

#[test]
fn recovery_on_a_non_go_binary_is_a_clean_no_op() {
    let mut binary = Binary::open(fixture("hello-x64.elf")).unwrap();
    let before = binary.symbols.len();
    let report = binary.recover_go_symbols();
    assert!(report.functions.is_empty(), "a C binary has no gopclntab");
    assert_eq!(binary.symbols.len(), before, "recovery must not touch symbols when there is no table");
}
