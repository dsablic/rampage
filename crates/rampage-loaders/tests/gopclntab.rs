use std::path::PathBuf;

use rampage_loaders::{Binary, SymbolKind};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

#[test]
fn recovers_function_names_from_a_stripped_go_binary() {
    // The fixture is built with `-ldflags "-s -w"`, so there is no real symbol table: every Function symbol
    // below is recovered from the pclntab, which `Binary::open` does automatically.
    let binary = Binary::open(fixture("hello-go-x64.elf")).unwrap();

    let attached = |name: &str| {
        binary.symbols.iter().find(|symbol| symbol.name == name && symbol.kind == SymbolKind::Function)
    };
    let main = attached("main.main").expect("main.main recovered at load");
    let greet = attached("main.greet").expect("main.greet recovered at load");
    assert!(main.address > 0x400000, "main.main at implausible address {:#x}", main.address);
    assert!(greet.address > 0x400000, "main.greet at implausible address {:#x}", greet.address);
    assert_ne!(main.address, greet.address);

    // Recovery pulls in the wider Go runtime too, not just package main.
    assert!(binary.symbols.len() > 100, "expected many recovered functions, got {}", binary.symbols.len());
    assert!(binary.symbols.iter().any(|symbol| symbol.name.starts_with("runtime.")));
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
