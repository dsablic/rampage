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
    for (name, add, main) in [
        ("hello-x64.elf", "add", "main"),
        ("hello-x64.exe", "add", "entry"),
        ("hello-x64.macho", "_add", "_main"),
    ] {
        let binary = open(name);
        let found = functions::from_symbols(&binary);
        let names: Vec<_> = found.iter().map(|function| function.name.as_str()).collect();
        assert!(names.contains(&add) && names.contains(&main), "{name}: {names:?}");
        assert!(found.windows(2).all(|pair| pair[0].address < pair[1].address), "{name}: not sorted or duplicated");
        assert!(found.iter().any(|function| function.address == binary.entry), "{name}: entry missing");
    }
}
