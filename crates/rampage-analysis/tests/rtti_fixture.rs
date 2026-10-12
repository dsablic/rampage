//! Checks RTTI class recovery against a committed, stripped Mach-O arm64 fixture built from
//! `tests/fixtures/src/classes.cpp`. The binary carries no vtable or typeinfo symbols, so recovery relies
//! entirely on the Itanium RTTI structures in its data.

use std::path::PathBuf;

use rampage_analysis::classes;
use rampage_loaders::Binary;

fn fixture() -> Binary {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/classes-arm64.macho");
    Binary::open(path).unwrap()
}

#[test]
fn recovers_class_names_and_base_edges_from_stripped_rtti() {
    let binary = fixture();
    // The fixture is stripped: no named vtable symbols feed the symbol-driven path.
    let recovery = classes::recover(&binary);
    assert!(recovery.classes.is_empty(), "expected no symbol-derived classes, got {:?}", recovery.classes);

    let find = |name: &str| {
        recovery.rtti_classes.iter().find(|class| class.name == name).unwrap_or_else(|| {
            panic!("missing {name}; got {:?}", recovery.rtti_classes.iter().map(|c| &c.name).collect::<Vec<_>>())
        })
    };
    assert_eq!(recovery.rtti_classes.len(), 4, "{:?}", recovery.rtti_classes);
    assert!(find("Shape").bases.is_empty());
    assert!(find("Printable").bases.is_empty());
    assert_eq!(find("Circle").bases, ["Shape"]);
    let mut square_bases = find("Square").bases.clone();
    square_bases.sort();
    assert_eq!(square_bases, ["Printable", "Shape"]);
    assert!(recovery.rtti_classes.iter().all(|class| class.abi == "itanium"));
}
