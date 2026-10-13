use std::path::PathBuf;

use rampage_analysis::{diagnostics, functions::Names, language};
use rampage_loaders::{Binary, Section, SectionKind, Symbol, SymbolKind};

fn binary() -> Binary {
    Binary::open(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/runtime-arm64.snapshot.json"))
        .unwrap()
}

#[test]
fn demangled_names_keep_both_original_and_display_name_lookups() {
    let mut binary = binary();
    binary.symbols.push(Symbol {
        name: "_ZN3Foo3barEi".to_owned(),
        address: 0x1010,
        size: 4,
        kind: SymbolKind::Function,
    });
    let names = Names::new(&binary);
    assert_eq!(names.get(0x1010), Some("Foo::bar(int)"));
    assert_eq!(names.address_of("Foo::bar(int)"), Some(0x1010));
    assert_eq!(names.address_of("_ZN3Foo3barEi"), Some(0x1010));
    let metadata = language::metadata(&binary);
    assert_eq!(metadata.symbols[0].original, "_ZN3Foo3barEi");
}

#[test]
fn selectors_stop_at_bounded_valid_utf8_and_complete_terminators() {
    let mut binary = binary();
    binary.sections.push(Section {
        name: "__objc_methname".to_owned(),
        address: 0x3000,
        size: 8,
        kind: SectionKind::ReadOnlyData,
        file_offset: None,
        file_size: 8,
    });
    let metadata = language::metadata(&binary);
    assert_eq!(metadata.selectors.len(), 1);
    assert_eq!(metadata.selectors[0].address, 0x3000);
    assert!(metadata.limitations.iter().any(|text| text.contains("selectors")));
}

#[test]
fn diagnostics_report_sampled_bytes_without_claiming_they_are_source_code() {
    let audit = diagnostics::diagnostics(&binary());
    assert_eq!(audit.regions.len(), 1);
    assert_eq!(audit.regions[0].bytes_sampled, 20);
    assert!(audit.limitations.iter().any(|text| text.contains("not evidence")));
}

#[test]
fn duplicate_demangled_constructors_keep_unambiguous_original_names() {
    let mut binary = binary();
    for (address, name) in [(0x1000, "_ZN1AC1Ev"), (0x1010, "_ZN1AC2Ev")] {
        binary.symbols.push(Symbol { name: name.to_owned(), address, size: 4, kind: SymbolKind::Function });
    }
    let names = Names::new(&binary);
    assert_eq!(names.get(0x1010), Some("_ZN1AC2Ev"));
    assert_eq!(names.address_of("A::A()"), None);
}

#[test]
fn demangled_aliases_never_shadow_original_symbol_names() {
    let mut binary = binary();
    for (address, name) in [(0x1000, "_Z3foov"), (0x1010, "foo()")] {
        binary.symbols.push(Symbol { name: name.to_owned(), address, size: 4, kind: SymbolKind::Function });
    }
    let names = Names::new(&binary);
    assert_eq!(names.address_of("foo()"), Some(0x1010));
    assert_eq!(names.get(0x1000), Some("_Z3foov"));
}

#[test]
fn diagnostics_fall_back_to_executable_segments_without_sections() {
    let mut binary = binary();
    binary.sections.clear();
    assert!(!diagnostics::diagnostics(&binary).regions.is_empty());
}

#[test]
fn named_itanium_vtables_follow_only_captured_code_pointers() {
    let mut binary =
        Binary::open(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/metadata.snapshot.json"))
            .unwrap();
    binary.symbols.push(Symbol { name: "_ZTV3Foo".to_owned(), address: 0x3000, size: 24, kind: SymbolKind::Data });
    let metadata = language::metadata(&binary);
    assert_eq!(metadata.symbols[0].category, "vtable");
    assert_eq!(metadata.symbols[0].vtable_targets, [0x1000]);
}

#[test]
fn objective_c_classes_and_metadata_derived_method_names_reach_language_metadata_and_names() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/objc-arm64-stripped.macho");
    let binary = Binary::open(path).unwrap();
    let metadata = language::metadata(&binary);
    let dog = metadata.objc.classes.iter().find(|class| class.name == "Dog").unwrap();
    assert_eq!(dog.superclasses, ["Animal", "NSObject"]);
    let fetch = dog.methods.iter().find(|method| method.selector == "fetch:").unwrap();
    let names = Names::new(&binary);
    assert_eq!(names.get(fetch.implementation.unwrap()), Some("-[Dog fetch:]"));
    assert!(names.address_of("-[Dog(Tricks) rollOver]").is_some());
    assert_eq!(metadata.objc.categories[1].class.as_deref(), Some("NSString"));
}
