use std::collections::BTreeSet;
use std::path::PathBuf;

use rampage_loaders::objc::{ObjcReport, parse};
use rampage_loaders::{Binary, Symbol, SymbolKind};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn method_names(report: &ObjcReport) -> BTreeSet<String> {
    let classes = report.classes.iter().flat_map(|class| &class.methods);
    classes.chain(report.categories.iter().flat_map(|category| &category.methods)).map(|m| m.name.clone()).collect()
}

fn class<'a>(report: &'a ObjcReport, name: &str) -> &'a rampage_loaders::objc::ObjcClass {
    report.classes.iter().find(|class| class.name == name).unwrap()
}

/// The fixture's file with `patch` applied to its bytes, given the file offset of an address, reopened.
fn patched(name: &str, tag: &str, patch: impl FnOnce(&Binary, &mut Vec<u8>)) -> Binary {
    let original = Binary::open(fixture(name)).unwrap();
    let mut bytes = std::fs::read(fixture(name)).unwrap();
    patch(&original, &mut bytes);
    let path = std::env::temp_dir().join(format!("rampage-objc-{tag}-{}.macho", std::process::id()));
    std::fs::write(&path, &bytes).unwrap();
    let binary = Binary::open(&path).unwrap();
    std::fs::remove_file(&path).ok();
    binary
}

fn offset(binary: &Binary, address: u64) -> usize {
    let segment = binary.segment_containing(address).unwrap();
    (segment.file_offset + address - segment.address) as usize
}

fn put(bytes: &mut [u8], at: usize, value: &[u8]) {
    bytes[at..at + value.len()].copy_from_slice(value);
}

/// A pointer field's loaded value: its chained rebase target, or the stored address of a classic image.
fn pointer(binary: &Binary, at: u64) -> u64 {
    binary.rebase_target(at).unwrap_or_else(|| u64::from_le_bytes(binary.read(at, 8).unwrap().try_into().unwrap()))
}

#[test]
fn classes_categories_and_members_are_recovered_and_match_the_compilers_symbols() {
    let binary = Binary::open(fixture("objc-arm64.macho")).unwrap();
    assert!(binary.has_chained_fixups());
    let report = parse(&binary);
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    let animal = class(&report, "Animal");
    assert_eq!(animal.superclass.as_deref(), Some("NSObject"));
    assert_eq!(animal.instance_size, 24);
    assert_eq!(animal.protocols, ["Named"]);
    let legs = animal.ivars.iter().find(|ivar| ivar.name == "_legs").unwrap();
    assert_eq!((legs.offset, legs.size, legs.type_encoding.as_deref()), (Some(8), 4, Some("i")));
    let property = animal.properties.iter().find(|property| property.name == "name").unwrap();
    assert_eq!(property.attributes.as_deref(), Some("T@\"NSString\",C,N,V_name"));
    let dog = class(&report, "Dog");
    assert_eq!(dog.superclasses, ["Animal", "NSObject"]);
    assert_eq!(dog.instance_size, 32);
    let population = dog.methods.iter().find(|method| method.selector == "population").unwrap();
    assert!(population.class_method);
    assert_eq!(population.name, "+[Dog population]");
    let categories: Vec<_> =
        report.categories.iter().map(|category| (category.class.as_deref(), category.name.as_str())).collect();
    assert_eq!(categories, [(Some("Dog"), "Tricks"), (Some("NSString"), "Shout")]);

    // Every method implementation carries the very name the compiler gave its local symbol.
    let symbols: BTreeSet<(u64, String)> = binary
        .symbols
        .iter()
        .filter(|symbol| symbol.name.starts_with("-[") || symbol.name.starts_with("+["))
        .map(|symbol| (symbol.address, symbol.name.clone()))
        .collect();
    let classes = report.classes.iter().flat_map(|class| &class.methods);
    let methods: BTreeSet<(u64, String)> = classes
        .chain(report.categories.iter().flat_map(|category| &category.methods))
        .map(|method| (method.implementation.unwrap(), method.name.clone()))
        .collect();
    assert_eq!(symbols.len(), 15);
    assert_eq!(methods, symbols);
}

#[test]
fn stripped_images_name_method_implementations_from_the_metadata() {
    let reference = Binary::open(fixture("objc-arm64.macho")).unwrap();
    let expected: BTreeSet<(u64, String)> = method_names(&parse(&reference))
        .into_iter()
        .map(|name| (reference.symbol_by_name(&name).unwrap().address, name))
        .collect();
    for (name, merged) in
        [("objc-arm64-stripped.macho", false), ("objc-arm64e-stripped.macho", false), ("objc-x64-stripped.macho", true)]
    {
        let binary = Binary::open(fixture(name)).unwrap();
        assert!(binary.warnings.is_empty(), "{name}: {:?}", binary.warnings);
        let names: BTreeSet<&str> = binary.symbols.iter().map(|symbol| symbol.name.as_str()).collect();
        for method in ["-[Dog fetch:]", "+[Dog population]", "+[Animal animalWithName:]", "-[NSString(Shout) shout]"] {
            assert!(names.contains(method), "{name} lacks {method}");
        }
        // The x86_64 link merges the local category into its class, so its methods are the class's own there.
        let roll_over = if merged { "-[Dog rollOver]" } else { "-[Dog(Tricks) rollOver]" };
        assert!(names.contains(roll_over), "{name} lacks {roll_over}");
        let recovered = binary.symbols.iter().filter(|symbol| symbol.name.contains('[')).count();
        assert_eq!(recovered, 15, "{name}");
        for symbol in binary.symbols.iter().filter(|symbol| symbol.name.contains('[')) {
            assert!(binary.is_code(symbol.address), "{name}: {} at {:#x}", symbol.name, symbol.address);
            assert_eq!(symbol.kind, SymbolKind::Function);
        }
    }
    // Stripping keeps the layout, so the arm64 copy names exactly the addresses the symbol table did.
    let stripped = Binary::open(fixture("objc-arm64-stripped.macho")).unwrap();
    let recovered: BTreeSet<(u64, String)> = stripped
        .symbols
        .iter()
        .filter(|symbol| symbol.name.contains('['))
        .map(|symbol| (symbol.address, symbol.name.clone()))
        .collect();
    assert_eq!(recovered, expected);
}

#[test]
fn metadata_names_never_replace_an_existing_symbol() {
    let mut binary = Binary::open(fixture("objc-arm64-stripped.macho")).unwrap();
    let fetch = binary.symbols.iter().find(|symbol| symbol.name == "-[Dog fetch:]").unwrap().address;
    binary.symbols.retain(|symbol| !symbol.name.contains('['));
    binary.symbols.push(Symbol {
        name: "analyst_name".to_owned(),
        address: fetch,
        size: 0,
        kind: SymbolKind::Function,
    });
    binary.recover_objc_symbols();
    let at_fetch: Vec<&str> =
        binary.symbols.iter().filter(|symbol| symbol.address == fetch).map(|symbol| symbol.name.as_str()).collect();
    assert_eq!(at_fetch, ["analyst_name"]);
    assert!(binary.symbols.iter().any(|symbol| symbol.name == "-[Dog speak]"));
}

#[test]
fn a_method_count_past_the_image_skips_only_that_list() {
    let binary = patched("objc-arm64-stripped.macho", "count", |original, bytes| {
        let dog = class(&parse(original), "Dog").address;
        let ro = pointer(original, dog + 32) & !7;
        let methods = pointer(original, ro + 32);
        put(bytes, offset(original, methods + 4), &0xffff_fff0u32.to_le_bytes());
    });
    let report = parse(&binary);
    assert!(report.warnings.iter().any(|warning| warning.contains("claims 4294967280 entries")), "{report:?}");
    let names = method_names(&report);
    assert!(!names.contains("-[Dog fetch:]"));
    assert!(names.contains("+[Dog population]"));
    assert!(names.contains("-[Animal speak]"));
}

#[test]
fn a_superclass_cycle_stops_the_chain_walk() {
    let binary = patched("objc-x64-stripped.macho", "cycle", |original, bytes| {
        let dog = class(&parse(original), "Dog").address;
        put(bytes, offset(original, dog + 8), &dog.to_le_bytes());
    });
    let report = parse(&binary);
    let dog = class(&report, "Dog");
    assert_eq!(dog.superclass.as_deref(), Some("Dog"));
    assert!(dog.superclasses.is_empty());
    assert!(report.warnings.iter().any(|warning| warning.contains("loops back")), "{:?}", report.warnings);
}

#[test]
fn pointers_outside_the_image_or_code_are_skipped_with_warnings() {
    let binary = patched("objc-x64-stripped.macho", "outside", |original, bytes| {
        let report = parse(original);
        let animal = class(&report, "Animal").address;
        put(bytes, offset(original, animal + 32), &0x4141_4141_4140u64.to_le_bytes());
        // An absolute method list entry's implementation, sent to data.
        let dog = class(&report, "Dog").address;
        let ro = pointer(original, dog + 32);
        let methods = pointer(original, ro + 32);
        put(bytes, offset(original, methods + 8 + 16), &ro.to_le_bytes());
    });
    let report = parse(&binary);
    assert!(report.classes.iter().all(|class| class.name != "Animal"));
    let dog = class(&report, "Dog");
    assert_eq!(dog.superclass, None);
    assert!(dog.methods.iter().any(|method| method.implementation.is_none()));
    let warnings = report.warnings.join("\n");
    assert!(warnings.contains("class_ro_t outside the image"), "{warnings}");
    assert!(warnings.contains("does not point into code"), "{warnings}");
}

#[test]
fn a_misaligned_list_is_skipped() {
    let binary = patched("objc-x64-stripped.macho", "misaligned", |original, bytes| {
        let dog = class(&parse(original), "Dog").address;
        let ro = pointer(original, dog + 32);
        let methods = pointer(original, ro + 32);
        put(bytes, offset(original, ro + 32), &(methods + 2).to_le_bytes());
    });
    let report = parse(&binary);
    assert!(report.warnings.iter().any(|warning| warning.contains("misaligned")), "{:?}", report.warnings);
    assert!(!method_names(&report).contains("-[Dog fetch:]"));
}

#[test]
fn corrupted_metadata_never_panics() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for name in ["objc-arm64-stripped.macho", "objc-x64-stripped.macho"] {
        let original = Binary::open(fixture(name)).unwrap();
        let ranges: Vec<(usize, usize)> = original
            .sections
            .iter()
            .filter(|section| section.name.starts_with("__objc_") && section.file_size > 0)
            .map(|section| (section.file_offset.unwrap() as usize, section.file_size as usize))
            .collect();
        let pristine = std::fs::read(fixture(name)).unwrap();
        let path = std::env::temp_dir().join(format!("rampage-objc-fuzz-{}.macho", std::process::id()));
        for _ in 0..150 {
            let mut bytes = pristine.clone();
            for _ in 0..1 + next() % 16 {
                let (start, len) = ranges[(next() % ranges.len() as u64) as usize];
                bytes[start + (next() % len as u64) as usize] = next() as u8;
            }
            std::fs::write(&path, &bytes).unwrap();
            if let Ok(binary) = Binary::open(&path) {
                let _ = parse(&binary);
            }
        }
        std::fs::remove_file(&path).ok();
    }
}
