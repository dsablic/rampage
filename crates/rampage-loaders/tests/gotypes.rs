use std::path::PathBuf;

use rampage_loaders::Binary;
use rampage_loaders::gotypes::{GoModuleLayout, GoTypeRequest, go_type_index};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

/// The fixtures of tests/fixtures/src/gotypes, one per layout era, with their word size.
const FIXTURES: &[(&str, GoModuleLayout, u64)] = &[
    ("gotypes-go1.16-x86.elf", GoModuleLayout::Go116, 4),
    ("gotypes-go1.20-x64.elf", GoModuleLayout::Go120, 8),
    ("gotypes-go1.26-x86.elf", GoModuleLayout::Go126, 4),
    ("gotypes-go1.27-s390x.elf", GoModuleLayout::Go127, 8),
];

fn request(name: &str) -> GoTypeRequest {
    GoTypeRequest { name: name.into(), limit: 128, ..GoTypeRequest::default() }
}

#[test]
fn reads_struct_layouts_from_every_layout_era() {
    for &(name, layout, word) in FIXTURES {
        let binary = Binary::open(fixture(name)).unwrap();
        let index = go_type_index(&binary).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(index.stats().layout, Some(layout), "{name}");
        assert!(!index.stats().truncated && index.warnings().is_empty(), "{name}: {:?}", index.warnings());

        let lookup = index.lookup(binary.image_bytes(), &request("main.Record")).unwrap();
        assert_eq!((lookup.source, lookup.definitions.len(), lookup.ambiguous), ("go_runtime", 1, false), "{name}");
        let record = &lookup.definitions[0];
        assert_eq!((record.kind, record.named, record.package.as_deref()), ("struct", true, Some("main")), "{name}");
        let fields: Vec<(&str, u64, &str)> =
            record.members.iter().map(|m| (m.name.as_str(), m.offset, m.type_name.as_str())).collect();
        let (offsets, size): (&[u64], u64) = if word == 8 {
            (&[0, 32, 48, 56, 72, 80, 88, 96, 104, 112, 128], 144)
        } else {
            (&[0, 16, 24, 28, 44, 48, 52, 56, 60, 64, 72], 80)
        };
        let expected = [
            "Base:main.Base",
            "Name:string",
            "flags:uint16",
            "Inner:main.Inner",
            "Next:*main.Record",
            "Values:map[string]int32",
            "Buckets:[4]uint8",
            "Notify:chan<- int",
            "Hook:func(int, string) (bool, error)",
            "Any:interface {}",
            "Shape:main.Shape",
        ];
        let got: Vec<String> = fields.iter().map(|(field, _, ty)| format!("{field}:{ty}")).collect();
        assert_eq!(got, expected, "{name}");
        assert_eq!(fields.iter().map(|field| field.1).collect::<Vec<_>>(), offsets, "{name}");
        assert_eq!(record.byte_size, size, "{name}");
        assert!(record.members[0].embedded && !record.members[1].embedded, "{name}: Base is embedded");
        assert!(!record.members[2].exported && record.members[1].exported, "{name}: flags is unexported");

        // By-value members expand inline; promoted fields resolve through the embedded struct.
        let nested = index.lookup(binary.image_bytes(), &GoTypeRequest { depth: 1, ..request("main.Record") }).unwrap();
        let inner = &nested.definitions[0].members[3];
        assert_eq!(
            inner.members.iter().map(|m| (m.name.as_str(), m.offset)).collect::<Vec<_>>(),
            [("Count", 0), ("Ratio", 8)]
        );
        let path = |path: &str| {
            let request = GoTypeRequest { member: Some(path.into()), limit: 0, ..request("main.Record") };
            index.lookup(binary.image_bytes(), &request).unwrap().definitions[0].selection.clone().unwrap()
        };
        let ratio = path("Inner.Ratio");
        assert_eq!((ratio.offset, ratio.byte_size, ratio.type_name.as_str()), (offsets[3] + 8, 8, "float64"));
        assert_eq!(path("Tags").offset, word, "promoted through Base");
        assert_eq!(path("Buckets[3]").offset, offsets[6] + 3);

        let at = GoTypeRequest { byte_offset: Some(offsets[3] + 12), limit: 0, ..request("main.Record") };
        let selected = index.lookup(binary.image_bytes(), &at).unwrap().definitions[0].selection.clone().unwrap();
        assert_eq!((selected.path.as_str(), selected.within), ("Inner.Ratio", Some(4)), "{name}");
    }
}

#[test]
fn reads_interfaces_methods_maps_and_qualified_names() {
    for &(name, _, _) in FIXTURES {
        let binary = Binary::open(fixture(name)).unwrap();
        let index = go_type_index(&binary).unwrap();
        let lookup = |name: &str| index.lookup(binary.image_bytes(), &request(name)).unwrap();

        let shape = lookup("main.Shape");
        let methods: Vec<_> = shape.definitions[0]
            .methods
            .iter()
            .map(|method| format!("{} {}", method.name, method.type_name.as_deref().unwrap_or("?")))
            .collect();
        assert_eq!(methods, ["Area func() float64", "Name func() string"], "{name}");

        // A named map: key and element, and its method from the uncommon type that follows the map descriptor,
        // whose size differs between the hashmap, swiss-map and go1.27 layouts.
        let map = &lookup("main.Index").definitions[0];
        assert_eq!((map.kind, map.key.as_deref(), map.elem.as_deref()), ("map", Some("string"), Some("*main.Record")));
        assert_eq!(map.methods.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(), ["Len"], "{name}");

        // Pointer-receiver methods live on the pointer type; ones reached through an interface keep an address.
        let error = &lookup("*main.Error").definitions[0];
        assert_eq!((error.kind, error.elem.as_deref()), ("pointer", Some("main.Error")));
        assert_eq!(error.methods[0].name, "Error");
        let address = error.methods[0].address.expect("Error is called through the error interface");
        assert!(binary.is_code(address), "{name}: {address:#x}");

        // The package-path-qualified spelling finds the same named type, and only the named one.
        assert_eq!(lookup("main.Square").definitions.len(), 1);
        assert_eq!(lookup("main.Square").definitions[0].kind, "struct");

        let page = index.list(Some("main."), 0, 100);
        let names: Vec<_> = page.types.iter().map(|ty| ty.name.as_str()).collect();
        for expected in ["main.Base", "main.Index", "main.Inner", "main.Record", "main.Shape", "main.Square"] {
            assert!(names.contains(&expected), "{name}: {expected} not listed in {names:?}");
        }
        assert!(page.types.iter().all(|ty| !ty.name.starts_with('*')), "listing holds named types only");
    }
}

#[test]
fn a_lookup_does_bounded_work_independent_of_the_image() {
    // A lookup decodes the requested type and what its members name, not the index: the same request costs the
    // same on every fixture, and stays small.
    let mut costs = Vec::new();
    for &(name, _, _) in FIXTURES {
        let binary = Binary::open(fixture(name)).unwrap();
        let index = go_type_index(&binary).unwrap();
        assert!(index.stats().types > 250, "{name}: {}", index.stats().types);
        let lookup = index.lookup(binary.image_bytes(), &request("main.Record")).unwrap();
        costs.push(lookup.work.steps);
        let deep = GoTypeRequest { depth: 4, ..request("main.Record") };
        assert!(index.lookup(binary.image_bytes(), &deep).unwrap().work.steps < 400);
    }
    assert!(costs.iter().all(|&cost| cost == costs[0] && cost < 200), "{costs:?}");
}

#[test]
fn reads_the_other_go_fixtures_across_formats() {
    // ELF, Mach-O (arm64) and PE images of go1.27: `error` is an interface every Go program carries.
    for name in [
        "hello-go-x64.elf",
        "hello-go-arm64.elf",
        "buildinfo-go-arm64.macho",
        "buildinfo-go-x64.elf",
        "buildinfo-go-x64.exe",
    ] {
        let binary = Binary::open(fixture(name)).unwrap();
        let index = go_type_index(&binary).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(index.stats().types > 200, "{name}: {:?}", index.stats());
        let error = index.lookup(binary.image_bytes(), &request("error")).unwrap();
        let methods: Vec<_> = error.definitions[0].methods.iter().map(|method| method.name.as_str()).collect();
        assert_eq!((error.definitions[0].kind, methods), ("interface", vec!["Error"]), "{name}");
    }
}

#[test]
fn non_go_and_unknown_names_are_reported_not_fabricated() {
    let c = Binary::open(fixture("hello-x64.elf")).unwrap();
    assert!(go_type_index(&c).unwrap_err().contains("not a Go binary"));
    let binary = Binary::open(fixture("gotypes-go1.20-x64.elf")).unwrap();
    let index = go_type_index(&binary).unwrap();
    let missing = index.lookup(binary.image_bytes(), &request("main.Nope")).unwrap();
    assert!(missing.definitions.is_empty() && missing.matches == 0);
    assert!(index.suggestions("main.Recor").contains(&"main.Record".to_owned()));
    let both = GoTypeRequest { member: Some("Name".into()), byte_offset: Some(0), ..request("main.Record") };
    assert!(index.lookup(binary.image_bytes(), &both).is_err());
    let bad = GoTypeRequest { member: Some("Nope".into()), ..request("main.Record") };
    let lookup = index.lookup(binary.image_bytes(), &bad).unwrap();
    assert!(lookup.definitions.is_empty() && lookup.warnings[0].contains("no field \"Nope\""), "{:?}", lookup.warnings);
}
