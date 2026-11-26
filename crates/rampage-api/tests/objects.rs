//! Relocatable objects and static-archive members as projects (tests/fixtures/build-objects.sh): calls to externs
//! and local functions, data references through relocations, strings, decompiled C that names its callees, and
//! one project per archive member.

use std::path::{Path, PathBuf};

use rampage_analysis::discover::XrefKind;
use rampage_api::{Project, Session, StringsQuery, XrefQuery};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/objects/");

const OBJECTS: [&str; 11] = [
    "objects-x86_64.o",
    "objects-x86_64-pic.o",
    "objects-x86.o",
    "objects-aarch64.o",
    "objects-aarch64-pic.o",
    "objects-arm.o",
    "objects-thumb.o",
    "objects-mipsel.o",
    "objects-mipsel-pic.o",
    "objects-riscv64.o",
    "objects-riscv64-pic.o",
];

fn project(name: &str) -> Project {
    Project::new(rampage_loaders::Binary::open(format!("{DIR}{name}")).unwrap())
}

fn address(project: &Project, name: &str) -> u64 {
    project.binary.symbol_by_name(name).unwrap_or_else(|| panic!("no {name}")).address
}

#[test]
fn main_calls_externs_and_local_functions_by_name() {
    for name in OBJECTS {
        let project = project(name);
        let main = address(&project, "main");
        let xrefs = project.xrefs(XrefQuery::From(main), None, Some(500)).unwrap().items;
        // A tail call to strlen is a jump; everything else a call.
        let reached = |callee: &str| {
            let target = address(&project, callee);
            xrefs.iter().any(|xref| xref.to == target && matches!(xref.kind, XrefKind::Call | XrefKind::Jump))
        };
        for callee in ["hal_init", "printf", "strlen", "sum", "dispatch"] {
            assert!(reached(callee), "{name}: main does not reach {callee}: {xrefs:#?}");
        }
        // The reference carries the relocation the object records for it (on MIPS PIC, the `%call16` GOT load).
        assert!(
            xrefs
                .iter()
                .any(|xref| xref.relocation.as_ref().is_some_and(|site| site.symbol.as_deref() == Some("printf"))),
            "{name}: no relocation evidence for printf"
        );
        // Functions are discovered from their symbols, with sizes.
        let functions = project.functions(&Default::default()).unwrap().items;
        for function in ["sum", "scale", "twice", "thrice", "dispatch", "main"] {
            assert!(functions.iter().any(|row| row.name == function), "{name}: {function} not listed");
        }
    }
}

#[test]
fn data_references_through_relocations_reach_globals_and_strings() {
    for name in ["objects-x86_64.o", "objects-aarch64.o", "objects-mipsel.o", "objects-riscv64.o", "objects-thumb.o"] {
        let project = project(name);
        let greeting = address(&project, "greeting");
        let xrefs = project.xrefs(XrefQuery::To(greeting), None, Some(50)).unwrap().items;
        assert!(
            xrefs.iter().any(|xref| xref.from_function.as_deref() == Some("main")),
            "{name}: main does not read greeting: {xrefs:#?}"
        );
        // `greeting` points at its string once relocated.
        let width = project.binary.arch.default_pointer_size().unwrap();
        let pointer = project.binary.read_pointer(greeting, width);
        let pointer = pointer.or_else(|| {
            let bytes = project.binary.read(greeting, u64::from(width))?;
            Some(if width == 8 {
                u64::from_le_bytes(bytes.try_into().ok()?)
            } else {
                u64::from(u32::from_le_bytes(bytes.try_into().ok()?))
            })
        });
        let text = project.binary.read(pointer.unwrap(), 12).unwrap();
        assert_eq!(text, b"hello object", "{name}");
        let strings = project.strings(&StringsQuery { contains: Some("hello object".into()), ..Default::default() });
        assert_eq!(strings.items.len(), 1, "{name}");
    }
}

#[test]
fn decompiled_c_names_externs_and_follows_tail_calls_into_them() {
    for name in OBJECTS {
        let project = project(name);
        let main = project.decompile(address(&project, "main")).unwrap_or_else(|error| panic!("{name}: {error}"));
        for callee in ["hal_init(", "printf(", "strlen(", "sum("] {
            assert!(main.code.contains(callee), "{name}: no {callee} in\n{}", main.code);
        }
        let scale = project.decompile(address(&project, "scale")).unwrap();
        assert!(scale.code.contains("ext_counter"), "{name}: {}", scale.code);
    }
}

fn member(archive: &str, selector: &str) -> PathBuf {
    PathBuf::from(format!("{DIR}{archive}({selector})"))
}

#[test]
fn archive_members_are_projects_of_their_own() {
    let session = Session::default().with_analysis_store(None);
    let first = session.open(&member("libobjects-gnu.a", "objects.o#0"), None).unwrap();
    let again = session.open(&member("libobjects-gnu.a", "#0"), None).unwrap();
    let second = session.open(&member("libobjects-gnu.a", "objects.o#2"), None).unwrap();
    let helper = session.open(&member("libobjects-gnu.a", "helper.o"), None).unwrap();
    assert!(std::sync::Arc::ptr_eq(&first, &again), "one member, two spellings, one project");
    assert!(!std::sync::Arc::ptr_eq(&first, &second));
    assert_eq!(helper.summary().archive_member.unwrap().name, "helper.o");
    assert!(helper.binary.symbol_by_name("hal_init").is_some());
    let Err(error) = session.open(Path::new(&format!("{DIR}libobjects-gnu.a")), None) else {
        panic!("a whole archive")
    };
    let mut text = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        text.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    let error = text;
    assert!(error.contains("objects.o#0"), "{error}");

    let page = rampage_api::static_archive_inventory(
        Path::new(&format!("{DIR}libobjects-bsd.a")),
        &rampage_api::ArchiveQuery { contains: Some("hal_init".into()), ..Default::default() },
    )
    .unwrap();
    assert_eq!((page.kind, page.members_total, page.matched), ("bsd", 2, 1));
    assert_eq!(page.members[0].member.name, "helper.o");
    assert!(page.members[0].open.ends_with("libobjects-bsd.a(helper.o)"));
    assert_eq!(page.members[0].format, "elf relocatable x86_64");
    // The row's path opens the member.
    let opened = session.open(Path::new(&page.members[0].open), None).unwrap();
    assert!(opened.binary.symbol_by_name("ext_counter").is_some());
}
