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

/// A conditional jump to an extern (a conditional sibling call: x86 `jne`, ARM `bne`) decompiles as a call to it.
#[test]
fn conditional_sibling_calls_to_externs_decompile_as_calls() {
    for name in ["objects-sibcall-x86_64.o", "objects-sibcall-arm.o"] {
        let project = project(name);
        let decompiled =
            project.decompile(address(&project, "sibling")).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(decompiled.code.contains("ext_a()"), "{name}:\n{}", decompiled.code);
        assert!(decompiled.code.contains("return 1;"), "{name}:\n{}", decompiled.code);
    }
}

/// Relocation evidence belongs to the instruction relocated: the `cbz` after a `bl ext_a` has none of its own.
#[test]
fn relocation_evidence_is_not_borrowed_from_a_neighbouring_instruction() {
    let aarch64 = project("objects-call-cbz-aarch64.o");
    let xrefs = aarch64.xrefs(XrefQuery::From(address(&aarch64, "sibling")), None, None).unwrap().items;
    let call = xrefs.iter().find(|xref| xref.kind == XrefKind::Call).unwrap();
    assert_eq!(call.relocation.as_ref().map(|site| site.kind.as_str()), Some("R_AARCH64_CALL26"));
    let branch = xrefs.iter().find(|xref| xref.kind == XrefKind::Jump).unwrap();
    assert!(branch.relocation.is_none(), "{branch:?}");
    // A RISC-V `call` is relocated at its `auipc`; the reference recorded at the `jalr` carries that relocation.
    let riscv = project("objects-riscv64.o");
    let main = address(&riscv, "main");
    let xrefs = riscv.xrefs(XrefQuery::From(main), None, Some(500)).unwrap().items;
    let printf = xrefs.iter().find(|xref| xref.to_name.as_deref() == Some("printf")).unwrap();
    assert_eq!(printf.relocation.as_ref().map(|site| site.kind.as_str()), Some("R_RISCV_CALL_PLT"));
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

/// A symbol's address under its plain or underscored (COFF i386, Mach-O) spelling.
fn either(project: &Project, name: &str) -> u64 {
    let binary = &project.binary;
    binary
        .symbol_by_name(name)
        .or_else(|| binary.symbol_by_name(&format!("_{name}")))
        .unwrap_or_else(|| panic!("no {name}"))
        .address
}

#[test]
fn coff_and_macho_objects_decompile_with_their_callees_named() {
    for name in [
        "objects-coff-x86_64.obj",
        "objects-coff-x86.obj",
        "objects-coff-aarch64.obj",
        "objects-coff-thumb.obj",
        "objects-macho-x86_64.o",
        "objects-macho-arm64.o",
    ] {
        let project = project(name);
        let main = project.decompile(either(&project, "main")).unwrap_or_else(|error| panic!("{name}: {error}"));
        for callee in ["hal_init(", "printf(", "sum("] {
            assert!(main.code.contains(callee), "{name}: no {callee} in\n{}", main.code);
        }
        if name.contains("coff") {
            // A call through an import pointer is a call to the import.
            let imports = project.decompile(either(&project, "uses_imports")).unwrap();
            assert!(imports.code.contains("GetTickCount("), "{name}: {}", imports.code);
        }
    }
}

/// Signatures from a COFF `.lib` and a Mach-O universal library name their functions in programs linked against
/// them (lld-link; ld64.lld for the arm64 slice), and the relocation-exact patterns alone name the functions whose
/// fields the linker filled in.
#[test]
fn coff_and_macho_library_signatures_name_the_functions_of_linked_programs() {
    let cases: [(&str, Option<rampage_arch::Arch>, &str, &[&str]); 2] = [
        (
            "libobjects-coff.lib",
            None,
            "linked-coff-x86_64.exe",
            &[
                "dispatch",
                "hal_init",
                "main",
                "scale",
                "set_flags",
                "sum",
                "thrice",
                "twice",
                "uses_imports",
                "weak_hook",
            ],
        ),
        // `_twice`, `_thrice` and `_far_element` are under the hash gate's four instructions; `_bump`'s GOT load
        // is relaxed by the linker into an address computation no relocation names.
        (
            "libobjects-macho.a",
            Some(rampage_arch::Arch::Aarch64),
            "linked-macho-arm64",
            &["_dispatch", "_main", "_scale", "_sum"],
        ),
    ];
    for (library, arch, linked, expected) in cases {
        let built = rampage_api::build_library_signatures(&Path::new(DIR).join(library), arch, &|| false).unwrap();
        assert!(built.report.functions > 0 && built.report.pat_records > 0, "{library}: {:?}", built.report);
        let program = project(linked);
        let found = program.apply_signatures(&built.database, false).unwrap();
        let mut names: Vec<&str> = found.matches.iter().map(|item| item.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, expected, "{library}");

        // The patterns alone: a database with every hash entry taken out.
        let mut json: serde_json::Value = serde_json::from_str(&built.database.to_json()).unwrap();
        for key in ["exact", "ambiguous", "ambiguous_exact", "calls", "ambiguous_calls"] {
            json.as_object_mut().unwrap().remove(key);
        }
        json["entries"] = serde_json::json!({});
        let patterns = rampage_api::SignatureDb::from_json(&json.to_string()).unwrap();
        let found = program.apply_signatures(&patterns, false).unwrap();
        let named: Vec<&str> = found.matches.iter().map(|item| item.name.as_str()).collect();
        let relocated = if library.ends_with(".lib") { "uses_imports" } else { "_main" };
        assert!(named.contains(&relocated), "{library}: {named:?}");
        assert!(named.iter().all(|name| expected.contains(name)), "{library}: {named:?}");
    }
    // A single object builds signatures too, now that its functions have sizes.
    assert!(project("objects-coff-x86_64.obj").build_signatures().len() > 4);
    assert!(project("objects-macho-arm64.o").build_signatures().len() > 2);
}

/// Signatures built from a static library name its functions in a program linked against it, where the objects'
/// masked hashes alone miss the functions whose MIPS `%hi`/`%lo` pairs the linker filled in.
#[test]
fn library_signatures_name_the_functions_of_a_program_linked_against_the_library() {
    let library = Path::new(DIR).join("libobjects-mipsel.a");
    let built = rampage_api::build_library_signatures(&library, None, &|| false).unwrap();
    assert_eq!((built.report.members, built.report.members_used), (2, 2));
    assert!(built.report.pat_records >= 6, "{:?}", built.report);
    let program = project("linked-mipsel");
    let found = program.apply_signatures(&built.database, false).unwrap();
    let mut names: Vec<&str> = found.matches.iter().map(|item| item.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["dispatch", "hal_init", "main", "scale", "sum", "thrice", "twice"]);
    // Each one is where the linker put it: the program's entry calls main.
    let entry = program.binary.entry.unwrap();
    let main = found.matches.iter().find(|item| item.name == "main").unwrap().address;
    let calls = program.xrefs(XrefQuery::From(entry), None, Some(50)).unwrap().items;
    assert!(calls.iter().any(|xref| xref.to == main), "{calls:?}");

    // The same objects' hashes, without the relocation-exact patterns, name only what has no relocations.
    let hashes = project("objects-mipsel.o").build_signatures();
    let only = program.apply_signatures(&hashes, false).unwrap();
    let mut hashed: Vec<&str> = only.matches.iter().map(|item| item.name.as_str()).collect();
    hashed.sort_unstable();
    assert_eq!(hashed, ["thrice", "twice"]);
    // Building is deterministic.
    let again = rampage_api::build_library_signatures(&library, None, &|| false).unwrap();
    assert_eq!(again.database.to_json(), built.database.to_json());
}

/// Members that are no object are skipped by their format, counted by why; a cancelled build writes nothing.
#[test]
fn library_signature_builds_skip_by_member_format_and_stop_when_cancelled() {
    let imports = rampage_api::build_library_signatures(&Path::new(DIR).join("imports-coff.lib"), None, &|| false);
    let error = imports.err().expect("an import library has no code").to_string();
    assert!(error.contains("short import object"), "{error}");
    let built = rampage_api::build_library_signatures(&Path::new(DIR).join("libobjects-coff.lib"), None, &|| false);
    assert!(built.unwrap().report.skipped.is_empty());
    let cancelled = rampage_api::build_library_signatures(&Path::new(DIR).join("libobjects-mipsel.a"), None, &|| true);
    assert!(cancelled.err().unwrap().to_string().contains("cancelled"));
}

/// An image offset at a universal library's member opens that member of its own slice.
#[test]
fn an_image_offset_in_a_universal_library_opens_the_member_of_that_slice() {
    let path = Path::new(DIR).join("libobjects-macho.a");
    let data = std::fs::read(&path).unwrap();
    let arm = rampage_loaders::ar::read_library(&data, Some(rampage_arch::Arch::Aarch64)).unwrap();
    let member = arm.archive.members.iter().find(|member| member.name == "objects.o").unwrap();
    let image = rampage_loaders::ImageAt::new(member.offset, None);
    let binary = rampage_loaders::Binary::open_image(&path, Some(image), None).unwrap();
    assert_eq!(binary.arch, rampage_arch::Arch::Aarch64);
    assert_eq!(binary.archive_member.as_ref(), Some(member));
}
