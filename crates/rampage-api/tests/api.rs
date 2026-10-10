use std::path::PathBuf;
use std::sync::Arc;

use rampage_api::{ApiError, FunctionsQuery, Session, StringsQuery, XrefQuery};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

#[test]
fn session_reuses_loaded_projects() {
    let session = Session::default();
    let first = session.open(&fixture("hello-x64.elf"), None).unwrap();
    let second = session.open(&fixture("../bin/hello-x64.elf"), None).unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    let other_slice = session.open(&fixture("hello-universal.macho"), Some(rampage_arch::Arch::Aarch64)).unwrap();
    assert!(!Arc::ptr_eq(&first, &other_slice));
}

#[test]
fn functions_are_paginated_and_filterable() {
    let project = Session::default().open(&fixture("hello-x64.elf"), None).unwrap();
    let all = project.functions(&FunctionsQuery::default()).unwrap();
    assert_eq!(all.items.len(), all.total);
    let page = project.functions(&FunctionsQuery { offset: Some(2), limit: Some(3), ..Default::default() }).unwrap();
    assert_eq!(page.total, all.total);
    assert_eq!(page.offset, 2);
    let addresses = |rows: &[rampage_api::FunctionRow]| rows.iter().map(|row| row.address).collect::<Vec<_>>();
    assert_eq!(addresses(&page.items), addresses(&all.items[2..5]));
    let past_end = project.functions(&FunctionsQuery { offset: Some(usize::MAX), ..Default::default() }).unwrap();
    assert!(past_end.items.is_empty());

    let mains =
        project.functions(&FunctionsQuery { name_contains: Some("MAIN".into()), ..Default::default() }).unwrap();
    assert!(mains.items.iter().any(|row| row.name == "main"));
    assert!(mains.items.iter().all(|row| row.name.to_lowercase().contains("main")));
}

#[test]
fn strings_filter_by_text() {
    let project = Session::default().open(&fixture("hello-x64.exe"), None).unwrap();
    let found = project.strings(&StringsQuery { contains: Some("FIXTURE".into()), ..Default::default() });
    assert_eq!(found.total, 1);
    assert_eq!(found.items[0].text, "rampage fixture greeting");
}

#[test]
fn function_containing_maps_instructions_to_their_function() {
    let project = Session::default().open(&fixture("hello-x64.elf"), None).unwrap();
    let main = project.resolve("main").unwrap();
    assert_eq!(project.function_containing(main).unwrap(), Some(main));
    assert_eq!(project.function_containing(main + 4).unwrap(), Some(main));
    assert_eq!(project.function_containing(0).unwrap(), None);
}

#[test]
fn xrefs_name_their_endpoints() {
    let project = Session::default().open(&fixture("hello-x64.elf"), None).unwrap();
    let rows = project.xrefs(&XrefQuery::To(project.resolve("puts").unwrap())).unwrap();
    assert!(
        rows.iter().any(|row| row.from_function.as_deref() == Some("main") && row.to_name.as_deref() == Some("puts"))
    );
}

#[test]
fn resolve_reports_unknown_names() {
    let project = Session::default().open(&fixture("hello-x64.elf"), None).unwrap();
    assert_eq!(project.resolve("0x10").unwrap(), 0x10);
    assert_eq!(project.resolve("16").unwrap(), 16);
    assert_eq!(project.resolve("sub_abc").unwrap(), 0xabc);
    assert!(matches!(project.resolve("nope"), Err(ApiError::NotFound(_))));
    assert!(matches!(project.resolve("0xzz"), Err(ApiError::Invalid(_))));
}

#[test]
fn disassembly_labels_known_names() {
    let project = Session::default().open(&fixture("hello-x64.elf"), None).unwrap();
    let lines = project.disassemble(Some("main"), 2).unwrap();
    assert_eq!(lines[0].label.as_deref(), Some("main"));
    assert_eq!(lines[1].label, None);
}

#[test]
fn arm64_binaries_are_analyzed() {
    let project = Session::default().open(&fixture("hello-arm64.macho"), None).unwrap();
    let functions = project.functions(&FunctionsQuery::default()).unwrap();
    assert!(functions.items.iter().any(|function| function.name == "_main"), "{:?}", functions.items);
    let lines = project.disassemble(Some("_main"), 2).unwrap();
    assert_eq!(lines[0].text, "stp x29, x30, [sp, #-16]!");
    assert_eq!(lines[1].text, "mov x29, sp");
}

#[test]
fn disassembly_comments_name_targets_and_strings() {
    let project = Session::default().open(&fixture("hello-arm64.macho"), None).unwrap();
    let lines = project.disassemble(Some("_main"), 5).unwrap();
    let comments: Vec<_> = lines.iter().filter_map(|line| line.comment.as_deref()).collect();
    assert_eq!(comments, ["\"rampage fixture greeting\"", "_puts"]);

    // x86-64 ELF passes the string as a 32-bit immediate.
    let project = Session::default().open(&fixture("hello-x64.elf"), None).unwrap();
    let lines = project.disassemble(Some("main"), 4).unwrap();
    assert!(lines.iter().any(|line| line.comment.as_deref() == Some("\"rampage fixture greeting\"")), "{lines:?}");
}

#[test]
fn names_do_not_depend_on_whether_analysis_has_run() {
    let label = |project: &rampage_api::Project| project.disassemble(Some("0x140028d60"), 1).unwrap()[0].label.clone();
    let project = Session::default().open(&fixture("hello-x64.exe"), None).unwrap();
    let before = label(&project);
    project.functions(&FunctionsQuery::default()).unwrap();
    assert_eq!(before.as_deref(), Some("puts"));
    assert_eq!(label(&project), before);
}

#[test]
fn bare_import_names_resolve_to_elf_plt_stubs() {
    let project = Session::default().open(&fixture("hello-x64-dyn.elf"), None).unwrap();
    let stub = project.resolve("puts").unwrap();
    let rows = project.xrefs(&XrefQuery::To(stub)).unwrap();
    assert!(rows.iter().any(|row| row.to_name.as_deref() == Some("puts@plt")), "{rows:?}");
}
