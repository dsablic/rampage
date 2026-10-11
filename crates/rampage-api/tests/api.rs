use std::path::PathBuf;
use std::sync::Arc;

use rampage_api::{ApiError, EdgeKind, FunctionsQuery, Session, StringsQuery, XrefQuery};

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
    let rows = project.xrefs(XrefQuery::To(project.resolve("puts").unwrap()), None, None).unwrap().items;
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
    let rows = project.xrefs(XrefQuery::To(stub), None, None).unwrap().items;
    assert!(rows.iter().any(|row| row.to_name.as_deref() == Some("puts@plt")), "{rows:?}");
}

#[test]
fn function_listing_groups_instructions_by_block() {
    let project = Session::default().open(&fixture("hello-arm64.macho"), None).unwrap();
    let main = project.resolve("_main").unwrap();
    let listing = project.function_listing(main + 8).unwrap();
    assert_eq!(listing.address, main);
    assert_eq!(listing.name, "_main");
    let lines: Vec<_> = listing.blocks.iter().flatten().collect();
    assert_eq!(lines.first().unwrap().address, main);
    assert_eq!(lines.last().unwrap().text, "ret");
    assert!(project.function_listing(0).is_err());
}

#[test]
fn imports_with_the_same_name_keep_their_own_slots() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/malformed/dup.exe");
    let project = Session::default().open(&path, None).unwrap();
    let query = rampage_api::ListQuery { contains: Some("free".into()), ..Default::default() };
    let slots: Vec<_> = project.imports(&query).items.iter().filter(|i| i.name == "free").map(|i| i.slot).collect();
    assert_eq!(slots.len(), 2);
    assert_ne!(slots[0], slots[1]);
}

/// A copy of a fixture in a fresh temporary directory, so edits write their log there.
fn scratch_copy(name: &str, test: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("rampage-api-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(name);
    std::fs::copy(fixture(name), &path).unwrap();
    path
}

#[test]
fn renames_and_comments_show_everywhere_and_persist() {
    let path = scratch_copy("hello-arm64.macho", "annotate");
    let project = Session::default().open(&path, None).unwrap();
    let main = project.resolve("_main").unwrap();
    assert!(project.rename(main, Some("entry_logic")).unwrap().changed);
    assert!(project.comment(main + 0xc, Some("greeting pointer")).unwrap().changed);

    assert_eq!(project.resolve("entry_logic").unwrap(), main);
    let functions = project.functions(&FunctionsQuery::default()).unwrap();
    assert!(functions.items.iter().any(|function| function.name == "entry_logic"));
    let lines = project.disassemble(Some("entry_logic"), 4).unwrap();
    assert_eq!(lines[0].label.as_deref(), Some("entry_logic"));
    assert_eq!(lines[3].note.as_deref(), Some("greeting pointer"));
    let calls = project.xrefs(XrefQuery::From(main), None, None).unwrap().items;
    assert!(calls.iter().all(|row| row.from_function.as_deref() == Some("entry_logic")));

    // Names stay unique identifiers.
    assert!(project.rename(main, Some("has space")).is_err());
    assert!(project.rename(main, Some("_puts")).is_err());
    assert!(project.rename(main, Some("sub_1234")).is_err());

    // Undo and redo, then a fresh session replays the log.
    project.undo().unwrap();
    assert_eq!(project.comment_at(main + 0xc), None);
    project.redo().unwrap();
    let reopened = Session::default().open(&path, None).unwrap();
    assert_eq!(reopened.function_name(main), "entry_logic");
    assert_eq!(reopened.comment_at(main + 0xc).as_deref(), Some("greeting pointer"));
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn a_slice_opens_once_however_it_is_asked_for() {
    let path = scratch_copy("hello-universal.macho", "session");
    let session = Session::default();
    let default = session.open(&path, None).unwrap();
    let explicit = session.open(&path, Some(default.binary.arch)).unwrap();
    assert!(std::sync::Arc::ptr_eq(&default, &explicit));
    let other = default.binary.slices.iter().copied().find(|&arch| arch != default.binary.arch).unwrap();
    assert!(!std::sync::Arc::ptr_eq(&default, &session.open(&path, Some(other)).unwrap()));
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn function_graphs_connect_blocks_by_their_branches() {
    let project = Session::default().open(&fixture("hello-x64.elf"), None).unwrap();
    let functions = project.functions(&FunctionsQuery::default()).unwrap().items;
    let largest = functions.iter().max_by_key(|function| function.blocks).unwrap();
    let graph = project.function_graph(largest.address).unwrap();
    assert_eq!(graph.blocks.len(), largest.blocks);
    assert!(graph.entry().is_some());
    assert!(graph.edges.iter().all(|edge| edge.from < graph.blocks.len() && edge.to < graph.blocks.len()));
    // Every conditional branch has both of its edges.
    for (index, block) in graph.blocks.iter().enumerate() {
        if matches!(block.lines.last().unwrap().flow, rampage_arch::Flow::ConditionalJump(_)) {
            let kinds: Vec<_> = graph.edges.iter().filter(|edge| edge.from == index).map(|edge| edge.kind).collect();
            assert!(kinds.contains(&EdgeKind::Taken) && kinds.contains(&EdgeKind::NotTaken), "block {index}");
        }
    }
}

#[test]
fn decompiles_a_function_to_c_when_ghidra_is_present() {
    // The decompiler needs a local Ghidra install for processor specs; skip cleanly without one.
    if rampage_decompiler::sleigh_home().is_none() {
        return;
    }
    let session = Session::default();
    let project = session.open(&fixture("hello-x64.elf"), None).unwrap();
    let address = project.resolve("add").unwrap();
    let decompilation = project.decompile(address).unwrap();
    assert_eq!(decompilation.name, "add");
    assert!(decompilation.code.contains("return"), "{}", decompilation.code);
    // A known call target renders by name, not by address.
    let main = project.resolve("main").unwrap();
    assert!(project.decompile(main).unwrap().code.contains("puts"));
}
