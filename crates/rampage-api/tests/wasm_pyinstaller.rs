use std::path::PathBuf;

use rampage_api::{PyInstallerPage, PyInstallerResult, WasmList, pyinstaller_archive, wasm_module};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

#[test]
fn a_wasm_file_is_not_a_project_but_the_file_tool_reads_it() {
    assert!(rampage_loaders::Binary::open(fixture("module.wasm")).is_err());
    let page = wasm_module(&fixture("module.wasm"), None, None, None).unwrap().unwrap();
    let module = &page.module;
    assert!(module.complete, "{:?}", module.limitations);
    assert_eq!((module.version, module.layer, module.supported), (1, 0, true));
    assert_eq!(module.module_name.as_deref(), Some("module.wasm"));
    assert_eq!((module.counts.imports, module.counts.imported_functions, module.counts.functions), (2, 2, 2));
    assert_eq!((module.counts.memories, module.counts.exports), (1, 3));
    assert!(module.custom_sections.iter().any(|name| name == "producers"));
    assert!(module.producers.iter().any(|field| field.field == "processed-by"));
    assert!((page.imports.is_none(), page.total) == (true, None));

    let functions = wasm_module(&fixture("module.wasm"), Some(WasmList::Functions), Some(1), Some(2)).unwrap().unwrap();
    let functions = functions.functions.unwrap();
    let names: Vec<_> = functions.iter().map(|function| function.name.as_deref().unwrap()).collect();
    assert_eq!(names, ["host_log", "add"]);
    assert!(functions[0].imported && functions[0].body_size.is_none());
    assert_eq!(functions[1].signature.as_deref(), Some("(func (param i32 i32) (result i32))"));
    assert!(functions[1].body_size.is_some_and(|size| size > 0));

    let exports = wasm_module(&fixture("module.wasm"), Some(WasmList::Exports), None, Some(1)).unwrap().unwrap();
    assert_eq!((exports.total, exports.returned, exports.next_offset), (Some(3), 1, Some(1)));
    let imports = wasm_module(&fixture("module.wasm"), Some(WasmList::Imports), None, None).unwrap().unwrap();
    let imports = imports.imports.unwrap();
    assert_eq!((imports[1].module.as_str(), imports[1].name.as_str(), imports[1].kind), ("env", "log", "func"));
}

#[test]
fn malformed_component_and_foreign_files_are_bounded_answers() {
    let malformed = wasm_module(&fixture("malformed.wasm"), Some(WasmList::Imports), None, None).unwrap().unwrap();
    assert!(!malformed.module.complete);
    assert_eq!(malformed.module.counts.types, 1);
    assert!(malformed.module.limitations[0].contains("malformed at file offset"), "{:?}", malformed.module.limitations);
    let component = wasm_module(&fixture("component.wasm"), None, None, None).unwrap().unwrap();
    assert!(!component.module.supported && component.module.sections.is_empty());
    assert!(wasm_module(&fixture("hello-x64.elf"), None, None, None).unwrap().is_none());
    assert!(wasm_module(&fixture("module.wasm"), None, None, Some(101)).is_err());
}

fn archive_page(name: &str, offset: Option<usize>, limit: Option<usize>) -> PyInstallerPage {
    match pyinstaller_archive(&fixture(name), offset, limit).unwrap() {
        Some(PyInstallerResult::Archive(page)) => *page,
        other => panic!("{name}: {other:?}"),
    }
}

#[test]
fn pyinstaller_archives_with_both_cookie_layouts_page_their_toc() {
    let page = archive_page("pyinstaller-312.elf", Some(3), Some(2));
    let archive = &page.archive;
    assert_eq!(archive.python_version, "3.12");
    assert_eq!(archive.python_library.as_deref(), Some("libpython3.12.so.1.0"));
    assert_eq!((archive.cookie_size, archive.trailing_bytes, archive.entries_total), (88, 512, 9));
    assert!(archive.toc_complete && archive.cookie_candidates_examined == 1);
    let names: Vec<_> = page.entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(names, ["main", "PYZ-00.pyz"]);
    assert_eq!((page.returned, page.next_offset), (2, Some(5)));
    let pyz = archive.pyz.as_ref().unwrap();
    assert_eq!((pyz.magic_valid, pyz.python_version), (true, Some("3.12")));
    let bytes = std::fs::read(fixture("pyinstaller-312.elf")).unwrap();
    assert_eq!(&bytes[pyz.offset as usize..][..4], b"PYZ\0");

    let legacy = archive_page("pyinstaller-27.macho", None, None);
    assert_eq!((legacy.archive.cookie_size, legacy.archive.python_version.as_str()), (24, "2.7"));
    assert_eq!(legacy.archive.pyz.as_ref().unwrap().python_version, Some("2.7"));
    assert_eq!((legacy.returned, legacy.more), (3, false));
    assert!(pyinstaller_archive(&fixture("hello-x64.elf"), None, None).unwrap().is_none());
    assert!(pyinstaller_archive(&fixture("hello-x64.elf"), None, Some(0)).is_err());
}

#[test]
fn a_stray_cookie_magic_is_no_archive_with_the_rejected_candidates() {
    let path = std::env::temp_dir().join(format!("rampage-stray-magic-{}.bin", std::process::id()));
    std::fs::write(&path, b"a bootloader holding MEI\x0c\x0b\x0a\x0b\x0e as a constant").unwrap();
    let result = pyinstaller_archive(&path, None, None);
    std::fs::remove_file(&path).unwrap();
    let Some(PyInstallerResult::NoCookie(miss)) = result.unwrap() else { panic!("expected no cookie") };
    assert_eq!(miss.rejected_candidates.len(), 1);
    assert!(miss.rejected_candidates[0].contains("cookie magic at 0x15"), "{:?}", miss.rejected_candidates);
    let json = serde_json::to_value(&miss).unwrap();
    assert!(json["archive"].is_null());
}
