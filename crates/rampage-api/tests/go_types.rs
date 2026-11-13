use rampage_api::Project;
use rampage_api::tools;
use rampage_loaders::Binary;
use rampage_loaders::gopclntab::GoTableVersion;
use serde_json::{Value, json};

fn fixture(name: &str) -> Binary {
    Binary::open(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)).unwrap()
}

fn call(project: &Project, tool: &str, arguments: Value) -> (Value, bool) {
    let (text, failed) = tools::call(&tools::tools(), project, tool, arguments);
    (if failed { Value::String(text) } else { serde_json::from_str(&text).unwrap() }, failed)
}

#[test]
fn list_types_keeps_the_empty_library_page_when_go_metadata_is_unreadable() {
    // A go1.2-era pclntab (here: declared on a modern image) has no supported runtime type layout.
    let mut binary = fixture("hello-go-x64.elf");
    binary.go_table = Some(GoTableVersion::Go12);
    let project = Project::new(binary);
    let (page, failed) = call(&project, "list_types", json!({}));
    assert!(!failed, "{page}");
    assert_eq!(page["total"], 0);
    assert!(page.get("source").is_none(), "the library page, not a Go page: {page}");
    let (error, failed) = call(&project, "list_types", json!({"source": "go"}));
    assert!(failed && error.as_str().unwrap().contains("go1.16"), "{error}");
}

#[test]
fn get_type_keeps_the_sources_tried_when_a_go_selection_fails() {
    let project = Project::new(fixture("gotypes-go1.20-x64.elf"));
    let (error, failed) = call(&project, "get_type", json!({"name": "main.Record", "member": "Nope"}));
    let text = error.as_str().unwrap();
    assert!(failed && text.contains("no DWARF") && text.contains("no field \"Nope\""), "{text}");
    let (page, failed) = call(&project, "list_types", json!({"contains": "main.Rec"}));
    assert!(!failed && page["source"] == "go_runtime", "{page}");
}
