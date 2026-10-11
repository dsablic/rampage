use rampage_api::Project;
use rampage_loaders::Binary;

fn project(name: &str) -> Project {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name);
    Project::new(Binary::open(path).unwrap())
}

#[test]
fn elf_plt_signatures_bind_by_address_and_survive_display_renames() {
    let project = project("hello-x64-dyn.elf");
    let main = project.resolve("main").unwrap();
    let before = project.decompile(main).unwrap().code;
    assert!(before.contains("\"rampage fixture greeting\""), "{before}");
    let puts = project.resolve("puts").unwrap();
    project.rename(puts, Some("print_greeting")).unwrap();
    let after = project.decompile(main).unwrap().code;
    assert!(after.contains("print_greeting(\"rampage fixture greeting\")"), "{after}");
    project.undo().unwrap();
    assert_eq!(project.decompile(main).unwrap().code, before);
    project.redo().unwrap();
    assert_eq!(project.decompile(main).unwrap().code, after);
}

#[test]
fn semantic_tokens_link_caller_operations_and_named_call_targets() {
    let project = project("hello-x64-dyn.elf");
    let main = project.resolve("main").unwrap();
    let puts = project.resolve("puts").unwrap();
    let result = project.decompile(main).unwrap();
    assert!(
        result.tokens.iter().any(|token| token.kind == "function" && token.address == Some(puts)),
        "{:?}",
        result.tokens
    );
    assert!(
        result.tokens.iter().any(|token| token.kind == "operator" && token.address.is_some()),
        "{:?}",
        result.tokens
    );
    let second = project.decompile(main).unwrap();
    assert!(result.tokens.iter().any(|token| token.kind == "block" && token.address == Some(main)));
    assert!(result.tokens.iter().any(|token| token.kind == "call" && token.address == Some(puts)));
    assert_eq!(second.tokens.len(), result.tokens.len());
    let json = serde_json::to_value(&result).unwrap();
    assert!(json["structure"]["blocks"][0]["start"].as_str().unwrap().starts_with("0x"));
    for token in &result.tokens {
        if let Some((start, end)) = token.span {
            assert_eq!(&result.code[start..end], token.text);
        }
    }
    assert!(result.tokens.iter().filter_map(|token| token.span).count() >= 3);
}

#[test]
fn cached_function_declarations_follow_rename_undo_and_redo() {
    let project = project("hello-x64.elf");
    let add = project.resolve("add").unwrap();
    let before = project.decompile(add).unwrap().code;
    project.rename(add, Some("addition_logic")).unwrap();
    let after = project.decompile(add).unwrap().code;
    assert!(after.contains("addition_logic("), "{after}");
    assert!(!after.contains(" add("), "{after}");
    project.undo().unwrap();
    assert_eq!(project.decompile(add).unwrap().code, before);
    project.redo().unwrap();
    assert_eq!(project.decompile(add).unwrap().code, after);
}

#[test]
fn renaming_an_unnamed_function_does_not_assign_a_runtime_signature() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    let mut binary = Binary::open(path).unwrap();
    let add = binary.symbols.iter().find(|symbol| symbol.name == "add").unwrap().address;
    binary.symbols.retain(|symbol| symbol.address != add);
    binary.symbols.retain(|symbol| symbol.name != "puts");
    binary.imports.retain(|import| import.name != "puts");
    binary.import_slots.retain(|slot| slot.name != "puts");
    binary.exports.retain(|export| export.address != add);
    binary.function_starts.push(add);
    let project = Project::new(binary);
    let before = project.decompile(add).unwrap().code;
    project.rename(add, Some("puts")).unwrap();
    let after = project.decompile(add).unwrap().code;
    assert!(!after.contains("char *"), "{after}");
    assert!(before.contains("param_2") && after.contains("param_2"), "{before}\n{after}");
}

#[test]
fn external_annotation_refresh_updates_cached_declarations() {
    use rampage_api::annotations::{Annotations, Field};
    let path = std::env::temp_dir().join(format!("rampage-decompiler-refresh-{}.jsonl", std::process::id()));
    assert!(!path.exists());
    let binary_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    let project =
        Project::with_annotations(Binary::open(binary_path).unwrap(), Annotations::open(path.clone()).unwrap());
    let add = project.resolve("add").unwrap();
    project.decompile(add).unwrap();
    let mut writer = Annotations::open(path.clone()).unwrap();
    writer.set(Field::Name, add, Some("external_add".to_owned())).unwrap();
    project.refresh_annotations().unwrap();
    let result = project.decompile(add);
    std::fs::remove_file(&path).unwrap();
    let mut lock = path.as_os_str().to_owned();
    lock.push(".lock");
    std::fs::remove_file(std::path::PathBuf::from(lock)).unwrap();
    assert!(result.unwrap().code.contains("external_add("));
}
