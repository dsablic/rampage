use rampage_api::Project;
use rampage_loaders::Binary;

fn project() -> Project {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    Project::new(Binary::open(path).unwrap())
}

#[test]
fn signature_annotations_apply_named_parameters_and_undo_redo() {
    let project = project();
    let add = project.resolve("add").unwrap();
    let before = project.decompile(add).unwrap().code;
    let changed = project.set_signature(add + 1, Some("int4 sum(int4 left,int4 right);")).unwrap();
    assert_eq!(changed.address, add);
    let after = project.decompile(add).unwrap().code;
    assert!(after.contains("left") && after.contains("right"), "{after}");
    project.undo().unwrap();
    assert_eq!(project.decompile(add).unwrap().code, before);
    project.redo().unwrap();
    assert_eq!(project.decompile(add).unwrap().code, after);
    assert!(project.set_signature(add, Some("malformed signature")).is_err());
    assert_eq!(project.decompile(add).unwrap().code, after);
}

#[test]
fn import_slot_signatures_also_apply_to_corresponding_plt_calls() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf");
    let binary = Binary::open(path).unwrap();
    let slot = binary.import_slots.iter().find(|slot| slot.name == "puts").unwrap().address;
    let project = Project::new(binary);
    project.set_signature(slot, Some("int4 custom(int4 arg);")).unwrap();
    let code = project.decompile(project.resolve("main").unwrap()).unwrap().code;
    assert!(!code.contains("\"rampage fixture greeting\""), "{code}");
}

#[test]
fn user_types_are_loaded_before_signatures_and_invalid_input_is_not_saved() {
    let project = project();
    let add = project.resolve("add").unwrap();
    project.set_types(add, Some("typedef int4 number; struct pair { int4 first; int4 second; };")).unwrap();
    project.set_signature(add, Some("number sum(number left,number right);")).unwrap();
    let code = project.decompile(add).unwrap().code;
    assert!(code.contains("number left") && code.contains("number right"), "{code}");
    assert!(project.set_types(add, Some("struct broken {")).is_err());
    assert_eq!(project.annotation_list().types.len(), 1);
}

#[test]
fn unsafe_array_bounds_and_type_bound_signatures_are_rejected() {
    let project = project();
    let add = project.resolve("add").unwrap();
    for text in [
        "typedef int4 huge[4294967297];",
        "typedef int4 huge[-4294967295];",
        "typedef int4 huge[1073741824];",
        "typedef int4 huge[65536][65536];",
        "const extern int4 add(int4 evil,int4 other);",
    ] {
        assert!(project.set_types(add, Some(text)).is_err(), "{text}");
    }
    assert!(project.annotation_list().types.is_empty());
    assert!(project.set_signature(add, Some("int4 f(int4 values[65536]);")).is_err());
    assert!(project.set_types(add, Some("typedef int4 values[010];")).is_err());
    assert!(project.annotation_list().signatures.is_empty());
}

#[test]
fn shared_logs_replay_types_and_prevent_undoing_a_required_typedef() {
    use rampage_api::annotations::Annotations;
    let path = std::env::temp_dir().join(format!("rampage-typed-shared-{}.jsonl", std::process::id()));
    assert!(!path.exists());
    let open = || {
        let binary_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
        Project::with_annotations(Binary::open(binary_path).unwrap(), Annotations::open(path.clone()).unwrap())
    };
    let first = open();
    let second = open();
    let add = first.resolve("add").unwrap();
    first.set_types(add, Some("typedef int4 number;")).unwrap();
    second.set_signature(add, Some("number sum(number left,number right);")).unwrap();
    assert!(first.undo().is_err());
    assert!(first.set_types(add, None).is_err());
    let reopened = open();
    let code = reopened.decompile(add).unwrap().code;
    std::fs::remove_file(&path).unwrap();
    let mut lock = path.as_os_str().to_owned();
    lock.push(".lock");
    std::fs::remove_file(std::path::PathBuf::from(lock)).unwrap();
    assert!(code.contains("number left"), "{code}");
}

#[test]
fn concurrent_type_removal_and_signature_creation_preserve_a_valid_log() {
    use rampage_api::annotations::Annotations;
    use std::sync::{Arc, Barrier};
    let path = std::env::temp_dir().join(format!("rampage-typed-race-{}.jsonl", std::process::id()));
    assert!(!path.exists());
    let open = || {
        let binary_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
        Project::with_annotations(Binary::open(binary_path).unwrap(), Annotations::open(path.clone()).unwrap())
    };
    let first = Arc::new(open());
    let second = Arc::new(open());
    let add = first.resolve("add").unwrap();
    first.set_types(add, Some("typedef int4 number;")).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let left = Arc::clone(&first);
    let wait = Arc::clone(&barrier);
    let removal = std::thread::spawn(move || {
        wait.wait();
        left.set_types(add, None)
    });
    let wait = Arc::clone(&barrier);
    let signature = std::thread::spawn(move || {
        wait.wait();
        second.set_signature(add, Some("number sum(number left,number right);"))
    });
    let outcomes = (removal.join().unwrap().is_ok(), signature.join().unwrap().is_ok());
    let valid = open().decompile(add);
    std::fs::remove_file(&path).unwrap();
    let mut lock = path.as_os_str().to_owned();
    lock.push(".lock");
    std::fs::remove_file(std::path::PathBuf::from(lock)).unwrap();
    assert_ne!(outcomes, (true, true));
    valid.unwrap();
}
