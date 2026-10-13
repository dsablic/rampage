use std::path::PathBuf;
use std::sync::Arc;

use rampage_api::{ApiError, FunctionsQuery, ListQuery, Session};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An ELF with junk after it, then `hello-x64-dyn.elf` twice at odd offsets: the outer file still opens as the
/// first ELF.
fn outer_file(test: &str) -> (Scratch, PathBuf, u64, u64) {
    let directory = std::env::temp_dir().join(format!("rampage-api-embedded-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let inner = std::fs::read(fixture("hello-x64-dyn.elf")).unwrap();
    let mut file = std::fs::read(fixture("hello-x64.elf")).unwrap();
    file.extend(b"junk".repeat(77));
    file.push(b'!');
    let first = file.len() as u64;
    file.extend(&inner);
    file.extend(b"more junk");
    let second = file.len() as u64;
    file.extend(&inner);
    let path = directory.join("firmware.bin");
    std::fs::write(&path, file).unwrap();
    (Scratch(directory), path, first, second)
}

#[test]
fn an_embedded_image_has_the_functions_and_imports_of_the_extracted_file() {
    let (_scratch, path, offset, _) = outer_file("same");
    let direct = Session::default().open(&fixture("hello-x64-dyn.elf"), None).unwrap();
    let embedded = Session::default().open_at(&path, None, Some(offset)).unwrap();
    let names = |project: &rampage_api::Project| {
        let functions = project.functions(&FunctionsQuery::default()).unwrap();
        functions.items.iter().map(|row| (row.address, row.name.clone())).collect::<Vec<_>>()
    };
    let embedded_names = names(&embedded);
    assert!(embedded_names.iter().any(|(_, name)| name == "main"));
    assert_eq!(embedded_names, names(&direct));
    let imports =
        |project: &rampage_api::Project| serde_json::to_value(project.imports(&ListQuery::default())).unwrap();
    assert_eq!(imports(&embedded), imports(&direct));

    let triage = embedded.triage();
    assert_eq!(triage.image_hashes.sha256, direct.triage().image_hashes.sha256);
    assert_eq!(triage.embedded.map(|embedded| embedded.offset), Some(offset));
    assert!(triage.hints.iter().any(|hint| hint.contains(&format!("offset {offset:#x}"))), "{:?}", triage.hints);
}

#[test]
fn annotations_on_an_embedded_image_stay_in_its_own_sidecar() {
    let (scratch, path, first, second) = outer_file("annotations");
    let session = Session::default();
    let embedded = session.open_at(&path, None, Some(first)).unwrap();
    let main = embedded.resolve("main").unwrap();
    embedded.rename(main, Some("embedded_main")).unwrap();
    assert!(scratch.0.join(format!("firmware.bin@{first:#x}.rampage")).exists());
    assert!(!scratch.0.join("firmware.bin.rampage").exists());

    let reopened = Session::default().open_at(&path, None, Some(first)).unwrap();
    assert_eq!(reopened.annotation_list().names.len(), 1);
    assert_eq!(reopened.function_name(main), "embedded_main");
    for other in [session.open(&path, None).unwrap(), session.open_at(&path, None, Some(second)).unwrap()] {
        assert!(other.annotation_list().names.is_empty());
        assert!(!Arc::ptr_eq(&other, &embedded));
    }
    assert!(Arc::ptr_eq(&session.open_at(&path, None, Some(first)).unwrap(), &embedded));
}

#[test]
fn a_bad_offset_is_a_load_error() {
    let (_scratch, path, first, _) = outer_file("bad");
    let session = Session::default();
    for offset in [first + 1, u64::MAX] {
        let error = session.open_at(&path, None, Some(offset)).err().expect("no image there");
        assert!(matches!(error, ApiError::Load { .. }), "{error}");
    }
}
