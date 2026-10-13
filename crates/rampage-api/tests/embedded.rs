use std::path::PathBuf;
use std::sync::Arc;

use rampage_api::{ApiError, FunctionsQuery, ListQuery, Session};
use rampage_loaders::ImageAt;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn at(offset: u64) -> Option<ImageAt> {
    Some(ImageAt::new(offset, None))
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
    let embedded = Session::default().open_at(&path, None, at(offset)).unwrap();
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
    let embedded = session.open_at(&path, None, at(first)).unwrap();
    let main = embedded.resolve("main").unwrap();
    embedded.rename(main, Some("embedded_main")).unwrap();
    assert!(scratch.0.join(format!("firmware.bin@{first:#x}.rampage-image")).exists());
    assert!(!scratch.0.join("firmware.bin.rampage").exists());

    let reopened = Session::default().open_at(&path, None, at(first)).unwrap();
    assert_eq!(reopened.annotation_list().names.len(), 1);
    assert_eq!(reopened.function_name(main), "embedded_main");
    for other in [session.open(&path, None).unwrap(), session.open_at(&path, None, at(second)).unwrap()] {
        assert!(other.annotation_list().names.is_empty());
        assert!(!Arc::ptr_eq(&other, &embedded));
    }
    assert!(Arc::ptr_eq(&session.open_at(&path, None, at(first)).unwrap(), &embedded));
}

#[test]
fn a_bad_offset_is_a_load_error() {
    let (_scratch, path, first, _) = outer_file("bad");
    let session = Session::default();
    for offset in [first + 1, u64::MAX] {
        let error = session.open_at(&path, None, at(offset)).err().expect("no image there");
        assert!(matches!(error, ApiError::Load { .. }), "{error}");
    }
}

#[test]
fn an_image_length_takes_in_the_overlay_the_header_extent_leaves_out() {
    let (_scratch, path, _, second) = outer_file("length");
    let size = std::fs::metadata(fixture("hello-x64-dyn.elf")).unwrap().len();
    let mut longer = std::fs::read(&path).unwrap();
    longer.extend(b"appended overlay");
    std::fs::write(&path, &longer).unwrap();
    let session = Session::default();

    let cut = session.open_at(&path, None, at(second)).unwrap();
    assert_eq!(cut.binary.overlay, None);
    let triage = cut.triage();
    let hint = format!(
        "16 bytes follow the image in the outer file and were not examined; an image length of {:#x}",
        size + 16
    );
    assert!(triage.hints.iter().any(|text| text.starts_with(&hint)), "{:?}", triage.hints);

    let whole = session.open_at(&path, None, Some(ImageAt::new(second, Some(size + 16)))).unwrap();
    assert_eq!(whole.binary.overlay.map(|overlay| (overlay.offset, overlay.size)), Some((size, 16)));
    assert!(!whole.triage().hints.iter().any(|text| text.contains("were not examined")));
    assert!(!Arc::ptr_eq(&whole, &cut));
    let main = whole.resolve("main").unwrap();
    whole.rename(main, Some("whole_main")).unwrap();
    assert!(Session::default().open_at(&path, None, at(second)).unwrap().annotation_list().names.is_empty());
    let reopened = Session::default().open_at(&path, None, Some(ImageAt::new(second, Some(size + 16)))).unwrap();
    assert_eq!(reopened.function_name(main), "whole_main");
}

#[test]
fn an_embedded_image_and_a_file_named_like_its_location_keep_separate_annotations() {
    let (scratch, path, first, _) = outer_file("collision");
    let named_like = scratch.0.join(format!("firmware.bin@{first:#x}"));
    std::fs::copy(fixture("hello-x64-dyn.elf"), &named_like).unwrap();
    let embedded = Session::default().open_at(&path, None, at(first)).unwrap();
    let plain = Session::default().open(&named_like, None).unwrap();
    let main = embedded.resolve("main").unwrap();
    assert_eq!(plain.resolve("main").unwrap(), main);
    embedded.rename(main, Some("embedded_main")).unwrap();
    plain.rename(main, Some("plain_main")).unwrap();

    assert_eq!(Session::default().open_at(&path, None, at(first)).unwrap().function_name(main), "embedded_main");
    assert_eq!(Session::default().open(&named_like, None).unwrap().function_name(main), "plain_main");
}

#[test]
fn offset_zero_without_a_length_is_the_file_itself() {
    let (scratch, path, _, _) = outer_file("zero");
    let session = Session::default();
    let zero = session.open_at(&path, None, at(0)).unwrap();
    let plain = session.open(&path, None).unwrap();
    assert!(Arc::ptr_eq(&zero, &plain));
    assert_eq!(zero.binary.embedded, None);
    let main = zero.resolve("main").unwrap();
    zero.rename(main, Some("outer_main")).unwrap();
    assert!(scratch.0.join("firmware.bin.rampage").exists());
    assert_eq!(Session::default().open(&path, None).unwrap().function_name(main), "outer_main");

    let length = std::fs::metadata(fixture("hello-x64.elf")).unwrap().len();
    let explicit = session.open_at(&path, None, Some(ImageAt::new(0, Some(length)))).unwrap();
    assert!(!Arc::ptr_eq(&explicit, &plain));
    assert!(explicit.binary.embedded.is_some());
}

#[test]
fn an_unsuffixed_embedded_sidecar_is_reported_not_loaded() {
    let (scratch, path, first, _) = outer_file("unsuffixed");
    let old = scratch.0.join(format!("firmware.bin@{first:#x}.rampage"));
    std::fs::write(&old, "").unwrap();
    let embedded = Session::default().open_at(&path, None, at(first)).unwrap();
    let warning = format!("annotations at {} were not loaded", old.display());
    assert!(embedded.binary.warnings.iter().any(|text| text.starts_with(&warning)), "{:?}", embedded.binary.warnings);
}
