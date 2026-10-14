use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use rampage_api::tools::{Group, file_tools};
use rampage_api::{ArchiveQuery, MAX_ARCHIVE_RESULT_BYTES, Packs, archive_inventory};
use serde_json::{Value, json};

static SERIAL: AtomicUsize = AtomicUsize::new(0);

struct Input(PathBuf);

impl Input {
    fn new(names: &[Vec<u8>]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rampage-api-zip32-{}-{}.zip",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, zip(names)).unwrap();
        Self(path)
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

fn zip(names: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = if names.is_empty() { vec![] } else { b"PK\x03\x04not a local header".to_vec() };
    let cd = bytes.len();
    for name in names {
        let mut record = [0; 46];
        record[..4].copy_from_slice(b"PK\x01\x02");
        record[8..10].copy_from_slice(&0x800u16.to_le_bytes());
        record[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend(record);
        bytes.extend(name);
    }
    let mut end = [0; 22];
    end[..4].copy_from_slice(b"PK\x05\x06");
    end[8..10].copy_from_slice(&(names.len() as u16).to_le_bytes());
    end[10..12].copy_from_slice(&(names.len() as u16).to_le_bytes());
    end[12..16].copy_from_slice(&((bytes.len() - cd) as u32).to_le_bytes());
    end[16..20].copy_from_slice(&(cd as u32).to_le_bytes());
    bytes.extend(end);
    bytes
}

#[test]
fn typed_and_file_tool_pages_share_metadata_identity_and_never_need_a_binary_or_sidecar() {
    let input = Input::new(&[b"duplicate".to_vec(), b"duplicate".to_vec(), b"../member".to_vec()]);
    let before = std::fs::read(&input.0).unwrap();
    assert!(rampage_loaders::Binary::open(&input.0).is_err());
    let query = ArchiveQuery { offset: Some(1), limit: Some(1), contains: Some("duplicate".to_owned()) };
    let page = archive_inventory(&input.0, &query).unwrap();
    assert_eq!(
        (page.declared, page.examined, page.validated, page.retained, page.matched, page.returned),
        (3, 3, 3, 3, 2, 1)
    );
    assert_eq!(page.members[0].member_ref.ordinal, 1);
    assert!(!page.more);
    assert_eq!(page.next_offset, None);
    assert!(page.central_directory_complete && !page.truncated);
    let tool = file_tools().into_iter().find(|tool| tool.name == "archive_inventory").unwrap();
    assert_eq!(tool.group, Group::Carve);
    assert!(tool.input_schema["required"].as_array().unwrap().contains(&json!("path")));
    let packs = Packs::lazy(&[PathBuf::from("/nonexistent/rampage-archive-unused-pack")]);
    let output = tool
        .call(
            &packs,
            json!({ "path": input.0, "offset": 1, "limit": 1,
        "contains": "duplicate" }),
        )
        .unwrap();
    assert!(!packs.is_loaded());
    assert_eq!(output, serde_json::to_value(&page).unwrap());
    assert_eq!(std::fs::read(&input.0).unwrap(), before);
    assert!(!input.0.with_extension("zip.rampage").exists());
}

#[test]
fn json_byte_paging_always_advances_with_maximum_escaped_names_and_exact_stable_counts() {
    let input = Input::new(&vec![vec![0; 1024]; 100]);
    let mut offset = 0;
    let mut ordinals = Vec::new();
    let mut identity = None;
    loop {
        let page = archive_inventory(&input.0, &ArchiveQuery { offset: Some(offset), ..Default::default() }).unwrap();
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_ARCHIVE_RESULT_BYTES);
        assert_eq!((page.declared, page.validated, page.retained, page.matched), (100, 100, 100, 100));
        assert!(page.returned > 0 && page.returned < 100);
        if let Some(reference) = &identity {
            assert_eq!(&page.archive_ref, reference);
        } else {
            identity = Some(page.archive_ref.clone());
        }
        for member in &page.members {
            assert_eq!(member.raw_name_hex.len(), 2048);
            assert_eq!(member.name_display.as_ref().unwrap().len(), 1024);
            ordinals.push(member.member_ref.ordinal);
        }
        match page.next_offset {
            Some(next) => {
                assert!(page.more && next > offset);
                assert_eq!(next, offset + page.returned);
                offset = next;
            }
            None => {
                assert!(!page.more);
                break;
            }
        }
    }
    assert_eq!(ordinals, (0..100).collect::<Vec<_>>());
    let past = archive_inventory(&input.0, &ArchiveQuery { offset: Some(usize::MAX), ..Default::default() }).unwrap();
    assert_eq!(past.returned, 0);
    assert!(!past.more);
}

#[test]
fn full_raw_names_are_filtered_before_truncation_and_no_match_is_only_about_validated_metadata() {
    let name = format!("{}λ-needle", "x".repeat(1023)).into_bytes();
    let input = Input::new(&[name, b"other".to_vec()]);
    let page =
        archive_inventory(&input.0, &ArchiveQuery { contains: Some("λ-needle".to_owned()), ..Default::default() })
            .unwrap();
    assert_eq!((page.validated, page.retained, page.matched, page.returned), (2, 2, 1, 1));
    assert_eq!(page.members[0].name_display.as_ref().unwrap().len(), 1023);
    assert!(page.members[0].name_truncated);
    let empty =
        archive_inventory(&input.0, &ArchiveQuery { contains: Some("absent".to_owned()), ..Default::default() })
            .unwrap();
    assert_eq!((empty.validated, empty.matched, empty.returned), (2, 0, 0));
    assert!(!empty.more);
}

#[test]
fn invalid_queries_and_native_image_parameters_are_refused_before_io() {
    let missing = PathBuf::from("/nonexistent/rampage-archive-query");
    for query in [
        ArchiveQuery { limit: Some(0), ..Default::default() },
        ArchiveQuery { limit: Some(101), ..Default::default() },
        ArchiveQuery { contains: Some("λ".repeat(513)), ..Default::default() },
    ] {
        assert!(matches!(archive_inventory(&missing, &query), Err(rampage_api::ApiError::Invalid(_))));
    }
    let tool = file_tools().into_iter().find(|tool| tool.name == "archive_inventory").unwrap();
    for field in ["arch", "image_offset", "image_length", "extract", "auto_open"] {
        let mut input = json!({ "path": missing });
        input[field] = json!(0);
        let error = tool.call(&Packs::default(), input).unwrap_err();
        assert!(error.contains("unknown field"), "{error}");
    }
    assert!(tool.call(&Packs::default(), json!({})).is_err());
    assert!(tool.call(&Packs::default(), json!({ "path": missing, "offset": -1 })).is_err());
    assert!(tool.call(&Packs::default(), json!({ "path": missing, "contains": "x".repeat(70_000) })).is_err());
    let error =
        tool.call(&Packs::default(), json!({ "path": "/nonexistent/".to_owned() + &"λ".repeat(5000) })).unwrap_err();
    assert!(error.len() <= 4096);
    assert!(error.ends_with("[archive error truncated]"));
}

#[test]
fn deserialization_debug_expansion_is_bounded_before_archive_io_or_project_loading() {
    let input = Input::new(&[]);
    let before = std::fs::read(&input.0).unwrap();
    let packs = Packs::lazy(&[PathBuf::from("/nonexistent/rampage-archive-unused-pack")]);
    let tool = file_tools().into_iter().find(|tool| tool.name == "archive_inventory").unwrap();
    let unexpected = "\u{0085}".repeat(15_000);
    for field in ["offset", "limit"] {
        let mut arguments = json!({ "path": input.0 });
        arguments[field] = json!(unexpected);
        assert!(arguments.to_string().len() < 48_000);
        let error = tool.call(&packs, arguments).unwrap_err();
        assert!(error.starts_with("invalid arguments:"), "{error}");
        assert!(error.contains("invalid type"));
        assert!(error.ends_with("[archive error truncated]"));
        assert!(error.len() <= 4096);
        assert!(std::str::from_utf8(error.as_bytes()).is_ok());
        assert!(!error.contains("cannot read"));
        assert!(!packs.is_loaded());
    }
    assert_eq!(std::fs::read(&input.0).unwrap(), before);
    assert!(!input.0.with_extension("zip.rampage").exists());
}

#[cfg(unix)]
#[test]
fn non_utf8_native_file_paths_fail_serialization_instead_of_panicking() {
    use std::os::unix::ffi::OsStringExt;
    let path = PathBuf::from(std::ffi::OsString::from_vec(b"/nonexistent/\xff.zip".to_vec()));
    let result = archive_inventory(&path, &ArchiveQuery::default());
    assert!(matches!(result, Err(rampage_api::ApiError::Invalid(_))));
}

#[test]
fn empty_archive_file_tool_returns_valid_bounded_json() {
    let input = Input::new(&[]);
    let tool = file_tools().into_iter().find(|tool| tool.name == "archive_inventory").unwrap();
    let output = tool.call(&Packs::default(), json!({ "path": input.0 })).unwrap();
    let text = output.to_string();
    assert!(text.len() <= MAX_ARCHIVE_RESULT_BYTES);
    let parsed: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["declared"], 0);
    assert_eq!(parsed["members"], json!([]));
    assert_eq!(parsed["central_directory_complete"], true);
}
