//! The `.rampage` annotation log format, pinned by committed logs (docs/stability.md). Each fixture was written by
//! rampage's own writers on `tests/fixtures/bin/hello-x64.elf`: names, comments, a batch, ledger entries (one
//! updated) and checked edits (a type library declaration and a data type). `hello-x64-0.1.0.jsonl` is the log as
//! rampage 0.1.0 wrote it, before identity lines carried `format`; `hello-x64-format1.jsonl` as format 1 writes it.
//! Every later build must open both, read and checked, with the same result.

use std::path::{Path, PathBuf};

use rampage_api::annotations::{ANNOTATION_LOG_FORMAT, Annotations};
use sha2::{Digest, Sha256};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(name)
}

/// A copy of the fixture binary with `log` beside it as its annotation log, in a fresh directory.
struct Copy {
    root: PathBuf,
    log: PathBuf,
}

impl Copy {
    fn new(name: &str, log: &str) -> Self {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("rampage-log-format-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::copy(fixture("bin/hello-x64.elf"), root.join("hello-x64.elf")).unwrap();
        let path = root.join("hello-x64.elf.rampage");
        std::fs::write(&path, log).unwrap();
        Self { root, log: path }
    }
}

impl Drop for Copy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn image() -> [u8; 32] {
    Sha256::digest(std::fs::read(fixture("bin/hello-x64.elf")).unwrap()).into()
}

fn assert_contents(annotations: &Annotations, label: &str) {
    assert_eq!(annotations.name(0x1001910), Some("compat_main"), "{label}");
    assert_eq!(annotations.name(0x1001900), Some("compat_add"), "{label}");
    assert_eq!(annotations.name(0x10018d6), Some("compat_start_c"), "{label}");
    assert_eq!(annotations.comment(0x1001910), Some("entry logic, pinned by the format fixture"), "{label}");
    assert_eq!(annotations.comment(0x1001900), Some("adds two ints"), "{label}");
    let findings = annotations.findings();
    assert_eq!(findings.len(), 2, "{label}");
    assert!(findings[&1].contains("compat_main calls compat_add"), "{label}");
    assert!(findings[&2].contains("\"status\":\"resolved\"") && findings[&2].contains("the stack pointer"));
    assert!(annotations.type_library().values().any(|value| value.contains("struct CompatPair")), "{label}");
    assert!(annotations.data_types()[&0x100019a].contains("\"byte_length\":24"), "{label}");
    assert!(annotations.warnings().is_empty(), "{label}: {:?}", annotations.warnings());
}

#[test]
fn committed_logs_of_every_format_1_writer_open_read_and_checked() {
    for name in ["hello-x64-0.1.0.jsonl", "hello-x64-format1.jsonl"] {
        let text = std::fs::read_to_string(fixture(&format!("annotation-logs/{name}"))).unwrap();
        let copy = Copy::new(name, &text);
        let read = Annotations::open_for_image(copy.log.clone(), Some(image())).unwrap();
        assert_contents(&read, name);
        let checked = Annotations::open_for_image_checked(copy.log.clone(), Some(image())).unwrap();
        assert_contents(&checked, name);
    }
    assert_eq!(ANNOTATION_LOG_FORMAT, 1);
}

#[test]
fn a_new_edit_lands_after_an_old_log_and_declares_the_format() {
    let text = std::fs::read_to_string(fixture("annotation-logs/hello-x64-0.1.0.jsonl")).unwrap();
    let copy = Copy::new("append", &text);
    let mut annotations = Annotations::open_for_image_checked(copy.log.clone(), None).unwrap();
    annotations.set(rampage_api::annotations::Field::Name, 0x1001910, Some("compat_entry".to_owned())).unwrap();
    let written = std::fs::read_to_string(&copy.log).unwrap();
    assert!(written.starts_with(&text), "an append never rewrites earlier records");
    let reopened = Annotations::open_checked(copy.log.clone()).unwrap();
    assert_eq!(reopened.name(0x1001910), Some("compat_entry"));
    // A writer that knows its image logs the format with it.
    let copy = Copy::new("identity", &text);
    let mut annotations = Annotations::open_for_image(copy.log.clone(), Some([7; 32])).unwrap();
    annotations.set(rampage_api::annotations::Field::Comment, 0x1001900, Some("x".to_owned())).unwrap();
    let written = std::fs::read_to_string(&copy.log).unwrap();
    let identity = written.lines().rev().find(|line| line.contains("\"image\"")).unwrap();
    assert!(identity.ends_with(&format!(",\"format\":{ANNOTATION_LOG_FORMAT}}}")), "{identity}");
}

#[test]
fn later_format_1_additions_are_skipped_and_a_newer_format_is_refused() {
    let text = std::fs::read_to_string(fixture("annotation-logs/hello-x64-format1.jsonl")).unwrap();
    // A later 1.x writer may add edits of a new field and new keys on lone edits and identity lines.
    let later = format!(
        "{text}{{\"image\":\"{}\",\"format\":1,\"writer\":\"rampage 1.9\"}}\n\
         {{\"field\":\"bookmark\",\"address\":\"0x1001910\",\"value\":\"b\",\"previous\":null}}\n\
         {{\"field\":\"name\",\"address\":\"0x1001900\",\"value\":\"compat_sum\",\"previous\":\"compat_add\",\"by\":\"x\"}}\n",
        rampage_arch::hex::bytes(&image())
    );
    let copy = Copy::new("later", &later);
    for checked in [false, true] {
        let annotations = if checked {
            Annotations::open_for_image_checked(copy.log.clone(), Some(image()))
        } else {
            Annotations::open_for_image(copy.log.clone(), Some(image()))
        };
        let annotations = annotations.unwrap();
        assert_eq!(annotations.name(0x1001900), Some("compat_sum"), "checked {checked}");
        assert_eq!(annotations.name(0x1001910), Some("compat_main"), "checked {checked}");
    }

    // A log a newer format wrote is refused, naming the format, and nothing is appended to it.
    let newer = format!("{text}{{\"image\":\"{}\",\"format\":2}}\n", rampage_arch::hex::bytes(&image()));
    let copy = Copy::new("newer", &newer);
    for checked in [false, true] {
        let error = if checked {
            Annotations::open_checked(copy.log.clone()).err()
        } else {
            Annotations::open(copy.log.clone()).err()
        };
        let error = error.unwrap_or_else(|| panic!("checked {checked}: a format-2 log opened"));
        assert!(error.contains("format 2") && error.contains("newer rampage"), "{error}");
    }
    assert_eq!(std::fs::read_to_string(&copy.log).unwrap(), newer);
}
