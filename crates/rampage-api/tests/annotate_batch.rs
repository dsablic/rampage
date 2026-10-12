use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use rampage_api::annotations::{Edit, Field};
use rampage_api::{ApiError, BatchEntry, MAX_BATCH, Session};

fn scratch_copy(test: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("rampage-api-batch-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("hello-arm64.macho");
    std::fs::copy(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-arm64.macho"), &path)
        .unwrap();
    path
}

fn entry(at: &str, name: Option<&str>, comment: Option<&str>) -> BatchEntry {
    BatchEntry { at: at.to_owned(), name: name.map(str::to_owned), comment: comment.map(str::to_owned) }
}

fn hex(address: u64) -> String {
    format!("{address:#x}")
}

/// Runs `edit` while another process holds the log's lock, and has that process name `other` `name` before
/// letting go. Returns `edit`'s error, which it must give once it sees that name taken.
fn race_another_process(
    path: &Path,
    other: u64,
    name: &str,
    edit: impl FnOnce() -> Result<(), ApiError> + Send,
) -> String {
    let log = PathBuf::from(format!("{}.rampage", path.display()));
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(format!("{}.lock", log.display()))
        .unwrap();
    lock.lock().unwrap();
    std::thread::scope(|scope| {
        let editing = scope.spawn(edit);
        // Long enough for `edit` to have read the log and to be waiting for the lock.
        std::thread::sleep(std::time::Duration::from_millis(300));
        let taken = Edit { field: Field::Name, address: other, value: Some(name.to_owned()), previous: None };
        let line = format!("{}\n", serde_json::to_string(&taken).unwrap());
        OpenOptions::new().create(true).append(true).open(&log).unwrap().write_all(line.as_bytes()).unwrap();
        lock.unlock().unwrap();
        editing.join().unwrap().unwrap_err().to_string()
    })
}

#[test]
fn rename_sees_a_name_another_process_gave_while_it_waited() {
    let path = scratch_copy("race-rename");
    let project = Session::default().open(&path, None).unwrap();
    let main = project.resolve("_main").unwrap();
    let error = race_another_process(&path, main + 4, "taken", || project.rename(main, Some("taken")).map(drop));
    assert!(error.contains(&format!("\"taken\" already names {:#x}", main + 4)), "{error}");
    assert_eq!(project.name_at(main), Some("_main".to_owned()));
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn a_batch_sees_a_name_another_process_gave_while_it_waited() {
    let path = scratch_copy("race-batch");
    let project = Session::default().open(&path, None).unwrap();
    let main = project.resolve("_main").unwrap();
    let error = race_another_process(&path, main + 4, "taken", || {
        project.annotate_batch(&[entry("_main", Some("taken"), None)]).map(drop)
    });
    assert!(error.contains(&format!("\"taken\" already names {:#x}", main + 4)), "{error}");
    assert!(project.undo().unwrap().is_empty());
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn one_invalid_entry_applies_nothing_and_every_problem_is_listed() {
    let path = scratch_copy("atomic");
    let project = Session::default().open(&path, None).unwrap();
    let main = project.resolve("_main").unwrap();
    let error = project
        .annotate_batch(&[
            entry("_main", Some("greet"), Some("entry")),
            entry(&hex(main + 4), Some("two words"), None),
            entry("no_such_name", Some("lost"), None),
            entry(&hex(main + 8), Some("sub_1234"), None),
            entry(&hex(main + 12), None, None),
            entry(&hex(main + 16), None, Some("  ")),
            entry(&hex(main + 20), Some("_puts"), None),
        ])
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("nothing applied: 6 of 7 entries are invalid"), "{error}");
    for index in 1..=6 {
        assert!(error.contains(&format!("\nentry {index} (")), "{error}");
    }
    assert!(!error.contains("entry 0"), "{error}");
    assert!(error.contains("looks like an address") && error.contains("already names"), "{error}");
    let list = project.annotation_list();
    assert!(list.names.is_empty() && list.comments.is_empty());
    assert!(project.undo().unwrap().is_empty());
    let reopened = Session::default().open(&path, None).unwrap().annotation_list();
    assert!(reopened.names.is_empty() && reopened.comments.is_empty());
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn names_must_be_unique_within_the_batch() {
    let path = scratch_copy("duplicates");
    let project = Session::default().open(&path, None).unwrap();
    let main = project.resolve("_main").unwrap();
    let error = project
        .annotate_batch(&[entry("_main", Some("twin"), None), entry(&hex(main + 4), Some("twin"), None)])
        .unwrap_err()
        .to_string();
    assert!(error.contains(&format!("entry 1 ({:?}): \"twin\" is also given to {main:#x} by entry 0", hex(main + 4))));
    let error = project
        .annotate_batch(&[entry("_main", Some("first"), Some("a")), entry(&hex(main), Some("second"), Some("b"))])
        .unwrap_err()
        .to_string();
    assert!(error.contains(&format!("entry 0 also names {main:#x}")), "{error}");
    assert!(error.contains(&format!("entry 0 also comments {main:#x}")), "{error}");
    assert!(project.annotation_list().names.is_empty());
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn an_entry_with_several_problems_counts_once() {
    let path = scratch_copy("count");
    let project = Session::default().open(&path, None).unwrap();
    let error = project.annotate_batch(&[entry("_main", Some("two words"), Some("  "))]).unwrap_err().to_string();
    assert!(error.starts_with("nothing applied: 1 of 1 entries are invalid"), "{error}");
    assert_eq!(error.matches("\nentry 0 (").count(), 2, "{error}");
    assert!(error.contains("the comment is blank; a batch cannot remove comments"), "{error}");
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn a_batch_undoes_and_redoes_as_one_step_and_persists() {
    let path = scratch_copy("undo");
    let project = Session::default().open(&path, None).unwrap();
    let main = project.resolve("_main").unwrap();
    project.comment(main + 4, Some("kept")).unwrap();
    let result = project
        .annotate_batch(&[
            entry("_main", Some("greet"), Some("entry point")),
            entry(&hex(main + 4), Some("after_prologue"), Some("kept")),
            entry(&hex(main + 8), None, Some(" trimmed ")),
        ])
        .unwrap();
    assert_eq!(result.changed, 3);
    assert_eq!(result.entries[2].comment.as_deref(), Some("trimmed"));
    assert_eq!(project.resolve("greet").unwrap(), main);
    let again = project.annotate_batch(&[entry("greet", Some("greet"), Some("entry point"))]).unwrap();
    assert_eq!((again.changed, again.entries[0].changed), (0, false));

    let undone = project.undo().unwrap();
    assert_eq!(undone.len(), 4);
    let list = project.annotation_list();
    assert!(list.names.is_empty());
    assert_eq!(list.comments.len(), 1);
    assert_eq!(project.comment_at(main + 4).as_deref(), Some("kept"));
    assert_eq!(project.redo().unwrap().len(), 4);
    assert_eq!(project.function_name(main), "greet");

    let reopened = Session::default().open(&path, None).unwrap();
    assert_eq!(reopened.resolve("after_prologue").unwrap(), main + 4);
    assert_eq!(reopened.comment_at(main).as_deref(), Some("entry point"));
    assert_eq!(reopened.comment_at(main + 8).as_deref(), Some("trimmed"));
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn a_batch_may_hand_a_name_to_another_address_it_frees() {
    let path = scratch_copy("swap");
    let project = Session::default().open(&path, None).unwrap();
    let main = project.resolve("_main").unwrap();
    project.rename(main, Some("left")).unwrap();
    project.rename(main + 4, Some("right")).unwrap();
    project.annotate_batch(&[entry("left", Some("right"), None), entry("right", Some("left"), None)]).unwrap();
    assert_eq!((project.resolve("right").unwrap(), project.resolve("left").unwrap()), (main, main + 4));
    let error = project.annotate_batch(&[entry(&hex(main + 8), Some("left"), None)]).unwrap_err().to_string();
    assert!(error.contains(&format!("\"left\" already names {:#x}", main + 4)), "{error}");
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn oversized_batches_are_refused() {
    let path = scratch_copy("bound");
    let project = Session::default().open(&path, None).unwrap();
    let entries: Vec<_> = (0..=MAX_BATCH).map(|index| entry(&hex(0x1000 + index as u64), None, Some("x"))).collect();
    let error = project.annotate_batch(&entries).unwrap_err().to_string();
    assert!(error.contains("1001 entries; at most 1000 per call"), "{error}");
    assert!(project.annotation_list().comments.is_empty());
    let names = vec!["x".to_owned(); MAX_BATCH + 1];
    assert!(project.check_names(&names).is_err());
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn check_names_reports_validity_and_use() {
    let path = scratch_copy("check");
    let project = Session::default().open(&path, None).unwrap();
    let main = project.resolve("_main").unwrap();
    project.rename(main, Some("greet")).unwrap();
    let names: Vec<String> =
        ["greet", "_puts", "sub_10", "two words", "fresh", "0X1000"].iter().map(|name| (*name).to_owned()).collect();
    let checks = project.check_names(&names).unwrap();
    assert_eq!((checks[0].used_at, checks[0].used_by, checks[0].valid), (Some(main), Some("user"), true));
    assert_eq!(checks[1].used_by, Some("symbol"));
    assert!(checks[2].address_shaped && !checks[2].valid);
    assert!(!checks[3].valid && !checks[3].address_shaped && checks[3].problem.is_some());
    assert!(checks[4].valid && checks[4].used_at.is_none() && checks[4].problem.is_none());
    assert!(checks[5].address_shaped && !checks[5].valid);
    assert!(checks[5].problem.as_deref().is_some_and(|problem| problem.contains("looks like an address")));
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
