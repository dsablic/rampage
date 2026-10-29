use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use rampage_api::annotations::{Edit, Field};
use rampage_api::{
    LedgerConfidence, LedgerEvidence, LedgerKind, LedgerQuery, LedgerRequest, LedgerStatus, MAX_LEDGER_EVIDENCE,
    MAX_LEDGER_TEXT, Session,
};

fn scratch_copy(test: &str, fixture: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("rampage-api-findings-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(fixture);
    std::fs::copy(fixtures().join(fixture), &path).unwrap();
    path
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin")
}

fn create(kind: LedgerKind, text: &str) -> LedgerRequest {
    LedgerRequest { kind: Some(kind), text: Some(text.to_owned()), ..LedgerRequest::default() }
}

fn update(id: u64) -> LedgerRequest {
    LedgerRequest { id: Some(id), ..LedgerRequest::default() }
}

fn ids(list: &rampage_api::LedgerList) -> Vec<u64> {
    list.findings.iter().map(|finding| finding.id).collect()
}

fn all(project: &rampage_api::Project) -> rampage_api::LedgerList {
    project.list_findings(&LedgerQuery::default()).unwrap()
}

#[test]
fn entries_persist_and_replay_with_stable_ids() {
    let path = scratch_copy("persist", "hello-arm64.macho");
    let project = Session::default().open(&path, None).unwrap();
    let main = project.resolve("_main").unwrap();
    let recorded = project
        .record_finding(&LedgerRequest {
            address: Some(format!("{:#x}", main + 4)),
            function: Some(format!("{:#x}", main + 8)),
            evidence: Some(vec![LedgerEvidence { tool: "decompile".into(), detail: "at=_main".into() }]),
            confidence: Some(LedgerConfidence::High),
            ..create(LedgerKind::Finding, "  main prints a greeting  ")
        })
        .unwrap();
    assert!(recorded.created && recorded.changed);
    let finding = &recorded.finding;
    assert_eq!((finding.id, finding.text.as_str(), finding.status), (1, "main prints a greeting", LedgerStatus::Open));
    assert_eq!((finding.address, finding.function), (Some(main + 4), Some(main)));
    assert_eq!(finding.function_name.as_deref(), Some("_main"));
    assert!(finding.image_sha256.is_some() && !finding.image_changed);
    assert_eq!(project.record_finding(&create(LedgerKind::Unknown, "what does x0 hold?")).unwrap().finding.id, 2);
    assert_eq!(project.record_finding(&create(LedgerKind::Question, "is this packed?")).unwrap().finding.id, 3);
    // Ledger entries are not names or comments.
    assert!(project.annotation_list().comments.is_empty());

    let reopened = Session::default().open(&path, None).unwrap();
    let list = all(&reopened);
    assert_eq!(ids(&list), [1, 2, 3]);
    assert_eq!(list.findings[0].evidence[0].tool, "decompile");
    assert_eq!(list.findings[0].confidence, Some(LedgerConfidence::High));
    assert_eq!(list.findings[0].function_name.as_deref(), Some("_main"));
    assert_eq!(reopened.record_finding(&create(LedgerKind::Finding, "next")).unwrap().finding.id, 4);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn each_call_is_one_undo_step_and_ids_are_never_reused() {
    let path = scratch_copy("undo", "hello-arm64.macho");
    let project = Session::default().open(&path, None).unwrap();
    project.record_finding(&create(LedgerKind::Unknown, "first")).unwrap();
    project.record_finding(&LedgerRequest { status: Some(LedgerStatus::Resolved), ..update(1) }).unwrap();

    let undone = project.undo().unwrap();
    assert_eq!((undone.len(), undone[0].field, undone[0].address), (1, Field::Finding, 1));
    assert_eq!(all(&project).findings[0].status, LedgerStatus::Open);
    project.undo().unwrap();
    assert!(all(&project).findings.is_empty());
    project.redo().unwrap();
    assert_eq!(all(&project).findings[0].text, "first");
    project.undo().unwrap();

    // The undone entry's id stays retired, in this process and after a reopen.
    assert_eq!(project.record_finding(&create(LedgerKind::Finding, "second")).unwrap().finding.id, 2);
    let reopened = Session::default().open(&path, None).unwrap();
    assert_eq!(ids(&all(&reopened)), [2]);
    assert_eq!(reopened.record_finding(&create(LedgerKind::Finding, "third")).unwrap().finding.id, 3);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn an_update_changes_only_the_fields_it_gives() {
    let path = scratch_copy("update", "hello-arm64.macho");
    let project = Session::default().open(&path, None).unwrap();
    let main = project.resolve("_main").unwrap();
    project
        .record_finding(&LedgerRequest {
            address: Some("_main".into()),
            confidence: Some(LedgerConfidence::Low),
            ..create(LedgerKind::Question, "who calls main?")
        })
        .unwrap();
    let resolved = project
        .record_finding(&LedgerRequest {
            status: Some(LedgerStatus::Resolved),
            resolution: Some("dyld via start".into()),
            ..update(1)
        })
        .unwrap();
    assert!(!resolved.created && resolved.changed);
    let finding = &resolved.finding;
    assert_eq!((finding.kind, finding.text.as_str()), (LedgerKind::Question, "who calls main?"));
    assert_eq!((finding.address, finding.confidence), (Some(main), Some(LedgerConfidence::Low)));
    assert_eq!(finding.resolution.as_deref(), Some("dyld via start"));

    // Repeating it changes nothing and adds no undo step: one undo reverts the update.
    let again = project.record_finding(&LedgerRequest { status: Some(LedgerStatus::Resolved), ..update(1) }).unwrap();
    assert!(!again.changed);
    project.undo().unwrap();
    assert_eq!(all(&project).findings[0].status, LedgerStatus::Open);
    // An empty resolution clears it.
    project.redo().unwrap();
    let cleared = project.record_finding(&LedgerRequest { resolution: Some(String::new()), ..update(1) }).unwrap();
    assert_eq!(cleared.finding.resolution, None);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn filters_page_and_count_per_kind() {
    let path = scratch_copy("filters", "hello-arm64.macho");
    let project = Session::default().open(&path, None).unwrap();
    let main = project.resolve("_main").unwrap();
    project
        .record_finding(&LedgerRequest { address: Some("_main".into()), ..create(LedgerKind::Finding, "A") })
        .unwrap();
    project
        .record_finding(&LedgerRequest {
            address: Some(format!("{:#x}", main + 4)),
            ..create(LedgerKind::Unknown, "Opaque constant")
        })
        .unwrap();
    project
        .record_finding(&LedgerRequest { function: Some("_main".into()), ..create(LedgerKind::Question, "Q") })
        .unwrap();
    for index in 0..5 {
        project.record_finding(&create(LedgerKind::Unknown, &format!("bulk {index}"))).unwrap();
    }
    project.record_finding(&LedgerRequest { status: Some(LedgerStatus::Resolved), ..update(2) }).unwrap();
    project.record_finding(&LedgerRequest { status: Some(LedgerStatus::Rejected), ..update(4) }).unwrap();

    let list = all(&project);
    assert_eq!((list.total, list.returned, list.next_offset, list.byte_capped), (8, 8, None, false));
    let counts: Vec<_> =
        list.counts.iter().map(|counts| (counts.kind, counts.open, counts.resolved, counts.rejected)).collect();
    assert_eq!(
        counts,
        [(LedgerKind::Finding, 1, 0, 0), (LedgerKind::Unknown, 4, 1, 1), (LedgerKind::Question, 1, 0, 0)]
    );

    let query = |query: LedgerQuery| ids(&project.list_findings(&query).unwrap());
    assert_eq!(query(LedgerQuery { kind: Some(LedgerKind::Unknown), ..LedgerQuery::default() }), [2, 4, 5, 6, 7, 8]);
    assert_eq!(query(LedgerQuery { status: Some(LedgerStatus::Open), ..LedgerQuery::default() }), [1, 3, 5, 6, 7, 8]);
    assert_eq!(query(LedgerQuery { address: Some("_main".into()), ..LedgerQuery::default() }), [1]);
    // By function: its own entries, and entries at addresses inside it.
    assert_eq!(query(LedgerQuery { function: Some(format!("{:#x}", main + 4)), ..LedgerQuery::default() }), [1, 2, 3]);
    assert_eq!(query(LedgerQuery { contains: Some("OPAQUE".into()), ..LedgerQuery::default() }), [2]);

    let page =
        project.list_findings(&LedgerQuery { offset: Some(2), limit: Some(3), ..LedgerQuery::default() }).unwrap();
    assert_eq!((ids(&page), page.total, page.offset, page.next_offset), (vec![3, 4, 5], 8, 2, Some(5)));
    let last = project.list_findings(&LedgerQuery { offset: Some(7), ..LedgerQuery::default() }).unwrap();
    assert_eq!((ids(&last), last.next_offset), (vec![8], None));
    for limit in [0, 101] {
        assert!(project.list_findings(&LedgerQuery { limit: Some(limit), ..LedgerQuery::default() }).is_err());
    }
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn malformed_requests_are_refused_and_record_nothing() {
    let path = scratch_copy("caps", "hello-arm64.macho");
    let project = Session::default().open(&path, None).unwrap();
    let evidence = |tool: &str, detail: &str| LedgerEvidence { tool: tool.into(), detail: detail.into() };
    let refused = [
        LedgerRequest { text: Some("no kind".into()), ..LedgerRequest::default() },
        LedgerRequest { kind: Some(LedgerKind::Finding), ..LedgerRequest::default() },
        create(LedgerKind::Finding, "   "),
        create(LedgerKind::Finding, &"x".repeat(MAX_LEDGER_TEXT + 1)),
        LedgerRequest {
            evidence: Some(vec![evidence("xrefs", "to=_main"); MAX_LEDGER_EVIDENCE + 1]),
            ..create(LedgerKind::Finding, "too much evidence")
        },
        LedgerRequest { evidence: Some(vec![evidence("Not A Tool", "")]), ..create(LedgerKind::Finding, "bad tool") },
        LedgerRequest {
            evidence: Some(vec![evidence("xrefs", &"d".repeat(301))]),
            ..create(LedgerKind::Finding, "long")
        },
        LedgerRequest { resolution: Some("r".repeat(1001)), ..create(LedgerKind::Finding, "long resolution") },
        LedgerRequest { address: Some("no_such_name".into()), ..create(LedgerKind::Finding, "bad address") },
        LedgerRequest { status: Some(LedgerStatus::Resolved), ..update(7) },
    ];
    for request in &refused {
        assert!(project.record_finding(request).is_err(), "{request:?}");
    }
    assert!(all(&project).findings.is_empty());
    assert!(project.undo().unwrap().is_empty());
    // The longest allowed text is accepted whole.
    let longest = project.record_finding(&create(LedgerKind::Finding, &"x".repeat(MAX_LEDGER_TEXT))).unwrap();
    assert_eq!(longest.finding.text.len(), MAX_LEDGER_TEXT);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn concurrent_writers_never_lose_or_duplicate_entries() {
    let path = scratch_copy("concurrent", "hello-arm64.macho");
    // Two sessions are two independent writers of one log, as two processes are.
    let first = Session::default().open(&path, None).unwrap();
    let second = Session::default().open(&path, None).unwrap();
    let recorded: Vec<Vec<u64>> = std::thread::scope(|scope| {
        let writers: Vec<_> = [(&first, "first"), (&second, "second")]
            .into_iter()
            .map(|(project, writer)| {
                scope.spawn(move || {
                    (0..20)
                        .map(|index| {
                            let text = format!("{writer} {index}");
                            project.record_finding(&create(LedgerKind::Finding, &text)).unwrap().finding.id
                        })
                        .collect()
                })
            })
            .collect();
        writers.into_iter().map(|writer| writer.join().unwrap()).collect()
    });
    let mut every: Vec<u64> = recorded.concat();
    every.sort_unstable();
    assert_eq!(every, (1..=40).collect::<Vec<_>>());
    for project in [&first, &second] {
        project.refresh_annotations().unwrap();
        let list = project.list_findings(&LedgerQuery { limit: Some(100), ..LedgerQuery::default() }).unwrap();
        assert_eq!(ids(&list), (1..=40).collect::<Vec<_>>());
    }
    // Each writer undoes only its own last entry.
    let undone = first.undo().unwrap();
    assert_eq!(undone[0].address, *recorded[0].last().unwrap());
    let reopened = Session::default().open(&path, None).unwrap();
    assert_eq!(all(&reopened).total, 39);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

/// Records an entry while another process holds the log's lock and logs entry 1 before letting go: the new entry
/// must take the next id, not the one it would have picked from what it read before waiting.
#[test]
fn an_id_is_chosen_under_the_log_lock() {
    let path = scratch_copy("lock", "hello-arm64.macho");
    let project = Session::default().open(&path, None).unwrap();
    let log = PathBuf::from(format!("{}.rampage", path.display()));
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(format!("{}.lock", log.display()))
        .unwrap();
    lock.lock().unwrap();
    let id = std::thread::scope(|scope| {
        let recording = scope.spawn(|| project.record_finding(&create(LedgerKind::Unknown, "mine")).unwrap());
        std::thread::sleep(std::time::Duration::from_millis(300));
        let foreign = Edit {
            field: Field::Finding,
            address: 1,
            value: Some(r#"{"kind":"finding","status":"open","text":"theirs"}"#.to_owned()),
            previous: None,
        };
        let line = format!("{}\n", serde_json::to_string(&foreign).unwrap());
        OpenOptions::new().create(true).append(true).open(&log).unwrap().write_all(line.as_bytes()).unwrap();
        lock.unlock().unwrap();
        recording.join().unwrap().finding.id
    });
    assert_eq!(id, 2);
    let list = all(&project);
    assert_eq!(list.findings.iter().map(|finding| finding.text.as_str()).collect::<Vec<_>>(), ["theirs", "mine"]);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn unreadable_entries_are_reported_not_dropped_silently() {
    let path = scratch_copy("unreadable", "hello-arm64.macho");
    let log = PathBuf::from(format!("{}.rampage", path.display()));
    let broken = Edit { field: Field::Finding, address: 5, value: Some("not json".to_owned()), previous: None };
    std::fs::write(&log, format!("{}\n", serde_json::to_string(&broken).unwrap())).unwrap();
    let project = Session::default().open(&path, None).unwrap();
    let list = all(&project);
    assert!(list.findings.is_empty());
    assert!(list.warnings.iter().any(|warning| warning.contains("could not be read") && warning.contains('5')));
    assert!(project.record_finding(&LedgerRequest { status: Some(LedgerStatus::Resolved), ..update(5) }).is_err());
    assert_eq!(project.record_finding(&create(LedgerKind::Finding, "after")).unwrap().finding.id, 6);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

fn replace(path: &Path, fixture: &str) {
    let replacement = path.with_extension("replacement");
    std::fs::copy(fixtures().join(fixture), &replacement).unwrap();
    std::fs::rename(&replacement, path).unwrap();
}

#[test]
fn entries_made_on_another_build_are_kept_and_flagged() {
    let path = scratch_copy("rebuilt", "hello-x64.elf");
    let project = Session::default().open(&path, None).unwrap();
    project
        .record_finding(&LedgerRequest { address: Some("0x1000".into()), ..create(LedgerKind::Finding, "built once") })
        .unwrap();
    project.record_finding(&create(LedgerKind::Question, "nowhere in particular")).unwrap();
    assert!(all(&project).findings.iter().all(|finding| !finding.image_changed));

    replace(&path, "hello-x64-dyn.elf");
    let rebuilt = Session::default().open(&path, None).unwrap();
    let list = all(&rebuilt);
    assert_eq!(ids(&list), [1, 2]);
    assert!(list.findings.iter().all(|finding| finding.image_changed));
    assert!(list.warnings.iter().any(|warning| warning.contains("different image")), "{:?}", list.warnings);
    // Re-anchoring an entry on this build clears its flag; a status change alone does not.
    let moved = rebuilt.record_finding(&LedgerRequest { address: Some("0x1004".into()), ..update(1) }).unwrap();
    assert!(!moved.finding.image_changed);
    let resolved =
        rebuilt.record_finding(&LedgerRequest { status: Some(LedgerStatus::Resolved), ..update(2) }).unwrap();
    assert!(resolved.finding.image_changed);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
