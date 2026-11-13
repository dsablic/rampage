use std::path::PathBuf;

use rampage_loaders::Binary;

use super::*;

fn project() -> Project {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
    Project::with_annotations(Binary::open(&path).unwrap(), Annotations::in_memory())
}

fn comment(at: u64, value: &str) -> Planned {
    Planned {
        field: Field::Comment,
        old: at,
        new: Some(at),
        value: value.to_owned(),
        method: Some(MatchMethod::ExactBytes),
        via_reference: false,
        status: TransferStatus::Transfer,
        reason: None,
    }
}

#[test]
fn apply_refuses_a_target_edited_after_matching_and_records_provenance_first() {
    let target = project();
    let at = target.resolve("main").unwrap();
    let planned = [comment(at, "from the old build")];

    // Someone comments the target after the preview: the write is refused, nothing is overwritten.
    target.comment(at, Some("edited meanwhile")).unwrap();
    let refused = target.apply_transfer(&target, "old.elf", &planned, 0.7).unwrap_err();
    assert!(refused.to_string().contains("changed after matching"), "{refused}");
    assert_eq!(target.comment_at(at).as_deref(), Some("edited meanwhile"));
    assert!(target.annotations().findings().is_empty());

    // Unchanged since matching: written with the provenance entry in the same (first) batch.
    target.comment(at, None).unwrap();
    let (applied, written) = target.apply_transfer(&target, "old.elf", &planned, 0.7).unwrap();
    assert_eq!((applied.batches, applied.batches_needed, written, applied.changed), (1, 1, 1, 1));
    assert!(applied.provenance_finding.is_some() && applied.error.is_none());
    assert_eq!(target.comment_at(at).as_deref(), Some("from the old build"));
    // One undo takes both back.
    target.undo().unwrap();
    assert_eq!(target.comment_at(at), None);
    assert!(target.annotations().findings().is_empty());
}
