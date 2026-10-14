#[path = "../../../tests/fixtures/pdb/support.rs"]
#[allow(dead_code)]
mod support;

use std::path::Path;
use std::process::Output;

use assert_cmd::Command;
use rampage_api::{Project, Session};
use serde_json::{Value, json};
use support::{TempFiles, fixture, module_stream, rsds_offset, stream_offset};

fn command() -> Command {
    let mut command = Command::cargo_bin("rampage").unwrap();
    command
        .env_remove("RAMPAGE_PACKS")
        .env_remove("RAMPAGE_MCP_TOOLS")
        .env_remove("CLICOLOR_FORCE")
        .env("NO_COLOR", "1")
        .write_stdin("");
    command
}

fn import(path: &Path, pdb: &Path, extra: &[&str]) -> Output {
    command().args(["type", "import-pdb-names"]).arg(path).arg("--pdb").arg(pdb).args(extra).output().unwrap()
}

fn receipt(output: &Output, success: bool) -> Value {
    assert_eq!(output.status.success(), success, "{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stdout.len() <= 60_000, "{}", output.stdout.len());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn open(path: &Path) -> std::sync::Arc<Project> {
    Session::default().open(path, None).unwrap()
}

#[test]
fn preview_preserves_annotation_bytes_and_one_detail_apply_persists_one_whole_atomic_batch_without_durable_undo() {
    let files = TempFiles::new();
    let path = files.write("whole.exe", &std::fs::read(fixture("fixture.exe")).unwrap());
    let log = path.with_file_name("whole.exe.rampage");
    let project = open(&path);
    project.comment(0x140001020, Some("keep this comment")).unwrap();
    let before = std::fs::read(&log).unwrap();
    let arguments = json!({ "pdb": fixture("fixture.pdb"), "apply": false, "offset": 0, "limit": 1 });
    let (expected, failed) =
        rampage_api::tools::call(&rampage_api::tools::tools(), &project, "import_pdb_names", arguments);
    assert!(!failed, "{expected}");
    let output = import(&path, &fixture("fixture.pdb"), &["--json", "--limit", "1"]);
    let preview = receipt(&output, true);
    assert_eq!(output.stdout, expected.as_bytes());
    assert_eq!(preview["status"], "preview");
    assert_eq!(preview["apply_requested"], false);
    assert_eq!(preview["whole_apply_succeeded"], false);
    assert_eq!(preview["applied_total"], 0);
    assert!(preview["identity"]["guid"].is_string());
    assert!(preview["identity"]["age"].as_u64().unwrap() > 0);
    assert_eq!(preview["details"].as_array().unwrap().len(), 1);
    assert_eq!(preview["more"], true);
    assert_eq!(preview["next_offset"], 1);
    assert_eq!(std::fs::read(&log).unwrap(), before);
    assert!(open(&path).annotation_list().names.is_empty());

    let applied = receipt(&import(&path, &fixture("fixture.pdb"), &["--json", "--apply", "--limit", "1"]), true);
    assert_eq!(applied["whole_apply_succeeded"], true);
    assert_eq!(applied["status"], "applied");
    assert_eq!(applied["identity"], preview["identity"]);
    assert_eq!(applied["preview_total"], preview["preview_total"]);
    assert_eq!(applied["applied_total"], 2);
    assert_eq!(applied["details"].as_array().unwrap().len(), 1);
    let persisted = std::fs::read(&log).unwrap();
    let appended = std::str::from_utf8(persisted.strip_prefix(before.as_slice()).unwrap()).unwrap();
    let records: Vec<Value> = appended.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["edits"], 2);
    assert!(records[0]["batch"].is_string());
    assert!(records[1..].iter().all(|record| record["batch"] == records[0]["batch"]));
    let reopened = open(&path);
    assert_eq!(reopened.resolve("pdb_mix").unwrap(), 0x140001000);
    assert_eq!(reopened.resolve("pdb_local").unwrap(), 0x140001020);
    assert_eq!(reopened.comment_at(0x140001020).as_deref(), Some("keep this comment"));
    assert!(reopened.undo().unwrap().is_empty());
    assert_eq!(reopened.resolve("pdb_mix").unwrap(), 0x140001000);
    assert_eq!(reopened.resolve("pdb_local").unwrap(), 0x140001020);
    assert_eq!(std::fs::read(&log).unwrap(), persisted);
    assert_eq!(open(&path).annotation_list().names.len(), 2);
    assert_eq!(open(&path).comment_at(0x140001020).as_deref(), Some("keep this comment"));
}

#[test]
fn an_out_of_range_detail_page_still_applies_all_eligible_names_and_preserves_existing_labels() {
    let files = TempFiles::new();
    let path = files.write("preserved.exe", &std::fs::read(fixture("fixture.exe")).unwrap());
    let project = open(&path);
    project.rename(0x140001000, Some("user_mix")).unwrap();
    let offset = usize::MAX.to_string();
    let result = receipt(
        &import(&path, &fixture("fixture.pdb"), &["--json", "--apply", "--offset", &offset, "--limit", "1"]),
        true,
    );
    assert_eq!(result["whole_apply_succeeded"], true);
    assert_eq!(result["applied_total"], 1);
    assert_eq!(result["details"], json!([]));
    assert_eq!(result["more"], false);
    assert_eq!(result["next_offset"], Value::Null);
    let reopened = open(&path);
    assert_eq!(reopened.function_name(0x140001000), "user_mix");
    assert_eq!(reopened.resolve("pdb_local").unwrap(), 0x140001020);
    assert_eq!(reopened.function_name(0x140001030), "pdb_export");
    assert_eq!(reopened.function_name(reopened.binary.entry.unwrap()), "entry");
    let log = path.with_file_name("preserved.exe.rampage");
    let persisted = std::fs::read(&log).unwrap();
    assert!(reopened.undo().unwrap().is_empty());
    assert_eq!(reopened.function_name(0x140001000), "user_mix");
    assert_eq!(reopened.resolve("pdb_local").unwrap(), 0x140001020);
    assert_eq!(std::fs::read(&log).unwrap(), persisted);
    assert_eq!(open(&path).resolve("pdb_local").unwrap(), 0x140001020);
}

#[test]
fn mismatched_guid_and_malformed_explicit_pdb_inputs_return_failure_receipts_without_partial_edits() {
    let files = TempFiles::new();
    let image = std::fs::read(fixture("fixture.exe")).unwrap();
    let mut mismatch = image.clone();
    mismatch[rsds_offset(&image) + 4] ^= 1;
    let pdb = std::fs::read(fixture("fixture.pdb")).unwrap();
    let truncated = files.write("truncated.pdb", &pdb[..pdb.len() - 1]);
    let garbage = files.write("garbage.pdb", b"not a PDB");
    let mut ambiguous = pdb.clone();
    let start = stream_offset(&pdb, module_stream(&pdb), 0);
    let local = pdb[start..start + 1024].windows(10).position(|name| name == b"pdb_local\0").unwrap();
    ambiguous[start + local..start + local + 10].copy_from_slice(b"pdb_mix\0\0\0");
    let ambiguous = files.write("ambiguous.pdb", &ambiguous);
    let missing = truncated.with_file_name("missing.pdb");
    for (index, (image, pdb)) in [
        (&mismatch, fixture("fixture.pdb")),
        (&image, truncated),
        (&image, garbage),
        (&image, ambiguous),
        (&image, missing),
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("rejected-{index}.exe");
        let path = files.write(&name, image);
        let project = open(&path);
        project.rename(0x140001020, Some("keep_user_local")).unwrap();
        project.comment(0x140001000, Some("keep comment")).unwrap();
        let log = path.with_file_name(format!("{name}.rampage"));
        let before = std::fs::read(&log).unwrap();
        for apply in [false, true] {
            let extra = if apply { &["--json", "--apply"][..] } else { &["--json"][..] };
            let rejected = receipt(&import(&path, &pdb, extra), false);
            assert_eq!(rejected["ok"], false);
            assert_eq!(rejected["status"], "rejected");
            assert_eq!(rejected["apply_requested"], apply);
            assert_eq!(rejected["whole_apply_succeeded"], false);
            assert_eq!(rejected["applied_total"], 0);
            assert!(rejected["error"].is_string());
            if index == 0 {
                assert!(rejected["error"].as_str().unwrap().contains("GUID/age"), "{rejected}");
            }
            assert_eq!(std::fs::read(&log).unwrap(), before);
            assert!(open(&path).resolve("pdb_mix").is_err());
            assert_eq!(open(&path).resolve("keep_user_local").unwrap(), 0x140001020);
        }
    }
}

#[test]
fn invalid_cli_arguments_do_not_open_or_edit_existing_annotations() {
    let files = TempFiles::new();
    let path = files.write("invalid.exe", &std::fs::read(fixture("fixture.exe")).unwrap());
    open(&path).rename(0x140001020, Some("keep_user_local")).unwrap();
    let log = path.with_file_name("invalid.exe.rampage");
    let before = std::fs::read(&log).unwrap();
    let missing_pdb =
        command().args(["type", "import-pdb-names"]).arg(&path).args(["--json", "--apply"]).output().unwrap();
    assert_eq!(missing_pdb.status.code(), Some(2));
    assert!(missing_pdb.stdout.is_empty());
    assert_eq!(std::fs::read(&log).unwrap(), before);
    for invalid in [
        &["--limit", "0"][..],
        &["--limit", "1001"][..],
        &["--limit", "18446744073709551616"][..],
        &["--offset", "18446744073709551616"][..],
        &["--arch", "invalid-architecture"][..],
    ] {
        let extra: Vec<_> = ["--json", "--apply"].into_iter().chain(invalid.iter().copied()).collect();
        let output = import(&path, &fixture("fixture.pdb"), &extra);
        assert_eq!(output.status.code(), Some(2), "{invalid:?}");
        assert!(output.stdout.is_empty(), "{invalid:?}");
        assert_eq!(std::fs::read(&log).unwrap(), before);
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_explicit_pdb_paths_return_bounded_rejection_receipts_before_project_io() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let files = TempFiles::new();
    let path = files.write("path-encoding.exe", &std::fs::read(fixture("fixture.exe")).unwrap());
    let project = open(&path);
    project.rename(0x140001020, Some("keep_user_local")).unwrap();
    project.comment(0x140001000, Some("keep comment")).unwrap();
    let log = path.with_file_name("path-encoding.exe.rampage");
    let before = std::fs::read(&log).unwrap();
    let missing_file = path.with_file_name("missing.exe");
    for (name, exists) in [(b"missing-\xff.pdb".as_slice(), false), (b"existing-\xff.pdb".as_slice(), true)] {
        let pdb = path.with_file_name(OsString::from_vec(name.to_vec()));
        if exists {
            match std::fs::write(&pdb, std::fs::read(fixture("fixture.pdb")).unwrap()) {
                #[cfg(target_os = "macos")]
                Err(error) if error.raw_os_error() == Some(92) => {
                    // macOS filesystems can reject non-UTF-8 names with EILSEQ before the CLI runs.
                    continue;
                }
                result => result.unwrap(),
            }
        }
        for input in [&path, &missing_file] {
            for apply in [false, true] {
                let extra = if apply { &["--json", "--apply"][..] } else { &["--json"][..] };
                let output = import(input, &pdb, extra);
                assert_eq!(output.status.code(), Some(1), "{}", String::from_utf8_lossy(&output.stderr));
                assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
                let rejected = receipt(&output, false);
                assert_eq!(rejected["status"], "rejected");
                assert_eq!(rejected["apply_requested"], apply);
                assert_eq!(rejected["whole_apply_succeeded"], false);
                assert_eq!(rejected["applied_total"], 0);
                assert!(rejected["error"].as_str().unwrap().contains("PDB path cannot be represented as UTF-8"));
                assert_eq!(std::fs::read(&log).unwrap(), before);
                assert!(!missing_file.with_file_name("missing.exe.rampage").exists());
                let unchanged = open(&path);
                assert_eq!(unchanged.resolve("keep_user_local").unwrap(), 0x140001020);
                assert!(unchanged.resolve("pdb_mix").is_err());
                assert_eq!(unchanged.comment_at(0x140001000).as_deref(), Some("keep comment"));
            }
        }
    }
}

#[test]
fn valid_unicode_file_and_pdb_paths_still_preview_and_apply_all_eligible_names() {
    let files = TempFiles::new();
    let pdb = files.write("débogage.pdb", &std::fs::read(fixture("fixture.pdb")).unwrap());
    let path = files.write("exécutable.exe", &std::fs::read(fixture("fixture.exe")).unwrap());
    let preview = receipt(&import(&path, &pdb, &["--json", "--limit", "1"]), true);
    assert_eq!(preview["status"], "preview");
    assert!(open(&path).annotation_list().names.is_empty());
    let applied = receipt(&import(&path, &pdb, &["--json", "--apply", "--limit", "1"]), true);
    assert_eq!(applied["whole_apply_succeeded"], true);
    assert_eq!(applied["applied_total"], 2);
    assert_eq!(applied["identity"], preview["identity"]);
    assert_eq!(open(&path).resolve("pdb_mix").unwrap(), 0x140001000);
    assert_eq!(open(&path).resolve("pdb_local").unwrap(), 0x140001020);
}

#[cfg(target_os = "linux")]
#[test]
fn native_non_utf8_file_paths_still_import_from_valid_unicode_pdb_paths() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let files = TempFiles::new();
    let pdb = files.write("débogage.pdb", &std::fs::read(fixture("fixture.pdb")).unwrap());
    let path = pdb.with_file_name(OsString::from_vec(b"native-\xff.exe".to_vec()));
    std::fs::write(&path, std::fs::read(fixture("fixture.exe")).unwrap()).unwrap();
    let preview = receipt(&import(&path, &pdb, &["--json", "--limit", "1"]), true);
    assert_eq!(preview["status"], "preview");
    assert!(open(&path).annotation_list().names.is_empty());
    let applied = receipt(&import(&path, &pdb, &["--json", "--apply", "--limit", "1"]), true);
    assert_eq!(applied["whole_apply_succeeded"], true);
    assert_eq!(applied["applied_total"], 2);
    assert_eq!(applied["identity"], preview["identity"]);
    assert_eq!(open(&path).resolve("pdb_mix").unwrap(), 0x140001000);
    assert_eq!(open(&path).resolve("pdb_local").unwrap(), 0x140001020);
}

#[test]
fn image_selection_and_arch_aliases_apply_only_to_file_and_use_the_existing_sidecar_identity() {
    let files = TempFiles::new();
    let image = std::fs::read(fixture("fixture.exe")).unwrap();
    let whole = files.write("whole.exe", &image);
    let normalized = receipt(
        &import(&whole, &fixture("fixture.pdb"), &["--json", "--arch", "amd64", "--image-offset", "0", "--apply"]),
        true,
    );
    assert_eq!(normalized["applied_total"], 2);
    assert!(whole.with_file_name("whole.exe.rampage").is_file());
    assert!(!whole.with_file_name("whole.exe@0x0.rampage-image").exists());
    assert_eq!(open(&whole).resolve("pdb_mix").unwrap(), 0x140001000);

    let mut container = vec![0; 0x25];
    container.extend_from_slice(&image);
    container.extend_from_slice(b"not part of the selected image");
    let embedded = files.write("container.bin", &container);
    let length = image.len().to_string();
    let output = command()
        .args(["--json", "type", "--arch", "x64", "import-pdb-names"])
        .arg(&embedded)
        .args(["--image-offset", "0x25", "--image-length", &length, "--pdb"])
        .arg(fixture("fixture.pdb"))
        .args(["--apply", "--limit", "1"])
        .output()
        .unwrap();
    let result = receipt(&output, true);
    assert_eq!(result["identity"], normalized["identity"]);
    assert_eq!(result["applied_total"], 2);
    let reloaded = Session::default()
        .open_at(&embedded, None, Some(rampage_loaders::ImageAt::new(0x25, Some(image.len() as u64))))
        .unwrap();
    assert_eq!(reloaded.resolve("pdb_mix").unwrap(), 0x140001000);
    assert_eq!(reloaded.resolve("pdb_local").unwrap(), 0x140001020);
    assert!(!embedded.with_file_name("container.bin.rampage").exists());
    assert!(embedded.with_file_name(format!("container.bin@0x25+{:#x}.rampage-image", image.len())).is_file());
}

#[test]
fn human_output_distinguishes_preview_whole_apply_and_rejection_and_pages_only_details() {
    let files = TempFiles::new();
    let path = files.write("human.exe", &std::fs::read(fixture("fixture.exe")).unwrap());
    let preview = import(&path, &fixture("fixture.pdb"), &["--limit", "1"]);
    assert!(preview.status.success(), "{}", String::from_utf8_lossy(&preview.stderr));
    let text = String::from_utf8(preview.stdout).unwrap();
    for phrase in ["PDB identity: GUID", "age", "preview only", "annotations unchanged", "0 applied", "--offset 1"] {
        assert!(text.contains(phrase), "{phrase}: {text}");
    }
    assert!(open(&path).annotation_list().names.is_empty());
    let applied = import(&path, &fixture("fixture.pdb"), &["--apply", "--limit", "1"]);
    assert!(applied.status.success(), "{}", String::from_utf8_lossy(&applied.stderr));
    let text = String::from_utf8(applied.stdout).unwrap();
    for phrase in ["whole apply succeeded", "one atomic annotation batch", "2 applied", "details do not select writes"]
    {
        assert!(text.contains(phrase), "{phrase}: {text}");
    }
    assert!(!text.contains("undoable"), "{text}");
    let missing = path.with_file_name("missing.pdb");
    let rejected = import(&path, &missing, &["--apply"]);
    assert_eq!(rejected.status.code(), Some(1));
    let text = String::from_utf8(rejected.stdout).unwrap();
    assert!(text.contains("whole apply did not succeed"), "{text}");
    assert!(text.contains("error:"), "{text}");
    assert_eq!(open(&path).annotation_list().names.len(), 2);
}
