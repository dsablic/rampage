use std::path::PathBuf;
use std::process::Output;
use std::sync::atomic::{AtomicUsize, Ordering};

use assert_cmd::Command;
use serde_json::{Value, json};

static SERIAL: AtomicUsize = AtomicUsize::new(0);

struct Input {
    directory: PathBuf,
    path: PathBuf,
    bytes: Vec<u8>,
}

impl Input {
    fn new(names: &[Vec<u8>]) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "rampage-cli-zip32-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("input.zip");
        let bytes = zip(names);
        std::fs::write(&path, &bytes).unwrap();
        Self { directory, path, bytes }
    }

    fn unchanged(&self) {
        assert_eq!(std::fs::read(&self.path).unwrap(), self.bytes);
        assert_eq!(std::fs::read_dir(&self.directory).unwrap().count(), 1, "unexpected sidecar or extracted member");
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        std::fs::remove_file(&self.path).unwrap();
        std::fs::remove_dir(&self.directory).unwrap();
    }
}

fn zip(names: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = if names.is_empty() { vec![] } else { b"PK\x03\x04not a local header".to_vec() };
    let cd = bytes.len();
    for name in names {
        let mut record = [0; 46];
        record[..4].copy_from_slice(b"PK\x01\x02");
        record[8..10].copy_from_slice(&9u16.to_le_bytes());
        record[10..12].copy_from_slice(&8u16.to_le_bytes());
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

fn command() -> Command {
    let mut command = Command::cargo_bin("rampage").unwrap();
    command.env_remove("RAMPAGE_PACKS").env_remove("RAMPAGE_MCP_TOOLS").env("NO_COLOR", "1").write_stdin("");
    command
}

fn run(input: &Input, extra: &[&str]) -> Output {
    command().args(["binary", "archive-inventory"]).arg(&input.path).args(extra).output().unwrap()
}

fn page(output: &Output) -> Value {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stdout.len() <= 60_000);
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn canonical_archive_inventory_opens_zip_metadata_not_a_binary_and_does_not_write_anything() {
    let input = Input::new(&[b"duplicate".to_vec(), b"duplicate".to_vec(), b"../member".to_vec()]);
    assert!(rampage_loaders::Binary::open(&input.path).is_err());
    let result = page(&run(&input, &["--json", "--offset", "1", "--limit", "1", "--contains", "duplicate"]));
    assert_eq!(result["declared"], 3);
    assert_eq!(result["validated"], 3);
    assert_eq!(result["matched"], 2);
    assert_eq!(result["returned"], 1);
    assert_eq!(result["members"][0]["member_ref"]["ordinal"], 1);
    assert_eq!(result["members"][0]["encrypted"], true);
    assert_eq!(result["members"][0]["data_descriptor"], true);
    assert_eq!(result["members"][0]["compression_method"], 8);
    assert_eq!(result["more"], false);
    let report = run(&input, &[]);
    assert!(report.status.success());
    let text = String::from_utf8(report.stdout).unwrap();
    assert!(text.contains("central-directory metadata evidence"));
    assert!(text.contains("not whole-payload identity"));
    assert!(text.contains("No member/local-header offset is followed"));
    input.unchanged();
}

#[test]
fn json_pages_match_the_file_tool_and_advance_even_for_maximally_escaped_names() {
    let input = Input::new(&vec![vec![0; 1024]; 100]);
    let first = page(&run(&input, &["--json"]));
    assert!(first["returned"].as_u64().unwrap() < 100);
    assert_eq!(first["more"], true);
    let tool = rampage_api::tools::file_tools().into_iter().find(|tool| tool.name == "archive_inventory").unwrap();
    let expected = tool.call(&rampage_api::Packs::default(), json!({ "path": input.path })).unwrap();
    assert_eq!(first, expected);
    let next = first["next_offset"].as_u64().unwrap();
    assert!(next > 0);
    let second = page(&run(&input, &["--json", "--offset", &next.to_string()]));
    assert_eq!(second["members"][0]["member_ref"]["ordinal"], next);
    assert_eq!(first["archive_ref"], second["archive_ref"]);
    input.unchanged();
}

#[test]
fn unsupported_primary_image_flags_are_rejected_before_any_file_io() {
    for options in
        [vec!["--arch", "x86_64"], vec!["--image-offset", "0"], vec!["--image-offset", "0", "--image-length", "22"]]
    {
        let output = command()
            .args(["binary", "archive-inventory", "/nonexistent/rampage-archive-input"])
            .args(options)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("does not accept --arch, --image-offset or --image-length"), "{error}");
        assert!(!error.contains("No such file"));
    }
    assert!(!command().args(["archive-inventory", "/nonexistent/input.zip"]).output().unwrap().status.success());
}

#[test]
fn empty_zip_and_old_directory_inventory_and_carve_routes_remain_distinct() {
    let input = Input::new(&[]);
    assert_eq!(page(&run(&input, &["--json"]))["members"], json!([]));
    let directory = command().args(["binary", "inventory"]).arg(&input.directory).arg("--json").output().unwrap();
    assert!(directory.status.success());
    let inventory: Value = serde_json::from_slice(&directory.stdout).unwrap();
    assert_eq!(inventory["binaries"], json!([]));
    assert!(inventory.get("archive_ref").is_none());
    let carve = command().args(["binary", "carve"]).arg(&input.path).arg("--json").output().unwrap();
    assert!(carve.status.success());
    let carved: Value = serde_json::from_slice(&carve.stdout).unwrap();
    assert!(carved.get("archive_ref").is_none());
    input.unchanged();
}

#[cfg(unix)]
#[test]
fn non_utf8_native_path_json_serialization_is_a_reported_error_not_a_panic() {
    use std::os::unix::ffi::OsStringExt;
    let path = std::ffi::OsString::from_vec(b"/nonexistent/\xff.zip".to_vec());
    let output = command().args(["binary", "archive-inventory"]).arg(path).arg("--json").output().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("JSON-serializable"), "{error}");
    assert!(!error.contains("panicked"));
}
