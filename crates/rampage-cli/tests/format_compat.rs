//! Data pack and `.rpack` formats pinned by committed fixtures (docs/stability.md, docs/data-packs.md): the
//! `compat-v1` pack (YARA, constants and PeID contents) and an archive of it that rampage 0.1.0 exported. Every
//! later build must load the pack and import the archive; manifests and archives of a later format 1 load with
//! warnings, and a newer format major is refused naming the version.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::str::contains;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn rampage() -> Command {
    let mut command = Command::cargo_bin("rampage").unwrap();
    command.env_remove("RAMPAGE_PACKS");
    command
}

/// A fresh directory removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("rampage-format-compat-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A copy of the `compat-v1` pack in `scratch`, with its manifest changed by `change`.
fn pack_copy(scratch: &Scratch, change: impl FnOnce(String) -> String) -> PathBuf {
    let source = fixtures().join("packs/compat-v1");
    let copy = scratch.0.join("compat-v1");
    std::fs::create_dir_all(&copy).unwrap();
    for entry in std::fs::read_dir(&source).unwrap() {
        let path = entry.unwrap().path();
        std::fs::copy(&path, copy.join(path.file_name().unwrap())).unwrap();
    }
    let manifest = copy.join("rampage-pack.toml");
    let text = std::fs::read_to_string(&manifest).unwrap();
    std::fs::write(&manifest, change(text)).unwrap();
    copy
}

fn json(output: &[u8]) -> serde_json::Value {
    serde_json::from_slice(output).unwrap()
}

#[test]
fn the_committed_pack_loads_and_its_0_1_0_archive_imports() {
    let pack = fixtures().join("packs/compat-v1");
    let checked = rampage().args(["--json", "pack", "check"]).arg(&pack).assert().success();
    let checked = json(&checked.get_output().stdout);
    let statuses: Vec<&str> =
        checked["contents"].as_array().unwrap().iter().map(|content| content["status"].as_str().unwrap()).collect();
    assert_eq!(statuses, ["loaded", "loaded", "loaded"]);
    assert!(checked.get("warnings").is_none(), "{checked}");
    rampage()
        .args(["binary", "scan-yara", "--pack"])
        .arg(&pack)
        .arg(fixtures().join("bin/hello-x64.exe"))
        .assert()
        .success();

    let scratch = Scratch::new("legacy");
    let archive = fixtures().join("packs/compat-v1-rampage-0.1.0.rpack");
    let destination = scratch.0.join("imported");
    let imported =
        rampage().args(["--json", "pack", "import"]).arg(&archive).arg("--into").arg(&destination).assert().success();
    let imported = json(&imported.get_output().stdout);
    assert_eq!(imported["manifest"]["exported_by"], "rampage 0.1.0");
    assert_eq!(imported["manifest"]["rampage_version"]["max_exclusive"], "0.2.0");
    for file in ["rampage-pack.toml", "pe.yar", "constants.json", "userdb.txt"] {
        assert_eq!(std::fs::read(destination.join(file)).unwrap(), std::fs::read(pack.join(file)).unwrap(), "{file}");
    }
    rampage().args(["pack", "check"]).arg(&destination).assert().success();

    // A fresh export of the same pack declares its format and minimum rampage, with no upper bound.
    let exported = scratch.0.join("fresh.rpack");
    let fresh = rampage().args(["--json", "pack", "export"]).arg(&pack).arg("-o").arg(&exported).assert().success();
    let fresh = json(&fresh.get_output().stdout);
    assert_eq!(fresh["manifest"]["format_version"], 1);
    assert!(fresh["manifest"]["min_rampage_version"].is_string(), "{fresh}");
    assert!(fresh["manifest"].get("rampage_version").is_none(), "{fresh}");
}

#[test]
fn a_later_format_1_manifest_loads_with_warnings_and_a_newer_major_is_refused() {
    let scratch = Scratch::new("manifest");
    let later = pack_copy(&scratch, |text| {
        format!(
            "format_version = 1\nhomepage = \"https://example.com\"\n{}\n[[contents]]\nkind = \"sigma\"\npath = \
             \"pe.yar\"\nlevel = 3\n",
            text.replace("kind = \"yara\"", "kind = \"yara\"\nnamespace = \"later\"")
        )
    });
    let checked = rampage().args(["--json", "pack", "check"]).arg(&later).assert().failure();
    let checked = json(&checked.get_output().stdout);
    let warnings = checked["warnings"].to_string();
    assert!(warnings.contains("homepage"), "{warnings}");
    assert!(warnings.contains("namespace") && warnings.contains("level"), "{warnings}");
    let contents = checked["contents"].as_array().unwrap();
    assert_eq!(contents.len(), 4);
    assert!(contents[..3].iter().all(|content| content["status"] == "loaded"), "{checked}");
    assert_eq!((contents[3]["kind"].as_str(), contents[3]["status"].as_str()), (Some("sigma"), Some("unsupported")));
    // Loaded as a pack, its known contents work and the problems reach the analysis.
    rampage()
        .args(["binary", "scan-yara", "--pack"])
        .arg(&later)
        .arg(fixtures().join("bin/hello-x64.exe"))
        .assert()
        .success()
        .stdout(contains("compat_pe"))
        .stderr(contains("does not know were ignored: homepage"));

    let scratch = Scratch::new("major");
    let newer = pack_copy(&scratch, |text| format!("format_version = 2\n{text}"));
    rampage()
        .args(["pack", "check"])
        .arg(&newer)
        .assert()
        .failure()
        .stdout(contains("format_version 2 is newer than this rampage reads (1)"));
}

#[test]
fn a_constants_file_of_a_newer_major_is_refused_naming_it() {
    let scratch = Scratch::new("constants");
    let copy = pack_copy(&scratch, |text| text);
    let path = Path::new(&copy).join("constants.json");
    let text = std::fs::read_to_string(&path).unwrap().replacen('{', "{ \"format_version\": 2,", 1);
    std::fs::write(&path, text).unwrap();
    rampage()
        .args(["pack", "check"])
        .arg(&copy)
        .assert()
        .failure()
        .stdout(contains("constants format_version 2 is newer than this rampage reads (1)"));
}
