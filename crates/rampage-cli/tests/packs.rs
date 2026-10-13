use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn rampage() -> Command {
    let mut command = Command::cargo_bin("rampage").unwrap();
    command.env_remove("RAMPAGE_PACKS");
    command
}

/// A pack directory removed on drop.
struct Pack(PathBuf);

impl Pack {
    fn new(name: &str, contents: &str) -> Self {
        let path = std::env::temp_dir().join(format!("rampage-cli-pack-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        let manifest = format!(
            "name = \"{name}\"\nversion = \"0.2.0\"\nlicense = \"CC0-1.0\"\nsource = \"https://example.com/{name}\"\n\
             description = \"CLI test pack\"\n{contents}"
        );
        std::fs::write(path.join("rampage-pack.toml"), manifest).unwrap();
        Self(path)
    }

    fn write(&self, relative: &str, text: &str) {
        std::fs::write(self.0.join(relative), text).unwrap();
    }

    fn arg(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for Pack {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn yara_pack(name: &str) -> Pack {
    let pack = Pack::new(name, "[[contents]]\nkind = \"yara\"\npath = \"pe.yar\"\n");
    pack.write("pe.yar", "rule pack_pe : format { strings: $mz = \"MZ\" condition: $mz at 0 }");
    pack
}

#[test]
fn yara_runs_pack_rules_without_rules_of_its_own() {
    let pack = yara_pack("yara");
    rampage()
        .args(["yara", "--pack", pack.arg()])
        .arg(fixture("hello-x64.exe"))
        .assert()
        .success()
        .stdout(contains("pack_pe [format] (1 string matches)"));
    rampage()
        .env("RAMPAGE_PACKS", pack.arg())
        .arg("yara")
        .arg(fixture("hello-x64.exe"))
        .assert()
        .success()
        .stdout(contains("pack_pe [format]"));
    rampage().arg("yara").arg(fixture("hello-x64.exe")).assert().failure().stderr(contains("no YARA rules"));
}

#[test]
fn a_pack_in_both_the_flag_and_the_environment_loads_once_without_warning() {
    let pack = yara_pack("both");
    rampage()
        .env("RAMPAGE_PACKS", pack.arg())
        .args(["yara", "--pack", pack.arg()])
        .arg(fixture("hello-x64.exe"))
        .assert()
        .success()
        .stdout(contains("pack_pe [format]"))
        .stderr("");
}

#[test]
fn packs_list_shows_flag_then_environment_packs_then_the_builtin_pack() {
    let flagged = yara_pack("flagged");
    let ambient = yara_pack("ambient");
    let output = rampage()
        .env("RAMPAGE_PACKS", ambient.arg())
        .args(["--json", "packs", "list", "--pack", flagged.arg()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let packs: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let names: Vec<&str> = packs.as_array().unwrap().iter().map(|pack| pack["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["flagged", "ambient", "rampage-builtin"]);
    assert_eq!(packs[2]["license"], "Apache-2.0");
    assert_eq!(packs[0]["license"], "CC0-1.0");
    assert_eq!(packs[0]["source"], "https://example.com/flagged");
    assert_eq!(packs[0]["contents"][0]["status"], "loaded");

    rampage()
        .args(["packs", "list", "--pack", flagged.arg()])
        .assert()
        .success()
        .stdout(contains("rampage-builtin").and(contains("flagged 0.2.0 (CC0-1.0)")))
        .stdout(contains("loaded: yara pe.yar: 1 YARA rule files"));
}

#[test]
fn packs_check_fails_on_a_content_that_does_not_load_and_analysis_warns() {
    let pack = Pack::new(
        "broken",
        "[[contents]]\nkind = \"yara\"\npath = \"broken.yar\"\n[[contents]]\nkind = \"peid\"\npath = \"ok.txt\"\n",
    );
    pack.write("broken.yar", "rule broken {");
    pack.write("ok.txt", "[Pack MZ]\nsignature = 4D 5A 78 00 01 00 00 00 04\nep_only = false\n");
    rampage()
        .args(["packs", "check", pack.arg()])
        .assert()
        .failure()
        .stdout(contains("error: yara broken.yar: YARA rules:").and(contains("loaded: peid ok.txt: 1 PeID")))
        .stderr(contains("does not fully load"));
    rampage()
        .args(["detect", "--pack", pack.arg()])
        .arg(fixture("hello-x64.exe"))
        .assert()
        .success()
        .stdout(contains("] Pack MZ ("))
        .stderr(contains("rampage: warning: pack ").and(contains("yara broken.yar")));
    // A command that consults no heuristic database does not load packs, so it has nothing to warn about.
    rampage().args(["info", "--pack", pack.arg()]).arg(fixture("hello-x64.exe")).assert().success().stderr("");

    let valid = yara_pack("valid");
    rampage().args(["packs", "check", valid.arg()]).assert().success();
}

#[test]
fn identify_without_the_bundled_database_accepts_a_pack_database_alone() {
    let pack = Pack::new("sigs", "[[contents]]\nkind = \"signatures\"\npath = \"x86_64.json\"\n");
    pack.write("x86_64.json", r#"{"arch":"x86_64","scheme":2,"entries":{}}"#);
    rampage()
        .args(["identify", "--no-bundled", "--pack", pack.arg()])
        .arg(fixture("hello-x64.elf"))
        .assert()
        .success()
        .stdout(contains("0 matched, 0 applied"));
    rampage()
        .args(["identify", "--no-bundled", "--pack", pack.arg()])
        .arg(fixture("hello-arm64.macho"))
        .assert()
        .failure()
        .stderr(contains("needs a signature database or a pack with one for this architecture"));
}
