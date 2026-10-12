use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn rampage(args: &[&str], file: &str) -> assert_cmd::assert::Assert {
    Command::cargo_bin("rampage").unwrap().args(args).arg(fixture(file)).assert()
}

#[test]
fn user_databases_must_be_bounded_regular_files() {
    rampage(&["detect", "--peid", "/dev/zero"], "hello-x64.exe")
        .failure()
        .stderr(contains("cannot read PeID database /dev/zero: not a regular file"));
    rampage(&["identify", "--db", "/dev/zero"], "hello-x64.elf")
        .failure()
        .stderr(contains("cannot read signature database /dev/zero: not a regular file"));
    rampage(&["compare", "--reference", "/dev/zero"], "hello-x64.elf")
        .failure()
        .stderr(contains("cannot read comparison reference /dev/zero: not a regular file"));
}

fn json(args: &[&str], file: &str) -> serde_json::Value {
    let output = rampage(args, file).success().get_output().stdout.clone();
    serde_json::from_slice(&output).unwrap()
}

/// A scratch directory removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("rampage-cli-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn arg(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn detect_labels_kind_and_confidence_as_the_json_does() {
    rampage(&["detect"], "hello-x64.exe").success().stdout(contains("[compiler] MinGW/GCC (strong): "));
    let detections = json(&["--json", "detect"], "hello-x64.exe");
    let mingw = detections.as_array().unwrap().iter().find(|detection| detection["name"] == "MinGW/GCC").unwrap();
    assert_eq!((mingw["kind"].as_str(), mingw["confidence"].as_str()), (Some("compiler"), Some("strong")));
}

#[test]
fn yara_scans_a_rule_file_and_a_rule_directory() {
    let rules = Scratch::new("yara");
    std::fs::write(rules.0.join("pe.yar"), "rule pe_header : format { strings: $mz = \"MZ\" condition: $mz at 0 }")
        .unwrap();
    let file = rules.0.join("pe.yar");
    rampage(&["yara", "--rules", file.to_str().unwrap()], "hello-x64.exe")
        .success()
        .stdout(contains("pe_header [format] (1 string matches)"));
    rampage(&["yara", "--rules", rules.arg()], "hello-x64.elf").success().stdout(contains("no rules matched"));
    std::fs::write(rules.0.join("broken.yar"), "rule broken {").unwrap();
    rampage(&["yara", "--rules", rules.arg()], "hello-x64.exe").failure().stderr(contains("YARA rules"));
}

#[test]
fn capa_and_capabilities_render_alike() {
    let rules = Scratch::new("capa");
    std::fs::write(
        rules.0.join("console.yml"),
        "rule:\n  meta:\n    name: write output to console\n    namespace: host-interaction/console\n    \
         scopes:\n      static: file\n  features:\n    - or:\n      - import: puts\n      - import: printf\n",
    )
    .unwrap();
    rampage(&["capa", "--rules", rules.arg()], "hello-x64.exe")
        .success()
        .stdout(contains("[host-interaction] write output to console ("));
    rampage(&["capa", "--rules", rules.arg()], "musl-static-x86_64.elf")
        .success()
        .stdout(contains("no capa rules matched"));
    let capabilities = json(&["--json", "capabilities"], "hello-x64.exe");
    let first = &capabilities[0];
    let line = format!("[{}] {} (", first["category"].as_str().unwrap(), first["name"].as_str().unwrap());
    rampage(&["capabilities"], "hello-x64.exe").success().stdout(contains(line));
}

const ASSEMBLY: &str = "Microsoft.Bcl.HashCode.dll";

#[test]
fn dotnet_pages_types_and_shows_the_module_and_entry_point() {
    rampage(&["dotnet", "--limit", "2"], ASSEMBLY)
        .success()
        .stdout(contains("assembly   Microsoft.Bcl.HashCode 1.0.0.0"))
        .stdout(contains("module     Microsoft.Bcl.HashCode.dll (mvid "))
        .stdout(contains("entry      none"))
        .stdout(contains("... 9 more types (page with --offset 2, or filter with --contains)"));
    rampage(&["dotnet", "--limit", "0"], ASSEMBLY).failure().stderr(contains("--limit"));

    let first = json(&["--json", "dotnet", "--limit", "2"], ASSEMBLY);
    let next = json(&["--json", "dotnet", "--offset", "2", "--limit", "2"], ASSEMBLY);
    assert_eq!(next["types"]["offset"], 2);
    assert_eq!(next["types"]["items"].as_array().unwrap().len(), 2);
    assert_ne!(next["types"]["items"][0], first["types"]["items"][0]);
    rampage(&["dotnet", "--offset", "9", "--limit", "5"], ASSEMBLY).success().stdout(contains("more types").not());

    rampage(&["dotnet"], "hello-x64.exe").success().stdout(contains("not a .NET assembly"));
}

#[test]
fn identify_overlays_or_replaces_the_bundled_database() {
    rampage(&["identify", "--no-bundled"], "hello-x64.elf").failure().stderr(contains("--db"));
    let bundled = json(&["--json", "identify"], "hello-x64.elf");
    assert!(bundled["matched"].as_u64().unwrap() > 0, "{bundled}");
    rampage(&["identify"], "hello-x64.elf").success().stdout(contains(" matched, 0 applied"));

    let database = std::env::temp_dir().join(format!("rampage-cli-empty-db-{}.json", std::process::id()));
    std::fs::write(&database, rampage_api::SignatureDb::default().to_json()).unwrap();
    let database_arg = database.to_str().unwrap();
    let overlaid = json(&["--json", "identify", "--db", database_arg], "hello-x64.elf");
    let alone = json(&["--json", "identify", "--db", database_arg, "--no-bundled"], "hello-x64.elf");
    std::fs::remove_file(&database).unwrap();
    assert_eq!(overlaid["matched"], bundled["matched"]);
    assert_eq!(alone["matched"], 0, "{alone}");
}
