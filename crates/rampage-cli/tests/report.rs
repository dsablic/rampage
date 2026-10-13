use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn report(args: &[&str]) -> assert_cmd::assert::Assert {
    Command::cargo_bin("rampage").unwrap().arg("report").args(args).assert()
}

fn json(args: &[&str]) -> Value {
    let output = Command::cargo_bin("rampage").unwrap().arg("--json").arg("report").args(args).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap()
}

fn path(name: &str) -> String {
    fixture(name).to_str().unwrap().to_owned()
}

#[test]
fn triage_report_renders_text_and_json() {
    let exe = path("hello-x64.exe");
    report(&["triage-report", &exe])
        .success()
        .stdout(predicates::str::contains("== Toolchain"))
        .stdout(predicates::str::contains("MinGW-w64"))
        .stdout(predicates::str::contains("limitations:"));
    let value = json(&["triage-report", &exe, "--limit", "1"]);
    assert_eq!(value["workflow"], "triage_report");
    let imports = value["sections"].as_array().unwrap().iter().find(|s| s["title"] == "Imports by library").unwrap();
    assert_eq!(imports["findings"].as_array().unwrap().len(), 1);
    assert_eq!(imports["truncated"], true);
}

#[test]
fn find_crypto_renders_constants_and_referencing_functions() {
    let go = path("hello-go-arm64.elf");
    report(&["find-crypto", &go])
        .success()
        .stdout(predicates::str::contains("== Cryptographic constants (1)"))
        .stdout(predicates::str::contains("expand 32-byte k"))
        .stdout(predicates::str::contains("internal/chacha8rand.block"));
    let value = json(&["find-crypto", &go]);
    assert_eq!(value["workflow"], "find_crypto");
}

#[test]
fn find_main_renders_candidates_and_the_decompilation_preview() {
    report(&["find-main", &path("hello-x64.elf")])
        .success()
        .stdout(predicates::str::contains("[high] the binary names this function `main` @0x1001910"))
        .stdout(predicates::str::contains("== Decompilation preview"))
        .stdout(predicates::str::contains("puts("));
    let value = json(&["find-main", &path("hello-x64.elf"), "--no-decompile"]);
    assert_eq!(value["workflow"], "find_main");
    assert!(value["sections"].as_array().unwrap().iter().all(|s| s["title"] != "Decompilation preview"));
}

#[test]
fn network_surface_renders_an_empty_report_honestly() {
    report(&["network-surface", &path("hello-x64.elf")])
        .success()
        .stdout(predicates::str::contains("No networking APIs"))
        .stdout(predicates::str::contains("(nothing observed)"))
        .stdout(predicates::str::contains("Absence of evidence is not evidence of absence"));
}

#[test]
fn diff_builds_needs_and_uses_other() {
    let elf = path("hello-x64.elf");
    report(&["diff-builds", &elf]).failure().stderr(predicates::str::contains("--other"));
    report(&["diff-builds", &elf, "--other", &path("hello-x64-dyn.elf")])
        .success()
        .stdout(predicates::str::contains("compared with: Elf x86_64"))
        .stdout(predicates::str::contains("`add` has the same masked hash"));
}

#[test]
fn diff_builds_compares_embedded_images_on_both_sides() {
    let directory = std::env::temp_dir().join(format!("rampage-cli-diff-embedded-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let embed = |name: &str, junk: usize| {
        let mut file = b"junk".repeat(junk);
        file.push(b'!');
        let offset = format!("{:#x}", file.len());
        file.extend(std::fs::read(fixture(name)).unwrap());
        let path = directory.join(format!("{name}.bin"));
        std::fs::write(&path, file).unwrap();
        (path.to_str().unwrap().to_owned(), offset)
    };
    let (base, base_offset) = embed("hello-x64.elf", 10);
    let (other, other_offset) = embed("hello-x64-dyn.elf", 30);
    let direct = json(&["diff-builds", &path("hello-x64.elf"), "--other", &path("hello-x64-dyn.elf")]);
    let embedded = json(&[
        "diff-builds",
        &base,
        "--image-offset",
        &base_offset,
        "--other",
        &other,
        "--other-image-offset",
        &other_offset,
    ]);
    assert_eq!(embedded["sections"], direct["sections"]);
    assert_eq!(embedded["other"]["sha256"], direct["other"]["sha256"]);
    let step = embedded["next_steps"].as_array().unwrap().iter().find(|step| step["arguments"]["path"] == other);
    assert_eq!(step.unwrap()["arguments"]["image_offset"], other_offset.as_str());
    report(&["diff-builds", &path("hello-x64.elf"), "--other", &other])
        .failure()
        .stderr(predicates::str::contains("hello-x64-dyn.elf.bin"));
    report(&["diff-builds", &base, "--other-image-length", "0x10", "--other", &other]).failure();
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn other_is_rejected_outside_diff_builds() {
    let exe = path("hello-x64.exe");
    report(&["triage-report", &exe, "--other", &exe]).failure();
}

#[test]
fn arguments_are_checked_before_the_binary_is_opened() {
    let missing = "/nonexistent/rampage-binary";
    report(&["triage-report", missing, "--other", missing])
        .failure()
        .stderr(predicates::str::contains("--other only applies to diff-builds"));
    report(&["diff-builds", missing]).failure().stderr(predicates::str::contains("diff-builds needs --other"));
}

#[test]
fn persistence_surface_and_string_decoding_render() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rampage-api/tests/fixtures");
    let persist = fixtures.join("persist-x64.elf");
    report(&["persistence-surface", persist.to_str().unwrap()])
        .success()
        .stdout(predicates::str::contains("== Autostart locations in strings"))
        .stdout(predicates::str::contains("/etc/systemd/system/updater.service"))
        .stdout(predicates::str::contains("limitations:"));
    let decode = fixtures.join("decode-x64.elf");
    report(&["string-decoding", decode.to_str().unwrap()])
        .success()
        .stdout(predicates::str::contains("[medium] `decode` has a byte loop applying XOR"))
        .stdout(predicates::str::contains("== Referenced data blobs (3)"));
    assert_eq!(json(&["string-decoding", decode.to_str().unwrap()])["workflow"], "string_decoding");
}
