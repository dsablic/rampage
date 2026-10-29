use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

fn run(args: &[&str], file: &str) -> Output {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(file);
    Command::new(env!("CARGO_BIN_EXE_rampage"))
        .env_remove("RAMPAGE_PACKS")
        .args(["binary"])
        .args(&args[..1])
        .arg(path)
        .args(&args[1..])
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn wasm_module_prints_a_summary_and_pages_a_list_as_text_or_json() {
    let text = stdout(&run(&["wasm-module", "--list", "exports"], "module.wasm"));
    assert!(text.contains("module name: module.wasm"), "{text}");
    assert!(text.contains("export add func"), "{text}");
    let json: Value = serde_json::from_str(&stdout(&run(
        &["wasm-module", "--json", "--list", "functions", "--limit", "1"],
        "module.wasm",
    )))
    .unwrap();
    assert_eq!((json["returned"].as_u64(), json["next_offset"].as_u64()), (Some(1), Some(1)));
    assert_eq!(json["functions"][0]["imported"], true);
    let foreign = stdout(&run(&["wasm-module", "--json"], "hello-x64.elf"));
    assert_eq!(foreign.trim(), "null");
    assert!(!run(&["wasm-module", "--offset", "1"], "module.wasm").status.success());
}

#[test]
fn pyinstaller_archive_reports_the_cookie_and_toc_and_refuses_image_selectors() {
    let text = stdout(&run(&["pyinstaller-archive", "--limit", "5"], "pyinstaller-312.elf"));
    assert!(text.contains("Python 3.12 (312), library libpython3.12.so.1.0"), "{text}");
    assert!(text.contains("z pyz"), "{text}");
    assert!(text.contains("continue with --offset 5"), "{text}");
    let legacy: Value =
        serde_json::from_str(&stdout(&run(&["pyinstaller-archive", "--json"], "pyinstaller-27.macho"))).unwrap();
    assert_eq!(legacy["cookie_layout"], "legacy");
    let none = stdout(&run(&["pyinstaller-archive"], "hello-x64.elf"));
    assert!(none.starts_with("no PyInstaller cookie"), "{none}");
    let refused = run(&["pyinstaller-archive", "--arch", "x86_64"], "pyinstaller-312.elf");
    assert!(!refused.status.success());
}
