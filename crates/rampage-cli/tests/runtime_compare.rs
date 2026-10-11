use assert_cmd::Command;
use rampage_loaders::{Binary, Details};

struct Fixture(std::path::PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn byte_comparison_uses_explicit_inputs_without_loading_annotation_sidecars() {
    let root = Fixture(std::env::temp_dir().join(format!("rampage-cli-runtime-compare-{}", std::process::id())));
    std::fs::create_dir(&root.0).unwrap();
    let original_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-arm64.macho");
    let original = Binary::open(&original_path).unwrap();
    let Details::MachO(details) = &original.details else { panic!("not Mach-O") };
    let uuid = details.uuid.as_deref().unwrap();
    let image_base =
        original.segments.iter().find(|segment| segment.file_offset == 0 && segment.file_size > 0).unwrap().address;
    let snapshot_path = root.0.join("snapshot.json");
    let snapshot = serde_json::json!({"format": "rampage-snapshot-v1", "arch": "aarch64", "entry": null,
        "provenance": "controlled CLI comparison", "regions": [{"name": "selected", "address": "0x1000",
            "permissions": "r--", "bytes": "cffaedfe"}],
        "modules": [{"name": "fixture", "path": "/never/opened", "uuid": uuid,
            "image_base": format!("{image_base:#x}"), "runtime_base": "0x1000"}]});
    std::fs::write(&snapshot_path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    std::fs::create_dir(snapshot_path.with_extension("json.rampage")).unwrap();
    let output = Command::cargo_bin("rampage")
        .unwrap()
        .args(["--json", "compare-runtime"])
        .arg(&snapshot_path)
        .arg("--original")
        .arg(original_path)
        .args(["--module", uuid, "--range", "0x1000:4"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["equal_bytes"], 4);
    assert_eq!(result["spans"][0]["runtime_address"], "0x1000");
    assert_eq!(result["spans"][0]["image_address"], format!("{image_base:#x}"));
}
