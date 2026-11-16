//! dex_metadata and dex_code on the committed Android fixtures (tests/fixtures/android) and hostile inputs.

use std::path::PathBuf;

use rampage_api::Packs;
use rampage_api::tools::file_tools;
use serde_json::{Value, json};

fn android(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/android").join(name)
}

fn call(tool: &str, input: Value) -> Result<Value, String> {
    let tool = file_tools().into_iter().find(|candidate| candidate.name == tool).unwrap();
    tool.call(&Packs::default(), input)
}

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("rampage-api-android-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn the_apk_summary_has_manifest_permissions_components_and_jni() {
    let out = call("dex_metadata", json!({"path": android("recorder.apk")})).unwrap();
    assert_eq!(out["kind"], "apk");
    assert_eq!(out["package"], "com.example.recorder");
    assert_eq!(out["version_code"], 7);
    assert_eq!(out["sdk"]["target"], 33);
    let permissions = out["permissions"].as_array().unwrap();
    let audio = permissions.iter().find(|row| row["name"] == "android.permission.RECORD_AUDIO").unwrap();
    assert_eq!(audio["protection_level"], "dangerous");
    assert_eq!(audio["category"], "microphone");
    assert_eq!(audio["privacy"], true);
    let internet = permissions.iter().find(|row| row["name"] == "android.permission.INTERNET").unwrap();
    assert_eq!(internet["privacy"], false);
    assert_eq!(out["start_at_boot"], json!(["com.example.recorder.BootReceiver"]));
    let receiver = out["components"].as_array().unwrap().iter().find(|row| row["kind"] == "receiver").unwrap();
    assert_eq!(receiver["in_dex"], true);
    assert_eq!(receiver["exported"], false);
    let lib = &out["native_libs"][0];
    assert_eq!(lib["abi"], "arm64-v8a");
    assert_eq!(lib["jni_exports"], json!(["Java_com_example_recorder_Capture_nativeEncode"]));
    assert_eq!(lib["jni_onload"], true);
    let dex: Vec<&str> = out["dex"].as_array().unwrap().iter().map(|row| row["path"].as_str().unwrap()).collect();
    assert_eq!(dex, ["classes.dex", "classes2.dex"]);
    assert_eq!(out["dex"][0]["checksum_valid"], true);
    assert_eq!(out["page"]["total"], 3);
}

#[test]
fn classes_and_methods_page_with_filters() {
    let apk = android("recorder.apk");
    let classes = call("dex_metadata", json!({"path": apk, "prefix": "com.example.recorder.Cap"})).unwrap();
    let items = classes["page"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["class"], "com.example.recorder.Capture");
    assert_eq!(items[0]["native_methods"], 1);
    let methods =
        call("dex_metadata", json!({"path": apk, "list": "methods", "package": "com.example", "limit": 2})).unwrap();
    assert_eq!(methods["page"]["returned"], 2);
    assert_eq!(methods["page"]["next_offset"], 2);
    let descriptor =
        call("dex_metadata", json!({"path": apk, "list": "methods", "prefix": "Lcom/example/recorder/Boot"})).unwrap();
    assert_eq!(descriptor["page"]["total"], 1);
    let components = call("dex_metadata", json!({"path": apk, "list": "components"})).unwrap();
    assert_eq!(components["page"]["total"], 4);
}

#[test]
fn a_bare_dex_and_a_directory_are_read() {
    let out = call("dex_metadata", json!({"path": android("recorder.dex")})).unwrap();
    assert_eq!(out["kind"], "dex");
    assert!(out.get("package").is_none());
    let directory = call("dex_metadata", json!({"path": android(""), "max_files": 1})).unwrap();
    assert_eq!(directory["files_total"], 2);
    assert_eq!(directory["files"].as_array().unwrap().len(), 1);
    let next = directory["next_cursor"].as_str().unwrap();
    let second = call("dex_metadata", json!({"path": android(""), "cursor": next})).unwrap();
    assert_eq!(second["files"].as_array().unwrap().len(), 1);
    assert!(second["next_cursor"].is_null());
}

#[test]
fn hostile_and_foreign_inputs_are_refused_with_a_reason() {
    let dir = scratch("hostile");
    let text = dir.join("notes.txt");
    std::fs::write(&text, "plain text").unwrap();
    assert!(call("dex_metadata", json!({"path": text})).unwrap_err().contains("not an APK"));
    let truncated = dir.join("cut.dex");
    let bytes = std::fs::read(android("recorder.dex")).unwrap();
    std::fs::write(&truncated, &bytes[..bytes.len() / 2]).unwrap();
    assert!(call("dex_metadata", json!({"path": truncated})).is_err());
    let apk = std::fs::read(android("recorder.apk")).unwrap();
    let cut = dir.join("cut.apk");
    std::fs::write(&cut, &apk[..apk.len() - 30]).unwrap();
    assert!(call("dex_metadata", json!({"path": cut})).is_err());
    assert!(call("dex_metadata", json!({"path": android("recorder.apk"), "list": "strings"})).is_err());
    assert!(call("dex_metadata", json!({"path": android("recorder.apk"), "limit": 0})).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
