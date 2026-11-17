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
    assert_eq!(audio["protection_level"], "dangerous|instant");
    assert_eq!(audio["base_level"], "dangerous");
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
    assert_eq!(directory["files_total"], 3);
    assert_eq!(directory["files"].as_array().unwrap().len(), 1);
    let next = directory["next_cursor"].as_str().unwrap();
    let second = call("dex_metadata", json!({"path": android(""), "cursor": next})).unwrap();
    assert_eq!(second["files"].as_array().unwrap().len(), 2);
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

#[test]
fn dex_code_lists_a_method_with_references_payloads_and_tries() {
    let apk = android("recorder.apk");
    let start = call("dex_code", json!({"path": apk, "method": "com.example.recorder.Capture.start"})).unwrap();
    let lines: Vec<String> = start["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| format!("{} {}", row["op"].as_str().unwrap(), row["args"].as_str().unwrap()).trim_end().to_owned())
        .collect();
    assert_eq!(lines[1], "invoke-virtual {v0}, Landroid/media/AudioRecord;->startRecording()V");
    assert_eq!(lines[2], "const-string v1, \"https://telemetry.example.com/upload\"");
    assert_eq!(start["instructions"][2]["ref"]["kind"], "string");
    assert_eq!(start["registers"], 3);
    let dispatch =
        call("dex_code", json!({"path": apk, "method": "Lcom/example/recorder/Capture;->dispatch(I)I", "at": ":0008"}))
            .unwrap();
    assert_eq!(dispatch["instructions"][0]["op"], "packed-switch-payload");
    assert_eq!(dispatch["instructions"][0]["args"], "first_key=0x10, targets=[:0005]");
    let guarded =
        call("dex_code", json!({"path": apk, "method": "com.example.recorder.Capture.guarded", "limit": 1})).unwrap();
    assert_eq!(guarded["tries"][0]["handlers"][0]["type"], "Ljava/io/IOException;");
    assert_eq!(guarded["tries"][0]["end"], ":0003");
    assert_eq!(guarded["next_offset"], 1);
    let native = call("dex_code", json!({"path": apk, "method": "com.example.recorder.Capture.nativeEncode"})).unwrap();
    assert!(native["body"].is_null());
    let index = guarded["index"].as_u64().unwrap();
    let by_index = call("dex_code", json!({"path": apk, "method": format!("classes.dex:{index}")})).unwrap();
    assert_eq!(by_index["method"], guarded["method"]);
    let dex = call("dex_code", json!({"path": android("recorder.dex"), "method": index.to_string()})).unwrap();
    assert_eq!(dex["method"], guarded["method"]);
}

#[test]
fn dex_code_refuses_unknown_methods_and_bad_addresses() {
    let apk = android("recorder.apk");
    assert!(
        call("dex_code", json!({"path": apk, "method": "com.example.Nope.run"})).unwrap_err().contains("no method")
    );
    assert!(call("dex_code", json!({"path": apk, "method": "nonsense"})).is_err());
    let past = json!({"path": apk, "method": "com.example.recorder.Capture.start", "at": "0x400"});
    assert!(call("dex_code", past).unwrap_err().contains("past the end"));
    assert!(call("dex_code", json!({"path": apk, "method": "classes9.dex:0"})).is_err());
}

#[test]
fn the_privacy_section_links_capture_calls_to_permissions_and_boot() {
    let out = call("dex_metadata", json!({"path": android("recorder.apk"), "limit": 1})).unwrap();
    let privacy = &out["privacy"];
    assert_eq!(privacy["media"], json!(["microphone"]));
    let capture = &privacy["capture_apis"][0];
    assert_eq!(capture["api"], "Landroid/media/AudioRecord;->startRecording()V");
    assert_eq!(capture["callers"], json!(["Lcom/example/recorder/Capture;->start()V"]));
    assert_eq!(capture["permission_requested"], true);
    assert_eq!(capture["reached_from_boot"], json!(["com.example.recorder.BootReceiver"]));
    let directory = call("dex_metadata", json!({"path": android("")})).unwrap();
    assert_eq!(directory["files"][0]["privacy"]["capture_apis_total"], 1);
}

#[test]
fn endpoint_inventory_reads_dex_strings_with_the_methods_that_load_them() {
    let out = call("endpoint_inventory", json!({"path": android("recorder.apk")})).unwrap();
    let text = out.to_string();
    assert!(text.contains("telemetry.example.com"), "{text}");
    assert!(text.contains("10.0.0.1"), "{text}");
    assert!(text.contains("dex_string"));
    assert!(text.contains("Lcom/example/recorder/Capture;->start()V"));
    assert!(text.contains("recorder.apk!classes2.dex"));
    let dex = call("endpoint_inventory", json!({"path": android("recorder.dex")})).unwrap();
    assert!(dex.to_string().contains("telemetry.example.com"));
}

#[test]
fn native_methods_link_to_their_jni_exports() {
    let out = call("dex_metadata", json!({"path": android("recorder.apk"), "limit": 1})).unwrap();
    let jni = &out["jni"];
    assert_eq!(jni["native_methods"], 1);
    assert_eq!(jni["linked"][0]["method"], "Lcom/example/recorder/Capture;->nativeEncode([B)I");
    assert_eq!(jni["linked"][0]["bound_by_name"][0]["symbol"], "Java_com_example_recorder_Capture_nativeEncode");
    assert_eq!(jni["linked"][0]["bound_by_name"][0]["library"], "lib/arm64-v8a/libnative.so");
    assert_eq!(jni["unlinked"], json!([]));
    assert_eq!(jni["exports_without_native"], json!([]));
    let dex = call("dex_metadata", json!({"path": android("recorder.dex"), "limit": 1})).unwrap();
    assert_eq!(dex["jni"]["unlinked"][0]["expected_symbol"], "Java_com_example_recorder_Capture_nativeEncode");
}

/// Runs `tool` on `input`, asserting it finishes within `seconds` and returns at most 60,000 JSON bytes.
fn bounded(tool: &str, input: Value, seconds: u64) -> Value {
    let started = std::time::Instant::now();
    let out = call(tool, input).unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed < std::time::Duration::from_secs(seconds), "{tool} took {elapsed:?}");
    let size = out.to_string().len();
    assert!(size <= 60_000, "{tool} returned {size} bytes");
    out
}

#[test]
fn tries_sharing_one_huge_handler_stay_bounded() {
    let dir = scratch("tries");
    let path = dir.join("tries.dex");
    std::fs::write(&path, rampage_dex::testkit::shared_handler(65_535, 60_000)).unwrap();
    let method = "Lcom/example/recorder/Capture;-><init>()V";
    let out = bounded("dex_code", json!({"path": path, "method": method}), 20);
    assert_eq!(out["tries_total"], 65_535);
    assert!(out["tries"].as_array().unwrap().len() <= 64);
    assert_eq!(out["tries"][0]["handlers_total"], 60_000);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn one_long_string_shared_by_every_id_stays_bounded() {
    let dir = scratch("strings");
    let path = dir.join("strings.dex");
    std::fs::write(&path, rampage_dex::testkit::shared_string(1 << 20)).unwrap();
    bounded("endpoint_inventory", json!({"path": path}), 20);
    bounded("dex_metadata", json!({"path": path, "list": "methods"}), 20);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn classes_sharing_a_huge_interface_list_stay_bounded() {
    let dir = scratch("interfaces");
    let path = dir.join("interfaces.dex");
    let classes = rampage_dex::testkit::shared_interfaces(100, 60_000);
    std::fs::write(&path, rampage_dex::testkit::write_dex(&classes, 35)).unwrap();
    let out = bounded("dex_metadata", json!({"path": path, "limit": 500}), 30);
    let row = &out["page"]["items"][0];
    assert_eq!(row["interfaces_total"], 60_000);
    assert_eq!(row["interfaces"].as_array().unwrap().len(), 32);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_manifest_with_huge_lists_stays_bounded_and_pages() {
    use rampage_dex::testkit::{XmlNode, XmlValue, sample_classes, write_axml, write_dex, write_zip};
    let mut manifest = XmlNode::new("manifest").plain("package", XmlValue::Str("com.example.big".to_owned()));
    for index in 0..20_000 {
        manifest = manifest
            .child(XmlNode::new("uses-permission").android("name", XmlValue::Str(format!("com.example.P{index}"))));
    }
    let manifest = write_axml(&manifest, false);
    let dex = write_dex(&sample_classes(), 35);
    let mut members: Vec<(String, Vec<u8>)> = vec![("AndroidManifest.xml".to_owned(), manifest)];
    for index in 0..40 {
        let name = if index == 0 { "classes.dex".to_owned() } else { format!("classes{}.dex", index + 1) };
        members.push((name, dex.clone()));
    }
    let borrowed: Vec<(&str, &[u8], bool)> =
        members.iter().map(|(name, bytes)| (name.as_str(), bytes.as_slice(), true)).collect();
    let dir = scratch("big-manifest");
    let path = dir.join("big.apk");
    std::fs::write(&path, write_zip(&borrowed)).unwrap();
    let out = bounded("dex_metadata", json!({"path": path, "limit": 1}), 30);
    assert_eq!(out["permissions_total"], 20_000);
    assert!(out["permissions"].as_array().unwrap().len() < 20_000);
    assert_eq!(out["dex_total"], 40);
    let page = bounded("dex_metadata", json!({"path": path, "list": "permissions", "offset": 19_999}), 30);
    assert_eq!(page["page"]["items"][0]["name"], "com.example.P19999");
    let files = bounded("dex_metadata", json!({"path": path, "list": "dex_files", "limit": 5}), 30);
    assert_eq!(files["page"]["total"], 40);
    std::fs::remove_dir_all(dir).unwrap();
}
