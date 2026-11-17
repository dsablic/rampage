//! privacy_surface on the committed privacy APK (tests/fixtures/android/watch.apk): a boot receiver starting a
//! service that records audio and uploads it, a push service reaching the same capture, a push-to-talk activity
//! recording on a click and uploading through an interface resolved by name, and a periodic Worker that opens the
//! camera and sends through a native method whose library connects and sends.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

fn android(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/android").join(name)
}

pub(crate) fn report(path: &Path, input: Value) -> Value {
    rampage_api::privacy_surface_input(path, &input).expect("an Android input").unwrap()
}

pub(crate) fn findings<'a>(report: &'a Value, title: &str) -> &'a Vec<Value> {
    let section = report["sections"].as_array().unwrap().iter().find(|section| section["title"] == title);
    section.unwrap_or_else(|| panic!("no section {title}"))["findings"].as_array().unwrap()
}

/// The finding of `section` whose observation contains every needle.
pub(crate) fn find<'a>(report: &'a Value, section: &str, needles: &[&str]) -> Option<&'a Value> {
    findings(report, section).iter().find(|finding| {
        let observation = finding["observation"].as_str().unwrap();
        needles.iter().all(|needle| observation.contains(needle))
    })
}

pub(crate) fn evidence(finding: &Value) -> String {
    finding["evidence"].as_array().unwrap().iter().map(|line| line.as_str().unwrap()).collect::<Vec<_>>().join("\n")
}

#[test]
fn the_apk_report_has_dex_and_native_sources_sinks_paths_and_triggers() {
    let out = report(&android("watch.apk"), json!({"max_per_section": 100}));
    assert_eq!(out["input"]["kind"], "apk");
    assert!(out.get("target").is_none());
    // As docs/device-privacy-check.md quotes it.
    assert_eq!(
        out["summary"][0],
        "DEX: 3 capture sources in 3 methods (camera, microphone); 2 methods can send over the network or a socket \
         and 0 more can write files; 3 capture-to-send paths; 2 captures are reached from boot or app start with no \
         user-facing trigger found among their callers."
    );

    let record = find(&out, "Capture sources", &["Recorder;->record()[B", "AudioRecord.startRecording", "microphone"])
        .expect("the AudioRecord capture");
    assert_eq!(record["confidence"], "high");
    assert!(evidence(record).contains("origin: dex classes.dex"));
    assert!(find(&out, "Capture sources", &["TalkActivity;->onClick", "MediaRecorder.setAudioSource"]).is_some());
    assert!(find(&out, "Capture sources", &["Snapshot;->take()V", "Camera.open", "camera"]).is_some());

    // Sinks: the URL connection, and the native method bound to a library that connects and sends.
    let upload = find(&out, "Send and write sinks", &["Uploader;->upload([B)V", "can send over the network"]).unwrap();
    assert!(
        evidence(upload).contains("java.net.URL.openConnection")
            || upload["observation"].as_str().unwrap().contains("URL")
    );
    let native = find(&out, "Send and write sinks", &["Net;->nativeSend([B)I", "lib/arm64-v8a/libnet.so"]).unwrap();
    assert!(evidence(native).contains("Java_com_example_watch_Net_nativeSend"), "{native:#}");
    // The library's own report is merged, labelled with its origin.
    let library = find(&out, "Send and write sinks", &["lib/arm64-v8a/libnet.so: "]).unwrap();
    assert!(evidence(library).starts_with("origin: lib/arm64-v8a/libnet.so"));

    // Paths: the camera capture calls the JNI sink directly; boot capture and upload share a caller; the
    // push-to-talk capture reaches the upload through a by_name edge, ranked lower.
    let camera = find(
        &out,
        "Capture-to-send paths",
        &["camera capture in `Lcom/example/watch/Snapshot;->take()V`", "nativeSend"],
    )
    .unwrap();
    assert!(camera["observation"].as_str().unwrap().contains("calls the sink directly"));
    let boot = find(&out, "Capture-to-send paths", &["Recorder;->record()[B", "Uploader;->upload([B)V"]).unwrap();
    assert!(boot["observation"].as_str().unwrap().contains("both are reached from"), "{boot:#}");
    let talk = find(&out, "Capture-to-send paths", &["TalkActivity;->onClick", "Uploader;->upload([B)V"]).unwrap();
    assert!(evidence(talk).contains("by_name"), "{talk:#}");
    assert_ne!(talk["confidence"], "high");

    // Triggers: boot (no_user_trigger), push, the scheduled Worker (no_user_trigger), the click (user input).
    let quiet = find(
        &out,
        "Capture triggers",
        &["no_user_trigger: microphone capture in `Lcom/example/watch/Recorder;->record()[B`"],
    )
    .expect("the boot capture has no user trigger");
    assert!(quiet["observation"].as_str().unwrap().contains("start at boot"));
    assert!(find(&out, "Capture triggers", &["Recorder;->record()[B", "push message"]).is_some());
    assert!(find(&out, "Capture triggers", &["no_user_trigger: camera capture", "Snapshot;->take()V"]).is_some());
    assert!(find(&out, "Capture triggers", &["Snapshot;->take()V", "scheduled job"]).is_some());
    assert!(find(&out, "Capture triggers", &["TalkActivity;->onClick", "follows user input"]).is_some());
    assert!(find(&out, "Capture triggers", &["no_user_trigger", "onClick"]).is_none());

    // Decoded strings: the XOR-hidden upload URL names the upload sink's endpoint; the byte-array host is named
    // beside the JNI sink by its caller.
    let decoded = find(&out, "Decoded strings", &["Codec;->decode", "https://upload.example.net/v2/audio"]).unwrap();
    let lines = evidence(decoded);
    assert!(lines.contains("call site: `Lcom/example/watch/Uploader;->upload([B)V`"), "{lines}");
    assert!(lines.contains("inputs: \""), "{lines}");
    let upload = find(&out, "Send and write sinks", &["Uploader;->upload([B)V", "URL.openConnection"]).unwrap();
    assert!(evidence(upload).contains("names endpoint \"https://upload.example.net/v2/audio\""), "{upload:#}");
    assert!(evidence(upload).contains("decoded by `Lcom/example/watch/Codec;"), "{upload:#}");
    let host = "names endpoint \"collector.example.net\" (local: documentation name (RFC 2606)), decoded by \
                `Lcom/example/watch/Strings;->get(I)Ljava/lang/String;` from 0 by its caller \
                `Lcom/example/watch/Snapshot;->take()V`";
    assert!(evidence(native).contains(host), "{native:#}");
    let path = find(&out, "Capture-to-send paths", &["Recorder;->record()[B", "Uploader;->upload([B)V"]).unwrap();
    assert!(evidence(path).contains("upload.example.net"), "{path:#}");
    assert!(
        out["summary"].to_string().contains("2 strings decoded by emulating static decoder methods at 2 call sites")
    );
}

#[test]
fn decoded_strings_reach_endpoint_inventory_and_dex_metadata() {
    let tool = |name: &str| rampage_api::tools::file_tools().into_iter().find(|tool| tool.name == name).unwrap();
    let packs = rampage_api::Packs::default();
    let out = tool("endpoint_inventory")
        .call(&packs, json!({"path": android("watch.apk"), "limit": 500, "decode": true}))
        .unwrap();
    let rows = out["endpoints"].as_array().unwrap();
    let url = rows.iter().find(|row| row["value"] == "https://upload.example.net/v2/audio").expect("the decoded URL");
    let evidence = &url["evidence"][0];
    assert_eq!(evidence["origin"], "dex_decoded");
    assert!(evidence["decoded_by"].as_str().unwrap().starts_with("Lcom/example/watch/Codec;->decode"));
    assert_eq!(evidence["functions"], json!(["Lcom/example/watch/Uploader;->upload([B)V"]));
    assert_eq!(url["signal"], "network_code");
    assert!(rows.iter().any(|row| row["value"] == "collector.example.net"));

    let page =
        tool("dex_metadata").call(&packs, json!({"path": android("watch.apk"), "list": "decoded_strings"})).unwrap();
    assert_eq!(page["page"]["total"], 2);
    let host =
        page["page"]["items"].as_array().unwrap().iter().find(|row| row["output"] == "collector.example.net").unwrap();
    assert_eq!(host["decoder"], "Lcom/example/watch/Strings;->get(I)Ljava/lang/String;");
    assert_eq!(host["inputs"], json!(["0"]));
    let filtered = tool("dex_metadata")
        .call(
            &packs,
            json!({"path": android("watch.apk"), "list": "decoded_strings", "prefix": "com.example.watch.Snapshot"}),
        )
        .unwrap();
    assert_eq!(filtered["page"]["total"], 1);
}

#[test]
fn other_files_are_left_to_the_binary_route() {
    let elf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/privacy-x64.elf");
    assert!(rampage_api::privacy_surface_input(&elf, &json!({})).is_none());
    let dex = report(&android("recorder.dex"), json!({}));
    assert_eq!(dex["input"]["kind"], "dex");
    assert!(find(&dex, "Capture sources", &["Capture;->start()V", "AudioRecord"]).is_some());
}

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("rampage-api-privacy-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn place(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// An extracted tree: an init .rc service starting the privacy fixture's ALSA capture program at boot, the
/// privacy APK, and a program without capture APIs.
fn tree() -> PathBuf {
    let root = scratch("tree");
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    place(&root, "system/bin/voiced", &std::fs::read(fixtures.join("privacy-arm64.elf")).unwrap());
    place(&root, "system/etc/init/voiced.rc", b"service voiced /system/bin/voiced\n    class main\n    user audio\n");
    place(&root, "init.rc", b"on boot\n    class_start main\n");
    place(&root, "init.rc", b"on boot\n    class_start main\n");
    place(&root, "system/app/Watch/Watch.apk", &std::fs::read(android("watch.apk")).unwrap());
    let hello = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-arm64.elf");
    place(&root, "system/bin/hello", &std::fs::read(hello).unwrap());
    root
}

#[test]
fn a_tree_ties_init_services_to_captures_and_pages_by_cursor() {
    let root = tree();
    let out = report(&root, json!({"max_per_section": 200}));
    assert_eq!(out["input"]["kind"], "directory");
    assert_eq!(out["input"]["files"], 2);
    let boot = find(&out, "Capture triggers", &["no_user_trigger: system/bin/voiced is started at boot"]).unwrap();
    let lines = evidence(boot);
    assert!(lines.contains("init service voiced, class main"), "{lines}");
    assert!(lines.contains("system/etc/init/voiced.rc:1"), "{lines}");
    assert!(find(&out, "Capture sources", &["system/bin/voiced: `record_loop`"]).is_some());
    assert!(
        find(&out, "Capture sources", &["system/app/Watch/Watch.apk: `Lcom/example/watch/Recorder;->record()[B`"])
            .is_some()
    );
    let service =
        find(&out, "Boot services", &["/system/bin/voiced is started at boot by init service voiced"]).unwrap();
    assert!(evidence(service).contains("in the tree as system/bin/voiced"));
    let limits = out["limitations"].to_string();
    assert!(limits.contains("system/bin/hello"), "{limits}");

    // One file per page: the cursor walks the rest.
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let page = report(&root, json!({"max_files": 1, "cursor": cursor}));
        pages += 1;
        assert!(page["input"]["files"].as_u64().unwrap() <= 1);
        match page["input"]["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
        assert!(pages < 5);
    }
    assert_eq!(pages, 2);
    assert!(rampage_api::privacy_surface_input(&root, &json!({"max_files": 0})).unwrap().is_err());
    std::fs::remove_dir_all(root).unwrap();
}

/// A bare DEX file: `App.onCreate` (an Application) calls `Rec.go`, which records; `extra` adds invokes to
/// onCreate, and `callers` more static methods call `Rec.go`.
fn app_dex(extra: &[(&str, u8)], callers: usize) -> Vec<u8> {
    use rampage_dex::testkit::{Asm, ClassSpec, STATIC, VIRTUAL, write_dex};
    let mut create = Asm::new();
    for (method, op) in extra {
        create = create.invoke(*op, &[], method);
    }
    let create = create.invoke(STATIC, &[], "Lcom/example/q/Rec;->go()V").return_void().code(1, 1, 0);
    let go = Asm::new()
        .new_instance(0, "Landroid/media/AudioRecord;")
        .invoke(VIRTUAL, &[0], "Landroid/media/AudioRecord;->startRecording()V")
        .return_void()
        .code(1, 0, 1);
    let mut rec = ClassSpec::new("Lcom/example/q/Rec;", "Ljava/lang/Object;").method("go", "V", &[], 0x9, Some(go));
    let call = Asm::new().invoke(STATIC, &[], "Lcom/example/q/Rec;->go()V").return_void();
    for index in 0..callers {
        rec = rec.method(&format!("c{index}"), "V", &[], 0x9, Some(call.clone().code(0, 0, 0)));
    }
    let app = ClassSpec::new("Lcom/example/q/App;", "Landroid/app/Application;").method(
        "onCreate",
        "V",
        &[],
        0x1,
        Some(create),
    );
    write_dex(&[app, rec], 35)
}

#[test]
fn reflection_dynamic_loading_and_cut_walks_withhold_no_user_trigger() {
    let root = scratch("withheld");
    let quiet = "no_user_trigger: microphone capture in `Lcom/example/q/Rec;->go()V`";
    let plain = root.join("plain.dex");
    std::fs::write(&plain, app_dex(&[], 0)).unwrap();
    assert!(find(&report(&plain, json!({})), "Capture triggers", &[quiet]).is_some());
    for (name, extra, reason) in [
        ("reflect", ("Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;", 0x71), "reflection"),
        ("loader", ("Ldalvik/system/DexClassLoader;-><init>()V", 0x70), "dynamic loading"),
    ] {
        let path = root.join(format!("{name}.dex"));
        std::fs::write(&path, app_dex(&[extra], 0)).unwrap();
        let out = report(&path, json!({}));
        assert!(find(&out, "Capture triggers", &[quiet]).is_none(), "{name}");
        let start = find(&out, "Capture triggers", &["Rec;->go()V` is reached from app start"]).unwrap();
        assert!(evidence(start).contains(reason), "{name}: {start:#}");
    }
    // Many callers of one capture: the walk is cut, says so, and states nothing.
    let fan = root.join("fan.dex");
    std::fs::write(&fan, app_dex(&[], 20_000)).unwrap();
    let started = std::time::Instant::now();
    let out = report(&fan, json!({}));
    eprintln!("20000 callers of one capture: {:?}", started.elapsed());
    assert!(started.elapsed() < std::time::Duration::from_secs(30));
    assert!(find(&out, "Capture triggers", &[quiet]).is_none());
    let limits = out["limitations"].to_string();
    assert!(limits.contains("hit that bound"), "{limits}");
    std::fs::remove_dir_all(root).unwrap();
}

/// `App.onCreate` calls `Port.run` on an interface; `Impl.run` (found only by name) records. `extra` more
/// implementers of an unrelated interface `Many` are called from `App.other`.
fn interface_dex(extra: usize) -> Vec<u8> {
    use rampage_dex::testkit::{Asm, ClassSpec, INTERFACE, VIRTUAL, write_dex};
    let object = "Ljava/lang/Object;";
    let create = Asm::new()
        .new_instance(0, "Lcom/example/q/Impl;")
        .invoke(INTERFACE, &[0], "Lcom/example/q/Port;->run()V")
        .return_void()
        .code(2, 1, 1);
    let other = Asm::new().invoke(INTERFACE, &[0], "Lcom/example/q/Many;->tick()V").return_void().code(1, 1, 1);
    let app = ClassSpec::new("Lcom/example/q/App;", "Landroid/app/Application;")
        .method("onCreate", "V", &[], 0x1, Some(create))
        .method("other", "V", &[], 0x1, Some(other));
    let mut port = ClassSpec::new("Lcom/example/q/Port;", object).method("run", "V", &[], 0x401, None);
    port.access = 0x601;
    let record = Asm::new()
        .new_instance(0, "Landroid/media/AudioRecord;")
        .invoke(VIRTUAL, &[0], "Landroid/media/AudioRecord;->startRecording()V")
        .return_void()
        .code(2, 1, 1);
    let mut implementer = ClassSpec::new("Lcom/example/q/Impl;", object).method("run", "V", &[], 0x1, Some(record));
    implementer.interfaces = vec!["Lcom/example/q/Port;".to_owned()];
    let mut many = ClassSpec::new("Lcom/example/q/Many;", object).method("tick", "V", &[], 0x401, None);
    many.access = 0x601;
    let mut classes = vec![app, port, implementer, many];
    for index in 0..extra {
        let mut class = ClassSpec::new(&format!("Lcom/example/q/M{index};"), object).method(
            "tick",
            "V",
            &[],
            0x1,
            Some(Asm::new().return_void().code(1, 1, 0)),
        );
        class.interfaces = vec!["Lcom/example/q/Many;".to_owned()];
        classes.push(class);
    }
    write_dex(&classes, 35)
}

/// A static capture `Rec.go` called directly from `App.onCreate`, and `App.other` calling an interface `Many`
/// that `extra` classes implement.
fn cut_dex(extra: usize) -> Vec<u8> {
    use rampage_dex::testkit::{Asm, ClassSpec, INTERFACE, STATIC, VIRTUAL, write_dex};
    let object = "Ljava/lang/Object;";
    let create = Asm::new().invoke(STATIC, &[], "Lcom/example/q/Rec;->go()V").return_void().code(1, 1, 0);
    let other = Asm::new().invoke(INTERFACE, &[0], "Lcom/example/q/Many;->tick()V").return_void().code(1, 1, 1);
    let app = ClassSpec::new("Lcom/example/q/App;", "Landroid/app/Application;")
        .method("onCreate", "V", &[], 0x1, Some(create))
        .method("other", "V", &[], 0x1, Some(other));
    let go = Asm::new()
        .new_instance(0, "Landroid/media/AudioRecord;")
        .invoke(VIRTUAL, &[0], "Landroid/media/AudioRecord;->startRecording()V")
        .return_void()
        .code(1, 0, 1);
    let rec = ClassSpec::new("Lcom/example/q/Rec;", object).method("go", "V", &[], 0x9, Some(go));
    let mut many = ClassSpec::new("Lcom/example/q/Many;", object).method("tick", "V", &[], 0x401, None);
    many.access = 0x601;
    let mut classes = vec![app, rec, many];
    for index in 0..extra {
        let mut class = ClassSpec::new(&format!("Lcom/example/q/M{index};"), object).method(
            "tick",
            "V",
            &[],
            0x1,
            Some(Asm::new().return_void().code(1, 1, 0)),
        );
        class.interfaces = vec!["Lcom/example/q/Many;".to_owned()];
        classes.push(class);
    }
    write_dex(&classes, 35)
}

#[test]
fn by_name_callers_graph_bounds_and_unread_dex_files_withhold_no_user_trigger() {
    let root = scratch("incomplete");
    let quiet = "no_user_trigger: microphone capture";
    // A caller linked by name.
    let path = root.join("byname.dex");
    std::fs::write(&path, interface_dex(0)).unwrap();
    let out = report(&path, json!({}));
    assert!(find(&out, "Capture triggers", &[quiet]).is_none());
    let start = find(&out, "Capture triggers", &["Impl;->run()V` is reached from app start"]).unwrap();
    assert!(evidence(start).contains("linked by name"), "{start:#}");

    // A by-name call with more than 32 targets elsewhere: the graph is cut, so nothing is stated.
    let plain = root.join("plain.dex");
    std::fs::write(&plain, app_dex(&[], 0)).unwrap();
    assert!(find(&report(&plain, json!({})), "Capture triggers", &[quiet]).is_some());
    let cut = root.join("cut.dex");
    std::fs::write(&cut, cut_dex(40)).unwrap();
    let out = report(&cut, json!({}));
    let limits = out["limitations"].to_string();
    assert!(limits.contains("possible targets"), "{limits}");
    let start = find(&out, "Capture triggers", &["is reached from app start"]).unwrap();
    assert!(evidence(start).contains("no_user_trigger not stated"), "{start:#}");

    // An APK whose second DEX file does not parse.
    let garbage = [b"dex\n035\0".as_slice(), &[0xffu8; 200]].concat();
    let apk =
        rampage_dex::testkit::write_zip(&[("classes.dex", &app_dex(&[], 0), false), ("classes2.dex", &garbage, false)]);
    let path = root.join("broken.apk");
    std::fs::write(&path, apk).unwrap();
    let out = report(&path, json!({}));
    assert!(find(&out, "Capture triggers", &[quiet]).is_none());
    let start = find(&out, "Capture triggers", &["Rec;->go()V` is reached from app start"]).unwrap();
    assert!(evidence(start).contains("classes2.dex was not read"), "{start:#}");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_program_matched_by_file_name_only_is_not_said_to_lack_a_trigger() {
    let root = scratch("basename");
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    place(&root, "system/bin/voiced", &std::fs::read(fixtures.join("privacy-arm64.elf")).unwrap());
    place(&root, "vendor/etc/init/voiced.rc", b"service voiced /vendor/bin/voiced\n    class main\n");
    place(&root, "init.rc", b"on boot\n    class_start main\n");
    let out = report(&root, json!({}));
    assert!(find(&out, "Capture triggers", &["no_user_trigger: system/bin/voiced"]).is_none());
    let maybe = find(&out, "Capture triggers", &["system/bin/voiced: a program with capture sources may be started"]);
    assert!(evidence(maybe.unwrap()).contains("matched by file name only"));
    std::fs::remove_dir_all(root).unwrap();
}
