//! privacy_surface on privacy-{x64,arm64}.elf (tests/fixtures/privacy.c): an always-on microphone loop that uploads
//! over HTTP, a camera frame grabbed from a timer and written to a file, a microphone opened on a network command
//! and published over MQTT, push-to-talk behind an input-device read (in a caller, the same function and a sibling
//! call), a capture also bound to a key through a handler table, one past the walk's bound, a local IPC send and a
//! sysfs write that are not sinks, and a playback-only decoy.

use std::path::PathBuf;

use rampage_api::{Finding, FindingConfidence, ReportLimits, Section, Session, WorkflowReport};

const FIXTURES: [&str; 2] = ["privacy-x64.elf", "privacy-arm64.elf"];

fn report(path: PathBuf) -> WorkflowReport {
    Session::default().open(&path, None).unwrap().privacy_surface(ReportLimits::new(Some(100))).unwrap()
}

fn fixture(name: &str) -> WorkflowReport {
    report(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name))
}

fn section<'a>(report: &'a WorkflowReport, title: &str) -> &'a Section {
    report.section(title).unwrap_or_else(|| panic!("no section {title:?} in {report:#?}"))
}

/// The finding whose observation contains every needle.
fn find<'a>(section: &'a Section, needles: &[&str]) -> Option<&'a Finding> {
    section.findings.iter().find(|finding| needles.iter().all(|needle| finding.observation.contains(needle)))
}

fn has_evidence(finding: &Finding, needle: &str) -> bool {
    finding.evidence.iter().any(|line| line.contains(needle))
}

#[test]
fn constant_arguments_confirm_capture_and_exclude_playback() {
    for name in FIXTURES {
        let report = fixture(name);
        let sources = section(&report, "Capture sources");
        for (needles, detail) in [
            (["`record_loop`", "ALSA PCM stream for capture (microphone)"], "stream = 1 (SND_PCM_STREAM_CAPTURE)"),
            (["`grab_frame`", "VIDIOC_STREAMON ioctl (camera)"], "request 0x40045612"),
            (["`grab_frame`", "VIDIOC_DQBUF ioctl (camera)"], "request 0xc0585611"),
            (["`listen_on_request`", "tinyalsa PCM for capture"], "flags = 0x10000000 (sets PCM_IN)"),
            (["`record_while_pressed`", "PulseAudio simple stream for capture"], "direction = 2 (PA_STREAM_RECORD)"),
            (["`button_loop`", "EVIOCGRAB ioctl (input devices)"], "request 0x40044590"),
        ] {
            let finding = find(sources, &needles).unwrap_or_else(|| panic!("{name}: {needles:?} in {sources:#?}"));
            assert_eq!(finding.confidence, FindingConfidence::High, "{name}: {finding:#?}");
            assert_eq!(finding.evidence[0], "evidence: argument", "{name}: {finding:#?}");
            assert!(has_evidence(finding, detail), "{name}: {finding:#?}");
        }
        let readi = find(sources, &["`record_loop`", "reads frames from an ALSA PCM"]).unwrap();
        assert_eq!(readi.evidence[0], "evidence: name");
        let device = find(sources, &["`grab_frame`", "\"/dev/video0\""]).unwrap();
        assert_eq!(device.evidence[0], "evidence: string");

        // The decoy plays a chime: its playback stream is excluded, never a source.
        assert!(sources.findings.iter().all(|finding| !finding.observation.contains("play_chime")), "{name}");
        let excluded = section(&report, "Excluded: not capture");
        let chime = find(excluded, &["`play_chime`", "not for capture"]).unwrap();
        assert!(has_evidence(chime, "stream = 0 (SND_PCM_STREAM_PLAYBACK)"), "{chime:#?}");
    }
}

#[test]
fn sinks_name_their_endpoints_and_skip_device_opens() {
    for name in FIXTURES {
        let report = fixture(name);
        let sinks = section(&report, "Send and write sinks");
        let upload = find(sinks, &["`upload_chunk` can send over the network", "curl_easy_perform"]).unwrap();
        assert!(has_evidence(upload, "\"https://ingest.vendor-cloud.example/v1/audio\""), "{upload:#?}");
        let publish = find(sinks, &["`listen_on_request`", "mosquitto_publish"]).unwrap();
        assert!(has_evidence(publish, "\"mqtt.vendor-cloud.example\""), "{publish:#?}");
        assert!(has_evidence(publish, "by its caller `command_server`"), "{publish:#?}");
        let file = find(sinks, &["`grab_frame` can write a file", "\"/tmp/frame.raw\" for writing"]).unwrap();
        assert!(has_evidence(file, "mode \"wb\"") && has_evidence(file, "`fwrite`"), "{file:#?}");
        // open("/dev/video0", O_RDWR) and open("/dev/input/event1") are device opens, not file writes.
        assert!(sinks.findings.iter().all(|finding| !finding.observation.contains("`open")), "{name}: {sinks:#?}");
        // A sysfs LED write is a device write, and an AF_UNIX send is IPC on the device.
        assert!(sinks.findings.iter().all(|finding| !finding.observation.contains("/sys/")), "{name}: {sinks:#?}");
        assert!(sinks.findings.iter().all(|finding| !finding.observation.contains("notify_daemon")), "{sinks:#?}");
    }
}

#[test]
fn paths_are_ranked_from_same_function_to_direct_calls() {
    for name in FIXTURES {
        let report = fixture(name);
        let paths = section(&report, "Capture-to-send paths");
        assert_eq!(paths.total, 4, "{name}: {paths:#?}");
        let first = &paths.findings[0];
        assert!(first.observation.contains("`listen_on_request` and a send to the network in `listen_on_request`"));
        assert_eq!(first.confidence, FindingConfidence::High);
        let direct =
            find(paths, &["`record_loop` and a send to the network in `upload_chunk`", "calls the sink directly"])
                .unwrap();
        assert!(has_evidence(direct, "chain: record_loop -> upload_chunk"), "{direct:#?}");
        assert!(has_evidence(direct, "writable global") && has_evidence(direct, "(`audio`)"), "{direct:#?}");
        let file = find(paths, &["`grab_frame` and a send to a file in `grab_frame`"]).unwrap();
        assert_eq!(file.confidence, FindingConfidence::Medium, "a file sink is weaker: {file:#?}");
        let position = |finding: &Finding| paths.findings.iter().position(|other| std::ptr::eq(other, finding));
        assert!(position(direct) < position(file), "a direct network send outranks a file write: {paths:#?}");
        assert!(find(paths, &["command_server", "calls the capture directly"]).is_some(), "{name}: {paths:#?}");
        assert!(paths.findings.iter().all(|finding| !finding.observation.contains("record_while_pressed")));
    }
}

#[test]
fn triggers_name_timer_network_and_boot_paths_and_respect_user_input() {
    for name in FIXTURES {
        let report = fixture(name);
        let triggers = section(&report, "Capture triggers");
        let timer = find(triggers, &["`grab_frame` runs from a callback registered beside a timer"]).unwrap();
        assert!(has_evidence(timer, "`start_timer` calls `setitimer`"), "{timer:#?}");
        assert!(has_evidence(timer, "chain: start_timer (registers callback) -> on_timer -> grab_frame"));
        let command = find(triggers, &["`listen_on_request` is reached from a function that receives"]).unwrap();
        assert!(has_evidence(command, "chain: command_server -> listen_on_request"), "{command:#?}");
        let boot = find(triggers, &["`listen_on_request` is reached from main"]).unwrap();
        assert!(has_evidence(boot, "main (registers callback) -> command_server"), "{boot:#?}");

        let unprompted: Vec<&str> = triggers
            .findings
            .iter()
            .filter(|finding| finding.observation.starts_with("no_user_trigger:"))
            .map(|finding| finding.observation.as_str())
            .collect();
        assert_eq!(unprompted.len(), 3, "{name}: {unprompted:#?}");
        for function in ["`record_loop`", "`grab_frame`", "`listen_on_request`"] {
            assert!(unprompted.iter().any(|text| text.contains(function)), "{name}: {function}");
        }
        // Push to talk follows a key press: never flagged.
        assert!(find(triggers, &["`record_while_pressed` follows user input"]).is_some(), "{triggers:#?}");
        assert!(!unprompted.iter().any(|text| text.contains("record_while_pressed")));
        assert!(!unprompted.iter().any(|text| text.contains("button_loop")), "an input reader is not flagged");
        assert!(report.summary[0].contains("3 captures are reached from program start"), "{:?}", report.summary);
    }
}

#[test]
fn reports_are_bounded_and_suggest_where_to_read() {
    let report = fixture("privacy-x64.elf");
    assert!(!report.limitations.is_empty());
    assert!(report.summary.iter().any(|line| line.contains("not of intent")), "{:?}", report.summary);
    let decompile: Vec<&str> =
        report.next_steps.iter().filter(|step| step.tool == "decompile").map(|step| step.reason.as_str()).collect();
    assert!(decompile[0].contains("`listen_on_request`"), "{decompile:?}");
    assert!(report.next_steps.iter().any(|step| step.tool == "endpoint_inventory" && step.group == Some("carve")));
    for section in &report.sections {
        assert_eq!(section.truncated, section.total > section.findings.len(), "{section:#?}");
    }

    let cut = Session::default()
        .open(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/privacy-x64.elf"), None)
        .unwrap()
        .privacy_surface(ReportLimits::new(Some(1)))
        .unwrap();
    // Each section is sorted before it is cut, so the one finding kept is the strongest: an argument-level source
    // (the highest addresses are as strong as the lowest), a no_user_trigger statement, the best path.
    let sources = section(&cut, "Capture sources");
    let all = section(&report, "Capture sources").total;
    assert!(sources.truncated && sources.findings.len() == 1 && sources.total == all, "{sources:#?}");
    assert_eq!(sources.findings[0].confidence, FindingConfidence::High, "{sources:#?}");
    let triggers = section(&cut, "Capture triggers");
    assert!(triggers.findings[0].observation.starts_with("no_user_trigger:"), "{triggers:#?}");
    let paths = section(&cut, "Capture-to-send paths");
    assert_eq!(paths.total, 4);
    assert!(paths.truncated && paths.findings[0].observation.contains("in `listen_on_request`: in the same"));
}

#[test]
fn user_input_data_tables_and_cut_walks_withhold_no_user_trigger() {
    for name in FIXTURES {
        let report = fixture(name);
        let triggers = section(&report, "Capture triggers");
        let flagged = |function: &str| {
            triggers.findings.iter().any(|finding| {
                finding.observation.starts_with("no_user_trigger:") && finding.observation.contains(function)
            })
        };
        // Push to talk in one function: the key read and the capture share `talk_on_key`.
        assert!(find(triggers, &["`talk_on_key` follows user input"]).is_some(), "{name}: {triggers:#?}");
        assert!(!flagged("`talk_on_key`"));
        // A sibling key read: `assistant_loop` records only after `button_pressed`.
        let sibling = find(triggers, &["`record_clip` may follow user input"]).unwrap();
        assert!(has_evidence(sibling, "`assistant_loop` also calls `button_pressed`"), "{sibling:#?}");
        assert!(!flagged("`record_clip`"));
        // Bound to a key through a handler table: callers through the table are not followed.
        let assistant = find(triggers, &["`start_assistant` is reached from main"]).unwrap();
        assert!(has_evidence(assistant, "no_user_trigger not stated: `start_assistant` is referenced from data"));
        assert!(!flagged("`start_assistant`"));
        // Eight calls below main: the walk is cut, so nothing is claimed about its trigger.
        assert!(triggers.findings.iter().all(|finding| !finding.observation.contains("`deep_capture`")), "{name}");
        assert!(report.limitations.iter().any(|text| text.contains("trigger search walks at most 6 call levels")));
    }
}

#[test]
fn ambiguous_evidence_is_marked_and_ranked_lower() {
    for name in FIXTURES {
        let report = fixture(name);
        let sources = section(&report, "Capture sources");
        // A PCM node whose direction letter a format fills in says neither direction.
        let node = find(sources, &["`deep_capture`", "ALSA PCM device node (either direction)"]).unwrap();
        assert_eq!(node.confidence, FindingConfidence::Low, "{node:#?}");
        assert!(has_evidence(node, "ambiguous:"), "{node:#?}");
        let video = find(sources, &["`grab_frame`", "\"/dev/video0\""]).unwrap();
        assert!(has_evidence(video, "ambiguous:") && video.observation.contains("capture, output or codec"));
        let argument = find(sources, &["`grab_frame`", "VIDIOC_STREAMON"]).unwrap();
        assert!(!has_evidence(argument, "ambiguous:"), "{argument:#?}");
    }
}

#[test]
fn a_program_without_capture_says_so() {
    let report = report(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf"));
    assert_eq!(report.summary[0], "No microphone, camera, screen or input-device capture was observed.");
    assert!(report.sections.iter().all(|section| section.total == 0), "{report:#?}");
}

#[test]
fn triage_report_points_at_privacy_surface_for_capture_imports() {
    let project = Session::default()
        .open(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/privacy-x64.elf"), None)
        .unwrap();
    let triage = project.triage_report(ReportLimits::default()).unwrap();
    let step = triage.next_steps.iter().find(|step| step.tool == "privacy_surface").expect("a privacy_surface step");
    assert_eq!(step.group, Some("carve"));
    assert!(step.reason.contains("snd_pcm_open"), "{step:?}");
}
