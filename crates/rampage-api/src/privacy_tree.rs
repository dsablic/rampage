//! `privacy_surface` on a directory, such as `fs_extract`'s output: one page of programs and APKs that may capture
//! (each with its own report, findings labelled with the file), merged into one report, plus how the tree's init
//! files start each program (Android init `.rc` services, systemd units, init scripts), so a capture reached from
//! a program's start is tied to the device's boot across files. Paged by cursor like `endpoint_inventory`.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::Project;
use crate::endpoints::{read_head, unescape_path, walk};
use crate::init_services::{Start, names, scan};
use crate::workflows::{Confidence, Finding, ReportInput, ReportLimits, Section, WorkflowReport, may_capture};

const DEFAULT_FILES: usize = 10;
const MAX_FILES: usize = 50;
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const MAX_TIMEOUT_MS: u64 = 300_000;
/// Programs larger than this are skipped.
const MAX_PROGRAM_BYTES: u64 = 256 << 20;
/// Programs listed as skipped for lacking capture APIs, by name.
const MAX_SKIPPED_NAMED: usize = 20;
/// Ways each program is started, listed per program.
const MAX_STARTS: usize = 4;

struct Arguments {
    limits: ReportLimits,
    cursor: Option<String>,
    max_files: usize,
    timeout: Duration,
}

fn arguments(input: &Value) -> Result<Arguments, String> {
    let number = |key: &str| -> Result<Option<u64>, String> {
        match input.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => value
                .as_u64()
                .map(Some)
                .ok_or_else(|| format!("invalid arguments: {key} must be a non-negative integer")),
        }
    };
    let max_files = number("max_files")?.map_or(DEFAULT_FILES, |count| count as usize);
    if !(1..=MAX_FILES).contains(&max_files) {
        return Err(format!("max_files must be in 1..={MAX_FILES}"));
    }
    let timeout = number("timeout_ms")?.unwrap_or(DEFAULT_TIMEOUT_MS);
    if !(1..=MAX_TIMEOUT_MS).contains(&timeout) {
        return Err(format!("timeout_ms must be in 1..={MAX_TIMEOUT_MS}"));
    }
    let cursor = match input.get("cursor") {
        None | Some(Value::Null) => None,
        Some(Value::String(cursor)) => Some(cursor.clone()),
        Some(_) => return Err("invalid arguments: cursor must be a string".to_owned()),
    };
    Ok(Arguments {
        limits: ReportLimits::new(number("max_per_section")?.map(|count| count as usize)),
        cursor,
        max_files,
        timeout: Duration::from_millis(timeout),
    })
}

/// A finding of the file at `relative`, labelled with it.
fn labelled(mut finding: Finding, relative: &str) -> Finding {
    finding.observation = format!("{relative}: {}", finding.observation);
    if !finding.evidence.first().is_some_and(|line| line.starts_with("origin:")) {
        finding.evidence.insert(0, format!("origin: {relative}"));
    } else {
        finding.evidence[0] = format!("origin: {relative} {}", &finding.evidence[0]["origin: ".len()..]);
    }
    finding
}

/// The report on the directory `root`.
pub(crate) fn report(root: &Path, input: &Value) -> Result<WorkflowReport, String> {
    let args = arguments(input)?;
    let deadline = Instant::now() + args.timeout;
    let (files, symlinks) = walk(root, deadline)?;
    let starts = scan(files.iter().map(|(_, relative, path, size)| (relative.as_str(), path.as_path(), *size)));
    let start = match &args.cursor {
        Some(cursor) => {
            let cursor = unescape_path(cursor)?;
            files.partition_point(|(key, ..)| *key < cursor)
        }
        None => 0,
    };
    let limits = args.limits;
    let titles = [
        "Capture sources",
        "Capture-to-send paths",
        "Capture triggers",
        "Send and write sinks",
        "Excluded: not capture",
        "Capture strings not referenced from code",
    ];
    let mut sections: Vec<Section> = titles.iter().map(|title| Section::new(*title, limits)).collect();
    let mut boot_section = Section::new("Boot services", limits);
    let mut limitations: BTreeSet<String> = BTreeSet::new();
    let mut summary: Vec<String> = Vec::new();
    let mut analysed = 0usize;
    let mut without_capture: Vec<String> = Vec::new();
    let mut without_capture_total = 0usize;
    let mut skipped: Vec<String> = Vec::new();
    let mut next_cursor = None;
    let mut boot_captures = 0usize;
    for (_, relative, path, size) in &files[start..] {
        let Ok(head) = read_head(path) else { continue };
        let extension = relative.rsplit('.').next().map(str::to_ascii_lowercase);
        let zip = head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06");
        let android =
            rampage_dex::is_dex(&head) || (zip && matches!(extension.as_deref(), Some("apk" | "aab" | "jar")));
        let executable = !android && rampage_unpack::executable_format(&head).is_some();
        if !android && !executable {
            continue;
        }
        // A page ends only at a file it would read, so the last page is not empty of programs.
        if analysed > 0 && (Instant::now() >= deadline || analysed >= args.max_files) {
            next_cursor = Some(relative.clone());
            break;
        }
        if *size > MAX_PROGRAM_BYTES {
            skipped.push(format!("{relative} (over {} MiB)", MAX_PROGRAM_BYTES >> 20));
            continue;
        }
        let report = if android {
            crate::android_privacy::report(path, limits)
        } else {
            let bytes = match std::fs::read(path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    skipped.push(format!("{relative} (unreadable: {error})"));
                    continue;
                }
            };
            let binary = match rampage_loaders::Binary::open(path) {
                Ok(binary) => binary,
                Err(error) => {
                    skipped.push(format!("{relative} (did not load: {error})"));
                    continue;
                }
            };
            if !may_capture(&binary, &bytes) {
                without_capture_total += 1;
                if without_capture.len() < MAX_SKIPPED_NAMED {
                    without_capture.push(relative.clone());
                }
                continue;
            }
            drop(bytes);
            Project::new(binary).privacy_surface(limits).map_err(|error| error.to_string())
        };
        analysed += 1;
        let report = match report {
            Ok(report) => report,
            Err(error) => {
                skipped.push(format!("{relative} ({error})"));
                continue;
            }
        };
        let program_start: Vec<&Start> = starts
            .starts
            .iter()
            .filter(|start| names(&start.program, relative).is_some_and(|how| how != "file name only"))
            .collect();
        let by_name: Vec<&Start> = if program_start.is_empty() {
            starts.starts.iter().filter(|start| names(&start.program, relative).is_some()).collect()
        } else {
            Vec::new()
        };
        let captures = report.sections.first().is_some_and(|section| section.total > 0);
        for (section, found) in sections.iter_mut().zip(&report.sections) {
            section.extend(found.findings.iter().cloned().map(|finding| labelled(finding, relative)));
            section.total += found.total - found.findings.len().min(found.total);
        }
        if let Some(line) = report.summary.first() {
            summary.push(format!("{relative}: {line}"));
        }
        limitations.extend(report.limitations.iter().cloned());
        let at_start: Vec<&Finding> = report
            .section("Capture triggers")
            .map(|section| {
                section.findings.iter().filter(|finding| finding.observation.starts_with("no_user_trigger:")).collect()
            })
            .unwrap_or_default();
        let boot: Vec<&&Start> = program_start.iter().chain(&by_name).filter(|start| start.boot).collect();
        if captures && let Some(first) = boot.first() {
            boot_captures += 1;
            let matched = names(&first.program, relative).unwrap_or("path");
            let mut evidence = vec![
                format!("origin: {relative}"),
                "trigger: start at boot (init)".to_owned(),
                format!("{} ({}:{}), matched by {matched}", first.how, first.file, first.line),
            ];
            evidence.extend(
                boot.iter()
                    .skip(1)
                    .take(MAX_STARTS - 1)
                    .map(|start| format!("also: {} ({}:{})", start.how, start.file, start.line)),
            );
            let (observation, confidence) = if at_start.is_empty() {
                (format!("{relative}: a program with capture sources is started at boot"), Confidence::Medium)
            } else {
                evidence.extend(at_start.iter().map(|finding| format!("in the program: {}", finding.observation)));
                (
                    format!(
                        "no_user_trigger: {relative} is started at boot, and its capture is reached from program start \
                         with no user-facing trigger found"
                    ),
                    if matched == "file name only" { Confidence::Low } else { Confidence::Medium },
                )
            };
            let triggers = &mut sections[2];
            triggers.findings.insert(0, Finding::new("privacy_surface", confidence, observation).evidence(evidence));
            triggers.total += 1;
            if triggers.findings.len() > limits.per_section {
                triggers.findings.truncate(limits.per_section);
                triggers.truncated = true;
            }
        }
    }
    for start in &starts.starts {
        let found = files
            .iter()
            .find(|(_, relative, ..)| names(&start.program, relative).is_some_and(|how| how != "file name only"));
        let observation = format!(
            "{} {} {}",
            start.program,
            if start.boot { "is started at boot by" } else { "is started on a trigger by" },
            start.how
        );
        let mut evidence = vec![format!("{}:{}", start.file, start.line)];
        evidence.push(match found {
            Some((_, relative, ..)) => format!("in the tree as {relative}"),
            None => "not found in the tree".to_owned(),
        });
        boot_section.push(Finding::new("privacy_surface", Confidence::Observed, observation).evidence(evidence));
    }
    for section in &mut sections {
        section.truncated = section.total > section.findings.len();
    }

    let mut report = WorkflowReport::for_input(
        "privacy_surface",
        ReportInput {
            kind: "directory",
            path: root.display().to_string(),
            sha256: None,
            files: Some(analysed),
            next_cursor: next_cursor.clone(),
        },
    );
    let booted = starts.starts.iter().filter(|start| start.boot).count();
    report.summary.push(format!(
        "{analysed} programs and APKs analysed on this page ({without_capture_total} more programs import no capture \
         API and name no capture device, and were not analysed); {} init files name {} programs started at boot and \
         {} started on a trigger; {boot_captures} analysed programs with capture sources are started at boot.",
        starts.files,
        booted,
        starts.starts.len() - booted
    ));
    report.summary.extend(summary);
    if next_cursor.is_some() {
        report.summary.push("More files remain: call again with cursor set to input.next_cursor.".to_owned());
    }
    report.summary.push(
        "This is evidence of what the code can do and how it is reached, not of intent or that it runs.".to_owned(),
    );
    report.sections.extend(sections);
    report.sections.push(boot_section);
    if !without_capture.is_empty() {
        let more = without_capture_total - without_capture.len();
        let more = if more > 0 { format!(" and {more} more") } else { String::new() };
        report.limitation(format!(
            "Programs not analysed because they import no capture API and name no capture device or Android capture \
             class (a program capturing through raw system calls or names built at run time is missed): {}{more}.",
            without_capture.join(", ")
        ));
    }
    if !skipped.is_empty() {
        report.limitation(format!("Files not analysed: {}.", skipped.join("; ")));
    }
    if symlinks > 0 {
        report.limitation(format!(
            "{symlinks} symbolic links were not followed (a systemd unit enabled by a link in a .wants directory is \
             read from the unit file itself)."
        ));
    }
    for note in &starts.notes {
        report.limitation(format!("Init files: {note}."));
    }
    report.limitation(
        "Boot starts are read from Android init .rc files (a service not marked disabled starts with its class at \
         boot; `start` in an `on boot` or boot-complete property action), systemd units with a boot target in \
         WantedBy, init.d scripts and inittab. Programs are matched to init files by their device path, or by file \
         name alone when the path does not match the tree (marked so). Programs started by other programs at run \
         time are not traced.",
    );
    for text in limitations {
        report.limitation(text);
    }
    if let Some(cursor) = &next_cursor {
        report.step("privacy_surface", serde_json::json!({ "cursor": cursor }), "Read the next page of the tree.");
    }
    report.step("endpoint_inventory", serde_json::json!({}), "List every endpoint the tree's programs name.");
    Ok(report)
}
