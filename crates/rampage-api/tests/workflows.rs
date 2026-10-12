use std::path::PathBuf;
use std::sync::Arc;

use rampage_api::{FindingConfidence, Project, ReportLimits, Section, Session, WorkflowReport};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn local_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn open(path: PathBuf) -> Arc<Project> {
    Session::default().open(&path, None).unwrap()
}

fn section<'a>(report: &'a WorkflowReport, title: &str) -> &'a Section {
    report.section(title).unwrap_or_else(|| panic!("no section {title:?} in {report:#?}"))
}

fn observations(section: &Section) -> Vec<&str> {
    section.findings.iter().map(|finding| finding.observation.as_str()).collect()
}

fn has_observation(section: &Section, needle: &str) -> bool {
    section.findings.iter().any(|finding| finding.observation.contains(needle))
}

/// Every report carries limitations and only bounded lists, and serializes.
fn assert_well_formed(report: &WorkflowReport) {
    assert!(!report.limitations.is_empty(), "{report:#?}");
    assert!(!report.summary.is_empty(), "{report:#?}");
    for section in &report.sections {
        assert!(section.total >= section.findings.len());
        assert_eq!(section.truncated, section.total > section.findings.len(), "{section:#?}");
        for finding in &section.findings {
            assert!(!finding.source.is_empty());
        }
    }
    serde_json::to_string(report).unwrap();
}

#[test]
fn triage_report_on_a_mingw_pe_names_the_toolchain_and_imports() {
    let report = open(fixture("hello-x64.exe")).triage_report(ReportLimits::default()).unwrap();
    assert_well_formed(&report);
    assert_eq!(report.workflow, "triage_report");
    let toolchain = section(&report, "Toolchain");
    assert!(has_observation(toolchain, "MinGW/GCC"), "{:?}", observations(toolchain));
    let imports = section(&report, "Imports by library");
    assert!(!imports.findings.is_empty());
    assert!(has_observation(imports, "api-ms-win-crt-runtime-l1-1-0.dll"), "{:?}", observations(imports));
    assert!(report.summary.iter().any(|line| line.contains("MinGW/GCC")), "{:?}", report.summary);
    assert!(report.next_steps.iter().any(|step| step.tool == "find_main"));
    // Shared-hash signature matches are reported as likely stubs, never as a confident identification.
    let functions = section(&report, "Functions");
    let shared = functions.findings.iter().find(|finding| finding.observation.contains("__lctrans")).unwrap();
    assert_eq!(shared.confidence, FindingConfidence::Low);
}

#[test]
fn triage_report_surfaces_network_strings_and_suggests_network_surface() {
    let report = open(local_fixture("net-client-x64.elf")).triage_report(ReportLimits::default()).unwrap();
    assert_well_formed(&report);
    let strings = section(&report, "Notable strings");
    assert!(has_observation(strings, "URL: \"http://updates.example.com:8080/check\""), "{:?}", observations(strings));
    assert!(has_observation(strings, "IPv4-like address: \"198.51.100.23\""), "{:?}", observations(strings));
    assert!(report.next_steps.iter().any(|step| step.tool == "network_surface"), "{:?}", report.next_steps);
    let capabilities = section(&report, "Capabilities");
    assert!(capabilities.findings.iter().all(|finding| finding.confidence == FindingConfidence::Low));
    assert!(has_observation(capabilities, "Network communication"));
}

#[test]
fn triage_report_on_a_static_binary_states_the_missing_imports() {
    let report = open(fixture("musl-static-x86_64.elf")).triage_report(ReportLimits::default()).unwrap();
    assert_well_formed(&report);
    assert!(section(&report, "Imports by library").findings.is_empty());
    assert!(report.limitations.iter().any(|text| text.contains("No dynamic imports")));
    let functions = section(&report, "Functions");
    assert!(has_observation(functions, "functions discovered"));
    assert!(has_observation(functions, "`exit`"), "{:?}", observations(functions));
}

#[test]
fn triage_report_reports_truncated_sections() {
    let report = open(fixture("hello-x64.exe")).triage_report(ReportLimits::new(Some(1))).unwrap();
    assert_well_formed(&report);
    let imports = section(&report, "Imports by library");
    assert_eq!(imports.findings.len(), 1);
    assert!(imports.truncated && imports.total > 1, "{imports:#?}");
}
