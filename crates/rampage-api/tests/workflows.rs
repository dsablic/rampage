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
fn triage_report_lists_network_indicators_before_build_paths() {
    let report = open(fixture("hello-go-x64.elf")).triage_report(ReportLimits::new(Some(1))).unwrap();
    let strings = section(&report, "Notable strings");
    assert!(strings.truncated, "{strings:#?}");
    assert!(strings.findings[0].observation.starts_with("URL:"), "{:?}", observations(strings));
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

fn best_candidate(report: &WorkflowReport) -> &rampage_api::Finding {
    section(report, "Candidates").findings.first().unwrap_or_else(|| panic!("no candidate in {report:#?}"))
}

#[test]
fn find_main_trusts_the_main_symbol_and_corroborates_it_from_the_startup_code() {
    let report = open(fixture("hello-x64.elf")).find_main(ReportLimits::default(), true).unwrap();
    assert_well_formed(&report);
    let best = best_candidate(&report);
    assert_eq!(best.address, Some(0x1001910));
    assert_eq!(best.confidence, FindingConfidence::High);
    assert!(best.evidence.iter().any(|line| line.contains("corroborated by disassemble")), "{best:#?}");
    assert!(has_observation(section(&report, "Candidate calls"), "`puts`"));
    assert!(has_observation(section(&report, "Candidate strings"), "rampage fixture greeting"));
    let preview = section(&report, "Decompilation preview").excerpt.as_ref().expect("a decompilation preview");
    assert!(preview.text.contains("puts("), "{}", preview.text);
    assert!(report.next_steps.iter().any(|step| step.tool == "decompile"));
    // A named candidate needs no rename suggestion.
    assert!(report.next_steps.iter().all(|step| step.tool != "rename"));
}

#[test]
fn find_main_follows_the_libc_start_main_argument_in_a_stripped_binary() {
    let symbols = open(local_fixture("net-client-x64.elf"));
    let main = symbols.resolve("main").unwrap();
    let report = open(local_fixture("net-client-x64-stripped.elf")).find_main(ReportLimits::default(), false).unwrap();
    assert_well_formed(&report);
    let best = best_candidate(&report);
    assert_eq!(best.address, Some(main));
    assert_eq!(best.confidence, FindingConfidence::Medium);
    assert!(best.observation.contains("heuristic"));
    assert!(best.evidence.iter().any(|line| line.contains("lea rdi")), "{best:#?}");
    assert!(has_observation(section(&report, "Candidate calls"), "`send@plt`"));
    assert!(report.section("Decompilation preview").is_none());
    assert!(report.next_steps.iter().any(|step| step.tool == "rename"));
}

#[test]
fn find_main_marks_an_unnamed_startup_target_as_low_confidence() {
    let report = open(fixture("musl-static-x86_64.elf")).find_main(ReportLimits::default(), false).unwrap();
    assert_well_formed(&report);
    let best = best_candidate(&report);
    assert_eq!(best.address, Some(0x1002b50));
    assert_eq!(best.confidence, FindingConfidence::Low);
    assert!(has_observation(section(&report, "Candidate strings"), "another-program-entirely"));
    // Low confidence never earns a rename suggestion.
    assert!(report.next_steps.iter().all(|step| step.tool != "rename"));
}

#[test]
fn find_main_follows_the_mingw_crt_to_main() {
    let report = open(fixture("hello-x64.exe")).find_main(ReportLimits::default(), false).unwrap();
    assert_well_formed(&report);
    let candidates = section(&report, "Candidates");
    assert_eq!(candidates.total, 1, "{candidates:#?}");
    let best = best_candidate(&report);
    assert_eq!(best.address, Some(0x140001010));
    assert_eq!(best.confidence, FindingConfidence::Low);
    assert!(best.evidence.iter().any(|line| line.contains("_cexit")), "{best:#?}");
    assert!(has_observation(section(&report, "Candidate calls"), "import `puts`"));
}

#[test]
fn find_main_uses_the_mach_o_entry_convention() {
    let report = open(fixture("hello-x64-stripped.macho")).find_main(ReportLimits::default(), false).unwrap();
    assert_well_formed(&report);
    let best = best_candidate(&report);
    assert_eq!(best.address, Some(0x100000480));
    assert_eq!(best.confidence, FindingConfidence::Medium);
    assert!(best.observation.contains("LC_MAIN"));
}

#[test]
fn find_main_finds_go_main_main() {
    let report = open(fixture("hello-go-x64.elf")).find_main(ReportLimits::default(), false).unwrap();
    assert!(best_candidate(&report).observation.contains("`main.main`"));
    assert!(has_observation(section(&report, "Candidate calls"), "`main.greet`"));
}

#[test]
fn find_main_reports_an_honest_not_found() {
    let report = open(fixture("libhelper-x64.so")).find_main(ReportLimits::default(), true).unwrap();
    assert_well_formed(&report);
    assert!(section(&report, "Candidates").findings.is_empty());
    assert!(report.summary[0].contains("No main candidate found"), "{:?}", report.summary);
    assert!(report.section("Decompilation preview").is_none());
    assert!(report.next_steps.iter().any(|step| step.tool == "list_functions"));
}

#[test]
fn network_surface_maps_apis_and_strings_to_the_functions_using_them() {
    let report = open(local_fixture("net-client-x64.elf")).network_surface(ReportLimits::default()).unwrap();
    assert_well_formed(&report);
    let apis = section(&report, "Networking APIs");
    for api in ["`socket`", "`connect`", "`getaddrinfo`", "`send`"] {
        assert!(has_observation(apis, api), "{api} missing from {:?}", observations(apis));
    }
    let connect = apis.findings.iter().find(|finding| finding.observation.contains("`connect`")).unwrap();
    assert!(connect.evidence.iter().any(|line| line.contains("`open_connection`")), "{connect:#?}");
    let strings = section(&report, "Network indicators in strings");
    let url = strings.findings.iter().find(|finding| finding.observation.starts_with("URL")).unwrap();
    assert!(url.evidence.iter().any(|line| line.contains("referenced from `main`")), "{url:#?}");
    let functions = section(&report, "Functions referencing networking evidence");
    let names: Vec<&str> = observations(functions);
    assert!(names[0].starts_with("`open_connection`"), "{names:?}");
    assert!(names.iter().any(|name| name.starts_with("`main`")), "{names:?}");
    assert!(has_observation(section(&report, "Networking capability tags"), "Network communication"));
    assert!(report.next_steps.iter().any(|step| step.tool == "decompile"));
}

#[test]
fn network_surface_without_networking_is_empty_but_honest() {
    let report = open(fixture("hello-x64.elf")).network_surface(ReportLimits::default()).unwrap();
    assert_well_formed(&report);
    assert!(report.sections.iter().all(|section| section.findings.is_empty()), "{report:#?}");
    assert!(report.summary[0].starts_with("No networking APIs"), "{:?}", report.summary);
    assert!(report.limitations.iter().any(|text| text.contains("Absence of evidence is not evidence of absence")));
}

#[test]
fn network_surface_reports_truncation() {
    let report = open(local_fixture("net-client-x64.elf")).network_surface(ReportLimits::new(Some(2))).unwrap();
    assert_well_formed(&report);
    let apis = section(&report, "Networking APIs");
    assert_eq!(apis.findings.len(), 2);
    assert!(apis.truncated && apis.total == 5, "{apis:#?}");
}

#[test]
fn diff_builds_matches_add_across_static_and_dynamic_builds() {
    let report =
        open(fixture("hello-x64.elf")).diff_builds(&fixture("hello-x64-dyn.elf"), ReportLimits::default()).unwrap();
    assert_well_formed(&report);
    assert!(report.other.is_some());
    let identical = section(&report, "Identical functions");
    let add = identical.findings.iter().find(|finding| finding.observation.contains("`add`")).unwrap();
    assert_eq!(add.confidence, FindingConfidence::High);
    assert_eq!(add.address, Some(0x1001900));
    assert!(add.evidence[0].ends_with("0x1001510"), "{add:#?}");
    let imports = section(&report, "Import differences");
    assert!(has_observation(imports, "added: `puts` from libc.so.6"), "{:?}", observations(imports));
    assert!(has_observation(section(&report, "Removed functions"), "`__libc_start_main`"));
    assert!(report.limitations.iter().any(|text| text.contains("not proven semantic equivalence")));
}

#[test]
fn diff_builds_pairs_stripped_functions_by_hash() {
    let report = open(local_fixture("net-client-x64.elf"))
        .diff_builds(&local_fixture("net-client-x64-stripped.elf"), ReportLimits::default())
        .unwrap();
    assert_well_formed(&report);
    let matched = section(&report, "Functions matched by hash");
    assert!(has_observation(matched, "`main` and `sub_10016d0`"), "{:?}", observations(matched));
    assert!(has_observation(matched, "`open_connection` and `sub_1001730`"), "{:?}", observations(matched));
    assert!(section(&report, "Changed functions").findings.is_empty());
    assert!(section(&report, "Import differences").findings.is_empty());
}

#[test]
fn diff_builds_of_one_file_finds_no_changes() {
    let report =
        open(fixture("hello-x64.elf")).diff_builds(&fixture("hello-x64.elf"), ReportLimits::default()).unwrap();
    assert_well_formed(&report);
    assert!(report.summary[0].contains("byte-identical"), "{:?}", report.summary);
    for title in
        ["Changed functions", "Added functions", "Removed functions", "Import differences", "String differences"]
    {
        assert!(section(&report, title).findings.is_empty(), "{title}: {report:#?}");
    }
}

#[test]
fn diff_builds_refuses_another_architecture() {
    let error =
        open(fixture("hello-x64.elf")).diff_builds(&fixture("hello-arm64.elf"), ReportLimits::default()).unwrap_err();
    assert!(error.to_string().contains("one architecture"), "{error}");
}

#[test]
fn diff_builds_reports_truncation() {
    let report =
        open(fixture("hello-x64.elf")).diff_builds(&fixture("hello-x64-dyn.elf"), ReportLimits::new(Some(4))).unwrap();
    assert_well_formed(&report);
    let removed = section(&report, "Removed functions");
    assert_eq!(removed.findings.len(), 4);
    assert!(removed.truncated && removed.total > 4, "{removed:#?}");
}

#[test]
fn find_main_bounds_the_candidate_profile() {
    let report = open(fixture("musl-static-x86_64.elf")).find_main(ReportLimits::new(Some(3)), false).unwrap();
    assert_well_formed(&report);
    let calls = section(&report, "Candidate calls");
    assert_eq!(calls.findings.len(), 3);
    assert!(calls.truncated && calls.total > 3, "{calls:#?}");
}
