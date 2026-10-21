use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::{FindingConfidence, Project, ReportLimits, Section, Session, WorkflowReport};
use rampage_loaders::LoadError;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

fn local_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A fresh directory under the canonical temp dir, removed on drop (including when a test panics).
struct Scratch(PathBuf);

impl Scratch {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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
    // Every suggestion names the group serving its tool, so an agent knows which one to enable.
    for step in &report.next_steps {
        assert_eq!(step.group, rampage_api::tools::group_of(step.tool).map(|group| group.name()), "{step:?}");
        assert!(step.group.is_some(), "{step:?}");
    }
    serde_json::to_string(report).unwrap();
}

#[test]
fn triage_report_on_a_mingw_pe_names_the_toolchain_and_imports() {
    let report = open(fixture("hello-x64.exe")).triage_report(ReportLimits::default()).unwrap();
    assert_well_formed(&report);
    assert_eq!(report.workflow, "triage_report");
    let toolchain = section(&report, "Toolchain");
    assert!(has_observation(toolchain, "MinGW-w64"), "{:?}", observations(toolchain));
    let imports = section(&report, "Imports by library");
    assert!(!imports.findings.is_empty());
    assert!(has_observation(imports, "api-ms-win-crt-runtime-l1-1-0.dll"), "{:?}", observations(imports));
    assert!(report.summary.iter().any(|line| line.contains("MinGW-w64")), "{:?}", report.summary);
    assert!(report.next_steps.iter().any(|step| step.tool == "find_main"));
    // The curated default corpus withholds the generic stub hash the frozen musl database names `__lctrans`.
    let functions = section(&report, "Functions");
    assert!(!has_observation(functions, "__lctrans"), "{:?}", observations(functions));
}

#[test]
fn triage_report_reports_shared_hash_signature_matches_as_likely_stubs() {
    // The frozen musl database still names a generic MinGW stub hash `__lctrans`, so a pack supplying it reproduces
    // a name proposed at several addresses.
    let scratch = Scratch::new("rampage-api-shared-hash-pack");
    let directory = scratch.0.clone();
    std::fs::write(directory.join("x86_64.json"), include_str!("../../rampage-signatures/data/musl-x86_64.json"))
        .unwrap();
    std::fs::write(
        directory.join("rampage-pack.toml"),
        "name = \"legacy-musl\"\nversion = \"1.0.0\"\nlicense = \"MIT\"\nsource = \"https://example.com/legacy-musl\"\n\
         description = \"Test pack\"\n[[contents]]\nkind = \"signatures\"\npath = \"x86_64.json\"\narch = \"x86_64\"\n",
    )
    .unwrap();
    let packs = rampage_api::Packs::load(std::slice::from_ref(&directory));
    let project = Session::default().with_packs(Arc::new(packs)).open(&fixture("hello-x64.exe"), None);
    let report = project.unwrap().triage_report(ReportLimits::default());
    drop(scratch);
    let report = report.unwrap();
    assert_well_formed(&report);
    // Shared-hash signature matches are reported as likely stubs, never as a confident identification.
    let functions = section(&report, "Functions");
    let shared = functions.findings.iter().find(|finding| finding.observation.contains("__lctrans"));
    let shared = shared.unwrap_or_else(|| panic!("{:?}", observations(functions)));
    assert_eq!(shared.confidence, FindingConfidence::Low);
    assert!(shared.observation.contains("share the masked hash"), "{}", shared.observation);
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
    // The default cap can cut the bundled-signature matches short; look at all of them.
    let full = open(fixture("musl-static-x86_64.elf")).triage_report(ReportLimits::new(Some(200))).unwrap();
    let functions = section(&full, "Functions");
    assert!(has_observation(functions, "`exit`"), "{:?}", observations(functions));
    let identify = report.next_steps.iter().find(|step| step.tool == "identify_functions").unwrap();
    assert_eq!(identify.group, Some("detection"));
    let json = serde_json::to_value(identify).unwrap();
    assert_eq!(json["group"], "detection");
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
    // References are recovered by analysis, an inference rather than a structural observation.
    for title in ["Candidate calls", "Candidate strings"] {
        assert!(section(&report, title).findings.iter().all(|finding| finding.confidence == FindingConfidence::High));
    }
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
    let provenance = "named by a signature in the bundled starter database";
    assert!(best.evidence.iter().any(|line| line.contains(provenance)), "{best:#?}");
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
fn find_crypto_links_a_constant_to_the_code_that_uses_it() {
    // Go's runtime seeds its ChaCha8 random source with the ChaCha "expand 32-byte k" constant.
    let report = open(fixture("hello-go-arm64.elf")).find_crypto(ReportLimits::default()).unwrap();
    assert_well_formed(&report);
    let constants = section(&report, "Cryptographic constants");
    assert!(has_observation(constants, "expand 32-byte k"), "{constants:#?}");
    let finding = &constants.findings[0];
    assert!(finding.evidence.iter().any(|line| line.contains("ChaCha")), "{finding:#?}");
    let functions = section(&report, "Functions referencing crypto evidence");
    assert!(has_observation(functions, "`internal/chacha8rand.block`"), "{functions:#?}");
    assert!(report.next_steps.iter().any(|step| step.tool == "decompile"), "{report:#?}");
}

#[test]
fn find_crypto_without_crypto_is_empty_but_honest() {
    let report = open(fixture("hello-x64.elf")).find_crypto(ReportLimits::default()).unwrap();
    assert_well_formed(&report);
    assert!(report.sections.iter().all(|section| section.findings.is_empty()), "{report:#?}");
    assert!(report.summary[0].starts_with("No algorithm constants"), "{:?}", report.summary);
    assert!(report.limitations.iter().any(|text| text.contains("not that the algorithm runs")));
}

#[test]
fn find_crypto_says_when_the_constant_scan_hit_its_cap() {
    // 3000 ChaCha constants in `.text` and 2000 in `.rdata`: neither segment reaches the cap alone, but together
    // they pass it, so the pooled scan drops the highest-addressed hits.
    let mut bytes = std::fs::read(fixture("hello-x64.exe")).unwrap();
    let mut plant = |file_offset: usize, count: usize| {
        let constants = b"expand 32-byte k".repeat(count);
        bytes[file_offset..file_offset + constants.len()].copy_from_slice(&constants);
    };
    plant(0x2_8400 - 16 * 3000, 3000);
    plant(0x2_8600, 2000);
    let directory = std::env::temp_dir().join(format!("rampage-api-crypto-cap-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("many-constants.exe");
    std::fs::write(&path, &bytes).unwrap();
    let report = open(path).find_crypto(ReportLimits::default());
    std::fs::remove_dir_all(&directory).unwrap();
    let report = report.unwrap();
    assert_well_formed(&report);
    assert!(
        report.limitations.iter().any(|text| text.contains("cap of 4096 hits") && text.contains("dropped")),
        "{:?}",
        report.limitations
    );
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
    // Stripped and static images include unnamed bodies too small to hash; they must still pair with themselves.
    for name in ["hello-x64.elf", "musl-static-x86_64.elf", "hello-arm64.elf", "hello-x64.exe"] {
        let report = open(fixture(name)).diff_builds(&fixture(name), ReportLimits::default()).unwrap();
        assert_well_formed(&report);
        assert!(report.summary[0].contains("byte-identical"), "{name}: {:?}", report.summary);
        for title in
            ["Changed functions", "Added functions", "Removed functions", "Import differences", "String differences"]
        {
            assert!(section(&report, title).findings.is_empty(), "{name} {title}: {report:#?}");
        }
    }
}

#[test]
fn diff_builds_refuses_another_architecture() {
    let error =
        open(fixture("hello-x64.elf")).diff_builds(&fixture("hello-arm64.elf"), ReportLimits::default()).unwrap_err();
    assert!(error.to_string().contains("needs both binaries in x86_64"), "{error}");
}

#[test]
fn diff_builds_reports_load_failures_as_such() {
    let directory = std::env::temp_dir().join(format!("rampage-diff-load-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let snapshot = directory.join("unknown-arch.json");
    let text = r#"{"format": "rampage-snapshot-v1", "arch": "vax", "entry": null, "provenance": "test",
        "regions": [{"name": "r", "address": "0x1000", "permissions": "r--", "bytes": "00"}]}"#;
    std::fs::write(&snapshot, text).unwrap();
    let error = open(fixture("hello-x64.elf")).diff_builds(&snapshot, ReportLimits::default()).unwrap_err();
    std::fs::remove_dir_all(&directory).unwrap();
    // Unsupported, but not an architecture mismatch: the file does not load in any architecture.
    let unsupported = matches!(&error, rampage_api::ApiError::Load { source: LoadError::Unsupported(_), .. });
    assert!(unsupported, "{error:?}");
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

#[test]
fn persistence_surface_maps_unix_autostart_paths_to_the_code_writing_them() {
    let report = open(local_fixture("persist-x64.elf")).persistence_surface(ReportLimits::default()).unwrap();
    assert_well_formed(&report);
    let locations = section(&report, "Autostart locations in strings");
    for mechanism in [
        "systemd unit location: \"/etc/systemd/system/updater.service\"",
        "cron table location",
        "XDG autostart entry location",
        "macOS LaunchAgents plist location",
        "shell startup file: \".bashrc\"",
    ] {
        assert!(has_observation(locations, mechanism), "{mechanism} missing from {:?}", observations(locations));
    }
    let unit = locations.findings.iter().find(|finding| finding.observation.contains("systemd unit location")).unwrap();
    assert_eq!(unit.confidence, FindingConfidence::High);
    assert!(unit.evidence.iter().any(|line| line.contains("referenced from `install_unit`")), "{unit:#?}");
    // File-opening APIs count only because `append_line`, which calls fopen, is called by functions naming autostart
    // locations; stream writes are not listed.
    let apis = section(&report, "Persistence-related APIs");
    assert!(has_observation(apis, "`fopen` from libc.so.6 (file open/write)"), "{:?}", observations(apis));
    assert!(!has_observation(apis, "`fputs`"), "{:?}", observations(apis));
    let fopen = apis.findings.iter().find(|finding| finding.observation.contains("`fopen`")).unwrap();
    assert!(fopen.evidence[1].contains("references an autostart location"), "{fopen:#?}");
    let functions = observations(section(&report, "Functions referencing persistence indicators"));
    for name in ["`main`", "`install_unit`", "`append_line`"] {
        assert!(functions.iter().any(|observation| observation.starts_with(name)), "{name}: {functions:?}");
    }
    assert!(report.summary[0].contains("indicators, not evidence"), "{:?}", report.summary);
    // Functions naming autostart locations are suggested before the one only calling a file API.
    let decompile: Vec<&str> = report
        .next_steps
        .iter()
        .filter(|step| step.tool == "decompile")
        .map(|step| step.reason.split('`').nth(1).unwrap())
        .collect();
    assert_eq!(decompile, ["main", "install_unit", "append_line"], "{:?}", report.next_steps);
    assert!(report.next_steps.iter().any(|step| step.tool == "xrefs"), "{:?}", report.next_steps);
}

#[test]
fn persistence_surface_reports_windows_run_keys_services_and_tags() {
    let report = open(local_fixture("persist-x64.exe")).persistence_surface(ReportLimits::default()).unwrap();
    assert_well_formed(&report);
    let locations = section(&report, "Autostart locations in strings");
    assert!(has_observation(locations, "Windows Run registry key"), "{:?}", observations(locations));
    assert!(has_observation(locations, "Windows scheduled task command"), "{:?}", observations(locations));
    let run = locations.findings.iter().find(|finding| finding.observation.contains("Run registry key")).unwrap();
    assert!(run.evidence.iter().any(|line| line.starts_with("referenced from")), "{run:#?}");
    let apis = section(&report, "Persistence-related APIs");
    for api in ["`CreateServiceA`", "`OpenSCManagerA`", "`RegSetValueExA`"] {
        assert!(has_observation(apis, api), "{api} missing from {:?}", observations(apis));
    }
    let create = apis.findings.iter().find(|finding| finding.observation.contains("`CreateServiceA`")).unwrap();
    assert!(create.observation.ends_with("(service installation)"), "{create:#?}");
    assert!(create.evidence.iter().any(|line| line.starts_with("referenced from")), "{create:#?}");
    // The registry write is listed because its caller also names the Run key; the stdio write is not listed.
    let set = apis.findings.iter().find(|finding| finding.observation.contains("`RegSetValueExA`")).unwrap();
    assert!(set.evidence[1].contains("autostart registry key"), "{set:#?}");
    assert!(!has_observation(apis, "`fwrite`"), "{:?}", observations(apis));
    let tags = section(&report, "Persistence capability tags");
    assert!(has_observation(tags, "Registry autorun modification indicators"), "{:?}", observations(tags));
    assert!(has_observation(tags, "Service installation indicators"), "{:?}", observations(tags));
    assert!(tags.findings.iter().all(|finding| finding.confidence == FindingConfidence::Low));
    assert!(!section(&report, "Functions referencing persistence indicators").findings.is_empty());
}

#[test]
fn persistence_surface_without_indicators_is_empty_but_honest() {
    let report = open(fixture("hello-x64.elf")).persistence_surface(ReportLimits::default()).unwrap();
    assert_well_formed(&report);
    assert!(report.sections.iter().all(|section| section.findings.is_empty()), "{report:#?}");
    assert!(report.summary[0].starts_with("No autostart location strings"), "{:?}", report.summary);
    assert!(report.limitations.iter().any(|text| text.contains("listed only beside an autostart location")));
    assert!(report.limitations.iter().any(|text| text.contains("Absence of evidence is not evidence of absence")));
}

#[test]
fn string_decoding_finds_a_byte_xor_loop_and_the_blobs_passed_to_it() {
    for name in ["decode-x64.elf", "decode-arm64.elf"] {
        let report = open(local_fixture(name)).string_decoding(ReportLimits::default()).unwrap();
        assert_well_formed(&report);
        let routines = section(&report, "Candidate decoding routines");
        assert_eq!(routines.total, 1, "{name}: {routines:#?}");
        let decode = &routines.findings[0];
        assert!(decode.observation.starts_with("`decode` has a byte loop applying XOR"), "{name}: {decode:#?}");
        assert!(decode.observation.contains("3 direct call sites, 3 passing"), "{name}: {decode:#?}");
        assert_eq!(decode.confidence, FindingConfidence::Medium, "{name}");
        let sites = section(&report, "Call sites");
        assert_eq!(sites.total, 3, "{name}: {sites:#?}");
        assert!(sites.findings.iter().all(|site| site.evidence[0].contains("from `main`")), "{name}: {sites:#?}");
        let blobs = section(&report, "Referenced data blobs");
        assert_eq!(blobs.total, 3, "{name}: {blobs:#?}");
        // The first blob is the 12-byte encoded "hello, world", cut at the next referenced blob.
        let first = &blobs.findings[0];
        assert!(first.evidence[0].starts_with("about 12 bytes"), "{name}: {first:#?}");
        assert!(first.evidence[1].starts_with("entropy 3.42 bits/byte, 58% non-printable"), "{name}: {first:#?}");
        assert_eq!(first.evidence[2], "leading bytes 32944c115887b411663db790", "{name}");
        let functions = section(&report, "Functions calling candidates or referencing their blobs");
        assert!(has_observation(functions, "`main` references 4 items"), "{name}: {functions:#?}");
        assert!(report.next_steps.iter().any(|step| step.tool == "decompile"), "{name}");
        assert!(report.limitations.iter().any(|text| text.contains("Nothing is emulated or executed")));
    }
}

#[test]
fn string_decoding_without_encoded_arguments_stays_low() {
    // Go's runtime has XOR byte loops (random seeding, hex dumping) whose callers pass no encoded-looking data.
    let report = open(fixture("hello-go-x64.elf")).string_decoding(ReportLimits::default()).unwrap();
    assert_well_formed(&report);
    let routines = section(&report, "Candidate decoding routines");
    assert!(routines.total > 0, "{report:#?}");
    assert!(routines.findings.iter().all(|finding| finding.confidence == FindingConfidence::Low), "{routines:#?}");
    assert_eq!(section(&report, "Referenced data blobs").total, 0);
}

#[test]
fn string_decoding_without_byte_loops_is_empty_but_honest() {
    let report = open(fixture("hello-x64.elf")).string_decoding(ReportLimits::default()).unwrap();
    assert_well_formed(&report);
    assert!(report.sections.iter().all(|section| section.findings.is_empty()), "{report:#?}");
    assert!(report.summary[0].starts_with("No byte loop"), "{:?}", report.summary);
    let covered = "recognized on x86, AArch64, 32-bit ARM, MIPS, PowerPC, RISC-V, SPARC, s390x and m68k";
    assert!(report.limitations.iter().any(|text| text.contains(covered)), "{:?}", report.limitations);
}

#[test]
fn string_decoding_reports_truncation() {
    let report = open(local_fixture("decode-x64.elf")).string_decoding(ReportLimits::new(Some(1))).unwrap();
    assert_well_formed(&report);
    let sites = section(&report, "Call sites");
    assert_eq!(sites.findings.len(), 1);
    assert!(sites.truncated && sites.total == 3, "{sites:#?}");
}
