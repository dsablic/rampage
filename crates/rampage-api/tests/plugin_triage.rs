use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use rampage_api::{
    Packs, PluginTriageReport, PreparedPluginTriage, Project, ProjectWorkspaceTaskControl, ReportLimits, Session,
    WorkflowReport, prepare_plugin_triage, prepare_plugin_triage_with_analysis,
};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/net-client-x64.elf")
}

fn with_control<T>(work: impl FnOnce(&ProjectWorkspaceTaskControl<'_>) -> T) -> T {
    let cancellation = AtomicBool::new(false);
    let mut observer = |_| {};
    work(&ProjectWorkspaceTaskControl::new(&cancellation, &mut observer))
}

#[test]
fn default_preparation_does_not_start_discovery_or_other_primitive_caches() {
    let project = Session::default().open(&fixture(), None).unwrap();
    with_control(|control| {
        assert!(prepare_plugin_triage(Arc::clone(&project), ReportLimits::default(), control).is_err());
    });
    assert_eq!(project.analysis_cache_status(), Default::default());
}

#[test]
fn explicit_analysis_preparation_admits_current_source_and_names_changes_invalidate_it() {
    let project = Arc::new(Project::new(rampage_loaders::Binary::open(fixture()).unwrap()));
    with_control(|control| {
        let prepared =
            prepare_plugin_triage_with_analysis(Arc::clone(&project), ReportLimits::default(), control).unwrap();
        assert!(project.analysis_cache_status().program);
        assert!(prepared.fact_count() > 2);
        prepared.revalidate(control).unwrap();
        project.rename(project.binary.entry.unwrap(), Some("plugin_triage_new_entry_name")).unwrap();
        assert!(prepared.revalidate(control).is_err());
    });
}

#[test]
fn configured_packs_and_oversized_metadata_are_rejected_before_explicit_discovery() {
    with_control(|control| {
        let project = Session::default().open(&fixture(), None).unwrap();
        let packs = Arc::new(Packs::lazy(&[PathBuf::from("not-a-pack-and-must-not-be-opened")]));
        project.set_packs(Arc::clone(&packs));
        assert!(prepare_plugin_triage_with_analysis(Arc::clone(&project), ReportLimits::default(), control).is_err());
        assert!(!packs.is_loaded());
        assert!(!project.analysis_cache_status().program);

        let mut binary = rampage_loaders::Binary::open(fixture()).unwrap();
        binary.sections[0].name = "x".repeat(rampage_plugin_contract::MAX_TEXT_BYTES + 1);
        let project = Arc::new(Project::new(binary));
        assert!(prepare_plugin_triage_with_analysis(Arc::clone(&project), ReportLimits::default(), control).is_err());
        assert!(!project.analysis_cache_status().program);
    });
}

#[test]
fn configuration_changes_and_cancellation_invalidate_prepared_use() {
    let project = Session::default().open(&fixture(), None).unwrap();
    let cancellation = AtomicBool::new(false);
    let mut observer = |_| {};
    let control = ProjectWorkspaceTaskControl::new(&cancellation, &mut observer);
    let prepared =
        prepare_plugin_triage_with_analysis(Arc::clone(&project), ReportLimits::default(), &control).unwrap();
    cancellation.store(true, Ordering::Release);
    assert!(prepared.revalidate(&control).is_err());
    cancellation.store(false, Ordering::Release);
    project.set_packs(Arc::new(Packs::default()));
    assert!(prepared.revalidate(&control).is_err());
}

struct SourceCopy(PathBuf);

impl SourceCopy {
    fn new() -> Self {
        use std::io::Write;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-plugin-triage-{}-{}.elf",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        let source = Self(path);
        file.write_all(&std::fs::read(fixture()).unwrap()).unwrap();
        source
    }

    fn sidecar(&self) -> PathBuf {
        let mut path = self.0.as_os_str().to_owned();
        path.push(".rampage");
        PathBuf::from(path)
    }
}

impl Drop for SourceCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.sidecar());
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn checked_plugin_open_is_fresh_and_admits_a_bounded_unmanaged_elf() {
    let source = SourceCopy::new();
    let session = Session::default();
    let legacy = session.open(&source.0, None).unwrap();
    let checked = rampage_api::open_plugin_triage_source(&session, &source.0, None, None).unwrap();
    assert!(!Arc::ptr_eq(&legacy, &checked));
    assert_eq!(checked.analysis_cache_status(), Default::default());
    checked.binary.validate_backing_source().unwrap();
}

#[test]
fn checked_plugin_open_rejects_source_and_sidecar_oversize_before_native_preparation() {
    let source = SourceCopy::new();
    let session = Session::default();
    // Establish that this source's preload profile is admitted independently of either size refusal.
    rampage_api::open_plugin_triage_source(&session, &source.0, None, None).unwrap();
    let sidecar = std::fs::File::create(source.sidecar()).unwrap();
    sidecar.set_len(16 * 1024 * 1024 + 1).unwrap();
    let error = rampage_api::open_plugin_triage_source(&session, &source.0, None, None).err().unwrap();
    assert!(error.to_string().contains("checked annotation"));
    std::fs::remove_file(source.sidecar()).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&source.0)
        .unwrap()
        .set_len(rampage_api::MAX_PLUGIN_TRIAGE_SOURCE_BYTES as u64 + 1)
        .unwrap();
    let error = rampage_api::open_plugin_triage_source(&session, &source.0, None, None).err().unwrap();
    assert!(error.to_string().contains("16 MiB"));
}

#[test]
fn checked_plugin_open_does_not_reuse_legacy_cached_bad_sidecar_ingestion() {
    let source = SourceCopy::new();
    let session = Session::default();
    session.open(&source.0, None).unwrap();
    std::fs::write(source.sidecar(), b"not-json\n").unwrap();
    // Ordinary opening may reuse its old project. Plugin opening must ingest this sidecar freshly and reject it.
    let error = rampage_api::open_plugin_triage_source(&session, &source.0, None, None).err().unwrap();
    assert!(error.to_string().contains("checked annotation"));
}

#[test]
fn already_loaded_managed_sources_are_refused_before_discovery_or_metadata_production() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/Microsoft.Bcl.HashCode.dll");
    let project = Arc::new(Project::new(rampage_loaders::Binary::open(&path).unwrap()));
    with_control(|control| {
        let error = prepare_plugin_triage(Arc::clone(&project), ReportLimits::default(), control).err().unwrap();
        assert!(error.to_string().contains("managed CLR"));
        let error =
            prepare_plugin_triage_with_analysis(Arc::clone(&project), ReportLimits::default(), control).err().unwrap();
        assert!(error.to_string().contains("managed CLR"));
    });
    assert_eq!(project.analysis_cache_status(), Default::default());
    let error = rampage_api::open_plugin_triage_source(&Session::default(), &path, None, None).err().unwrap();
    assert!(error.to_string().contains("managed CLR"));
}

#[test]
fn same_bytes_at_replaced_path_cannot_upgrade_the_original_descriptor() {
    let source = SourceCopy::new();
    let replacement = SourceCopy::new();
    let project = Session::default().open(&source.0, None).unwrap();
    with_control(|control| {
        let prepared =
            prepare_plugin_triage_with_analysis(Arc::clone(&project), ReportLimits::default(), control).unwrap();
        std::fs::rename(&replacement.0, &source.0).unwrap();
        assert!(prepared.revalidate(control).is_err());
        assert!(prepare_plugin_triage(project, ReportLimits::default(), control).is_err());
    });
}

#[test]
fn owned_snapshot_provenance_path_is_not_original_source_authority() {
    let document = br#"{"format":"rampage-snapshot-v1","arch":"x86_64",
        "provenance":"a/path/does/not/grant/source/authority","regions":[
        {"name":"code","address":"0x1000","permissions":"r-x","bytes":"c3"}]}"#;
    let binary = rampage_loaders::Binary::from_snapshot_bytes(document.to_vec()).unwrap();
    let project = Arc::new(Project::new(binary));
    with_control(|control| {
        assert!(prepare_plugin_triage_with_analysis(Arc::clone(&project), ReportLimits::default(), control).is_err());
    });
    assert!(!project.analysis_cache_status().program);
}

/// Differential oracle only: the compiled component remains the sole producer of the plugin report.
fn assert_builtin_body_parity(plugin: &PluginTriageReport, builtin: &WorkflowReport) {
    assert_eq!(serde_json::to_value(&plugin.report).unwrap(), serde_json::to_value(builtin).unwrap());
}

fn run_compiled(prepared: &PreparedPluginTriage, control: &ProjectWorkspaceTaskControl<'_>) -> PluginTriageReport {
    let component_path = PathBuf::from(std::env::var_os("RAMPAGE_TRIAGE_COMPONENT").expect("compiled component path"));
    let worker = PathBuf::from(std::env::var_os("RAMPAGE_PLUGIN_WORKER").expect("trusted plugin worker path"));
    let component = rampage_api::read_plugin_triage_component(&component_path).unwrap();
    prepared.run_component(&component, &rampage_plugin::PluginConfig::new(worker), None, control).unwrap()
}

#[test]
#[ignore = "parent execution lane supplies RAMPAGE_TRIAGE_COMPONENT and RAMPAGE_PLUGIN_WORKER"]
fn compiled_component_matches_unchanged_builtin_body_on_admitted_fixtures() {
    let paths = [
        fixture(),
        fixture().with_file_name("net-client-x64-stripped.elf"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.exe"),
    ];
    for path in paths {
        for per_section in [1, 25] {
            let project = Session::default().open(&path, None).unwrap();
            let limits = ReportLimits::new(Some(per_section));
            with_control(|control| {
                let prepared = prepare_plugin_triage_with_analysis(Arc::clone(&project), limits, control).unwrap();
                eprintln!(
                    "owned fixture {:?}, section limit {per_section}, {} facts",
                    path.file_name().unwrap(),
                    prepared.fact_count()
                );
                let plugin = run_compiled(&prepared, control);
                // This oracle is deliberately outside preparation and outside the component execution path.
                let builtin = project.triage_report(limits).unwrap();
                assert_builtin_body_parity(&plugin, &builtin);
                assert!(serde_json::to_vec(&plugin).unwrap().len() <= rampage_api::MAX_PLUGIN_TRIAGE_REPORT_BYTES);
                assert_eq!(plugin.provenance.content_authority, "plugin_claims");
            });
        }
    }
}
