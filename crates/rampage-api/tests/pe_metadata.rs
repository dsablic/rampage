use std::path::PathBuf;

use rampage_api::{PeResourcesQuery, Session};
use rampage_loaders::pe_resources::{ResourceKey, ResourcePayload};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

#[test]
fn lists_and_decodes_compiled_resources() {
    for name in ["pe-metadata-x64.exe", "pe-metadata-x86.exe"] {
        let project = Session::default().open(&fixture(name), None).unwrap();
        let summary = project.pe_resources(&PeResourcesQuery::default()).unwrap().unwrap();
        assert!(summary.warnings.is_empty() && !summary.truncated, "{name}: {:?}", summary.warnings);
        let types: Vec<_> = summary.types.iter().map(|count| (count.type_name.as_str(), count.count)).collect();
        assert_eq!(types, [("BLOB", 1), ("RT_STRING", 1), ("RT_VERSION", 1), ("RT_MANIFEST", 1)], "{name}");
        assert_eq!((summary.total_leaves, summary.resources.total, summary.returned), (4, 4, 4));
        assert!(summary.resources.items.iter().all(|entry| entry.leaf.in_file && entry.leaf.file_offset.is_some()));
        let strings = summary.resources.items.iter().find(|entry| entry.leaf.type_name == "RT_STRING").unwrap();
        // String table 1 holds ids 0..=15; LANGUAGE 0x09, 0x01 is en-US.
        assert_eq!(
            (strings.leaf.name.clone(), strings.leaf.language.clone()),
            (Some(ResourceKey::Id(1)), Some(ResourceKey::Id(0x409)))
        );
        assert!(strings.decoded.is_none());

        let page = project
            .pe_resources(&PeResourcesQuery { type_filter: Some("version".to_owned()), ..Default::default() })
            .unwrap()
            .unwrap();
        assert_eq!((page.total_leaves, page.resources.total), (4, 1));
        let Some(ResourcePayload::Version(version)) = &page.resources.items[0].decoded else { panic!("{name}") };
        let fixed = version.fixed.as_ref().unwrap();
        assert_eq!((fixed.file_version.as_str(), fixed.product_version.as_str()), ("1.2.3.4", "5.6.7.8"));
        assert_eq!((fixed.flag_names.as_slice(), fixed.file_type_name), (&["prerelease"][..], Some("app")));
        let table = &version.string_tables[0];
        assert_eq!((table.language, table.code_page), (Some(0x409), Some(1200)));
        let value =
            |key: &str| table.strings.iter().find(|string| string.key == key).map(|string| string.value.as_str());
        assert_eq!(value("CompanyName"), Some("Rampage Fixtures"));
        assert_eq!(value("OriginalFilename"), Some("pe-resources.exe"));
        assert_eq!(version.translations.len(), 1);

        let page = project
            .pe_resources(&PeResourcesQuery { type_filter: Some("RT_MANIFEST".to_owned()), ..Default::default() })
            .unwrap()
            .unwrap();
        let Some(ResourcePayload::Manifest(manifest)) = &page.resources.items[0].decoded else { panic!("{name}") };
        let level = manifest.requested_execution_level.as_ref().unwrap();
        assert_eq!(level.level.as_deref(), Some("requireAdministrator"));
        assert_eq!(manifest.dependent_assemblies, ["Microsoft.Windows.Common-Controls"]);

        let past = project
            .pe_resources(&PeResourcesQuery { offset: Some(3), limit: Some(5), ..Default::default() })
            .unwrap()
            .unwrap();
        assert_eq!((past.resources.offset, past.returned, past.resources.total), (3, 1, 4));
    }
}

#[test]
fn reads_the_compiled_load_config() {
    let project = Session::default().open(&fixture("pe-metadata-x64.exe"), None).unwrap();
    let report = project.pe_load_config().unwrap().unwrap();
    assert_eq!(report.bits, 64);
    let config = report.load_config.as_ref().unwrap();
    assert_eq!((config.declared_size, config.read_size), (Some(320), 320));
    assert!(config.absent_fields.is_empty() && config.security_cookie.is_some());
    let guard = config.guard.as_ref().unwrap();
    assert!(
        guard.flag_names.contains(&"cf_instrumented") && guard.flag_names.contains(&"eh_continuation_table_present")
    );
    let table = guard.function_table.unwrap();
    assert_eq!((table.count, table.entry_size, table.in_image), (3, 4, true));
    assert_eq!(config.eh_continuations.unwrap().count, 2);
    assert_eq!(config.long_jump_targets.unwrap().count, 1);
    assert!(config.safe_seh.is_none());
    // The linker does not set DllCharacteristics GUARD_CF for a hand-written load config.
    assert!(!report.dll_characteristics.contains(&"cfg"));
    assert!(report.findings.iter().any(|finding| finding.contains("does not enforce CFG")), "{:?}", report.findings);

    let project = Session::default().open(&fixture("pe-metadata-x86.exe"), None).unwrap();
    let report = project.pe_load_config().unwrap().unwrap();
    let config = report.load_config.as_ref().unwrap();
    assert_eq!((report.bits, config.declared_size), (32, Some(92)));
    let seh = config.safe_seh.as_ref().unwrap();
    assert_eq!((seh.table.count, seh.handlers.as_slice(), seh.table.in_image), (2, &[0x1060, 0x1070][..], true));
    assert!(config.guard.is_some());
    // The structure stops after GuardFlags, so the long-jump table the source also fills is never read.
    assert!(config.long_jump_targets.is_none() && config.absent_fields.contains(&"guard_long_jump_target_table"));
}

#[test]
fn native_non_pe_images_return_none() {
    let project = Session::default().open(&fixture("hello-x64.elf"), None).unwrap();
    assert!(project.pe_resources(&PeResourcesQuery::default()).unwrap().is_none());
    assert!(project.pe_load_config().unwrap().is_none());
    let project = Session::default().open(&fixture("hello-x64.exe"), None).unwrap();
    let summary = project.pe_resources(&PeResourcesQuery::default()).unwrap().unwrap();
    assert_eq!(summary.total_leaves, 0);
}
