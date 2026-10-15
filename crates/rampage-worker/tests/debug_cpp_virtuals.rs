use std::path::PathBuf;

use rampage_api::annotations::Annotations;
use rampage_api::{DecompilerWorkerConfig, Project};
use rampage_loaders::Binary;
use serde_json::Value;

struct LogFiles(PathBuf);

impl Drop for LogFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("jsonl.lock"));
    }
}

fn worker() -> DecompilerWorkerConfig {
    DecompilerWorkerConfig { executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()), ..Default::default() }
}

#[test]
#[ignore = "requires centrally compiled owned virtual C++ fixtures through the --check wrapper"]
fn projected_storage_and_exact_source_links_match_workers_after_persistent_reopen_and_undo() {
    let root =
        PathBuf::from(std::env::var_os("RAMPAGE_DEBUG_CPP_VIRTUAL_FIXTURES").expect("owned virtual fixture wrapper"));
    let oracle: Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/debug-cpp-virtuals/oracle.json")).unwrap();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let path = root.join(variant).join("records.debug.elf");
        let files =
            LogFiles(std::env::temp_dir().join(format!("virtual-worker-{}-{variant}.jsonl", std::process::id())));
        let project = Project::with_annotations(
            Binary::open(&path).unwrap(),
            Annotations::open_checked(files.0.clone()).unwrap(),
        );
        project.set_decompiler_worker(Some(worker()));
        let review = project.review_debug_layouts().unwrap();
        assert_eq!(review.virtual_evidence.tables.iter().map(|table| table.methods.len()).sum::<usize>(), 4);
        let evidence = serde_json::to_value(&review.virtual_evidence).unwrap();
        let imported = project.apply_reviewed_debug_layouts(&review.review_sha256).unwrap().imported.unwrap();
        assert_eq!(imported.applied.len(), 6);
        assert!(project.annotation_list().types[0].text.starts_with("!rampage-plain-layout-v2\n"));
        let reopened = Project::with_annotations(
            Binary::open(&path).unwrap(),
            Annotations::open_checked(files.0.clone()).unwrap(),
        );
        reopened.set_decompiler_worker(Some(worker()));
        let persisted = reopened.review_debug_layouts().unwrap();
        assert!(persisted.approved.is_empty());
        assert_eq!(serde_json::to_value(&persisted.virtual_evidence).unwrap(), evidence);
        for method in oracle["groups"]["records"]["methods"].as_array().unwrap() {
            let entry = project.binary.symbol_by_name(method["symbol"].as_str().unwrap()).unwrap().address;
            let isolated = reopened.decompile(entry).unwrap();
            project.set_decompiler_worker(None);
            let native = project.decompile(entry).unwrap();
            assert_eq!(native.language_id, isolated.language_id);
            assert_eq!(native.code, isolated.code);
            assert_eq!(native.structure, isolated.structure);
            assert_eq!(native.recovery_status, isolated.recovery_status);
            assert_eq!(serde_json::to_value(native.tokens).unwrap(), serde_json::to_value(isolated.tokens).unwrap());
            project.set_decompiler_worker(Some(worker()));
        }
        assert_eq!(project.undo().unwrap().len(), imported.applied.len() + 1);
        assert!(project.annotation_list().types.is_empty());
        assert!(project.annotation_list().signatures.is_empty());
        reopened.refresh_annotations().unwrap();
        assert!(reopened.annotation_list().types.is_empty());
        assert!(reopened.annotation_list().signatures.is_empty());
    }
}
