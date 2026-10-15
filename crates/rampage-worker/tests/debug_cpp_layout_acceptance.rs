use std::collections::BTreeMap;
use std::path::PathBuf;

use rampage_api::{DecompilerWorkerConfig, Project};
use rampage_loaders::Binary;
use serde::Deserialize;

#[derive(Deserialize)]
struct Oracle {
    groups: BTreeMap<String, Group>,
}

#[derive(Deserialize)]
struct Group {
    #[serde(default)]
    methods: Vec<Method>,
}

#[derive(Deserialize)]
struct Method {
    symbol: String,
    field: String,
}

fn worker() -> DecompilerWorkerConfig {
    DecompilerWorkerConfig { executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()), ..Default::default() }
}

#[test]
#[ignore = "requires centrally compiled owned C++ fixtures through the --check wrapper"]
fn checked_cpp_this_methods_and_actual_field_accesses_match_native_and_worker_replay() {
    let root = PathBuf::from(std::env::var_os("RAMPAGE_DEBUG_CPP_LAYOUT_FIXTURES").expect("owned C++ fixture wrapper"));
    let oracle: Oracle =
        serde_json::from_str(include_str!("../../../tests/fixtures/debug-cpp-layouts/oracle.json")).unwrap();
    for variant in ["dwarf4-o1", "dwarf5-o2"] {
        let path = root.join(variant).join("records.debug.elf");
        let project = Project::new(Binary::open(&path).unwrap());
        project.set_decompiler_worker(Some(worker()));
        let review = project.review_debug_layouts().unwrap();
        assert!(!review.approved.is_empty());
        let imported = project.apply_reviewed_debug_layouts(&review.review_sha256).unwrap().imported.unwrap();
        for method in &oracle.groups["records"].methods {
            let address = project.binary.symbol_by_name(&method.symbol).unwrap().address;
            assert!(imported.applied.contains(&address));
            let isolated = project.decompile(address).unwrap();
            assert!(isolated.code.contains(&format!("->{}", method.field)), "{}", isolated.code);
            project.set_decompiler_worker(None);
            let native = project.decompile(address).unwrap();
            assert_eq!(native.language_id, isolated.language_id);
            assert_eq!(native.code, isolated.code);
            assert_eq!(native.structure, isolated.structure);
            assert_eq!(native.recovery_status, isolated.recovery_status);
            assert_eq!(serde_json::to_value(native.tokens).unwrap(), serde_json::to_value(isolated.tokens).unwrap());
            project.set_decompiler_worker(Some(worker()));
        }
        project.undo().unwrap();
        assert!(project.annotation_list().types.is_empty());
        assert!(project.annotation_list().signatures.is_empty());
    }
}
