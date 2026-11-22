use std::path::PathBuf;

use rampage_api::Session;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

/// The bundled musl database names standard library functions in a stripped static binary with no user database.
/// The fixture is a different program from the one the database was built from, so this exercises genuine
/// cross-binary matching, not self-identity.
fn assert_bundled_names_library_code(name: &str) {
    let project = Session::default().open(&fixture(name), None).unwrap();
    let result = project.apply_signatures_default(None, false).unwrap();
    assert!(result.matched >= 10, "{name}: only {} matches from the bundled database", result.matched);
    let names: Vec<&str> = result.matches.iter().map(|m| m.name.as_str()).collect();
    assert!(names.contains(&"vfprintf"), "{name}: expected vfprintf among {names:?}");
    // The bundled database names most of them; the bundled call graph can add callees of named functions.
    let builtin = result.matches.iter().filter(|m| m.source == rampage_api::packs::BUILTIN_PACK).count();
    assert!(builtin >= 10, "{name}: only {builtin} matches from the bundled database");
    assert!(
        result
            .matches
            .iter()
            .all(|m| m.source == rampage_api::packs::BUILTIN_PACK || m.source == rampage_api::CALL_GRAPH)
    );
}

#[test]
fn bundled_database_names_musl_functions_x86_64() {
    assert_bundled_names_library_code("musl-static-x86_64.elf");
}

#[test]
fn bundled_database_names_musl_functions_aarch64() {
    assert_bundled_names_library_code("musl-static-aarch64.elf");
}

/// The held-out GCC 14.3 firmware fixtures (`tools/embedded-signatures/build.py fixture`, never used to build the
/// embedded set, its operand tier or its call graph): the embedded signatures and their operand tier name
/// `signatures` library functions and the embedded call graph `call_graph` more, and every name is the library
/// function the truth holds there.
fn assert_embedded_firmware_names(core: &str, signatures: usize, call_graph: usize, propagated: &[&str]) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let project = Session::default().open(&root.join(format!("firmware/embedded-libs-{core}.elf")), None).unwrap();
    let truth = std::fs::read_to_string(root.join(format!("data/eval-truth-embedded-{core}.json"))).unwrap();
    let truth: std::collections::BTreeMap<String, String> = serde_json::from_str(&truth).unwrap();
    let result = project.apply_signatures_default(None, false).unwrap();
    for found in &result.matches {
        let address = format!("{:#x}", found.address);
        assert_eq!(truth.get(&address), Some(&found.name), "{core} {address}: {}", found.source);
    }
    let count = |source: &str| result.matches.iter().filter(|found| found.source == source).count();
    assert_eq!(count(rampage_api::EMBEDDED_SIGNATURES), signatures, "{core}");
    assert_eq!(count(rampage_api::CALL_GRAPH), call_graph, "{core}");
    assert_eq!(result.matched, signatures + call_graph, "{core}");
    for name in propagated {
        let found = result.matches.iter().find(|found| found.name == *name);
        assert_eq!(found.map(|found| found.source.as_str()), Some(rampage_api::CALL_GRAPH), "{core} {name}");
    }
}

#[test]
fn embedded_call_graph_names_more_library_code_in_held_out_firmware_m4f() {
    assert_embedded_firmware_names("m4f", 91, 10, &["vTaskSuspendAll", "xTaskIncrementTick"]);
}

#[test]
fn embedded_call_graph_names_more_library_code_in_held_out_firmware_m0() {
    assert_embedded_firmware_names("m0", 73, 32, &["memset", "memmove"]);
}
