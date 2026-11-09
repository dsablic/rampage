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
