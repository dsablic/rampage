use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::{FuzzyBuildRequest, Project, SignatureDb, USER_SIGNATURES, load_signature_database, tools};
use rampage_arch::Arch;
use rampage_loaders::{Binary, Symbol, SymbolKind};
use serde_json::{Value, json};

const PREFIX: &str = "554889E5B82A00000083C00783C00783C00783C00783C00783C00783C0075D90";
const SUFFIX: &str = "83C0019090C3";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rampage-signature-import-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        Self(directory)
    }

    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn pat(&self) -> PathBuf {
        self.write("owned.pat", format!("{PREFIX} 06 2FCD 0026 :0000 owned_pat_function\n---\n"))
    }

    fn project(&self) -> Project {
        let snapshot = json!({
            "format":"rampage-snapshot-v1", "arch":"x86_64", "data_big_endian":false,
            "provenance":"owned hand-authored signature import body", "seeds":["0x1000"],
            "regions":[{"name":"code", "address":"0x1000", "permissions":"r-x",
                "bytes":format!("{PREFIX}{SUFFIX}")}]
        });
        Project::new(Binary::from_snapshot_bytes(serde_json::to_vec(&snapshot).unwrap()).unwrap())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn identify(project: &Project, database: &Path, extra: Value) -> Value {
    let mut arguments = json!({"database":database, "no_bundled":true});
    arguments.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    let (text, failed) = tools::call(&tools::tools(), project, "identify_functions", arguments);
    assert!(!failed, "{text}");
    serde_json::from_str(&text).unwrap()
}

#[test]
fn pat_import_reaches_native_matching_without_writes_and_preserves_analyst_names() {
    let fixture = Fixture::new();
    let path = fixture.pat();
    let before = std::fs::read(&path).unwrap();
    let database = load_signature_database(&path, Arch::X86_64).unwrap();
    assert_eq!(database.pat_records(), 1);
    let project = fixture.project();
    let preview = project.identify_functions(Some(&database), false, false).unwrap();
    assert_eq!(preview.matched, 1);
    assert_eq!(preview.applied, 0);
    assert_eq!(preview.matches[0].source, USER_SIGNATURES);
    assert_eq!(project.function_name(0x1000), "sub_1000");
    project.rename(0x1000, Some("analyst_name")).unwrap();
    let applied = project.identify_functions(Some(&database), false, true).unwrap();
    assert_eq!(applied.matched, 1);
    assert_eq!(applied.applied, 0);
    assert!(!applied.matches[0].unnamed);
    assert_eq!(project.function_name(0x1000), "analyst_name");
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
}

#[test]
fn mcp_pat_preview_and_empty_detail_apply_keep_whole_result_semantics() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let path = fixture.pat();
    let preview = identify(&project, &path, json!({"limit":1}));
    assert_eq!(preview["matched"], 1);
    assert_eq!(preview["applied"], 0);
    assert_eq!(preview["matches"][0]["name"], "owned_pat_function");
    assert_eq!(preview["matches"][0]["source"], USER_SIGNATURES);
    assert_eq!(project.function_name(0x1000), "sub_1000");
    let applied = identify(&project, &path, json!({"apply":true,"offset":99,"limit":1}));
    assert_eq!(applied["matched"], 1);
    assert_eq!(applied["applied"], 1);
    assert_eq!(applied["matches"], json!([]));
    assert_eq!(project.function_name(0x1000), "owned_pat_function");
}

#[test]
fn mcp_rejected_pat_or_page_never_applies_names() {
    let fixture = Fixture::new();
    let project = fixture.project();
    let valid = fixture.pat();
    let invalid =
        fixture.write("invalid.pat", format!("{PREFIX} 06 2FCD 0026 :0000 owned_pat_function ^0000 target\n---\n"));
    for arguments in [
        json!({"database":invalid,"apply":true,"no_bundled":true}),
        json!({"database":valid,"apply":true,"no_bundled":true,"limit":0}),
    ] {
        let (text, failed) = tools::call(&tools::tools(), &project, "identify_functions", arguments);
        assert!(failed, "{text}");
        assert_eq!(project.function_name(0x1000), "sub_1000");
        assert!(project.undo().unwrap().is_empty());
    }
}

#[test]
fn json_extensionless_and_gzip_keep_native_pat_namespace() {
    let fixture = Fixture::new();
    let pat = load_signature_database(&fixture.pat(), Arch::X86_64).unwrap();
    for name in ["native.json", "native"] {
        let path = fixture.write(name, pat.to_json());
        let loaded = load_signature_database(&path, Arch::Aarch64).unwrap();
        assert_eq!(loaded.pat_records(), 1);
        assert_eq!(fixture.project().identify_functions(Some(&loaded), false, false).unwrap().matched, 1);
    }
    let path = fixture.write("native.json.gz", pat.to_gzip().unwrap());
    assert_eq!(load_signature_database(&path, Arch::X86_64).unwrap().pat_records(), 1);
    let empty = SignatureDb::from_json(r#"{"arch":"x86_64","scheme":2,"entries":{}}"#).unwrap();
    let path = fixture.write("empty.json", empty.to_json());
    assert!(load_signature_database(&path, Arch::X86_64).unwrap().is_empty());
}

#[test]
fn explicit_extensions_reject_mismatches_and_unsupported_formats() {
    let fixture = Fixture::new();
    for (name, text, expected) in [
        ("wrong.pat", "{}", "PAT line"),
        ("wrong.json", "---", "cannot load signature database"),
        ("wrong.gz", "---", "gzip"),
        ("untrusted.fidbf", "{}", "explicitly configured trusted JVM/Ghidra"),
        ("unknown.db", "{}", "unsupported extension"),
    ] {
        let path = fixture.write(name, text);
        let error = load_signature_database(&path, Arch::X86_64).unwrap_err().to_string();
        assert!(error.contains(expected), "{error}");
    }
    let path = fixture.write("unsupported.pat", format!("{PREFIX} 06 2FCD 0026 :0000 owned ^0000 target\n---\n"));
    let error = load_signature_database(&path, Arch::X86_64).unwrap_err().to_string();
    assert!(error.contains("PAT line 1") && error.contains("references"), "{error}");
}

#[test]
fn database_admission_rejects_oversize_special_files_and_links() {
    let fixture = Fixture::new();
    let path = fixture.write("oversize.pat", "");
    std::fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(16 * 1024 * 1024 + 1).unwrap();
    assert!(load_signature_database(&path, Arch::X86_64).unwrap_err().to_string().contains("larger than 16 MiB"));
    let json = fixture.write("oversize.json", "");
    std::fs::OpenOptions::new().write(true).open(&json).unwrap().set_len(64 * 1024 * 1024 + 1).unwrap();
    assert!(load_signature_database(&json, Arch::X86_64).unwrap_err().to_string().contains("larger than 64 MiB"));
    assert!(load_signature_database(&fixture.0, Arch::X86_64).is_err());
    #[cfg(unix)]
    {
        let link = fixture.0.join("link.pat");
        std::os::unix::fs::symlink(fixture.pat(), &link).unwrap();
        assert!(load_signature_database(&link, Arch::X86_64).unwrap_err().to_string().contains("not a regular file"));
        let link = fixture.0.join("link.json");
        std::os::unix::fs::symlink(&json, &link).unwrap();
        assert!(load_signature_database(&link, Arch::X86_64).unwrap_err().to_string().contains("not a regular file"));
        assert!(load_signature_database(Path::new("/dev/zero"), Arch::X86_64).is_err());
    }
}

#[test]
fn untrusted_filename_controls_are_escaped_in_errors() {
    let fixture = Fixture::new();
    let path = fixture.write("bad\nname.pat", "{}");
    let error = load_signature_database(&path, Arch::X86_64).unwrap_err().to_string();
    assert!(!error.contains('\n'), "{error:?}");
    assert!(error.contains("\\n"), "{error}");
}

#[cfg(unix)]
#[test]
fn non_utf8_extension_is_not_treated_as_extensionless_json() {
    use std::os::unix::ffi::OsStrExt;

    let fixture = Fixture::new();
    let path = fixture.0.join(std::ffi::OsStr::from_bytes(b"unknown.\xff"));
    let error = load_signature_database(&path, Arch::X86_64).unwrap_err().to_string();
    assert!(error.contains("unsupported extension"), "{error}");
}

fn fuzzy_project(named: bool, changed_immediate: bool) -> Project {
    let body = "554889E5B82A00000083C00783C00783C00783C00783C00783C00783C00783FF03740383C00535785634125DC3";
    let body = if changed_immediate { body.replacen("B82A000000", "B82B000000", 1) } else { body.to_owned() };
    let snapshot = json!({
        "format":"rampage-snapshot-v1", "arch":"x86_64", "data_big_endian":false,
        "provenance":"owned branching fuzzy integration body", "seeds":["0x1000"],
        "regions":[{"name":"code", "address":"0x1000", "permissions":"r-x", "bytes":body}]
    });
    let mut binary = Binary::from_snapshot_bytes(serde_json::to_vec(&snapshot).unwrap()).unwrap();
    if named {
        binary.symbols.push(Symbol {
            name: "owned_fuzzy_source".to_owned(),
            address: 0x1000,
            size: (body.len() / 2) as u64,
            kind: SymbolKind::Function,
        });
    }
    Project::new(binary)
}

#[test]
fn fuzzy_file_integration_is_secondary_and_errors_precede_exact_writes() {
    let fixture = Fixture::new();
    let source = fuzzy_project(true, false);
    let request: FuzzyBuildRequest = serde_json::from_value(json!({
        "owned_names":["owned_fuzzy_source"],
        "provenance":{"library":"owned", "source":"hand-authored body", "cohort":"source"}
    }))
    .unwrap();
    let build = source.build_fuzzy_signatures(&request).unwrap();
    let build_request = fixture.write("build-request.json", serde_json::to_vec(&request).unwrap());
    assert_eq!(source.build_fuzzy_signature_file(&build_request).unwrap().references, 1);
    let output = fixture.0.join("built-fuzzy.json");
    let (text, failed) = tools::call(
        &tools::tools(),
        &source,
        "build_signatures",
        json!({"output":output,"fuzzy_request":build_request}),
    );
    assert!(!failed, "{text}");
    assert_eq!(serde_json::from_str::<Value>(&text).unwrap()["fuzzy_references"], 1);
    assert!(output.is_file());
    let database = fixture.write("fuzzy.json", build.database.unwrap().save_json().unwrap());
    let request = fixture.write(
        "query.json",
        json!({
            "cohort":"held-out-query", "addresses":[4096], "candidates_per_function":2
        })
        .to_string(),
    );
    let identical_target = fuzzy_project(false, false);
    let arguments = json!({"fuzzy_database":database,"fuzzy_request":request,"apply":true});
    let (text, failed) = tools::call(&tools::tools(), &identical_target, "identify_functions", arguments);
    assert!(failed, "identical executable code must reject a different text cohort: {text}");
    assert!(text.contains("executable code duplicates"), "{text}");
    assert_eq!(identical_target.function_name(0x1000), "sub_1000");
    assert!(identical_target.undo().unwrap().is_empty());

    let target = fuzzy_project(false, true);
    let arguments = json!({"fuzzy_database":database,"fuzzy_request":request,"apply":true});
    let (text, failed) = tools::call(&tools::tools(), &target, "identify_functions", arguments);
    assert!(!failed, "{text}");
    let value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["matched"], 0);
    assert_eq!(value["applied"], 0);
    assert_eq!(value["fuzzy"]["suggestions_total"], 1);
    assert_eq!(value["fuzzy"]["candidates_total"], 1);
    assert_eq!(value["fuzzy"]["suggestions"][0]["status"], "candidate_evidence");
    assert_eq!(target.function_name(0x1000), "sub_1000");
    assert!(target.undo().unwrap().is_empty());

    let exact = fixture.write("exact.json", fuzzy_project(true, true).build_signatures().to_json());
    fixture.write(
        "query.json",
        json!({
            "cohort":"source", "addresses":[4096], "candidates_per_function":2
        })
        .to_string(),
    );
    let arguments = json!({
        "database":exact,"fuzzy_database":database,"fuzzy_request":request,"apply":true
    });
    let (text, failed) = tools::call(&tools::tools(), &target, "identify_functions", arguments);
    assert!(failed, "{text}");
    assert_eq!(target.function_name(0x1000), "sub_1000");
    assert!(target.undo().unwrap().is_empty());
}
