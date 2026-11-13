//! The persistent analysis store: a project analysed through the store (on a hit) must answer exactly as a fresh
//! analysis does; damaged, foreign or mismatched store contents are refused and re-analysed; concurrent openers
//! agree. The golden test ties analysis output to `ANALYSIS_VERSION`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::tools::{call_shared, tools};
use rampage_api::{ANALYSIS_VERSION, AnalysisStore, Project, RawProjectRequest, Session, program_digest};
use serde_json::{Value, json};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");
const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/analysis-cache-golden.json");
const GOLDEN_UPDATE: &str = "RAMPAGE_UPDATE_ANALYSIS_GOLDEN";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-analysis-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn store(&self, max_bytes: u64) -> Arc<AnalysisStore> {
        Arc::new(AnalysisStore::at(self.0.join("store.sqlite"), max_bytes))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every ordinary fixture binary, and the firmware ELFs.
fn ordinary_fixtures() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for directory in ["bin", "firmware"] {
        for entry in std::fs::read_dir(Path::new(FIXTURES).join(directory)).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let wanted = match directory {
                "bin" => !name.ends_with(".txt"),
                _ => name.ends_with(".elf"),
            };
            if wanted {
                paths.push(path);
            }
        }
    }
    paths.sort();
    paths
}

fn raw_fixtures() -> Vec<(&'static str, PathBuf, Value)> {
    let fixture = |relative: &str| Path::new(FIXTURES).join(relative);
    let length = |path: &Path| std::fs::metadata(path).unwrap().len();
    let cortex = fixture("firmware/raw-cortex-m.bin");
    let tables = fixture("firmware/raw-cortex-m-tables.bin");
    let msp430 = fixture("sleigh/msp430.bin");
    let mos6502 = fixture("sleigh/6502.bin");
    vec![
        (
            "raw-cortex-m",
            cortex.clone(),
            json!({
                "profile": "cortex-m3", "offset": 0, "length": length(&cortex),
                "base_address": "0x8000000", "vector_table": true,
            }),
        ),
        (
            "raw-cortex-m-tables",
            tables.clone(),
            json!({
                "profile": "cortex-m3", "offset": 0, "length": length(&tables),
                "base_address": "0x8000000", "vector_table": true, "pointer_tables": true,
            }),
        ),
        (
            "raw-cortex-m-stages-srec",
            fixture("firmware/raw-cortex-m-stages.srec"),
            json!({ "profile": "cortex-m3", "format": "srec" }),
        ),
        (
            "msp430",
            msp430.clone(),
            json!({
                "profile": "TI_MSP430:LE:16:default", "offset": 0, "length": length(&msp430),
                "base_address": "0x4400", "entry": "0x4400",
            }),
        ),
        (
            "6502",
            mos6502.clone(),
            json!({
                "profile": "6502:LE:16:default", "offset": 0, "length": length(&mos6502),
                "base_address": "0x8000", "entry": "0x8000", "seeds": ["0x8000", "0x8010"],
            }),
        ),
    ]
}

fn raw_request(value: &Value) -> RawProjectRequest {
    serde_json::from_value(value.clone()).unwrap()
}

fn open(session: &Session, path: &Path) -> Option<Arc<Project>> {
    session.open(path, None).ok()
}

fn call(project: &Arc<Project>, name: &str, input: Value) -> String {
    let mut project = Arc::clone(project);
    let (text, _) = call_shared(&tools(), &mut project, name, input);
    text
}

/// Tool outputs that read discovery: every function, the entry function's graph and references both ways.
fn observations(project: &Arc<Project>) -> Vec<String> {
    let functions = call(project, "list_functions", json!({ "limit": 1_000_000 }));
    let mut outputs = vec![functions.clone()];
    let rows: Value = serde_json::from_str(&functions).unwrap_or(Value::Null);
    let first = rows
        .get("items")
        .or(Some(&rows))
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|row| row.get("address"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(address) = first {
        outputs.push(call(project, "function_graph", json!({ "at": address })));
        outputs.push(call(project, "xrefs", json!({ "to": address, "limit": 1000 })));
        outputs.push(call(project, "xrefs", json!({ "from": address, "limit": 1000 })));
        outputs.push(call(project, "disassemble", json!({ "at": address, "count": 64 })));
    }
    outputs.push(call(project, "analysis_diagnostics", json!({})));
    outputs
}

fn state(project: &Project) -> &'static str {
    project.analysis_store_status().state
}

/// Analyses `open()` three times: without a store, as a store miss, and as a hit from another session. The hit must
/// answer every observation exactly as the fresh analysis did, also after the same annotation edit.
fn assert_equivalent(label: &str, store: &Arc<AnalysisStore>, open: impl Fn(&Session) -> Option<Arc<Project>>) {
    let Some(fresh) = open(&Session::default().with_analysis_store(None)) else { return };
    let Ok(expected) = program_digest(&fresh) else {
        // Not analysable (a managed assembly, a library archive): the store must not change that.
        let cached = open(&Session::default().with_analysis_store(Some(Arc::clone(store)))).unwrap();
        assert!(program_digest(&cached).is_err(), "{label}");
        return;
    };
    assert_eq!(state(&fresh), "disabled", "{label}");
    let miss = open(&Session::default().with_analysis_store(Some(Arc::clone(store)))).unwrap();
    assert_eq!(program_digest(&miss).unwrap(), expected, "{label}");
    let miss_status = miss.analysis_store_status();
    // Another fixture with identical bytes may have stored this entry already.
    assert!(matches!(miss_status.state, "miss" | "hit"), "{label}: {miss_status:?}");
    let hit = open(&Session::default().with_analysis_store(Some(Arc::clone(store)))).unwrap();
    assert_eq!(program_digest(&hit).unwrap(), expected, "{label}");
    let hit_status = hit.analysis_store_status();
    assert_eq!(hit_status.state, "hit", "{label}: {hit_status:?}");
    assert_eq!(hit_status.key, miss_status.key, "{label}");
    assert_eq!(observations(&hit), observations(&fresh), "{label}");
    let info = |project: &Arc<Project>| -> Value {
        let mut value: Value = serde_json::from_str(&call(project, "binary_info", json!({}))).unwrap();
        value.as_object_mut().unwrap().remove("analysis_store");
        value
    };
    assert_eq!(info(&hit), info(&fresh), "{label}");
    // Annotations apply over a cached analysis exactly as over a fresh one.
    let functions: Value = serde_json::from_str(&call(&fresh, "list_functions", json!({ "limit": 1 }))).unwrap();
    let address = functions.pointer("/items/0/address").or(functions.pointer("/0/address")).and_then(Value::as_str);
    if let Some(address) = address {
        for project in [&fresh, &hit] {
            let text = call(project, "rename", json!({ "at": address, "name": "renamed_by_test" }));
            assert!(!text.is_empty(), "{label}");
        }
        assert_eq!(observations(&hit), observations(&fresh), "{label} after rename");
    }
}

/// Fixture paths may carry an annotation sidecar from other tests; copy each binary into scratch so renames stay
/// in memory and never touch shared sidecars.
fn private_copy(scratch: &Scratch, path: &Path) -> PathBuf {
    let copy = scratch.0.join(path.file_name().unwrap());
    std::fs::copy(path, &copy).unwrap();
    copy
}

#[test]
fn every_fixture_answers_identically_from_the_store() {
    let scratch = Scratch::new();
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    for path in ordinary_fixtures() {
        let copy = private_copy(&scratch, &path);
        assert_equivalent(&path.display().to_string(), &store, |session| open(session, &copy));
        // The copy's annotation sidecar holds the test rename; drop it so the next fixture starts clean.
        for entry in std::fs::read_dir(&scratch.0).unwrap() {
            let entry = entry.unwrap().path();
            if entry.file_name().unwrap().to_string_lossy().starts_with(copy.file_name().unwrap().to_str().unwrap()) {
                let _ = std::fs::remove_file(entry);
            }
        }
    }
}

#[test]
fn raw_projects_answer_identically_from_the_store() {
    let scratch = Scratch::new();
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    for (label, path, request) in raw_fixtures() {
        let request = raw_request(&request);
        assert_equivalent(label, &store, |session| Some(session.open_raw(&path, &request).unwrap()));
    }
}

#[test]
fn different_raw_interpretations_of_the_same_bytes_never_share_an_entry() {
    let scratch = Scratch::new();
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    let (_, path, value) = raw_fixtures().remove(0);
    let request = raw_request(&value);
    let mut other = value.clone();
    other["seeds"] = json!(["0x8000100"]);
    let other = raw_request(&other);
    let session = || Session::default().with_analysis_store(Some(Arc::clone(&store)));
    let first = session().open_raw(&path, &request).unwrap();
    program_digest(&first).unwrap();
    let second = session().open_raw(&path, &other).unwrap();
    let fresh = Session::default().with_analysis_store(None).open_raw(&path, &other).unwrap();
    assert_eq!(program_digest(&second).unwrap(), program_digest(&fresh).unwrap());
    assert_eq!(state(&second), "miss");
    assert_ne!(first.analysis_store_status().key, second.analysis_store_status().key);
}

fn hello() -> PathBuf {
    Path::new(FIXTURES).join("bin/hello-x64.elf")
}

/// Stores `hello()`'s analysis and returns its key.
fn populate(store: &Arc<AnalysisStore>) -> String {
    let project = open(&Session::default().with_analysis_store(Some(Arc::clone(store))), &hello()).unwrap();
    program_digest(&project).unwrap();
    project.analysis_store_status().key.unwrap()
}

fn reopen(store: &Arc<AnalysisStore>) -> (rampage_api::AnalysisStoreStatus, String) {
    let project = open(&Session::default().with_analysis_store(Some(Arc::clone(store))), &hello()).unwrap();
    let digest = program_digest(&project).unwrap();
    (project.analysis_store_status(), digest)
}

fn fresh_digest() -> String {
    program_digest(&open(&Session::default().with_analysis_store(None), &hello()).unwrap()).unwrap()
}

fn sql(store: &AnalysisStore, statement: &str, params: impl rusqlite::Params) {
    let connection = rusqlite::Connection::open(store.path()).unwrap();
    connection.execute(statement, params).unwrap();
}

fn payload(store: &AnalysisStore, key: &str) -> Vec<u8> {
    let connection = rusqlite::Connection::open(store.path()).unwrap();
    connection.query_row("SELECT payload FROM analysis WHERE key = ?1", [key], |row| row.get(0)).unwrap()
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).to_vec()
}

#[test]
fn a_flipped_payload_byte_fails_its_checksum_and_is_reanalysed() {
    let scratch = Scratch::new();
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    let key = populate(&store);
    let mut bytes = payload(&store, &key);
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x40;
    sql(&store, "UPDATE analysis SET payload = ?1 WHERE key = ?2", rusqlite::params![bytes, key]);
    let (status, digest) = reopen(&store);
    assert_eq!(status.state, "rejected", "{status:?}");
    assert!(status.detail.unwrap().contains("checksum"));
    assert_eq!(digest, fresh_digest());
    // The fresh analysis replaced the damaged entry.
    assert_eq!(reopen(&store).0.state, "hit");
}

#[test]
fn a_payload_with_a_matching_checksum_but_damaged_content_is_refused() {
    let scratch = Scratch::new();
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    let key = populate(&store);
    let bytes = payload(&store, &key);
    for damaged in [bytes[..bytes.len() - 3].to_vec(), [bytes.as_slice(), &[0]].concat(), {
        let mut flipped = bytes.clone();
        let index = bytes.len() - 1;
        flipped[index] = 0xff;
        flipped
    }] {
        sql(
            &store,
            "UPDATE analysis SET payload = ?1, sha256 = ?2 WHERE key = ?3",
            rusqlite::params![damaged, sha256(&damaged), key],
        );
        let (status, digest) = reopen(&store);
        assert_eq!(status.state, "rejected", "{status:?}");
        assert!(status.detail.unwrap().contains("malformed"));
        assert_eq!(digest, fresh_digest());
    }
}

#[test]
fn an_entry_filed_under_another_key_is_refused() {
    let scratch = Scratch::new();
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    let key = populate(&store);
    let other = open(
        &Session::default().with_analysis_store(Some(Arc::clone(&store))),
        &Path::new(FIXTURES).join("bin/hello-arm64.elf"),
    )
    .unwrap();
    program_digest(&other).unwrap();
    let other_key = other.analysis_store_status().key.unwrap();
    // Swap the two rows' contents, checksums and all: each now sits under the other's key.
    let connection = rusqlite::Connection::open(store.path()).unwrap();
    connection
        .execute_batch(&format!(
            "UPDATE analysis SET key = 'swap' WHERE key = '{key}';
             UPDATE analysis SET key = '{key}' WHERE key = '{other_key}';
             UPDATE analysis SET key = '{other_key}' WHERE key = 'swap';"
        ))
        .unwrap();
    let (status, digest) = reopen(&store);
    assert_eq!(status.state, "rejected", "{status:?}");
    assert!(status.detail.unwrap().contains("embedded key"));
    assert_eq!(digest, fresh_digest());
}

#[test]
fn a_store_with_another_schema_is_neither_read_nor_written() {
    let scratch = Scratch::new();
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    let key = populate(&store);
    sql(&store, "UPDATE meta SET value = 'rampage-analysis-store-v0' WHERE name = 'schema'", []);
    for _ in 0..2 {
        let (status, digest) = reopen(&store);
        assert_eq!(status.state, "rejected", "{status:?}");
        assert!(status.detail.unwrap().contains("another schema"));
        assert_eq!(digest, fresh_digest());
    }
    let connection = rusqlite::Connection::open(store.path()).unwrap();
    let schema: String = connection.query_row("SELECT value FROM meta", [], |row| row.get(0)).unwrap();
    assert_eq!(schema, "rampage-analysis-store-v0");
    let rows: i64 =
        connection.query_row("SELECT count(*) FROM analysis WHERE key = ?1", [&key], |row| row.get(0)).unwrap();
    assert_eq!(rows, 1);
}

#[test]
fn truncated_and_garbage_store_files_fall_back_to_fresh_analysis() {
    let scratch = Scratch::new();
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    populate(&store);
    // Fold the WAL into the main file so truncating it loses committed pages.
    rusqlite::Connection::open(store.path())
        .unwrap()
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .unwrap();
    let length = std::fs::metadata(store.path()).unwrap().len();
    for cut in [length / 2, 100, 0] {
        let file = std::fs::OpenOptions::new().write(true).open(store.path()).unwrap();
        file.set_len(cut).unwrap();
        drop(file);
        let (status, digest) = reopen(&store);
        assert!(matches!(status.state, "rejected" | "miss" | "hit"), "{cut}: {status:?}");
        assert_eq!(digest, fresh_digest(), "{cut}");
    }
    for name in ["store.sqlite-wal", "store.sqlite-shm"] {
        let _ = std::fs::remove_file(scratch.0.join(name));
    }
    std::fs::write(store.path(), b"this is not a database at all, just text that ends early").unwrap();
    let (status, digest) = reopen(&store);
    assert_eq!(status.state, "rejected", "{status:?}");
    assert_eq!(digest, fresh_digest());
}

#[test]
fn concurrent_openers_agree_and_every_reader_sees_a_whole_entry() {
    let scratch = Scratch::new();
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    let paths: Vec<PathBuf> = ["hello-x64.elf", "hello-arm64.elf", "hello-x64.exe", "hello-x64.macho"]
        .iter()
        .map(|name| Path::new(FIXTURES).join("bin").join(name))
        .collect();
    let expected: Vec<String> = paths
        .iter()
        .map(|path| program_digest(&open(&Session::default().with_analysis_store(None), path).unwrap()).unwrap())
        .collect();
    std::thread::scope(|scope| {
        for round in 0..8 {
            let (store, paths, expected) = (&store, &paths, &expected);
            scope.spawn(move || {
                for step in 0..paths.len() * 2 {
                    let index = (round + step) % paths.len();
                    let session = Session::default().with_analysis_store(Some(Arc::clone(store)));
                    let project = open(&session, &paths[index]).unwrap();
                    assert_eq!(program_digest(&project).unwrap(), expected[index]);
                    let status = project.analysis_store_status();
                    assert!(matches!(status.state, "hit" | "miss"), "{status:?}");
                }
            });
        }
    });
    for path in &paths {
        let project = open(&Session::default().with_analysis_store(Some(Arc::clone(&store))), path).unwrap();
        program_digest(&project).unwrap();
        assert_eq!(state(&project), "hit");
    }
}

#[test]
fn the_size_bound_evicts_the_least_recently_used_entry() {
    let scratch = Scratch::new();
    let probe = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    let key = populate(&probe);
    let one = payload(&probe, &key).len() as u64;
    std::fs::remove_file(probe.path()).unwrap();
    for name in ["store.sqlite-wal", "store.sqlite-shm"] {
        let _ = std::fs::remove_file(scratch.0.join(name));
    }
    // Room for hello-x64.elf's entry and a little more, but not for both fixtures together.
    let store = scratch.store(one * 2 + one / 2);
    populate(&store);
    let other_path = Path::new(FIXTURES).join("bin/hello-x64-dyn.elf");
    let other = open(&Session::default().with_analysis_store(Some(Arc::clone(&store))), &other_path).unwrap();
    program_digest(&other).unwrap();
    assert_eq!(state(&other), "miss");
    let connection = rusqlite::Connection::open(store.path()).unwrap();
    let total: i64 = connection.query_row("SELECT sum(bytes) FROM analysis", [], |row| row.get(0)).unwrap();
    assert!(total as u64 <= store.max_bytes());
    let keys: i64 = connection.query_row("SELECT count(*) FROM analysis", [], |row| row.get(0)).unwrap();
    if keys == 1 {
        assert_eq!(reopen(&store).0.state, "miss");
    }
}

#[test]
fn a_disabled_store_reports_disabled_and_writes_nothing() {
    let scratch = Scratch::new();
    let project = open(&Session::default().with_analysis_store(None), &hello()).unwrap();
    assert_eq!(state(&project), "disabled");
    program_digest(&project).unwrap();
    assert_eq!(state(&project), "disabled");
    let pending = open(&Session::default().with_analysis_store(Some(scratch.store(1 << 30))), &hello()).unwrap();
    assert_eq!(state(&pending), "pending");
    let info: Value = serde_json::from_str(&call(&pending, "binary_info", json!({}))).unwrap();
    assert_eq!(info["analysis_store"], json!({ "state": "pending" }));
    assert!(!scratch.0.join("store.sqlite").exists());
}

/// Analysis output per fixture, recorded under `ANALYSIS_VERSION`. When discovery or a loader changes any
/// fixture's analysis, this fails until `ANALYSIS_VERSION` is bumped (so stored entries from older builds are
/// never read as current) and the digests are re-recorded with `RAMPAGE_UPDATE_ANALYSIS_GOLDEN=1`.
#[test]
fn analysis_cache_golden() {
    let mut digests = BTreeMap::new();
    let session = Session::default().with_analysis_store(None);
    for path in ordinary_fixtures() {
        let Some(project) = open(&session, &path) else { continue };
        if let Ok(digest) = program_digest(&project) {
            let name = path.strip_prefix(FIXTURES).unwrap().to_string_lossy().replace('\\', "/");
            digests.insert(name, digest);
        }
    }
    for (label, path, request) in raw_fixtures() {
        let project = session.open_raw(&path, &raw_request(&request)).unwrap();
        digests.insert(format!("raw:{label}"), program_digest(&project).unwrap());
    }
    let recorded: Value = std::fs::read(GOLDEN)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(json!({ "version": 0, "digests": {} }));
    let recorded_version = recorded["version"].as_u64().unwrap_or(0);
    let recorded_digests: BTreeMap<String, String> =
        serde_json::from_value(recorded["digests"].clone()).unwrap_or_default();
    let changed: Vec<&String> =
        digests.keys().filter(|name| recorded_digests.get(*name).is_some_and(|old| old != &digests[*name])).collect();
    let update = std::env::var(GOLDEN_UPDATE).is_ok_and(|value| value == "1");
    assert!(
        changed.is_empty() || recorded_version != u64::from(ANALYSIS_VERSION),
        "analysis output changed for {changed:?} without a version bump: increment ANALYSIS_VERSION in \
         crates/rampage-api/src/analysis_cache.rs, then re-record with {GOLDEN_UPDATE}=1"
    );
    if update {
        let document = json!({ "version": ANALYSIS_VERSION, "digests": digests });
        std::fs::write(GOLDEN, serde_json::to_string_pretty(&document).unwrap() + "\n").unwrap();
        return;
    }
    assert_eq!(
        recorded_version,
        u64::from(ANALYSIS_VERSION),
        "ANALYSIS_VERSION changed: re-record the digests with {GOLDEN_UPDATE}=1"
    );
    assert_eq!(recorded_digests, digests, "fixture set changed: re-record the digests with {GOLDEN_UPDATE}=1");
}
