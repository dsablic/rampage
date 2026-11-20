//! Stored decompilations through the supervised worker (the path an installed MCP server takes): a cold store,
//! then a warm one from another session, answer exactly as a storeless worker project, and the warm answers come
//! from the store. The worker binary is this build's, so this always runs.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rampage_api::{AnalysisStore, DecompilerWorkerConfig, FunctionsQuery, Project, RawProjectRequest, Session};
use serde_json::{Value, json};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("rampage-worker-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn with_worker(project: Arc<Project>) -> Arc<Project> {
    project.set_decompiler_worker(Some(DecompilerWorkerConfig {
        executable: Some(env!("CARGO_BIN_EXE_rampage-worker").into()),
        ..Default::default()
    }));
    project
}

fn decompile_all(project: &Project, addresses: &[u64]) -> Vec<Value> {
    addresses
        .iter()
        .map(|&address| match project.decompile(address) {
            Ok(decompilation) => serde_json::to_value(decompilation).unwrap(),
            Err(error) => json!({ "error": error.to_string() }),
        })
        .collect()
}

fn check(name: &str, open: impl Fn(Option<Arc<AnalysisStore>>) -> Arc<Project>, scratch: &Scratch) {
    let store = Arc::new(AnalysisStore::at(scratch.0.join("store.sqlite"), rampage_api::DEFAULT_MAX_BYTES));
    let fresh = with_worker(open(None));
    let rows = fresh.functions(&FunctionsQuery { limit: Some(100_000), ..Default::default() }).unwrap().items;
    let addresses: Vec<u64> = rows.iter().step_by(rows.len().div_ceil(6).max(1)).map(|row| row.address).collect();
    let expected = decompile_all(&fresh, &addresses);
    let succeeded = expected.iter().filter(|value| value.get("error").is_none()).count() as u64;
    assert!(succeeded > 0, "{name}");
    let cold = with_worker(open(Some(Arc::clone(&store))));
    assert_eq!(decompile_all(&cold, &addresses), expected, "{name}: cold");
    assert_eq!(cold.analysis_store_status().decompilations.unwrap().stored, succeeded, "{name}");
    let warm = with_worker(open(Some(Arc::clone(&store))));
    assert_eq!(decompile_all(&warm, &addresses), expected, "{name}: warm");
    let counts = warm.analysis_store_status().decompilations.unwrap();
    assert_eq!((counts.hits, counts.stored, counts.rejected), (succeeded, 0, 0), "{name}");
    // In-process results are keyed apart: a project without the worker never reads the worker's entries.
    let in_process = open(Some(Arc::clone(&store)));
    decompile_all(&in_process, &addresses);
    assert_eq!(in_process.analysis_store_status().decompilations.unwrap().hits, 0, "{name}");
}

#[test]
fn worker_decompilations_from_the_store_equal_fresh_ones() {
    let scratch = Scratch::new("native");
    let copy = scratch.0.join("hello-x64-dyn.elf");
    std::fs::copy(Path::new(FIXTURES).join("bin/hello-x64-dyn.elf"), &copy).unwrap();
    check(
        "hello-x64-dyn.elf",
        |store| Session::default().with_analysis_store(store).open(&copy, None).unwrap(),
        &scratch,
    );

    let raw = Scratch::new("raw");
    let image = Path::new(FIXTURES).join("firmware/raw-cortex-m.bin");
    let length = std::fs::metadata(&image).unwrap().len();
    let request: RawProjectRequest = serde_json::from_value(json!({
        "profile": "cortex-m3", "offset": 0, "length": length, "base_address": "0x8000000", "vector_table": true,
    }))
    .unwrap();
    check(
        "raw-cortex-m.bin",
        |store| Session::default().with_analysis_store(store).open_raw(&image, &request).unwrap(),
        &raw,
    );
}
