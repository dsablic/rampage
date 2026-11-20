//! Stored decompilations: a decompilation served from the store must equal a fresh one, before and after edits;
//! comments and findings keep stored results, other edits make them miss and recompute; damaged, foreign or
//! misfiled rows are refused and decompiled afresh. The golden test ties decompiler output to
//! `DECOMPILE_CACHE_VERSION`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rampage_api::{
    AnalysisStore, DECOMPILE_CACHE_VERSION, DerivedCounts, FunctionsQuery, Project, RawProjectRequest, Session,
};
use serde_json::{Value, json};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");
const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/data/decompile-cache-golden.json");
const GOLDEN_UPDATE: &str = "RAMPAGE_UPDATE_DECOMPILE_GOLDEN";
/// Functions decompiled per fixture, so the debug-build engine keeps the suite quick.
const PER_FIXTURE: usize = 6;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "rampage-decompile-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn store(&self, max_bytes: u64) -> Arc<AnalysisStore> {
        Arc::new(AnalysisStore::at(self.0.join("store.sqlite"), max_bytes))
    }

    /// A private copy of a fixture, so edits write their annotation log here and never beside shared fixtures.
    fn copy(&self, relative: &str) -> PathBuf {
        let source = Path::new(FIXTURES).join(relative);
        let copy = self.0.join(source.file_name().unwrap());
        std::fs::copy(&source, &copy).unwrap();
        copy
    }

    /// Removes a copy's annotation log, so the next project over it starts without the last one's edits.
    fn forget_edits(&self, copy: &Path) {
        let prefix = copy.file_name().unwrap().to_string_lossy().into_owned();
        for entry in std::fs::read_dir(&self.0).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name.starts_with(&prefix) && name != prefix {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
enum Input {
    Native(PathBuf),
    Raw(PathBuf, RawProjectRequest),
}

impl Input {
    fn open(&self, store: Option<&Arc<AnalysisStore>>) -> Arc<Project> {
        let session = Session::default().with_analysis_store(store.cloned());
        match self {
            Input::Native(path) => session.open(path, None).unwrap(),
            Input::Raw(path, request) => session.open_raw(path, request).unwrap(),
        }
    }

    fn path(&self) -> &Path {
        match self {
            Input::Native(path) | Input::Raw(path, _) => path,
        }
    }
}

fn inputs(scratch: &Scratch) -> Vec<(&'static str, Input)> {
    let mut inputs: Vec<(&'static str, Input)> = [
        "bin/hello-x64-dyn.elf",
        "bin/hello-arm64.elf",
        "bin/hello-thumb.elf",
        "bin/hello-mips.elf",
        "bin/eval-types-x86_64.elf",
        "firmware/cortex-m3.elf",
    ]
    .into_iter()
    .map(|relative| (relative, Input::Native(scratch.copy(relative))))
    .collect();
    let raw = scratch.copy("firmware/raw-cortex-m.bin");
    let length = std::fs::metadata(&raw).unwrap().len();
    let request = serde_json::from_value(json!({
        "profile": "cortex-m3", "offset": 0, "length": length, "base_address": "0x8000000", "vector_table": true,
    }))
    .unwrap();
    inputs.push(("firmware/raw-cortex-m.bin", Input::Raw(raw, request)));
    inputs
}

/// Up to [`PER_FIXTURE`] function starts, spread over the function list.
fn functions(project: &Project) -> Vec<u64> {
    let rows = project.functions(&FunctionsQuery { limit: Some(100_000), ..FunctionsQuery::default() }).unwrap().items;
    let step = rows.len().div_ceil(PER_FIXTURE).max(1);
    rows.iter().step_by(step).map(|row| row.address).collect()
}

/// Each function's decompilation as JSON, or its error text: a failure must be reproduced, never hidden.
fn decompile_all(project: &Project, addresses: &[u64]) -> Vec<Value> {
    addresses
        .iter()
        .map(|&address| match project.decompile(address) {
            Ok(decompilation) => serde_json::to_value(decompilation).unwrap(),
            Err(error) => json!({ "error": error.to_string() }),
        })
        .collect()
}

fn counts(project: &Project) -> DerivedCounts {
    project.analysis_store_status().decompilations.unwrap_or_default()
}

/// Fresh (no store) in reverse order, then a cold store in order, then a warm store from another session: every
/// decompilation must be identical, and the warm one must come entirely from the store.
#[test]
fn stored_decompilations_equal_fresh_ones() {
    let scratch = Scratch::new();
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    for (label, input) in inputs(&scratch) {
        assert_stored_decompilations_equal_fresh_ones(label, &input, &store);
    }
}

/// The same for Raw projects whose code a decoder provider produced: a scatter-loaded image, and one reopened with
/// record seeds carried over.
#[test]
fn stored_decompilations_of_decoded_raw_projects_equal_fresh_ones() {
    let scratch = Scratch::new();
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    for name in ["raw-cortex-m-scatter-gcc.bin", "raw-cortex-m-records.bin"] {
        let (path, stream, decoded) = crate::analysis_cache::packed_cortex_m(&scratch.0, name);
        let input = Input::Raw(path, crate::analysis_cache::packed_request(stream, decoded));
        assert_stored_decompilations_equal_fresh_ones(name, &input, &store);
    }
}

fn assert_stored_decompilations_equal_fresh_ones(label: &str, input: &Input, store: &Arc<AnalysisStore>) {
    let fresh = input.open(None);
    let addresses = functions(&fresh);
    assert!(!addresses.is_empty(), "{label}");
    let reversed: Vec<u64> = addresses.iter().rev().copied().collect();
    let mut expected = decompile_all(&fresh, &reversed);
    expected.reverse();
    assert!(fresh.analysis_store_status().decompilations.is_none(), "{label}: no store, no lookups");
    let cold = input.open(Some(store));
    assert_eq!(decompile_all(&cold, &addresses), expected, "{label}: cold");
    let succeeded = expected.iter().filter(|value| value.get("error").is_none()).count() as u64;
    assert!(succeeded > 0, "{label}: nothing decompiled");
    assert_eq!(counts(&cold).stored, succeeded, "{label}: {:?}", counts(&cold));
    let warm = input.open(Some(store));
    assert_eq!(decompile_all(&warm, &addresses), expected, "{label}: warm");
    assert_eq!(warm.analysis_store_status().state, "hit", "{label}: warm discovery");
    let warm_counts = counts(&warm);
    assert_eq!((warm_counts.hits, warm_counts.stored, warm_counts.rejected), (succeeded, 0, 0), "{label}");
    // The decompile tool answers from the store exactly as it does fresh.
    let at = format!("{:#x}", addresses[0]);
    let tool = |project: &Arc<Project>| {
        let mut project = Arc::clone(project);
        rampage_api::tools::call_shared(
            &rampage_api::tools::tools(),
            &mut project,
            "decompile",
            json!({ "at": at, "view": "code" }),
        )
        .0
    };
    assert_eq!(tool(&warm), tool(&fresh), "{label}: tool");
}

/// The in-process engine is reused across functions while the annotations stay the same, and a stored result is
/// served to every later process, so a decompilation must not depend on what that engine decompiled before: each
/// function decompiled alone, in a project of its own, equals the same function decompiled after all the others.
/// One fixture also carries a signature, which feeds callers' argument recovery and type propagation.
#[test]
fn a_decompilation_does_not_depend_on_what_the_engine_decompiled_before() {
    let scratch = Scratch::new();
    for (label, input) in inputs(&scratch) {
        let sequential = input.open(None);
        let addresses = functions(&sequential);
        let signature = (label == "bin/hello-x64-dyn.elf").then(|| addresses[addresses.len() / 2]);
        let annotate = |project: &Project| {
            if let Some(address) = signature {
                project.set_signature(address, Some("int4 annotated(int4 a, int4 b);")).unwrap();
            }
        };
        annotate(&sequential);
        let after_others = decompile_all(&sequential, &addresses);
        drop(sequential);
        for (index, &address) in addresses.iter().enumerate() {
            scratch.forget_edits(input.path());
            let alone = input.open(None);
            annotate(&alone);
            assert_eq!(decompile_all(&alone, &[address]), [after_others[index].clone()], "{label} {address:#x}");
        }
        scratch.forget_edits(input.path());
    }
}

/// After each edit, a stored project answers as a fresh project with the same annotations: comments and
/// findings keep every stored result; a rename or signature misses and recomputes; undo restores the hits.
#[test]
fn edits_invalidate_exactly_the_decompilations_they_can_change() {
    let scratch = Scratch::new();
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    let input = Input::Native(scratch.copy("bin/hello-x64-dyn.elf"));
    let seed = input.open(Some(&store));
    let addresses = functions(&seed);
    let target = addresses[0];
    let original = decompile_all(&seed, &addresses);
    let baseline = counts(&seed).stored;
    assert!(baseline > 0);
    drop(seed);
    scratch.forget_edits(input.path());

    // A fresh project with the edits applied so far is the reference after each step.
    type Edit = Box<dyn Fn(&Project)>;
    let edits: Vec<(&str, Edit)> = vec![
        (
            "comment",
            Box::new(move |project: &Project| {
                project.comment(target, Some("analyst note")).unwrap();
            }),
        ),
        (
            "rename",
            Box::new(move |project: &Project| {
                project.rename(target, Some("renamed_target")).unwrap();
            }),
        ),
        (
            "signature",
            Box::new(move |project: &Project| {
                project.set_signature(target, Some("int4 renamed_target(int4 a);")).unwrap();
            }),
        ),
    ];
    let warm = input.open(Some(&store));
    assert_eq!(decompile_all(&warm, &addresses), original);
    assert_eq!(counts(&warm).hits, baseline);
    for (step, (label, edit)) in edits.iter().enumerate() {
        let before = counts(&warm);
        edit(&warm);
        let got = decompile_all(&warm, &addresses);
        let after = counts(&warm);
        // The reference: a fresh, storeless project with the same edits in the same order.
        let reference_path = scratch.0.join(format!("reference-{step}.elf"));
        std::fs::copy(input.path(), &reference_path).unwrap();
        let reference = Input::Native(reference_path).open(None);
        for (_, edit) in &edits[..=step] {
            edit(&reference);
        }
        assert_eq!(got, decompile_all(&reference, &addresses), "{label}");
        if *label == "comment" {
            assert_eq!(after.hits - before.hits, addresses.len() as u64, "{label}: comments keep every result");
            assert_eq!(after.stored, before.stored, "{label}");
        } else {
            assert_eq!(after.hits, before.hits, "{label}: every result recomputed");
            assert!(after.stored > before.stored, "{label}");
        }
    }
    // Undoing the signature and the rename returns to annotations seen before: their stored results hit again.
    warm.undo().unwrap();
    warm.undo().unwrap();
    let before = counts(&warm);
    assert_eq!(decompile_all(&warm, &addresses), original, "after undo (the comment stays out of the C)");
    assert_eq!(counts(&warm).hits - before.hits, addresses.len() as u64);
}

fn sql(store: &AnalysisStore, statement: &str, params: impl rusqlite::Params) -> usize {
    let connection = rusqlite::Connection::open(store.path()).unwrap();
    connection.execute(statement, params).unwrap()
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).to_vec()
}

fn derived_rows(store: &AnalysisStore) -> Vec<(String, Vec<u8>)> {
    let connection = rusqlite::Connection::open(store.path()).unwrap();
    let mut statement = connection.prepare("SELECT key, payload FROM derived ORDER BY key").unwrap();
    statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?))).unwrap().map(Result::unwrap).collect()
}

/// Stores `hello-x64-dyn.elf`'s first function's decompilation and returns the fresh result.
fn populate(store: &Arc<AnalysisStore>, input: &Input) -> (u64, Value) {
    let project = input.open(Some(store));
    let address = functions(&project)[0];
    let value = serde_json::to_value(project.decompile(address).unwrap()).unwrap();
    assert_eq!(counts(&project).stored, 1);
    (address, value)
}

/// Opens again and decompiles `address`: the result and how the lookup went.
fn again(store: &Arc<AnalysisStore>, input: &Input, address: u64) -> (Value, DerivedCounts) {
    let project = input.open(Some(store));
    let value = serde_json::to_value(project.decompile(address).unwrap()).unwrap();
    (value, counts(&project))
}

#[test]
fn damaged_misfiled_and_foreign_rows_are_refused_and_decompiled_afresh() {
    let scratch = Scratch::new();
    let input = Input::Native(scratch.copy("bin/hello-x64-dyn.elf"));
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    let (address, expected) = populate(&store, &input);
    let (key, payload) = derived_rows(&store).remove(0);
    assert!(key.starts_with("decompile:"), "{key}");

    // A flipped byte fails the checksum.
    let mut flipped = payload.clone();
    let middle = flipped.len() / 2;
    flipped[middle] ^= 0x20;
    sql(&store, "UPDATE derived SET payload = ?1 WHERE key = ?2", rusqlite::params![flipped, key]);
    let (value, counts) = again(&store, &input, address);
    assert_eq!(value, expected);
    assert_eq!((counts.hits, counts.rejected, counts.stored), (0, 1, 1), "{counts:?}");
    assert!(counts.last_rejection.unwrap().contains("checksum"));

    // Content damaged behind a matching checksum: truncated, extended, or a valid body for another function.
    let other_function = {
        let text = String::from_utf8_lossy(&payload).into_owned();
        let address_field = format!("\"address\":{address}");
        assert!(text.contains(&address_field), "the stored body names its function");
        text.replacen(&address_field, &format!("\"address\":{}", address + 1), 1).into_bytes()
    };
    for damaged in [payload[..payload.len() - 7].to_vec(), [payload.as_slice(), b" x"].concat(), other_function] {
        sql(
            &store,
            "UPDATE derived SET payload = ?1, sha256 = ?2 WHERE key = ?3",
            rusqlite::params![damaged, sha256(&damaged), key],
        );
        let (value, counts) = again(&store, &input, address);
        assert_eq!(value, expected);
        assert_eq!((counts.hits, counts.rejected), (0, 1), "{counts:?}");
        assert!(counts.last_rejection.unwrap().contains("malformed"));
    }

    // A whole, valid row filed under another key is refused by its embedded key.
    let (_, good) = derived_rows(&store).remove(0);
    let other = scratch.copy("bin/hello-arm64.elf");
    let other = Input::Native(other);
    let (other_address, other_expected) = populate(&store, &other);
    let other_key = derived_rows(&store).into_iter().map(|(key, _)| key).find(|candidate| *candidate != key).unwrap();
    sql(
        &store,
        "UPDATE derived SET payload = ?1, sha256 = ?2 WHERE key = ?3",
        rusqlite::params![good, sha256(&good), other_key],
    );
    let (value, counts) = again(&store, &other, other_address);
    assert_eq!(value, other_expected);
    assert!(counts.last_rejection.unwrap().contains("embedded key"), "misfiled row");

    // A store with another schema is neither read nor written.
    sql(&store, "UPDATE meta SET value = 'other-schema' WHERE name = 'schema'", []);
    let (value, counts) = again(&store, &input, address);
    assert_eq!(value, expected);
    assert_eq!((counts.hits, counts.stored), (0, 0), "{counts:?}");
}

/// Once an image has been through patch authority (a patch, or a check such as `integrity_checks`), tools read
/// an effective view that is rebuilt after every edit. Views are keyed by their own bytes, apart from the original
/// (their loader skips the recovery an ordinary open runs), so the first view over some bytes analyses afresh and
/// every later view over the same bytes, after an edit, reuses its discovery and decompilations. Every answer
/// equals a storeless project's.
#[test]
fn effective_views_reuse_stored_analysis_across_edits() {
    const MAIN_PATCH: (u64, [u8; 5], [u8; 5]) = (0x100191e, [0xb8, 5, 0, 0, 0], [0xb8, 7, 0, 0, 0]);
    let scratch = Scratch::new();
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    let path = scratch.copy("bin/hello-x64.elf");
    let input = Input::Native(path.clone());
    let reference_copy = scratch.0.join("reference.elf");
    std::fs::copy(&path, &reference_copy).unwrap();
    let reference = Input::Native(reference_copy).open(None);
    let digest = |project: &Project| rampage_api::program_digest(project).unwrap();

    let project = input.open(Some(&store));
    let main = project.resolve("main").unwrap();
    digest(&project);
    let original_key = project.analysis_store_status().key.unwrap();
    let decompiled = |project: &Project| serde_json::to_value(project.decompile(main).unwrap()).unwrap();
    let original_main = decompiled(&project);

    // A patched view: its own bytes, its own entry, answers as a storeless patched view.
    let (address, original, replacement) = MAIN_PATCH;
    let patched = project.patch_bytes(address, &original, &replacement, false).unwrap().project;
    let reference_patched = reference.patch_bytes(address, &original, &replacement, false).unwrap().project;
    assert_eq!(digest(&patched), digest(&reference_patched));
    let patched_key = patched.analysis_store_status().key.unwrap();
    assert_ne!(patched_key, original_key);
    assert_eq!(decompiled(&patched), decompiled(&reference_patched));
    assert!(decompiled(&patched)["code"].as_str().unwrap().contains("return 7;"));

    // Undo the patch: the view has no patches but stays a view, keyed apart from the original.
    patched.undo().unwrap();
    reference_patched.undo().unwrap();
    let view = patched.effective_snapshot().unwrap();
    let reference_view = reference_patched.effective_snapshot().unwrap();
    assert_eq!(digest(&view), digest(&reference_view));
    let status = view.analysis_store_status();
    assert_eq!(status.state, "miss", "{status:?}");
    let view_key = status.key.unwrap();
    assert_ne!(view_key, original_key, "a view never shares the original's entry");
    assert_eq!(decompiled(&view), decompiled(&reference_view));
    assert_eq!(decompiled(&view), original_main, "this fixture has nothing to recover: same C as the original");
    let counts = view.analysis_store_status().decompilations.unwrap();
    assert_eq!((counts.stored, counts.hits), (1, 1), "{counts:?}");

    // A comment builds a new view over the same bytes: discovery and the decompilation come from the store.
    view.comment(main, Some("analyst note")).unwrap();
    reference_view.comment(main, Some("analyst note")).unwrap();
    let next = view.effective_snapshot().unwrap();
    let reference_next = reference_view.effective_snapshot().unwrap();
    assert!(!Arc::ptr_eq(&next, &view), "an edit builds a new view");
    assert_eq!(digest(&next), digest(&reference_next));
    let status = next.analysis_store_status();
    assert_eq!((status.state, status.key.as_deref()), ("hit", Some(view_key.as_str())), "{status:?}");
    assert_eq!(decompiled(&next), decompiled(&reference_next));
    assert_eq!(next.analysis_store_status().decompilations.unwrap().hits, 1);

    // Patching again returns to the patched bytes, whose entries were stored above.
    let repatched = next.patch_bytes(address, &original, &replacement, false).unwrap().project;
    let reference_repatched = reference_next.patch_bytes(address, &original, &replacement, false).unwrap().project;
    assert_eq!(digest(&repatched), digest(&reference_repatched));
    assert_eq!(decompiled(&repatched), decompiled(&reference_repatched));
    let status = repatched.analysis_store_status();
    assert_eq!((status.state, status.key.as_deref()), ("hit", Some(patched_key.as_str())), "{status:?}");
}

/// Where a decompilation runs is part of its key: an in-process result is never served to a project whose
/// decompilations run in a worker (here one that cannot start, so a served result would hide the failure), and
/// decompiler options are part of it too.
#[test]
fn the_worker_setting_and_decompiler_options_are_part_of_the_key() {
    let scratch = Scratch::new();
    let input = Input::Native(scratch.copy("bin/hello-x64-dyn.elf"));
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    let (address, expected) = populate(&store, &input);
    let project = input.open(Some(&store));
    project.set_decompiler_worker(Some(rampage_api::DecompilerWorkerConfig {
        executable: Some(PathBuf::from("/nonexistent/rampage-worker")),
        ..Default::default()
    }));
    assert!(project.decompile(address).is_err(), "a worker that cannot start fails, stored result or not");
    assert_eq!(counts(&project).hits, 0);
    project.set_decompiler_worker(None);
    assert_eq!(serde_json::to_value(project.decompile(address).unwrap()).unwrap(), expected);
    assert_eq!(counts(&project).hits, 1);
    project.set_decompiler_options(Some(rampage_api::DecompilerOptions {
        compiler: Some("default".into()),
        ..Default::default()
    }));
    let other = project.decompile(address);
    let fresh = input.open(None);
    fresh.set_decompiler_options(Some(rampage_api::DecompilerOptions {
        compiler: Some("default".into()),
        ..Default::default()
    }));
    assert_eq!(
        other.map(|value| serde_json::to_value(value).unwrap()).map_err(|error| error.to_string()),
        fresh.decompile(address).map(|value| serde_json::to_value(value).unwrap()).map_err(|error| error.to_string()),
    );
    assert_eq!(counts(&project).hits, 1, "other options never reuse the default options' result");
}

/// A file rewritten in place after it was opened is not the bytes the key hashed: the store is neither read nor
/// written, and the answer (result or refusal) is a storeless project's, also with a signature, which makes a
/// fresh decompilation check its source.
#[test]
fn a_file_changed_in_place_is_decompiled_as_without_a_store() {
    use std::io::{Seek, SeekFrom, Write};
    for signature in [false, true] {
        let scratch = Scratch::new();
        let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
        let path = scratch.copy("bin/hello-x64-dyn.elf");
        let input = Input::Native(path.clone());
        let (address, _) = populate(&store, &input);
        let annotate = |project: &Project| {
            if signature {
                project.set_signature(address, Some("int4 changed(int4 a);")).unwrap();
            }
        };
        let seed = input.open(Some(&store));
        annotate(&seed);
        seed.decompile(address).unwrap();
        drop(seed);
        // Both projects analyse the original bytes, then the file changes under them.
        let stored = input.open(Some(&store));
        let fresh = input.open(None);
        for project in [&stored, &fresh] {
            project.functions(&FunctionsQuery::default()).unwrap();
        }
        let segment = stored
            .binary
            .segments
            .iter()
            .find(|segment| segment.file_size > 0 && segment.contains(address))
            .unwrap()
            .clone();
        let offset = segment.file_offset + (address - segment.address);
        let mut file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&[0xc3]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let answer = |project: &Project| {
            project
                .decompile(address)
                .map(|value| serde_json::to_value(value).unwrap())
                .map_err(|error| error.to_string())
        };
        assert_eq!(answer(&stored), answer(&fresh), "signature: {signature}");
        let counts = counts(&stored);
        assert_eq!((counts.hits, counts.stored), (0, 0), "signature: {signature}: {counts:?}");
    }
}

#[test]
fn truncated_and_garbage_store_files_fall_back_to_fresh_decompilation() {
    let scratch = Scratch::new();
    let input = Input::Native(scratch.copy("bin/hello-x64-dyn.elf"));
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    let (address, expected) = populate(&store, &input);
    // Fold the write-ahead log into the file first, so truncating the file loses committed pages.
    let connection = rusqlite::Connection::open(store.path()).unwrap();
    let _: (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap();
    drop(connection);
    let bytes = std::fs::read(store.path()).unwrap();
    for damaged in [bytes[..bytes.len() / 2].to_vec(), b"not a database at all".repeat(100), Vec::new()] {
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", store.path().display()));
        }
        std::fs::write(store.path(), &damaged).unwrap();
        let project = input.open(Some(&store));
        let value = serde_json::to_value(project.decompile(address).unwrap()).unwrap();
        assert_eq!(value, expected);
    }
}

#[test]
fn the_size_bound_counts_stored_decompilations_with_discovery() {
    let scratch = Scratch::new();
    let input = Input::Native(scratch.copy("bin/eval-types-x86_64.elf"));
    let unbounded = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    let project = input.open(Some(&unbounded));
    let addresses = functions(&project);
    decompile_all(&project, &addresses);
    let total = |store: &AnalysisStore| -> u64 { store.inspect().unwrap().kinds.iter().map(|kind| kind.bytes).sum() };
    let everything = total(&unbounded);
    let report = unbounded.inspect().unwrap();
    assert!(report.kinds.iter().any(|kind| kind.kind == "decompile" && kind.entries > 1), "{report:?}");
    // A bound of half of everything keeps the store under it, evicting the least recently used entries.
    let scratch_bounded = Scratch::new();
    let bounded = scratch_bounded.store(everything / 2);
    let project = input.open(Some(&bounded));
    let expected = decompile_all(&input.open(None), &addresses);
    assert_eq!(decompile_all(&project, &addresses), expected);
    assert!(total(&bounded) <= everything / 2, "{} > {}", total(&bounded), everything / 2);
    // Every write keeps the running total that eviction checks equal to what the rows hold.
    for store in [&unbounded, &bounded] {
        let connection = rusqlite::Connection::open(store.path()).unwrap();
        let kept: String =
            connection.query_row("SELECT value FROM meta WHERE name = 'bytes'", [], |row| row.get(0)).unwrap();
        assert_eq!(kept.parse::<u64>().unwrap(), total(store));
    }
    // Clearing removes the file; the next open works afresh.
    assert!(bounded.clear().unwrap() > 0);
    assert!(!bounded.path().exists());
    assert_eq!(decompile_all(&input.open(Some(&bounded)), &addresses), expected);
}

/// A lost or damaged running total is recounted from the rows rather than trusted: eviction still keeps the bound.
#[test]
fn a_damaged_running_total_is_recounted() {
    let scratch = Scratch::new();
    let input = Input::Native(scratch.copy("bin/eval-types-x86_64.elf"));
    let probe = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    let project = input.open(Some(&probe));
    let addresses = functions(&project);
    decompile_all(&project, &addresses);
    let everything: u64 = probe.inspect().unwrap().kinds.iter().map(|kind| kind.bytes).sum();
    drop(project);
    let other = Scratch::new();
    let bounded = other.store(everything / 2);
    let project = input.open(Some(&bounded));
    decompile_all(&project, &addresses[..1]);
    sql(&bounded, "UPDATE meta SET value = 'not a number' WHERE name = 'bytes'", []);
    decompile_all(&project, &addresses);
    let held: u64 = bounded.inspect().unwrap().kinds.iter().map(|kind| kind.bytes).sum();
    assert!(held <= everything / 2, "{held} > {}", everything / 2);
}

/// A payload longer than the bound is refused without being read, and decompiled afresh.
#[test]
fn an_oversized_row_is_refused_unread() {
    let scratch = Scratch::new();
    let input = Input::Native(scratch.copy("bin/hello-x64-dyn.elf"));
    let store = scratch.store(1 << 20);
    let (address, expected) = populate(&store, &input);
    let (key, _) = derived_rows(&store).remove(0);
    let huge = vec![0u8; 2 << 20];
    sql(
        &store,
        "UPDATE derived SET payload = ?1, sha256 = ?2 WHERE key = ?3",
        rusqlite::params![huge, sha256(&huge), key],
    );
    let (value, counts) = again(&store, &input, address);
    assert_eq!(value, expected);
    assert_eq!(counts.hits, 0);
    assert!(counts.last_rejection.unwrap().contains("size bound"));
}

/// `clear` deletes only a rampage store: a mistyped `RAMPAGE_ANALYSIS_CACHE` naming another file leaves it alone.
#[test]
fn clear_refuses_a_file_that_is_not_a_rampage_store() {
    let scratch = Scratch::new();
    let text = scratch.0.join("notes.txt");
    std::fs::write(&text, b"not a database").unwrap();
    assert!(AnalysisStore::at(&text, 1 << 30).clear().is_err());
    assert!(text.exists());
    let other = scratch.0.join("other.sqlite");
    let connection = rusqlite::Connection::open(&other).unwrap();
    connection
        .execute_batch("CREATE TABLE meta (name TEXT, value TEXT); INSERT INTO meta VALUES ('schema', 'x');")
        .unwrap();
    drop(connection);
    assert!(AnalysisStore::at(&other, 1 << 30).clear().is_err());
    assert!(other.exists());
    let plain = scratch.0.join("plain.sqlite");
    rusqlite::Connection::open(&plain).unwrap().execute_batch("CREATE TABLE t (x);").unwrap();
    assert!(AnalysisStore::at(&plain, 1 << 30).clear().is_err());
    assert!(plain.exists());
    let input = Input::Native(scratch.copy("bin/hello-x64-dyn.elf"));
    let store = scratch.store(rampage_api::DEFAULT_MAX_BYTES);
    populate(&store, &input);
    assert!(store.clear().unwrap() > 0);
    assert!(!store.path().exists());
}

/// Decompiled C per fixture function, recorded per operating system under `DECOMPILE_CACHE_VERSION`. When the
/// decompiler pipeline changes any function's C, this fails until the version is bumped (so results stored by an
/// older build are never served as this build's; the executable's own stamp in the key already covers a rebuild)
/// and the digests are re-recorded with `RAMPAGE_UPDATE_DECOMPILE_GOLDEN=1`.
///
/// Digests are of the C text only, and kept per OS: the engine is built against libc++ on macOS and libstdc++ on
/// Linux, and nothing guarantees identical text across them. On an OS with no recorded digests the test only
/// reports that, so CI on another OS never fails on a recording made here. A function that fails to decompile is
/// recorded as an error, so a platform difference in what decompiles shows as a change too.
#[test]
fn decompile_cache_golden() {
    use sha2::Digest;
    let scratch = Scratch::new();
    let mut digests = std::collections::BTreeMap::new();
    for (label, input) in inputs(&scratch) {
        let project = input.open(None);
        for address in functions(&project) {
            let value = match project.decompile(address) {
                Ok(decompilation) => rampage_arch::hex::bytes(&sha2::Sha256::digest(decompilation.code.as_bytes())),
                Err(error) => format!("error: {error}"),
            };
            digests.insert(format!("{label}@{address:#x}"), value);
        }
    }
    let errors = digests.values().filter(|value| value.starts_with("error: ")).count();
    assert!(errors < digests.len() / 4, "{errors} of {} fixture functions fail to decompile", digests.len());
    let os = std::env::consts::OS;
    let recorded: Value = std::fs::read(GOLDEN)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(json!({ "version": 0, "digests": {} }));
    let recorded_version = recorded["version"].as_u64().unwrap_or(0);
    let recorded_digests: Option<std::collections::BTreeMap<String, String>> =
        serde_json::from_value(recorded["digests"][os].clone()).ok();
    let changed: Vec<&String> = digests
        .keys()
        .filter(|name| {
            recorded_digests.as_ref().and_then(|recorded| recorded.get(*name)).is_some_and(|old| old != &digests[*name])
        })
        .collect();
    assert!(
        changed.is_empty() || recorded_version != u64::from(DECOMPILE_CACHE_VERSION),
        "decompiled C changed for {changed:?} without a version bump: increment DECOMPILE_CACHE_VERSION in \
         crates/rampage-api/src/decompile_cache.rs, then re-record with {GOLDEN_UPDATE}=1"
    );
    if std::env::var(GOLDEN_UPDATE).is_ok_and(|value| value == "1") {
        let mut document = if recorded_version == u64::from(DECOMPILE_CACHE_VERSION) {
            recorded.clone()
        } else {
            json!({ "version": DECOMPILE_CACHE_VERSION, "digests": {} })
        };
        document["digests"][os] = json!(digests);
        std::fs::write(GOLDEN, serde_json::to_string_pretty(&document).unwrap() + "\n").unwrap();
        return;
    }
    let Some(recorded_digests) = recorded_digests else {
        eprintln!("no decompile digests recorded for {os}; record them with {GOLDEN_UPDATE}=1 to check this OS");
        return;
    };
    assert_eq!(
        recorded_version,
        u64::from(DECOMPILE_CACHE_VERSION),
        "DECOMPILE_CACHE_VERSION changed: re-record the digests with {GOLDEN_UPDATE}=1"
    );
    assert_eq!(recorded_digests, digests, "fixture set changed: re-record the digests with {GOLDEN_UPDATE}=1");
}
