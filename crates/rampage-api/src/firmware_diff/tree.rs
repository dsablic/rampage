//! Comparing two filesystems (images `fs_list` reads, or directories) by entry path: files added, removed and
//! changed (by size, then by SHA-256 of the content), type, link and mode changes; then the endpoints the changed
//! files name, and each changed executable or image taken apart and compared in turn.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::PathBuf;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::inputs::{Component, Opener, SideInput, Tree};
use super::{ComponentDiff, Delta, Run};

/// Files written to scratch space per filesystem pair (changed, added and removed ones).
const MAX_MATERIALISED: usize = 2000;
/// Changed files larger than this are not taken apart.
const MAX_RECURSE_BYTES: u64 = 256 << 20;
/// Extensions of data files taken apart as firmware images when they change.
const IMAGE_EXTENSIONS: [&str; 6] = ["bin", "img", "fw", "rom", "hex", "srec"];

/// One entry, with what reading its content needs.
#[derive(Debug, Clone)]
struct Entry {
    path: String,
    /// `file`, `image`, `dir`, `symlink` or `other`.
    kind: &'static str,
    size: u64,
    mode: u32,
    link: Option<String>,
    /// The entry's index in an image, or its file in a directory.
    index: usize,
    disk: Option<PathBuf>,
}

impl Entry {
    fn has_content(&self) -> bool {
        matches!(self.kind, "file" | "image")
    }

    fn row(&self) -> Value {
        let mut row = json!({"path": self.path, "type": self.kind});
        if self.has_content() {
            row["size"] = json!(self.size);
        }
        if let Some(link) = &self.link {
            row["link"] = json!(link);
        }
        row
    }
}

fn normalised(path: &str) -> String {
    let mut path = path;
    loop {
        if let Some(rest) = path.strip_prefix("./") {
            path = rest;
        } else if let Some(rest) = path.strip_prefix('/') {
            path = rest;
        } else {
            break;
        }
    }
    path.trim_end_matches('/').to_owned()
}

fn limits(run: &Run) -> rampage_unpack::Limits {
    rampage_unpack::Limits { max_total_bytes: run.budget.bytes_left.max(1), ..rampage_unpack::Limits::default() }
}

fn list(run: &mut Run, tree: &Tree) -> Result<Vec<Entry>, String> {
    match tree {
        Tree::Image { path, at, inner } => {
            let entries =
                rampage_unpack::with_image(path, *at, inner, limits(run), |image, _| image.entries().to_vec())
                    .map_err(|error| error.to_string())?;
            Ok(entries
                .into_iter()
                .enumerate()
                .map(|(index, entry)| {
                    use rampage_unpack::EntryKind;
                    let kind = match entry.kind {
                        EntryKind::File => "file",
                        EntryKind::Image => "image",
                        EntryKind::Dir => "dir",
                        EntryKind::Symlink => "symlink",
                        _ => "other",
                    };
                    Entry {
                        path: normalised(&entry.path),
                        kind,
                        size: entry.size,
                        mode: entry.mode & 0o7777,
                        link: entry.link,
                        index,
                        disk: None,
                    }
                })
                .collect())
        }
        Tree::Dir(root) => {
            let deadline = std::time::Instant::now() + run.budget.remaining();
            let (files, _) = crate::endpoints::walk(root, deadline)?;
            Ok(files
                .into_iter()
                .enumerate()
                .map(|(index, (_, text, disk, size))| Entry {
                    path: text,
                    kind: "file",
                    size,
                    mode: 0,
                    link: None,
                    index,
                    disk: Some(disk),
                })
                .collect())
        }
    }
}

/// Receives each chunk of content with the position of its entry.
type Sink<'a> = dyn FnMut(usize, &[u8]) -> Result<(), String> + 'a;

/// A file whose content differs: its old and new entries, and their digests when sizes alone did not tell.
type Changed<'a> = (&'a Entry, &'a Entry, Option<(&'a String, &'a String)>);

/// Reads the content of `entries` from `tree`, handing each chunk to `sink` with the entry's position in `entries`;
/// stops when time or the byte budget runs out. Returns the positions read whole and why reading stopped early.
fn read(run: &mut Run, tree: &Tree, entries: &[&Entry], sink: &mut Sink) -> (BTreeSet<usize>, Option<String>) {
    let mut done = BTreeSet::new();
    let mut stopped = None;
    match tree {
        Tree::Image { path, at, inner } => {
            let deadline = std::time::Instant::now() + run.budget.remaining();
            let outcome = rampage_unpack::with_image(path, *at, inner, limits(run), |image, budget| {
                for (position, entry) in entries.iter().enumerate() {
                    if std::time::Instant::now() >= deadline {
                        stopped = Some("the time budget ran out".to_owned());
                        break;
                    }
                    let mut failed = None;
                    let result = image.read(entry.index, budget, &mut |chunk| {
                        sink(position, chunk).map_err(|error| {
                            failed = Some(error.clone());
                            rampage_unpack::UnpackError::Invalid(error)
                        })
                    });
                    match result {
                        Ok(()) => {
                            done.insert(position);
                        }
                        Err(rampage_unpack::UnpackError::Limit(reason)) => {
                            stopped = Some(reason);
                            break;
                        }
                        Err(error) => {
                            if let Some(failed) = failed {
                                stopped = Some(failed);
                                break;
                            }
                            // One unreadable entry does not stop the others.
                            let _ = error;
                        }
                    }
                }
                budget.bytes
            });
            match outcome {
                Ok(bytes) => {
                    run.budget.charge(bytes);
                }
                Err(error) => stopped = Some(error.to_string()),
            }
            if stopped.as_deref().is_some_and(|reason| reason.contains("max_bytes")) {
                run.budget.stopped.get_or_insert("bytes");
            }
        }
        Tree::Dir(_) => {
            for (position, entry) in entries.iter().enumerate() {
                if !run.budget.time_left() || !run.budget.charge(entry.size) {
                    stopped = Some("the time or byte budget ran out".to_owned());
                    break;
                }
                let Some(disk) = &entry.disk else { continue };
                let Ok(mut file) = std::fs::File::open(disk) else { continue };
                let mut buffer = vec![0u8; 1 << 16];
                let mut whole = true;
                loop {
                    match file.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(count) => {
                            if let Err(error) = sink(position, &buffer[..count]) {
                                stopped = Some(error);
                                whole = false;
                                break;
                            }
                        }
                        Err(_) => {
                            whole = false;
                            break;
                        }
                    }
                }
                if stopped.is_some() {
                    break;
                }
                if whole {
                    done.insert(position);
                }
            }
        }
    }
    (done, stopped)
}

/// SHA-256 of each entry's content, by path.
fn hashes(run: &mut Run, tree: &Tree, entries: &[&Entry]) -> (BTreeMap<String, String>, Option<String>) {
    let mut hashers: Vec<Sha256> = entries.iter().map(|_| Sha256::new()).collect();
    let (done, stopped) = read(run, tree, entries, &mut |position, chunk| {
        hashers[position].update(chunk);
        Ok(())
    });
    run.budget.files_hashed += done.len();
    let digests = hashers
        .into_iter()
        .enumerate()
        .filter(|(position, _)| done.contains(position))
        .map(|(position, hasher)| (entries[position].path.clone(), rampage_arch::hex::bytes(&hasher.finalize())))
        .collect();
    (digests, stopped)
}

/// Each entry's content as a file: its own file in a directory, else a new file in scratch space.
fn materialise(run: &mut Run, tree: &Tree, entries: &[&Entry]) -> (BTreeMap<String, PathBuf>, Option<String>) {
    if let Tree::Dir(_) = tree {
        let files = entries.iter().filter_map(|entry| Some((entry.path.clone(), entry.disk.clone()?))).collect();
        return (files, None);
    }
    let targets: Vec<PathBuf> = entries.iter().map(|entry| run.scratch.file(&entry.path)).collect();
    let mut open: Vec<Option<std::fs::File>> = entries.iter().map(|_| None).collect();
    let (done, stopped) = read(run, tree, entries, &mut |position, chunk| {
        if open[position].is_none() {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&targets[position])
                .map_err(|error| format!("write scratch file: {error}"))?;
            open[position] = Some(file);
        }
        open[position]
            .as_mut()
            .expect("opened")
            .write_all(chunk)
            .map_err(|error| format!("write scratch file: {error}"))
    });
    drop(open);
    let mut files = BTreeMap::new();
    for (position, entry) in entries.iter().enumerate() {
        if !done.contains(&position) {
            continue;
        }
        // An empty file sends no chunk.
        if !targets[position].exists() && std::fs::File::create_new(&targets[position]).is_err() {
            continue;
        }
        files.insert(entry.path.clone(), targets[position].clone());
    }
    (files, stopped)
}

/// The content of the one file at `path` in `tree` as a file, or `None` when the tree has no such file.
pub(crate) fn materialise_one(run: &mut Run, tree: &Tree, path: &str) -> Result<Option<PathBuf>, String> {
    let entries = list(run, tree)?;
    let wanted = normalised(path);
    let Some(entry) = entries.iter().find(|entry| entry.path == wanted && entry.has_content()) else {
        return Ok(None);
    };
    let (mut files, stopped) = materialise(run, tree, &[entry]);
    match files.remove(&wanted) {
        Some(file) => Ok(Some(file)),
        None => Err(format!("`{path}` could not be read: {}", stopped.unwrap_or_else(|| "unreadable".to_owned()))),
    }
}

/// What a file's first bytes say it is: an executable format, a filesystem image, `text`, or `data`.
fn sniff(path: &std::path::Path) -> &'static str {
    let mut head = vec![0u8; 1088];
    let read = std::fs::File::open(path).and_then(|mut file| file.read(&mut head)).unwrap_or(0);
    head.truncate(read);
    if let Some(format) = rampage_unpack::executable_format(&head) {
        return format;
    }
    if let Some(format) = rampage_unpack::detect_bytes(&head) {
        return format.name();
    }
    if head.first() == Some(&rampage_loaders::esp::ESP_IMAGE_MAGIC) {
        return "esp_image";
    }
    let printable = head.iter().all(|&byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace());
    if printable || std::str::from_utf8(&head).is_ok() { "text" } else { "data" }
}

/// Whether a changed file is worth taking apart: an executable, an image or archive, or firmware-like data.
fn worth_recursing(format: &str, path: &str, size: u64) -> bool {
    if size > MAX_RECURSE_BYTES {
        return false;
    }
    match format {
        "text" => false,
        "data" => {
            let extension = path.rsplit_once('.').map(|(_, extension)| extension.to_ascii_lowercase());
            extension.is_some_and(|extension| IMAGE_EXTENSIONS.contains(&extension.as_str()))
        }
        _ => true,
    }
}

/// Compares two filesystems into `diff.files`, then compares what is inside each changed file.
pub(crate) fn compare_trees(run: &mut Run, id: &str, old: &Tree, new: &Tree, diff: &mut ComponentDiff, depth: usize) {
    let (old_entries, new_entries) = match (list(run, old), list(run, new)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(error), _) | (_, Err(error)) => {
            diff.status = "not_compared";
            diff.notes.push(format!("not listed: {error}"));
            run.skip(id, format!("the filesystem could not be listed: {error}"));
            return;
        }
    };
    let index = |entries: &[Entry]| -> (BTreeMap<String, Entry>, usize) {
        let mut map = BTreeMap::new();
        let mut duplicates = 0;
        for entry in entries.iter().filter(|entry| !entry.path.is_empty()) {
            if map.insert(entry.path.clone(), entry.clone()).is_some() {
                duplicates += 1;
            }
        }
        (map, duplicates)
    };
    let ((a, a_duplicates), (b, b_duplicates)) = (index(&old_entries), index(&new_entries));
    if a_duplicates + b_duplicates > 0 {
        diff.notes.push(format!(
            "{} paths occur more than once in a listing; the last occurrence is compared",
            a_duplicates + b_duplicates
        ));
    }
    let paths: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    let (mut added, mut removed, mut metadata, mut by_size, mut same_size) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for path in paths {
        match (a.get(path), b.get(path)) {
            (None, Some(entry)) => added.push(entry),
            (Some(entry), None) => removed.push(entry),
            (Some(x), Some(y)) => {
                if x.kind != y.kind {
                    metadata.push(json!({"path": path, "what": format!("type {} -> {}", x.kind, y.kind)}));
                    continue;
                }
                if x.link != y.link {
                    metadata.push(json!({"path": path, "what": format!("link {:?} -> {:?}", x.link, y.link)}));
                }
                if x.mode != y.mode {
                    metadata.push(json!({"path": path, "what": format!("mode {:04o} -> {:04o}", x.mode, y.mode)}));
                }
                if x.has_content() {
                    if x.size != y.size { by_size.push((x, y)) } else { same_size.push((x, y)) }
                }
            }
            (None, None) => {}
        }
    }
    let olds: Vec<&Entry> = same_size.iter().map(|(x, _)| *x).collect();
    let news: Vec<&Entry> = same_size.iter().map(|(_, y)| *y).collect();
    let (old_digests, old_stop) = hashes(run, old, &olds);
    let (new_digests, new_stop) = hashes(run, new, &news);
    let mut changed: Vec<Changed> = by_size.into_iter().map(|(x, y)| (x, y, None)).collect();
    let mut unchanged = 0;
    let mut not_hashed = Vec::new();
    for (x, y) in same_size {
        match (old_digests.get(&x.path), new_digests.get(&y.path)) {
            (Some(p), Some(q)) if p == q => unchanged += 1,
            (Some(p), Some(q)) => changed.push((x, y, Some((p, q)))),
            _ => not_hashed.push(x.path.clone()),
        }
    }
    changed.sort_by(|p, q| p.0.path.cmp(&q.0.path));
    if !not_hashed.is_empty() {
        let why = old_stop.or(new_stop).unwrap_or_else(|| "unreadable".to_owned());
        run.skip(
            format!("{id}: {} same-size files", not_hashed.len()),
            format!("their content was not compared ({why}); the first is `{}`", not_hashed[0]),
        );
    }

    // The files whose content differs, as files, for formats, endpoints and taking them apart.
    let mut want_old: Vec<&Entry> = changed.iter().map(|(x, _, _)| *x).collect();
    want_old.extend(removed.iter().filter(|entry| entry.has_content()).copied());
    let mut want_new: Vec<&Entry> = changed.iter().map(|(_, y, _)| *y).collect();
    want_new.extend(added.iter().filter(|entry| entry.has_content()).copied());
    let cut = |entries: &mut Vec<&Entry>| {
        let total = entries.len();
        entries.truncate(MAX_MATERIALISED);
        total - entries.len()
    };
    let left_out = cut(&mut want_old) + cut(&mut want_new);
    if left_out > 0 {
        run.skip(
            id.to_owned(),
            format!("{left_out} changed, added or removed files were not read (more than {MAX_MATERIALISED})"),
        );
    }
    let (old_files, _) = materialise(run, old, &want_old);
    let (new_files, _) = materialise(run, new, &want_new);
    let format_of = |files: &BTreeMap<String, PathBuf>, path: &str| files.get(path).map(|file| sniff(file));

    let mut changed_rows = Vec::new();
    for (x, y, digests) in &changed {
        let mut row = json!({"path": x.path, "old_size": x.size, "new_size": y.size});
        if let Some((p, q)) = digests {
            row["old_sha256"] = json!(p);
            row["new_sha256"] = json!(q);
        }
        if let Some(format) = format_of(&new_files, &y.path).or(format_of(&old_files, &x.path)) {
            row["format"] = json!(format);
        }
        changed_rows.push(row);
    }
    let rows_with_format = |entries: &[&Entry], files: &BTreeMap<String, PathBuf>| -> Vec<Value> {
        entries
            .iter()
            .map(|entry| {
                let mut row = entry.row();
                if let Some(format) = format_of(files, &entry.path) {
                    row["format"] = json!(format);
                }
                row
            })
            .collect()
    };
    let added_rows = rows_with_format(&added, &new_files);
    let removed_rows = rows_with_format(&removed, &old_files);

    let endpoints = endpoint_changes(run, id, &old_files, &new_files);
    let rows = run.rows;
    let cap = |mut rows_in: Vec<Value>| {
        rows_in.truncate(rows);
        rows_in
    };
    let mut files = json!({
        "entries": {"old": a.len(), "new": b.len()},
        "unchanged": unchanged,
        "changed_total": changed_rows.len(),
        "added_total": added_rows.len(),
        "removed_total": removed_rows.len(),
        "metadata_changed_total": metadata.len(),
        "changed": cap(changed_rows),
        "added": cap(added_rows),
        "removed": cap(removed_rows),
        "metadata_changed": cap(metadata),
        "endpoints": endpoints,
    });
    if !not_hashed.is_empty() {
        files["not_hashed"] = json!(not_hashed.len());
    }
    if matches!(old, Tree::Dir(_)) || matches!(new, Tree::Dir(_)) {
        diff.notes.push("directories: regular files are compared; symlinks are not followed or listed".to_owned());
    }
    diff.files = Some(files);

    // Each changed file that is code or an image: taken apart and compared as components of its own.
    for (x, y, _) in &changed {
        let (Some(old_file), Some(new_file)) = (old_files.get(&x.path), new_files.get(&y.path)) else { continue };
        let format = sniff(new_file);
        if !worth_recursing(format, &y.path, x.size.max(y.size)) {
            continue;
        }
        if !run.budget.time_left() {
            run.skip(format!("{id}::{}", y.path), "the time budget ran out before this file was taken apart");
            continue;
        }
        let ephemeral = matches!(old, Tree::Image { .. });
        let layout = |run: &mut Run, file: &PathBuf, reuse: &[super::inputs::StreamReuse]| {
            super::inputs::layout(&SideInput::of(file.clone()), run, reuse)
        };
        let old_layout = match layout(run, old_file, &[]) {
            Ok(layout) => layout,
            Err(error) => {
                run.skip(format!("{id}::{}", x.path), error);
                continue;
            }
        };
        let reuse: Vec<_> = old_layout.components.iter().filter_map(|component| component.reuse.clone()).collect();
        let new_layout = match layout(run, new_file, &reuse) {
            Ok(layout) => layout,
            Err(error) => {
                run.skip(format!("{id}::{}", y.path), error);
                continue;
            }
        };
        if old_layout.kind == "opaque" && new_layout.kind == "opaque" {
            continue;
        }
        let mark = |mut components: Vec<Component>| {
            for component in &mut components {
                component.ephemeral = ephemeral;
            }
            components
        };
        for (sub, a, b) in super::inputs::pair(mark(old_layout.components), mark(new_layout.components)) {
            super::compare(run, format!("{id}::{}::{sub}", y.path), a, b, depth + 1);
        }
    }
}

/// Endpoints the changed, added and removed files name, in one version only, by file.
fn endpoint_changes(
    run: &mut Run,
    id: &str,
    old_files: &BTreeMap<String, PathBuf>,
    new_files: &BTreeMap<String, PathBuf>,
) -> Value {
    let mut stopped = false;
    let mut scan = |run: &mut Run, files: &BTreeMap<String, PathBuf>| -> BTreeMap<(String, String, String), Value> {
        let mut found = BTreeMap::new();
        for (path, file) in files {
            if !run.budget.time_left() {
                stopped = true;
                break;
            }
            let query = crate::InventoryQuery {
                path: file.clone(),
                cursor: None,
                max_files: None,
                timeout_ms: None,
                xrefs: Some(false),
                decode: false,
                kinds: None,
                limit: None,
            };
            let Ok(inventory) = crate::endpoints::scan(&query) else { continue };
            for row in inventory.rows.into_values() {
                let mut value = json!({"path": path, "kind": row.kind.name(), "value": row.value});
                if let Some(reason) = row.reason {
                    value["local"] = json!(reason);
                }
                found.insert((path.clone(), row.kind.name().to_owned(), row.value), value);
            }
        }
        found
    };
    let (a, b) = (scan(run, old_files), scan(run, new_files));
    if stopped {
        run.skip(format!("{id}: endpoints"), "the time budget ran out while files were scanned for endpoints");
    }
    let only = |x: &BTreeMap<(String, String, String), Value>, y: &BTreeMap<(String, String, String), Value>| {
        x.iter().filter(|(key, _)| !y.contains_key(*key)).map(|(_, value)| value.clone()).collect::<Vec<_>>()
    };
    let mut delta = Delta::of(only(&b, &a), only(&a, &b));
    delta.added.truncate(run.rows);
    delta.removed.truncate(run.rows);
    serde_json::to_value(delta).unwrap_or_default()
}

/// The Android facts (manifest, permissions, components, native libraries, classes, capture APIs, DEX files) that
/// differ between two APK or DEX components; `None` when they cannot be read or nothing differs.
pub(crate) fn android_changes(old: &Component, new: &Component) -> Option<Value> {
    let path = |component: &Component| -> Option<PathBuf> {
        match &component.open {
            Opener::Tree(Tree::Image { path, at, inner }) if at.offset == 0 && inner.is_empty() => Some(path.clone()),
            Opener::Dex => component.facts.get("path").and_then(Value::as_str).map(PathBuf::from),
            _ => None,
        }
    };
    let (a, b) = (crate::android::diff_facts(&path(old)?).ok()?, crate::android::diff_facts(&path(new)?).ok()?);
    let mut changes = serde_json::Map::new();
    let keys: BTreeSet<&&str> = a.keys().chain(b.keys()).collect();
    for key in keys {
        let empty = Vec::new();
        let (x, y) = (a.get(*key).unwrap_or(&empty), b.get(*key).unwrap_or(&empty));
        let (x, y): (BTreeSet<&String>, BTreeSet<&String>) = (x.iter().collect(), y.iter().collect());
        let added: Vec<Value> = y.difference(&x).map(|text| json!(text)).collect();
        let removed: Vec<Value> = x.difference(&y).map(|text| json!(text)).collect();
        if added.is_empty() && removed.is_empty() {
            continue;
        }
        let mut delta = Delta::of(added, removed);
        delta.added.truncate(super::SUMMARY_ROWS * 5);
        delta.removed.truncate(super::SUMMARY_ROWS * 5);
        changes.insert((*key).to_owned(), serde_json::to_value(delta).unwrap_or_default());
    }
    Some(Value::Object(changes))
}
