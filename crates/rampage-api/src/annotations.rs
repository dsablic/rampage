//! User annotations: names and comments, kept as an append-only log of edits.
//!
//! Every edit records the value it replaced, so undo is just another edit that restores it, and the log on disk
//! remains a complete history in JSON Lines that people and tools can read. Several processes (the UI, an MCP
//! server, the CLI) may share one log: each appends its own edits and picks up the others' through `refresh`.

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ApiError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Field {
    Name,
    Comment,
    Signature,
    Types,
    Global,
}

/// One change: `field` at `address` went from `previous` to `value` (`None` removes it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edit {
    pub field: Field,
    #[serde(
        serialize_with = "rampage_arch::hex::address",
        deserialize_with = "rampage_arch::hex::deserialize_address"
    )]
    pub address: u64,
    pub value: Option<String>,
    pub previous: Option<String>,
}

impl Edit {
    fn inverse(&self) -> Edit {
        Edit { field: self.field, address: self.address, value: self.previous.clone(), previous: self.value.clone() }
    }
}

#[derive(Default)]
pub struct Annotations {
    names: BTreeMap<u64, String>,
    /// Each name's address, for resolving names.
    addresses: HashMap<String, u64>,
    comments: BTreeMap<u64, String>,
    signatures: BTreeMap<u64, String>,
    types: BTreeMap<u64, String>,
    globals: BTreeMap<u64, String>,
    /// Steps applied in this session, for undo; and undone ones, for redo. A step is the edits one call made,
    /// in order: a single edit, or a whole batch, which undoes and redoes together.
    done: Vec<Vec<Edit>>,
    undone: Vec<Vec<Edit>>,
    /// Where edits are appended; `None` keeps them in memory only.
    log: Option<Log>,
    /// Whether `locked` holds the log's lock, which edits made inside it must not try to take again.
    held: bool,
}

#[derive(Default)]
struct Log {
    path: PathBuf,
    /// How many bytes of the file have been applied: every complete line before this offset. Other processes'
    /// edits, and a line still being written, lie past it.
    read: u64,
    /// The file read, to notice it being replaced by another of any size.
    identity: Option<(u64, u64)>,
}

impl Annotations {
    /// Loads the log at `path` if it exists; later edits are appended to it.
    pub fn open(path: PathBuf) -> Result<Self, String> {
        let mut annotations = Self { log: Some(Log { path, ..Log::default() }), ..Self::default() };
        annotations.refresh()?;
        Ok(annotations)
    }

    pub fn in_memory() -> Self {
        Self::default()
    }

    pub(crate) fn snapshot(&self) -> Self {
        Self {
            names: self.names.clone(),
            addresses: self.addresses.clone(),
            comments: self.comments.clone(),
            signatures: self.signatures.clone(),
            types: self.types.clone(),
            globals: self.globals.clone(),
            ..Self::default()
        }
    }

    /// Applies edits other processes have appended to the log since it was last read. Returns whether any were.
    pub fn refresh(&mut self) -> Result<bool, String> {
        let Some(log) = &mut self.log else { return Ok(false) };
        let (restart, edits) = read_new_edits(log)?;
        if restart {
            self.names.clear();
            self.addresses.clear();
            self.comments.clear();
            self.signatures.clear();
            self.types.clear();
            self.globals.clear();
        }
        for edit in &edits {
            self.apply(edit);
        }
        Ok(restart || !edits.is_empty())
    }

    fn apply(&mut self, edit: &Edit) {
        match edit.field {
            Field::Name => {
                if let Some(old) = self.names.remove(&edit.address)
                    && self.addresses.get(&old) == Some(&edit.address)
                {
                    // Edits from several clients can leave a name at two addresses; keep resolving the other.
                    match self.names.iter().find(|(_, name)| **name == old) {
                        Some((&other, _)) => self.addresses.insert(old, other),
                        None => self.addresses.remove(&old),
                    };
                }
                if let Some(value) = &edit.value {
                    self.names.insert(edit.address, value.clone());
                    self.addresses.insert(value.clone(), edit.address);
                }
            }
            Field::Comment => match &edit.value {
                Some(value) => drop(self.comments.insert(edit.address, value.clone())),
                None => drop(self.comments.remove(&edit.address)),
            },
            Field::Signature | Field::Types | Field::Global => {
                let values = match edit.field {
                    Field::Signature => &mut self.signatures,
                    Field::Types => &mut self.types,
                    _ => &mut self.globals,
                };
                match &edit.value {
                    Some(value) => {
                        values.insert(edit.address, value.clone());
                    }
                    None => {
                        values.remove(&edit.address);
                    }
                }
            }
        }
    }

    /// Appends `edits` to the log in one write, so a batch reaches other readers whole. The appended lines are
    /// read back, harmlessly, by the next `refresh`. A file left ending mid-line (by an interrupted write) gets a
    /// newline first, so the fragment becomes a line of its own, which reading skips.
    fn record(&mut self, edits: &[Edit]) -> Result<(), String> {
        let Some(log) = &mut self.log else { return Ok(()) };
        let error = |error: std::io::Error| format!("{}: {error}", log.path.display());
        let mut file = OpenOptions::new().read(true).create(true).append(true).open(&log.path).map_err(error)?;
        let len = file.metadata().map_err(error)?.len();
        let mut last = *b"\n";
        if len > 0 {
            file.seek(SeekFrom::Start(len - 1)).map_err(error)?;
            file.read_exact(&mut last).map_err(error)?;
        }
        let mut lines = if last[0] == b'\n' { String::new() } else { "\n".to_owned() };
        for edit in edits {
            lines.push_str(&serde_json::to_string(edit).map_err(|error| error.to_string())?);
            lines.push('\n');
        }
        file.write_all(lines.as_bytes()).map_err(error)
    }

    fn commit(&mut self, edits: &[Edit]) -> Result<(), String> {
        self.record(edits)?;
        for edit in edits {
            self.apply(edit);
        }
        Ok(())
    }

    /// Sets or clears `field` at `address`, recording the edit. Returns false when nothing changed.
    pub fn set(&mut self, field: Field, address: u64, value: Option<String>) -> Result<bool, String> {
        self.set_validated(field, address, value, |_| Ok(()))
    }

    /// Runs `work` holding the log's cross-process lock, after picking up other processes' edits, so that what it
    /// checks against them (such as a name being free) still holds when it edits.
    pub(crate) fn locked<T>(&mut self, work: impl FnOnce(&mut Self) -> Result<T, ApiError>) -> Result<T, ApiError> {
        let _lock = self.log_lock().map_err(ApiError::Invalid)?;
        self.refresh().map_err(ApiError::Invalid)?;
        self.held = true;
        let result = work(self);
        self.held = false;
        result
    }

    fn log_lock(&self) -> Result<Option<File>, String> {
        let Some(log) = self.log.as_ref().filter(|_| !self.held) else { return Ok(None) };
        let mut path = log.path.as_os_str().to_owned();
        path.push(".lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(PathBuf::from(path))
            .map_err(|error| error.to_string())?;
        file.lock().map_err(|error| error.to_string())?;
        Ok(Some(file))
    }

    pub(crate) fn set_validated(
        &mut self,
        field: Field,
        address: u64,
        value: Option<String>,
        validate: impl FnOnce(&Self) -> Result<(), String>,
    ) -> Result<bool, String> {
        let _lock = self.log_lock()?;
        self.refresh()?;
        let previous = self.field_map(field).get(&address).cloned();
        if previous == value {
            return Ok(false);
        }
        let edit = Edit { field, address, value, previous };
        let mut candidate = self.snapshot();
        candidate.apply(&edit);
        validate(&candidate)?;
        self.commit(std::slice::from_ref(&edit))?;
        self.done.push(vec![edit]);
        self.undone.clear();
        Ok(true)
    }

    /// Sets each `(field, address, value)` in order as one undo step, after `validate` accepts the state they
    /// leave; all are recorded or none. Returns, for each, whether it changed anything.
    pub(crate) fn set_batch_validated(
        &mut self,
        changes: &[(Field, u64, Option<String>)],
        validate: impl FnOnce(&Self) -> Result<(), String>,
    ) -> Result<Vec<bool>, String> {
        let _lock = self.log_lock()?;
        self.refresh()?;
        let mut candidate = self.snapshot();
        let mut edits = Vec::new();
        let mut changed = Vec::with_capacity(changes.len());
        for (field, address, value) in changes {
            let previous = candidate.field_map(*field).get(address).cloned();
            changed.push(previous != *value);
            if previous != *value {
                let edit = Edit { field: *field, address: *address, value: value.clone(), previous };
                candidate.apply(&edit);
                edits.push(edit);
            }
        }
        if edits.is_empty() {
            return Ok(changed);
        }
        validate(&candidate)?;
        self.commit(&edits)?;
        self.done.push(edits);
        self.undone.clear();
        Ok(changed)
    }

    pub(crate) fn import_signatures(
        &mut self,
        signatures: &[(u64, String)],
        prepare: impl Fn(&Self, u64, &str) -> String,
        validate: impl FnOnce(&Self) -> Result<(), String>,
    ) -> Result<Vec<u64>, String> {
        let _lock = self.log_lock()?;
        self.refresh()?;
        let mut candidate = self.snapshot();
        let mut seen = std::collections::BTreeSet::new();
        let edits: Vec<_> = signatures
            .iter()
            .filter(|(address, _)| !self.signatures.contains_key(address) && seen.insert(*address))
            .map(|(address, declaration)| Edit {
                field: Field::Signature,
                address: *address,
                value: Some(prepare(self, *address, declaration)),
                previous: None,
            })
            .collect();
        for edit in &edits {
            candidate.apply(edit);
        }
        validate(&candidate)?;
        let mut applied = Vec::new();
        for edit in edits {
            self.commit(std::slice::from_ref(&edit))?;
            self.undone.clear();
            applied.push(edit.address);
            self.done.push(vec![edit]);
        }
        Ok(applied)
    }

    /// Reverts the last step made through this instance: one edit, or a whole batch. Returns its edits, in the
    /// order they were made; empty when there is nothing to undo.
    pub fn undo(&mut self) -> Result<Vec<Edit>, String> {
        self.undo_validated(|_| Ok(()))
    }

    pub(crate) fn undo_validated(
        &mut self,
        validate: impl FnOnce(&Self) -> Result<(), String>,
    ) -> Result<Vec<Edit>, String> {
        if self.done.is_empty() {
            return Ok(Vec::new());
        }
        let _lock = self.log_lock()?;
        self.refresh()?;
        let Some(step) = self.done.last().cloned() else { return Ok(Vec::new()) };
        let inverses: Vec<Edit> = step.iter().rev().map(Edit::inverse).collect();
        self.replay(&inverses, validate)?;
        self.done.pop();
        self.undone.push(step.clone());
        Ok(step)
    }

    /// Reapplies the last undone step. Returns its edits; empty when there is nothing to redo.
    pub fn redo(&mut self) -> Result<Vec<Edit>, String> {
        self.redo_validated(|_| Ok(()))
    }

    pub(crate) fn redo_validated(
        &mut self,
        validate: impl FnOnce(&Self) -> Result<(), String>,
    ) -> Result<Vec<Edit>, String> {
        if self.undone.is_empty() {
            return Ok(Vec::new());
        }
        let _lock = self.log_lock()?;
        self.refresh()?;
        let Some(step) = self.undone.last().cloned() else { return Ok(Vec::new()) };
        self.replay(&step, validate)?;
        self.undone.pop();
        self.done.push(step.clone());
        Ok(step)
    }

    /// Commits `edits` in order, each only over the value it replaces, and only once `validate` accepts the result
    /// when the step touches what the decompiler checks.
    fn replay(&mut self, edits: &[Edit], validate: impl FnOnce(&Self) -> Result<(), String>) -> Result<(), String> {
        let mut candidate = self.snapshot();
        for edit in edits {
            candidate.check_unchanged(edit)?;
            candidate.apply(edit);
        }
        let checked = edits.iter().any(|edit| {
            matches!(edit.field, Field::Signature | Field::Types | Field::Global)
                || (edit.field == Field::Name && !candidate.globals().is_empty())
        });
        if checked {
            validate(&candidate)?;
        }
        self.commit(edits)
    }

    /// Fails when another client changed `edit`'s field since `edit.previous` was set there: undoing or redoing
    /// over that change would silently discard it.
    fn check_unchanged(&self, edit: &Edit) -> Result<(), String> {
        if self.field_map(edit.field).get(&edit.address) == edit.previous.as_ref() {
            return Ok(());
        }
        Err(format!("{:#x} was edited by another client since; not changed", edit.address))
    }

    fn field_map(&self, field: Field) -> &BTreeMap<u64, String> {
        match field {
            Field::Name => &self.names,
            Field::Comment => &self.comments,
            Field::Signature => &self.signatures,
            Field::Types => &self.types,
            Field::Global => &self.globals,
        }
    }

    pub fn name(&self, address: u64) -> Option<&str> {
        self.names.get(&address).map(String::as_str)
    }

    pub fn comment(&self, address: u64) -> Option<&str> {
        self.comments.get(&address).map(String::as_str)
    }

    pub fn address_of(&self, name: &str) -> Option<u64> {
        self.addresses.get(name).copied()
    }

    pub fn names(&self) -> &BTreeMap<u64, String> {
        &self.names
    }

    pub fn comments(&self) -> &BTreeMap<u64, String> {
        &self.comments
    }

    pub fn signatures(&self) -> &BTreeMap<u64, String> {
        &self.signatures
    }

    pub fn types(&self) -> &BTreeMap<u64, String> {
        &self.types
    }

    pub fn globals(&self) -> &BTreeMap<u64, String> {
        &self.globals
    }
}

/// Reads the complete lines appended to `log` since it was last read. Returns their edits, and whether the file
/// was replaced (it shrank or is another file), in which case they are its whole contents and earlier state must be
/// dropped. Lines that do not parse, such as a fragment an interrupted write left behind, are skipped.
fn read_new_edits(log: &mut Log) -> Result<(bool, Vec<Edit>), String> {
    let path = log.path.clone();
    let error = |error: std::io::Error| format!("{}: {error}", path.display());
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(problem) if problem.kind() == std::io::ErrorKind::NotFound => return Ok((false, Vec::new())),
        Err(problem) => return Err(error(problem)),
    };
    let metadata = file.metadata().map_err(error)?;
    let identity = file_identity(&metadata);
    let restart = metadata.len() < log.read || (log.identity.is_some() && log.identity != identity);
    if restart {
        *log = Log { path: path.clone(), ..Log::default() };
    }
    log.identity = identity;
    if metadata.len() == log.read {
        return Ok((restart, Vec::new()));
    }
    file.seek(SeekFrom::Start(log.read)).map_err(error)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(error)?;
    // Only complete lines: the rest may still be being written.
    let complete = bytes.iter().rposition(|&byte| byte == b'\n').map_or(0, |end| end + 1);
    let edits = bytes[..complete]
        .split(|&byte| byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<Edit>(line).ok())
        .collect();
    log.read += complete as u64;
    Ok((restart, edits))
}

#[cfg(unix)]
fn file_identity(metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn file_identity(_: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_log(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("rampage-{name}-{}.rampage", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn cleanup(path: PathBuf) {
        std::fs::remove_file(&path).unwrap();
        cleanup_lock(path);
    }

    fn cleanup_lock(path: PathBuf) {
        let mut lock = path.as_os_str().to_owned();
        lock.push(".lock");
        let _ = std::fs::remove_file(PathBuf::from(lock));
    }

    #[test]
    fn edits_undo_redo_and_replay_from_the_log() {
        let path = temporary_log("annotations");
        let mut annotations = Annotations::open(path.clone()).unwrap();
        assert!(annotations.set(Field::Name, 0x1000, Some("parse".into())).unwrap());
        assert!(!annotations.set(Field::Name, 0x1000, Some("parse".into())).unwrap());
        annotations.set(Field::Comment, 0x1004, Some("length check".into())).unwrap();
        annotations.set(Field::Name, 0x1000, Some("parse_header".into())).unwrap();
        assert_eq!(annotations.undo().unwrap()[0].value, Some("parse_header".into()));
        assert_eq!(annotations.name(0x1000), Some("parse"));
        assert_eq!(annotations.address_of("parse_header"), None);
        annotations.redo().unwrap();
        assert_eq!(annotations.name(0x1000), Some("parse_header"));
        annotations.set(Field::Comment, 0x1004, None).unwrap();

        let replayed = Annotations::open(path.clone()).unwrap();
        assert_eq!(replayed.name(0x1000), Some("parse_header"));
        assert_eq!(replayed.comment(0x1004), None);
        assert_eq!(replayed.address_of("parse_header"), Some(0x1000));
        cleanup(path);
    }

    #[test]
    fn sees_edits_from_another_writer() {
        let path = temporary_log("shared");
        let mut ui = Annotations::open(path.clone()).unwrap();
        let mut agent = Annotations::open(path.clone()).unwrap();
        agent.set(Field::Name, 0x2000, Some("decrypt".into())).unwrap();
        assert!(ui.refresh().unwrap());
        assert_eq!(ui.name(0x2000), Some("decrypt"));
        ui.set(Field::Comment, 0x2000, Some("xor loop".into())).unwrap();
        agent.set(Field::Name, 0x2000, Some("decrypt_config".into())).unwrap();
        assert_eq!(agent.comment(0x2000), Some("xor loop"));
        ui.refresh().unwrap();
        assert_eq!(ui.name(0x2000), Some("decrypt_config"));
        cleanup(path);
    }

    #[test]
    fn survives_an_interrupted_write() {
        let path = temporary_log("interrupted");
        let mut annotations = Annotations::open(path.clone()).unwrap();
        annotations.set(Field::Name, 0x10, Some("first".into())).unwrap();
        OpenOptions::new().append(true).open(&path).unwrap().write_all(br#"{"field":"name","addr"#).unwrap();
        let mut reopened = Annotations::open(path.clone()).unwrap();
        assert_eq!(reopened.name(0x10), Some("first"));
        reopened.set(Field::Name, 0x20, Some("second".into())).unwrap();
        let replayed = Annotations::open(path.clone()).unwrap();
        assert_eq!((replayed.name(0x10), replayed.name(0x20)), (Some("first"), Some("second")));
        cleanup(path);
    }

    #[test]
    fn a_line_read_while_half_written_is_read_whole_later() {
        let path = temporary_log("torn");
        let mut reader = Annotations::open(path.clone()).unwrap();
        let line = serde_json::to_string(&Edit {
            field: Field::Name,
            address: 0x30,
            value: Some("late".into()),
            previous: None,
        })
        .unwrap();
        let (head, tail) = line.split_at(10);
        let mut file = OpenOptions::new().create(true).append(true).open(&path).unwrap();
        file.write_all(head.as_bytes()).unwrap();
        assert!(!reader.refresh().unwrap());
        file.write_all(format!("{tail}\n").as_bytes()).unwrap();
        assert!(reader.refresh().unwrap());
        assert_eq!(reader.name(0x30), Some("late"));
        reader.set(Field::Name, 0x40, Some("after".into())).unwrap();
        assert_eq!(Annotations::open(path.clone()).unwrap().name(0x40), Some("after"));
        cleanup(path);
    }

    #[test]
    fn undo_refuses_to_discard_another_clients_edit() {
        let path = temporary_log("conflict");
        let mut ui = Annotations::open(path.clone()).unwrap();
        let mut agent = Annotations::open(path.clone()).unwrap();
        ui.set(Field::Name, 0x10, Some("a".into())).unwrap();
        agent.set(Field::Name, 0x10, Some("b".into())).unwrap();
        assert!(ui.undo().is_err());
        assert_eq!(ui.name(0x10), Some("b"));
        cleanup(path);
    }

    #[test]
    fn a_name_left_at_two_addresses_still_resolves() {
        let mut annotations = Annotations::in_memory();
        let edit =
            |address, value: &str| Edit { field: Field::Name, address, value: Some(value.into()), previous: None };
        annotations.apply(&edit(0x10, "foo"));
        annotations.apply(&edit(0x20, "foo"));
        annotations.apply(&edit(0x20, "baz"));
        assert_eq!(annotations.address_of("foo"), Some(0x10));
    }

    #[test]
    fn debug_import_deduplicates_entries_and_does_not_replace_existing_signatures() {
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Signature, 0x10, Some("int4 preserved(void);".to_owned())).unwrap();
        let candidates = vec![
            (0x10, "int4 ignored(void);".to_owned()),
            (0x20, "int4 first(void);".to_owned()),
            (0x20, "int4 second(void);".to_owned()),
        ];
        let applied =
            annotations.import_signatures(&candidates, |_, _, declaration| declaration.to_owned(), |_| Ok(())).unwrap();
        assert_eq!(applied, vec![0x20]);
        assert_eq!(annotations.signatures()[&0x10], "int4 preserved(void);");
        assert_eq!(annotations.signatures()[&0x20], "int4 first(void);");
        annotations.undo().unwrap();
        assert!(!annotations.signatures().contains_key(&0x20));
        annotations.redo().unwrap();
        assert_eq!(annotations.signatures()[&0x20], "int4 first(void);");
    }

    #[test]
    fn a_batch_is_one_undo_step_written_in_one_append() {
        let path = temporary_log("batch");
        let mut annotations = Annotations::open(path.clone()).unwrap();
        annotations.set(Field::Comment, 0x10, Some("before".into())).unwrap();
        let changes = vec![
            (Field::Name, 0x10, Some("first".to_owned())),
            (Field::Comment, 0x10, Some("before".to_owned())),
            (Field::Name, 0x20, Some("second".to_owned())),
            (Field::Comment, 0x20, Some("note".to_owned())),
        ];
        assert_eq!(annotations.set_batch_validated(&changes, |_| Ok(())).unwrap(), [true, false, true, true]);
        assert_eq!(annotations.undo().unwrap().len(), 3);
        assert_eq!((annotations.name(0x10), annotations.name(0x20), annotations.comment(0x20)), (None, None, None));
        assert_eq!(annotations.comment(0x10), Some("before"));
        annotations.redo().unwrap();
        let replayed = Annotations::open(path.clone()).unwrap();
        assert_eq!((replayed.name(0x10), replayed.name(0x20)), (Some("first"), Some("second")));
        assert_eq!(replayed.comment(0x20), Some("note"));
        assert_eq!(annotations.undo().unwrap().len(), 3);
        assert_eq!(annotations.undo().unwrap()[0].value.as_deref(), Some("before"));
        assert!(annotations.undo().unwrap().is_empty());
        cleanup(path);
    }

    #[test]
    fn a_refused_batch_records_nothing() {
        let path = temporary_log("refused-batch");
        let mut annotations = Annotations::open(path.clone()).unwrap();
        let changes = vec![(Field::Name, 0x10, Some("a".to_owned())), (Field::Name, 0x20, Some("b".to_owned()))];
        assert!(annotations.set_batch_validated(&changes, |_| Err("no".to_owned())).is_err());
        assert!(annotations.names().is_empty());
        assert!(annotations.undo().unwrap().is_empty());
        assert!(Annotations::open(path.clone()).unwrap().names().is_empty());
        let _ = std::fs::remove_file(&path);
        cleanup_lock(path);
    }

    #[test]
    fn undoing_a_batch_refuses_when_another_client_changed_any_of_it() {
        let path = temporary_log("batch-conflict");
        let mut agent = Annotations::open(path.clone()).unwrap();
        let mut ui = Annotations::open(path.clone()).unwrap();
        let changes = vec![(Field::Name, 0x10, Some("a".to_owned())), (Field::Name, 0x20, Some("b".to_owned()))];
        agent.set_batch_validated(&changes, |_| Ok(())).unwrap();
        ui.set(Field::Name, 0x20, Some("c".into())).unwrap();
        assert!(agent.undo().is_err());
        assert_eq!((agent.name(0x10), agent.name(0x20)), (Some("a"), Some("c")));
        cleanup(path);
    }
}
