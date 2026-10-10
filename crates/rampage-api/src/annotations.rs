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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Field {
    Name,
    Comment,
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
    /// Edits applied in this session, for undo; and undone ones, for redo.
    done: Vec<Edit>,
    undone: Vec<Edit>,
    /// Where edits are appended; `None` keeps them in memory only.
    log: Option<Log>,
}

#[derive(Default)]
struct Log {
    path: PathBuf,
    /// How many bytes of the file have been applied; other processes' edits lie past this.
    read: u64,
    /// Complete lines read, for error messages.
    lines: usize,
    /// The file ends in a valid edit without a newline, which the next append must supply.
    unterminated: bool,
    /// Where an unreadable final fragment (an interrupted write) starts; the next append replaces it.
    fragment: Option<u64>,
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

    /// Applies edits other processes have appended to the log since it was last read. Returns whether any were.
    pub fn refresh(&mut self) -> Result<bool, String> {
        let Some(log) = &mut self.log else { return Ok(false) };
        let (restart, edits) = read_new_edits(log)?;
        if restart {
            self.names.clear();
            self.addresses.clear();
            self.comments.clear();
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
                    self.addresses.remove(&old);
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
        }
    }

    /// Appends `edit` to the log. The appended line is read back, harmlessly, by the next `refresh`.
    fn record(&mut self, edit: &Edit) -> Result<(), String> {
        let Some(log) = &mut self.log else { return Ok(()) };
        let mut line = if log.unterminated { "\n".to_owned() } else { String::new() };
        line.push_str(&serde_json::to_string(edit).map_err(|error| error.to_string())?);
        line.push('\n');
        let error = |error: std::io::Error| format!("{}: {error}", log.path.display());
        let mut file = OpenOptions::new().create(true).append(true).open(&log.path).map_err(error)?;
        if let Some(fragment) = log.fragment {
            file.set_len(fragment).map_err(error)?;
        }
        file.write_all(line.as_bytes()).map_err(error)?;
        if let Some(fragment) = log.fragment.take() {
            log.read = log.read.min(fragment);
        }
        log.unterminated = false;
        Ok(())
    }

    fn commit(&mut self, edit: &Edit) -> Result<(), String> {
        self.record(edit)?;
        self.apply(edit);
        Ok(())
    }

    /// Sets or clears `field` at `address`, recording the edit. Returns false when nothing changed.
    pub fn set(&mut self, field: Field, address: u64, value: Option<String>) -> Result<bool, String> {
        self.refresh()?;
        let previous = self.field_map(field).get(&address).cloned();
        if previous == value {
            return Ok(false);
        }
        let edit = Edit { field, address, value, previous };
        self.commit(&edit)?;
        self.done.push(edit);
        self.undone.clear();
        Ok(true)
    }

    /// Reverts the last edit made through this instance. Returns the edit undone.
    pub fn undo(&mut self) -> Result<Option<Edit>, String> {
        self.refresh()?;
        let Some(edit) = self.done.pop() else { return Ok(None) };
        self.commit(&edit.inverse())?;
        self.undone.push(edit.clone());
        Ok(Some(edit))
    }

    /// Reapplies the last undone edit. Returns it.
    pub fn redo(&mut self) -> Result<Option<Edit>, String> {
        self.refresh()?;
        let Some(edit) = self.undone.pop() else { return Ok(None) };
        self.commit(&edit)?;
        self.done.push(edit.clone());
        Ok(Some(edit))
    }

    fn field_map(&self, field: Field) -> &BTreeMap<u64, String> {
        match field {
            Field::Name => &self.names,
            Field::Comment => &self.comments,
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
}

/// Reads the edits appended to `log` since it was last read. Returns them, and whether the file shrank (it was
/// replaced), in which case they are its whole contents and earlier state must be dropped.
fn read_new_edits(log: &mut Log) -> Result<(bool, Vec<Edit>), String> {
    let path = log.path.clone();
    let error = |error: std::io::Error| format!("{}: {error}", path.display());
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(problem) if problem.kind() == std::io::ErrorKind::NotFound => return Ok((false, Vec::new())),
        Err(problem) => return Err(error(problem)),
    };
    let len = file.metadata().map_err(error)?.len();
    let restart = len < log.read;
    if restart {
        *log = Log { path: path.clone(), ..Log::default() };
    }
    if len == log.read {
        return Ok((restart, Vec::new()));
    }
    let start = log.read;
    file.seek(SeekFrom::Start(start)).map_err(error)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(error)?;

    let mut edits = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let end = bytes[offset..].iter().position(|&byte| byte == b'\n').map(|index| offset + index);
        let line = String::from_utf8_lossy(&bytes[offset..end.unwrap_or(bytes.len())]);
        let parsed = (!line.trim().is_empty()).then(|| serde_json::from_str::<Edit>(&line));
        match (end, parsed) {
            (Some(_), Some(Err(problem))) => {
                return Err(format!("{}:{}: {problem}", path.display(), log.lines + 1));
            }
            (Some(_), parsed) => {
                edits.extend(parsed.and_then(Result::ok));
                log.lines += 1;
            }
            (None, Some(Ok(edit))) => {
                edits.push(edit);
                log.unterminated = true;
            }
            (None, Some(Err(_))) => log.fragment = Some(start + offset as u64),
            (None, None) => {}
        }
        offset = end.map_or(bytes.len(), |end| end + 1);
    }
    log.read = start + bytes.len() as u64;
    Ok((restart, edits))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_log(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("rampage-{name}-{}.rampage", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn edits_undo_redo_and_replay_from_the_log() {
        let path = temporary_log("annotations");
        let mut annotations = Annotations::open(path.clone()).unwrap();
        assert!(annotations.set(Field::Name, 0x1000, Some("parse".into())).unwrap());
        assert!(!annotations.set(Field::Name, 0x1000, Some("parse".into())).unwrap());
        annotations.set(Field::Comment, 0x1004, Some("length check".into())).unwrap();
        annotations.set(Field::Name, 0x1000, Some("parse_header".into())).unwrap();
        assert_eq!(annotations.undo().unwrap().map(|edit| edit.value), Some(Some("parse_header".into())));
        assert_eq!(annotations.name(0x1000), Some("parse"));
        assert_eq!(annotations.address_of("parse_header"), None);
        annotations.redo().unwrap();
        assert_eq!(annotations.name(0x1000), Some("parse_header"));
        annotations.set(Field::Comment, 0x1004, None).unwrap();

        let replayed = Annotations::open(path.clone()).unwrap();
        assert_eq!(replayed.name(0x1000), Some("parse_header"));
        assert_eq!(replayed.comment(0x1004), None);
        assert_eq!(replayed.address_of("parse_header"), Some(0x1000));
        std::fs::remove_file(path).unwrap();
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
        std::fs::remove_file(path).unwrap();
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
        std::fs::remove_file(path).unwrap();
    }
}
