//! User annotations: names and comments, kept as an append-only log of edits.
//!
//! Every edit records the value it replaced, so undo is just another edit that restores it, and the log on disk
//! remains a complete history in JSON Lines that people and tools can read.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
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
    #[serde(with = "hex_address")]
    pub address: u64,
    pub value: Option<String>,
    pub previous: Option<String>,
}

impl Edit {
    fn inverse(&self) -> Edit {
        Edit { field: self.field, address: self.address, value: self.previous.clone(), previous: self.value.clone() }
    }
}

mod hex_address {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(address: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{address:#x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        let digits = text.strip_prefix("0x").ok_or_else(|| serde::de::Error::custom("address must start with 0x"))?;
        u64::from_str_radix(digits, 16).map_err(serde::de::Error::custom)
    }
}

#[derive(Default)]
pub struct Annotations {
    names: BTreeMap<u64, String>,
    comments: BTreeMap<u64, String>,
    /// Edits applied in this session, for undo; and undone ones, for redo.
    done: Vec<Edit>,
    undone: Vec<Edit>,
    /// Where edits are appended; `None` keeps them in memory only.
    log: Option<PathBuf>,
}

impl Annotations {
    /// Loads the log at `path` if it exists; later edits are appended to it.
    pub fn open(path: PathBuf) -> Result<Self, String> {
        let mut annotations = Self { log: Some(path.clone()), ..Self::default() };
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(annotations),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        for (number, line) in BufReader::new(file).lines().enumerate() {
            let line = line.map_err(|error| format!("{}: {error}", path.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            let edit: Edit =
                serde_json::from_str(&line).map_err(|error| format!("{}:{}: {error}", path.display(), number + 1))?;
            annotations.apply(&edit);
        }
        Ok(annotations)
    }

    pub fn in_memory() -> Self {
        Self::default()
    }

    fn map(&mut self, field: Field) -> &mut BTreeMap<u64, String> {
        match field {
            Field::Name => &mut self.names,
            Field::Comment => &mut self.comments,
        }
    }

    fn apply(&mut self, edit: &Edit) {
        let map = self.map(edit.field);
        match &edit.value {
            Some(value) => map.insert(edit.address, value.clone()),
            None => map.remove(&edit.address),
        };
    }

    fn record(&mut self, edit: &Edit) -> Result<(), String> {
        let Some(path) = &self.log else { return Ok(()) };
        let mut line = serde_json::to_string(edit).map_err(|error| error.to_string())?;
        line.push('\n');
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| file.write_all(line.as_bytes()))
            .map_err(|error| format!("{}: {error}", path.display()))
    }

    /// Sets or clears `field` at `address`, recording the edit. Returns false when nothing changed.
    pub fn set(&mut self, field: Field, address: u64, value: Option<String>) -> Result<bool, String> {
        let previous = self.map(field).get(&address).cloned();
        if previous == value {
            return Ok(false);
        }
        let edit = Edit { field, address, value, previous };
        self.record(&edit)?;
        self.apply(&edit);
        self.done.push(edit);
        self.undone.clear();
        Ok(true)
    }

    /// Reverts the last edit of this session. Returns the edit undone.
    pub fn undo(&mut self) -> Result<Option<Edit>, String> {
        let Some(edit) = self.done.pop() else { return Ok(None) };
        let inverse = edit.inverse();
        self.record(&inverse)?;
        self.apply(&inverse);
        self.undone.push(edit.clone());
        Ok(Some(edit))
    }

    /// Reapplies the last undone edit. Returns it.
    pub fn redo(&mut self) -> Result<Option<Edit>, String> {
        let Some(edit) = self.undone.pop() else { return Ok(None) };
        self.record(&edit)?;
        self.apply(&edit);
        self.done.push(edit.clone());
        Ok(Some(edit))
    }

    pub fn name(&self, address: u64) -> Option<&str> {
        self.names.get(&address).map(String::as_str)
    }

    pub fn comment(&self, address: u64) -> Option<&str> {
        self.comments.get(&address).map(String::as_str)
    }

    pub fn address_of(&self, name: &str) -> Option<u64> {
        self.names.iter().find(|(_, candidate)| candidate.as_str() == name).map(|(&address, _)| address)
    }

    pub fn names(&self) -> &BTreeMap<u64, String> {
        &self.names
    }

    pub fn comments(&self) -> &BTreeMap<u64, String> {
        &self.comments
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_undo_redo_and_replay_from_the_log() {
        let path = std::env::temp_dir().join(format!("rampage-annotations-{}.rampage", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut annotations = Annotations::open(path.clone()).unwrap();
        assert!(annotations.set(Field::Name, 0x1000, Some("parse".into())).unwrap());
        assert!(!annotations.set(Field::Name, 0x1000, Some("parse".into())).unwrap());
        annotations.set(Field::Comment, 0x1004, Some("length check".into())).unwrap();
        annotations.set(Field::Name, 0x1000, Some("parse_header".into())).unwrap();
        assert_eq!(annotations.undo().unwrap().map(|edit| edit.value), Some(Some("parse_header".into())));
        assert_eq!(annotations.name(0x1000), Some("parse"));
        annotations.redo().unwrap();
        assert_eq!(annotations.name(0x1000), Some("parse_header"));
        annotations.set(Field::Comment, 0x1004, None).unwrap();

        let replayed = Annotations::open(path.clone()).unwrap();
        assert_eq!(replayed.name(0x1000), Some("parse_header"));
        assert_eq!(replayed.comment(0x1004), None);
        assert_eq!(replayed.address_of("parse_header"), Some(0x1000));
        std::fs::remove_file(path).unwrap();
    }
}
