//! Many names and comments in one call, applied all-or-nothing as one undo step, and a read-only pre-flight
//! check of candidate names.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::ApiError;
use crate::annotations::{Annotations, Field};
use crate::decompile::DecompilerState;
use crate::project::{Project, check_name, is_address_shaped};
use rampage_decompiler::DecompilerOptions;

/// The most entries one batch, or one name check, takes.
pub const MAX_BATCH: usize = 1000;

/// One entry of a batch: a name, a comment, or both, for one address.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchEntry {
    /// An address (`0x401000`) or a name: symbol, export, import, user name, or `sub_<hex>`. Names resolve as they
    /// were before the batch, not as earlier entries leave them.
    pub at: String,
    /// The new name: an identifier not used elsewhere.
    #[serde(default)]
    pub name: Option<String>,
    /// The comment to set (not blank).
    #[serde(default)]
    pub comment: Option<String>,
}

/// What a batch did to one entry.
#[derive(Debug, Clone, Serialize)]
pub struct BatchOutcome {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// False when everything the entry sets was already set.
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchResult {
    /// How many entries changed something.
    pub changed: usize,
    pub entries: Vec<BatchOutcome>,
}

/// Whether a candidate name could be given, and what already has it.
#[derive(Debug, Clone, Serialize)]
pub struct NameCheck {
    pub name: String,
    /// An identifier `rename` accepts (whether or not it is free).
    pub valid: bool,
    /// Read as an address (`sub_<hex>`, `0x...`), so never usable as a name.
    pub address_shaped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    /// The address the name already refers to.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub used_at: Option<u64>,
    /// `user` for a user name, `symbol` for a symbol, export, stub or import name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_by: Option<&'static str>,
}

fn check_size(len: usize, what: &str) -> Result<(), ApiError> {
    if len > MAX_BATCH {
        return Err(ApiError::Invalid(format!("{len} {what}; at most {MAX_BATCH} per call, so split them")));
    }
    Ok(())
}

impl Project {
    /// Applies every entry's name and comment as one undo step, after checking them all by `rename`'s and
    /// `comment`'s rules (names also unique within the batch). One invalid entry applies nothing; the error lists
    /// each invalid entry by index.
    pub fn annotate_batch(&self, entries: &[BatchEntry]) -> Result<BatchResult, ApiError> {
        check_size(entries.len(), "entries")?;
        // The same locks, in the same order, as `rename`, so validation and edit cannot interleave with another's.
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        let mut annotations = self.annotations.write().expect("annotations lock");
        annotations.locked(|annotations| self.annotate_locked(&state, &options, annotations, entries))
    }

    /// `annotate_batch` once it holds the locks.
    fn annotate_locked(
        &self,
        state: &DecompilerState,
        options: &DecompilerOptions,
        annotations: &mut Annotations,
        entries: &[BatchEntry],
    ) -> Result<BatchResult, ApiError> {
        let mut problems = Vec::new();
        let mut addresses = Vec::with_capacity(entries.len());
        let mut named: HashMap<u64, usize> = HashMap::new();
        let mut commented: HashMap<u64, usize> = HashMap::new();
        let mut names: HashMap<&str, (usize, u64)> = HashMap::new();
        for (index, entry) in entries.iter().enumerate() {
            let mut problem = |reason: String| problems.push((index, reason));
            let address = match self.resolve_in(annotations, &entry.at) {
                Ok(address) => address,
                Err(error) => {
                    problem(error.to_string());
                    addresses.push(None);
                    continue;
                }
            };
            addresses.push(Some(address));
            if entry.name.is_none() && entry.comment.is_none() {
                problem("give `name`, `comment` or both".to_owned());
            }
            if entry.comment.as_deref().is_some_and(|comment| comment.trim().is_empty()) {
                problem("the comment is blank; a batch cannot remove comments".to_owned());
            }
            if entry.comment.is_some()
                && let Some(earlier) = commented.insert(address, index)
            {
                problem(format!("entry {earlier} also comments {address:#x}"));
            }
            let Some(name) = entry.name.as_deref() else { continue };
            if let Err(reason) = check_name(name) {
                problem(reason);
                continue;
            }
            if let Some(earlier) = named.insert(address, index) {
                problem(format!("entry {earlier} also names {address:#x}"));
            }
            match names.get(name) {
                Some(&(earlier, other)) if other != address => {
                    problem(format!("{name:?} is also given to {other:#x} by entry {earlier}"));
                }
                Some(_) => {}
                None => drop(names.insert(name, (index, address))),
            }
        }
        // A user name this batch moves off its address is free for another entry to take.
        for (index, entry) in entries.iter().enumerate() {
            let (Some(name), Some(address)) = (entry.name.as_deref(), addresses[index]) else { continue };
            if check_name(name).is_err() {
                continue;
            }
            let existing = match annotations.address_of(name) {
                Some(user) if user == address => None,
                Some(user) if !named.contains_key(&user) => Some(user),
                _ => self.symbol_address(name).filter(|&symbol| symbol != address),
            };
            if let Some(existing) = existing {
                problems.push((index, format!("{name:?} already names {existing:#x}")));
            }
        }
        if !problems.is_empty() {
            problems.sort_by_key(|(index, _)| *index);
            let mut invalid: Vec<usize> = problems.iter().map(|(index, _)| *index).collect();
            invalid.dedup();
            let mut message = format!("nothing applied: {} of {} entries are invalid", invalid.len(), entries.len());
            for (index, reason) in &problems {
                message.push_str(&format!("\nentry {index} ({:?}): {reason}", entries[*index].at));
            }
            return Err(ApiError::Invalid(message));
        }

        let mut changes = Vec::new();
        let mut owners = Vec::new();
        let mut outcomes = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let address = addresses[index].expect("every entry resolved");
            let comment = entry.comment.as_deref().map(str::trim).map(str::to_owned);
            for (field, value) in [(Field::Name, entry.name.clone()), (Field::Comment, comment.clone())] {
                if value.is_some() {
                    changes.push((field, address, value));
                    owners.push(index);
                }
            }
            outcomes.push(BatchOutcome { address, name: entry.name.clone(), comment, changed: false });
        }
        let changed = annotations
            .set_batch_validated(&changes, |candidate| {
                if candidate.globals().is_empty() && candidate.data_types().is_empty() {
                    return Ok(());
                }
                self.validate_annotation_snapshot(state, options, candidate)
            })
            .map_err(ApiError::Invalid)?;
        for (owner, changed) in owners.into_iter().zip(changed) {
            outcomes[owner].changed |= changed;
        }
        Ok(BatchResult { changed: outcomes.iter().filter(|outcome| outcome.changed).count(), entries: outcomes })
    }

    /// Reports, for each candidate name, whether `rename` would accept it and what already uses it.
    pub fn check_names(&self, names: &[String]) -> Result<Vec<NameCheck>, ApiError> {
        check_size(names.len(), "names")?;
        let annotations = self.annotations();
        Ok(names
            .iter()
            .map(|name| {
                let problem = check_name(name).err();
                let user = annotations.address_of(name);
                let used_at = user.or_else(|| self.symbol_address(name));
                NameCheck {
                    name: name.clone(),
                    valid: problem.is_none(),
                    address_shaped: is_address_shaped(name),
                    problem,
                    used_at,
                    used_by: used_at.map(|_| if user.is_some() { "user" } else { "symbol" }),
                }
            })
            .collect())
    }
}
