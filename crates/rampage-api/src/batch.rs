//! Atomic annotation batches and a read-only pre-flight check of candidate names.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::ApiError;
use crate::annotations::{Annotations, Field};
use crate::decompile::DecompilerState;
use crate::project::{Project, check_name, is_address_shaped};
use rampage_decompiler::DecompilerOptions;

/// One field's new value at one address (or ledger id), as a batch writes it.
pub(crate) type AnnotationChange = (Field, u64, Option<String>);

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

/// A checked annotation operation. `value` is required: explicit null clears the annotation.
/// Addresses and names resolve against the source snapshot, before any operation in the batch.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum AnnotationBatchEntry {
    Rename {
        at: String,
        #[serde(deserialize_with = "required_annotation_value")]
        #[schemars(required, schema_with = "annotation_value_schema")]
        value: Option<String>,
    },
    Comment {
        at: String,
        #[serde(deserialize_with = "required_annotation_value")]
        #[schemars(required, schema_with = "annotation_value_schema")]
        value: Option<String>,
    },
    Signature {
        at: String,
        #[serde(deserialize_with = "required_annotation_value")]
        #[schemars(required, schema_with = "annotation_value_schema")]
        value: Option<String>,
    },
    Types {
        at: String,
        #[serde(deserialize_with = "required_annotation_value")]
        #[schemars(required, schema_with = "annotation_value_schema")]
        value: Option<String>,
    },
    Global {
        at: String,
        #[serde(deserialize_with = "required_annotation_value")]
        #[schemars(required, schema_with = "annotation_value_schema")]
        value: Option<String>,
    },
}

fn required_annotation_value<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

fn annotation_value_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    <Option<String> as schemars::JsonSchema>::json_schema(generator)
}

impl AnnotationBatchEntry {
    fn parts(&self) -> (Field, &str, Option<&str>) {
        let (field, at, value) = match self {
            Self::Rename { at, value } => (Field::Name, at, value),
            Self::Comment { at, value } => (Field::Comment, at, value),
            Self::Signature { at, value } => (Field::Signature, at, value),
            Self::Types { at, value } => (Field::Types, at, value),
            Self::Global { at, value } => (Field::Global, at, value),
        };
        (field, at, value.as_deref())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AnnotationBatchOutcome {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub field: Field,
    /// The normalized value; null means the annotation was cleared.
    pub value: Option<String>,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnnotationBatchResult {
    pub changed: usize,
    pub entries: Vec<AnnotationBatchOutcome>,
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
    /// Validates the complete candidate and appends one atomic, undoable heterogeneous annotation batch.
    /// Duplicate field/address pairs refuse, including signature addresses normalized to their function entry.
    pub fn batch_annotations(&self, entries: &[AnnotationBatchEntry]) -> Result<AnnotationBatchResult, ApiError> {
        self.batch_annotations_with_preflight(entries, |_| Ok(()))
    }

    /// Checks the complete response under the same authority lock, before any append or history publication.
    pub fn batch_annotations_with_preflight(
        &self,
        entries: &[AnnotationBatchEntry],
        preflight: impl FnOnce(&AnnotationBatchResult) -> Result<(), ApiError>,
    ) -> Result<AnnotationBatchResult, ApiError> {
        self.batch_annotations_with_extra(entries, |_| Ok(Vec::new()), preflight)
    }

    /// [`Project::batch_annotations_with_preflight`] with further changes, made from the locked current annotations
    /// (such as a provenance ledger entry), in the same batch and undo step.
    pub(crate) fn batch_annotations_with_extra(
        &self,
        entries: &[AnnotationBatchEntry],
        extra: impl FnOnce(&Annotations) -> Result<Vec<AnnotationChange>, ApiError>,
        preflight: impl FnOnce(&AnnotationBatchResult) -> Result<(), ApiError>,
    ) -> Result<AnnotationBatchResult, ApiError> {
        check_size(entries.len(), "entries")?;
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        let mut annotations = self.annotations.write().expect("annotations lock");
        annotations.locked_staged_checked(|current| {
            self.validate_patch_context(current)?;
            crate::decompile::validate_cached_layout_source(self, &state)?;
            crate::debug_layout_import::validate_replay_source(self, current)?;
            crate::debug_type_import::validate_replay_source(self, current)?;
            crate::debug_type_import::validate_options(current, &options)?;
            let mut changes = self.annotation_batch_changes(current, entries)?;
            changes.extend(extra(current)?);
            let outcomes: Vec<_> = changes
                .iter()
                .map(|(field, address, value)| {
                    let previous = match field {
                        Field::Name => current.names().get(address),
                        Field::Comment => current.comments().get(address),
                        Field::Signature => current.signatures().get(address),
                        Field::Types => current.types().get(address),
                        Field::Global => current.globals().get(address),
                        Field::Finding => current.findings().get(address),
                        _ => unreachable!("public annotation batch fields"),
                    };
                    AnnotationBatchOutcome {
                        address: *address,
                        field: *field,
                        value: value.clone(),
                        changed: previous != value.as_ref(),
                    }
                })
                .collect();
            let mut result = AnnotationBatchResult {
                changed: outcomes.iter().filter(|outcome| outcome.changed).count(),
                entries: outcomes,
            };
            if result.changed == 0 {
                self.validate_annotation_snapshot(&state, &options, current).map_err(ApiError::Invalid)?;
                preflight(&result)?;
                return Ok(result);
            }
            let changed = current
                .set_batch_validated(&changes, |candidate| {
                    self.validate_annotation_snapshot(&state, &options, candidate)?;
                    preflight(&result).map_err(|error| error.to_string())
                })
                .map_err(ApiError::Invalid)?;
            for (outcome, changed) in result.entries.iter_mut().zip(changed) {
                outcome.changed = changed;
            }
            result.changed = result.entries.iter().filter(|entry| entry.changed).count();
            Ok(result)
        })
    }

    fn annotation_batch_changes(
        &self,
        current: &Annotations,
        entries: &[AnnotationBatchEntry],
    ) -> Result<Vec<(Field, u64, Option<String>)>, ApiError> {
        let mut changes = Vec::with_capacity(entries.len());
        let mut targets = HashMap::new();
        let mut renamed = HashMap::new();
        let mut names = HashMap::new();
        let mut bytes = 0usize;
        // Checked on the first signature entry, then reused rather than rechecked per entry.
        let mut analysis = None;
        for (index, entry) in entries.iter().enumerate() {
            let (field, at, value) = entry.parts();
            bytes = bytes.saturating_add(at.len()).saturating_add(value.map_or(0, str::len));
            if at.len() > 4096 || value.is_some_and(|value| value.len() > 1024 * 1024) || bytes > 8 * 1024 * 1024 {
                return Err(ApiError::Invalid("annotation batch exceeds its bounded input budget".into()));
            }
            let mut address = self.resolve_in(current, at)?;
            if field == Field::Signature && self.binary.import_slot(address).is_none() {
                let checked = match analysis {
                    Some(checked) => checked,
                    None => *analysis.insert(self.analysis()?),
                };
                address = checked.function_containing(address).unwrap_or(address);
            }
            if let Some(earlier) = targets.insert((field as u8, address), index) {
                return Err(ApiError::Invalid(format!(
                    "nothing applied: entry {earlier} and entry {index} both set {field:?} at {address:#x}"
                )));
            }
            let value = if field == Field::Name {
                if let Some(name) = value {
                    check_name(name).map_err(ApiError::Invalid)?;
                    if let Some(other) = names.insert(name, address)
                        && other != address
                    {
                        return Err(ApiError::Invalid(format!("nothing applied: {name:?} is given to two addresses")));
                    }
                }
                renamed.insert(address, index);
                value
            } else {
                value.map(str::trim).filter(|value| !value.is_empty())
            };
            if let Some(value) = value {
                if matches!(field, Field::Signature | Field::Types | Field::Global) {
                    crate::decompile::validate_declaration_input(value)?;
                }
                if field == Field::Signature
                    && !self.binary.is_code(address)
                    && self.binary.import_slot(address).is_none()
                {
                    return Err(ApiError::Invalid("signature address is neither code nor an import slot".into()));
                }
                if field == Field::Global
                    && (self.binary.is_code(address)
                        || !self.binary.segments.iter().any(|segment| segment.contains(address)))
                {
                    return Err(ApiError::Invalid("global address requires mapped data, not code".into()));
                }
            }
            changes.push((field, address, value.map(str::to_owned)));
        }
        for (name, address) in names {
            let existing = match current.address_of(name) {
                Some(user) if user == address => None,
                Some(user) if !renamed.contains_key(&user) => Some(user),
                _ => self.symbol_address(name).filter(|&symbol| symbol != address),
            };
            if let Some(existing) = existing {
                return Err(ApiError::Invalid(format!("nothing applied: {name:?} already names {existing:#x}")));
            }
        }
        Ok(changes)
    }

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

#[cfg(test)]
#[path = "batch_tests.rs"]
mod tests;
