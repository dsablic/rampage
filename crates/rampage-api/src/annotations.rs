//! User annotations: names and comments, kept as an append-only log of edits.
//!
//! Every edit records the value it replaced, so undo is just another edit that restores it, and the log on disk
//! remains a complete history in JSON Lines that people and tools can read. Several processes (the UI, an MCP
//! server, the CLI) may share one log: each appends its own edits and picks up the others' through `refresh`.
//!
//! The binary beside a log can be rebuilt or replaced, and an address then may name different code. So a writer
//! that knows its image's SHA-256 logs it in an identity line (`{"image": "<hex>"}`) before the first edit it makes
//! on that image, and every edit is attributed to the identity line before it, or, in a log begun before identity
//! lines existed, to the first one. [`Annotations::warnings`] says when some edits were made on another image, or
//! when none can be attributed yet.

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

/// The line logged before a batch's edits, saying how many follow. Each of them carries the batch's id, so a reader
/// applies the batch only once all are there, and never takes edits written after an interrupted batch for the
/// rest of it. Readers that predate batches skip this line, which is not an edit, and apply the edits one by one.
#[derive(Serialize, Deserialize)]
struct BatchHeader {
    batch: String,
    edits: usize,
}

/// One of a batch's edits, as logged.
#[derive(Serialize)]
struct BatchMember<'a> {
    #[serde(flatten)]
    edit: &'a Edit,
    batch: &'a str,
}

/// Enough of a log line to tell a batch header (both), a batch's edit (`batch` only), an identity line (`image`)
/// and a lone edit (none).
#[derive(Deserialize)]
struct LineKind {
    #[serde(default)]
    batch: Option<String>,
    #[serde(default)]
    edits: Option<usize>,
    #[serde(default)]
    image: Option<String>,
}

/// The line logged before the edits a writer makes on one image: that image's SHA-256, in hex. Readers that predate
/// it skip it, as it is not an edit.
#[derive(Serialize)]
struct ImageLine<'a> {
    image: &'a str,
}

/// An id no other batch in the log is likely to share: this process's, the time's, and a count.
fn batch_id() -> String {
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |time| time.as_nanos());
    format!("{:x}-{nanos:x}-{count:x}", std::process::id())
}

/// Appended to an undo's refusal over another client's edits, which repeats until the step is undone or discarded;
/// a refusal ending with it is one [`Annotations::discard_undo_step`] can clear.
pub const DISCARD_HINT: &str =
    "; discard_undo drops this step from the undo history (its edits stay in effect) so earlier ones can be undone";

/// Why replaying a step changed nothing.
enum Refusal {
    /// Another client's edits since block it; trying again will not help until they change.
    Blocked(String),
    /// The result failed validation, or the log could not be written.
    Failed(String),
}

impl Refusal {
    fn message(self) -> String {
        match self {
            Self::Blocked(message) | Self::Failed(message) => message,
        }
    }
}

#[derive(Default)]
pub struct Annotations {
    names: BTreeMap<u64, String>,
    /// Each name's address, for resolving names.
    addresses: HashMap<String, u64>,
    name_owners: BTreeMap<String, std::collections::BTreeSet<u64>>,
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
    /// Explicit checked ingestion. Legacy `open` does not retroactively provide an allocation-safe boundary.
    checked_reads: bool,
    managed_layouts: usize,
}

const CHECKED_CACHE_BYTES: usize = 8 * 1024 * 1024;
const CHECKED_VALUE_BYTES: usize = 1024 * 1024;
const CHECKED_RECORDS: usize = 8192;
const CHECKED_HISTORY_STEPS: usize = 1024;
const CHECKED_READ_BYTES: usize = 16 * 1024 * 1024;
const CHECKED_LINE_BYTES: usize = 2 * 1024 * 1024;
const CHECKED_ERROR: &str = "checked annotation input is malformed, unstable, or exceeds its bounded ingestion budget";

#[derive(Default)]
struct CheckedBudget {
    bytes: usize,
    records: usize,
}

impl CheckedBudget {
    fn text(&mut self, text: &str) -> Result<(), String> {
        self.bytes = self.bytes.checked_add(text.len()).ok_or(CHECKED_ERROR)?;
        self.records += 1;
        if text.len() > CHECKED_VALUE_BYTES || self.bytes > CHECKED_CACHE_BYTES || self.records > CHECKED_RECORDS {
            return Err(CHECKED_ERROR.to_owned());
        }
        Ok(())
    }
    fn edit(&mut self, edit: &Edit) -> Result<(), String> {
        self.records += 1;
        if let Some(value) = &edit.value {
            if edit.field == Field::Name && value.len() > 128 {
                return Err(CHECKED_ERROR.to_owned());
            }
            self.text(value)?;
        }
        if let Some(previous) = &edit.previous {
            if edit.field == Field::Name && previous.len() > 128 {
                return Err(CHECKED_ERROR.to_owned());
            }
            self.text(previous)?;
        }
        if self.records > CHECKED_RECORDS {
            return Err(CHECKED_ERROR.to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
struct Log {
    path: PathBuf,
    /// How many bytes of the file have been applied: every complete line before this offset. Other processes'
    /// edits, and a line still being written, lie past it.
    read: u64,
    /// The file read, to notice it being replaced by another of any size.
    identity: Option<(u64, u64)>,
    /// The SHA-256 (hex) of the image these annotations are applied to, when known.
    image: Option<String>,
    /// The identity line last read: the image the edits after it were made on.
    logged_image: Option<String>,
    /// Edits were read before any identity line, so the image they were made on is not known yet.
    unattributed: bool,
    /// An image other than `image` that some edits read were made on.
    other_image: Option<String>,
}

impl Log {
    /// Attributes edits just read to the image they were made on.
    fn attribute_edits(&mut self) {
        match &self.logged_image {
            None => self.unattributed = true,
            Some(logged) => self.note_image(logged.clone()),
        }
    }

    fn note_image(&mut self, logged: String) {
        if self.image.as_ref().is_some_and(|image| *image != logged) {
            self.other_image = Some(logged);
        }
    }

    /// Reads an identity line. The first one in a log also stands for the edits before it, which were logged by
    /// writers that predate identity lines.
    fn read_image(&mut self, logged: String) {
        if self.logged_image.is_none() && std::mem::take(&mut self.unattributed) {
            self.note_image(logged.clone());
        }
        self.logged_image = Some(logged);
    }
}

impl Annotations {
    /// Loads the log at `path` if it exists; later edits are appended to it.
    pub fn open(path: PathBuf) -> Result<Self, String> {
        Self::open_for_image(path, None)
    }

    /// [`Annotations::open`] for an image whose SHA-256 is `image`: edits are logged as made on it, and
    /// [`Annotations::warnings`] compares it with the images earlier edits were made on.
    pub fn open_for_image(path: PathBuf, image: Option<[u8; 32]>) -> Result<Self, String> {
        let image = image.map(|digest| rampage_arch::hex::bytes(&digest));
        let mut annotations = Self { log: Some(Log { path, image, ..Log::default() }), ..Self::default() };
        annotations.refresh()?;
        Ok(annotations)
    }

    /// Bounded boundary for logs containing checked layout bundles. Limits apply BEFORE reading/serde:
    /// 16 MiB unread raw bytes, 2 MiB/line, 8192 lines, depth 8 and 65536 structural separators.
    /// Cache/history limits: 8 MiB cumulative text, 1 MiB/value, 8192 counted entries, 1024 undo/redo steps.
    /// Ordinary legacy `open` remains compatible and is not claimed allocation-safe for hostile old objects.
    pub fn open_checked(path: PathBuf) -> Result<Self, String> {
        Self::open_for_image_checked(path, None)
    }

    pub fn open_for_image_checked(path: PathBuf, image: Option<[u8; 32]>) -> Result<Self, String> {
        if path.as_os_str().len() > 4096 {
            return Err(CHECKED_ERROR.to_owned());
        }
        let image = image.map(|digest| rampage_arch::hex::bytes(&digest));
        let mut annotations =
            Self { log: Some(Log { path, image, ..Log::default() }), checked_reads: true, ..Self::default() };
        annotations.refresh()?;
        Ok(annotations)
    }

    pub(crate) fn preflight_checked(&self) -> Result<(), String> {
        self.preflight_checked_with_history(self, &[])
    }

    pub(crate) fn has_checked_layouts(&self) -> bool {
        self.managed_layouts != 0
    }

    fn preflight_checked_with_history(&self, history: &Self, extra: &[Edit]) -> Result<(), String> {
        let mut budget = CheckedBudget::default();
        let rows = self
            .names
            .len()
            .saturating_add(self.comments.len())
            .saturating_add(self.signatures.len())
            .saturating_add(self.types.len())
            .saturating_add(self.globals.len())
            .saturating_add(self.addresses.len())
            .saturating_add(self.name_owners.len());
        if rows > CHECKED_RECORDS {
            return Err(CHECKED_ERROR.to_owned());
        }
        if self.names.values().chain(self.addresses.keys()).chain(self.name_owners.keys()).any(|name| name.len() > 128)
        {
            return Err(CHECKED_ERROR.to_owned());
        }
        for text in self
            .names
            .values()
            .chain(self.comments.values())
            .chain(self.signatures.values())
            .chain(self.types.values())
            .chain(self.globals.values())
            .chain(self.addresses.keys())
            .chain(self.name_owners.keys())
        {
            budget.text(text)?;
        }
        for owners in self.name_owners.values() {
            budget.records = budget
                .records
                .checked_add(owners.len())
                .filter(|&records| records <= CHECKED_RECORDS)
                .ok_or(CHECKED_ERROR)?;
        }
        if history.done.len() + history.undone.len() + usize::from(!extra.is_empty()) > CHECKED_HISTORY_STEPS {
            return Err(CHECKED_ERROR.to_owned());
        }
        for step in history.done.iter().chain(&history.undone) {
            budget.records += 1;
            for edit in step {
                budget.edit(edit)?;
            }
        }
        if !extra.is_empty() {
            budget.records += 1;
        }
        for edit in extra {
            budget.edit(edit)?;
        }
        if let Some(log) = &history.log {
            if log.path.as_os_str().len() > 4096 {
                return Err(CHECKED_ERROR.to_owned());
            }
            budget.bytes = budget.bytes.checked_add(4096 + 3 * 128).ok_or(CHECKED_ERROR)?;
            budget.records += 4;
            for text in [&log.image, &log.logged_image, &log.other_image].into_iter().flatten() {
                if text.len() > 128 {
                    return Err(CHECKED_ERROR.to_owned());
                }
            }
        }
        if budget.records > CHECKED_RECORDS || budget.bytes > CHECKED_CACHE_BYTES {
            return Err(CHECKED_ERROR.to_owned());
        }
        Ok(())
    }

    /// Why these annotations may not fit this image: some were made on another image (a different build at the
    /// same path), or the log predates identity lines, so nothing says which image they were made on.
    pub fn warnings(&self) -> Vec<String> {
        let Some(log) = &self.log else { return Vec::new() };
        let Some(image) = &log.image else { return Vec::new() };
        let path = log.path.display();
        let mut warnings = Vec::new();
        if let Some(other) = &log.other_image {
            warnings.push(format!(
                "annotations in {path} include edits made on a different image (sha256 {other}) than this one \
                 (sha256 {image}); their addresses may no longer name the same code"
            ));
        }
        if log.unattributed && log.logged_image.is_none() {
            warnings.push(format!(
                "annotations in {path} were logged without the image they were made on, so they are unverified \
                 against this one (sha256 {image}); the next edit records it"
            ));
        }
        warnings
    }

    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Takes over the undo and redo steps of `previous`, an instance this one replaces, when both write the same
    /// log: the steps are edits in that log, so reloading the binary beside it leaves them as undoable as before.
    pub(crate) fn inherit_history(&mut self, previous: &Self) {
        let path = |annotations: &Self| annotations.log.as_ref().map(|log| log.path.clone());
        if self.log.is_some() && path(self) == path(previous) {
            self.done.clone_from(&previous.done);
            self.undone.clone_from(&previous.undone);
        }
    }

    pub(crate) fn snapshot(&self) -> Self {
        Self {
            names: self.names.clone(),
            addresses: self.addresses.clone(),
            name_owners: self.name_owners.clone(),
            comments: self.comments.clone(),
            signatures: self.signatures.clone(),
            types: self.types.clone(),
            globals: self.globals.clone(),
            checked_reads: self.checked_reads,
            managed_layouts: self.managed_layouts,
            ..Self::default()
        }
    }

    /// Reads current shared edits into a detached candidate without publishing cache, cursor or history.
    pub(crate) fn checked_snapshot(&self) -> Result<Self, ApiError> {
        self.preflight_checked().map_err(ApiError::Invalid)?;
        let _lock = self.log_lock_checked().map_err(ApiError::Invalid)?;
        let mut candidate = Self { log: self.log.clone(), held: true, checked_reads: true, ..self.snapshot() };
        candidate.refresh().map_err(ApiError::Invalid)?;
        candidate.log = None;
        candidate.held = false;
        Ok(candidate)
    }

    /// Applies edits other processes have appended to the log since it was last read. Returns whether any were.
    pub fn refresh(&mut self) -> Result<bool, String> {
        if self.checked_reads || self.has_checked_layouts() {
            self.preflight_checked()?;
            let mut staged = Self {
                done: self.done.clone(),
                undone: self.undone.clone(),
                log: self.log.clone(),
                held: self.held,
                checked_reads: true,
                ..self.snapshot()
            };
            let changed = staged.refresh_inner(true)?;
            staged.preflight_checked()?;
            *self = staged;
            return Ok(changed);
        }
        self.refresh_inner(false)
    }

    fn refresh_inner(&mut self, checked: bool) -> Result<bool, String> {
        let Some(log) = &mut self.log else { return Ok(false) };
        let (restart, edits) = read_new_edits(log, checked)?;
        if checked {
            let mut budget = CheckedBudget::default();
            for edit in &edits {
                budget.edit(edit)?;
            }
        }
        if restart {
            self.names.clear();
            self.addresses.clear();
            self.name_owners.clear();
            self.comments.clear();
            self.signatures.clear();
            self.types.clear();
            self.globals.clear();
            self.managed_layouts = 0;
        }
        for edit in &edits {
            self.apply(edit);
        }
        Ok(restart || !edits.is_empty())
    }

    fn apply(&mut self, edit: &Edit) {
        if matches!(edit.field, Field::Types | Field::Signature) {
            let old = self.field_map(edit.field).get(&edit.address).is_some_and(|text| text.starts_with('!'));
            let new = edit.value.as_ref().is_some_and(|text| text.starts_with('!'));
            if old != new {
                if new {
                    self.managed_layouts += 1;
                } else {
                    self.managed_layouts -= 1;
                }
            }
        }
        match edit.field {
            Field::Name => {
                if let Some(old) = self.names.remove(&edit.address) {
                    let owners = self.name_owners.get_mut(&old).expect("indexed name owners");
                    owners.remove(&edit.address);
                    let next = owners.first().copied();
                    if owners.is_empty() {
                        self.name_owners.remove(&old);
                    }
                    if self.addresses.get(&old) == Some(&edit.address) {
                        match next {
                            Some(other) => self.addresses.insert(old, other),
                            None => self.addresses.remove(&old),
                        };
                    }
                }
                if let Some(value) = &edit.value {
                    self.names.insert(edit.address, value.clone());
                    self.addresses.insert(value.clone(), edit.address);
                    self.name_owners.entry(value.clone()).or_default().insert(edit.address);
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

    /// Appends `edits` to the log in one write. Several are written as a batch (see `BatchHeader`), which readers
    /// apply whole or not at all, even if the write is cut short. The appended lines are read back, harmlessly, by
    /// the next `refresh`. A file left ending mid-line (by an interrupted write) gets a newline first, so the
    /// fragment becomes a line of its own, which reading skips.
    fn record(&mut self, edits: &[Edit]) -> Result<(), String> {
        if self.checked_reads {
            return self.record_checked(edits);
        }
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
        let mut push = |line: Result<String, serde_json::Error>| -> Result<(), String> {
            lines.push_str(&line.map_err(|error| error.to_string())?);
            lines.push('\n');
            Ok(())
        };
        // Every caller has read the log up to now under its lock, so the last identity line is current.
        let new_image = log.image.clone().filter(|image| log.logged_image.as_ref() != Some(image));
        if let Some(image) = &new_image {
            push(serde_json::to_string(&ImageLine { image }))?;
        }
        if let [edit] = edits {
            push(serde_json::to_string(edit))?;
        } else {
            let batch = batch_id();
            push(serde_json::to_string(&BatchHeader { batch: batch.clone(), edits: edits.len() }))?;
            for edit in edits {
                push(serde_json::to_string(&BatchMember { edit, batch: &batch }))?;
            }
        }
        file.write_all(lines.as_bytes()).map_err(error)?;
        if new_image.is_some() {
            log.logged_image = new_image;
        }
        Ok(())
    }

    fn record_checked(&mut self, edits: &[Edit]) -> Result<(), String> {
        let Some(log) = &mut self.log else { return Ok(()) };
        let new_image = log.image.clone().filter(|image| log.logged_image.as_ref() != Some(image));
        let mut encoded = CheckedLogBuffer::default();
        if let Some(image) = &new_image {
            encoded.line(&ImageLine { image })?;
        }
        if let [edit] = edits {
            encoded.line(edit)?;
        } else {
            let batch = batch_id();
            encoded.line(&BatchHeader { batch: batch.clone(), edits: edits.len() })?;
            for edit in edits {
                encoded.line(&BatchMember { edit, batch: &batch })?;
            }
        }
        checked_outer_preflight(&encoded.bytes)?;
        let mut file = checked_log_append(&log.path).map_err(|_| CHECKED_ERROR.to_owned())?;
        let before = file.metadata().map_err(|_| CHECKED_ERROR.to_owned())?;
        if !before.is_file() || before.len() < log.read {
            return Err(CHECKED_ERROR.to_owned());
        }
        if before.len() != 0 {
            file.seek(SeekFrom::Start(before.len() - 1)).map_err(|_| CHECKED_ERROR.to_owned())?;
            let mut last = [0];
            file.read_exact(&mut last).map_err(|_| CHECKED_ERROR.to_owned())?;
            if last != *b"\n" {
                return Err(CHECKED_ERROR.to_owned());
            }
        }
        let unread = usize::try_from(before.len() - log.read).map_err(|_| CHECKED_ERROR.to_owned())?;
        let combined_len =
            unread.checked_add(encoded.bytes.len()).filter(|&size| size <= CHECKED_READ_BYTES).ok_or(CHECKED_ERROR)?;
        let mut combined = Vec::with_capacity(combined_len);
        combined.resize(unread, 0);
        file.seek(SeekFrom::Start(log.read)).map_err(|_| CHECKED_ERROR.to_owned())?;
        file.read_exact(&mut combined).map_err(|_| CHECKED_ERROR.to_owned())?;
        combined.extend_from_slice(&encoded.bytes);
        checked_outer_preflight(&combined)?;
        let after = file.metadata().map_err(|_| CHECKED_ERROR.to_owned())?;
        let pathname = std::fs::symlink_metadata(&log.path).map_err(|_| CHECKED_ERROR.to_owned())?;
        if pathname.file_type().is_symlink()
            || checked_log_stamp(&before) != checked_log_stamp(&after)
            || checked_log_stamp(&after) != checked_log_stamp(&pathname)
        {
            return Err(CHECKED_ERROR.to_owned());
        }
        file.write_all(&encoded.bytes).map_err(|_| CHECKED_ERROR.to_owned())?;
        if new_image.is_some() {
            log.logged_image = new_image;
        }
        Ok(())
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

    /// Checked PDB apply stages refresh, cursor and history under the same log lock, publishing only on success.
    /// This does not roll back durable writes: work must finish all fallible validation before its final commit.
    pub(crate) fn locked_staged<T>(
        &mut self,
        work: impl FnOnce(&mut Self) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        let _lock = self.log_lock().map_err(ApiError::Invalid)?;
        let mut staged = Self {
            done: self.done.clone(),
            undone: self.undone.clone(),
            log: self.log.clone(),
            held: true,
            ..self.snapshot()
        };
        staged.refresh().map_err(ApiError::Invalid)?;
        let result = work(&mut staged)?;
        staged.held = self.held;
        *self = staged;
        Ok(result)
    }

    /// Checked import/option publication: preflight the already constructed object BEFORE cloning, and
    /// ingest shared edits with bounded outer JSON before publishing cache, history or cursor.
    pub(crate) fn locked_staged_checked<T>(
        &mut self,
        work: impl FnOnce(&mut Self) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        self.preflight_checked().map_err(ApiError::Invalid)?;
        let _lock = self.log_lock_checked().map_err(ApiError::Invalid)?;
        let mut staged = Self {
            done: self.done.clone(),
            undone: self.undone.clone(),
            log: self.log.clone(),
            held: true,
            checked_reads: true,
            ..self.snapshot()
        };
        staged.refresh().map_err(ApiError::Invalid)?;
        let result = work(&mut staged)?;
        staged.checked_reads = self.checked_reads || staged.has_checked_layouts();
        staged.held = self.held;
        *self = staged;
        Ok(result)
    }

    fn log_lock(&self) -> Result<Option<File>, String> {
        if self.checked_reads {
            return self.log_lock_checked();
        }
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

    fn log_lock_checked(&self) -> Result<Option<File>, String> {
        let Some(log) = self.log.as_ref().filter(|_| !self.held) else { return Ok(None) };
        let mut path = log.path.as_os_str().to_owned();
        path.push(".lock");
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, open};
            let flags = OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            let mode = Mode::RUSR | Mode::WUSR;
            let descriptor = open(std::path::Path::new(&path), flags, mode).map_err(|_| CHECKED_ERROR.to_owned())?;
            let file = File::from(descriptor);
            if !file.metadata().map_err(|_| CHECKED_ERROR.to_owned())?.is_file() {
                return Err(CHECKED_ERROR.to_owned());
            }
            file.lock().map_err(|_| CHECKED_ERROR.to_owned())?;
            Ok(Some(file))
        }
        #[cfg(not(unix))]
        Err(CHECKED_ERROR.to_owned())
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
        let value_limit = if field == Field::Name { 128 } else { CHECKED_VALUE_BYTES };
        if self.checked_reads && value.as_ref().is_some_and(|value| value.len() > value_limit) {
            return Err(CHECKED_ERROR.to_owned());
        }
        let previous = self.field_map(field).get(&address).cloned();
        if previous == value {
            return Ok(false);
        }
        if field == Field::Types {
            crate::debug_layout_import::preserve_bundle(previous.as_deref(), value.as_deref())?;
        }
        let edit = Edit { field, address, value, previous };
        let mut candidate = self.snapshot();
        candidate.apply(&edit);
        if self.checked_reads {
            self.preflight_checked_with_history(self, std::slice::from_ref(&edit))?;
            candidate.preflight_checked_with_history(self, std::slice::from_ref(&edit))?;
        }
        crate::debug_layout_import::validate_transition(self, &candidate)?;
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
        if self.checked_reads {
            let mut budget = CheckedBudget::default();
            for (field, _, value) in changes {
                budget.records += 1;
                if let Some(value) = value {
                    if *field == Field::Name && value.len() > 128 {
                        return Err(CHECKED_ERROR.to_owned());
                    }
                    budget.text(value)?;
                }
            }
            if budget.records > CHECKED_RECORDS {
                return Err(CHECKED_ERROR.to_owned());
            }
        }
        let mut candidate = self.snapshot();
        let mut edits = Vec::new();
        let mut changed = Vec::with_capacity(changes.len());
        for (field, address, value) in changes {
            let previous = candidate.field_map(*field).get(address).cloned();
            changed.push(previous != *value);
            if previous != *value {
                if *field == Field::Types {
                    crate::debug_layout_import::preserve_bundle(previous.as_deref(), value.as_deref())?;
                }
                let edit = Edit { field: *field, address: *address, value: value.clone(), previous };
                candidate.apply(&edit);
                edits.push(edit);
            }
        }
        if edits.is_empty() {
            return Ok(changed);
        }
        if self.checked_reads {
            self.preflight_checked_with_history(self, &edits)?;
            candidate.preflight_checked_with_history(self, &edits)?;
        }
        crate::debug_layout_import::validate_transition(self, &candidate)?;
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
        self.replay(&inverses, validate).map_err(|refusal| match refusal {
            Refusal::Blocked(message) => format!("{message}{DISCARD_HINT}"),
            Refusal::Failed(message) => message,
        })?;
        self.done.pop();
        self.undone.push(step.clone());
        Ok(step)
    }

    /// Drops the last step from this instance's undo history without reverting it, for a step another client's
    /// edits block from undoing, which would otherwise block every earlier step too. Its edits stay in effect, and
    /// the log is untouched. Unless `force` is set, it refuses a step that undo could still revert: one client
    /// (such as an assistant sharing the user's project) must not silently take away another's undo. Returns the
    /// dropped step's edits; empty when there is nothing to undo.
    pub fn discard_undo_step(&mut self, force: bool) -> Result<Vec<Edit>, String> {
        let Some(step) = self.done.last() else { return Ok(Vec::new()) };
        if !force {
            let inverses: Vec<Edit> = step.iter().rev().map(Edit::inverse).collect();
            self.refresh()?;
            if self.snapshot().blocked(&inverses).is_none() {
                return Err("no other client's edit blocks undoing the last step, so undo can still revert it; \
                            discard it anyway only with force"
                    .to_owned());
            }
        }
        Ok(self.done.pop().unwrap_or_default())
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
        self.replay(&step, validate).map_err(Refusal::message)?;
        self.undone.pop();
        self.done.push(step.clone());
        Ok(step)
    }

    /// Commits `edits` in order, each only over the value it replaces, and only once `validate` accepts the result
    /// when the step touches what the decompiler checks.
    fn replay(&mut self, edits: &[Edit], validate: impl FnOnce(&Self) -> Result<(), String>) -> Result<(), Refusal> {
        let mut candidate = self.snapshot();
        if let Some(message) = candidate.blocked(edits) {
            return Err(Refusal::Blocked(message));
        }
        if self.checked_reads {
            candidate.preflight_checked_with_history(self, &[]).map_err(Refusal::Failed)?;
        }
        crate::debug_layout_import::validate_transition(self, &candidate).map_err(Refusal::Failed)?;
        let checked = edits.iter().any(|edit| {
            matches!(edit.field, Field::Signature | Field::Types | Field::Global)
                || (edit.field == Field::Name && !candidate.globals().is_empty())
        });
        if checked {
            validate(&candidate).map_err(Refusal::Failed)?;
        }
        self.commit(edits).map_err(Refusal::Failed)
    }

    /// Applies `edits` to this state, saying why they cannot be replayed over other clients' edits: a field
    /// changed since, or a name since given to another address. `None` when nothing blocks them.
    fn blocked(&mut self, edits: &[Edit]) -> Option<String> {
        let mut conflicts = Vec::new();
        for edit in edits {
            if !self.is_unchanged(edit) {
                conflicts.push(edit.address);
            }
            self.apply(edit);
        }
        if !conflicts.is_empty() {
            conflicts.sort_unstable();
            conflicts.dedup();
            let verb = if conflicts.len() == 1 { "was" } else { "were" };
            return Some(format!("{} {verb} edited by another client since; not changed", address_list(&conflicts)));
        }
        let mut taken = Vec::new();
        for edit in edits.iter().filter(|edit| edit.field == Field::Name) {
            let Some(name) = &edit.value else { continue };
            if self.names.iter().any(|(&address, other)| other == name && address != edit.address) {
                taken.push(format!("{name:?}"));
            }
        }
        (!taken.is_empty())
            .then(|| format!("another client has since given {} to another address; not changed", taken.join(", ")))
    }

    /// Whether `edit`'s field still holds `edit.previous`: if another client changed it since, undoing or redoing
    /// over that change would silently discard it.
    fn is_unchanged(&self, edit: &Edit) -> bool {
        self.field_map(edit.field).get(&edit.address) == edit.previous.as_ref()
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
/// dropped. Lines that do not parse, such as a fragment an interrupted write left behind, are skipped, as are the
/// edits of a batch cut short. A batch still incomplete at the end is left to be read again with what follows.
fn read_new_edits(log: &mut Log, checked: bool) -> Result<(bool, Vec<Edit>), String> {
    let path = log.path.clone();
    let error = |error: std::io::Error| format!("{}: {error}", path.display());
    let opened = if checked { checked_log_file(&path) } else { File::open(&path) };
    let mut file = match opened {
        Ok(file) => file,
        Err(problem) if problem.kind() == std::io::ErrorKind::NotFound => return Ok((false, Vec::new())),
        Err(problem) => return Err(error(problem)),
    };
    let metadata = file.metadata().map_err(error)?;
    if checked && (!metadata.is_file() || metadata.len().saturating_sub(log.read) > CHECKED_READ_BYTES as u64) {
        return Err(CHECKED_ERROR.to_owned());
    }
    let identity = file_identity(&metadata);
    let restart = metadata.len() < log.read || (log.identity.is_some() && log.identity != identity);
    if restart {
        *log = Log { path: path.clone(), image: log.image.take(), ..Log::default() };
    }
    log.identity = identity;
    if metadata.len() == log.read {
        return Ok((restart, Vec::new()));
    }
    file.seek(SeekFrom::Start(log.read)).map_err(error)?;
    let mut bytes = Vec::new();
    if checked {
        if metadata.len().saturating_sub(log.read) > CHECKED_READ_BYTES as u64 {
            return Err(CHECKED_ERROR.to_owned());
        }
        (&mut file)
            .take(CHECKED_READ_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| CHECKED_ERROR.to_owned())?;
        if bytes.len() > CHECKED_READ_BYTES {
            return Err(CHECKED_ERROR.to_owned());
        }
        checked_outer_preflight(&bytes)?;
        let after = file.metadata().map_err(|_| CHECKED_ERROR.to_owned())?;
        let pathname = std::fs::symlink_metadata(&path).map_err(|_| CHECKED_ERROR.to_owned())?;
        if pathname.file_type().is_symlink()
            || checked_log_stamp(&metadata) != checked_log_stamp(&after)
            || checked_log_stamp(&after) != checked_log_stamp(&pathname)
        {
            return Err(CHECKED_ERROR.to_owned());
        }
    } else {
        file.read_to_end(&mut bytes).map_err(error)?;
    }
    // Only complete lines: the rest may still be being written.
    let complete = bytes.iter().rposition(|&byte| byte == b'\n').map_or(0, |end| end + 1);
    let mut lines = Vec::new();
    let mut start = 0;
    for line in bytes[..complete].split_inclusive(|&byte| byte == b'\n') {
        lines.push((start, line));
        start += line.len();
    }
    let mut edits = Vec::new();
    let mut read = complete;
    let mut index = 0;
    while let Some(&(start, line)) = lines.get(index) {
        index += 1;
        match serde_json::from_slice::<LineKind>(line) {
            Ok(LineKind { batch: Some(batch), edits: Some(count), .. }) => {
                if checked && (batch.len() > 128 || count > CHECKED_RECORDS) {
                    return Err(CHECKED_ERROR.to_owned());
                }
                let members: Vec<Edit> =
                    lines[index..].iter().take(count).map_while(|(_, line)| batch_member(line, &batch)).collect();
                index += members.len();
                if members.len() == count {
                    log.attribute_edits();
                    edits.extend(members);
                } else if index == lines.len() {
                    read = start;
                    break;
                }
            }
            Ok(LineKind { batch: Some(_), edits: None, .. }) => {}
            Ok(LineKind { batch: None, edits: None, image: Some(image) }) => {
                if checked && image.len() > 128 {
                    return Err(CHECKED_ERROR.to_owned());
                }
                log.read_image(image);
            }
            _ => {
                if let Ok(edit) = serde_json::from_slice::<Edit>(line) {
                    log.attribute_edits();
                    edits.push(edit);
                } else if checked {
                    return Err(CHECKED_ERROR.to_owned());
                }
            }
        }
    }
    log.read += read as u64;
    Ok((restart, edits))
}

fn checked_log_file(path: &std::path::Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, open};
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let descriptor = open(path, flags, Mode::empty())?;
        Ok(File::from(descriptor))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(std::io::Error::other(CHECKED_ERROR))
    }
}

fn checked_log_append(path: &std::path::Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, open};
        let flags =
            OFlags::RDWR | OFlags::APPEND | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let descriptor = open(path, flags, Mode::RUSR | Mode::WUSR)?;
        Ok(File::from(descriptor))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(std::io::Error::other(CHECKED_ERROR))
    }
}

#[derive(Default)]
struct CheckedLogBuffer {
    bytes: Vec<u8>,
    line_bytes: usize,
}

impl Write for CheckedLogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let error = || std::io::Error::other(CHECKED_ERROR);
        let size =
            self.bytes.len().checked_add(bytes.len()).filter(|&size| size <= CHECKED_READ_BYTES).ok_or_else(error)?;
        let mut line_bytes = self.line_bytes;
        for &byte in bytes {
            line_bytes += 1;
            if line_bytes > CHECKED_LINE_BYTES {
                return Err(error());
            }
            if byte == b'\n' {
                line_bytes = 0;
            }
        }
        if size > self.bytes.capacity() {
            let capacity = size.max(self.bytes.capacity().saturating_mul(2)).min(CHECKED_READ_BYTES);
            self.bytes.try_reserve_exact(capacity - self.bytes.len()).map_err(|_| error())?;
        }
        self.bytes.extend_from_slice(bytes);
        self.line_bytes = line_bytes;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CheckedLogBuffer {
    fn line(&mut self, value: &impl Serialize) -> Result<(), String> {
        serde_json::to_writer(&mut *self, value).map_err(|_| CHECKED_ERROR.to_owned())?;
        self.write_all(b"\n").map_err(|_| CHECKED_ERROR.to_owned())
    }
}

type CheckedLogStamp = (Option<(u64, u64)>, u64, Option<std::time::SystemTime>, i64, i64);

fn checked_log_stamp(metadata: &std::fs::Metadata) -> CheckedLogStamp {
    #[cfg(unix)]
    let changed = {
        use std::os::unix::fs::MetadataExt;
        (metadata.ctime(), metadata.ctime_nsec())
    };
    #[cfg(not(unix))]
    let changed = (0, 0);
    (file_identity(metadata), metadata.len(), metadata.modified().ok(), changed.0, changed.1)
}

fn checked_outer_preflight(bytes: &[u8]) -> Result<(), String> {
    let mut records = 0usize;
    let mut separators = 0usize;
    for line in bytes.split_inclusive(|&byte| byte == b'\n') {
        records += 1;
        if records > CHECKED_RECORDS || line.len() > CHECKED_LINE_BYTES {
            return Err(CHECKED_ERROR.to_owned());
        }
        let mut depth = 0usize;
        let mut string = false;
        let mut escaped = false;
        for &byte in line {
            if string {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    string = false;
                }
            } else {
                match byte {
                    b'"' => string = true,
                    b'{' | b'[' => {
                        depth += 1;
                        separators += 1;
                    }
                    b'}' | b']' => depth = depth.checked_sub(1).ok_or(CHECKED_ERROR)?,
                    b',' | b':' => separators += 1,
                    _ => {}
                }
                if depth > 8 || separators > 65536 {
                    return Err(CHECKED_ERROR.to_owned());
                }
            }
        }
        if line.ends_with(b"\n") && (depth != 0 || string) {
            return Err(CHECKED_ERROR.to_owned());
        }
    }
    Ok(())
}

/// The edit `line` holds if it belongs to `batch`.
fn batch_member(line: &[u8], batch: &str) -> Option<Edit> {
    let kind: LineKind = serde_json::from_slice(line).ok()?;
    if kind.edits.is_some() || kind.batch.as_deref() != Some(batch) {
        return None;
    }
    serde_json::from_slice(line).ok()
}

/// The most addresses an error lists before counting the rest.
const LISTED_ADDRESSES: usize = 20;

fn address_list(addresses: &[u64]) -> String {
    let mut list: Vec<String> =
        addresses.iter().take(LISTED_ADDRESSES).map(|address| format!("{address:#x}")).collect();
    if addresses.len() > LISTED_ADDRESSES {
        list.push(format!("{} more", addresses.len() - LISTED_ADDRESSES));
    }
    list.join(", ")
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

    struct CheckedLogFiles(PathBuf);

    impl Drop for CheckedLogFiles {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            cleanup_lock(self.0.clone());
        }
    }

    #[test]
    fn indexed_duplicate_name_owners_keep_last_writer_and_lowest_surviving_address() {
        let files = CheckedLogFiles(temporary_log("checked-duplicate-name-owners"));
        let mut first = Annotations::open_checked(files.0.clone()).unwrap();
        first.set(Field::Name, 20, Some("shared".to_owned())).unwrap();
        let mut second = Annotations::open_checked(files.0.clone()).unwrap();
        second.set(Field::Name, 10, Some("shared".to_owned())).unwrap();
        second.set(Field::Name, 30, Some("shared".to_owned())).unwrap();
        second.refresh().unwrap();
        assert_eq!(second.address_of("shared"), Some(30));
        first.refresh().unwrap();
        assert_eq!(first.address_of("shared"), Some(30));
        second.set(Field::Name, 30, None).unwrap();
        second.refresh().unwrap();
        assert_eq!(second.address_of("shared"), Some(10));
        first.refresh().unwrap();
        assert_eq!(first.address_of("shared"), Some(10));
        assert!(second.undo().unwrap_err().contains("another address"));
        assert_eq!(second.address_of("shared"), Some(10));
        second.set(Field::Name, 30, Some("shared".to_owned())).unwrap();
        second.refresh().unwrap();
        assert_eq!(second.address_of("shared"), Some(30));
    }

    #[test]
    fn checked_encoded_line_limits_reject_before_append_and_preserve_readable_undo() {
        let files = CheckedLogFiles(temporary_log("checked-encoded-write"));
        let mut annotations = Annotations::open_checked(files.0.clone()).unwrap();
        let before = annotations.log.clone();
        let oversized = "\0".repeat(384 * 1024);
        assert_eq!(annotations.set(Field::Comment, 1, Some(oversized)).unwrap_err(), CHECKED_ERROR);
        assert!(!files.0.exists());
        assert!(annotations.comments.is_empty() && annotations.done.is_empty() && annotations.undone.is_empty());
        assert_eq!(annotations.log, before);
        let accepted = "\0".repeat(32);
        annotations.set(Field::Comment, 1, Some(accepted.clone())).unwrap();
        annotations.refresh().unwrap();
        assert_eq!(annotations.comment(1), Some(accepted.as_str()));
        assert_eq!(annotations.undo().unwrap().len(), 1);
        annotations.refresh().unwrap();
        assert_eq!(annotations.comment(1), None);
        assert_eq!(Annotations::open_checked(files.0.clone()).unwrap().comment(1), None);
    }

    #[test]
    fn checked_writer_refuses_an_unterminated_tail_without_extending_it() {
        let files = CheckedLogFiles(temporary_log("checked-pending-tail"));
        let partial = b"{\"field\":\"comment\"";
        std::fs::write(&files.0, partial).unwrap();
        let mut annotations = Annotations::open_checked(files.0.clone()).unwrap();
        assert_eq!(annotations.set(Field::Comment, 1, Some("new".to_owned())).unwrap_err(), CHECKED_ERROR);
        assert_eq!(std::fs::read(&files.0).unwrap(), partial);
        assert!(annotations.comments.is_empty() && annotations.done.is_empty());
        assert_eq!(annotations.log.as_ref().unwrap().read, 0);
    }

    #[test]
    fn checked_writer_counts_pending_batch_bytes_before_appending_a_new_record() {
        let files = CheckedLogFiles(temporary_log("checked-pending-byte-budget"));
        let mut file = File::create(&files.0).unwrap();
        serde_json::to_writer(&mut file, &BatchHeader { batch: "pending".to_owned(), edits: 3901 }).unwrap();
        file.write_all(b"\n").unwrap();
        for address in 0..3900 {
            let edit = Edit { field: Field::Comment, address, value: Some("p".repeat(4000)), previous: None };
            serde_json::to_writer(&mut file, &BatchMember { edit: &edit, batch: "pending" }).unwrap();
            file.write_all(b"\n").unwrap();
        }
        drop(file);
        let length = std::fs::metadata(&files.0).unwrap().len();
        assert!(length < CHECKED_READ_BYTES as u64);
        let mut annotations = Annotations::open_checked(files.0.clone()).unwrap();
        assert!(annotations.comments.is_empty());
        assert_eq!(annotations.log.as_ref().unwrap().read, 0);
        let value = "\0".repeat(300 * 1024);
        assert_eq!(annotations.set(Field::Comment, 10_000, Some(value)).unwrap_err(), CHECKED_ERROR);
        assert_eq!(std::fs::metadata(&files.0).unwrap().len(), length);
        assert!(annotations.comments.is_empty() && annotations.done.is_empty());
        assert_eq!(annotations.log.as_ref().unwrap().read, 0);
        Annotations::open_checked(files.0.clone()).unwrap();
    }

    #[test]
    fn checked_open_bounds_a_real_large_types_envelope_before_decoding() {
        let path = temporary_log("checked-large-types-envelope");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"{\"field\":\"types\",\"address\":\"0x1\",\"value\":\"").unwrap();
        let chunk = [b'x'; 65536];
        for _ in 0..(CHECKED_READ_BYTES / chunk.len() + 1) {
            file.write_all(&chunk).unwrap();
        }
        file.write_all(b"\",\"previous\":null}\n").unwrap();
        drop(file);
        let length = std::fs::metadata(&path).unwrap().len();
        assert_eq!(Annotations::open_checked(path.clone()).err().unwrap(), CHECKED_ERROR);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
        cleanup(path);
    }

    #[test]
    fn checked_staging_rejects_hostile_escapes_without_publishing_cursor_cache_or_history() {
        let path = temporary_log("checked-hostile-escapes");
        let mut annotations = Annotations::open_checked(path.clone()).unwrap();
        annotations.set(Field::Comment, 1, Some("original".to_owned())).unwrap();
        annotations.refresh().unwrap();
        let before_log = annotations.log.clone();
        let before_done = annotations.done.clone();
        let before_undone = annotations.undone.clone();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"field\":\"types\",\"address\":\"0x2\",\"value\":\"\\u0021rampage-layout\\n").unwrap();
        let escaped = b"\\u0078".repeat(4096);
        for _ in 0..(CHECKED_LINE_BYTES / escaped.len() + 1) {
            file.write_all(&escaped).unwrap();
        }
        file.write_all(b"\",\"previous\":null}\n").unwrap();
        drop(file);
        let length = std::fs::metadata(&path).unwrap().len();
        let result: Result<(), ApiError> = annotations.locked_staged_checked(|_| panic!("must refuse before work"));
        assert_eq!(result.unwrap_err().to_string(), CHECKED_ERROR);
        assert_eq!(annotations.log, before_log);
        assert_eq!(annotations.done, before_done);
        assert_eq!(annotations.undone, before_undone);
        assert_eq!(annotations.comment(1), Some("original"));
        assert!(annotations.types().is_empty());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
        cleanup(path);
    }

    #[test]
    fn checked_snapshot_preflights_preconstructed_legacy_cache_and_history_without_cloning() {
        let mut annotations = Annotations::in_memory();
        annotations.comments.insert(1, "x".repeat(CHECKED_VALUE_BYTES + 1));
        assert_eq!(annotations.checked_snapshot().err().unwrap().to_string(), CHECKED_ERROR);
        assert_eq!(annotations.comments[&1].len(), CHECKED_VALUE_BYTES + 1);
        annotations.comments.clear();
        annotations.done.resize_with(CHECKED_HISTORY_STEPS + 1, Vec::new);
        assert_eq!(annotations.checked_snapshot().err().unwrap().to_string(), CHECKED_ERROR);
        assert_eq!(annotations.done.len(), CHECKED_HISTORY_STEPS + 1);
    }

    #[test]
    fn checked_precommit_reserves_the_new_step_and_keeps_its_undo_state_representable() {
        for edit_count in [1usize, 2] {
            let largest_base = CHECKED_RECORDS - (5 + 3 * edit_count);
            for excess in [0, 1] {
                let original = Annotations {
                    comments: (0..largest_base + excess).map(|address| (address as u64, "x".to_owned())).collect(),
                    log: Some(Log { path: PathBuf::from("checked-budget.rampage"), ..Default::default() }),
                    checked_reads: true,
                    ..Default::default()
                };
                original.preflight_checked().unwrap();
                let edits: Vec<_> = (0..edit_count)
                    .map(|index| Edit {
                        field: Field::Comment,
                        address: 10_000 + index as u64,
                        value: Some("x".to_owned()),
                        previous: None,
                    })
                    .collect();
                let mut candidate = original.snapshot();
                for edit in &edits {
                    candidate.apply(edit);
                }
                let result = candidate.preflight_checked_with_history(&original, &edits);
                if excess != 0 {
                    assert_eq!(result.unwrap_err(), CHECKED_ERROR);
                    assert!(original.done.is_empty());
                    continue;
                }
                result.unwrap();
                candidate.log = original.log.clone();
                candidate.done.push(edits);
                candidate.preflight_checked().unwrap();
                original.preflight_checked_with_history(&candidate, &[]).unwrap();
            }
        }
    }

    #[test]
    fn checked_reader_rejects_deep_complete_json_but_legacy_reader_keeps_ordinary_compatibility() {
        let path = temporary_log("checked-deep-json");
        let nested = format!("{}0{}", "[".repeat(9), "]".repeat(9));
        let text = format!(
            "{{\"field\":\"comment\",\"address\":\"0x1\",\"value\":\"kept\",\"previous\":null,\"extra\":{nested}}}\n"
        );
        std::fs::write(&path, text).unwrap();
        assert_eq!(Annotations::open_checked(path.clone()).err().unwrap(), CHECKED_ERROR);
        assert_eq!(Annotations::open(path.clone()).unwrap().comment(1), Some("kept"));
        cleanup(path);
    }

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
    fn failed_staged_refresh_preserves_private_cache_history_cursor_and_external_log_bytes() {
        let path = temporary_log("failed-staged-refresh");
        let mut annotations = Annotations::open_for_image(path.clone(), Some([1; 32])).unwrap();
        for (field, address, value) in [
            (Field::Name, 0x10, "original"),
            (Field::Comment, 0x20, "original comment"),
            (Field::Signature, 0x30, "int4 original(void);"),
            (Field::Types, 0x40, "typedef int4 original_type;"),
            (Field::Global, 0x50, "int4 original_global;"),
        ] {
            annotations.set(field, address, Some(value.to_owned())).unwrap();
        }
        annotations.set(Field::Comment, 0x60, Some("redo comment".to_owned())).unwrap();
        annotations.undo().unwrap();
        annotations.refresh().unwrap();
        let before_cache = annotations.snapshot();
        let before_done = annotations.done.clone();
        let before_undone = annotations.undone.clone();
        let before_log = annotations.log.clone();
        let before_warnings = annotations.warnings();
        assert!(!before_done.is_empty());
        assert!(!before_undone.is_empty());
        assert!(!annotations.held);

        let mut writer = Annotations::open_for_image(path.clone(), Some([2; 32])).unwrap();
        for (field, address, value) in [
            (Field::Name, 0x10, "external_name"),
            (Field::Comment, 0x20, "external comment"),
            (Field::Signature, 0x30, "int4 external_name(void);"),
            (Field::Types, 0x40, "typedef int4 external_type;"),
            (Field::Global, 0x50, "int4 external_global;"),
        ] {
            writer.set(field, address, Some(value.to_owned())).unwrap();
        }
        let external_bytes = std::fs::read(&path).unwrap();
        let result: Result<(), ApiError> = annotations.locked_staged(|staged| {
            assert!(staged.held);
            assert_eq!(staged.name(0x10), Some("external_name"));
            assert_eq!(staged.address_of("original"), None);
            assert_eq!(staged.comment(0x20), Some("external comment"));
            assert_eq!(staged.signatures()[&0x30], "int4 external_name(void);");
            assert_eq!(staged.types()[&0x40], "typedef int4 external_type;");
            assert_eq!(staged.globals()[&0x50], "int4 external_global;");
            assert!(staged.log.as_ref().unwrap().read > before_log.as_ref().unwrap().read);
            assert_ne!(staged.warnings(), before_warnings);
            Err(ApiError::Invalid("source changed after staged refresh".to_owned()))
        });
        assert!(result.unwrap_err().to_string().contains("source changed"));
        assert_eq!(annotations.names, before_cache.names);
        assert_eq!(annotations.addresses, before_cache.addresses);
        assert_eq!(annotations.comments, before_cache.comments);
        assert_eq!(annotations.signatures, before_cache.signatures);
        assert_eq!(annotations.types, before_cache.types);
        assert_eq!(annotations.globals, before_cache.globals);
        assert_eq!(annotations.done, before_done);
        assert_eq!(annotations.undone, before_undone);
        assert_eq!(annotations.log, before_log);
        assert_eq!(annotations.warnings(), before_warnings);
        assert!(!annotations.held);
        assert_eq!(std::fs::read(&path).unwrap(), external_bytes);

        assert!(annotations.refresh().unwrap());
        assert_eq!(annotations.name(0x10), Some("external_name"));
        assert_eq!(annotations.address_of("external_name"), Some(0x10));
        assert_eq!(annotations.comment(0x20), Some("external comment"));
        assert_ne!(annotations.warnings(), before_warnings);
        assert_eq!(annotations.log.as_ref().unwrap().read, external_bytes.len() as u64);
        assert_eq!(annotations.done, before_done);
        assert_eq!(annotations.undone, before_undone);
        assert_eq!(std::fs::read(&path).unwrap(), external_bytes);
        assert!(!annotations.refresh().unwrap());
        cleanup(path);
    }

    #[test]
    fn staged_batch_success_publishes_history_and_preserves_an_outer_log_lock_on_success_and_failure() {
        let path = temporary_log("nested-staged-batch");
        let mut annotations = Annotations::open(path.clone()).unwrap();
        annotations.set(Field::Comment, 0x10, Some("earlier step".to_owned())).unwrap();
        let changes = [(Field::Name, 0x10, Some("first".to_owned())), (Field::Name, 0x20, Some("second".to_owned()))];
        annotations
            .locked(|outer| {
                assert!(outer.held);
                let changed = outer.locked_staged(|staged| {
                    assert!(staged.held);
                    staged.set_batch_validated(&changes, |_| Ok(())).map_err(ApiError::Invalid)
                })?;
                assert_eq!(changed, [true, true]);
                assert!(outer.held);
                assert_eq!(outer.name(0x10), Some("first"));
                assert_eq!(outer.done.len(), 2);
                let before = std::fs::read(&path).unwrap();
                let failed: Result<(), ApiError> = outer.locked_staged(|staged| {
                    assert!(staged.held);
                    Err(ApiError::Invalid("source changed".to_owned()))
                });
                assert!(failed.is_err());
                assert!(outer.held);
                assert_eq!(std::fs::read(&path).unwrap(), before);
                Ok(())
            })
            .unwrap();
        assert!(!annotations.held);
        assert_eq!(annotations.undo().unwrap().len(), 2);
        assert!(annotations.names().is_empty());
        assert_eq!(annotations.undo().unwrap()[0].value.as_deref(), Some("earlier step"));
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
    fn discarding_a_blocked_undo_step_unblocks_the_earlier_ones() {
        let path = temporary_log("discard");
        let mut ui = Annotations::open(path.clone()).unwrap();
        let mut agent = Annotations::open(path.clone()).unwrap();
        ui.set(Field::Comment, 0x20, Some("kept".into())).unwrap();
        ui.set(Field::Name, 0x10, Some("a".into())).unwrap();
        agent.set(Field::Name, 0x10, Some("b".into())).unwrap();
        let error = ui.undo().unwrap_err();
        assert!(error.contains("discard_undo"), "{error}");
        assert!(ui.undo().is_err());
        let log = std::fs::read_to_string(&path).unwrap();

        let discarded = ui.discard_undo_step(false).unwrap();
        assert_eq!(discarded.len(), 1);
        assert_eq!((discarded[0].address, discarded[0].value.as_deref()), (0x10, Some("a")));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), log);
        assert_eq!(ui.name(0x10), Some("b"));
        assert_eq!(ui.undo().unwrap()[0].address, 0x20);
        assert_eq!(ui.comment(0x20), None);
        assert!(ui.discard_undo_step(false).unwrap().is_empty());
        cleanup(path);
    }

    #[test]
    fn discarding_refuses_a_step_undo_could_still_revert_unless_forced() {
        let path = temporary_log("discard-unblocked");
        let mut user = Annotations::open(path.clone()).unwrap();
        let mut agent = Annotations::open(path.clone()).unwrap();
        user.set(Field::Name, 0x10, Some("parse".into())).unwrap();
        // Another client's edit elsewhere does not block it.
        agent.set(Field::Name, 0x20, Some("other".into())).unwrap();
        let error = user.discard_undo_step(false).unwrap_err();
        assert!(error.contains("force"), "{error}");
        assert_eq!(user.undo().unwrap()[0].address, 0x10, "the step is still there to undo");
        user.redo().unwrap();
        let dropped = user.discard_undo_step(true).unwrap();
        assert_eq!((dropped[0].address, user.name(0x10)), (0x10, Some("parse")));
        assert!(user.undo().unwrap().is_empty());
        // A name another client has since taken blocks it as much as an edit to the same address.
        user.set(Field::Name, 0x30, Some("first".into())).unwrap();
        user.set(Field::Name, 0x30, Some("second".into())).unwrap();
        agent.set(Field::Name, 0x40, Some("first".into())).unwrap();
        assert_eq!(user.discard_undo_step(false).unwrap()[0].value.as_deref(), Some("second"));
        cleanup(path);
    }

    #[test]
    fn only_a_refusal_over_another_clients_edit_suggests_discarding() {
        let mut annotations = Annotations::in_memory();
        annotations.set(Field::Signature, 0x10, Some("int4 f(void);".into())).unwrap();
        let error = annotations.undo_validated(|_| Err("the decompiler rejects it".to_owned())).unwrap_err();
        assert_eq!(error, "the decompiler rejects it");
        assert!(annotations.discard_undo_step(false).is_err(), "a validation failure is no other client's block");

        let path = temporary_log("undo-io");
        let mut writer = Annotations::open(path.clone()).unwrap();
        writer.set(Field::Comment, 0x10, Some("note".into())).unwrap();
        let writable = std::fs::metadata(&path).unwrap().permissions();
        let mut read_only = writable.clone();
        read_only.set_readonly(true);
        std::fs::set_permissions(&path, read_only).unwrap();
        let error = writer.undo().unwrap_err();
        assert!(!error.contains("discard_undo"), "{error}");
        std::fs::set_permissions(&path, writable).unwrap();

        let mut agent = Annotations::open(path.clone()).unwrap();
        agent.set(Field::Comment, 0x10, Some("changed".into())).unwrap();
        assert!(writer.undo().unwrap_err().contains("discard_undo"));
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

    fn name_edit(address: u64, value: &str) -> Edit {
        Edit { field: Field::Name, address, value: Some(value.into()), previous: None }
    }

    fn append(path: &PathBuf, text: &str) {
        OpenOptions::new().create(true).append(true).open(path).unwrap().write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn a_batch_is_logged_under_a_header_and_replays_whole() {
        let path = temporary_log("batch-header");
        let mut annotations = Annotations::open(path.clone()).unwrap();
        let changes = vec![(Field::Name, 0x10, Some("a".to_owned())), (Field::Name, 0x20, Some("b".to_owned()))];
        annotations.set_batch_validated(&changes, |_| Ok(())).unwrap();
        let log = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        let header: BatchHeader = serde_json::from_str(lines[0]).unwrap();
        assert_eq!((header.edits, lines.len()), (2, 3));
        assert!(lines[1..].iter().all(|line| line.contains(&format!("\"batch\":\"{}\"", header.batch))));
        let replayed = Annotations::open(path.clone()).unwrap();
        assert_eq!((replayed.name(0x10), replayed.name(0x20)), (Some("a"), Some("b")));
        cleanup(path);
    }

    #[test]
    fn a_batch_cut_short_is_never_applied() {
        let path = temporary_log("batch-truncated");
        let header = serde_json::to_string(&BatchHeader { batch: "cut".into(), edits: 3 }).unwrap();
        let member = |address, value| {
            serde_json::to_string(&BatchMember { edit: &name_edit(address, value), batch: "cut" }).unwrap()
        };
        append(&path, &format!("{header}\n{}\n{}\n", member(0x10, "a"), member(0x20, "b")));
        let mut reader = Annotations::open(path.clone()).unwrap();
        assert!(reader.names().is_empty());

        // The interrupted write is followed by another client's edits, which are not taken for the rest of it.
        let mut writer = Annotations::open(path.clone()).unwrap();
        writer.set(Field::Name, 0x30, Some("c".into())).unwrap();
        writer
            .set_batch_validated(
                &[(Field::Name, 0x40, Some("d".into())), (Field::Name, 0x50, Some("e".into()))],
                |_| Ok(()),
            )
            .unwrap();
        reader.refresh().unwrap();
        let replayed = Annotations::open(path.clone()).unwrap();
        for annotations in [&reader, &replayed] {
            assert_eq!(annotations.names().keys().copied().collect::<Vec<_>>(), [0x30, 0x40, 0x50]);
        }
        cleanup(path);
    }

    #[test]
    fn a_batch_read_while_being_written_is_applied_once_complete() {
        let path = temporary_log("batch-in-progress");
        let header = serde_json::to_string(&BatchHeader { batch: "late".into(), edits: 2 }).unwrap();
        let member = |address, value| {
            serde_json::to_string(&BatchMember { edit: &name_edit(address, value), batch: "late" }).unwrap()
        };
        append(&path, &format!("{header}\n{}\n", member(0x10, "a")));
        let mut reader = Annotations::open(path.clone()).unwrap();
        assert!(reader.names().is_empty());
        append(&path, &format!("{}\n", member(0x20, "b")));
        assert!(reader.refresh().unwrap());
        assert_eq!((reader.name(0x10), reader.name(0x20)), (Some("a"), Some("b")));
        cleanup(path);
    }

    fn open_on(path: &std::path::Path, image: u8) -> Annotations {
        Annotations::open_for_image(path.to_path_buf(), Some([image; 32])).unwrap()
    }

    #[test]
    fn edits_are_logged_after_the_identity_of_the_image_they_were_made_on() {
        let path = temporary_log("image-identity");
        let mut first = open_on(&path, 0xaa);
        first.set(Field::Name, 0x10, Some("a".into())).unwrap();
        first
            .set_batch_validated(&[(Field::Name, 0x20, Some("b".into())), (Field::Comment, 0x20, None)], |_| Ok(()))
            .unwrap();
        let mut same = open_on(&path, 0xaa);
        same.set(Field::Name, 0x30, Some("c".into())).unwrap();
        let log = std::fs::read_to_string(&path).unwrap();
        assert_eq!(log.matches("\"image\"").count(), 1, "{log}");
        assert!(log.starts_with(&format!("{{\"image\":\"{}\"}}\n", "aa".repeat(32))), "{log}");
        assert!(open_on(&path, 0xaa).warnings().is_empty());
        // A reader that predates identity lines still replays every edit.
        let old: Vec<Edit> = log.lines().filter_map(|line| serde_json::from_str(line).ok()).collect();
        assert_eq!(old.len(), 3);

        let rebuilt = open_on(&path, 0xbb);
        assert_eq!(rebuilt.name(0x30), Some("c"), "annotations still apply by address");
        let warnings = rebuilt.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains(&format!("different image (sha256 {})", "aa".repeat(32))), "{warnings:?}");
        assert!(Annotations::open(path.clone()).unwrap().warnings().is_empty(), "no image to compare");
        cleanup(path);
    }

    #[test]
    fn edits_made_on_another_image_are_reported_to_every_image_but_that_one() {
        let path = temporary_log("image-mixed");
        open_on(&path, 0xaa).set(Field::Name, 0x10, Some("a".into())).unwrap();
        open_on(&path, 0xbb).set(Field::Name, 0x20, Some("b".into())).unwrap();
        let mut a = open_on(&path, 0xaa);
        assert!(a.warnings()[0].contains(&"bb".repeat(32)), "{:?}", a.warnings());
        // Switching back to the first image logs its identity again, for the edits after it.
        a.set(Field::Name, 0x30, Some("c".into())).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().matches("\"image\"").count(), 3);
        assert!(open_on(&path, 0xbb).warnings()[0].contains(&"aa".repeat(32)));
        cleanup(path);
    }

    #[test]
    fn a_log_without_identity_lines_is_unverified_until_an_image_is_recorded() {
        let path = temporary_log("image-legacy");
        append(&path, &(serde_json::to_string(&name_edit(0x10, "a")).unwrap() + "\n"));
        let mut legacy = open_on(&path, 0xaa);
        assert_eq!(legacy.name(0x10), Some("a"));
        let warnings = legacy.warnings();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("unverified"), "{warnings:?}");
        // The first identity line stands for the edits before it: the note is given once, not on every open.
        legacy.set(Field::Comment, 0x10, Some("checked".into())).unwrap();
        assert!(legacy.warnings().is_empty(), "{:?}", legacy.warnings());
        assert!(open_on(&path, 0xaa).warnings().is_empty());
        assert!(open_on(&path, 0xbb).warnings()[0].contains("different image"));
        cleanup(path);
    }

    #[test]
    fn logs_written_before_batch_headers_replay_unchanged() {
        let path = temporary_log("old-format");
        let lines: Vec<String> = [name_edit(0x10, "a"), name_edit(0x20, "b")]
            .iter()
            .map(|edit| serde_json::to_string(edit).unwrap() + "\n")
            .collect();
        append(&path, &lines.concat());
        let replayed = Annotations::open(path.clone()).unwrap();
        assert_eq!((replayed.name(0x10), replayed.name(0x20)), (Some("a"), Some("b")));
        // What a reader that predates batches makes of one: the header is no edit, the edits are.
        let mut annotations = Annotations::open(path.clone()).unwrap();
        annotations
            .set_batch_validated(
                &[(Field::Name, 0x30, Some("c".into())), (Field::Name, 0x40, Some("d".into()))],
                |_| Ok(()),
            )
            .unwrap();
        let log = std::fs::read_to_string(&path).unwrap();
        let old: Vec<Edit> = log.lines().filter_map(|line| serde_json::from_str(line).ok()).collect();
        assert_eq!(old.iter().map(|edit| edit.address).collect::<Vec<_>>(), [0x10, 0x20, 0x30, 0x40]);
        cleanup(path);
    }

    #[test]
    fn a_conflicting_batch_undo_lists_every_changed_address_up_to_a_bound() {
        let path = temporary_log("batch-conflicts");
        let mut agent = Annotations::open(path.clone()).unwrap();
        let mut ui = Annotations::open(path.clone()).unwrap();
        let changes: Vec<_> = (0..25).map(|index| (Field::Comment, 0x10 * index, Some("a".to_owned()))).collect();
        agent.set_batch_validated(&changes, |_| Ok(())).unwrap();
        ui.set(Field::Comment, 0x20, Some("b".into())).unwrap();
        ui.set(Field::Comment, 0x30, Some("b".into())).unwrap();
        let error = agent.undo().unwrap_err();
        assert!(error.starts_with("0x20, 0x30 were edited by another client"), "{error}");
        let changes: Vec<_> = (0..25).map(|index| (Field::Comment, 0x10 * index, Some("c".to_owned()))).collect();
        ui.set_batch_validated(&changes, |_| Ok(())).unwrap();
        let error = agent.undo().unwrap_err();
        assert!(error.contains(", 0x130, 5 more were edited"), "{error}");
        assert!(!error.contains("0x140"), "{error}");
        cleanup(path);
    }

    #[test]
    fn undo_and_redo_refuse_to_duplicate_a_name_another_client_took() {
        let path = temporary_log("undo-name-taken");
        let mut agent = Annotations::open(path.clone()).unwrap();
        let mut ui = Annotations::open(path.clone()).unwrap();
        agent.set(Field::Name, 0x10, Some("foo".into())).unwrap();
        agent.set(Field::Name, 0x10, Some("bar".into())).unwrap();
        ui.set(Field::Name, 0x30, Some("foo".into())).unwrap();
        let error = agent.undo().unwrap_err();
        assert!(error.contains("\"foo\""), "{error}");
        assert_eq!(agent.name(0x10), Some("bar"));
        assert_eq!(agent.address_of("foo"), Some(0x30));

        agent.set(Field::Name, 0x40, Some("baz".into())).unwrap();
        agent.undo().unwrap();
        ui.set(Field::Name, 0x50, Some("baz".into())).unwrap();
        let error = agent.redo().unwrap_err();
        assert!(error.contains("\"baz\""), "{error}");
        assert_eq!(agent.name(0x40), None);
        cleanup(path);
    }
}
