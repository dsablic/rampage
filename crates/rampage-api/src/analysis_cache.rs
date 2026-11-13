//! Persistent analysis store: discovered functions, blocks, switches and cross-references kept in a per-user SQLite
//! file, so re-opening an already-analysed binary skips discovery. See `docs/analysis-cache.md`.
//!
//! An entry is found by a key that hashes every input discovery reads (the whole source file, the image's place in
//! it, the loaded format and architecture, a Raw Project's interpretation and decoder binding), the store schema,
//! [`ANALYSIS_VERSION`] and the identity of the running executable. The file is untrusted: an entry is used only when
//! its payload's SHA-256 matches, its embedded key matches, and it decodes completely under the codec's bounds and
//! ordering checks; anything else is a rejection that falls back to a fresh analysis. Annotations are never stored
//! here: they stay in their own log and apply over cached and fresh analyses alike.

mod codec;

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rampage_analysis::discover::Program;
use rampage_loaders::{Binary, Format};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Bump whenever discovery, the loaders it reads, or anything else changes a [`Program`] for the same input
/// bytes. `analysis_cache_golden` (tests/integration) records each fixture's analysis digest under this
/// version and fails when the output changes but the version did not.
pub const ANALYSIS_VERSION: u32 = 1;
/// The store's table layout and payload encoding; part of the file name, so other layouts never share a file.
const SCHEMA: &str = "rampage-analysis-store-v1";
/// The default bound on stored payload bytes; the least recently used entries are evicted beyond it.
pub const DEFAULT_MAX_BYTES: u64 = 1024 * 1024 * 1024;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The environment variable that configures the store: unset uses the default (on in release builds, off in debug
/// builds), `off`/`0`/`false` disables it, `on`/`1` selects the default file, and anything else is the file path.
pub const ANALYSIS_CACHE_VARIABLE: &str = "RAMPAGE_ANALYSIS_CACHE";
/// The store's size bound in MiB (default 1024).
pub const ANALYSIS_CACHE_MAX_VARIABLE: &str = "RAMPAGE_ANALYSIS_CACHE_MAX_MB";

/// A persistent analysis store file and its size bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisStore {
    path: PathBuf,
    max_bytes: u64,
}

/// What the persistent store did for a project, as `binary_info` reports it under `analysis_store`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalysisStoreStatus {
    /// `disabled` (no store configured), `unsupported` (captures and byte-patched views are never stored),
    /// `pending` (analysis has not run in this process), `hit` (loaded from the store, discovery skipped), `miss`
    /// (analysed fresh; `detail` says whether it was stored) or `rejected` (an entry existed but failed validation,
    /// so the binary was analysed fresh).
    pub state: &'static str,
    /// The entry key: SHA-256 over every analysis input. Present once analysis ran with a store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AnalysisStoreStatus {
    pub(crate) fn new(state: &'static str, key: Option<String>, detail: Option<String>) -> Self {
        Self { state, key, detail }
    }
}

/// A stored payload and its SHA-256.
type Row = (Vec<u8>, Vec<u8>);

pub(crate) enum Lookup {
    Hit(Program),
    Absent,
    /// The entry or the file failed validation, or the store could not be read.
    Rejected(String),
}

impl AnalysisStore {
    /// A store in the SQLite file at `path` (created on first write), holding at most `max_bytes` of payloads.
    pub fn at(path: impl Into<PathBuf>, max_bytes: u64) -> Self {
        Self { path: path.into(), max_bytes }
    }

    /// The store [`ANALYSIS_CACHE_VARIABLE`] selects, read once per process.
    pub fn from_env() -> Option<Arc<Self>> {
        static STORE: OnceLock<Option<Arc<AnalysisStore>>> = OnceLock::new();
        STORE
            .get_or_init(|| {
                let max_bytes = std::env::var(ANALYSIS_CACHE_MAX_VARIABLE)
                    .ok()
                    .and_then(|value| value.trim().parse::<u64>().ok())
                    .map_or(DEFAULT_MAX_BYTES, |megabytes| megabytes.saturating_mul(1024 * 1024));
                let path = match std::env::var_os(ANALYSIS_CACHE_VARIABLE) {
                    None if cfg!(debug_assertions) => None,
                    None => default_path(),
                    Some(value) => match value.to_str().map(str::trim) {
                        Some("" | "0" | "off" | "false" | "no") => None,
                        Some("1" | "on" | "true" | "yes") => default_path(),
                        _ => Some(PathBuf::from(value)),
                    },
                };
                path.map(|path| Arc::new(Self::at(path, max_bytes)))
            })
            .clone()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    fn connect(&self, create: bool) -> rusqlite::Result<Connection> {
        let mut flags =
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        if create {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let connection = Connection::open_with_flags(&self.path, flags)?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        Ok(connection)
    }

    /// The entry for `key`, verified. Never writes beyond refreshing the entry's use time.
    pub(crate) fn load(&self, key: &str) -> Lookup {
        match std::fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Lookup::Absent,
            Err(error) => return Lookup::Rejected(format!("store unreadable: {error}")),
            Ok(metadata) if !metadata.is_file() => return Lookup::Rejected("store is not a regular file".into()),
            Ok(_) => {}
        }
        let read = || -> rusqlite::Result<Result<Option<Row>, String>> {
            let connection = self.connect(false)?;
            match check_schema(&connection)? {
                Ok(()) => {}
                // A store another process is creating right now has no entries yet.
                Err(Schema::Missing) => return Ok(Ok(None)),
                Err(Schema::Foreign) => return Ok(Err("store has another schema".into())),
            }
            // One statement reads one consistent snapshot, so a concurrent writer is seen entirely or not at all.
            let row = connection
                .query_row("SELECT payload, sha256 FROM analysis WHERE key = ?1", [key], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .optional()?;
            if row.is_some() {
                // Best effort: a busy store only leaves the use time stale.
                let _ = connection.execute(
                    "UPDATE analysis SET last_used = ?2 WHERE key = ?1 AND last_used < ?3",
                    params![key, now(), now() - 60_000_000_000],
                );
            }
            Ok(Ok(row))
        };
        let (payload, digest) = match read() {
            Ok(Ok(Some(row))) => row,
            Ok(Ok(None)) => return Lookup::Absent,
            Ok(Err(reason)) => return Lookup::Rejected(reason),
            Err(error) => return Lookup::Rejected(format!("store unreadable: {error}")),
        };
        if payload.len() as u64 > self.max_bytes {
            return Lookup::Rejected("entry exceeds the store's size bound".into());
        }
        if Sha256::digest(&payload).as_slice() != digest.as_slice() {
            return Lookup::Rejected("entry checksum mismatch".into());
        }
        match codec::decode(key, &payload) {
            Ok(program) => Lookup::Hit(program),
            Err(codec::Malformed(reason)) => Lookup::Rejected(format!("entry malformed: {reason}")),
        }
    }

    /// Stores `program` under `key`, then evicts least recently used entries beyond the size bound.
    pub(crate) fn store(&self, key: &str, program: &Program) -> Result<(), String> {
        if !codec::encodable(program) {
            return Err("analysis has decode gates the store cannot represent".into());
        }
        let payload = codec::encode(key, program);
        if payload.len() as u64 > self.max_bytes / 2 {
            return Err(format!("entry of {} bytes exceeds half the store's size bound", payload.len()));
        }
        let digest = Sha256::digest(&payload).to_vec();
        if let Some(parent) = self.path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            create_private_dir(parent).map_err(|error| format!("store directory: {error}"))?;
        }
        let write = || -> rusqlite::Result<Result<(), String>> {
            let mut connection = self.connect(true)?;
            // Set before the first table exists (later a no-op), so evicted pages can be returned to the file system.
            connection.execute_batch("PRAGMA auto_vacuum = INCREMENTAL")?;
            // WAL lets readers proceed during a write; each process sees whole transactions only.
            let _: String = connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
            let transaction = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS analysis (
                     key TEXT PRIMARY KEY,
                     payload BLOB NOT NULL,
                     sha256 BLOB NOT NULL,
                     bytes INTEGER NOT NULL,
                     last_used INTEGER NOT NULL
                 );",
            )?;
            transaction.execute("INSERT OR IGNORE INTO meta (name, value) VALUES ('schema', ?1)", [SCHEMA])?;
            if check_schema(&transaction)?.is_err() {
                return Ok(Err("store has another schema; not written".into()));
            }
            transaction.execute(
                "INSERT OR REPLACE INTO analysis (key, payload, sha256, bytes, last_used) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![key, payload, digest, payload.len() as i64, now()],
            )?;
            let mut evict = Vec::new();
            {
                let mut statement = transaction
                    .prepare("SELECT key, bytes FROM analysis ORDER BY key = ?1 DESC, last_used DESC, key")?;
                let mut rows = statement.query([key])?;
                let mut total = 0u64;
                while let Some(row) = rows.next()? {
                    total = total.saturating_add(row.get::<_, i64>(1)?.max(0) as u64);
                    if total > self.max_bytes {
                        evict.push(row.get::<_, String>(0)?);
                    }
                }
            }
            for old in &evict {
                transaction.execute("DELETE FROM analysis WHERE key = ?1", [old])?;
            }
            transaction.commit()?;
            if !evict.is_empty() {
                // Best effort: a reader holding the WAL only delays reclaiming space until a later write.
                let _ = connection.execute_batch("PRAGMA incremental_vacuum");
            }
            Ok(Ok(()))
        };
        match write() {
            Ok(result) => result,
            Err(error) => Err(format!("store not written: {error}")),
        }
    }
}

enum Schema {
    /// No schema yet: the file is new or still being created.
    Missing,
    /// Another layout; such a file is never read or written.
    Foreign,
}

fn check_schema(connection: &Connection) -> rusqlite::Result<Result<(), Schema>> {
    let schema: Option<String> =
        match connection.query_row("SELECT value FROM meta WHERE name = 'schema'", [], |row| row.get(0)).optional() {
            Ok(schema) => schema,
            Err(rusqlite::Error::SqliteFailure(_, Some(message))) if message.starts_with("no such table") => None,
            Err(error) => return Err(error),
        };
    Ok(match schema.as_deref() {
        Some(SCHEMA) => Ok(()),
        Some(_) => Err(Schema::Foreign),
        None => Err(Schema::Missing),
    })
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| i64::try_from(elapsed.as_nanos()).unwrap_or(i64::MAX))
}

/// `$XDG_CACHE_HOME/rampage`, else `$HOME/.cache/rampage` (where the bundled Sleigh specifications are also
/// materialized), else `%LOCALAPPDATA%\rampage`.
fn default_path() -> Option<PathBuf> {
    let xdg = std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from).filter(|path| path.is_absolute());
    let root = xdg
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(PathBuf::from))?;
    Some(root.join("rampage").join(format!("{SCHEMA}.sqlite")))
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// The store key for analysing `binary` under the Raw decoder `binding` (see `decoder::analysis_binding`), or
/// `None` when the binary is never stored: a runtime capture, whose bytes are not a file's.
pub(crate) fn key(binary: &Binary, binding: Option<&str>) -> Option<String> {
    if binary.format == Format::Snapshot {
        return None;
    }
    let file = binary.file_bytes();
    let image = binary.image_bytes();
    let offset = (image.as_ptr() as usize).checked_sub(file.as_ptr() as usize)?;
    let mut hash = Sha256::new();
    hash.update(SCHEMA.as_bytes());
    hash.update([0]);
    hash.update(ANALYSIS_VERSION.to_le_bytes());
    hash.update(env!("CARGO_PKG_VERSION").as_bytes());
    hash.update([0]);
    hash.update(executable_stamp().as_bytes());
    hash.update([0]);
    hash.update(format!("{:?}\0{}\0", binary.format, binary.arch).as_bytes());
    hash.update((offset as u64).to_le_bytes());
    hash.update((image.len() as u64).to_le_bytes());
    hash.update((file.len() as u64).to_le_bytes());
    hash.update(Sha256::digest(file));
    hash.update(binding.unwrap_or("-").as_bytes());
    Some(rampage_arch::hex::bytes(&hash.finalize()))
}

/// The running executable's path, length and modification time, so a rebuilt binary never reads entries an
/// earlier build wrote, even one that forgot to bump [`ANALYSIS_VERSION`].
fn executable_stamp() -> &'static str {
    static STAMP: OnceLock<String> = OnceLock::new();
    STAMP.get_or_init(|| {
        let Ok(path) = std::env::current_exe() else { return "unknown".into() };
        let Ok(metadata) = std::fs::metadata(&path) else { return format!("{}", path.display()) };
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |elapsed| elapsed.as_nanos());
        format!("{}\0{}\0{modified}", path.display(), metadata.len())
    })
}

/// The digest `analysis_cache_golden` records per fixture: SHA-256 of the store encoding with an empty key.
#[doc(hidden)]
pub fn program_digest(project: &crate::Project) -> Result<String, crate::ApiError> {
    let analysis = project.analysis()?;
    Ok(rampage_arch::hex::bytes(&Sha256::digest(codec::encode("", &analysis.program))))
}
