//! `report_observation`: an opt-in, local, append-only store of typed observations an agent can back with evidence
//! ("a function starts here, confirmed by a debugger stop"). Observations are weak labels a corpus may pick up
//! later; recording one changes no analysis, annotation or pack, and nothing is ever promoted from it without the
//! gate.
//!
//! The store is a directory of its own (by default `target/flywheel/observations/`), not the binary's annotation
//! sidecar: the sidecar is the analyst's record, replayed by every client of the binary and bound by its reader's
//! limits, while observations are unreviewed labels for the corpus that one place must collect across binaries.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{FlywheelError, now_ms, sha256_file, sha256_text};
use crate::tools::Group;

/// The environment variable naming the observation directory, which opts an ordinary session in.
pub const OBSERVATIONS_VARIABLE: &str = "RAMPAGE_OBSERVATIONS";
const STORE_FILE: &str = "observations.jsonl";
/// The store stops accepting observations past this size.
const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EVIDENCE: usize = 8;
const MAX_DETAIL_CHARS: usize = 1024;
const MAX_NOTE_CHARS: usize = 2048;
const MAX_NAME_CHARS: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    /// A function starts at the address.
    FunctionStart,
    /// The function at the address has this name.
    FunctionName,
    /// The function at the address is this library's function of this name.
    LibraryFunction,
    /// The address is not a function start (a false discovery).
    NotAFunction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    DebuggerStop,
    BuildId,
    SymbolFile,
    StringReference,
    ToolResult,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub source: EvidenceSource,
    /// What was seen: the tool call and result, the build ID, the debugger stop.
    pub detail: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    path: String,
    kind: ObservationKind,
    address: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    library: Option<String>,
    evidence: Vec<Evidence>,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Serialize)]
struct Record<'a> {
    id: String,
    recorded_unix_ms: u64,
    binary: Value,
    kind: ObservationKind,
    address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    library: Option<&'a str>,
    evidence: &'a [Evidence],
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a str>,
    /// Always `weak_label`: unreviewed, never applied or promoted on its own.
    status: &'static str,
}

/// The opt-in observation store.
pub struct ObservationStore {
    directory: PathBuf,
    lock: Mutex<()>,
}

impl ObservationStore {
    pub fn new(directory: PathBuf) -> ObservationStore {
        ObservationStore { directory, lock: Mutex::new(()) }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn file(&self) -> PathBuf {
        self.directory.join(STORE_FILE)
    }

    /// Validates and appends one observation, returning its id.
    pub fn record(&self, input: Value) -> Result<Value, FlywheelError> {
        let input: Input = serde_json::from_value(input).map_err(|error| FlywheelError::Invalid(error.to_string()))?;
        let invalid = |message: String| Err(FlywheelError::Invalid(message));
        let address = input.address.trim();
        let digits = address.strip_prefix("0x").or_else(|| address.strip_prefix("0X")).unwrap_or(address);
        let Ok(address) = u64::from_str_radix(digits, 16) else {
            return invalid(format!("address {:?} must be a hex address such as \"0x401000\"", input.address));
        };
        let needs_name = matches!(input.kind, ObservationKind::FunctionName | ObservationKind::LibraryFunction);
        match &input.name {
            None if needs_name => return invalid("this kind of observation needs `name`".to_owned()),
            Some(name)
                if name.is_empty() || name.chars().count() > MAX_NAME_CHARS || name.chars().any(char::is_control) =>
            {
                return invalid(format!("name must be 1 to {MAX_NAME_CHARS} characters without control characters"));
            }
            _ => {}
        }
        if input.library.is_some() && input.kind != ObservationKind::LibraryFunction {
            return invalid("`library` belongs to library_function observations".to_owned());
        }
        if input.evidence.is_empty() || input.evidence.len() > MAX_EVIDENCE {
            return invalid(format!("give 1 to {MAX_EVIDENCE} evidence items: an observation must be backed"));
        }
        if input
            .evidence
            .iter()
            .any(|item| item.detail.trim().is_empty() || item.detail.chars().count() > MAX_DETAIL_CHARS)
        {
            return invalid(format!(
                "each evidence detail must say what was seen, in at most {MAX_DETAIL_CHARS} characters"
            ));
        }
        if input.note.as_ref().is_some_and(|note| note.chars().count() > MAX_NOTE_CHARS) {
            return invalid(format!("note is longer than {MAX_NOTE_CHARS} characters"));
        }
        let path = Path::new(&input.path);
        let metadata =
            std::fs::metadata(path).map_err(|error| FlywheelError::Invalid(format!("{}: {error}", path.display())))?;
        if !metadata.is_file() {
            return invalid(format!("{} is not a regular file", path.display()));
        }
        let binary = json!({ "path": input.path, "sha256": sha256_file(path)?, "size": metadata.len() });
        let address = format!("{address:#x}");
        let recorded_unix_ms = now_ms();
        let id = format!(
            "ob-{}",
            &sha256_text(&format!(
                "{}\0{address}\0{:?}\0{recorded_unix_ms}\0{}",
                binary["sha256"],
                input.kind,
                std::process::id()
            ))[..12]
        );
        let record = Record {
            id: id.clone(),
            recorded_unix_ms,
            binary,
            kind: input.kind,
            address: address.clone(),
            name: input.name.as_deref(),
            library: input.library.as_deref(),
            evidence: &input.evidence,
            note: input.note.as_deref(),
            status: "weak_label",
        };
        let mut line = serde_json::to_string(&record).map_err(FlywheelError::json)?;
        line.push('\n');
        let _guard = self.lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        std::fs::create_dir_all(&self.directory).map_err(|error| FlywheelError::io(&self.directory, error))?;
        let file = self.file();
        let size = std::fs::metadata(&file).map_or(0, |metadata| metadata.len());
        if size + line.len() as u64 > MAX_STORE_BYTES {
            return Err(FlywheelError::Refused(format!(
                "the observation store {} is full ({MAX_STORE_BYTES} bytes); nothing was recorded",
                file.display()
            )));
        }
        let mut handle = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file)
            .map_err(|error| FlywheelError::io(&file, error))?;
        handle.write_all(line.as_bytes()).map_err(|error| FlywheelError::io(&file, error))?;
        Ok(json!({
            "id": id,
            "recorded": true,
            "kind": input.kind,
            "address": address,
            "store": file,
            "status": "weak_label",
            "note": "Recorded as an unreviewed weak label for the corpus. Nothing was renamed, annotated or \
                     promoted; the flywheel gate decides whether anything built from it lands.",
        }))
    }
}

/// The `report_observation` tool: served in core whenever an observation store is configured.
pub struct ObservationTool {
    pub group: Group,
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
}

impl ObservationTool {
    pub fn call(&self, store: &ObservationStore, input: Value) -> Result<Value, String> {
        store.record(input).map_err(|error| error.to_json())
    }
}

pub fn observation_tool() -> ObservationTool {
    ObservationTool {
        group: Group::Core,
        name: "report_observation",
        description: "Record one evidence-backed observation about a binary in the operator's local observation \
            store, as a weak label for the flywheel corpus: a function start (`function_start`), a function's name \
            (`function_name`), a library function (`library_function`, with `name` and optionally `library`), or \
            an address that is not a function (`not_a_function`). `evidence` (1-8 items) says what confirms it: \
            a debugger stop, a build ID, a symbol file, a string reference, a tool result. Nothing is renamed, \
            annotated or promoted; observations only become candidates through the flywheel's held-out gate. \
            Returns the observation id.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "The binary the observation is about." },
                "kind": {
                    "type": "string",
                    "enum": ["function_start", "function_name", "library_function", "not_a_function"]
                },
                "address": { "type": "string", "description": "Hex address, such as \"0x401000\"." },
                "name": { "type": "string", "description": "The function's name (function_name, library_function)." },
                "library": { "type": "string", "description": "The library (library_function only)." },
                "evidence": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 8,
                    "items": {
                        "type": "object",
                        "properties": {
                            "source": {
                                "type": "string",
                                "enum": ["debugger_stop", "build_id", "symbol_file", "string_reference", "tool_result", "other"]
                            },
                            "detail": { "type": "string", "description": "What was seen, at most 1024 characters." }
                        },
                        "required": ["source", "detail"],
                        "additionalProperties": false
                    }
                },
                "note": { "type": "string" }
            },
            "required": ["path", "kind", "address", "evidence"],
            "additionalProperties": false
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observations_are_validated_appended_and_never_applied() {
        let directory = std::env::temp_dir().join(format!("rampage-observations-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let store = ObservationStore::new(directory.clone());
        let binary = std::env::current_exe().unwrap();
        let evidence = json!([{ "source": "debugger_stop", "detail": "stopped at 0x401000 after break main" }]);
        let ok = store
            .record(json!({ "path": binary, "kind": "function_start", "address": "0x401000", "evidence": evidence }))
            .unwrap();
        assert_eq!(ok["status"], "weak_label");
        let text = std::fs::read_to_string(store.file()).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("\"sha256\""));

        let refused = [
            json!({ "path": binary, "kind": "function_name", "address": "0x401000", "evidence": evidence }),
            json!({ "path": binary, "kind": "function_start", "address": "0x401000", "evidence": [] }),
            json!({ "path": binary, "kind": "function_start", "address": "main", "evidence": evidence }),
            json!({ "path": binary, "kind": "function_start", "address": "0x1", "evidence": evidence, "extra": 1 }),
            json!({ "path": binary, "kind": "function_start", "address": "0x1", "library": "zlib", "evidence": evidence }),
        ];
        for input in refused {
            let error = store.record(input.clone()).unwrap_err();
            assert_eq!(error.kind(), "invalid_argument", "{input}");
        }
        assert_eq!(std::fs::read_to_string(store.file()).unwrap().lines().count(), 1, "refusals record nothing");
        let _ = std::fs::remove_dir_all(&directory);
    }
}
