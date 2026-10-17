//! Versioned, evaluator-only parity task manifests and deterministic answer checks.
//!
//! These checks are not an agent runner or evidence of AI task success. Fixture digests must be
//! independently computed before a run; manifest parsing only validates their spelling. Only
//! `agent_prompt` belongs in a model request, never the manifest, source references, or answer contract.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParityTask {
    pub version: u32,
    pub id: String,
    pub kind: TaskKind,
    pub question: String,
    pub fixture: FixtureIdentity,
    pub truth_reference: String,
    pub required_capabilities: Vec<String>,
    /// Implementation inventory, not a measured task outcome.
    pub capability_status: CapabilityStatus,
    pub capability_evidence: String,
    pub answer: AnswerContract,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    Analysis,
    /// An inventory probe, excluded from analysis-task success counts.
    Capability,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureIdentity {
    pub id: String,
    /// All manifest paths are repository-relative, not manifest-directory-relative.
    pub path: PathBuf,
    pub sha256: String,
    pub source: PathBuf,
    pub build: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Supported,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AnswerContract {
    /// Exactly these JSON fields and values; no substring matching or extra claims.
    Exact { fields: BTreeMap<String, Value> },
    /// Exactly one JSON array field, with unique strings; ordering is immaterial.
    StringSet { field: String, values: Vec<String> },
}

/// Runner-supplied disposition. Runtime/tool errors are failures, not unsupported capabilities.
#[derive(Debug, Clone, PartialEq)]
pub enum TaskAttempt {
    Unmeasured,
    Unknown { reason: String },
    Unsupported { reason: String },
    Failed { reason: String },
    Answer(Value),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskOutcome {
    AnswerMatches,
    AnswerMismatch,
    Failed,
    Unknown,
    Unmeasured,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaskCheck {
    pub task_id: String,
    pub kind: TaskKind,
    pub outcome: TaskOutcome,
    pub reason: String,
}

#[derive(Debug)]
pub struct ManifestError {
    pub path: PathBuf,
    pub message: String,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path.display(), self.message)
    }
}

impl std::error::Error for ManifestError {}

impl ParityTask {
    pub fn from_toml(text: &str) -> Result<Self, String> {
        let task: Self = toml::from_str(text).map_err(|error| error.to_string())?;
        task.validate()?;
        Ok(task)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!("unsupported manifest version {}", self.version));
        }
        for (label, id) in [("task", &self.id), ("fixture", &self.fixture.id)] {
            if !valid_id(id) {
                return Err(format!("invalid {label} id {id:?}; use lowercase ASCII letters, digits and hyphens"));
            }
        }
        for (label, value) in [
            ("question", &self.question),
            ("truth_reference", &self.truth_reference),
            ("capability_evidence", &self.capability_evidence),
        ] {
            if value.trim().is_empty() {
                return Err(format!("{label} must not be empty"));
            }
        }
        for path in [&self.fixture.path, &self.fixture.source, &self.fixture.build] {
            if path.as_os_str().is_empty() || path.components().any(|part| !matches!(part, Component::Normal(_))) {
                return Err(format!("fixture path must be repository-relative without traversal: {}", path.display()));
            }
        }
        if self.fixture.sha256.len() != 64
            || !self.fixture.sha256.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("fixture sha256 must contain 64 lowercase hexadecimal digits".to_owned());
        }
        if self.required_capabilities.is_empty()
            || self.required_capabilities.iter().any(|name| name.trim().is_empty())
            || self.required_capabilities.iter().collect::<BTreeSet<_>>().len() != self.required_capabilities.len()
        {
            return Err("required_capabilities must be nonempty, unique, nonblank names".to_owned());
        }
        match &self.answer {
            AnswerContract::Exact { fields } => {
                if fields.is_empty() || fields.keys().any(|field| field.trim().is_empty()) {
                    return Err("exact contract requires nonblank fields".to_owned());
                }
            }
            AnswerContract::StringSet { field, values } => {
                if field.trim().is_empty()
                    || values.is_empty()
                    || values.iter().any(|value| value.trim().is_empty())
                    || values.iter().collect::<BTreeSet<_>>().len() != values.len()
                {
                    return Err("string_set contract requires a field and nonempty unique nonblank values".to_owned());
                }
            }
        }
        Ok(())
    }

    /// Give the runner's actual opened path, possibly an isolated copy. No truth or source names are included.
    pub fn agent_prompt(&self, opened_path: &Path) -> String {
        let path = serde_json::to_string(&opened_path.to_string_lossy()).expect("path string is serializable");
        format!(
            "Analyze the binary at {path} using only the connected MCP server.\n\n{}\n\n\
             Return a JSON object answering the question. If evidence is insufficient, report unknown; \
             if the required capability is unavailable, report unsupported. Keep evidence in the tool transcript.",
            self.question
        )
    }

    /// Compare an independently computed digest, not a model-supplied claim.
    pub fn matches_fixture_digest(&self, actual_sha256: &str) -> bool {
        self.fixture.sha256 == actual_sha256
    }

    /// Contract checking only. Matching text proves neither MCP execution nor a successful agent investigation.
    pub fn check(&self, attempt: &TaskAttempt) -> TaskCheck {
        let (outcome, reason) = match attempt {
            TaskAttempt::Unmeasured => (TaskOutcome::Unmeasured, "no task run recorded".to_owned()),
            TaskAttempt::Unknown { reason } => (TaskOutcome::Unknown, reason.clone()),
            TaskAttempt::Unsupported { reason } => (TaskOutcome::Unsupported, reason.clone()),
            TaskAttempt::Failed { reason } => (TaskOutcome::Failed, reason.clone()),
            TaskAttempt::Answer(answer) => {
                if self.answer.matches(answer) {
                    (TaskOutcome::AnswerMatches, "answer matches the declared contract only".to_owned())
                } else {
                    (TaskOutcome::AnswerMismatch, "answer does not match the declared contract".to_owned())
                }
            }
        };
        TaskCheck { task_id: self.id.clone(), kind: self.kind, outcome, reason }
    }
}

impl AnswerContract {
    pub fn matches(&self, answer: &Value) -> bool {
        let Some(object) = answer.as_object() else { return false };
        match self {
            Self::Exact { fields } => {
                object.len() == fields.len() && fields.iter().all(|(field, value)| object.get(field) == Some(value))
            }
            Self::StringSet { field, values } => {
                if object.len() != 1 {
                    return false;
                }
                let Some(items) = object.get(field).and_then(Value::as_array) else { return false };
                let Some(items) = items.iter().map(Value::as_str).collect::<Option<Vec<_>>>() else { return false };
                let actual: BTreeSet<_> = items.iter().copied().collect();
                actual.len() == items.len() && actual == values.iter().map(String::as_str).collect()
            }
        }
    }
}

/// Parse separately named documents atomically; duplicate IDs and inconsistent fixture references are errors.
pub fn parse_task_documents<I, P, S>(documents: I) -> Result<Vec<ParityTask>, ManifestError>
where
    I: IntoIterator<Item = (P, S)>,
    P: Into<PathBuf>,
    S: AsRef<str>,
{
    let mut tasks = Vec::new();
    let mut ids = BTreeSet::new();
    let mut fixtures = BTreeMap::new();
    let mut paths = BTreeMap::new();
    for (path, text) in documents {
        let path = path.into();
        let error = |message| ManifestError { path: path.clone(), message };
        let task = ParityTask::from_toml(text.as_ref()).map_err(error)?;
        if !ids.insert(task.id.clone()) {
            return Err(error(format!("duplicate task id {:?}", task.id)));
        }
        let identity = (
            task.fixture.path.clone(),
            task.fixture.sha256.clone(),
            task.fixture.source.clone(),
            task.fixture.build.clone(),
        );
        if let Some(previous) = fixtures.insert(task.fixture.id.clone(), identity.clone())
            && previous != identity
        {
            return Err(error(format!("conflicting fixture identity {:?}", task.fixture.id)));
        }
        let reference = (task.fixture.id.clone(), task.fixture.sha256.clone());
        if let Some(previous) = paths.insert(task.fixture.path.clone(), reference.clone())
            && previous != reference
        {
            return Err(error(format!("conflicting fixture path {}", task.fixture.path.display())));
        }
        tasks.push(task);
    }
    if tasks.is_empty() {
        return Err(ManifestError { path: PathBuf::from("<tasks>"), message: "task suite is empty".to_owned() });
    }
    tasks.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(tasks)
}

/// Load immediate `.toml` children in deterministic order. This performs no analysis, execution or network I/O.
pub fn load_tasks(directory: &Path) -> Result<Vec<ParityTask>, ManifestError> {
    let error = |path: PathBuf, message: String| ManifestError { path, message };
    let entries = std::fs::read_dir(directory).map_err(|cause| error(directory.to_owned(), cause.to_string()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry.map_err(|cause| error(directory.to_owned(), cause.to_string()))?.path();
        if path.extension().is_some_and(|extension| extension == "toml") {
            paths.push(path);
        }
    }
    paths.sort();
    let documents = paths
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path).map_err(|cause| error(path.clone(), cause.to_string()))?;
            Ok((path, text))
        })
        .collect::<Result<Vec<_>, ManifestError>>()?;
    parse_task_documents(documents)
}

fn valid_id(id: &str) -> bool {
    id.bytes().next().is_some_and(|byte| byte.is_ascii_lowercase())
        && id.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
