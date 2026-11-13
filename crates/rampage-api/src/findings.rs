//! The investigation ledger: findings an agent established, unknowns it could not settle and questions it left
//! open, each with the tool calls that support it. Entries live in the annotation log (`Field::Finding`, keyed by
//! id), so they persist beside the binary, replay on reopen, undo and redo like comments, and are shared with every
//! other process using the same log under its lock.

use serde::{Deserialize, Serialize};

use crate::annotations::{Annotations, CHECKED_CACHE_BYTES, CHECKED_RECORDS, Edit, Field};
use crate::rows::Matcher;
use crate::{ApiError, Project};

/// Longest `text`, in bytes.
pub const MAX_LEDGER_TEXT: usize = 2000;
/// Longest `resolution`, in bytes.
pub const MAX_LEDGER_RESOLUTION: usize = 1000;
/// Most evidence references per entry.
pub const MAX_LEDGER_EVIDENCE: usize = 8;
const MAX_EVIDENCE_TOOL: usize = 64;
const MAX_EVIDENCE_DETAIL: usize = 300;
/// Most entries one ledger holds: an eighth of the rows a checked annotation cache holds.
pub const MAX_LEDGER_ENTRIES: usize = CHECKED_RECORDS / 8;
/// Most bytes of entry JSON one ledger holds: a quarter of the checked annotation cache.
pub const MAX_LEDGER_BYTES: usize = CHECKED_CACHE_BYTES / 4;
/// Most entries per `list_findings` page.
pub const MAX_LEDGER_PAGE: usize = 100;
const DEFAULT_LEDGER_PAGE: usize = 50;
/// A page stops adding entries once its JSON would pass this many bytes; one entry always fits.
const LEDGER_PAGE_BYTES: usize = 48_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LedgerKind {
    Finding,
    Unknown,
    Question,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LedgerStatus {
    Open,
    Resolved,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LedgerConfidence {
    Low,
    Medium,
    High,
}

/// A reference to a tool call that supports an entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LedgerEvidence {
    /// The tool called, such as `decompile` (at most 64 bytes of `[a-z0-9_]`).
    pub tool: String,
    /// What it showed, or the arguments that reproduce it (at most 300 bytes).
    pub detail: String,
}

/// Creates an entry (no `id`) or updates one (`id`): an update changes only the fields it gives.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LedgerRequest {
    /// The entry to update; omit to create one.
    pub id: Option<u64>,
    /// Required when creating.
    pub kind: Option<LedgerKind>,
    /// What was established or is unknown. Required when creating; at most 2000 bytes.
    pub text: Option<String>,
    /// The address or name it concerns.
    pub address: Option<String>,
    /// An address or name inside the function it concerns; stored as that function's start.
    pub function: Option<String>,
    /// Supporting tool calls; replaces the list when given (at most 8).
    pub evidence: Option<Vec<LedgerEvidence>>,
    pub confidence: Option<LedgerConfidence>,
    /// Defaults to open when creating.
    pub status: Option<LedgerStatus>,
    /// How it was settled (at most 1000 bytes); an empty string clears it.
    pub resolution: Option<String>,
}

/// Which entries `list_findings` returns, and the page.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LedgerQuery {
    pub kind: Option<LedgerKind>,
    pub status: Option<LedgerStatus>,
    /// Only entries at this address or name.
    pub address: Option<String>,
    /// Only entries in the function containing this address or name: by their function or their address.
    pub function: Option<String>,
    /// Case-insensitive substring of the text or resolution.
    pub contains: Option<String>,
    /// Matching entries to skip.
    pub offset: Option<usize>,
    /// Entries per page (default 50, at most 100).
    pub limit: Option<usize>,
}

/// An entry as logged: its value in the annotation log, under its id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFinding {
    kind: LedgerKind,
    status: LedgerStatus,
    text: String,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "optional_hex")]
    address: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "optional_hex")]
    function: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    evidence: Vec<LedgerEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confidence: Option<LedgerConfidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolution: Option<String>,
    /// The SHA-256 of the image the entry's address and function were recorded on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    image: Option<String>,
}

mod optional_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        rampage_arch::hex::optional_address(value, serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
        let Some(text) = Option::<String>::deserialize(deserializer)? else { return Ok(None) };
        let digits = text.strip_prefix("0x").ok_or_else(|| serde::de::Error::custom("address must start with 0x"))?;
        u64::from_str_radix(digits, 16).map(Some).map_err(serde::de::Error::custom)
    }
}

/// One ledger entry.
#[derive(Debug, Clone, Serialize)]
pub struct LedgerEntry {
    pub id: u64,
    pub kind: LedgerKind,
    pub status: LedgerStatus,
    pub text: String,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub address: Option<u64>,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub function: Option<u64>,
    /// The function's current name, when the entry names one.
    pub function_name: Option<String>,
    pub evidence: Vec<LedgerEvidence>,
    pub confidence: Option<LedgerConfidence>,
    pub resolution: Option<String>,
    /// The SHA-256 of the image its address and function were recorded on, when known.
    pub image_sha256: Option<String>,
    /// Recorded on a different image than this one: its address and function may no longer name the same code.
    pub image_changed: bool,
}

/// The outcome of `record_finding`.
#[derive(Debug, Clone, Serialize)]
pub struct LedgerRecord {
    pub finding: LedgerEntry,
    /// A new entry, rather than an update.
    pub created: bool,
    /// False when an update changed nothing (and so made no undo step).
    pub changed: bool,
}

/// How many entries of one kind are in each status, over the whole ledger.
#[derive(Debug, Clone, Serialize)]
pub struct LedgerCounts {
    pub kind: LedgerKind,
    pub open: usize,
    pub resolved: usize,
    pub rejected: usize,
}

/// A page of ledger entries, in id order.
#[derive(Debug, Clone, Serialize)]
pub struct LedgerList {
    /// Why entries may not fit this image, and entries that could not be read.
    pub warnings: Vec<String>,
    pub counts: Vec<LedgerCounts>,
    /// Entries matching the filters.
    pub total: usize,
    pub offset: usize,
    pub returned: usize,
    /// Where the next page starts, when more match.
    pub next_offset: Option<usize>,
    /// The page stopped early to stay within its JSON byte budget.
    pub byte_capped: bool,
    pub findings: Vec<LedgerEntry>,
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::Invalid(message.into())
}

fn bounded_text(field: &str, text: &str, limit: usize) -> Result<String, ApiError> {
    let text = text.trim();
    if text.len() > limit {
        return Err(invalid(format!("{field} is {} bytes; at most {limit}", text.len())));
    }
    Ok(text.to_owned())
}

fn validate_evidence(evidence: &[LedgerEvidence]) -> Result<Vec<LedgerEvidence>, ApiError> {
    if evidence.len() > MAX_LEDGER_EVIDENCE {
        return Err(invalid(format!("{} evidence references; at most {MAX_LEDGER_EVIDENCE}", evidence.len())));
    }
    evidence
        .iter()
        .map(|item| {
            let tool = item.tool.trim();
            if tool.is_empty()
                || tool.len() > MAX_EVIDENCE_TOOL
                || !tool.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            {
                return Err(invalid(format!(
                    "evidence tool {tool:?} must be 1-{MAX_EVIDENCE_TOOL} bytes of [a-z0-9_]"
                )));
            }
            let detail = bounded_text("evidence detail", &item.detail, MAX_EVIDENCE_DETAIL)?;
            Ok(LedgerEvidence { tool: tool.to_owned(), detail })
        })
        .collect()
}

impl StoredFinding {
    fn parse(value: &str) -> Option<Self> {
        serde_json::from_str(value).ok()
    }

    fn encode(&self) -> String {
        serde_json::to_string(self).expect("ledger entry JSON")
    }

    /// Whether it names an address or a function, which may stop fitting another image.
    fn anchored(&self) -> bool {
        self.address.is_some() || self.function.is_some()
    }
}

/// A new open `finding` entry for `annotations`, as the change that records it, for a write that keeps its
/// provenance in the ledger within its own batch. Checked like `record_finding`'s entries.
pub(crate) fn provenance_entry(
    annotations: &Annotations,
    text: &str,
    evidence: &[LedgerEvidence],
) -> Result<(u64, crate::batch::AnnotationChange), ApiError> {
    let text = bounded_text("text", text, MAX_LEDGER_TEXT)?;
    let evidence = validate_evidence(evidence)?;
    if annotations.findings().len() >= MAX_LEDGER_ENTRIES {
        return Err(invalid(format!("the ledger holds its maximum of {MAX_LEDGER_ENTRIES} entries")));
    }
    let id = annotations.next_finding_id().ok_or_else(|| invalid("the ledger has used every id"))?;
    let entry = StoredFinding {
        kind: LedgerKind::Finding,
        status: LedgerStatus::Open,
        text,
        address: None,
        function: None,
        evidence,
        confidence: Some(LedgerConfidence::High),
        resolution: None,
        image: None,
    };
    let value = entry.encode();
    let total = annotations.findings().values().map(String::len).sum::<usize>() + value.len();
    if total > MAX_LEDGER_BYTES {
        return Err(invalid(format!("the ledger's entries would hold {total} bytes, past {MAX_LEDGER_BYTES}")));
    }
    let edit = Edit { field: Field::Finding, address: id, value: Some(value), previous: None };
    annotations.ledger_headroom(&edit).map_err(ApiError::Invalid)?;
    Ok((id, (Field::Finding, id, edit.value)))
}

impl Project {
    /// Records a new ledger entry, or updates the entry `request.id`, as one undo step.
    pub fn record_finding(&self, request: &LedgerRequest) -> Result<LedgerRecord, ApiError> {
        let text = request.text.as_deref().map(|text| bounded_text("text", text, MAX_LEDGER_TEXT)).transpose()?;
        if text.as_deref().is_some_and(str::is_empty) {
            return Err(invalid("text is blank"));
        }
        let resolution = request
            .resolution
            .as_deref()
            .map(|text| bounded_text("resolution", text, MAX_LEDGER_RESOLUTION))
            .transpose()?;
        let evidence = request.evidence.as_deref().map(validate_evidence).transpose()?;
        let address = request.address.as_deref().map(|at| self.resolve(at)).transpose()?;
        let function = request.function.as_deref().map(|at| self.function_start(at)).transpose()?;
        let mut annotations = self.annotations.write().expect("annotations lock");
        let image = annotations.image_sha256().map(str::to_owned);
        let (id, entry, created, changed) = annotations.locked(|annotations| {
            let (id, previous) = match request.id {
                Some(id) => {
                    let value = annotations
                        .findings()
                        .get(&id)
                        .ok_or_else(|| invalid(format!("no ledger entry has id {id}")))?;
                    let previous = StoredFinding::parse(value)
                        .ok_or_else(|| invalid(format!("ledger entry {id} is unreadable; it cannot be updated")))?;
                    (id, Some(previous))
                }
                None => {
                    if annotations.findings().len() >= MAX_LEDGER_ENTRIES {
                        return Err(invalid(format!("the ledger holds its maximum of {MAX_LEDGER_ENTRIES} entries")));
                    }
                    let id = annotations
                        .next_finding_id()
                        .ok_or_else(|| invalid("the ledger has used every id; no entry can be created"))?;
                    (id, None)
                }
            };
            let created = previous.is_none();
            let mut entry = match previous {
                Some(previous) => previous,
                None => StoredFinding {
                    kind: request.kind.ok_or_else(|| invalid("kind is required when creating an entry"))?,
                    status: LedgerStatus::Open,
                    text: text.clone().ok_or_else(|| invalid("text is required when creating an entry"))?,
                    address: None,
                    function: None,
                    evidence: Vec::new(),
                    confidence: None,
                    resolution: None,
                    image: None,
                },
            };
            if let Some(kind) = request.kind {
                entry.kind = kind;
            }
            if let Some(text) = &text {
                entry.text.clone_from(text);
            }
            if let Some(status) = request.status {
                entry.status = status;
            }
            if request.confidence.is_some() {
                entry.confidence = request.confidence;
            }
            if let Some(evidence) = &evidence {
                entry.evidence.clone_from(evidence);
            }
            if let Some(resolution) = &resolution {
                entry.resolution = (!resolution.is_empty()).then(|| resolution.clone());
            }
            if address.is_some() || function.is_some() || created {
                entry.address = address.or(entry.address);
                entry.function = function.or(entry.function);
                // Only an address or function can stop fitting another image.
                entry.image = if entry.anchored() { image.clone() } else { None };
            }
            let edit = Edit {
                field: Field::Finding,
                address: id,
                value: Some(entry.encode()),
                previous: annotations.findings().get(&id).cloned(),
            };
            if edit.value != edit.previous {
                let length = |value: &Option<String>| value.as_ref().map_or(0, String::len);
                let (before, after) = (length(&edit.previous), length(&edit.value));
                let total = annotations.findings().values().map(String::len).sum::<usize>() - before + after;
                // A ledger already past the cap (from an older build) can still shrink.
                if total > MAX_LEDGER_BYTES && after > before {
                    return Err(invalid(format!(
                        "the ledger's entries would hold {total} bytes, past its maximum of {MAX_LEDGER_BYTES}; \
                         nothing was recorded"
                    )));
                }
                annotations.ledger_headroom(&edit).map_err(ApiError::Invalid)?;
            }
            let changed = annotations.set(Field::Finding, id, edit.value).map_err(ApiError::Invalid)?;
            Ok((id, entry, created, changed))
        })?;
        let finding = self.finding_row(&annotations, image.as_deref(), id, entry);
        Ok(LedgerRecord { finding, created, changed })
    }

    /// Ledger entries matching `query`, a page at a time, with counts per kind and status over the whole ledger.
    pub fn list_findings(&self, query: &LedgerQuery) -> Result<LedgerList, ApiError> {
        let limit = query.limit.unwrap_or(DEFAULT_LEDGER_PAGE);
        if !(1..=MAX_LEDGER_PAGE).contains(&limit) {
            return Err(invalid(format!("limit must be 1..={MAX_LEDGER_PAGE}")));
        }
        let address = query.address.as_deref().map(|at| self.resolve(at)).transpose()?;
        let function = query.function.as_deref().map(|at| self.function_start(at)).transpose()?;
        let matcher = Matcher::new(query.contains.as_deref());
        // The image and its warnings belong to the writer; an effective snapshot's frozen view has no log.
        let (image, mut warnings) = {
            let authority = self.annotations.read().expect("annotations lock");
            (authority.image_sha256().map(str::to_owned), authority.warnings())
        };
        let annotations = self.annotations();
        let mut unreadable = Vec::new();
        let mut entries = Vec::new();
        for (&id, value) in annotations.findings() {
            match StoredFinding::parse(value) {
                Some(entry) => entries.push((id, entry)),
                None => unreadable.push(id),
            }
        }
        if !unreadable.is_empty() {
            let shown: Vec<String> = unreadable.iter().take(20).map(u64::to_string).collect();
            warnings.push(format!(
                "{} ledger entries could not be read and are left out (ids {}{})",
                unreadable.len(),
                shown.join(", "),
                if unreadable.len() > shown.len() { ", ..." } else { "" }
            ));
        }
        let counts = [LedgerKind::Finding, LedgerKind::Unknown, LedgerKind::Question]
            .into_iter()
            .map(|kind| {
                let count =
                    |status| entries.iter().filter(|(_, entry)| entry.kind == kind && entry.status == status).count();
                LedgerCounts {
                    kind,
                    open: count(LedgerStatus::Open),
                    resolved: count(LedgerStatus::Resolved),
                    rejected: count(LedgerStatus::Rejected),
                }
            })
            .collect();
        let mut matching = Vec::new();
        for (id, entry) in entries {
            if query.kind.is_some_and(|kind| kind != entry.kind)
                || query.status.is_some_and(|status| status != entry.status)
                || address.is_some_and(|address| entry.address != Some(address))
                || !(matcher.matches(&entry.text)
                    || entry.resolution.as_deref().is_some_and(|text| matcher.matches(text)))
            {
                continue;
            }
            if let Some(function) = function
                && entry.function != Some(function)
                && match entry.address {
                    Some(address) => self.function_containing(address)? != Some(function),
                    None => true,
                }
            {
                continue;
            }
            matching.push((id, entry));
        }
        let total = matching.len();
        let offset = query.offset.unwrap_or(0).min(total);
        let mut findings = Vec::new();
        let mut bytes = 1024 + warnings.iter().map(|warning| warning.len() + 8).sum::<usize>();
        let mut byte_capped = false;
        for (id, entry) in matching.into_iter().skip(offset).take(limit) {
            let row = self.finding_row(&annotations, image.as_deref(), id, entry);
            let size = serde_json::to_string(&row).map_or(0, |text| text.len()) + 1;
            if !findings.is_empty() && bytes + size > LEDGER_PAGE_BYTES {
                byte_capped = true;
                break;
            }
            bytes += size;
            findings.push(row);
        }
        let returned = findings.len();
        let next_offset = (offset + returned < total).then_some(offset + returned);
        Ok(LedgerList { warnings, counts, total, offset, returned, next_offset, byte_capped, findings })
    }

    /// The start of the function containing the address or name `at`.
    fn function_start(&self, at: &str) -> Result<u64, ApiError> {
        let address = self.resolve(at)?;
        self.function_containing(address)?
            .ok_or_else(|| invalid(format!("no discovered function contains {address:#x} ({at})")))
    }

    fn finding_row(
        &self,
        annotations: &Annotations,
        current: Option<&str>,
        id: u64,
        entry: StoredFinding,
    ) -> LedgerEntry {
        let image_changed =
            entry.anchored() && entry.image.as_deref().is_some_and(|image| current.is_some_and(|now| now != image));
        LedgerEntry {
            id,
            kind: entry.kind,
            status: entry.status,
            text: entry.text,
            address: entry.address,
            function: entry.function,
            function_name: entry.function.map(|function| self.function_name_in(annotations, function)),
            evidence: entry.evidence,
            confidence: entry.confidence,
            resolution: entry.resolution,
            image_sha256: entry.image,
            image_changed,
        }
    }
}
