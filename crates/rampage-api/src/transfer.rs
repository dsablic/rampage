//! `transfer_annotations`: carries the annotations of an analyzed build over to this one through
//! [`crate::build_match`], previewing by default and applying as ordinary undoable batches with a provenance entry
//! in the findings ledger.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use rampage_loaders::{Binary, LoadError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::annotations::{Annotations, Field};
use crate::batch::{AnnotationBatchEntry, MAX_BATCH};
use crate::build_match::{BuildMatching, FunctionMatch, MatchMethod, Side, match_sides};
use crate::workflows::ReportTarget;
use crate::{ApiError, LedgerEvidence, Project};

/// The default lowest match confidence whose annotations transfer: every method but the call-graph neighbourhood.
pub const DEFAULT_MIN_CONFIDENCE: f64 = 0.7;
const DEFAULT_PAGE: usize = 100;
const MAX_PAGE: usize = 1000;
/// Rows stop being added once the result's JSON would pass this many bytes; one row always fits.
const PAGE_BYTES: usize = 48_000;
/// Annotation values longer than this are cut in rows (never in what is written).
const ROW_VALUE_CHARS: usize = 160;

/// Which rows a call pages.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransferList {
    /// One row per source annotation: where it goes and whether it transfers.
    #[default]
    Transfers,
    /// Every matched function pair.
    Matches,
    /// Matched pairs whose bytes and masked hash both differ.
    Changed,
    /// Functions only in this build.
    Added,
    /// Functions only in the source build.
    Removed,
    /// Functions left unmatched because the evidence fits more than one counterpart.
    Ambiguous,
}

impl TransferList {
    fn name(self) -> &'static str {
        match self {
            TransferList::Transfers => "transfers",
            TransferList::Matches => "matches",
            TransferList::Changed => "changed",
            TransferList::Added => "added",
            TransferList::Removed => "removed",
            TransferList::Ambiguous => "ambiguous",
        }
    }
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransferRequest {
    /// File path of the analyzed build (same architecture) whose saved annotations (its `.rampage` log) are carried
    /// over to this build; that log is only read.
    pub from: String,
    /// Write every transferable annotation to this build's log as one undoable batch (several when more than 1000)
    /// with a provenance entry in the findings ledger; omitted or false only previews.
    #[serde(default)]
    pub apply: bool,
    /// Lowest match confidence whose annotations transfer, 0 to 1 (default 0.7). Methods: exact_bytes 1.0,
    /// symbol_name 0.95, masked_hash 0.9, unique_string 0.8, call_graph 0.75, neighbourhood 0.6.
    #[schemars(range(min = 0.0, max = 1.0))]
    pub min_confidence: Option<f64>,
    /// Rows to page: transfers (default), matches, changed, added, removed or ambiguous.
    pub list: Option<TransferList>,
    /// Rows to skip.
    pub offset: Option<usize>,
    /// Rows per page, 1..=1000 (default 100), additionally bounded to 48000 JSON bytes.
    #[schemars(range(min = 1, max = 1000))]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    /// Matched, but the new build already has a different value there, or the name is used elsewhere.
    Conflict,
    /// No counterpart for its address could be established.
    NotTransferred,
    /// Matched below `min_confidence`.
    BelowThreshold,
    /// Transfers (preview) or was written (apply).
    Transfer,
    /// The new build already has the same value there.
    AlreadyPresent,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatchSummary {
    pub source_functions: usize,
    pub target_functions: usize,
    pub matched: usize,
    pub by_method: BTreeMap<&'static str, usize>,
    /// Matched with the same bytes or masked hash.
    pub unchanged: usize,
    pub changed: usize,
    pub added: usize,
    pub removed: usize,
    pub ambiguous: usize,
    /// Anchor-propagation rounds run, and whether the round limit stopped them.
    pub rounds: usize,
    pub round_limited: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TransferCounts {
    /// Source annotations considered (every field), and how they ended.
    pub source_annotations: usize,
    pub transfer: usize,
    pub already_present: usize,
    pub conflict: usize,
    pub below_threshold: usize,
    pub not_transferred: usize,
    /// Transferring annotations by field.
    pub transfer_by_field: BTreeMap<&'static str, usize>,
    /// Transferring annotations by the match method that placed them.
    pub transfer_by_method: BTreeMap<&'static str, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferApplied {
    /// Annotations the batches changed.
    pub changed: usize,
    /// Batches written; each is one undo step (the last also records the provenance entry).
    pub batches: usize,
    /// The findings-ledger entry recording the source build, threshold and methods.
    pub provenance_finding: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferReport {
    /// `preview` or `applied`.
    pub status: &'static str,
    pub source_path: String,
    pub source: ReportTarget,
    pub target: ReportTarget,
    pub min_confidence: f64,
    pub matching: MatchSummary,
    pub annotations: TransferCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied: Option<TransferApplied>,
    pub list: &'static str,
    pub total: usize,
    pub offset: usize,
    pub returned: usize,
    pub next_offset: Option<usize>,
    /// The page stopped early to stay within its JSON byte budget.
    pub byte_capped: bool,
    pub rows: Vec<Value>,
    pub notes: Vec<&'static str>,
}

/// One source annotation and where it goes.
struct Planned {
    field: Field,
    old: u64,
    new: Option<u64>,
    value: String,
    method: Option<MatchMethod>,
    /// Placed through a data reference of a matched function rather than at the match itself.
    via_reference: bool,
    status: TransferStatus,
    reason: Option<String>,
}

fn field_name(field: Field) -> &'static str {
    match field {
        Field::Name => "name",
        Field::Comment => "comment",
        Field::Signature => "signature",
        Field::Types => "types",
        Field::Global => "global",
        Field::LocalName => "local_name",
        Field::LocalType => "local_type",
        Field::TypeHint => "type_hint",
        Field::DataType => "data_type",
        Field::OperandType => "operand_type",
        Field::TypeLibrary => "type_library",
        Field::DebugTypes => "debug_types",
        Field::Patch => "patch",
        Field::Finding => "finding",
        Field::Unknown => "unknown",
    }
}

/// The source build at `path` with its saved annotations, read only.
fn open_source(target: &Project, path: &Path) -> Result<Project, ApiError> {
    let arch = target.binary.arch;
    let binary = match Binary::open_image(path, None, Some(arch)) {
        Ok(binary) => binary,
        Err(source @ LoadError::Unsupported(_)) if Binary::open_image(path, None, None).is_ok() => {
            return Err(ApiError::Invalid(format!(
                "{}: {source}; a transfer needs both binaries in {arch}",
                path.display()
            )));
        }
        Err(source) => return Err(ApiError::Load { path: path.to_owned(), source }),
    };
    let log = crate::session::annotation_path(path, None, &binary);
    let digest: [u8; 32] = Sha256::digest(binary.image_bytes()).into();
    let annotations = Annotations::open_for_image(log, Some(digest)).map_err(ApiError::Invalid)?;
    Ok(Project::with_annotations(binary, annotations))
}

/// Where old data address `address` lies in the new build, through the data references that matched same-layout
/// functions make to it at the same instruction offsets; `None` unless every such reference agrees.
fn through_references(
    address: u64,
    references: &HashMap<u64, Vec<(u64, u64)>>,
    old_matches: &HashMap<u64, FunctionMatch>,
    new: &Side,
) -> Option<(u64, MatchMethod)> {
    let mut found: Option<(u64, MatchMethod)> = None;
    for &(function, offset) in references.get(&address)? {
        let Some(matched) = old_matches.get(&function).filter(|matched| matched.same_layout) else { continue };
        let target = new.function_at(matched.new)?;
        let at = target.data_refs.iter().filter(|(from, _)| *from == offset).map(|(_, to)| *to);
        let mut targets: Vec<u64> = at.collect();
        targets.dedup();
        let [to] = targets[..] else { return None };
        match found {
            None => found = Some((to, matched.method)),
            Some((earlier, method)) if earlier == to => {
                // The weakest method that placed it.
                if matched.method.confidence() < method.confidence() {
                    found = Some((to, matched.method));
                }
            }
            Some(_) => return None,
        }
    }
    found
}

impl Project {
    /// Matches the functions of the build at `request.from` with this one's and transfers its saved annotations:
    /// a preview, or with `apply` a write. See [`TransferRequest`].
    pub fn transfer_annotations(&self, request: &TransferRequest) -> Result<TransferReport, ApiError> {
        let min_confidence = request.min_confidence.unwrap_or(DEFAULT_MIN_CONFIDENCE);
        if !(0.0..=1.0).contains(&min_confidence) {
            return Err(ApiError::Invalid("min_confidence must be between 0 and 1".to_owned()));
        }
        let limit = request.limit.unwrap_or(DEFAULT_PAGE);
        if !(1..=MAX_PAGE).contains(&limit) {
            return Err(ApiError::Invalid(format!("limit must be 1..={MAX_PAGE}")));
        }
        let path = Path::new(&request.from);
        let source = open_source(self, path)?;
        let (old, new) = (Side::of(&source)?, Side::of(self)?);
        let matching = match_sides(&old, &new);
        let mut planned = self.plan_transfer(&source, &old, &new, &matching, min_confidence)?;

        let mut applied = None;
        if request.apply {
            applied = Some(self.apply_transfer(&source, &request.from, &planned, min_confidence)?);
            for entry in planned.iter_mut().filter(|entry| entry.status == TransferStatus::Transfer) {
                entry.reason = Some("written".to_owned());
            }
        }

        let mut counts = TransferCounts { source_annotations: planned.len(), ..TransferCounts::default() };
        for entry in &planned {
            match entry.status {
                TransferStatus::Transfer => {
                    counts.transfer += 1;
                    *counts.transfer_by_field.entry(field_name(entry.field)).or_default() += 1;
                    if let Some(method) = entry.method {
                        *counts.transfer_by_method.entry(method.name()).or_default() += 1;
                    }
                }
                TransferStatus::AlreadyPresent => counts.already_present += 1,
                TransferStatus::Conflict => counts.conflict += 1,
                TransferStatus::BelowThreshold => counts.below_threshold += 1,
                TransferStatus::NotTransferred => counts.not_transferred += 1,
            }
        }
        let mut by_method: BTreeMap<&'static str, usize> = BTreeMap::new();
        for matched in &matching.matches {
            *by_method.entry(matched.method.name()).or_default() += 1;
        }
        let changed = matching.matches.iter().filter(|matched| matched.changed).count();
        let summary = MatchSummary {
            source_functions: old.functions.len(),
            target_functions: new.functions.len(),
            matched: matching.matches.len(),
            by_method,
            unchanged: matching.matches.len() - changed,
            changed,
            added: matching.added.len(),
            removed: matching.removed.len(),
            ambiguous: matching.ambiguity_count,
            rounds: matching.rounds,
            round_limited: matching.round_limited,
        };

        let list = request.list.unwrap_or_default();
        let rows = self.rows(&source, &old, &new, &matching, &planned, list);
        let offset = request.offset.unwrap_or(0);
        let mut report = TransferReport {
            status: if request.apply { "applied" } else { "preview" },
            source_path: request.from.clone(),
            source: ReportTarget::of(&source),
            target: ReportTarget::of(self),
            min_confidence,
            matching: summary,
            annotations: counts,
            applied,
            list: list.name(),
            total: rows.len(),
            offset,
            returned: 0,
            next_offset: None,
            byte_capped: false,
            rows: Vec::new(),
            notes: vec![
                "Matches are signature-level: equal bytes or masked hashes, unique symbols and strings, and call-graph \
                 position are evidence of the same function, not proof of the same behavior.",
                "Matching is one-to-one: functions whose evidence fits more than one counterpart stay unmatched and \
                 are listed under `ambiguous`, never guessed.",
                "Annotations inside a function move by offset only when the matched bodies have the same size and the \
                 same bytes or masked hash; data annotations move through a matching symbol or the data references \
                 of such functions, else they are not transferred.",
                "Local names and types, type hints, data and operand types, type libraries, debug types, patches and \
                 findings are not transferred.",
            ],
        };
        let mut bytes = serde_json::to_string(&report).map_or(0, |text| text.len());
        let end = offset.saturating_add(limit).min(rows.len());
        for (index, row) in rows.into_iter().enumerate().take(end).skip(offset) {
            let size = row.to_string().len() + 1;
            if !report.rows.is_empty() && bytes + size > PAGE_BYTES {
                report.byte_capped = true;
                report.next_offset = Some(index);
                break;
            }
            bytes += size;
            report.rows.push(row);
        }
        report.returned = report.rows.len();
        if report.next_offset.is_none() && offset + report.returned < report.total {
            report.next_offset = Some(offset + report.returned);
        }
        Ok(report)
    }

    fn plan_transfer(
        &self,
        source: &Project,
        old: &Side,
        new: &Side,
        matching: &BuildMatching,
        min_confidence: f64,
    ) -> Result<Vec<Planned>, ApiError> {
        let old_analysis = source.analysis()?;
        let old_matches: HashMap<u64, FunctionMatch> =
            matching.matches.iter().map(|matched| (matched.old, *matched)).collect();
        let mut references: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
        for function in &old.functions {
            for &(offset, to) in &function.data_refs {
                references.entry(to).or_default().push((function.address, offset));
            }
        }
        let place = |address: u64| -> Result<(u64, MatchMethod, bool), String> {
            if let Some(matched) = old_matches.get(&address) {
                return Ok((matched.new, matched.method, false));
            }
            if old.function_at(address).is_some() {
                return Err("its function has no counterpart in this build (removed, or ambiguous)".to_owned());
            }
            if let Some(start) = old_analysis.function_containing(address) {
                return match old_matches.get(&start) {
                    Some(matched) if matched.same_layout => {
                        Ok((matched.new + (address - start), matched.method, false))
                    }
                    Some(_) => Err("it is inside a function that changed, so offsets do not carry over".to_owned()),
                    None => Err("its function has no counterpart in this build (removed, or ambiguous)".to_owned()),
                };
            }
            if let Some(name) = source.symbol_name(address)
                && source.symbol_address(name) == Some(address)
                && let Some(to) = self.symbol_address(name)
            {
                return Ok((to, MatchMethod::SymbolName, false));
            }
            if let Some((to, method)) = through_references(address, &references, &old_matches, new) {
                return Ok((to, method, true));
            }
            Err("no matched function references it at an unchanged instruction, and no symbol names it".to_owned())
        };

        let annotations = source.annotations();
        let mut planned = Vec::new();
        let supported = [
            (Field::Name, annotations.names()),
            (Field::Comment, annotations.comments()),
            (Field::Signature, annotations.signatures()),
            (Field::Types, annotations.types()),
            (Field::Global, annotations.globals()),
        ];
        for (field, values) in supported {
            for (&address, value) in values {
                let mut entry = Planned {
                    field,
                    old: address,
                    new: None,
                    value: value.clone(),
                    method: None,
                    via_reference: false,
                    status: TransferStatus::Transfer,
                    reason: None,
                };
                match place(address) {
                    Ok((to, method, via_reference)) => {
                        entry.new = Some(to);
                        entry.method = Some(method);
                        entry.via_reference = via_reference;
                        if method.confidence() < min_confidence {
                            entry.status = TransferStatus::BelowThreshold;
                        }
                    }
                    Err(reason) => {
                        entry.status = TransferStatus::NotTransferred;
                        entry.reason = Some(reason);
                    }
                }
                planned.push(entry);
            }
        }
        let unsupported = [
            (Field::LocalName, annotations.local_names()),
            (Field::LocalType, annotations.local_types()),
            (Field::TypeHint, annotations.type_hints()),
            (Field::DataType, annotations.data_types()),
            (Field::OperandType, annotations.operand_types()),
            (Field::TypeLibrary, annotations.type_library()),
            (Field::DebugTypes, annotations.debug_types()),
            (Field::Patch, annotations.patches()),
        ];
        for (field, values) in unsupported {
            for (&address, value) in values {
                planned.push(Planned {
                    field,
                    old: address,
                    new: None,
                    value: value.clone(),
                    method: None,
                    via_reference: false,
                    status: TransferStatus::NotTransferred,
                    reason: Some(format!("{} annotations are not transferred", field_name(field))),
                });
            }
        }
        drop(annotations);
        self.check_conflicts(&mut planned);
        planned.sort_by_key(|entry| (entry.status, entry.old, field_name(entry.field)));
        Ok(planned)
    }

    /// Marks transfers that the new build already has, or that clash with it or with each other.
    fn check_conflicts(&self, planned: &mut [Planned]) {
        let current = self.annotations();
        let mut targets: HashMap<(u8, u64), usize> = HashMap::new();
        let mut names: HashMap<String, usize> = HashMap::new();
        let mut clashes = Vec::new();
        for (index, entry) in planned.iter_mut().enumerate() {
            if entry.status != TransferStatus::Transfer {
                continue;
            }
            let Some(to) = entry.new else { continue };
            let existing = match entry.field {
                Field::Name => current.names().get(&to),
                Field::Comment => current.comments().get(&to),
                Field::Signature => current.signatures().get(&to),
                Field::Types => current.types().get(&to),
                Field::Global => current.globals().get(&to),
                _ => None,
            };
            let conflict = |entry: &mut Planned, reason: String| {
                entry.status = TransferStatus::Conflict;
                entry.reason = Some(reason);
            };
            match existing {
                Some(value) if *value == entry.value => {
                    entry.status = TransferStatus::AlreadyPresent;
                    continue;
                }
                Some(value) => {
                    let value = value.chars().take(ROW_VALUE_CHARS).collect::<String>();
                    conflict(
                        entry,
                        format!("this build already has a different {}: {value:?}", field_name(entry.field)),
                    );
                    continue;
                }
                None => {}
            }
            if entry.field == Field::Name {
                if existing.is_none() && self.symbol_name(to) == Some(entry.value.as_str()) {
                    entry.status = TransferStatus::AlreadyPresent;
                    continue;
                }
                if let Err(problem) = crate::project::check_name(&entry.value) {
                    conflict(entry, problem);
                    continue;
                }
                let used = current
                    .address_of(&entry.value)
                    .or_else(|| self.symbol_address(&entry.value))
                    .filter(|&at| at != to);
                if let Some(at) = used {
                    conflict(entry, format!("the name already names {at:#x} in this build"));
                    continue;
                }
                if let Some(&earlier) = names.get(&entry.value) {
                    clashes.push((earlier, index, "the name would go to two addresses"));
                } else {
                    names.insert(entry.value.clone(), index);
                }
            }
            if let Some(&earlier) = targets.get(&(entry.field as u8, to)) {
                clashes.push((earlier, index, "two source annotations land on the same address"));
            } else {
                targets.insert((entry.field as u8, to), index);
            }
        }
        for (earlier, later, reason) in clashes {
            for index in [earlier, later] {
                planned[index].status = TransferStatus::Conflict;
                planned[index].reason = Some(reason.to_owned());
            }
        }
    }

    fn apply_transfer(
        &self,
        source: &Project,
        source_path: &str,
        planned: &[Planned],
        min_confidence: f64,
    ) -> Result<TransferApplied, ApiError> {
        let entries: Vec<AnnotationBatchEntry> = planned
            .iter()
            .filter(|entry| entry.status == TransferStatus::Transfer)
            .filter_map(|entry| {
                let at = format!("{:#x}", entry.new?);
                let value = Some(entry.value.clone());
                Some(match entry.field {
                    Field::Name => AnnotationBatchEntry::Rename { at, value },
                    Field::Comment => AnnotationBatchEntry::Comment { at, value },
                    Field::Signature => AnnotationBatchEntry::Signature { at, value },
                    Field::Types => AnnotationBatchEntry::Types { at, value },
                    Field::Global => AnnotationBatchEntry::Global { at, value },
                    _ => return None,
                })
            })
            .collect();
        if entries.is_empty() {
            return Ok(TransferApplied { changed: 0, batches: 0, provenance_finding: None });
        }
        let mut methods: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut fields: BTreeMap<&'static str, usize> = BTreeMap::new();
        for entry in planned.iter().filter(|entry| entry.status == TransferStatus::Transfer) {
            *fields.entry(field_name(entry.field)).or_default() += 1;
            if let Some(method) = entry.method {
                *methods.entry(method.name()).or_default() += 1;
            }
        }
        let tally = |counts: &BTreeMap<&str, usize>| {
            counts.iter().map(|(name, count)| format!("{name} {count}")).collect::<Vec<_>>().join(", ")
        };
        let source_target = ReportTarget::of(source);
        let shown_path: String = source_path.chars().take(300).collect();
        let text = format!(
            "transfer_annotations: {} annotations transferred from build sha256 {} ({shown_path}) to this build at \
             min_confidence {min_confidence}. By match method: {}. By field: {}.",
            entries.len(),
            source_target.sha256,
            tally(&methods),
            tally(&fields),
        );
        let evidence = [LedgerEvidence {
            tool: "transfer_annotations".to_owned(),
            detail: format!("from sha256 {}, min_confidence {min_confidence}", source_target.sha256),
        }];
        let chunks: Vec<&[AnnotationBatchEntry]> = entries.chunks(MAX_BATCH).collect();
        let mut changed = 0;
        let mut provenance = None;
        for (index, chunk) in chunks.iter().enumerate() {
            let last = index + 1 == chunks.len();
            let result = self.batch_annotations_with_extra(
                chunk,
                |current| {
                    if !last {
                        return Ok(Vec::new());
                    }
                    let (id, change) = crate::findings::provenance_entry(current, &text, &evidence)?;
                    provenance = Some(id);
                    Ok(vec![change])
                },
                |_| Ok(()),
            )?;
            changed += result.entries.iter().filter(|entry| entry.changed && entry.field != Field::Finding).count();
        }
        Ok(TransferApplied { changed, batches: chunks.len(), provenance_finding: provenance })
    }

    fn rows(
        &self,
        source: &Project,
        old: &Side,
        new: &Side,
        matching: &BuildMatching,
        planned: &[Planned],
        list: TransferList,
    ) -> Vec<Value> {
        let hex = |address: u64| format!("{address:#x}");
        let match_row = |matched: &FunctionMatch| {
            json!({
                "old": hex(matched.old),
                "new": hex(matched.new),
                "old_name": source.function_name(matched.old),
                "new_name": self.function_name(matched.new),
                "method": matched.method.name(),
                "confidence": matched.method.confidence(),
                "changed": matched.changed,
            })
        };
        match list {
            TransferList::Transfers => planned
                .iter()
                .map(|entry| {
                    let mut row = json!({
                        "kind": field_name(entry.field),
                        "old": hex(entry.old),
                        "status": entry.status,
                    });
                    let value: String = entry.value.chars().take(ROW_VALUE_CHARS).collect();
                    if value.len() < entry.value.len() {
                        row["value_truncated"] = json!(true);
                    }
                    row["value"] = json!(value);
                    if let Some(to) = entry.new {
                        row["new"] = json!(hex(to));
                    }
                    if let Some(method) = entry.method {
                        row["method"] = json!(method.name());
                        row["confidence"] = json!(method.confidence());
                    }
                    if entry.via_reference {
                        row["via"] = json!("data_reference");
                    }
                    if let Some(reason) = &entry.reason {
                        row["reason"] = json!(reason);
                    }
                    row
                })
                .collect(),
            TransferList::Matches => matching.matches.iter().map(match_row).collect(),
            TransferList::Changed => matching.matches.iter().filter(|matched| matched.changed).map(match_row).collect(),
            TransferList::Added => matching
                .added
                .iter()
                .map(|&address| {
                    let size = new.function_at(address).map_or(0, |function| function.size);
                    json!({ "new": hex(address), "name": self.function_name(address), "size": size })
                })
                .collect(),
            TransferList::Removed => matching
                .removed
                .iter()
                .map(|&address| {
                    let size = old.function_at(address).map_or(0, |function| function.size);
                    json!({ "old": hex(address), "name": source.function_name(address), "size": size })
                })
                .collect(),
            TransferList::Ambiguous => matching
                .ambiguities
                .iter()
                .map(|ambiguity| serde_json::to_value(ambiguity).unwrap_or_default())
                .collect(),
        }
    }
}
