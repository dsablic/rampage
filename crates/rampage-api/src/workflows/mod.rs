//! Guided investigation workflows: bounded compositions of the analysis primitives into one structured report an
//! agent can act on. Every finding names the primitive and the evidence behind it, every list is capped (and says
//! when it was cut), and every report states its limitations. Reports describe what was observed, never a verdict.

mod diff_builds;
mod find_crypto;
mod find_main;
mod indicators;
mod network_surface;
mod persistence_surface;
mod registry;
mod string_decoding;
mod triage_report;

use std::collections::{BTreeMap, BTreeSet};

use rampage_arch::Arch;
use rampage_capabilities::{Capability, names};
use rampage_loaders::{Format, SymbolKind};
use serde::Serialize;
use serde_json::Value;

use crate::{Project, XrefQuery};

pub use indicators::{Indicator, IndicatorKind, classify};
pub use registry::{WORKFLOWS, Workflow, WorkflowOptions, workflow};

/// Findings per section unless the caller asks for another count.
pub const DEFAULT_SECTION_LIMIT: usize = 25;
/// The most findings any section may hold, whatever the caller asks for.
pub const MAX_SECTION_LIMIT: usize = 200;
/// Evidence items kept per finding; the rest are counted in a final "... and N more" item.
const MAX_EVIDENCE: usize = 8;
const MAX_NEXT_STEPS: usize = 10;
/// Characters of quoted binary text (strings, names) kept in an observation.
pub const MAX_QUOTE_CHARS: usize = 160;

/// How far a finding can be trusted. `Observed` is read directly from the file's bytes or structure (a header
/// field, an import entry, a string's presence, bytes compared); the other levels rate an inference, including
/// everything recovered by code analysis (references, calls, discovered functions), which is at most `High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
    Observed,
}

impl Confidence {
    /// The level as it appears in a report's JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Observed => "observed",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub observation: String,
    /// What the observation rests on: matched names, addresses, instructions.
    pub evidence: Vec<String>,
    /// The primitive (tool) that produced the evidence.
    pub source: &'static str,
    pub confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "rampage_arch::hex::optional_address")]
    pub address: Option<u64>,
    /// Evidence items dropped past `MAX_EVIDENCE`, summed over every `evidence` call.
    #[serde(skip)]
    omitted: usize,
}

impl Finding {
    pub fn new(source: &'static str, confidence: Confidence, observation: impl Into<String>) -> Self {
        Self { observation: observation.into(), evidence: Vec::new(), source, confidence, address: None, omitted: 0 }
    }

    pub fn at(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }

    /// Adds evidence, keeping at most `MAX_EVIDENCE` items and counting the rest in one final item.
    pub fn evidence<S: Into<String>>(mut self, items: impl IntoIterator<Item = S>) -> Self {
        if self.omitted > 0 {
            self.evidence.pop();
        }
        for item in items {
            if self.evidence.len() < MAX_EVIDENCE {
                self.evidence.push(item.into());
            } else {
                self.omitted += 1;
            }
        }
        if self.omitted > 0 {
            self.evidence.push(format!("... and {} more", self.omitted));
        }
        self
    }
}

/// Verbatim output of a primitive, such as a decompilation preview.
#[derive(Debug, Clone, Serialize)]
pub struct Excerpt {
    pub source: &'static str,
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub title: String,
    pub findings: Vec<Finding>,
    /// Findings available before the cap was applied.
    pub total: usize,
    /// Whether `findings` holds fewer than `total`.
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<Excerpt>,
    #[serde(skip)]
    limit: usize,
}

impl Section {
    pub fn new(title: impl Into<String>, limits: ReportLimits) -> Self {
        Self {
            title: title.into(),
            findings: Vec::new(),
            total: 0,
            truncated: false,
            excerpt: None,
            limit: limits.per_section,
        }
    }

    /// Records a finding, keeping it only while the section is under its cap.
    pub fn push(&mut self, finding: Finding) {
        self.total += 1;
        if self.findings.len() < self.limit {
            self.findings.push(finding);
        } else {
            self.truncated = true;
        }
    }

    pub fn extend(&mut self, findings: impl IntoIterator<Item = Finding>) {
        for finding in findings {
            self.push(finding);
        }
    }
}

/// A follow-up tool call: the tool to run, its group, its arguments (beside the binary's `path`), and why.
#[derive(Debug, Clone, Serialize)]
pub struct NextStep {
    pub tool: &'static str,
    /// The tool group serving `tool` (see [`crate::tools::Group`]); an MCP client that has not enabled it calls
    /// enable_tools with it first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<&'static str>,
    pub arguments: Value,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportTarget {
    pub format: Format,
    pub arch: Arch,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub entry: Option<u64>,
    pub sha256: String,
}

impl ReportTarget {
    pub fn of(project: &Project) -> Self {
        let binary = &project.binary;
        Self {
            format: binary.format,
            arch: binary.arch,
            entry: binary.entry,
            sha256: project.triage().image_hashes.sha256.clone(),
        }
    }
}

/// The uniform result of every workflow. Sections serialize last, so that a reader cut short by size still has the
/// summary, limitations and next steps.
#[derive(Debug, Clone, Serialize)]
pub struct WorkflowReport {
    pub workflow: &'static str,
    pub target: ReportTarget,
    /// The second binary, for workflows that compare two.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other: Option<ReportTarget>,
    pub summary: Vec<String>,
    pub limitations: Vec<String>,
    pub next_steps: Vec<NextStep>,
    /// Suggestions dropped past `MAX_NEXT_STEPS`.
    #[serde(skip_serializing_if = "is_zero")]
    pub next_steps_omitted: usize,
    pub sections: Vec<Section>,
}

fn is_zero(count: &usize) -> bool {
    *count == 0
}

impl WorkflowReport {
    pub fn new(workflow: &'static str, project: &Project) -> Self {
        Self {
            workflow,
            target: ReportTarget::of(project),
            other: None,
            summary: Vec::new(),
            sections: Vec::new(),
            next_steps: Vec::new(),
            next_steps_omitted: 0,
            limitations: Vec::new(),
        }
    }

    /// Suggests a follow-up call, ignoring duplicates and counting anything past `MAX_NEXT_STEPS`.
    pub fn step(&mut self, tool: &'static str, arguments: Value, reason: impl Into<String>) {
        if self.next_steps.iter().any(|step| step.tool == tool && step.arguments == arguments) {
            return;
        }
        if self.next_steps.len() < MAX_NEXT_STEPS {
            let group = crate::tools::group_of(tool).map(crate::tools::Group::name);
            self.next_steps.push(NextStep { tool, group, arguments, reason: reason.into() });
        } else {
            self.next_steps_omitted += 1;
        }
    }

    pub fn limitation(&mut self, text: impl Into<String>) {
        self.limitations.push(text.into());
    }

    /// Shrinks the report until its compact JSON is at most `max_bytes` long, by halving the findings of the
    /// section holding the most (each cut section reads as truncated) and, failing that, dropping excerpts. The
    /// summary, limitations and next steps are kept whole, and a limitation says the report was cut.
    pub fn fit(&mut self, max_bytes: usize) {
        let size = |report: &Self| serde_json::to_string(report).map_or(0, |json| json.len());
        if size(self) <= max_bytes {
            return;
        }
        self.limitation(format!(
            "The report was cut to fit {max_bytes} bytes: some sections hold fewer findings than requested (each \
             gives its total) and excerpts may be dropped. Ask for a smaller max_per_section, or page through the \
             primitive tools for the rest."
        ));
        while size(self) > max_bytes {
            let fullest = self.sections.iter_mut().filter(|section| !section.findings.is_empty());
            if let Some(section) = fullest.max_by_key(|section| section.findings.len()) {
                section.findings.truncate(section.findings.len() / 2);
                section.truncated = true;
            } else if let Some(section) = self.sections.iter_mut().find(|section| section.excerpt.is_some()) {
                section.excerpt = None;
            } else {
                break;
            }
        }
    }

    /// The section titled `title`, for tests and renderers.
    pub fn section(&self, title: &str) -> Option<&Section> {
        self.sections.iter().find(|section| section.title == title)
    }
}

/// Caps applied to a report's sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportLimits {
    pub per_section: usize,
}

impl ReportLimits {
    /// `requested` findings per section, clamped to 1..=`MAX_SECTION_LIMIT` (default `DEFAULT_SECTION_LIMIT`).
    pub fn new(requested: Option<usize>) -> Self {
        Self { per_section: requested.unwrap_or(DEFAULT_SECTION_LIMIT).clamp(1, MAX_SECTION_LIMIT) }
    }
}

impl Default for ReportLimits {
    fn default() -> Self {
        Self::new(None)
    }
}

/// `text` cut to `MAX_QUOTE_CHARS` characters, marked when cut.
pub fn quote(text: &str) -> String {
    if text.chars().count() <= MAX_QUOTE_CHARS {
        return format!("{text:?}");
    }
    let cut: String = text.chars().take(MAX_QUOTE_CHARS).collect();
    format!("{cut:?}...")
}

/// Whether `name` (decorated or not) is the API `pattern` names: the shared normalization of
/// `rampage_capabilities::names` (a lowercase stem that also matches with a Windows `A`/`W` suffix, or a prefix
/// ending in `*`).
pub(crate) fn api_matches(pattern: &str, name: &str) -> bool {
    names::stem_matches(pattern, &names::import_stem(name))
}

/// The value of the first `(pattern, value)` entry of `table` that `name` matches (see `api_matches`).
pub(crate) fn match_api<T: Copy>(table: &[(&str, T)], name: &str) -> Option<T> {
    names::find_pattern(table, name).copied()
}

/// References read per traced item when looking for the functions that use it.
const REFERENCES_PER_ITEM: usize = 200;

/// The functions referencing one traced item (an API, a string, a constant).
pub(crate) struct Users {
    /// Function start to name and reference count, for every referencing function found.
    functions: BTreeMap<u64, (String, usize)>,
    references: usize,
    /// Whether references were looked up at all (they are not when analysis is unavailable).
    traced: bool,
    /// Whether some target had more references than were read.
    truncated: bool,
}

impl Users {
    /// The reference count (stating when it is a lower bound) and each referencing function.
    pub(crate) fn evidence(&self) -> Vec<String> {
        if !self.traced {
            return Vec::new();
        }
        let count = if self.truncated {
            format!(
                "at least {} references from discovered functions (read up to {REFERENCES_PER_ITEM} per target)",
                self.references
            )
        } else {
            format!("{} references from discovered functions", self.references)
        };
        let referencing =
            self.functions.iter().map(|(address, (name, _))| format!("referenced from `{name}` ({address:#x})"));
        std::iter::once(count).chain(referencing).collect()
    }

    /// The evidence, keeping only the referencing functions in `scope` (with the scope's reason after the count),
    /// or `None` when `scope` keeps none.
    fn evidence_within(&mut self, scope: Option<&Scope>) -> Option<Vec<String>> {
        let Some(scope) = scope else { return Some(self.evidence()) };
        self.functions.retain(|address, _| scope.functions.contains(address));
        if self.functions.is_empty() {
            return None;
        }
        self.references = self.functions.values().map(|(_, count)| count).sum();
        let mut evidence = self.evidence();
        evidence.insert(1, scope.why.to_owned());
        Some(evidence)
    }

    /// The start of every referencing function.
    pub(crate) fn addresses(&self) -> impl Iterator<Item = u64> + '_ {
        self.functions.keys().copied()
    }
}

/// The functions an API must be referenced from to be listed, and why, as an evidence line.
pub(crate) struct Scope {
    pub(crate) functions: BTreeSet<u64>,
    pub(crate) why: &'static str,
}

/// Traces items (APIs, strings, constants) to the functions that reference them, and gathers per-function evidence
/// for a ranked "Functions referencing ..." section.
pub(crate) struct Tracer<'p> {
    project: &'p Project,
    analyzed: bool,
    /// Function start to (name, evidence), across every traced item.
    users: BTreeMap<u64, (String, Vec<String>)>,
    /// Items whose references were cut at `REFERENCES_PER_ITEM`.
    truncated: usize,
    /// Items whose references could not be read, with the first error.
    failed: usize,
    first_failure: Option<String>,
}

impl<'p> Tracer<'p> {
    /// A tracer for `project`, stating in `report` when references are unavailable.
    pub(crate) fn new(project: &'p Project, report: &mut WorkflowReport) -> Self {
        let analysis_error = project.analysis().err().map(|error| error.to_string());
        if let Some(error) = &analysis_error {
            report.limitation(format!(
                "Code references are unavailable ({error}); referencing functions are not listed."
            ));
        }
        Self {
            project,
            analyzed: analysis_error.is_none(),
            users: BTreeMap::new(),
            truncated: 0,
            failed: 0,
            first_failure: None,
        }
    }

    /// The functions referencing any of `targets`, other than the targets themselves.
    pub(crate) fn users(&mut self, targets: &[u64]) -> Users {
        let mut users = Users { functions: BTreeMap::new(), references: 0, traced: self.analyzed, truncated: false };
        if !self.analyzed {
            return users;
        }
        let mut targets = targets.to_vec();
        targets.sort_unstable();
        targets.dedup();
        for &target in &targets {
            let page = match self.project.xrefs(XrefQuery::To(target), None, Some(REFERENCES_PER_ITEM)) {
                Ok(page) => page,
                Err(error) => {
                    self.failed += 1;
                    self.first_failure.get_or_insert_with(|| format!("{target:#x}: {error}"));
                    continue;
                }
            };
            if page.total > page.items.len() {
                users.truncated = true;
            }
            for row in page.items {
                // A PLT stub or the API's own body referencing it is plumbing, not a user.
                if let Ok(Some(function)) = self.project.function_containing(row.from)
                    && targets.binary_search(&function).is_err()
                {
                    users.references += 1;
                    users.functions.entry(function).or_insert_with(|| (self.project.function_name(function), 0)).1 += 1;
                }
            }
        }
        if users.truncated {
            self.truncated += 1;
        }
        users
    }

    /// Credits every function in `found` with `evidence`, for the ranked section.
    pub(crate) fn record(&mut self, found: &Users, evidence: &str) {
        for (&address, (name, _)) in &found.functions {
            self.users.entry(address).or_insert_with(|| (name.clone(), Vec::new())).1.push(evidence.to_owned());
        }
    }

    /// The imports and statically linked or local functions whose names `area` maps to an area, each with the
    /// functions referencing it, recorded for the ranked section.
    pub(crate) fn api_section(
        &mut self,
        title: &str,
        limits: ReportLimits,
        area: impl Fn(&str) -> Option<&'static str>,
    ) -> Section {
        self.api_section_within(title, limits, |name| area(name).map(|area| (area, None)))
    }

    /// [`Self::api_section`], where an API that `area` gives a [`Scope`] is listed only when functions in the
    /// scope reference it, with only those functions as its users.
    pub(crate) fn api_section_within<'s>(
        &mut self,
        title: &str,
        limits: ReportLimits,
        area: impl Fn(&str) -> Option<(&'static str, Option<&'s Scope>)>,
    ) -> Section {
        let project = self.project;
        let mut section = Section::new(title, limits);
        let mut seen = BTreeSet::new();
        for import in &project.binary.imports {
            let Some((area, scope)) = area(&import.name) else { continue };
            if !seen.insert(import.name.as_str()) {
                continue;
            }
            let mut targets: Vec<u64> = project
                .binary
                .import_slots
                .iter()
                .filter(|slot| slot.name == import.name)
                .map(|slot| slot.address)
                .collect();
            targets.extend(project.resolve(&import.name).ok());
            let mut found = self.users(&targets);
            let Some(evidence) = found.evidence_within(scope) else { continue };
            let library = import.library.as_deref().unwrap_or("an unrecorded library");
            let mut finding = Finding::new(
                "list_imports",
                Confidence::Observed,
                format!("imports `{}` from {library} ({area})", import.name),
            )
            .evidence(evidence);
            if let Some(&address) = targets.first() {
                finding = finding.at(address);
            }
            section.push(finding);
            self.record(&found, &format!("calls `{}` ({area})", import.name));
        }
        for symbol in &project.binary.symbols {
            if symbol.kind != SymbolKind::Function
                || !project.binary.is_code(symbol.address)
                || seen.contains(symbol.name.as_str())
            {
                continue;
            }
            let Some((area, scope)) = area(&symbol.name) else { continue };
            seen.insert(symbol.name.as_str());
            let mut found = self.users(&[symbol.address]);
            let Some(evidence) = found.evidence_within(scope) else { continue };
            section.push(
                Finding::new(
                    "list_functions",
                    Confidence::Observed,
                    format!("contains function `{}` ({area}), statically linked or local", symbol.name),
                )
                .at(symbol.address)
                .evidence(evidence),
            );
            self.record(&found, &format!("calls `{}` ({area})", symbol.name));
        }
        section
    }

    /// The functions credited with evidence, most evidence first, as the section `title` (each finding says it
    /// "references N items of {what}"), plus their (address, name) in rank order. States in `report` when some
    /// references were cut or unreadable.
    pub(crate) fn finish(
        self,
        report: &mut WorkflowReport,
        title: &str,
        what: &str,
        limits: ReportLimits,
    ) -> (Section, Vec<(u64, String)>) {
        let mut ranked: Vec<(u64, (String, Vec<String>))> = self.users.into_iter().collect();
        ranked.sort_by(|a, b| b.1.1.len().cmp(&a.1.1.len()).then(a.0.cmp(&b.0)));
        let mut section = Section::new(title, limits);
        for (address, (name, evidence)) in &ranked {
            let items = if evidence.len() == 1 { "1 item".to_owned() } else { format!("{} items", evidence.len()) };
            section.push(
                Finding::new("xrefs", Confidence::High, format!("`{name}` references {items} of {what}"))
                    .at(*address)
                    .evidence(evidence.iter().cloned()),
            );
        }
        if self.truncated > 0 {
            report.limitation(format!(
                "References were read up to {REFERENCES_PER_ITEM} per target; {} items had more, so their \
                 referencing functions and counts are incomplete.",
                self.truncated
            ));
        }
        if let Some(error) = self.first_failure {
            report.limitation(format!(
                "References to {} items could not be read (first: {error}); their referencing functions are not \
                 listed.",
                self.failed
            ));
        }
        (section, ranked.into_iter().map(|(address, (name, _))| (address, name)).collect())
    }
}

/// The capability tags `capabilities` holds, as findings that say the building blocks are present, not that the
/// behavior runs.
pub(crate) fn capability_section<'c>(
    title: &str,
    limits: ReportLimits,
    capabilities: impl IntoIterator<Item = &'c Capability>,
) -> Section {
    let mut section = Section::new(title, limits);
    for capability in capabilities {
        section.push(
            Finding::new(
                "capabilities",
                Confidence::Low,
                format!(
                    "building blocks of '{}' ({}) are present; this does not show the behavior executes",
                    capability.name, capability.category
                ),
            )
            .evidence(capability.evidence.iter().cloned()),
        );
    }
    section
}

/// Whether `name` is a default name the analysis made up rather than one the binary or user supplied.
pub fn is_default_name(name: &str, address: u64) -> bool {
    rampage_analysis::functions::is_default_name(name, address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_cap_findings_and_report_truncation() {
        let mut section = Section::new("s", ReportLimits::new(Some(2)));
        for index in 0..5 {
            section.push(Finding::new("test", Confidence::Low, format!("finding {index}")));
        }
        assert_eq!(section.findings.len(), 2);
        assert_eq!(section.total, 5);
        assert!(section.truncated);
    }

    #[test]
    fn evidence_is_capped_with_a_count_of_the_rest() {
        let finding = Finding::new("test", Confidence::Low, "x").evidence((0..20).map(|index| index.to_string()));
        assert_eq!(finding.evidence.len(), MAX_EVIDENCE + 1);
        assert_eq!(finding.evidence.last().unwrap(), "... and 12 more");
    }

    #[test]
    fn evidence_overflow_is_counted_once_across_calls() {
        let finding = Finding::new("test", Confidence::Low, "x")
            .evidence((0..10).map(|index| index.to_string()))
            .evidence(["a", "b", "c"]);
        assert_eq!(finding.evidence.len(), MAX_EVIDENCE + 1);
        assert_eq!(finding.evidence.iter().filter(|item| item.starts_with("... and")).count(), 1);
        assert_eq!(finding.evidence.last().unwrap(), "... and 5 more");
    }

    #[test]
    fn confidence_names_match_the_json() {
        for confidence in [Confidence::Low, Confidence::Medium, Confidence::High, Confidence::Observed] {
            assert_eq!(serde_json::to_value(confidence).unwrap(), confidence.as_str());
        }
    }

    #[test]
    fn api_names_match_across_decorations() {
        assert_eq!(names::import_stem("__imp__exit"), "exit");
        assert_eq!(names::import_stem("getaddrinfo@plt"), "getaddrinfo");
        assert_eq!(names::import_stem("_WinMain@16"), "winmain");
        assert!(api_matches("getprocaddress", "__imp_GetProcAddress"));
        assert!(api_matches("loadlibraryex", "LoadLibraryExA"));
        assert!(api_matches("bcrypt*", "BCryptOpenAlgorithmProvider"));
        assert!(!api_matches("connect", "connected"));
        assert!(!api_matches("send", "sendfile"));
        assert_eq!(match_api(&[("puts", 1), ("put*", 2)], "putchar"), Some(2));
        assert_eq!(match_api(&[("puts", 1)], "printf"), None);
    }

    #[test]
    fn tracing_counts_each_target_once_and_states_cut_references() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
        let project = Project::new(rampage_loaders::Binary::open(path).unwrap());
        let mut report = WorkflowReport::new("test", &project);
        let mut tracer = Tracer::new(&project, &mut report);
        let puts = project.resolve("puts").unwrap();
        let once = tracer.users(&[puts]);
        assert!(once.references > 0);
        assert_eq!(tracer.users(&[puts, puts]).references, once.references);
        assert!(!once.truncated);

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-go-x64.elf");
        let project = Project::new(rampage_loaders::Binary::open(path).unwrap());
        let mut report = WorkflowReport::new("test", &project);
        let mut tracer = Tracer::new(&project, &mut report);
        let analysis = project.analysis().unwrap();
        let busiest = analysis
            .program
            .xrefs
            .iter()
            .map(|xref| xref.to)
            .max_by_key(|&to| project.xrefs(XrefQuery::To(to), None, Some(0)).unwrap().total)
            .unwrap();
        assert!(project.xrefs(XrefQuery::To(busiest), None, Some(0)).unwrap().total > REFERENCES_PER_ITEM);
        let cut = tracer.users(&[busiest]);
        assert!(cut.truncated);
        assert!(cut.evidence()[0].starts_with("at least"), "{:?}", cut.evidence());
        tracer.finish(&mut report, "Functions", "evidence", ReportLimits::default());
        assert!(report.limitations.iter().any(|text| text.contains("1 items had more")), "{:?}", report.limitations);
    }

    #[test]
    fn api_sections_name_the_primitive_and_count_references() {
        let fixture = |name: &str| {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name);
            Project::new(rampage_loaders::Binary::open(path).unwrap())
        };
        let area = |name: &str| (name == "puts" || name == "add").then_some("test");
        for (name, source) in [("hello-x64-dyn.elf", "list_imports"), ("hello-x64.elf", "list_functions")] {
            let project = fixture(name);
            let mut report = WorkflowReport::new("test", &project);
            let mut tracer = Tracer::new(&project, &mut report);
            let section = tracer.api_section("APIs", ReportLimits::default(), area);
            let finding = section.findings.iter().find(|finding| finding.source == source);
            let finding = finding.unwrap_or_else(|| panic!("{name}: {section:#?}"));
            assert!(finding.evidence[0].ends_with("references from discovered functions"), "{finding:#?}");
        }
    }

    #[test]
    fn scoped_apis_are_listed_only_from_functions_in_scope() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf");
        let project = Project::new(rampage_loaders::Binary::open(path).unwrap());
        let mut report = WorkflowReport::new("test", &project);
        let mut tracer = Tracer::new(&project, &mut report);
        let outside = Scope { functions: BTreeSet::from([1]), why: "in scope" };
        let area = |scope| move |name: &str| (name == "puts").then_some(("test", Some(scope)));
        assert_eq!(tracer.api_section_within("APIs", ReportLimits::default(), area(&outside)).total, 0);

        let all = tracer.api_section("APIs", ReportLimits::default(), |name| (name == "puts").then_some("test"));
        let users: BTreeSet<u64> = all.findings[0].evidence[1..]
            .iter()
            .map(|line| u64::from_str_radix(line.rsplit_once("(0x").unwrap().1.trim_end_matches(')'), 16).unwrap())
            .collect();
        let inside = Scope { functions: users.iter().copied().take(1).collect(), why: "in scope" };
        let section = tracer.api_section_within("APIs", ReportLimits::default(), area(&inside));
        let evidence = &section.findings[0].evidence;
        assert_eq!(evidence[1], "in scope", "{evidence:?}");
        assert_eq!(evidence.len(), 3, "only the function in scope is listed: {evidence:?}");
    }

    #[test]
    fn next_steps_past_the_cap_are_counted() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
        let project = Project::new(rampage_loaders::Binary::open(path).unwrap());
        let mut report = WorkflowReport::new("test", &project);
        for index in 0..MAX_NEXT_STEPS + 3 {
            report.step("decompile", serde_json::json!({ "at": index }), "read it");
        }
        report.step("decompile", serde_json::json!({ "at": 0 }), "a duplicate is not a dropped step");
        assert_eq!(report.next_steps.len(), MAX_NEXT_STEPS);
        assert_eq!(report.next_steps_omitted, 3);
        assert_eq!(serde_json::to_value(&report).unwrap()["next_steps_omitted"], 3);
    }

    #[test]
    fn fitting_shrinks_sections_and_keeps_the_rest() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf");
        let project = Project::new(rampage_loaders::Binary::open(path).unwrap());
        let mut report = WorkflowReport::new("test", &project);
        report.summary.push("summary".to_owned());
        report.limitation("limitation");
        let limits = ReportLimits::new(Some(MAX_SECTION_LIMIT));
        for title in ["big", "small"] {
            let mut section = Section::new(title, limits);
            let count = if title == "big" { MAX_SECTION_LIMIT } else { 3 };
            section.extend((0..count).map(|index| Finding::new("test", Confidence::Low, "x".repeat(100 + index))));
            report.sections.push(section);
        }
        let untouched = serde_json::to_string(&report).unwrap();
        report.fit(untouched.len());
        assert_eq!(serde_json::to_string(&report).unwrap(), untouched);

        report.fit(8_000);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.len() <= 8_000, "{}", json.len());
        let big = report.section("big").unwrap();
        assert!(big.truncated && big.total == MAX_SECTION_LIMIT && big.findings.len() < 50);
        assert_eq!(report.section("small").unwrap().findings.len(), 3);
        assert_eq!(report.summary, ["summary"]);
        assert_eq!(report.limitations.len(), 2);
        assert!(report.limitations[1].contains("cut to fit 8000 bytes"));
        assert!(json.find("\"limitations\"").unwrap() < json.find("\"sections\"").unwrap());
    }

    #[test]
    fn limits_are_clamped() {
        assert_eq!(ReportLimits::new(Some(0)).per_section, 1);
        assert_eq!(ReportLimits::new(Some(10_000)).per_section, MAX_SECTION_LIMIT);
        assert_eq!(ReportLimits::default().per_section, DEFAULT_SECTION_LIMIT);
    }

    #[test]
    fn long_quotes_are_cut() {
        let long = "a".repeat(MAX_QUOTE_CHARS + 10);
        assert!(quote(&long).ends_with("..."));
        assert_eq!(quote("short"), "\"short\"");
    }
}
