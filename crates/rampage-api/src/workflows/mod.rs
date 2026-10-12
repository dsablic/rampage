//! Guided investigation workflows: bounded compositions of the analysis primitives into one structured report an
//! agent can act on. Every finding names the primitive and the evidence behind it, every list is capped (and says
//! when it was cut), and every report states its limitations. Reports describe what was observed, never a verdict.

mod diff_builds;
mod find_crypto;
mod find_main;
mod indicators;
mod network_surface;
mod triage_report;

use rampage_arch::Arch;
use rampage_loaders::Format;
use serde::Serialize;
use serde_json::Value;

use crate::Project;

pub use indicators::{Indicator, IndicatorKind, classify};

/// Findings per section unless the caller asks for another count.
pub const DEFAULT_SECTION_LIMIT: usize = 25;
/// The most findings any section may hold, whatever the caller asks for.
pub const MAX_SECTION_LIMIT: usize = 200;
/// Evidence items kept per finding; the rest are counted in a final "... and N more" item.
const MAX_EVIDENCE: usize = 8;
const MAX_NEXT_STEPS: usize = 10;
/// Characters of quoted binary text (strings, names) kept in an observation.
pub const MAX_QUOTE_CHARS: usize = 160;

/// How far a finding can be trusted. `Observed` is read directly from the file's structure (a header field, an
/// import entry, a string's presence); the other levels rate an inference drawn from such observations.
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

/// A follow-up tool call: the tool to run, its arguments (beside the binary's `path`), and why.
#[derive(Debug, Clone, Serialize)]
pub struct NextStep {
    pub tool: &'static str,
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

/// The uniform result of every workflow.
#[derive(Debug, Clone, Serialize)]
pub struct WorkflowReport {
    pub workflow: &'static str,
    pub target: ReportTarget,
    /// The second binary, for workflows that compare two.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other: Option<ReportTarget>,
    pub summary: Vec<String>,
    pub sections: Vec<Section>,
    pub next_steps: Vec<NextStep>,
    pub limitations: Vec<String>,
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
            limitations: Vec::new(),
        }
    }

    /// Suggests a follow-up call, ignoring duplicates and anything past `MAX_NEXT_STEPS`.
    pub fn step(&mut self, tool: &'static str, arguments: Value, reason: impl Into<String>) {
        let duplicate = self.next_steps.iter().any(|step| step.tool == tool && step.arguments == arguments);
        if !duplicate && self.next_steps.len() < MAX_NEXT_STEPS {
            self.next_steps.push(NextStep { tool, arguments, reason: reason.into() });
        }
    }

    pub fn limitation(&mut self, text: impl Into<String>) {
        self.limitations.push(text.into());
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

/// An import or symbol name without the decorations loaders and toolchains add (`__imp_`, an `@plt`, `@16` or
/// `@GLIBC_2.2.5` suffix, leading underscores), lowercased, for matching against the API tables.
pub(crate) fn normalize_api(name: &str) -> String {
    let name = name.strip_prefix("__imp_").unwrap_or(name);
    let name = name.split('@').next().unwrap_or(name);
    name.trim_start_matches('_').to_ascii_lowercase()
}

/// Whether `name` (decorated or not) is the API `pattern` names. A pattern is a lowercase stem that also matches
/// with a Windows `A`/`W` suffix (`connect`, `loadlibrary`), or a prefix ending in `*` (`bcrypt*`).
pub(crate) fn api_matches(pattern: &str, name: &str) -> bool {
    let name = normalize_api(name);
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == pattern || name.strip_suffix(['a', 'w']) == Some(pattern),
    }
}

/// The value of the first `(pattern, value)` entry of `table` that `name` matches (see `api_matches`).
pub(crate) fn match_api<T: Copy>(table: &[(&str, T)], name: &str) -> Option<T> {
    table.iter().find(|(pattern, _)| api_matches(pattern, name)).map(|&(_, value)| value)
}

/// Whether `name` is a default name the analysis made up rather than one the binary or user supplied.
pub fn is_default_name(name: &str) -> bool {
    name.starts_with("sub_")
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
        assert_eq!(normalize_api("__imp__exit"), "exit");
        assert_eq!(normalize_api("getaddrinfo@plt"), "getaddrinfo");
        assert_eq!(normalize_api("_WinMain@16"), "winmain");
        assert!(api_matches("getprocaddress", "__imp_GetProcAddress"));
        assert!(api_matches("loadlibraryex", "LoadLibraryExA"));
        assert!(api_matches("bcrypt*", "BCryptOpenAlgorithmProvider"));
        assert!(!api_matches("connect", "connected"));
        assert!(!api_matches("send", "sendfile"));
        assert_eq!(match_api(&[("puts", 1), ("put*", 2)], "putchar"), Some(2));
        assert_eq!(match_api(&[("puts", 1)], "printf"), None);
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
