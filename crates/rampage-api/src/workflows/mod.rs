//! Guided investigation workflows: bounded compositions of the analysis primitives into one structured report an
//! agent can act on. Every finding names the primitive and the evidence behind it, every list is capped (and says
//! when it was cut), and every report states its limitations. Reports describe what was observed, never a verdict.

mod find_main;
mod indicators;
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
}

impl Finding {
    pub fn new(source: &'static str, confidence: Confidence, observation: impl Into<String>) -> Self {
        Self { observation: observation.into(), evidence: Vec::new(), source, confidence, address: None }
    }

    pub fn at(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }

    /// Adds evidence, keeping at most `MAX_EVIDENCE` items and counting the rest.
    pub fn evidence<S: Into<String>>(mut self, items: impl IntoIterator<Item = S>) -> Self {
        let mut extra = 0usize;
        for item in items {
            if self.evidence.len() < MAX_EVIDENCE {
                self.evidence.push(item.into());
            } else {
                extra += 1;
            }
        }
        if extra > 0 {
            self.evidence.push(format!("... and {extra} more"));
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
