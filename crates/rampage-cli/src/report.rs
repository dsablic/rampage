//! `rampage report`: runs a guided investigation workflow and renders its report.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use rampage_api::{ReportLimits, WorkflowReport};

use crate::commands::{Options, open, write_json};

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Workflow {
    /// One-shot overview with suggested next steps
    TriageReport,
}

pub struct ReportOptions {
    pub other: Option<PathBuf>,
    pub limit: Option<usize>,
}

pub fn report(
    out: &mut impl Write,
    workflow: Workflow,
    path: &Path,
    report_options: &ReportOptions,
    options: &Options,
) -> Result<()> {
    let project = open(path, options)?;
    let limits = ReportLimits::new(report_options.limit);
    let report = match workflow {
        Workflow::TriageReport => {
            if report_options.other.is_some() {
                bail!("--other only applies to diff-builds");
            }
            project.triage_report(limits)?
        }
    };
    if options.json {
        return write_json(out, &report);
    }
    render(out, &report)
}

fn render(out: &mut impl Write, report: &WorkflowReport) -> Result<()> {
    let target = &report.target;
    let entry = target.entry.map_or_else(|| "no entry".to_owned(), |entry| format!("entry {entry:#x}"));
    writeln!(out, "{}: {:?} {}, {entry}, sha256 {}", report.workflow, target.format, target.arch, target.sha256)?;
    if let Some(other) = &report.other {
        writeln!(out, "compared with: {:?} {}, sha256 {}", other.format, other.arch, other.sha256)?;
    }
    writeln!(out)?;
    for line in &report.summary {
        writeln!(out, "  {line}")?;
    }
    for section in &report.sections {
        let shown = if section.truncated {
            format!("{} of {}", section.findings.len(), section.total)
        } else {
            section.total.to_string()
        };
        writeln!(out, "\n== {} ({shown})", section.title)?;
        if section.findings.is_empty() && section.excerpt.is_none() {
            writeln!(out, "  (nothing observed)")?;
        }
        for finding in &section.findings {
            let confidence = serde_json::to_value(finding.confidence)?;
            let at = finding.address.map(|address| format!(" @{address:#x}")).unwrap_or_default();
            writeln!(
                out,
                "  [{}] {}{at}  ({})",
                confidence.as_str().unwrap_or("?"),
                finding.observation,
                finding.source
            )?;
            for evidence in &finding.evidence {
                writeln!(out, "      {evidence}")?;
            }
        }
        if let Some(excerpt) = &section.excerpt {
            writeln!(out, "  --- {} ---", excerpt.source)?;
            for line in excerpt.text.lines() {
                writeln!(out, "  {line}")?;
            }
            if excerpt.truncated {
                writeln!(out, "  ... (cut)")?;
            }
        }
    }
    if !report.next_steps.is_empty() {
        writeln!(out, "\nnext steps:")?;
        for step in &report.next_steps {
            writeln!(out, "  {} {}  -- {}", step.tool, step.arguments, step.reason)?;
        }
    }
    writeln!(out, "\nlimitations:")?;
    for limitation in &report.limitations {
        writeln!(out, "  - {limitation}")?;
    }
    Ok(())
}
