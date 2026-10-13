//! `rampage report`: runs a guided investigation workflow and renders its report.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use rampage_api::{ReportLimits, WorkflowReport};
use rampage_loaders::ImageAt;

use crate::commands::{Options, open, write_json};

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Workflow {
    /// One-shot overview with suggested next steps
    TriageReport,
    /// Locate the program's own entry logic past the runtime startup code
    FindMain,
    /// Networking imports, network-like strings and the functions referencing them
    NetworkSurface,
    /// Algorithm constants, crypto APIs and the functions referencing them
    FindCrypto,
    /// Autostart locations, service/registry APIs and the functions referencing them (indicators, not intent)
    PersistenceSurface,
    /// Candidate string-decoding loops, their call sites and the encoded-looking data passed to them
    StringDecoding,
    /// Compare with another build (--other): matched, changed, added and removed functions
    DiffBuilds,
}

pub struct ReportOptions {
    pub other: Option<PathBuf>,
    /// Where in `other` an embedded image to compare with starts.
    pub other_image: Option<ImageAt>,
    pub limit: Option<usize>,
    pub no_decompile: bool,
}

pub fn report(
    out: &mut impl Write,
    workflow: Workflow,
    path: &Path,
    report_options: &ReportOptions,
    options: &Options,
) -> Result<()> {
    match (workflow, &report_options.other) {
        (Workflow::DiffBuilds, None) => bail!("diff-builds needs --other <file>"),
        (Workflow::DiffBuilds, Some(_)) | (_, None) => {}
        (_, Some(_)) => bail!("--other only applies to diff-builds"),
    }
    let project = open(path, options)?;
    let limits = ReportLimits::new(report_options.limit);
    let report = match (workflow, &report_options.other) {
        (Workflow::TriageReport, _) => project.triage_report(limits)?,
        (Workflow::FindMain, _) => project.find_main(limits, !report_options.no_decompile)?,
        (Workflow::NetworkSurface, _) => project.network_surface(limits)?,
        (Workflow::FindCrypto, _) => project.find_crypto(limits)?,
        (Workflow::PersistenceSurface, _) => project.persistence_surface(limits)?,
        (Workflow::StringDecoding, _) => project.string_decoding(limits)?,
        (Workflow::DiffBuilds, Some(other)) => project.diff_builds_image(other, report_options.other_image, limits)?,
        (Workflow::DiffBuilds, None) => unreachable!("checked before opening the binary"),
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
            format!(" ({} of {})", section.findings.len(), section.total)
        } else if section.excerpt.is_some() && section.total == 0 {
            String::new()
        } else {
            format!(" ({})", section.total)
        };
        writeln!(out, "\n== {}{shown}", section.title)?;
        if section.findings.is_empty() && section.excerpt.is_none() {
            writeln!(out, "  (nothing observed)")?;
        }
        for finding in &section.findings {
            let at = finding.address.map(|address| format!(" @{address:#x}")).unwrap_or_default();
            writeln!(out, "  [{}] {}{at}  ({})", finding.confidence.as_str(), finding.observation, finding.source)?;
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
        if report.next_steps_omitted > 0 {
            writeln!(out, "  ... and {} more not listed", report.next_steps_omitted)?;
        }
    }
    writeln!(out, "\nlimitations:")?;
    for limitation in &report.limitations {
        writeln!(out, "  - {limitation}")?;
    }
    Ok(())
}
