//! `rampage report`: runs a guided investigation workflow and renders its report.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Result, bail};
use clap::ValueEnum;
use clap::builder::PossibleValue;
use rampage_api::workflows::{self, WorkflowOptions};
use rampage_api::{ReportLimits, WorkflowReport};
use rampage_loaders::ImageAt;

use crate::commands::{Options, open, write_json};

/// A registered workflow as `rampage report` names it: its tool name in kebab-case.
#[derive(Clone, Copy)]
pub struct Workflow {
    workflow: &'static dyn workflows::Workflow,
    command: &'static str,
}

impl Workflow {
    pub(crate) fn registered(self) -> &'static dyn workflows::Workflow {
        self.workflow
    }
}

impl clap::ValueEnum for Workflow {
    fn value_variants<'a>() -> &'a [Self] {
        static VARIANTS: OnceLock<Vec<Workflow>> = OnceLock::new();
        VARIANTS.get_or_init(|| {
            workflows::WORKFLOWS
                .iter()
                .map(|&workflow| {
                    // Leaked once per registered workflow: clap takes possible values as static strings.
                    let command: &'static str = Box::leak(workflow.name().replace('_', "-").into_boxed_str());
                    Workflow { workflow, command }
                })
                .collect()
        })
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(PossibleValue::new(self.command).help(self.workflow.summary()))
    }
}

pub struct ReportOptions {
    pub other: Option<PathBuf>,
    /// Where in `other` an embedded image to compare with starts.
    pub other_image: Option<ImageAt>,
    pub limit: Option<usize>,
    pub no_decompile: bool,
    pub component: Option<PathBuf>,
    pub component_worker: Option<PathBuf>,
    pub prepare_analysis: bool,
}

pub fn report(
    out: &mut impl Write,
    workflow: Workflow,
    path: &Path,
    report_options: &ReportOptions,
    options: &Options,
) -> Result<()> {
    if report_options.component.is_some() && workflow.workflow.name() != "triage_report" {
        bail!("--component is supported only for the experimental triage-report workflow");
    }
    if report_options.component.is_none()
        && (report_options.component_worker.is_some() || report_options.prepare_analysis)
    {
        bail!("component preparation and worker options require --component");
    }
    match (workflow.workflow.compares(), &report_options.other) {
        (true, None) => bail!("{} needs --other <file>", workflow.command),
        (true, Some(_)) | (false, None) => {}
        (false, Some(_)) => bail!("--other only applies to {}", comparing_commands()),
    }
    let component = report_options.component.as_deref().map(rampage_api::read_plugin_triage_component).transpose()?;
    let project = if component.is_some() {
        let session = rampage_api::Session::default().with_packs(std::sync::Arc::clone(&options.packs));
        rampage_api::open_plugin_triage_source(&session, path, options.arch, options.image)?
    } else {
        open(path, options)?
    };
    if let Some(component) = component {
        use std::sync::atomic::AtomicBool;

        let worker = match &report_options.component_worker {
            Some(path) => path.clone(),
            None => match std::env::var_os("RAMPAGE_PLUGIN_WORKER") {
                Some(path) => PathBuf::from(path),
                None => std::env::current_exe()?.with_file_name(if cfg!(windows) {
                    "rampage-plugin-worker.exe"
                } else {
                    "rampage-plugin-worker"
                }),
            },
        };
        let config = rampage_api::ComponentPluginConfig::new(worker.canonicalize()?);
        let cancellation = AtomicBool::new(false);
        let mut observer = |_| {};
        let control = rampage_api::ProjectWorkspaceTaskControl::new(&cancellation, &mut observer);
        let limits = ReportLimits::new(report_options.limit);
        let prepared = if report_options.prepare_analysis {
            rampage_api::prepare_plugin_triage_with_analysis(project, limits, &control)?
        } else {
            rampage_api::prepare_plugin_triage(project, limits, &control)?
        };
        let result = prepared.run_component(&component, &config, Some(&cancellation), &control)?;
        return crate::report_plugin::emit(out, result, options.json);
    }
    let run_options = WorkflowOptions {
        limits: ReportLimits::new(report_options.limit),
        decompile: !report_options.no_decompile,
        other: report_options.other.clone(),
        other_image: report_options.other_image,
        evaluate: false,
    };
    let report = workflow.workflow.run(&project, &run_options)?;
    if options.json {
        return write_json(out, &report);
    }
    render(out, &report)
}

/// The workflows taking `--other`, as `rampage report` names them.
fn comparing_commands() -> String {
    let comparing = Workflow::value_variants().iter().filter(|workflow| workflow.workflow.compares());
    comparing.map(|workflow| workflow.command).collect::<Vec<_>>().join(", ")
}

pub(crate) fn render(out: &mut impl Write, report: &WorkflowReport) -> Result<()> {
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
            format!(" (showing {} of {} findings)", section.findings.len(), section.total)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_workflow_is_a_report_value() {
        for &registered in workflows::WORKFLOWS {
            let command = registered.name().replace('_', "-");
            let parsed = Workflow::from_str(&command, false).unwrap();
            assert!(std::ptr::addr_eq(parsed.workflow, registered), "{command}");
            assert_eq!(parsed.to_possible_value().unwrap().get_help().unwrap().to_string(), registered.summary());
        }
        assert_eq!(Workflow::value_variants().len(), workflows::WORKFLOWS.len());
        assert_eq!(comparing_commands(), "diff-builds");
    }
}
