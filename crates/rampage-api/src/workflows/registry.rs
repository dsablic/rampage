//! The workflow registry: every guided workflow implements [`Workflow`] and is listed in [`WORKFLOWS`], from which
//! the tool list (MCP and the UI's assistant) and the CLI's `rampage report` both take them.

use std::path::PathBuf;

use rampage_loaders::ImageAt;
use schemars::JsonSchema;
use serde_json::Value;

use super::{ReportLimits, WorkflowReport};
use crate::tools::Group;
use crate::{ApiError, Project};

/// Everything a workflow run can be given; each workflow reads the options that apply to it.
#[derive(Debug, Clone, Default)]
pub struct WorkflowOptions {
    pub limits: ReportLimits,
    /// Include a bounded decompilation preview (find_main).
    pub decompile: bool,
    /// The second binary, for a workflow that [`Workflow::compares`] two.
    pub other: Option<PathBuf>,
    /// Where in `other` an embedded image to compare with starts.
    pub other_image: Option<ImageAt>,
}

/// A guided workflow: a bounded composition of the analysis primitives into one [`WorkflowReport`].
pub trait Workflow: Sync {
    /// The tool name (`snake_case`); the CLI spells it in kebab-case.
    fn name(&self) -> &'static str;
    /// One line for `rampage report --help`.
    fn summary(&self) -> &'static str;
    /// The tool description a model reads.
    fn description(&self) -> &'static str;
    fn group(&self) -> Group;
    /// The JSON schema of the tool's arguments.
    fn input_schema(&self) -> Value;
    /// The run options the tool's JSON `input` asks for; an error the model can read when it is invalid.
    fn options(&self, input: Value) -> Result<WorkflowOptions, String>;
    /// Whether it compares with a second binary, which it then requires.
    fn compares(&self) -> bool {
        false
    }
    fn run(&self, project: &Project, options: &WorkflowOptions) -> Result<WorkflowReport, ApiError>;
}

/// Every workflow, in the order tools and the CLI list them.
pub static WORKFLOWS: &[&dyn Workflow] = &[
    &super::triage_report::TriageReport,
    &super::find_main::FindMain,
    &super::network_surface::NetworkSurface,
    &super::find_crypto::FindCrypto,
    &super::persistence_surface::PersistenceSurface,
    &super::string_decoding::StringDecoding,
    &super::diff_builds::DiffBuilds,
];

/// The workflow called `name`.
pub fn workflow(name: &str) -> Option<&'static dyn Workflow> {
    WORKFLOWS.iter().copied().find(|workflow| workflow.name() == name)
}

// The arguments of a workflow that takes only the per-section cap. Not a doc comment: the schema would carry it.
#[derive(serde::Deserialize, JsonSchema)]
pub(super) struct ReportArgs {
    /// Findings kept per report section (default 25, at most 200); each section says when it was cut, and large
    /// reports are cut further to fit one tool result.
    max_per_section: Option<usize>,
}

/// The input schema of [`ReportArgs`].
pub(super) fn report_schema() -> Value {
    crate::tools::schema::<ReportArgs>()
}

/// The options [`ReportArgs`] in `input` ask for.
pub(super) fn report_options(input: Value) -> Result<WorkflowOptions, String> {
    let args: ReportArgs = crate::tools::arguments(input)?;
    Ok(WorkflowOptions { limits: ReportLimits::new(args.max_per_section), ..WorkflowOptions::default() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_names_are_unique_snake_case_and_listed_with_their_group() {
        let mut names = std::collections::BTreeSet::new();
        for &registered in WORKFLOWS {
            let name = registered.name();
            assert!(names.insert(name), "{name} is registered twice");
            assert!(name.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_'), "{name}");
            assert!(std::ptr::addr_eq(workflow(name).unwrap(), registered), "{name}");
            assert!(registered.group().description().contains(name), "{name} is missing from its group's description");
            assert!(!registered.summary().is_empty() && !registered.description().is_empty(), "{name}");
            assert!(registered.input_schema()["properties"].is_object(), "{name}");
        }
        assert!(workflow("triage").is_none());
    }

    #[test]
    fn every_workflow_is_a_tool_of_its_group() {
        let tools = crate::tools::tools();
        for workflow in WORKFLOWS {
            let tool = tools.iter().find(|tool| tool.name == workflow.name());
            let tool = tool.unwrap_or_else(|| panic!("{} is not a tool", workflow.name()));
            assert_eq!(tool.group, workflow.group(), "{}", workflow.name());
            assert_eq!(tool.description, workflow.description(), "{}", workflow.name());
            assert_eq!(tool.input_schema, workflow.input_schema(), "{}", workflow.name());
        }
    }

    #[test]
    fn options_parse_each_workflows_arguments() {
        for workflow in WORKFLOWS {
            let mut input = serde_json::json!({ "max_per_section": 3 });
            if workflow.compares() {
                input["other"] = "other.elf".into();
            }
            let options = workflow.options(input).unwrap();
            assert_eq!(options.limits.per_section, 3, "{}", workflow.name());
            assert_eq!(options.other.is_some(), workflow.compares(), "{}", workflow.name());
            let error = workflow.options(serde_json::json!(42)).unwrap_err();
            assert!(error.starts_with("invalid arguments:"), "{error}");
        }
        let diff = workflow("diff_builds").unwrap();
        let error = diff.options(serde_json::json!({ "other": "b", "other_image_length": 16 })).unwrap_err();
        assert_eq!(error, "`other_image_length` needs `other_image_offset`");
        let find_main = workflow("find_main").unwrap();
        assert!(find_main.options(serde_json::json!({})).unwrap().decompile);
        assert!(!find_main.options(serde_json::json!({ "decompile": false })).unwrap().decompile);
    }
}
