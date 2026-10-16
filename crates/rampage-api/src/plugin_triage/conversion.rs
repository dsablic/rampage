use rampage_plugin_contract as contract;
use serde_json::json;

use super::{
    MAX_PLUGIN_TRIAGE_REPORT_BYTES, PluginTriageProvenance, PluginTriageReport, PreparedPluginTriage, bounds, invalid,
};
use crate::{ApiError, Finding, FindingConfidence, ReportLimits, ReportTarget, Section, WorkflowReport};

pub(super) fn adopt(
    prepared: &PreparedPluginTriage,
    response: contract::GuestResponse,
    component_sha256: String,
) -> Result<PluginTriageReport, ApiError> {
    if response.schema_version != contract::SCHEMA_VERSION {
        return Err(invalid("unsupported triage component response schema"));
    }
    let body = match response.outcome {
        contract::GuestOutcome::Report { body } => body,
        contract::GuestOutcome::Failure { code } => {
            return Err(ApiError::Unavailable(format!("triage component rejected request: {code:?}")));
        }
    };
    contract::validate_report(&prepared.facts, &body)
        .map_err(|_| invalid("triage component report failed fact-reference or schema validation"))?;
    let report = convert(prepared, body);
    let envelope = PluginTriageReport {
        provenance: PluginTriageProvenance {
            content_authority: "plugin_claims",
            confidence_interpretation: "plugin_claimed_including_observed_not_host_observation",
            component_sha256,
            interface: contract::COMPONENT_INTERFACE,
            source_revalidated_non_atomic: true,
            host_preparation_outside_component_limits: true,
        },
        report,
    };
    // Preserve the entire admitted report or reject it, never byte-truncate JSON or quietly drop suggestions.
    bounds::serialize_bounded(&envelope, MAX_PLUGIN_TRIAGE_REPORT_BYTES)?;
    Ok(envelope)
}

fn convert(prepared: &PreparedPluginTriage, body: contract::ReportBody) -> WorkflowReport {
    let binary = &prepared.project.binary;
    let limits = ReportLimits { per_section: prepared.facts.per_section as usize };
    let mut report = WorkflowReport {
        workflow: "triage_report",
        target: ReportTarget {
            format: binary.format,
            arch: binary.arch,
            entry: binary.entry,
            sha256: rampage_arch::hex::bytes(&prepared.image_sha256),
        },
        other: None,
        summary: body.summary,
        limitations: body.limitations,
        next_steps: Vec::new(),
        next_steps_omitted: body.next_steps_omitted as usize,
        sections: Vec::with_capacity(body.sections.len()),
    };
    for section in body.sections {
        let mut result = Section::new(section.title, limits);
        for finding in section.findings {
            let confidence = match finding.confidence {
                contract::Confidence::Low => FindingConfidence::Low,
                contract::Confidence::Medium => FindingConfidence::Medium,
                contract::Confidence::High => FindingConfidence::High,
                contract::Confidence::Observed => FindingConfidence::Observed,
            };
            let mut result_finding = Finding::new(finding.source.tool(), confidence, finding.observation);
            // Evidence has already been contract-validated, including its optional omission marker.
            result_finding.evidence = finding.evidence;
            result_finding.address = finding.address;
            result.findings.push(result_finding);
        }
        result.total = section.total as usize;
        result.truncated = section.truncated;
        report.sections.push(result);
    }
    for step in body.next_steps {
        let arguments = match &step.action {
            contract::Action::FindMain | contract::Action::DotnetMetadata | contract::Action::NetworkSurface => {
                json!({})
            }
            contract::Action::DotnetIl { method } => json!({ "method": format!("{method:#010x}") }),
            contract::Action::AnalysisDiagnostics { include_discovery } => {
                json!({ "include_discovery": include_discovery })
            }
            contract::Action::IdentifyFunctions { apply } => json!({ "apply": apply }),
            contract::Action::Xrefs { to } => json!({ "to": format!("{to:#x}") }),
        };
        // This constructs an inert WorkflowReport suggestion; it never dispatches any tool.
        let tool = step.action.tool();
        let group = crate::tools::group_of(tool).map(crate::tools::Group::name);
        report.next_steps.push(crate::NextStep { tool, group, arguments, reason: step.reason });
    }
    report
}
