use super::{
    AnnotationTransition, Effect, Group, Handler, MAX_RESULT_CHARS, SharedResult, Tool, arguments, error_chain, schema,
};
use crate::{ApiError, ExportFormat, ExportImageRequest, IntegrityRequest, Project};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct IntegrityArgs {
    /// Write corrected stored values as byte patches (default false: preview in fix.writes).
    fix: Option<bool>,
    /// Check ids to fix (default: invalid checks of medium or high confidence).
    ids: Option<Vec<usize>>,
    /// Confirm matches by running the image's CRC routine with evaluate_function (default true).
    emulate: Option<bool>,
    /// From receipt, required with fix.
    source_sha256: Option<String>,
    /// From receipt, required with fix.
    expected_revision: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ExportImageArgs {
    /// New file; existing files are never overwritten.
    destination: PathBuf,
    /// `original` (default): the source container (HEX/S-record records, binary file, native file); `binary`: raw
    /// bytes.
    format: Option<String>,
    /// binary: write only the region holding this address (default: all non-RAM regions, gaps filled).
    region: Option<String>,
    /// binary: gap fill byte (default 255).
    fill: Option<u8>,
    /// PE: recompute the optional-header CheckSum.
    pe_checksum: Option<bool>,
    /// Reviewed revision from list_patches; required when patches are active.
    expected_revision: Option<String>,
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::Invalid(message.into())
}

fn bounded(value: serde_json::Value) -> Result<serde_json::Value, ApiError> {
    if value.to_string().len() > MAX_RESULT_CHARS {
        return Err(invalid("result exceeds the output budget"));
    }
    Ok(value)
}

fn tool<A: serde::de::DeserializeOwned + JsonSchema + 'static>(
    name: &'static str,
    description: &'static str,
    effect: Effect,
    run: fn(&mut Arc<Project>, A) -> Result<SharedResult, ApiError>,
) -> Tool {
    Tool {
        group: Group::Formats,
        name,
        description,
        input_schema: schema::<A>(),
        interactive: false,
        effect,
        reads_annotations: true,
        handler: Handler::Shared(Box::new(move |project, input| {
            run(project, arguments(input)?).map_err(|error| error_chain(&error))
        })),
    }
}

pub(super) fn tools() -> Vec<Tool> {
    vec![
        tool(
            "integrity_checks",
            "Find checksum/CRC/digest fields protecting an image (CRC-32 incl. MPEG-2/STM32 words, CRC-16/8, \
             byte/word sums, XOR, Adler-32, Fletcher, SHA-256/MD5): brute-force matches in the original image over \
             layout and code-referenced ranges, CRC tables/polynomials in code, and the image's routine run by \
             emulation. Each check: algorithm, stored address/size/endian, ranges, stored vs computed on the \
             patched image, evidence, confidence. fix: true writes corrected values as patches in dependency order.",
            Effect::Annotations,
            |project, args: IntegrityArgs| {
                let request = IntegrityRequest {
                    emulate: args.emulate.unwrap_or(true),
                    fix: args.fix.unwrap_or(false),
                    ids: args.ids.unwrap_or_default(),
                    source_sha256: args.source_sha256,
                    expected_revision: args.expected_revision,
                };
                let outcome = project.integrity_checks(&request)?;
                let value = bounded(json!(outcome.report))?;
                *project = outcome.project;
                Ok(SharedResult {
                    value,
                    transition: outcome.transition.map(|(before, after)| AnnotationTransition { before, after }),
                })
            },
        ),
        tool(
            "export_image",
            "Write the patched image to a new file in its original format: Intel HEX/S-record with only changed \
             data records re-encoded (layout, address and start records kept), the original binary file with \
             mapped ranges rewritten, or the native file (pe_checksum recomputes a PE CheckSum); or format binary \
             (one region or flat with fill). Reports path, sha256 and regions. Unpatched export equals the input.",
            Effect::FileWrite,
            |project, args: ExportImageArgs| {
                let format = match args.format.as_deref() {
                    None | Some("original") => ExportFormat::Original,
                    Some("binary") => ExportFormat::Binary,
                    Some(other) => return Err(invalid(format!("format {other:?}: original or binary"))),
                };
                let region = args.region.as_deref().map(|text| project.resolve(text)).transpose()?;
                let request = ExportImageRequest {
                    destination: args.destination,
                    format,
                    region,
                    fill: args.fill.unwrap_or(0xff),
                    pe_checksum: args.pe_checksum.unwrap_or(false),
                    expected_revision: args.expected_revision,
                };
                let exported = project.export_image(&request)?;
                bounded(json!(exported)).map(SharedResult::read)
            },
        ),
    ]
}
