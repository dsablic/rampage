use super::{Effect, Group, Handler, MAX_RESULT_CHARS, SharedResult, Tool, arguments, error_chain, schema};
use crate::{ApiError, Project};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct PatchArgs {
    /// Address or retained name resolved against the current effective snapshot.
    at: String,
    /// Explicit original-source bytes, not bytes from an existing patch. Lowercase contiguous hex, 1..4096 bytes.
    original_hex: String,
    /// Equal-length replacement bytes. No assembly or execution is performed.
    replacement_hex: String,
    /// Explicit consent to patch eligible data payload in addition to executable payload.
    allow_data: bool,
    /// Original source SHA-256 copied from list_patches.receipt.
    source_sha256: String,
    /// Reviewed patch-set revision copied from list_patches.receipt.
    expected_revision: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RevertArgs {
    /// Exact start address or retained name of the active patch.
    at: String,
    source_sha256: String,
    expected_revision: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    offset: Option<usize>,
    /// At most 100 records, additionally bounded by the complete JSON byte budget.
    #[schemars(range(min = 1, max = 100))]
    limit: Option<usize>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ExportArgs {
    /// New destination file. Existing files, including the original source, are never overwritten.
    destination: PathBuf,
    source_sha256: String,
    /// Exact reviewed patch revision; checked again by the exporter under the annotation writer lock.
    expected_revision: String,
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::Invalid(message.into())
}

fn hex_bytes(text: &str) -> Result<Vec<u8>, ApiError> {
    if text.is_empty()
        || text.len() > 8192
        || !text.len().is_multiple_of(2)
        || !text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("patch bytes require 1..4096 bytes of contiguous lowercase even-length hex"));
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte: u8| if byte <= b'9' { byte - b'0' } else { byte - b'a' + 10 };
            Ok((digit(pair[0]) << 4) | digit(pair[1]))
        })
        .collect()
}

fn reviewed(project: &Arc<Project>, source: &str, revision: &str) -> Result<crate::PatchReceipt, ApiError> {
    let receipt = project.patch_receipt()?;
    if receipt.source_sha256 != source || receipt.revision_sha256 != revision {
        return Err(invalid("source or patch revision differs from review; acquire a new list_patches receipt"));
    }
    Ok(receipt)
}

fn bounded(value: Value) -> Result<Value, ApiError> {
    if value.to_string().len() > MAX_RESULT_CHARS {
        return Err(invalid("patch JSON exceeds the complete output budget; narrow the page or destination"));
    }
    Ok(value)
}

fn mutation_preflight(receipt: crate::PatchReceipt) -> Result<(), ApiError> {
    let mut value = json!({ "changed": false, "receipt": receipt });
    value["receipt"]["active_ranges"] = json!(usize::MAX);
    value["receipt"]["changed_bytes"] = json!(usize::MAX);
    bounded(value).map(|_| ())
}

fn shared<A: serde::de::DeserializeOwned + JsonSchema + 'static>(
    name: &'static str,
    description: &'static str,
    effect: Effect,
    run: fn(&mut Arc<Project>, A) -> Result<SharedResult, ApiError>,
) -> Tool {
    Tool {
        group: Group::Core,
        name,
        description,
        input_schema: schema::<A>(),
        interactive: false,
        effect,
        reads_annotations: true,
        handler: Handler::Shared(Box::new(move |project, input| {
            if input.to_string().len() > 24_000 {
                return Err("patch arguments exceed the input byte budget".into());
            }
            run(project, arguments(input)?).map_err(|error| error_chain(&error))
        })),
    }
}

pub(super) fn tools() -> Vec<Tool> {
    vec![
        shared(
            "patch_bytes",
            "Persist a bounded equal-length byte patch in the existing annotation history and return an effective \
             revision receipt. Requires explicit original-source preimage, source hash, reviewed revision and \
             allow_data consent. Only whole-file little-endian ELF64 x86-64/AArch64 payloads and Raw project \
             regions; no headers, captured/debugger memory writes, execution, assembly or source-file \
             modification. Read list_patches first.",
            Effect::Annotations,
            |project, args: PatchArgs| {
                let original = hex_bytes(&args.original_hex)?;
                let replacement = hex_bytes(&args.replacement_hex)?;
                let address = project.resolve(&args.at)?;
                mutation_preflight(reviewed(project, &args.source_sha256, &args.expected_revision)?)?;
                let outcome = project.patch_bytes_reviewed(
                    address,
                    &original,
                    &replacement,
                    args.allow_data,
                    &args.source_sha256,
                    &args.expected_revision,
                )?;
                let value = bounded(json!({ "changed": outcome.changed, "receipt": outcome.receipt }))?;
                let result = SharedResult::patch(value, &outcome);
                *project = outcome.project;
                Ok(result)
            },
        ),
        shared(
            "revert_patch",
            "Remove one exact-start active byte patch through annotation history. Requires explicit source and \
             reviewed revision. Returns an effective revision receipt; does not write the original file.",
            Effect::Annotations,
            |project, args: RevertArgs| {
                let address = project.resolve(&args.at)?;
                mutation_preflight(reviewed(project, &args.source_sha256, &args.expected_revision)?)?;
                let outcome = project.revert_patch_reviewed(address, &args.source_sha256, &args.expected_revision)?;
                let value = bounded(json!({ "changed": outcome.changed, "receipt": outcome.receipt }))?;
                let result = SharedResult::patch(value, &outcome);
                *project = outcome.project;
                Ok(result)
            },
        ),
        shared(
            "list_patches",
            "Page active original-image-bound byte patches and obtain a source/effective/revision hash receipt for \
             explicit patch or export review. Whole records and valid JSON only; follow next_offset for more.",
            Effect::None,
            |project, args: ListArgs| {
                let limit = args.limit.unwrap_or(100);
                if !(1..=100).contains(&limit) {
                    return Err(invalid("patch page limit must be 1..100"));
                }
                let receipt = project.patch_receipt()?;
                let patches = project.list_patches()?;
                let offset = args.offset.unwrap_or(0).min(patches.len());
                let mut page = json!({
                    "receipt": receipt, "patches": [], "total": patches.len(), "offset": offset,
                    "next_offset": Value::Null,
                });
                for patch in patches.iter().skip(offset).take(limit) {
                    page["patches"].as_array_mut().unwrap().push(json!(patch));
                    let end = offset + page["patches"].as_array().unwrap().len();
                    page["next_offset"] = if end < patches.len() { json!(end) } else { Value::Null };
                    if page.to_string().len() > MAX_RESULT_CHARS {
                        page["patches"].as_array_mut().unwrap().pop();
                        page["next_offset"] = json!(end - 1);
                        break;
                    }
                }
                bounded(page).map(SharedResult::read)
            },
        ),
        shared(
            "export_patched",
            "Create a new file containing the reviewed effective bytes, without overwriting any file or copying \
             annotations. Requires explicit destination, original source SHA-256 and expected revision from \
             list_patches. No execution or in-place source mutation; stale revision refuses before file creation.",
            Effect::FileWrite,
            |project, args: ExportArgs| {
                let receipt = reviewed(project, &args.source_sha256, &args.expected_revision)?;
                bounded(json!({ "path": args.destination, "receipt": receipt }))?;
                let exported = project.export_patched(&args.destination, &args.expected_revision)?;
                bounded(json!(exported)).map(SharedResult::read)
            },
        ),
    ]
}
