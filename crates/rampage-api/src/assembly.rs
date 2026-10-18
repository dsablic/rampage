//! Read-only assembly proposals. Encoding evidence is not execution or permission to install bytes.

use rampage_arch::assemble::{Assembly, MAX_INSTRUCTIONS, MAX_OUTPUT_BYTES, MAX_SOURCE_BYTES};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ApiError, Project};

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssemblyRequest {
    /// Numeric address string or an existing resolvable function/symbol/import/analyst name.
    pub at: String,
    /// Literal assembly, never a filename or shell command. One instruction per nonempty line.
    #[schemars(length(max = 16384))]
    pub source: String,
}

#[derive(Debug, Serialize)]
pub struct AssemblyReport {
    pub architecture: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub instruction_big_endian: bool,
    pub data_big_endian: bool,
    pub bytes_hex: String,
    #[serde(flatten)]
    pub assembly: Assembly,
    pub read_only: bool,
    pub execution_verified: bool,
    pub limitations: &'static [&'static str],
}

impl Project {
    /// Assemble literal source for the current target into an in-memory proposal only.
    /// Resolves the base address, never symbolic operands, and never applies, exports or executes bytes.
    pub fn assemble(&self, request: &AssemblyRequest) -> Result<AssemblyReport, ApiError> {
        if request.source.len() > MAX_SOURCE_BYTES {
            return Err(ApiError::Invalid("assembly line 0: source exceeds 16 KiB".to_owned()));
        }
        let address = self.resolve(&request.at)?;
        let target = self.binary.target();
        let assembly = rampage_arch::assemble::assemble(&target, address, &request.source)
            .map_err(|error| ApiError::Invalid(error.to_string().escape_debug().to_string()))?;
        if assembly.instruction_count > MAX_INSTRUCTIONS || assembly.bytes.len() > MAX_OUTPUT_BYTES {
            return Err(ApiError::Invalid("assembler result exceeds its public instruction/byte limits".to_owned()));
        }
        let report = AssemblyReport {
            architecture: target.arch.to_string(),
            address,
            instruction_big_endian: target.big_endian,
            data_big_endian: target.data_big_endian,
            bytes_hex: rampage_arch::hex::bytes(&assembly.bytes),
            assembly,
            read_only: true,
            execution_verified: false,
            limitations: &[
                "Encoding and canonical decoding are evidence, not execution or ABI/behavior verification.",
                "Proposal only: no source, image, annotation or export bytes were written.",
                "One instruction per line; no labels, comments, directives, memory operands, macros or symbols.",
                "Only the base address resolves names; branch operands must be supported numeric literals.",
            ],
        };
        let json = serde_json::to_vec(&report)
            .map_err(|error| ApiError::Invalid(format!("cannot serialize assembly proposal: {error}")))?;
        if json.len() > 60_000 {
            return Err(ApiError::Invalid("assembly proposal exceeds 60000 JSON bytes; no strings cut".to_owned()));
        }
        Ok(report)
    }
}
