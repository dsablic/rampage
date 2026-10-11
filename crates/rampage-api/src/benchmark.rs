use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{ApiError, Project};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceAnalysis {
    pub tool: String,
    pub version: String,
    pub image_sha256: String,
    pub arch: String,
    #[serde(deserialize_with = "bounded_functions")]
    pub functions: Vec<String>,
}

fn bounded_functions<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("at most one million hexadecimal function addresses")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element::<String>()? {
                if values.len() == 1_000_000 || value.len() > 18 {
                    return Err(serde::de::Error::custom("reference function-count or address-length limit exceeded"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Visitor)
}

#[derive(Debug, Serialize)]
pub struct Comparison {
    pub reference_tool: String,
    pub reference_version: String,
    pub matched: usize,
    pub reference_functions: usize,
    pub rampage_functions: usize,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub missing: Vec<u64>,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub extra: Vec<u64>,
    pub limitations: Vec<String>,
}

impl Project {
    pub fn compare_functions(&self, reference: &ReferenceAnalysis) -> Result<Comparison, ApiError> {
        if reference.functions.len() > 1_000_000
            || reference.tool.len() > 256
            || reference.version.len() > 256
            || reference.tool.is_empty()
            || reference.version.is_empty()
            || reference.tool.chars().chain(reference.version.chars()).any(char::is_control)
        {
            return Err(ApiError::Invalid(
                "comparison requires tool/version and at most one million functions".to_owned(),
            ));
        }
        if self.binary.format == rampage_loaders::Format::Snapshot {
            return Err(ApiError::Invalid(
                "snapshot comparisons require mapping-aware identities and are not yet supported".to_owned(),
            ));
        }
        if reference.image_sha256 != self.triage().image_hashes.sha256 || reference.arch != self.binary.arch.to_string()
        {
            return Err(ApiError::Invalid("reference architecture or image SHA-256 does not match".to_owned()));
        }
        let expected: BTreeSet<_> = reference
            .functions
            .iter()
            .map(|value| {
                rampage_loaders::snapshot::address(value).map_err(|error| ApiError::Invalid(error.to_string()))
            })
            .collect::<Result<_, _>>()?;
        // A few reference addresses outside rampage's code ranges are genuine differences (functions rampage
        // did not find or classify as code), counted as missing. A majority out of range means the reference is
        // in a different address space (for example unadjusted ASLR addresses), which is an error, not a result.
        let out_of_range = expected.iter().filter(|&&address| !self.binary.is_code(address)).count();
        if out_of_range * 2 > expected.len() {
            return Err(ApiError::Invalid(
                "most reference addresses are outside executable image ranges; check the address space".to_owned(),
            ));
        }
        let actual: BTreeSet<_> = self.analysis()?.program.functions.iter().map(|function| function.address).collect();
        let mut limitations = vec![
            "Function-start comparison only; reference-tool output is not ground truth.".to_owned(),
            "Matching addresses do not establish matching CFGs, types, semantics or decompilation.".to_owned(),
            "Reference addresses must use this image's address space, not unadjusted runtime ASLR addresses."
                .to_owned(),
        ];
        if out_of_range > 0 {
            limitations.push(format!("{out_of_range} reference addresses are outside rampage's code ranges."));
        }
        Ok(Comparison {
            reference_tool: reference.tool.clone(),
            reference_version: reference.version.clone(),
            matched: actual.intersection(&expected).count(),
            reference_functions: expected.len(),
            rampage_functions: actual.len(),
            missing: expected.difference(&actual).copied().collect(),
            extra: actual.difference(&expected).copied().collect(),
            limitations,
        })
    }
}
