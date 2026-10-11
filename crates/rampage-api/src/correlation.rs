use serde::Serialize;

use crate::{ApiError, Project};
use rampage_loaders::{Binary, Details, Format};

#[derive(Debug, Serialize)]
pub struct RuntimeCorrelation {
    pub module_uuid: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub runtime_address: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub image_address: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub runtime_base: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub image_base: u64,
    pub limitations: Vec<String>,
}

fn uuid(text: &str) -> Option<String> {
    let value = rampage_loaders::snapshot::canonical_module_identity(text);
    (value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())).then(|| value.to_ascii_lowercase())
}

impl Project {
    /// Correlates an explicit captured address with an explicitly opened UUID-matched Mach-O image.
    pub fn correlate_runtime(
        &self,
        module_uuid: &str,
        original: &Binary,
        address: u64,
    ) -> Result<RuntimeCorrelation, ApiError> {
        if self.binary.format != Format::Snapshot || self.binary.arch != original.arch {
            return Err(ApiError::Invalid(
                "correlation requires a snapshot and matching original architecture".to_owned(),
            ));
        }
        let wanted = uuid(module_uuid).ok_or_else(|| ApiError::Invalid("invalid Mach-O module UUID".to_owned()))?;
        let original_uuid = match &original.details {
            Details::MachO(details) => details.uuid.as_deref().and_then(uuid),
            _ => None,
        };
        if original_uuid.as_deref() != Some(&wanted) {
            return Err(ApiError::Invalid("original image UUID does not match selected module".to_owned()));
        }
        let mut matches =
            self.binary.snapshot_modules.iter().filter(|module| uuid(&module.uuid).as_deref() == Some(&wanted));
        let module = matches
            .next()
            .ok_or_else(|| ApiError::NotFound("module UUID is not recorded in the snapshot".to_owned()))?;
        if matches.next().is_some() {
            return Err(ApiError::Invalid("module UUID has ambiguous runtime mappings".to_owned()));
        }
        let image_base = rampage_loaders::snapshot::address(&module.image_base)
            .map_err(|error| ApiError::Invalid(error.to_string()))?;
        let runtime_base = rampage_loaders::snapshot::address(&module.runtime_base)
            .map_err(|error| ApiError::Invalid(error.to_string()))?;
        if !original
            .segments
            .iter()
            .any(|segment| segment.address == image_base && segment.file_offset == 0 && segment.file_size > 0)
        {
            return Err(ApiError::Invalid(
                "recorded original header base does not match the original image".to_owned(),
            ));
        }
        let image_address = address
            .checked_sub(runtime_base)
            .and_then(|offset| image_base.checked_add(offset))
            .ok_or_else(|| ApiError::Invalid("runtime address cannot be mapped without overflow".to_owned()))?;
        if self.binary.read(address, 1).is_none() || original.segment_containing(image_address).is_none() {
            return Err(ApiError::Invalid("address is not captured memory inside the UUID-matched module".to_owned()));
        }
        Ok(RuntimeCorrelation {
            module_uuid: wanted,
            runtime_address: address,
            image_address,
            image_base,
            runtime_base,
            limitations: vec![
                "UUID/header-slide correlation only; runtime bytes may differ from the original image.".to_owned(),
                "No relocation reconstruction, authentication stripping or automatic external-file loading.".to_owned(),
            ],
        })
    }
}
