use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ApiError, FunctionInventoryCacheKey, FunctionInventoryCacheRow, MAX_ROWS, invalid};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Document {
    pub version: String,
    pub key: FunctionInventoryCacheKey,
    pub total_functions: u64,
    pub truncated: bool,
    pub rows: Vec<FunctionInventoryCacheRow>,
    pub payload_sha256: String,
}

impl Document {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.version != "FunctionInventoryCacheV0"
            || !self.key.supported()
            || self.rows.len() > MAX_ROWS
            || self.total_functions < self.rows.len() as u64
            || self.truncated != (self.total_functions > self.rows.len() as u64)
            || self.payload_sha256 != payload_digest(&self.key, self.total_functions, self.truncated, &self.rows)?
        {
            return Err(invalid("inventory cache schema, counts or checksum rejected"));
        }
        let mut previous = None;
        for row in &self.rows {
            let address = parse_address(&row.address)?;
            if previous.is_some_and(|previous| previous >= address) || row.name.len() > 4096 {
                return Err(invalid("inventory cache row order or name rejected"));
            }
            previous = Some(address);
        }
        Ok(())
    }
}

impl FunctionInventoryCacheKey {
    fn supported(&self) -> bool {
        self.decoder == "rampage-decoder-target-v1"
            && self.discovery == "rampage-recursive-global-noreturn-v1"
            && self.naming == "rampage-default-namer-rendered-v1"
            && [&self.source_sha256, &self.image_sha256, &self.context_sha256, &self.names_sha256].into_iter().all(
                |hash| {
                    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                },
            )
    }
}

pub(super) fn payload_digest(
    key: &FunctionInventoryCacheKey,
    total: u64,
    truncated: bool,
    rows: &[FunctionInventoryCacheRow],
) -> Result<String, ApiError> {
    let mut hash = Sha256::new();
    hash.update(b"FunctionInventoryCacheV0.payload\0");
    for field in [
        &key.source_sha256,
        &key.image_sha256,
        &key.context_sha256,
        &key.names_sha256,
        &key.decoder,
        &key.discovery,
        &key.naming,
    ] {
        hash.update((field.len() as u64).to_le_bytes());
        hash.update(field.as_bytes());
    }
    hash.update(total.to_le_bytes());
    hash.update([u8::from(truncated)]);
    hash.update((rows.len() as u64).to_le_bytes());
    for row in rows {
        parse_address(&row.address)?;
        hash.update((row.address.len() as u64).to_le_bytes());
        hash.update(row.address.as_bytes());
        hash.update((row.name.len() as u64).to_le_bytes());
        hash.update(row.name.as_bytes());
        hash.update(row.size.to_le_bytes());
        hash.update(row.block_count.to_le_bytes());
        hash.update(row.instruction_count.to_le_bytes());
    }
    Ok(rampage_arch::hex::bytes(&hash.finalize()))
}

pub(super) fn parse_address(text: &str) -> Result<u64, ApiError> {
    let digits = text.strip_prefix("0x").ok_or_else(|| invalid("inventory address is not canonical"))?;
    if digits.is_empty()
        || digits.len() > 16
        || digits.len() > 1 && digits.starts_with('0')
        || !digits.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("inventory address is not canonical"));
    }
    u64::from_str_radix(digits, 16).map_err(|_| invalid("inventory address exceeds u64"))
}
