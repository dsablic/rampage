//! Ordinary Raw Projects opened from an explicit regular-file range with an asserted closed profile and mapping.
//! The request is an analyst assertion, not header admission; bytes are read once through the checked range source.

use std::path::Path;

use rampage_loaders::{Binary, MAX_RAW_BYTES, MAX_RAW_SEEDS, RawCodeOptions, RawProfile};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::range_source::RangeSource;
use crate::{ApiError, FileOffset};

/// One Raw interpretation of a file range: closed profile, source range, code-space mapping, entry and seeds.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RawProjectRequest {
    /// Closed Raw language ID (any case), or a processor alias such as `msp430`, `avr` or `z80`; not a path,
    /// compiler or ABI selection.
    #[schemars(schema_with = "profile_schema")]
    pub profile: String,
    /// Original-file BYTE offset of the first code byte.
    pub offset: FileOffset,
    /// Exact source byte count, 1..=131072.
    pub length: FileOffset,
    /// Internal code-space BYTE address of the first selected byte, including word-addressed processors.
    pub base_address: FileOffset,
    /// Optional internal code-space BYTE address of the asserted entry; aligned and inside the mapped range.
    #[serde(default)]
    pub entry: Option<FileOffset>,
    /// At most 8192 explicit internal code-space BYTE addresses of function starts inside the mapped range.
    #[serde(default)]
    #[schemars(length(max = 8192))]
    pub seeds: Vec<FileOffset>,
}

fn profile_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let ids: Vec<&str> = RawProfile::ALL.iter().map(|profile| profile.language_id()).collect();
    schemars::json_schema!({
        "type": "string",
        "description": "Closed Raw language ID (any case), or a processor alias such as msp430, avr or z80; not a \
                        path, compiler or ABI selection. ARM/Thumb and x86 code use inspect_raw_code instead.",
        "enum": ids,
    })
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

/// Short names agents use for each Raw profile's processor, lowercased with separators removed.
const PROFILE_ALIASES: [(RawProfile, &[&str]); 16] = [
    (RawProfile::Msp430, &["msp430", "timsp430"]),
    (RawProfile::Avr8, &["avr", "avr8", "atmega", "atmelavr"]),
    (RawProfile::Mos6502, &["6502", "mos6502"]),
    (RawProfile::I8051, &["8051", "i8051", "mcs51", "intel8051"]),
    (RawProfile::Pic16, &["pic16", "pic"]),
    (RawProfile::SuperH2, &["sh2", "superh", "superh2", "sh"]),
    (RawProfile::V850, &["v850", "necv850"]),
    (RawProfile::Tricore, &["tricore", "aurix"]),
    (RawProfile::Xtensa, &["xtensa"]),
    (RawProfile::Z80, &["z80"]),
    (RawProfile::Hcs12, &["hcs12", "s12", "68hc12", "hc12"]),
    (RawProfile::Mc6805, &["6805", "mc6805", "hc05", "68hc05"]),
    (RawProfile::Cr16c, &["cr16c", "cr16"]),
    (RawProfile::Ebpf, &["ebpf", "bpf"]),
    (RawProfile::Loongarch64, &["loongarch64", "loongarch", "la64"]),
    (RawProfile::Hexagon, &["hexagon", "qdsp6"]),
];

/// Names of processors that have no Raw profile because inspect_raw_code decodes them in a headerless file.
const RAW_CODE_ARCHES: [&str; 14] =
    ["arm", "thumb", "cortex", "armv", "aarch", "arm64", "a64", "x86", "x64", "amd64", "i386", "i686", "ia32", "intel"];

/// The closed profile `name` selects: an exact language ID, the same ID in any case, or a processor alias such as
/// `msp430` or `avr`. Otherwise an error naming the closest profiles, or inspect_raw_code for ARM and x86 code.
pub fn resolve_raw_profile(name: &str) -> Result<RawProfile, String> {
    if let Ok(profile) = RawProfile::from_language_id(name) {
        return Ok(profile);
    }
    if let Some(profile) = RawProfile::ALL.into_iter().find(|profile| profile.language_id().eq_ignore_ascii_case(name))
    {
        return Ok(profile);
    }
    let key: String = name.chars().filter(char::is_ascii_alphanumeric).collect::<String>().to_ascii_lowercase();
    if let Some((profile, _)) = PROFILE_ALIASES.iter().find(|(_, aliases)| aliases.contains(&key.as_str())) {
        return Ok(*profile);
    }
    let language_prefix = name.split(':').next().unwrap_or(name).to_ascii_lowercase();
    if let Some((profile, _)) = PROFILE_ALIASES.iter().find(|(profile, _)| {
        profile.language_id().split(':').next().is_some_and(|prefix| prefix.eq_ignore_ascii_case(&language_prefix))
    }) {
        return Err(format!(
            "unsupported Raw profile {name:?}, not a closed Raw language ID or alias; the Raw profile \
             for this processor is {:?}",
            profile.language_id()
        ));
    }
    let profiles: Vec<&str> = RawProfile::ALL.iter().map(|profile| profile.language_id()).collect();
    if RAW_CODE_ARCHES.iter().any(|arch| key.starts_with(arch)) {
        return Err(format!(
            "unsupported Raw profile {name:?}, not a closed Raw language ID: ARM/Thumb (Cortex-M), AArch64 and \
             x86 code have no Raw profile. Decode a headerless file's bytes with inspect_raw_code \
             instead, e.g. {{\"path\":...,\"offset\":0,\"length\":256,\
             \"arch\":\"arm\",\"mode\":\"thumb\",\"code_byte_order\":\"little\",\"data_byte_order\":\"little\",\
             \"base_address\":0}}. Raw profiles: {}",
            profiles.join(", ")
        ));
    }
    let mut ranked: Vec<(usize, &str)> =
        profiles.iter().map(|profile| (edit_distance(&key, &alias_key(profile)), *profile)).collect();
    ranked.sort();
    let closest: Vec<&str> = ranked.iter().take(3).map(|(_, profile)| *profile).collect();
    Err(format!(
        "unsupported Raw profile {name:?}, not a closed Raw language ID or alias; closest: {}. All Raw profiles: {}",
        closest.join(", "),
        profiles.join(", ")
    ))
}

/// The processor part of a language ID as an alias key (`TI_MSP430:LE:16:default` -> `timsp430`).
fn alias_key(language_id: &str) -> String {
    language_id
        .split(':')
        .next()
        .unwrap_or(language_id)
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase()
}

fn edit_distance(left: &str, right: &str) -> usize {
    let right: Vec<char> = right.chars().collect();
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    for (row, left) in left.chars().enumerate() {
        let mut current = vec![row + 1];
        for (column, right) in right.iter().enumerate() {
            let substitution = previous[column] + usize::from(left != *right);
            current.push(substitution.min(previous[column + 1] + 1).min(current[column] + 1));
        }
        previous = current;
    }
    previous[right.len()]
}

impl RawProjectRequest {
    fn options(&self) -> Result<(usize, RawCodeOptions), ApiError> {
        let profile = resolve_raw_profile(&self.profile).map_err(ApiError::Invalid)?;
        let length = usize::try_from(self.length.0)
            .ok()
            .filter(|length| (1..=MAX_RAW_BYTES).contains(length))
            .ok_or_else(|| invalid("Raw length must be 1..=131072 bytes"))?;
        if self.seeds.len() > MAX_RAW_SEEDS {
            return Err(invalid("Raw accepts at most 8192 seeds"));
        }
        self.offset.0.checked_add(length as u64).ok_or_else(|| invalid("Raw source range overflows"))?;
        let options = RawCodeOptions {
            profile,
            base: self.base_address.0,
            entry: self.entry.map(|entry| entry.0),
            seeds: self.seeds.iter().map(|seed| seed.0).collect(),
        };
        Ok((length, options))
    }
}

/// Reads exactly the requested range of a regular, non-symlinked file (revalidated after the read) and admits it
/// as a Raw [`Binary`]. No native header admission, sidecar or annotation log is involved.
pub fn open_raw_binary(path: &Path, request: &RawProjectRequest) -> Result<Binary, ApiError> {
    let (length, options) = request.options()?;
    let source = RangeSource::open(path, request.offset.0, length)?;
    let bytes = source.read()?;
    source.revalidate()?;
    Binary::from_raw_code(bytes, options).map_err(|source| ApiError::Load { path: path.to_owned(), source })
}

/// What to do with a file no native loader recognises: the Raw selectors that read headerless code, with examples.
pub fn headerless_guidance() -> String {
    let profiles: Vec<&str> = RawProfile::ALL.iter().map(|profile| profile.language_id()).collect();
    format!(
        "The file has no recognised executable header; for a headerless image (raw firmware, a memory dump) choose \
         how to read it. ARM/Thumb (Cortex-M), AArch64 and x86 bytes: inspect_raw_code, e.g. {{\"path\":...,\
         \"offset\":0,\"length\":256,\"arch\":\"arm\",\"mode\":\"thumb\",\"code_byte_order\":\"little\",\
         \"data_byte_order\":\"little\",\"base_address\":0}}. Other processors: pass `raw` to a raw-capable tool \
         (binary_info, list_functions, disassemble, decompile, ...), e.g. \"raw\":{{\"profile\":\"msp430\",\
         \"offset\":0,\"length\":4096,\"base_address\":0}}; profiles: {}. carve finds executables embedded in it.",
        profiles.join(", ")
    )
}
