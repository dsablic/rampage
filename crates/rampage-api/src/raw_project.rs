//! Ordinary Raw Projects opened from an explicit regular-file range with an asserted closed profile and mapping.
//! The request is an analyst assertion, not header admission; bytes are read once through the checked range source.

use std::path::Path;

use rampage_loaders::{Binary, MAX_RAW_SEEDS, RawCodeOptions, RawProfile};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer};

use crate::range_source::RangeSource;
use crate::{ApiError, FileOffset};

/// One Raw interpretation of a file range: closed profile, source range, code-space mapping, entry and seeds.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RawProjectRequest {
    /// Closed Raw language ID (any case), or a processor alias such as `msp430`, `avr`, `z80` or `cortex-m4`;
    /// not a path, compiler or ABI selection.
    #[schemars(schema_with = "profile_schema")]
    pub profile: String,
    /// Original-file BYTE offset of the first code byte.
    pub offset: FileOffset,
    /// Exact source byte count: 1..=131072, or 1..=4194304 for ARM:LE:32:Cortex.
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
    /// ARM:LE:32:Cortex only: `true` reads a Cortex-M vector table at base_address, or give its code-space BYTE
    /// address. Accepted Thumb handlers become the entry (Reset, unless `entry` is given) and seeds; every word
    /// read is reported with its verdict in binary_info.
    #[serde(default, deserialize_with = "vector_table")]
    #[schemars(schema_with = "vector_table_schema")]
    pub vector_table: Option<RawVectorTable>,
}

/// Where to read a Cortex-M vector table from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawVectorTable {
    /// At base_address, the start of the mapped range.
    AtBase,
    /// At this code-space byte address.
    At(u64),
}

fn vector_table<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<RawVectorTable>, D::Error> {
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Null | serde_json::Value::Bool(false) => Ok(None),
        serde_json::Value::Bool(true) => Ok(Some(RawVectorTable::AtBase)),
        value => serde_json::from_value::<FileOffset>(value)
            .map(|address| Some(RawVectorTable::At(address.0)))
            .map_err(|error| serde::de::Error::custom(format!("vector_table: true, false or an address: {error}"))),
    }
}

fn vector_table_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "description": "ARM:LE:32:Cortex only: true reads a Cortex-M vector table at base_address, or give its \
                        code-space BYTE address. Accepted Thumb handlers become the entry and seeds.",
        "anyOf": [{ "type": "boolean" }, { "type": "integer", "minimum": 0 }, { "type": "string" }, { "type": "null" }]
    })
}

fn profile_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let ids: Vec<&str> = RawProfile::ALL.iter().map(|profile| profile.language_id()).collect();
    schemars::json_schema!({
        "type": "string",
        "description": "Closed Raw language ID (any case), or a processor alias such as msp430, avr, z80 or \
                        cortex-m4; not a path, compiler or ABI selection. A-profile ARM, AArch64 and x86 code use \
                        inspect_raw_code instead.",
        "enum": ids,
    })
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

/// Short names agents use for each Raw profile's processor, lowercased with separators removed.
const PROFILE_ALIASES: [(RawProfile, &[&str]); 17] = [
    (RawProfile::Msp430, &["msp430", "timsp430"]),
    (RawProfile::Avr8, &["avr", "avr8", "atmega", "atmelavr"]),
    (RawProfile::Mos6502, &["6502", "mos6502"]),
    (RawProfile::I8051, &["8051", "i8051", "mcs51", "intel8051"]),
    (RawProfile::Pic16, &["pic16"]),
    (RawProfile::SuperH2, &["sh2", "superh2"]),
    (RawProfile::V850, &["v850", "necv850"]),
    (RawProfile::Tricore, &["tricore", "aurix"]),
    (RawProfile::Xtensa, &["xtensa"]),
    (RawProfile::Z80, &["z80"]),
    (RawProfile::Hcs12, &["hcs12", "s12", "68hc12", "hc12"]),
    (RawProfile::Mc6805, &["6805", "mc6805", "hc05", "68hc05"]),
    (RawProfile::Cr16c, &["cr16c"]),
    (RawProfile::Ebpf, &["ebpf"]),
    (RawProfile::Loongarch64, &["loongarch64", "loongarch", "la64"]),
    (RawProfile::Hexagon, &["hexagon", "qdsp6"]),
    (
        RawProfile::CortexM,
        &[
            "cortexm",
            "cortexm0",
            "cortexm0plus",
            "cortexm1",
            "cortexm3",
            "cortexm4",
            "cortexm4f",
            "cortexm7",
            "armcortexm",
            "thumb",
            "thumb2",
            "armthumb",
            "armv6m",
            "armv7m",
            "armv7em",
            "thumbv6m",
            "thumbv7m",
            "thumbv7em",
        ],
    ),
];

/// Families agents name that no Raw profile covers, though a profile's name may look close (PIC32 is MIPS, not
/// PIC-16).
const UNPROFILED_FAMILIES: [&str; 14] = [
    "pic10", "pic12", "pic17", "pic18", "pic24", "pic32", "dspic", "mips", "riscv", "rv32", "rv64", "ppc", "powerpc",
    "sparc",
];

/// Names of processors that have no Raw profile because inspect_raw_code decodes them in a headerless file. Cortex-M
/// aliases resolve before this list is consulted.
const RAW_CODE_ARCHES: [&str; 13] =
    ["arm", "cortex", "armv", "aarch", "arm64", "a64", "x86", "x64", "amd64", "i386", "i686", "ia32", "intel"];

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
    let profiles: Vec<&str> = RawProfile::ALL.iter().map(|profile| profile.language_id()).collect();
    // Another variant, byte order or size of a profiled processor is not covered: say so rather than offer the
    // profile, which would decode different instructions.
    let language_prefix = name.split(':').next().unwrap_or(name);
    if name.contains(':')
        && let Some(profile) = RawProfile::ALL.into_iter().find(|profile| {
            profile.language_id().split(':').next().is_some_and(|prefix| prefix.eq_ignore_ascii_case(language_prefix))
        })
    {
        return Err(format!(
            "unsupported Raw profile {name:?}: no Raw profile covers this variant; the only {language_prefix} \
             profile is {:?}. All Raw profiles: {}",
            profile.language_id(),
            profiles.join(", ")
        ));
    }
    if UNPROFILED_FAMILIES.iter().any(|family| key.starts_with(family)) {
        return Err(format!(
            "unsupported Raw profile {name:?}: no Raw profile covers this processor. All Raw profiles: {}",
            profiles.join(", ")
        ));
    }
    if RAW_CODE_ARCHES.iter().any(|arch| key.starts_with(arch)) {
        return Err(format!(
            "unsupported Raw profile {name:?}, not a closed Raw language ID: Cortex-M (ARMv6-M/ARMv7-M Thumb) \
             code uses the ARM:LE:32:Cortex profile (alias cortex-m), e.g. \"raw\":{{\"profile\":\"cortex-m\",\
             \"offset\":0,\"length\":...,\"base_address\":\"0x8000000\",\"vector_table\":true}}. A-profile \
             ARM, AArch64 and x86 code have no Raw profile: decode a headerless file's bytes with \
             inspect_raw_code instead, e.g. {{\"path\":...,\"offset\":0,\"length\":256,\
             \"arch\":\"arm\",\"mode\":\"thumb\",\"code_byte_order\":\"little\",\"data_byte_order\":\"little\",\
             \"base_address\":0}}. Raw profiles: {}",
            profiles.join(", ")
        ));
    }
    let mut ranked: Vec<(usize, &str)> = PROFILE_ALIASES
        .iter()
        .map(|(profile, aliases)| {
            let language = profile.language_id();
            let distance = aliases
                .iter()
                .map(|alias| edit_distance(&key, alias))
                .chain([edit_distance(&key, &alias_key(language))])
                .min()
                .unwrap_or(usize::MAX);
            (distance, language)
        })
        .collect();
    ranked.sort();
    // Only near spellings are offered; a distant name gets the full list alone.
    let near = (key.len() / 3).max(2);
    let closest: Vec<&str> =
        ranked.iter().take_while(|(distance, _)| *distance <= near).take(3).map(|(_, profile)| *profile).collect();
    let closest = if closest.is_empty() { String::new() } else { format!("; closest: {}", closest.join(", ")) };
    Err(format!(
        "unsupported Raw profile {name:?}, not a closed Raw language ID or alias{closest}. All Raw profiles: {}",
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
        let max = profile.max_bytes();
        let length =
            usize::try_from(self.length.0).ok().filter(|length| (1..=max).contains(length)).ok_or_else(|| {
                ApiError::Invalid(format!("Raw length must be 1..={max} bytes for {}", profile.language_id()))
            })?;
        if self.seeds.len() > MAX_RAW_SEEDS {
            return Err(invalid("Raw accepts at most 8192 seeds"));
        }
        self.offset.0.checked_add(length as u64).ok_or_else(|| invalid("Raw source range overflows"))?;
        let options = RawCodeOptions {
            profile,
            base: self.base_address.0,
            entry: self.entry.map(|entry| entry.0),
            seeds: self.seeds.iter().map(|seed| seed.0).collect(),
            vector_table: self.vector_table.map(|table| match table {
                RawVectorTable::AtBase => self.base_address.0,
                RawVectorTable::At(address) => address,
            }),
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
         how to read it. Pass `raw` to a raw-capable tool (binary_info, list_functions, disassemble, decompile, ...), \
         e.g. \"raw\":{{\"profile\":\"msp430\",\"offset\":0,\"length\":4096,\"base_address\":0}}, or for a \
         Cortex-M flash image \"raw\":{{\"profile\":\"cortex-m\",\"offset\":0,\"length\":...,\
         \"base_address\":\"0x8000000\",\"vector_table\":true}}; profiles: {}. A-profile ARM, AArch64 and x86 bytes: \
         inspect_raw_code, e.g. {{\"path\":...,\"offset\":0,\"length\":256,\"arch\":\"arm\",\"mode\":\"thumb\",\
         \"code_byte_order\":\"little\",\"data_byte_order\":\"little\",\"base_address\":0}}. carve finds \
         executables embedded in it.",
        profiles.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review of the benchmark v2 fixes: ambiguous aliases and hints offered a profile for another variant.
    #[test]
    fn aliases_select_one_profile_and_other_variants_are_not_offered_one() {
        assert_eq!(resolve_raw_profile("msp430"), Ok(RawProfile::Msp430));
        assert_eq!(resolve_raw_profile("TI_MSP430:le:16:DEFAULT"), Ok(RawProfile::Msp430));
        for ambiguous in ["pic", "sh", "superh", "bpf", "cr16"] {
            assert!(resolve_raw_profile(ambiguous).is_err(), "{ambiguous}");
        }
        for variant in ["SuperH:LE:32:SH-4", "Xtensa:BE:32:default", "avr8:LE:16:extended"] {
            let error = resolve_raw_profile(variant).unwrap_err();
            assert!(error.contains("no Raw profile covers this variant"), "{error}");
        }
        for family in ["pic32", "PIC32MX", "mips32", "riscv32"] {
            let error = resolve_raw_profile(family).unwrap_err();
            assert!(error.contains("no Raw profile covers this processor") && !error.contains("closest"), "{error}");
        }
        assert!(resolve_raw_profile("msp431").unwrap_err().contains("closest: TI_MSP430:LE:16:default"));
        let aliases =
            ["cortex-m3", "Cortex-M4", "CORTEX-M0+", "thumb", "armv7m", "ARMv6-M", "arm:le:32:cortex", "thumbv7em"];
        for alias in aliases.into_iter().chain(["thumbv6m", "thumbv7m"]) {
            assert_eq!(resolve_raw_profile(alias), Ok(RawProfile::CortexM), "{alias}");
        }
        // Another ARM variant names the one ARM profile; A-profile ARM and AArch64 point at inspect_raw_code.
        assert!(resolve_raw_profile("ARM:LE:32:v8").unwrap_err().contains("the only ARM profile is"));
        for other in ["arm", "armv7a", "cortex-a53", "aarch64", "cortex-m33", "cortex-m55"] {
            let error = resolve_raw_profile(other).unwrap_err();
            assert!(error.contains("inspect_raw_code") && error.contains("ARM:LE:32:Cortex"), "{error}");
        }
    }
}
