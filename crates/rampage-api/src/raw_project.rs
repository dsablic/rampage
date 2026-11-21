//! Ordinary Raw Projects opened from an explicit regular-file range with an asserted closed profile and mapping.
//! The request is an analyst assertion, not header admission; bytes are read once through the checked range source.
//! Further regions of the same file (a later stage at its RAM base, constant data, RAM, a decoder provider's
//! transient output) and Intel HEX or S-record input map into the same project.

use std::path::Path;

use rampage_loaders::raw_records::{MAX_RAW_RECORD_TEXT_BYTES, RawRecordFormat, parse_raw_records};
use rampage_loaders::{
    Binary, MAX_RAW_REGIONS, MAX_RAW_SEEDS, RawCodeOptions, RawImage, RawProfile, RawRecordFacts, RawRegion,
    RawRegionKind, RawRegionSource,
};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer};

use crate::range_source::RangeSource;
use crate::{ApiError, FileOffset};

/// Largest file `format: esp` reads: a 16 MiB flash dump.
const MAX_ESP_FILE_BYTES: usize = 16 * 1024 * 1024;
/// Where the ESP8266's cache maps flash offset 0.
const ESP8266_IROM_BASE: u64 = 0x4020_0000;
/// Flash bytes the ESP8266's cache maps from there.
const ESP8266_IROM_WINDOW: usize = 0x10_0000;
/// The prefix of a file read for ESP guidance: the bootloader and the partition table lie in the first 64 KiB.
const ESP_GUIDANCE_PREFIX: u64 = 0x1_0000;

/// One Raw interpretation of a file range: closed profile, source range, code-space mapping, entry and seeds.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RawProjectRequest {
    /// Closed Raw language ID (any case), or a processor alias such as `msp430`, `avr`, `z80` or `cortex-m4`;
    /// not a path, compiler or ABI selection.
    #[schemars(schema_with = "profile_schema")]
    pub profile: String,
    /// How the file states its bytes: `binary` (the default) maps the offset/length range at base_address;
    /// `ihex` (Intel HEX) and `srec` (Motorola S-records) take every address from the file's data records, so
    /// offset, length and base_address are then omitted. Each contiguous run of records is one code region, the
    /// lowest the primary one; a start-address record becomes the entry unless `entry` or the vector table's Reset
    /// names another address, and binary_info reports the verdict on it.
    #[serde(default, deserialize_with = "format")]
    #[schemars(schema_with = "format_schema")]
    pub format: RawInputFormat,
    /// Original-file BYTE offset of the first code byte (default 0).
    #[serde(default)]
    pub offset: Option<FileOffset>,
    /// Exact source byte count: 1..=131072, or 1..=4194304 for ARM:LE:32:Cortex, MIPS and Xtensa (with
    /// `decode`, the encoded count, at most 8 MiB). Default: the rest of the file from offset.
    #[serde(default)]
    pub length: Option<FileOffset>,
    /// Map a decoder provider's output over offset/length as the primary code region instead of the range itself,
    /// e.g. a compressed application image: vector_table, pointer_tables and seeds then read the decoded bytes,
    /// whose size (expected_output_size) obeys the length cap above. Parameters as a region's `decode` or
    /// probe_compression's decode_arguments; binary_info reports the decode receipt with the region.
    #[serde(default)]
    pub decode: Option<RawRegionDecode>,
    /// Internal code-space BYTE address of the first selected byte, including word-addressed processors. Required
    /// for the `binary` format.
    #[serde(default)]
    pub base_address: Option<FileOffset>,
    /// Optional internal code-space BYTE address of the asserted entry; aligned and inside the mapped range. The
    /// MIPS profiles default it to base_address (a boot ROM's reset vector).
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
    /// ARM:LE:32:Cortex only: `true` scans the image for tables of Thumb code pointers (handler arrays, command
    /// tables) and seeds the targets of the tables it accepts; every table found, accepted or refused, is reported
    /// with the evidence per entry in binary_info. `false` never scans. Unset (automatic) scans only when discovery
    /// from the entry, seeds, vector table and scatter-load jump finds fewer than one function per 16 KiB of code,
    /// and binary_info and list_functions then say so.
    #[serde(default)]
    #[schemars(schema_with = "pointer_tables_schema")]
    pub pointer_tables: Option<bool>,
    /// ARM:LE:32:Cortex only: the reset code at the entry is followed (a bounded interpreter, nothing runs) for the
    /// sections startup code copies to their run addresses and the RAM it zeroes; binary_info reports each with its
    /// evidence. By default each complete copy from mapped bytes to an unmapped destination is mapped there (code,
    /// or RAM for data) and the jump into copied code is seeded; `false` reports them only.
    #[serde(default)]
    #[schemars(schema_with = "scatter_load_schema")]
    pub scatter_load: Option<bool>,
    /// ARM:LE:32:Cortex, MIPS and Xtensa only: up to 15 further regions of the same file mapped beside the primary code
    /// region, e.g. a second stage at its RAM base, constant data, or RAM. Regions never overlap; references between them
    /// resolve, entry and seeds may lie in any code region, and binary_info reports each region with its source
    /// range and SHA-256. vector_table reads the primary region only, pointer_tables every code region. All backed regions
    /// together hold at most 4194304 bytes.
    #[serde(default, deserialize_with = "regions")]
    #[schemars(length(max = 15))]
    pub regions: Vec<RawRegionRequest>,
}

/// How a Raw request's file states its bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RawInputFormat {
    #[default]
    Binary,
    Ihex,
    Srec,
    /// An Espressif app image (magic 0xE9) at `offset` (default 0): every segment mapped at its load address.
    Esp,
}

fn format<'de, D: Deserializer<'de>>(deserializer: D) -> Result<RawInputFormat, D::Error> {
    let name = Option::<String>::deserialize(deserializer)?;
    // `raw` and `bin` are what agents call a flat binary.
    match name.as_deref().map(str::to_ascii_lowercase).as_deref() {
        None | Some("binary" | "raw" | "bin") => Ok(RawInputFormat::Binary),
        Some("ihex") => Ok(RawInputFormat::Ihex),
        Some("srec") => Ok(RawInputFormat::Srec),
        Some("esp") => Ok(RawInputFormat::Esp),
        _ => Err(serde::de::Error::custom(format!("format {:?}: binary, ihex, srec or esp", name.unwrap_or_default()))),
    }
}

fn format_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "description": "binary (default) maps offset/length at base_address; ihex (Intel HEX) and srec (Motorola \
                        S-records) take addresses from the records, so offset, length and base_address are omitted; \
                        esp maps the ESP32/ESP8266 app image at offset (default 0) by its segment headers.",
        "type": ["string", "null"],
        "enum": ["binary", "ihex", "srec", "esp", null]
    })
}

fn regions<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<RawRegionRequest>, D::Error> {
    Ok(Option::<Vec<RawRegionRequest>>::deserialize(deserializer)?.unwrap_or_default())
}

/// One further region of a Raw project: what it holds, where it is mapped and where its bytes come from.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RawRegionRequest {
    /// `code`: executable bytes the program does not write (r-x); seeds may lie here and its literal pools read
    /// as constants. `data`: constant bytes (r--). `ram`: memory the program writes (rw-), whose bytes, if any,
    /// are initial values and never constants.
    pub kind: RawRegionKindRequest,
    /// Internal code-space BYTE address of the region's first byte.
    pub base_address: FileOffset,
    /// Original-file BYTE offset of the region's source bytes. Omit only for a `ram` region without bytes
    /// (zero-filled or uninitialised RAM, memory-mapped I/O), for a region copied `from` another one, or, for
    /// ihex/srec input, to state the kind of the record run with exactly this base_address and length (runs are
    /// `code` otherwise; the first stays code). With ihex/srec input, regions never take offset, decode or from:
    /// the file is record text.
    #[serde(default)]
    pub offset: Option<FileOffset>,
    /// Source byte count at `offset` (the encoded count when `decode` is given, the slice size with `from`), or
    /// the mapped size of a `ram` region without bytes.
    pub length: FileOffset,
    /// Map a copy of `length` bytes of another region's bytes instead of a file range: code or data the program
    /// copies from its load address to its run address (scatter-load), including from the decoded primary
    /// region. binary_info reports the source region and slice with the region's SHA-256.
    #[serde(default)]
    pub from: Option<RawRegionFrom>,
    /// Map the output of a decoder provider over the source range instead of the range itself, e.g. a compressed
    /// second stage at its RAM base. The decoded bytes exist only in memory; binary_info reports the decode
    /// receipt (source range and hash, codec, parameters, output hash) with the region.
    #[serde(default)]
    pub decode: Option<RawRegionDecode>,
}

/// The bytes a region copies from an earlier region.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RawRegionFrom {
    /// The source region: 0, "primary" or "raw.code" for the primary code region (its decoded bytes with
    /// `decode`); n or its name `raw.<kind>.<n>` for regions[n-1], which must come earlier and have bytes.
    #[serde(deserialize_with = "region_reference")]
    #[schemars(schema_with = "region_reference_schema")]
    pub region: RegionReference,
    /// BYTE offset into the source region's bytes (not an address) of the first copied byte.
    pub offset: FileOffset,
}

/// A region named by number, or by name, whose kind must then match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionReference {
    /// 0 for the primary region, n for regions[n-1].
    pub index: usize,
    /// The kind a `raw.<kind>.<n>` name states.
    pub kind: Option<RawRegionKindRequest>,
}

fn region_reference<'de, D: Deserializer<'de>>(deserializer: D) -> Result<RegionReference, D::Error> {
    let refuse = |what: &dyn std::fmt::Display| {
        serde::de::Error::custom(format!(
            "from.region {what}: 0, \"primary\" or \"raw.code\" for the primary region, or n or \"raw.<kind>.<n>\" \
             for regions[n-1]"
        ))
    };
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Number(number) => number
            .as_u64()
            .and_then(|index| usize::try_from(index).ok())
            .map(|index| RegionReference { index, kind: None })
            .ok_or_else(|| refuse(&number)),
        serde_json::Value::String(name) if name == "primary" || name == "raw.code" => {
            Ok(RegionReference { index: 0, kind: None })
        }
        serde_json::Value::String(name) => name
            .strip_prefix("raw.")
            .and_then(|rest| rest.split_once('.'))
            .and_then(|(kind, index)| {
                let kind = match kind {
                    "code" => RawRegionKindRequest::Code,
                    "data" => RawRegionKindRequest::Data,
                    "ram" => RawRegionKindRequest::Ram,
                    _ => return None,
                };
                let index = index.parse::<usize>().ok().filter(|&index| index >= 1)?;
                Some(RegionReference { index, kind: Some(kind) })
            })
            .ok_or_else(|| refuse(&format!("{name:?}"))),
        other => Err(refuse(&other)),
    }
}

fn region_reference_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "description": "0, \"primary\" or \"raw.code\" for the primary code region; n or \"raw.<kind>.<n>\" for \
                        regions[n-1], which must come earlier.",
        "type": ["integer", "string"],
        "minimum": 0
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RawRegionKindRequest {
    Code,
    Data,
    Ram,
}

/// Decoder-provider parameters for a region, as decode_file_range takes them.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RawRegionDecode {
    /// Required decoder selection, as decode_file_range takes it; no codec guessing.
    pub codec: crate::ContentCodec,
    /// Every variant parameter, required for codec lzss and refused for the others, as decode_file_range.
    #[serde(default)]
    pub lzss: Option<crate::LzssParameters>,
    /// Analyst-supplied decoded size, which is the region's mapped size; does not prove a stream boundary.
    pub expected_output_size: FileOffset,
    /// Initial ring write position; default 4078 (0xfee) for lzss-4k, zero otherwise, as decode_file_range.
    #[serde(default)]
    pub initial_write_offset: Option<u16>,
    /// Dictionary initialization byte; default zero.
    #[serde(default)]
    pub dictionary_fill: Option<u8>,
    /// Cooperative decoder-phase timeout, default 3000 ms, at most 10000.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

fn pointer_tables_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "description": "ARM:LE:32:Cortex only: true seeds functions from tables of Thumb code pointers it accepts; \
                        false never scans; unset scans only when discovery is sparse (under one function per 16 KiB).",
        "type": ["boolean", "null"]
    })
}

fn scatter_load_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "description": "Cortex-M: map startup copies at run addresses (default true); false only reports them.",
        "type": ["boolean", "null"]
    })
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
const PROFILE_ALIASES: [(RawProfile, &[&str]); 19] = [
    (RawProfile::Msp430, &["msp430", "timsp430"]),
    (RawProfile::Avr8, &["avr", "avr8", "atmega", "atmelavr"]),
    (RawProfile::Mos6502, &["6502", "mos6502"]),
    (RawProfile::I8051, &["8051", "i8051", "mcs51", "intel8051"]),
    (RawProfile::Pic16, &["pic16"]),
    (RawProfile::SuperH2, &["sh2", "superh2"]),
    (RawProfile::V850, &["v850", "necv850"]),
    (RawProfile::Tricore, &["tricore", "aurix"]),
    (RawProfile::Xtensa, &["xtensa", "tensilica", "esp32", "esp32s2", "esp32s3", "esp8266", "lx6", "lx7", "lx106"]),
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
    (RawProfile::Mips32Be, &["mips", "mips32", "mipsbe", "mips32be", "mipseb", "mips32eb", "mips32r2"]),
    (RawProfile::Mips32Le, &["mipsel", "mips32el", "mipsle", "mips32le"]),
];

/// The alias keys of the Cortex-M profile.
fn cortex_m_aliases() -> &'static [&'static str] {
    PROFILE_ALIASES.iter().find(|(profile, _)| *profile == RawProfile::CortexM).map_or(&[], |(_, aliases)| aliases)
}

/// ARMv8-M cores and architecture names as alias keys: the Cortex-M profile decodes ARMv6-M/ARMv7-M, so none of
/// them is its alias.
const ARMV8M_CORES: [&str; 10] = [
    "cortexm23",
    "cortexm33",
    "cortexm35",
    "cortexm52",
    "cortexm55",
    "cortexm85",
    "armv8m",
    "armv81m",
    "thumbv8m",
    "thumbv81m",
];

/// Families agents name that no Raw profile covers, though a profile's name may look close (PIC32 is MIPS, not
/// PIC-16).
const UNPROFILED_FAMILIES: [&str; 16] = [
    "pic10",
    "pic12",
    "pic17",
    "pic18",
    "pic24",
    "pic32",
    "dspic",
    "mips64",
    "micromips",
    "mips16",
    "riscv",
    "rv32",
    "rv64",
    "ppc",
    "powerpc",
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
    // A Cortex-M core spelled with `arm` and `thumb` around it (`arm-thumb-cortex-m`, `arm_cortex_m4_thumb`).
    let core = key.strip_prefix("arm").unwrap_or(&key);
    let core = core.strip_prefix("thumb").or_else(|| core.strip_suffix("thumb")).unwrap_or(core);
    if core.starts_with("cortexm") && cortex_m_aliases().contains(&core) {
        return Ok(RawProfile::CortexM);
    }
    let profiles: Vec<&str> = RawProfile::ALL.iter().map(|profile| profile.language_id()).collect();
    if ARMV8M_CORES.iter().any(|core| key.contains(core)) {
        return Err(format!(
            "unsupported Raw profile {name:?}: ARMv8-M and ARMv8.1-M (cores Cortex-M23, M33, M35P, M52, \
             M55, M85) have no Raw profile. ARM:LE:32:Cortex decodes ARMv6-M/ARMv7-M Thumb (aliases cortex-m, cortex-m0, cortex-m0+, \
             cortex-m3, cortex-m4, cortex-m7, thumb); to read ARMv8-M code as that, leaving the instructions only \
             ARMv8-M has undecoded, pass profile \"cortex-m\" explicitly. inspect_raw_code decodes headerless bytes \
             of A-profile ARM, AArch64 and x86. Raw profiles: {}",
            profiles.join(", ")
        ));
    }
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

/// The decode receipt as a region reports it: the provider's receipt without the source path, the preview and the
/// standing limitations text, which decode_file_range returns for the same parameters.
fn region_receipt(receipt: &crate::DecodeReceipt) -> Result<serde_json::Value, ApiError> {
    let mut value = serde_json::to_value(receipt).map_err(|_| invalid("decode receipt serialization failed"))?;
    if let Some(object) = value.as_object_mut() {
        for key in ["file_path", "preview", "limitations"] {
            object.remove(key);
        }
    }
    Ok(value)
}

/// `length` bytes at `offset` of the file, read once and revalidated.
fn file_range(path: &Path, offset: u64, length: usize) -> Result<(Vec<u8>, RawRegionSource), ApiError> {
    let source = RangeSource::open(path, offset, length)?;
    let bytes = source.read()?;
    source.revalidate()?;
    Ok((bytes, RawRegionSource::FileRange { offset, length: length as u64 }))
}

/// The decoder provider's `mapped`-byte output over `length` bytes at `offset`, with its receipt as the source.
fn decoded_range(
    path: &Path,
    offset: u64,
    length: usize,
    decode: &RawRegionDecode,
    mapped: usize,
) -> Result<(Vec<u8>, RawRegionSource), ApiError> {
    let request = crate::DecodeFileRequest {
        codec: decode.codec,
        lzss: decode.lzss,
        offset,
        length,
        expected_output_size: mapped,
        initial_write_offset: decode
            .initial_write_offset
            .unwrap_or_else(|| crate::default_initial_write_offset(decode.codec)),
        dictionary_fill: decode.dictionary_fill.unwrap_or(0),
        timeout_ms: decode.timeout_ms.unwrap_or(3000),
        preview_offset: 0,
        preview_size: 0,
    };
    let decoded = crate::decode_file_range(path, &request)?;
    let receipt = region_receipt(&decoded.receipt)?;
    Ok((decoded.bytes().to_vec(), RawRegionSource::Decoded { offset, length: length as u64, receipt }))
}

fn region_kind_name(kind: RawRegionKindRequest) -> &'static str {
    match kind {
        RawRegionKindRequest::Code => "code",
        RawRegionKindRequest::Data => "data",
        RawRegionKindRequest::Ram => "ram",
    }
}

fn region_kind(kind: RawRegionKindRequest) -> RawRegionKind {
    match kind {
        RawRegionKindRequest::Code => RawRegionKind::Code,
        RawRegionKindRequest::Data => RawRegionKind::Data,
        RawRegionKindRequest::Ram => RawRegionKind::Ram,
    }
}

impl RawProjectRequest {
    fn options(&self, profile: RawProfile, base: u64) -> Result<RawCodeOptions, ApiError> {
        if self.seeds.len() > MAX_RAW_SEEDS {
            return Err(invalid("Raw accepts at most 8192 seeds"));
        }
        Ok(RawCodeOptions {
            profile,
            base,
            entry: self.entry.map(|entry| entry.0),
            seeds: self.seeds.iter().map(|seed| seed.0).collect(),
            vector_table: self.vector_table.map(|table| match table {
                RawVectorTable::AtBase => base,
                RawVectorTable::At(address) => address,
            }),
            pointer_tables: self.pointer_tables == Some(true),
        })
    }

    /// Whether admission follows the reset code for scatter-load copies, and maps them: by default on Cortex-M.
    fn scatter_load_mode(&self, profile: RawProfile) -> Result<Option<bool>, ApiError> {
        match (profile.m_profile(), self.scatter_load) {
            (true, requested) => Ok(Some(requested.unwrap_or(true))),
            (false, None) => Ok(None),
            (false, Some(_)) => Err(ApiError::Invalid(format!(
                "Raw scatter_load is defined only for ARM:LE:32:Cortex, not {}",
                profile.language_id()
            ))),
        }
    }

    /// Reads every additional region's bytes. `budget` is the byte count the profile still admits.
    fn read_regions(&self, path: &Path, profile: RawProfile, mut budget: usize) -> Result<Vec<RawRegion>, ApiError> {
        if self.regions.is_empty() {
            return Ok(Vec::new());
        }
        if !profile.native_decoder() {
            return Err(ApiError::Invalid(format!(
                "Raw {} maps one code region: `regions` is defined only for ARM:LE:32:Cortex, MIPS and Xtensa",
                profile.language_id()
            )));
        }
        if self.regions.len() >= MAX_RAW_REGIONS {
            return Err(ApiError::Invalid(format!(
                "Raw maps at most {MAX_RAW_REGIONS} regions, the primary one included"
            )));
        }
        let mut regions = Vec::new();
        for (index, region) in self.regions.iter().enumerate() {
            let refuse = |message: String| ApiError::Invalid(format!("Raw regions[{index}]: {message}"));
            let kind = region_kind(region.kind);
            let base = region.base_address.0;
            if let Some(from) = &region.from {
                if region.offset.is_some() || region.decode.is_some() {
                    return Err(refuse("from copies another region's bytes: omit offset and decode".into()));
                }
                let reference = from.region;
                if reference.index > index {
                    return Err(refuse(format!(
                        "from.region {} must name the primary region (0) or an earlier region (1..={index})",
                        reference.index
                    )));
                }
                if let Some(named) = reference.kind
                    && self.regions[reference.index - 1].kind != named
                {
                    let actual = region_kind_name(self.regions[reference.index - 1].kind);
                    return Err(refuse(format!(
                        "from.region raw.{}.{} names a {} region, but regions[{}] is {actual}: raw.{actual}.{}",
                        region_kind_name(named),
                        reference.index,
                        region_kind_name(named),
                        reference.index - 1,
                        reference.index
                    )));
                }
                let length = region.length.0;
                if length == 0 || length > budget as u64 {
                    return Err(refuse(format!(
                        "length must be 1..={budget} bytes: all backed regions together hold at most {} bytes",
                        profile.max_bytes()
                    )));
                }
                budget -= length as usize;
                let source = match reference.index {
                    0 => "raw.code".to_owned(),
                    n => format!("raw.{}.{n}", region_kind_name(self.regions[n - 1].kind)),
                };
                regions.push(RawRegion {
                    kind,
                    base,
                    size: length,
                    bytes: None,
                    source: RawRegionSource::Slice { region: source, offset: from.offset.0, length },
                });
                continue;
            }
            let Some(offset) = region.offset else {
                if kind != RawRegionKind::Ram || region.decode.is_some() {
                    return Err(refuse(
                        "only a ram region without decode may omit offset; code and data need bytes".into(),
                    ));
                }
                if region.length.0 == 0 {
                    return Err(refuse("length must be at least 1".into()));
                }
                regions.push(RawRegion {
                    kind,
                    base,
                    size: region.length.0,
                    bytes: None,
                    source: RawRegionSource::Unbacked,
                });
                continue;
            };
            let length = usize::try_from(region.length.0).ok().filter(|&length| length >= 1);
            let length = length.ok_or_else(|| refuse("length must be at least 1".into()))?;
            let mapped = match &region.decode {
                None => length,
                Some(decode) => usize::try_from(decode.expected_output_size.0).unwrap_or(usize::MAX),
            };
            if mapped > budget {
                return Err(ApiError::Invalid(format!(
                    "Raw {} regions together hold more than {} bytes",
                    profile.language_id(),
                    profile.max_bytes()
                )));
            }
            budget -= mapped;
            let (bytes, source) = match &region.decode {
                None => file_range(path, offset.0, length)?,
                Some(decode) => decoded_range(path, offset.0, length, decode, mapped)
                    .map_err(|error| refuse(format!("decode: {error}")))?,
            };
            regions.push(RawRegion { kind, base, size: bytes.len() as u64, bytes: Some(bytes), source });
        }
        Ok(regions)
    }

    fn binary_image(&self, path: &Path, profile: RawProfile) -> Result<RawImage, ApiError> {
        let Some(base) = self.base_address else {
            return Err(invalid(
                "Raw format binary needs base_address, the code-space address of the byte at offset (offset defaults \
                 to 0, length to the rest of the file); format ihex or srec takes the addresses from the records \
                 instead",
            ));
        };
        let offset = self.offset.unwrap_or(FileOffset(0));
        let max = profile.max_bytes();
        let options = self.options(profile, base.0)?;
        // With decode, `length` counts encoded bytes (the decoder provider's input cap) and the decoded size is the
        // mapped one, under the profile's cap.
        let limit = if self.decode.is_some() { crate::MAX_DECODE_INPUT_BYTES } else { max };
        let what = if self.decode.is_some() { "encoded bytes with decode" } else { "bytes" };
        let refuse_length = |omitted: String| {
            ApiError::Invalid(format!("Raw length must be 1..={limit} {what} for {}{omitted}", profile.language_id()))
        };
        let in_limit = |length: u64| usize::try_from(length).ok().filter(|length| (1..=limit).contains(length));
        // An explicit length is checked before the file is read.
        if let Some(length) = self.length {
            in_limit(length.0).ok_or_else(|| refuse_length(String::new()))?;
            offset.0.checked_add(length.0).ok_or_else(|| invalid("Raw source range overflows"))?;
        }
        // The file's size, observed through the checked range source, for an omitted length (the rest of the file)
        // and to say what fits; the range itself is checked again when it is read.
        let size = RangeSource::open(path, 0, 0)?.size();
        let length = match self.length {
            Some(length) => length.0,
            None => size.checked_sub(offset.0).filter(|&rest| rest > 0).ok_or_else(|| {
                ApiError::Invalid(format!(
                    "Raw offset {0} ({0:#x}) is at or past the end of the file, which holds {size} bytes \
                         ({size:#x}); offset must be below {size}",
                    offset.0
                ))
            })?,
        };
        if offset.0.checked_add(length).is_none_or(|end| end > size) {
            return Err(ApiError::Invalid(format!(
                "Raw {}, or omit length to read from offset to the end of the file",
                crate::range_source::outside(offset.0, length, size)
            )));
        }
        let length = in_limit(length).ok_or_else(|| {
            refuse_length(format!(" (the file holds {length} bytes from offset {}: give a length)", offset.0))
        })?;
        let (bytes, source) = match &self.decode {
            None => file_range(path, offset.0, length)?,
            Some(decode) => {
                let mapped = usize::try_from(decode.expected_output_size.0)
                    .ok()
                    .filter(|size| (1..=max).contains(size))
                    .ok_or_else(|| {
                        ApiError::Invalid(format!(
                            "Raw decode.expected_output_size must be 1..={max} bytes for {}",
                            profile.language_id()
                        ))
                    })?;
                decoded_range(path, offset.0, length, decode, mapped)
                    .map_err(|error| ApiError::Invalid(format!("Raw decode: {error}")))?
            }
        };
        let regions = self.read_regions(path, profile, max - bytes.len())?;
        let scatter_load = self.scatter_load_mode(profile)?;
        Ok(RawImage { bytes, options, source: Some(source), regions, records: None, esp: None, scatter_load })
    }

    /// The ESP app image at `offset` (default 0) of the file: each segment the chip's memory map places becomes a
    /// region at its load address (IRAM and IROM code, DROM data, DRAM and RTC RAM with their initial bytes; the
    /// rest of the chip's DRAM, .bss and heap, as RAM without bytes), the segment holding the entry the primary one, and the header's entry the entry. An ESP8266 image at the start
    /// of a flash dump also maps the rest of the flash as IROM, at 0x40200000 plus its offset, as the cache does.
    fn esp_image(&self, path: &Path, profile: RawProfile) -> Result<RawImage, ApiError> {
        if profile != RawProfile::Xtensa {
            return Err(ApiError::Invalid(format!(
                "Raw format esp reads ESP32 and ESP8266 app images, whose code is Xtensa: use profile xtensa, not {}",
                profile.language_id()
            )));
        }
        if self.length.is_some() || self.base_address.is_some() || self.decode.is_some() {
            return Err(invalid(
                "Raw format esp takes every address from the app image's segment headers: give only offset (the \
                 image's file offset, default 0), and omit length, base_address and decode",
            ));
        }
        let offset = self.offset.map_or(0, |offset| offset.0);
        let source = RangeSource::open_sized(path, 0, |size| {
            usize::try_from(size).ok().filter(|&size| (1..=MAX_ESP_FILE_BYTES).contains(&size)).ok_or_else(|| {
                ApiError::Invalid(format!("Raw format esp reads files of 1..={MAX_ESP_FILE_BYTES} bytes"))
            })
        })?;
        let file = source.read()?;
        source.revalidate()?;
        let load = |source| ApiError::Load { path: path.to_owned(), source };
        let mut image = rampage_loaders::esp::parse_app_image(&file, offset).map_err(load)?;
        if !image.chip.xtensa() {
            return Err(ApiError::Invalid(format!(
                "the app image at {offset:#x} is for an ESP32-family chip without an Xtensa core (RISC-V: C2, C3, C5, \
                 C6, H2, P4) or one rampage has no memory map for; it has no Xtensa code"
            )));
        }
        let max = profile.max_bytes();
        let mut regions: Vec<RawRegion> = Vec::new();
        for (index, segment) in image.segments.iter().enumerate() {
            let Some(kind) = segment.kind else { continue };
            let start = (offset + segment.image_offset) as usize;
            let bytes = file[start..start + segment.length as usize].to_vec();
            let source = RawRegionSource::EspSegment {
                image_offset: offset,
                segment: index,
                offset: offset + segment.image_offset,
                length: segment.length,
            };
            regions.push(RawRegion {
                kind,
                base: segment.load_address,
                size: segment.length,
                bytes: Some(bytes),
                source,
            });
        }
        if image.chip == rampage_loaders::esp::EspChip::Esp8266 && offset == 0 {
            // The rest of the flash, past the boot image, is what the cache maps at 0x40200000 + offset.
            let from = (image.length as usize).next_multiple_of(0x1000);
            let used_end = file.len() - file.iter().rev().take_while(|&&byte| byte == 0xff).count();
            if used_end > ESP8266_IROM_WINDOW {
                image.notes.push(format!(
                    "flash past {ESP8266_IROM_WINDOW:#x} (up to {used_end:#x}) is not mapped: the ESP8266's cache maps \
                     only the first 1 MiB at 0x40200000"
                ));
            }
            let end = used_end.min(ESP8266_IROM_WINDOW);
            if end > from {
                let used: usize = regions.iter().map(|region| region.size as usize).sum();
                let room = from + max.saturating_sub(used);
                if end > room {
                    image.notes.push(format!(
                        "IROM mapped only up to flash {room:#x} of {end:#x}: the profile's {max}-byte limit"
                    ));
                }
                let end = end.min(room);
                regions.push(RawRegion {
                    kind: RawRegionKind::Code,
                    base: ESP8266_IROM_BASE + from as u64,
                    size: (end - from) as u64,
                    bytes: Some(file[from..end].to_vec()),
                    source: RawRegionSource::FileRange { offset: from as u64, length: (end - from) as u64 },
                });
            }
        }
        drop(file);
        // The rest of the chip's DRAM (.bss, the heap) is RAM without bytes around the image's DRAM segments.
        if let Some(dram) = image.chip.dram() {
            let mut taken: Vec<(u64, u64)> = regions
                .iter()
                .map(|region| (region.base, region.base + region.size))
                .filter(|&(start, end)| start < dram.end && dram.start < end)
                .collect();
            taken.sort_unstable();
            let mut at = dram.start;
            for (start, end) in taken.into_iter().chain([(dram.end, dram.end)]) {
                if start > at {
                    regions.push(RawRegion {
                        kind: RawRegionKind::Ram,
                        base: at,
                        size: start - at,
                        bytes: None,
                        source: RawRegionSource::Unbacked,
                    });
                }
                at = at.max(end);
            }
        }
        let total: usize = regions.iter().filter_map(|region| region.bytes.as_ref()).map(Vec::len).sum();
        if total > max {
            return Err(ApiError::Invalid(format!(
                "the app image's mapped segments hold {total} bytes; Raw Xtensa maps at most {max}"
            )));
        }
        let primary = regions
            .iter()
            .position(|region| {
                region.kind == RawRegionKind::Code && (region.base..region.base + region.size).contains(&image.entry)
            })
            .or_else(|| regions.iter().position(|region| region.kind == RawRegionKind::Code))
            .ok_or_else(|| invalid("the app image maps no code segment"))?;
        let primary = regions.remove(primary);
        let mut requested = self.clone();
        requested.entry = Some(self.entry.unwrap_or(FileOffset(image.entry)));
        let mut options = requested.options(profile, primary.base)?;
        options.entry = requested.entry.map(|entry| entry.0);
        let extra = self.read_regions(path, profile, max - total)?;
        regions.extend(extra);
        if regions.len() >= MAX_RAW_REGIONS {
            return Err(ApiError::Invalid(format!(
                "Raw maps at most {MAX_RAW_REGIONS} regions; the app image and `regions` state {}",
                regions.len() + 1
            )));
        }
        Ok(RawImage {
            bytes: primary.bytes.unwrap_or_default(),
            options,
            source: Some(primary.source),
            regions,
            records: None,
            esp: Some(image),
            scatter_load: None,
        })
    }

    fn record_image(&self, path: &Path, profile: RawProfile, format: RawRecordFormat) -> Result<RawImage, ApiError> {
        if self.offset.is_some() || self.length.is_some() || self.base_address.is_some() || self.decode.is_some() {
            return Err(ApiError::Invalid(format!(
                "Raw format {} takes every address from the file's records: omit offset, length, base_address and \
                 decode",
                format.name()
            )));
        }
        let source = RangeSource::open_sized(path, 0, |size| {
            usize::try_from(size).ok().filter(|&size| (1..=MAX_RAW_RECORD_TEXT_BYTES).contains(&size)).ok_or_else(
                || {
                    ApiError::Invalid(format!(
                        "Raw {} record files hold 1..={MAX_RAW_RECORD_TEXT_BYTES} bytes",
                        format.name()
                    ))
                },
            )
        })?;
        let text = source.read()?;
        source.revalidate()?;
        let load = |source| ApiError::Load { path: path.to_owned(), source };
        let max = profile.max_bytes();
        let records = parse_raw_records(&text, format, max).map_err(load)?;
        drop(text);
        let facts = RawRecordFacts { format, data_records: records.data_records, start_address: records.start_address };
        let total: usize = records.runs.iter().map(|(_, bytes)| bytes.len()).sum();
        let mut runs = records.runs.into_iter();
        let (base, bytes) = runs.next().ok_or_else(|| invalid("Raw records hold no data"))?;
        let mut regions: Vec<RawRegion> = runs
            .map(|(base, bytes)| RawRegion {
                kind: RawRegionKind::Code,
                base,
                size: bytes.len() as u64,
                bytes: Some(bytes),
                source: RawRegionSource::Records { format },
            })
            .collect();
        if !regions.is_empty() && !profile.native_decoder() {
            return Err(ApiError::Invalid(format!(
                "Raw {} maps one code region, and the {} records form {} separate runs; only ARM:LE:32:Cortex and \
                 the MIPS and Xtensa profiles map several regions",
                profile.language_id(),
                format.name(),
                regions.len() + 1
            )));
        }
        // A `regions` entry without offset whose range is exactly a later run states that run's kind (a run of
        // writable data among the code); the others are read as usual.
        let mut requested = self.clone();
        requested.regions.clear();
        for region in &self.regions {
            let run = regions.iter_mut().find(|run| {
                region.offset.is_none()
                    && region.decode.is_none()
                    && region.from.is_none()
                    && run.base == region.base_address.0
                    && run.size == region.length.0
            });
            match run {
                Some(run) => run.kind = region_kind(region.kind),
                None => requested.regions.push(region.clone()),
            }
        }
        // The opened file is record text, not bytes: a further region can only be unbacked RAM.
        if let Some(index) = self
            .regions
            .iter()
            .position(|region| region.offset.is_some() || region.decode.is_some() || region.from.is_some())
        {
            return Err(ApiError::Invalid(format!(
                "Raw regions[{index}]: format {} reads record text, so a region cannot take offset, decode or from; \
                 give a record run's exact base_address and length to state its kind, or omit offset for \
                 unbacked RAM",
                format.name()
            )));
        }
        regions.extend(requested.read_regions(path, profile, max - total)?);
        if regions.len() >= MAX_RAW_REGIONS {
            return Err(ApiError::Invalid(format!(
                "Raw maps at most {MAX_RAW_REGIONS} regions, the primary one included; the {} records and `regions` \
                 form {}",
                format.name(),
                regions.len() + 1
            )));
        }
        let scatter_load = self.scatter_load_mode(profile)?;
        let options = self.options(profile, base)?;
        Ok(RawImage {
            bytes,
            options,
            source: Some(RawRegionSource::Records { format }),
            regions,
            records: Some(facts),
            esp: None,
            scatter_load,
        })
    }
}

/// Reads exactly the requested ranges of a regular, non-symlinked file (revalidated after each read) and admits
/// them as a Raw [`Binary`]. No native header admission, sidecar or annotation log is involved; decoded regions
/// stay in memory.
pub fn open_raw_binary(path: &Path, request: &RawProjectRequest) -> Result<Binary, ApiError> {
    Binary::from_raw_image(raw_image(path, request)?).map_err(|source| ApiError::Load { path: path.to_owned(), source })
}

/// The Raw image `request` maps from `path`, read but not yet admitted.
pub(crate) fn raw_image(path: &Path, request: &RawProjectRequest) -> Result<RawImage, ApiError> {
    let profile = resolve_raw_profile(&request.profile).map_err(ApiError::Invalid)?;
    match request.format {
        RawInputFormat::Binary => request.binary_image(path, profile),
        RawInputFormat::Ihex => request.record_image(path, profile, RawRecordFormat::Ihex),
        RawInputFormat::Srec => request.record_image(path, profile, RawRecordFormat::Srec),
        RawInputFormat::Esp => request.esp_image(path, profile),
    }
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
         executables embedded in it. An Intel HEX or S-record file takes \"format\":\"ihex\" or \"srec\" in          `raw` instead of offset, length and base_address.",
        profiles.join(", ")
    )
}

/// Which record format a file's first line suggests: `ihex` for an Intel HEX record (`:` and hex digits), `srec`
/// for a Motorola S-record (`S0`..`S9` and hex digits). Reads at most the first 4 KiB.
pub fn sniff_record_format(path: &Path) -> Option<&'static str> {
    use std::io::Read;
    let mut head = Vec::with_capacity(4096);
    std::fs::File::open(path).ok()?.take(4096).read_to_end(&mut head).ok()?;
    // Records are ASCII: read up to the first other byte, after an optional UTF-8 byte order mark.
    let body = head.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&head);
    let end = body.iter().position(|byte| !byte.is_ascii()).unwrap_or(body.len());
    let text = std::str::from_utf8(&body[..end]).ok()?;
    let line = text.lines().map(str::trim).find(|line| !line.is_empty())?;
    let hex_tail = |tail: &str| tail.len() >= 8 && tail.bytes().all(|byte| byte.is_ascii_hexdigit());
    if let Some(tail) = line.strip_prefix(':') {
        return hex_tail(tail).then_some("ihex");
    }
    let mut chars = line.chars();
    if chars.next() == Some('S') && chars.next().is_some_and(|kind| kind.is_ascii_digit()) {
        return hex_tail(&line[2..]).then_some("srec");
    }
    None
}

/// Whether the file starts with the DEX magic (`dex\n`).
fn is_dex(path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 4];
    std::fs::File::open(path).and_then(|mut file| file.read_exact(&mut head)).is_ok()
        && rampage_unpack::executable_format(&head) == Some("dex")
}

/// [`headerless_guidance`], led by the record format when the file looks like Intel HEX or S-records. A filesystem
/// image gets the filesystem tools instead, and a DEX file `dex_metadata`.
/// Whether a file with no executable header has a format of its own with pointed guidance: a filesystem image,
/// DEX, or an Intel HEX or S-record file.
pub fn headerless_format_known(path: &Path) -> bool {
    crate::filesystem_guidance(path).is_some()
        || is_dex(path)
        || sniff_record_format(path).is_some()
        || esp_guidance(path).is_some()
}

/// The first bytes of `path`, at most `limit`.
fn file_prefix(path: &Path, limit: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path).ok()?.take(limit).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

/// Application partitions whose headers ESP guidance reads.
const MAX_ESP_GUIDANCE_PROBES: usize = 16;

/// Up to `length` bytes of `path` at `offset`.
fn file_range_prefix(path: &Path, offset: u64, length: u64) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).ok()?;
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut bytes = Vec::new();
    file.take(length).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

/// The `raw` selector for the ESP app image at `offset`.
fn esp_selector(offset: u64) -> String {
    format!("\"raw\":{{\"profile\":\"xtensa\",\"format\":\"esp\",\"offset\":\"{offset:#x}\"}}")
}

/// How to read an Espressif file: an app image (magic 0xE9 at the start) or a flash dump (a bootloader image at
/// 0x1000 or 0, and a partition table), with the `raw` selector for each application image it holds.
pub fn esp_guidance(path: &Path) -> Option<String> {
    use rampage_loaders::esp;
    let bytes = file_prefix(path, ESP_GUIDANCE_PREFIX)?;
    if let Some(layout) = esp::flash_layout(&bytes) {
        let mut parts = Vec::new();
        if let Some(bootloader) = &layout.bootloader {
            parts.push(format!("an {} bootloader image at {:#x}", bootloader.chip.label(), bootloader.offset));
        }
        if let Some(table) = &layout.partition_table {
            let entries: Vec<String> = table
                .partitions
                .iter()
                .map(|partition| {
                    format!("{} ({}/{}) at {:#x}", partition.label, partition.kind, partition.subtype, partition.offset)
                })
                .collect();
            parts.push(format!("a partition table at {:#x}: {}", table.offset, entries.join(", ")));
        }
        if layout.flash_base != 0 {
            parts.push(format!(
                "it starts at flash offset {:#x}, so each partition lies {:#x} bytes before its flash offset in the \
                 file",
                layout.flash_base, layout.flash_base
            ));
        }
        // Each application partition's header is read where the table puts it.
        let apps: Vec<String> = layout
            .partition_table
            .iter()
            .flat_map(|table| &table.partitions)
            .filter(|partition| partition.kind == "app")
            .take(MAX_ESP_GUIDANCE_PROBES)
            .filter_map(|partition| Some((partition, layout.file_offset(partition.offset)?)))
            .filter(|&(_, offset)| {
                file_range_prefix(path, offset, 64).is_some_and(|head| esp::looks_like_app_image(&head, 0))
            })
            .map(|(partition, offset)| format!("{} with {}", partition.label, esp_selector(offset)))
            .collect();
        let open = match (apps.is_empty(), &layout.bootloader) {
            (false, _) => format!("read each application with `raw`: {}", apps.join("; ")),
            (true, Some(bootloader)) => format!("read the boot image with {}", esp_selector(bootloader.offset)),
            (true, None) => "no application partition holds an app image".to_owned(),
        };
        return Some(format!(
            "The file is an ESP32/ESP8266 flash dump holding {}; {open}. file_layout and carve list the same \
             structure.",
            parts.join(" and ")
        ));
    }
    esp::looks_like_app_image(&bytes, 0).then(|| {
        let chip = esp::image_chip(&bytes, 0).unwrap_or(esp::EspChip::Other);
        let flash = if chip == esp::EspChip::Esp8266 {
            " (an ESP8266 flash dump's boot image: the rest of the flash maps as IROM at 0x40200000 plus its offset)"
        } else {
            ""
        };
        format!(
            "The file starts with an {} app image (magic 0xE9){flash}: read it with {}, which maps every segment at \
             its load address and reports the chip, checksum, SHA-256 and esp_app_desc in binary_info.",
            chip.label(),
            esp_selector(0)
        )
    })
}

pub fn headerless_guidance_for(path: &Path) -> String {
    if let Some(guidance) = crate::filesystem_guidance(path) {
        return guidance;
    }
    if let Some(guidance) = esp_guidance(path) {
        return guidance;
    }
    if is_dex(path) {
        return "The file is Dalvik bytecode (DEX), not a native executable: read it with dex_metadata, and its \
                classes and methods with the other `android` group tools."
            .to_owned();
    }
    match sniff_record_format(path) {
        Some(format) => {
            let name = if format == "ihex" { "an Intel HEX" } else { "a Motorola S-record" };
            format!(
                "The file looks like {name} file: read it with \"raw\":{{\"profile\":\"cortex-m\",\"format\":\"{format}\"}}                  (or another profile), which takes every address from the records. {}",
                headerless_guidance()
            )
        }
        None => headerless_guidance(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Benchmark v4 Haiku pass: an Intel HEX file opened by path got only the headerless hint, which never
    /// mentioned `format`, and the agent gave up.
    #[test]
    fn record_files_are_recognised_by_their_first_line() {
        let directory = std::env::temp_dir().join(format!("rampage-sniff-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let write = |name: &str, bytes: &[u8]| {
            let path = directory.join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        };
        let ihex = write("a.bin", b"\r\n:100000000000022009010000110100001101000046\r\n:00000001FF\r\n");
        let srec = write("b.bin", b"S00F000068656C6C6F202020202000003C\nS1130000000002200901000011010000110100004A\n");
        let bom = write("c.bin", b"\xef\xbb\xbf:020000040800F2\n");
        assert_eq!(sniff_record_format(&ihex), Some("ihex"));
        assert_eq!(sniff_record_format(&srec), Some("srec"));
        assert_eq!(sniff_record_format(&bom), Some("ihex"));
        assert!(headerless_guidance_for(&ihex).starts_with("The file looks like an Intel HEX file"));
        assert!(headerless_guidance_for(&srec).contains("\"format\":\"srec\""));
        for (name, bytes) in [
            ("d.bin", &b"\x00\x00\x02\x20\x09\x01\x00\x00"[..]),
            ("e.bin", b":not hex at all"),
            ("f.bin", b"Some text line"),
            ("g.bin", b"S1 short"),
            ("h.bin", b""),
        ] {
            let path = write(name, bytes);
            assert_eq!(sniff_record_format(&path), None, "{name}");
            assert_eq!(headerless_guidance_for(&path), headerless_guidance(), "{name}");
        }
        assert!(headerless_guidance().contains("\"format\":\"ihex\""));
        // 1.7.0 docs audit: a bare DEX file got the headerless-image hint.
        let dex = write("classes.dex", b"dex\n035\0\0\0\0\0");
        assert!(headerless_guidance_for(&dex).contains("dex_metadata"));
        std::fs::remove_dir_all(&directory).unwrap();
    }

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
        for family in ["pic32", "PIC32MX", "mips64", "microMIPS", "mips16e", "riscv32"] {
            let error = resolve_raw_profile(family).unwrap_err();
            assert!(error.contains("no Raw profile covers this processor") && !error.contains("closest"), "{error}");
        }
        for (alias, profile) in [
            ("mips", RawProfile::Mips32Be),
            ("MIPS32", RawProfile::Mips32Be),
            ("mips32r2", RawProfile::Mips32Be),
            ("mipsel", RawProfile::Mips32Le),
            ("MIPS:LE:32:default", RawProfile::Mips32Le),
        ] {
            assert_eq!(resolve_raw_profile(alias), Ok(profile), "{alias}");
        }
        assert!(resolve_raw_profile("MIPS:BE:64:default").unwrap_err().contains("no Raw profile covers this variant"));
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

    /// Haiku suite v4: Cortex-M spellings the agents used, and `format` names for a flat binary.
    #[test]
    fn cortex_m_spellings_select_the_profile_and_armv8m_cores_are_named() {
        let spellings = [
            "cortex-m0",
            "Cortex-M0+",
            "cortex-m3",
            "CORTEX-M4",
            "cortex-m7",
            "arm-cortex-m",
            "thumb",
            "arm_thumb",
            "arm-thumb-cortex-m",
            "arm_cortex_m4_thumb",
        ];
        for spelling in spellings {
            assert_eq!(resolve_raw_profile(spelling), Ok(RawProfile::CortexM), "{spelling}");
        }
        for core in [
            "cortex-m33",
            "Cortex-M23",
            "arm_cortex_m33_thumb",
            "cortex-m85",
            "armv8m",
            "ARMv8-M.main",
            "thumbv8m.base",
            "armv8.1-m",
        ] {
            let error = resolve_raw_profile(core).unwrap_err();
            assert!(error.contains("ARMv8-M and ARMv8.1-M") && error.contains("pass profile \"cortex-m\""), "{error}");
        }
        for (name, format) in
            [("bin", RawInputFormat::Binary), ("RAW", RawInputFormat::Binary), ("ihex", RawInputFormat::Ihex)]
        {
            let request: RawProjectRequest =
                serde_json::from_value(serde_json::json!({ "profile": "cortex-m", "format": name })).unwrap();
            assert_eq!(request.format, format, "{name}");
        }
        let refused =
            serde_json::from_value::<RawProjectRequest>(serde_json::json!({ "profile": "x", "format": "elf" }));
        assert!(refused.unwrap_err().to_string().contains("binary, ihex, srec or esp"));
    }
}
