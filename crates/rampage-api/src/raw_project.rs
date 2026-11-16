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
    /// Original-file BYTE offset of the first code byte. Required for the `binary` format.
    #[serde(default)]
    pub offset: Option<FileOffset>,
    /// Exact source byte count: 1..=131072, or 1..=4194304 for ARM:LE:32:Cortex (with `decode`, the encoded
    /// count, at most 8 MiB). Required for the `binary` format.
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
    /// ARM:LE:32:Cortex only: up to 15 further regions of the same file mapped beside the primary code region, e.g.
    /// a second stage at its RAM base, constant data, or RAM. Regions never overlap; references between them
    /// resolve, entry and seeds may lie in any code region, and binary_info reports each region with its source
    /// range and SHA-256. vector_table and pointer_tables read the primary region only. All backed regions
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
}

fn format<'de, D: Deserializer<'de>>(deserializer: D) -> Result<RawInputFormat, D::Error> {
    match Option::<String>::deserialize(deserializer)?.as_deref() {
        None | Some("binary") => Ok(RawInputFormat::Binary),
        Some("ihex") => Ok(RawInputFormat::Ihex),
        Some("srec") => Ok(RawInputFormat::Srec),
        Some(other) => Err(serde::de::Error::custom(format!("format {other:?}: binary, ihex or srec"))),
    }
}

fn format_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "description": "binary (default) maps offset/length at base_address; ihex (Intel HEX) and srec (Motorola \
                        S-records) take addresses from the records, so offset, length and base_address are omitted.",
        "type": ["string", "null"],
        "enum": ["binary", "ihex", "srec", null]
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
                "Raw {} maps one code region: `regions` is defined only for ARM:LE:32:Cortex",
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
        let (Some(offset), Some(length), Some(base)) = (self.offset, self.length, self.base_address) else {
            return Err(invalid(
                "Raw needs offset, length and base_address (or format ihex/srec, whose records state the addresses)",
            ));
        };
        let max = profile.max_bytes();
        let options = self.options(profile, base.0)?;
        // With decode, `length` counts encoded bytes (the decoder provider's input cap) and the decoded size is the
        // mapped one, under the profile's cap.
        let limit = if self.decode.is_some() { crate::MAX_DECODE_INPUT_BYTES } else { max };
        let length = usize::try_from(length.0).ok().filter(|length| (1..=limit).contains(length)).ok_or_else(|| {
            let what = if self.decode.is_some() { "encoded bytes with decode" } else { "bytes" };
            ApiError::Invalid(format!("Raw length must be 1..={limit} {what} for {}", profile.language_id()))
        })?;
        offset.0.checked_add(length as u64).ok_or_else(|| invalid("Raw source range overflows"))?;
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
        Ok(RawImage { bytes, options, source: Some(source), regions, records: None, scatter_load })
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
                "Raw {} maps one code region, and the {} records form {} separate runs; only ARM:LE:32:Cortex maps \
                 several regions",
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

/// [`headerless_guidance`], led by the record format when the file looks like Intel HEX or S-records. A filesystem
/// image gets the filesystem tools instead.
pub fn headerless_guidance_for(path: &Path) -> String {
    if let Some(guidance) = crate::filesystem_guidance(path) {
        return guidance;
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
