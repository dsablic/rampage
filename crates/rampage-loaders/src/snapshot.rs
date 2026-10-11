use rampage_arch::Arch;
use serde::{Deserialize, Serialize};

use crate::{Binary, LoadError, Perms, Section, SectionKind, Segment};

pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub format: String,
    pub arch: String,
    #[serde(default)]
    pub big_endian: bool,
    #[serde(default)]
    pub data_big_endian: bool,
    pub provenance: String,
    pub regions: Vec<SnapshotRegion>,
    #[serde(default)]
    pub seeds: Vec<String>,
    pub entry: Option<String>,
    #[serde(default)]
    pub modules: Vec<SnapshotModule>,
    #[serde(default)]
    pub registers: Vec<SnapshotRegister>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<SnapshotTarget>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotTarget {
    pub platform: SnapshotPlatform,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotPlatform {
    Default,
    Darwin,
    Windows,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotModule {
    pub name: String,
    pub path: String,
    pub uuid: String,
    pub image_base: String,
    pub runtime_base: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRegister {
    pub thread_id: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRegion {
    pub name: String,
    pub address: String,
    pub permissions: String,
    pub bytes: String,
    #[serde(default)]
    pub thumb: bool,
}

pub fn address(text: &str) -> Result<u64, LoadError> {
    if text.len() > 18 {
        return Err(LoadError::Malformed("hexadecimal address exceeds 64-bit width".to_owned()));
    }
    let value = text
        .strip_prefix("0x")
        .filter(|hex| !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok());
    value.ok_or_else(|| LoadError::Malformed(format!("expected a hexadecimal address, got {text:?}")))
}

/// Normalize recognized UUID spellings; preserve opaque producer identifiers without inventing aliases.
pub fn canonical_module_identity(value: &str) -> String {
    let bytes = value.as_bytes();
    let compact = bytes.len() == 32 && bytes.iter().all(u8::is_ascii_hexdigit);
    let dashed = bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) { *byte == b'-' } else { byte.is_ascii_hexdigit() }
        });
    if compact || dashed { value.replace('-', "").to_ascii_lowercase() } else { value.to_owned() }
}

pub(crate) fn load(source: Vec<u8>, wanted: Option<Arch>) -> Result<Binary, LoadError> {
    let snapshot: Snapshot = serde_json::from_slice(&source)
        .map_err(|error| LoadError::Malformed(format!("invalid memory snapshot: {error}")))?;
    if snapshot.format != "rampage-snapshot-v1" || snapshot.regions.is_empty() || snapshot.regions.len() > 4096 {
        return Err(LoadError::Malformed("expected rampage-snapshot-v1 with 1–4096 regions".to_owned()));
    }
    let arch: Arch = snapshot.arch.parse().map_err(LoadError::Unsupported)?;
    if let Some(compiler) = snapshot.target.as_ref().and_then(|target| target.compiler.as_deref())
        && (compiler.is_empty()
            || compiler.len() > 64
            || !compiler.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    {
        return Err(LoadError::Malformed("invalid snapshot compiler specification ID".to_owned()));
    }
    if wanted.is_some_and(|wanted| wanted != arch) {
        return Err(LoadError::Unsupported(format!("snapshot architecture is {arch}")));
    }
    if snapshot.modules.len() > 4096 || snapshot.registers.len() > 4096 {
        return Err(LoadError::Malformed("snapshot module/register limit exceeded".to_owned()));
    }
    let mut uuids = std::collections::BTreeSet::new();
    for module in &snapshot.modules {
        if module.name.len() > 4096
            || module.path.len() > 4096
            || module.uuid.is_empty()
            || module.uuid.len() > 128
            || !uuids.insert(canonical_module_identity(&module.uuid))
        {
            return Err(LoadError::Malformed("invalid or duplicate snapshot module identity".to_owned()));
        }
        address(&module.image_base)?;
        address(&module.runtime_base)?;
    }
    let mut register_names = std::collections::BTreeSet::new();
    for register in &snapshot.registers {
        let thread = address(&register.thread_id)?;
        address(&register.value)?;
        if register.name.is_empty()
            || register.name.len() > 32
            || !register.name.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || !register_names.insert((thread, &register.name))
        {
            return Err(LoadError::Malformed("invalid or duplicate snapshot register".to_owned()));
        }
    }
    let mut regions = snapshot
        .regions
        .into_iter()
        .map(|region| Ok((address(&region.address)?, region)))
        .collect::<Result<Vec<_>, LoadError>>()?;
    regions.sort_by_key(|(at, _)| *at);
    let mut data = Vec::new();
    let mut segments = Vec::new();
    let mut sections = Vec::new();
    let mut thumb = Vec::new();
    let mut previous_end = 0;
    for (at, region) in regions {
        if region.bytes.is_empty()
            || region.bytes.len() % 2 != 0
            || !region.bytes.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(LoadError::Malformed("snapshot bytes must be nonempty, even-length ASCII hex".to_owned()));
        }
        let size = region.bytes.len() / 2;
        if data.len().checked_add(size).is_none_or(|total| total > MAX_SNAPSHOT_BYTES) {
            return Err(LoadError::Malformed("snapshot exceeds the 64 MiB decoded-byte limit".to_owned()));
        }
        let end = at
            .checked_add(size as u64)
            .ok_or_else(|| LoadError::Malformed("snapshot region overflows address space".to_owned()))?;
        if at < previous_end {
            return Err(LoadError::Malformed("snapshot regions overlap".to_owned()));
        }
        previous_end = end;
        let perms = match region.permissions.as_bytes() {
            [r @ (b'r' | b'-'), w @ (b'w' | b'-'), x @ (b'x' | b'-')] => {
                Perms { read: *r == b'r', write: *w == b'w', execute: *x == b'x' }
            }
            _ => return Err(LoadError::Malformed("snapshot permissions must have the form rwx or r-x".to_owned())),
        };
        if region.thumb && (arch != Arch::Arm || !perms.execute || at % 2 != 0) {
            return Err(LoadError::Malformed("Thumb regions require aligned executable ARM code".to_owned()));
        }
        let offset = data.len() as u64;
        for pair in region.bytes.as_bytes().as_chunks::<2>().0 {
            let hex = std::str::from_utf8(pair).unwrap();
            data.push(
                u8::from_str_radix(hex, 16)
                    .map_err(|_| LoadError::Malformed("invalid hexadecimal snapshot bytes".to_owned()))?,
            );
        }
        if region.thumb {
            thumb.push(at..end);
        }
        sections.push(Section {
            name: region.name.clone(),
            address: at,
            size: size as u64,
            kind: if perms.execute { SectionKind::Code } else { SectionKind::Data },
            file_offset: Some(offset),
            file_size: size as u64,
        });
        segments.push(Segment {
            name: region.name,
            address: at,
            size: size as u64,
            file_offset: offset,
            file_size: size as u64,
            perms,
        });
    }
    let mut seeds = snapshot.seeds.iter().map(|seed| address(seed)).collect::<Result<Vec<_>, _>>()?;
    let entry = snapshot.entry.as_deref().map(address).transpose()?;
    seeds.extend(entry);
    seeds.sort_unstable();
    seeds.dedup();
    for &seed in &seeds {
        if !segments.iter().any(|segment| segment.perms.execute && segment.contains(seed)) {
            return Err(LoadError::Malformed(format!("snapshot seed {seed:#x} is not captured executable memory")));
        }
    }
    let mut binary = Binary::from_snapshot(
        arch,
        snapshot.big_endian,
        snapshot.data_big_endian,
        snapshot.provenance,
        data,
        source,
        segments,
        sections,
        thumb,
        seeds,
        entry,
    )?;
    binary.snapshot_modules = snapshot.modules;
    binary.snapshot_registers = snapshot.registers;
    binary.snapshot_target = snapshot.target;
    Ok(binary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> serde_json::Value {
        serde_json::json!({
            "format": "rampage-snapshot-v1", "arch": "aarch64", "provenance": "unit fixture",
            "regions": [{"name": "code", "address": "0x1000", "permissions": "r-x", "bytes": "c0035fd6"}],
            "seeds": ["0x1000"], "entry": "0x1000"
        })
    }

    #[test]
    fn invalid_regions_seeds_and_formats_are_rejected_without_panics() {
        for (field, value) in [
            ("address", "0xffffffffffffffff"),
            ("address", "-1"),
            ("address", "0x+1"),
            ("bytes", "c00"),
            ("bytes", "zzzz"),
            ("bytes", "+1"),
            ("bytes", "éé"),
            ("permissions", "rwxanything"),
        ] {
            let mut input = fixture();
            input["regions"][0][field] = value.into();
            assert!(load(serde_json::to_vec(&input).unwrap(), None).is_err(), "{field}={value}");
        }
        let mut input = fixture();
        input["seeds"] = serde_json::json!(["0x2000"]);
        assert!(load(serde_json::to_vec(&input).unwrap(), None).is_err());
        let mut input = fixture();
        let duplicate = input["regions"][0].clone();
        input["regions"].as_array_mut().unwrap().push(duplicate);
        assert!(load(serde_json::to_vec(&input).unwrap(), None).is_err());
        let source = serde_json::to_vec(&fixture()).unwrap();
        for end in 0..source.len() {
            assert!(load(source[..end].to_vec(), None).is_err());
        }
        assert!(load(source, Some(Arch::X86_64)).is_err());
    }

    #[test]
    fn declared_target_context_is_preserved_and_malformed_context_is_rejected() {
        let mut input = fixture();
        input["target"] = serde_json::json!({"platform": "darwin", "compiler": "apple"});
        let binary = load(serde_json::to_vec(&input).unwrap(), None).unwrap();
        let context = binary.snapshot_target.unwrap();
        assert_eq!(context.platform, SnapshotPlatform::Darwin);
        assert_eq!(context.compiler.as_deref(), Some("apple"));
        for context in [
            serde_json::json!({"platform": "unknown"}),
            serde_json::json!({"platform": "darwin", "compiler": "../apple"}),
            serde_json::json!({"platform": "darwin", "compiler": ""}),
            serde_json::json!({"platform": "darwin", "compiler": "a".repeat(65)}),
        ] {
            input["target"] = context;
            assert!(load(serde_json::to_vec(&input).unwrap(), None).is_err());
        }
        input.as_object_mut().unwrap().remove("target");
        assert!(load(serde_json::to_vec(&input).unwrap(), None).unwrap().snapshot_target.is_none());
    }

    #[test]
    fn equivalent_uuid_spellings_cannot_create_ambiguous_module_mappings() {
        let mut input = fixture();
        input["modules"] = serde_json::json!([
            {"name": "first", "path": "first", "uuid": "0123456789abcdef0123456789abcdef",
                "image_base": "0x0", "runtime_base": "0x1000"},
            {"name": "second", "path": "second", "uuid": "01234567-89AB-CDEF-0123-456789ABCDEF",
                "image_base": "0x0", "runtime_base": "0x2000"}
        ]);
        assert!(load(serde_json::to_vec(&input).unwrap(), None).is_err());
        input["modules"][0]["uuid"] = serde_json::json!("fixture-uuid");
        input["modules"][1]["uuid"] = serde_json::json!("fixtureuuid");
        assert!(load(serde_json::to_vec(&input).unwrap(), None).is_ok());
        input["modules"][0]["uuid"] = serde_json::json!("0123456789abcdef0123456789abcdef");
        input["modules"][1]["uuid"] = serde_json::json!("0123456789abcdef0123456789abcdef-");
        assert!(load(serde_json::to_vec(&input).unwrap(), None).is_ok());
    }

    #[test]
    fn malformed_metadata_and_duplicate_registers_are_rejected() {
        let mut input = fixture();
        input["modules"] = serde_json::json!([{ "name": "fixture", "path": "file", "uuid": "uuid",
            "image_base": "0x0", "runtime_base": "-1" }]);
        assert!(load(serde_json::to_vec(&input).unwrap(), None).is_err());
        assert!(address(&format!("0x{}1", "0".repeat(1000))).is_err());
        let mut input = fixture();
        input["registers"] = serde_json::json!([
            { "thread_id": "0x1", "name": "sp", "value": "0x1000" },
            { "thread_id": "0x01", "name": "sp", "value": "0x2000" }
        ]);
        assert!(load(serde_json::to_vec(&input).unwrap(), None).is_err());
    }
}
