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
    let value = text
        .strip_prefix("0x")
        .filter(|hex| !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok());
    value.ok_or_else(|| LoadError::Malformed(format!("expected a hexadecimal address, got {text:?}")))
}

pub(crate) fn load(source: Vec<u8>, wanted: Option<Arch>) -> Result<Binary, LoadError> {
    let snapshot: Snapshot = serde_json::from_slice(&source)
        .map_err(|error| LoadError::Malformed(format!("invalid memory snapshot: {error}")))?;
    if snapshot.format != "rampage-snapshot-v1" || snapshot.regions.is_empty() || snapshot.regions.len() > 4096 {
        return Err(LoadError::Malformed("expected rampage-snapshot-v1 with 1–4096 regions".to_owned()));
    }
    let arch: Arch = snapshot.arch.parse().map_err(LoadError::Unsupported)?;
    if wanted.is_some_and(|wanted| wanted != arch) {
        return Err(LoadError::Unsupported(format!("snapshot architecture is {arch}")));
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
    Binary::from_snapshot(
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
    )
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
}
