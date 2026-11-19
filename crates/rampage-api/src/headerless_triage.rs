//! `triage` of a file with no recognised executable header: what the file holds at container level (its layout,
//! compressed-component candidates, embedded executables) and the calls that read it further, instead of an error.

use std::path::Path;

use serde_json::{Value, json};

use crate::ApiError;

/// Occupied regions listed, largest first.
const MAX_REGIONS: usize = 12;
/// Compressed-component candidates and carve candidates listed.
const MAX_CANDIDATES: usize = 8;

/// The container-level triage of `path`, which `reason` says could not be parsed as an executable: a
/// `file_layout` summary of its first 64 MiB (largest occupied regions, entropy, fill), the compressed components
/// its headers describe, `carve`'s first candidates and the concrete follow-up calls. Nothing is decoded.
pub fn headerless_triage(path: &Path, reason: &str) -> Result<Value, ApiError> {
    let layout = crate::file_layout(path, &crate::FileLayoutRequest { hints: Some(true), ..Default::default() })?;
    let layout = serde_json::to_value(&layout).map_err(|error| ApiError::Invalid(error.to_string()))?;
    let path_text = path.to_string_lossy();
    let mut regions: Vec<&Value> =
        layout["regions"].as_array().into_iter().flatten().filter(|region| region["kind"] == "occupied").collect();
    regions.sort_by_key(|region| std::cmp::Reverse(region["length"].as_u64().unwrap_or(0)));
    let largest: Vec<Value> = regions
        .iter()
        .take(MAX_REGIONS)
        .map(|region| {
            json!({
                "offset": region["offset"],
                "length": region["length"],
                "entropy_bits_per_byte": region["entropy_bits_per_byte"],
            })
        })
        .collect();
    let components: Vec<Value> = layout["hints"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hint| hint.get("container").cloned())
        .take(MAX_CANDIDATES)
        .map(|mut component| {
            // file_layout keeps the header's uninterpreted words; the summary leaves them there.
            if let Some(fields) = component.as_object_mut() {
                fields.remove("other_header_words");
            }
            component
        })
        .collect();
    let mut next = Vec::new();
    for component in &components {
        let sizes: Vec<u64> = component["decoded_size_candidates"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|word| word["value"].as_u64())
            .collect();
        let mut arguments = json!({
            "path": path_text,
            "offset": component["payload_offset"],
            "length": component["payload_length"],
        });
        if let Some(&size) = sizes.first() {
            arguments["expected_output_size"] = json!(size);
        }
        next.push(json!({
            "tool": "probe_compression",
            "arguments": arguments,
            "why": "a header describes this payload; the probe ranks codecs and gives `open_as_raw` for the winner",
        }));
    }
    if components.is_empty() {
        // No header described a payload: probe the largest high-entropy regions directly.
        for region in regions.iter().filter(|region| region["entropy_bits_per_byte"].as_f64() > Some(7.2)).take(3) {
            next.push(json!({
                "tool": "probe_compression",
                "arguments": { "path": path_text, "offset": region["offset"], "length": region["length"] },
                "why": "a high-entropy region: compressed or encrypted; the probe tells which codecs decode it",
            }));
        }
    }
    next.push(json!({
        "tool": "binary_info",
        "arguments": { "path": path_text, "raw": "the probe's open_as_raw, plus profile (e.g. cortex-m) and base_address" },
        "why": "opens the decoded image as a Raw project; every raw-capable tool then takes the same `raw`",
    }));
    let carving = crate::carve(path, Some(MAX_CANDIDATES)).ok();
    let embedded: Vec<Value> = carving
        .as_ref()
        .map(|carving| carving.candidates.iter().take(MAX_CANDIDATES).filter_map(|c| serde_json::to_value(c).ok()))
        .into_iter()
        .flatten()
        .collect();
    if !embedded.is_empty() {
        next.push(json!({
            "tool": "triage",
            "arguments": { "path": path_text, "image_offset": "an embedded candidate's offset" },
            "why": "carve found executables inside the file",
        }));
    }
    Ok(json!({
        "parsed_as_executable": false,
        "reason": reason,
        "file_size": layout["source_size"],
        "layout": {
            "summary": layout["summary"],
            "whole_range_entropy": layout["entropy"]["whole_range"],
            "largest_occupied_regions": largest,
            "regions_total": layout["bounds"]["regions"]["total"],
        },
        "compressed_components": components,
        "embedded_executables": embedded,
        "next": next,
        "limitations": [
            "Container-level only: nothing was decoded, mapped or executed. file_layout lists every region; \
             compressed-component fields are inferred from values, not known.",
            "Only the first 64 MiB were laid out.",
        ],
    }))
}

#[cfg(test)]
mod tests {
    use rampage_decode::Lzss;
    use rampage_decode::encode;

    use super::*;

    /// Seventh Haiku run: `triage` on a compressed update file only errored, and the agent found the layout and
    /// the decoder itself. It now names the payloads and the probe calls for them.
    #[test]
    fn a_container_file_gets_its_layout_components_and_next_calls() {
        let plain = encode::synthetic_firmware(24 << 10, 1);
        let packed = encode::lzss(&Lzss::classic_4k(4078, 0), &plain);
        let mut file = vec![0xff; 256];
        let header = file.len();
        file.extend(0x6000_0000u32.to_le_bytes());
        file.extend((packed.len() as u32).to_le_bytes());
        file.extend((plain.len() as u32).to_le_bytes());
        file.extend(packed.iter().fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte))).to_le_bytes());
        file.extend(&packed);
        file.extend([0xff; 512]);
        let directory = std::env::temp_dir().join(format!("rampage-headerless-triage-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("update.bin");
        std::fs::write(&path, &file).unwrap();
        let report = headerless_triage(&path, "no header").unwrap();
        std::fs::remove_dir_all(&directory).unwrap();
        assert_eq!(report["parsed_as_executable"], false, "{report:#}");
        assert_eq!(report["compressed_components"][0]["payload_offset"], header + 16, "{report:#}");
        let probe = &report["next"][0];
        assert_eq!(probe["tool"], "probe_compression", "{report:#}");
        assert_eq!(probe["arguments"]["offset"], header + 16, "{report:#}");
        assert_eq!(probe["arguments"]["length"], packed.len(), "{report:#}");
        assert_eq!(probe["arguments"]["expected_output_size"], plain.len(), "{report:#}");
        assert!(report["next"].as_array().unwrap().iter().any(|call| call["tool"] == "binary_info"), "{report:#}");
    }
}
