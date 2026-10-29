//! PE resources and load config, from `rampage_loaders::pe_resources` and `rampage_loaders::pe_load_config`: one
//! filterable page of resource leaves with RT_VERSION and RT_MANIFEST payloads decoded under a byte budget, and the
//! load config's security cookie, SafeSEH, CFG, CET and dynamic relocation evidence.

use std::collections::HashMap;

use rampage_loaders::pe_load_config::{self, PeLoadConfig};
use rampage_loaders::pe_resources::{self, PeResources, ResourceKey, ResourceLeaf, ResourcePayload};
use serde::Serialize;

use crate::rows::{FittedPage, fit_window, item_budget, json_size};
use crate::{ApiError, Project};

/// Serialized bytes of decoded payloads one page may carry beyond its first; later payloads are skipped and
/// counted. The first payload on a page is always decoded, so paging one at a time reaches every payload.
pub const MAX_RESOURCE_DECODE_BYTES: usize = 24_000;
/// Type rows listed; `types_total` counts them all.
pub const MAX_RESOURCE_TYPE_ROWS: usize = 256;
/// JSON bytes the type rows may take.
const MAX_RESOURCE_TYPE_BYTES: usize = 12_000;

/// One page of resource leaves whose type matches `type_filter` (`RT_ICON`, `ICON`, `3` or a string type name).
#[derive(Debug, Default, Clone)]
pub struct PeResourcesQuery {
    pub type_filter: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct PeResourcesSummary {
    pub directory_rva: Option<u32>,
    pub directory_size: Option<u32>,
    /// Every leaf the walk reached, before the type filter.
    pub total_leaves: usize,
    /// Leaves per type, in directory order: at most 256 rows, and fewer when they overrun their byte share.
    pub types: Vec<ResourceTypeCount>,
    /// Distinct types, numeric and string-named counted apart.
    pub types_total: usize,
    pub types_truncated: bool,
    /// `total` counts the leaves matching the filter; the page is cut to fit the result's JSON budget.
    pub resources: FittedPage<ResourceEntry>,
    pub returned: usize,
    /// RT_VERSION/RT_MANIFEST payloads on this page left undecoded because the page's decode budget was spent.
    pub decode_skipped: usize,
    pub tables_visited: usize,
    pub entries_visited: usize,
    /// Whether a walk limit stopped the directory walk early, so `total_leaves` is a lower bound.
    pub truncated: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceTypeCount {
    /// The numeric id or string name, so a string type named like a predefined one stays apart from it.
    #[serde(rename = "type")]
    pub type_key: ResourceKey,
    pub type_name: String,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct ResourceEntry {
    #[serde(flatten)]
    pub leaf: ResourceLeaf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<ResourcePayload>,
    /// Whether a decodable payload was left undecoded for the page's decode budget.
    #[serde(skip)]
    pub decode_skipped: bool,
}

impl Project {
    /// The PE resource directory, or `None` when the image is not a PE.
    pub fn pe_resources(&self, query: &PeResourcesQuery) -> Result<Option<PeResourcesSummary>, ApiError> {
        let Some(report) = pe_resources::resources(&self.binary)
            .map_err(|error| ApiError::Invalid(format!("malformed PE resources: {error}")))?
        else {
            return Ok(None);
        };
        summarize(report, self.binary.image_bytes(), query).map(Some)
    }

    /// The PE load config, CET and DllCharacteristics cross-checks, or `None` when the image is not a PE.
    pub fn pe_load_config(&self) -> Result<Option<PeLoadConfig>, ApiError> {
        pe_load_config::load_config(&self.binary)
            .map_err(|error| ApiError::Invalid(format!("malformed PE load config: {error}")))
    }
}

/// The type counts and one fitted page of `report`'s leaves, decoding payloads from `image`.
fn summarize(report: PeResources, image: &[u8], query: &PeResourcesQuery) -> Result<PeResourcesSummary, ApiError> {
    let counts = type_counts(&report.leaves);
    let types_total = counts.len();
    let types = fit_window(counts, MAX_RESOURCE_TYPE_ROWS, MAX_RESOURCE_TYPE_BYTES).map(|window| window.items)?;
    let total_leaves = report.leaves.len();
    let filter = query.type_filter.as_deref();
    let matching: Vec<ResourceLeaf> =
        report.leaves.into_iter().filter(|leaf| filter.is_none_or(|filter| leaf.matches_type(filter))).collect();
    let mut summary = PeResourcesSummary {
        directory_rva: report.directory_rva,
        directory_size: report.directory_size,
        total_leaves,
        types_truncated: types.len() < types_total,
        types,
        types_total,
        resources: FittedPage::empty(),
        returned: 0,
        decode_skipped: 0,
        tables_visited: report.tables_visited,
        entries_visited: report.entries_visited,
        truncated: report.truncated,
        warnings: report.warnings,
    };
    let budget = item_budget(&summary)?;
    let total = matching.len();
    let offset = query.offset.unwrap_or(0).min(total);
    let mut decoder = PayloadBudget { first: true, remaining: MAX_RESOURCE_DECODE_BYTES, row_budget: budget };
    let rows = matching.into_iter().skip(offset).map(|leaf| decoder.entry(image, leaf));
    summary.resources = FittedPage::fit(total, offset, query.limit, budget, rows)?;
    summary.returned = summary.resources.items.len();
    summary.decode_skipped = summary.resources.items.iter().filter(|entry| entry.decode_skipped).count();
    Ok(summary)
}

/// Leaves per type key, in directory order.
fn type_counts(leaves: &[ResourceLeaf]) -> Vec<ResourceTypeCount> {
    let mut rows: Vec<ResourceTypeCount> = Vec::new();
    let mut index: HashMap<&ResourceKey, usize> = HashMap::new();
    for leaf in leaves {
        let row = *index.entry(&leaf.type_key).or_insert_with(|| {
            rows.push(ResourceTypeCount {
                type_key: leaf.type_key.clone(),
                type_name: leaf.type_name.clone(),
                count: 0,
            });
            rows.len() - 1
        });
        rows[row].count += 1;
    }
    rows
}

/// Decides which payloads on a page are decoded: the first always (unless the row could not fit the page with
/// it), later ones while [`MAX_RESOURCE_DECODE_BYTES`] lasts. Once it is spent nothing more is decoded.
struct PayloadBudget {
    first: bool,
    remaining: usize,
    /// The JSON bytes one row may take at most.
    row_budget: usize,
}

impl PayloadBudget {
    fn entry(&mut self, image: &[u8], leaf: ResourceLeaf) -> ResourceEntry {
        if !leaf.is_decodable() {
            return ResourceEntry { leaf, decoded: None, decode_skipped: false };
        }
        if !self.first && self.remaining == 0 {
            return ResourceEntry { leaf, decoded: None, decode_skipped: true };
        }
        let decoded = pe_resources::decode(image, &leaf);
        let size = decoded.as_ref().map_or(Ok(0), json_size).unwrap_or(usize::MAX);
        let fits = if self.first {
            // Room for the `decoded` key and the row's braces besides the two parts.
            json_size(&leaf).is_ok_and(|leaf_size| leaf_size.saturating_add(size).saturating_add(64) <= self.row_budget)
        } else {
            size <= self.remaining
        };
        self.first = false;
        if fits {
            self.remaining = self.remaining.saturating_sub(size);
            ResourceEntry { leaf, decoded, decode_skipped: false }
        } else {
            ResourceEntry { leaf, decoded: None, decode_skipped: decoded.is_some() }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(type_key: ResourceKey, type_name: &str) -> ResourceLeaf {
        ResourceLeaf {
            type_key,
            type_name: type_name.to_owned(),
            name: None,
            language: None,
            data_rva: 0,
            size: 0,
            code_page: 0,
            file_offset: None,
            in_file: false,
        }
    }

    #[test]
    fn numeric_and_string_types_are_counted_apart() {
        let icon = leaf(ResourceKey::Id(3), "RT_ICON");
        let named = leaf(ResourceKey::Name("RT_ICON".to_owned()), "RT_ICON");
        let rows = type_counts(&[icon.clone(), named, icon]);
        let rows: Vec<_> = rows.iter().map(|row| (row.type_key.clone(), row.count)).collect();
        assert_eq!(rows, [(ResourceKey::Id(3), 2), (ResourceKey::Name("RT_ICON".to_owned()), 1)]);
    }

    fn report(leaves: Vec<ResourceLeaf>) -> PeResources {
        PeResources {
            directory_rva: Some(0x1000),
            directory_size: Some(0x100),
            leaves,
            tables_visited: 1,
            entries_visited: 1,
            truncated: false,
            warnings: Vec::new(),
        }
    }

    /// `count` RT_MANIFEST leaves, each pointing at the same `size` bytes of manifest text at the image's start.
    fn manifests(count: usize, size: usize) -> (Vec<ResourceLeaf>, Vec<u8>) {
        let image = format!("<assembly>{}</assembly>", "x".repeat(size)).into_bytes();
        let mut manifest = leaf(ResourceKey::Id(24), "RT_MANIFEST");
        (manifest.file_offset, manifest.size, manifest.in_file) = (Some(0), image.len() as u32, true);
        (vec![manifest; count], image)
    }

    #[test]
    fn decoding_stops_once_the_page_budget_is_spent() {
        let (leaves, image) = manifests(6, 8_000);
        let summary = summarize(report(leaves), &image, &PeResourcesQuery::default()).unwrap();
        let decoded = summary.resources.items.iter().filter(|entry| entry.decoded.is_some()).count();
        assert!((1..6).contains(&decoded), "{decoded}");
        assert_eq!(summary.decode_skipped, summary.returned - decoded);
        assert!(summary.decode_skipped > 0);
        assert!(json_size(&summary).unwrap() <= crate::tools::MAX_RESULT_CHARS);
    }

    #[test]
    fn the_first_payload_on_a_page_is_decoded_even_past_the_decode_budget() {
        let (leaves, image) = manifests(2, 2 * MAX_RESOURCE_DECODE_BYTES);
        let summary = summarize(report(leaves), &image, &PeResourcesQuery::default()).unwrap();
        assert!(summary.resources.items[0].decoded.is_some());
        assert!(summary.resources.items.get(1).is_none_or(|entry| entry.decoded.is_none()));
        let next = PeResourcesQuery { offset: Some(1), limit: Some(1), ..Default::default() };
        let (leaves, image) = manifests(2, 2 * MAX_RESOURCE_DECODE_BYTES);
        let summary = summarize(report(leaves), &image, &next).unwrap();
        assert!(summary.resources.items[0].decoded.is_some());
    }

    #[test]
    fn long_rows_are_byte_capped_into_whole_pages() {
        let leaves: Vec<_> = (0..200)
            .map(|index| {
                let mut row = leaf(ResourceKey::Id(10), "RT_RCDATA");
                row.name = Some(ResourceKey::Name(format!("{index}-{}", "n".repeat(700))));
                row
            })
            .collect();
        let query = PeResourcesQuery { limit: Some(1000), ..Default::default() };
        let summary = summarize(report(leaves), &[], &query).unwrap();
        let page = &summary.resources;
        assert!(page.byte_capped && page.items.len() < 200);
        assert_eq!(page.next_offset, Some(page.items.len()));
        assert!(json_size(&summary).unwrap() <= crate::tools::MAX_RESULT_CHARS);
    }

    #[test]
    fn type_rows_are_capped() {
        let leaves: Vec<_> =
            (0..1000).map(|index| leaf(ResourceKey::Name(format!("T{index}")), &format!("T{index}"))).collect();
        let summary = summarize(report(leaves), &[], &PeResourcesQuery::default()).unwrap();
        assert_eq!((summary.types.len(), summary.types_total), (MAX_RESOURCE_TYPE_ROWS, 1000));
        assert!(summary.types_truncated);
        assert!(json_size(&summary).unwrap() <= crate::tools::MAX_RESULT_CHARS);
    }

    #[test]
    fn many_distinct_types_are_counted_in_linear_time() {
        let leaves: Vec<_> =
            (0..16_384).map(|index| leaf(ResourceKey::Name(format!("{index:0>200}")), "long")).collect();
        let started = std::time::Instant::now();
        assert_eq!(type_counts(&leaves).len(), 16_384);
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }
}
