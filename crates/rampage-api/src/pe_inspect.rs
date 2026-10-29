//! PE resources and load config, from `rampage_loaders::pe_resources` and `rampage_loaders::pe_load_config`: one
//! filterable page of resource leaves with RT_VERSION and RT_MANIFEST payloads decoded under a byte budget, and the
//! load config's security cookie, SafeSEH, CFG, CET and dynamic relocation evidence.

use rampage_loaders::pe_load_config::{self, PeLoadConfig};
use rampage_loaders::pe_resources::{self, ResourceLeaf, ResourcePayload};
use serde::Serialize;

use crate::{ApiError, Page, Project};

/// Serialized bytes of decoded payloads one page may carry; later payloads are skipped and counted.
pub const MAX_RESOURCE_DECODE_BYTES: usize = 24_000;

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
    /// Leaves per type, in directory order.
    pub types: Vec<ResourceTypeCount>,
    /// `total` counts the leaves matching the filter.
    pub resources: Page<ResourceEntry>,
    pub returned: usize,
    /// RT_VERSION/RT_MANIFEST payloads on this page left undecoded because the page's decode budget was spent.
    pub decode_skipped: usize,
    pub tables_visited: usize,
    pub entries_visited: usize,
    /// Whether a walk limit stopped the directory walk early, so `total_leaves` is a lower bound.
    pub truncated: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ResourceTypeCount {
    pub type_name: String,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct ResourceEntry {
    #[serde(flatten)]
    pub leaf: ResourceLeaf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<ResourcePayload>,
}

impl Project {
    /// The PE resource directory, or `None` when the image is not a PE.
    pub fn pe_resources(&self, query: &PeResourcesQuery) -> Result<Option<PeResourcesSummary>, ApiError> {
        let Some(report) = pe_resources::resources(&self.binary)
            .map_err(|error| ApiError::Invalid(format!("malformed PE resources: {error}")))?
        else {
            return Ok(None);
        };
        let mut types: Vec<ResourceTypeCount> = Vec::new();
        for leaf in &report.leaves {
            match types.iter_mut().find(|count| count.type_name == leaf.type_name) {
                Some(count) => count.count += 1,
                None => types.push(ResourceTypeCount { type_name: leaf.type_name.clone(), count: 1 }),
            }
        }
        let total_leaves = report.leaves.len();
        let filter = query.type_filter.as_deref();
        let page = Page::of(
            report.leaves.into_iter().filter(|leaf| filter.is_none_or(|filter| leaf.matches_type(filter))),
            query.offset,
            query.limit,
        );
        let image = self.binary.image_bytes();
        let (mut budget, mut decode_skipped) = (MAX_RESOURCE_DECODE_BYTES, 0);
        let resources = page.map(|leaf| {
            let decoded = pe_resources::decode(image, &leaf).filter(|payload| {
                let size = serde_json::to_string(payload).map_or(usize::MAX, |text| text.len());
                let fits = size <= budget;
                if fits {
                    budget -= size;
                } else {
                    decode_skipped += 1;
                }
                fits
            });
            ResourceEntry { leaf, decoded }
        });
        Ok(Some(PeResourcesSummary {
            directory_rva: report.directory_rva,
            directory_size: report.directory_size,
            total_leaves,
            types,
            returned: resources.items.len(),
            resources,
            decode_skipped,
            tables_visited: report.tables_visited,
            entries_visited: report.entries_visited,
            truncated: report.truncated,
            warnings: report.warnings,
        }))
    }

    /// The PE load config, CET and DllCharacteristics cross-checks, or `None` when the image is not a PE.
    pub fn pe_load_config(&self) -> Result<Option<PeLoadConfig>, ApiError> {
        pe_load_config::load_config(&self.binary)
            .map_err(|error| ApiError::Invalid(format!("malformed PE load config: {error}")))
    }
}
