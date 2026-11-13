//! Queries and the rows they return.

use rampage_arch::Arch;
use rampage_loaders::{Format, Section, Segment};
use serde::{Deserialize, Serialize};

use crate::ApiError;
use crate::annotations::Field;

#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct FunctionsQuery {
    /// Only functions whose name contains this text (case-insensitive).
    pub name_contains: Option<String>,
    /// Rows to skip.
    pub offset: Option<usize>,
    /// Most rows to return.
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct ListQuery {
    /// Only entries whose name or library contains this text (case-insensitive).
    pub contains: Option<String>,
    /// Rows to skip.
    pub offset: Option<usize>,
    /// Most rows to return.
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct StringsQuery {
    /// Minimum length in characters (default 4).
    pub min_len: Option<usize>,
    /// Only strings containing this text (case-insensitive).
    pub contains: Option<String>,
    /// Rows to skip.
    pub offset: Option<usize>,
    /// Most rows to return.
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct Page<T> {
    pub total: usize,
    pub offset: usize,
    pub items: Vec<T>,
}

impl<T> Page<T> {
    /// The `limit` items after the first `offset`, out of everything `items` yields.
    pub(crate) fn of(items: impl IntoIterator<Item = T>, offset: Option<usize>, limit: Option<usize>) -> Self {
        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or(usize::MAX);
        let mut total = 0;
        let mut window = Vec::new();
        for item in items {
            if total >= offset && window.len() < limit {
                window.push(item);
            }
            total += 1;
        }
        Page { total, offset: offset.min(total), items: window }
    }

    pub(crate) fn map<U>(self, convert: impl FnMut(T) -> U) -> Page<U> {
        Page { total: self.total, offset: self.offset, items: self.items.into_iter().map(convert).collect() }
    }
}

/// A page of a list fitted to the tool-result JSON budget as well as to `limit`: whole items only, and always at
/// least the first one (a first item too large for the budget is an error, so paging always progresses).
#[derive(Debug, Serialize)]
pub struct FittedPage<T> {
    pub total: usize,
    pub offset: usize,
    pub items: Vec<T>,
    /// Where the next page starts; `None` on the last page.
    pub next_offset: Option<usize>,
    /// Whether the JSON byte budget, not `limit`, ended the page.
    pub byte_capped: bool,
}

impl<T: Serialize> FittedPage<T> {
    /// An empty page, standing in for the real one while the rest of a result is measured.
    pub(crate) fn empty() -> Self {
        Self { total: 0, offset: 0, items: Vec::new(), next_offset: None, byte_capped: false }
    }

    /// The items after the first `offset` of `items`, as many as `limit` allows and fit `budget` JSON bytes.
    pub(crate) fn of(
        items: Vec<T>,
        offset: Option<usize>,
        limit: Option<usize>,
        budget: usize,
    ) -> Result<Self, ApiError> {
        let total = items.len();
        let offset = offset.unwrap_or(0).min(total);
        Self::fit(total, offset, limit, budget, items.into_iter().skip(offset))
    }

    /// Like [`FittedPage::of`] for `rest`, the items of a `total`-long list from `offset` on, produced lazily.
    pub(crate) fn fit(
        total: usize,
        offset: usize,
        limit: Option<usize>,
        budget: usize,
        rest: impl IntoIterator<Item = T>,
    ) -> Result<Self, ApiError> {
        let window = fit_window(rest, limit.unwrap_or(usize::MAX), budget)?;
        let next = offset.saturating_add(window.items.len());
        Ok(Self {
            total,
            offset,
            next_offset: (next < total).then_some(next),
            items: window.items,
            byte_capped: window.byte_capped,
        })
    }
}

/// The items of one page and whether the byte budget ended it.
pub(crate) struct Window<T> {
    pub items: Vec<T>,
    pub byte_capped: bool,
}

/// Bytes kept free beside a measured header for the paging numbers it does not hold yet.
const PAGING_SLACK: usize = 96;

/// The JSON bytes a result's list items may take once `header` (the result without them) is in it.
pub(crate) fn item_budget(header: &impl Serialize) -> Result<usize, ApiError> {
    crate::tools::MAX_RESULT_CHARS
        .checked_sub(json_size(header)? + PAGING_SLACK)
        .ok_or_else(|| ApiError::Invalid("the result's fixed fields exceed its JSON byte budget".to_owned()))
}

/// At most `limit` items from the start of `items`, as many whole ones as fit `budget` JSON bytes. A first item
/// that cannot fit is an error rather than an empty page, so paging always progresses.
pub(crate) fn fit_window<T: Serialize>(
    items: impl IntoIterator<Item = T>,
    limit: usize,
    budget: usize,
) -> Result<Window<T>, ApiError> {
    let mut window = Window { items: Vec::new(), byte_capped: false };
    let mut used = 0;
    for item in items.into_iter().take(limit) {
        // One more byte for the separating comma.
        let size = json_size(&item)? + 1;
        if used + size > budget {
            if window.items.is_empty() {
                return Err(ApiError::Invalid(format!(
                    "one item is {size} JSON bytes, over the {budget} this result has room for"
                )));
            }
            window.byte_capped = true;
            break;
        }
        used += size;
        window.items.push(item);
    }
    Ok(window)
}

/// The compact JSON length of `value`, as a tool result is sent.
pub(crate) fn json_size(value: &impl Serialize) -> Result<usize, ApiError> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|error| ApiError::Invalid(format!("result is not JSON-serializable: {error}")))
}

/// How a unit enum variant (a kind, a confidence) reads in JSON, so text output uses the same words.
pub fn label(value: &impl Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(text)) => text,
        Ok(other) => other.to_string(),
        Err(_) => "?".to_owned(),
    }
}

/// A case-insensitive substring filter; without a needle it matches everything.
pub(crate) struct Matcher(Option<String>);

impl Matcher {
    pub(crate) fn new(needle: Option<&str>) -> Self {
        Self(needle.map(str::to_lowercase))
    }

    pub(crate) fn is_everything(&self) -> bool {
        self.0.is_none()
    }

    pub(crate) fn matches(&self, text: &str) -> bool {
        self.0.as_deref().is_none_or(|needle| text.to_lowercase().contains(needle))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn labels_match_the_json() {
        assert_eq!(super::label(&rampage_loaders::dotnet::BodyKind::Il), "il");
        assert_eq!(super::label(&rampage_detect::Kind::Packer), "packer");
        assert_eq!(super::label(&rampage_detect::Kind::Runtime), "runtime");
        assert_eq!(super::label(&3), "3");
    }

    #[test]
    fn fitted_pages_hold_whole_items_within_the_budget() {
        let items: Vec<String> = (0..10).map(|index| format!("{index}{}", "x".repeat(98))).collect();
        // Each item is 101 JSON bytes plus a comma.
        let page = super::FittedPage::of(items.clone(), Some(2), Some(5), 350).unwrap();
        assert_eq!((page.items.len(), page.byte_capped, page.next_offset, page.total), (3, true, Some(5), 10));
        assert!(page.items[0].starts_with('2'));
        let page = super::FittedPage::of(items.clone(), Some(8), None, 10_000).unwrap();
        assert_eq!((page.items.len(), page.byte_capped, page.next_offset), (2, false, None));
        let page = super::FittedPage::of(items.clone(), Some(20), None, 10_000).unwrap();
        assert_eq!((page.offset, page.items.len(), page.next_offset), (10, 0, None));
        let error = super::FittedPage::of(items, None, None, 50).unwrap_err();
        assert!(error.to_string().contains("one item is 102 JSON bytes"), "{error}");
    }
}

#[derive(Debug, Serialize)]
pub struct Summary<'a> {
    pub format: Format,
    pub arch: Arch,
    pub slices: &'a [Arch],
    /// Where the image lies in the outer file, when it was opened at an offset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded: Option<rampage_loaders::Embedded>,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub entry: Option<u64>,
    pub segments: &'a [Segment],
    pub sections: &'a [Section],
    pub symbols: usize,
    pub imports: usize,
    pub exports: usize,
    pub function_starts: usize,
    pub warnings: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<&'a str>,
    #[serde(skip_serializing_if = "<[rampage_loaders::snapshot::SnapshotModule]>::is_empty")]
    pub snapshot_modules: &'a [rampage_loaders::snapshot::SnapshotModule],
    #[serde(skip_serializing_if = "<[rampage_loaders::snapshot::SnapshotRegister]>::is_empty")]
    pub snapshot_registers: &'a [rampage_loaders::snapshot::SnapshotRegister],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_target: Option<&'a rampage_loaders::snapshot::SnapshotTarget>,
    /// A Raw Project's asserted interpretation, with vector-table evidence when seeding was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<RawSummary<'a>>,
    /// The persistent analysis store's part in this project's analysis (hit, miss, pending, disabled, ...).
    pub analysis_store: crate::AnalysisStoreStatus,
}

#[derive(Debug, Serialize)]
pub struct RawSummary<'a> {
    pub profile: rampage_loaders::RawProfile,
    /// Base address and byte count of the primary code region, `regions[0]`.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub base_address: u64,
    pub length: u64,
    /// Discovery seeds, supplied, vector-table handlers and pointer-table targets together (the entry is counted
    /// separately).
    pub seed_count: usize,
    /// Every mapped region, the primary code region first: kind, mapping, SHA-256 of its bytes and where they came
    /// from (a file range, a decoder provider's receipt, record data, or nothing for unbacked RAM).
    pub regions: &'a [rampage_loaders::RawRegionInfo],
    /// Intel HEX or S-record input: the format, data records read and the verdict on the start-address record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records: Option<&'a rampage_loaders::RawRecordsEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector_table: Option<&'a rampage_loaders::raw_vectors::VectorTable>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer_tables: Option<&'a rampage_loaders::raw_pointers::PointerTables>,
}

#[derive(Debug, Serialize)]
pub struct FunctionRow {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
    /// Bytes covered by the function's blocks.
    pub size: u64,
    pub blocks: usize,
    pub instructions: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportRow {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    pub name: String,
    /// Where the loader stores the import's address, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub slot: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Annotation {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub text: String,
}

/// The user's names and comments.
#[derive(Debug, Clone, Serialize)]
pub struct AnnotationList {
    /// Why the annotations may not fit this image, such as having been made on another build of it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub names: Vec<Annotation>,
    pub comments: Vec<Annotation>,
    pub signatures: Vec<Annotation>,
    pub types: Vec<Annotation>,
    pub globals: Vec<Annotation>,
    pub local_names: Vec<Annotation>,
    pub local_types: Vec<Annotation>,
    pub type_library: Vec<Annotation>,
    pub data_types: Vec<Annotation>,
    pub operand_types: Vec<Annotation>,
    pub type_hints: Vec<Annotation>,
    pub debug_types: Vec<Annotation>,
}

/// The outcome of a rename or comment.
#[derive(Debug, Clone, Serialize)]
pub struct EditResult {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub field: Field,
    /// The value now set, or `None` when it was removed.
    pub value: Option<String>,
    /// False when the value was already set.
    pub changed: bool,
}
