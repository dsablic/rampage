//! Typed transport selectors for the native search API. Immediates are never resolved as addresses.

use std::path::Path;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use crate::search::{
    SearchBudget, SearchImmediate, SearchMode, SearchQuery, SearchRange, SearchReference, SearchStringEncoding,
    SearchTextEncoding,
};
use crate::{ApiError, Project};

pub const MAX_SEARCH_REQUEST_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum SearchAddress {
    Number(u64),
    Name(String),
}

impl SearchAddress {
    fn resolve(&self, project: &Project) -> Result<u64, ApiError> {
        match self {
            Self::Number(address) => Ok(*address),
            Self::Name(name) => project.resolve(name),
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchRequestRange {
    pub start: SearchAddress,
    pub end: SearchAddress,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SearchRequestReference {
    Address { target: SearchAddress },
    String { text: String, encoding: SearchStringEncoding },
    Import { name: String, library: Option<String> },
    Constant { immediate: SearchImmediate },
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SearchRequestMode {
    Bytes {
        pattern: String,
    },
    Text {
        pattern: String,
        encoding: SearchTextEncoding,
        #[serde(default)]
        regex: bool,
    },
    Immediate {
        immediate: SearchImmediate,
    },
    Instruction {
        mnemonic: Option<String>,
        operands: Option<String>,
    },
    References {
        target: SearchAddress,
    },
    FunctionsReferencing {
        reference: SearchRequestReference,
    },
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchRequest {
    pub mode: SearchRequestMode,
    /// Half-open virtual address range. Each endpoint accepts a number, address string or resolvable name.
    #[serde(default)]
    pub range: Option<SearchRequestRange>,
    /// Hit rows to skip, never a scan limit. Continuation offsets only page already observed hits.
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_limit")]
    #[schemars(range(min = 1, max = 1000))]
    pub limit: usize,
    /// Defaults true for transports; context names preserve native symbol provenance and truncation markers.
    #[serde(default = "default_context")]
    pub include_context: bool,
    #[serde(default)]
    pub budget: SearchBudget,
}

fn default_limit() -> usize {
    100
}

fn default_context() -> bool {
    true
}

impl SearchRequest {
    pub fn from_json(bytes: &[u8]) -> Result<Self, ApiError> {
        if bytes.len() > MAX_SEARCH_REQUEST_BYTES {
            return Err(ApiError::Invalid("search request exceeds 1 MiB".to_owned()));
        }
        serde_json::from_slice(bytes).map_err(|error| ApiError::Invalid(format!("invalid search request: {error}")))
    }

    /// Read a complete, stable bounded regular file using checked source descriptors, never target metadata.
    /// Platforms without the checked RangeSource reader can use an inline JSON request instead.
    pub fn from_file(path: &Path) -> Result<Self, ApiError> {
        let size = crate::range_source::RangeSource::open(path, 0, 0)?.size();
        if size > MAX_SEARCH_REQUEST_BYTES as u64 {
            return Err(ApiError::Invalid("search request exceeds 1 MiB".to_owned()));
        }
        let source = crate::range_source::RangeSource::open(path, 0, size as usize)?;
        if source.size() != size {
            return Err(ApiError::Unavailable("search request size changed while opening".to_owned()));
        }
        let bytes = source.read()?;
        source.revalidate()?;
        Self::from_json(&bytes)
    }

    pub fn resolve(&self, project: &Project) -> Result<SearchQuery, ApiError> {
        let mode = match &self.mode {
            SearchRequestMode::Bytes { pattern } => SearchMode::Bytes { pattern: pattern.clone() },
            SearchRequestMode::Text { pattern, encoding, regex } => {
                SearchMode::Text { pattern: pattern.clone(), encoding: *encoding, regex: *regex }
            }
            SearchRequestMode::Immediate { immediate } => SearchMode::Immediate { immediate: immediate.clone() },
            SearchRequestMode::Instruction { mnemonic, operands } => {
                SearchMode::Instruction { mnemonic: mnemonic.clone(), operands: operands.clone() }
            }
            SearchRequestMode::References { target } => SearchMode::References { target: target.resolve(project)? },
            SearchRequestMode::FunctionsReferencing { reference } => SearchMode::FunctionsReferencing {
                reference: match reference {
                    SearchRequestReference::Address { target } => {
                        SearchReference::Address { target: target.resolve(project)? }
                    }
                    SearchRequestReference::String { text, encoding } => {
                        SearchReference::String { text: text.clone(), encoding: *encoding }
                    }
                    SearchRequestReference::Import { name, library } => {
                        SearchReference::Import { name: name.clone(), library: library.clone() }
                    }
                    SearchRequestReference::Constant { immediate } => {
                        SearchReference::Constant { immediate: immediate.clone() }
                    }
                },
            },
        };
        let range = self
            .range
            .as_ref()
            .map(|range| {
                Ok::<_, ApiError>(SearchRange {
                    start: range.start.resolve(project)?,
                    end: range.end.resolve(project)?,
                })
            })
            .transpose()?;
        Ok(SearchQuery {
            mode,
            range,
            offset: self.offset,
            limit: self.limit,
            include_context: self.include_context,
            budget: self.budget,
        })
    }
}

impl Project {
    /// Resolve typed transport selectors and return a complete byte-bounded page from one native search.
    pub fn search_page(&self, request: &SearchRequest) -> Result<Value, ApiError> {
        crate::tools::search_page::page(self, request)
    }
}
