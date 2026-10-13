//! Queries and the rows they return.

use rampage_arch::Arch;
use rampage_loaders::{Format, Section, Segment};
use serde::{Deserialize, Serialize};

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
