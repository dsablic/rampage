//! File offsets and byte counts as every client takes them: the CLI's `--image-offset`, MCP's `image_offset` and
//! the tools' own offset arguments all accept the same spellings and reject the rest with the same message.

use std::borrow::Cow;

use serde::de::{self, Deserializer, Visitor};

/// What a file offset may look like, for error messages.
const SPELLINGS: &str = "a non-negative integer, or a string in hex (\"0x1000\") or decimal";

/// Parses a file offset or byte count written in hex (`0x...`) or decimal.
pub fn parse_file_offset(text: &str) -> Result<u64, String> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    }
    .map_err(|_| format!("{text:?} is not a file offset or byte count: give {SPELLINGS}"))
}

/// A file offset or byte count argument: an integer, or a string in hex (`0x...`) or decimal. Anything else, such
/// as `-1` or `1.5`, fails to deserialize with a message that says what is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileOffset(pub u64);

impl<'de> serde::Deserialize<'de> for FileOffset {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OffsetVisitor;

        impl Visitor<'_> for OffsetVisitor {
            type Value = FileOffset;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a file offset or byte count: {SPELLINGS}")
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<FileOffset, E> {
                Ok(FileOffset(value))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<FileOffset, E> {
                u64::try_from(value)
                    .map(FileOffset)
                    .map_err(|_| E::custom(format!("{value} is not a file offset or byte count: give {SPELLINGS}")))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<FileOffset, E> {
                Err(E::custom(format!("{value} is not a file offset or byte count: give {SPELLINGS}")))
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<FileOffset, E> {
                parse_file_offset(text).map(FileOffset).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(OffsetVisitor)
    }
}

impl schemars::JsonSchema for FileOffset {
    fn schema_name() -> Cow<'static, str> {
        "FileOffset".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "A file offset or byte count: an integer, or a string in hex (\"0x1000\") or decimal.",
            "anyOf": [{ "type": "integer", "minimum": 0 }, { "type": "string" }]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_json(text: &str) -> Result<u64, String> {
        serde_json::from_str::<FileOffset>(text).map(|offset| offset.0).map_err(|error| error.to_string())
    }

    #[test]
    fn integers_and_hex_or_decimal_strings_are_offsets() {
        assert_eq!(from_json("4096"), Ok(4096));
        assert_eq!(from_json("\"0x1000\""), Ok(4096));
        assert_eq!(from_json("\"0X1000\""), Ok(4096));
        assert_eq!(from_json("\"4096\""), Ok(4096));
        assert_eq!(parse_file_offset("0x10"), Ok(16));
    }

    #[test]
    fn anything_else_is_refused_with_what_is_accepted() {
        for text in ["-1", "1.5", "\"-1\"", "\"0xzz\"", "\"\"", "true", "null", "[1]"] {
            let error = from_json(text).unwrap_err();
            assert!(error.contains("file offset or byte count"), "{text}: {error}");
            assert!(error.contains("\"0x1000\""), "{text}: {error}");
            assert!(!error.contains("untagged"), "{text}: {error}");
        }
        assert!(parse_file_offset("1.5").unwrap_err().contains("hex (\"0x1000\") or decimal"));
    }
}
