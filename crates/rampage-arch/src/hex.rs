//! Serializes addresses as `"0x…"` strings. JSON numbers lose precision above 2^53 in many consumers
//! (JavaScript, jq), and hex is how people and models read addresses anyway.

use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serializer};

pub fn address<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("{value:#x}"))
}

pub fn optional_address<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => address(value, serializer),
        None => serializer.serialize_none(),
    }
}

pub fn addresses<S: Serializer>(values: &[u64], serializer: S) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_seq(Some(values.len()))?;
    for value in values {
        seq.serialize_element(&format_args!("{value:#x}").to_string())?;
    }
    seq.end()
}

/// Parses a `"0x…"` address, the inverse of [`address`].
pub fn deserialize_address<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let text = String::deserialize(deserializer)?;
    let digits = text.strip_prefix("0x").ok_or_else(|| serde::de::Error::custom("address must start with 0x"))?;
    u64::from_str_radix(digits, 16).map_err(serde::de::Error::custom)
}

/// Lowercase hex digits for `bytes`, without separators.
pub fn bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}
