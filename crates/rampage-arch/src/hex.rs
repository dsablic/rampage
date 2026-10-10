//! Serializes addresses as `"0x…"` strings. JSON numbers lose precision above 2^53 in many consumers
//! (JavaScript, jq), and hex is how people and models read addresses anyway.

use serde::Serializer;
use serde::ser::SerializeSeq;

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
