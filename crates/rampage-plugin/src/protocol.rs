use std::io::{self, Read, Write};

use serde::Serialize;

use crate::{MAX_OUTPUT_BYTES, PluginError};

mod raw;

pub(crate) const VERSION: u32 = 1;
pub(crate) const MAX_REQUEST_BYTES: usize = 15 * 1024 * 1024;
pub(crate) const MAX_RESPONSE_BYTES: usize = MAX_OUTPUT_BYTES * 2 + 4096;
pub(crate) const MAX_STDERR_BYTES: usize = 64 * 1024;

#[derive(Serialize)]
pub(crate) struct Request<'a> {
    pub version: u32,
    pub component_hex: &'a str,
    pub input_hex: &'a str,
    pub fuel: u64,
    pub execution_timeout_ms: u64,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum Response<'a> {
    Ok { version: u32, output_hex: &'a str },
    Error { version: u32, code: PluginError },
}

pub(crate) fn decode_request(bytes: &[u8]) -> Result<Request<'_>, PluginError> {
    raw::request(bytes)
}

pub(crate) fn decode_response(bytes: &[u8]) -> Result<Response<'_>, PluginError> {
    raw::response(bytes)
}

fn check_hex(text: &str, limit: usize) -> Result<(), PluginError> {
    if text.len() > limit * 2
        || !text.len().is_multiple_of(2)
        || !text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PluginError::Protocol);
    }
    Ok(())
}

pub(crate) fn decode_hex(text: &str, limit: usize) -> Result<Vec<u8>, PluginError> {
    check_hex(text, limit)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(text.len() / 2).map_err(|_| PluginError::Resource)?;
    for pair in text.as_bytes().as_chunks::<2>().0 {
        let digit = |byte| if byte <= b'9' { byte - b'0' } else { byte - b'a' + 10 };
        bytes.push((digit(pair[0]) << 4) | digit(pair[1]));
    }
    Ok(bytes)
}

pub(crate) fn encode_hex(
    bytes: &[u8],
    mut check: impl FnMut() -> Result<(), PluginError>,
) -> Result<String, PluginError> {
    let length = bytes.len().checked_mul(2).ok_or(PluginError::Resource)?;
    let mut text = String::new();
    text.try_reserve_exact(length).map_err(|_| PluginError::Resource)?;
    let digits = b"0123456789abcdef";
    for chunk in bytes.chunks(8192) {
        check()?;
        for &byte in chunk {
            text.push(digits[(byte >> 4) as usize] as char);
            text.push(digits[(byte & 15) as usize] as char);
        }
    }
    check()?;
    Ok(text)
}

pub(crate) fn serialize(
    value: &impl Serialize,
    limit: usize,
    check: impl FnMut() -> Result<(), PluginError>,
) -> Result<Vec<u8>, PluginError> {
    let mut writer = BoundedWriter { bytes: Vec::new(), limit, check, failure: None };
    let result = serde_json::to_writer(&mut writer, value);
    if let Some(error) = writer.failure {
        return Err(error);
    }
    result.map_err(|_| PluginError::Protocol)?;
    (writer.check)()?;
    Ok(writer.bytes)
}

struct BoundedWriter<C> {
    bytes: Vec<u8>,
    limit: usize,
    check: C,
    failure: Option<PluginError>,
}

impl<C: FnMut() -> Result<(), PluginError>> Write for BoundedWriter<C> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let bytes = &bytes[..bytes.len().min(8192)];
        let result = (self.check)().and_then(|()| {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(PluginError::Protocol);
            }
            self.bytes.try_reserve(bytes.len()).map_err(|_| PluginError::Resource)?;
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        });
        result.map_err(|error| {
            self.failure = Some(error);
            io::Error::other("plugin serialization rejected")
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn read_request(mut input: impl Read) -> Result<Vec<u8>, PluginError> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let capacity = chunk.len().min(MAX_REQUEST_BYTES.saturating_sub(bytes.len()) + 1);
        let count = match input.read(&mut chunk[..capacity]) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(PluginError::Protocol),
        };
        if count == 0 {
            return Ok(bytes);
        }
        if count > MAX_REQUEST_BYTES.saturating_sub(bytes.len()) {
            return Err(PluginError::Protocol);
        }
        bytes.try_reserve(count).map_err(|_| PluginError::Resource)?;
        bytes.extend_from_slice(&chunk[..count]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_duplicate_and_nested_request_fields_before_payload_decoding() {
        let requests: &[&[u8]] = &[
            br#"{"version":1,"version":1}"#,
            br#"{"version":1,"component_hex":"","input_hex":"","fuel":1,"execution_timeout_ms":1,"x":0}"#,
            br#"{"version":1,"component_hex":[]}"#,
        ];
        for bytes in requests {
            assert!(decode_request(bytes).is_err());
        }
    }

    #[test]
    fn checks_hex_shape_and_length_before_allocation() {
        for text in ["0", "ff00", "FG", "\\u0066"] {
            assert_eq!(decode_hex(text, 1), Err(PluginError::Protocol));
        }
        assert_eq!(decode_hex("ff", 1), Ok(vec![255]));
    }

    #[test]
    fn bounded_writer_does_not_finish_an_oversized_or_cancelled_request() {
        assert_eq!(serialize(&"long text", 4, || Ok(())), Err(PluginError::Protocol));
        assert_eq!(serialize(&"text", 100, || Err(PluginError::Cancelled)), Err(PluginError::Cancelled));
    }

    #[test]
    fn response_shapes_are_checked_without_serde_enum_buffering() {
        let responses: &[&[u8]] = &[
            br#"{"version":1,"status":"ok","output_hex":"","unknown":{"nested":[{}]}}"#,
            br#"{"version":1,"status":"other","output_hex":{}}"#,
            br#"{"version":1,"status":"ok","output_hex":"\u0066\u0066"}"#,
            br#"{"version":1,"status":"ok","output_hex":"FF"}"#,
            br#"{"version":1,"status":"ok","output_hex":"f"}"#,
            br#"{"version":1,"status":"ok","output_hex":"","code":"fuel"}"#,
            br#"{"version":1,"status":"error","code":"unrecognized"}"#,
            br#"{"version":1,"status":"error","code":{"nested":[]}}"#,
            br#"{"version":1,"status":"ok","output_hex":0}"#,
            br#"{"version":1,"status":"ok","status":"error","output_hex":""}"#,
        ];
        for bytes in responses {
            assert!(raw::response(bytes).is_err());
        }
        assert!(matches!(
            raw::response(br#"{"version":1,"status":"error","code":"fuel"}"#),
            Ok(Response::Error { code: PluginError::Fuel, .. })
        ));
        assert!(matches!(
            raw::response(br#"{"output_hex":"ff00","version":1,"status":"ok"}"#),
            Ok(Response::Ok { output_hex: "ff00", .. })
        ));
    }

    #[test]
    fn each_hex_field_has_its_own_raw_limit_before_any_decoded_allocation() {
        let input = "ff".repeat(crate::MAX_INPUT_BYTES + 1);
        let request = format!(
            "{{\"version\":1,\"component_hex\":\"\",\"input_hex\":\"{input}\",\"fuel\":1,\"execution_timeout_ms\":1}}"
        );
        assert!(request.len() < MAX_REQUEST_BYTES);
        assert!(raw::request(request.as_bytes()).is_err());
        let component_only = format!(
            concat!(
                "{{\"version\":1,\"component_hex\":\"{}\",\"input_hex\":\"\",",
                "\"fuel\":1,\"execution_timeout_ms\":1}}"
            ),
            input
        );
        assert!(raw::request(component_only.as_bytes()).is_ok());

        let component = "ff".repeat(crate::MAX_COMPONENT_BYTES + 1);
        let request = format!(
            concat!(
                "{{\"version\":1,\"component_hex\":\"{}\",\"input_hex\":\"\",",
                "\"fuel\":1,\"execution_timeout_ms\":1}}"
            ),
            component
        );
        assert!(request.len() < MAX_REQUEST_BYTES);
        assert!(raw::request(request.as_bytes()).is_err());

        let output = "ff".repeat(MAX_OUTPUT_BYTES + 1);
        let response = format!("{{\"version\":1,\"status\":\"ok\",\"output_hex\":\"{output}\"}}");
        assert!(response.len() < MAX_RESPONSE_BYTES);
        assert!(raw::response(response.as_bytes()).is_err());
    }
}
