//! Flat, allocation-free protocol decoding. No serde enum buffering or escaped string decoding occurs.

use super::{MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Request, Response, VERSION};
use crate::{MAX_COMPONENT_BYTES, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, PluginError};

#[derive(Clone, Copy)]
enum Kind {
    Number,
    Hex(usize),
    Status,
    Code,
}

#[derive(Clone, Copy)]
enum Scalar<'a> {
    Number(u64),
    Text(&'a str),
}

pub(super) fn request(bytes: &[u8]) -> Result<Request<'_>, PluginError> {
    let fields = object(
        bytes,
        MAX_REQUEST_BYTES,
        &[
            ("version", Kind::Number),
            ("component_hex", Kind::Hex(MAX_COMPONENT_BYTES)),
            ("input_hex", Kind::Hex(MAX_INPUT_BYTES)),
            ("fuel", Kind::Number),
            ("execution_timeout_ms", Kind::Number),
        ],
    )?;
    if number(fields[0])? != VERSION as u64 {
        return Err(PluginError::Protocol);
    }
    Ok(Request {
        version: VERSION,
        component_hex: text(fields[1])?,
        input_hex: text(fields[2])?,
        fuel: number(fields[3])?,
        execution_timeout_ms: number(fields[4])?,
    })
}

pub(super) fn response(bytes: &[u8]) -> Result<Response<'_>, PluginError> {
    let fields = object(
        bytes,
        MAX_RESPONSE_BYTES,
        &[
            ("version", Kind::Number),
            ("status", Kind::Status),
            ("output_hex", Kind::Hex(MAX_OUTPUT_BYTES)),
            ("code", Kind::Code),
        ],
    )?;
    if number(fields[0])? != VERSION as u64 {
        return Err(PluginError::Protocol);
    }
    match text(fields[1])? {
        "ok" if fields[3].is_none() => Ok(Response::Ok { version: VERSION, output_hex: text(fields[2])? }),
        "error" if fields[2].is_none() => Ok(Response::Error {
            version: VERSION,
            code: PluginError::from_wire_name(text(fields[3])?).ok_or(PluginError::Protocol)?,
        }),
        _ => Err(PluginError::Protocol),
    }
}

fn text<'a>(value: Option<Scalar<'a>>) -> Result<&'a str, PluginError> {
    match value {
        Some(Scalar::Text(text)) => Ok(text),
        _ => Err(PluginError::Protocol),
    }
}

fn number(value: Option<Scalar<'_>>) -> Result<u64, PluginError> {
    match value {
        Some(Scalar::Number(number)) => Ok(number),
        _ => Err(PluginError::Protocol),
    }
}

fn object<'a>(bytes: &'a [u8], limit: usize, fields: &[(&str, Kind)]) -> Result<[Option<Scalar<'a>>; 5], PluginError> {
    if bytes.len() > limit {
        return Err(PluginError::Protocol);
    }
    let mut reader = Reader { bytes, offset: 0 };
    let mut values = [None; 5];
    reader.take(b'{')?;
    loop {
        let key = reader.string(32, false)?;
        let index = fields.iter().position(|(name, _)| *name == key).ok_or(PluginError::Protocol)?;
        if values[index].is_some() {
            return Err(PluginError::Protocol);
        }
        reader.take(b':')?;
        values[index] = Some(match fields[index].1 {
            Kind::Number => Scalar::Number(reader.number()?),
            Kind::Hex(limit) => Scalar::Text(reader.string(limit * 2, true)?),
            Kind::Status => {
                let status = reader.string(5, false)?;
                if !matches!(status, "ok" | "error") {
                    return Err(PluginError::Protocol);
                }
                Scalar::Text(status)
            }
            Kind::Code => {
                let code = reader.string(32, false)?;
                PluginError::from_wire_name(code).ok_or(PluginError::Protocol)?;
                Scalar::Text(code)
            }
        });
        reader.whitespace();
        if reader.bytes.get(reader.offset) == Some(&b'}') {
            reader.offset += 1;
            reader.whitespace();
            if reader.offset != bytes.len() {
                return Err(PluginError::Protocol);
            }
            return Ok(values);
        }
        reader.take(b',')?;
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn whitespace(&mut self) {
        while self.bytes.get(self.offset).is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t')) {
            self.offset += 1;
        }
    }

    fn take(&mut self, byte: u8) -> Result<(), PluginError> {
        self.whitespace();
        if self.bytes.get(self.offset) != Some(&byte) {
            return Err(PluginError::Protocol);
        }
        self.offset += 1;
        Ok(())
    }

    fn string(&mut self, limit: usize, hex: bool) -> Result<&'a str, PluginError> {
        self.take(b'"')?;
        let start = self.offset;
        loop {
            let byte = *self.bytes.get(self.offset).ok_or(PluginError::Protocol)?;
            let length = self.offset - start;
            if byte == b'"' {
                if hex && !length.is_multiple_of(2) {
                    return Err(PluginError::Protocol);
                }
                let text = std::str::from_utf8(&self.bytes[start..self.offset]).map_err(|_| PluginError::Protocol)?;
                self.offset += 1;
                return Ok(text);
            }
            if length >= limit
                || (hex && !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
                || (!hex && !(byte.is_ascii_alphanumeric() || byte == b'_'))
            {
                return Err(PluginError::Protocol);
            }
            self.offset += 1;
        }
    }

    fn number(&mut self) -> Result<u64, PluginError> {
        self.whitespace();
        let start = self.offset;
        let mut value = 0u64;
        while let Some(byte @ b'0'..=b'9') = self.bytes.get(self.offset).copied() {
            if self.offset - start >= 20 || (self.offset > start && self.bytes[start] == b'0') {
                return Err(PluginError::Protocol);
            }
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add((byte - b'0') as u64))
                .ok_or(PluginError::Protocol)?;
            self.offset += 1;
        }
        if self.offset == start {
            return Err(PluginError::Protocol);
        }
        Ok(value)
    }
}
