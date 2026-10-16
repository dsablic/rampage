//! Allocation-free lexical admission before serde, including internally tagged enum Content buffering.

use crate::*;

const MAX_KEYS: usize = 32;
const MAX_KEY_BYTES: usize = 64;
const MAX_NUMBER_BYTES: usize = 32;

/// Completes byte/shape admission before serde can allocate collections or tagged-enum buffers.
pub fn decode_facts(bytes: &[u8]) -> Result<TriageFacts, FailureCode> {
    preflight_facts_json(bytes)?;
    let facts = serde_json::from_slice(bytes).map_err(|_| FailureCode::InvalidInput)?;
    validate_facts(&facts)?;
    Ok(facts)
}

/// Host provenance remains external even when decoding and semantic reference validation succeed.
pub fn decode_response(bytes: &[u8], facts: &TriageFacts) -> Result<GuestResponse, FailureCode> {
    preflight_response_json(bytes)?;
    let response: GuestResponse = serde_json::from_slice(bytes).map_err(|_| FailureCode::InvalidReport)?;
    if response.schema_version != SCHEMA_VERSION {
        return Err(FailureCode::UnsupportedSchema);
    }
    if let GuestOutcome::Report { body } = &response.outcome {
        validate_report(facts, body)?;
    }
    Ok(response)
}

pub fn preflight_facts_json(bytes: &[u8]) -> Result<(), FailureCode> {
    admit(bytes, MAX_INPUT_BYTES, MAX_TEXT_BYTES).map_err(|error| match error {
        Error::Invalid => FailureCode::InvalidInput,
        Error::Limit => FailureCode::InputLimit,
    })
}

pub fn preflight_response_json(bytes: &[u8]) -> Result<(), FailureCode> {
    admit(bytes, MAX_OUTPUT_BYTES, MAX_OUTPUT_TEXT_BYTES).map_err(|error| match error {
        Error::Invalid => FailureCode::InvalidReport,
        Error::Limit => FailureCode::OutputLimit,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Error {
    Invalid,
    Limit,
}

fn admit(bytes: &[u8], byte_limit: usize, text_limit: usize) -> Result<(), Error> {
    if bytes.len() > byte_limit {
        return Err(Error::Limit);
    }
    std::str::from_utf8(bytes).map_err(|_| Error::Invalid)?;
    let mut parser = Parser { bytes, offset: 0, nodes: 0, containers: 0, array_items: 0, text_limit };
    parser.value(0)?;
    parser.whitespace();
    if parser.offset != bytes.len() {
        return Err(Error::Invalid);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    bytes: [u8; MAX_KEY_BYTES],
    length: usize,
}

impl Key {
    const EMPTY: Self = Self { bytes: [0; MAX_KEY_BYTES], length: 0 };
}

struct Parser<'a> {
    bytes: &'a [u8],
    offset: usize,
    nodes: usize,
    containers: usize,
    array_items: usize,
    text_limit: usize,
}

impl Parser<'_> {
    fn whitespace(&mut self) {
        while self.bytes.get(self.offset).is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n')) {
            self.offset += 1;
        }
    }

    fn take(&mut self, byte: u8) -> Result<(), Error> {
        self.whitespace();
        if self.bytes.get(self.offset) != Some(&byte) {
            return Err(Error::Invalid);
        }
        self.offset += 1;
        Ok(())
    }

    fn node(&mut self) -> Result<(), Error> {
        if self.nodes >= MAX_JSON_NODES {
            return Err(Error::Limit);
        }
        self.nodes += 1;
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<(), Error> {
        self.node()?;
        self.whitespace();
        match self.bytes.get(self.offset).copied().ok_or(Error::Invalid)? {
            b'{' | b'[' => {
                if depth >= MAX_JSON_DEPTH || self.containers >= MAX_JSON_CONTAINERS {
                    return Err(Error::Limit);
                }
                self.containers += 1;
                if self.bytes[self.offset] == b'{' { self.object(depth + 1) } else { self.array(depth + 1) }
            }
            b'"' => self.string(false).map(|_| ()),
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(Error::Invalid),
        }
    }

    fn object(&mut self, depth: usize) -> Result<(), Error> {
        self.take(b'{')?;
        self.whitespace();
        if self.bytes.get(self.offset) == Some(&b'}') {
            self.offset += 1;
            return Ok(());
        }
        let mut keys = [Key::EMPTY; MAX_KEYS];
        let mut count = 0;
        loop {
            if count == MAX_KEYS {
                return Err(Error::Limit);
            }
            self.node()?;
            let key = self.string(true)?;
            if keys[..count].contains(&key) {
                return Err(Error::Invalid);
            }
            keys[count] = key;
            count += 1;
            self.take(b':')?;
            self.value(depth)?;
            self.whitespace();
            if self.bytes.get(self.offset) == Some(&b'}') {
                self.offset += 1;
                return Ok(());
            }
            self.take(b',')?;
        }
    }

    fn array(&mut self, depth: usize) -> Result<(), Error> {
        self.take(b'[')?;
        self.whitespace();
        if self.bytes.get(self.offset) == Some(&b']') {
            self.offset += 1;
            return Ok(());
        }
        let mut count = 0;
        loop {
            if count >= MAX_RECORDS || self.array_items >= MAX_JSON_ARRAY_ITEMS {
                return Err(Error::Limit);
            }
            count += 1;
            self.array_items += 1;
            self.value(depth)?;
            self.whitespace();
            if self.bytes.get(self.offset) == Some(&b']') {
                self.offset += 1;
                return Ok(());
            }
            self.take(b',')?;
        }
    }

    fn string(&mut self, is_key: bool) -> Result<Key, Error> {
        self.take(b'"')?;
        let start = self.offset;
        let mut decoded = 0;
        let mut key = Key::EMPTY;
        let limit = if is_key { MAX_KEY_BYTES } else { self.text_limit };
        loop {
            if self.offset - start > limit * 6 {
                return Err(Error::Limit);
            }
            let byte = *self.bytes.get(self.offset).ok_or(Error::Invalid)?;
            self.offset += 1;
            match byte {
                b'"' => return Ok(key),
                b'\\' => {
                    let escape = *self.bytes.get(self.offset).ok_or(Error::Invalid)?;
                    self.offset += 1;
                    let decoded_byte = match escape {
                        b'"' | b'\\' | b'/' => escape,
                        b'b' => 8,
                        b'f' => 12,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'u' => {
                            let character = self.unicode()?;
                            let mut utf8 = [0; 4];
                            let text = character.encode_utf8(&mut utf8);
                            Self::decoded(&mut key, &mut decoded, text.as_bytes(), is_key, limit)?;
                            continue;
                        }
                        _ => return Err(Error::Invalid),
                    };
                    Self::decoded(&mut key, &mut decoded, &[decoded_byte], is_key, limit)?;
                }
                0..=0x1f => return Err(Error::Invalid),
                _ => Self::decoded(&mut key, &mut decoded, &[byte], is_key, limit)?,
            }
        }
    }

    fn decoded(key: &mut Key, decoded: &mut usize, bytes: &[u8], is_key: bool, limit: usize) -> Result<(), Error> {
        if bytes.len() > limit.saturating_sub(*decoded) {
            return Err(Error::Limit);
        }
        if is_key {
            key.bytes[*decoded..*decoded + bytes.len()].copy_from_slice(bytes);
            key.length += bytes.len();
        }
        *decoded += bytes.len();
        Ok(())
    }

    fn unicode(&mut self) -> Result<char, Error> {
        let first = self.hex_quad()?;
        let scalar = if (0xd800..=0xdbff).contains(&first) {
            if !self.bytes[self.offset..].starts_with(b"\\u") {
                return Err(Error::Invalid);
            }
            self.offset += 2;
            let second = self.hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(Error::Invalid);
            }
            0x10000 + ((u32::from(first) - 0xd800) << 10) + u32::from(second) - 0xdc00
        } else {
            u32::from(first)
        };
        char::from_u32(scalar).ok_or(Error::Invalid)
    }

    fn hex_quad(&mut self) -> Result<u16, Error> {
        let mut value = 0;
        for _ in 0..4 {
            let byte = *self.bytes.get(self.offset).ok_or(Error::Invalid)?;
            self.offset += 1;
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err(Error::Invalid),
            };
            value = (value << 4) | u16::from(digit);
        }
        Ok(value)
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), Error> {
        if !self.bytes[self.offset..].starts_with(literal) {
            return Err(Error::Invalid);
        }
        self.offset += literal.len();
        Ok(())
    }

    fn digits(&mut self) -> bool {
        let start = self.offset;
        while self.bytes.get(self.offset).is_some_and(u8::is_ascii_digit) {
            self.offset += 1;
        }
        self.offset > start
    }

    fn number(&mut self) -> Result<(), Error> {
        let start = self.offset;
        if self.bytes.get(self.offset) == Some(&b'-') {
            self.offset += 1;
        }
        match self.bytes.get(self.offset) {
            Some(b'0') => self.offset += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(Error::Invalid),
        }
        if self.bytes.get(self.offset) == Some(&b'.') {
            self.offset += 1;
            if !self.digits() {
                return Err(Error::Invalid);
            }
        }
        if self.bytes.get(self.offset).is_some_and(|byte| matches!(byte, b'e' | b'E')) {
            self.offset += 1;
            if self.bytes.get(self.offset).is_some_and(|byte| matches!(byte, b'-' | b'+')) {
                self.offset += 1;
            }
            if !self.digits() {
                return Err(Error::Invalid);
            }
        }
        if self.offset - start > MAX_NUMBER_BYTES {
            return Err(Error::Limit);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_items_and_split_arrays_are_bounded_before_serde() {
        let items = std::iter::repeat_n("\"\"", 300_000).collect::<Vec<_>>().join(",");
        let json = format!("{{\"evidence\":[{items}]}}");
        assert!(json.len() < MAX_INPUT_BYTES);
        assert_eq!(preflight_facts_json(json.as_bytes()), Err(FailureCode::InputLimit));
        let rows = "0,".repeat(MAX_RECORDS - 1) + "0";
        let json = format!("[[{rows}],[{rows}]]");
        assert_eq!(preflight_facts_json(json.as_bytes()), Err(FailureCode::InputLimit));
    }

    #[test]
    fn escaped_text_respects_decoded_utf8_boundaries() {
        for (unit, count) in [("\\u0061", MAX_TEXT_BYTES), ("\\ud83d\\ude00", MAX_TEXT_BYTES / 4)] {
            let valid = format!("\"{}\"", unit.repeat(count));
            assert_eq!(preflight_facts_json(valid.as_bytes()), Ok(()));
            let oversized = format!("\"{}\"", unit.repeat(count + 1));
            assert_eq!(preflight_facts_json(oversized.as_bytes()), Err(FailureCode::InputLimit));
        }
        let literal = format!("\"{}\"", "é".repeat(MAX_TEXT_BYTES / 2));
        assert_eq!(preflight_facts_json(literal.as_bytes()), Ok(()));
        for invalid in [r#""\ud800""#, r#""\udc00""#, r#""\ud800\u0041""#, r#""\x41""#] {
            assert_eq!(preflight_facts_json(invalid.as_bytes()), Err(FailureCode::InvalidInput));
        }
    }

    #[test]
    fn decoded_duplicate_keys_are_rejected_before_tagged_buffering() {
        for json in [r#"{"status":"report","sta\u0074us":"failure"}"#, r#"{"outcome":{"code":1,"co\u0064e":2}}"#] {
            assert_eq!(preflight_facts_json(json.as_bytes()), Err(FailureCode::InvalidInput));
        }
        assert_eq!(preflight_facts_json(br#"{"sta\u0074us":"available"}"#), Ok(()));
    }

    #[test]
    fn depth_and_cumulative_container_budgets_are_enforced() {
        let deep = "[".repeat(MAX_JSON_DEPTH + 1) + &"]".repeat(MAX_JSON_DEPTH + 1);
        assert_eq!(preflight_facts_json(deep.as_bytes()), Err(FailureCode::InputLimit));
        let containers = "{\"a\":[],\"b\":[]},".repeat(MAX_RECORDS - 1) + "{\"a\":[],\"b\":[]}";
        let json = format!("[{containers}]");
        assert!(json.len() < MAX_INPUT_BYTES);
        assert_eq!(preflight_facts_json(json.as_bytes()), Err(FailureCode::InputLimit));
    }

    #[test]
    fn cumulative_object_members_are_bounded() {
        let object = r#"{"a":0,"b":0,"c":0,"d":0,"e":0,"f":0,"g":0,"h":0}"#;
        let json = format!("[{}{}]", (object.to_owned() + ",").repeat(MAX_RECORDS - 1), object);
        assert!(json.len() < MAX_INPUT_BYTES);
        assert_eq!(preflight_facts_json(json.as_bytes()), Err(FailureCode::InputLimit));
    }
}
