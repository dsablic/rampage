//! Allocation-free JSON preflight before Serde's internally tagged enum buffering.

const MAX_REQUEST_BYTES: usize = 128 * 1024 * 1024;
pub(crate) const MAX_LAYOUT_WIRE_BYTES: usize = 384 * 1024;
const MAX_REQUEST_NODES: usize = 1024 * 1024;
const MAX_OPERATION_NODES: usize = 64 * 1024;
const MAX_LAYOUT_NODES: usize = 2048;
const MAX_LAYOUT_TEXT: usize = 64 * 1024;
const MAX_OBJECT_KEYS: usize = 32;
const MAX_KEY_BYTES: usize = 128;
const MAX_DEFAULT_STRING: usize = 4096;
const MAX_TAG_BYTES: usize = 32;
const MAX_LAYOUT_STRING: usize = 128;
const MAX_LAYOUT_ARRAY: usize = 128;

#[derive(Clone, Copy)]
enum Policy {
    Worker,
    Layout,
    NamedTypes,
}

#[derive(Clone, Copy)]
enum Context {
    Request,
    Operation,
    LayoutObject,
    LayoutFields,
    LayoutAlignments,
    Other,
}

#[derive(Clone, Copy)]
struct Key {
    bytes: [u8; MAX_KEY_BYTES],
    len: usize,
}

impl Key {
    const EMPTY: Self = Self { bytes: [0; MAX_KEY_BYTES], len: 0 };

    fn is(&self, value: &[u8]) -> bool {
        &self.bytes[..self.len] == value
    }

    fn same(&self, other: &Self) -> bool {
        self.len == other.len && self.bytes[..self.len] == other.bytes[..other.len]
    }
}

struct WireError {
    operation: Option<usize>,
    message: &'static str,
}

impl WireError {
    fn message(self) -> String {
        match self.operation {
            Some(index) => format!("operation {index}: {}", self.message),
            None => self.message.to_owned(),
        }
    }
}

struct Scanner<'a> {
    bytes: &'a [u8],
    position: usize,
    nodes: usize,
    text: usize,
    policy: Policy,
    operation: Option<(usize, usize)>,
}

impl<'a> Scanner<'a> {
    fn new(bytes: &'a [u8], policy: Policy) -> Self {
        Self { bytes, position: 0, nodes: 0, text: 0, policy, operation: None }
    }

    fn error(&self, message: &'static str) -> WireError {
        WireError { operation: self.operation.map(|(index, _)| index), message }
    }

    fn whitespace(&mut self) {
        while matches!(self.bytes.get(self.position), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.position += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), WireError> {
        if self.bytes.get(self.position) != Some(&byte) {
            return Err(self.error("invalid JSON wire syntax"));
        }
        self.position += 1;
        Ok(())
    }

    fn value(&mut self, context: Context, depth: usize, string_limit: usize) -> Result<Option<Key>, WireError> {
        let (max_depth, max_nodes) = match self.policy {
            Policy::Worker => (32, MAX_REQUEST_NODES),
            Policy::Layout => (12, MAX_LAYOUT_NODES),
            Policy::NamedTypes => (32, MAX_OPERATION_NODES),
        };
        if depth > max_depth || self.nodes >= max_nodes {
            return Err(self.error("JSON wire depth/node limit exceeded"));
        }
        if let Some((_, start)) = self.operation
            && matches!(self.policy, Policy::Worker)
            && self.nodes.saturating_sub(start) >= MAX_OPERATION_NODES
        {
            return Err(self.error("worker operation wire node limit exceeded"));
        }
        self.nodes += 1;
        self.whitespace();
        if matches!(context, Context::Operation | Context::LayoutObject) && self.bytes.get(self.position) != Some(&b'{')
        {
            return Err(self.error("operation/layout records must use object representation"));
        }
        if matches!(context, Context::LayoutFields | Context::LayoutAlignments)
            && self.bytes.get(self.position) != Some(&b'[')
        {
            return Err(self.error("layout collections must use array representation"));
        }
        match self.bytes.get(self.position) {
            Some(b'{') => self.object(context, depth),
            Some(b'[') => {
                self.array(context, depth)?;
                Ok(None)
            }
            Some(b'"') => {
                self.string(string_limit, false)?;
                Ok(None)
            }
            Some(b't') => {
                self.literal(b"true")?;
                Ok(None)
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(None)
            }
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(None)
            }
            Some(b'-' | b'0'..=b'9') => {
                self.number()?;
                Ok(None)
            }
            _ => Err(self.error("invalid JSON wire value")),
        }
    }

    fn default_string_limit(&self) -> usize {
        match self.policy {
            Policy::Worker => MAX_DEFAULT_STRING,
            Policy::Layout => MAX_LAYOUT_STRING,
            Policy::NamedTypes => 256,
        }
    }

    fn property_string_limit(&self, key: &Key) -> usize {
        if key.is(b"op") || key.is(b"kind") {
            return MAX_TAG_BYTES;
        }
        if matches!(self.policy, Policy::Worker)
            && (key.is(b"hex_bytes") || key.is(b"declaration") || key.is(b"declarations"))
        {
            return MAX_REQUEST_BYTES;
        }
        self.default_string_limit()
    }

    fn object(&mut self, context: Context, depth: usize) -> Result<Option<Key>, WireError> {
        self.expect(b'{')?;
        let mut seen = [Key::EMPTY; MAX_OBJECT_KEYS];
        let mut count = 0;
        let mut operation_tag = None;
        self.whitespace();
        if self.bytes.get(self.position) == Some(&b'}') {
            self.position += 1;
            return Ok(None);
        }
        loop {
            if count == MAX_OBJECT_KEYS {
                return Err(self.error("JSON wire object key count limit exceeded"));
            }
            let key = self.string(MAX_KEY_BYTES, true)?;
            if seen[..count].iter().any(|previous| previous.same(&key)) {
                return Err(self.error("duplicate JSON wire object key"));
            }
            seen[count] = key;
            count += 1;
            self.whitespace();
            self.expect(b':')?;
            self.whitespace();
            if (key.is(b"op") || (key.is(b"kind") && matches!(self.policy, Policy::Layout)))
                && self.bytes.get(self.position) != Some(&b'"')
            {
                return Err(self.error("wire tags must use string representation"));
            }
            if matches!(context, Context::Request)
                && key.is(b"operations")
                && self.bytes.get(self.position) == Some(&b'[')
            {
                self.operations(depth + 1)?;
            } else if matches!(context, Context::Operation)
                && key.is(b"op")
                && self.bytes.get(self.position) == Some(&b'"')
            {
                // The tag is a node too; use the normal bounded path for its raw syntax before capturing it.
                let start = self.position;
                self.value(Context::Other, depth + 1, MAX_TAG_BYTES)?;
                let end = self.position;
                self.position = start;
                operation_tag = Some(self.string(MAX_TAG_BYTES, true)?);
                self.position = end;
            } else if matches!(self.policy, Policy::Layout)
                && [b"layout".as_slice(), b"organization", b"ty", b"scalar", b"pointee"].iter().any(|name| key.is(name))
            {
                self.value(Context::LayoutObject, depth + 1, self.default_string_limit())?;
            } else if matches!(self.policy, Policy::Layout) && key.is(b"fields") {
                self.value(Context::LayoutFields, depth + 1, self.default_string_limit())?;
            } else if matches!(self.policy, Policy::Layout) && key.is(b"scalar_alignments") {
                self.value(Context::LayoutAlignments, depth + 1, self.default_string_limit())?;
            } else {
                self.value(Context::Other, depth + 1, self.property_string_limit(&key))?;
            }
            self.whitespace();
            match self.bytes.get(self.position) {
                Some(b'}') => {
                    self.position += 1;
                    return Ok(operation_tag);
                }
                Some(b',') => {
                    self.position += 1;
                    self.whitespace();
                }
                _ => return Err(self.error("invalid JSON wire object delimiter")),
            }
        }
    }

    fn array(&mut self, context: Context, depth: usize) -> Result<(), WireError> {
        self.expect(b'[')?;
        self.whitespace();
        if self.bytes.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(());
        }
        let mut count = 0usize;
        loop {
            if matches!(self.policy, Policy::Layout) && count >= MAX_LAYOUT_ARRAY {
                return Err(self.error("layout wire array count limit exceeded"));
            }
            if matches!(self.policy, Policy::NamedTypes) && count >= 256 {
                return Err(self.error("named type wire array count limit exceeded (256)"));
            }
            count += 1;
            let element = if matches!(context, Context::LayoutFields) { Context::LayoutObject } else { Context::Other };
            self.value(element, depth + 1, self.default_string_limit())?;
            self.whitespace();
            match self.bytes.get(self.position) {
                Some(b']') => {
                    self.position += 1;
                    return Ok(());
                }
                Some(b',') => self.position += 1,
                _ => return Err(self.error("invalid JSON wire array delimiter")),
            }
        }
    }

    fn operations(&mut self, depth: usize) -> Result<(), WireError> {
        // Count and check the array itself without treating its elements as unclassified objects.
        self.expect(b'[')?;
        self.nodes += 1;
        if depth > 32 || self.nodes > MAX_REQUEST_NODES {
            return Err(self.error("JSON wire depth/node limit exceeded"));
        }
        self.whitespace();
        if self.bytes.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(());
        }
        let mut index = 0usize;
        loop {
            self.whitespace();
            let operation_start = self.position;
            self.operation = Some((index, self.nodes));
            let tag = self.value(Context::Operation, depth + 1, MAX_DEFAULT_STRING)?;
            let end = self.position;
            if tag.is_some_and(|tag| tag.is(b"assert_plain_struct_layout")) {
                // A second allocation-free pass bounds the entire operation, including unknown payloads.
                // It runs before any Serde Content exists, whether the tag is first, last, or escaped.
                scan_layout(&self.bytes[operation_start..end], Some(index))?;
            }
            if tag.is_some_and(|tag| tag.is(b"assert_named_types")) {
                let bytes = &self.bytes[operation_start..end];
                if bytes.len() > crate::type_library::MAX_TYPE_JSON_BYTES {
                    return Err(self.error("named type assertion wire exceeds 1 MiB"));
                }
                let mut scanner = Scanner::new(bytes, Policy::NamedTypes);
                scanner.operation = Some((index, 0));
                scanner.finish(Context::Operation)?;
            }
            self.operation = None;
            self.whitespace();
            match self.bytes.get(self.position) {
                Some(b']') => {
                    self.position += 1;
                    return Ok(());
                }
                Some(b',') => self.position += 1,
                _ => return Err(self.error("invalid worker operations wire delimiter")),
            }
            index += 1;
        }
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), WireError> {
        if !self.bytes[self.position..].starts_with(literal) {
            return Err(self.error("invalid JSON wire literal"));
        }
        self.position += literal.len();
        Ok(())
    }

    fn number(&mut self) -> Result<(), WireError> {
        let start = self.position;
        if self.bytes.get(self.position) == Some(&b'-') {
            self.position += 1;
        }
        match self.bytes.get(self.position) {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => {
                self.digits(start)?;
            }
            _ => return Err(self.error("invalid JSON wire number")),
        }
        if self.bytes.get(self.position) == Some(&b'.') {
            self.position += 1;
            if !matches!(self.bytes.get(self.position), Some(b'0'..=b'9')) {
                return Err(self.error("invalid JSON wire number"));
            }
            self.digits(start)?;
        }
        if matches!(self.bytes.get(self.position), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.bytes.get(self.position), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if !matches!(self.bytes.get(self.position), Some(b'0'..=b'9')) {
                return Err(self.error("invalid JSON wire number"));
            }
            self.digits(start)?;
        }
        if self.position.saturating_sub(start) > 32 {
            return Err(self.error("JSON wire number byte limit exceeded"));
        }
        Ok(())
    }

    fn digits(&mut self, start: usize) -> Result<(), WireError> {
        while matches!(self.bytes.get(self.position), Some(b'0'..=b'9')) {
            if self.position.saturating_sub(start) >= 32 {
                return Err(self.error("JSON wire number byte limit exceeded"));
            }
            self.position += 1;
        }
        Ok(())
    }

    fn hex4(&mut self) -> Result<u32, WireError> {
        let mut value = 0;
        for _ in 0..4 {
            let digit = match self.bytes.get(self.position) {
                Some(byte @ b'0'..=b'9') => u32::from(*byte - b'0'),
                Some(byte @ b'a'..=b'f') => u32::from(*byte - b'a' + 10),
                Some(byte @ b'A'..=b'F') => u32::from(*byte - b'A' + 10),
                _ => return Err(self.error("invalid JSON wire Unicode escape")),
            };
            self.position += 1;
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn string(&mut self, limit: usize, capture: bool) -> Result<Key, WireError> {
        self.expect(b'"')?;
        let mut decoded = 0usize;
        let mut key = Key::EMPTY;
        loop {
            let byte = *self.bytes.get(self.position).ok_or_else(|| self.error("unterminated JSON wire string"))?;
            self.position += 1;
            let mut unicode = [0u8; 4];
            let single;
            let emitted = match byte {
                b'"' => {
                    if capture {
                        key.len = decoded;
                    }
                    return Ok(key);
                }
                b'\\' => {
                    let escape =
                        *self.bytes.get(self.position).ok_or_else(|| self.error("invalid JSON wire escape"))?;
                    self.position += 1;
                    match escape {
                        b'"' | b'\\' | b'/' => {
                            single = [escape];
                            &single[..]
                        }
                        b'b' | b'f' | b'n' | b'r' | b't' => {
                            single = [match escape {
                                b'b' => 8,
                                b'f' => 12,
                                b'n' => 10,
                                b'r' => 13,
                                _ => 9,
                            }];
                            &single[..]
                        }
                        b'u' => {
                            let first = self.hex4()?;
                            let point = if (0xd800..=0xdbff).contains(&first) {
                                self.expect(b'\\')?;
                                self.expect(b'u')?;
                                let last = self.hex4()?;
                                if !(0xdc00..=0xdfff).contains(&last) {
                                    return Err(self.error("invalid JSON wire surrogate pair"));
                                }
                                0x10000 + ((first - 0xd800) << 10) + last - 0xdc00
                            } else {
                                first
                            };
                            let character =
                                char::from_u32(point).ok_or_else(|| self.error("invalid JSON wire Unicode scalar"))?;
                            character.encode_utf8(&mut unicode).as_bytes()
                        }
                        _ => return Err(self.error("invalid JSON wire escape")),
                    }
                }
                0..=31 => return Err(self.error("unescaped control byte in JSON wire string")),
                _ => {
                    single = [byte];
                    &single[..]
                }
            };
            if emitted.len() > limit.saturating_sub(decoded) {
                return Err(self.error("JSON wire decoded string byte limit exceeded"));
            }
            if matches!(self.policy, Policy::Layout) {
                if emitted.len() > MAX_LAYOUT_TEXT.saturating_sub(self.text) {
                    return Err(self.error("layout wire cumulative decoded text limit exceeded"));
                }
                self.text += emitted.len();
            }
            if capture {
                if emitted.len() > MAX_KEY_BYTES.saturating_sub(decoded) {
                    return Err(self.error("JSON wire captured string byte limit exceeded"));
                }
                key.bytes[decoded..decoded + emitted.len()].copy_from_slice(emitted);
            }
            decoded += emitted.len();
        }
    }

    fn finish(&mut self, context: Context) -> Result<(), WireError> {
        if std::str::from_utf8(self.bytes).is_err() {
            return Err(self.error("JSON wire is not UTF-8"));
        }
        self.whitespace();
        if matches!(context, Context::Request) && self.bytes.get(self.position) != Some(&b'{') {
            return Err(self.error("worker request wire must be an object"));
        }
        self.value(context, 0, self.default_string_limit())?;
        self.whitespace();
        if self.position != self.bytes.len() {
            return Err(self.error("trailing JSON wire input"));
        }
        Ok(())
    }
}

fn scan_layout(bytes: &[u8], operation: Option<usize>) -> Result<(), WireError> {
    if bytes.len() > MAX_LAYOUT_WIRE_BYTES {
        return Err(WireError { operation, message: "layout wire encoded byte limit exceeded" });
    }
    let mut scanner = Scanner::new(bytes, Policy::Layout);
    scanner.operation = operation.map(|index| (index, 0));
    scanner.finish(Context::LayoutObject)
}

pub(crate) fn preflight_layout(bytes: &[u8]) -> Result<(), String> {
    scan_layout(bytes, None).map_err(WireError::message)
}

pub(crate) fn decode_worker<T>(bytes: &[u8], decode: impl FnOnce(&[u8]) -> Result<T, String>) -> Result<T, String> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err("worker request exceeds protocol limit".to_owned());
    }
    Scanner::new(bytes, Policy::Worker).finish(Context::Request).map_err(WireError::message)?;
    decode(bytes)
}

#[cfg(test)]
mod tests {
    use crate::layout::{
        LayoutField, LayoutOrganization, LayoutScalar, LayoutType, MAX_LAYOUT_FIELDS, MAX_LAYOUT_NAME_BYTES,
        MAX_LAYOUT_SIZE, PlainStructLayout, ScalarKind,
    };
    use crate::worker::{PROTOCOL_VERSION, WorkerOperation, WorkerRequest};

    use super::*;

    fn request(operation: &str) -> Vec<u8> {
        format!(
            r#"{{"version":{PROTOCOL_VERSION},"arch":"x86_64","mappings":[{{"base":4096,"hex_bytes":"c3",
            "size":1,"readable":true,"writable":false,"executable":true}}],"operations":[{operation}],
            "decompile":{{"address":4096}},"validate_only":true}}"#
        )
        .into_bytes()
    }

    fn reject_before_decode(bytes: &[u8]) -> String {
        let mut decoded = false;
        let error = decode_worker(bytes, |_| {
            decoded = true;
            Ok(())
        })
        .unwrap_err();
        assert!(!decoded, "Serde decoder was entered for hostile wire bytes");
        assert!(error.len() <= 160, "wire diagnostic exceeded its fixed bound");
        error
    }

    fn maximum_layout() -> PlainStructLayout {
        let fields = (0..MAX_LAYOUT_FIELDS)
            .map(|index| {
                let last = index == MAX_LAYOUT_FIELDS - 1;
                let suffix = if last { MAX_LAYOUT_NAME_BYTES - 5 } else { MAX_LAYOUT_NAME_BYTES - 4 };
                LayoutField {
                    name: format!("f{index:03}{}", "x".repeat(suffix)),
                    offset: if last { MAX_LAYOUT_SIZE - 1 } else { index as u32 },
                    size: 1,
                    ty: LayoutType::Scalar {
                        scalar: LayoutScalar {
                            name: if last { "a".to_owned() } else { "s".repeat(MAX_LAYOUT_NAME_BYTES) },
                            kind: ScalarKind::UnsignedInteger,
                            size: 1,
                            alignment: 1,
                        },
                    },
                }
            })
            .collect();
        PlainStructLayout {
            name: "s".repeat(MAX_LAYOUT_NAME_BYTES),
            size: MAX_LAYOUT_SIZE,
            alignment: 1,
            organization: LayoutOrganization {
                pointer_size: 8,
                int_size: 4,
                long_size: 8,
                scalar_alignments: [1, 2, 4, 8],
            },
            fields,
        }
    }

    // The authored test schemas contain ASCII strings without JSON backslashes/quotes in their contents.
    fn escape_ascii_strings(bytes: &[u8]) -> Vec<u8> {
        let mut quoted = false;
        let mut escaped = Vec::new();
        for &byte in bytes {
            if byte == b'"' {
                quoted = !quoted;
                escaped.push(byte);
            } else if quoted {
                assert!(byte.is_ascii() && byte != b'\\');
                escaped.extend_from_slice(format!("\\u{byte:04x}").as_bytes());
            } else {
                escaped.push(byte);
            }
        }
        assert!(!quoted);
        escaped
    }

    #[test]
    fn raw_assertion_arrays_are_rejected_before_decoder_for_first_last_and_escaped_tags_keys() {
        let zeros = format!("[{}0]", "0,".repeat(1_000_000));
        let payload = format!(r#"{{"f\u0069elds":{zeros}}}"#);
        for operation in [
            format!(r#"{{"op":"assert_plain_struct_layout","layout":{payload}}}"#),
            format!(r#"{{"layout":{payload},"op":"assert_plain_struct_layout"}}"#),
            format!(r#"{{"layout":{payload},"\u006fp":"\u0061ssert_plain_struct_layout"}}"#),
            format!(r#"{{"layout":{{"fields":[{{"ty":{{"unknown":{zeros}}}}}]}},"op":"assert_plain_struct_layout"}}"#),
        ] {
            let error = reject_before_decode(&request(&operation));
            assert!(error.starts_with("operation 0:"), "{error}");
        }
    }

    #[test]
    fn positional_operations_and_noncanonical_layout_tags_never_reach_materialization() {
        let zeros = format!("[{}0]", "0,".repeat(50_000));
        let escaped = "\\u0061".repeat(100_000);
        for operation in [
            format!(r#"["assert_plain_struct_layout",{{"fields":{zeros}}}]"#),
            format!(r#"["assert_plain_struct_layout",{{"declarations":"{escaped}"}}]"#),
            r#"["parse_types","typedef int4 word;"]"#.to_owned(),
        ] {
            let error = reject_before_decode(&request(&operation));
            assert!(error.contains("object representation"), "{error}");
        }
        let tag = "x".repeat(MAX_TAG_BYTES + 1);
        for layout in [
            format!(r#"{{"fields":[{{"ty":{{"kind":"scalar","scalar":["n","{tag}",1,1]}}}}]}}"#),
            format!(r#"{{"fields":[{{"ty":{{"kind":"scalar","scalar":{{"kind":{{"{tag}":null}}}}}}}}]}}"#),
            r#"{"fields":[["name",0,4,{"kind":"scalar"}]]}"#.to_owned(),
            r#"{"fields":[{"ty":["scalar",{}]}]}"#.to_owned(),
            r#"{"organization":[8,4,8,[1,2,4,8]]}"#.to_owned(),
        ] {
            assert!(preflight_layout(layout.as_bytes()).is_err());
            let operation = format!(r#"{{"layout":{layout},"op":"assert_plain_struct_layout"}}"#);
            reject_before_decode(&request(&operation));
        }
        assert!(preflight_layout(br#"["record",4,4,{},[]]"#).is_err());
    }

    #[test]
    fn whole_assertion_unknown_properties_receive_array_node_text_and_encoded_budgets() {
        let array = format!("[{}0]", "0,".repeat(MAX_LAYOUT_ARRAY));
        let matrix = format!("[{}[0]]", format!("{array},").repeat(17));
        let strings = format!("[{}\"x\"]", format!("\"{}\",", "x".repeat(MAX_LAYOUT_STRING)).repeat(127));
        let text = format!("[{strings},{strings},{strings},{strings},{strings}]");
        let whitespace = " ".repeat(MAX_LAYOUT_WIRE_BYTES);
        let legacy_text = "a".repeat(MAX_LAYOUT_WIRE_BYTES);
        for (payload, expected) in [
            (format!(r#""unknown":{array}"#), "array count"),
            (format!(r#""unknown":{matrix}"#), "array count"),
            (format!(r#""unknown":{text}"#), "cumulative decoded text"),
            (format!(r#""unknown":{whitespace}null"#), "encoded byte"),
            (format!(r#""declarations":"{legacy_text}""#), "encoded byte"),
        ] {
            let operation = format!(r#"{{"layout":{{}},{payload},"op":"assert_plain_struct_layout"}}"#);
            let error = reject_before_decode(&request(&operation));
            assert!(error.contains(expected), "{error}");
        }
        let row = format!("[{}0]", "0,".repeat(127));
        let matrix = format!("[{}[0]]", format!("{row},").repeat(17));
        let operation = format!(r#"{{"layout":{{}},"unknown":{matrix},"op":"assert_plain_struct_layout"}}"#);
        assert!(reject_before_decode(&request(&operation)).contains("depth/node"));
    }

    #[test]
    fn raw_giant_tags_keys_and_escaped_names_cannot_reach_serde_scratch_or_diagnostics() {
        let giant = "hostile_marker".repeat(100_000);
        let escaped = "\\u0061".repeat(200_000);
        for operation in [
            format!(r#"{{"op":"{giant}","layout":{{}}}}"#),
            format!(r#"{{"layout":{{"name":"{escaped}"}},"op":"assert_plain_struct_layout"}}"#),
            format!(r#"{{"op":"assert_plain_struct_layout","layout":{{"fields":[{{"ty":{{"kind":"{giant}"}}}}]}}}}"#),
            format!(r#"{{"layout":{{}},"{giant}":null,"op":"assert_plain_struct_layout"}}"#),
            format!(r#"{{"layout":{{}},"{escaped}":null,"op":"assert_plain_struct_layout"}}"#),
        ] {
            let error = reject_before_decode(&request(&operation));
            assert!(!error.contains("hostile_marker"), "diagnostic echoed hostile bytes");
        }
        let error = reject_before_decode(format!(r#"{{"version":"{giant}"}}"#).as_bytes());
        assert!(!error.contains("hostile_marker"));
    }

    #[test]
    fn raw_depth_duplicates_malformed_escapes_and_positional_request_bypasses_are_rejected() {
        for levels in [13, 33] {
            let nested = format!("{}0{}", "[".repeat(levels), "]".repeat(levels));
            let operation = format!(r#"{{"layout":{{}},"unknown":{nested},"op":"assert_plain_struct_layout"}}"#);
            assert!(reject_before_decode(&request(&operation)).contains("depth/node"));
        }
        for operation in [
            r#"{"op":"assert_plain_struct_layout","\u006fp":"parse_types","layout":{}}"#,
            r#"{"op":"assert_plain_struct_layout","layout":{"name":"x","n\u0061me":"y"}}"#,
            r#"{"op":"assert_plain_struct_layout","layout":{"name":"\uD800"}}"#,
            r#"{"op":"assert_plain_struct_layout","layout":{"name":"\uDC00"}}"#,
            r#"{"op":"assert_plain_struct_layout","layout":{"name":"\uD800\u0061"}}"#,
            r#"{"op":"assert_plain_struct_layout","layout":{"name":"\q"}}"#,
        ] {
            reject_before_decode(&request(operation));
        }
        reject_before_decode(b"[4,\"x86_64\",false]");
        reject_before_decode(b"{\"operations\":[],\"operati\\u006fns\":[]}");
        reject_before_decode(b"{\"unknown\":\"\xff\"}");
        let properties = (0..MAX_OBJECT_KEYS).map(|index| format!("\"unknown_{index}\":0,")).collect::<String>();
        let operation = format!(r#"{{{properties}"op":"assert_plain_struct_layout"}}"#);
        assert!(reject_before_decode(&request(&operation)).contains("key count"));
    }

    #[test]
    fn maximum_layout_names_fields_size_and_text_survive_fully_escaped_raw_wire() {
        let layout = maximum_layout();
        layout.validate().unwrap();
        let isolated = escape_ascii_strings(&serde_json::to_vec(&layout).unwrap());
        assert_eq!(PlainStructLayout::from_wire(&isolated).unwrap(), layout);
        let operation = WorkerOperation::AssertPlainStructLayout { layout: layout.clone(), expected_context: None };
        let bytes = escape_ascii_strings(&serde_json::to_vec(&operation).unwrap());
        let operation = std::str::from_utf8(&bytes).unwrap();
        let decoded: WorkerRequest = decode_worker(&request(operation), |bytes| {
            serde_json::from_slice(bytes).map_err(|_| "invalid schema".to_owned())
        })
        .unwrap();
        let WorkerOperation::AssertPlainStructLayout { layout: actual, .. } = &decoded.operations[0] else {
            panic!("wrong operation")
        };
        assert_eq!(*actual, layout);
    }

    #[test]
    fn large_legacy_hex_type_and_prototype_strings_keep_wire_compatibility() {
        let hex = "ab".repeat(1024 * 1024);
        let declaration = "a".repeat(1024 * 1024);
        let operation = format!(r#"{{"declarations":"{declaration}","op":"parse_types"}}"#);
        let bytes = request(&operation);
        let text = std::str::from_utf8(&bytes).unwrap().replace("\"c3\"", &format!("\"{hex}\""));
        let decoded: WorkerRequest = decode_worker(text.as_bytes(), |bytes| {
            serde_json::from_slice(bytes).map_err(|_| "invalid schema".to_owned())
        })
        .unwrap();
        assert_eq!(decoded.mappings[0].hex_bytes, hex);
        let WorkerOperation::ParseTypes { declarations } = &decoded.operations[0] else { panic!("wrong operation") };
        assert_eq!(*declarations, declaration);
        let escaped = "\\u0061".repeat(256 * 1024);
        let operation = format!(r#"{{"declaration":"{escaped}","op":"prototype","address":4096,"indirect":false}}"#);
        let decoded: WorkerRequest = decode_worker(&request(&operation), |bytes| {
            serde_json::from_slice(bytes).map_err(|_| "invalid schema".to_owned())
        })
        .unwrap();
        let WorkerOperation::Prototype { declaration, .. } = &decoded.operations[0] else { panic!("wrong operation") };
        assert_eq!(declaration.len(), 256 * 1024);
    }

    #[test]
    fn isolated_layout_wire_errors_are_constant_and_unknown_payloads_are_bounded() {
        let giant = "hostile_marker".repeat(100_000);
        let array = format!("[{}0]", "0,".repeat(100_000));
        for bytes in [
            format!(r#"{{"name":"{giant}"}}"#),
            format!(r#"{{"{giant}":null}}"#),
            format!(r#"{{"fields":{array}}}"#),
            format!(r#"{{"fields":[{{"ty":{{"kind":"{giant}"}}}}]}}"#),
        ] {
            let error = PlainStructLayout::from_wire(bytes.as_bytes()).unwrap_err().to_string();
            assert!(error.len() < 160);
            assert!(!error.contains("hostile_marker"));
        }
    }
}
