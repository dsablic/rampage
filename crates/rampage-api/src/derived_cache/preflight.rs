use super::{ApiError, DOCUMENT_BYTES, MAX_ROWS, invalid};

/// Allocation-free lexical budget pass; serde subsequently enforces JSON grammar and strict wire fields.
pub(super) fn raw_preflight(bytes: &[u8]) -> Result<(), ApiError> {
    if bytes.is_empty() || bytes.len() > DOCUMENT_BYTES || std::str::from_utf8(bytes).is_err() {
        return Err(invalid("inventory cache exceeds its document budget or is not UTF-8"));
    }
    let mut stack = [(0u8, 0usize); 8];
    let mut depth = 0usize;
    let mut structures = 0usize;
    let mut string_bytes = 0usize;
    let mut whitespace = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            whitespace += 1;
            if whitespace > 256 {
                return Err(invalid("inventory cache whitespace budget exceeded"));
            }
        } else {
            whitespace = 0;
        }
        match byte {
            b'"' => {
                let start = index + 1;
                index = start;
                while index < bytes.len() && bytes[index] != b'"' {
                    if bytes[index] == b'\\' {
                        index += 1;
                    }
                    index += 1;
                    if index.saturating_sub(start) > 4096 {
                        return Err(invalid("inventory cache string budget exceeded"));
                    }
                }
                if index >= bytes.len() {
                    return Err(invalid("inventory cache string is incomplete"));
                }
                string_bytes += index - start;
                structures += 1;
            }
            b'[' | b'{' => {
                if depth == stack.len() {
                    return Err(invalid("inventory cache nesting budget exceeded"));
                }
                stack[depth] = (byte, 1);
                depth += 1;
                structures += 1;
            }
            b']' | b'}' => {
                let expected = if byte == b']' { b'[' } else { b'{' };
                if depth == 0 || stack[depth - 1].0 != expected {
                    return Err(invalid("inventory cache has mismatched containers"));
                }
                depth -= 1;
            }
            b',' => {
                structures += 1;
                if depth > 0 && stack[depth - 1].0 == b'[' {
                    stack[depth - 1].1 += 1;
                    if stack[depth - 1].1 > MAX_ROWS {
                        return Err(invalid("inventory cache array budget exceeded"));
                    }
                }
            }
            _ => {}
        }
        if structures > 65_536 || string_bytes > DOCUMENT_BYTES {
            return Err(invalid("inventory cache structural or string budget exceeded"));
        }
        index += 1;
    }
    if depth != 0 {
        return Err(invalid("inventory cache containers are incomplete"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::raw_preflight;

    #[test]
    fn escape_heavy_strings_use_encoded_bytes_at_the_exact_budget_boundary() {
        let encoded = format!("{}{}", r#"\"\\\u0041"#.repeat(409), r"\u0041");
        assert_eq!(encoded.len(), 4096);
        let json = format!("\"{encoded}\"");
        raw_preflight(json.as_bytes()).unwrap();
        assert_eq!(serde_json::from_str::<String>(&json).unwrap(), format!("{}A", "\"\\A".repeat(409)));

        let oversized = format!("\"{encoded}a\"");
        assert!(serde_json::from_str::<String>(&oversized).unwrap().len() < 4096);
        assert!(raw_preflight(oversized.as_bytes()).is_err());
    }

    #[test]
    fn oversized_unicode_escapes_are_rejected_before_a_decoding_scratch_buffer_is_needed() {
        for (encoded, expected) in
            [(r"\u0041".repeat(683), "A".repeat(683)), (r"\ud83d\ude00".repeat(342), "\u{1f600}".repeat(342))]
        {
            let json = format!("\"{encoded}\"");
            assert!(expected.len() < 4096);
            assert!(raw_preflight(json.as_bytes()).is_err());
            assert_eq!(serde_json::from_str::<String>(&json).unwrap(), expected);
        }
    }

    #[test]
    fn lexical_preflight_does_not_replace_final_json_escape_validation() {
        for json in [r#""\q""#, r#""\u00xz""#, r#""\u123""#, r#""\ud800""#, r#""\udc00""#] {
            raw_preflight(json.as_bytes()).unwrap();
            assert!(serde_json::from_str::<String>(json).is_err());
        }
        let incomplete = b"\"unterminated\\";
        assert!(raw_preflight(incomplete).is_err());
        assert!(serde_json::from_slice::<String>(incomplete).is_err());
    }
}
