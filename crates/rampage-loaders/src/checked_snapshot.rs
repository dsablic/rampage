use crate::LoadError;

const DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
const STRING_BYTES: usize = 1024 * 1024;
const ARRAY_ITEMS: usize = 4096;
const STRUCTURAL_UNITS: usize = 65_536;

enum Frame {
    Object,
    Array { items: usize, awaiting_value: bool },
}

fn invalid() -> LoadError {
    LoadError::Malformed("checked snapshot exceeds its raw structural or text budget".into())
}

fn begin_value(stack: &mut [Frame]) -> Result<(), LoadError> {
    if let Some(Frame::Array { items, awaiting_value }) = stack.last_mut()
        && *awaiting_value
    {
        *items += 1;
        if *items > ARRAY_ITEMS {
            return Err(invalid());
        }
        *awaiting_value = false;
    }
    Ok(())
}

/// A raw admission pass, not a replacement JSON parser. Runs before copying or deserializing source JSON.
pub(crate) fn preflight(data: &[u8]) -> Result<(), LoadError> {
    if data.len() > DOCUMENT_BYTES {
        return Err(invalid());
    }
    let mut stack = Vec::with_capacity(8);
    let mut quoted = false;
    let mut escaped = false;
    let mut string_start = 0usize;
    let mut units = 0usize;
    for (index, &byte) in data.iter().enumerate() {
        if quoted {
            if index - string_start > STRING_BYTES {
                return Err(invalid());
            }
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        if matches!(byte, b'{' | b'}' | b'[' | b']' | b':' | b',') {
            units += 1;
            if units > STRUCTURAL_UNITS {
                return Err(invalid());
            }
        }
        match byte {
            b'"' => {
                begin_value(&mut stack)?;
                quoted = true;
                string_start = index + 1;
            }
            b'{' | b'[' => {
                begin_value(&mut stack)?;
                if stack.len() == 8 {
                    return Err(invalid());
                }
                stack.push(if byte == b'{' { Frame::Object } else { Frame::Array { items: 0, awaiting_value: true } });
            }
            b'}' => {
                if !matches!(stack.pop(), Some(Frame::Object)) {
                    return Err(invalid());
                }
            }
            b']' => {
                if !matches!(stack.pop(), Some(Frame::Array { .. })) {
                    return Err(invalid());
                }
            }
            b',' => {
                if let Some(Frame::Array { awaiting_value, .. }) = stack.last_mut() {
                    *awaiting_value = true;
                }
            }
            b':' => {}
            byte if byte.is_ascii_whitespace() => {}
            _ => begin_value(&mut stack)?,
        }
    }
    if quoted || !stack.is_empty() {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaped_delimiters_are_text_and_each_array_value_is_counted_once() {
        let values = (0..ARRAY_ITEMS).map(|_| r#""\"[,]{}""#).collect::<Vec<_>>().join(",");
        assert!(preflight(format!("[{{\"values\":[{values}]}}]").as_bytes()).is_ok());
        assert!(preflight(format!("[{values},null]").as_bytes()).is_err());
        assert!(preflight(b"[null,true,false,-12,1.25,{},[]]").is_ok());
    }

    #[test]
    fn escaped_strings_and_nested_arrays_cannot_bypass_raw_budgets() {
        assert!(preflight(format!(r#"{{"value":"{}"}}"#, "\\u0061".repeat(STRING_BYTES / 6 + 1)).as_bytes()).is_err());
        assert!(preflight(b"[[[[[[[[[]]]]]]]]]").is_err());
        assert!(preflight(&vec![b' '; DOCUMENT_BYTES + 1]).is_err());
        assert!(preflight(b"{\"unterminated\":\"").is_err());
    }
}
