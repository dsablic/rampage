//! Bounding text read from untrusted input.

/// The longest prefix of `text` within `max` bytes that ends on a character boundary, and whether it was cut.
pub(crate) fn clip(text: &str, max: usize) -> (&str, bool) {
    if text.len() <= max {
        return (text, false);
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

#[cfg(test)]
mod tests {
    use super::clip;

    #[test]
    fn cuts_on_a_character_boundary() {
        assert_eq!(clip("short", 8), ("short", false));
        assert_eq!(clip("abcé", 4), ("abc", true));
        assert_eq!(clip("abcé", 5), ("abcé", false));
        assert_eq!(clip("é", 1), ("", true));
    }
}
