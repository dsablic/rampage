//! JNI symbol names: the `Java_` export a `native` method binds to by name, in its short form (class and method)
//! and its long form (with the argument signature, for overloads), mangled as the JNI specification says.

/// Mangles one name component: `_` → `_1`, `;` → `_2`, `[` → `_3`, `/` → `_`, other non-alphanumerics → `_0xxxx`.
pub fn mangle(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for unit in text.encode_utf16() {
        match unit {
            0x2f => out.push('_'),
            0x5f => out.push_str("_1"),
            0x3b => out.push_str("_2"),
            0x5b => out.push_str("_3"),
            unit if unit < 0x80 && (unit as u8).is_ascii_alphanumeric() => out.push(unit as u8 as char),
            unit => out.push_str(&format!("_0{unit:04x}")),
        }
    }
    out
}

/// The short and long JNI names of method `name` with parameter descriptors `params` on class `descriptor`
/// (`Lpkg/Class;`).
pub fn symbols(descriptor: &str, name: &str, params: &[String]) -> (String, String) {
    let class = descriptor.strip_prefix('L').and_then(|rest| rest.strip_suffix(';')).unwrap_or(descriptor);
    let short = format!("Java_{}_{}", mangle(class), mangle(name));
    let long = format!("{short}__{}", mangle(&params.concat()));
    (short, long)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_mangle_as_the_specification_says() {
        let (short, long) =
            symbols("Lcom/example/my_app/Native;", "encode", &["[B".to_owned(), "Ljava/lang/String;".to_owned()]);
        assert_eq!(short, "Java_com_example_my_1app_Native_encode");
        assert_eq!(long, "Java_com_example_my_1app_Native_encode___3BLjava_lang_String_2");
        assert_eq!(mangle("é"), "_000e9");
    }
}
