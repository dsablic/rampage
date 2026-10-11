use rampage_loaders::Binary;
use serde::Serialize;
use std::fmt::{self, Write};

struct BoundedName(String);

impl Write for BoundedName {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.0.len().saturating_add(text.len()) > 4096 {
            return Err(fmt::Error);
        }
        self.0.push_str(text);
        Ok(())
    }
}

pub fn demangle(name: &str) -> Option<String> {
    if name.len() > 4096 {
        return None;
    }
    // Microsoft Visual C++ names begin with '?'; the Itanium and Rust demanglers reject them outright.
    if name.starts_with('?') {
        return demangle_msvc(name);
    }
    let normalized = name.strip_prefix("__Z").map(|tail| format!("_Z{tail}"));
    let name = normalized.as_deref().unwrap_or(name);
    let mut output = BoundedName(String::new());
    if let Ok(symbol) = rustc_demangle::try_demangle(name) {
        write!(output, "{symbol:#}").ok()?;
    } else {
        cpp_demangle::Symbol::new(name).ok()?.structured_demangle(&mut output, &Default::default()).ok()?;
    }
    Some(output.0)
}

/// Demangles a Microsoft Visual C++ name. Return types, calling conventions, access specifiers and MS keywords
/// are dropped so the output reads like the Itanium demangler's (`Class::method(args)`).
fn demangle_msvc(name: &str) -> Option<String> {
    use msvc_demangler::DemangleFlags as Flags;
    let flags = Flags::NO_ACCESS_SPECIFIERS
        | Flags::NO_FUNCTION_RETURNS
        | Flags::NO_MS_KEYWORDS
        | Flags::NO_MEMBER_TYPE;
    let demangled = msvc_demangler::demangle(name, flags).ok()?;
    (!demangled.is_empty() && demangled != name && demangled.len() <= 4096).then_some(demangled)
}

#[derive(Debug, Serialize)]
pub struct LanguageMetadata {
    pub symbols: Vec<LanguageSymbol>,
    pub selectors: Vec<Selector>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct LanguageSymbol {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub original: String,
    pub display: String,
    pub category: &'static str,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub vtable_targets: Vec<u64>,
}

#[derive(Debug, Serialize)]
pub struct Selector {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
}

pub fn metadata(binary: &Binary) -> LanguageMetadata {
    let mut symbols = Vec::new();
    for symbol in &binary.symbols {
        let display = demangle(&symbol.name);
        let normalized =
            symbol.name.strip_prefix('_').filter(|_| symbol.name.starts_with("__Z")).unwrap_or(&symbol.name);
        let category = if symbol.name.contains("OBJC_CLASS_$_") {
            "objc_class"
        } else if normalized.starts_with("_ZTV") || symbol.name.starts_with("??_7") {
            "vtable"
        } else if normalized.starts_with("_ZTI") || normalized.starts_with("_ZTS") || symbol.name.starts_with("??_R") {
            "rtti"
        } else {
            "symbol"
        };
        if display.is_none() && category == "symbol" {
            continue;
        }
        // Only the Itanium layout is decoded here: the first two words are the offset-to-top and the RTTI
        // pointer, so function pointers start at index 2. The MSVC vftable layout differs and is not extracted.
        let mut vtable_targets = Vec::new();
        let itanium_vtable = normalized.starts_with("_ZTV");
        if itanium_vtable && symbol.size >= u64::from(binary.arch.pointer_size()) * 3 {
            let size = u64::from(binary.arch.pointer_size());
            for index in 2..(symbol.size / size).min(130) {
                let Some(at) = symbol.address.checked_add(index * size) else { break };
                let Some(pointer) = binary.read_pointer(at, size as u8).filter(|&at| binary.is_code(at)) else { break };
                vtable_targets.push(pointer);
            }
        }
        symbols.push(LanguageSymbol {
            address: symbol.address,
            original: symbol.name.clone(),
            display: display.unwrap_or_else(|| symbol.name.clone()),
            category,
            vtable_targets,
        });
    }
    let mut selectors = Vec::new();
    for section in binary.sections.iter().filter(|section| section.name == "__objc_methname") {
        let Some(bytes) = binary.read(section.address, section.size.min(4 * 1024 * 1024)) else { continue };
        let mut offset = 0;
        for name in bytes.split_inclusive(|&byte| byte == 0).take(20_000) {
            if name.last() == Some(&0)
                && name.len() <= 4096
                && let Ok(text) = std::str::from_utf8(&name[..name.len() - 1])
                && !text.is_empty()
            {
                selectors.push(Selector { address: section.address + offset, name: text.to_owned() });
            }
            offset += name.len() as u64;
        }
    }
    LanguageMetadata {
        symbols,
        selectors,
        limitations: vec![
            "Vtables require sized Itanium ABI symbols and readable function pointers; \
             stripped tables are not guessed."
                .to_owned(),
            "Objective-C selectors are strings, not recovered call edges or complete class layouts.".to_owned(),
            "MSVC names are demangled, but MSVC vtable targets and relative/authenticated vtables are not \
             extracted."
                .to_owned(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangles_cpp_macho_and_rust_names_without_changing_plain_names() {
        assert_eq!(demangle("_ZN3Foo3barEi").as_deref(), Some("Foo::bar(int)"));
        assert_eq!(demangle("__ZN3Foo3barEi").as_deref(), Some("Foo::bar(int)"));
        assert!(demangle("_ZTV3Foo").unwrap().contains("Foo"));
        assert_eq!(demangle("_ZN3foo3bar17h0123456789abcdefE").as_deref(), Some("foo::bar"));
        assert_eq!(demangle("main"), None);
        assert_eq!(demangle(&"_Z".repeat(3000)), None);
    }

    #[test]
    fn demangles_msvc_names() {
        assert_eq!(demangle("?func@@YAHHH@Z").as_deref(), Some("func(int,int)"));
        assert_eq!(demangle("?bar@Foo@@QEAAHH@Z").as_deref(), Some("Foo::bar(int)"));
        assert_eq!(demangle("??0Foo@@QEAA@XZ").as_deref(), Some("Foo::Foo(void)"));
        assert!(demangle("??_7Foo@@6B@").unwrap().contains("Foo"));
        // A plain name and an Itanium name are not MSVC; the '?' gate must not swallow them.
        assert_eq!(demangle("?notmangled"), None);
        assert_eq!(demangle("_ZN3Foo3barEi").as_deref(), Some("Foo::bar(int)"));
    }

    #[test]
    fn exponential_cpp_substitutions_stop_at_the_output_budget() {
        let digits = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut name = "_Z1f1AIiE".to_owned();
        for index in 0..18 {
            let letter = char::from(b'B' + index as u8);
            let substitution = char::from(digits[2 * index]);
            name.push_str(&format!("1{letter}IS{substitution}_S{substitution}_E"));
        }
        assert!(name.len() < 200);
        assert_eq!(demangle(&name), None);
    }
}
