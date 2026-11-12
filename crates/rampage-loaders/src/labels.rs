//! The label contract every user-visible function or data name obeys, shared by the annotation layer and the
//! readers (PDB) that propose names, so a proposed name is never one the annotation layer would refuse.

/// Refuses a name that is not an identifier, or that address resolution would read as an address. Resolution
/// parses `0x...` and `0X...` before looking up names, so such a name could never be looked up. It looks up names
/// before `sub_<hex>`, so naming one function `sub_401000` would shadow the default name of the function at
/// 0x401000. Other names that merely start with `sub_` (`sub_menu_init`) are fine.
pub fn check_name(name: &str) -> Result<(), String> {
    // Before the identifier rules, which refuse `0x...` too but with a less helpful reason.
    if is_address_shaped(name) {
        return Err(format!("{name:?} looks like an address; choose another name"));
    }
    let valid = !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.$@?:".contains(c));
    if !valid {
        return Err(format!("{name:?} is not a valid name: use letters, digits and _.$@?:"));
    }
    Ok(())
}

pub fn is_address_shaped(name: &str) -> bool {
    hex_address_digits(name).is_some() || default_name_address(name).is_some()
}

/// The hex digits of an address written `0x...` or `0X...`, as address resolution reads it.
pub fn hex_address_digits(text: &str) -> Option<&str> {
    text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"))
}

/// The address in a default function name `sub_<hex>`, as address resolution reads it.
pub fn default_name_address(text: &str) -> Option<u64> {
    text.strip_prefix("sub_").and_then(|hex| u64::from_str_radix(hex, 16).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_refuse_empty_address_shaped_and_non_identifier_names() {
        for bad in ["", "0x10", "0X10", "sub_401000", "1st", "Box<int>::get", "a b"] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
        for good in ["main", "sub_menu_init", "?get@?$Box@H@@UEBAHXZ", "geo::Rect::area", "_x@8", "a.b$c"] {
            assert!(check_name(good).is_ok(), "{good}");
        }
    }
}
