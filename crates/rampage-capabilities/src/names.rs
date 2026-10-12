//! Canonical import/API name normalization shared by every name-based matcher.
//!
//! A raw name as a loader reports it (`__imp__CreateFileW@28`, `_connect`, `send@plt`, `CONNECT`) is reduced to a
//! stem by [`import_stem`]. Tables of patterns are matched against stems by [`stem_matches`] / [`find_pattern`]:
//!
//! - an exact pattern (`createfile`) matches a stem equal to it, or equal to it after dropping one trailing
//!   Windows `A`/`W` charset suffix ([`strip_aw`]), so `createfile` matches `CreateFileA` and `CreateFileW`. Only
//!   the candidate is stripped, so a pattern that names one variant (`createfilew`) still matches only that one;
//! - a pattern ending in `*` (`bcrypt*`) matches any stem starting with the text before the `*`.
//!
//! Patterns are written lowercase. The A/W rule is lexical: a non-Windows name that happens to end in `a`/`w` is
//! stripped too, so an exact pattern also matches its own name plus one `a`/`w` (`connect` matches `connecta`).

/// Reduces a raw import or symbol name to its comparison stem. In order:
///
/// 1. one leading `__imp_` or `_imp__` import-thunk prefix is removed;
/// 2. unless the name is an MSVC C++ mangling (starts with `?`, where `@` is structural), everything from the
///    first `@` is removed: an ELF `@plt` stub suffix, a symbol version (`@GLIBC_2.2.5`, `@@GLIBC_2.2.5`) or an
///    x86 stdcall/fastcall argument-size suffix (`@28`);
/// 3. leading underscores are removed (Mach-O and x86 C decoration);
/// 4. the result is ASCII-lowercased.
///
/// No `A`/`W` suffix is removed here; see [`strip_aw`].
pub fn import_stem(name: &str) -> String {
    let name = name.strip_prefix("__imp_").or_else(|| name.strip_prefix("_imp__")).unwrap_or(name);
    let name = if name.starts_with('?') { name } else { name.split('@').next().unwrap_or(name) };
    name.trim_start_matches('_').to_ascii_lowercase()
}

/// Drops one trailing `a` or `w` (a Windows ANSI/wide charset suffix, once lowercased by [`import_stem`]).
pub fn strip_aw(stem: &str) -> &str {
    stem.strip_suffix(['a', 'w']).unwrap_or(stem)
}

/// Whether `stem` (from [`import_stem`]) matches a lowercase `pattern`: an exact pattern matches the stem as is or
/// after [`strip_aw`]; a pattern ending in `*` matches by prefix.
pub fn stem_matches(pattern: &str, stem: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => stem.starts_with(prefix),
        None => stem == pattern || strip_aw(stem) == pattern,
    }
}

/// The value of the first `(pattern, value)` entry whose pattern matches the raw `name`.
pub fn find_pattern<'t, T>(table: &'t [(&str, T)], name: &str) -> Option<&'t T> {
    let stem = import_stem(name);
    table.iter().find(|(pattern, _)| stem_matches(pattern, &stem)).map(|(_, value)| value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stems_drop_thunk_prefixes_suffixes_and_underscores() {
        assert_eq!(import_stem("__imp_connect"), "connect");
        assert_eq!(import_stem("__imp__CreateFileW@28"), "createfilew");
        assert_eq!(import_stem("_imp__send@16"), "send");
        assert_eq!(import_stem("connect@plt"), "connect");
        assert_eq!(import_stem("memcpy@@GLIBC_2.14"), "memcpy");
        assert_eq!(import_stem("_ptrace"), "ptrace");
        assert_eq!(import_stem("PTRACE"), "ptrace");
        assert_eq!(import_stem("?Foo@@YAXXZ"), "?foo@@yaxxz");
    }

    #[test]
    fn aw_suffix_is_stripped_once_from_the_candidate_only() {
        assert_eq!(strip_aw("createfilew"), "createfile");
        assert_eq!(strip_aw("dnsquery_a"), "dnsquery_");
        assert_eq!(strip_aw("socket"), "socket");
        assert!(stem_matches("createfile", "createfilew"));
        assert!(stem_matches("createfile", "createfilea"));
        assert!(stem_matches("createfile", "createfile"));
        assert!(stem_matches("createfilew", "createfilew"));
        assert!(!stem_matches("createfilew", "createfilea"));
        assert!(!stem_matches("createfile", "createfileaw"));
        assert!(!stem_matches("loadlibrary", "loadlibraryexw"));
    }

    #[test]
    fn star_patterns_match_by_prefix() {
        assert!(stem_matches("bcrypt*", "bcryptencrypt"));
        assert!(!stem_matches("bcrypt*", "ncryptencrypt"));
        let table = [("internetopen", 1), ("bcrypt*", 2)];
        assert_eq!(find_pattern(&table, "__imp_InternetOpenW"), Some(&1));
        assert_eq!(find_pattern(&table, "_BCryptHashData@24"), Some(&2));
        assert_eq!(find_pattern(&table, "socket"), None);
    }
}
