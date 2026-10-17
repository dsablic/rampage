//! Bounded declaration preparation, not a C preprocessor. No filesystem or host headers are consulted.

use rampage_decompiler::{DataOrganization, Platform};
use serde::Serialize;

use crate::ApiError;

pub const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_NESTING: usize = 128;

#[derive(Debug, Clone, Serialize)]
pub struct HeaderProvenance {
    pub project: String,
    pub version: String,
    pub sources: Vec<String>,
    pub license: String,
    pub license_source: String,
    pub license_text: String,
    pub adaptations: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeaderBundle {
    pub profile: String,
    pub provenance: Vec<HeaderProvenance>,
    pub declarations: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeaderDeclaration {
    pub declarations: String,
    /// A maximum member alignment in bytes; the native type factory must apply it after parsing.
    pub packing: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreparedHeader {
    pub declarations: Vec<HeaderDeclaration>,
    /// Deduplicated dependencies, not ordered textual include expansions.
    pub profiles: Vec<String>,
}

/// Explicit selection of `posix-linux` asserts Linux ABI; `Platform::Default` alone does not.
/// Call this with retained target/compiler metadata before importing any selected profile.
pub fn validate_header_profile(
    profile: &str,
    platform: Platform,
    compiler: &str,
    org: DataOrganization,
) -> Result<(), ApiError> {
    let windows_compiler = matches!(compiler, "windows" | "clangwindows");
    let darwin_compiler = matches!(compiler, "macosx" | "apple");
    match profile {
        "c" => {}
        "posix-linux" if platform == Platform::Default && !windows_compiler && !darwin_compiler => {}
        "win32" if platform == Platform::Windows && windows_compiler => {}
        "posix-linux" | "win32" => {
            return Err(invalid("header profile is incompatible with the target platform/compiler"));
        }
        _ => return Err(invalid("unknown bundled header profile (expected c, posix-linux or win32)")),
    }
    validate_widths(profile, org)
}

/// Width checks only: the two-argument interface has no platform evidence. The caller must also
/// invoke `validate_header_profile`; never auto-select Linux from ELF or a default compiler.
pub fn bundled_headers(profile: &str, org: DataOrganization) -> Result<HeaderBundle, ApiError> {
    validate_widths(profile, org)?;
    let declarations = match profile {
        "c" => include_str!("../resources/type-headers/c.h"),
        "posix-linux" => include_str!("../resources/type-headers/posix-linux.h"),
        "win32" => include_str!("../resources/type-headers/win32.h"),
        _ => return Err(invalid("unknown bundled header profile (expected c, posix-linux or win32)")),
    };
    let license_text = if profile == "win32" {
        concat!(
            include_str!("../resources/type-headers/LICENSE.mingw-w64"),
            "\n",
            include_str!("../resources/type-headers/DISCLAIMER.PD.mingw-w64")
        )
    } else {
        include_str!("../resources/type-headers/LICENSE.musl")
    };
    let manifest: serde_json::Value = serde_json::from_str(include_str!("../resources/type-headers/provenance.json"))
        .map_err(|error| invalid(&format!("invalid bundled provenance: {error}")))?;
    let provenance = &manifest["profiles"][profile];
    let text = |key: &str| -> Result<String, ApiError> {
        provenance[key].as_str().map(str::to_owned).ok_or_else(|| invalid("incomplete bundled header provenance"))
    };
    let sources = provenance["sources"]
        .as_array()
        .ok_or_else(|| invalid("missing bundled header sources"))?
        .iter()
        .map(|source| source.as_str().map(str::to_owned).ok_or_else(|| invalid("invalid bundled header source")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(HeaderBundle {
        profile: profile.to_owned(),
        provenance: vec![HeaderProvenance {
            project: text("project")?,
            version: text("version")?,
            sources,
            license: text("license")?,
            license_source: text("license_source")?,
            license_text: license_text.to_owned(),
            adaptations: text("adaptations")?,
        }],
        declarations: declarations.to_owned(),
    })
}

fn validate_widths(profile: &str, org: DataOrganization) -> Result<(), ApiError> {
    if !matches!(profile, "c" | "posix-linux" | "win32") {
        return Err(invalid("unknown bundled header profile (expected c, posix-linux or win32)"));
    }
    if !matches!(org.pointer, 4 | 8) || org.int != 4 || !matches!(org.long, 4 | 8) {
        return Err(invalid("bundled headers require pointer=4/8, int=4 and long=4/8"));
    }
    if profile == "win32" && org.long != 4 {
        return Err(invalid("win32 headers require the Windows LLP64/ILP32 data organization (long=4)"));
    }
    if profile == "posix-linux" && org.long != org.pointer {
        return Err(invalid("posix-linux headers require the supported Linux ILP32/LP64 data organization"));
    }
    Ok(())
}

/// Accept plain/preprocessed declarations plus allowlisted includes and balanced `pack(push,N)` /
/// `pack(pop)`. Reject macros, conditionals, continuations, literals and all other directives.
/// Includes select profiles, not files; stddef relies on the native target-sized size_t builtin.
/// Includes inside active packing scopes are unsupported because profiles cannot retain include-site packing.
pub fn prepare_header(input: &str) -> Result<PreparedHeader, ApiError> {
    if input.is_empty() || input.len() > MAX_HEADER_BYTES {
        return Err(invalid("header must contain 1..=65536 bytes"));
    }
    if input.contains('\0') || input.contains('\\') {
        return Err(invalid("NUL bytes, escapes and line continuations are not supported in headers"));
    }
    let stripped = strip_comments(input)?;
    let mut prepared = PreparedHeader { declarations: Vec::new(), profiles: Vec::new() };
    let mut pending = String::new();
    let mut delimiters = Vec::new();
    let mut packing = None;
    let mut stack = Vec::new();
    for line in stripped.lines() {
        if let Some(directive) = line.trim_start().strip_prefix('#') {
            if !pending.trim().is_empty() || !delimiters.is_empty() {
                return Err(invalid("header directives must occur between complete declarations"));
            }
            prepare_directive(directive, &mut prepared.profiles, &mut packing, &mut stack)?;
            continue;
        }
        for character in line.chars() {
            match character {
                '#' | '\'' | '"' => return Err(invalid("directives within declarations and literals are unsupported")),
                '(' | '[' | '{' => {
                    if delimiters.len() == MAX_NESTING {
                        return Err(invalid("header declaration nesting exceeds 128"));
                    }
                    delimiters.push(character);
                }
                ')' | ']' | '}' => {
                    let expected = match character {
                        ')' => '(',
                        ']' => '[',
                        _ => '{',
                    };
                    if delimiters.pop() != Some(expected) {
                        return Err(invalid("unbalanced header declaration delimiters"));
                    }
                }
                _ => {}
            }
            pending.push(character);
            if character == ';' && delimiters.is_empty() {
                if pending.trim() == ";" {
                    return Err(invalid("empty header declaration"));
                }
                prepared.declarations.push(HeaderDeclaration { declarations: pending.trim().to_owned(), packing });
                pending.clear();
            }
        }
        pending.push('\n');
    }
    if !delimiters.is_empty() || !pending.trim().is_empty() {
        return Err(invalid("header ends with an incomplete declaration (expected a terminating semicolon)"));
    }
    if !stack.is_empty() {
        return Err(invalid("header has an unmatched #pragma pack(push,N)"));
    }
    if prepared.declarations.is_empty() && prepared.profiles.is_empty() {
        return Err(invalid("header contains no declarations or bundled includes"));
    }
    Ok(prepared)
}

fn prepare_directive(
    directive: &str,
    profiles: &mut Vec<String>,
    packing: &mut Option<u32>,
    stack: &mut Vec<Option<u32>>,
) -> Result<(), ApiError> {
    let directive = directive.trim();
    let word_end = directive.find(|c: char| !c.is_ascii_alphanumeric() && c != '_').unwrap_or(directive.len());
    let (word, rest) = directive.split_at(word_end);
    let rest = rest.trim();
    if word == "include" {
        if packing.is_some() {
            return Err(invalid("bundled includes inside active #pragma pack scopes are unsupported"));
        }
        let name = rest
            .strip_prefix('<')
            .and_then(|text| text.strip_suffix('>'))
            .or_else(|| rest.strip_prefix('"').and_then(|text| text.strip_suffix('"')))
            .ok_or_else(|| invalid("include requires a literal bundled header name"))?;
        let profile = match name {
            "stdint.h" | "stddef.h" | "stdio.h" => "c",
            "sys/socket.h" => "posix-linux",
            "windows.h" => "win32",
            _ => return Err(invalid("include is not a bundled header name; filesystem includes are forbidden")),
        };
        if !profiles.iter().any(|existing| existing == profile) {
            profiles.push(profile.to_owned());
        }
        return Ok(());
    }
    if word != "pragma" {
        return Err(invalid("only bundled #include and #pragma pack(push,N)/pack(pop) directives are supported"));
    }
    let arguments = rest
        .strip_prefix("pack")
        .and_then(|text| text.trim().strip_prefix('('))
        .and_then(|text| text.strip_suffix(')'))
        .ok_or_else(|| invalid("unsupported pragma; expected pack(push,N) or pack(pop)"))?;
    let arguments: Vec<_> = arguments.split(',').map(str::trim).collect();
    if arguments == ["pop"] {
        *packing = stack.pop().ok_or_else(|| invalid("#pragma pack(pop) has no matching push"))?;
        return Ok(());
    }
    let ["push", value] = arguments.as_slice() else {
        return Err(invalid("unsupported pragma; expected pack(push,N) or pack(pop)"));
    };
    let value = match *value {
        "1" => 1,
        "2" => 2,
        "4" => 4,
        "8" => 8,
        "16" => 16,
        _ => return Err(invalid("pack alignment must be 1, 2, 4, 8 or 16")),
    };
    if stack.len() == MAX_NESTING {
        return Err(invalid("header packing nesting exceeds 128"));
    }
    stack.push(*packing);
    *packing = Some(value);
    Ok(())
}

fn strip_comments(input: &str) -> Result<String, ApiError> {
    let mut output = String::with_capacity(input.len());
    let mut characters = input.chars().peekable();
    let mut quoted = None;
    while let Some(character) = characters.next() {
        if let Some(quote) = quoted {
            output.push(character);
            if character == quote {
                quoted = None;
            } else if character == '\n' {
                return Err(invalid("unterminated quoted header token"));
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            quoted = Some(character);
        }
        if character == '/' && characters.peek() == Some(&'/') {
            characters.next();
            output.push(' ');
            for next in characters.by_ref() {
                if next == '\n' {
                    output.push('\n');
                    break;
                }
            }
        } else if character == '/' && characters.peek() == Some(&'*') {
            characters.next();
            output.push(' ');
            let mut closed = false;
            while let Some(next) = characters.next() {
                if next == '\n' {
                    output.push('\n');
                }
                if next == '*' && characters.peek() == Some(&'/') {
                    characters.next();
                    closed = true;
                    break;
                }
            }
            if !closed {
                return Err(invalid("unterminated header block comment"));
            }
        } else {
            output.push(character);
        }
    }
    if quoted.is_some() {
        return Err(invalid("unterminated quoted header token"));
    }
    Ok(output)
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_includes_reject_active_packing_even_for_already_selected_profiles() {
        for name in ["stdint.h", "stddef.h", "stdio.h", "sys/socket.h", "windows.h"] {
            let input = format!("#include <{name}>\n#pragma pack(push,1)\n#include <{name}>\n#pragma pack(pop)\n");
            let error = prepare_header(&input).expect_err("include-site packing must not be discarded");
            assert!(matches!(error, ApiError::Invalid(message) if message.contains("active #pragma pack")));
        }
    }

    #[test]
    fn ordinary_includes_allow_packed_declarations_and_includes_after_pop() {
        let prepared = prepare_header(concat!(
            "#include <sys/socket.h>\n",
            "#pragma pack(push,1)\n",
            "struct Packed { char tag; int value; };\n",
            "#pragma pack(pop)\n",
            "#include <stdio.h>\n",
            "struct Natural { char tag; int value; };\n"
        ))
        .expect("packing applies to inline declarations, not bundled includes");

        assert_eq!(prepared.profiles, ["posix-linux", "c"]);
        assert_eq!(prepared.declarations.len(), 2);
        assert_eq!(prepared.declarations[0].packing, Some(1));
        assert_eq!(prepared.declarations[1].packing, None);
    }
}
