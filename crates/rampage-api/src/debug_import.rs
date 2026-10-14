use serde::Serialize;

use crate::{ApiError, Project};

#[derive(Debug, Serialize)]
pub struct DebugImport {
    pub preview: rampage_loaders::debug::DebugReport,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub applied: Vec<u64>,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub preserved: Vec<u64>,
}

impl Project {
    /// Previews or imports bounded embedded-DWARF scalar/pointer function signatures without replacing user edits.
    pub fn import_debug_signatures(&self, apply: bool) -> Result<DebugImport, ApiError> {
        let mut preview =
            rampage_loaders::debug::signatures(&self.binary).map_err(|error| ApiError::Invalid(error.to_string()))?;
        let mut accepted = Vec::new();
        let mut by_address = std::collections::BTreeMap::new();
        let mut conflicts = std::collections::BTreeSet::new();
        for signature in preview.signatures {
            if !self.binary.is_code(signature.address)
                || self.function_containing(signature.address)?.is_some_and(|entry| entry != signature.address)
            {
                preview.warnings.push(format!(
                    "skipped debug function {} at {:#x}: not an exact executable entry",
                    signature.name, signature.address
                ));
            } else if let Some(previous) = by_address.insert(signature.address, signature)
                && by_address[&previous.address].declaration != previous.declaration
            {
                conflicts.insert(previous.address);
            }
        }
        for (address, signature) in by_address {
            if conflicts.contains(&address) {
                preview.warnings.push(format!("conflicting debug signatures at {address:#x}; skipped"));
            } else {
                accepted.push(signature);
            }
        }
        preview.signatures = accepted;
        let reserved = reserved_names(&self.annotations());
        for signature in &mut preview.signatures {
            let replacements = [
                ("int8_t", "int1"),
                ("uint8_t", "uint1"),
                ("int16_t", "int2"),
                ("uint16_t", "uint2"),
                ("int32_t", "int4"),
                ("uint32_t", "uint4"),
                ("int64_t", "int8"),
                ("uint64_t", "uint8"),
                ("float", "float4"),
                ("double", "float8"),
            ];
            for (source, target) in replacements {
                signature.declaration = replace_word(&signature.declaration, source, target);
            }
            let safe = safe_declaration_names(&signature.declaration, &reserved);
            if safe != signature.declaration {
                preview.warnings.push(format!(
                    "renamed debug declaration identifiers in {} to avoid user type names",
                    signature.name
                ));
                signature.declaration = safe;
            }
        }
        let mut applied = Vec::new();
        let mut preserved = Vec::new();
        if apply {
            let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
            let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
            let mut annotations = self.annotations.write().expect("annotations lock");
            let candidates: Vec<_> =
                preview.signatures.iter().map(|signature| (signature.address, signature.declaration.clone())).collect();
            applied = annotations
                .import_signatures(
                    &candidates,
                    |snapshot, _, declaration| safe_declaration_names(declaration, &reserved_names(snapshot)),
                    |candidate| self.validate_annotation_snapshot(&state, &options, candidate),
                )
                .map_err(ApiError::Invalid)?;
            preserved =
                candidates.iter().map(|&(address, _)| address).filter(|address| !applied.contains(address)).collect();
        }
        Ok(DebugImport { preview, applied, preserved })
    }
}

pub(crate) fn reserved_names(annotations: &crate::annotations::Annotations) -> std::collections::BTreeSet<String> {
    annotations
        .types()
        .values()
        .chain(annotations.globals().values())
        .flat_map(|declaration| {
            declaration
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .filter(|word| !word.is_empty())
                .map(str::to_owned)
        })
        .collect()
}

pub(crate) fn safe_declaration_names(text: &str, reserved: &std::collections::BTreeSet<String>) -> String {
    let text = safe_parameter_names(text, reserved);
    let Some(open) = text.find('(') else { return text };
    let prefix = text[..open].trim_end();
    let start = prefix
        .rfind(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .map_or(0, |index| index + 1);
    if !reserved.contains(&prefix[start..]) {
        return text;
    }
    let mut name = "debug_signature".to_owned();
    let mut index = 0;
    while reserved.contains(&name) {
        name = format!("debug_signature_{index}");
        index += 1;
    }
    format!("{}{}{}", &text[..start], name, &text[open..])
}

fn safe_parameter_names(text: &str, reserved: &std::collections::BTreeSet<String>) -> String {
    let Some(open) = text.find('(') else { return text.to_owned() };
    let Some(close) = text.rfind(')') else { return text.to_owned() };
    let mut used = reserved.clone();
    for parameter in text[open + 1..close].split(',') {
        let trimmed = parameter.trim_end();
        let start = trimmed
            .rfind(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .map_or(0, |index| index + 1);
        used.insert(trimmed[start..].to_owned());
    }
    let mut result = text[..=open].to_owned();
    for (index, parameter) in text[open + 1..close].split(',').enumerate() {
        if index != 0 {
            result.push(',');
        }
        let trimmed = parameter.trim_end();
        let start = trimmed
            .rfind(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .map_or(0, |index| index + 1);
        let name = &trimmed[start..];
        if reserved.contains(name) && name != "void" {
            result.push_str(&trimmed[..start]);
            let mut candidate = format!("debug_param_{index}");
            let mut suffix = 1;
            while used.contains(&candidate) {
                candidate = format!("debug_param_{index}_{suffix}");
                suffix += 1;
            }
            used.insert(candidate.clone());
            result.push_str(&candidate);
        } else {
            result.push_str(parameter);
        }
    }
    result.push_str(&text[close..]);
    result
}

fn replace_word(text: &str, source: &str, target: &str) -> String {
    let mut result = String::new();
    let mut start = 0;
    for (at, character) in text.char_indices() {
        if !character.is_ascii_alphanumeric() && character != '_' {
            let word = &text[start..at];
            result.push_str(if word == source { target } else { word });
            result.push(character);
            start = at + character.len_utf8();
        }
    }
    let word = &text[start..];
    result.push_str(if word == source { target } else { word });
    result
}
