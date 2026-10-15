use std::collections::{BTreeMap, BTreeSet};

use rampage_analysis::classes::{ClassEvidence, ClassRecovery, SlotClassification};
use rampage_loaders::debug::DebugLayoutTypeId;
use serde::Serialize;

use super::{check_backing, invalid, validate_native_work};
use crate::{ApiError, Project};

const MAX_TABLES: usize = 32;
const MAX_SLOTS: u64 = 64;
const MAX_ASSOCIATIONS: usize = 256;
const MAX_NAME_BYTES: usize = 4096;
const MAX_TEXT_BYTES: usize = 128 * 1024;
const RESERVED_TEXT_BYTES: usize = 8192;
const VERIFICATION: &str = "native_checked_source_evidence";

#[derive(Debug, Default, Serialize)]
pub struct DebugLayoutVirtualEvidence {
    pub tables: Vec<DebugLayoutVtableEvidence>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DebugLayoutVtableEvidence {
    pub raw: ClassEvidence,
    pub methods: Vec<DebugLayoutVirtualMethodEvidence>,
}

#[derive(Debug, Serialize)]
pub struct DebugLayoutVirtualMethodEvidence {
    pub slot_index: u64,
    pub declared_virtual_slot_index: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub method_address: u64,
    pub definition_id: DebugLayoutTypeId,
    pub record_id: DebugLayoutTypeId,
    pub declaration_id: DebugLayoutTypeId,
    pub object_pointer_id: DebugLayoutTypeId,
    pub linkage_name: String,
    pub layout_name: String,
    pub verification: &'static str,
}

/// Constructed only after exact producer proof and independent native validation of the source closure.
/// This is not proof that the analyst's current declarations match, or permission to apply a type.
#[derive(Debug)]
pub(crate) struct VerifiedVirtualMethod {
    pub(crate) virtual_slot_index: u64,
    pub(crate) method_address: u64,
    pub(crate) definition_id: DebugLayoutTypeId,
    pub(crate) record_id: DebugLayoutTypeId,
    pub(crate) declaration_id: DebugLayoutTypeId,
    pub(crate) object_pointer_id: DebugLayoutTypeId,
    pub(crate) linkage_name: String,
    pub(crate) layout_name: String,
}

pub(crate) fn collect_virtual_evidence(
    project: &Project,
    methods: &[VerifiedVirtualMethod],
) -> Result<DebugLayoutVirtualEvidence, ApiError> {
    if methods.is_empty() {
        return Ok(DebugLayoutVirtualEvidence::default());
    }
    validate_methods(methods)?;
    check_backing(project)?;
    let result = (|| {
        if project.binary.format != rampage_loaders::Format::Elf
            || project.binary.arch != rampage_arch::Arch::X86_64
            || project.binary.big_endian
        {
            return Err(invalid("virtual evidence requires x86-64 little-endian ELF"));
        }
        validate_native_work(project)?;
        let analysis = project.analysis()?;
        if analysis.program.functions.len() > 16_384 {
            return Err(invalid("virtual evidence discovered-entry count budget exceeded"));
        }
        let entries = analysis.program.functions.iter().map(|function| function.address).collect();
        let raw = rampage_analysis::classes::recover_named_bounded(&project.binary, MAX_TABLES, MAX_SLOTS);
        correlate(raw, methods, &entries)
    })();
    check_backing(project)?;
    result
}

fn validate_methods(methods: &[VerifiedVirtualMethod]) -> Result<(), ApiError> {
    if methods.len() > MAX_ASSOCIATIONS {
        return Err(invalid("virtual evidence verified-method count budget exceeded"));
    }
    let mut text = 0usize;
    for method in methods {
        if method.linkage_name.is_empty()
            || method.layout_name.is_empty()
            || method.linkage_name.len() > MAX_NAME_BYTES
            || method.layout_name.len() > MAX_NAME_BYTES
        {
            return Err(invalid("virtual evidence method name budget exceeded"));
        }
        text += method.linkage_name.len() + method.layout_name.len();
        if text > MAX_TEXT_BYTES - RESERVED_TEXT_BYTES {
            return Err(invalid("virtual evidence input text budget exceeded"));
        }
    }
    Ok(())
}

fn raw_text_bytes(raw: &ClassEvidence) -> Result<usize, ApiError> {
    let names = [Some(raw.name.as_str()), Some(raw.vtable_symbol.as_str()), raw.rtti_candidate.symbol.as_deref()];
    if names.into_iter().flatten().any(|name| name.len() > MAX_NAME_BYTES) {
        return Err(invalid("virtual evidence raw name budget exceeded"));
    }
    // Reserve the bounded static labels, including up to 64 slot classifications, before cloning associations.
    Ok(names.into_iter().flatten().map(str::len).sum::<usize>() + 1024)
}

fn correlate(
    raw: ClassRecovery,
    methods: &[VerifiedVirtualMethod],
    entries: &BTreeSet<u64>,
) -> Result<DebugLayoutVirtualEvidence, ApiError> {
    validate_methods(methods)?;
    if raw.classes.len() > MAX_TABLES || raw.classes.iter().any(|table| table.slots.len() > MAX_SLOTS as usize) {
        return Err(invalid("virtual evidence raw table/slot budget exceeded"));
    }
    if raw.warnings.len() > 64 || raw.limitations.len() > 16 {
        return Err(invalid("virtual evidence raw diagnostic budget exceeded"));
    }
    let mut diagnostic_bytes = 0usize;
    for diagnostic in raw.warnings.iter().chain(&raw.limitations) {
        diagnostic_bytes = diagnostic_bytes
            .checked_add(diagnostic.len())
            .filter(|&bytes| bytes <= RESERVED_TEXT_BYTES / 2)
            .ok_or_else(|| invalid("virtual evidence raw diagnostic budget exceeded"))?;
    }
    let mut text = RESERVED_TEXT_BYTES;
    for table in &raw.classes {
        text += raw_text_bytes(table)?;
        if text > MAX_TEXT_BYTES {
            return Err(invalid("virtual evidence raw text budget exceeded"));
        }
    }
    let mut targets = BTreeMap::new();
    let mut definitions = BTreeMap::new();
    let mut declarations = BTreeMap::new();
    let mut object_pointers = BTreeMap::new();
    for method in methods {
        *targets.entry(method.method_address).or_insert(0usize) += 1;
        *definitions.entry(method.definition_id).or_insert(0usize) += 1;
        *declarations.entry(method.declaration_id).or_insert(0usize) += 1;
        *object_pointers.entry(method.object_pointer_id).or_insert(0usize) += 1;
    }
    let mut notices = BTreeSet::new();
    let mut eligible = BTreeMap::new();
    for method in methods {
        if targets[&method.method_address] != 1
            || definitions[&method.definition_id] != 1
            || declarations[&method.declaration_id] != 1
            || object_pointers[&method.object_pointer_id] != 1
        {
            notices.insert("Duplicate method targets or producer identities remain raw and unassociated.");
        } else if !entries.contains(&method.method_address) {
            notices.insert("Methods lacking exact discovered-entry membership remain raw and unassociated.");
        } else {
            eligible.insert(method.method_address, method);
        }
    }
    let mut result =
        DebugLayoutVirtualEvidence { tables: Vec::new(), warnings: raw.warnings, limitations: raw.limitations };
    result.limitations.extend([
        "Associations are native-checked source evidence, not applied or current analyst type claims.".to_owned(),
        "Only exact raw target and declared slot-index equality associates methods; names, containing functions \
         and thunks are not followed. No object-vptr, table-owner or resolved indirect-call claim is made."
            .to_owned(),
        "Raw header confidence is unchanged: unverified prefixes retain unknown offset-to-top and candidate slot \
         positions, not proven address points. Null/unresolved entries stop the raw scan; relocations and \
         secondary tables are not reconstructed."
            .to_owned(),
        "At most 32 tables, 64 slots per table, 256 associations, 4096 bytes per name and 128 KiB of total text. \
         This evidence does not modify annotations, navigation or apply eligibility."
            .to_owned(),
    ]);
    let mut count = 0usize;
    for raw in raw.classes {
        let mut associated = Vec::new();
        for slot in &raw.slots {
            if slot.classification != SlotClassification::Function {
                continue;
            }
            let Some(method) = slot.target.and_then(|target| eligible.get(&target)) else {
                notices.insert(
                    "Code-backed slots without one exact eligible method target remain raw; interior targets \
                     and thunks are not resolved.",
                );
                continue;
            };
            if slot.target != Some(slot.raw_value) || slot.raw_value != method.method_address {
                notices.insert("Raw pointer and exact method target disagreement remains unassociated.");
                continue;
            }
            if slot.index != method.virtual_slot_index {
                notices.insert("Exact method targets at a different declared virtual slot index remain unassociated.");
                continue;
            }
            let bytes = method.linkage_name.len() + method.layout_name.len() + VERIFICATION.len();
            if count == MAX_ASSOCIATIONS || bytes > MAX_TEXT_BYTES - text {
                notices.insert("Virtual association count/text budget reached; remaining slots stay raw.");
                continue;
            }
            text += bytes;
            count += 1;
            associated.push(DebugLayoutVirtualMethodEvidence {
                slot_index: slot.index,
                declared_virtual_slot_index: method.virtual_slot_index,
                method_address: method.method_address,
                definition_id: method.definition_id,
                record_id: method.record_id,
                declaration_id: method.declaration_id,
                object_pointer_id: method.object_pointer_id,
                linkage_name: method.linkage_name.clone(),
                layout_name: method.layout_name.clone(),
                verification: VERIFICATION,
            });
        }
        result.tables.push(DebugLayoutVtableEvidence { raw, methods: associated });
    }
    result.warnings.extend(notices.into_iter().map(str::to_owned));
    Ok(result)
}

#[cfg(test)]
#[path = "virtuals_tests.rs"]
mod tests;
