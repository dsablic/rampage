use std::collections::BTreeSet;

use super::virtuals::{VerifiedVirtualMethod, collect_virtual_evidence};
use super::{
    Annotations, DebugLayoutPreview, DebugLayoutReport, DebugLayoutVirtualEvidence, check_backing, image_digest,
    invalid, layout_changes, method_identity_name, specification_identity, validate_report,
};
use crate::{ApiError, Project};

#[cfg(test)]
std::thread_local! {
    static SOURCE_VALIDATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn source_validation_count() -> usize {
    SOURCE_VALIDATIONS.get()
}

struct SourceVirtualMethod<'a> {
    virtual_slot_index: u64,
    method_address: u64,
    definition_id: rampage_loaders::debug::DebugLayoutTypeId,
    method: &'a rampage_loaders::debug::DebugLayoutMethod,
    layout_name: &'a str,
}

pub(super) fn checked_virtual_source_evidence(
    project: &Project,
    producer: &rampage_loaders::debug::DebugLayoutReport,
    preview: &DebugLayoutPreview<'_>,
) -> Result<DebugLayoutVirtualEvidence, ApiError> {
    let mut methods = Vec::new();
    let mut functions = Vec::new();
    for raw in &producer.signatures {
        let Some(method) = &raw.method else { continue };
        let Some(virtual_slot_index) = method.virtual_slot else { continue };
        if virtual_slot_index >= 64 {
            return Err(invalid("virtual source slot index exceeds the bounded named-table scope"));
        }
        let Some(function) = preview.report.functions.iter().find(|function| {
            function.address == raw.address
                && function.unit_offset == raw.id.unit_offset
                && function.die_offset == raw.id.die_offset
        }) else {
            continue;
        };
        let Some(record) = preview.report.types.iter().find(|record| {
            record.unit_offset == method.record_id.unit_offset
                && record.die_offset == method.record_id.die_offset
                && !record.projections.is_empty()
        }) else {
            continue;
        };
        method_identity_name(raw)?;
        if !function.dependencies.contains(&record.layout.name) {
            return Err(invalid("virtual source method does not depend on its exact projected record"));
        }
        functions.push(function.clone());
        methods.push(SourceVirtualMethod {
            virtual_slot_index,
            method_address: function.address,
            definition_id: raw.id,
            method,
            layout_name: &record.layout.name,
        });
    }
    if methods.is_empty() {
        return Ok(DebugLayoutVirtualEvidence::default());
    }
    let dependencies: BTreeSet<_> = functions.iter().flat_map(|function| function.dependencies.iter()).collect();
    let report = DebugLayoutReport {
        types: preview
            .report
            .types
            .iter()
            .filter(|record| dependencies.contains(&record.layout.name))
            .cloned()
            .collect(),
        functions,
        warnings: Vec::new(),
    };
    validate_report(&report)?;
    let (changes, _) = layout_changes(&report, &report.functions, &preview.image_sha256)?;
    let mut source = Annotations::in_memory();
    source.set_batch_validated(&changes, |_| Ok(())).map_err(ApiError::Invalid)?;
    if image_digest(project)? != preview.image_sha256 || specification_identity()? != preview.specifications {
        return Err(invalid("image or compiler context changed before virtual source validation"));
    }
    {
        let state = project.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&project.binary));
        if options != preview.options {
            return Err(invalid("compiler options changed before virtual source validation"));
        }
        project.check_layout_options(&options)?;
        check_backing(project)?;
        #[cfg(test)]
        SOURCE_VALIDATIONS.set(SOURCE_VALIDATIONS.get() + 1);
        let validation = project.validate_annotation_snapshot(&state, &options, &source);
        check_backing(project)?;
        validation.map_err(ApiError::Invalid)?;
    }
    let verified: Vec<_> = methods
        .into_iter()
        .map(|candidate| VerifiedVirtualMethod {
            virtual_slot_index: candidate.virtual_slot_index,
            method_address: candidate.method_address,
            definition_id: candidate.definition_id,
            record_id: candidate.method.record_id,
            declaration_id: candidate.method.declaration_id,
            object_pointer_id: candidate.method.object_pointer_id,
            linkage_name: candidate.method.linkage_name.clone(),
            layout_name: candidate.layout_name.to_owned(),
        })
        .collect();
    let evidence = collect_virtual_evidence(project, &verified)?;
    if image_digest(project)? != preview.image_sha256 || specification_identity()? != preview.specifications {
        return Err(invalid("image or compiler context changed during virtual source validation"));
    }
    Ok(evidence)
}
