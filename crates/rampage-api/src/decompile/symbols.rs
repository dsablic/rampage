use std::collections::BTreeMap;

use rampage_analysis::functions::{stub_names, thunk_names};
use rampage_decompiler::Decompiler;
use rampage_decompiler::worker::WorkerOperation;
use rampage_loaders::SymbolKind;

use crate::{ApiError, Project, annotations::Annotations};

fn canonical(name: &str) -> &str {
    name.strip_suffix("@plt").or_else(|| name.strip_suffix("@got")).unwrap_or(name)
}

fn failure(address: u64, operation: &str, error: impl std::fmt::Display) -> ApiError {
    ApiError::Unavailable(format!("{operation} at {address:#x}: {error}"))
}

pub(super) fn plan(project: &Project, annotations: &Annotations) -> Result<Vec<WorkerOperation>, ApiError> {
    let mut operations = Vec::new();
    let binary = &project.binary;
    let stubs: BTreeMap<_, _> = stub_names(binary).into_iter().chain(thunk_names(binary)).collect();
    let mut identities: BTreeMap<_, _> = project
        .analysis()?
        .program
        .functions
        .iter()
        .map(|function| {
            let identity = binary
                .symbols
                .iter()
                .find(|symbol| symbol.address == function.address && symbol.kind == SymbolKind::Function)
                .map(|symbol| symbol.name.clone())
                .or_else(|| stubs.get(&function.address).cloned())
                .or_else(|| {
                    binary
                        .exports
                        .iter()
                        .find(|export| export.address == function.address)
                        .map(|export| export.name.clone())
                })
                .unwrap_or_default();
            (function.address, identity)
        })
        .collect();
    identities.extend(stubs.iter().map(|(&address, name)| (address, name.clone())));
    for (&address, identity) in &identities {
        let display = project.function_name_in(annotations, address);
        operations.push(WorkerOperation::Symbol { address, name: display });
        if !identity.is_empty() {
            operations.push(WorkerOperation::RuntimePrototype {
                address,
                indirect: false,
                name: canonical(identity).to_owned(),
                optional: true,
            });
        }
    }
    for slot in &binary.import_slots {
        let display = annotations.name(slot.address).unwrap_or(&slot.name).to_owned();
        operations.push(WorkerOperation::Import { slot: slot.address, target: None, name: display });
        operations.push(WorkerOperation::RuntimePrototype {
            address: slot.address,
            indirect: true,
            name: canonical(&slot.name).to_owned(),
            optional: true,
        });
    }
    // Listed and inferred noreturn callees, so decompiled callers stop at calls to them as discovery does.
    let slots: std::collections::BTreeSet<_> = binary.import_slots.iter().map(|slot| slot.address).collect();
    for &address in &project.analysis()?.program.noreturn {
        let indirect = slots.contains(&address);
        if indirect || identities.contains_key(&address) {
            operations.push(WorkerOperation::NoReturn { address, indirect });
        }
    }
    Ok(operations)
}

pub(super) fn apply(operations: Vec<WorkerOperation>, engine: &mut Decompiler) -> Result<(), ApiError> {
    for operation in operations {
        match operation {
            WorkerOperation::Symbol { address, name } => {
                engine.set_symbol(address, &name).map_err(|error| failure(address, "register symbol", error))?
            }
            WorkerOperation::Import { slot, target, name } => {
                engine.add_import(slot, target, &name).map_err(|error| failure(slot, "register import", error))?
            }
            WorkerOperation::RuntimePrototype { address, indirect, name, .. } => {
                if let Some(prototype) = engine.c_prototype(&name) {
                    engine
                        .apply_prototype(address, indirect, &prototype)
                        .map_err(|error| failure(address, "apply runtime prototype", error))?;
                }
            }
            WorkerOperation::ParseTypes { declarations } => {
                engine.parse_c(&declarations).map_err(|error| ApiError::Invalid(error.to_string()))?
            }
            WorkerOperation::Global { address, declaration } => {
                engine.add_global(address, &declaration).map_err(|error| failure(address, "apply global", error))?
            }
            WorkerOperation::Prototype { address, indirect, declaration } => engine
                .apply_prototype(address, indirect, &declaration)
                .map_err(|error| failure(address, "apply signature", error))?,
            WorkerOperation::NoReturn { address, indirect } => {
                engine.set_noreturn(address, indirect).map_err(|error| failure(address, "mark noreturn", error))?
            }
            WorkerOperation::Mode { .. } => unreachable!(),
        }
    }
    Ok(())
}

pub(super) fn stub_targets(project: &Project, slot: u64) -> Vec<u64> {
    let binary = &project.binary;
    let mut result = Vec::new();
    for (start, _) in stub_names(binary).into_iter().chain(thunk_names(binary)) {
        let Ok(mut decoder) = binary.decoder() else { break };
        let mut at = start;
        for _ in 0..8 {
            let Some(bytes) = binary.code_from(at) else { break };
            let instruction = decoder.decode(bytes, at);
            if instruction.data_ref == Some(slot) {
                result.push(start);
                break;
            }
            if instruction.len == 0
                || matches!(
                    instruction.flow,
                    rampage_arch::Flow::Return
                        | rampage_arch::Flow::Halt
                        | rampage_arch::Flow::Invalid
                        | rampage_arch::Flow::IndirectJump
                        | rampage_arch::Flow::Jump(_)
                )
            {
                break;
            }
            at += u64::from(instruction.len);
        }
    }
    result
}
