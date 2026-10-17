use std::collections::BTreeSet;

use rampage_decompiler::results::{StructuredResult, TypeInfo, VariableKind};
use rampage_decompiler::worker::WorkerOperation;
use rampage_decompiler::{LocalOverride, VariableStorage};
use serde::{Deserialize, Serialize};

use crate::annotations::{
    Annotations, Field, LocalNameAnnotation, LocalTypeAnnotation, encode_local_names, encode_local_types,
    parse_local_names, parse_local_types,
};
use crate::{ApiError, Decompilation, EditResult, Project};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VariableEditRequest {
    pub variable: Option<String>,
    pub storage: Option<VariableStorage>,
    pub name: Option<String>,
    pub data_type: Option<String>,
    #[serde(default)]
    pub clear_name: bool,
    #[serde(default)]
    pub clear_type: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VariableDescriptor {
    pub name: String,
    pub data_type: TypeInfo,
    pub kind: VariableKind,
    /// Canonical complete storage JSON, stable across display-name changes within the same native mapping.
    pub key: Option<String>,
    pub storage: Option<VariableStorage>,
    pub editable: bool,
    pub unavailable_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VariableEditResult {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub storage: VariableStorage,
    pub edits: Vec<EditResult>,
    pub decompilation: Decompilation,
}

pub(crate) fn descriptors(structure: &StructuredResult) -> Vec<VariableDescriptor> {
    let mut descriptors: Vec<_> = structure
        .variables
        .iter()
        .map(|variable| {
            let storage = match variable.storage.as_slice() {
                [storage] => VariableStorage::try_from(storage).map_err(|error| error.to_string()),
                _ => Err("variable requires exactly one complete whole-symbol mapping".to_owned()),
            };
            let (storage, unavailable_reason) = match storage {
                Ok(storage) => (Some(storage), None),
                Err(reason) => (None, Some(reason)),
            };
            VariableDescriptor {
                name: variable.name.clone(),
                data_type: variable.data_type.clone(),
                kind: variable.kind,
                key: storage.as_ref().map(|storage| serde_json::to_string(storage).expect("storage JSON")),
                editable: storage.is_some(),
                storage,
                unavailable_reason,
            }
        })
        .collect();
    for index in 0..descriptors.len() {
        if descriptors[index].storage.is_some()
            && descriptors
                .iter()
                .enumerate()
                .any(|(other_index, other)| other_index != index && other.storage == descriptors[index].storage)
        {
            descriptors[index].editable = false;
            descriptors[index].unavailable_reason = Some("storage selector matches multiple variables".to_owned());
        }
    }
    descriptors
}

pub(crate) fn targets(annotations: &Annotations) -> BTreeSet<u64> {
    annotations.local_names().keys().chain(annotations.local_types().keys()).copied().collect()
}

pub(crate) fn plan(
    project: &Project,
    annotations: &Annotations,
    only_function: Option<u64>,
) -> Result<Vec<WorkerOperation>, ApiError> {
    let mut operations = Vec::new();
    for address in targets(annotations).into_iter().filter(|address| only_function.is_none_or(|only| only == *address))
    {
        if project.binary.code_from(address).is_none() {
            return Err(ApiError::Invalid("local override target is not file-backed code".to_owned()));
        }
        let names = local_names(annotations, address)?;
        let types = local_types(annotations, address)?;
        let mut overrides: Vec<_> = names
            .into_iter()
            .map(|entry| LocalOverride { storage: entry.storage, name: Some(entry.name), data_type: None })
            .collect();
        for entry in types {
            crate::decompile::validate_local_type(&entry.data_type)?;
            if let Some(existing) = overrides.iter_mut().find(|existing| existing.storage == entry.storage) {
                existing.data_type = Some(entry.data_type);
            } else {
                overrides.push(LocalOverride { storage: entry.storage, name: None, data_type: Some(entry.data_type) });
            }
        }
        operations.push(WorkerOperation::Symbol { address, name: project.function_name_in(annotations, address) });
        operations.push(WorkerOperation::LocalVariables { address, overrides });
    }
    Ok(operations)
}

fn local_names(annotations: &Annotations, address: u64) -> Result<Vec<LocalNameAnnotation>, ApiError> {
    annotations
        .local_names()
        .get(&address)
        .map(|text| parse_local_names(text))
        .transpose()
        .map(Option::unwrap_or_default)
        .map_err(ApiError::Invalid)
}

fn local_types(annotations: &Annotations, address: u64) -> Result<Vec<LocalTypeAnnotation>, ApiError> {
    annotations
        .local_types()
        .get(&address)
        .map(|text| parse_local_types(text))
        .transpose()
        .map(Option::unwrap_or_default)
        .map_err(ApiError::Invalid)
}

fn resolve<'a>(
    variables: &'a [VariableDescriptor],
    request: &VariableEditRequest,
) -> Result<&'a VariableStorage, ApiError> {
    let matches: Vec<_> = variables
        .iter()
        .filter(|variable| {
            request.variable.as_ref().is_some_and(|name| variable.name == *name)
                || request.storage.as_ref().is_some_and(|storage| variable.storage.as_ref() == Some(storage))
        })
        .collect();
    let [variable] = matches.as_slice() else {
        return Err(ApiError::Invalid(format!(
            "variable selector matched {} current variables; exactly one is required; inspect available variables",
            matches.len(),
        )));
    };
    if !variable.editable {
        return Err(ApiError::Invalid(
            variable
                .unavailable_reason
                .clone()
                .unwrap_or_else(|| "variable has no supported whole-symbol storage selector".to_owned()),
        ));
    }
    variable.storage.as_ref().ok_or_else(|| ApiError::Invalid("variable storage is unavailable".to_owned()))
}

fn validate_request(request: &VariableEditRequest) -> Result<(), ApiError> {
    if request.variable.is_some() == request.storage.is_some() {
        return Err(ApiError::Invalid("provide exactly one of variable or storage".to_owned()));
    }
    if request.variable.as_ref().is_some_and(|name| name.is_empty() || name.len() > 128) {
        return Err(ApiError::Invalid("variable selector requires a nonempty bounded display name".to_owned()));
    }
    if let Some(storage) = &request.storage {
        storage.validate().map_err(|error| ApiError::Invalid(error.to_string()))?;
    }
    if (request.name.is_some() && request.clear_name) || (request.data_type.is_some() && request.clear_type) {
        return Err(ApiError::Invalid("cannot set and clear the same variable field".to_owned()));
    }
    if request.name.is_none() && request.data_type.is_none() && !request.clear_name && !request.clear_type {
        return Err(ApiError::Invalid("provide a variable rename, retype, or clear operation".to_owned()));
    }
    if let Some(data_type) = &request.data_type {
        crate::decompile::validate_local_type(data_type)?;
    }
    Ok(())
}

impl Project {
    /// Resolves one current native variable and atomically publishes its storage-keyed edits with refreshed C.
    pub fn edit_variable(
        &self,
        function_address: u64,
        request: &VariableEditRequest,
    ) -> Result<VariableEditResult, ApiError> {
        self.edit_variable_with_preflight(function_address, request, |_| Ok(()))
    }

    /// Checks the complete prospective edit envelope, including refreshed C, before any durable annotation write.
    pub fn edit_variable_with_preflight(
        &self,
        function_address: u64,
        request: &VariableEditRequest,
        preflight: impl FnOnce(&VariableEditResult) -> Result<(), ApiError>,
    ) -> Result<VariableEditResult, ApiError> {
        validate_request(request)?;
        let address = self.function_containing(function_address)?.unwrap_or(function_address);
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        crate::decompile::validate_cached_layout_source(self, &state)?;
        let options = state.options.clone().unwrap_or_else(|| crate::decompile::default_options(&self.binary));
        let mut annotations = self.annotations.write().expect("annotations lock");
        annotations.locked_staged_checked(|annotations| {
            crate::debug_layout_import::validate_replay_source(self, annotations)?;
            let current = self.decompile_annotation_candidate(&state, &options, annotations, address)?;
            let address = current.address;
            let storage = resolve(&current.variables, request)?.clone();
            if let Some(name) = &request.name
                && current
                    .variables
                    .iter()
                    .any(|variable| variable.name == *name && variable.storage.as_ref() != Some(&storage))
            {
                return Err(ApiError::Invalid("local name is already used by another current variable".to_owned()));
            }
            let mut changes = Vec::new();
            if request.name.is_some() || request.clear_name {
                let mut entries = local_names(annotations, address)?;
                entries.retain(|entry| entry.storage != storage);
                if let Some(name) = &request.name {
                    entries.push(LocalNameAnnotation { storage: storage.clone(), name: name.clone() });
                }
                let value = (!entries.is_empty())
                    .then(|| encode_local_names(&entries))
                    .transpose()
                    .map_err(ApiError::Invalid)?;
                changes.push((Field::LocalName, address, value));
            }
            if request.data_type.is_some() || request.clear_type {
                let mut entries = local_types(annotations, address)?;
                entries.retain(|entry| entry.storage != storage);
                if let Some(data_type) = &request.data_type {
                    entries.push(LocalTypeAnnotation { storage: storage.clone(), data_type: data_type.clone() });
                }
                let value = (!entries.is_empty())
                    .then(|| encode_local_types(&entries))
                    .transpose()
                    .map_err(ApiError::Invalid)?;
                changes.push((Field::LocalType, address, value));
            }
            let mut prospective_edits = Some(
                changes
                    .iter()
                    .map(|(field, address, value)| {
                        let previous = match field {
                            Field::LocalName => annotations.local_names().get(address),
                            Field::LocalType => annotations.local_types().get(address),
                            _ => unreachable!("variable edits only change local collection fields"),
                        };
                        EditResult {
                            address: *address,
                            field: *field,
                            value: value.clone(),
                            changed: previous != value.as_ref(),
                        }
                    })
                    .collect::<Vec<_>>(),
            );
            let mut refreshed = None;
            let mut preflight = Some(preflight);
            let changed = annotations
                .set_batch_validated(&changes, |candidate| {
                    let decompilation = self
                        .decompile_annotation_candidate(&state, &options, candidate, address)
                        .map_err(|error| error.to_string())?;
                    for other in targets(candidate).into_iter().filter(|other| *other != address) {
                        self.decompile_annotation_candidate(&state, &options, candidate, other)
                            .map_err(|error| error.to_string())?;
                    }
                    let result = VariableEditResult {
                        address,
                        storage: storage.clone(),
                        edits: prospective_edits.take().expect("single candidate edit result"),
                        decompilation,
                    };
                    preflight.take().expect("single response preflight")(&result).map_err(|error| error.to_string())?;
                    refreshed = Some(result);
                    Ok(())
                })
                .map_err(ApiError::Invalid)?;
            let mut result = refreshed.unwrap_or_else(|| VariableEditResult {
                address,
                storage,
                edits: prospective_edits.take().expect("unchanged candidate edit result"),
                decompilation: current,
            });
            for (edit, changed) in result.edits.iter_mut().zip(changed) {
                edit.changed = changed;
            }
            if let Some(preflight) = preflight {
                preflight(&result)?;
            }
            Ok(result)
        })
    }
}

#[cfg(test)]
#[path = "variables_tests.rs"]
mod tests;
