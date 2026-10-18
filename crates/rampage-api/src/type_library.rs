use std::collections::BTreeSet;

use rampage_decompiler::worker::TypeQuery;
use rampage_decompiler::{DataOrganization, DecompilerOptions, NamedType};
use serde::{Deserialize, Serialize};

use crate::annotations::{
    Annotations, Field, LibraryDeclaration, TypeLibrarySource, encode_type_library, parse_type_library,
};
use crate::decompile::{DecompilerState, default_options};
use crate::type_headers::{HeaderBundle, bundled_headers, prepare_header, validate_header_profile};
use crate::{ApiError, Project};

const MAX_DECLARATIONS: usize = 256;
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_NATIVE_PROBES: usize = 512;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclareTypesRequest {
    pub declarations: Option<String>,
    pub header: Option<String>,
    #[serde(default)]
    pub profiles: Vec<String>,
    pub packing: Option<u32>,
    #[serde(default)]
    pub replace: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypeLibraryEntry {
    /// Layout, names and dependency edges come from the selected native type factory.
    #[serde(flatten)]
    pub metadata: NamedType,
    /// `library`, `profile`, or `native` (legacy/generated/builtin, read-only).
    pub scope: String,
    /// A definition group is the smallest replaceable/removable unit.
    pub declaration: Option<LibraryDeclaration>,
}

#[derive(Debug, Serialize)]
pub struct TypeLibraryPage {
    pub types: Vec<TypeLibraryEntry>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub next_offset: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct TypeLibraryEdit {
    pub changed: bool,
    pub types: Vec<TypeLibraryEntry>,
    pub removed: Vec<String>,
    pub warnings: Vec<String>,
    pub profiles: Vec<HeaderBundle>,
}

pub(crate) struct NativeInspection {
    pub(crate) language_id: String,
    pub(crate) organization: DataOrganization,
    pub(crate) types: Vec<NamedType>,
    pub(crate) declarations: Vec<Vec<NamedType>>,
}

struct PreparedUnit {
    declarations: String,
    packing: Option<u32>,
    source: Option<TypeLibrarySource>,
}

struct LibraryCommit<'a> {
    units: &'a [LibraryDeclaration],
    expected: &'a [NamedType],
    removed: &'a [String],
    result: TypeLibraryEdit,
}

pub(crate) fn stored_declarations(annotations: &Annotations) -> Result<Vec<LibraryDeclaration>, ApiError> {
    match annotations.type_library().get(&0) {
        Some(text) => parse_type_library(text).map_err(ApiError::Invalid),
        None => Ok(Vec::new()),
    }
}

pub(crate) fn library_value(units: &[LibraryDeclaration]) -> Result<Option<String>, ApiError> {
    if units.len() > MAX_DECLARATIONS
        || units.iter().map(|unit| unit.declarations.len()).sum::<usize>() > MAX_TEXT_BYTES
    {
        return Err(ApiError::Invalid("project library exceeds 256 units or 64 KiB of declarations".to_owned()));
    }
    if units.is_empty() { Ok(None) } else { encode_type_library(units).map(Some).map_err(ApiError::Invalid) }
}

pub(crate) fn validate_profile_replay(
    annotations: &Annotations,
    options: &DecompilerOptions,
    organization: DataOrganization,
    language_id: &str,
) -> Result<(), ApiError> {
    let compiler = language_id.rsplit(':').next().unwrap_or_default();
    let mut profiles = BTreeSet::new();
    for unit in stored_declarations(annotations)? {
        if let Some(source) = unit.source
            && source.kind == "profile"
            && profiles.insert(source.identity.clone())
        {
            validate_header_profile(&source.identity, options.platform, compiler, organization)?;
        }
    }
    Ok(())
}

fn library_annotations(units: &[LibraryDeclaration]) -> Result<Annotations, ApiError> {
    let mut annotations = Annotations::in_memory();
    // These snapshots measure declaration text only. The actual retained snapshot is separately
    // checked with its proof before measurement and again before commit; text carries no proof claim.
    let mut units = units.to_vec();
    for unit in &mut units {
        if unit.source.as_ref().is_some_and(|source| source.kind == "checked_debug_types") {
            unit.source = None;
        }
    }
    annotations.set(Field::TypeLibrary, 0, library_value(&units)?).map_err(ApiError::Invalid)?;
    Ok(annotations)
}

fn entry(metadata: NamedType, units: &[LibraryDeclaration]) -> TypeLibraryEntry {
    let declaration = units.iter().find(|unit| unit.names.contains(&metadata.name)).cloned();
    let scope = match declaration.as_ref().and_then(|unit| unit.source.as_ref()) {
        Some(source) if source.kind == "profile" => "profile",
        _ if declaration.is_some() => "library",
        _ => "native",
    };
    TypeLibraryEntry { metadata, scope: scope.to_owned(), declaration }
}

fn validate_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
        return Err(ApiError::Invalid("type name requires 1..=256 bytes without controls".to_owned()));
    }
    Ok(())
}

fn validate_request(request: &DeclareTypesRequest) -> Result<(), ApiError> {
    if request.declarations.is_none() && request.header.is_none() && request.profiles.is_empty() {
        return Err(ApiError::Invalid("provide declarations, an inline header, or explicit profiles".to_owned()));
    }
    if request.profiles.len() > MAX_DECLARATIONS
        || request.profiles.iter().any(|profile| profile.len() > 32)
        || request.packing.is_some_and(|packing| !matches!(packing, 1 | 2 | 4 | 8 | 16))
    {
        return Err(ApiError::Invalid("invalid profile count/name or packing (expected 1, 2, 4, 8 or 16)".to_owned()));
    }
    let mut bytes = 0usize;
    for text in [&request.declarations, &request.header].into_iter().flatten() {
        bytes = bytes.saturating_add(text.len());
        if text.trim().is_empty() || bytes > MAX_TEXT_BYTES || text.contains('\0') {
            return Err(ApiError::Invalid(
                "type input requires nonempty text totaling at most 64 KiB without NUL".into(),
            ));
        }
    }
    if let Some(text) = &request.declarations {
        if text.contains('#') {
            return Err(ApiError::Invalid("use header for bounded include/packing directives".to_owned()));
        }
        prepare_header(text)?;
    }
    if let Some(text) = &request.header {
        prepare_header(text)?;
    }
    Ok(())
}

fn prepare_units(
    request: &DeclareTypesRequest,
    options: &DecompilerOptions,
    native: &NativeInspection,
) -> Result<(Vec<PreparedUnit>, Vec<HeaderBundle>), ApiError> {
    let header = request.header.as_deref().map(prepare_header).transpose()?;
    let mut profiles = request.profiles.clone();
    if let Some(header) = &header {
        profiles.extend(header.profiles.iter().cloned());
    }
    let mut seen = BTreeSet::new();
    profiles.retain(|profile| seen.insert(profile.clone()));
    let mut units = Vec::new();
    let mut bundles = Vec::new();
    for profile in profiles {
        let compiler = native.language_id.rsplit(':').next().unwrap_or_default();
        validate_header_profile(&profile, options.platform, compiler, native.organization)?;
        let bundle = bundled_headers(&profile, native.organization)?;
        for declaration in prepare_header(&bundle.declarations)?.declarations {
            units.push(PreparedUnit {
                declarations: declaration.declarations,
                packing: declaration.packing,
                source: Some(TypeLibrarySource { kind: "profile".to_owned(), identity: profile.clone() }),
            });
        }
        bundles.push(bundle);
    }
    if let Some(declarations) = &request.declarations {
        for declaration in prepare_header(declarations)?.declarations {
            units.push(PreparedUnit { declarations: declaration.declarations, packing: request.packing, source: None });
        }
    }
    if let Some(header) = header {
        for declaration in header.declarations {
            units.push(PreparedUnit {
                declarations: declaration.declarations,
                packing: declaration.packing.or(request.packing),
                source: Some(TypeLibrarySource { kind: "header".to_owned(), identity: "inline".to_owned() }),
            });
        }
    }
    let bytes = units.iter().map(|unit| unit.declarations.len()).sum::<usize>();
    if units.is_empty() || units.len() > MAX_DECLARATIONS || bytes > MAX_TEXT_BYTES {
        return Err(ApiError::Invalid("prepared types exceed 256 declaration units or 64 KiB".to_owned()));
    }
    Ok((units, bundles))
}

impl Project {
    pub(crate) fn inspect_types(
        &self,
        state: &DecompilerState,
        options: &DecompilerOptions,
        annotations: &Annotations,
        name: Option<&str>,
        declarations: &[(String, Option<u32>)],
    ) -> Result<NativeInspection, ApiError> {
        crate::decompile::validate_cached_layout_source(self, state)?;
        crate::debug_layout_import::validate_replay_source(self, annotations)?;
        crate::debug_type_import::validate_replay_source(self, annotations)?;
        crate::debug_type_import::validate_options(annotations, options)?;
        if !self.binary.segments.iter().any(|segment| segment.perms.execute && segment.file_size > 0) {
            return Err(ApiError::Unavailable("no executable segments to decompile".to_owned()));
        }
        if let Some(config) = &state.worker {
            let query = match name {
                Some(name) => TypeQuery::Get { name: name.to_owned() },
                None => TypeQuery::Inventory,
            };
            let output =
                crate::decompile::isolated_type_query(self, annotations, options, config, query, declarations)?;
            let roots = if declarations.is_empty() {
                Vec::new()
            } else {
                worker_declaration_roots(&output, declarations.len())?
            };
            return Ok(NativeInspection {
                language_id: output.language_id,
                organization: DataOrganization {
                    pointer: output.data_organization.pointer,
                    int: output.data_organization.int,
                    long: output.data_organization.long,
                },
                types: output
                    .type_inventory
                    .ok_or_else(|| ApiError::Unavailable("worker omitted native type inventory".to_owned()))?,
                declarations: roots,
            });
        }
        let mut engine = self.build_decompiler(options, annotations)?;
        let mut roots = Vec::new();
        for (text, packing) in declarations {
            roots
                .push(engine.parse_type_library(text, *packing).map_err(|error| ApiError::Invalid(error.to_string()))?);
        }
        let types = match name {
            Some(name) => vec![engine.get_type(name).map_err(|error| ApiError::NotFound(error.to_string()))?],
            None => engine.type_inventory().map_err(|error| ApiError::Invalid(error.to_string()))?,
        };
        crate::debug_layout_import::validate_replay_source(self, annotations)?;
        crate::debug_type_import::validate_replay_source(self, annotations)?;
        Ok(NativeInspection {
            language_id: engine.language_id().to_owned(),
            organization: engine.data_organization(),
            types,
            declarations: roots,
        })
    }

    /// Lists only project-library and explicitly selected bundled-profile types, using native layouts.
    pub fn list_types(&self, contains: Option<&str>, offset: usize, limit: usize) -> Result<TypeLibraryPage, ApiError> {
        if limit == 0 || limit > MAX_DECLARATIONS || contains.is_some_and(|text| text.len() > 256) {
            return Err(ApiError::Invalid("type page limit must be 1..=256; filter is at most 256 bytes".to_owned()));
        }
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| default_options(&self.binary));
        let annotations = self.annotations.read().expect("annotations lock").checked_read_snapshot()?;
        {
            let units = stored_declarations(&annotations)?;
            let native = self.inspect_types(&state, &options, &annotations, None, &[])?;
            let mut types: Vec<_> = native
                .types
                .into_iter()
                .filter(|ty| {
                    units.iter().any(|unit| unit.names.contains(&ty.name))
                        && contains.is_none_or(|text| ty.name.contains(text))
                })
                .collect();
            types.sort_by(|left, right| left.name.cmp(&right.name));
            let total = types.len();
            let types: Vec<_> = types.into_iter().skip(offset).take(limit).map(|ty| entry(ty, &units)).collect();
            let end = offset.saturating_add(types.len());
            Ok(TypeLibraryPage { types, total, offset, limit, next_offset: (end < total).then_some(end) })
        }
    }

    /// Inspects a native named type; non-library types are read-only and have no declaration unit.
    pub fn get_type(&self, name: &str) -> Result<TypeLibraryEntry, ApiError> {
        validate_name(name)?;
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| default_options(&self.binary));
        let annotations = self.annotations.read().expect("annotations lock").checked_read_snapshot()?;
        {
            let units = stored_declarations(&annotations)?;
            let native = self.inspect_types(&state, &options, &annotations, Some(name), &[])?;
            let ty = native
                .types
                .into_iter()
                .find(|ty| ty.name == name)
                .ok_or_else(|| ApiError::NotFound(format!("no native type named {name:?}")))?;
            Ok(entry(ty, &units))
        }
    }

    pub fn declare_types(&self, request: &DeclareTypesRequest) -> Result<TypeLibraryEdit, ApiError> {
        self.declare_types_with_preflight(request, |_| Ok(()))
    }

    /// Preflights the complete prospective response before publishing annotations, cache or history.
    pub fn declare_types_with_preflight(
        &self,
        request: &DeclareTypesRequest,
        preflight: impl FnOnce(&TypeLibraryEdit) -> Result<(), ApiError>,
    ) -> Result<TypeLibraryEdit, ApiError> {
        validate_request(request)?;
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| default_options(&self.binary));
        let mut annotations = self.annotations.write().expect("annotations lock");
        annotations.locked_staged_checked(|annotations| {
            let current = self.inspect_types(&state, &options, annotations, None, &[])?;
            let (prepared, profiles) = prepare_units(request, &options, &current)?;
            let original = stored_declarations(annotations)?;
            let mut units = original.clone();
            let mut touched = BTreeSet::new();
            let mut probes = 0;
            for unit in prepared {
                if let Some(existing) = units.iter().find(|existing| {
                    existing.packing == unit.packing
                        && (tokens_equal(&existing.declarations, &unit.declarations)
                            || prepare_header(&existing.declarations).is_ok_and(|header| {
                                header
                                    .declarations
                                    .iter()
                                    .any(|statement| tokens_equal(&statement.declarations, &unit.declarations))
                            }))
                }) {
                    touched.extend(existing.names.iter().cloned());
                    continue;
                }
                if let Some((start, declaration)) =
                    self.complete_forward_unit(&state, &options, &units, &unit, &mut probes)?
                {
                    touched.extend(declaration.names.iter().cloned());
                    units.truncate(start);
                    units.push(declaration);
                    library_value(&units)?;
                    continue;
                }
                let (index, names) =
                    self.discover_unit(&state, &options, &units, &unit, request.replace, &mut probes)?;
                touched.extend(names.iter().cloned());
                let declaration = LibraryDeclaration {
                    names,
                    declarations: unit.declarations,
                    packing: unit.packing,
                    source: unit.source,
                };
                if let Some(index) = index {
                    units[index] = declaration;
                } else {
                    units.push(declaration);
                }
                library_value(&units)?;
            }
            let expected = self.inspect_types(&state, &options, &library_annotations(&units)?, None, &[])?;
            let result = TypeLibraryEdit {
                changed: original != units,
                types: expected
                    .types
                    .iter()
                    .filter(|ty| touched.contains(&ty.name))
                    .cloned()
                    .map(|ty| entry(ty, &units))
                    .collect(),
                removed: Vec::new(),
                warnings: definition_warnings(&units, &touched),
                profiles,
            };
            self.commit_type_library(
                &state,
                &options,
                annotations,
                LibraryCommit { units: &units, expected: &expected.types, removed: &[], result },
                preflight,
            )
        })
    }

    fn discover_unit(
        &self,
        state: &DecompilerState,
        options: &DecompilerOptions,
        units: &[LibraryDeclaration],
        input: &PreparedUnit,
        replace: bool,
        probes: &mut usize,
    ) -> Result<(Option<usize>, Vec<String>), ApiError> {
        let mut probe = |excluded: Option<usize>| -> Result<Vec<String>, ApiError> {
            *probes += 1;
            if *probes > MAX_NATIVE_PROBES {
                return Err(ApiError::Invalid("type-library native validation budget exceeded".to_owned()));
            }
            let retained = match excluded {
                Some(index) => units[..index].to_vec(),
                None => units.to_vec(),
            };
            let annotations = library_annotations(&retained)?;
            let before = self.inspect_types(state, options, &annotations, None, &[])?;
            let after =
                self.inspect_types(state, options, &annotations, None, &[(input.declarations.clone(), input.packing)])?;
            let roots = after
                .declarations
                .first()
                .ok_or_else(|| ApiError::Unavailable("native parser omitted declared type roots".to_owned()))?;
            let mut names: BTreeSet<_> = roots.iter().map(|ty| ty.name.clone()).collect();
            for ty in &after.types {
                if !before.types.iter().any(|prior| prior.name == ty.name) {
                    names.insert(ty.name.clone());
                }
            }
            for prior in &before.types {
                if excluded.is_some_and(|index| units[index].names.contains(&prior.name)) {
                    continue;
                }
                if after.types.iter().find(|ty| ty.name == prior.name) != Some(prior) {
                    return Err(ApiError::Invalid(format!("declaration changes existing type {:?}", prior.name)));
                }
            }
            if names.is_empty() || names.len() > MAX_DECLARATIONS {
                return Err(ApiError::Invalid("native declaration unit has no bounded named definitions".to_owned()));
            }
            Ok(names.into_iter().collect())
        };
        match probe(None) {
            Ok(names) => {
                if units.iter().any(|unit| unit.names.iter().any(|name| names.contains(name))) {
                    return Err(ApiError::Invalid("type name already belongs to the library; use replace".to_owned()));
                }
                return Ok((None, names));
            }
            Err(error @ ApiError::Unavailable(_)) => return Err(error),
            Err(error) if !replace => return Err(error),
            Err(_) => {}
        }
        for (index, unit) in units.iter().enumerate() {
            match probe(Some(index)) {
                Ok(names) if unit.names.iter().all(|name| names.contains(name)) => {
                    return Ok((Some(index), names));
                }
                Err(error @ ApiError::Unavailable(_)) => return Err(error),
                _ => {}
            }
        }
        Err(ApiError::Invalid(
            "replacement must redefine one complete library definition group without dropping its other names".into(),
        ))
    }

    fn complete_forward_unit(
        &self,
        state: &DecompilerState,
        options: &DecompilerOptions,
        units: &[LibraryDeclaration],
        input: &PreparedUnit,
        probes: &mut usize,
    ) -> Result<Option<(usize, LibraryDeclaration)>, ApiError> {
        let Some(tag) = definition_tag(&input.declarations) else {
            return Ok(None);
        };
        let Some(start) = units.iter().position(|unit| unit.names.iter().any(|name| name == tag)) else {
            return Ok(None);
        };
        *probes += 1;
        if *probes > MAX_NATIVE_PROBES {
            return Err(ApiError::Invalid("type-library native validation budget exceeded".to_owned()));
        }
        let current = self.inspect_types(state, options, &library_annotations(units)?, None, &[])?;
        if !current.types.iter().any(|ty| ty.name == tag && ty.incomplete) {
            return Ok(None);
        }
        let group = &units[start..];
        if group.iter().any(|unit| unit.packing != input.packing) {
            return Err(ApiError::Invalid(
                "forward completion crosses incompatible packing contexts; no declaration group was changed".into(),
            ));
        }
        let mut declarations = String::new();
        for unit in group {
            declarations.push_str(&unit.declarations);
            declarations.push('\n');
        }
        declarations.push_str(&input.declarations);
        if declarations.len() > MAX_TEXT_BYTES {
            return Err(ApiError::Invalid("completed declaration group exceeds 64 KiB".to_owned()));
        }
        let prefix = library_annotations(&units[..start])?;
        let before = self.inspect_types(state, options, &prefix, None, &[])?;
        let completed = self.inspect_types(state, options, &prefix, None, &[(declarations.clone(), input.packing)])?;
        let actual = completed
            .types
            .iter()
            .find(|ty| ty.name == tag)
            .ok_or_else(|| ApiError::Invalid("native completion did not retain the forward type".to_owned()))?;
        if actual.incomplete {
            return Err(ApiError::Invalid("native parser did not complete the forward type".to_owned()));
        }
        for previous in &current.types {
            let actual = completed
                .types
                .iter()
                .find(|ty| ty.name == previous.name)
                .ok_or_else(|| ApiError::Invalid(format!("forward completion dropped type {:?}", previous.name)))?;
            if actual != previous && !(previous.incomplete && !actual.incomplete && previous.kind == actual.kind) {
                return Err(ApiError::Invalid(format!(
                    "forward completion changes unrelated existing type {:?}",
                    previous.name,
                )));
            }
        }
        let roots = completed
            .declarations
            .first()
            .ok_or_else(|| ApiError::Unavailable("native parser omitted completed declaration roots".to_owned()))?;
        let mut names: BTreeSet<_> = roots.iter().map(|ty| ty.name.clone()).collect();
        for ty in &completed.types {
            if !before.types.iter().any(|previous| previous.name == ty.name) {
                names.insert(ty.name.clone());
            }
        }
        if !group.iter().flat_map(|unit| &unit.names).all(|name| names.contains(name)) {
            return Err(ApiError::Invalid("forward completion lost a sibling definition".to_owned()));
        }
        let source = if group.iter().all(|unit| unit.source == input.source) { input.source.clone() } else { None };
        Ok(Some((
            start,
            LibraryDeclaration { names: names.into_iter().collect(), declarations, packing: input.packing, source },
        )))
    }

    pub fn delete_type(&self, name: &str) -> Result<TypeLibraryEdit, ApiError> {
        self.delete_type_with_preflight(name, |_| Ok(()))
    }

    pub fn delete_type_with_preflight(
        &self,
        name: &str,
        preflight: impl FnOnce(&TypeLibraryEdit) -> Result<(), ApiError>,
    ) -> Result<TypeLibraryEdit, ApiError> {
        self.delete_type_transaction(name, false, preflight)
    }

    /// Explicitly removes the complete declaration group, still refusing dependencies outside that group.
    pub fn delete_type_group_with_preflight(
        &self,
        name: &str,
        preflight: impl FnOnce(&TypeLibraryEdit) -> Result<(), ApiError>,
    ) -> Result<TypeLibraryEdit, ApiError> {
        self.delete_type_transaction(name, true, preflight)
    }

    fn delete_type_transaction(
        &self,
        name: &str,
        definition_group: bool,
        preflight: impl FnOnce(&TypeLibraryEdit) -> Result<(), ApiError>,
    ) -> Result<TypeLibraryEdit, ApiError> {
        validate_name(name)?;
        let state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        let options = state.options.clone().unwrap_or_else(|| default_options(&self.binary));
        let mut annotations = self.annotations.write().expect("annotations lock");
        annotations.locked_staged_checked(|annotations| {
            let mut units = stored_declarations(annotations)?;
            let index = units
                .iter()
                .position(|unit| unit.names.iter().any(|candidate| candidate == name))
                .ok_or_else(|| ApiError::NotFound(format!("no library declaration defines {name:?}")))?;
            if units[index].names.len() != 1 && !definition_group {
                return Err(ApiError::Invalid(format!(
                    "type belongs to a multi-name definition group {:?}; explicitly remove the definition group",
                    units[index].names,
                )));
            }
            let removed = units.remove(index).names;
            let current = self.inspect_types(&state, &options, annotations, None, &[])?;
            reject_dependencies(&current.types, &removed)?;
            let expected = self.inspect_types(&state, &options, &library_annotations(&units)?, None, &[])?;
            let result = TypeLibraryEdit {
                changed: true,
                types: Vec::new(),
                removed: removed.clone(),
                warnings: if removed.len() > 1 {
                    vec!["explicitly removing one complete definition group; removed lists every name".to_owned()]
                } else {
                    Vec::new()
                },
                profiles: Vec::new(),
            };
            self.commit_type_library(
                &state,
                &options,
                annotations,
                LibraryCommit { units: &units, expected: &expected.types, removed: &removed, result },
                preflight,
            )
        })
    }

    fn commit_type_library(
        &self,
        state: &DecompilerState,
        options: &DecompilerOptions,
        annotations: &mut Annotations,
        pending: LibraryCommit<'_>,
        preflight: impl FnOnce(&TypeLibraryEdit) -> Result<(), ApiError>,
    ) -> Result<TypeLibraryEdit, ApiError> {
        let LibraryCommit { units, expected, removed, mut result } = pending;
        let value = library_value(units)?;
        let proofs = crate::debug_type_import::library_transition_proofs(annotations, units)?;
        if annotations.type_library().get(&0) == value.as_ref() {
            result.changed = false;
            preflight(&result)?;
            return Ok(result);
        }
        let mut preflight = Some(preflight);
        let changed = annotations
            .set_batch_validated(&[(Field::TypeLibrary, 0, value), (Field::DebugTypes, 0, proofs)], |candidate| {
                self.validate_annotation_snapshot(state, options, candidate)?;
                let actual =
                    self.inspect_types(state, options, candidate, None, &[]).map_err(|error| error.to_string())?;
                for expected in expected {
                    if units.iter().any(|unit| unit.names.contains(&expected.name))
                        && actual.types.iter().find(|ty| ty.name == expected.name) != Some(expected)
                    {
                        return Err(format!("annotation replay conflicts with library type {:?}", expected.name));
                    }
                }
                if actual.types.iter().any(|ty| removed.contains(&ty.name)) {
                    return Err(
                        "dependent annotations recreate a removed type, possibly as an incomplete forward".into()
                    );
                }
                reject_dependencies(&actual.types, removed).map_err(|error| error.to_string())?;
                preflight.take().expect("single type-library response preflight")(&result)
                    .map_err(|error| error.to_string())
            })
            .map_err(ApiError::Invalid)?;
        result.changed = changed.into_iter().any(|changed| changed);
        Ok(result)
    }

    pub(crate) fn validate_type_library_snapshot(
        &self,
        state: &DecompilerState,
        options: &DecompilerOptions,
        annotations: &Annotations,
    ) -> Result<(), ApiError> {
        let units = stored_declarations(annotations)?;
        if units.is_empty() {
            return Ok(());
        }
        let expected = self.inspect_types(state, options, &library_annotations(&units)?, None, &[])?;
        let actual = self.inspect_types(state, options, annotations, None, &[])?;
        let owned: BTreeSet<_> = units.iter().flat_map(|unit| unit.names.iter().cloned()).collect();
        for name in &owned {
            if !expected.types.iter().any(|ty| &ty.name == name) {
                return Err(ApiError::Invalid(format!("stored type unit no longer defines {name:?}")));
            }
        }
        for ty in &expected.types {
            if ty.incomplete && !owned.contains(&ty.name) {
                return Err(ApiError::Invalid(format!(
                    "library replay recreated an unowned incomplete dependency {:?}",
                    ty.name,
                )));
            }
        }
        for expected in expected.types {
            if units.iter().any(|unit| unit.names.contains(&expected.name))
                && actual.types.iter().find(|ty| ty.name == expected.name) != Some(&expected)
            {
                return Err(ApiError::Invalid(format!(
                    "annotation replay conflicts with library type {:?}",
                    expected.name,
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_type_library_transition(
        &self,
        state: &DecompilerState,
        options: &DecompilerOptions,
        previous: &[LibraryDeclaration],
        candidate: &Annotations,
    ) -> Result<(), ApiError> {
        let next = stored_declarations(candidate)?;
        let removed: Vec<_> = previous
            .iter()
            .flat_map(|unit| &unit.names)
            .filter(|name| !next.iter().any(|unit| unit.names.contains(name)))
            .cloned()
            .collect();
        if removed.is_empty() {
            return Ok(());
        }
        let actual = self.inspect_types(state, options, candidate, None, &[])?;
        reject_dependencies(&actual.types, &removed)?;
        if actual.types.iter().any(|ty| removed.contains(&ty.name)) {
            return Err(ApiError::Invalid(
                "dependent annotations recreate a removed library type; history was not changed".to_owned(),
            ));
        }
        Ok(())
    }
}

fn reject_dependencies(types: &[NamedType], removed: &[String]) -> Result<(), ApiError> {
    for ty in types.iter().filter(|ty| !removed.contains(&ty.name)) {
        if let Some(dependency) = ty.dependencies.iter().find(|dependency| removed.contains(dependency)) {
            return Err(ApiError::Invalid(format!(
                "type {:?} still depends on {dependency:?}; no cascade applied",
                ty.name
            )));
        }
    }
    Ok(())
}

fn definition_warnings(units: &[LibraryDeclaration], touched: &BTreeSet<String>) -> Vec<String> {
    units
        .iter()
        .filter(|unit| unit.names.len() > 1 && unit.names.iter().any(|name| touched.contains(name)))
        .map(|unit| format!("names {:?} share one atomic definition group; individual deletion is refused", unit.names))
        .collect()
}

fn tokens_equal(left: &str, right: &str) -> bool {
    crate::decompile::type_tokens(left).eq(crate::decompile::type_tokens(right))
}

fn definition_tag(text: &str) -> Option<&str> {
    let mut tokens = crate::decompile::type_tokens(text);
    let first = tokens.next()?;
    let kind = if first == "typedef" { tokens.next()? } else { first };
    if !matches!(kind, "struct" | "union" | "enum") {
        return None;
    }
    let name = tokens.next()?;
    (tokens.next()? == "{").then_some(name)
}

fn worker_declaration_roots(
    output: &rampage_decompiler::worker::WorkerOutput,
    count: usize,
) -> Result<Vec<Vec<NamedType>>, ApiError> {
    let declarations = output
        .type_declarations
        .as_ref()
        .ok_or_else(|| ApiError::Unavailable("worker omitted native declaration roots".to_owned()))?;
    if declarations.len() < count {
        return Err(ApiError::Unavailable("worker omitted native declaration roots".to_owned()));
    }
    Ok(declarations[declarations.len() - count..].to_vec())
}

#[cfg(test)]
#[path = "type_library_tests.rs"]
mod tests;
