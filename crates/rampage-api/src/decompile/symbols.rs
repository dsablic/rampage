use std::collections::BTreeMap;

use rampage_analysis::functions::{stub_names, thunk_names};
use rampage_decompiler::Decompiler;
use rampage_decompiler::worker::WorkerOperation;
use rampage_loaders::SymbolKind;

use crate::{ApiError, Project, annotations::Annotations};

fn canonical(name: &str) -> &str {
    name.strip_suffix("@plt").or_else(|| name.strip_suffix("@got")).unwrap_or(name)
}

pub(super) fn requires_import_context(operations: &[WorkerOperation]) -> bool {
    operations.iter().any(|operation| {
        matches!(operation,
        WorkerOperation::RuntimePrototype { name, .. }
            if matches!(name.trim_start_matches('_'), "memcpy" | "recv" | "CreateFileW")
                || name.starts_with("_recv@") || name.starts_with("_CreateFileW@"))
    })
}

pub(super) fn specialize_imports(
    annotations: &Annotations,
    options: &rampage_decompiler::DecompilerOptions,
    language_id: &str,
    organization: rampage_decompiler::DataOrganization,
    operations: &mut Vec<WorkerOperation>,
) -> Result<(), ApiError> {
    let posix = posix_context(annotations, options, language_id)?;
    let mut specialized = Vec::with_capacity(operations.len());
    for operation in operations.drain(..) {
        if let WorkerOperation::RuntimePrototype { address, indirect, name, optional } = operation {
            let declaration =
                crate::import_types::import_prototype(&name, options.platform, language_id, organization, posix);
            if let Some(prototype) = declaration {
                specialized.push(WorkerOperation::Prototype { address, indirect, declaration: prototype.declaration });
            } else if !matches!(name.trim_start_matches('_'), "recv" | "CreateFileW")
                && !name.starts_with("_recv@")
                && !name.starts_with("_CreateFileW@")
            {
                specialized.push(WorkerOperation::RuntimePrototype { address, indirect, name, optional });
            }
        } else {
            specialized.push(operation);
        }
    }
    *operations = specialized;
    Ok(())
}

pub(crate) fn posix_context(
    annotations: &Annotations,
    options: &rampage_decompiler::DecompilerOptions,
    language_id: &str,
) -> Result<Option<crate::import_types::PosixContext>, ApiError> {
    let explicit_posix = crate::type_library::stored_declarations(annotations)?.iter().any(|unit| {
        unit.source.as_ref().is_some_and(|source| source.kind == "profile" && source.identity == "posix-linux")
    });
    Ok(if explicit_posix {
        Some(crate::import_types::PosixContext::PosixLinuxProfile)
    } else if !matches!(language_id.rsplit(':').next(), Some("windows" | "clangwindows"))
        && (options.platform == rampage_decompiler::Platform::Darwin
            || matches!(language_id.rsplit(':').next(), Some("apple" | "macosx")))
    {
        Some(crate::import_types::PosixContext::TargetAssertion)
    } else {
        None
    })
}

fn failure(address: u64, operation: &str, error: impl std::fmt::Display) -> ApiError {
    ApiError::Unavailable(format!("{operation} at {address:#x}: {error}"))
}

pub(super) fn plan(project: &Project, annotations: &Annotations) -> Result<Vec<WorkerOperation>, ApiError> {
    crate::debug_layout_import::validate_replay_source(project, annotations)?;
    let analysis = project.analysis()?;
    crate::debug_layout_import::validate_replay_source(project, annotations)?;
    let mut operations = Vec::new();
    let binary = &project.binary;
    let stubs: BTreeMap<_, _> = stub_names(binary).into_iter().chain(thunk_names(binary)).collect();
    let mut identities: BTreeMap<_, _> = analysis
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
    operations.extend(data_names(project, annotations, &identities, &slots));
    operations.extend(raw_image_operations(binary));
    operations.extend(virtual_tables(project, annotations));
    Ok(operations)
}

/// The MSVC vftables of a PE, so virtual calls through them decompile with their slot's targets named. Each table
/// serves the type names of the classes whose vfptr it is (from RTTI): the class name with every run of characters
/// outside C identifiers made one `_` (`geo::Shape` is `geo_Shape`, `Box<int>` is `Box_int`), and its last
/// component alone (`Shape`) when no other class shares it. A pointer typed with one of these names, or the `this`
/// of a function in a table's slots, resolves calls through its vfptr.
fn virtual_tables(project: &Project, annotations: &Annotations) -> Option<WorkerOperation> {
    let metadata = project.binary.msvc_metadata()?;
    if metadata.vftables.is_empty() {
        return None;
    }
    let mut type_names: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let mut short: BTreeMap<String, std::collections::BTreeSet<u64>> = BTreeMap::new();
    for (descriptor, mangled) in metadata.vftables.iter().flat_map(|table| &table.subobjects) {
        if type_names.contains_key(descriptor) {
            continue;
        }
        let Some(name) = rampage_analysis::language::msvc_type_name(mangled) else { continue };
        let names = class_type_names(&name);
        if let Some(last) = names.get(1) {
            short.entry(last.clone()).or_default().insert(*descriptor);
        }
        type_names.insert(*descriptor, names);
    }
    for names in type_names.values_mut() {
        if names.len() > 1 && short.get(&names[1]).is_some_and(|owners| owners.len() > 1) {
            names.truncate(1);
        }
    }
    // Bounds the operation (a supervised worker request is at most 128 MiB): tables past a million slots, and target
    // names past 16 MiB, are left out; such calls stay unresolved or name their targets by address.
    const MAX_SLOTS: usize = 1 << 20;
    const MAX_NAME_BYTES: usize = 16 << 20;
    let mut slots = 0usize;
    let mut targets = std::collections::BTreeSet::new();
    let tables = metadata
        .vftables
        .iter()
        .take_while(|table| {
            slots += table.slots.len();
            slots <= MAX_SLOTS
        })
        .map(|table| {
            targets.extend(table.slots.iter().copied());
            let mut types: Vec<String> = table
                .subobjects
                .iter()
                .flat_map(|(descriptor, _)| type_names.get(descriptor).into_iter().flatten().cloned())
                .collect();
            types.sort();
            types.dedup();
            rampage_decompiler::VirtualTable {
                address: table.address,
                complete: table.type_descriptor,
                offset: i64::from(table.offset),
                slots: table.slots.clone(),
                truncated: table.truncated,
                types,
            }
        })
        .collect();
    let mut name_bytes = 0usize;
    let names = targets
        .into_iter()
        .map(|address| (address, project.function_name_in(annotations, address)))
        .filter(|(_, name)| !name.contains('\0'))
        .take_while(|(_, name)| {
            name_bytes += name.len();
            name_bytes <= MAX_NAME_BYTES
        })
        .collect();
    Some(WorkerOperation::VirtualTables { tables, names })
}

/// The C type names a class serves: its whole name as an identifier, then its last component when that differs.
fn class_type_names(name: &str) -> Vec<String> {
    let identifier = |text: &str| {
        let mut result = String::new();
        for character in text.chars() {
            if character.is_ascii_alphanumeric() || character == '_' {
                result.push(character);
            } else if !result.ends_with('_') {
                result.push('_');
            }
        }
        result.trim_matches('_').to_owned()
    };
    let mut names = Vec::new();
    let whole = identifier(name);
    if whole.is_empty() || whole.starts_with(|character: char| character.is_ascii_digit()) {
        return names;
    }
    names.push(whole);
    let mut depth = 0i32;
    let mut last = 0;
    let bytes = name.as_bytes();
    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            b'<' => depth += 1,
            b'>' => depth -= 1,
            b':' if depth == 0 && bytes.get(index + 1) == Some(&b':') => last = index + 2,
            _ => {}
        }
    }
    let tail = identifier(&name[last..]);
    if last != 0 && !tail.is_empty() && !tail.starts_with(|character: char| character.is_ascii_digit()) {
        names.push(tail);
    }
    names
}

/// Cortex-M Raw images only: their mapping is flash, which nothing writes at run time, they carry no prototypes, and
/// their code is often built with interprocedural register allocation. Headered formats keep Ghidra's defaults (a
/// PE's `.rdata` can be rewritten at run time by its pseudo-relocator, and ELF and PE callees have libc/import
/// prototypes), and so do the other Raw profiles, whose image is often RAM that the program writes (`lda counter`
/// would fold to its load-time byte). The engine resets the callee inference before each top-level decompilation,
/// so a cached engine gives the same C whatever was decompiled before.
fn raw_image_operations(binary: &rampage_loaders::Binary) -> Vec<WorkerOperation> {
    if !binary.m_profile() {
        return Vec::new();
    }
    let inference = rampage_decompiler::CalleeInference { register_effects: true, prototypes: true };
    vec![WorkerOperation::FoldReadOnly { enabled: true }, WorkerOperation::CalleeInference { inference }]
}

/// The architectural ARMv6-M/ARMv7-M system address map: every M-profile core decodes these ranges the same way,
/// whatever the device. A global in one with no other name reads `ram_20000004`, `periph_40021000` and so on.
const CORTEX_M_REGIONS: [(u64, u64, &str); 7] = [
    (0x0000_0000, 0x1fff_ffff, "code"),
    (0x2000_0000, 0x3fff_ffff, "ram"),
    (0x4000_0000, 0x5fff_ffff, "periph"),
    (0x6000_0000, 0x9fff_ffff, "extram"),
    (0xa000_0000, 0xdfff_ffff, "extdev"),
    (0xe000_0000, 0xe00f_ffff, "ppb"),
    (0xe010_0000, 0xffff_ffff, "vendor_sys"),
];

/// Mirrors the shim's `identifier()` check (shim.cc), which refuses any other name and with it the whole engine.
fn c_identifier(name: &str) -> bool {
    let mut characters = name.chars();
    characters.next().is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
        && name.len() <= 256
}

/// Names for globals the decompiler would otherwise call `iRam…`/`uRam…`: the analyst's name for a data address,
/// else the binary's data symbol (when that name is unique), and on a Cortex-M Raw image the architectural
/// region of the address. Names only; typed globals (`set_global`) keep their own symbols.
fn data_names(
    project: &Project,
    annotations: &Annotations,
    functions: &BTreeMap<u64, String>,
    slots: &std::collections::BTreeSet<u64>,
) -> Vec<WorkerOperation> {
    // The decompiler refuses a name beyond its data space (and with it the whole engine), so such names are left
    // out: an analyst may name any address. The data space is as wide as a pointer; the Raw profiles with a C
    // model but no native width (MSP430, AVR8) have 16-bit data spaces.
    let highest = match project.binary.arch.default_pointer_size() {
        Some(size) if size < 8 => (1u64 << (8 * u32::from(size))) - 1,
        Some(_) => u64::MAX,
        None => u64::from(u16::MAX),
    };
    let data = |address: &u64| *address <= highest && !functions.contains_key(address) && !slots.contains(address);
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for symbol in &project.binary.symbols {
        if symbol.kind == SymbolKind::Data {
            *counts.entry(symbol.name.as_str()).or_default() += 1;
        }
    }
    for symbol in &project.binary.symbols {
        if symbol.kind == SymbolKind::Data
            && counts.get(symbol.name.as_str()) == Some(&1)
            && c_identifier(&symbol.name)
            && data(&symbol.address)
        {
            names.entry(symbol.address).or_insert_with(|| symbol.name.clone());
        }
    }
    for (address, name) in annotations.names() {
        if data(address) && c_identifier(name) {
            names.insert(*address, name.clone());
        }
    }
    let mut operations: Vec<_> =
        names.into_iter().map(|(address, name)| WorkerOperation::DataName { address, name }).collect();
    if project.binary.m_profile() {
        operations.extend(CORTEX_M_REGIONS.iter().map(|&(first, last, prefix)| WorkerOperation::DataRegion {
            first,
            last,
            prefix: prefix.to_owned(),
        }));
    }
    operations
}

pub(super) fn apply(operations: Vec<WorkerOperation>, engine: &mut Decompiler) -> Result<(), ApiError> {
    let mut protected = BTreeMap::new();
    for operation in operations {
        let checks_types = matches!(
            &operation,
            WorkerOperation::TypeLibrary { .. }
                | WorkerOperation::ParseTypes { .. }
                | WorkerOperation::Global { .. }
                | WorkerOperation::Prototype { .. }
                | WorkerOperation::LocalVariables { .. }
                | WorkerOperation::TypeHints { .. }
        );
        match operation {
            WorkerOperation::TypeHints { address, hints } => {
                engine
                    .set_type_hints(address, &hints)
                    .map_err(|error| failure(address, "apply soft type hints", error))?;
            }
            WorkerOperation::LocalVariables { address, overrides } => {
                engine
                    .set_variable_overrides(address, &overrides)
                    .map_err(|error| failure(address, "apply variable overrides", error))?;
            }
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
            WorkerOperation::TypeLibrary { declarations, packing } => {
                let before = engine.type_inventory().map_err(|error| ApiError::Invalid(error.to_string()))?;
                let declared = engine
                    .parse_type_library(&declarations, packing)
                    .map_err(|error| ApiError::Invalid(error.to_string()))?;
                verify_library_types(engine, &protected)?;
                for ty in declared {
                    protected.insert(ty.name.clone(), ty);
                }
                for ty in engine.type_inventory().map_err(|error| ApiError::Invalid(error.to_string()))? {
                    if !before.iter().any(|prior| prior.name == ty.name) {
                        protected.insert(ty.name.clone(), ty);
                    }
                }
            }
            WorkerOperation::AssertPlainStructLayout { layout, expected_context } => {
                let current = crate::debug_layout_import::current_specification_digest()?;
                if expected_context.as_deref() != Some(current.as_str()) {
                    return Err(ApiError::Invalid(
                        "native assertion context does not match the pinned manifest".to_owned(),
                    ));
                }
                engine
                    .verify_bundled_plain_struct_counterpart(&layout)
                    .map_err(|error| ApiError::Invalid(error.to_string()))?
            }
            WorkerOperation::AssertNamedTypes { language_id, organization, types, expected_context } => {
                if expected_context.as_deref()
                    != Some(crate::debug_layout_import::current_specification_digest()?.as_str())
                {
                    return Err(ApiError::Invalid("named type assertion specification context changed".into()));
                }
                engine
                    .verify_bundled_named_types_counterpart(&language_id, organization, &types)
                    .map_err(|error| ApiError::Invalid(error.to_string()))?;
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
            WorkerOperation::DataName { address, name } => {
                engine.set_data_name(address, &name).map_err(|error| failure(address, "name data", error))?
            }
            WorkerOperation::DataRegion { first, last, prefix } => engine
                .add_data_region(first, last, &prefix)
                .map_err(|error| failure(first, "name data region", error))?,
            WorkerOperation::CalleeInference { inference } => engine
                .set_callee_inference(inference)
                .map_err(|error| ApiError::Unavailable(format!("callee inference: {error}")))?,
            WorkerOperation::FoldReadOnly { enabled } => engine
                .set_read_only_folding(enabled)
                .map_err(|error| ApiError::Unavailable(format!("read-only folding: {error}")))?,
            WorkerOperation::VirtualTables { tables, names } => engine
                .add_virtual_tables(&tables, &names)
                .map_err(|error| ApiError::Unavailable(format!("virtual tables: {error}")))?,
            WorkerOperation::Mode { .. } => unreachable!(),
        }
        if checks_types {
            verify_library_types(engine, &protected)?;
        }
    }
    Ok(())
}

fn verify_library_types(
    engine: &Decompiler,
    protected: &BTreeMap<String, rampage_decompiler::NamedType>,
) -> Result<(), ApiError> {
    for (name, expected) in protected {
        let actual = engine.get_type(name).map_err(|error| ApiError::Invalid(error.to_string()))?;
        if actual != *expected {
            return Err(ApiError::Invalid(format!("annotation replay redefines library type {name:?}")));
        }
    }
    Ok(())
}

pub(crate) fn stub_targets(project: &Project, slot: u64) -> Vec<u64> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_type_names_are_identifiers_with_the_last_component_after() {
        assert_eq!(class_type_names("geo::Shape"), ["geo_Shape", "Shape"]);
        assert_eq!(class_type_names("Shape"), ["Shape"]);
        assert_eq!(class_type_names("Box<int>"), ["Box_int"]);
        assert_eq!(class_type_names("FixedStack<int,4>"), ["FixedStack_int_4"]);
        // A template argument's `::` is not a scope of the class.
        assert_eq!(class_type_names("ns::Box<std::string>"), ["ns_Box_std_string", "Box_std_string"]);
        assert_eq!(class_type_names("`anonymous namespace'::Impl"), ["anonymous_namespace_Impl", "Impl"]);
        assert_eq!(class_type_names("<lambda_1>"), ["lambda_1"]);
        assert!(class_type_names("<>").is_empty());
    }
    use rampage_decompiler::{DataOrganization, DecompilerOptions, Platform};

    /// Folding and callee inference are for Cortex-M images, whose mapping is flash. An MSP430/AVR8 Raw image is
    /// often RAM the program writes, where folding would read a variable as its load-time byte.
    #[test]
    fn raw_image_inference_is_for_cortex_m_only() {
        let raw = |profile| {
            let options = rampage_loaders::RawCodeOptions {
                profile,
                base: 0x1000,
                entry: None,
                seeds: vec![],
                vector_table: None,
                pointer_tables: false,
            };
            rampage_loaders::Binary::from_raw_code(vec![0; 4], options).unwrap()
        };
        for profile in [rampage_loaders::RawProfile::Msp430, rampage_loaders::RawProfile::Avr8] {
            assert!(raw_image_operations(&raw(profile)).is_empty(), "{profile:?}");
        }
        let operations = raw_image_operations(&raw(rampage_loaders::RawProfile::CortexM));
        assert!(matches!(
            operations[..],
            [WorkerOperation::FoldReadOnly { enabled: true }, WorkerOperation::CalleeInference { .. }]
        ));
    }

    #[test]
    fn selected_windows_recv_replaces_generic_catalog_before_the_analyst_signature() {
        let mut operations = vec![
            WorkerOperation::RuntimePrototype { address: 0x1000, indirect: false, name: "recv".into(), optional: true },
            WorkerOperation::RuntimePrototype { address: 0x2000, indirect: true, name: "recv".into(), optional: true },
            WorkerOperation::Prototype {
                address: 0x1000,
                indirect: false,
                declaration: "int4 analyst_recv(void *socket);".into(),
            },
        ];
        specialize_imports(
            &Annotations::in_memory(),
            &DecompilerOptions { platform: Platform::Windows, ..Default::default() },
            "x86:LE:64:default:windows",
            DataOrganization { pointer: 8, int: 4, long: 4 },
            &mut operations,
        )
        .unwrap();
        assert_eq!(operations.len(), 3);
        for operation in &operations[..2] {
            let WorkerOperation::Prototype { declaration, .. } = operation else { panic!("target-bound prototype") };
            assert!(declaration.contains("int4 recv(uint8 s, char *buf, int4 len, int4 flags)"), "{declaration}");
        }
        assert!(matches!(&operations[2], WorkerOperation::Prototype { declaration, .. }
            if declaration == "int4 analyst_recv(void *socket);"));
    }

    #[test]
    fn default_model_does_not_promote_recv_to_a_posix_source_but_keeps_portable_memcpy() {
        let mut operations = vec![
            WorkerOperation::RuntimePrototype { address: 0x1000, indirect: false, name: "recv".into(), optional: true },
            WorkerOperation::RuntimePrototype {
                address: 0x2000,
                indirect: false,
                name: "memcpy".into(),
                optional: true,
            },
        ];
        specialize_imports(
            &Annotations::in_memory(),
            &DecompilerOptions::default(),
            "x86:LE:64:default:gcc",
            DataOrganization { pointer: 8, int: 4, long: 8 },
            &mut operations,
        )
        .unwrap();
        let [WorkerOperation::Prototype { address, declaration, .. }] = operations.as_slice() else {
            panic!("only the portable source is admitted")
        };
        assert_eq!(*address, 0x2000);
        assert!(declaration.contains("memcpy"));
    }
}
