//! Structural admission is not validation or a compiler cost proof; the supervisor also bounds this phase.

mod raw;

use wasmparser::{
    CanonicalFunction, CanonicalOption, ComponentAlias, ComponentDefinedType, ComponentType, ComponentTypeDeclaration,
    CompositeInnerType, CoreType, DataKind, ElementItems, ElementKind, Encoding, FromReader, FunctionBody,
    InstanceTypeDeclaration, ModuleTypeDeclaration, Operator, OperatorsReader, Parser, Payload, RecGroup,
    SectionLimited, TableInit, TypeRef,
};

use crate::{
    MAX_COMPONENT_BYTES, MAX_INSTANCES, MAX_MEMORIES, MAX_MEMORY_BYTES, MAX_TABLE_ELEMENTS, MAX_TABLES, PluginError,
};

const MAX_DEPTH: usize = 8;
const MAX_ENTRIES: usize = 32_768;
const MAX_TYPES: usize = 4096;
const MAX_FUNCTIONS: usize = 8192;
const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_LOCALS_PER_FUNCTION: usize = 4096;
const MAX_LOCALS: usize = 65_536;
const MAX_OPERATORS: usize = 1_000_000;
const MAX_CONTROL_DEPTH: usize = 128;
const MAX_NAMES_BYTES: usize = 256 * 1024;
const MAX_NAME_BYTES: usize = 1024;
const MAX_CUSTOM_BYTES: usize = 512 * 1024;
const MAX_DATA_BYTES: usize = 1024 * 1024;
const MAX_SEGMENTS: usize = 1024;

#[derive(Default)]
struct Structure {
    entries: usize,
    types: usize,
    functions: usize,
    bodies: usize,
    locals: usize,
    operators: usize,
    names: usize,
    custom: usize,
    data: usize,
    segments: usize,
    memories: usize,
    tables: usize,
    modules: usize,
    components: usize,
    instances: usize,
    component_instances: usize,
}

fn add(total: &mut usize, amount: usize, limit: usize) -> Result<(), PluginError> {
    *total = total.checked_add(amount).filter(|value| *value <= limit).ok_or(PluginError::StructuralLimit)?;
    Ok(())
}

fn parsed<T>(result: wasmparser::Result<T>) -> Result<T, PluginError> {
    result.map_err(|_| PluginError::Preflight)
}

fn section<'a, T: FromReader<'a>>(
    reader: SectionLimited<'a, T>,
    state: &mut Structure,
    mut visit: impl FnMut(&mut Structure, T) -> Result<(), PluginError>,
) -> Result<(), PluginError> {
    add(&mut state.entries, reader.count() as usize, MAX_ENTRIES)?;
    for item in reader {
        visit(state, parsed(item)?)?;
    }
    Ok(())
}

pub(crate) fn admit(bytes: &[u8]) -> Result<(), PluginError> {
    if bytes.len() > MAX_COMPONENT_BYTES {
        return Err(PluginError::ComponentTooLarge);
    }
    if bytes.get(..8) != Some(b"\0asm\x0d\0\x01\0".as_slice()) {
        return Err(PluginError::Preflight);
    }
    raw::admit(bytes)?;
    let mut state = Structure::default();
    let mut depth = 0;
    let mut finished = false;
    for payload in Parser::new(0).parse_all(bytes) {
        if finished {
            return Err(PluginError::Preflight);
        }
        match parsed(payload)? {
            Payload::Version { encoding, .. } => {
                if depth == 0 && encoding != Encoding::Component {
                    return Err(PluginError::Preflight);
                }
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err(PluginError::StructuralLimit);
                }
            }
            Payload::End(_) => {
                depth = depth.checked_sub(1).ok_or(PluginError::Preflight)?;
                finished = depth == 0;
            }
            Payload::ModuleSection { unchecked_range, .. } => {
                if unchecked_range.end > bytes.len() {
                    return Err(PluginError::Preflight);
                }
                add(&mut state.modules, 1, MAX_INSTANCES)?;
            }
            Payload::ComponentSection { unchecked_range, .. } => {
                if unchecked_range.end > bytes.len() {
                    return Err(PluginError::Preflight);
                }
                add(&mut state.components, 1, MAX_INSTANCES)?;
            }
            Payload::TypeSection(reader) => section(reader, &mut state, |state, group| state.rec_group(&group))?,
            Payload::CoreTypeSection(reader) => section(reader, &mut state, |state, ty| state.core_type(&ty))?,
            Payload::ComponentTypeSection(reader) => {
                section(reader, &mut state, |state, ty| state.component_type(&ty, 0))?;
            }
            Payload::ImportSection(reader) => {
                add(&mut state.entries, reader.count() as usize, MAX_ENTRIES)?;
                for import in reader.into_imports() {
                    let import = parsed(import)?;
                    add(&mut state.entries, 1, MAX_ENTRIES)?;
                    state.name(import.module)?;
                    state.name(import.name)?;
                    if matches!(import.ty, TypeRef::Func(_) | TypeRef::FuncExact(_)) {
                        add(&mut state.functions, 1, MAX_FUNCTIONS)?;
                    }
                    state.core_ref(import.ty)?;
                }
            }
            Payload::ComponentImportSection(reader) => {
                if depth == 1 && reader.count() != 0 {
                    return Err(PluginError::Abi);
                }
                section(reader, &mut state, |state, import| state.name(import.name.0))?;
            }
            Payload::FunctionSection(reader) => {
                add(&mut state.functions, reader.count() as usize, MAX_FUNCTIONS)?;
                section(reader, &mut state, |_, _| Ok(()))?;
            }
            Payload::CodeSectionStart { count, .. } => {
                add(&mut state.bodies, count as usize, MAX_FUNCTIONS)?;
            }
            Payload::CodeSectionEntry(body) => state.body(body)?,
            Payload::MemorySection(reader) => {
                add(&mut state.memories, reader.count() as usize, MAX_MEMORIES)?;
                section(reader, &mut state, |_, ty| check_memory(ty))?;
            }
            Payload::TableSection(reader) => {
                add(&mut state.tables, reader.count() as usize, MAX_TABLES)?;
                section(reader, &mut state, |state, table| {
                    check_table(table.ty)?;
                    if let TableInit::Expr(expr) = table.init {
                        state.operators(expr.get_operators_reader())?;
                    }
                    Ok(())
                })?;
            }
            Payload::GlobalSection(reader) => {
                section(reader, &mut state, |state, global| state.operators(global.init_expr.get_operators_reader()))?
            }
            Payload::ExportSection(reader) => {
                section(reader, &mut state, |state, export| state.name(export.name))?;
            }
            Payload::ComponentExportSection(reader) => {
                section(reader, &mut state, |state, export| state.name(export.name.0))?;
            }
            Payload::InstanceSection(reader) => section(reader, &mut state, |state, instance| {
                match instance {
                    wasmparser::Instance::Instantiate { args, .. } => {
                        add(&mut state.instances, 1, MAX_INSTANCES)?;
                        add(&mut state.entries, args.len(), MAX_ENTRIES)?;
                        for arg in args {
                            state.name(arg.name)?;
                        }
                    }
                    wasmparser::Instance::FromExports(exports) => {
                        add(&mut state.entries, exports.len(), MAX_ENTRIES)?;
                        for export in exports {
                            state.name(export.name)?;
                        }
                    }
                }
                Ok(())
            })?,
            Payload::ComponentInstanceSection(reader) => section(reader, &mut state, |state, instance| {
                match instance {
                    wasmparser::ComponentInstance::Instantiate { args, .. } => {
                        add(&mut state.component_instances, 1, MAX_INSTANCES)?;
                        add(&mut state.entries, args.len(), MAX_ENTRIES)?;
                        for arg in args {
                            state.name(arg.name)?;
                        }
                    }
                    wasmparser::ComponentInstance::FromExports(exports) => {
                        add(&mut state.entries, exports.len(), MAX_ENTRIES)?;
                        for export in exports {
                            state.name(export.name.0)?;
                        }
                    }
                }
                Ok(())
            })?,
            Payload::ComponentAliasSection(reader) => {
                section(reader, &mut state, |state, alias| state.alias(&alias))?;
            }
            Payload::ComponentCanonicalSection(reader) => section(reader, &mut state, |state, function| {
                let options = match function {
                    CanonicalFunction::Lift { options, .. } | CanonicalFunction::Lower { options, .. } => options,
                    _ => return Err(PluginError::Preflight),
                };
                add(&mut state.entries, options.len(), MAX_ENTRIES)?;
                for option in options {
                    if !matches!(
                        option,
                        CanonicalOption::UTF8
                            | CanonicalOption::UTF16
                            | CanonicalOption::CompactUTF16
                            | CanonicalOption::Memory(_)
                            | CanonicalOption::Realloc(_)
                            | CanonicalOption::PostReturn(_)
                    ) {
                        return Err(PluginError::Preflight);
                    }
                }
                Ok(())
            })?,
            Payload::DataSection(reader) => {
                add(&mut state.segments, reader.count() as usize, MAX_SEGMENTS)?;
                section(reader, &mut state, |state, data| {
                    add(&mut state.data, data.data.len(), MAX_DATA_BYTES)?;
                    if let DataKind::Active { offset_expr, .. } = data.kind {
                        state.operators(offset_expr.get_operators_reader())?;
                    }
                    Ok(())
                })?;
            }
            Payload::ElementSection(reader) => {
                add(&mut state.segments, reader.count() as usize, MAX_SEGMENTS)?;
                section(reader, &mut state, |state, element| {
                    if let ElementKind::Active { offset_expr, .. } = element.kind {
                        state.operators(offset_expr.get_operators_reader())?;
                    }
                    match element.items {
                        ElementItems::Functions(reader) => section(reader, state, |_, _| Ok(())),
                        ElementItems::Expressions(_, reader) => {
                            section(reader, state, |state, expr| state.operators(expr.get_operators_reader()))
                        }
                    }
                })?;
            }
            Payload::DataCountSection { count, .. } => {
                if count as usize > MAX_SEGMENTS {
                    return Err(PluginError::StructuralLimit);
                }
            }
            Payload::CustomSection(reader) => {
                state.name(reader.name())?;
                add(&mut state.custom, reader.data().len(), MAX_CUSTOM_BYTES)?;
            }
            Payload::StartSection { .. } => {}
            Payload::TagSection(_) | Payload::ComponentStartSection { .. } => return Err(PluginError::Preflight),
            _ => return Err(PluginError::Preflight),
        }
    }
    if !finished || depth != 0 {
        return Err(PluginError::Preflight);
    }
    Ok(())
}

fn check_memory(ty: wasmparser::MemoryType) -> Result<(), PluginError> {
    let pages = MAX_MEMORY_BYTES as u64 / 65_536;
    if ty.memory64 || ty.shared || ty.page_size_log2.is_some() {
        return Err(PluginError::Preflight);
    }
    if ty.initial > pages || ty.maximum.is_some_and(|maximum| maximum > pages) {
        return Err(PluginError::StructuralLimit);
    }
    Ok(())
}

fn check_table(ty: wasmparser::TableType) -> Result<(), PluginError> {
    if ty.table64 || ty.shared || ty.element_type != wasmparser::RefType::FUNCREF {
        return Err(PluginError::Preflight);
    }
    if ty.initial > MAX_TABLE_ELEMENTS as u64 || ty.maximum.is_some_and(|maximum| maximum > MAX_TABLE_ELEMENTS as u64) {
        return Err(PluginError::StructuralLimit);
    }
    Ok(())
}

impl Structure {
    fn name(&mut self, name: &str) -> Result<(), PluginError> {
        if name.len() > MAX_NAME_BYTES {
            return Err(PluginError::StructuralLimit);
        }
        add(&mut self.names, name.len(), MAX_NAMES_BYTES)
    }

    fn core_ref(&mut self, ty: TypeRef) -> Result<(), PluginError> {
        match ty {
            TypeRef::Memory(ty) => check_memory(ty),
            TypeRef::Table(ty) => check_table(ty),
            TypeRef::Tag(_) => Err(PluginError::Preflight),
            _ => Ok(()),
        }
    }

    fn rec_group(&mut self, group: &RecGroup) -> Result<(), PluginError> {
        add(&mut self.types, group.types().len(), MAX_TYPES)?;
        for ty in group.types() {
            let CompositeInnerType::Func(function) = &ty.composite_type.inner else {
                return Err(PluginError::Preflight);
            };
            if ty.composite_type.shared || function.params().len() > 128 || function.results().len() > 16 {
                return Err(PluginError::StructuralLimit);
            }
            add(&mut self.entries, function.params().len() + function.results().len(), MAX_ENTRIES)?;
        }
        Ok(())
    }

    fn core_type(&mut self, ty: &CoreType<'_>) -> Result<(), PluginError> {
        match ty {
            CoreType::Rec(group) => self.rec_group(group),
            CoreType::Module(declarations) => {
                add(&mut self.types, 1, MAX_TYPES)?;
                add(&mut self.entries, declarations.len(), MAX_ENTRIES)?;
                for declaration in declarations.iter() {
                    match declaration {
                        ModuleTypeDeclaration::Type(group) => self.rec_group(group)?,
                        ModuleTypeDeclaration::Import(import) => {
                            self.name(import.module)?;
                            self.name(import.name)?;
                            self.core_ref(import.ty)?;
                        }
                        ModuleTypeDeclaration::Export { name, ty } => {
                            self.name(name)?;
                            self.core_ref(*ty)?;
                        }
                        ModuleTypeDeclaration::OuterAlias { .. } => {}
                    }
                }
                Ok(())
            }
        }
    }

    fn component_type(&mut self, ty: &ComponentType<'_>, depth: usize) -> Result<(), PluginError> {
        if depth >= MAX_DEPTH {
            return Err(PluginError::StructuralLimit);
        }
        add(&mut self.types, 1, MAX_TYPES)?;
        match ty {
            ComponentType::Func(function) => {
                if function.async_ || function.params.len() > 128 {
                    return Err(PluginError::Preflight);
                }
                add(&mut self.entries, function.params.len(), MAX_ENTRIES)?;
                for (name, _) in function.params.iter() {
                    self.name(name)?;
                }
            }
            ComponentType::Defined(defined) => {
                let count = match defined {
                    ComponentDefinedType::Record(fields) => {
                        for (name, _) in fields.iter() {
                            self.name(name)?;
                        }
                        fields.len()
                    }
                    ComponentDefinedType::Variant(cases) => {
                        for case in cases.iter() {
                            self.name(case.name)?;
                        }
                        cases.len()
                    }
                    ComponentDefinedType::Tuple(types) => types.len(),
                    ComponentDefinedType::Flags(names) | ComponentDefinedType::Enum(names) => {
                        for name in names.iter() {
                            self.name(name)?;
                        }
                        names.len()
                    }
                    ComponentDefinedType::Primitive(_)
                    | ComponentDefinedType::List(_)
                    | ComponentDefinedType::Option(_)
                    | ComponentDefinedType::Result { .. } => 1,
                    _ => return Err(PluginError::Preflight),
                };
                add(&mut self.entries, count, MAX_ENTRIES)?;
            }
            ComponentType::Component(declarations) => {
                add(&mut self.entries, declarations.len(), MAX_ENTRIES)?;
                for declaration in declarations.iter() {
                    match declaration {
                        ComponentTypeDeclaration::CoreType(ty) => self.core_type(ty)?,
                        ComponentTypeDeclaration::Type(ty) => self.component_type(ty, depth + 1)?,
                        ComponentTypeDeclaration::Alias(alias) => self.alias(alias)?,
                        ComponentTypeDeclaration::Import(import) => self.name(import.name.0)?,
                        ComponentTypeDeclaration::Export { name, .. } => self.name(name.0)?,
                    }
                }
            }
            ComponentType::Instance(declarations) => {
                add(&mut self.entries, declarations.len(), MAX_ENTRIES)?;
                for declaration in declarations.iter() {
                    match declaration {
                        InstanceTypeDeclaration::CoreType(ty) => self.core_type(ty)?,
                        InstanceTypeDeclaration::Type(ty) => self.component_type(ty, depth + 1)?,
                        InstanceTypeDeclaration::Alias(alias) => self.alias(alias)?,
                        InstanceTypeDeclaration::Export { name, .. } => self.name(name.0)?,
                    }
                }
            }
            ComponentType::Resource { .. } => return Err(PluginError::Preflight),
        }
        Ok(())
    }

    fn alias(&mut self, alias: &ComponentAlias<'_>) -> Result<(), PluginError> {
        match alias {
            ComponentAlias::InstanceExport { name, .. } | ComponentAlias::CoreInstanceExport { name, .. } => {
                self.name(name)
            }
            ComponentAlias::Outer { .. } => Ok(()),
        }
    }

    fn body(&mut self, body: FunctionBody<'_>) -> Result<(), PluginError> {
        if body.as_bytes().len() > MAX_BODY_BYTES {
            return Err(PluginError::StructuralLimit);
        }
        let locals = parsed(body.get_locals_reader())?;
        if locals.get_count() as usize > MAX_LOCALS_PER_FUNCTION {
            return Err(PluginError::StructuralLimit);
        }
        let mut count = 0;
        for local in locals {
            let (amount, _) = parsed(local)?;
            add(&mut count, amount as usize, MAX_LOCALS_PER_FUNCTION)?;
        }
        add(&mut self.locals, count, MAX_LOCALS)?;
        self.operators(parsed(body.get_operators_reader())?)
    }

    fn operators(&mut self, mut reader: OperatorsReader<'_>) -> Result<(), PluginError> {
        let mut depth = 1;
        while !reader.eof() {
            add(&mut self.operators, 1, MAX_OPERATORS)?;
            let mut binary = reader.get_binary_reader();
            if matches!(
                parsed(binary.read_u8())?,
                0x06..=0x0a | 0x1f | 0xe0..=0xe6 | 0xfb | 0xfe
            ) {
                return Err(PluginError::Preflight);
            }
            match parsed(reader.read())? {
                Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. } => {
                    add(&mut depth, 1, MAX_CONTROL_DEPTH)?;
                }
                Operator::End => depth = depth.checked_sub(1).ok_or(PluginError::Preflight)?,
                Operator::BrTable { targets } => {
                    add(&mut self.entries, targets.len() as usize, MAX_ENTRIES)?;
                    for target in targets.targets() {
                        parsed(target)?;
                    }
                }
                _ => {}
            }
            if depth == 0 && !reader.eof() {
                return Err(PluginError::Preflight);
            }
        }
        if depth != 0 {
            return Err(PluginError::Preflight);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leb(mut value: usize, bytes: &mut Vec<u8>) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            bytes.push(if value == 0 { byte } else { byte | 0x80 });
            if value == 0 {
                break;
            }
        }
    }

    fn wrap(id: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = b"\0asm\x0d\0\x01\0".to_vec();
        bytes.push(id);
        leb(payload.len(), &mut bytes);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn rejects_core_text_truncated_and_unknown_encodings() {
        for bytes in [b"(component)".as_slice(), b"\0asm\x01\0\0\0", b"\0asm\x0d\0\x01\0\x01\xff"] {
            assert_eq!(admit(bytes), Err(PluginError::Preflight));
        }
        assert_eq!(admit(&wrap(100, &[0])), Err(PluginError::Preflight));
    }

    #[test]
    fn nested_work_and_declared_counts_are_not_skipped() {
        let mut nested = b"\0asm\x0d\0\x01\0".to_vec();
        for _ in 0..MAX_DEPTH {
            nested = wrap(4, &nested);
        }
        assert_eq!(admit(&nested), Err(PluginError::StructuralLimit));
        let mut module = b"\0asm\x01\0\0\0\x03".to_vec();
        let mut count = Vec::new();
        leb(MAX_FUNCTIONS + 1, &mut count);
        leb(count.len(), &mut module);
        module.extend_from_slice(&count);
        assert_eq!(admit(&wrap(1, &module)), Err(PluginError::StructuralLimit));
    }

    #[test]
    fn scans_nested_function_body_locals_and_operators() {
        let mut state = Structure::default();
        let mut bytes = vec![1];
        leb(MAX_LOCALS_PER_FUNCTION + 1, &mut bytes);
        bytes.extend_from_slice(&[0x7f, 0x0b]);
        let body = FunctionBody::new(wasmparser::BinaryReader::new(&bytes, 0));
        assert_eq!(state.body(body), Err(PluginError::StructuralLimit));
        let bytes = [0, 0xff, 0x0b];
        let body = FunctionBody::new(wasmparser::BinaryReader::new(&bytes, 0));
        assert_eq!(state.body(body), Err(PluginError::Preflight));
    }

    #[test]
    fn internal_core_imports_are_not_mistaken_for_host_component_capabilities() {
        let module = b"\0asm\x01\0\0\0\x01\x04\x01\x60\0\0\x02\x09\x01\x03env\x01f\0\0";
        assert_eq!(admit(&wrap(1, module)), Ok(()));
        let mut component = wrap(7, &[1, 0x40, 0, 1, 0]);
        component.extend_from_slice(&[10, 6, 1, 0, 1, b'f', 1, 0]);
        assert_eq!(admit(&component), Err(PluginError::Abi));
    }
}
