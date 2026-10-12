//! .NET (ECMA-335) metadata of a managed assembly, from `rampage_loaders::dotnet`: the assembly identity, its
//! references and entry point, its types with their methods and signatures, its P/Invoke imports and its custom
//! attributes, each list paged and filterable because a real assembly can hold thousands of entries. Method
//! bodies are CIL bytecode and are reported, never analyzed as native code.

use rampage_loaders::dotnet::{
    self, Assembly, AssemblyRef, BodyKind, CliHeader, CustomAttribute, EntryPoint, Module, PInvoke, TypeDef,
};
use serde::Serialize;

use crate::rows::Matcher;
use crate::{ApiError, Page, Project};

/// Which entries to list, case-insensitively matching `contains`: types by full name (`Namespace.Name`) or a
/// method name, P/Invoke imports by method, DLL or import name, and custom attributes by attribute type or
/// target. `offset`/`limit` page each of the three lists alike.
#[derive(Debug, Default, Clone)]
pub struct DotNetQuery {
    pub contains: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct DotNetCounts {
    pub types: usize,
    pub methods: usize,
    pub il_methods: usize,
    pub native_methods: usize,
    pub type_refs: usize,
    pub member_refs: usize,
    pub user_strings: usize,
    pub pinvokes: usize,
    pub custom_attributes: usize,
}

/// The assembly-level metadata plus one page each of its types, P/Invoke imports and custom attributes.
#[derive(Debug, Serialize)]
pub struct DotNetSummary {
    pub cli: CliHeader,
    pub runtime_version: String,
    pub module: Option<Module>,
    pub assembly: Option<Assembly>,
    pub assembly_refs: Vec<AssemblyRef>,
    pub entry_point: Option<EntryPoint>,
    pub counts: DotNetCounts,
    pub types: Page<TypeDef>,
    pub pinvokes: Page<PInvoke>,
    pub custom_attributes: Page<CustomAttribute>,
    pub warnings: Vec<String>,
}

impl Project {
    /// The .NET metadata of a managed assembly, or `None` when the image has no CLI header.
    pub fn dotnet_metadata(&self, query: &DotNetQuery) -> Result<Option<DotNetSummary>, ApiError> {
        let Some(metadata) = dotnet::metadata(&self.binary)
            .map_err(|error| ApiError::Invalid(format!("malformed .NET metadata: {error}")))?
        else {
            return Ok(None);
        };
        let methods = || metadata.types.iter().flat_map(|ty| &ty.methods);
        let counts = DotNetCounts {
            types: metadata.types.len(),
            methods: methods().count(),
            il_methods: methods().filter(|method| matches!(method.body, BodyKind::Il)).count(),
            native_methods: methods().filter(|method| matches!(method.body, BodyKind::Native)).count(),
            type_refs: metadata.type_refs.len(),
            member_refs: metadata.member_refs.len(),
            user_strings: metadata.user_strings.len(),
            pinvokes: metadata.pinvokes.len(),
            custom_attributes: metadata.custom_attributes.len(),
        };
        let matcher = Matcher::new(query.contains.as_deref());
        let wanted = |ty: &TypeDef| {
            matcher.matches(&ty.full_name()) || ty.methods.iter().any(|method| matcher.matches(&method.name))
        };
        let types = Page::of(metadata.types.into_iter().filter(wanted), query.offset, query.limit);
        let any = |texts: [Option<&str>; 3]| texts.into_iter().flatten().any(|text| matcher.matches(text));
        let pinvokes = metadata
            .pinvokes
            .into_iter()
            .filter(|pinvoke| any([pinvoke.method.as_deref(), pinvoke.module.as_deref(), Some(&pinvoke.import_name)]));
        let attributes = metadata
            .custom_attributes
            .into_iter()
            .filter(|attribute| any([attribute.attribute_type.as_deref(), attribute.parent.as_deref(), None]));
        Ok(Some(DotNetSummary {
            cli: metadata.cli,
            runtime_version: metadata.runtime_version,
            module: metadata.module,
            assembly: metadata.assembly,
            assembly_refs: metadata.assembly_refs,
            entry_point: metadata.entry_point,
            counts,
            types,
            pinvokes: Page::of(pinvokes, query.offset, query.limit),
            custom_attributes: Page::of(attributes, query.offset, query.limit),
            warnings: metadata.warnings,
        }))
    }
}
