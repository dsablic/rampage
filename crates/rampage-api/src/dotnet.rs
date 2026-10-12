//! .NET (ECMA-335) metadata of a managed assembly, from `rampage_loaders::dotnet`: the assembly identity, its
//! references and entry point, and its types with their methods, paged and filterable because a real assembly can
//! hold thousands of types. Method bodies are CIL bytecode and are reported, never analyzed as native code.

use rampage_loaders::dotnet::{self, Assembly, AssemblyRef, BodyKind, CliHeader, EntryPoint, Module, TypeDef};
use serde::Serialize;

use crate::{ApiError, Page, Project};

/// Which types to list: those whose full name (`Namespace.Name`) or one of whose method names contains `contains`
/// (case-insensitive), paged by `offset`/`limit`.
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
}

/// The assembly-level metadata plus one page of its types.
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
        };
        let needle = query.contains.as_deref().map(str::to_lowercase);
        let wanted = |ty: &TypeDef| match &needle {
            None => true,
            Some(needle) => {
                ty.full_name().to_lowercase().contains(needle)
                    || ty.methods.iter().any(|method| method.name.to_lowercase().contains(needle))
            }
        };
        let types = Page::of(metadata.types.into_iter().filter(wanted), query.offset, query.limit);
        Ok(Some(DotNetSummary {
            cli: metadata.cli,
            runtime_version: metadata.runtime_version,
            module: metadata.module,
            assembly: metadata.assembly,
            assembly_refs: metadata.assembly_refs,
            entry_point: metadata.entry_point,
            counts,
            types,
            warnings: metadata.warnings,
        }))
    }
}
