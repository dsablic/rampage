//! .NET (ECMA-335) metadata of a managed assembly, from `rampage_loaders::dotnet`: the assembly identity, its
//! references and entry point, the size of each list, and one page of one list -- its types with their methods
//! and signatures, its P/Invoke imports, or its custom attributes -- filterable because a real assembly can hold
//! thousands of entries. Method bodies are CIL bytecode and are reported, never analyzed as native code.

use std::str::FromStr;

use rampage_loaders::dotnet::{
    self, Assembly, AssemblyRef, BodyKind, CliHeader, CustomAttribute, EntryPoint, Module, PInvoke, TypeDef,
};
use serde::{Deserialize, Serialize};

use crate::rows::Matcher;
use crate::{ApiError, Page, Project};

/// Which list a [`DotNetQuery`] pages; each is its own paged view.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DotNetList {
    /// Types with their fields and methods.
    #[default]
    Types,
    /// P/Invoke imports: the DLL export each native method binds to.
    Pinvokes,
    /// Custom attributes with their targets and constructor arguments.
    Attributes,
}

impl FromStr for DotNetList {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        match text {
            "types" => Ok(Self::Types),
            "pinvokes" => Ok(Self::Pinvokes),
            "attributes" => Ok(Self::Attributes),
            _ => Err(format!("unknown list `{text}` (expected types, pinvokes or attributes)")),
        }
    }
}

/// One page of `list`, case-insensitively matching `contains`: types by full name (`Namespace.Name`) or a method
/// name, P/Invoke imports by method, DLL or import name, custom attributes by attribute type or target.
/// `parent_token` keeps only the attributes applied to that metadata token.
#[derive(Debug, Default, Clone)]
pub struct DotNetQuery {
    pub list: DotNetList,
    pub contains: Option<String>,
    pub parent_token: Option<u32>,
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

/// The assembly-level metadata, the size of every list, and one page of the list the query selected; the other
/// two lists are absent.
#[derive(Debug, Serialize)]
pub struct DotNetSummary {
    pub cli: CliHeader,
    pub runtime_version: String,
    pub module: Option<Module>,
    pub assembly: Option<Assembly>,
    pub assembly_refs: Vec<AssemblyRef>,
    pub entry_point: Option<EntryPoint>,
    pub counts: DotNetCounts,
    pub list: DotNetList,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub types: Option<Page<TypeDef>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinvokes: Option<Page<PInvoke>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_attributes: Option<Page<CustomAttribute>>,
    pub warnings: Vec<String>,
}

impl Project {
    /// The .NET metadata of a managed assembly, or `None` when the image has no CLI header.
    pub fn dotnet_metadata(&self, query: &DotNetQuery) -> Result<Option<DotNetSummary>, ApiError> {
        if query.parent_token.is_some() && query.list != DotNetList::Attributes {
            return Err(ApiError::Invalid("parent_token filters the attributes list only".to_owned()));
        }
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
        let any = |texts: [Option<&str>; 3]| texts.into_iter().flatten().any(|text| matcher.matches(text));
        let (mut types, mut pinvokes, mut custom_attributes) = (None, None, None);
        match query.list {
            DotNetList::Types => {
                let wanted = |ty: &TypeDef| {
                    matcher.matches(&ty.full_name()) || ty.methods.iter().any(|method| matcher.matches(&method.name))
                };
                types = Some(Page::of(metadata.types.into_iter().filter(wanted), query.offset, query.limit));
            }
            DotNetList::Pinvokes => {
                let wanted = |pinvoke: &PInvoke| {
                    any([pinvoke.method.as_deref(), pinvoke.module.as_deref(), Some(&pinvoke.import_name)])
                };
                pinvokes = Some(Page::of(metadata.pinvokes.into_iter().filter(wanted), query.offset, query.limit));
            }
            DotNetList::Attributes => {
                let wanted = |attribute: &CustomAttribute| {
                    query.parent_token.is_none_or(|parent| attribute.parent_token == parent)
                        && any([attribute.attribute_type.as_deref(), attribute.parent.as_deref(), None])
                };
                let attributes = metadata.custom_attributes.into_iter().filter(wanted);
                custom_attributes = Some(Page::of(attributes, query.offset, query.limit));
            }
        }
        Ok(Some(DotNetSummary {
            cli: metadata.cli,
            runtime_version: metadata.runtime_version,
            module: metadata.module,
            assembly: metadata.assembly,
            assembly_refs: metadata.assembly_refs,
            entry_point: metadata.entry_point,
            counts,
            list: query.list,
            types,
            pinvokes,
            custom_attributes,
            warnings: metadata.warnings,
        }))
    }
}
