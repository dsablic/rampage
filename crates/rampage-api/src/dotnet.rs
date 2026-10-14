//! .NET (ECMA-335) metadata of a managed assembly, from `rampage_loaders::dotnet`: the assembly identity, its
//! references and entry point, the size of each list, and one page of one list -- its types with their methods
//! and signatures, its P/Invoke imports, or its custom attributes -- filterable because a real assembly can hold
//! thousands of entries. Type rows include fields, methods, properties and events. Method bodies are CIL bytecode,
//! reported but never analyzed as native code; one method's CIL can be listed a page at a time by
//! [`Project::dotnet_il`].

use std::str::FromStr;

use rampage_loaders::dotnet::{
    self, Assembly, AssemblyRef, BodyKind, CliHeader, CustomAttribute, EntryPoint, ExceptionClause, IlBody, IlError,
    Instruction, MethodSelector, Module, PInvoke, TypeDef,
};
use serde::{Deserialize, Serialize};

use crate::rows::Matcher;
use crate::{ApiError, Page, Project};

/// Which list a [`DotNetQuery`] pages; each is its own paged view.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DotNetList {
    /// Types with their fields, methods, properties and events.
    #[default]
    Types,
    /// P/Invoke imports: the DLL export each native method binds to.
    Pinvokes,
    /// Custom attributes with their targets, constructor arguments and named field/property arguments.
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
/// or property/event name, P/Invoke imports by method, DLL or import name, custom attributes by attribute type or
/// target.
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
    pub properties: usize,
    pub events: usize,
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

/// One page of a managed method's CIL listing. `method` is a MethodDef token (`0x0600000d`, or decimal) or a
/// `Namespace.Type::Name` (nested types as `Outer/Inner`; a bare method name also works) naming exactly one
/// method; an overloaded name is refused with the candidates' tokens. The page starts `offset` instructions in,
/// or, given `at` instead, at the instruction containing that IL byte offset (the `IL_xxxx` label numbering).
#[derive(Debug, Default, Clone)]
pub struct DotNetIlQuery {
    pub method: String,
    /// Instructions to skip: an instruction index, not an IL byte offset.
    pub offset: Option<usize>,
    pub limit: Option<usize>,
    /// The IL byte offset to start the page at; see [`parse_il_offset`].
    pub at: Option<u32>,
}

/// An IL byte offset as an ILDasm label (`IL_0042`, hex), hex with `0x`, or decimal.
pub fn parse_il_offset(text: &str) -> Result<u32, String> {
    let text = text.trim();
    let hex = ["IL_", "il_", "0x", "0X"].iter().find_map(|prefix| text.strip_prefix(prefix));
    let parsed = match hex {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|_| format!("`{text}` is not an IL offset (IL_0042, 0x42 or 66)"))
}

/// The index of the instruction that holds IL byte `at`, which must lie within the body's `code_size` bytes.
fn instruction_at(instructions: &[Instruction], at: u32, code_size: u32) -> Result<usize, ApiError> {
    if at >= code_size {
        return Err(ApiError::Invalid(format!("IL_{at:04x} is past the end of the {code_size}-byte body")));
    }
    Ok(instructions.partition_point(|instruction| instruction.offset <= at).saturating_sub(1))
}

/// A method's CIL: its header facts, its locals (up to a text cap), its exception clauses, and one page of its
/// instructions.
#[derive(Debug, Serialize)]
pub struct DotNetIl {
    pub token: u32,
    /// `Namespace.Type::Name`.
    pub method: String,
    pub signature: String,
    pub rva: u32,
    pub body: IlBody,
    pub init_locals: bool,
    /// Local variable types by index (`V_0`, `V_1`, ...), up to 64 KiB of type text.
    pub locals: Vec<String>,
    /// Locals the method declares, listed or not.
    pub locals_total: usize,
    /// Whether `locals` stops before `locals_total`.
    pub locals_truncated: bool,
    pub exception_clauses: Vec<ExceptionClause>,
    pub instructions: Page<Instruction>,
    /// Whether the listing stops before the end of the body (instruction cap, cut-off operand, short body).
    pub truncated: bool,
    pub warnings: Vec<String>,
}

/// A MethodDef token in hex (`0x...`) or decimal, else a method name.
fn method_selector(method: &str) -> MethodSelector<'_> {
    let token = match method.strip_prefix("0x").or_else(|| method.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => method.parse().ok(),
    };
    token.map_or(MethodSelector::Name(method), MethodSelector::Token)
}

impl Project {
    /// The CIL of one managed method, or `None` when the image has no CLI header.
    pub fn dotnet_il(&self, query: &DotNetIlQuery) -> Result<Option<DotNetIl>, ApiError> {
        let method = query.method.trim();
        if method.is_empty() {
            return Err(ApiError::Invalid("method is required: a MethodDef token or Type::Method name".to_owned()));
        }
        if query.at.is_some() && query.offset.is_some() {
            return Err(ApiError::Invalid(
                "give offset (an instruction index) or at (an IL offset), not both".to_owned(),
            ));
        }
        let listing = dotnet::method_il(&self.binary, method_selector(method)).map_err(|error| match error {
            IlError::Load(error) => ApiError::Invalid(format!("malformed .NET metadata: {error}")),
            IlError::NotFound(_) => ApiError::NotFound(error.to_string()),
            _ => ApiError::Invalid(error.to_string()),
        })?;
        let Some(il) = listing else { return Ok(None) };
        let offset = match query.at {
            Some(at) => Some(instruction_at(&il.instructions, at, il.body.code_size)?),
            None => query.offset,
        };
        Ok(Some(DotNetIl {
            token: il.token,
            method: il.method,
            signature: il.signature,
            rva: il.rva,
            body: il.body,
            init_locals: il.init_locals,
            locals: il.locals,
            locals_total: il.locals_total,
            locals_truncated: il.locals_truncated,
            exception_clauses: il.exception_clauses,
            instructions: Page::of(il.instructions, offset, query.limit),
            truncated: il.truncated,
            warnings: il.warnings,
        }))
    }

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
            properties: metadata.types.iter().map(|ty| ty.properties.len()).sum(),
            events: metadata.types.iter().map(|ty| ty.events.len()).sum(),
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
                    matcher.matches(&ty.full_name())
                        || ty.methods.iter().any(|method| matcher.matches(&method.name))
                        || ty.properties.iter().any(|property| matcher.matches(&property.name))
                        || ty.events.iter().any(|event| matcher.matches(&event.name))
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
