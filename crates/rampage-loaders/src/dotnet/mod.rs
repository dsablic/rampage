//! Reads .NET (ECMA-335 CLI) metadata from a managed PE image: the CLI header, the metadata root and its
//! streams, and the tables that name the assembly, its references, types, fields and methods.
//!
//! Method bodies of a managed assembly are CIL bytecode, not native code. Nothing here becomes a native
//! function start, symbol or analysis seed: discovery would otherwise disassemble IL as x86 or ARM. Methods
//! whose implementation flags mark them native (mixed-mode C++/CLI) are reported as [`BodyKind::Native`] so a
//! caller can see them, but they are still not seeded. The result is computed on demand by [`metadata`] and
//! never stored on [`Binary`].
//!
//! This is a bounded reader of untrusted input: it never panics, caps row counts at the 24-bit token limit,
//! caps string and literal lengths, checks every heap offset and table index, and turns inconsistencies into
//! warnings and partial results. Only an image that claims to be managed but whose CLI header or metadata root
//! cannot be read is an error.
//!
//! Method, field, property and member-reference signatures and event types are rendered as ILAsm-style text.
//! Properties and events include bounded MethodSemantics bindings; P/Invoke imports come from ImplMap.
//! Custom attributes decode fixed and named primitive/string/type arguments, single-dimensional arrays and enums
//! verified in this image. External enum underlying types remain unknown. Resource rows describe metadata links
//! and embedded location readability only; resource lengths, payloads and boxed attribute arguments are not decoded.
//!
//! [`method_il`] disassembles one method's CIL on request, with its locals and exception clauses; that is a
//! listing for a reader, never a source of native analysis.

mod heaps;
mod il;
mod signatures;
mod tables;

use std::cell::Cell;
use std::collections::HashMap;

use object::LittleEndian as LE;
use object::read::pe::{ImageNtHeaders, PeFile};
use rampage_arch::bytes::read_uint;
use serde::Serialize;

use crate::warnings::CappedWarnings;
use crate::{Binary, Format, LoadError};
use heaps::Heaps;
pub use il::{
    ClauseKind, ExceptionClause, IlError, Instruction, MAX_INSTRUCTIONS, MAX_LOCALS_TEXT, MethodIl, MethodSelector,
};
pub use signatures::UNREADABLE;
use signatures::{Generics, Reader};
use tables::{Coded as C, Tables};

const WARNINGS: CappedWarnings = CappedWarnings::new(256, ".NET metadata");
const MAX_STREAMS: usize = 64;
/// II.24.2.1: the version string length is at most 255 bytes, rounded up to a multiple of four.
const MAX_VERSION_BYTES: usize = 256;
const METADATA_SIGNATURE: u32 = 0x424A_5342;
/// Enclosing types prefixed to a nested type's name; deeper (or cyclic) nesting is cut off.
const MAX_NESTING: u32 = 16;
const MAX_NESTED_CLASS_ROWS: u32 = 100_000;
/// Reserve both decoded row indexes before reading a NestedClass row or updating its enclosing map.
const NESTED_CLASS_ROW_WORK: usize = 8;
const NESTING_ROW_LIMIT: &str =
    "NestedClass row limit exceeded; nesting not rendered and serialized enum names unavailable";
const NESTING_ROW_UNREADABLE: &str =
    "NestedClass row unreadable; nesting not rendered and serialized enum names unavailable";
const MAX_MEMBER_ACCESSORS: usize = 64;
const BUDGET_EXHAUSTED: &str = "signature text budget exhausted; remaining signatures not rendered";
pub const MAX_RESOURCE_ROWS: u32 = 100_000;
pub const MAX_RESOURCE_TEXT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_ENUM_CONSTANT_ROWS: u32 = 100_000;
pub const MAX_ENUM_CONSTANTS: usize = 10_000;
pub const MAX_ENUM_CONSTANT_WORK_BYTES: usize = 4 * 1024 * 1024;
const RESOURCE_NAME_TRUNCATED: &str = "<truncated>";

/// CLI header flags (II.25.3.3.1).
const COMIMAGE_FLAGS_NATIVE_ENTRYPOINT: u32 = 0x10;
const CLI_FLAG_NAMES: [(u32, &str); 6] = [
    (0x0000_0001, "il_only"),
    (0x0000_0002, "32bit_required"),
    (0x0000_0004, "il_library"),
    (0x0000_0008, "strong_name_signed"),
    (COMIMAGE_FLAGS_NATIVE_ENTRYPOINT, "native_entry_point"),
    (0x0002_0000, "32bit_preferred"),
];

/// MethodImplAttributes code type (II.23.1.10).
const CODE_TYPE_MASK: u16 = 0x0003;
const CODE_TYPE_NATIVE: u16 = 0x0001;
const CODE_TYPE_RUNTIME: u16 = 0x0003;
/// AssemblyFlags.PublicKey (II.23.1.2): the blob holds the full key rather than its 8-byte token.
const ASSEMBLY_FLAG_PUBLIC_KEY: u32 = 0x0001;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DotNetMetadata {
    pub cli: CliHeader,
    /// The metadata root's version string, the runtime the assembly was built against (e.g. `v4.0.30319`).
    pub runtime_version: String,
    pub streams: Vec<Stream>,
    pub module: Option<Module>,
    /// `None` for a netmodule, which has no Assembly row.
    pub assembly: Option<Assembly>,
    pub assembly_refs: Vec<AssemblyRef>,
    pub entry_point: Option<EntryPoint>,
    pub types: Vec<TypeDef>,
    pub type_refs: Vec<TypeRef>,
    pub member_refs: Vec<MemberRef>,
    /// Methods implemented in a native DLL (P/Invoke), from ImplMap.
    pub pinvokes: Vec<PInvoke>,
    pub custom_attributes: Vec<CustomAttribute>,
    pub resources: Vec<ManifestResource>,
    pub resource_counts: ResourceCounts,
    /// Literals from `#US` (what `ldstr` loads), capped.
    pub user_strings: Vec<String>,
    /// Declared row count of each table present, standard or not.
    pub tables: Vec<TableRows>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CliHeader {
    /// Minimum runtime the image needs, from the CLI header (2.5 for anything since .NET 2.0).
    pub runtime_major: u16,
    pub runtime_minor: u16,
    pub flags: u32,
    pub flag_names: Vec<&'static str>,
    /// A MethodDef or File token, or a native RVA when `native_entry_point` is set; 0 when there is none.
    pub entry_point_token: u32,
    pub metadata_rva: u32,
    pub metadata_size: u32,
    pub resources_rva: u32,
    pub resources_size: u32,
    pub strong_name_rva: u32,
    pub strong_name_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Stream {
    pub name: String,
    /// Offset from the metadata root.
    pub offset: u32,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Module {
    pub name: String,
    pub mvid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Assembly {
    pub name: String,
    pub version: String,
    pub culture: String,
    pub flags: u32,
    pub hash_algorithm: u32,
    /// Hex of the full public key, or `None` for an unsigned assembly.
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssemblyRef {
    pub name: String,
    pub version: String,
    pub culture: String,
    pub flags: u32,
    /// Hex of the public key token, or of the full key when `full_public_key` is set.
    pub public_key_or_token: Option<String>,
    pub full_public_key: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ResourceCounts {
    pub declared: u32,
    /// False when the header does not establish a count; `declared` is then only a zero placeholder.
    pub declared_known: bool,
    pub readable: u32,
    pub retained: usize,
    /// Rows or name text were omitted by a bound or a truncated metadata table.
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestResource {
    pub token: u32,
    pub name: Option<String>,
    pub name_truncated: bool,
    pub flags: u32,
    /// Directory-relative location for embedded resources, not a payload size.
    pub offset: u32,
    pub implementation_raw: u32,
    pub implementation: ResourceImplementation,
    pub availability: ResourceAvailability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceImplementation {
    Embedded,
    File {
        row: u32,
        token: Option<u32>,
        status: ResourceReferenceStatus,
        name: Option<String>,
        name_truncated: bool,
        flags: Option<u32>,
    },
    AssemblyRef {
        row: u32,
        token: Option<u32>,
        status: ResourceReferenceStatus,
        name: Option<String>,
        name_truncated: bool,
    },
    ExportedType {
        row: u32,
        token: Option<u32>,
        status: ResourceReferenceStatus,
    },
    Invalid {
        tag: u8,
        row: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceReferenceStatus {
    Readable,
    NullRow,
    OutOfRange,
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceAvailability {
    /// The declared directory must fit one section's backed file span. No length prefix or payload is read.
    Embedded {
        rva: Option<u32>,
        status: EmbeddedResourceStatus,
    },
    /// A metadata-only File/AssemblyRef link; the target is not resolved or read.
    External,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddedResourceStatus {
    ReadableLocation,
    DirectoryAbsent,
    DirectoryOverflow,
    OutsideDirectory,
    RvaOverflow,
    Unmapped,
    DirectoryUnreadable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntryPoint {
    /// A managed method; `method` is `Namespace.Type::Name` when the token resolves.
    Method { token: u32, method: Option<String> },
    /// An entry point in another module of a multi-module assembly.
    File { token: u32 },
    /// A native entry point RVA (mixed-mode images with `native_entry_point`).
    Native { rva: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TypeDef {
    pub token: u32,
    pub namespace: String,
    pub name: String,
    /// TypeAttributes (II.23.1.15).
    pub flags: u32,
    /// The base type's full name; `None` for interfaces and `System.Object`.
    pub extends: Option<String>,
    /// Token of the enclosing type for a nested type.
    pub enclosing: Option<u32>,
    pub fields: Vec<FieldDef>,
    pub methods: Vec<MethodDef>,
    pub properties: Vec<PropertyDef>,
    pub events: Vec<EventDef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventDef {
    pub token: u32,
    pub name: String,
    /// EventAttributes (II.23.1.4), retained even when the type is unreadable.
    pub flags: u16,
    /// The EventType TypeDefOrRef, including a bounded TypeSpec in the owning type's generic context.
    pub event_type: String,
    /// Up to 64 distinct add/remove/fire/other bindings to methods declared by the same type.
    /// These report MethodSemantics rows, not inferred behavior or validated method signatures.
    pub accessors: Vec<EventAccessor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EventAccessor {
    /// MethodSemanticsAttributes: 8 add, 16 remove, 32 fire or 4 other (II.23.1.12).
    pub semantics: u16,
    pub method_token: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PropertyDef {
    pub token: u32,
    pub name: String,
    /// PropertyAttributes (II.23.1.14), retained even when the signature is unreadable.
    pub flags: u16,
    /// Type, name and index parameter types, prefixed with `instance` when HASTHIS is set.
    pub signature: String,
    /// Up to 64 distinct getter/setter/other bindings to methods declared by the same type.
    /// These report MethodSemantics rows, not inferred accessors or validated method signatures.
    pub accessors: Vec<PropertyAccessor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PropertyAccessor {
    /// MethodSemanticsAttributes: 1 setter, 2 getter or 4 other (II.23.1.12).
    pub semantics: u16,
    pub method_token: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldDef {
    pub token: u32,
    pub name: String,
    /// FieldAttributes (II.23.1.5).
    pub flags: u16,
    /// The field's type and name, e.g. `uint32 _queue1`, or `<unreadable>` for a malformed signature blob.
    pub signature: String,
    /// Exact Constant-table evidence for a literal declared by a verified local enum, not a runtime value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_constant: Option<EnumConstant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnumConstant {
    /// IL integral type verified from the enum's sole instance field, `value__`.
    pub underlying_integral_type: &'static str,
    /// Decimal integer text, including the full unsigned 64-bit range; never a JSON number.
    pub value: String,
}

impl TypeDef {
    /// `Namespace.Name`, or just `Name` for a type in the global namespace.
    pub fn full_name(&self) -> String {
        qualified_name(&self.namespace, &self.name)
    }
}

/// `namespace.name`, or `name` when the namespace is empty.
fn qualified_name(namespace: &str, name: &str) -> String {
    if namespace.is_empty() { name.to_owned() } else { format!("{namespace}.{name}") }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MethodDef {
    pub token: u32,
    pub name: String,
    /// Return type, name, generic parameters and parameter types, e.g. `int32 Combine<T1>(T1)`, prefixed with
    /// `instance` for a method with `this`; `<unreadable>` for a malformed signature blob.
    pub signature: String,
    /// RVA of the method body; 0 for abstract, P/Invoke and runtime-provided methods.
    pub rva: u32,
    /// MethodAttributes (II.23.1.10).
    pub flags: u16,
    /// MethodImplAttributes (II.23.1.10).
    pub impl_flags: u16,
    pub body: BodyKind,
    /// The IL body header, read when the body is IL and its RVA maps into the image.
    pub il: Option<IlBody>,
    /// Parameter names in sequence order (the return value's row, sequence 0, is omitted).
    pub params: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyKind {
    /// CIL bytecode at `rva`; never native code.
    Il,
    /// Native code at `rva` (mixed-mode); reported, not seeded.
    Native,
    /// Supplied by the runtime (delegates and other `runtime` methods).
    Runtime,
    /// No body: abstract, extern, P/Invoke or internal call.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IlHeader {
    Tiny,
    Fat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct IlBody {
    pub header: IlHeader,
    /// Bytes of the header before the IL: 1 for tiny, usually 12 for fat.
    pub header_size: u32,
    pub code_size: u32,
    pub max_stack: u16,
    /// StandAloneSig token of the locals signature; 0 when there are no locals.
    pub local_var_sig_token: u32,
    /// Whether extra data sections (exception clauses) follow the code.
    pub more_sections: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TypeRef {
    pub token: u32,
    pub namespace: String,
    pub name: String,
    /// The assembly, module or enclosing type the reference resolves through.
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemberRef {
    pub token: u32,
    /// The type (or module, or method) the member belongs to.
    pub parent: Option<String>,
    pub name: String,
    /// The referenced method or field as text; `<unreadable>` for a malformed signature blob.
    pub signature: String,
}

/// A method whose body is an export of a native DLL (II.22.22).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PInvoke {
    pub method_token: u32,
    /// `Namespace.Type::Name` of the declaring method, when it resolves.
    pub method: Option<String>,
    /// The ModuleRef name: the DLL as written in the source (`kernel32.dll`, `libc`, ...).
    pub module: Option<String>,
    /// The export imported, which can differ from the method name.
    pub import_name: String,
    /// PInvokeAttributes (II.23.1.8): character set, calling convention, SetLastError.
    pub flags: u16,
}

/// One CustomAttribute row (II.22.10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustomAttribute {
    /// Token of what the attribute is applied to: the assembly, a type, method, field, parameter, ...
    pub parent_token: u32,
    /// The target as text: `Type::member` for a method, field, property or event, `Type::Method/param` for a
    /// parameter, `Owner<T>` for a generic parameter, nested types as `Outer/Inner`.
    pub parent: Option<String>,
    /// The constructor's declaring type, e.g. `System.Runtime.CompilerServices.CompilerGeneratedAttribute`.
    pub attribute_type: Option<String>,
    pub constructor_token: u32,
    /// Fixed constructor values, including arrays and verified local enums; `None` when unreadable/unsupported.
    pub arguments: Option<Vec<String>>,
    /// Named field/property values; `None` when the fixed or named portion cannot be decoded completely.
    pub named_arguments: Option<Vec<NamedArgument>>,
    /// Why some arguments are unavailable, including unknown external enum underlying types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments_error: Option<String>,
    /// Bytes in the attribute's value blob.
    pub blob_length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NamedArgument {
    pub kind: NamedArgumentKind,
    pub name: String,
    pub argument_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NamedArgumentKind {
    Field,
    Property,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TableRows {
    pub table: String,
    pub rows: u32,
}

/// Collected diagnostics, capped so hostile input cannot grow them without bound.
#[derive(Debug, Default)]
struct Warnings(Vec<String>);

impl Warnings {
    fn push(&mut self, warning: String) {
        WARNINGS.push(&mut self.0, warning);
    }
}

/// The .NET metadata of a loaded image, or `None` when it is not a managed PE (any ELF, Mach-O, snapshot, or a
/// PE without a CLI header). Errors only when the image declares a CLI header that cannot be read.
pub fn metadata(binary: &Binary) -> Result<Option<DotNetMetadata>, LoadError> {
    if binary.format != Format::Pe {
        return Ok(None);
    }
    parse_image(binary.image_bytes())
}

/// [`metadata`] for raw PE file bytes.
pub fn parse_image(image: &[u8]) -> Result<Option<DotNetMetadata>, LoadError> {
    parse_image_with(image, &mut |_, _, _| {})
}

/// The CIL listing of one method, or `None` when the image is not a managed PE.
pub fn method_il(binary: &Binary, method: MethodSelector) -> Result<Option<MethodIl>, IlError> {
    if binary.format != Format::Pe {
        return Ok(None);
    }
    image_method_il(binary.image_bytes(), method)
}

/// [`method_il`] for raw PE file bytes.
pub fn image_method_il(image: &[u8], method: MethodSelector) -> Result<Option<MethodIl>, IlError> {
    let mut listing = None;
    let parsed = parse_image_with(image, &mut |decoder, metadata, read_rva| {
        listing = Some(il::disassemble(decoder, metadata, read_rva, method));
    })?;
    match (parsed, listing) {
        (None, _) => Ok(None),
        (Some(_), Some(listing)) => listing.map(Some),
        (Some(metadata), None) => Err(IlError::Unreadable {
            method: method.to_string(),
            reason: format!("the metadata tables are unreadable: {}", metadata.warnings.join("; ")),
        }),
    }
}

/// Called with the decoded metadata while its tables are still open, and with the image's RVA reader.
type Visit<'v, 'a> = &'v mut dyn FnMut(&Decoder, &DotNetMetadata, &dyn Fn(u32) -> Option<&'a [u8]>);

fn parse_image_with<'a>(image: &'a [u8], visit: Visit<'_, 'a>) -> Result<Option<DotNetMetadata>, LoadError> {
    match object::FileKind::parse(image) {
        Ok(object::FileKind::Pe32) => from_pe::<object::pe::ImageNtHeaders32>(image, visit),
        Ok(object::FileKind::Pe64) => from_pe::<object::pe::ImageNtHeaders64>(image, visit),
        _ => Ok(None),
    }
}

fn from_pe<'a, Pe: ImageNtHeaders>(image: &'a [u8], visit: Visit<'_, 'a>) -> Result<Option<DotNetMetadata>, LoadError> {
    let file = PeFile::<Pe>::parse(image)?;
    let Some(directory) = file.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) else {
        return Ok(None);
    };
    let rva = directory.virtual_address.get(LE);
    if rva == 0 || directory.size.get(LE) == 0 {
        return Ok(None);
    }
    let sections = file.section_table();
    let read_rva = |rva: u32| sections.pe_data_at(image, rva);
    let mut metadata = parse_cli(rva, &read_rva, visit)?;
    let directory_status = |rva: u32, size: u32| {
        let Some((offset, remaining)) = sections.pe_file_range_at(rva) else {
            return EmbeddedResourceStatus::Unmapped;
        };
        if size > remaining || u64::from(offset) + u64::from(size) > image.len() as u64 {
            EmbeddedResourceStatus::DirectoryUnreadable
        } else {
            EmbeddedResourceStatus::ReadableLocation
        }
    };
    read_resource_locations(&mut metadata, &directory_status);
    Ok(Some(metadata))
}

/// Parses everything reachable from the CLI header at `cli_rva`. `read_rva` returns the file bytes from an RVA
/// to the end of its section.
fn parse_cli<'a>(
    cli_rva: u32,
    read_rva: &dyn Fn(u32) -> Option<&'a [u8]>,
    visit: Visit<'_, 'a>,
) -> Result<DotNetMetadata, LoadError> {
    let malformed = |what: &str| LoadError::Malformed(format!(".NET {what}"));
    // II.25.3.3: the CLI header is 72 bytes.
    let header =
        read_rva(cli_rva).filter(|bytes| bytes.len() >= 72).ok_or_else(|| malformed("CLI header is unmapped"))?;
    let field = |offset| read_u32(header, offset).unwrap_or(0);
    let flags = field(16);
    let cli = CliHeader {
        runtime_major: read_u16(header, 4).unwrap_or(0),
        runtime_minor: read_u16(header, 6).unwrap_or(0),
        flags,
        flag_names: CLI_FLAG_NAMES.iter().filter(|(bit, _)| flags & bit != 0).map(|&(_, name)| name).collect(),
        entry_point_token: field(20),
        metadata_rva: field(8),
        metadata_size: field(12),
        resources_rva: field(24),
        resources_size: field(28),
        strong_name_rva: field(32),
        strong_name_size: field(36),
    };

    let mut warnings = Warnings::default();
    let mapped = read_rva(cli.metadata_rva).ok_or_else(|| malformed("metadata root is unmapped"))?;
    let wanted = usize::try_from(cli.metadata_size).unwrap_or(usize::MAX);
    if mapped.len() < wanted {
        warnings.push(format!("metadata declares {wanted} bytes but only {} are mapped", mapped.len()));
    }
    let root = &mapped[..mapped.len().min(wanted)];
    let mut metadata = parse_root(root, cli, warnings, &mut |decoder, metadata| visit(decoder, metadata, read_rva))?;
    read_bodies(&mut metadata, read_rva);
    Ok(metadata)
}

/// Reads each IL method's body header. Only the header is read; the IL itself is never decoded or seeded.
fn read_bodies<'a>(metadata: &mut DotNetMetadata, read_rva: &dyn Fn(u32) -> Option<&'a [u8]>) {
    let mut warnings = Warnings(std::mem::take(&mut metadata.warnings));
    for method in metadata.types.iter_mut().flat_map(|ty| ty.methods.iter_mut()) {
        if method.body != BodyKind::Il {
            continue;
        }
        let Some(bytes) = read_rva(method.rva) else {
            warnings.push(format!("method {:#010x} body RVA {:#x} is unmapped", method.token, method.rva));
            continue;
        };
        match il_body(bytes) {
            Some(body) => {
                let end = u64::from(body.header_size) + u64::from(body.code_size);
                if end > bytes.len() as u64 {
                    warnings.push(format!("method {:#010x} IL body overruns its section", method.token));
                }
                method.il = Some(body);
            }
            None => warnings.push(format!("method {:#010x} has an invalid IL body header", method.token)),
        }
    }
    metadata.warnings = warnings.0;
}

fn read_resource_locations(
    metadata: &mut DotNetMetadata,
    directory_status: &dyn Fn(u32, u32) -> EmbeddedResourceStatus,
) {
    let mut warnings = Warnings(std::mem::take(&mut metadata.warnings));
    let cli = &metadata.cli;
    let mapped = directory_status(cli.resources_rva, cli.resources_size);
    for resource in &mut metadata.resources {
        if resource.implementation != ResourceImplementation::Embedded {
            continue;
        }
        let rva = (cli.resources_rva != 0).then(|| cli.resources_rva.checked_add(resource.offset)).flatten();
        let status = if cli.resources_rva == 0 || cli.resources_size == 0 {
            EmbeddedResourceStatus::DirectoryAbsent
        } else if rva.is_none() {
            EmbeddedResourceStatus::RvaOverflow
        } else if cli.resources_rva.checked_add(cli.resources_size).is_none() {
            EmbeddedResourceStatus::DirectoryOverflow
        } else if resource.offset >= cli.resources_size {
            EmbeddedResourceStatus::OutsideDirectory
        } else {
            mapped
        };
        if status != EmbeddedResourceStatus::ReadableLocation {
            warnings.push(format!("ManifestResource {:#010x}: embedded location {status:?}", resource.token));
        }
        resource.availability = ResourceAvailability::Embedded { rva, status };
    }
    metadata.warnings = warnings.0;
}

/// Decodes a method body header (II.25.4.2 tiny, II.25.4.3 fat).
fn il_body(bytes: &[u8]) -> Option<IlBody> {
    let first = *bytes.first()?;
    match first & 0x03 {
        0x02 => Some(IlBody {
            header: IlHeader::Tiny,
            header_size: 1,
            code_size: u32::from(first >> 2),
            max_stack: 8,
            local_var_sig_token: 0,
            more_sections: false,
        }),
        0x03 => {
            let flags = read_u16(bytes, 0)?;
            // The high nibble is the header size in 4-byte units; the fat header is 12 bytes, so it is 3.
            let dwords = u32::from(flags >> 12);
            if dwords < 3 {
                return None;
            }
            Some(IlBody {
                header: IlHeader::Fat,
                header_size: dwords * 4,
                code_size: read_u32(bytes, 4)?,
                max_stack: read_u16(bytes, 2)?,
                local_var_sig_token: read_u32(bytes, 8)?,
                more_sections: flags & 0x08 != 0,
            })
        }
        _ => None,
    }
}

/// Parses the metadata root (II.24.2.1), its stream headers (II.24.2.2), and the tables.
/// `visit` sees the decoded metadata while its tables are open; it is not called when they are unreadable.
fn parse_root(
    root: &[u8],
    cli: CliHeader,
    mut warnings: Warnings,
    visit: &mut dyn FnMut(&Decoder, &DotNetMetadata),
) -> Result<DotNetMetadata, LoadError> {
    let malformed = |what: &str| LoadError::Malformed(format!(".NET metadata root {what}"));
    if read_u32(root, 0) != Some(METADATA_SIGNATURE) {
        return Err(malformed("has no BSJB signature"));
    }
    let version_length = read_u32(root, 12).ok_or_else(|| malformed("is truncated"))?;
    let version_length = usize::try_from(version_length).unwrap_or(usize::MAX);
    if version_length > MAX_VERSION_BYTES {
        return Err(malformed("version string is too long"));
    }
    let version = root.get(16..16 + version_length).ok_or_else(|| malformed("is truncated"))?;
    let version_end = version.iter().position(|&byte| byte == 0).unwrap_or(version.len());
    let runtime_version = String::from_utf8_lossy(&version[..version_end]).into_owned();
    // The version length is meant to be a multiple of 4, but the CLR rounds up rather than rejecting it.
    let flags_offset = 16 + version_length.next_multiple_of(4);
    let stream_count = read_u16(root, flags_offset + 2).ok_or_else(|| malformed("is truncated"))?;

    let mut streams = Vec::new();
    let mut table_stream: Option<&[u8]> = None;
    let [mut strings, mut user_strings, mut guids, mut blobs] = [None; 4];
    let (mut uncompressed, mut jtd) = (false, false);
    let mut cursor = flags_offset + 4;
    for _ in 0..usize::from(stream_count).min(MAX_STREAMS) {
        let (Some(offset), Some(size)) = (read_u32(root, cursor), read_u32(root, cursor + 4)) else {
            warnings.push("stream headers are truncated".to_owned());
            break;
        };
        let name_area = root.get(cursor + 8..).unwrap_or_default();
        // II.24.2.2: the name is NUL-terminated, at most 32 bytes, padded to a 4-byte boundary.
        let Some(name_length) = name_area.iter().take(32).position(|&byte| byte == 0) else {
            warnings.push("stream header name is unterminated".to_owned());
            break;
        };
        let name = String::from_utf8_lossy(&name_area[..name_length]).into_owned();
        cursor += 8 + (name_length + 1).next_multiple_of(4);

        let data = usize::try_from(offset)
            .ok()
            .zip(usize::try_from(size).ok())
            .and_then(|(start, size)| root.get(start..start.checked_add(size)?));
        streams.push(Stream { name: name.clone(), offset, size });
        let Some(data) = data else {
            warnings.push(format!("stream {name} lies outside the metadata"));
            continue;
        };
        let slot = match name.as_str() {
            "#~" | "#-" => {
                uncompressed = name == "#-";
                &mut table_stream
            }
            // dnlib, following the CLR's minimal-delta handling, makes every index 4 bytes when it is present.
            "#JTD" => {
                jtd = true;
                continue;
            }
            "#Strings" => &mut strings,
            "#US" => &mut user_strings,
            "#GUID" => &mut guids,
            "#Blob" => &mut blobs,
            _ => continue,
        };
        // The CLR, and dnlib after it, reads the last of duplicate streams; obfuscators plant decoy earlier copies.
        if slot.replace(data).is_some() {
            warnings.push(format!("duplicate stream {name}; the last one is used"));
        }
    }
    if usize::from(stream_count) > MAX_STREAMS {
        warnings.push(format!("{stream_count} streams declared; only the first {MAX_STREAMS} are read"));
    }

    let heaps = Heaps {
        strings: strings.unwrap_or_default(),
        user_strings: user_strings.unwrap_or_default(),
        guids: guids.unwrap_or_default(),
        blobs: blobs.unwrap_or_default(),
    };
    let (user_strings, complete) = heaps.user_string_literals();
    if !complete {
        warnings.push(format!("#US heap is malformed or exceeds {} literals; truncated", heaps::MAX_USER_STRINGS));
    }
    let mut metadata = DotNetMetadata {
        cli,
        runtime_version,
        streams,
        module: None,
        assembly: None,
        assembly_refs: Vec::new(),
        entry_point: None,
        types: Vec::new(),
        type_refs: Vec::new(),
        member_refs: Vec::new(),
        pinvokes: Vec::new(),
        custom_attributes: Vec::new(),
        resources: Vec::new(),
        resource_counts: ResourceCounts { truncated: true, ..ResourceCounts::default() },
        user_strings,
        tables: Vec::new(),
        warnings: Vec::new(),
    };
    match table_stream {
        Some(stream) => match Tables::parse(stream, uncompressed && jtd, &mut warnings) {
            Some(tables) => {
                let mut decoder = Decoder::new(&tables, heaps, &mut warnings);
                decoder.decode(&mut metadata);
                // The visitor gets a budget of its own: a metadata-heavy image must not leave it nothing.
                decoder.budget.set(signatures::TOTAL_BUDGET);
                decoder.budget_reported = false;
                visit(&decoder, &metadata);
            }
            None => {
                if let Some(declared) = Tables::declared_count(stream, tables::MANIFEST_RESOURCE) {
                    metadata.resource_counts.declared = declared;
                    metadata.resource_counts.declared_known = true;
                    warnings
                        .push("ManifestResource declared count recovered from an incomplete table header".to_owned());
                }
                warnings.push("table stream header is unreadable".to_owned());
            }
        },
        None => warnings.push("metadata has no #~ table stream".to_owned()),
    }
    metadata.warnings = warnings.0;
    Ok(metadata)
}

struct Decoder<'t, 'a> {
    tables: &'t Tables<'a>,
    heaps: Heaps<'a>,
    warnings: &'t mut Warnings,
    /// GenericParam `(number, name)` rows by owning TypeDef or MethodDef, sorted by number: the first row of
    /// each number below the arity cap, so a hostile table cannot make a lookup scan its rows.
    generic_params: HashMap<(u8, u32), Vec<(u32, String)>>,
    /// Signature work (text rendered, blob bytes read) left for this image.
    budget: Cell<usize>,
    /// Whether the warning that the budget ran out has been given; it is given once, not per signature.
    budget_reported: bool,
    /// The enclosing TypeDef row of each nested TypeDef row, from NestedClass.
    enclosing: HashMap<u32, u32>,
    /// A bounded initial scan must finish before any later index can claim unique serialized names.
    enclosing_complete: bool,
    /// The owning MethodDef row of each Param row, filled in as the methods are decoded.
    param_methods: HashMap<u32, u32>,
    member_types: MemberTypes,
    enum_underlying: HashMap<u32, u8>,
    named_enums: HashMap<String, Option<u8>>,
    enum_constants: HashMap<u32, EnumConstant>,
}

/// `Namespace.Type::member` for each method and field token.
type MemberOwners = HashMap<u32, String>;
/// Owning TypeDef row by `(table, row)` of a mapped Property or Event.
type MemberTypes = HashMap<(u8, u32), u32>;

struct ResourceBudget {
    remaining: usize,
    exhausted: bool,
}

fn charge_enum_work(budget: &Cell<usize>, bytes: usize) -> Option<()> {
    let left = budget.get().checked_sub(bytes);
    budget.set(left.unwrap_or(0));
    left.map(|_| ())
}

fn read_enclosing_types(
    rows: u32,
    budget: &Cell<usize>,
    mut read: impl FnMut(u32) -> Option<(u32, u32)>,
) -> Result<HashMap<u32, u32>, &'static str> {
    if rows > MAX_NESTED_CLASS_ROWS {
        return Err(NESTING_ROW_LIMIT);
    }
    let mut enclosing = HashMap::new();
    for row in 1..=rows {
        charge_enum_work(budget, NESTED_CLASS_ROW_WORK).ok_or(BUDGET_EXHAUSTED)?;
        let (nested, outer) = read(row).ok_or(NESTING_ROW_UNREADABLE)?;
        enclosing.insert(nested, outer);
    }
    Ok(enclosing)
}

impl ResourceBudget {
    fn charge(&mut self, bytes: usize) -> bool {
        match self.remaining.checked_sub(bytes) {
            Some(left) => {
                self.remaining = left;
                true
            }
            None => {
                self.remaining = 0;
                self.exhausted = true;
                false
            }
        }
    }
}

impl signatures::Resolve for Decoder<'_, '_> {
    fn type_name(&self, table: u8, row: u32) -> Option<String> {
        matches!(table, tables::TYPE_DEF | tables::TYPE_REF).then(|| self.row_label(table, row))?
    }

    fn type_spec(&self, row: u32) -> Option<&[u8]> {
        self.heaps.blob(self.tables.cell(tables::TYPE_SPEC, row, 0)?)
    }

    fn enum_underlying(&self, table: u8, row: u32) -> Option<u8> {
        (table == tables::TYPE_DEF).then(|| self.enum_underlying.get(&row).copied())?
    }

    fn named_enum_underlying(&self, name: &str) -> Option<u8> {
        self.named_enums.get(name).copied().flatten()
    }
}

impl<'t, 'a> Decoder<'t, 'a> {
    fn new(tables: &'t Tables<'a>, heaps: Heaps<'a>, warnings: &'t mut Warnings) -> Self {
        Self::with_budget(tables, heaps, warnings, signatures::TOTAL_BUDGET)
    }

    fn with_budget(
        tables: &'t Tables<'a>,
        heaps: Heaps<'a>,
        warnings: &'t mut Warnings,
        initial_budget: usize,
    ) -> Self {
        let budget = Cell::new(initial_budget);
        let mut generic_params: HashMap<_, Vec<_>> = HashMap::new();
        let table = tables::GENERIC_PARAM;
        for row in 1..=tables.rows(table) {
            let owner = tables.cell(table, row, 2).and_then(|value| C::TypeOrMethodDef.decode(value));
            let number = tables.cell(table, row, 0).filter(|&number| number < signatures::MAX_ARITY);
            let (Some(number), Some(owner)) = (number, owner) else { continue };
            let params: &mut Vec<_> = generic_params.entry(owner).or_default();
            if params.iter().all(|&(seen, _)| seen != number) {
                let name = tables.cell(table, row, 3).and_then(|offset| heaps.string(offset)).unwrap_or_default();
                params.push((number, name));
            }
        }
        for params in generic_params.values_mut() {
            params.sort_unstable_by_key(|&(number, _)| number);
        }
        let mut budget_reported = false;
        let (enclosing, enclosing_complete) =
            match read_enclosing_types(tables.rows(tables::NESTED_CLASS), &budget, |row| {
                Some((tables.cell(tables::NESTED_CLASS, row, 0)?, tables.cell(tables::NESTED_CLASS, row, 1)?))
            }) {
                Ok(enclosing) => {
                    (enclosing, tables.rows(tables::NESTED_CLASS) == tables.declared[usize::from(tables::NESTED_CLASS)])
                }
                Err(warning) => {
                    warnings.push(warning.to_owned());
                    budget_reported = warning == BUDGET_EXHAUSTED;
                    (HashMap::new(), false)
                }
            };
        Self {
            tables,
            heaps,
            warnings,
            generic_params,
            budget,
            budget_reported,
            enclosing,
            enclosing_complete,
            param_methods: HashMap::new(),
            member_types: HashMap::new(),
            enum_underlying: HashMap::new(),
            named_enums: HashMap::new(),
            enum_constants: HashMap::new(),
        }
    }
}

impl Decoder<'_, '_> {
    fn decode(&mut self, metadata: &mut DotNetMetadata) {
        metadata.tables = (0..64u8)
            .filter(|&id| self.tables.declared[usize::from(id)] > 0)
            .map(|id| TableRows {
                table: tables::TABLE_NAMES
                    .get(usize::from(id))
                    .map_or_else(|| format!("0x{id:02x}"), |n| n.to_string()),
                rows: self.tables.declared[usize::from(id)],
            })
            .collect();

        metadata.module = (self.tables.rows(tables::MODULE) > 0).then(|| Module {
            name: self.string(tables::MODULE, 1, 1),
            mvid: self.tables.cell(tables::MODULE, 1, 2).and_then(|index| self.heaps.guid(index)),
        });
        metadata.assembly = (self.tables.rows(tables::ASSEMBLY) > 0).then(|| self.assembly());
        metadata.assembly_refs =
            (1..=self.tables.rows(tables::ASSEMBLY_REF)).map(|row| self.assembly_ref(row)).collect();
        metadata.type_refs = (1..=self.tables.rows(tables::TYPE_REF)).map(|row| self.type_ref(row)).collect();
        metadata.member_refs = (1..=self.tables.rows(tables::MEMBER_REF)).map(|row| self.member_ref(row)).collect();
        metadata.types = self.types();
        let owners = member_owners(&metadata.types, |row| self.row_label(tables::TYPE_DEF, row));
        metadata.pinvokes = self.pinvokes(&owners);
        metadata.custom_attributes = self.custom_attributes(&owners);
        metadata.entry_point = self.entry_point(&metadata.cli, &owners);
        self.resources(metadata);
    }

    fn resources(&mut self, metadata: &mut DotNetMetadata) {
        let table = tables::MANIFEST_RESOURCE;
        let readable = self.tables.rows(table);
        let mut budget = ResourceBudget { remaining: MAX_RESOURCE_TEXT_BYTES, exhausted: false };
        let mut names_truncated = false;
        for row in 1..=readable.min(MAX_RESOURCE_ROWS) {
            if budget.exhausted {
                break;
            }
            let cell = |column| self.tables.cell(table, row, column).unwrap_or(0);
            let (offset, flags, name_index, implementation_raw) = (cell(0), cell(1), cell(2), cell(3));
            let (name, name_truncated) = self.resource_name(name_index, row, "name", &mut budget);
            let (implementation, availability, link_truncated) =
                self.resource_implementation(implementation_raw, row, &mut budget);
            names_truncated |= name_truncated || link_truncated;
            metadata.resources.push(ManifestResource {
                token: token(table, row),
                name,
                name_truncated,
                flags,
                offset,
                implementation_raw,
                implementation,
                availability,
            });
        }
        metadata.resource_counts = ResourceCounts {
            declared: self.tables.declared[usize::from(table)],
            declared_known: true,
            readable,
            retained: metadata.resources.len(),
            truncated: names_truncated
                || budget.exhausted
                || metadata.resources.len() as u32 != self.tables.declared[usize::from(table)],
        };
        if metadata.resources.len() as u32 != readable || budget.exhausted {
            self.warnings.push(format!(
                "ManifestResource inventory budget exhausted: retained {} of {readable} readable rows \
                 (limit {MAX_RESOURCE_ROWS} rows, {MAX_RESOURCE_TEXT_BYTES} name-work bytes)",
                metadata.resources.len()
            ));
        }
    }

    fn resource_name(
        &mut self,
        index: u32,
        row: u32,
        label: &str,
        budget: &mut ResourceBudget,
    ) -> (Option<String>, bool) {
        let invalid = |warnings: &mut Warnings, reason: &str| {
            warnings.push(format!("ManifestResource row {row}: {label} #Strings offset {index:#x} {reason}"));
            (None, false)
        };
        if !budget.charge(1) {
            return (None, true);
        }
        let Some(tail) = usize::try_from(index).ok().and_then(|index| self.heaps.strings.get(index..)) else {
            return invalid(self.warnings, "is outside the heap");
        };
        let mut length = 0;
        let mut terminated = false;
        while length <= heaps::MAX_NAME_BYTES {
            if !budget.charge(1) {
                break;
            }
            match tail.get(length) {
                Some(0) => {
                    terminated = true;
                    break;
                }
                Some(_) if length < heaps::MAX_NAME_BYTES => length += 1,
                Some(_) => break,
                None => return invalid(self.warnings, "is unterminated"),
            }
        }
        let truncated = !terminated;
        let bytes = &tail[..length];
        let text = match std::str::from_utf8(bytes) {
            Ok(text) => text,
            Err(error) if truncated && error.error_len().is_none() => {
                let Ok(text) = std::str::from_utf8(&bytes[..error.valid_up_to()]) else {
                    return invalid(self.warnings, "has invalid UTF-8");
                };
                text
            }
            Err(_) => return invalid(self.warnings, "has invalid UTF-8"),
        };
        if truncated {
            self.warnings.push(format!("ManifestResource row {row}: {label} truncated by the name/work limit"));
            if !budget.charge(RESOURCE_NAME_TRUNCATED.len()) {
                return (None, true);
            }
            (Some(format!("{text}{RESOURCE_NAME_TRUNCATED}")), true)
        } else {
            (Some(text.to_owned()), false)
        }
    }

    fn resource_implementation(
        &mut self,
        raw: u32,
        resource_row: u32,
        budget: &mut ResourceBudget,
    ) -> (ResourceImplementation, ResourceAvailability, bool) {
        if raw == 0 {
            return (
                ResourceImplementation::Embedded,
                ResourceAvailability::Embedded { rva: None, status: EmbeddedResourceStatus::DirectoryAbsent },
                false,
            );
        }
        let Some((table, row)) = C::Implementation.decode(raw) else {
            self.warnings.push(format!("ManifestResource row {resource_row}: reserved Implementation tag {}", raw & 3));
            return (
                ResourceImplementation::Invalid { tag: (raw & 3) as u8, row: raw >> 2 },
                ResourceAvailability::Unavailable,
                false,
            );
        };
        let status = if row == 0 {
            ResourceReferenceStatus::NullRow
        } else if row > tables::MAX_ROWS || row > self.tables.declared[usize::from(table)] {
            ResourceReferenceStatus::OutOfRange
        } else if row > self.tables.rows(table) {
            ResourceReferenceStatus::Unreadable
        } else {
            ResourceReferenceStatus::Readable
        };
        let target_token = matches!(status, ResourceReferenceStatus::Readable | ResourceReferenceStatus::Unreadable)
            .then(|| token(table, row));
        if status != ResourceReferenceStatus::Readable {
            self.warnings.push(format!(
                "ManifestResource row {resource_row}: Implementation {} row {row} is {status:?}",
                tables::TABLE_NAMES[usize::from(table)]
            ));
        }
        if table == tables::EXPORTED_TYPE {
            self.warnings.push(format!(
                "ManifestResource row {resource_row}: ExportedType Implementation is unsupported for resource links"
            ));
            return (
                ResourceImplementation::ExportedType { row, token: target_token, status },
                ResourceAvailability::Unavailable,
                false,
            );
        }
        let (name, name_truncated) = if status == ResourceReferenceStatus::Readable {
            let column = if table == tables::FILE { 1 } else { 6 };
            let index = self.tables.cell(table, row, column).unwrap_or(0);
            self.resource_name(index, resource_row, "Implementation name", budget)
        } else {
            (None, false)
        };
        let implementation = if table == tables::FILE {
            ResourceImplementation::File {
                row,
                token: target_token,
                status,
                name,
                name_truncated,
                flags: (status == ResourceReferenceStatus::Readable).then(|| self.tables.cell(table, row, 0)).flatten(),
            }
        } else {
            ResourceImplementation::AssemblyRef { row, token: target_token, status, name, name_truncated }
        };
        let availability = if status == ResourceReferenceStatus::Readable {
            ResourceAvailability::External
        } else {
            ResourceAvailability::Unavailable
        };
        (implementation, availability, name_truncated)
    }

    fn string(&mut self, table: u8, row: u32, column: usize) -> String {
        let offset = self.tables.cell(table, row, column).unwrap_or(0);
        self.heaps.string(offset).unwrap_or_else(|| {
            self.warnings.push(format!(
                "{} row {row}: string offset {offset:#x} is outside #Strings",
                tables::TABLE_NAMES[usize::from(table)]
            ));
            String::new()
        })
    }

    fn blob_hex(&self, table: u8, row: u32, column: usize) -> Option<String> {
        self.tables
            .cell(table, row, column)
            .filter(|&offset| offset != 0)
            .and_then(|offset| self.heaps.blob(offset))
            .filter(|blob| !blob.is_empty())
            .map(heaps::hex)
    }

    fn version(&self, table: u8, row: u32, first_column: usize) -> String {
        let part = |index| self.tables.cell(table, row, first_column + index).unwrap_or(0);
        format!("{}.{}.{}.{}", part(0), part(1), part(2), part(3))
    }

    fn assembly(&mut self) -> Assembly {
        let table = tables::ASSEMBLY;
        Assembly {
            name: self.string(table, 1, 7),
            version: self.version(table, 1, 1),
            culture: self.string(table, 1, 8),
            flags: self.tables.cell(table, 1, 5).unwrap_or(0),
            hash_algorithm: self.tables.cell(table, 1, 0).unwrap_or(0),
            public_key: self.blob_hex(table, 1, 6),
        }
    }

    fn assembly_ref(&mut self, row: u32) -> AssemblyRef {
        let table = tables::ASSEMBLY_REF;
        let flags = self.tables.cell(table, row, 4).unwrap_or(0);
        AssemblyRef {
            name: self.string(table, row, 6),
            version: self.version(table, row, 0),
            culture: self.string(table, row, 7),
            flags,
            public_key_or_token: self.blob_hex(table, row, 5),
            full_public_key: flags & ASSEMBLY_FLAG_PUBLIC_KEY != 0,
        }
    }

    fn type_ref(&mut self, row: u32) -> TypeRef {
        let table = tables::TYPE_REF;
        TypeRef {
            token: token(table, row),
            namespace: self.string(table, row, 2),
            name: self.string(table, row, 1),
            scope: self.tables.cell(table, row, 0).and_then(|value| self.coded_label(C::ResolutionScope, value)),
        }
    }

    /// A readable name for the row a coded index selects, for display only: `None` for a null or dangling index.
    fn coded_label(&self, coded: C, value: u32) -> Option<String> {
        let (table, row) = coded.decode(value)?;
        self.row_label(table, row)
    }

    /// A readable name for a row: a type's full name, a member's or module's name, a TypeSpec as text.
    fn row_label(&self, table: u8, row: u32) -> Option<String> {
        if row == 0 || row > self.tables.rows(table) {
            return None;
        }
        let string = |column| self.heaps.string(self.tables.cell(table, row, column)?);
        match table {
            tables::TYPE_DEF | tables::TYPE_REF => self.type_label(table, row, 0),
            tables::TYPE_SPEC => Some(self.type_spec_text(row).unwrap_or_else(|| format!("TypeSpec#{row}"))),
            tables::MODULE | tables::FIELD | tables::PROPERTY | tables::EVENT => string(1),
            tables::MODULE_REF => string(0),
            tables::ASSEMBLY_REF => string(6),
            tables::ASSEMBLY => string(7),
            tables::METHOD_DEF => string(3),
            tables::PARAM => string(2),
            tables::GENERIC_PARAM => string(3),
            _ => Some(format!("{}#{row}", tables::TABLE_NAMES[usize::from(table)])),
        }
    }

    /// `Namespace.Name` of a TypeDef or TypeRef row after its enclosing types, in ILAsm's `Outer/Inner` form:
    /// a TypeDef's from NestedClass, a TypeRef's from a ResolutionScope that names another TypeRef.
    fn type_label(&self, table: u8, row: u32, depth: u32) -> Option<String> {
        if row == 0 || row > self.tables.rows(table) {
            return None;
        }
        let string = |column| self.heaps.string(self.tables.cell(table, row, column)?);
        let name = qualified_name(&string(2).unwrap_or_default(), &string(1)?);
        let outer = match table {
            _ if depth >= MAX_NESTING => None,
            tables::TYPE_DEF => self.enclosing.get(&row).map(|&outer| (tables::TYPE_DEF, outer)),
            _ => self
                .tables
                .cell(table, row, 0)
                .and_then(|value| C::ResolutionScope.decode(value))
                .filter(|&(scope, _)| scope == tables::TYPE_REF),
        };
        match outer.and_then(|(table, outer)| self.type_label(table, outer, depth + 1)) {
            Some(outer) => Some(format!("{outer}/{name}")),
            None => Some(name),
        }
    }

    /// The target rows of every owner row's list column (II.22.37, II.22.26): from a row's start to the next
    /// row's start, through the Ptr table when an unoptimized `#-` stream has one. A start below an earlier
    /// row's is raised to it and a target row already handed out is skipped, so each target row lands in at
    /// most one list: out-of-order or duplicated lists in a hostile file cannot multiply the output.
    fn member_lists(&mut self, owner: u8, column: usize, target: u8, ptr: u8) -> Vec<Vec<u32>> {
        self.member_lists_eligible(owner, column, target, ptr, None)
    }

    /// Ineligible owners still delimit list ranges, but cannot reserve target rows.
    fn member_lists_eligible(
        &mut self,
        owner: u8,
        column: usize,
        target: u8,
        ptr: u8,
        eligible: Option<&[bool]>,
    ) -> Vec<Vec<u32>> {
        let ptr_rows = self.tables.rows(ptr);
        let target_rows = self.tables.rows(target);
        let count = if ptr_rows > 0 { ptr_rows } else { target_rows };
        let limit = count.saturating_add(1);
        let owners = self.tables.rows(owner);
        let mut starts = Vec::with_capacity(owners as usize);
        let mut floor = 1;
        for row in 1..=owners {
            let start = self.tables.cell(owner, row, column).unwrap_or(0).clamp(1, limit);
            if start < floor {
                self.warnings.push(format!(
                    "{} row {row}: {} list is out of order",
                    tables::TABLE_NAMES[usize::from(owner)],
                    tables::TABLE_NAMES[usize::from(target)]
                ));
            }
            floor = floor.max(start);
            starts.push(floor);
        }
        let mut assigned = vec![false; target_rows as usize + 1];
        (0..starts.len())
            .map(|index| {
                if eligible.is_some_and(|rows| !rows.get(index).copied().unwrap_or(false)) {
                    return Vec::new();
                }
                let end = starts.get(index + 1).copied().unwrap_or(limit);
                (starts[index]..end)
                    .filter_map(|index| if ptr_rows > 0 { self.tables.cell(ptr, index, 0) } else { Some(index) })
                    .filter(|&row| {
                        row != 0 && row <= target_rows && !std::mem::replace(&mut assigned[row as usize], true)
                    })
                    .collect()
            })
            .collect()
    }

    fn types(&mut self) -> Vec<TypeDef> {
        let table = tables::TYPE_DEF;
        let field_lists = self.member_lists(table, 4, tables::FIELD, tables::FIELD_PTR);
        let method_lists = self.member_lists(table, 5, tables::METHOD_DEF, tables::METHOD_PTR);
        self.index_enums(&field_lists);
        self.index_enum_constants(&field_lists);
        let (member_types, property_lists, event_lists) = self.property_and_event_types();
        self.member_types = member_types;
        let mut accessors = self.member_accessors(&method_lists);
        let param_lists = self.member_lists(tables::METHOD_DEF, 5, tables::PARAM, tables::PARAM_PTR);
        for (params, method) in param_lists.iter().zip(1..) {
            self.param_methods.extend(params.iter().map(|&param| (param, method)));
        }
        field_lists
            .into_iter()
            .zip(method_lists)
            .zip(property_lists)
            .zip(event_lists)
            .zip(1..)
            .map(|((((fields, methods), properties), events), row)| {
                let fields = fields.into_iter().map(|field| self.field(field, row)).collect();
                let methods = methods
                    .into_iter()
                    .map(|method| self.method(method, row, &param_lists[method as usize - 1]))
                    .collect();
                let properties = properties
                    .into_iter()
                    .map(|property| {
                        let name = self.string(tables::PROPERTY, property, 1);
                        PropertyDef {
                            token: token(tables::PROPERTY, property),
                            flags: self.tables.cell(tables::PROPERTY, property, 0).unwrap_or(0) as u16,
                            signature: self.signature(tables::PROPERTY, property, &name, Some(row)),
                            name,
                            accessors: accessors.remove(&(tables::PROPERTY, property)).unwrap_or_default(),
                        }
                    })
                    .collect();
                let events = events
                    .into_iter()
                    .map(|event| EventDef {
                        token: token(tables::EVENT, event),
                        name: self.string(tables::EVENT, event, 1),
                        flags: self.tables.cell(tables::EVENT, event, 0).unwrap_or(0) as u16,
                        event_type: self.event_type(event, row),
                        accessors: accessors
                            .remove(&(tables::EVENT, event))
                            .unwrap_or_default()
                            .into_iter()
                            .map(|binding| EventAccessor {
                                semantics: binding.semantics,
                                method_token: binding.method_token,
                            })
                            .collect(),
                    })
                    .collect();
                TypeDef {
                    token: token(table, row),
                    namespace: self.string(table, row, 2),
                    name: self.string(table, row, 1),
                    flags: self.tables.cell(table, row, 0).unwrap_or(0),
                    extends: self.tables.cell(table, row, 3).and_then(|value| self.coded_label(C::TypeDefOrRef, value)),
                    enclosing: self.enclosing.get(&row).map(|&outer| token(table, outer)),
                    fields,
                    methods,
                    properties,
                    events,
                }
            })
            .collect()
    }

    fn index_enums(&mut self, field_lists: &[Vec<u32>]) {
        if self.tables.rows(tables::CUSTOM_ATTRIBUTE) == 0 {
            return;
        }
        for (fields, row) in field_lists.iter().zip(1..) {
            if self.budget.get() == 0 {
                break;
            }
            let identifier = |table, row, column| self.enum_identifier(table, row, column);
            if self.verified_enum_base(row, identifier).is_none() {
                continue;
            }
            if let Some(underlying) = self.enum_value_field_underlying(fields, identifier) {
                self.enum_underlying.insert(row, underlying);
            }
        }
        if self.enum_underlying.is_empty() {
            return;
        }
        self.index_named_enums();
    }

    fn index_named_enums(&mut self) {
        self.named_enums.clear();
        let Some(enclosing) = self.enum_enclosing_types() else { return };
        // Include non-enum types when detecting duplicate names; a valid enum beside an invalid namesake is
        // ambiguous too. A partial index cannot rule out an unreadable namesake.
        for row in 1..=self.tables.rows(tables::TYPE_DEF) {
            let Some(name) = self.serialized_type_def_name(row, 0, &enclosing) else {
                self.named_enums.clear();
                return;
            };
            let underlying = self.enum_underlying.get(&row).copied();
            self.named_enums.entry(name).and_modify(|kind| *kind = None).or_insert(underlying);
        }
    }

    fn enum_enclosing_types(&self) -> Option<HashMap<u32, u32>> {
        charge_enum_work(&self.budget, 1)?;
        if !self.enclosing_complete
            || [tables::TYPE_DEF, tables::NESTED_CLASS]
                .iter()
                .any(|&table| self.tables.rows(table) != self.tables.declared[usize::from(table)])
        {
            return None;
        }
        let mut enclosing = HashMap::new();
        let types = self.tables.rows(tables::TYPE_DEF);
        for row in 1..=self.tables.rows(tables::NESTED_CLASS) {
            charge_enum_work(&self.budget, 1)?;
            let nested = self.tables.cell(tables::NESTED_CLASS, row, 0)?;
            let outer = self.tables.cell(tables::NESTED_CLASS, row, 1)?;
            if nested == 0 || nested > types || outer == 0 || outer > types || enclosing.contains_key(&nested) {
                return None;
            }
            enclosing.insert(nested, outer);
        }
        Some(enclosing)
    }

    fn verified_enum_base<'s>(
        &'s self,
        row: u32,
        identifier: impl Fn(u8, u32, usize) -> Option<&'s str>,
    ) -> Option<()> {
        let base = self.tables.cell(tables::TYPE_DEF, row, 3).and_then(|value| C::TypeDefOrRef.decode(value));
        let (tables::TYPE_REF, base) = base? else { return None };
        let scope = self.tables.cell(tables::TYPE_REF, base, 0).and_then(|value| C::ResolutionScope.decode(value));
        let valid_scope = scope
            .is_some_and(|(table, row)| table == tables::ASSEMBLY_REF && row != 0 && row <= self.tables.rows(table));
        if !valid_scope
            || identifier(tables::TYPE_REF, base, 1) != Some("Enum")
            || identifier(tables::TYPE_REF, base, 2) != Some("System")
        {
            return None;
        }
        Some(())
    }

    fn enum_value_field_underlying<'s>(
        &'s self,
        fields: &[u32],
        identifier: impl Fn(u8, u32, usize) -> Option<&'s str>,
    ) -> Option<u8> {
        let mut instances = fields
            .iter()
            .copied()
            .filter(|&field| self.tables.cell(tables::FIELD, field, 0).is_some_and(|flags| flags & 0x0010 == 0));
        let field = instances.next()?;
        if instances.next().is_some() {
            return None;
        }
        let flags = self.tables.cell(tables::FIELD, field, 0)?;
        let blob = self.tables.cell(tables::FIELD, field, 2).and_then(|offset| self.heaps.blob(offset));
        let &[0x06, underlying @ 0x04..=0x0B] = blob? else { return None };
        (identifier(tables::FIELD, field, 1) == Some("value__") && flags & 0x8650 == 0x0600).then_some(underlying)
    }

    fn constant_identifier(&self, table: u8, row: u32, column: usize, budget: &Cell<usize>) -> Option<&str> {
        // Reserve the maximum scan before touching an identifier, including failed lookups.
        let reservation = heaps::MAX_NAME_BYTES + 1;
        charge_enum_work(budget, reservation)?;
        let text = self.heaps.exact_string(self.tables.cell(table, row, column)?);
        if let Some(text) = text {
            budget.set(budget.get() + reservation - text.len() - 1);
        }
        text
    }

    fn index_enum_constants(&mut self, field_lists: &[Vec<u32>]) {
        let table = tables::CONSTANT;
        let rows = self.tables.rows(table);
        if self.tables.declared[usize::from(table)] == 0 {
            return;
        }
        // An unseen suffix could duplicate an earlier parent. A partial index proves no unique parents.
        if rows > MAX_ENUM_CONSTANT_ROWS || rows != self.tables.declared[usize::from(table)] {
            self.warnings.push("Constant evidence unavailable: table incomplete or row limit exceeded".to_owned());
            return;
        }
        let budget = Cell::new(MAX_ENUM_CONSTANT_WORK_BYTES);
        let mut parents = HashMap::new();
        for row in 1..=rows {
            if charge_enum_work(&budget, 16).is_none() {
                self.warnings.push("Constant evidence unavailable: index work budget exhausted".to_owned());
                return;
            }
            let parent = self.tables.cell(table, row, 1).and_then(|raw| C::HasConstant.decode(raw));
            let Some((kind, field)) = parent else {
                self.warnings.push(format!("Constant row {row}: reserved HasConstant parent tag"));
                continue;
            };
            if field == 0 || field > self.tables.rows(kind) {
                self.warnings.push(format!("Constant row {row}: invalid HasConstant parent row {field}"));
                continue;
            }
            if kind != tables::FIELD {
                self.warnings.push(format!(
                    "Constant row {row}: {} constants are unsupported; not enum-field evidence",
                    tables::TABLE_NAMES[usize::from(kind)]
                ));
                continue;
            }
            match parents.entry(field) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(Some(row));
                }
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    entry.insert(None);
                    self.warnings
                        .push(format!("Constant row {row}: duplicate Field parent {field}; evidence rejected"));
                }
            }
        }
        let mut visited = 0usize;
        let mut limited = false;
        'owners: for (fields, owner) in field_lists.iter().zip(1..) {
            let work_rows = fields.len().saturating_add(1);
            visited = visited.saturating_add(work_rows);
            if visited > MAX_ENUM_CONSTANT_ROWS as usize
                || charge_enum_work(&budget, work_rows.saturating_mul(16)).is_none()
            {
                limited = true;
                break;
            }
            let identifier = |table, row, column| self.constant_identifier(table, row, column, &budget);
            let enum_base = self.verified_enum_base(owner, identifier);
            let underlying = enum_base.and_then(|()| self.enum_value_field_underlying(fields, identifier));
            if budget.get() == 0 {
                limited = true;
                break;
            }
            if enum_base.is_none() {
                continue;
            }
            for &field in fields {
                let Some(Some(row)) = parents.get(&field).copied() else { continue };
                if self.enum_constants.len() == MAX_ENUM_CONSTANTS {
                    limited = true;
                    break 'owners;
                }
                let evidence =
                    underlying.and_then(|underlying| self.enum_constant(field, owner, row, underlying, &budget));
                if let Some(evidence) = evidence {
                    self.enum_constants.insert(field, evidence);
                } else {
                    self.warnings.push(format!("Constant row {row}: unverified local enum literal; evidence rejected"));
                }
                if budget.get() == 0 {
                    limited = true;
                    break 'owners;
                }
            }
        }
        if limited {
            self.warnings.push(format!(
                "enum Constant evidence budget exhausted ({} retained; limits {MAX_ENUM_CONSTANTS} constants, \
                 {MAX_ENUM_CONSTANT_ROWS} work rows, {MAX_ENUM_CONSTANT_WORK_BYTES} work/text bytes)",
                self.enum_constants.len()
            ));
        }
    }

    fn enum_constant(
        &self,
        field: u32,
        owner: u32,
        row: u32,
        underlying: u8,
        budget: &Cell<usize>,
    ) -> Option<EnumConstant> {
        charge_enum_work(budget, 32)?;
        let flags = self.tables.cell(tables::FIELD, field, 0)?;
        if flags & 0x8050 != 0x8050 || flags & 0x0020 != 0 {
            return None;
        }
        let signature = self.heaps.blob(self.tables.cell(tables::FIELD, field, 2)?)?;
        let [0x06, 0x11, target @ ..] = signature else { return None };
        let (target_row, used) = heaps::compressed_length(target)?;
        let target_row = u32::try_from(target_row).ok()?;
        if used != target.len() || C::TypeDefOrRef.decode(target_row) != Some((tables::TYPE_DEF, owner)) {
            return None;
        }
        // The high byte is the Constant row's required zero padding, not part of its element type.
        if self.tables.cell(tables::CONSTANT, row, 0)? != u32::from(underlying) {
            return None;
        }
        let blob = self.heaps.blob(self.tables.cell(tables::CONSTANT, row, 2)?)?;
        let (name, width) = match underlying {
            0x04 => ("int8", 1),
            0x05 => ("uint8", 1),
            0x06 => ("int16", 2),
            0x07 => ("uint16", 2),
            0x08 => ("int32", 4),
            0x09 => ("uint32", 4),
            0x0A => ("int64", 8),
            0x0B => ("uint64", 8),
            _ => return None,
        };
        if blob.len() != width {
            return None;
        }
        let field_name = self.constant_identifier(tables::FIELD, field, 1, budget)?;
        charge_enum_work(budget, field_name.len() + name.len() + 20)?;
        let value = read_uint(blob, 0, width, false)?;
        let value = if underlying & 1 == 0 {
            let shift = 64 - width * 8;
            (((value << shift) as i64) >> shift).to_string()
        } else {
            value.to_string()
        };
        Some(EnumConstant { underlying_integral_type: name, value })
    }

    fn enum_identifier(&self, table: u8, row: u32, column: usize) -> Option<&str> {
        self.constant_identifier(table, row, column, &self.budget)
    }

    /// Canonical reflection spelling, as in CLR TypeNameBuilder::EscapeName, not an ILAsm label.
    fn serialized_type_def_name(&self, row: u32, depth: u32, enclosing: &HashMap<u32, u32>) -> Option<String> {
        charge_enum_work(&self.budget, 1)?;
        if depth > MAX_NESTING {
            return None;
        }
        let flags = self.tables.cell(tables::TYPE_DEF, row, 0)?;
        if (flags & 7 >= 2) != enclosing.contains_key(&row) {
            return None;
        }
        let identifier = |column| self.enum_identifier(tables::TYPE_DEF, row, column);
        let (namespace, name) = (identifier(2)?, identifier(1)?);
        if name.is_empty() {
            return None;
        }
        let outer = match enclosing.get(&row) {
            Some(&outer) => Some(self.serialized_type_def_name(outer, depth + 1, enclosing)?),
            None => None,
        };
        // These seven ASCII characters, and only these, are reserved in CLR identifier components.
        let reserved = |byte| matches!(byte, b'+' | b',' | b'\\' | b'[' | b']' | b'*' | b'&');
        let escapes = namespace.bytes().chain(name.bytes()).filter(|&byte| reserved(byte)).count();
        let length = namespace.len()
            + name.len()
            + escapes
            + usize::from(!namespace.is_empty())
            + outer.as_ref().map_or(0, |outer| outer.len() + 1);
        charge_enum_work(&self.budget, length)?;
        if length > signatures::MAX_TEXT {
            return None;
        }
        let mut key = String::with_capacity(length);
        if let Some(outer) = outer {
            key.push_str(&outer);
            key.push('+');
        }
        for (index, component) in [namespace, name].into_iter().enumerate() {
            if index == 1 && !namespace.is_empty() {
                key.push('.');
            }
            for character in component.chars() {
                if character.is_ascii() && reserved(character as u8) {
                    key.push('\\');
                }
                key.push(character);
            }
        }
        Some(key)
    }

    fn member_accessors(&mut self, method_lists: &[Vec<u32>]) -> HashMap<(u8, u32), Vec<PropertyAccessor>> {
        let table = tables::METHOD_SEMANTICS;
        if self.tables.rows(table) == 0 {
            return HashMap::new();
        }
        let mut method_types = HashMap::new();
        for (methods, owner) in method_lists.iter().zip(1..) {
            method_types.extend(methods.iter().map(|&method| (method, owner)));
        }
        let mut accessors: HashMap<(u8, u32), Vec<PropertyAccessor>> = HashMap::new();
        let mut capped = std::collections::HashSet::new();
        for row in 1..=self.tables.rows(table) {
            let association = self.tables.cell(table, row, 2).and_then(|value| C::HasSemantics.decode(value));
            let Some((target, member)) = association else { continue };
            let method = self.tables.cell(table, row, 1).unwrap_or(0);
            let semantics = self.tables.cell(table, row, 0).unwrap_or(0) as u16;
            let owner = self.member_types.get(&(target, member));
            let (kind, valid) = match target {
                tables::PROPERTY => ("property", matches!(semantics, 1 | 2 | 4)),
                tables::EVENT => ("event", matches!(semantics, 4 | 8 | 16 | 32)),
                _ => continue,
            };
            if owner.is_none() || owner != method_types.get(&method) || !valid {
                self.warnings.push(format!("MethodSemantics row {row}: invalid {kind} method binding"));
                continue;
            }
            let bindings = accessors.entry((target, member)).or_default();
            let binding = PropertyAccessor { semantics, method_token: token(tables::METHOD_DEF, method) };
            if bindings.contains(&binding) {
                continue;
            }
            if bindings.len() < MAX_MEMBER_ACCESSORS {
                bindings.push(binding);
            } else if capped.insert((target, member)) {
                let table = tables::TABLE_NAMES[usize::from(target)];
                self.warnings.push(format!("{table} row {member}: accessor bindings capped at {MAX_MEMBER_ACCESSORS}"));
            }
        }
        accessors
    }

    fn field(&mut self, row: u32, owner: u32) -> FieldDef {
        let name = self.string(tables::FIELD, row, 1);
        FieldDef {
            token: token(tables::FIELD, row),
            signature: self.signature(tables::FIELD, row, &name, Some(owner)),
            name,
            flags: self.tables.cell(tables::FIELD, row, 0).unwrap_or(0) as u16,
            enum_constant: self.enum_constants.remove(&row),
        }
    }

    fn member_ref(&mut self, row: u32) -> MemberRef {
        let table = tables::MEMBER_REF;
        let name = self.string(table, row, 1);
        MemberRef {
            token: token(table, row),
            parent: self.tables.cell(table, row, 0).and_then(|value| self.coded_label(C::MemberRefParent, value)),
            signature: self.signature(table, row, &name, None),
            name,
        }
    }

    /// The `(number, name)` generic parameters of TypeDef or MethodDef `row`.
    fn generics(&self, table: u8, row: u32) -> &[(u32, String)] {
        self.generic_params.get(&(table, row)).map_or(&[], Vec::as_slice)
    }

    fn type_spec_text(&self, row: u32) -> Option<String> {
        let blob = signatures::Resolve::type_spec(self, row)?;
        Some(Reader::new(self, Generics::default(), &self.budget).type_spec(blob)?.text)
    }

    /// A MethodDef, Field, Property or MemberRef signature rendered with its name, in the generic context of
    /// TypeDef `owner`; `None` when the blob is missing or malformed.
    fn render_signature(&self, table: u8, row: u32, name: &str, owner: Option<u32>) -> Option<String> {
        let column = if table == tables::METHOD_DEF { 4 } else { 2 };
        let blob = self.heaps.blob(self.tables.cell(table, row, column)?)?;
        let generics = Generics {
            type_params: owner.map_or(&[], |owner| self.generics(tables::TYPE_DEF, owner)),
            method_params: if table == tables::METHOD_DEF { self.generics(table, row) } else { &[] },
        };
        let mut reader = Reader::new(self, generics, &self.budget);
        match table {
            tables::FIELD => reader.field(blob).map(|ty| format!("{} {name}", ty.text)),
            tables::METHOD_DEF => reader.method(blob).map(|method| method.render(name, &generics)),
            tables::PROPERTY => reader.property(blob).map(|property| property.render(name, &generics)),
            _ => reader.member(blob).map(|member| member.render(name, &generics)),
        }
    }

    fn signature(&mut self, table: u8, row: u32, name: &str, owner: Option<u32>) -> String {
        if let Some(text) = self.render_signature(table, row, name, owner) {
            return text;
        }
        self.unreadable_signature(table, row, "signature blob")
    }

    fn event_type(&mut self, row: u32, owner: u32) -> String {
        let value = self.tables.cell(tables::EVENT, row, 2).unwrap_or(0);
        let generics = Generics { type_params: self.generics(tables::TYPE_DEF, owner), method_params: &[] };
        if let Some(ty) = Reader::new(self, generics, &self.budget).event_type(value) {
            return ty.text;
        }
        self.unreadable_signature(tables::EVENT, row, "type reference")
    }

    fn unreadable_signature(&mut self, table: u8, row: u32, what: &str) -> String {
        // A spent budget fails every later signature too: one warning says so instead of one per row.
        if self.budget.get() == 0 {
            if !std::mem::replace(&mut self.budget_reported, true) {
                self.warnings.push(BUDGET_EXHAUSTED.to_owned());
            }
        } else {
            let table = tables::TABLE_NAMES[usize::from(table)];
            self.warnings.push(format!("{table} row {row}: {what} is malformed or exceeds the rendering caps"));
        }
        UNREADABLE.to_owned()
    }

    /// ImplMap rows (II.22.22), each naming the DLL export a P/Invoke method binds to.
    fn pinvokes(&mut self, owners: &MemberOwners) -> Vec<PInvoke> {
        let table = tables::IMPL_MAP;
        let mut pinvokes = Vec::new();
        for row in 1..=self.tables.rows(table) {
            let member = self.tables.cell(table, row, 1).and_then(|value| C::MemberForwarded.decode(value));
            // II.22.22: MemberForwarded can name a Field, but the CLR only binds methods.
            let Some((tables::METHOD_DEF, method)) = member else {
                self.warnings.push(format!("ImplMap row {row} does not forward a method"));
                continue;
            };
            let method_token = token(tables::METHOD_DEF, method);
            let scope = self.tables.cell(table, row, 3).unwrap_or(0);
            let module = (scope != 0 && scope <= self.tables.rows(tables::MODULE_REF))
                .then(|| self.string(tables::MODULE_REF, scope, 0));
            pinvokes.push(PInvoke {
                method_token,
                method: owners.get(&method_token).cloned(),
                module,
                import_name: self.string(table, row, 2),
                flags: self.tables.cell(table, row, 0).unwrap_or(0) as u16,
            });
        }
        pinvokes
    }

    /// CustomAttribute rows (II.22.10) with their attribute type and, where decodable, constructor arguments.
    fn custom_attributes(&mut self, owners: &MemberOwners) -> Vec<CustomAttribute> {
        let table = tables::CUSTOM_ATTRIBUTE;
        let mut attributes = Vec::new();
        if self.tables.rows(table) == 0 {
            return attributes;
        }
        for row in 1..=self.tables.rows(table) {
            let parent = self.tables.cell(table, row, 0).and_then(|value| C::HasCustomAttribute.decode(value));
            let constructor = self.tables.cell(table, row, 1).and_then(|value| C::CustomAttributeType.decode(value));
            let value = self.tables.cell(table, row, 2).and_then(|offset| self.heaps.blob(offset));
            if value.is_none() {
                self.warnings.push(format!("CustomAttribute row {row}: value blob is outside #Blob"));
            }
            let parent_token = parent.map_or(0, |(table, row)| token(table, row));
            let parent = parent.and_then(|(table, row)| self.attribute_target(table, row, owners, &self.member_types));
            let constructor_token = constructor.map_or(0, |(table, row)| token(table, row));
            let (attribute_type, signature) = match constructor {
                Some((tables::METHOD_DEF, method)) => (
                    owners
                        .get(&constructor_token)
                        .and_then(|owner| owner.rsplit_once("::"))
                        .map(|(ty, _)| ty.to_owned()),
                    self.tables.cell(tables::METHOD_DEF, method, 4),
                ),
                Some((_, member)) => (
                    self.tables
                        .cell(tables::MEMBER_REF, member, 0)
                        .and_then(|value| self.coded_label(C::MemberRefParent, value)),
                    self.tables.cell(tables::MEMBER_REF, member, 2),
                ),
                None => (None, None),
            };
            let params = signature
                .and_then(|offset| self.heaps.blob(offset))
                .and_then(|blob| Reader::new(self, Generics::default(), &self.budget).method(blob))
                .map(|method| method.params);
            let decoded = params.zip(value).map(|(params, value)| {
                Reader::new(self, Generics::default(), &self.budget).attribute_arguments(&params, value)
            });
            let (arguments, named_arguments, arguments_error) = match decoded {
                Some(decoded) => (decoded.arguments, decoded.named_arguments, decoded.error.map(str::to_owned)),
                None => (None, None, Some("constructor signature or attribute value is unreadable".to_owned())),
            };
            if self.budget.get() == 0 && !std::mem::replace(&mut self.budget_reported, true) {
                self.warnings.push(BUDGET_EXHAUSTED.to_owned());
            }
            attributes.push(CustomAttribute {
                parent_token,
                parent,
                attribute_type,
                constructor_token,
                arguments,
                named_arguments,
                arguments_error,
                blob_length: value.map_or(0, <[u8]>::len),
            });
        }
        attributes
    }

    /// Property/Event ownership and each type's member rows in map/pointer-list order.
    fn property_and_event_types(&mut self) -> (MemberTypes, Vec<Vec<u32>>, Vec<Vec<u32>>) {
        let mut types = HashMap::new();
        let mut properties = vec![Vec::new(); self.tables.rows(tables::TYPE_DEF) as usize];
        let mut events = vec![Vec::new(); properties.len()];
        let mut event_owners = std::collections::HashSet::new();
        let maps = [
            (tables::PROPERTY_MAP, tables::PROPERTY, tables::PROPERTY_PTR),
            (tables::EVENT_MAP, tables::EVENT, tables::EVENT_PTR),
        ];
        for (map, target, ptr) in maps {
            let eligible = (target == tables::EVENT).then(|| {
                (1..=self.tables.rows(map))
                    .map(|row| {
                        let parent = self.tables.cell(map, row, 0).unwrap_or(0);
                        if parent == 0 || parent > self.tables.rows(tables::TYPE_DEF) {
                            self.warnings.push(format!("EventMap row {row}: invalid owning TypeDef {parent}"));
                            return false;
                        }
                        if event_owners.insert(parent) {
                            return true;
                        }
                        self.warnings.push(format!(
                            "EventMap row {row}: duplicate owning TypeDef {parent}; later map rows ignored"
                        ));
                        false
                    })
                    .collect::<Vec<_>>()
            });
            for (members, row) in
                self.member_lists_eligible(map, 1, target, ptr, eligible.as_deref()).into_iter().zip(1..)
            {
                if let Some(parent) = self.tables.cell(map, row, 0) {
                    let lists = if target == tables::PROPERTY { &mut properties } else { &mut events };
                    if let Some(list) = parent.checked_sub(1).and_then(|row| lists.get_mut(row as usize)) {
                        list.extend(&members);
                    }
                    types.extend(members.into_iter().map(|member| ((target, member), parent)));
                }
            }
        }
        (types, properties, events)
    }

    /// What a custom attribute is applied to: a member as `Type::member`, a parameter as `Type::Method/param`,
    /// a generic parameter as `Owner<T>`, anything else by its row label. A parameter, property or event whose
    /// owner does not resolve is named with its table, e.g. `Property Count`.
    fn attribute_target(&self, table: u8, row: u32, owners: &MemberOwners, members: &MemberTypes) -> Option<String> {
        if let Some(owner) = owners.get(&token(table, row)) {
            return Some(owner.clone());
        }
        let name = self.row_label(table, row)?;
        let (owner, separator) = match table {
            tables::PARAM => {
                let method = self.param_methods.get(&row);
                let sequence = self.tables.cell(table, row, 1).unwrap_or(0);
                let name = match name.as_str() {
                    "" if sequence == 0 => "return".to_owned(),
                    "" => format!("#{sequence}"),
                    _ => name,
                };
                let owner = method.and_then(|&method| owners.get(&token(tables::METHOD_DEF, method)).cloned());
                return Some(self.owned_label(table, owner, &format!("/{name}"), &name));
            }
            tables::GENERIC_PARAM => {
                let owner = self.tables.cell(table, row, 2).and_then(|value| C::TypeOrMethodDef.decode(value));
                let owner = owner.and_then(|(owner, row)| match owner {
                    tables::METHOD_DEF => owners.get(&token(owner, row)).cloned(),
                    _ => self.row_label(owner, row),
                });
                return Some(self.owned_label(table, owner, &format!("<{name}>"), &name));
            }
            tables::PROPERTY | tables::EVENT => {
                (members.get(&(table, row)).and_then(|&ty| self.row_label(tables::TYPE_DEF, ty)), "::")
            }
            _ => return Some(name),
        };
        Some(self.owned_label(table, owner, &format!("{separator}{name}"), &name))
    }

    /// `owner` followed by `suffix`, or, when the owner is unknown, the table's name and `name`.
    fn owned_label(&self, table: u8, owner: Option<String>, suffix: &str, name: &str) -> String {
        match owner {
            Some(owner) => format!("{owner}{suffix}"),
            None => format!("{} {name}", tables::TABLE_NAMES[usize::from(table)]),
        }
    }

    fn method(&mut self, row: u32, owner: u32, params: &[u32]) -> MethodDef {
        let table = tables::METHOD_DEF;
        let rva = self.tables.cell(table, row, 0).unwrap_or(0);
        let impl_flags = self.tables.cell(table, row, 1).unwrap_or(0) as u16;
        let body = match (rva, impl_flags & CODE_TYPE_MASK) {
            (0, _) => BodyKind::None,
            (_, CODE_TYPE_NATIVE) => BodyKind::Native,
            (_, CODE_TYPE_RUNTIME) => BodyKind::Runtime,
            // IL and OPTIL (code type 2) both store CIL.
            _ => BodyKind::Il,
        };
        let mut params: Vec<(u32, String)> = params
            .iter()
            .filter_map(|&param| {
                let sequence = self.tables.cell(tables::PARAM, param, 1)?;
                (sequence > 0).then(|| (sequence, self.string(tables::PARAM, param, 2)))
            })
            .collect();
        params.sort_by_key(|&(sequence, _)| sequence);
        let name = self.string(table, row, 3);
        MethodDef {
            signature: self.signature(table, row, &name, Some(owner)),
            token: token(table, row),
            name,
            rva,
            flags: self.tables.cell(table, row, 2).unwrap_or(0) as u16,
            impl_flags,
            body,
            il: None,
            params: params.into_iter().map(|(_, name)| name).collect(),
        }
    }

    fn entry_point(&mut self, cli: &CliHeader, owners: &MemberOwners) -> Option<EntryPoint> {
        let value = cli.entry_point_token;
        if value == 0 {
            return None;
        }
        if cli.flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0 {
            return Some(EntryPoint::Native { rva: value });
        }
        match (value >> 24) as u8 {
            tables::METHOD_DEF => {
                let method = owners.get(&value).cloned();
                if method.is_none() {
                    self.warnings.push(format!("entry point token {value:#010x} does not resolve"));
                }
                Some(EntryPoint::Method { token: value, method })
            }
            tables::FILE => Some(EntryPoint::File { token: value }),
            _ => {
                self.warnings.push(format!("entry point token {value:#010x} is not a MethodDef or File"));
                None
            }
        }
    }
}

/// `Type::member` for every method and field, each type named by `label` from its row (with its enclosing types).
fn member_owners(types: &[TypeDef], label: impl Fn(u32) -> Option<String>) -> MemberOwners {
    let mut owners = HashMap::new();
    for (ty, row) in types.iter().zip(1..) {
        let full_name = label(row).unwrap_or_else(|| ty.full_name());
        let methods = ty.methods.iter().map(|method| (method.token, &method.name));
        for (token, name) in methods.chain(ty.fields.iter().map(|field| (field.token, &field.name))) {
            owners.insert(token, format!("{full_name}::{name}"));
        }
    }
    owners
}

fn token(table: u8, row: u32) -> u32 {
    (u32::from(table) << 24) | (row & tables::MAX_ROWS)
}

// CLI metadata is always little-endian (II.24.1).
fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    read_uint(bytes, offset, 2, false).map(|value| value as u16)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    read_uint(bytes, offset, 4, false).map(|value| value as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table stream header declaring `present` `(table, rows)` in table order, with narrow heap indexes.
    fn table_stream(present: &[(u8, u32)]) -> Vec<u8> {
        let mut stream = vec![0, 0, 0, 0, 2, 0, 0, 1];
        let valid = present.iter().fold(0u64, |valid, &(table, _)| valid | (1 << table));
        stream.extend_from_slice(&valid.to_le_bytes());
        stream.extend_from_slice(&0u64.to_le_bytes());
        for &(_, rows) in present {
            stream.extend_from_slice(&rows.to_le_bytes());
        }
        stream
    }

    /// A table stream with one TypeDef owning a MethodDef per blob, every index 2 bytes wide.
    fn method_tables(signatures: &[&[u8]]) -> (Vec<u8>, Vec<u8>) {
        let mut blobs = vec![0u8];
        let mut stream = table_stream(&[(tables::TYPE_DEF, 1), (tables::METHOD_DEF, signatures.len() as u32)]);
        // TypeDef: flags, name "M", no namespace or base, field list 1, method list 1.
        for (value, width) in [(0u32, 4), (1, 2), (0, 2), (0, 2), (1, 2), (1, 2)] {
            stream.extend_from_slice(&value.to_le_bytes()[..width]);
        }
        for signature in signatures {
            let offset = blobs.len() as u32;
            blobs.push(signature.len() as u8);
            blobs.extend_from_slice(signature);
            for (value, width) in [(0u32, 4), (0, 2), (0, 2), (1, 2), (offset, 2), (1, 2)] {
                stream.extend_from_slice(&value.to_le_bytes()[..width]);
            }
        }
        (stream, blobs)
    }

    #[test]
    fn a_spent_signature_budget_is_reported_once() {
        let int32 = [0x00, 0, 0x08];
        let (stream, blobs) = method_tables(&[&int32, &int32, &int32, &[0x00, 0, 0x99]]);
        let mut warnings = Warnings::default();
        let tables = Tables::parse(&stream, false, &mut warnings).unwrap();
        let heaps = Heaps { strings: b"\0M\0", blobs: &blobs, ..Heaps::default() };
        let mut decoder = Decoder::new(&tables, heaps, &mut warnings);
        // `int32` and the 3 bytes read: room for one signature only.
        decoder.budget.set(10);
        let types = decoder.types();
        let signatures: Vec<&str> = types[0].methods.iter().map(|method| method.signature.as_str()).collect();
        assert_eq!(signatures, ["int32 M()", UNREADABLE, UNREADABLE, UNREADABLE]);
        assert_eq!(warnings.0, [BUDGET_EXHAUSTED]);
    }

    #[test]
    fn failed_enum_identity_lookups_spend_the_shared_budget() {
        let (stream, blobs) = method_tables(&[&[0x00, 0, 0x01]]);
        let mut warnings = Warnings::default();
        let tables = Tables::parse(&stream, false, &mut warnings).unwrap();
        let heaps = Heaps { strings: b"\0M\0", blobs: &blobs, ..Heaps::default() };
        let mut decoder = Decoder::new(&tables, heaps, &mut warnings);
        decoder.budget.set(40);
        assert!(decoder.serialized_type_def_name(1, 0, &HashMap::new()).is_none());
        assert_eq!(decoder.budget.get(), 0, "failed raw identifier lookups still cost work");
        assert_eq!(decoder.signature(tables::METHOD_DEF, 1, "M", None), UNREADABLE);
        assert_eq!(decoder.signature(tables::METHOD_DEF, 1, "M", None), UNREADABLE);
        assert_eq!(warnings.0, [BUDGET_EXHAUSTED]);
    }

    fn enum_identity_tables(definitions: &[(u32, &str, &str)], nested: &[(u32, u32)]) -> (Vec<u8>, Vec<u8>) {
        let mut stream =
            table_stream(&[(tables::TYPE_DEF, definitions.len() as u32), (tables::NESTED_CLASS, nested.len() as u32)]);
        let mut strings = vec![0];
        for &(flags, namespace, name) in definitions {
            let namespace_offset = strings.len() as u32;
            strings.extend(namespace.as_bytes());
            strings.push(0);
            let name_offset = strings.len() as u32;
            strings.extend(name.as_bytes());
            strings.push(0);
            for (value, width) in [(flags, 4), (name_offset, 2), (namespace_offset, 2), (0, 2), (1, 2), (1, 2)] {
                stream.extend_from_slice(&value.to_le_bytes()[..width]);
            }
        }
        for &(nested, outer) in nested {
            stream.extend_from_slice(&(nested as u16).to_le_bytes());
            stream.extend_from_slice(&(outer as u16).to_le_bytes());
        }
        (stream, strings)
    }

    #[test]
    fn initial_nested_class_scan_reserves_each_row_before_any_access_and_discards_failed_scans() {
        for (available, expected_reads, complete) in
            [(0, 0, false), (7, 0, false), (8, 1, false), (15, 1, false), (16, 2, true)]
        {
            let budget = Cell::new(available);
            let mut reads = 0;
            let result = read_enclosing_types(2, &budget, |row| {
                reads += 1;
                assert_eq!(budget.get(), available - reads * NESTED_CLASS_ROW_WORK, "reserve before row {row}");
                Some((3, row))
            });
            assert_eq!(reads, expected_reads, "available {available}");
            assert_eq!(budget.get(), 0);
            if complete {
                assert_eq!(result.unwrap().get(&3), Some(&2), "within-limit last-wins display behavior is unchanged");
            } else {
                assert_eq!(result, Err(BUDGET_EXHAUSTED), "no partial map escapes a failed scan");
            }
        }
        let budget = Cell::new(NESTED_CLASS_ROW_WORK);
        let result = read_enclosing_types(1, &budget, |_| {
            assert_eq!(budget.get(), 0, "failed reads also reserve their work first");
            None
        });
        assert_eq!(result, Err(NESTING_ROW_UNREADABLE));
        assert_eq!(budget.get(), 0);
    }

    #[test]
    fn initial_nested_class_scan_caps_huge_duplicate_tables_before_unbounded_accesses() {
        for rows in [MAX_NESTED_CLASS_ROWS, MAX_NESTED_CLASS_ROWS + 1, 1_000_000] {
            let budget = Cell::new(signatures::TOTAL_BUDGET);
            let mut reads = 0;
            let result = read_enclosing_types(rows, &budget, |row| {
                assert!(row <= MAX_NESTED_CLASS_ROWS, "the cap is checked before touching a row");
                reads += 1;
                assert_eq!(
                    budget.get(),
                    signatures::TOTAL_BUDGET - reads * NESTED_CLASS_ROW_WORK,
                    "every duplicate row is charged before access"
                );
                Some((3, 2))
            });
            if rows == MAX_NESTED_CLASS_ROWS {
                assert_eq!(reads, MAX_NESTED_CLASS_ROWS as usize);
                assert_eq!(result.unwrap(), HashMap::from([(3, 2)]));
            } else {
                assert_eq!(reads, 0, "a known oversized table is refused before its first row access");
                assert_eq!(budget.get(), signatures::TOTAL_BUDGET);
                assert_eq!(result, Err(NESTING_ROW_LIMIT));
            }
            assert!(budget.get() > 0, "structural row limits do not spend the whole signature budget");
        }
    }

    #[test]
    fn decoder_initial_nested_scan_shares_its_budget_and_preserves_within_limit_ilasm_names() {
        let (stream, strings) =
            enum_identity_tables(&[(0, "", "<Module>"), (1, "Demo", "Program"), (2, "", "Inner")], &[(3, 1), (3, 2)]);
        let mut warnings = Warnings::default();
        let tables = Tables::parse(&stream, false, &mut warnings).unwrap();
        let heaps = Heaps { strings: &strings, ..Heaps::default() };
        let mut decoder = Decoder::new(&tables, heaps, &mut warnings);
        assert_eq!(decoder.budget.get(), signatures::TOTAL_BUDGET - 2 * NESTED_CLASS_ROW_WORK);
        assert!(decoder.enclosing_complete);
        assert_eq!(decoder.type_label(tables::TYPE_DEF, 3, 0).as_deref(), Some("Demo.Program/Inner"));
        decoder.enum_underlying.insert(3, 0x06);
        decoder.index_named_enums();
        assert!(decoder.named_enums.is_empty(), "duplicate parents still cannot prove enum identity");
        assert_eq!(signatures::Resolve::enum_underlying(&decoder, tables::TYPE_DEF, 3), Some(0x06));
        assert!(warnings.0.is_empty());
    }

    #[test]
    fn failed_initial_nested_budget_cannot_be_reinterpreted_as_complete_enum_name_evidence() {
        let (stream, strings) =
            enum_identity_tables(&[(0, "", "<Module>"), (1, "Demo", "Program"), (2, "", "Inner")], &[(3, 2)]);
        for available in [0, NESTED_CLASS_ROW_WORK - 1] {
            let mut warnings = Warnings::default();
            let tables = Tables::parse(&stream, false, &mut warnings).unwrap();
            let heaps = Heaps { strings: &strings, ..Heaps::default() };
            let mut decoder = Decoder::with_budget(&tables, heaps, &mut warnings, available);
            assert_eq!(decoder.budget.get(), 0);
            assert!(decoder.enclosing.is_empty());
            assert!(!decoder.enclosing_complete);
            assert!(decoder.budget_reported);
            assert_eq!(decoder.signature(tables::METHOD_DEF, 1, "M", None), UNREADABLE);
            // Even independently funded later name work must not treat an abandoned initial scan as complete.
            decoder.budget.set(signatures::TOTAL_BUDGET);
            decoder.enum_underlying.insert(3, 0x06);
            decoder.index_named_enums();
            assert!(decoder.named_enums.is_empty());
            assert_eq!(signatures::Resolve::enum_underlying(&decoder, tables::TYPE_DEF, 3), Some(0x06));
            assert_eq!(warnings.0, [BUDGET_EXHAUSTED], "initial budget failure is diagnosed once");
        }
    }

    #[test]
    fn enum_identity_escape_expansion_is_charged_before_retaining_a_key() {
        let name = "\\".repeat(heaps::MAX_NAME_BYTES);
        let (stream, strings) = enum_identity_tables(&[(1, "", &name)], &[]);
        let mut warnings = Warnings::default();
        let tables = Tables::parse(&stream, false, &mut warnings).unwrap();
        let heaps = Heaps { strings: &strings, ..Heaps::default() };
        let mut decoder = Decoder::new(&tables, heaps, &mut warnings);
        decoder.enum_underlying.insert(1, 0x06);
        // Index validation + one node + two NUL-terminated identifiers + doubled escape output.
        let cost = 2 + 1 + name.len() + 1 + name.len() * 2;
        for (available, retained) in [(cost - 1, false), (cost, true)] {
            decoder.budget.set(available);
            decoder.index_named_enums();
            assert_eq!(decoder.named_enums.contains_key(&"\\".repeat(name.len() * 2)), retained);
            assert_eq!(decoder.budget.get(), 0);
        }
    }

    #[test]
    fn incomplete_typedef_tables_or_unreadable_names_cannot_prove_enum_name_uniqueness() {
        let (stream, strings) = enum_identity_tables(&[(1, "", "Mode"), (1, "", "Mode")], &[]);
        let mut warnings = Warnings::default();
        let truncated = &stream[..stream.len() - 14];
        let tables = Tables::parse(truncated, false, &mut warnings).unwrap();
        assert_eq!(tables.rows(tables::TYPE_DEF), 1);
        let heaps = Heaps { strings: &strings, ..Heaps::default() };
        let mut decoder = Decoder::new(&tables, heaps, &mut warnings);
        decoder.enum_underlying.insert(1, 0x06);
        decoder.named_enums.insert("stale".to_owned(), Some(0x06));
        decoder.index_named_enums();
        assert!(decoder.named_enums.is_empty());

        let (stream, _) = enum_identity_tables(&[(1, "", "Mode"), (1, "", "Mode")], &[]);
        let mut warnings = Warnings::default();
        let tables = Tables::parse(&stream, false, &mut warnings).unwrap();
        let heaps = Heaps { strings: b"\0\0Mode\0\0\xff\0", ..Heaps::default() };
        let mut decoder = Decoder::new(&tables, heaps, &mut warnings);
        decoder.enum_underlying.insert(1, 0x06);
        decoder.index_named_enums();
        assert!(decoder.named_enums.is_empty(), "a valid key seen before invalid UTF-8 is not trustworthy");
        assert!(decoder.budget.get() < signatures::TOTAL_BUDGET - heaps::MAX_NAME_BYTES);
    }

    #[test]
    fn partial_budget_depth_or_text_limited_enum_indexes_never_retain_earlier_keys() {
        let (stream, strings) = enum_identity_tables(&[(1, "", "Mode"), (1, "", "Other")], &[]);
        let mut warnings = Warnings::default();
        let tables = Tables::parse(&stream, false, &mut warnings).unwrap();
        let heaps = Heaps { strings: &strings, ..Heaps::default() };
        let mut decoder = Decoder::new(&tables, heaps, &mut warnings);
        decoder.enum_underlying.insert(1, 0x06);
        decoder.budget.set(1030);
        decoder.index_named_enums();
        assert!(decoder.named_enums.is_empty());
        assert_eq!(decoder.budget.get(), 0, "a later failed reservation invalidates earlier names");

        for (levels, raw) in [(MAX_NESTING + 3, "N".to_owned()), (MAX_NESTING, "\\".repeat(512))] {
            let mut definitions = vec![(2, "", raw.as_str()); levels as usize];
            definitions[0].0 = 1;
            let nested: Vec<_> = (2..=levels).map(|row| (row, row - 1)).collect();
            let (stream, strings) = enum_identity_tables(&definitions, &nested);
            let mut warnings = Warnings::default();
            let tables = Tables::parse(&stream, false, &mut warnings).unwrap();
            let heaps = Heaps { strings: &strings, ..Heaps::default() };
            let mut decoder = Decoder::new(&tables, heaps, &mut warnings);
            decoder.enum_underlying.insert(1, 0x06);
            decoder.index_named_enums();
            assert!(decoder.named_enums.is_empty(), "levels {levels}, raw length {}", raw.len());
            assert!(decoder.budget.get() > 0, "depth and text caps bound walks without spending the image budget");
        }
    }

    #[test]
    fn resource_name_budget_charges_failed_lookups_and_exact_boundaries() {
        let stream = table_stream(&[]);
        let mut warnings = Warnings::default();
        let tables = Tables::parse(&stream, false, &mut warnings).unwrap();
        let heaps = Heaps { strings: b"\0M\0\xff\0", ..Heaps::default() };
        let mut decoder = Decoder::new(&tables, heaps, &mut warnings);
        let mut budget = ResourceBudget { remaining: 4, exhausted: false };
        assert_eq!(decoder.resource_name(u32::MAX, 1, "name", &mut budget), (None, false));
        assert_eq!(budget.remaining, 3);
        assert_eq!(decoder.resource_name(1, 2, "name", &mut budget), (Some("M".to_owned()), false));
        assert_eq!(budget.remaining, 0);
        assert!(!budget.exhausted);
        assert_eq!(decoder.resource_name(1, 3, "name", &mut budget), (None, true));
        assert!(budget.exhausted);
        let mut budget = ResourceBudget { remaining: 3, exhausted: false };
        assert_eq!(decoder.resource_name(3, 4, "name", &mut budget), (None, false));
        assert_eq!(budget.remaining, 0, "invalid UTF-8 still costs the lookup and inspected bytes");
    }

    #[test]
    fn resource_implementation_does_not_claim_unavailable_declared_rows_are_readable() {
        let stream = table_stream(&[(tables::FILE, 1)]);
        let mut warnings = Warnings::default();
        let tables = Tables::parse(&stream, false, &mut warnings).unwrap();
        let mut decoder = Decoder::new(&tables, Heaps::default(), &mut warnings);
        let mut budget = ResourceBudget { remaining: 1, exhausted: false };
        let (implementation, availability, _) = decoder.resource_implementation(4, 1, &mut budget);
        assert!(matches!(
            implementation,
            ResourceImplementation::File {
                row: 1,
                token: Some(0x2600_0001),
                status: ResourceReferenceStatus::Unreadable,
                name: None,
                ..
            }
        ));
        assert_eq!(availability, ResourceAvailability::Unavailable);
    }

    #[test]
    fn failed_event_type_lookups_spend_the_shared_signature_budget() {
        let mut stream = table_stream(&[(tables::TYPE_DEF, 1), (tables::EVENT, 3), (tables::TYPE_SPEC, 1)]);
        for (value, width) in [(0u32, 4), (1, 2), (0, 2), (0, 2), (1, 2), (1, 2)] {
            stream.extend_from_slice(&value.to_le_bytes()[..width]);
        }
        for value in [3u32, 6, 4] {
            for column in [0, 1, value] {
                stream.extend_from_slice(&(column as u16).to_le_bytes());
            }
        }
        stream.extend_from_slice(&1u16.to_le_bytes());
        let mut warnings = Warnings::default();
        let tables = Tables::parse(&stream, false, &mut warnings).unwrap();
        let heaps = Heaps { strings: b"\0M\0", blobs: &[0, 1, 0x99], ..Heaps::default() };
        let mut decoder = Decoder::new(&tables, heaps, &mut warnings);
        decoder.budget.set(3);
        assert_eq!(decoder.event_type(1, 1), UNREADABLE);
        assert_eq!(decoder.budget.get(), 2, "a reserved coded tag still costs lookup work");
        assert_eq!(decoder.event_type(2, 1), UNREADABLE);
        assert_eq!(decoder.budget.get(), 0, "a failed TypeSpec costs its lookup and bytes read");
        assert_eq!(decoder.event_type(3, 1), UNREADABLE);
        assert_eq!(decoder.signature(tables::METHOD_DEF, 1, "M", None), UNREADABLE);
        assert_eq!(warnings.0.iter().filter(|warning| warning.as_str() == BUDGET_EXHAUSTED).count(), 1);
    }

    #[test]
    fn event_text_and_other_signatures_share_the_image_budget() {
        let (stream, blobs) = method_tables(&[&[0x00, 0, 0x01]]);
        let mut warnings = Warnings::default();
        let tables = Tables::parse(&stream, false, &mut warnings).unwrap();
        let heaps = Heaps { strings: b"\0M\0", blobs: &blobs, ..Heaps::default() };
        let mut decoder = Decoder::new(&tables, heaps, &mut warnings);
        decoder.budget.set(3);
        let ty = Reader::new(&decoder, Generics::default(), &decoder.budget).event_type(4).unwrap();
        assert_eq!(ty.text, "M");
        assert_eq!(decoder.budget.get(), 1, "lookup work and rendered event text both count");
        assert_eq!(decoder.signature(tables::METHOD_DEF, 1, "M", None), UNREADABLE);
        assert_eq!(warnings.0, [BUDGET_EXHAUSTED]);
    }

    #[test]
    fn decodes_tiny_and_fat_headers() {
        let tiny = il_body(&[0x16, 0x2A]).unwrap();
        assert_eq!((tiny.header, tiny.code_size, tiny.header_size), (IlHeader::Tiny, 5, 1));
        let fat = il_body(&[0x1B, 0x30, 0x04, 0x00, 0x20, 0, 0, 0, 0x01, 0, 0, 0x11]).unwrap();
        assert_eq!(fat.header, IlHeader::Fat);
        assert_eq!((fat.code_size, fat.max_stack, fat.header_size), (0x20, 4, 12));
        assert_eq!(fat.local_var_sig_token, 0x1100_0001);
        assert!(fat.more_sections);
        assert_eq!(il_body(&[0x03, 0x10]), None);
        assert_eq!(il_body(&[0x13, 0x30, 0x01]), None);
        assert_eq!(il_body(&[0x00]), None);
    }

    #[test]
    fn generic_parameters_are_indexed_by_number_within_the_arity_cap() {
        // 200,000 GenericParam rows on TypeDef 1 numbered 0..1000 over and over: only one row per number below
        // the cap is kept, so every VAR lookup searches at most MAX_ARITY sorted entries.
        let rows = 200_000u32;
        let mut stream = table_stream(&[(tables::GENERIC_PARAM, rows)]);
        for row in 0..rows {
            let number = (rows - row) % 1000;
            for (value, width) in [(number, 2), (0, 2), (1 << 1, 2), (u32::from(number == 3), 2)] {
                stream.extend_from_slice(&value.to_le_bytes()[..width]);
            }
        }
        let mut warnings = Warnings::default();
        let tables = Tables::parse(&stream, false, &mut warnings).unwrap();
        let heaps = Heaps { strings: b"\0T\0", ..Heaps::default() };
        let decoder = Decoder::new(&tables, heaps, &mut warnings);
        let params = decoder.generics(tables::TYPE_DEF, 1);
        let numbers: Vec<u32> = params.iter().map(|&(number, _)| number).collect();
        assert_eq!(numbers, (0..signatures::MAX_ARITY).collect::<Vec<_>>());
        assert_eq!(params[3].1, "T");
    }
}
