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
//! Not decoded: signatures (so no parameter or return types), generic parameters, custom attributes,
//! resources, and the exception-handling sections that follow a fat method body.

mod heaps;
mod tables;

use object::LittleEndian as LE;
use object::read::pe::{ImageNtHeaders, PeFile};
use serde::Serialize;

use crate::{Binary, Format, LoadError};
use heaps::Heaps;
use tables::{Coded, Tables};

const MAX_WARNINGS: usize = 256;
const MAX_STREAMS: usize = 64;
/// II.24.2.1: the version string length is at most 255 bytes, rounded up to a multiple of four.
const MAX_VERSION_BYTES: usize = 256;
const METADATA_SIGNATURE: u32 = 0x424A_5342;

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
    pub fields: Vec<String>,
    pub methods: Vec<MethodDef>,
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
        if self.0.len() < MAX_WARNINGS - 1 {
            self.0.push(warning);
        } else if self.0.len() == MAX_WARNINGS - 1 {
            self.0.push(".NET metadata warning limit reached; further diagnostics are truncated".to_owned());
        }
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
    match object::FileKind::parse(image) {
        Ok(object::FileKind::Pe32) => from_pe::<object::pe::ImageNtHeaders32>(image),
        Ok(object::FileKind::Pe64) => from_pe::<object::pe::ImageNtHeaders64>(image),
        _ => Ok(None),
    }
}

fn from_pe<Pe: ImageNtHeaders>(image: &[u8]) -> Result<Option<DotNetMetadata>, LoadError> {
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
    parse_cli(rva, &read_rva).map(Some)
}

/// Parses everything reachable from the CLI header at `cli_rva`. `read_rva` returns the file bytes from an RVA
/// to the end of its section.
fn parse_cli<'a>(cli_rva: u32, read_rva: &dyn Fn(u32) -> Option<&'a [u8]>) -> Result<DotNetMetadata, LoadError> {
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
    let mut metadata = parse_root(root, cli, warnings)?;
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
fn parse_root(root: &[u8], cli: CliHeader, mut warnings: Warnings) -> Result<DotNetMetadata, LoadError> {
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
        user_strings,
        tables: Vec::new(),
        warnings: Vec::new(),
    };
    match table_stream {
        Some(stream) => match Tables::parse(stream, uncompressed && jtd, &mut warnings) {
            Some(tables) => Decoder { tables: &tables, heaps, warnings: &mut warnings }.decode(&mut metadata),
            None => warnings.push("table stream header is unreadable".to_owned()),
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
            mvid: self.cell(tables::MODULE, 1, 2).and_then(|index| self.heaps.guid(index)),
        });
        metadata.assembly = (self.tables.rows(tables::ASSEMBLY) > 0).then(|| self.assembly());
        metadata.assembly_refs =
            (1..=self.tables.rows(tables::ASSEMBLY_REF)).map(|row| self.assembly_ref(row)).collect();
        metadata.type_refs = (1..=self.tables.rows(tables::TYPE_REF)).map(|row| self.type_ref(row)).collect();
        metadata.member_refs = (1..=self.tables.rows(tables::MEMBER_REF))
            .map(|row| MemberRef {
                token: token(tables::MEMBER_REF, row),
                parent: self
                    .cell(tables::MEMBER_REF, row, 0)
                    .and_then(|value| self.coded_label(C::MemberRefParent, value)),
                name: self.string(tables::MEMBER_REF, row, 1),
            })
            .collect();
        metadata.types = self.types();
        metadata.entry_point = self.entry_point(metadata);
    }

    fn cell(&self, table: u8, row: u32, column: usize) -> Option<u32> {
        self.tables.cell(table, row, column)
    }

    fn string(&mut self, table: u8, row: u32, column: usize) -> String {
        let offset = self.cell(table, row, column).unwrap_or(0);
        self.heaps.string(offset).unwrap_or_else(|| {
            self.warnings.push(format!(
                "{} row {row}: string offset {offset:#x} is outside #Strings",
                tables::TABLE_NAMES[usize::from(table)]
            ));
            String::new()
        })
    }

    fn blob_hex(&self, table: u8, row: u32, column: usize) -> Option<String> {
        self.cell(table, row, column)
            .filter(|&offset| offset != 0)
            .and_then(|offset| self.heaps.blob(offset))
            .filter(|blob| !blob.is_empty())
            .map(heaps::hex)
    }

    fn version(&self, table: u8, row: u32, first_column: usize) -> String {
        let part = |index| self.cell(table, row, first_column + index).unwrap_or(0);
        format!("{}.{}.{}.{}", part(0), part(1), part(2), part(3))
    }

    fn assembly(&mut self) -> Assembly {
        let table = tables::ASSEMBLY;
        Assembly {
            name: self.string(table, 1, 7),
            version: self.version(table, 1, 1),
            culture: self.string(table, 1, 8),
            flags: self.cell(table, 1, 5).unwrap_or(0),
            hash_algorithm: self.cell(table, 1, 0).unwrap_or(0),
            public_key: self.blob_hex(table, 1, 6),
        }
    }

    fn assembly_ref(&mut self, row: u32) -> AssemblyRef {
        let table = tables::ASSEMBLY_REF;
        let flags = self.cell(table, row, 4).unwrap_or(0);
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
            scope: self.cell(table, row, 0).and_then(|value| self.coded_label(C::ResolutionScope, value)),
        }
    }

    /// A readable name for the row a coded index selects, for display only: `None` for a null or dangling index.
    fn coded_label(&self, coded: Coded, value: u32) -> Option<String> {
        let (table, row) = coded.decode(value)?;
        if row == 0 || row > self.tables.rows(table) {
            return None;
        }
        let string = |column| self.heaps.string(self.cell(table, row, column)?);
        let qualified = |name: Option<String>, namespace: Option<String>| {
            Some(qualified_name(namespace.as_deref().unwrap_or(""), &name?))
        };
        match table {
            tables::TYPE_DEF => qualified(string(1), string(2)),
            tables::TYPE_REF => qualified(string(1), string(2)),
            tables::TYPE_SPEC => Some(format!("TypeSpec#{row}")),
            tables::MODULE | tables::MODULE_REF => string(if table == tables::MODULE { 1 } else { 0 }),
            tables::ASSEMBLY_REF => string(6),
            tables::METHOD_DEF => string(3),
            _ => Some(format!("{}#{row}", tables::TABLE_NAMES[usize::from(table)])),
        }
    }

    /// The target rows of every owner row's list column (II.22.37, II.22.26): from a row's start to the next
    /// row's start, through the Ptr table when an unoptimized `#-` stream has one. A start below an earlier
    /// row's is raised to it and a target row already handed out is skipped, so each target row lands in at
    /// most one list: out-of-order or duplicated lists in a hostile file cannot multiply the output.
    fn member_lists(&mut self, owner: u8, column: usize, target: u8, ptr: u8) -> Vec<Vec<u32>> {
        let ptr_rows = self.tables.rows(ptr);
        let target_rows = self.tables.rows(target);
        let count = if ptr_rows > 0 { ptr_rows } else { target_rows };
        let limit = count.saturating_add(1);
        let owners = self.tables.rows(owner);
        let mut starts = Vec::with_capacity(owners as usize);
        let mut floor = 1;
        for row in 1..=owners {
            let start = self.cell(owner, row, column).unwrap_or(0).clamp(1, limit);
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
                let end = starts.get(index + 1).copied().unwrap_or(limit);
                (starts[index]..end)
                    .filter_map(|index| if ptr_rows > 0 { self.cell(ptr, index, 0) } else { Some(index) })
                    .filter(|&row| {
                        row != 0 && row <= target_rows && !std::mem::replace(&mut assigned[row as usize], true)
                    })
                    .collect()
            })
            .collect()
    }

    fn types(&mut self) -> Vec<TypeDef> {
        let mut enclosing = std::collections::HashMap::new();
        for row in 1..=self.tables.rows(tables::NESTED_CLASS) {
            if let (Some(nested), Some(outer)) =
                (self.cell(tables::NESTED_CLASS, row, 0), self.cell(tables::NESTED_CLASS, row, 1))
            {
                enclosing.insert(nested, token(tables::TYPE_DEF, outer));
            }
        }
        let table = tables::TYPE_DEF;
        let field_lists = self.member_lists(table, 4, tables::FIELD, tables::FIELD_PTR);
        let method_lists = self.member_lists(table, 5, tables::METHOD_DEF, tables::METHOD_PTR);
        let param_lists = self.member_lists(tables::METHOD_DEF, 5, tables::PARAM, tables::PARAM_PTR);
        field_lists
            .into_iter()
            .zip(method_lists)
            .zip(1..)
            .map(|((fields, methods), row)| {
                let fields = fields.into_iter().map(|field| self.string(tables::FIELD, field, 1)).collect();
                let methods =
                    methods.into_iter().map(|method| self.method(method, &param_lists[method as usize - 1])).collect();
                TypeDef {
                    token: token(table, row),
                    namespace: self.string(table, row, 2),
                    name: self.string(table, row, 1),
                    flags: self.cell(table, row, 0).unwrap_or(0),
                    extends: self.cell(table, row, 3).and_then(|value| self.coded_label(C::TypeDefOrRef, value)),
                    enclosing: enclosing.get(&row).copied(),
                    fields,
                    methods,
                }
            })
            .collect()
    }

    fn method(&mut self, row: u32, params: &[u32]) -> MethodDef {
        let table = tables::METHOD_DEF;
        let rva = self.cell(table, row, 0).unwrap_or(0);
        let impl_flags = self.cell(table, row, 1).unwrap_or(0) as u16;
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
                let sequence = self.cell(tables::PARAM, param, 1)?;
                (sequence > 0).then(|| (sequence, self.string(tables::PARAM, param, 2)))
            })
            .collect();
        params.sort_by_key(|&(sequence, _)| sequence);
        MethodDef {
            token: token(table, row),
            name: self.string(table, row, 3),
            rva,
            flags: self.cell(table, row, 2).unwrap_or(0) as u16,
            impl_flags,
            body,
            il: None,
            params: params.into_iter().map(|(_, name)| name).collect(),
        }
    }

    fn entry_point(&mut self, metadata: &DotNetMetadata) -> Option<EntryPoint> {
        let value = metadata.cli.entry_point_token;
        if value == 0 {
            return None;
        }
        if metadata.cli.flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0 {
            return Some(EntryPoint::Native { rva: value });
        }
        match (value >> 24) as u8 {
            tables::METHOD_DEF => {
                let method = metadata.types.iter().find_map(|ty| {
                    let method = ty.methods.iter().find(|method| method.token == value)?;
                    Some(format!("{}::{}", ty.full_name(), method.name))
                });
                if method.is_none() {
                    self.warnings.push(format!("entry point token {value:#010x} does not resolve"));
                }
                Some(EntryPoint::Method { token: value, method })
            }
            0x26 => Some(EntryPoint::File { token: value }),
            _ => {
                self.warnings.push(format!("entry point token {value:#010x} is not a MethodDef or File"));
                None
            }
        }
    }
}

use Coded as C;

fn token(table: u8, row: u32) -> u32 {
    (u32::from(table) << 24) | (row & tables::MAX_ROWS)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    bytes.get(offset..end).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    bytes.get(offset..end).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from(read_u32(bytes, offset)?) | (u64::from(read_u32(bytes, offset.checked_add(4)?)?) << 32))
}

fn read_uint(bytes: &[u8], offset: usize, width: usize) -> Option<u32> {
    match width {
        2 => read_u16(bytes, offset).map(u32::from),
        4 => read_u32(bytes, offset),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
