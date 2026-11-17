//! The DEX file format (versions 035 through 041): the header, the id tables, class definitions, class data, code
//! items and the map list. Every offset and count is checked against the file before use, tables are read in place
//! rather than copied, and nothing is allocated from a header count until its table is known to fit the file.

use std::collections::HashMap;

use serde::Serialize;
use sha1::{Digest, Sha1};

use crate::error::{DexError, Result, malformed};
use crate::read::{Cursor, Mutf8, adler32, mutf8, u16_at, u32_at};

/// `NO_INDEX` in the DEX format: an absent superclass or source file.
pub const NO_INDEX: u32 = u32::MAX;
/// Warnings one file keeps.
pub const MAX_WARNINGS: usize = 64;
/// Bytes of a name (a type, member or proto component) in reference text; longer ones are cut with `…`.
pub const MAX_NAME_BYTES: usize = 1024;
/// Catch clauses decoded per method body, across its distinct handlers.
pub const MAX_CLAUSES: usize = 65_536;
/// Entries of one type_list: 16-bit type indexes cannot address more.
pub const MAX_TYPE_LIST: u32 = 65_535;
/// Decoded strings longer than this are kept, by data offset, so a string many ids share is decoded once.
const CACHED_STRING_BYTES: usize = 256;

/// Caps on the work one DEX file may cause. Every DEX file is treated as hostile.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Bytes of one DEX file.
    pub max_file_bytes: usize,
    /// Entries of any one id table.
    pub max_ids: u32,
    /// Bytes of one string's modified UTF-8.
    pub max_string_bytes: usize,
    /// Code units of one method body.
    pub max_code_units: u32,
    /// Encoded fields and methods decoded across all class data of one file (shared class data counts each time).
    pub max_members: usize,
    /// Superclass levels a hierarchy walk follows.
    pub max_hierarchy: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: 256 << 20,
            max_ids: 1 << 22,
            max_string_bytes: 1 << 20,
            max_code_units: 4 << 20,
            max_members: 4 << 20,
            max_hierarchy: 64,
        }
    }
}

/// One id table: its entry count and file offset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Table {
    pub count: u32,
    pub offset: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    /// The three version digits of the magic, e.g. 35 or 39.
    pub version: u16,
    pub checksum: u32,
    /// Whether the Adler-32 of the file after the checksum field matches `checksum`. Reported, never required.
    pub checksum_valid: bool,
    pub signature: String,
    /// Whether the SHA-1 of the file after the signature matches `signature`. Reported, never required.
    pub signature_valid: bool,
    pub file_size: u32,
    pub header_size: u32,
    pub map_offset: u32,
    pub strings: Table,
    pub types: Table,
    pub protos: Table,
    pub fields: Table,
    pub methods: Table,
    pub classes: Table,
    pub data: Table,
}

/// One map_list entry: a section's type, item count and offset.
#[derive(Debug, Clone, Serialize)]
pub struct MapItem {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub code: u16,
    pub count: u32,
    pub offset: u32,
}

/// A method prototype: its return type and parameter types as descriptors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Proto {
    pub shorty: String,
    pub return_type: String,
    pub parameters: Vec<String>,
}

impl Proto {
    /// `(params)ret` in descriptor form, as smali writes it.
    pub fn descriptor(&self) -> String {
        format!("({}){}", self.parameters.concat(), self.return_type)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldRef {
    pub class: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
}

impl FieldRef {
    pub fn text(&self) -> String {
        format!("{}->{}:{}", self.class, self.name, self.kind)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MethodRef {
    pub class: String,
    pub name: String,
    pub proto: Proto,
}

impl MethodRef {
    /// `Lpkg/Class;->name(params)ret`, the smali form.
    pub fn text(&self) -> String {
        format!("{}->{}{}", self.class, self.name, self.proto.descriptor())
    }
}

/// A class_def_item, with indexes still unresolved.
#[derive(Debug, Clone)]
pub struct ClassDef {
    pub index: u32,
    pub class_idx: u32,
    pub access: u32,
    pub superclass_idx: u32,
    /// The interface type_list's offset; read it with [`Dex::interfaces`].
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

/// A static field's initial value (`static_values`): integers, booleans and chars as `Int`, strings, null.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitialValue {
    Int(i64),
    String(String),
    Null,
    /// A float, type, method, enum, array or annotation value.
    Other,
}

#[derive(Debug, Clone, Copy)]
pub struct EncodedField {
    pub field_idx: u32,
    pub access: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct EncodedMethod {
    pub method_idx: u32,
    pub access: u32,
    pub code_off: u32,
}

#[derive(Debug, Clone, Default)]
pub struct ClassData {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

impl ClassData {
    pub fn methods(&self) -> impl Iterator<Item = &EncodedMethod> {
        self.direct_methods.iter().chain(&self.virtual_methods)
    }
}

/// One catch clause: the exception type (`None` for catch-all) and the handler address in code units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Catch {
    #[serde(rename = "type")]
    pub type_idx: Option<u32>,
    pub address: u32,
}

/// A try range: `start` and `count` in code units, and the index of its handler in [`CodeItem::handlers`]. Tries
/// that share a handler share one decoded copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Try {
    pub start: u32,
    pub count: u16,
    pub handler: usize,
}

/// A method body.
#[derive(Debug, Clone)]
pub struct CodeItem {
    pub offset: u32,
    pub registers: u16,
    pub ins: u16,
    pub outs: u16,
    pub debug_info_off: u32,
    pub insns: Vec<u16>,
    pub tries: Vec<Try>,
    /// Each distinct encoded catch handler once: its clauses in order.
    pub handlers: Vec<Vec<Catch>>,
}

impl CodeItem {
    /// The catch clauses of `range`.
    pub fn catches(&self, range: &Try) -> &[Catch] {
        self.handlers.get(range.handler).map_or(&[], Vec::as_slice)
    }
}

/// A method handle: its kind and the field or method it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodHandle {
    pub kind: u16,
    pub target: u16,
}

impl MethodHandle {
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            0 => "static-put",
            1 => "static-get",
            2 => "instance-put",
            3 => "instance-get",
            4 => "invoke-static",
            5 => "invoke-instance",
            6 => "invoke-constructor",
            7 => "invoke-direct",
            8 => "invoke-interface",
            _ => "unknown",
        }
    }

    pub fn is_field(&self) -> bool {
        self.kind <= 3
    }
}

/// A parsed DEX file. The bytes are kept; tables are read in place on demand.
pub struct Dex {
    data: Vec<u8>,
    pub header: Header,
    pub map: Vec<MapItem>,
    pub call_sites: Table,
    pub method_handles: Table,
    pub limits: Limits,
    /// Problems that did not stop parsing: checksum or signature mismatches, map/header disagreements, overlaps.
    pub warnings: Vec<String>,
    /// Warnings beyond [`MAX_WARNINGS`], counted but not kept.
    pub warnings_dropped: usize,
    /// Further DEX headers a version 041 container holds after this one (not read).
    pub container_extra: usize,
    strings_cache: std::sync::Mutex<HashMap<usize, std::sync::Arc<Mutf8>>>,
    classes_by_type: HashMap<u32, u32>,
}

fn map_kind(code: u16) -> &'static str {
    match code {
        0x0000 => "header_item",
        0x0001 => "string_id_item",
        0x0002 => "type_id_item",
        0x0003 => "proto_id_item",
        0x0004 => "field_id_item",
        0x0005 => "method_id_item",
        0x0006 => "class_def_item",
        0x0007 => "call_site_id_item",
        0x0008 => "method_handle_item",
        0x1000 => "map_list",
        0x1001 => "type_list",
        0x1002 => "annotation_set_ref_list",
        0x1003 => "annotation_set_item",
        0x2000 => "class_data_item",
        0x2001 => "code_item",
        0x2002 => "string_data_item",
        0x2003 => "debug_info_item",
        0x2004 => "annotation_item",
        0x2005 => "encoded_array_item",
        0x2006 => "annotations_directory_item",
        0xf000 => "hiddenapi_class_data_item",
        _ => "unknown",
    }
}

/// The fixed item size of a map type whose items all have one, for overlap checks.
fn fixed_size(code: u16) -> Option<u32> {
    match code {
        0x0000 => Some(0x70),
        0x0001 | 0x0002 | 0x0007 => Some(4),
        0x0003 => Some(12),
        0x0004 | 0x0005 | 0x0008 => Some(8),
        0x0006 => Some(32),
        _ => None,
    }
}

/// Whether the bytes start with a DEX magic (`dex\n0NN\0`).
pub fn is_dex(data: &[u8]) -> bool {
    data.len() >= 8 && &data[..4] == b"dex\n" && data[4..7].iter().all(u8::is_ascii_digit) && data[7] == 0
}

impl Dex {
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        Self::parse_with(data, Limits::default())
    }

    pub fn parse_with(mut data: Vec<u8>, limits: Limits) -> Result<Self> {
        if data.len() > limits.max_file_bytes {
            return Err(DexError::Limit(format!(
                "{} bytes is more than the {}-byte DEX limit",
                data.len(),
                limits.max_file_bytes
            )));
        }
        if data.len() < 0x70 {
            return Err(malformed(format!("{} bytes is shorter than a DEX header", data.len())));
        }
        if !is_dex(&data) {
            return Err(malformed("no DEX magic"));
        }
        let version: u16 = std::str::from_utf8(&data[4..7]).ok().and_then(|text| text.parse().ok()).unwrap_or(0);
        if !(35..=41).contains(&version) {
            return Err(DexError::Unsupported(format!("DEX version {version:03} (035 through 041 are read)")));
        }
        let mut warnings = Vec::new();
        let endian = u32_at(&data, 0x28).unwrap_or(0);
        if endian == 0x7856_3412 {
            return Err(DexError::Unsupported("big-endian (reverse endian tag) DEX".to_owned()));
        }
        if endian != 0x1234_5678 {
            return Err(malformed(format!("endian tag {endian:#x}")));
        }
        let file_size = u32_at(&data, 0x20).unwrap_or(0);
        let header_size = u32_at(&data, 0x24).unwrap_or(0);
        if header_size < 0x70 || header_size as usize > data.len() {
            return Err(malformed(format!("header size {header_size:#x}")));
        }
        if file_size < header_size {
            return Err(malformed(format!("file size {file_size} is smaller than the {header_size}-byte header")));
        }
        if (file_size as usize) > data.len() {
            return Err(malformed(format!("header says {file_size} bytes but the file has {}: truncated", data.len())));
        }
        let mut container_extra = 0usize;
        if (file_size as usize) < data.len() {
            // A version 041 container holds several DEX files, each starting with its own header.
            let mut at = file_size as usize;
            while version >= 41 && container_extra < 4096 && data.get(at..at + 8).is_some_and(is_dex) {
                container_extra += 1;
                match u32_at(&data, at + 0x20) {
                    Some(size) if size >= 0x70 => at += size as usize,
                    _ => break,
                }
            }
            if container_extra > 0 {
                warnings.push(format!(
                    "this DEX 041 container holds {container_extra} more DEX file(s) after the first; only the first \
                     is read"
                ));
            } else {
                warnings.push(format!(
                    "{} bytes after the declared file size {file_size} are ignored",
                    data.len() - file_size as usize
                ));
            }
            data.truncate(file_size as usize);
        }
        let word = |offset| u32_at(&data, offset).unwrap_or(0);
        let checksum = word(0x08);
        let checksum_valid = adler32(&data[12..]) == checksum;
        if !checksum_valid {
            warnings.push(format!("checksum {checksum:#010x} does not match the file's Adler-32"));
        }
        let signature: String = data[12..32].iter().map(|byte| format!("{byte:02x}")).collect();
        let digest: String = Sha1::digest(&data[32..]).iter().map(|byte| format!("{byte:02x}")).collect();
        let signature_valid = digest == signature;
        if !signature_valid {
            warnings.push("SHA-1 signature does not match the file".to_owned());
        }
        let table = |at| Table { count: word(at), offset: word(at + 4) };
        let header = Header {
            version,
            checksum,
            checksum_valid,
            signature,
            signature_valid,
            file_size,
            header_size,
            map_offset: word(0x34),
            strings: table(0x38),
            types: table(0x40),
            protos: table(0x48),
            fields: table(0x50),
            methods: table(0x58),
            classes: table(0x60),
            data: table(0x68),
        };
        let mut dex = Dex {
            data,
            header,
            map: Vec::new(),
            call_sites: Table::default(),
            method_handles: Table::default(),
            limits,
            warnings,
            warnings_dropped: 0,
            container_extra,
            strings_cache: std::sync::Mutex::new(HashMap::new()),
            classes_by_type: HashMap::new(),
        };
        let header = dex.header.clone();
        for (name, table, size) in [
            ("string_ids", header.strings, 4),
            ("type_ids", header.types, 4),
            ("proto_ids", header.protos, 12),
            ("field_ids", header.fields, 8),
            ("method_ids", header.methods, 8),
            ("class_defs", header.classes, 32),
        ] {
            dex.check_table(name, table, size)?;
        }
        if header.types.count > 65_536 || header.protos.count > 65_536 {
            return Err(malformed("more than 65536 type or proto ids, which 16-bit indexes cannot address"));
        }
        dex.read_map()?;
        dex.check_table("call_site_ids", dex.call_sites, 4)?;
        dex.check_table("method_handles", dex.method_handles, 8)?;
        let mut classes_by_type = HashMap::new();
        for index in 0..header.classes.count {
            let class_idx = u32_at(&dex.data, (header.classes.offset + index * 32) as usize).unwrap_or(NO_INDEX);
            if let std::collections::hash_map::Entry::Vacant(slot) = classes_by_type.entry(class_idx) {
                slot.insert(index);
            } else {
                dex.warn(format!("class_def {index} redefines type {class_idx}; the first definition is used"));
            }
        }
        dex.classes_by_type = classes_by_type;
        Ok(dex)
    }

    /// Records a warning, keeping at most [`MAX_WARNINGS`] and counting the rest.
    pub(crate) fn warn(&mut self, text: String) {
        if self.warnings.len() < MAX_WARNINGS {
            self.warnings.push(text);
        } else {
            self.warnings_dropped += 1;
        }
    }

    fn check_table(&self, name: &str, table: Table, size: u32) -> Result<()> {
        if table.count == 0 {
            return Ok(());
        }
        if table.count > self.limits.max_ids {
            return Err(DexError::Limit(format!(
                "{name} has {} entries, more than {}",
                table.count, self.limits.max_ids
            )));
        }
        let end = u64::from(table.offset) + u64::from(table.count) * u64::from(size);
        if table.offset < 0x70 || end > self.data.len() as u64 {
            return Err(malformed(format!(
                "{name} ({} entries at {:#x}) does not fit the {}-byte file",
                table.count,
                table.offset,
                self.data.len()
            )));
        }
        if !table.offset.is_multiple_of(4) {
            return Err(malformed(format!("{name} at {:#x} is not 4-byte aligned", table.offset)));
        }
        Ok(())
    }

    fn read_map(&mut self) -> Result<()> {
        let offset = self.header.map_offset as usize;
        if offset == 0 {
            self.warn("no map_list".to_owned());
            return Ok(());
        }
        let count = u32_at(&self.data, offset)
            .ok_or_else(|| malformed(format!("map_list at {offset:#x} is outside the file")))?;
        if u64::from(count) * 12 + 4 > (self.data.len() - offset) as u64 || count > 4096 {
            return Err(malformed(format!("map_list declares {count} items, more than fit the file")));
        }
        let mut items = Vec::with_capacity(count as usize);
        for index in 0..count as usize {
            let at = offset + 4 + index * 12;
            let code = u16_at(&self.data, at).unwrap_or(0);
            let item = MapItem {
                kind: map_kind(code),
                code,
                count: u32_at(&self.data, at + 4).unwrap_or(0),
                offset: u32_at(&self.data, at + 8).unwrap_or(0),
            };
            if u64::from(item.offset) > self.data.len() as u64 {
                self.warn(format!("map item {} at {:#x} is outside the file", item.kind, item.offset));
            }
            items.push(item);
        }
        let header = self.header.clone();
        let expected = [
            (0x0001, header.strings),
            (0x0002, header.types),
            (0x0003, header.protos),
            (0x0004, header.fields),
            (0x0005, header.methods),
            (0x0006, header.classes),
        ];
        for (code, table) in expected {
            match items.iter().find(|item| item.code == code) {
                Some(item) if item.count != table.count || item.offset != table.offset => self.warn(format!(
                    "map_list {} ({} at {:#x}) disagrees with the header ({} at {:#x})",
                    item.kind, item.count, item.offset, table.count, table.offset
                )),
                None if table.count > 0 => self.warn(format!("map_list has no {}", map_kind(code))),
                _ => {}
            }
        }
        if let Some(item) = items.iter().find(|item| item.code == 0x0007) {
            self.call_sites = Table { count: item.count, offset: item.offset };
        }
        if let Some(item) = items.iter().find(|item| item.code == 0x0008) {
            self.method_handles = Table { count: item.count, offset: item.offset };
        }
        let mut extents: Vec<(u64, u64, &str)> = items
            .iter()
            .filter_map(|item| {
                let size = fixed_size(item.code)?;
                let size = if item.code == 0 {
                    u64::from(header.header_size)
                } else {
                    u64::from(size) * u64::from(item.count)
                };
                (size > 0).then_some((u64::from(item.offset), u64::from(item.offset) + size, item.kind))
            })
            .collect();
        extents.sort();
        for pair in extents.windows(2) {
            if pair[1].0 < pair[0].1 {
                self.warn(format!("map sections {} and {} overlap", pair[0].2, pair[1].2));
            }
        }
        self.map = items;
        Ok(())
    }

    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    fn id(&self, table: Table, size: u32, index: u32, what: &str) -> Result<usize> {
        if index >= table.count {
            return Err(malformed(format!("{what} index {index} is past the {} entries", table.count)));
        }
        Ok((table.offset + index * size) as usize)
    }

    /// The data offset of string `index`, which several ids may share.
    pub fn string_offset(&self, index: u32) -> Result<u32> {
        let at = self.id(self.header.strings, 4, index, "string")?;
        Ok(u32_at(&self.data, at).unwrap_or(0))
    }

    /// The string with index `index`. The scan for its terminator is bounded by its declared length, and a long
    /// string is decoded once however many ids share it.
    pub fn string(&self, index: u32) -> Result<std::sync::Arc<Mutf8>> {
        let offset = self.string_offset(index)? as usize;
        if offset < 0x70 {
            return Err(malformed(format!("string {index} data offset {offset:#x} is inside the header")));
        }
        if let Some(cached) = self.strings_cache.lock().ok().and_then(|cache| cache.get(&offset).cloned()) {
            return Ok(cached);
        }
        let mut cursor = Cursor::new(&self.data, offset);
        let length = cursor.uleb128()?;
        // Each UTF-16 unit takes at most three bytes of modified UTF-8.
        let window = self.limits.max_string_bytes.min((length as usize).saturating_mul(3));
        let decoded = std::sync::Arc::new(mutf8(&self.data, cursor.pos, length, window)?);
        if decoded.text.len() > CACHED_STRING_BYTES
            && let Ok(mut cache) = self.strings_cache.lock()
        {
            cache.insert(offset, decoded.clone());
        }
        Ok(decoded)
    }

    /// String `index` as a name for reference text: cut to [`MAX_NAME_BYTES`].
    fn name(&self, index: u32) -> Result<String> {
        Ok(cut(&self.string(index)?.text))
    }

    /// The string `index` as text (cut to [`MAX_NAME_BYTES`]), or a placeholder naming the problem.
    pub fn string_text(&self, index: u32) -> String {
        self.name(index).unwrap_or_else(|_| format!("<bad string {index}>"))
    }

    /// The descriptor of type `index` (`Ljava/lang/String;`, `I`, `[B`), cut to [`MAX_NAME_BYTES`].
    pub fn type_descriptor(&self, index: u32) -> Result<String> {
        let at = self.id(self.header.types, 4, index, "type")?;
        self.name(u32_at(&self.data, at).unwrap_or(NO_INDEX))
    }

    pub fn type_text(&self, index: u32) -> String {
        self.type_descriptor(index).unwrap_or_else(|_| format!("<bad type {index}>"))
    }

    fn type_list(&self, offset: u32) -> Result<Vec<u16>> {
        if offset == 0 {
            return Ok(Vec::new());
        }
        let mut cursor = Cursor::new(&self.data, offset as usize);
        let count = cursor.u32()?;
        if count > MAX_TYPE_LIST {
            return Err(malformed(format!("type_list at {offset:#x} declares {count} entries")));
        }
        let bytes = cursor
            .bytes(count as usize * 2)
            .map_err(|_| malformed(format!("type_list at {offset:#x} declares {count} entries, more than fit")))?;
        Ok(bytes.as_chunks::<2>().0.iter().map(|pair| u16::from_le_bytes(*pair)).collect())
    }

    pub fn proto(&self, index: u32) -> Result<Proto> {
        let at = self.id(self.header.protos, 12, index, "proto")?;
        let shorty = self.name(u32_at(&self.data, at).unwrap_or(NO_INDEX))?;
        let return_type = self.type_descriptor(u32_at(&self.data, at + 4).unwrap_or(NO_INDEX))?;
        let parameters = self
            .type_list(u32_at(&self.data, at + 8).unwrap_or(0))?
            .into_iter()
            .map(|index| self.type_descriptor(u32::from(index)))
            .collect::<Result<_>>()?;
        Ok(Proto { shorty, return_type, parameters })
    }

    pub fn field(&self, index: u32) -> Result<FieldRef> {
        let at = self.id(self.header.fields, 8, index, "field")?;
        Ok(FieldRef {
            class: self.type_descriptor(u32::from(u16_at(&self.data, at).unwrap_or(0)))?,
            kind: self.type_descriptor(u32::from(u16_at(&self.data, at + 2).unwrap_or(0)))?,
            name: self.name(u32_at(&self.data, at + 4).unwrap_or(NO_INDEX))?,
        })
    }

    pub fn field_text(&self, index: u32) -> String {
        self.field(index).map_or_else(|_| format!("<bad field {index}>"), |field| field.text())
    }

    /// The class type index of method `index`, without resolving anything else.
    pub fn method_class_idx(&self, index: u32) -> Result<u32> {
        let at = self.id(self.header.methods, 8, index, "method")?;
        Ok(u32::from(u16_at(&self.data, at).unwrap_or(0)))
    }

    /// The name string index of method `index`.
    pub fn method_name_idx(&self, index: u32) -> Result<u32> {
        let at = self.id(self.header.methods, 8, index, "method")?;
        Ok(u32_at(&self.data, at + 4).unwrap_or(NO_INDEX))
    }

    pub fn method(&self, index: u32) -> Result<MethodRef> {
        let at = self.id(self.header.methods, 8, index, "method")?;
        Ok(MethodRef {
            class: self.type_descriptor(u32::from(u16_at(&self.data, at).unwrap_or(0)))?,
            proto: self.proto(u32::from(u16_at(&self.data, at + 2).unwrap_or(0)))?,
            name: self.name(u32_at(&self.data, at + 4).unwrap_or(NO_INDEX))?,
        })
    }

    pub fn method_text(&self, index: u32) -> String {
        self.method(index).map_or_else(|_| format!("<bad method {index}>"), |method| method.text())
    }

    pub fn proto_text(&self, index: u32) -> String {
        self.proto(index).map_or_else(|_| format!("<bad proto {index}>"), |proto| proto.descriptor())
    }

    pub fn method_handle(&self, index: u32) -> Result<MethodHandle> {
        let at = self.id(self.method_handles, 8, index, "method handle")?;
        Ok(MethodHandle { kind: u16_at(&self.data, at).unwrap_or(0), target: u16_at(&self.data, at + 4).unwrap_or(0) })
    }

    pub fn method_handle_text(&self, index: u32) -> String {
        match self.method_handle(index) {
            Ok(handle) if handle.is_field() => {
                format!("{}@{}", handle.kind_name(), self.field_text(u32::from(handle.target)))
            }
            Ok(handle) => format!("{}@{}", handle.kind_name(), self.method_text(u32::from(handle.target))),
            Err(_) => format!("<bad method handle {index}>"),
        }
    }

    /// A call site as text: its bootstrap method handle, name and method type, read from its encoded array.
    pub fn call_site_text(&self, index: u32) -> String {
        let bad = || format!("<bad call site {index}>");
        let Ok(at) = self.id(self.call_sites, 4, index, "call site") else { return bad() };
        let offset = u32_at(&self.data, at).unwrap_or(0) as usize;
        let mut cursor = Cursor::new(&self.data, offset);
        let Ok(count) = cursor.uleb128() else { return bad() };
        let mut parts = Vec::new();
        for _ in 0..count.min(3) {
            let Ok(value) = crate::value::read(&mut cursor) else { return bad() };
            parts.push(match value {
                crate::value::Value::MethodHandle(handle) => self.method_handle_text(handle),
                crate::value::Value::String(string) => format!("\"{}\"", escape(&self.string_text(string))),
                crate::value::Value::MethodType(proto) => self.proto_text(proto),
                other => format!("{other:?}"),
            });
        }
        format!("call_site_{index}({})", parts.join(", "))
    }

    pub fn class_count(&self) -> u32 {
        self.header.classes.count
    }

    pub fn class_def(&self, index: u32) -> Result<ClassDef> {
        let at = self.id(self.header.classes, 32, index, "class_def")?;
        let word = |offset| u32_at(&self.data, at + offset).unwrap_or(0);
        Ok(ClassDef {
            index,
            class_idx: word(0),
            access: word(4),
            superclass_idx: word(8),
            interfaces_off: word(12),
            source_file_idx: word(16),
            annotations_off: word(20),
            class_data_off: word(24),
            static_values_off: word(28),
        })
    }

    /// The first `max` interfaces `class` implements, and how many it declares.
    /// Only those `max` entries are read.
    pub fn interfaces(&self, class: &ClassDef, max: usize) -> Result<(Vec<u16>, usize)> {
        let offset = class.interfaces_off;
        if offset == 0 {
            return Ok((Vec::new(), 0));
        }
        let mut cursor = Cursor::new(&self.data, offset as usize);
        let count = cursor.u32()?;
        if count > MAX_TYPE_LIST || (offset as usize + 4).saturating_add(count as usize * 2) > self.data.len() {
            return Err(malformed(format!("type_list at {offset:#x} declares {count} entries")));
        }
        let first = (0..(count as usize).min(max)).map(|_| cursor.u16()).collect::<Result<_>>()?;
        Ok((first, count as usize))
    }

    /// The superclass type of class_def `index`, read without the rest of the definition.
    fn superclass_of(&self, index: u32) -> Option<u32> {
        let at = self.id(self.header.classes, 32, index, "class_def").ok()?;
        u32_at(&self.data, at + 8)
    }

    /// The class_def defining type `type_idx`, when this file defines it.
    pub fn class_def_for_type(&self, type_idx: u32) -> Option<u32> {
        self.classes_by_type.get(&type_idx).copied()
    }

    /// The superclass descriptors of `class`, nearest first, as far as this file defines them, cut at
    /// [`Limits::max_hierarchy`] levels; a cycle ends the walk. The last entry may be a class defined elsewhere.
    pub fn superclasses(&self, class: &ClassDef) -> Vec<String> {
        let mut chain = Vec::new();
        let mut seen = vec![class.class_idx];
        let mut next = class.superclass_idx;
        while next != NO_INDEX && chain.len() < self.limits.max_hierarchy {
            if seen.contains(&next) {
                break;
            }
            seen.push(next);
            chain.push(self.type_text(next));
            next = match self.class_def_for_type(next).and_then(|index| self.superclass_of(index)) {
                Some(superclass) => superclass,
                None => break,
            };
        }
        chain
    }

    /// The fields and methods of `class`, charging each decoded member to `budget` (see [`Limits::max_members`]).
    pub fn class_data(&self, class: &ClassDef, budget: &mut usize) -> Result<ClassData> {
        if class.class_data_off == 0 {
            return Ok(ClassData::default());
        }
        let mut cursor = Cursor::new(&self.data, class.class_data_off as usize);
        let sizes = [cursor.uleb128()?, cursor.uleb128()?, cursor.uleb128()?, cursor.uleb128()?];
        let total: u64 = sizes.iter().map(|&size| u64::from(size)).sum();
        // Each encoded member takes at least two bytes, so a count beyond that is a lie, not a large class.
        if total * 2 > (self.data.len() - cursor.pos) as u64 {
            return Err(malformed(format!(
                "class_data at {:#x} declares {total} members, more than fit",
                class.class_data_off
            )));
        }
        if *budget < total as usize {
            return Err(DexError::Limit(format!("more than {} class members decoded", self.limits.max_members)));
        }
        *budget -= total as usize;
        let mut data = ClassData::default();
        for (slot, &count) in sizes.iter().enumerate().take(2) {
            let mut index = 0u32;
            let mut fields = Vec::with_capacity(count as usize);
            for _ in 0..count {
                index = index.checked_add(cursor.uleb128()?).ok_or_else(|| malformed("field index overflows"))?;
                fields.push(EncodedField { field_idx: index, access: cursor.uleb128()? });
            }
            if slot == 0 { data.static_fields = fields } else { data.instance_fields = fields }
        }
        for (slot, &count) in sizes.iter().enumerate().skip(2) {
            let mut index = 0u32;
            let mut methods = Vec::with_capacity(count as usize);
            for _ in 0..count {
                index = index.checked_add(cursor.uleb128()?).ok_or_else(|| malformed("method index overflows"))?;
                methods.push(EncodedMethod {
                    method_idx: index,
                    access: cursor.uleb128()?,
                    code_off: cursor.uleb128()?,
                });
            }
            if slot == 2 { data.direct_methods = methods } else { data.virtual_methods = methods }
        }
        Ok(data)
    }

    /// The initial values of `class`'s static fields (`fields`, its class data's static fields in order) from its
    /// `static_values`, at most `max`: `(field_idx, value)`. Reading stops at an array or annotation value.
    pub fn static_values(&self, class: &ClassDef, fields: &[EncodedField], max: usize) -> Vec<(u32, InitialValue)> {
        if class.static_values_off == 0 {
            return Vec::new();
        }
        let mut cursor = Cursor::new(&self.data, class.static_values_off as usize);
        let Ok(size) = cursor.uleb128() else { return Vec::new() };
        let mut out = Vec::new();
        for field in fields.iter().take((size as usize).min(max)) {
            let Ok(value) = crate::value::read(&mut cursor) else { break };
            let value = match value {
                crate::value::Value::Int(value) => InitialValue::Int(value),
                crate::value::Value::Bool(value) => InitialValue::Int(i64::from(value)),
                crate::value::Value::String(index) => match self.string(index) {
                    Ok(text) => InitialValue::String(text.text.clone()),
                    Err(_) => InitialValue::Other,
                },
                crate::value::Value::Null => InitialValue::Null,
                crate::value::Value::Array | crate::value::Value::Annotation => {
                    out.push((field.field_idx, InitialValue::Other));
                    break;
                }
                _ => InitialValue::Other,
            };
            out.push((field.field_idx, value));
        }
        out
    }

    /// The method body at `offset`, with its try ranges and handlers.
    pub fn code_item(&self, offset: u32) -> Result<CodeItem> {
        if offset < 0x70 || !offset.is_multiple_of(4) {
            return Err(malformed(format!("code_item offset {offset:#x}")));
        }
        let mut cursor = Cursor::new(&self.data, offset as usize);
        let registers = cursor.u16()?;
        let ins = cursor.u16()?;
        let outs = cursor.u16()?;
        let tries_size = cursor.u16()?;
        let debug_info_off = cursor.u32()?;
        let units = cursor.u32()?;
        if units > self.limits.max_code_units {
            return Err(DexError::Limit(format!(
                "method body of {units} code units is above the {}-unit cap",
                self.limits.max_code_units
            )));
        }
        if ins > registers {
            return Err(malformed(format!("code_item at {offset:#x}: {ins} ins exceed {registers} registers")));
        }
        let bytes = cursor
            .bytes(units as usize * 2)
            .map_err(|_| malformed(format!("code_item at {offset:#x}: {units} code units run past the end")))?;
        let insns: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
        let mut tries = Vec::new();
        let mut handlers: Vec<Vec<Catch>> = Vec::new();
        if tries_size > 0 {
            if units % 2 == 1 {
                cursor.u16()?;
            }
            let mut raw = Vec::with_capacity(usize::from(tries_size));
            for _ in 0..tries_size {
                raw.push((cursor.u32()?, cursor.u16()?, cursor.u16()?));
            }
            let handlers_at = cursor.pos;
            let mut list = Cursor::new(&self.data, handlers_at);
            let list_size = list.uleb128()?;
            if u64::from(list_size) > (self.data.len() - handlers_at) as u64 {
                return Err(malformed(format!("code_item at {offset:#x}: {list_size} handler lists do not fit")));
            }
            let mut by_offset: HashMap<u16, usize> = HashMap::new();
            let mut clauses = 0usize;
            for (start, count, handler_off) in raw {
                if u64::from(start) + u64::from(count) > u64::from(units) {
                    return Err(malformed(format!("try range {start:#x}+{count} runs past the {units}-unit body")));
                }
                if let Some(&index) = by_offset.get(&handler_off) {
                    tries.push(Try { start, count, handler: index });
                    continue;
                }
                let mut handler = Cursor::new(&self.data, handlers_at + usize::from(handler_off));
                let size = handler.sleb128()?;
                let typed = size.unsigned_abs() as usize;
                clauses = clauses.saturating_add(typed + usize::from(size <= 0));
                if clauses > MAX_CLAUSES {
                    return Err(DexError::Limit(format!(
                        "code_item at {offset:#x}: more than {MAX_CLAUSES} catch clauses"
                    )));
                }
                let mut catches = Vec::with_capacity(typed.min(1024));
                for _ in 0..typed {
                    catches.push(Catch { type_idx: Some(handler.uleb128()?), address: handler.uleb128()? });
                }
                if size <= 0 {
                    catches.push(Catch { type_idx: None, address: handler.uleb128()? });
                }
                by_offset.insert(handler_off, handlers.len());
                tries.push(Try { start, count, handler: handlers.len() });
                handlers.push(catches);
            }
        }
        Ok(CodeItem { offset, registers, ins, outs, debug_info_off, insns, tries, handlers })
    }
}

/// `text` cut to at most [`MAX_NAME_BYTES`] at a character boundary, marked with `…` when cut.
pub fn cut(text: &str) -> String {
    if text.len() <= MAX_NAME_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_NAME_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// Escapes a string for display in quotes: backslash, quote and control characters.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

/// `Lcom/example/Foo;` as `com.example.Foo`, `[I` as `int[]`; other text unchanged.
pub fn java_name(descriptor: &str) -> String {
    let dims = descriptor.bytes().take_while(|&byte| byte == b'[').count();
    let base = &descriptor[dims..];
    let name = match base {
        "V" => "void".to_owned(),
        "Z" => "boolean".to_owned(),
        "B" => "byte".to_owned(),
        "S" => "short".to_owned(),
        "C" => "char".to_owned(),
        "I" => "int".to_owned(),
        "J" => "long".to_owned(),
        "F" => "float".to_owned(),
        "D" => "double".to_owned(),
        _ => match base.strip_prefix('L').and_then(|rest| rest.strip_suffix(';')) {
            Some(name) => name.replace('/', "."),
            None => base.to_owned(),
        },
    };
    name + &"[]".repeat(dims)
}

/// `com.example.Foo` as `Lcom/example/Foo;`; a descriptor is returned unchanged.
pub fn descriptor_of(name: &str) -> String {
    if name.starts_with('L') && name.ends_with(';') || name.starts_with('[') {
        return name.to_owned();
    }
    format!("L{};", name.replace('.', "/"))
}

/// The names of the access flags set in `flags` for a class, field or method.
pub fn access_names(flags: u32, kind: Member) -> Vec<&'static str> {
    let table: &[(u32, &str)] = &[
        (0x1, "public"),
        (0x2, "private"),
        (0x4, "protected"),
        (0x8, "static"),
        (0x10, "final"),
        (0x20, "synchronized"),
        (0x40, if kind == Member::Field { "volatile" } else { "bridge" }),
        (0x80, if kind == Member::Field { "transient" } else { "varargs" }),
        (0x100, "native"),
        (0x200, "interface"),
        (0x400, "abstract"),
        (0x800, "strict"),
        (0x1000, "synthetic"),
        (0x2000, "annotation"),
        (0x4000, "enum"),
        (0x1_0000, "constructor"),
        (0x2_0000, "declared-synchronized"),
    ];
    table
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .filter(|(bit, _)| match kind {
            Member::Class => !matches!(bit, 0x20 | 0x40 | 0x80 | 0x100 | 0x800 | 0x1_0000 | 0x2_0000),
            Member::Field => !matches!(bit, 0x20 | 0x100 | 0x200 | 0x400 | 0x800 | 0x2000 | 0x1_0000 | 0x2_0000),
            Member::Method => !matches!(bit, 0x200 | 0x2000 | 0x4000),
        })
        .map(|(_, name)| *name)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Member {
    Class,
    Field,
    Method,
}

pub const ACC_NATIVE: u32 = 0x100;
