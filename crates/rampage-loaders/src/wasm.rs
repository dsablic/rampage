//! WebAssembly: a bounded, read-only summary of a core module (sections, index-space counts, start function, custom
//! sections, the `name` and `producers` sections) and its imports, exports and functions, parsed with `wasmparser`.
//! Nothing is validated, compiled or executed; component-model binaries are recognised and reported unsupported.

use std::path::Path;

use serde::Serialize;
use wasmparser::{CompositeInnerType, KnownCustom, Name, Parser, Payload, TypeRef};

use crate::LoadError;
use crate::carve::map_regular_file;
use crate::warnings::CappedWarnings;

/// The most sections retained in [`WasmModule::sections`]; later ones are counted only.
pub const MAX_SECTIONS: usize = 64;
/// The most custom-section names retained.
pub const MAX_CUSTOM_SECTIONS: usize = 32;
/// The most imports, exports and functions each retained.
pub const MAX_ITEMS: usize = 65_536;
/// The most section items (types, imports, functions, exports, names, bodies) decoded in one parse.
pub const MAX_DECODED: usize = 1 << 20;
/// The longest import, export or function name or signature retained, in bytes; longer ones are cut at a char
/// boundary and marked with `...`.
pub const MAX_TEXT_BYTES: usize = 256;
/// The longest custom-section name or producers string retained, in bytes, so that the summary stays small.
pub const MAX_LABEL_BYTES: usize = 64;
const MAX_PRODUCER_FIELDS: usize = 8;
const MAX_PRODUCER_VALUES: usize = 8;
/// The most limitations listed; one of each kind is listed and repeats are counted (see [`Limit`]).
const MAX_LIMITATIONS: usize = 32;
const LIMITATIONS: CappedWarnings = CappedWarnings::new(MAX_LIMITATIONS, "WebAssembly");

/// What a `.wasm` file holds: a core module is parsed, a component (layer 1) is only recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WasmEncoding {
    Module,
    Component,
}

#[derive(Debug, Clone, Serialize)]
pub struct WasmSection {
    pub id: u8,
    /// The section's spec name (`type`, `import`, ...), or the custom section's own name.
    pub name: String,
    /// File offset of the section contents, after its id and size.
    pub offset: u64,
    pub size: u64,
}

/// Index-space counts. Imported functions, tables, memories, globals and tags are counted in `imports` (and
/// imported functions again in `imported_functions`), not in the defined counts.
#[derive(Debug, Clone, Default, Serialize)]
pub struct WasmCounts {
    pub types: u32,
    pub imports: u32,
    pub imported_functions: u32,
    pub functions: u32,
    pub tables: u32,
    pub memories: u32,
    pub globals: u32,
    pub tags: u32,
    pub exports: u32,
    pub data_segments: u32,
    pub elem_segments: u32,
    /// The data-count section's value, when present.
    pub data_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WasmProducerValue {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WasmProducerField {
    /// `language`, `processed-by` or `sdk` (or another field a producer wrote).
    pub field: String,
    pub values: Vec<WasmProducerValue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WasmImport {
    /// The import's position in the import section, counting every flattened import.
    pub index: u32,
    pub module: String,
    pub name: String,
    /// `func`, `table`, `memory`, `global` or `tag`.
    pub kind: &'static str,
    /// The function index this import takes, for a function import.
    pub function_index: Option<u32>,
    pub type_index: Option<u32>,
    /// The function signature, or the table, memory, global or tag type.
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WasmExport {
    pub name: String,
    /// `func`, `table`, `memory`, `global` or `tag`.
    pub kind: &'static str,
    /// Index into the kind's index space (imports first).
    pub index: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct WasmFunction {
    /// Function index, imports first.
    pub index: u32,
    pub imported: bool,
    pub type_index: Option<u32>,
    pub signature: Option<String>,
    /// File offset and size of the body (locals and code), for a defined function.
    pub body_offset: Option<u64>,
    pub body_size: Option<u64>,
    /// The `name` section's function name.
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WasmModule {
    pub file_size: u64,
    pub encoding: WasmEncoding,
    /// The header's version field (1 for core modules) and layer field (0 module, 1 component).
    pub version: u16,
    pub layer: u16,
    /// Whether the binary was parsed: false for a component, whose sections are not read.
    pub supported: bool,
    pub sections: Vec<WasmSection>,
    pub sections_total: usize,
    pub counts: WasmCounts,
    pub start_function: Option<u32>,
    pub custom_sections: Vec<String>,
    pub custom_sections_total: usize,
    /// The `name` section's module name.
    pub module_name: Option<String>,
    pub producers: Vec<WasmProducerField>,
    /// Whether every section was parsed and every item retained.
    pub complete: bool,
    pub limitations: Vec<String>,
    #[serde(skip)]
    pub imports: Vec<WasmImport>,
    #[serde(skip)]
    pub exports: Vec<WasmExport>,
    /// Imported functions first, then defined ones, in function-index order.
    #[serde(skip)]
    pub functions: Vec<WasmFunction>,
}

/// Parses the regular file at `path`, or returns `None` when it does not start with the `\0asm` magic.
pub fn wasm_file(path: &Path) -> Result<Option<WasmModule>, LoadError> {
    Ok(match map_regular_file(path)? {
        Some(data) => parse(&data),
        None => None,
    })
}

/// Parses `data` as a WebAssembly binary, or returns `None` when it does not start with the `\0asm` magic. Malformed
/// input yields what was parsed before the error, with `complete` false and the error in `limitations`.
pub fn parse(data: &[u8]) -> Option<WasmModule> {
    if data.len() < 8 || &data[..4] != b"\0asm" {
        return None;
    }
    let version = u16::from_le_bytes([data[4], data[5]]);
    let layer = u16::from_le_bytes([data[6], data[7]]);
    let mut module = WasmModule {
        file_size: data.len() as u64,
        encoding: if layer == 1 { WasmEncoding::Component } else { WasmEncoding::Module },
        version,
        layer,
        supported: layer == 0,
        sections: Vec::new(),
        sections_total: 0,
        counts: WasmCounts::default(),
        start_function: None,
        custom_sections: Vec::new(),
        custom_sections_total: 0,
        module_name: None,
        producers: Vec::new(),
        complete: true,
        limitations: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        functions: Vec::new(),
    };
    if layer != 0 {
        module.complete = false;
        module.limitations.push(if layer == 1 {
            "Component-model binary (layer 1): unsupported; only core modules are parsed, so no sections were read."
                .to_owned()
        } else {
            format!("Unknown layer {layer}: not a core module; no sections were read.")
        });
        return Some(module);
    }
    Walk {
        module: &mut module,
        decoded: 0,
        types: Vec::new(),
        defined: 0,
        names: std::collections::BTreeMap::new(),
        repeats: Vec::new(),
    }
    .run(data);
    Some(module)
}

struct Walk<'m> {
    module: &'m mut WasmModule,
    decoded: usize,
    /// Each type's signature (or composite type), by type index.
    types: Vec<String>,
    /// Code-section bodies seen, matched to defined functions in order.
    defined: usize,
    /// Function names from the `name` section by function index (the first of repeats), applied once the function
    /// list is complete.
    names: std::collections::BTreeMap<u32, String>,
    /// How often each kind of limitation recurred after its first, listed, occurrence.
    repeats: Vec<(Limit, usize)>,
}

/// What kind of limitation a parse met. Only the first of each kind is described; the rest are counted, so hostile
/// input (millions of unknown sections) cannot grow the list or make recording it quadratic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Limit {
    Malformed,
    Budget,
    Sections,
    Imports,
    Exports,
    Functions,
    CustomSection,
    UnknownSection,
    RepeatedName,
    ProducerFields,
    ProducerValues,
}

impl Limit {
    /// Whether each repeat is a separate problem in the input worth counting, rather than one cap hit again.
    fn repeats_are_findings(self) -> bool {
        matches!(self, Limit::CustomSection | Limit::UnknownSection | Limit::RepeatedName | Limit::ProducerValues)
    }
}

impl Walk<'_> {
    fn run(mut self, data: &[u8]) {
        for payload in Parser::new(0).parse_all(data) {
            let payload = match payload {
                Ok(payload) => payload,
                Err(error) => {
                    let text = format!("malformed at file offset {:#x}: {}", error.offset(), error.message());
                    self.limit(Limit::Malformed, || text);
                    break;
                }
            };
            if let Some((id, range)) = payload.as_section() {
                // Sections are charged to the decode budget too, so a file of millions of empty ones stays cheap.
                if !self.budget() {
                    break;
                }
                self.section(id, &payload, range);
            }
            if let Err(error) = self.payload(payload) {
                let text = format!("malformed at file offset {:#x}: {}", error.offset(), error.message());
                self.limit(Limit::Malformed, || text);
                break;
            }
        }
        self.finish();
    }

    /// Records a limitation of `kind`: described by `text` the first time, counted after that.
    fn limit(&mut self, kind: Limit, text: impl FnOnce() -> String) {
        self.module.complete = false;
        match self.repeats.iter_mut().find(|(seen, _)| *seen == kind) {
            Some((_, count)) => *count += 1,
            None => {
                self.repeats.push((kind, 0));
                LIMITATIONS.push(&mut self.module.limitations, text());
            }
        }
    }

    /// Counts one decoded item against [`MAX_DECODED`]; false once the budget is spent.
    fn budget(&mut self) -> bool {
        if self.decoded >= MAX_DECODED {
            self.limit(Limit::Budget, || {
                format!("decode budget of {MAX_DECODED} sections and section items spent; later ones are not listed")
            });
            return false;
        }
        self.decoded += 1;
        true
    }

    fn section(&mut self, id: u8, payload: &Payload, range: std::ops::Range<usize>) {
        self.module.sections_total += 1;
        let name = match payload {
            Payload::CustomSection(custom) => {
                self.module.custom_sections_total += 1;
                let name = label(custom.name());
                if self.module.custom_sections.len() < MAX_CUSTOM_SECTIONS {
                    self.module.custom_sections.push(name.clone());
                }
                name
            }
            _ => section_name(id).to_owned(),
        };
        if self.module.sections.len() < MAX_SECTIONS {
            self.module.sections.push(WasmSection {
                id,
                name,
                offset: range.start as u64,
                size: (range.end - range.start) as u64,
            });
        } else if self.module.sections.len() == MAX_SECTIONS {
            self.limit(Limit::Sections, || {
                format!("more than {MAX_SECTIONS} sections; later sections are counted, not listed")
            });
        }
    }

    fn payload(&mut self, payload: Payload) -> wasmparser::Result<()> {
        let counts = &mut self.module.counts;
        match payload {
            Payload::TableSection(reader) => counts.tables = reader.count(),
            Payload::MemorySection(reader) => counts.memories = reader.count(),
            Payload::GlobalSection(reader) => counts.globals = reader.count(),
            Payload::TagSection(reader) => counts.tags = reader.count(),
            Payload::ElementSection(reader) => counts.elem_segments = reader.count(),
            Payload::DataSection(reader) => counts.data_segments = reader.count(),
            Payload::DataCountSection { count, .. } => counts.data_count = Some(count),
            Payload::StartSection { func, .. } => self.module.start_function = Some(func),
            Payload::TypeSection(reader) => {
                for group in reader {
                    for sub in group?.types() {
                        if !self.budget() {
                            return Ok(());
                        }
                        self.module.counts.types += 1;
                        self.types.push(clip(&match &sub.composite_type.inner {
                            CompositeInnerType::Func(func) => func.to_string(),
                            _ => sub.to_string(),
                        }));
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import?;
                    if !self.budget() {
                        return Ok(());
                    }
                    let counts = &mut self.module.counts;
                    let index = counts.imports;
                    counts.imports += 1;
                    let (kind, type_index, function_index, description) = match import.ty {
                        TypeRef::Func(ty) | TypeRef::FuncExact(ty) => {
                            counts.imported_functions += 1;
                            ("func", Some(ty), Some(counts.imported_functions - 1), self.signature(ty))
                        }
                        TypeRef::Table(table) => (
                            "table",
                            None,
                            None,
                            format!("{} min {} max {}", table.element_type, table.initial, maximum(table.maximum)),
                        ),
                        TypeRef::Memory(memory) => (
                            "memory",
                            None,
                            None,
                            format!(
                                "{}pages min {} max {}{}",
                                if memory.memory64 { "i64 " } else { "" },
                                memory.initial,
                                maximum(memory.maximum),
                                if memory.shared { " shared" } else { "" }
                            ),
                        ),
                        TypeRef::Global(global) => (
                            "global",
                            None,
                            None,
                            format!("{}{}", if global.mutable { "mut " } else { "" }, global.content_type),
                        ),
                        TypeRef::Tag(tag) => ("tag", Some(tag.func_type_idx), None, self.signature(tag.func_type_idx)),
                    };
                    if let Some(function_index) = function_index {
                        self.push_function(WasmFunction {
                            index: function_index,
                            imported: true,
                            type_index,
                            signature: Some(description.clone()),
                            body_offset: None,
                            body_size: None,
                            name: None,
                        });
                    }
                    if self.module.imports.len() < MAX_ITEMS {
                        self.module.imports.push(WasmImport {
                            index,
                            module: clip(import.module),
                            name: clip(import.name),
                            kind,
                            function_index,
                            type_index,
                            description,
                        });
                    } else {
                        self.limit(Limit::Imports, || {
                            format!("more than {MAX_ITEMS} imports; later imports are counted, not listed")
                        });
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for ty in reader {
                    let ty = ty?;
                    if !self.budget() {
                        return Ok(());
                    }
                    let index = self.module.counts.imported_functions + self.module.counts.functions;
                    self.module.counts.functions += 1;
                    let signature = Some(self.signature(ty));
                    self.push_function(WasmFunction {
                        index,
                        imported: false,
                        type_index: Some(ty),
                        signature,
                        body_offset: None,
                        body_size: None,
                        name: None,
                    });
                }
            }
            Payload::ExportSection(reader) => {
                self.module.counts.exports = reader.count();
                for export in reader {
                    let export = export?;
                    if !self.budget() {
                        return Ok(());
                    }
                    if self.module.exports.len() >= MAX_ITEMS {
                        self.limit(Limit::Exports, || {
                            format!("more than {MAX_ITEMS} exports; later exports are counted, not listed")
                        });
                        break;
                    }
                    self.module.exports.push(WasmExport {
                        name: clip(export.name),
                        kind: external_kind(export.kind),
                        index: export.index,
                    });
                }
            }
            Payload::CodeSectionEntry(body) => {
                if !self.budget() {
                    return Ok(());
                }
                let range = body.range();
                let position = self.module.counts.imported_functions as usize + self.defined;
                self.defined += 1;
                if let Some(function) = self.module.functions.get_mut(position) {
                    function.body_offset = Some(range.start as u64);
                    function.body_size = Some((range.end - range.start) as u64);
                }
            }
            Payload::CustomSection(custom) => {
                let parsed = match custom.as_known() {
                    KnownCustom::Name(reader) => self.name_section(reader),
                    KnownCustom::Producers(reader) => self.producers(reader),
                    _ => Ok(()),
                };
                // A malformed custom section is skipped, not fatal: the module's own sections stand without it.
                if let Err(error) = parsed {
                    self.limit(Limit::CustomSection, || {
                        format!(
                            "custom section `{}` malformed at file offset {:#x}: {}",
                            label(custom.name()),
                            error.offset(),
                            error.message()
                        )
                    });
                }
            }
            Payload::UnknownSection { id, range, .. } => {
                self.limit(Limit::UnknownSection, || {
                    format!("unknown section id {id} at file offset {:#x} skipped", range.start)
                });
            }
            _ => {}
        }
        Ok(())
    }

    fn signature(&self, ty: u32) -> String {
        self.types.get(ty as usize).cloned().unwrap_or_else(|| format!("type {ty} (undefined)"))
    }

    fn push_function(&mut self, function: WasmFunction) {
        if self.module.functions.len() < MAX_ITEMS {
            self.module.functions.push(function);
        } else {
            self.limit(Limit::Functions, || {
                format!("more than {MAX_ITEMS} functions; later functions are counted, not listed")
            });
        }
    }

    fn name_section(&mut self, reader: wasmparser::NameSectionReader) -> wasmparser::Result<()> {
        for name in reader {
            match name? {
                Name::Module { name, .. } => self.module.module_name = Some(clip(name)),
                Name::Function(map) => {
                    for naming in map {
                        let naming = naming?;
                        if !self.budget() {
                            return Ok(());
                        }
                        if (naming.index as usize) >= MAX_ITEMS {
                            continue;
                        }
                        match self.names.entry(naming.index) {
                            std::collections::btree_map::Entry::Vacant(entry) => {
                                entry.insert(clip(naming.name));
                            }
                            std::collections::btree_map::Entry::Occupied(_) => {
                                let index = naming.index;
                                self.limit(Limit::RepeatedName, || {
                                    format!("the name section names function {index} again; the first name is kept")
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn producers(&mut self, reader: wasmparser::ProducersSectionReader) -> wasmparser::Result<()> {
        for field in reader {
            let field = field?;
            if self.module.producers.len() >= MAX_PRODUCER_FIELDS {
                self.limit(Limit::ProducerFields, || {
                    format!("more than {MAX_PRODUCER_FIELDS} producers fields; later fields are not listed")
                });
                break;
            }
            let mut values = Vec::new();
            for value in field.values {
                let value = value?;
                if values.len() >= MAX_PRODUCER_VALUES {
                    self.limit(Limit::ProducerValues, || {
                        format!("more than {MAX_PRODUCER_VALUES} values in a producers field")
                    });
                    break;
                }
                values.push(WasmProducerValue { name: label(value.name), version: label(value.version) });
            }
            self.module.producers.push(WasmProducerField { field: label(field.name), values });
        }
        Ok(())
    }

    fn finish(self) {
        let defined = self.module.counts.functions as usize;
        if self.module.complete && self.defined != defined {
            let text = format!("{} code bodies for {defined} declared functions", self.defined);
            self.module.complete = false;
            LIMITATIONS.push(&mut self.module.limitations, text);
        }
        let repeated: usize =
            self.repeats.iter().filter(|(kind, _)| kind.repeats_are_findings()).map(|(_, count)| count).sum();
        if repeated > 0 {
            let text = format!("{repeated} further limitations repeat a kind listed above and are not listed");
            LIMITATIONS.push(&mut self.module.limitations, text);
        }
        for (index, name) in self.names {
            if let Some(function) = self.module.functions.get_mut(index as usize) {
                function.name = Some(name);
            }
        }
    }
}

fn section_name(id: u8) -> &'static str {
    match id {
        0 => "custom",
        1 => "type",
        2 => "import",
        3 => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        7 => "export",
        8 => "start",
        9 => "element",
        10 => "code",
        11 => "data",
        12 => "data_count",
        13 => "tag",
        _ => "unknown",
    }
}

fn external_kind(kind: wasmparser::ExternalKind) -> &'static str {
    use wasmparser::ExternalKind;
    match kind {
        ExternalKind::Func | ExternalKind::FuncExact => "func",
        ExternalKind::Table => "table",
        ExternalKind::Memory => "memory",
        ExternalKind::Global => "global",
        ExternalKind::Tag => "tag",
    }
}

fn maximum(maximum: Option<u64>) -> String {
    maximum.map_or_else(|| "none".to_owned(), |maximum| maximum.to_string())
}

/// `text` cut to [`MAX_TEXT_BYTES`] at a char boundary, marked with `...` when cut.
fn clip(text: &str) -> String {
    cut(text, MAX_TEXT_BYTES)
}

/// `text` cut to [`MAX_LABEL_BYTES`], as [`clip`] does.
fn label(text: &str) -> String {
    cut(text, MAX_LABEL_BYTES)
}

fn cut(text: &str, max: usize) -> String {
    match crate::text::clip(text, max) {
        (text, false) => text.to_owned(),
        (text, true) => format!("{text}..."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leb(mut value: usize, out: &mut Vec<u8>) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    fn section(id: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![id];
        leb(contents.len(), &mut out);
        out.extend(contents);
        out
    }

    fn string(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        leb(text.len(), &mut out);
        out.extend(text.as_bytes());
        out
    }

    /// A module importing `env.log(i32)`, defining `add(i32, i32) -> i32` and exporting it and a memory.
    fn module() -> Vec<u8> {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        bytes.extend(section(1, &[2, 0x60, 1, 0x7f, 0, 0x60, 2, 0x7f, 0x7f, 1, 0x7f]));
        let mut imports = vec![1];
        imports.extend(string("env"));
        imports.extend(string("log"));
        imports.extend([0, 0]);
        bytes.extend(section(2, &imports));
        bytes.extend(section(3, &[1, 1]));
        bytes.extend(section(5, &[1, 0, 1]));
        let mut exports = vec![2];
        exports.extend(string("add"));
        exports.extend([0, 1]);
        exports.extend(string("memory"));
        exports.extend([2, 0]);
        bytes.extend(section(7, &exports));
        bytes.extend(section(10, &[1, 7, 0, 0x20, 0, 0x20, 1, 0x6a, 0x0b]));
        let mut names = string("name");
        let mut module_name = string("demo");
        let mut sub = vec![0];
        leb(module_name.len(), &mut sub);
        sub.append(&mut module_name);
        names.extend(sub);
        let mut functions = vec![2, 0];
        functions.extend(string("log"));
        functions.push(1);
        functions.extend(string("add"));
        names.push(1);
        leb(functions.len(), &mut names);
        names.extend(functions);
        bytes.extend(section(0, &names));
        let mut producers = string("producers");
        producers.push(1);
        producers.extend(string("language"));
        producers.push(1);
        producers.extend(string("C11"));
        producers.extend(string(""));
        bytes.extend(section(0, &producers));
        bytes
    }

    #[test]
    fn summarises_a_core_module() {
        let module = parse(&module()).unwrap();
        assert!(module.complete, "{:?}", module.limitations);
        assert_eq!((module.encoding, module.version, module.layer), (WasmEncoding::Module, 1, 0));
        let ids: Vec<u8> = module.sections.iter().map(|section| section.id).collect();
        assert_eq!(ids, [1, 2, 3, 5, 7, 10, 0, 0]);
        assert_eq!(module.custom_sections, ["name", "producers"]);
        let counts = &module.counts;
        assert_eq!((counts.types, counts.imports, counts.imported_functions, counts.functions), (2, 1, 1, 1));
        assert_eq!((counts.memories, counts.exports), (1, 2));
        assert_eq!(module.module_name.as_deref(), Some("demo"));
        assert_eq!(module.producers[0].field, "language");
        assert_eq!(module.producers[0].values[0].name, "C11");
        assert_eq!(module.imports[0].description, "(func (param i32))");
        assert_eq!((module.exports[1].name.as_str(), module.exports[1].kind), ("memory", "memory"));
        let add = &module.functions[1];
        assert_eq!((add.index, add.imported, add.name.as_deref()), (1, false, Some("add")));
        assert_eq!(add.signature.as_deref(), Some("(func (param i32 i32) (result i32))"));
        assert_eq!(add.body_size, Some(7));
        assert_eq!(module.functions[0].name.as_deref(), Some("log"));
    }

    #[test]
    fn truncation_at_every_length_never_panics_and_reports_partial_results() {
        let bytes = module();
        for end in 0..bytes.len() {
            let Some(module) = parse(&bytes[..end]) else {
                assert!(end < 8);
                continue;
            };
            if end > 8 {
                assert!(!module.complete || module.sections_total > 0, "{end}");
            }
        }
        let cut = parse(&bytes[..bytes.len() - 3]).unwrap();
        assert!(!cut.complete);
        assert!(cut.limitations.iter().any(|text| text.contains("malformed")), "{:?}", cut.limitations);
        assert_eq!(cut.counts.functions, 1);
    }

    #[test]
    fn hostile_counts_and_components_are_bounded_or_refused() {
        // A function section claiming u32::MAX entries in two bytes.
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        bytes.extend(section(3, &[0xff, 0xff, 0xff, 0xff, 0x0f, 0]));
        let module = parse(&bytes).unwrap();
        assert!(!module.complete);
        assert!(module.functions.len() <= 1);

        let component = parse(b"\0asm\x0d\0\x01\0").unwrap();
        assert_eq!(
            (component.encoding, component.supported, component.complete),
            (WasmEncoding::Component, false, false)
        );
        assert!(component.sections.is_empty());
        assert!(component.limitations[0].contains("Component-model"));
        assert!(parse(b"\x7fELF\x02\x01\x01\0").is_none());
        assert!(parse(b"\0asm").is_none());
    }

    #[test]
    fn a_malformed_name_section_is_skipped_not_fatal() {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        let mut names = string("name");
        names.extend([1, 9, 3]);
        bytes.extend(section(0, &names));
        bytes.extend(section(5, &[1, 0, 1]));
        let module = parse(&bytes).unwrap();
        assert_eq!(module.counts.memories, 1);
        assert!(
            module.limitations.iter().any(|text| text.contains("custom section `name`")),
            "{:?}",
            module.limitations
        );
    }

    #[test]
    fn many_unknown_sections_are_counted_not_listed_and_charged_to_the_budget() {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        bytes.extend([0x20, 0].repeat(MAX_DECODED + 10));
        let started = std::time::Instant::now();
        let module = parse(&bytes).unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(30));
        assert!(!module.complete);
        assert_eq!(module.sections_total, MAX_DECODED);
        assert!(module.limitations.len() <= MAX_LIMITATIONS, "{}", module.limitations.len());
        assert!(module.limitations[0].contains("unknown section id 32"), "{:?}", module.limitations);
        assert!(module.limitations.iter().any(|text| text.contains("decode budget")), "{:?}", module.limitations);
        assert!(
            module.limitations.last().unwrap().contains("further limitations repeat a kind"),
            "{:?}",
            module.limitations
        );
    }

    #[test]
    fn duplicate_misordered_and_surplus_code_bodies_are_flagged() {
        // A second code section: the parser stops at it, keeping what came before.
        let mut duplicate = module();
        duplicate.extend(section(10, &[1, 2, 0, 0x0b]));
        let parsed = parse(&duplicate).unwrap();
        assert!(!parsed.complete);
        assert_eq!(parsed.functions[1].body_size, Some(7), "the first body stays matched");
        assert!(parsed.limitations.iter().any(|text| text.contains("out of order")), "{:?}", parsed.limitations);

        // The code section before the function section declaring its function.
        let mut misordered = b"\0asm\x01\0\0\0".to_vec();
        misordered.extend(section(1, &[1, 0x60, 0, 0]));
        misordered.extend(section(10, &[1, 2, 0, 0x0b]));
        misordered.extend(section(3, &[1, 0]));
        let parsed = parse(&misordered).unwrap();
        assert!(!parsed.complete);
        assert!(parsed.functions.iter().all(|function| function.body_offset.is_none()));

        // More bodies than declared functions.
        let mut surplus = b"\0asm\x01\0\0\0".to_vec();
        surplus.extend(section(1, &[1, 0x60, 0, 0]));
        surplus.extend(section(3, &[1, 0]));
        surplus.extend(section(10, &[2, 2, 0, 0x0b, 2, 0, 0x0b]));
        let parsed = parse(&surplus).unwrap();
        assert!(!parsed.complete);
        assert_eq!(parsed.functions.len(), 1);
        assert!(parsed.limitations.iter().any(|text| text.contains("inconsistent")), "{:?}", parsed.limitations);
    }

    #[test]
    fn a_name_section_repeating_an_index_keeps_the_first_name() {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        bytes.extend(section(1, &[1, 0x60, 0, 0]));
        bytes.extend(section(3, &[1, 0]));
        bytes.extend(section(10, &[1, 2, 0, 0x0b]));
        let repeats = 5_000;
        let mut map = Vec::new();
        leb(repeats, &mut map);
        for index in 0..repeats {
            map.push(0);
            map.extend(string(&format!("f{index}")));
        }
        let mut names = string("name");
        names.push(1);
        leb(map.len(), &mut names);
        names.extend(map);
        bytes.extend(section(0, &names));
        let module = parse(&bytes).unwrap();
        assert_eq!(module.functions[0].name.as_deref(), Some("f0"));
        assert!(!module.complete);
        assert!(module.limitations.len() <= 3, "{:?}", module.limitations);
        assert!(module.limitations[0].contains("names function 0 again"), "{:?}", module.limitations);
    }

    #[test]
    fn long_text_is_clipped_at_a_char_boundary() {
        let text = "é".repeat(MAX_TEXT_BYTES);
        let clipped = clip(&text);
        assert!(clipped.ends_with("...") && clipped.len() <= MAX_TEXT_BYTES + 3);
    }
}
