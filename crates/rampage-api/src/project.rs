use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use rampage_analysis::discover::{Program, Xref, XrefKind};
use rampage_analysis::functions::{self, Names};
use rampage_analysis::strings::{self, FoundString};
use rampage_arch::{Arch, Flow, UnsupportedArch, decoder_for};
use rampage_loaders::{Binary, Format, LoadError, Section, Segment};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{path}")]
    Load { path: PathBuf, source: LoadError },
    #[error(transparent)]
    Unsupported(#[from] UnsupportedArch),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
}

type ProjectKey = (PathBuf, Option<Arch>);

/// Loaded binaries keyed by path and requested architecture, each analyzed at most once.
#[derive(Default)]
pub struct Session {
    projects: Mutex<HashMap<ProjectKey, Arc<Project>>>,
}

impl Session {
    pub fn open(&self, path: &Path, arch: Option<Arch>) -> Result<Arc<Project>, ApiError> {
        let key = (path.canonicalize().unwrap_or_else(|_| path.to_owned()), arch);
        if let Some(project) = self.projects.lock().expect("session lock").get(&key) {
            return Ok(Arc::clone(project));
        }
        let binary =
            Binary::open_with(path, arch).map_err(|source| ApiError::Load { path: path.to_owned(), source })?;
        let project = Arc::new(Project::new(binary));
        self.projects.lock().expect("session lock").entry(key).or_insert_with(|| Arc::clone(&project));
        Ok(project)
    }
}

pub struct Project {
    pub binary: Binary,
    names: Names,
    analysis: OnceLock<Result<Analysis, UnsupportedArch>>,
}

struct Analysis {
    program: Program,
    /// The project's names plus names only analysis can find (import thunks).
    names: Names,
    /// The program's cross-references sorted by source address.
    xrefs_by_source: Vec<Xref>,
    /// Every block as (start, end, function), sorted by start, for address-to-function lookups.
    blocks: Vec<(u64, u64, u64)>,
}

#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct FunctionsQuery {
    /// Only functions whose name contains this text (case-insensitive).
    pub name_contains: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct StringsQuery {
    /// Minimum length in characters (default 4).
    pub min_len: Option<usize>,
    /// Only strings containing this text (case-insensitive).
    pub contains: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone)]
pub enum XrefQuery {
    /// References whose target is this address.
    To(u64),
    /// References made by the function starting at this address, or by the instruction at it.
    From(u64),
}

#[derive(Debug, Serialize)]
pub struct Page<T> {
    pub total: usize,
    pub offset: usize,
    pub items: Vec<T>,
}

#[derive(Debug, Serialize)]
pub struct Summary<'a> {
    pub format: Format,
    pub arch: Arch,
    pub slices: &'a [Arch],
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub entry: Option<u64>,
    pub segments: &'a [Segment],
    pub sections: &'a [Section],
    pub symbols: usize,
    pub imports: usize,
    pub exports: usize,
    pub function_starts: usize,
    pub warnings: &'a [String],
}

#[derive(Debug, Serialize)]
pub struct FunctionRow {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
    /// Bytes covered by the function's blocks.
    pub size: u64,
    pub blocks: usize,
    pub instructions: usize,
}

#[derive(Debug, Serialize)]
pub struct DisassemblyLine {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub bytes: String,
    pub text: String,
    pub flow: Flow,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub data_ref: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub immediate: Option<u64>,
    /// Symbol or function name at this address, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// What the instruction refers to: the name of its branch target or data reference, or the string there.
    /// For an immediate it is a guess: the number may only happen to equal an address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct XrefRow {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub from: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub to: u64,
    pub kind: XrefKind,
    pub from_function: Option<String>,
    pub to_name: Option<String>,
}

fn page<T>(items: Vec<T>, offset: Option<usize>, limit: Option<usize>) -> Page<T> {
    let total = items.len();
    let offset = offset.unwrap_or(0).min(total);
    let items = items.into_iter().skip(offset).take(limit.unwrap_or(usize::MAX)).collect();
    Page { total, offset, items }
}

fn contains_ignoring_case(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

impl Project {
    pub fn new(binary: Binary) -> Self {
        let names = Names::new(&binary);
        Self { binary, names, analysis: OnceLock::new() }
    }

    pub fn summary(&self) -> Summary<'_> {
        let binary = &self.binary;
        Summary {
            format: binary.format,
            arch: binary.arch,
            slices: &binary.slices,
            entry: binary.entry,
            segments: &binary.segments,
            sections: &binary.sections,
            symbols: binary.symbols.len(),
            imports: binary.imports.len(),
            exports: binary.exports.len(),
            function_starts: binary.function_starts.len(),
            warnings: &binary.warnings,
        }
    }

    fn analysis(&self) -> Result<&Analysis, ApiError> {
        let analysis = self.analysis.get_or_init(|| {
            let program = functions::analyze(&self.binary)?;
            let mut blocks: Vec<(u64, u64, u64)> = program
                .functions
                .iter()
                .flat_map(|function| function.blocks.iter().map(|block| (block.start, block.end, function.address)))
                .collect();
            blocks.sort_unstable();
            let mut xrefs_by_source = program.xrefs.clone();
            xrefs_by_source.sort_unstable_by_key(|xref| (xref.from, xref.to));
            let mut names = Names::new(&self.binary);
            names.extend(functions::thunk_names(&self.binary, &program));
            Ok(Analysis { program, names, xrefs_by_source, blocks })
        });
        analysis.as_ref().map_err(|error| ApiError::Unsupported(UnsupportedArch(error.0)))
    }

    /// Names known so far: the binary's own, plus analysis-found ones once analysis has run.
    fn names(&self) -> &Names {
        match self.analysis.get() {
            Some(Ok(analysis)) => &analysis.names,
            _ => &self.names,
        }
    }

    /// Parses `0x` hex, decimal, a symbol or export name, or a `sub_<hex>` name.
    pub fn resolve(&self, text: &str) -> Result<u64, ApiError> {
        let text = text.trim();
        if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            return u64::from_str_radix(hex, 16)
                .map_err(|_| ApiError::Invalid(format!("invalid hex address {text:?}")));
        }
        if let Ok(address) = text.parse() {
            return Ok(address);
        }
        if let Some(address) = self.names.address_of(text) {
            return Ok(address);
        }
        // Import thunks are only named once analysis has found them.
        if !text.starts_with("sub_")
            && let Ok(analysis) = self.analysis()
            && let Some(address) = analysis.names.address_of(text)
        {
            return Ok(address);
        }
        if let Some(address) = text.strip_prefix("sub_").and_then(|hex| u64::from_str_radix(hex, 16).ok()) {
            return Ok(address);
        }
        Err(ApiError::NotFound(format!("no symbol or export named {text:?}")))
    }

    pub fn functions(&self, query: &FunctionsQuery) -> Result<Page<FunctionRow>, ApiError> {
        let analysis = self.analysis()?;
        let rows = analysis
            .program
            .functions
            .iter()
            .map(|function| FunctionRow {
                address: function.address,
                name: self.names().function_name(function.address),
                size: function.blocks.iter().map(|block| block.end - block.start).sum(),
                blocks: function.blocks.len(),
                instructions: function.instruction_count,
            })
            .filter(|row| query.name_contains.as_deref().is_none_or(|needle| contains_ignoring_case(&row.name, needle)))
            .collect();
        Ok(page(rows, query.offset, query.limit))
    }

    /// The start of the function whose block contains `address`, preferring the latest-starting block.
    pub fn function_containing(&self, address: u64) -> Result<Option<u64>, ApiError> {
        let blocks = &self.analysis()?.blocks;
        let candidates = blocks.partition_point(|&(start, _, _)| start <= address);
        Ok(blocks[..candidates]
            .iter()
            .rev()
            .take(16)
            .find(|&&(_, end, _)| address < end)
            .map(|&(_, _, function)| function))
    }

    pub fn disassemble(&self, at: Option<&str>, count: usize) -> Result<Vec<DisassemblyLine>, ApiError> {
        let mut decoder = decoder_for(self.binary.arch)?;
        let start = match at {
            Some(text) => self.resolve(text)?,
            None => self
                .binary
                .entry
                .ok_or_else(|| ApiError::Invalid("no entry point; pass an address or symbol".to_owned()))?,
        };
        let code = self
            .binary
            .read_to_segment_end(start)
            .ok_or_else(|| ApiError::Invalid(format!("address {start:#x} is not backed by file data")))?;

        let mut lines = Vec::with_capacity(count.min(4096));
        let mut offset = 0;
        while lines.len() < count && offset < code.len() {
            let address = start + offset as u64;
            let insn = decoder.decode(&code[offset..], address);
            let bytes = &code[offset..offset + usize::from(insn.len)];
            lines.push(DisassemblyLine {
                address,
                bytes: bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
                text: decoder.format(bytes, address),
                flow: insn.flow,
                data_ref: insn.data_ref,
                immediate: insn.immediate,
                label: self.names().get(address).map(str::to_owned),
                comment: self.describe_reference(&insn),
            });
            offset += usize::from(insn.len);
        }
        Ok(lines)
    }

    /// Names what an instruction refers to: its branch target or data reference by name, or the string stored
    /// at the data reference.
    fn describe_reference(&self, insn: &rampage_arch::Insn) -> Option<String> {
        let target = match insn.flow {
            Flow::Call(target) | Flow::Jump(target) | Flow::ConditionalJump(target) => Some(target),
            _ => None,
        };
        if let Some(name) = target.and_then(|target| self.names().get(target)) {
            return Some(name.to_owned());
        }
        // A pointer-sized immediate (x86 `mov`/`push`) counts only when it names something or points at a string.
        let data = insn.data_ref.or(insn.immediate)?;
        if let Some(name) = self.names().get(data) {
            return Some(name.to_owned());
        }
        string_at(&self.binary, data).map(|text| format!("{text:?}"))
    }

    pub fn strings(&self, query: &StringsQuery) -> Page<FoundString> {
        let found = strings::scan(&self.binary, query.min_len.unwrap_or(4))
            .into_iter()
            .filter(|string| {
                query.contains.as_deref().is_none_or(|needle| contains_ignoring_case(&string.text, needle))
            })
            .collect();
        page(found, query.offset, query.limit)
    }

    pub fn xrefs(&self, query: &XrefQuery) -> Result<Vec<XrefRow>, ApiError> {
        let analysis = self.analysis()?;
        let from_range = |start: u64, end: u64| {
            let by_source = &analysis.xrefs_by_source;
            let first = by_source.partition_point(|xref| xref.from < start);
            let last = by_source.partition_point(|xref| xref.from < end);
            &by_source[first..last]
        };
        let mut selected: Vec<Xref> = match *query {
            XrefQuery::To(address) => analysis.program.xrefs_to(address).to_vec(),
            XrefQuery::From(address) => match analysis.program.function_at(address) {
                Some(function) => {
                    function.blocks.iter().flat_map(|block| from_range(block.start, block.end)).copied().collect()
                }
                None => from_range(address, address.saturating_add(1)).to_vec(),
            },
        };
        selected.sort_unstable();
        selected.dedup();
        let mut rows = selected
            .iter()
            .map(|xref| {
                Ok(XrefRow {
                    from: xref.from,
                    to: xref.to,
                    kind: xref.kind,
                    from_function: self
                        .function_containing(xref.from)?
                        .map(|function| self.names().function_name(function)),
                    to_name: self.names().get(xref.to).map(str::to_owned),
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?;
        rows.sort_by_key(|row| (row.from, row.to));
        Ok(rows)
    }
}

/// The NUL-terminated printable ASCII string at `address`, if there is one of at least four characters. Long
/// strings are cut at 80 characters.
fn string_at(binary: &Binary, address: u64) -> Option<String> {
    const LIMIT: usize = 80;
    let bytes = binary.read_to_segment_end(address)?;
    let text: Vec<u8> = bytes.iter().copied().take_while(|&byte| byte != 0).take(LIMIT + 1).collect();
    let printable = |byte: u8| byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' || byte == b'\n';
    if text.len() < 4 || !text.iter().all(|&byte| printable(byte)) {
        return None;
    }
    let mut text = String::from_utf8_lossy(&text[..text.len().min(LIMIT)]).into_owned();
    if bytes.len() > LIMIT && bytes[..=LIMIT].iter().all(|&byte| byte != 0) {
        text.push_str("...");
    }
    Some(text)
}
