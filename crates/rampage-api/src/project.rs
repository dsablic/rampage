use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use rampage_analysis::discover::{Program, XrefKind};
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
    /// Symbol or function name at this address, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
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
            Ok(Analysis { program, blocks })
        });
        analysis.as_ref().map_err(|error| ApiError::Unsupported(UnsupportedArch(error.0)))
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
            .map(|function| {
                let end = function.blocks.iter().map(|block| block.end).max().unwrap_or(function.address);
                FunctionRow {
                    address: function.address,
                    name: self.names.function_name(function.address),
                    size: end.saturating_sub(function.address),
                    blocks: function.blocks.len(),
                    instructions: function.instruction_count,
                }
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
                label: self.names.get(address).map(str::to_owned),
            });
            offset += usize::from(insn.len);
        }
        Ok(lines)
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
        let program = &self.analysis()?.program;
        let selected: Vec<_> = match *query {
            XrefQuery::To(address) => program.xrefs_to(address).to_vec(),
            XrefQuery::From(address) => match program.function_at(address) {
                Some(function) => program.xrefs.iter().filter(|xref| function.contains(xref.from)).copied().collect(),
                None => program.xrefs.iter().filter(|xref| xref.from == address).copied().collect(),
            },
        };
        let mut rows = selected
            .iter()
            .map(|xref| {
                Ok(XrefRow {
                    from: xref.from,
                    to: xref.to,
                    kind: xref.kind,
                    from_function: self
                        .function_containing(xref.from)?
                        .map(|function| self.names.function_name(function)),
                    to_name: self.names.get(xref.to).map(str::to_owned),
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?;
        rows.sort_by_key(|row| (row.from, row.to));
        Ok(rows)
    }
}
