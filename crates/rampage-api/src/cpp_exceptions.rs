//! Paged MSVC C++ exception-handling evidence for x86 and x64 PE images: per-function try blocks with typed catch
//! handlers, cleanup (unwind) funclets and SEH scopes, and the thrown types of `_ThrowInfo` records.

use rampage_arch::Arch;
use rampage_loaders::Format;
use rampage_loaders::msvc::{self, EhFunction, ThrowInfo};
use serde::Serialize;

use crate::rows::{fit_window, json_size};
use crate::{ApiError, Project};

/// Room left for the summary and paging fields around one page of rows.
const PAGE_BUDGET: usize = crate::tools::MAX_RESULT_CHARS - 8_000;
pub const DEFAULT_LIMIT: usize = 50;
pub const MAX_LIMIT: usize = 100;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionList {
    /// Functions with exception tables.
    #[default]
    Functions,
    /// `_ThrowInfo` records: the types each thrown object can be caught as.
    Throws,
}

#[derive(Debug, Serialize)]
pub struct Catch {
    /// The caught type, demangled; `...` for a catch-all.
    #[serde(rename = "type")]
    pub caught: String,
    pub by_reference: bool,
    pub is_const: bool,
    /// The catch funclet.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub handler: u64,
}

#[derive(Debug, Serialize)]
pub struct TryRegion {
    pub try_low: i32,
    pub try_high: i32,
    pub catch_high: i32,
    /// Code covered by the try block (x64, from the IP-to-state map); empty on x86.
    pub ranges: Vec<msvc::AddressRange>,
    pub catches: Vec<Catch>,
}

#[derive(Debug, Serialize)]
pub struct HandlerRow {
    /// The function the tables belong to: its unwind range on x64, the function holding the registration on x86.
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub function: Option<u64>,
    pub name: Option<String>,
    pub kind: &'static str,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub handler: Option<u64>,
    pub handler_import: Option<String>,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub table: u64,
    pub max_state: i32,
    pub try_blocks: Vec<TryRegion>,
    /// Destructor-calling cleanup funclets, one per state that has one.
    pub cleanups: Vec<msvc::UnwindAction>,
    pub scopes: Vec<msvc::SehScope>,
}

#[derive(Debug, Serialize)]
pub struct ThrowRow {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    /// Demangled catchable types, the thrown type first, then its public bases.
    pub types: Vec<String>,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub destructor: Option<u64>,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub copy_functions: Vec<u64>,
}

#[derive(Debug, Serialize)]
pub struct ExceptionPage {
    pub functions_total: usize,
    pub try_blocks_total: usize,
    pub catch_handlers_total: usize,
    pub cleanup_funclets_total: usize,
    pub throws_total: usize,
    pub undecoded_handlers: usize,
    pub list: &'static str,
    pub total: usize,
    pub offset: usize,
    pub functions: Vec<HandlerRow>,
    pub throws: Vec<ThrowRow>,
    pub more: bool,
    pub next_offset: Option<usize>,
    pub byte_capped: bool,
    pub warnings: Vec<String>,
    pub limitations: Vec<&'static str>,
}

const LIMITATIONS: [&str; 4] = [
    "Decoded: __CxxFrameHandler3 FuncInfo (x86 and x64), the x64 __C_specific_handler scope table when the handler \
     is an import thunk, and _ThrowInfo records. __CxxFrameHandler4 (compressed tables, /d2FH4) and x86 SEH \
     (_except_handler3/4) are counted or not read; see undecoded_handlers.",
    "x86 tables are found by their FuncInfo version stamp and full validation, and tied to a function only through \
     a `push` of the handler thunk inside it; x86 try blocks carry no code ranges because the state is a frame slot \
     written at run time.",
    "Funclets are code the runtime enters, not calls: catch handlers, cleanups and filters are reported here and \
     seeded as function starts, so they appear as their own functions.",
    "Type names come from RTTI type descriptors; a catch of a type without RTTI shows its stored name.",
];

fn type_name(raw: &str) -> String {
    rampage_analysis::language::msvc_type_name(raw).unwrap_or_else(|| raw.to_owned())
}

fn handler_row(project: &Project, function: EhFunction, owner: Option<u64>) -> HandlerRow {
    let address = function.function.or(owner);
    let try_blocks = function
        .try_blocks
        .into_iter()
        .map(|block| TryRegion {
            try_low: block.try_low,
            try_high: block.try_high,
            catch_high: block.catch_high,
            ranges: block.ranges,
            catches: block
                .catches
                .into_iter()
                .map(|catch| Catch {
                    caught: catch.mangled.as_deref().map_or_else(|| "...".to_owned(), type_name),
                    by_reference: catch.adjectives & 8 != 0,
                    is_const: catch.adjectives & 1 != 0,
                    handler: catch.handler,
                })
                .collect(),
        })
        .collect();
    HandlerRow {
        function: address,
        name: address.map(|address| project.function_name(address)),
        kind: function.kind,
        handler: function.handler,
        handler_import: function.handler_import,
        table: function.table,
        max_state: function.max_state,
        try_blocks,
        cleanups: function.unwind.into_iter().filter(|entry| entry.action.is_some()).collect(),
        scopes: function.scopes,
    }
}

fn throw_row(throw: ThrowInfo) -> ThrowRow {
    ThrowRow {
        address: throw.address,
        types: throw.types.iter().map(|caught| type_name(&caught.mangled)).collect(),
        destructor: throw.destructor,
        copy_functions: throw.types.iter().filter_map(|caught| caught.copy_function).collect(),
    }
}

impl Project {
    /// One page of the image's MSVC exception-handling tables, optionally only those of the function containing
    /// `function`.
    pub fn exception_handlers(
        &self,
        list: ExceptionList,
        function: Option<u64>,
        offset: usize,
        limit: usize,
    ) -> Result<ExceptionPage, ApiError> {
        if self.binary.format != Format::Pe || !matches!(self.binary.arch, Arch::X86 | Arch::X86_64) {
            return Err(ApiError::Invalid("exception handlers are read only from x86 and x64 PE images".to_owned()));
        }
        let limit = limit.clamp(1, MAX_LIMIT);
        let report = msvc::exception_tables(&self.binary);
        let program = &self.analysis()?.program;
        // The nearest preceding discovered function whose blocks hold `address`; funclets are functions of their own
        // and may sit between a parent's blocks, so a few earlier starts are tried.
        let containing = |address: u64| {
            let end = program.functions.partition_point(|found| found.address <= address);
            program.functions[..end]
                .iter()
                .rev()
                .take(64)
                .find(|found| found.contains(address))
                .map(|found| found.address)
        };
        // x86 tables name no function; the function holding a registration of the handler thunk owns them.
        let owners: Vec<Option<u64>> = report
            .functions
            .iter()
            .map(|entry| entry.function.or_else(|| entry.registrations.iter().find_map(|&at| containing(at))))
            .collect();
        let selected = function.map(|address| containing(address).unwrap_or(address));
        let try_blocks_total = report.functions.iter().map(|entry| entry.try_blocks.len()).sum();
        let catch_handlers_total =
            report.functions.iter().flat_map(|entry| &entry.try_blocks).map(|block| block.catches.len()).sum();
        let cleanup_funclets_total =
            report.functions.iter().flat_map(|entry| &entry.unwind).filter(|entry| entry.action.is_some()).count();
        let mut page = ExceptionPage {
            functions_total: report.functions.len(),
            try_blocks_total,
            catch_handlers_total,
            cleanup_funclets_total,
            throws_total: report.throws.len(),
            undecoded_handlers: report.undecoded_handlers,
            list: match list {
                ExceptionList::Functions => "functions",
                ExceptionList::Throws => "throws",
            },
            total: 0,
            offset,
            functions: Vec::new(),
            throws: Vec::new(),
            more: false,
            next_offset: None,
            byte_capped: false,
            warnings: report.warnings,
            limitations: LIMITATIONS.to_vec(),
        };
        let budget = PAGE_BUDGET.saturating_sub(json_size(&page.warnings)?);
        let shown = match list {
            ExceptionList::Functions => {
                let rows: Vec<(EhFunction, Option<u64>)> = report
                    .functions
                    .into_iter()
                    .zip(owners)
                    .filter(|(_, owner)| selected.is_none() || *owner == selected)
                    .collect();
                page.total = rows.len();
                let window = fit_window(
                    rows.into_iter().skip(offset).map(|(entry, owner)| handler_row(self, entry, owner)),
                    limit,
                    budget,
                )?;
                page.byte_capped = window.byte_capped;
                page.functions = window.items;
                page.functions.len()
            }
            ExceptionList::Throws => {
                page.total = report.throws.len();
                let window = fit_window(report.throws.into_iter().skip(offset).map(throw_row), limit, budget)?;
                page.byte_capped = window.byte_capped;
                page.throws = window.items;
                page.throws.len()
            }
        };
        let next = offset.saturating_add(shown);
        page.more = next < page.total;
        page.next_offset = page.more.then_some(next);
        Ok(page)
    }
}
