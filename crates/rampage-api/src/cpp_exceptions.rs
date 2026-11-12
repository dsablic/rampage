//! Paged MSVC C++ evidence for x86 and x64 PE images: per-function try blocks with typed catch handlers, cleanup
//! (unwind) funclets and SEH scopes, the thrown types of `_ThrowInfo` records, and the vftable page of
//! `class_evidence`. Everything is read once at load (`Binary::msvc_metadata`); these views only page it, with
//! every row capped so one function's tables can never exceed a page.

use rampage_analysis::classes::ClassRecovery;
use rampage_arch::Arch;
use rampage_loaders::Format;
use rampage_loaders::msvc::{self, EhFunction, ThrowInfo};
use serde::Serialize;

use crate::rows::{fit_window, json_size};
use crate::{ApiError, Project};

/// Room left for the summary and paging fields around one page of rows.
const PAGE_BUDGET: usize = crate::tools::MAX_RESULT_CHARS - 8_000;
/// Largest JSON size of one row; caps shrink until a row fits.
const ROW_BUDGET: usize = 16_000;
/// Longest demangled type name a row carries.
const MAX_TYPE_NAME_BYTES: usize = 256;
pub const DEFAULT_LIMIT: usize = 50;
pub const MAX_LIMIT: usize = 100;
/// Bytes the vftable page of `class_evidence` may take.
const VFTABLE_PAGE_BUDGET: usize = 24_000;
pub const DEFAULT_VFTABLE_LIMIT: usize = 16;
/// Bytes the RTTI class page of `class_evidence` may take.
const RTTI_CLASS_PAGE_BUDGET: usize = 16_000;
pub const DEFAULT_RTTI_CLASS_LIMIT: usize = 50;
pub const MAX_RTTI_CLASS_LIMIT: usize = 200;

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
    /// The caught type, demangled (at most 256 bytes); `...` for a catch-all.
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
    pub ranges_total: usize,
    pub catches: Vec<Catch>,
    pub catches_total: usize,
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
    /// Exact counts; the lists below hold a capped window starting at `detail_offset`.
    pub try_blocks_total: usize,
    pub cleanups_total: usize,
    pub scopes_total: usize,
    /// The row lists less than all of its try blocks, catches, ranges, cleanups or scopes. Ask again with
    /// `function` set to this function and `detail_offset` to page its try blocks, cleanups and scopes.
    pub truncated: bool,
    pub try_blocks: Vec<TryRegion>,
    /// Destructor-calling cleanup funclets, one per state that has one.
    pub cleanups: Vec<msvc::UnwindAction>,
    pub scopes: Vec<msvc::SehScope>,
}

#[derive(Debug, Serialize)]
pub struct ThrowRow {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    /// Demangled catchable types (at most 256 bytes each), the thrown type first, then its public bases.
    pub types: Vec<String>,
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub destructor: Option<u64>,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub copy_functions: Vec<u64>,
}

#[derive(Debug, Serialize)]
pub struct ExceptionPage {
    pub experimental: bool,
    pub functions_total: usize,
    pub try_blocks_total: usize,
    pub catch_handlers_total: usize,
    pub cleanup_funclets_total: usize,
    pub throws_total: usize,
    pub undecoded_handlers: usize,
    pub warnings: Vec<String>,
    pub list: &'static str,
    pub total: usize,
    pub offset: usize,
    pub detail_offset: usize,
    pub more: bool,
    pub next_offset: Option<usize>,
    pub byte_capped: bool,
    pub functions: Vec<HandlerRow>,
    pub throws: Vec<ThrowRow>,
    pub limitations: Vec<&'static str>,
}

const LIMITATIONS: [&str; 5] = [
    "Experimental: the row shape may change. Validated only on clang-cl output using __CxxFrameHandler3. MSVC \
     cl.exe x64 builds since Visual Studio 2019 16.3 default to __CxxFrameHandler4 (/d2FH4), whose compressed \
     tables are not decoded and are counted in undecoded_handlers; cl.exe x86 places catch blocks inline in the \
     parent function rather than as separate funclets, which has not been validated.",
    "Decoded: __CxxFrameHandler3 FuncInfo (x86 and x64), the x64 __C_specific_handler scope table when the \
     handler is an import thunk, and _ThrowInfo records. x86 SEH (_except_handler3/4) is not read.",
    "x86 tables are found by their FuncInfo version stamp and full validation, and tied to a function only \
     through a store of the handler thunk's address inside it; x86 try blocks carry no code ranges because the \
     state is a frame slot written at run time.",
    "Funclets are code the runtime enters, not calls: catch handlers, cleanups and filters are reported here and \
     seeded as function starts, so they appear as their own functions.",
    "Rows are capped: each lists a window of its try blocks, catches, ranges, cleanups and scopes with exact \
     totals and `truncated`; type names are cut at 256 bytes. Tables were read at load under a bounded budget.",
];

fn type_name(raw: &str) -> String {
    let mut name = rampage_analysis::language::msvc_type_name(raw).unwrap_or_else(|| raw.to_owned());
    if name.len() > MAX_TYPE_NAME_BYTES {
        let mut end = MAX_TYPE_NAME_BYTES;
        while !name.is_char_boundary(end) {
            end -= 1;
        }
        name.truncate(end);
        name.push('…');
    }
    name
}

/// How many of each detail list a row shows; halved until the row fits [`ROW_BUDGET`].
#[derive(Clone, Copy)]
struct Caps {
    try_blocks: usize,
    catches: usize,
    ranges: usize,
    cleanups: usize,
    scopes: usize,
}

impl Caps {
    const START: Caps = Caps { try_blocks: 16, catches: 16, ranges: 16, cleanups: 64, scopes: 32 };

    fn halved(self) -> Option<Caps> {
        let half = |value: usize| (value / 2).max(1);
        let next = Caps {
            try_blocks: half(self.try_blocks),
            catches: half(self.catches),
            ranges: half(self.ranges),
            cleanups: half(self.cleanups),
            scopes: half(self.scopes),
        };
        (next.try_blocks + next.catches + next.ranges + next.cleanups + next.scopes
            < self.try_blocks + self.catches + self.ranges + self.cleanups + self.scopes)
            .then_some(next)
    }
}

fn handler_row(project: &Project, function: &EhFunction, owner: Option<u64>, detail: usize, caps: Caps) -> HandlerRow {
    let address = function.function.or(owner);
    let cleanups: Vec<&msvc::UnwindAction> = function.unwind.iter().filter(|entry| entry.action.is_some()).collect();
    let mut truncated = false;
    let mut window = |total: usize, cap: usize| {
        let shown = total.saturating_sub(detail).min(cap);
        truncated |= shown < total;
        shown
    };
    let try_shown = window(function.try_blocks.len(), caps.try_blocks);
    let cleanups_shown = window(cleanups.len(), caps.cleanups);
    let scopes_shown = window(function.scopes.len(), caps.scopes);
    let try_blocks = function
        .try_blocks
        .iter()
        .skip(detail)
        .take(try_shown)
        .map(|block| {
            truncated |= block.catches.len() > caps.catches || block.ranges.len() > caps.ranges;
            TryRegion {
                try_low: block.try_low,
                try_high: block.try_high,
                catch_high: block.catch_high,
                ranges: block.ranges.iter().take(caps.ranges).cloned().collect(),
                ranges_total: block.ranges.len(),
                catches: block
                    .catches
                    .iter()
                    .take(caps.catches)
                    .map(|catch| Catch {
                        caught: catch.mangled.as_deref().map_or_else(|| "...".to_owned(), type_name),
                        by_reference: catch.adjectives & 8 != 0,
                        is_const: catch.adjectives & 1 != 0,
                        handler: catch.handler,
                    })
                    .collect(),
                catches_total: block.catches.len(),
            }
        })
        .collect();
    HandlerRow {
        function: address,
        name: address.map(|address| project.function_name(address)),
        kind: function.kind,
        handler: function.handler,
        handler_import: function.handler_import.clone(),
        table: function.table,
        max_state: function.max_state,
        try_blocks_total: function.try_blocks.len(),
        cleanups_total: cleanups.len(),
        scopes_total: function.scopes.len(),
        truncated,
        try_blocks,
        cleanups: cleanups.into_iter().skip(detail).take(cleanups_shown).cloned().collect(),
        scopes: function.scopes.iter().skip(detail).take(scopes_shown).cloned().collect(),
    }
}

/// A row that fits [`ROW_BUDGET`], shrinking its detail caps as needed.
fn bounded_row(
    project: &Project,
    function: &EhFunction,
    owner: Option<u64>,
    detail: usize,
) -> Result<HandlerRow, ApiError> {
    let mut caps = Caps::START;
    loop {
        let row = handler_row(project, function, owner, detail, caps);
        if json_size(&row)? <= ROW_BUDGET {
            return Ok(row);
        }
        match caps.halved() {
            Some(next) => caps = next,
            None => return Ok(row),
        }
    }
}

fn throw_row(throw: &ThrowInfo) -> ThrowRow {
    ThrowRow {
        address: throw.address,
        types: throw.types.iter().map(|caught| type_name(&caught.mangled)).collect(),
        destructor: throw.destructor,
        copy_functions: throw.types.iter().filter_map(|caught| caught.copy_function).collect(),
    }
}

impl Project {
    /// One page of the image's MSVC exception-handling tables, optionally only those of the function containing
    /// `function`, whose try blocks, cleanups and scopes then page from `detail_offset`.
    pub fn exception_handlers(
        &self,
        list: ExceptionList,
        function: Option<u64>,
        offset: usize,
        detail_offset: usize,
        limit: usize,
    ) -> Result<ExceptionPage, ApiError> {
        if self.binary.format != Format::Pe || !matches!(self.binary.arch, Arch::X86 | Arch::X86_64) {
            return Err(ApiError::Invalid("exception handlers are read only from x86 and x64 PE images".to_owned()));
        }
        if detail_offset > 0 && function.is_none() {
            return Err(ApiError::Invalid("detail_offset pages one function's tables; set `function` too".to_owned()));
        }
        let limit = limit.clamp(1, MAX_LIMIT);
        let empty = msvc::EhReport::default();
        let report = self.binary.msvc_metadata().map_or(&empty, |metadata| &metadata.exceptions);
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
            experimental: true,
            functions_total: report.functions.len(),
            try_blocks_total,
            catch_handlers_total,
            cleanup_funclets_total,
            throws_total: report.throws.len(),
            undecoded_handlers: report.undecoded_handlers,
            warnings: report.warnings.clone(),
            list: match list {
                ExceptionList::Functions => "functions",
                ExceptionList::Throws => "throws",
            },
            total: 0,
            offset,
            detail_offset,
            more: false,
            next_offset: None,
            byte_capped: false,
            functions: Vec::new(),
            throws: Vec::new(),
            limitations: LIMITATIONS.to_vec(),
        };
        let budget = PAGE_BUDGET.saturating_sub(json_size(&page.warnings)?);
        let shown = match list {
            ExceptionList::Functions => {
                let rows: Vec<(&EhFunction, Option<u64>)> = report
                    .functions
                    .iter()
                    .zip(owners)
                    .filter(|(_, owner)| selected.is_none() || *owner == selected)
                    .collect();
                page.total = rows.len();
                let rows = rows.into_iter().skip(offset).take(limit);
                let rows: Vec<HandlerRow> = rows
                    .map(|(entry, owner)| bounded_row(self, entry, owner, detail_offset))
                    .collect::<Result<_, _>>()?;
                let window = fit_window(rows, limit, budget)?;
                page.byte_capped = window.byte_capped;
                page.functions = window.items;
                page.functions.len()
            }
            ExceptionList::Throws => {
                page.total = report.throws.len();
                let window = fit_window(report.throws.iter().skip(offset).map(throw_row), limit, budget)?;
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

    /// Class evidence with one byte-capped page of MSVC vftables and one of RTTI classes.
    pub fn class_evidence(&self, vftables: ClassPage, rtti_classes: ClassPage) -> Result<ClassRecovery, ApiError> {
        let mut recovery = rampage_analysis::classes::recover(&self.binary);
        let all = std::mem::take(&mut recovery.vftables);
        let limit = vftables.limit.clamp(1, MAX_LIMIT);
        let window = fit_window(all.into_iter().skip(vftables.offset), limit, VFTABLE_PAGE_BUDGET)?;
        let next = vftables.offset.saturating_add(window.items.len());
        recovery.vftables_offset = vftables.offset;
        recovery.vftables_next_offset = (next < recovery.vftables_total).then_some(next);
        recovery.vftables = window.items;
        let all = std::mem::take(&mut recovery.rtti_classes);
        let limit = rtti_classes.limit.clamp(1, MAX_RTTI_CLASS_LIMIT);
        let window = fit_window(all.into_iter().skip(rtti_classes.offset), limit, RTTI_CLASS_PAGE_BUDGET)?;
        let next = rtti_classes.offset.saturating_add(window.items.len());
        recovery.rtti_classes_offset = rtti_classes.offset;
        recovery.rtti_classes_next_offset = (next < recovery.rtti_classes_total).then_some(next);
        recovery.rtti_classes = window.items;
        Ok(recovery)
    }
}

/// One page of a `class_evidence` list: rows to skip, and at most how many to return.
#[derive(Debug, Clone, Copy)]
pub struct ClassPage {
    pub offset: usize,
    pub limit: usize,
}

impl ClassPage {
    pub const VFTABLES: Self = Self { offset: 0, limit: DEFAULT_VFTABLE_LIMIT };
    pub const RTTI_CLASSES: Self = Self { offset: 0, limit: DEFAULT_RTTI_CLASS_LIMIT };
}

#[cfg(test)]
mod tests {
    use rampage_loaders::Binary;
    use rampage_loaders::msvc::{CatchHandler, TryBlock, UnwindAction};

    use super::*;

    fn project() -> Project {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/msvc-cpp/msvc-cpp-x64.exe");
        Project::new(Binary::open(path).unwrap())
    }

    /// A function whose tables would serialize to megabytes: 4096 try blocks of 256 catches with long type names,
    /// 65536 cleanups.
    fn enormous() -> EhFunction {
        let catch = CatchHandler {
            adjectives: 8,
            type_descriptor: Some(0x1000),
            mangled: Some(format!(".?AV{}@@", "Long".repeat(1000))),
            handler: 0x1_4000_1000,
        };
        let block = TryBlock {
            try_low: 0,
            try_high: 1,
            catch_high: 2,
            ranges: vec![msvc::AddressRange { start: 1, end: 2 }; 300],
            catches: vec![catch; 256],
        };
        EhFunction {
            function: Some(0x1_4000_1000),
            function_end: None,
            kind: "cxx_frame_handler3",
            handler: None,
            handler_import: Some("__CxxFrameHandler3".to_owned()),
            registrations: Vec::new(),
            table: 0x1_4000_3000,
            max_state: 65_536,
            unwind: vec![UnwindAction { state: 0, to_state: -1, action: Some(0x1_4000_1000) }; 65_536],
            try_blocks: vec![block; 4096],
            scopes: Vec::new(),
        }
    }

    #[test]
    fn an_enormous_function_row_is_capped_with_exact_totals_and_pages_by_detail_offset() {
        let project = project();
        let function = enormous();
        let row = bounded_row(&project, &function, None, 0).unwrap();
        assert!(json_size(&row).unwrap() <= ROW_BUDGET);
        assert!(row.truncated);
        assert_eq!((row.try_blocks_total, row.cleanups_total), (4096, 65_536));
        assert_eq!(row.try_blocks[0].catches_total, 256);
        assert!(row.try_blocks[0].catches[0].caught.len() <= MAX_TYPE_NAME_BYTES + '…'.len_utf8());
        // A later detail page starts where asked and is bounded the same way.
        let later = bounded_row(&project, &function, None, 4000).unwrap();
        assert!(json_size(&later).unwrap() <= ROW_BUDGET);
        assert!(!later.try_blocks.is_empty());
        let past = bounded_row(&project, &function, None, 70_000).unwrap();
        assert!(past.try_blocks.is_empty() && past.cleanups.is_empty() && past.truncated);
    }

    #[test]
    fn detail_offset_requires_a_function() {
        let project = project();
        let error = project.exception_handlers(ExceptionList::Functions, None, 0, 1, 10).unwrap_err();
        assert!(error.to_string().contains("set `function`"), "{error}");
    }
}
