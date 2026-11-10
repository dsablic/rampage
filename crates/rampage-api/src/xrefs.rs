use rampage_analysis::discover::{Xref, XrefKind};
use serde::Serialize;

use crate::rows::Page;
use crate::{ApiError, Project};

#[derive(Debug, Clone, Copy)]
pub enum XrefQuery {
    /// References whose target is this address.
    To(u64),
    /// References made by the function starting at this address, or by the instruction at it.
    From(u64),
}

#[derive(Debug, Clone, Serialize)]
pub struct XrefRow {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub from: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub to: u64,
    pub kind: XrefKind,
    pub from_function: Option<String>,
    pub to_name: Option<String>,
}

impl Project {
    /// Cross-references to or from an address, ordered by source then target.
    pub fn xrefs(
        &self,
        query: XrefQuery,
        offset: Option<usize>,
        limit: Option<usize>,
    ) -> Result<Page<XrefRow>, ApiError> {
        let analysis = self.analysis()?;
        let xrefs = &analysis.program.xrefs;
        let from_range = |start: u64, end: u64| {
            let by_source = &analysis.xrefs_by_source;
            let first = by_source.partition_point(|&index| xrefs[index].from < start);
            let last = by_source.partition_point(|&index| xrefs[index].from < end);
            by_source[first..last].iter().map(|&index| xrefs[index])
        };
        let mut selected: Vec<Xref> = match query {
            XrefQuery::To(address) => analysis.program.xrefs_to(address).to_vec(),
            XrefQuery::From(address) => match analysis.program.function_at(address) {
                Some(function) => function.blocks.iter().flat_map(|block| from_range(block.start, block.end)).collect(),
                None => from_range(address, address.saturating_add(1)).collect(),
            },
        };
        selected.sort_unstable_by_key(|xref| (xref.from, xref.to, xref.kind));
        selected.dedup();
        let page = Page::of(selected, offset, limit);
        let mut rows = Vec::with_capacity(page.items.len());
        for xref in &page.items {
            rows.push(XrefRow {
                from: xref.from,
                to: xref.to,
                kind: xref.kind,
                from_function: analysis.function_containing(xref.from).map(|function| self.function_name(function)),
                to_name: self.name_at(xref.to),
            });
        }
        Ok(Page { total: page.total, offset: page.offset, items: rows })
    }
}
