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
    /// For a call edge from an Objective-C message send to a method implementation it may reach: the send's
    /// selector, receiver class and how certain the edge is. Absent on every other reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objc: Option<ObjcEdge>,
}

/// How an Objective-C send reaches the implementation an xref row points at.
#[derive(Debug, Clone, Serialize)]
pub struct ObjcEdge {
    pub selector: Option<String>,
    /// The receiver's class, `+` prefixed when the receiver is the class object (a class method send).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<String>,
    /// `resolved` (the one implementation) or `ambiguous` (one of several a subclass override or category makes
    /// reachable). Sends of unknown receiver class add no rows; `objc_sends` lists their candidates.
    pub confidence: &'static str,
    /// How many implementations the send may reach, this one included.
    pub alternatives: usize,
}

impl ObjcEdge {
    pub(crate) fn of(send: &rampage_analysis::objc_dispatch::Send) -> Self {
        ObjcEdge {
            selector: send.selector.clone(),
            receiver: send.receiver.as_ref().map(|receiver| {
                if receiver.class_object { format!("+{}", receiver.class) } else { receiver.class.clone() }
            }),
            confidence: send.confidence.as_str(),
            alternatives: send.targets.len(),
        }
    }
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
        let ranges: Vec<(u64, u64)> = match query {
            XrefQuery::To(_) => Vec::new(),
            XrefQuery::From(address) => match analysis.program.function_at(address) {
                Some(function) => function.blocks.iter().map(|block| (block.start, block.end)).collect(),
                None => vec![(address, address.saturating_add(1))],
            },
        };
        let mut selected: Vec<(Xref, Option<&rampage_analysis::objc_dispatch::Send>)> = match query {
            XrefQuery::To(address) => analysis.program.xrefs_to(address).iter().map(|&xref| (xref, None)).collect(),
            XrefQuery::From(_) => {
                ranges.iter().flat_map(|&(start, end)| from_range(start, end)).map(|xref| (xref, None)).collect()
            }
        };
        // Objective-C sends add call edges to the implementations they may reach. They are resolved only when
        // this query can involve one: it is to a method implementation, or its references reach a send entry.
        let dispatch = match query {
            XrefQuery::To(address) => self.objc_dispatch_if(|hints| hints.is_implementation(address))?,
            XrefQuery::From(_) => {
                self.objc_dispatch_if(|hints| selected.iter().any(|(xref, _)| hints.reaches_send(xref.to)))?
            }
        };
        let sends: Vec<&rampage_analysis::objc_dispatch::Send> = match (dispatch, query) {
            (None, _) => Vec::new(),
            (Some(dispatch), XrefQuery::To(address)) => {
                dispatch.sends.iter().filter(|send| send.targets.contains(&address)).collect()
            }
            (Some(dispatch), XrefQuery::From(_)) => {
                ranges.iter().flat_map(|&(start, end)| dispatch.sends_in(start, end)).collect()
            }
        };
        for send in sends.into_iter().filter(|send| send.confidence.has_edges()) {
            for &target in &send.targets {
                if matches!(query, XrefQuery::To(address) if address != target) {
                    continue;
                }
                selected.push((Xref { to: target, from: send.site, kind: XrefKind::Call }, Some(send)));
            }
        }
        selected.sort_unstable_by_key(|(xref, _)| (xref.from, xref.to, xref.kind));
        selected.dedup_by_key(|(xref, _)| *xref);
        let page = Page::of(selected, offset, limit);
        let mut rows = Vec::with_capacity(page.items.len());
        for (xref, send) in &page.items {
            rows.push(XrefRow {
                from: xref.from,
                to: xref.to,
                kind: xref.kind,
                from_function: analysis.function_containing(xref.from).map(|function| self.function_name(function)),
                to_name: self.name_at(xref.to),
                objc: send.map(ObjcEdge::of),
            });
        }
        Ok(Page { total: page.total, offset: page.offset, items: rows })
    }
}
