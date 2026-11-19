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
    /// References whose target lies in `[start, end)`: an imported peripheral's registers.
    ToRange(u64, u64),
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
    /// `read` or `write`, for a load or store at a constant address in an imported peripheral.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<&'static str>,
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
            XrefQuery::To(_) | XrefQuery::ToRange(..) => Vec::new(),
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
            XrefQuery::ToRange(start, end) => {
                xrefs.iter().filter(|xref| (start..end).contains(&xref.to)).map(|&xref| (xref, None)).collect()
            }
        };
        // Loads and stores at constant addresses inside imported peripherals, which discovery does not record.
        let registers = match query {
            XrefQuery::To(address) => self.register_xrefs(address, address.saturating_add(1))?,
            XrefQuery::ToRange(start, end) => self.register_xrefs(start, end)?,
            XrefQuery::From(_) => Vec::new(),
        };
        let writes: std::collections::BTreeSet<(u64, u64)> =
            registers.iter().filter(|(_, write)| *write).map(|(xref, _)| (xref.from, xref.to)).collect();
        let reads: std::collections::BTreeSet<(u64, u64)> =
            registers.iter().filter(|(_, write)| !*write).map(|(xref, _)| (xref.from, xref.to)).collect();
        selected.extend(registers.into_iter().map(|(xref, _)| (xref, None)));
        // Objective-C sends add call edges to the implementations they may reach. They are resolved only when
        // this query can involve one: it is to a method implementation, or its references reach a send entry.
        let dispatch = match query {
            XrefQuery::To(address) => self.objc_dispatch_if(|hints| hints.is_implementation(address))?,
            XrefQuery::ToRange(..) => None,
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
            (Some(_), XrefQuery::ToRange(..)) => Vec::new(),
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
                access: if writes.contains(&(xref.from, xref.to)) {
                    Some("write")
                } else if reads.contains(&(xref.from, xref.to)) {
                    Some("read")
                } else {
                    None
                },
            });
        }
        Ok(Page { total: page.total, offset: page.offset, items: rows })
    }

    /// Why `xrefs` to `address` found nothing, and where to look instead: the start of the string `address` lies
    /// inside when that start is referenced, and on 32-bit ARM the Thumb `bl` encodings outside every discovered
    /// function that target it. Always ends with what the search covered.
    pub fn xrefs_to_empty_notes(&self, address: u64) -> Result<Vec<String>, ApiError> {
        let analysis = self.analysis()?;
        let mut notes = Vec::new();
        if let Some((start, text)) = self.string_start_before(address) {
            let references = analysis.program.xrefs_to(start).len();
            if references > 0 {
                notes.push(format!(
                    "{address:#x} lies {} bytes into the string {text:?} at {start:#x}, which has {references} \
                     reference{}: pass `to` {start:#x}",
                    address - start,
                    if references == 1 { "" } else { "s" }
                ));
            }
        }
        if self.binary.arch == rampage_arch::Arch::Arm {
            let target = address & !1;
            let sites: Vec<u64> = thumb_bl_sites(self, target)
                .into_iter()
                .filter(|&site| analysis.function_containing(site).is_none())
                .take(MAX_UNDISCOVERED_CALLS + 1)
                .collect();
            if !sites.is_empty() {
                let listed: Vec<String> =
                    sites.iter().take(MAX_UNDISCOVERED_CALLS).map(|site| format!("{site:#x}")).collect();
                notes.push(format!(
                    "Thumb `bl` encodings outside every discovered function target {target:#x}: {}{}. Discovery did \
                     not reach that code, so it is unproven: `disassemble` there, and pass the enclosing routine's \
                     start in `raw.seeds` to make it a function",
                    listed.join(", "),
                    if sites.len() > MAX_UNDISCOVERED_CALLS { ", ..." } else { "" }
                ));
            }
        }
        notes.push(
            "No direct reference from discovered code: calls through function pointers or computed addresses, and \
             code discovery did not reach, are not resolved."
                .to_owned(),
        );
        Ok(notes)
    }

    /// When `address` lies inside a printable ASCII run (not at its start): the run's start and up to 64 bytes of
    /// its text.
    fn string_start_before(&self, address: u64) -> Option<(u64, String)> {
        let printable = |at: u64| self.binary.read(at, 1).is_some_and(|byte| (0x20..0x7f).contains(&byte[0]));
        if !printable(address) {
            return None;
        }
        let mut start = address;
        while address - start < 256 && start > 0 && printable(start - 1) {
            start -= 1;
        }
        if start == address {
            return None;
        }
        let mut end = address;
        while end - start < 64 && printable(end) {
            end += 1;
        }
        let bytes = self.binary.read(start, end - start)?;
        Some((start, String::from_utf8_lossy(bytes).into_owned()))
    }
}

/// Most undiscovered `bl` sites an empty `xrefs` note names.
const MAX_UNDISCOVERED_CALLS: usize = 8;

/// Sites of Thumb `bl` encodings at halfword boundaries of executable, file-backed segments that land on `target`.
fn thumb_bl_sites(project: &Project, target: u64) -> Vec<u64> {
    let mut sites = Vec::new();
    for segment in project.binary.segments.iter().filter(|segment| segment.perms.execute && segment.file_size > 0) {
        let Some(bytes) = project.binary.read(segment.address, segment.file_size.min(segment.size)) else { continue };
        let skip = (segment.address % 2) as usize;
        let base = segment.address + skip as u64;
        let halfwords: Vec<u16> =
            bytes[skip.min(bytes.len())..].as_chunks::<2>().0.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
        for (index, pair) in halfwords.windows(2).enumerate() {
            let site = base + 2 * index as u64;
            if thumb_bl_target(pair[0], pair[1], site) == Some(target) {
                sites.push(site);
            }
        }
    }
    sites
}

/// Where a Thumb `bl` (halfwords `first`, `second`) at `site` lands, when the halfwords encode one.
pub(crate) fn thumb_bl_target(first: u16, second: u16, site: u64) -> Option<u64> {
    if first & 0xf800 != 0xf000 || second & 0xd000 != 0xd000 {
        return None;
    }
    let (first, second) = (u32::from(first), u32::from(second));
    let sign = (first >> 10) & 1;
    let i1 = !((second >> 13) & 1 ^ sign) & 1;
    let i2 = !((second >> 11) & 1 ^ sign) & 1;
    let offset = (sign << 24) | (i1 << 23) | (i2 << 22) | ((first & 0x3ff) << 12) | ((second & 0x7ff) << 1);
    // Sign-extend the 25-bit offset.
    let offset = i64::from(((offset << 7) as i32) >> 7);
    (site + 4).checked_add_signed(offset)
}
