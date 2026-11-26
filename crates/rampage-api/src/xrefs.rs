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
    /// `read` or `write`, for a load or store at a constant address in an imported peripheral, or through a base
    /// register (see `base`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<&'static str>,
    /// For a load or store whose address is a base register plus an offset (a structure field reached from a
    /// literal-pool or MOVW/MOVT base): where the base came from. Absent on direct references.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<BaseEvidence>,
    /// In a relocatable object, the relocation applied in the referencing instruction (or data word): its type,
    /// symbol and addend, as the object file records them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relocation: Option<rampage_loaders::relocatable::RelocationSite>,
}

/// How a load or store reached its target through a base register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BaseEvidence {
    /// The instruction that put the base in the register: a literal-pool load, MOVT, `adr`, a completed address
    /// pair or a GOT load.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub site: u64,
    /// The base address.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    /// The target's distance from the base; negative below it.
    pub offset: i64,
    /// Bytes the instruction reads or writes.
    pub width: u8,
}

impl BaseEvidence {
    pub(crate) fn of(field: &rampage_analysis::discover::FieldRef) -> Self {
        BaseEvidence { site: field.base_site, address: field.base, offset: field.offset(), width: field.width }
    }
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
        // Loads and stores at constant addresses inside imported peripherals, from the p-code access scan.
        // Discovery records only those it resolves itself (literal-pool and MOVW/MOVT bases, and on Raw Cortex-M
        // unmapped peripheral space); rows both find are merged below.
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
        let mut decoder = self.binary.relocated().and_then(|_| self.binary.decoder().ok());
        for (xref, send) in &page.items {
            let field = analysis
                .program
                .field_ref(xref.from, xref.to)
                .filter(|_| xref.kind == XrefKind::Data && send.is_none());
            rows.push(XrefRow {
                from: xref.from,
                to: xref.to,
                kind: xref.kind,
                from_function: analysis.function_containing(xref.from).map(|function| self.function_name(function)),
                to_name: self.name_at(xref.to),
                objc: send.map(ObjcEdge::of),
                access: if writes.contains(&(xref.from, xref.to)) || field.is_some_and(|field| field.write) {
                    Some("write")
                } else if reads.contains(&(xref.from, xref.to)) || field.is_some() {
                    Some("read")
                } else {
                    None
                },
                base: field.map(BaseEvidence::of),
                relocation: self.relocation_at(xref.from, xref.to, &mut decoder),
            });
        }
        Ok(Page { total: page.total, offset: page.offset, items: rows })
    }

    /// The relocation applied in the instruction at `from` (or, outside code, the pointer-sized word there), in a
    /// relocatable object.
    fn relocation_at(
        &self,
        from: u64,
        to: u64,
        decoder: &mut Option<Box<dyn rampage_arch::Disassembler>>,
    ) -> Option<rampage_loaders::relocatable::RelocationSite> {
        let relocated = self.binary.relocated()?;
        let width = u64::from(self.binary.arch.default_pointer_size().unwrap_or(4));
        let length = match (self.binary.code_from(from), decoder.as_mut()) {
            (Some(bytes), Some(decoder)) => u64::from(decoder.decode(bytes, from).len.max(1)),
            _ => width,
        };
        let within = relocated.sites_in(from..from.saturating_add(length)).first();
        // A RISC-V PCREL_LO12 names the `auipc` whose HI20 relocation carries the symbol and addend.
        if let Some(site) = within.filter(|site| site.kind.starts_with("R_RISCV_PCREL_LO12")) {
            let high = relocated.sites_in(site.value..site.value.saturating_add(1)).first();
            return high.or(Some(site)).cloned();
        }
        // A RISC-V `call` is relocated at its `auipc` while the call is recorded at the `jalr` after it.
        let call = |site: &&rampage_loaders::relocatable::RelocationSite| {
            matches!(site.kind.as_str(), "R_RISCV_CALL" | "R_RISCV_CALL_PLT") && site.value == to
        };
        within.or_else(|| relocated.sites_in(from.saturating_sub(4)..from).iter().find(call)).cloned()
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
            let sites = thumb_bl_sites(self, target, |site| analysis.function_containing(site).is_none());
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

    /// When `address` lies inside a C string (not at its start): a run of at least four printable ASCII bytes,
    /// at most 256 long and ended by a NUL. The run's start and up to 64 bytes of its text.
    fn string_start_before(&self, address: u64) -> Option<(u64, String)> {
        let byte = |at: u64| self.binary.read(at, 1).map(|byte| byte[0]);
        let printable = |at: u64| byte(at).is_some_and(|byte| (0x20..0x7f).contains(&byte));
        if !printable(address) {
            return None;
        }
        let mut start = address;
        while address - start < MAX_STRING && start > 0 && printable(start - 1) {
            start -= 1;
        }
        let mut end = address;
        while end - start < MAX_STRING && printable(end) {
            end += 1;
        }
        if start == address || end - start < 4 || byte(end) != Some(0) {
            return None;
        }
        let bytes = self.binary.read(start, (end - start).min(64))?;
        Some((start, String::from_utf8_lossy(bytes).into_owned()))
    }
}

/// Most undiscovered `bl` sites an empty `xrefs` note names.
const MAX_UNDISCOVERED_CALLS: usize = 8;

/// Longest printable run an empty `xrefs` note reads as a string.
const MAX_STRING: u64 = 256;

/// Most bytes of Thumb code the empty-`xrefs` `bl` scan reads.
const MAX_BL_SCAN_BYTES: u64 = 64 << 20;

/// Up to `MAX_UNDISCOVERED_CALLS + 1` sites, kept by `keep`, of Thumb `bl` encodings that land on `target`: in
/// every executable file-backed segment of an M-profile image, or in the Thumb ranges of another little-endian
/// ARM image (A32 code is never read as Thumb). At most [`MAX_BL_SCAN_BYTES`] are read.
fn thumb_bl_sites(project: &Project, target: u64, keep: impl Fn(u64) -> bool) -> Vec<u64> {
    let binary = &project.binary;
    let ranges: Vec<std::ops::Range<u64>> = if binary.m_profile() {
        binary
            .segments
            .iter()
            .filter(|segment| segment.perms.execute && segment.file_size > 0)
            .map(|segment| segment.address..segment.address + segment.file_size.min(segment.size))
            .collect()
    } else if !binary.big_endian {
        binary.thumb.clone()
    } else {
        Vec::new()
    };
    let mut sites = Vec::new();
    let mut budget = MAX_BL_SCAN_BYTES;
    for range in ranges {
        let start = range.start + range.start % 2;
        let length = range.end.saturating_sub(start).min(budget);
        budget -= length;
        let Some(bytes) = binary.read(start, length) else { continue };
        let halfword = |index: usize| u16::from_le_bytes([bytes[2 * index], bytes[2 * index + 1]]);
        for index in 0..(bytes.len() / 2).saturating_sub(1) {
            let site = start + 2 * index as u64;
            if thumb_bl_target(halfword(index), halfword(index + 1), site) == Some(target) && keep(site) {
                sites.push(site);
                if sites.len() > MAX_UNDISCOVERED_CALLS {
                    return sites;
                }
            }
        }
        if budget == 0 {
            break;
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
