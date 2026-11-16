//! `lock_mechanisms`: find and explain the mechanisms that make a device refuse a repair: signature and MAC
//! verification, challenge-response unlocks, binding to a unique chip ID, anti-rollback counters, debug and
//! readout protection, and feature or region locks.
//!
//! The tool explains; it does not defeat. For each mechanism it reports what is checked, which data the decision
//! consults, where the decision is made and what each path does (reset, halt, error return, a flag written), with
//! the evidence and a confidence. It never suggests a patch and never reads out key material.
//!
//! How: crypto routines are recognized by algorithm constants (`rampage-constants`) in their call tree and by
//! library names; registers by an imported CMSIS-SVD map (generic names such as UID, OTP, RDP) and, on Cortex-M
//! firmware, the architectural debug registers. A p-code dataflow ([`flow`]) over the functions near that evidence
//! records which sources decide each conditional branch, return value and store; a decision whose sources carry a
//! lock-relevant role becomes a mechanism. Decisions that only propagate a verdict to a caller are folded into the
//! caller's decision. Plain integrity checks (a CRC, an unkeyed digest), identity reads that decide nothing and
//! crypto whose result decides nothing are listed separately as not locks.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rampage_analysis::discover::XrefKind;
use rampage_constants::Kind;
use serde::Serialize;

use crate::{ApiError, Project};

mod flow;
mod labels;
#[cfg(test)]
mod tests;

use flow::{Effect, FunctionFlow, Lifter, Source, Taint, Val};
use labels::Label;

/// Instructions lifted across all analyzed functions before the analysis stops.
const MAX_INSTRUCTIONS: usize = 1_500_000;
/// Functions analyzed at most.
const MAX_FUNCTIONS: usize = 2048;
/// Caller levels added above the evidence.
const CALLER_DEPTH: usize = 4;
/// Callee levels searched for crypto evidence below a routine.
const PROFILE_DEPTH: usize = 4;
const PROFILE_NODES: usize = 128;
/// Levels a call's result is followed into the callee's own sources.
const RESULT_DEPTH: usize = 6;
/// The largest written or returned constant a report shows.
const MAX_SHOWN_VALUE: u64 = 0xffff;
/// Bytes before a curve parameter a reference to the structure holding it may point at.
const CURVE_SLACK: u64 = 64;
/// Blocks explored on each side of a decision.
const PATH_BLOCKS: usize = 16;
pub const DEFAULT_LIMIT: usize = 10;
pub const MAX_LIMIT: usize = 50;
const MAX_NOT_LOCKS: usize = 16;
const MAX_RELATED: usize = 8;
/// JSON bytes a page may take, within the tool result budget.
const MAX_BYTES: usize = 56_000;

/// The categories `lock_mechanisms` reports.
pub const CATEGORIES: [&str; 7] = [
    "signature_verification",
    "mac_verification",
    "challenge_response",
    "device_binding",
    "anti_rollback",
    "debug_lock",
    "feature_lock",
];

#[derive(Debug, Clone, Default)]
pub struct LockQuery {
    /// Only this category.
    pub category: Option<String>,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct LockReport {
    /// Whether gate tracing ran (ARM/Thumb, AArch64 and x86-64).
    pub supported: bool,
    pub total: usize,
    pub offset: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub mechanisms: Vec<Mechanism>,
    /// Checks and identity or crypto use found while searching that are not locks.
    pub not_locks: Vec<NotLock>,
    pub not_locks_total: usize,
    pub coverage: Coverage,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub functions_analyzed: usize,
    pub instructions: usize,
    /// The instruction or function budget ran out; mechanisms may be missing.
    pub incomplete: bool,
    pub crypto_constants: usize,
    pub svd_peripherals: usize,
    pub firmware: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Mechanism {
    pub id: usize,
    pub category: &'static str,
    pub confidence: &'static str,
    pub summary: String,
    /// The branch that decides; absent for a mechanism that only configures protection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    /// What is checked, and by which routine.
    pub checks: Vec<String>,
    /// The data and registers the decision depends on.
    pub consults: Vec<Consulted>,
    /// What each path out of the decision does.
    pub outcomes: Vec<Outcome>,
    /// Which outcome is the refusal: `branch`, `fallthrough`, `conditional`, `otherwise`, or `unknown`.
    pub failure_path: &'static str,
    /// Inner decisions that pass their verdict up, further decision sites, flag consumers and configuration writes.
    pub related: Vec<Related>,
    pub evidence: Vec<String>,
    /// Fixed RAM addresses an outcome writes (flags other decisions may test).
    #[serde(skip)]
    written: Vec<u64>,
    /// A decision on the debug status alone, and whether the side taken with a debugger attached is the refusal.
    #[serde(skip)]
    debugger_only: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub function: u64,
    pub function_name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub at: u64,
    pub condition: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Consulted {
    /// `public_key_algorithm`, `mac_algorithm`, `digest_algorithm`, `unique_id`, `random`, `counter`,
    /// `fuse_or_option`, `protection_setting`, `debug_status`, `constant_data` or `external_data`.
    pub kind: &'static str,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "optional_address")]
    pub at: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    /// `branch` (the branch is taken), `fallthrough`, `conditional` (a conditionally executed instruction runs) or
    /// `otherwise`.
    pub path: &'static str,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub at: u64,
    /// `reset`, `exit`, `halt`, `transfer`, `writes`, `returns`, `calls`, `selects` or `continues`.
    pub effect: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Related {
    /// `inner_decision`, `decision`, `flag_consumer` or `configures`.
    pub role: &'static str,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub function: u64,
    pub function_name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub at: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotLock {
    /// `integrity_check`, `identity_read` or `crypto_without_decision`.
    pub kind: &'static str,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub function: u64,
    pub function_name: String,
    /// The first decision, read or call it describes.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub at: u64,
    pub detail: String,
}

fn optional_address<S: serde::Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(address) => serializer.serialize_str(&format!("{address:#x}")),
        None => serializer.serialize_none(),
    }
}

/// Crypto evidence in a routine's call tree.
#[derive(Debug, Clone, Default)]
struct Profile {
    signature: BTreeSet<String>,
    mac: BTreeSet<String>,
    hash: BTreeSet<String>,
    crc: bool,
}

/// A decision before grouping.
struct Candidate {
    function: u64,
    gate: usize,
    labels: BTreeSet<Label>,
    category: &'static str,
    /// The candidate this one passes its verdict up to.
    outer: Option<usize>,
}

/// The analysis state shared by the classification steps.
struct Context<'p> {
    project: &'p Project,
    firmware: bool,
    flows: BTreeMap<u64, FunctionFlow>,
    summaries: HashMap<u64, u64>,
    callees: BTreeMap<u64, BTreeSet<u64>>,
    callers: BTreeMap<u64, BTreeSet<u64>>,
    /// Function to the crypto constants it references: (kind, algorithm).
    crypto: BTreeMap<u64, BTreeSet<(Kind, String)>>,
    crc_routines: BTreeSet<u64>,
    reset_routines: BTreeSet<u64>,
    noreturn: Vec<u64>,
    peripherals: std::sync::Arc<crate::peripherals::PeripheralMap>,
    /// Labels of what analyzed functions store at RAM addresses: (start, end) to labels.
    globals: Vec<Stored>,
    /// Functions each function reaches through calls (bounded), for telling a challenge issued elsewhere from
    /// randomness a check draws itself.
    reached: std::cell::RefCell<HashMap<u64, BTreeSet<u64>>>,
    profiles: std::cell::RefCell<HashMap<u64, Profile>>,
    /// What each function's result (returned value and pointer outputs) derives from, by role; with and without
    /// other functions' stores to RAM.
    results: std::cell::RefCell<HashMap<(u64, bool, bool), BTreeSet<Label>>>,
    names: std::cell::RefCell<HashMap<u64, String>>,
}

impl Context<'_> {
    /// Whether a call to `target` never comes back: known not to return, or analyzed with no return and no
    /// tail jump through a pointer (an import stub's jump returns to the caller).
    fn stops(&self, target: u64) -> bool {
        if self.noreturn.binary_search(&target).is_ok() {
            return true;
        }
        self.flows.get(&target).is_some_and(|callee| {
            callee.returns.is_empty()
                && callee.indirect_jumps.is_empty()
                && callee.import_jumps.is_empty()
                && !callee.blocks.is_empty()
        })
    }

    /// Whether `function`'s call tree computes a signature, MAC or digest.
    fn is_crypto(&self, function: u64) -> bool {
        let profile = self.profile(function);
        !profile.signature.is_empty() || !profile.mac.is_empty() || !profile.hash.is_empty()
    }

    fn name(&self, address: u64) -> String {
        self.names
            .borrow_mut()
            .entry(address)
            .or_insert_with(|| match self.project.binary.import_slot(address) {
                // A call through an import slot is a call to the import.
                Some(slot) => slot.name.clone(),
                None => self.project.function_name(address),
            })
            .clone()
    }

    /// The role of the register or memory at `address`.
    fn address_label(&self, address: u64) -> Option<Label> {
        if let Some(hit) = self.peripherals.at(address) {
            return labels::register_role(hit.peripheral, hit.register, &hit.name(), address);
        }
        if self.firmware { labels::architectural(address) } else { None }
    }

    fn profile(&self, root: u64) -> Profile {
        if let Some(known) = self.profiles.borrow().get(&root) {
            return known.clone();
        }
        let mut profile = Profile::default();
        let mut seen = BTreeSet::from([root]);
        let mut frontier = vec![root];
        for _ in 0..=PROFILE_DEPTH {
            let mut next = Vec::new();
            for function in frontier {
                let name = self.name(function);
                if let Some(library) = labels::signature_api(&name) {
                    profile.signature.insert(library.to_owned());
                }
                if let Some(library) = labels::mac_api(&name) {
                    profile.mac.insert(library.to_owned());
                }
                for (kind, algorithm) in self.crypto.get(&function).into_iter().flatten() {
                    match kind {
                        Kind::PublicKey => {
                            profile.signature.insert(algorithm.clone());
                        }
                        Kind::Mac => {
                            profile.mac.insert(algorithm.clone());
                        }
                        Kind::Hash => {
                            profile.hash.insert(algorithm.clone());
                        }
                        Kind::Checksum => profile.crc = true,
                        _ => {}
                    }
                }
                if self.crc_routines.contains(&function) {
                    profile.crc = true;
                }
                if self.flows.get(&function).is_some_and(FunctionFlow::hmac_pads) {
                    profile.mac.insert("HMAC".to_owned());
                }
                for &callee in self.callees.get(&function).into_iter().flatten() {
                    if seen.len() < PROFILE_NODES && seen.insert(callee) {
                        next.push(callee);
                    }
                }
            }
            frontier = next;
        }
        // "SHA-256 / BLAKE2s" (an initial value two algorithms share) adds nothing next to "SHA-256".
        for names in [&mut profile.signature, &mut profile.hash] {
            let known: Vec<String> = names.iter().filter(|name| !name.contains(" / ")).cloned().collect();
            names
                .retain(|name| !name.contains(" / ") || !name.split(" / ").any(|part| known.iter().any(|k| k == part)));
        }
        if !profile.mac.is_empty() && !profile.hash.is_empty() {
            let hashes: Vec<String> = profile.hash.iter().cloned().collect();
            profile.mac = profile
                .mac
                .iter()
                .map(|mac| if mac == "HMAC" { format!("HMAC-{}", hashes.join("/")) } else { mac.clone() })
                .collect();
        }
        self.profiles.borrow_mut().insert(root, profile.clone());
        profile
    }

    /// The roles `function` itself has: crypto constants it references and library names.
    fn own_labels(&self, function: u64, out: &mut BTreeSet<Label>) {
        for (kind, algorithm) in self.crypto.get(&function).into_iter().flatten() {
            match kind {
                Kind::PublicKey => {
                    out.insert(Label::Signature(algorithm.clone()));
                }
                Kind::Mac => {
                    out.insert(Label::Mac(algorithm.clone()));
                }
                Kind::Hash => {
                    out.insert(Label::Hash(algorithm.clone()));
                }
                Kind::Checksum => {
                    out.insert(Label::Crc);
                }
                _ => {}
            }
        }
        if self.crc_routines.contains(&function) {
            out.insert(Label::Crc);
        }
        let name = self.name(function);
        if let Some(library) = labels::signature_api(&name) {
            out.insert(Label::Signature(library.to_owned()));
        }
        if let Some(library) = labels::mac_api(&name) {
            out.insert(Label::Mac(library.to_owned()));
        }
        if let Some(library) = labels::random_api(&name) {
            out.insert(Label::Random(library.to_owned()));
        }
    }

    /// The roles of what `function` hands back, its returned value or (`written`) what it writes through the
    /// pointers it was given: its own roles, and the roles of the sources that output derives from, followed through
    /// callees. Crypto elsewhere in its call tree whose result does not reach that output does not count.
    fn result_labels(&self, function: u64, depth: usize, globals: bool) -> BTreeSet<Label> {
        self.output_labels(function, false, depth, globals)
    }

    fn output_labels(&self, function: u64, written: bool, depth: usize, globals: bool) -> BTreeSet<Label> {
        if let Some(known) = self.results.borrow().get(&(function, written, globals)) {
            return known.clone();
        }
        let mut out = BTreeSet::new();
        self.own_labels(function, &mut out);
        let Some(flow) = self.flows.get(&function) else { return out };
        if depth >= RESULT_DEPTH {
            return out;
        }
        // A cycle reads the partial answer.
        self.results.borrow_mut().insert((function, written, globals), out.clone());
        let output = if written { flow.param_writes } else { flow.returned };
        for bit in output.bits() {
            self.source_labels(function, bit, depth + 1, globals, &mut out);
        }
        if flow.hmac_pads() {
            let hashes: Vec<String> = out
                .iter()
                .filter_map(|label| if let Label::Hash(name) = label { Some(name.clone()) } else { None })
                .collect();
            if !hashes.is_empty() {
                out.insert(Label::Mac(format!("HMAC-{}", tidy(hashes).join("/"))));
            }
        }
        self.results.borrow_mut().insert((function, written, globals), out.clone());
        out
    }

    /// The labels of source `bit` of `function`; `globals` adds what other functions stored at a RAM address.
    fn source_labels(&self, function: u64, bit: usize, depth: usize, globals: bool, out: &mut BTreeSet<Label>) {
        let Some(flow) = self.flows.get(&function) else { return };
        let Some(source) = flow.source_of(bit) else { return };
        match source {
            Source::Call(Some(target)) => {
                if target != function {
                    out.extend(self.output_labels(target, false, depth, globals));
                }
            }
            Source::Written(Some(target)) => {
                if target != function {
                    out.extend(self.output_labels(target, true, depth, globals));
                }
            }
            Source::Call(None) | Source::Written(None) | Source::Overflow => {}
            Source::Load(address) => {
                out.extend(self.address_label(address));
                if globals {
                    self.global_labels(function, address, 4, out);
                }
            }
            Source::Pointer(address) => {
                if globals {
                    self.global_labels(function, address, 32, out);
                }
            }
            Source::Param(_) => {}
        }
    }

    /// The roles of what other functions stored in `span` bytes at `address`, as `reader` reads it. Randomness
    /// the reader stored itself or through its callees (a nonce drawn for the same computation) is not a challenge
    /// issued earlier, so it does not count.
    fn global_labels(&self, reader: u64, address: u64, span: u64, out: &mut BTreeSet<Label>) {
        let end = address.saturating_add(span);
        for stored in &self.globals {
            if stored.start < end && address < stored.end {
                let related = stored.by == reader || self.reaches(reader).contains(&stored.by);
                out.extend(
                    stored.labels.iter().filter(|label| !related || !matches!(label, Label::Random(_))).cloned(),
                );
            }
        }
    }

    fn reaches(&self, root: u64) -> BTreeSet<u64> {
        if let Some(known) = self.reached.borrow().get(&root) {
            return known.clone();
        }
        let mut seen = BTreeSet::new();
        let mut frontier = vec![root];
        for _ in 0..PROFILE_DEPTH {
            let mut next = Vec::new();
            for function in frontier {
                for &callee in self.callees.get(&function).into_iter().flatten() {
                    if seen.len() < PROFILE_NODES && seen.insert(callee) {
                        next.push(callee);
                    }
                }
            }
            frontier = next;
        }
        self.reached.borrow_mut().insert(root, seen.clone());
        seen
    }

    fn taint_labels(&self, function: u64, taint: Taint, globals: bool) -> BTreeSet<Label> {
        let mut out = BTreeSet::new();
        for bit in taint.bits() {
            self.source_labels(function, bit, 0, globals, &mut out);
        }
        // "SHA-256 / BLAKE2s" (an initial value two algorithms share) adds nothing next to "SHA-256".
        let plain: Vec<String> = out
            .iter()
            .filter_map(|label| match label {
                Label::Hash(name) | Label::Signature(name) if !name.contains(" / ") => Some(name.clone()),
                _ => None,
            })
            .collect();
        out.retain(|label| match label {
            Label::Hash(name) | Label::Signature(name) => {
                !name.contains(" / ") || !name.split(" / ").any(|part| plain.iter().any(|p| p == part))
            }
            _ => true,
        });
        out
    }
}

/// Algorithm names without the shared ones another name already covers ("SHA-256 / BLAKE2s" next to "SHA-256").
fn tidy(names: Vec<String>) -> Vec<String> {
    let plain: Vec<String> = names.iter().filter(|name| !name.contains(" / ")).cloned().collect();
    let mut kept: Vec<String> = names
        .into_iter()
        .filter(|name| !name.contains(" / ") || !name.split(" / ").any(|part| plain.iter().any(|p| p == part)))
        .collect();
    kept.sort();
    kept.dedup();
    kept
}

/// The category a decision's labels make it, or `None` when they are not a lock (see [`not_lock_kind`]).
fn categorize(labels: &BTreeSet<Label>) -> Option<&'static str> {
    let any = |predicate: fn(&Label) -> bool| labels.iter().any(predicate);
    // A response to a challenge proves something only under a key: a signature or a MAC (a plain digest of the
    // challenge could come from anyone).
    let keyed = any(|label| matches!(label, Label::Signature(_) | Label::Mac(_)));
    if any(|label| matches!(label, Label::Random(_))) && keyed {
        return Some("challenge_response");
    }
    if any(|label| matches!(label, Label::UniqueId(..))) {
        return Some("device_binding");
    }
    if any(|label| matches!(label, Label::Counter(..))) {
        return Some("anti_rollback");
    }
    if any(|label| matches!(label, Label::Signature(_))) {
        return Some("signature_verification");
    }
    if any(|label| matches!(label, Label::Mac(_))) {
        return Some("mac_verification");
    }
    if any(|label| matches!(label, Label::Protection(..) | Label::DebugStatus(..))) {
        return Some("debug_lock");
    }
    if any(|label| matches!(label, Label::Fuse(..))) {
        return Some("feature_lock");
    }
    None
}

/// Whether labels that are not a lock describe a plain integrity check.
fn not_lock_kind(labels: &BTreeSet<Label>) -> Option<&'static str> {
    labels.iter().any(|label| matches!(label, Label::Crc | Label::Hash(_))).then_some("integrity_check")
}

fn consulted(label: &Label) -> Option<Consulted> {
    let (kind, name, at) = match label {
        Label::Signature(name) => ("public_key_algorithm", name.clone(), None),
        Label::Mac(name) => ("mac_algorithm", name.clone(), None),
        Label::Hash(name) => ("digest_algorithm", name.clone(), None),
        Label::Crc => return None,
        Label::UniqueId(name, at) => ("unique_id", name.clone(), Some(*at)),
        Label::Random(name) => ("random", name.clone(), None),
        Label::Counter(name, at) => ("counter", name.clone(), Some(*at)),
        Label::Fuse(name, at) => ("fuse_or_option", name.clone(), Some(*at)),
        Label::Protection(name, at) => ("protection_setting", name.clone(), Some(*at)),
        Label::DebugStatus(name, at) => ("debug_status", name.clone(), Some(*at)),
    };
    Some(Consulted { kind, name, at })
}

fn joined(labels: &BTreeSet<Label>, pick: fn(&Label) -> Option<&String>) -> String {
    let names: BTreeSet<&String> = labels.iter().filter_map(pick).collect();
    names.into_iter().cloned().collect::<Vec<_>>().join(", ")
}

/// What one side of a decision does.
struct Side {
    path: &'static str,
    at: u64,
    effect: &'static str,
    detail: String,
    /// Fixed addresses this side writes.
    written: Vec<u64>,
}

impl Side {
    fn fails(&self) -> bool {
        matches!(self.effect, "reset" | "exit" | "halt")
    }
}

impl Project {
    /// The lock mechanisms in the image: see the module documentation.
    pub fn lock_mechanisms(&self, query: &LockQuery) -> Result<LockReport, ApiError> {
        if let Some(category) = &query.category
            && !CATEGORIES.contains(&category.as_str())
        {
            return Err(ApiError::Invalid(format!("category {category:?}: one of {}", CATEGORIES.join(", "))));
        }
        let limit = if query.limit == 0 { DEFAULT_LIMIT } else { query.limit.min(MAX_LIMIT) };
        let analysis = self.analysis()?;
        let program = &analysis.program;
        let binary = &self.binary;
        let firmware = binary.arch == rampage_arch::Arch::Arm && rampage_signatures::firmware_like(binary);
        let peripherals = self.peripheral_map();
        let mut limitations = Vec::new();
        let mut coverage = Coverage {
            functions_analyzed: 0,
            instructions: 0,
            incomplete: false,
            crypto_constants: 0,
            svd_peripherals: peripherals.peripherals().count(),
            firmware,
        };
        let mut lifter = match Lifter::new(binary) {
            Ok(lifter) => lifter,
            Err(reason) => {
                limitations.push(format!(
                    "No decisions were traced: {reason}. Gate tracing supports 32-bit ARM and Thumb (including \
                     Cortex-M), AArch64 and x86-64."
                ));
                return Ok(LockReport {
                    supported: false,
                    total: 0,
                    offset: query.offset,
                    next_offset: None,
                    mechanisms: Vec::new(),
                    not_locks: Vec::new(),
                    not_locks_total: 0,
                    coverage,
                    limitations,
                });
            }
        };

        // The call graph.
        let mut callees: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        let mut callers: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        for xref in program.xrefs.iter().filter(|xref| matches!(xref.kind, XrefKind::Call | XrefKind::Jump)) {
            let Some(from) = analysis.function_containing(xref.from) else { continue };
            if xref.kind == XrefKind::Jump && program.functions.binary_search_by_key(&xref.to, |f| f.address).is_err() {
                continue;
            }
            if from != xref.to {
                callees.entry(from).or_default().insert(xref.to);
                callers.entry(xref.to).or_default().insert(from);
            }
        }

        // Crypto constants and the functions referencing them.
        let packs = self.packs();
        let scan = rampage_constants::scan_binary_report(binary, packs.constants());
        let hits: Vec<_> = scan
            .hits
            .iter()
            .filter(|hit| {
                hit.section.is_none()
                    && matches!(hit.kind, Kind::Hash | Kind::PublicKey | Kind::Mac | Kind::Checksum)
                    && (hit.complete || hit.kind != Kind::Checksum)
            })
            .collect();
        coverage.crypto_constants = hits.iter().filter(|hit| hit.kind != Kind::Checksum).count();
        let ranges: Vec<CryptoRange> = {
            let mut ranges: Vec<CryptoRange> = hits
                .iter()
                .map(|hit| {
                    // Curve parameters often sit in a struct referenced at its base, a little before the hit.
                    let curve = hit.kind == Kind::PublicKey && !hit.algorithm.starts_with("RSA");
                    let slack = if curve { CURVE_SLACK } else { 0 };
                    CryptoRange {
                        start: hit.address.saturating_sub(slack),
                        hit: hit.address,
                        end: hit.address.saturating_add(hit.length as u64),
                        kind: hit.kind,
                        algorithm: hit.algorithm.to_string(),
                    }
                })
                .collect();
            ranges.sort_by_key(|range| range.start);
            ranges
        };
        // A reference before a curve parameter reaches it only through one object: no symbol starts and no other
        // reference points between them.
        let mut symbol_starts: Vec<u64> = binary.symbols.iter().map(|symbol| symbol.address).collect();
        symbol_starts.sort_unstable();
        let reaches = |range: &CryptoRange, at: u64| -> bool {
            if at < range.start || at >= range.end {
                return false;
            }
            if at >= range.hit {
                return true;
            }
            let after = |sorted: &[u64]| {
                let first = sorted.partition_point(|&address| address <= at);
                sorted.get(first).is_some_and(|&address| address <= range.hit)
            };
            let first = program.xrefs.partition_point(|xref| xref.to <= at);
            let referenced_between = program.xrefs.get(first).is_some_and(|xref| xref.to < range.hit);
            // Another algorithm's constant in the gap (a DigestInfo table before curve parameters) is its own object.
            let other_algorithm = hits.iter().any(|other| {
                other.algorithm != range.algorithm.as_str()
                    && other.address < range.hit
                    && at < other.address.saturating_add(other.length as u64)
            });
            !after(&symbol_starts) && !referenced_between && !other_algorithm
        };
        let mut crypto: BTreeMap<u64, BTreeSet<(Kind, String)>> = BTreeMap::new();
        for range in &ranges {
            let first = program.xrefs.partition_point(|xref| xref.to < range.start);
            for xref in program.xrefs[first..].iter().take_while(|xref| xref.to < range.end) {
                if reaches(range, xref.to)
                    && let Some(function) = analysis.function_containing(xref.from)
                {
                    crypto.entry(function).or_default().insert((range.kind, range.algorithm.clone()));
                }
            }
        }
        if binary.arch == rampage_arch::Arch::Arm && !ranges.is_empty() {
            // Thumb code reaches tables through literal-pool words holding their address.
            for (slot, value) in pool_words(binary, &ranges) {
                for range in ranges.iter().filter(|range| reaches(range, value)) {
                    for from in xrefs_to(program, slot) {
                        if let Some(function) = analysis.function_containing(from) {
                            crypto.entry(function).or_default().insert((range.kind, range.algorithm.clone()));
                        }
                    }
                }
            }
        }
        let crc_routines = crate::integrity::crc_routine_addresses(self);

        // Registers with a role, through the constant-address access scan (firmware or an imported map only).
        let accesses = if firmware || !peripherals.is_empty() { self.access_index().ok() } else { None };
        if (firmware || !peripherals.is_empty()) && accesses.is_none() {
            limitations.push("The register access scan was unavailable; register roles were not traced.".into());
        }
        let label_of = |address: u64| -> Option<Label> {
            if let Some(hit) = peripherals.at(address) {
                return labels::register_role(hit.peripheral, hit.register, &hit.name(), address);
            }
            if firmware { labels::architectural(address) } else { None }
        };
        let mut seeds: BTreeSet<u64> = crypto.keys().copied().collect();
        seeds.extend(crc_routines.iter().copied());
        let mut reset_writers = BTreeSet::new();
        if let Some(accesses) = &accesses {
            for access in &accesses.by_address {
                if label_of(access.address).is_some() {
                    seeds.insert(access.function);
                }
                if firmware && access.write && access.address == labels::AIRCR {
                    seeds.insert(access.function);
                    reset_writers.insert(access.function);
                }
            }
        }
        for function in &program.functions {
            let name = self.function_name(function.address);
            if labels::signature_api(&name).is_some()
                || labels::mac_api(&name).is_some()
                || labels::random_api(&name).is_some()
            {
                seeds.extend(callers.get(&function.address).into_iter().flatten().copied());
                seeds.insert(function.address);
            }
        }
        for import in &binary.import_slots {
            if labels::signature_api(&import.name).is_some()
                || labels::mac_api(&import.name).is_some()
                || labels::random_api(&import.name).is_some()
            {
                for xref in xrefs_to(program, import.address) {
                    if let Some(function) = analysis.function_containing(xref) {
                        seeds.insert(function);
                        seeds.extend(callers.get(&function).into_iter().flatten().copied());
                    }
                }
            }
        }
        if !peripherals.is_empty() && seeds.is_empty() && accesses.is_none() {
            limitations.push("No register accesses were traced.".into());
        }
        let mut candidates = seeds.clone();
        let mut frontier: Vec<u64> = seeds.into_iter().collect();
        for _ in 0..CALLER_DEPTH {
            let mut next = Vec::new();
            for function in frontier {
                for &caller in callers.get(&function).into_iter().flatten() {
                    if candidates.len() < MAX_FUNCTIONS && candidates.insert(caller) {
                        next.push(caller);
                    }
                }
            }
            frontier = next;
        }
        // Direct callees, so what a path calls (a reset, a jump into the image) is known.
        let callees_of_candidates: Vec<u64> =
            candidates.iter().flat_map(|function| callees.get(function).into_iter().flatten().copied()).collect();
        for callee in callees_of_candidates {
            if candidates.len() < MAX_FUNCTIONS {
                candidates.insert(callee);
            }
        }
        if candidates.len() >= MAX_FUNCTIONS {
            coverage.incomplete = true;
        }

        let starts: Vec<u64> = program.functions.iter().map(|function| function.address).collect();
        let mut noreturn = program.noreturn.clone();
        noreturn.sort_unstable();
        // Callees first, so each call knows which arguments the callee's result derives from.
        let mut flows = BTreeMap::new();
        let mut summaries: HashMap<u64, u64> = HashMap::new();
        for address in post_order(&candidates, &callees) {
            let Ok(index) = program.functions.binary_search_by_key(&address, |function| function.address) else {
                continue;
            };
            let function = &program.functions[index];
            let Some(blocks) = lifter.lift(function, &program.code_modes, &noreturn, MAX_INSTRUCTIONS) else {
                coverage.incomplete = true;
                break;
            };
            let scope = flow::Scope { function, starts: &starts, summaries: &summaries };
            let analyzed = lifter.analyze(&scope, blocks);
            summaries.insert(address, analyzed.parameters);
            flows.insert(address, analyzed);
        }

        // Tables the analyzed code forms or loads the address of (literal pools, movw/movt pairs).
        for (address, flow) in &flows {
            for range in &ranges {
                if flow.constants.range(range.start..range.end).any(|&at| reaches(range, at)) {
                    crypto.entry(*address).or_default().insert((range.kind, range.algorithm.clone()));
                }
            }
        }
        let mut context = Context {
            project: self,
            firmware,
            flows,
            summaries,
            callees,
            callers,
            crypto,
            crc_routines,
            reset_routines: BTreeSet::new(),
            noreturn,
            peripherals: peripherals.clone(),
            globals: Vec::new(),
            reached: Default::default(),
            profiles: Default::default(),
            results: Default::default(),
            names: Default::default(),
        };
        // Reset routines: a write of SYSRESETREQ with the AIRCR key, or any AIRCR write in a routine that never
        // returns.
        for &function in &reset_writers {
            let Some(flow) = context.flows.get(&function) else { continue };
            let requests = flow.stores.iter().any(|store| {
                store.address == labels::AIRCR
                    && store.value.is_some_and(|value| value >> 16 == 0x05FA && value & 4 != 0)
            });
            let never_returns = context.noreturn.binary_search(&function).is_ok() || !flow.self_loops.is_empty();
            if requests || never_returns {
                context.reset_routines.insert(function);
            }
        }
        // What analyzed functions store in RAM, by role, so a flag or buffer written in one function and read in
        // another (a challenge, an unlocked flag) carries its origin.
        let mut globals = Vec::new();
        for (address, flow) in &context.flows {
            for store in &flow.stores {
                if store.taint.is_empty() || label_of(store.address).is_some() {
                    continue;
                }
                let labels = context.taint_labels(*address, store.taint, false);
                if labels.is_empty() {
                    continue;
                }
                // What a call writes through a pointer carries only its randomness (a challenge buffer):
                // whether other outputs are written at all is not known.
                let labels: BTreeSet<Label> = if store.by_call {
                    labels.into_iter().filter(|label| matches!(label, Label::Random(_))).collect()
                } else {
                    labels
                };
                if labels.is_empty() {
                    continue;
                }
                globals.push(Stored {
                    start: store.address & !3,
                    end: store.address.saturating_add(store.span.max(1)),
                    labels,
                    by: *address,
                });
            }
        }
        context.globals = globals;

        // Decisions, outside the crypto routines' own internals (a verifier's checks of its padding or its point
        // arithmetic are the routine, not the decision that acts on it).
        let internals = crypto_internals(&context);
        let mut found: Vec<Candidate> = Vec::new();
        let mut integrity: BTreeMap<u64, (u64, BTreeSet<Label>)> = BTreeMap::new();
        for (address, flow) in &context.flows {
            if internals.contains(address) {
                continue;
            }
            for (index, gate) in flow.gates.iter().enumerate() {
                // A decision on nothing but data another function stored (a flag a mechanism sets) consumes that
                // mechanism's verdict; it is listed with it as a flag consumer, not as a mechanism of its own.
                let direct = context.taint_labels(*address, gate.taint, false);
                if direct.is_empty() {
                    continue;
                }
                let mut labels = context.taint_labels(*address, gate.taint, true);
                // A challenge is issued before the response is checked: randomness counts only when it reaches the
                // decision through data another function stored. Randomness the check itself draws (a nonce for
                // key exchange, signature padding) is not a challenge.
                if direct.iter().any(|label| matches!(label, Label::Random(_))) {
                    labels.retain(|label| !matches!(label, Label::Random(_)));
                }
                match categorize(&labels) {
                    Some(category) => {
                        found.push(Candidate { function: *address, gate: index, labels, category, outer: None })
                    }
                    None => {
                        if not_lock_kind(&labels).is_some() {
                            integrity.entry(*address).or_insert((gate.at, BTreeSet::new())).1.extend(labels);
                        }
                    }
                }
            }
        }
        // A decision in F whose verdict a caller decides on again (same category, through F's result) belongs to
        // the caller's decision.
        for index in 0..found.len() {
            let function = found[index].function;
            let category = found[index].category;
            let outer = found.iter().position(|other| {
                other.category == category
                    && other.function != function
                    && context.flows.get(&other.function).is_some_and(|flow| {
                        flow.gates[other.gate]
                            .taint
                            .bits()
                            .any(|bit| flow.source_of(bit) == Some(Source::Call(Some(function))))
                    })
            });
            found[index].outer = outer;
        }
        let root_of = |mut index: usize| {
            for _ in 0..16 {
                match found[index].outer {
                    Some(outer) if outer != index => index = outer,
                    _ => break,
                }
            }
            index
        };
        // Group roots by (function, category): one mechanism, further gates as related decisions.
        let mut groups: BTreeMap<(u64, &'static str), Vec<usize>> = BTreeMap::new();
        let mut inner: BTreeMap<(u64, &'static str), Vec<usize>> = BTreeMap::new();
        for index in 0..found.len() {
            let root = root_of(index);
            let key = (found[root].function, found[root].category);
            if root == index || found[index].function == found[root].function {
                groups.entry(key).or_default().push(index);
            } else {
                inner.entry(key).or_default().push(index);
            }
        }
        // Protection configured by writes, with or without a decision in the same function.
        let mut configures: BTreeMap<u64, Vec<(u64, String)>> = BTreeMap::new();
        if let Some(accesses) = &accesses {
            for access in accesses.by_address.iter().filter(|access| access.write) {
                if let Some(Label::Protection(name, _)) = label_of(access.address) {
                    configures.entry(access.function).or_default().push((access.instruction, name));
                }
            }
        }
        for function in configures.keys() {
            groups.entry((*function, "debug_lock")).or_default();
        }

        let mut mechanisms: Vec<Mechanism> = Vec::new();
        let mut consulted_functions: BTreeSet<u64> = BTreeSet::new();
        for ((function, category), members) in &groups {
            let mechanism = build_mechanism(
                &context,
                *function,
                category,
                members,
                inner.get(&(*function, *category)).map(Vec::as_slice).unwrap_or(&[]),
                &found,
                configures.get(function).map(Vec::as_slice).unwrap_or(&[]),
            );
            consulted_functions.insert(*function);
            for &member in members.iter().chain(inner.get(&(*function, *category)).into_iter().flatten()) {
                consulted_functions.insert(found[member].function);
            }
            mechanisms.push(mechanism);
        }
        // Flags a mechanism writes, and the decisions elsewhere that test them.
        add_flag_consumers(&context, &mut lifter, program, &starts, &mut mechanisms, &mut coverage);
        // A debugger presence check whose debugger side is not shown to be the refusal (a HardFault handler that
        // breaks into an attached debugger, semihosting, trace output) is not a lock.
        let mut presence_checks = Vec::new();
        mechanisms.retain(|mechanism| {
            if mechanism.debugger_only != Some(false) {
                return true;
            }
            if let Some(decision) = &mechanism.decision {
                let paths: Vec<String> =
                    mechanism.outcomes.iter().map(|outcome| format!("{}: {}", outcome.path, outcome.detail)).collect();
                presence_checks.push(NotLock {
                    kind: "debugger_presence_check",
                    function: decision.function,
                    function_name: decision.function_name.clone(),
                    at: decision.at,
                    detail: format!(
                        "decides on whether a debugger is attached (DHCSR), but the code does not show the attached \
                         side refusing while the other continues ({})",
                        paths.join("; ")
                    ),
                });
            }
            false
        });

        if let Some(category) = &query.category {
            mechanisms.retain(|mechanism| mechanism.category == category.as_str());
        }
        let rank = |confidence: &str| match confidence {
            "high" => 0,
            "medium" => 1,
            _ => 2,
        };
        mechanisms.sort_by(|a, b| {
            rank(a.confidence)
                .cmp(&rank(b.confidence))
                .then(a.decision.as_ref().map(|d| d.at).cmp(&b.decision.as_ref().map(|d| d.at)))
        });
        for (id, mechanism) in mechanisms.iter_mut().enumerate() {
            mechanism.id = id;
        }

        // Not locks.
        let internals = crypto_internals(&context);
        let mut not_locks = Vec::new();
        for (function, (at, labels)) in &integrity {
            if consulted_functions.contains(function) || internals.contains(function) {
                continue;
            }
            let what: Vec<String> = labels
                .iter()
                .filter_map(|label| match label {
                    Label::Crc => Some("a CRC or checksum".to_owned()),
                    Label::Hash(name) => Some(format!("an unkeyed {name} digest")),
                    _ => None,
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            not_locks.push(NotLock {
                kind: "integrity_check",
                function: *function,
                function_name: context.name(*function),
                at: *at,
                detail: format!(
                    "decides on {} with no key, so it detects damage but does not restrict who may change the data",
                    what.join(" and ")
                ),
            });
        }
        if let Some(accesses) = &accesses {
            let mut readers: BTreeMap<u64, (u64, BTreeSet<String>)> = BTreeMap::new();
            for access in accesses.by_address.iter().filter(|access| !access.write) {
                if let Some(Label::UniqueId(name, _)) = label_of(access.address)
                    && !consulted_functions.contains(&access.function)
                {
                    readers.entry(access.function).or_insert((access.instruction, BTreeSet::new())).1.insert(name);
                }
            }
            for (function, (at, names)) in readers {
                not_locks.push(NotLock {
                    kind: "identity_read",
                    function,
                    function_name: context.name(function),
                    at,
                    detail: format!(
                        "reads {} but no traced decision depends on it (for example a serial-number string)",
                        names.into_iter().collect::<Vec<_>>().join(", ")
                    ),
                });
            }
        }
        not_locks.extend(presence_checks);
        not_locks.extend(crypto_without_decision(&context, &consulted_functions));
        let not_locks_total = not_locks.len();
        not_locks.truncate(MAX_NOT_LOCKS);

        coverage.functions_analyzed = context.flows.len();
        if context.flows.is_empty() {
            limitations.push(format!(
                "No function was analyzed: of the {} functions discovery found, none references a crypto constant, a \
                 CRC routine, a known verify, MAC or random API, or a register with a role{}. Functions are chosen \
                 from that evidence and their callers, not traced exhaustively.",
                program.functions.len(),
                if peripherals.is_empty() {
                    " (without an imported SVD map only DHCSR, DAUTHCTRL and AIRCR writes)"
                } else {
                    ""
                }
            ));
        }
        if context.flows.values().any(|flow| flow.overflowed) {
            coverage.incomplete = true;
            limitations.push(
                "Some functions had more data sources than the dataflow tracks; their surplus sources carry no role."
                    .into(),
            );
        }
        coverage.instructions = lifter.instructions;
        if coverage.instructions > MAX_INSTRUCTIONS {
            coverage.incomplete = true;
        }
        if coverage.incomplete {
            limitations.push(format!(
                "The analysis stopped at its budget ({MAX_FUNCTIONS} functions, {MAX_INSTRUCTIONS} instructions); \
                 mechanisms may be missing."
            ));
        }
        if scan.truncated {
            limitations.push("The crypto constant scan reached its hit cap; some routines may be unrecognized.".into());
        }
        if peripherals.is_empty() && firmware {
            limitations.push(
                "No SVD map is imported: unique-ID, OTP/fuse, option-byte and RNG registers are vendor-specific and \
                 are only recognized by name after import_svd, so device binding, anti-rollback, feature locks and \
                 most debug locks are unknown here."
                    .into(),
            );
        } else if !firmware && peripherals.is_empty() {
            limitations.push(
                "Not firmware with registers to name: only signature, MAC and challenge-response checks are traced."
                    .into(),
            );
        }
        limitations.push(
            "Heuristic: a mechanism is a branch whose condition derives from recognized crypto, register roles or \
             library calls; decisions through memory the dataflow does not track, indirect calls and stripped \
             crypto without known constants are missed, and 'failure_path' is a reading of the code, not a proof."
                .into(),
        );

        let total = mechanisms.len();
        let page: Vec<Mechanism> = mechanisms.into_iter().skip(query.offset).take(limit).collect();
        let mut report = LockReport {
            supported: true,
            total,
            offset: query.offset,
            next_offset: None,
            mechanisms: page,
            not_locks,
            not_locks_total,
            coverage,
            limitations,
        };
        // A page ends early rather than past the result budget; next_offset continues it.
        while report.mechanisms.len() > 1 && serde_json::to_string(&report).map_or(0, |text| text.len()) > MAX_BYTES {
            report.mechanisms.pop();
        }
        let end = query.offset.saturating_add(report.mechanisms.len());
        report.next_offset = (end < total).then_some(end);
        Ok(report)
    }
}

/// Every source of a reference to `target`.
fn xrefs_to(program: &rampage_analysis::discover::Program, target: u64) -> impl Iterator<Item = u64> + '_ {
    let first = program.xrefs.partition_point(|xref| xref.to < target);
    program.xrefs[first..].iter().take_while(move |xref| xref.to == target).map(|xref| xref.from)
}

/// What an analyzed function stored at fixed addresses, by role.
struct Stored {
    start: u64,
    end: u64,
    labels: BTreeSet<Label>,
    /// The storing function.
    by: u64,
}

/// A crypto constant found in the image and the addresses a reference to it may point at.
struct CryptoRange {
    /// The hit, less the slack a curve parameter gets for a structure that holds it.
    start: u64,
    hit: u64,
    end: u64,
    kind: Kind,
    algorithm: String,
}

/// Aligned 32-bit words in mapped, read-only image data or code whose value falls in one of `ranges` (sorted by
/// start): (address, value).
fn pool_words(binary: &rampage_loaders::Binary, ranges: &[CryptoRange]) -> Vec<(u64, u64)> {
    let lowest = ranges.iter().map(|range| range.start).min().unwrap_or(u64::MAX);
    let highest = ranges.iter().map(|range| range.end).max().unwrap_or(0);
    let mut found = Vec::new();
    for segment in binary.segments.iter().filter(|segment| segment.perms.read && !segment.perms.write) {
        let Some(bytes) = binary.read(segment.address, segment.file_size) else { continue };
        let skip = usize::try_from(segment.address.next_multiple_of(4) - segment.address).unwrap_or(0);
        let (words, _) = bytes.get(skip..).unwrap_or_default().as_chunks::<4>();
        for (index, &word) in words.iter().enumerate() {
            let value = u64::from(if binary.big_endian { u32::from_be_bytes(word) } else { u32::from_le_bytes(word) });
            if value < lowest || value >= highest {
                continue;
            }
            let after = ranges.partition_point(|range| range.start <= value);
            if ranges[..after].iter().rev().take(8).any(|range| value < range.end) {
                found.push((segment.address + (skip + 4 * index) as u64, value));
            }
        }
    }
    found
}

fn build_mechanism(
    context: &Context,
    function: u64,
    category: &'static str,
    members: &[usize],
    inner: &[usize],
    found: &[Candidate],
    configures: &[(u64, String)],
) -> Mechanism {
    let flow = context.flows.get(&function);
    let mut labels: BTreeSet<Label> = BTreeSet::new();
    for &member in members.iter().chain(inner) {
        labels.extend(found[member].labels.iter().cloned());
    }
    for (_, name) in configures {
        labels.insert(Label::Protection(name.clone(), 0));
    }
    // The decision shown is the most telling of the function's gates: the earliest branch on the result of a call
    // that carries the evidence, else the earliest other branch, else a conditional instruction that returns,
    // branches or writes memory, else the last conditional select (the end of a compare chain).
    let telling = |member: usize| {
        let Some(flow) = flow else { return (4, 0) };
        let gate = &flow.gates[found[member].gate];
        let on_result = gate.taint.bits().any(|bit| match flow.source_of(bit) {
            Some(Source::Call(Some(target))) => !context.result_labels(target, 0, true).is_empty(),
            _ => false,
        });
        match (gate.target, &gate.effect) {
            (Some(_), _) if on_result => (0, gate.at),
            (Some(_), _) => (1, gate.at),
            (None, Some(Effect::Returns(_) | Effect::Branches(_) | Effect::Stores { .. })) => (2, gate.at),
            _ => (3, u64::MAX - gate.at),
        }
    };
    let mut members = members.to_vec();
    members.sort_by_key(|&member| telling(member));
    let primary = members.first().map(|&member| &found[member]);
    let mut related = Vec::new();
    let mut decision = None;
    let mut sides: Vec<Side> = Vec::new();
    if let (Some(primary), Some(flow)) = (primary, flow) {
        let gate = &flow.gates[primary.gate];
        decision = Some(Decision {
            function,
            function_name: context.name(function),
            at: gate.at,
            condition: gate.taint.condition(),
        });
        sides = outcomes(context, flow, gate);
        for &member in &members[1..] {
            let other = &flow.gates[found[member].gate];
            related.push(Related {
                role: "decision",
                function,
                function_name: context.name(function),
                at: other.at,
                detail: format!("also decides on the same evidence ({})", other.taint.condition()),
            });
        }
    }
    // One row per inner function: its first decision, and how many it makes.
    let mut inner_functions: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for &member in inner {
        let candidate = &found[member];
        if let Some(inner_flow) = context.flows.get(&candidate.function) {
            inner_functions.entry(candidate.function).or_default().push(inner_flow.gates[candidate.gate].at);
        }
    }
    for (inner_function, mut sites) in inner_functions {
        sites.sort_unstable();
        let more = match sites.len() {
            1 => String::new(),
            count => format!(" ({count} decisions)"),
        };
        related.push(Related {
            role: "inner_decision",
            function: inner_function,
            function_name: context.name(inner_function),
            at: sites[0],
            detail: format!("decides first{more}; its result is what this decision tests"),
        });
    }
    for (at, name) in configures {
        related.push(Related {
            role: "configures",
            function,
            function_name: context.name(function),
            at: *at,
            detail: format!("writes {name}"),
        });
    }
    related.truncate(MAX_RELATED);

    let mut consults: BTreeSet<Consulted> =
        labels.iter().filter(|label| !matches!(label, Label::Protection(_, 0))).filter_map(consulted).collect();
    for (_, name) in configures {
        consults.insert(Consulted { kind: "protection_setting", name: name.clone(), at: None });
    }
    // Data passed to the checking routine: read-only image data and addresses outside the image.
    let mut checks = Vec::new();
    if let (Some(primary), Some(flow)) = (primary, flow) {
        let gate = &flow.gates[primary.gate];
        for bit in gate.taint.bits() {
            if let Some(Source::Call(Some(target))) = flow.source_of(bit) {
                let mut carried = BTreeSet::new();
                context.source_labels(function, bit, 0, true, &mut carried);
                if carried.is_empty() {
                    continue;
                }
                let result = context.result_labels(target, 0, true);
                let signatures: Vec<String> = result
                    .iter()
                    .filter_map(|label| {
                        if let Label::Signature(name) = label { Some(format!("{name} signature")) } else { None }
                    })
                    .collect();
                let macs: Vec<String> = result
                    .iter()
                    .filter_map(|label| if let Label::Mac(name) = label { Some(format!("{name} MAC")) } else { None })
                    .collect();
                let mut what: Vec<String> = signatures.into_iter().chain(macs).collect();
                if what.is_empty() {
                    what.extend(result.iter().filter_map(|label| {
                        if let Label::Hash(name) = label { Some(format!("{name} digest")) } else { None }
                    }));
                }
                let name = context.name(target);
                if what.is_empty() {
                    checks.push(format!("the result of `{name}` ({target:#x})"));
                } else {
                    checks.push(format!("`{name}` ({target:#x}): {}", what.join(", ")));
                }
                data_arguments(context, function, &|callee| callee == target, &mut consults);
                data_arguments(context, target, &|callee| context.is_crypto(callee), &mut consults);
            }
        }
    }
    for &member in inner {
        data_arguments(context, found[member].function, &|callee| context.is_crypto(callee), &mut consults);
    }
    // One row per (kind, name), keeping the one with an address.
    let mut seen: BTreeSet<(&'static str, String)> = BTreeSet::new();
    let mut consults: Vec<Consulted> =
        consults.into_iter().rev().filter(|consulted| seen.insert((consulted.kind, consulted.name.clone()))).collect();
    consults.reverse();
    consults.truncate(16);
    checks.truncate(8);

    let failing: Vec<&Side> = sides.iter().filter(|side| side.fails()).collect();
    let transferring: Vec<&Side> = sides.iter().filter(|side| side.effect == "transfer").collect();
    let failure_path = if failing.len() == 1 {
        failing[0].path
    } else if transferring.len() == 1 && sides.len() == 2 {
        sides.iter().find(|side| side.effect != "transfer").map_or("unknown", |side| side.path)
    } else {
        "unknown"
    };

    let strong = labels.iter().any(|label| match label {
        Label::Signature(_) | Label::UniqueId(..) | Label::Protection(..) | Label::Counter(..) => true,
        Label::Mac(_) | Label::Random(_) => category == "challenge_response",
        Label::DebugStatus(..) => true,
        _ => false,
    });
    let decided = failure_path != "unknown" || sides.iter().any(|side| side.effect == "writes");
    let confidence = match (strong, decided, category) {
        (_, _, "feature_lock") => "medium",
        (true, true, _) => "high",
        (true, false, _) | (false, true, _) => "medium",
        _ => "low",
    };
    let confidence = if decision.is_none() && !configures.is_empty() { "high" } else { confidence };
    // A check known only by a library function's name (no algorithm constant) is at most medium.
    let named_only = matches!(category, "signature_verification" | "mac_verification")
        && labels.iter().all(|label| match label {
            Label::Signature(name) | Label::Mac(name) => labels::is_library(name),
            _ => true,
        });
    let confidence = if named_only && confidence == "high" { "medium" } else { confidence };
    // A decision on the debug status alone is a lock only when the side a debugger takes is the refusal and the
    // other continues; the condition's polarity says which side that is.
    let debugger_only = (category == "debug_lock"
        && configures.is_empty()
        && labels.iter().all(|label| matches!(label, Label::DebugStatus(..))))
    .then(|| {
        let Some(gate) = primary.and_then(|primary| flow.map(|flow| &flow.gates[primary.gate])) else { return false };
        let attached = match (gate.target, gate.taint.when_nonzero()) {
            (Some(_), Some(true)) => "branch",
            (Some(_), Some(false)) => "fallthrough",
            // A conditionally executed instruction is skipped when its condition holds.
            (None, Some(true)) => "otherwise",
            (None, Some(false)) => "conditional",
            (_, None) => return false,
        };
        failure_path == attached && sides.iter().any(|side| side.path != attached && !side.fails())
    });
    let confidence = if debugger_only.is_some() && confidence == "high" { "medium" } else { confidence };

    let what = match category {
        "signature_verification" => format!(
            "Signature verification: continuing depends on a valid {} signature",
            joined(&labels, |label| if let Label::Signature(name) = label { Some(name) } else { None })
        ),
        "mac_verification" => format!(
            "MAC verification: a keyed {} value must match",
            joined(&labels, |label| if let Label::Mac(name) = label { Some(name) } else { None })
        ),
        "challenge_response" => {
            let algorithm = [
                joined(&labels, |label| if let Label::Signature(name) = label { Some(name) } else { None }),
                joined(&labels, |label| if let Label::Mac(name) = label { Some(name) } else { None }),
                joined(&labels, |label| if let Label::Hash(name) = label { Some(name) } else { None }),
            ]
            .into_iter()
            .find(|text| !text.is_empty())
            .unwrap_or_default();
            format!(
                "Challenge-response: a random challenge ({}) must be answered with a matching {algorithm} response",
                joined(&labels, |label| if let Label::Random(name) = label { Some(name) } else { None })
            )
        }
        "device_binding" => format!(
            "Device binding: the chip's unique ID ({}) is compared with stored or expected data",
            joined(&labels, |label| if let Label::UniqueId(name, _) = label { Some(name) } else { None })
        ),
        "anti_rollback" => format!(
            "Anti-rollback: a version is compared with a counter in protected storage ({})",
            joined(&labels, |label| if let Label::Counter(name, _) = label { Some(name) } else { None })
        ),
        "debug_lock" => {
            let status =
                joined(&labels, |label| if let Label::DebugStatus(name, _) = label { Some(name) } else { None });
            let settings = joined(&labels, |label| match label {
                Label::Protection(name, _) => Some(name),
                _ => None,
            });
            match (status.is_empty(), settings.is_empty(), decision.is_some()) {
                (false, _, _) => format!("Debugger detection: behaviour depends on the debug status ({status})"),
                (true, false, true) => format!("Debug or readout protection: checks and configures {settings}"),
                _ => format!("Debug or readout protection: configures {settings}"),
            }
        }
        _ => format!(
            "Feature or region lock: behaviour depends on fuse or option bits ({})",
            joined(&labels, |label| if let Label::Fuse(name, _) = label { Some(name) } else { None })
        ),
    };
    let summary = match &decision {
        Some(decision) => {
            let paths = sides
                .iter()
                .map(|side| {
                    let marker = if side.path == failure_path { " (refusal)" } else { "" };
                    format!("{}{marker}: {}", side.path, side.detail)
                })
                .collect::<Vec<_>>()
                .join("; ");
            format!(
                "{what}. Decided in `{}` at {:#x} ({}); {paths}.",
                decision.function_name, decision.at, decision.condition
            )
        }
        None => format!("{what}, in `{}`.", context.name(function)),
    };
    let written: Vec<u64> = sides.iter().flat_map(|side| side.written.iter().copied()).collect();
    let mut evidence: Vec<String> = Vec::new();
    for label in &labels {
        match label {
            Label::Signature(name) => evidence.push(format!("public-key evidence in the check's call tree: {name}")),
            Label::Mac(name) => evidence.push(format!("keyed MAC evidence in the check's call tree: {name}")),
            Label::Hash(name) => evidence.push(format!("digest routine in the check's call tree: {name}")),
            Label::Random(name) => evidence.push(format!("the checked data derives from a random source: {name}")),
            Label::UniqueId(name, at) => {
                evidence.push(format!("decision derives from {name} ({at:#x}), named by the imported SVD"))
            }
            Label::Counter(name, at) => {
                evidence.push(format!("decision derives from {name} ({at:#x}), a counter in protected storage"))
            }
            Label::Fuse(name, at) => {
                evidence.push(format!("decision derives from {name} ({at:#x}), fuse or option storage"))
            }
            Label::Protection(name, at) if *at != 0 => {
                evidence.push(format!("decision derives from {name} ({at:#x}), a protection setting"))
            }
            Label::DebugStatus(name, at) => evidence
                .push(format!("decision derives from {name} ({at:#x}), the architectural debug status register")),
            _ => {}
        }
    }
    evidence.truncate(12);
    Mechanism {
        id: 0,
        category,
        confidence,
        summary,
        decision,
        checks,
        consults,
        outcomes: sides
            .into_iter()
            .map(|side| Outcome { path: side.path, at: side.at, effect: side.effect, detail: side.detail })
            .collect(),
        failure_path,
        related,
        evidence,
        written,
        debugger_only,
    }
}

/// Pointer arguments `function` passes to the calls `wanted` selects: read-only image data (`constant_data`, such
/// as a key or a table) and, in firmware, addresses outside the image (`external_data`, such as an image header in
/// another flash area). Only addresses are reported, never the bytes.
fn data_arguments(context: &Context, function: u64, wanted: &dyn Fn(u64) -> bool, consults: &mut BTreeSet<Consulted>) {
    let binary = &context.project.binary;
    let Some(flow) = context.flows.get(&function) else { return };
    for call in flow.calls.iter().filter(|call| call.target.is_some_and(wanted)) {
        for value in call.arguments.iter().flatten() {
            let Val::Const(address) = *value else { continue };
            if address < 0x1000 || binary.is_code(address) && !context.firmware {
                continue;
            }
            let kind = if binary.read_constant(address, 1).is_some() {
                "constant_data"
            } else if context.firmware
                && binary.segment_containing(address).is_none()
                && context.peripherals.at(address).is_none()
                && address < 0x2000_0000
            {
                "external_data"
            } else {
                continue;
            };
            let name = context.project.symbolic_name_at(address).unwrap_or_else(|| format!("data at {address:#x}"));
            if consults.len() < 24 {
                consults.insert(Consulted { kind, name, at: Some(address) });
            }
        }
    }
}

/// What each path out of `gate` does: the events closer to one side's start than to the other's.
fn outcomes(context: &Context, flow: &FunctionFlow, gate: &flow::Gate) -> Vec<Side> {
    let two = |first: &'static str, second: &'static str, target: u64| {
        let taken = reach(context, flow, target);
        let fall = reach(context, flow, gate.next);
        vec![side(context, flow, first, target, &taken, &fall), side(context, flow, second, gate.next, &fall, &taken)]
    };
    match (gate.target, &gate.effect) {
        (Some(target), _) => two("branch", "fallthrough", target),
        (None, Some(Effect::Branches(target))) => two("conditional", "otherwise", *target),
        (None, effect) => {
            let (kind, detail) = match effect {
                Some(Effect::Returns(value)) => ("returns", returns_text(*value)),
                Some(Effect::Stores { address, value }) => ("writes", write_text(context, *address, *value)),
                _ => ("selects", "selects a different value".to_owned()),
            };
            let written = match effect {
                Some(Effect::Stores { address, value: Some(_) }) => vec![*address],
                _ => Vec::new(),
            };
            let conditional = Side { path: "conditional", at: gate.at, effect: kind, detail, written };
            let otherwise = if matches!(effect, Some(Effect::Returns(_))) {
                side(context, flow, "otherwise", gate.next, &reach(context, flow, gate.next), &BTreeMap::new())
            } else {
                Side {
                    path: "otherwise",
                    at: gate.next,
                    effect: "continues",
                    detail: "continues without it".to_owned(),
                    written: Vec::new(),
                }
            };
            vec![conditional, otherwise]
        }
    }
}

/// A returned constant as text: small values formed by instructions in decimal (negative ones signed), others not
/// at all, since a register left over in a function with no result is not a result.
fn returns_text(value: Option<Val>) -> String {
    match value {
        Some(Val::Const(value)) => {
            let signed = value as u32 as i32;
            if value <= MAX_SHOWN_VALUE {
                format!("returns {value}")
            } else if value <= u64::from(u32::MAX) && (-0x10000..0).contains(&signed) {
                format!("returns {signed}")
            } else {
                "returns".to_owned()
            }
        }
        _ => "returns".to_owned(),
    }
}

/// A write as text. The value is shown only when it is a small, flag-like constant an instruction formed (the flow
/// drops values read from memory) and the target is not a key register; anything else could be key material.
fn write_text(context: &Context, address: u64, value: Option<u64>) -> String {
    let place = place(context, address);
    match value {
        Some(value) if value <= MAX_SHOWN_VALUE && !place.to_ascii_uppercase().contains("KEY") => {
            format!("writes {value:#x} to {place}")
        }
        _ => format!("writes {place}"),
    }
}

/// A name for a data address: a symbol, a register or the address.
fn place(context: &Context, address: u64) -> String {
    context.project.name_at(address).map_or_else(|| format!("{address:#x}"), |name| format!("{name} ({address:#x})"))
}

/// Blocks reachable from `start` within the function, breadth first: block index to (distance, first address).
/// A path ends at a call that never returns and at another decision (what follows is that decision's).
fn reach(context: &Context, flow: &FunctionFlow, start: u64) -> BTreeMap<usize, (usize, u64)> {
    let find = |address: u64| {
        let index = flow.blocks.partition_point(|block| block.start <= address);
        index.checked_sub(1).filter(|&index| address < flow.blocks[index].end().max(flow.blocks[index].start + 1))
    };
    let mut visited: BTreeMap<usize, (usize, u64)> = BTreeMap::new();
    let mut queue = std::collections::VecDeque::from([(start, 0usize)]);
    while let Some((address, distance)) = queue.pop_front() {
        if visited.len() >= PATH_BLOCKS {
            break;
        }
        let Some(index) = find(address) else { continue };
        if visited.contains_key(&index) {
            continue;
        }
        visited.insert(index, (distance, address));
        let block = &flow.blocks[index];
        let range = address..block.end();
        let stops = flow
            .calls
            .iter()
            .any(|call| range.contains(&call.at) && call.target.is_some_and(|target| context.stops(target)));
        let decides = flow.gates.iter().any(|gate| gate.target.is_some() && range.contains(&gate.at));
        if !stops && !decides {
            queue.extend(block.successors.iter().map(|&next| (next, distance + 1)));
        }
    }
    visited
}

/// The effect of one side: events in blocks this side reaches sooner than the other (a shared failure block
/// belongs to the side that reaches it directly).
fn side(
    context: &Context,
    flow: &FunctionFlow,
    path: &'static str,
    at: u64,
    mine: &BTreeMap<usize, (usize, u64)>,
    other: &BTreeMap<usize, (usize, u64)>,
) -> Side {
    let mut kind: Option<&'static str> = None;
    let mut details: Vec<String> = Vec::new();
    let mut returns: Option<String> = None;
    let mut written: Vec<u64> = Vec::new();
    let rank = |effect: &str| match effect {
        "reset" => 0,
        "exit" => 1,
        "halt" => 2,
        "transfer" => 3,
        "writes" => 4,
        "returns" => 5,
        "calls" => 6,
        _ => 7,
    };
    let note = |effect: &'static str, detail: String, kind: &mut Option<&'static str>, details: &mut Vec<String>| {
        if kind.is_none_or(|known| rank(effect) < rank(known)) {
            *kind = Some(effect);
        }
        if details.len() < 3 && !details.contains(&detail) {
            details.push(detail);
        }
    };
    let mut blocks: Vec<(usize, usize, u64)> =
        mine.iter().map(|(&index, &(distance, from))| (distance, index, from)).collect();
    blocks.sort_unstable();
    for (distance, index, from) in blocks {
        if other.get(&index).is_some_and(|&(theirs, _)| theirs <= distance) {
            continue;
        }
        let block = &flow.blocks[index];
        let range = from..block.end();
        if flow.self_loops.contains(&block.start) {
            note("halt", format!("loops forever at {:#x}", block.start), &mut kind, &mut details);
        }
        for call in flow.calls.iter().filter(|call| range.contains(&call.at)) {
            let Some(target) = call.target else { continue };
            let name = context.name(target);
            let callee = context.flows.get(&target);
            let stops = context.stops(target);
            if context.reset_routines.contains(&target) || labels::stop_api(&name) == Some("reset") {
                note("reset", format!("calls `{name}`, which requests a system reset"), &mut kind, &mut details);
            } else if labels::stop_api(&name) == Some("exit") {
                note("exit", format!("calls `{name}` and stops"), &mut kind, &mut details);
            } else if stops && callee.is_some_and(|callee| !callee.indirect_calls.is_empty()) {
                note(
                    "transfer",
                    format!("calls `{name}`, which transfers control through a pointer and does not return"),
                    &mut kind,
                    &mut details,
                );
            } else if labels::stop_api(&name) == Some("ignore") {
                note("calls", format!("calls `{name}`"), &mut kind, &mut details);
            } else if stops || labels::stop_api(&name) == Some("halt") {
                note("halt", format!("calls `{name}`, which does not return"), &mut kind, &mut details);
            } else {
                note("calls", format!("calls `{name}`"), &mut kind, &mut details);
            }
        }
        for store in flow.stores.iter().filter(|store| range.contains(&store.at) && !store.indexed && !store.by_call) {
            if context.firmware
                && store.address == labels::AIRCR
                && store.value.is_some_and(|value| value >> 16 == 0x05FA && value & 4 != 0)
            {
                note("reset", "requests a system reset (AIRCR.SYSRESETREQ)".to_owned(), &mut kind, &mut details);
                continue;
            }
            if store.value.is_some() {
                written.push(store.address);
            }
            note("writes", write_text(context, store.address, store.value), &mut kind, &mut details);
        }
        // Control leaves through a pointer: a computed jump, or an indirect call that does not come back (nothing
        // but a loop forever follows it). Calls through import slots are calls to the import, not transfers.
        let leaves = |at: u64| {
            flow.indirect_jumps.contains(&at)
                || flow.indirect_calls.contains(&at)
                    && block.successors.iter().all(|&next| {
                        flow.self_loops.contains(&next) || next == block.end() && flow.self_loops.contains(&block.end())
                    })
        };
        for &indirect in flow.indirect_calls.iter().chain(&flow.indirect_jumps).filter(|at| range.contains(at)) {
            if leaves(indirect) {
                note(
                    "transfer",
                    format!("transfers control through a pointer at {indirect:#x}"),
                    &mut kind,
                    &mut details,
                );
            }
        }
        if returns.is_none()
            && let Some(ret) = flow.returns.iter().find(|ret| range.contains(&ret.at))
        {
            returns = Some(returns_text(ret.value.filter(|_| ret.immediate)));
        }
    }
    if let Some(text) = returns {
        note("returns", text, &mut kind, &mut details);
    }
    let effect = kind.unwrap_or("continues");
    let detail = if details.is_empty() { "continues".to_owned() } else { details.join(", ") };
    Side { path, at, effect, detail, written }
}

/// Mechanisms whose paths write a flag in RAM: the decisions elsewhere that read it are listed as consumers.
fn add_flag_consumers(
    context: &Context,
    lifter: &mut Lifter,
    program: &rampage_analysis::discover::Program,
    starts: &[u64],
    mechanisms: &mut [Mechanism],
    coverage: &mut Coverage,
) {
    let accesses =
        if context.firmware || !context.peripherals.is_empty() { context.project.access_index().ok() } else { None };
    for mechanism in mechanisms.iter_mut() {
        let Some(decision) = &mechanism.decision else { continue };
        let Some(flow) = context.flows.get(&decision.function) else { continue };
        let flags: BTreeSet<u64> = flow
            .stores
            .iter()
            .filter(|store| {
                !store.indexed
                    && !store.by_call
                    && store.value.is_some()
                    && context.peripherals.at(store.address).is_none()
                    && context.address_label(store.address).is_none()
                    && context.project.binary.read_constant(store.address, 1).is_none()
                    && store.address != labels::AIRCR
                    && mechanism.written.contains(&store.address)
            })
            .map(|store| store.address)
            .collect();
        for flag in flags {
            let mut readers: BTreeSet<u64> = xrefs_to(program, flag)
                .filter_map(|from| context.project.function_containing(from).ok().flatten())
                .collect();
            if let Some(accesses) = &accesses {
                readers.extend(accesses.in_range(flag, flag.saturating_add(4)).iter().map(|access| access.function));
            }
            readers.remove(&decision.function);
            for reader in readers.into_iter().take(MAX_RELATED) {
                let local;
                let flow = match context.flows.get(&reader) {
                    Some(flow) => flow,
                    None => {
                        let Ok(index) = program.functions.binary_search_by_key(&reader, |f| f.address) else {
                            continue;
                        };
                        let function = &program.functions[index];
                        let Some(blocks) =
                            lifter.lift(function, &program.code_modes, &context.noreturn, MAX_INSTRUCTIONS)
                        else {
                            coverage.incomplete = true;
                            continue;
                        };
                        let scope = flow::Scope { function, starts, summaries: &context.summaries };
                        local = lifter.analyze(&scope, blocks);
                        &local
                    }
                };
                let reads = flow
                    .gates
                    .iter()
                    .find(|gate| gate.taint.bits().any(|bit| flow.source_of(bit) == Some(Source::Load(flag))));
                if let Some(gate) = reads
                    && mechanism.related.len() < MAX_RELATED
                {
                    mechanism.related.push(Related {
                        role: "flag_consumer",
                        function: reader,
                        function_name: context.name(reader),
                        at: gate.at,
                        detail: format!("decides on {}, which this mechanism writes", place(context, flag)),
                    });
                }
            }
        }
    }
}

/// Functions inside crypto routines: those referencing algorithm constants and everything they call.
fn crypto_internals(context: &Context) -> BTreeSet<u64> {
    let mut internals: BTreeSet<u64> = context
        .crypto
        .iter()
        .filter(|(_, entries)| entries.iter().any(|(kind, _)| *kind != Kind::Checksum))
        .map(|(&function, _)| function)
        .collect();
    let mut frontier: Vec<u64> = internals.iter().copied().collect();
    while let Some(function) = frontier.pop() {
        for &callee in context.callees.get(&function).into_iter().flatten() {
            if internals.len() < 4096 && internals.insert(callee) {
                frontier.push(callee);
            }
        }
    }
    internals
}

/// Functions that call a crypto routine (one referencing hash, MAC or public-key constants, or a wrapper directly
/// above one) without any branch or return value depending on the result, outside reported mechanisms and the
/// routines' own internals.
fn crypto_without_decision(context: &Context, mechanisms: &BTreeSet<u64>) -> Vec<NotLock> {
    let internals = crypto_internals(context);
    let crypto_routine = |function: u64| {
        let direct = |function: u64| {
            context.crypto.get(&function).is_some_and(|entries| entries.iter().any(|(kind, _)| *kind != Kind::Checksum))
        };
        direct(function) || context.callees.get(&function).into_iter().flatten().any(|&callee| direct(callee))
    };
    // A wrapper over crypto routines (it calls nothing else and writes no fixed memory) is part of the routine's
    // interface, not a user of it.
    let is_wrapper = |function: u64| {
        context
            .callees
            .get(&function)
            .is_some_and(|callees| !callees.is_empty() && callees.iter().all(|&callee| crypto_routine(callee)))
            && context.flows.get(&function).is_some_and(|flow| flow.stores.iter().all(|store| store.by_call))
    };
    let mut found = Vec::new();
    for (address, flow) in &context.flows {
        if mechanisms.contains(address) || internals.contains(address) || is_wrapper(*address) {
            continue;
        }
        let mut used: BTreeSet<String> = BTreeSet::new();
        let mut decides = false;
        let mut first: Option<u64> = None;
        for call in &flow.calls {
            let Some(target) = call.target else { continue };
            if !crypto_routine(target) || mechanisms.contains(&target) {
                continue;
            }
            // The register a function with no result leaves behind is not a result: the returned value counts
            // only when a caller decides on it or stores it.
            decides |= flow.gates.iter().any(|gate| gate.taint.mask & call.result.mask != 0)
                || flow.returned.mask & call.result.mask != 0 && result_used(context, *address);
            let profile = context.profile(target);
            first.get_or_insert(call.at);
            used.extend(profile.signature.iter().chain(&profile.mac).chain(&profile.hash).cloned());
        }
        if decides || used.is_empty() {
            continue;
        }
        found.push(NotLock {
            kind: "crypto_without_decision",
            function: *address,
            function_name: context.name(*address),
            at: first.unwrap_or(*address),
            detail: format!(
                "computes {} but no branch or return value in it depends on the result",
                used.into_iter().collect::<Vec<_>>().join(", ")
            ),
        });
    }
    found
}

/// Whether an analyzed caller of `function` branches on, stores or returns its result.
fn result_used(context: &Context, function: u64) -> bool {
    context.callers.get(&function).into_iter().flatten().any(|caller| {
        let Some(flow) = context.flows.get(caller) else { return true };
        let Some(bit) = flow.sources.iter().position(|source| *source == Source::Call(Some(function))) else {
            return false;
        };
        let mask = 1u64 << bit.min(flow::MAX_SOURCES - 1);
        flow.gates.iter().any(|gate| gate.taint.mask & mask != 0)
            || flow.stores.iter().any(|store| !store.by_call && store.taint.mask & mask != 0)
            || flow.returned.mask & mask != 0
    })
}

/// `functions` ordered callees first (a depth-first post-order over the call graph restricted to them; cycles
/// are cut where they are met).
fn post_order(functions: &BTreeSet<u64>, callees: &BTreeMap<u64, BTreeSet<u64>>) -> Vec<u64> {
    let mut order = Vec::with_capacity(functions.len());
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for &root in functions {
        if !seen.insert(root) {
            continue;
        }
        let mut stack: Vec<(u64, Vec<u64>)> = vec![(root, children(root, functions, callees))];
        while let Some((function, pending)) = stack.last_mut() {
            match pending.pop() {
                Some(child) => {
                    if seen.insert(child) {
                        let grandchildren = children(child, functions, callees);
                        stack.push((child, grandchildren));
                    }
                }
                None => {
                    order.push(*function);
                    stack.pop();
                }
            }
        }
    }
    order
}

fn children(function: u64, functions: &BTreeSet<u64>, callees: &BTreeMap<u64, BTreeSet<u64>>) -> Vec<u64> {
    callees.get(&function).into_iter().flatten().filter(|callee| functions.contains(callee)).copied().collect()
}
