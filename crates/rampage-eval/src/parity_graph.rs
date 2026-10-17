//! Offline agreement with the actual `export-cfg` and `ghidra_cfg_export.java` JSON formats.
//!
//! Matching follows `tools/cfg-benchmark.py`: exact numeric function entry and block-start addresses,
//! directed CFG endpoint pairs (edge kinds ignored), and `(source instruction, target)` call pairs
//! (call kinds retained as evidence, not matched). Items shared by functions count once per owner.
//! Rampage references are calls if their kind is `call` OR their target is another Rampage function
//! entry, including entries absent from Ghidra. Ghidra `COMPUTED_CALL*` pairs count only when Rampage
//! resolved the same pair; excluded pairs are reported separately. Call graphs drop the source
//! instruction, retaining `(owning function, target)`. Chains use the benchmark's straight-line collapse.
//! As in the Python benchmark, raw call disagreements still include excluded computed calls even
//! though aggregate call metrics do not. `disagreeing_functions` uses raw blocks, edges and calls.
//! Only common functions enter item denominators; one-sided functions remain explicit coverage.
//! Block ends are parsed/width-checked, not compared. Unknown edge endpoints remain in raw edge
//! scores but are removed for chain collapse, just as in the Python benchmark.
//!
//! Function/block duplicates and conflicting kinds for a call pair are rejected rather than silently
//! overwriting data. Repeated edges and identical call pairs have set semantics, as in the benchmark.
//! Unknown fields (including Rampage `noreturn_calls`) are ignored. No rebasing, Thumb-bit masking,
//! address-space inference, instruction-range matching, or truth/pass judgment is performed.
//!
//! Export formats contain no image identity. The caller must bind each exact JSON byte string to
//! observed image/exporter metadata; hashes are checked here, but provenance claims cannot be
//! authenticated offline. `provenance` is retained verbatim for run receipts, commands, logs, etc.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// JSON addresses are hex strings, never floating-point JSON numbers. Canonical output is lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address(pub u64);

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{:#x}", self.0))
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let digits = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"));
        digits
            .filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .and_then(|digits| u64::from_str_radix(digits, 16).ok())
            .map(Self)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid u64 hex address: {text:?}")))
    }
}

/// Address context must match on both sides. Use explicit slice/embedded-image selections when applicable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageIdentity {
    pub image_sha256: String,
    pub architecture: String,
    pub address_bits: u8,
    pub address_space: String,
    pub image_base: Address,
    pub image_offset: u64,
    pub image_length: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportBinding {
    pub image: ImageIdentity,
    /// `rampage` or `ghidra`, respectively.
    pub tool: String,
    pub version: String,
    /// For example `rampage export-cfg` or `tools/ghidra_cfg_export.java`.
    pub exporter: String,
    /// Hash of the exporter executable/script, supplied by the runner.
    pub exporter_sha256: String,
    /// Hash of the exact UTF-8 bytes passed to `compare_exports`, including whitespace.
    pub export_sha256: String,
    #[serde(default)]
    pub provenance: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphRequest {
    pub rampage: ExportBinding,
    pub ghidra: ExportBinding,
    /// Global item limit, independently applied to disagreement, coverage, and excluded-call lists.
    pub max_details: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphError(pub String);

impl fmt::Display for GraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for GraphError {}

type Result<T> = std::result::Result<T, GraphError>;
type Pair = (Address, Address);

/// Precision/recall are directional agreement with Ghidra, not accuracy against ground truth.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Agreement {
    pub rampage: usize,
    pub ghidra: usize,
    pub matched: usize,
    pub only_rampage: usize,
    pub only_ghidra: usize,
    pub union: usize,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    pub jaccard: Option<f64>,
}

impl Agreement {
    fn add<T: Ord>(&mut self, rampage: &BTreeSet<T>, ghidra: &BTreeSet<T>) {
        self.rampage += rampage.len();
        self.ghidra += ghidra.len();
        self.matched += rampage.intersection(ghidra).count();
        self.only_rampage = self.rampage - self.matched;
        self.only_ghidra = self.ghidra - self.matched;
        self.union = self.rampage + self.only_ghidra;
        self.precision = ratio(self.matched, self.rampage);
        self.recall = ratio(self.matched, self.ghidra);
        self.jaccard = ratio(self.matched, self.union);
    }
}

fn ratio(numerator: usize, denominator: usize) -> Option<f64> {
    (denominator != 0).then(|| numerator as f64 / denominator as f64)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bounded<T> {
    pub total: usize,
    pub omitted: usize,
    pub items: Vec<T>,
}

impl<T> Bounded<T> {
    fn new() -> Self {
        Self { total: 0, omitted: 0, items: Vec::new() }
    }

    fn push(&mut self, item: T, limit: usize) {
        self.total += 1;
        if self.items.len() < limit {
            self.items.push(item);
        } else {
            self.omitted += 1;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Rampage,
    Ghidra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageItem {
    pub side: Side,
    pub function: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCoverage {
    pub rampage: usize,
    pub ghidra: usize,
    pub common: usize,
    pub only_rampage: usize,
    pub only_ghidra: usize,
    pub unmatched: Bounded<CoverageItem>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphMetric {
    Blocks,
    Edges,
    Chains,
    ChainEdges,
    Calls,
    CallGraph,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disagreement {
    pub function: Address,
    pub metric: GraphMetric,
    pub side: Side,
    /// Block/chain address, or edge/call source. For call graphs, the owning function.
    pub source: Address,
    pub target: Option<Address>,
    pub kind: Option<String>,
    pub ghidra_noreturn: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcludedCall {
    pub function: Address,
    pub source: Address,
    pub target: Address,
    pub kind: String,
}

/// Unfiltered call-pair differences, corresponding to Python's `calls_only_*` diagnostic lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawCallDisagreements {
    pub only_rampage: usize,
    pub only_ghidra: usize,
    /// Entry-address order, Rampage before Ghidra, then numeric source/target order.
    pub details: Bounded<Disagreement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphReceipt {
    pub schema_version: u32,
    pub semantics: String,
    pub reference_is_truth: bool,
    /// Exact request echoed only after checking both raw-export hashes and image context equality.
    pub binding: GraphRequest,
    pub functions: FunctionCoverage,
    pub identical_block_functions: usize,
    /// Common functions with differing raw blocks, CFG edges or call pairs, as in Python's diagnostics.
    /// Includes functions differing only by an excluded Ghidra computed call, even at max_details = 0.
    pub disagreeing_functions: usize,
    pub blocks: Agreement,
    pub edges: Agreement,
    pub chains: Agreement,
    pub chain_edges: Agreement,
    pub calls: Agreement,
    pub call_graph: Agreement,
    pub ghidra_computed_calls: Bounded<ExcludedCall>,
    pub raw_call_disagreements: RawCallDisagreements,
    /// Differences in the scored sets; Calls/CallGraph use the computed-call filter, unlike raw_call_disagreements.
    /// Entry-address order, then metric enum order, Rampage before Ghidra, then numeric item order.
    /// Unlike the Python display's worst-Jaccard ranking, this is a stable bounded prefix, not a top-N.
    pub disagreements: Bounded<Disagreement>,
}

#[derive(Deserialize)]
struct RampageFunction {
    address: Address,
    blocks: Vec<Address>,
    edges: Vec<(Address, Address, String)>,
    references: Vec<(Address, Address, String)>,
}

#[derive(Deserialize)]
struct GhidraExport {
    functions: Vec<GhidraFunction>,
}

#[derive(Deserialize)]
struct GhidraFunction {
    address: Address,
    noreturn: bool,
    blocks: Vec<GhidraBlock>,
    calls: Vec<(Address, Address, String)>,
}

#[derive(Deserialize)]
struct GhidraBlock {
    start: Address,
    end: Address,
    successors: Vec<(Address, String)>,
}

#[derive(Default)]
struct Function {
    blocks: BTreeSet<Address>,
    edges: BTreeSet<Pair>,
    calls: BTreeMap<Pair, String>,
    noreturn: bool,
}

/// Parses exports without executing tools or reading files. Scores only functions present on both sides.
/// A zero denominator serializes as null; empty inputs and zero common functions are not parity successes.
pub fn compare_exports(request: &GraphRequest, rampage_json: &str, ghidra_json: &str) -> Result<GraphReceipt> {
    validate_binding(&request.rampage, "rampage", rampage_json)?;
    validate_binding(&request.ghidra, "ghidra", ghidra_json)?;
    if request.rampage.image != request.ghidra.image {
        return Err(GraphError("image identity/address context differs between exports".into()));
    }
    let bits = request.rampage.image.address_bits;
    let rampage = parse_rampage(rampage_json, bits)?;
    let ghidra = parse_ghidra(ghidra_json, bits)?;
    let r_starts: BTreeSet<_> = rampage.keys().copied().collect();
    let g_starts: BTreeSet<_> = ghidra.keys().copied().collect();
    let common: Vec<_> = r_starts.intersection(&g_starts).copied().collect();
    let limit = request.max_details;
    let mut unmatched = Bounded::new();
    for (side, starts, other) in [(Side::Rampage, &r_starts, &g_starts), (Side::Ghidra, &g_starts, &r_starts)] {
        for &function in starts.difference(other) {
            unmatched.push(CoverageItem { side, function }, limit);
        }
    }
    let mut report = GraphReceipt {
        schema_version: 1,
        semantics: "cfg-benchmark-v1/exact-address-owned-sets".into(),
        reference_is_truth: false,
        binding: request.clone(),
        functions: FunctionCoverage {
            rampage: rampage.len(),
            ghidra: ghidra.len(),
            common: common.len(),
            only_rampage: rampage.len() - common.len(),
            only_ghidra: ghidra.len() - common.len(),
            unmatched,
        },
        identical_block_functions: 0,
        disagreeing_functions: 0,
        blocks: Agreement::default(),
        edges: Agreement::default(),
        chains: Agreement::default(),
        chain_edges: Agreement::default(),
        calls: Agreement::default(),
        call_graph: Agreement::default(),
        ghidra_computed_calls: Bounded::new(),
        disagreements: Bounded::new(),
        raw_call_disagreements: RawCallDisagreements { only_rampage: 0, only_ghidra: 0, details: Bounded::new() },
    };
    for start in common {
        let r = &rampage[&start];
        let g = &ghidra[&start];
        let r_calls: BTreeSet<_> = r.calls.keys().copied().collect();
        let g_raw_calls: BTreeSet<_> = g.calls.keys().copied().collect();
        report.raw_call_disagreements.only_rampage += r_calls.difference(&g_raw_calls).count();
        report.raw_call_disagreements.only_ghidra += g_raw_calls.difference(&r_calls).count();
        for (side, calls, other, kinds) in
            [(Side::Rampage, &r_calls, &g_raw_calls, &r.calls), (Side::Ghidra, &g_raw_calls, &r_calls, &g.calls)]
        {
            for &(source, target) in calls.difference(other) {
                report.raw_call_disagreements.details.push(
                    Disagreement {
                        function: start,
                        metric: GraphMetric::Calls,
                        side,
                        source,
                        target: Some(target),
                        kind: kinds.get(&(source, target)).cloned(),
                        ghidra_noreturn: g.noreturn,
                    },
                    limit,
                );
            }
        }
        let mut g_calls = BTreeSet::new();
        for (&(source, target), kind) in &g.calls {
            if !kind.starts_with("COMPUTED_CALL") || r_calls.contains(&(source, target)) {
                g_calls.insert((source, target));
            } else {
                report
                    .ghidra_computed_calls
                    .push(ExcludedCall { function: start, source, target, kind: kind.clone() }, limit);
            }
        }
        let r_graph = r_calls.iter().map(|&(_, target)| (start, target)).collect();
        let g_graph = g_calls.iter().map(|&(_, target)| (start, target)).collect();
        let (r_chains, r_chain_edges) = collapse(start, &r.blocks, &r.edges);
        let (g_chains, g_chain_edges) = collapse(start, &g.blocks, &g.edges);
        let r_blocks = r.blocks.iter().map(|&block| (block, None)).collect();
        let g_blocks = g.blocks.iter().map(|&block| (block, None)).collect();
        let r_chains = r_chains.iter().map(|&block| (block, None)).collect();
        let g_chains = g_chains.iter().map(|&block| (block, None)).collect();
        for (metric, score, r_items, g_items) in [
            (GraphMetric::Blocks, &mut report.blocks, r_blocks, g_blocks),
            (GraphMetric::Edges, &mut report.edges, with_targets(&r.edges), with_targets(&g.edges)),
            (GraphMetric::Chains, &mut report.chains, r_chains, g_chains),
            (
                GraphMetric::ChainEdges,
                &mut report.chain_edges,
                with_targets(&r_chain_edges),
                with_targets(&g_chain_edges),
            ),
            (GraphMetric::Calls, &mut report.calls, with_targets(&r_calls), with_targets(&g_calls)),
            (GraphMetric::CallGraph, &mut report.call_graph, with_targets(&r_graph), with_targets(&g_graph)),
        ] {
            score.add(&r_items, &g_items);
            for (side, items, other, calls) in
                [(Side::Rampage, &r_items, &g_items, &r.calls), (Side::Ghidra, &g_items, &r_items, &g.calls)]
            {
                for &(source, target) in items.difference(other) {
                    let kind = if metric == GraphMetric::Calls {
                        target.and_then(|target| calls.get(&(source, target))).cloned()
                    } else {
                        None
                    };
                    report.disagreements.push(
                        Disagreement {
                            function: start,
                            metric,
                            side,
                            source,
                            target,
                            kind,
                            ghidra_noreturn: g.noreturn,
                        },
                        limit,
                    );
                }
            }
        }
        report.identical_block_functions += usize::from(r.blocks == g.blocks);
        report.disagreeing_functions +=
            usize::from(r.blocks != g.blocks || r.edges != g.edges || r_calls != g_raw_calls);
    }
    Ok(report)
}

fn with_targets(items: &BTreeSet<Pair>) -> BTreeSet<(Address, Option<Address>)> {
    items.iter().map(|&(source, target)| (source, Some(target))).collect()
}

fn validate_binding(binding: &ExportBinding, tool: &str, text: &str) -> Result<()> {
    if binding.tool != tool || binding.version.trim().is_empty() || binding.exporter.trim().is_empty() {
        return Err(GraphError(format!("{tool}: tool, version and exporter identity are required")));
    }
    for digest in [&binding.image.image_sha256, &binding.exporter_sha256, &binding.export_sha256] {
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
            return Err(GraphError(format!("{tool}: expected lowercase SHA-256 hex")));
        }
    }
    if rampage_arch::hex::bytes(&Sha256::digest(text.as_bytes())) != binding.export_sha256 {
        return Err(GraphError(format!("{tool}: export SHA-256 does not match supplied bytes")));
    }
    let image = &binding.image;
    if !(1..=64).contains(&image.address_bits)
        || image.architecture.trim().is_empty()
        || image.address_space.trim().is_empty()
        || image.image_length == Some(0)
    {
        return Err(GraphError(format!("{tool}: invalid image/address context")));
    }
    check_address(image.image_base, image.address_bits)
}

fn check_address(address: Address, bits: u8) -> Result<()> {
    if bits < 64 && address.0 >= (1_u64 << bits) {
        return Err(GraphError(format!("address {:#x} exceeds {bits}-bit address width", address.0)));
    }
    Ok(())
}

fn insert_block(function: &mut Function, block: Address, bits: u8) -> Result<()> {
    check_address(block, bits)?;
    if !function.blocks.insert(block) {
        return Err(GraphError(format!("duplicate block start {:#x}", block.0)));
    }
    Ok(())
}

fn insert_call(function: &mut Function, source: Address, target: Address, kind: String) -> Result<()> {
    if kind.is_empty() {
        return Err(GraphError("empty call kind".into()));
    }
    if function.calls.get(&(source, target)).is_some_and(|previous| previous != &kind) {
        return Err(GraphError(format!("conflicting call kinds at {:#x} -> {:#x}", source.0, target.0)));
    }
    function.calls.insert((source, target), kind);
    Ok(())
}

fn parse_rampage(text: &str, bits: u8) -> Result<BTreeMap<Address, Function>> {
    let raw: Vec<RampageFunction> =
        serde_json::from_str(text).map_err(|error| GraphError(format!("rampage JSON: {error}")))?;
    let starts: BTreeSet<_> = raw.iter().map(|function| function.address).collect();
    let mut functions = BTreeMap::new();
    for raw in raw {
        check_address(raw.address, bits)?;
        let mut function = Function::default();
        for block in raw.blocks {
            insert_block(&mut function, block, bits)?;
        }
        for (source, target, _) in raw.edges {
            check_address(source, bits)?;
            check_address(target, bits)?;
            function.edges.insert((source, target));
        }
        for (source, target, kind) in raw.references {
            check_address(source, bits)?;
            check_address(target, bits)?;
            if kind == "call" || (target != raw.address && starts.contains(&target)) {
                insert_call(&mut function, source, target, kind)?;
            }
        }
        insert_function(&mut functions, raw.address, function)?;
    }
    Ok(functions)
}

fn parse_ghidra(text: &str, bits: u8) -> Result<BTreeMap<Address, Function>> {
    let raw: GhidraExport = serde_json::from_str(text).map_err(|error| GraphError(format!("ghidra JSON: {error}")))?;
    let mut functions = BTreeMap::new();
    for raw in raw.functions {
        check_address(raw.address, bits)?;
        let mut function = Function { noreturn: raw.noreturn, ..Function::default() };
        for block in raw.blocks {
            insert_block(&mut function, block.start, bits)?;
            check_address(block.end, bits)?;
            for (target, _) in block.successors {
                check_address(target, bits)?;
                function.edges.insert((block.start, target));
            }
        }
        for (source, target, kind) in raw.calls {
            check_address(source, bits)?;
            check_address(target, bits)?;
            insert_call(&mut function, source, target, kind)?;
        }
        insert_function(&mut functions, raw.address, function)?;
    }
    Ok(functions)
}

fn insert_function(functions: &mut BTreeMap<Address, Function>, start: Address, function: Function) -> Result<()> {
    if functions.insert(start, function).is_some() {
        return Err(GraphError(format!("duplicate function entry {:#x}", start.0)));
    }
    Ok(())
}

/// Literal equivalent of the Python benchmark, including filtering non-block endpoints only for chains.
fn collapse(entry: Address, blocks: &BTreeSet<Address>, edges: &BTreeSet<Pair>) -> (BTreeSet<Address>, BTreeSet<Pair>) {
    let edges: BTreeSet<_> =
        edges.iter().copied().filter(|(source, target)| blocks.contains(source) && blocks.contains(target)).collect();
    let mut successors: BTreeMap<_, BTreeSet<_>> = blocks.iter().map(|&block| (block, BTreeSet::new())).collect();
    let mut predecessors = successors.clone();
    for &(source, target) in &edges {
        successors.get_mut(&source).expect("filtered source").insert(target);
        predecessors.get_mut(&target).expect("filtered target").insert(source);
    }
    let merged = |block: Address| -> bool {
        let previous = &predecessors[&block];
        if block == entry || previous.len() != 1 {
            return false;
        }
        let previous = *previous.first().expect("single predecessor");
        previous != block && successors[&previous].len() == 1 && successors[&previous].contains(&block)
    };
    let leader = |mut block: Address| -> Address {
        let mut seen = BTreeSet::from([block]);
        while merged(block) {
            block = *predecessors[&block].first().expect("merged predecessor");
            if !seen.insert(block) {
                break;
            }
        }
        block
    };
    let leaders: BTreeSet<_> = blocks.iter().copied().filter(|&block| !merged(block)).collect();
    let collapsed = edges
        .iter()
        .filter(|(_, target)| leaders.contains(target))
        .map(|&(source, target)| (leader(source), target))
        .collect();
    (leaders, collapsed)
}
