//! One-to-one function matching between two builds of the same program, for `transfer_annotations`.
//!
//! Matches are made in stages, each only between functions no earlier stage matched, and each only where the
//! evidence is unique on both sides (ambiguity is reported, never resolved by guessing):
//! 1. a symbol name (symbol, export, stub) that names one function in each build;
//! 2. identical body bytes;
//! 3. an identical masked signature hash (`rampage_signatures::function_hash_in`: addresses and relative operands
//!    wildcarded);
//! 4. then, repeated until nothing changes (bounded by [`MAX_ROUNDS`]):
//!    - a string referenced by exactly one unmatched function in each build;
//!    - call-graph propagation from the matched functions ([`rampage_signatures::CallGraph`], two-sided and
//!      anchored: the old build is the "training" side and each matched function's identity its name), for bodies
//!      of comparable size; a callee that makes no calls and whose masked hash differs is placed by its call
//!      position alone and scored as such (`call_position`);
//!    - only when those match nothing more: the call-graph neighbourhood, the same matched callers and callees,
//!      found once in each build, for bodies of comparable size.
//!
//! A derived stage only builds on matches at least as confident as itself (strings on strings and better,
//! propagation on call-graph matches and better), so a weak match never yields a stronger-scored one.
//!
//! A match says whether the function changed: equal bytes or masked hash means unchanged at signature level.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{Hash, Hasher};

use rampage_analysis::discover::XrefKind;
use rampage_signatures::{CallGraph, FunctionHash, MaskContext, function_hash_in};
use serde::Serialize;

use crate::workflows::is_default_name;
use crate::{ApiError, Project};

/// Rounds of the anchor-propagation stages at most; each round that matches nothing ends the loop earlier.
pub const MAX_ROUNDS: usize = 16;
/// Bodies shorter than this are too common to match by their bytes alone.
const MIN_EXACT_BYTES: u64 = 8;
/// Strings shorter than this are too common to anchor a match.
const MIN_ANCHOR_STRING: usize = 6;
/// Ambiguities kept for the report; the count covers all of them.
const MAX_AMBIGUITIES: usize = 200;
/// The architecture key under which the old build's call sequences are recorded for propagation.
const GRAPH_ARCH: &str = "build";

/// How a pair of functions was matched, from the strongest evidence to the weakest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MatchMethod {
    ExactBytes,
    SymbolName,
    MaskedHash,
    UniqueString,
    CallGraph,
    CallPosition,
    Neighbourhood,
}

impl MatchMethod {
    pub const ALL: [MatchMethod; 7] = [
        MatchMethod::ExactBytes,
        MatchMethod::SymbolName,
        MatchMethod::MaskedHash,
        MatchMethod::UniqueString,
        MatchMethod::CallGraph,
        MatchMethod::CallPosition,
        MatchMethod::Neighbourhood,
    ];

    pub fn name(self) -> &'static str {
        match self {
            MatchMethod::ExactBytes => "exact_bytes",
            MatchMethod::SymbolName => "symbol_name",
            MatchMethod::MaskedHash => "masked_hash",
            MatchMethod::UniqueString => "unique_string",
            MatchMethod::CallGraph => "call_graph",
            MatchMethod::CallPosition => "call_position",
            MatchMethod::Neighbourhood => "neighbourhood",
        }
    }

    /// The confidence a match by this method carries, in [0, 1].
    pub fn confidence(self) -> f64 {
        match self {
            MatchMethod::ExactBytes => 1.0,
            MatchMethod::SymbolName => 0.95,
            MatchMethod::MaskedHash => 0.9,
            MatchMethod::UniqueString => 0.8,
            MatchMethod::CallGraph => 0.75,
            MatchMethod::CallPosition => 0.6,
            MatchMethod::Neighbourhood => 0.6,
        }
    }
}

/// One matched pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionMatch {
    pub old: u64,
    pub new: u64,
    pub method: MatchMethod,
    /// Neither the bytes nor the masked hash are the same.
    pub changed: bool,
    /// Same size and the same bytes or masked hash: an offset inside one is the same instruction in the other.
    pub same_layout: bool,
}

/// Functions left unmatched because the evidence pointed at more than one counterpart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ambiguity {
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub old: Vec<u64>,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub new: Vec<u64>,
    pub reason: &'static str,
}

/// One build's functions with what matching compares.
pub(crate) struct Side {
    pub(crate) functions: Vec<Function>,
    index: HashMap<u64, usize>,
    calls: BTreeMap<u64, Vec<u64>>,
    callers: HashMap<u64, BTreeSet<u64>>,
}

pub(crate) struct Function {
    pub(crate) address: u64,
    pub(crate) size: u64,
    /// The symbol, export or stub name, when the binary has one that is not a default name.
    pub(crate) symbol: Option<String>,
    exact: Option<u64>,
    masked: Option<FunctionHash>,
    strings: BTreeSet<String>,
    /// Data references made from inside the body: (offset of the referencing instruction, target).
    pub(crate) data_refs: Vec<(u64, u64)>,
}

impl Side {
    pub(crate) fn of(project: &Project) -> Result<Side, ApiError> {
        let analysis = project.analysis()?;
        let program = &analysis.program;
        let target = project.binary.target();
        let image = MaskContext::from_binary(&project.binary);
        let texts: HashMap<u64, &str> = project
            .scanned_strings()
            .iter()
            .filter(|found| found.text.chars().count() >= MIN_ANCHOR_STRING)
            .map(|found| (found.address, found.text.as_str()))
            .collect();
        let mut functions: Vec<Function> = program
            .functions
            .iter()
            .map(|function| {
                let size = function.end().saturating_sub(function.address);
                let body = function.body(&project.binary);
                let exact = body.filter(|bytes| bytes.len() as u64 >= MIN_EXACT_BYTES).map(|bytes| {
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    bytes.hash(&mut hasher);
                    hasher.finish()
                });
                let masked = body.and_then(|bytes| function_hash_in(&target, &image, bytes, function.address));
                let symbol = project
                    .symbol_name(function.address)
                    .filter(|name| !is_default_name(name, function.address))
                    .map(str::to_owned);
                Function {
                    address: function.address,
                    size,
                    symbol,
                    exact,
                    masked,
                    strings: BTreeSet::new(),
                    data_refs: Vec::new(),
                }
            })
            .collect();
        let index: HashMap<u64, usize> =
            functions.iter().enumerate().map(|(index, function)| (function.address, index)).collect();
        for xref in program.xrefs.iter().filter(|xref| xref.kind == XrefKind::Data) {
            let Some(owner) = analysis.function_containing(xref.from).and_then(|start| index.get(&start)) else {
                continue;
            };
            let function = &mut functions[*owner];
            function.data_refs.push((xref.from - function.address, xref.to));
            if let Some(text) = texts.get(&xref.to) {
                function.strings.insert((*text).to_owned());
            }
        }
        for function in &mut functions {
            function.data_refs.sort_unstable();
        }
        let calls = crate::signatures::call_sequences(&project.binary, program);
        let mut callers: HashMap<u64, BTreeSet<u64>> = HashMap::new();
        for (caller, targets) in &calls {
            for target in targets {
                callers.entry(*target).or_default().insert(*caller);
            }
        }
        Ok(Side { functions, index, calls, callers })
    }

    pub(crate) fn function_at(&self, address: u64) -> Option<&Function> {
        self.index.get(&address).map(|&index| &self.functions[index])
    }
}

/// The outcome of matching an old build with a new one.
pub struct BuildMatching {
    /// Sorted by old address.
    pub matches: Vec<FunctionMatch>,
    /// Old functions without a counterpart, sorted.
    pub removed: Vec<u64>,
    /// New functions without a counterpart, sorted.
    pub added: Vec<u64>,
    /// At most [`MAX_AMBIGUITIES`]; `ambiguity_count` counts them all.
    pub ambiguities: Vec<Ambiguity>,
    pub ambiguity_count: usize,
    /// Anchor-propagation rounds run.
    pub rounds: usize,
    /// Propagation stopped at [`MAX_ROUNDS`] while still matching.
    pub round_limited: bool,
}

struct State<'a> {
    old: &'a Side,
    new: &'a Side,
    old_to_new: HashMap<usize, (usize, MatchMethod)>,
    new_to_old: HashMap<usize, usize>,
    ambiguities: Vec<Ambiguity>,
    ambiguity_count: usize,
    ambiguous_keys: BTreeSet<(Vec<u64>, Vec<u64>)>,
}

impl State<'_> {
    fn pair(&mut self, old: usize, new: usize, method: MatchMethod) -> bool {
        if self.old_to_new.contains_key(&old) || self.new_to_old.contains_key(&new) {
            return false;
        }
        self.old_to_new.insert(old, (new, method));
        self.new_to_old.insert(new, old);
        true
    }

    /// Whether old function `old` is matched with at least `method`'s confidence: an anchor `method` may build on.
    fn anchors(&self, old: usize, method: MatchMethod) -> bool {
        self.old_to_new.get(&old).is_some_and(|&(_, by)| by.confidence() >= method.confidence())
    }

    fn ambiguous(&mut self, old: &[usize], new: &[usize], reason: &'static str) {
        let addresses = |side: &Side, indices: &[usize]| -> Vec<u64> {
            let mut addresses: Vec<u64> = indices.iter().map(|&index| side.functions[index].address).collect();
            addresses.sort_unstable();
            addresses
        };
        let key = (addresses(self.old, old), addresses(self.new, new));
        if !self.ambiguous_keys.insert(key.clone()) {
            return;
        }
        self.ambiguity_count += 1;
        if self.ambiguities.len() < MAX_AMBIGUITIES {
            self.ambiguities.push(Ambiguity { old: key.0, new: key.1, reason });
        }
    }

    /// Pairs the unmatched functions whose key occurs exactly once on each side; returns how many were paired.
    fn unique_keys<K: Hash + Eq + Clone>(
        &mut self,
        old_key: impl Fn(&Function) -> Option<K>,
        new_key: impl Fn(&Function) -> Option<K>,
        method: MatchMethod,
        reason: &'static str,
    ) -> usize {
        let mut groups: HashMap<K, (Vec<usize>, Vec<usize>)> = HashMap::new();
        for (index, function) in self.old.functions.iter().enumerate() {
            if !self.old_to_new.contains_key(&index)
                && let Some(key) = old_key(function)
            {
                groups.entry(key).or_default().0.push(index);
            }
        }
        for (index, function) in self.new.functions.iter().enumerate() {
            if !self.new_to_old.contains_key(&index)
                && let Some(key) = new_key(function)
            {
                groups.entry(key).or_default().1.push(index);
            }
        }
        let mut pairs = Vec::new();
        let mut ambiguous = Vec::new();
        for (old, new) in groups.into_values() {
            match (&old[..], &new[..]) {
                ([old], [new]) => pairs.push((*old, *new)),
                ([], _) | (_, []) => {}
                _ => ambiguous.push((old, new)),
            }
        }
        pairs.sort_unstable();
        ambiguous.sort();
        for (old, new) in ambiguous {
            self.ambiguous(&old, &new, reason);
        }
        pairs.into_iter().filter(|&(old, new)| self.pair(old, new, method)).count()
    }

    /// Strings referenced by exactly one function on each side, among those not matched at least as confidently,
    /// pair those functions when both are unmatched, unless another such string pairs either with a different one.
    fn unique_strings(&mut self) -> usize {
        fn referencing<'a>(side: &'a Side, matched: &dyn Fn(usize) -> bool) -> HashMap<&'a str, Vec<usize>> {
            let mut by_text: HashMap<&str, Vec<usize>> = HashMap::new();
            for (index, function) in side.functions.iter().enumerate().filter(|(index, _)| !matched(*index)) {
                for text in &function.strings {
                    by_text.entry(text.as_str()).or_default().push(index);
                }
            }
            by_text
        }
        let method = MatchMethod::UniqueString;
        let old = referencing(self.old, &|index| self.anchors(index, method));
        let new = referencing(self.new, &|index| self.new_to_old.get(&index).is_some_and(|&o| self.anchors(o, method)));
        let mut offered_old: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        let mut offered_new: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for (text, olds) in &old {
            if let ([o], Some([n])) = (&olds[..], new.get(text).map(Vec::as_slice)) {
                offered_old.entry(*o).or_default().insert(*n);
                offered_new.entry(*n).or_default().insert(*o);
            }
        }
        let mut paired = 0;
        let mut conflicts = Vec::new();
        for (o, candidates) in &offered_old {
            let [n] = candidates.iter().copied().collect::<Vec<_>>()[..] else {
                conflicts.push((vec![*o], candidates.iter().copied().collect::<Vec<_>>()));
                continue;
            };
            if offered_new[&n].len() != 1 {
                conflicts.push((offered_new[&n].iter().copied().collect(), vec![n]));
                continue;
            }
            if self.pair(*o, n, MatchMethod::UniqueString) {
                paired += 1;
            }
        }
        for (old, new) in conflicts {
            self.ambiguous(&old, &new, "unique strings point at different counterparts");
        }
        paired
    }

    /// Call-graph propagation through [`CallGraph::propagate`]: the old build's call sequences, with each function
    /// named by its address, are the training side; the new functions matched at least as confidently as a
    /// call-graph match carry their old counterpart's name. Bodies must be of comparable size; a callee that makes
    /// no calls and differs in masked hash is placed only by its call position, which scores lower.
    fn call_graph(&mut self, graph: &CallGraph) -> usize {
        let token = |address: u64| format!("{address:x}");
        let names: BTreeMap<u64, String> = self
            .old_to_new
            .iter()
            .filter(|(old, _)| self.anchors(**old, MatchMethod::CallGraph))
            .map(|(&old, &(new, _))| (self.new.functions[new].address, token(self.old.functions[old].address)))
            .collect();
        let added = graph.propagate(GRAPH_ARCH, &self.new.calls, &names, None);
        let mut paired = 0;
        for (new_address, name) in added {
            let Ok(old_address) = u64::from_str_radix(&name, 16) else { continue };
            let (Some(&old), Some(&new)) = (self.old.index.get(&old_address), self.new.index.get(&new_address)) else {
                continue;
            };
            let (a, b) = (&self.old.functions[old], &self.new.functions[new]);
            if !comparable(a.size, b.size) {
                continue;
            }
            let leaf = self.new.calls.get(&new_address).is_none_or(Vec::is_empty);
            let same_hash = a.masked.is_some() && a.masked == b.masked;
            let method = if leaf && !same_hash { MatchMethod::CallPosition } else { MatchMethod::CallGraph };
            if self.pair(old, new, method) {
                paired += 1;
            }
        }
        paired
    }

    /// Unmatched functions with the same matched callers and callees (in new-build addresses), found once on each
    /// side, and bodies within a factor of two in size.
    fn neighbourhood(&mut self) -> usize {
        let new_of = |old_address: u64| -> Option<u64> {
            let old = *self.old.index.get(&old_address)?;
            self.old_to_new.get(&old).map(|&(new, _)| self.new.functions[new].address)
        };
        let new_matched =
            |address: u64| self.new.index.get(&address).is_some_and(|index| self.new_to_old.contains_key(index));
        type Key = (Vec<u64>, Vec<u64>);
        let key_of = |side: &Side, address: u64, map: &dyn Fn(u64) -> Option<u64>| -> Option<Key> {
            let mut callers: Vec<u64> =
                side.callers.get(&address).into_iter().flatten().filter_map(|&caller| map(caller)).collect();
            let mut callees: Vec<u64> =
                side.calls.get(&address).into_iter().flatten().filter_map(|&callee| map(callee)).collect();
            callers.sort_unstable();
            callers.dedup();
            callees.sort_unstable();
            callees.dedup();
            (!callers.is_empty() || !callees.is_empty()).then_some((callers, callees))
        };
        let mut old_keys: HashMap<Key, Vec<usize>> = HashMap::new();
        for (index, function) in self.old.functions.iter().enumerate() {
            if !self.old_to_new.contains_key(&index)
                && let Some(key) = key_of(self.old, function.address, &new_of)
            {
                old_keys.entry(key).or_default().push(index);
            }
        }
        let mut new_keys: HashMap<Key, Vec<usize>> = HashMap::new();
        for (index, function) in self.new.functions.iter().enumerate() {
            if !self.new_to_old.contains_key(&index)
                && let Some(key) =
                    key_of(self.new, function.address, &|address| new_matched(address).then_some(address))
            {
                new_keys.entry(key).or_default().push(index);
            }
        }
        let mut pairs = Vec::new();
        let mut ambiguous = Vec::new();
        for (key, olds) in old_keys {
            let Some(news) = new_keys.get(&key) else { continue };
            match (&olds[..], &news[..]) {
                ([o], [n]) => pairs.push((*o, *n)),
                _ => ambiguous.push((olds.clone(), news.clone())),
            }
        }
        pairs.sort_unstable();
        ambiguous.sort();
        for (old, new) in ambiguous {
            self.ambiguous(&old, &new, "the same matched callers and callees fit more than one function");
        }
        let mut paired = 0;
        for (o, n) in pairs {
            if !comparable(self.old.functions[o].size, self.new.functions[n].size) {
                continue;
            }
            if self.pair(o, n, MatchMethod::Neighbourhood) {
                paired += 1;
            }
        }
        paired
    }
}

/// Body sizes within a factor of two of each other.
fn comparable(a: u64, b: u64) -> bool {
    let (a, b) = (a.max(1), b.max(1));
    a.max(b) <= 2 * a.min(b)
}

/// Matches the functions of `old` with those of `new`. See the module documentation.
pub fn match_builds(old: &Project, new: &Project) -> Result<BuildMatching, ApiError> {
    let (old, new) = (Side::of(old)?, Side::of(new)?);
    Ok(match_sides(&old, &new))
}

pub(crate) fn match_sides(old: &Side, new: &Side) -> BuildMatching {
    let mut state = State {
        old,
        new,
        old_to_new: HashMap::new(),
        new_to_old: HashMap::new(),
        ambiguities: Vec::new(),
        ambiguity_count: 0,
        ambiguous_keys: BTreeSet::new(),
    };
    let symbol = |function: &Function| function.symbol.clone();
    state.unique_keys(symbol, symbol, MatchMethod::SymbolName, "a symbol name occurs more than once");
    let exact = |function: &Function| function.exact.map(|hash| (hash, function.size));
    state.unique_keys(exact, exact, MatchMethod::ExactBytes, "identical bytes occur more than once");
    let masked = |function: &Function| function.masked;
    state.unique_keys(masked, masked, MatchMethod::MaskedHash, "a masked hash occurs more than once");

    let mut graph = CallGraph::new("old build", "");
    for (caller, targets) in &old.calls {
        let callees = targets.iter().map(|target| Some(format!("{target:x}"))).collect();
        graph.insert(GRAPH_ARCH, &format!("{caller:x}"), callees, None);
    }
    let mut rounds = 0;
    let mut round_limited = false;
    loop {
        if rounds == MAX_ROUNDS {
            round_limited = true;
            break;
        }
        rounds += 1;
        let mut paired = state.unique_strings();
        paired += state.call_graph(&graph);
        if paired == 0 {
            paired += state.neighbourhood();
        }
        if paired == 0 {
            break;
        }
    }

    let mut matches: Vec<FunctionMatch> = state
        .old_to_new
        .iter()
        .map(|(&o, &(n, method))| {
            let (a, b) = (&old.functions[o], &new.functions[n]);
            let same_bytes = a.exact.is_some() && a.exact == b.exact && a.size == b.size;
            let same_hash = a.masked.is_some() && a.masked == b.masked;
            FunctionMatch {
                old: a.address,
                new: b.address,
                method,
                changed: !same_bytes && !same_hash,
                same_layout: a.size == b.size && (same_bytes || same_hash),
            }
        })
        .collect();
    matches.sort_unstable_by_key(|matched| matched.old);
    let removed = (0..old.functions.len())
        .filter(|index| !state.old_to_new.contains_key(index))
        .map(|index| old.functions[index].address)
        .collect();
    let added = (0..new.functions.len())
        .filter(|index| !state.new_to_old.contains_key(index))
        .map(|index| new.functions[index].address)
        .collect();
    BuildMatching {
        matches,
        removed,
        added,
        ambiguities: state.ambiguities,
        ambiguity_count: state.ambiguity_count,
        rounds,
        round_limited,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(address: u64, size: u64, exact: Option<u64>, symbol: Option<&str>) -> Function {
        Function {
            address,
            size,
            symbol: symbol.map(str::to_owned),
            exact,
            masked: exact.map(|hash| [hash as u8; 32]),
            strings: BTreeSet::new(),
            data_refs: Vec::new(),
        }
    }

    fn side(functions: Vec<Function>, calls: &[(u64, &[u64])]) -> Side {
        let index = functions.iter().enumerate().map(|(index, function)| (function.address, index)).collect();
        let calls: BTreeMap<u64, Vec<u64>> = functions
            .iter()
            .map(|function| {
                let targets = calls.iter().find(|(caller, _)| *caller == function.address).map(|(_, t)| t.to_vec());
                (function.address, targets.unwrap_or_default())
            })
            .collect();
        let mut callers: HashMap<u64, BTreeSet<u64>> = HashMap::new();
        for (caller, targets) in &calls {
            for target in targets {
                callers.entry(*target).or_default().insert(*caller);
            }
        }
        Side { functions, index, calls, callers }
    }

    fn methods(matching: &BuildMatching) -> Vec<(u64, u64, MatchMethod)> {
        matching.matches.iter().map(|matched| (matched.old, matched.new, matched.method)).collect()
    }

    #[test]
    fn stages_pair_uniquely_and_report_ambiguity() {
        // 0x10 exported, 0x20 unique bytes, 0x30/0x40 identical stubs (ambiguous), 0x50 changed and only reachable
        // from 0x10's call sequence.
        let old = side(
            vec![
                function(0x10, 32, Some(1), Some("api")),
                function(0x20, 32, Some(2), None),
                function(0x30, 16, Some(3), None),
                function(0x40, 16, Some(3), None),
                function(0x50, 40, Some(5), None),
            ],
            &[(0x10, &[0x20, 0x50]), (0x50, &[0x20])],
        );
        let new = side(
            vec![
                function(0x110, 36, Some(9), Some("api")),
                function(0x120, 32, Some(2), None),
                function(0x130, 16, Some(3), None),
                function(0x140, 16, Some(3), None),
                function(0x150, 48, Some(6), None),
            ],
            &[(0x110, &[0x120, 0x150]), (0x150, &[0x120])],
        );
        let matching = match_sides(&old, &new);
        assert_eq!(
            methods(&matching),
            vec![
                (0x10, 0x110, MatchMethod::SymbolName),
                (0x20, 0x120, MatchMethod::ExactBytes),
                (0x50, 0x150, MatchMethod::CallGraph),
            ]
        );
        assert!(matching.matches[0].changed && !matching.matches[1].changed && matching.matches[2].changed);
        assert_eq!(matching.removed, vec![0x30, 0x40]);
        assert_eq!(matching.added, vec![0x130, 0x140]);
        assert!(matching.ambiguities.iter().any(|ambiguity| ambiguity.old == vec![0x30, 0x40]));
    }

    #[test]
    fn neighbourhood_pairs_a_changed_callee_whose_caller_changed_shape() {
        // The caller gained a call, so its sequence no longer fits; the callee keeps the same matched neighbours.
        let old = side(
            vec![
                function(0x10, 32, Some(1), Some("api")),
                function(0x20, 32, Some(2), None),
                function(0x60, 32, Some(6), None),
            ],
            &[(0x10, &[0x20])],
        );
        let new = side(
            vec![
                function(0x110, 32, Some(9), Some("api")),
                function(0x120, 40, Some(7), None),
                function(0x160, 32, Some(6), None),
                function(0x170, 400, Some(8), None),
            ],
            &[(0x110, &[0x160, 0x120])],
        );
        let matching = match_sides(&old, &new);
        assert_eq!(methods(&matching)[1], (0x20, 0x120, MatchMethod::Neighbourhood));
        assert_eq!(matching.added, vec![0x170]);
    }

    #[test]
    fn a_neighbourhood_match_never_seeds_a_call_graph_match() {
        // api's call sequence changed shape, so 0x20 pairs only by neighbourhood; its callee 0x30 (which calls the
        // exactly matched 0x40) must not then be scored as a call-graph match derived from it.
        let old = side(
            vec![
                function(0x10, 32, Some(1), Some("api")),
                function(0x20, 32, Some(2), None),
                function(0x30, 32, Some(3), None),
                function(0x40, 32, Some(4), None),
                function(0x60, 32, Some(6), None),
            ],
            &[(0x10, &[0x20]), (0x20, &[0x30]), (0x30, &[0x40])],
        );
        let new = side(
            vec![
                function(0x110, 32, Some(9), Some("api")),
                function(0x120, 36, Some(7), None),
                function(0x130, 36, Some(8), None),
                function(0x140, 32, Some(4), None),
                function(0x160, 32, Some(6), None),
            ],
            &[(0x110, &[0x160, 0x120]), (0x120, &[0x130]), (0x130, &[0x140])],
        );
        let matching = match_sides(&old, &new);
        for matched in &matching.matches {
            if matched.method.confidence() < MatchMethod::CallGraph.confidence() {
                continue;
            }
            assert!(![0x20, 0x30].contains(&matched.old), "{:?}", methods(&matching));
        }
        assert!(methods(&matching).contains(&(0x20, 0x120, MatchMethod::Neighbourhood)));
    }

    #[test]
    fn a_leaf_placed_by_call_position_alone_scores_below_call_graph() {
        let leaf = |size| {
            let old = side(
                vec![function(0x10, 32, Some(1), Some("api")), function(0x20, 32, Some(2), None)],
                &[(0x10, &[0x20])],
            );
            let new = side(
                vec![function(0x110, 32, Some(9), Some("api")), function(0x120, size, Some(7), None)],
                &[(0x110, &[0x120])],
            );
            methods(&match_sides(&old, &new))
        };
        // A replaced helper of similar size: matched, but only as a call position (below the 0.7 default).
        assert_eq!(leaf(40)[1], (0x20, 0x120, MatchMethod::CallPosition));
        assert!(MatchMethod::CallPosition.confidence() < 0.7);
        // Of very different size: not matched at all.
        assert_eq!(leaf(400).len(), 1);
    }
}
