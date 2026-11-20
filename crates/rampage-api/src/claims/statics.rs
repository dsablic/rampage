//! Claims checked on the decoded code: `calls` (a call, through stubs or callees, and the order of two calls),
//! `references` (who references an address or string) and `constant` (an immediate in a function's code).

use std::collections::{BTreeSet, HashMap, VecDeque};

use rampage_analysis::discover::XrefKind;
use rampage_arch::Flow;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Address, Budget, Confidence, Outcome, address, function_start};
use crate::search_code::{CodeImmediate, CodeSearchKind, CodeSearchQuery, CodeValue};
use crate::{FunctionGraph, Project};

pub const DEFAULT_DEPTH: u32 = 1;
pub const MAX_DEPTH: u32 = 8;
/// Functions a transitive search visits.
const MAX_VISITED: usize = 4096;
/// Stub hops followed from a call target to what it forwards to.
const MAX_STUB_HOPS: usize = 4;
/// Instructions of a function that forwards: a PLT entry, an import thunk, a veneer.
const MAX_STUB_INSTRUCTIONS: usize = 8;
/// Rows a list in the evidence shows.
const SHOWN: usize = 8;
/// Occurrences of a claimed string whose references are checked.
const MAX_STRING_TARGETS: usize = 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CallsClaim {
    function: Address,
    callee: String,
    /// Levels of calls searched: 1 (default) is a direct call, through stubs; at most 8.
    depth: Option<u32>,
    /// The claim is that every path through `function` calls `callee` before it calls this.
    before: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReferencesClaim {
    target: Option<Address>,
    string: Option<String>,
    by: Option<Address>,
    only_by: Option<Vec<Address>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConstantClaim {
    function: Address,
    value: crate::evaluate::IntegerText,
    bits: Option<u16>,
}

/// Imports that call back through a function pointer they are given (sorting, threads, timers, exit handlers,
/// enumerations, dispatch): a call into one may reach any function whose address was passed, so it counts as an
/// unresolved transfer when a claim rests on a call's absence.
const CALLBACK_IMPORTS: [&str; 40] = [
    "qsort",
    "qsort_r",
    "bsearch",
    "lfind",
    "lsearch",
    "tsearch",
    "twalk",
    "tfind",
    "tdelete",
    "ftw",
    "nftw",
    "scandir",
    "pthread_create",
    "pthread_once",
    "atexit",
    "at_quick_exit",
    "on_exit",
    "__cxa_atexit",
    "__libc_start_main",
    "signal",
    "sigaction",
    "thrd_create",
    "call_once",
    "dl_iterate_phdr",
    "CreateThread",
    "_beginthread",
    "_beginthreadex",
    "CreateRemoteThread",
    "QueueUserWorkItem",
    "CreateTimerQueueTimer",
    "SetTimer",
    "EnumWindows",
    "EnumChildWindows",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "RegisterWaitForSingleObject",
    "dispatch_async",
    "dispatch_sync",
    "dispatch_once",
    "xTaskCreate",
];

/// A name as the binary may spell it: without an `@plt` or symbol-version suffix or an `__imp_` import-thunk prefix,
/// and on Mach-O without the one leading underscore its C symbols carry.
fn normalize(name: &str, macho: bool) -> String {
    let name = name.split('@').next().unwrap_or(name);
    let name = name.strip_prefix("__imp_").unwrap_or(name);
    let name = if macho { name.strip_prefix('_').unwrap_or(name) } else { name };
    name.to_owned()
}

fn is_macho(project: &Project) -> bool {
    project.binary.format == rampage_loaders::Format::MachO
}

/// What a callee claim names: an address when it resolves, and its names.
struct Callee {
    text: String,
    address: Option<u64>,
    names: BTreeSet<String>,
}

impl Callee {
    /// The callee `text` names: an address or symbol the project resolves, or an import. Anything else is invalid,
    /// never "not called".
    fn new(project: &Project, text: &str) -> Result<Self, Outcome> {
        let macho = is_macho(project);
        let address = project.resolve(text).ok().map(|address| project.thumb_code_address(address).0);
        let wanted = normalize(text, macho);
        let import = project.binary.import_slots.iter().any(|import| normalize(&import.name, macho) == wanted);
        if address.is_none() && !import {
            return Err(Outcome::invalid(format!("{text:?} names no function, symbol or import in the binary")));
        }
        let mut names = BTreeSet::new();
        if !text.trim_start().starts_with("0x") && text.parse::<u64>().is_err() {
            names.insert(wanted);
        }
        if let Some(name) = address.and_then(|address| project.name_at(address)) {
            names.insert(normalize(&name, macho));
        }
        names.retain(|name| !name.is_empty() && !name.starts_with("sub_"));
        Ok(Self { text: text.to_owned(), address, names })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SiteKind {
    Call,
    /// A jump out of the function: a tail call.
    Tail,
    /// An indirect call or jump whose targets the analysis resolved.
    Resolved,
    /// An indirect call or jump with no known target, or an instruction with unknown successors.
    Unresolved,
}

#[derive(Debug, Clone)]
struct Site {
    at: u64,
    kind: SiteKind,
    targets: Vec<u64>,
    /// Imports reached through a slot the instruction reads.
    imports: Vec<String>,
}

/// The import name of an import slot.
fn import_at(project: &Project, slot: u64) -> Option<String> {
    project.binary.import_slots.iter().find(|import| import.address == slot).map(|import| import.name.clone())
}

/// Call and reference targets of the one instruction at `at`.
fn instruction_targets(project: &Project, at: u64) -> (Vec<u64>, Vec<u64>) {
    let Ok(analysis) = project.analysis() else { return (Vec::new(), Vec::new()) };
    let xrefs = &analysis.program.xrefs;
    let by_source = &analysis.xrefs_by_source;
    let first = by_source.partition_point(|&index| xrefs[index].from < at);
    let (mut code, mut data) = (Vec::new(), Vec::new());
    for &index in &by_source[first..] {
        let xref = xrefs[index];
        if xref.from != at {
            break;
        }
        match xref.kind {
            XrefKind::Call | XrefKind::Jump => code.push(xref.to),
            XrefKind::Data => data.push(xref.to),
        }
    }
    (code, data)
}

/// The call sites of a function: calls, tail jumps, and indirect transfers, resolved or not.
fn sites(project: &Project, graph: &FunctionGraph) -> Vec<Site> {
    let inside = |target: u64| {
        graph.blocks.iter().any(|block| block.start == target)
            || project.analysis().is_ok_and(|analysis| analysis.function_containing(target) == Some(graph.address))
    };
    let function = project.analysis().ok().and_then(|analysis| analysis.program.function_at(graph.address).cloned());
    let mut sites = Vec::new();
    for line in graph.blocks.iter().flat_map(|block| &block.lines) {
        let at = line.address;
        if line.decode_gate.is_some() {
            sites.push(Site { at, kind: SiteKind::Unresolved, targets: Vec::new(), imports: Vec::new() });
            continue;
        }
        let site = match line.flow {
            Flow::Call(target) => Site { at, kind: SiteKind::Call, targets: vec![target], imports: Vec::new() },
            Flow::Jump(target) if !inside(target) => {
                Site { at, kind: SiteKind::Tail, targets: vec![target], imports: Vec::new() }
            }
            Flow::IndirectJump if function.as_ref().and_then(|function| function.switch_cases(at)).is_some() => {
                continue;
            }
            Flow::IndirectCall | Flow::IndirectJump => {
                let (code, data) = instruction_targets(project, at);
                let code: Vec<u64> = code.into_iter().filter(|&target| !inside(target)).collect();
                let imports: Vec<String> = data
                    .iter()
                    .chain(line.data_ref.iter())
                    .filter_map(|&slot| import_at(project, slot))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                if code.is_empty() && imports.is_empty() {
                    Site { at, kind: SiteKind::Unresolved, targets: Vec::new(), imports }
                } else {
                    Site { at, kind: SiteKind::Resolved, targets: code, imports }
                }
            }
            _ => continue,
        };
        sites.push(site);
    }
    sites
}

/// The addresses and names a call to `target` reaches through forwarding stubs (PLT entries, import thunks,
/// veneers): `target` itself first.
fn forwards(project: &Project, target: u64) -> (Vec<u64>, BTreeSet<String>) {
    let macho = is_macho(project);
    let mut addresses = vec![target];
    let mut names = BTreeSet::new();
    let mut current = target;
    for _ in 0..MAX_STUB_HOPS {
        if let Some(name) = project.name_at(current).or_else(|| import_at(project, current)) {
            names.insert(normalize(&name, macho));
        }
        let Ok(analysis) = project.analysis() else { break };
        let Some(function) = analysis.program.function_at(current) else { break };
        if function.instruction_count > MAX_STUB_INSTRUCTIONS || function.blocks.len() > 1 {
            break;
        }
        let Ok(graph) = project.function_graph(current) else { break };
        let stub_sites = sites(project, &graph);
        let has_return = graph.blocks.iter().flat_map(|block| &block.lines).any(|line| line.flow == Flow::Return);
        if has_return || stub_sites.len() != 1 || stub_sites[0].kind == SiteKind::Call {
            break;
        }
        names.extend(stub_sites[0].imports.iter().map(|name| normalize(name, macho)));
        match stub_sites[0].targets.as_slice() {
            [next] if !addresses.contains(next) => {
                addresses.push(*next);
                current = *next;
            }
            _ => break,
        }
    }
    names.retain(|name| !name.is_empty() && !name.starts_with("sub_"));
    (addresses, names)
}

fn reaches(project: &Project, site: &Site, callee: &Callee) -> bool {
    let macho = is_macho(project);
    if site.imports.iter().any(|name| callee.names.contains(&normalize(name, macho))) {
        return true;
    }
    site.targets.iter().any(|&target| {
        let (addresses, names) = forwards(project, target);
        callee.address.is_some_and(|wanted| addresses.contains(&wanted))
            || names.iter().any(|name| callee.names.contains(name))
    })
}

/// Whether the site calls an import that calls back through a pointer it is given.
fn calls_back(project: &Project, site: &Site) -> bool {
    let macho = is_macho(project);
    let listed = |name: &str| CALLBACK_IMPORTS.contains(&name);
    site.imports.iter().any(|name| listed(&normalize(name, macho)))
        || site.targets.iter().any(|&target| forwards(project, target).1.iter().any(|name| listed(name)))
}

fn site_row(project: &Project, site: &Site) -> Value {
    let mut row = json!({"at": address(site.at)});
    let targets: Vec<String> = site
        .targets
        .iter()
        .map(|&target| project.name_at(target).unwrap_or_else(|| format!("{target:#x}")))
        .chain(site.imports.iter().cloned())
        .collect();
    if !targets.is_empty() {
        row["to"] = json!(targets);
    }
    let kind = match site.kind {
        SiteKind::Call => "call",
        SiteKind::Tail => "tail_jump",
        SiteKind::Resolved => "indirect_resolved",
        SiteKind::Unresolved => "unresolved",
    };
    row["kind"] = json!(kind);
    row
}

/// A breadth-first search for a call chain from `start` to `callee` of at most `depth` calls.
#[derive(Debug, Clone, Default)]
struct Search {
    /// The chain found: (function, call site) pairs, the last site reaching the callee.
    path: Option<Vec<(u64, u64)>>,
    visited: usize,
    /// Unresolved sites, and calls into imports that call back, in the functions searched, with their function.
    unresolved: Vec<(u64, u64)>,
    /// The function budget or the deadline stopped the search.
    truncated: bool,
}

impl Search {
    /// Whether the callee may be reached although no chain was found.
    fn uncertain(&self) -> bool {
        self.path.is_none() && (self.truncated || !self.unresolved.is_empty())
    }
}

fn search(project: &Project, start: u64, callee: &Callee, depth: u32, budget: Budget) -> Search {
    let mut queue = VecDeque::from([(start, 1u32)]);
    let mut parent: HashMap<u64, (u64, u64)> = HashMap::new();
    let mut seen = BTreeSet::from([start]);
    let mut result = Search::default();
    while let Some((function, level)) = queue.pop_front() {
        if result.visited >= MAX_VISITED || budget.expired() {
            result.truncated = true;
            break;
        }
        result.visited += 1;
        let Ok(graph) = project.function_graph(function) else { continue };
        for site in sites(project, &graph) {
            if site.kind == SiteKind::Unresolved {
                result.unresolved.push((function, site.at));
                continue;
            }
            if reaches(project, &site, callee) {
                let mut path = vec![(function, site.at)];
                let mut current = function;
                while let Some(&(caller, at)) = parent.get(&current) {
                    path.push((caller, at));
                    current = caller;
                }
                path.reverse();
                result.path = Some(path);
                return result;
            }
            if calls_back(project, &site) {
                result.unresolved.push((function, site.at));
            }
            if level < depth {
                for &target in &site.targets {
                    let Some(next) = forwards(project, target).0.last().copied() else { continue };
                    let discovered =
                        project.analysis().is_ok_and(|analysis| analysis.program.function_at(next).is_some());
                    if discovered && seen.insert(next) {
                        parent.insert(next, (function, site.at));
                        queue.push_back((next, level + 1));
                    }
                }
            }
        }
    }
    result
}

pub(crate) fn calls(project: &Project, claim: &CallsClaim, budget: Budget) -> Outcome {
    let start = match function_start(project, &claim.function) {
        Ok(start) => start,
        Err(outcome) => return outcome,
    };
    let depth = claim.depth.unwrap_or(DEFAULT_DEPTH);
    if !(1..=MAX_DEPTH).contains(&depth) {
        return Outcome::invalid(format!("depth must be 1..={MAX_DEPTH}"));
    }
    let callee = match Callee::new(project, &claim.callee) {
        Ok(callee) => callee,
        Err(outcome) => return outcome,
    };
    match &claim.before {
        Some(later) => match Callee::new(project, later) {
            Ok(later) => before(project, start, &callee, &later, depth, budget),
            Err(outcome) => outcome,
        },
        None => calls_within(project, start, &callee, depth, budget),
    }
}

fn calls_within(project: &Project, start: u64, callee: &Callee, depth: u32, budget: Budget) -> Outcome {
    let found = search(project, start, callee, depth, budget);
    let method = format!(
        "call sites in the decoded code{} of {}, following stubs (PLT entries, import thunks, veneers) and resolved \
         indirect calls",
        if depth > 1 { format!(" and callees to depth {depth}") } else { String::new() },
        project.function_name(start)
    );
    if let Some(path) = found.path {
        let chain: Vec<Value> = path
            .iter()
            .map(|&(function, at)| json!({"function": project.function_name(function), "site": address(at)}))
            .collect();
        return Outcome::verified(
            Confidence::Static,
            method,
            json!({"callee": callee.text, "chain": chain, "functions_searched": found.visited}),
        );
    }
    let mut evidence = json!({"callee": callee.text, "functions_searched": found.visited, "depth": depth});
    if depth == 1
        && let Ok(graph) = project.function_graph(start)
    {
        let rows: Vec<Value> = sites(project, &graph).iter().take(16).map(|site| site_row(project, site)).collect();
        evidence["call_sites"] = json!(rows);
    }
    if found.uncertain() {
        let rows: Vec<Value> = found
            .unresolved
            .iter()
            .take(SHOWN)
            .map(|&(function, at)| json!({"function": project.function_name(function), "site": address(at)}))
            .collect();
        evidence["unresolved"] = json!(rows);
        evidence["unresolved_total"] = json!(found.unresolved.len());
        let reason = if found.truncated {
            format!("the search stopped (at {MAX_VISITED} functions, or the time budget) before it was complete")
        } else {
            "no direct call was found, but indirect calls, jumps with unknown targets, or imports that call back \
             through a pointer remain"
                .to_owned()
        };
        return Outcome::unknown(method, evidence, reason).needs(
            "the unresolved sites' targets: run the function with evaluate_function (its calls list) or trace it in \
             the debugger, or claim about a narrower function",
        );
    }
    Outcome::refuted(Confidence::Static, method, evidence)
}

/// One instruction position: block index and line index.
type Position = (usize, usize);

/// What a call site is to a `before` claim.
#[derive(Clone, Copy, PartialEq)]
enum Mark {
    /// It calls the first callee (directly, or through callees within the depth), and not the later one.
    First,
    /// It calls the later callee, and not the first.
    Later,
    /// It may call either, or both in an order not known: an unresolved transfer, a call back, an incomplete search.
    Unresolved,
}

fn before(project: &Project, start: u64, first: &Callee, later: &Callee, depth: u32, budget: Budget) -> Outcome {
    let graph = match project.function_graph(start) {
        Ok(graph) => graph,
        Err(error) => return error.into(),
    };
    let Some(entry) = graph.entry() else { return Outcome::invalid("the function has no entry block") };
    let all = sites(project, &graph);
    // Transitive searches from each callee, done once per callee and side.
    let mut cache: HashMap<(u64, bool), Search> = HashMap::new();
    let mut transitive = |next: u64, of_first: bool| -> Search {
        cache
            .entry((next, of_first))
            .or_insert_with(|| search(project, next, if of_first { first } else { later }, depth - 1, budget))
            .clone()
    };
    let mut marks: HashMap<u64, Mark> = HashMap::new();
    for site in &all {
        let mark = if site.kind == SiteKind::Unresolved {
            Some(Mark::Unresolved)
        } else {
            let mut to_first = reaches(project, site, first);
            let mut to_later = reaches(project, site, later);
            let mut uncertain_first = false;
            let mut uncertain_later = false;
            if depth > 1 {
                for &target in &site.targets {
                    let Some(&next) = forwards(project, target).0.last() else { continue };
                    let discovered =
                        project.analysis().is_ok_and(|analysis| analysis.program.function_at(next).is_some());
                    if !discovered {
                        continue;
                    }
                    let found = transitive(next, true);
                    to_first |= found.path.is_some();
                    uncertain_first |= found.uncertain();
                    let found = transitive(next, false);
                    to_later |= found.path.is_some();
                    uncertain_later |= found.uncertain();
                }
            }
            if calls_back(project, site) {
                uncertain_first = true;
                uncertain_later = true;
            }
            match (to_first, to_later) {
                (true, false) if !uncertain_later => Some(Mark::First),
                (false, true) if !uncertain_first => Some(Mark::Later),
                (false, false) if !uncertain_first && !uncertain_later => None,
                _ => Some(Mark::Unresolved),
            }
        };
        if let Some(mark) = mark {
            marks.insert(site.at, mark);
        }
    }
    if budget.expired() {
        return Outcome::unknown("", Value::Null, "the call's time budget ran out during the search")
            .needs("a larger timeout_ms, or a smaller depth");
    }
    let successors = |block: usize| graph.edges.iter().filter(move |edge| edge.from == block).map(|edge| edge.to);
    let method = format!(
        "paths through the control-flow graph of {} from its entry to each call of {}{}",
        project.function_name(start),
        later.text,
        if depth > 1 { format!(", either callee counted through callees to depth {depth}") } else { String::new() }
    );
    // From the entry, before any call of the first callee: the later calls reached and the unresolved transfers met.
    let mut parent: HashMap<usize, usize> = HashMap::new();
    let mut queue = VecDeque::from([entry]);
    let mut seen = BTreeSet::from([entry]);
    let mut violation: Option<(usize, u64)> = None;
    let mut unresolved_before = Vec::new();
    'blocks: while let Some(block) = queue.pop_front() {
        for line in &graph.blocks[block].lines {
            match marks.get(&line.address) {
                Some(Mark::First) => continue 'blocks,
                Some(Mark::Later) => {
                    violation.get_or_insert((block, line.address));
                    continue 'blocks;
                }
                Some(Mark::Unresolved) => unresolved_before.push(line.address),
                None => {}
            }
        }
        for next in successors(block) {
            if seen.insert(next) {
                parent.insert(next, block);
                queue.push_back(next);
            }
        }
    }
    let sites_of = |wanted: Mark| -> Vec<u64> {
        marks
            .iter()
            .filter(|(_, mark)| **mark == wanted)
            .map(|(&at, _)| at)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    let later_sites = sites_of(Mark::Later);
    let first_sites = sites_of(Mark::First);
    let any_unresolved = marks.values().any(|mark| *mark == Mark::Unresolved);
    let list = |sites: &[u64]| sites.iter().take(SHOWN).map(|&at| address(at)).collect::<Vec<_>>();
    let mut evidence = json!({
        "first": first.text,
        "later": later.text,
        "first_sites": list(&first_sites),
        "later_sites": list(&later_sites),
    });
    let unresolved_needs = "the targets of the unresolved calls or jumps: run the paths with evaluate_function or the \
                            debugger";
    let Some((block, site)) = violation else {
        if !unresolved_before.is_empty() {
            evidence["unresolved_before_first"] = json!(list(&unresolved_before));
            return Outcome::unknown(
                method,
                evidence,
                "every known call of the later callee comes after the first, but calls whose targets or order are not \
                 known run before it on some path, and one may call the later callee",
            )
            .needs(unresolved_needs);
        }
        if later_sites.is_empty() {
            if any_unresolved {
                return Outcome::unknown(
                    method,
                    evidence,
                    format!("no call of {} was found; unresolved calls remain", later.text),
                )
                .needs(unresolved_needs);
            }
            evidence["reason"] = json!(format!("{} never calls {}", project.function_name(start), later.text));
            return Outcome::refuted(Confidence::Static, method, evidence);
        }
        return Outcome::verified(Confidence::Static, method, evidence);
    };
    let mut path = vec![block];
    let mut current = block;
    while let Some(&previous) = parent.get(&current) {
        path.push(previous);
        current = previous;
    }
    path.reverse();
    let blocks: Vec<Value> = path.iter().take(32).map(|&index| address(graph.blocks[index].start)).collect();
    evidence["path_without_first"] = json!({"blocks": blocks, "reaches": address(site)});
    // Whether any call of the first callee can come before a call of the later one on some path.
    let mut later_after_first = false;
    let position: HashMap<u64, Position> = graph
        .blocks
        .iter()
        .enumerate()
        .flat_map(|(block, lines)| lines.lines.iter().enumerate().map(move |(line, row)| (row.address, (block, line))))
        .collect();
    for &first_site in &first_sites {
        let Some(&(block, line)) = position.get(&first_site) else { continue };
        if graph.blocks[block].lines[line + 1..].iter().any(|row| marks.get(&row.address) == Some(&Mark::Later)) {
            later_after_first = true;
            break;
        }
        let mut queue: VecDeque<usize> = successors(block).collect();
        let mut seen: BTreeSet<usize> = queue.iter().copied().collect();
        while let Some(next) = queue.pop_front() {
            if graph.blocks[next].lines.iter().any(|row| marks.get(&row.address) == Some(&Mark::Later)) {
                later_after_first = true;
                break;
            }
            for after in successors(next) {
                if seen.insert(after) {
                    queue.push_back(after);
                }
            }
        }
        if later_after_first {
            break;
        }
    }
    if !later_after_first && !any_unresolved {
        return Outcome::refuted(
            Confidence::Static,
            format!("{method}: no path calls {} before a call of {}", first.text, later.text),
            evidence,
        );
    }
    let reason = if later_after_first {
        format!(
            "some paths call {} first, but a path reaches the call of {} at {site:#x} without it; whether that path \
             can run is not checked",
            first.text, later.text
        )
    } else {
        format!(
            "a path reaches the call of {} at {site:#x} without a call of {}, and calls whose targets or order are \
             not known remain",
            later.text, first.text
        )
    };
    Outcome::unknown(method, evidence, reason)
        .needs("inputs that take that path, run with evaluate_function or the debugger, to see whether it can happen")
}

/// One reference to a claimed target, attributed to the function it comes from when it can be.
struct Reference {
    target: u64,
    from: u64,
    function: Option<u64>,
    /// A pointer in data at this address holds the target, and `function` references that pointer.
    via: Option<u64>,
}

pub(crate) fn references(project: &Project, claim: &ReferencesClaim) -> Outcome {
    let analysis = match project.analysis() {
        Ok(analysis) => analysis,
        Err(error) => return error.into(),
    };
    let mut truncated = false;
    let (targets, described) = match (&claim.target, &claim.string) {
        (Some(target), None) => match target.resolve(project) {
            Ok(address) => (vec![address], format!("{address:#x}")),
            Err(error) => return error.into(),
        },
        (None, Some(text)) => {
            if text.is_empty() || text.len() > 4096 {
                return Outcome::invalid("string is 1..=4096 bytes");
            }
            let query = crate::StringsQuery {
                min_len: Some(text.chars().count().clamp(1, 4)),
                contains: Some(text.clone()),
                offset: None,
                limit: None,
            };
            let mut found: Vec<u64> = project
                .strings(&query)
                .items
                .iter()
                .filter(|string| string.text == *text)
                .map(|string| string.address)
                .collect();
            if found.len() > MAX_STRING_TARGETS {
                found.truncate(MAX_STRING_TARGETS);
                truncated = true;
            }
            if found.is_empty() {
                return Outcome::invalid(format!(
                    "no string equal to {text:?} in the image: list_strings with contains finds the exact text"
                ));
            }
            (found, format!("{text:?}"))
        }
        _ => return Outcome::invalid("a references claim names a target (address or name) or a string"),
    };
    let mut found: Vec<Reference> = Vec::new();
    for &target in &targets {
        for xref in analysis.program.xrefs_to(target) {
            let function = analysis.function_containing(xref.from);
            if function.is_some() || project.binary.is_code(xref.from) {
                found.push(Reference { target, from: xref.from, function, via: None });
                continue;
            }
            // A pointer in data: who references the pointer.
            let users: Vec<_> = analysis.program.xrefs_to(xref.from).to_vec();
            if users.is_empty() {
                found.push(Reference { target, from: xref.from, function: None, via: Some(xref.from) });
            }
            for user in users {
                found.push(Reference {
                    target,
                    from: user.from,
                    function: analysis.function_containing(user.from),
                    via: Some(xref.from),
                });
            }
        }
    }
    let row = |reference: &Reference| {
        let mut row = json!({"site": address(reference.from)});
        if let Some(function) = reference.function {
            row["function"] = json!(project.function_name(function));
        }
        if let Some(via) = reference.via {
            row["via_pointer"] = address(via);
        }
        if targets.len() > 1 {
            row["target"] = address(reference.target);
        }
        row
    };
    let unattributed: Vec<&Reference> = found.iter().filter(|reference| reference.function.is_none()).collect();
    let method = format!(
        "references to {described} recorded by analysis (code, and pointers in data with the code that references \
         them); an address computed at run time is not seen"
    );
    let mut evidence = json!({
        "targets": targets.iter().take(SHOWN).map(|&target| address(target)).collect::<Vec<_>>(),
        "references": found.iter().take(16).map(row).collect::<Vec<_>>(),
        "total": found.len(),
    });
    let unattributed_reason = || {
        format!(
            "{} reference{} come{} from data or code outside every discovered function (a pointer table, or code \
             discovery did not reach), so who uses {} is not known",
            unattributed.len(),
            if unattributed.len() == 1 { "" } else { "s" },
            if unattributed.len() == 1 { "s" } else { "" },
            described
        )
    };
    let unattributed_needs = "the users of the pointer tables or code listed: xrefs to the table's start, or raw.seeds \
                              for undiscovered code";
    let absent_needs = "a run that shows the access: evaluate_function or a debugger watchpoint";
    match (&claim.by, &claim.only_by) {
        (None, None) => {
            if found.is_empty() {
                return Outcome::unknown(method, evidence, "no reference was found").needs(absent_needs);
            }
            Outcome::verified(Confidence::Static, method, evidence)
        }
        (Some(function), None) => {
            let function = match function_start(project, function) {
                Ok(function) => function,
                Err(outcome) => return outcome,
            };
            let mine: Vec<Value> =
                found.iter().filter(|reference| reference.function == Some(function)).map(row).collect();
            if !mine.is_empty() {
                evidence["by"] = json!(mine);
                return Outcome::verified(Confidence::Static, method, evidence);
            }
            let reason = format!("no reference from {} was found", project.function_name(function));
            Outcome::unknown(method, evidence, reason).needs(absent_needs)
        }
        (None, Some(functions)) => {
            if functions.is_empty() || functions.len() > 64 {
                return Outcome::invalid("only_by lists 1..=64 functions");
            }
            let mut allowed = BTreeSet::new();
            for function in functions {
                match function_start(project, function) {
                    Ok(function) => allowed.insert(function),
                    Err(outcome) => return outcome,
                };
            }
            let outside: Vec<Value> = found
                .iter()
                .filter(|reference| reference.function.is_some_and(|function| !allowed.contains(&function)))
                .map(row)
                .collect();
            if !outside.is_empty() {
                evidence["outside"] = json!(outside);
                return Outcome::refuted(Confidence::Static, method, evidence);
            }
            if !unattributed.is_empty() {
                return Outcome::unknown(method, evidence, unattributed_reason()).needs(unattributed_needs);
            }
            if truncated {
                return Outcome::unknown(
                    method,
                    evidence,
                    format!("the string occurs more than {MAX_STRING_TARGETS} times; only the first were checked"),
                )
                .needs("a target address for each occurrence");
            }
            if found.is_empty() {
                return Outcome::unknown(method, evidence, "no reference was found").needs(absent_needs);
            }
            Outcome::verified(Confidence::Static, method, evidence)
        }
        _ => Outcome::invalid("state by or only_by, not both"),
    }
}

/// Instruction sites in `start`'s function that load `value` from read-only data (a RIP-relative `.rodata` load on
/// x86, a literal outside the function on other targets): what ARM's literal-pool loads already count as.
fn read_only_loads(project: &Project, start: u64, value: u64, negative: bool) -> Vec<(u64, String)> {
    let Ok(graph) = project.function_graph(start) else { return Vec::new() };
    let binary = &project.binary;
    let mut found = Vec::new();
    for line in graph.blocks.iter().flat_map(|block| &block.lines) {
        let Some(at) = line.data_ref.filter(|_| line.accesses) else { continue };
        let read_only = binary.segment_containing(at).is_some_and(|segment| !segment.perms.write);
        if !read_only {
            continue;
        }
        let word = |size: u64| -> Option<u64> {
            let bytes = binary.read(at, size)?;
            let mut buffer = [0u8; 8];
            if binary.big_endian {
                buffer[8 - size as usize..].copy_from_slice(bytes);
                Some(u64::from_be_bytes(buffer))
            } else {
                buffer[..size as usize].copy_from_slice(bytes);
                Some(u64::from_le_bytes(buffer))
            }
        };
        let matches32 = (value <= 0xffff_ffff || (negative && (value as i64) >= i64::from(i32::MIN)))
            && word(4) == Some(value & 0xffff_ffff);
        let matches64 = value > 0xffff_ffff && word(8) == Some(value);
        if matches32 || matches64 {
            found.push((line.address, line.text.clone()));
        }
    }
    found
}

pub(crate) fn constant(project: &Project, claim: &ConstantClaim) -> Outcome {
    let start = match function_start(project, &claim.function) {
        Ok(start) => start,
        Err(outcome) => return outcome,
    };
    let (value, negative) = match super::run::parse_integer(&claim.value) {
        Ok(parsed) => parsed,
        Err(error) => return Outcome::invalid(error),
    };
    let analysis = match project.analysis() {
        Ok(analysis) => analysis,
        Err(error) => return error.into(),
    };
    let Some(function) = analysis.program.function_at(start) else { return Outcome::invalid("no such function") };
    let low = function.blocks.iter().map(|block| block.start).min().unwrap_or(start);
    let high = function.blocks.iter().map(|block| block.end).max().unwrap_or(start + 1);
    // The value as instructions may hold it: unsigned, and sign-extended from 32 bits (x86 imm32).
    let mut forms = vec![if negative { CodeValue::Signed(value as i64) } else { CodeValue::Unsigned(value) }];
    if !negative && (0x8000_0000..=0xffff_ffff).contains(&value) {
        forms.push(CodeValue::Signed(i64::from(value as u32 as i32)));
        forms.push(CodeValue::Unsigned(value | 0xffff_ffff_0000_0000));
    }
    let method = format!(
        "immediate operands, loaded literals and read-only data loads of {}'s decoded instructions",
        project.function_name(start)
    );
    let mut sites = BTreeSet::new();
    let mut complete = true;
    let mut limitations = Vec::new();
    for form in forms {
        let immediate = CodeImmediate {
            value: form,
            width_bits: claim.bits,
            include_displacements: false,
            include_addresses: false,
        };
        let query = match CodeSearchQuery::new(CodeSearchKind::Immediate(immediate))
            .and_then(|query| query.with_range(Some(low..high)))
            .and_then(|query| query.with_page(0, 1000))
        {
            Ok(query) => query,
            Err(error) => return error.into(),
        };
        let report = match project.search_code(&query) {
            Ok(report) => report,
            Err(error) => {
                return Outcome::unknown(method, Value::Null, crate::tools::error_chain(&error))
                    .needs("a disassembly read of the function");
            }
        };
        complete &= report.scan_complete && !report.total_is_lower_bound;
        for limitation in report.limitations.iter().skip(1) {
            if !limitations.contains(limitation) {
                limitations.push(limitation.clone());
            }
        }
        for hit in report.hits.iter().filter(|hit| hit.function == start) {
            sites.insert((hit.site, hit.text.clone(), hit.evidence.kind));
        }
    }
    if claim.bits.is_none() {
        for (site, text) in read_only_loads(project, start, value, negative) {
            if !sites.iter().any(|(known, _, _)| *known == site) {
                sites.insert((site, text, "read_only_load"));
            }
        }
    }
    let rows: Vec<Value> = sites
        .iter()
        .take(SHOWN)
        .map(|(site, text, kind)| json!({"site": address(*site), "instruction": text, "evidence": kind}))
        .collect();
    let mut evidence = json!({"value": format!("{value:#x}"), "sites": rows});
    if !sites.is_empty() {
        return Outcome::verified(Confidence::Static, method, evidence);
    }
    if !limitations.is_empty() {
        evidence["limitations"] = json!(limitations);
    }
    // An absent constant is never refuted: compilers build values from shifts and adds, compare against value - 1,
    // replace a division by a multiplier, or load the value from data the code addresses indirectly.
    let reason = if complete {
        "no instruction holds it, but a constant's absence proves nothing: it may be built from other values \
         (shifts and adds, a comparison with value - 1, a division's multiplier) or loaded from data"
            .to_owned()
    } else {
        "no instruction found holds it, and the scan of the function was incomplete".to_owned()
    };
    Outcome::unknown(method, evidence, reason)
        .needs("a returns or computes claim that shows the value in use, or a read of the disassembly")
}
