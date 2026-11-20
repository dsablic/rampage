//! Claims checked on the decoded code: `calls` (a call, through stubs or callees, and the order of two calls),
//! `references` (who references an address or string) and `constant` (an immediate in a function's code).

use std::collections::{BTreeSet, HashMap, VecDeque};

use rampage_analysis::discover::XrefKind;
use rampage_arch::{Arch, Flow};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Address, Confidence, Outcome, address, function_start};
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

/// A name as callers write it: without the leading underscores Mach-O and some ABIs add, an `@plt` or symbol
/// version suffix, or an import-thunk prefix.
fn normalize(name: &str) -> String {
    let name = name.split('@').next().unwrap_or(name);
    let name = name.strip_prefix("__imp_").or_else(|| name.strip_prefix("j_")).unwrap_or(name);
    name.trim_start_matches('_').to_owned()
}

/// What a callee claim names: an address when it resolves, and its names.
struct Callee {
    text: String,
    address: Option<u64>,
    names: BTreeSet<String>,
}

impl Callee {
    fn new(project: &Project, text: &str) -> Self {
        let address = project.resolve(text).ok().map(|address| project.thumb_code_address(address).0);
        let mut names = BTreeSet::from([normalize(text)]);
        if let Some(name) = address.and_then(|address| project.name_at(address)) {
            names.insert(normalize(&name));
        }
        names.retain(|name| !name.is_empty() && !name.starts_with("sub_"));
        Self { text: text.to_owned(), address, names }
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
                // A slot the instruction reads that is no import: a function pointer in data, whose value the
                // file holds (a vtable or callback table).
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
    let mut addresses = vec![target];
    let mut names = BTreeSet::new();
    let mut current = target;
    for _ in 0..MAX_STUB_HOPS {
        if let Some(name) = project.name_at(current).or_else(|| import_at(project, current)) {
            names.insert(normalize(&name));
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
        names.extend(stub_sites[0].imports.iter().map(|name| normalize(name)));
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
    if site.imports.iter().any(|name| callee.names.contains(&normalize(name))) {
        return true;
    }
    site.targets.iter().any(|&target| {
        let (addresses, names) = forwards(project, target);
        callee.address.is_some_and(|wanted| addresses.contains(&wanted))
            || names.iter().any(|name| callee.names.contains(name))
    })
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
struct Search {
    /// The chain found: (function, call site) pairs, the last site reaching the callee.
    path: Option<Vec<(u64, u64)>>,
    visited: usize,
    /// Unresolved sites in the functions searched, with their function.
    unresolved: Vec<(u64, u64)>,
    truncated: bool,
}

fn search(project: &Project, start: u64, callee: &Callee, depth: u32) -> Search {
    let mut queue = VecDeque::from([(start, 1u32)]);
    let mut parent: HashMap<u64, (u64, u64)> = HashMap::new();
    let mut seen = BTreeSet::from([start]);
    let mut result = Search { path: None, visited: 0, unresolved: Vec::new(), truncated: false };
    while let Some((function, level)) = queue.pop_front() {
        if result.visited >= MAX_VISITED {
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

pub(crate) fn calls(project: &Project, claim: &CallsClaim) -> Outcome {
    let start = match function_start(project, &claim.function) {
        Ok(start) => start,
        Err(outcome) => return outcome,
    };
    let depth = claim.depth.unwrap_or(DEFAULT_DEPTH);
    if !(1..=MAX_DEPTH).contains(&depth) {
        return Outcome::invalid(format!("depth must be 1..={MAX_DEPTH}"));
    }
    let callee = Callee::new(project, &claim.callee);
    if callee.address.is_none() && callee.names.is_empty() {
        return Outcome::invalid(format!("{:?} names no function or import", claim.callee));
    }
    match &claim.before {
        Some(later) => before(project, start, &callee, &Callee::new(project, later), depth),
        None => calls_within(project, start, &callee, depth),
    }
}

fn calls_within(project: &Project, start: u64, callee: &Callee, depth: u32) -> Outcome {
    let found = search(project, start, callee, depth);
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
    if !found.unresolved.is_empty() || found.truncated {
        let rows: Vec<Value> = found
            .unresolved
            .iter()
            .take(SHOWN)
            .map(|&(function, at)| json!({"function": project.function_name(function), "site": address(at)}))
            .collect();
        evidence["unresolved"] = json!(rows);
        evidence["unresolved_total"] = json!(found.unresolved.len());
        let reason = if found.truncated {
            format!("the search stopped at {MAX_VISITED} functions")
        } else {
            "no direct call was found, but indirect calls or jumps with unknown targets remain".to_owned()
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

fn before(project: &Project, start: u64, first: &Callee, later: &Callee, depth: u32) -> Outcome {
    let graph = match project.function_graph(start) {
        Ok(graph) => graph,
        Err(error) => return error.into(),
    };
    let Some(entry) = graph.entry() else { return Outcome::invalid("the function has no entry block") };
    let all = sites(project, &graph);
    let by_address: HashMap<u64, &Site> = all.iter().map(|site| (site.at, site)).collect();
    // What each instruction is: a call of the first callee (directly or, with depth, through a callee), of the later
    // one, or an unresolved transfer.
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        First,
        Later,
        Unresolved,
    }
    let mark = |site: &Site| -> Option<Mark> {
        if site.kind == SiteKind::Unresolved {
            return Some(Mark::Unresolved);
        }
        if reaches(project, site, first) {
            return Some(Mark::First);
        }
        if depth > 1 {
            for &target in &site.targets {
                if let Some(&next) = forwards(project, target).0.last()
                    && search(project, next, first, depth - 1).path.is_some()
                {
                    return Some(Mark::First);
                }
            }
        }
        reaches(project, site, later).then_some(Mark::Later)
    };
    let mut marks: HashMap<u64, Mark> = HashMap::new();
    for site in &all {
        if let Some(found) = mark(site) {
            marks.insert(site.at, found);
        }
    }
    let successors = |block: usize| graph.edges.iter().filter(move |edge| edge.from == block).map(|edge| edge.to);
    let method = format!(
        "paths through the control-flow graph of {} from its entry to each call of {}",
        project.function_name(start),
        later.text
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
    let later_sites: Vec<u64> = marks
        .iter()
        .filter(|(_, mark)| **mark == Mark::Later)
        .map(|(&at, _)| at)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let first_sites: Vec<u64> = marks
        .iter()
        .filter(|(_, mark)| **mark == Mark::First)
        .map(|(&at, _)| at)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
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
                "every direct call of the later callee comes after the first, but indirect calls or jumps with unknown \
                 targets run before it on some path, and one may call the later callee",
            )
            .needs(unresolved_needs);
        }
        if later_sites.is_empty() {
            if any_unresolved {
                return Outcome::unknown(
                    method,
                    evidence,
                    format!("no direct call of {} was found; unresolved indirect transfers remain", later.text),
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
    let _ = by_address;
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
            "a path reaches the call of {} at {site:#x} without a direct call of {}, and unresolved indirect calls \
             or jumps remain",
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
                limit: Some(64),
            };
            let found: Vec<u64> = project
                .strings(&query)
                .items
                .iter()
                .filter(|string| string.text == *text)
                .map(|string| string.address)
                .collect();
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
            if found.is_empty() {
                return Outcome::unknown(method, evidence, "no reference was found").needs(absent_needs);
            }
            Outcome::verified(Confidence::Static, method, evidence)
        }
        _ => Outcome::invalid("state by or only_by, not both"),
    }
}

/// Whether a missing immediate can refute: the decoder types every operand, and constants this large are encoded
/// whole on x86 (on AArch64 they are built from 16-bit pieces, on 32-bit ARM, MIPS and Xtensa only loaded
/// literals and movw/movt or lui pairs are seen).
fn absence_refutes(arch: Arch, value: u64) -> bool {
    let large = value >= 0x1_0000 && value.wrapping_neg() >= 0x1_0000;
    large && matches!(arch, Arch::X86 | Arch::X86_64)
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
    let method =
        format!("immediate operands and loaded literals of {}'s decoded instructions", project.function_name(start));
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
    // Instructions without typed operands leave the search incomplete; their rendered text still shows every
    // operand, so when the only gap is those and no instruction's text holds the value, the scan is complete.
    if !complete && limitations.iter().all(|limitation| limitation.contains("operand evidence")) {
        let hex_form = format!("{value:#x}");
        let signed_form = format!("{:#x}", value as u32 as i32);
        let decimal = value.to_string();
        let mentions = |text: &str| {
            let text = text.to_ascii_lowercase();
            text.contains(&hex_form)
                || text.contains(&signed_form)
                || text.split(|character: char| !character.is_ascii_digit()).any(|word| word == decimal)
        };
        if let Ok(graph) = project.function_graph(start) {
            let mut lines = graph.blocks.iter().flat_map(|block| &block.lines);
            complete = !lines.any(|line| mentions(&line.text) || line.immediates_hex.as_deref().is_some_and(mentions));
            if complete {
                evidence["text_checked"] = json!(true);
            }
        }
    }
    if complete && absence_refutes(project.binary.arch, value) {
        return Outcome::refuted(
            Confidence::Static,
            format!("{method}: none holds it; a value computed from other constants or read from a table is not seen"),
            evidence,
        );
    }
    let reason = match project.binary.arch {
        Arch::X86 | Arch::X86_64 if !complete => "the scan of the function was incomplete".to_owned(),
        Arch::X86 | Arch::X86_64 => {
            "no instruction holds it, but a small constant is often folded into other instructions (lea, shifts, \
             a division's multiplier)"
                .to_owned()
        }
        arch => format!(
            "no instruction holds it, but on {arch:?} constants are built from pieces or loaded in ways the search \
             does not see: its results are lower bounds"
        ),
    };
    Outcome::unknown(method, evidence, reason)
        .needs("a returns or computes claim that shows the value in use, or a read of the disassembly")
}
