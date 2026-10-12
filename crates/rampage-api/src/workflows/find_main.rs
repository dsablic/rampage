//! `find_main`: locates the program's own entry logic past the runtime startup code, from symbols when present
//! and otherwise from startup-code heuristics that are stated as heuristics, then profiles the best candidate.

use std::cell::OnceCell;
use std::collections::{BTreeSet, HashMap};

use rampage_arch::{Arch, Flow};
use rampage_capabilities::names;
use rampage_loaders::{Details, Format};
use serde_json::json;

use super::{Confidence, Excerpt, Finding, ReportLimits, Section, WorkflowReport, api_matches, is_default_name, quote};
use crate::{ApiError, DisassemblyLine, Project, XrefQuery};

/// Symbol names that conventionally mark a program's entry logic, most specific first: in a cgo binary `main` is
/// the Go runtime's C entry stub and `main.main` the program's own logic.
const ENTRY_SYMBOLS: [&str; 8] =
    ["main.main", "main", "_main", "wmain", "_wmain", "WinMain", "wWinMain", "_WinMain@16"];
/// Calls through which a C runtime ends the process with main's return value (patterns, see `api_matches`;
/// `_exit` and `_cexit` normalize to these).
const EXIT_NAMES: [&str; 2] = ["exit", "cexit"];
/// The C runtime functions whose first argument is main (patterns, see `api_matches`).
const LIBC_START_MAIN: [&str; 2] = ["libc_start_main", "uclibc_main"];
/// Instructions decoded per startup stub, and stubs followed from the entry point.
const STUB_INSTRUCTIONS: usize = 64;
const STUB_DEPTH: usize = 3;
/// How far before a CRT exit call the call to main is looked for.
const EXIT_LOOKBACK: usize = 16;
/// Functions reached from the entry point that are searched for the CRT exit pattern.
const CRT_FUNCTIONS: usize = 8;
const PREVIEW_LINES: usize = 60;
/// References read from the candidate when profiling it.
const PROFILE_REFERENCES: usize = 1000;

struct Candidate {
    address: u64,
    confidence: Confidence,
    source: &'static str,
    observation: String,
    evidence: Vec<String>,
}

fn is_libc_start_main(name: &str) -> bool {
    LIBC_START_MAIN.iter().any(|pattern| api_matches(pattern, name))
}

/// The register an instruction writes, read from its text (`mov rdi, ...` writes `rdi`).
fn destination(text: &str) -> Option<&str> {
    let (_, operands) = text.split_once(' ')?;
    Some(operands.split(',').next()?.trim())
}

/// The registers that carry a call's first pointer argument under the ELF ABIs modelled here.
fn first_argument_registers(arch: Arch) -> Option<&'static [&'static str]> {
    match arch {
        Arch::X86_64 => Some(&["rdi", "edi"]),
        Arch::Aarch64 => Some(&["x0"]),
        _ => None,
    }
}

/// Whether `lines` (the instructions just before a call) load the first three Windows x64 argument registers, as
/// a CRT does for `main(argc, argv, envp)`.
fn main_arguments_loaded(lines: &[DisassemblyLine]) -> bool {
    let written: Vec<&str> = lines.iter().filter_map(|line| destination(&line.text)).collect();
    [["ecx", "rcx"], ["edx", "rdx"], ["r8d", "r8"]].iter().all(|names| names.iter().any(|name| written.contains(name)))
}

fn describe(line: &DisassemblyLine) -> String {
    match &line.comment {
        Some(comment) => format!("{:#x}: {}  ; {comment}", line.address, line.text),
        None => format!("{:#x}: {}", line.address, line.text),
    }
}

impl Project {
    /// Locates the most likely start of the program's own logic and profiles it. Symbols are trusted first; the
    /// startup heuristics only propose candidates, each with the instructions it rests on.
    pub fn find_main(&self, limits: ReportLimits, decompile: bool) -> Result<WorkflowReport, ApiError> {
        let mut report = WorkflowReport::new("find_main", self);
        let mut candidates = self.symbol_candidates();
        if self.binary.format == Format::Elf {
            match first_argument_registers(self.binary.arch) {
                Some(registers) => candidates.extend(self.libc_start_candidate(registers)?),
                None => report.limitation(format!(
                    "The __libc_start_main heuristic models x86-64 and AArch64 argument registers only, not {}.",
                    self.binary.arch
                )),
            }
        }
        if self.binary.format == Format::Pe {
            let mingw = self.detect_tools(None)?.iter().any(|detection| detection.name.contains("MinGW"));
            if mingw {
                candidates.extend(self.mingw_candidates()?);
            } else {
                report.limitation(
                    "No MinGW toolchain signature matched; the MSVC CRT startup chain is not modelled, so without a \
                     symbol no PE heuristic candidate is proposed.",
                );
            }
        }
        candidates.extend(self.macho_entry_candidate());
        let candidates = merge(candidates);

        let mut found = Section::new("Candidates", limits);
        for candidate in &candidates {
            found.push(
                Finding::new(candidate.source, candidate.confidence, candidate.observation.clone())
                    .at(candidate.address)
                    .evidence(candidate.evidence.iter().cloned()),
            );
        }
        report.sections.push(found);

        match candidates.first() {
            Some(best) => {
                let name = self.function_name(best.address);
                report.summary.push(format!(
                    "Most likely entry logic: `{name}` at {:#x} ({} confidence, from {}).",
                    best.address,
                    best.confidence.as_str(),
                    best.source
                ));
                if candidates.len() > 1 {
                    report.summary.push(format!("{} distinct candidates were proposed.", candidates.len()));
                }
                self.profile(&mut report, best.address, limits)?;
                if decompile {
                    report.sections.push(self.preview(best.address, limits));
                }
                let at = format!("{:#x}", best.address);
                report.step("decompile", json!({ "at": at }), "Read the candidate's logic in full.");
                report.step("xrefs", json!({ "from": at }), "List everything the candidate references.");
                if is_default_name(&name, best.address) && best.confidence >= Confidence::Medium {
                    report.step(
                        "rename",
                        json!({ "at": at, "name": "main" }),
                        "Record the finding once the decompilation agrees that this is the program's main logic.",
                    );
                }
            }
            None => {
                report.summary.push(
                    "No main candidate found: no entry symbol, and no modelled startup pattern matched.".to_owned(),
                );
                if self.binary.entry.is_some() {
                    report.step("disassemble", json!({}), "Read the startup code at the entry point by hand.");
                }
                report.step("list_functions", json!({}), "Look for a plausible main among the discovered functions.");
            }
        }

        report.limitation("Symbol names are taken at face value; a binary can give any function the name main.");
        report.limitation(
            "Startup heuristics cover the ELF __libc_start_main first argument (x86-64, AArch64), the MinGW-w64 CRT \
             call before _cexit/exit, and the Mach-O LC_MAIN entry convention. Custom, obfuscated or other runtimes' \
             startup code (MSVC, Go without symbols, a hand-written _start) is not modelled.",
        );
        report.limitation(
            "A candidate marks where the program's own code likely begins; it does not show what the code does.",
        );
        Ok(report)
    }

    fn symbol_candidates(&self) -> Vec<Candidate> {
        let binary = &self.binary;
        let mut candidates = Vec::new();
        for name in ENTRY_SYMBOLS {
            let symbol = binary.symbols.iter().find(|symbol| symbol.name == name).map(|symbol| symbol.address);
            let export = binary.exports.iter().find(|export| export.name == name).map(|export| export.address);
            let Some(address) = symbol.or(export).filter(|&address| binary.is_code(address)) else { continue };
            candidates.push(Candidate {
                address,
                confidence: Confidence::High,
                source: if symbol.is_some() { "list_functions" } else { "list_exports" },
                observation: format!("the binary names this function `{name}`"),
                evidence: vec![format!(
                    "{} `{name}` at {address:#x}",
                    if symbol.is_some() { "symbol" } else { "export" }
                )],
            });
        }
        candidates
    }

    /// Names a startup stub's call target: by symbol, import or stub name, or else by bundled signature (matched
    /// once, on first need, since that hashes every function).
    fn transfer_name(&self, target: u64, signatures: &OnceCell<HashMap<u64, String>>) -> Option<(String, bool)> {
        self.name_at(target)
            .map(|name| (name, false))
            .or_else(|| signatures.get_or_init(|| self.signature_names()).get(&target).map(|name| (name.clone(), true)))
    }

    fn signature_names(&self) -> HashMap<u64, String> {
        self.apply_signatures_default(None, false)
            .map(|found| found.matches.into_iter().map(|found| (found.address, found.name)).collect())
            .unwrap_or_default()
    }

    /// Walks the startup stubs from the entry point, tracking the code address last loaded into the first-argument
    /// register, until a call to `__libc_start_main` (whose first argument is main by the C runtime ABI) or another
    /// transfer that ends the stub.
    fn libc_start_candidate(&self, registers: &[&str]) -> Result<Option<Candidate>, ApiError> {
        let Some(mut at) = self.binary.entry else { return Ok(None) };
        let signatures = OnceCell::new();
        let mut loaded: Option<(u64, String)> = None;
        let mut trail = Vec::new();
        for _ in 0..STUB_DEPTH {
            let mut follow = None;
            for line in self.disassemble(Some(&format!("{at:#x}")), STUB_INSTRUCTIONS)? {
                if destination(&line.text).is_some_and(|register| registers.contains(&register)) {
                    let value = line.data_ref.or(line.immediate).filter(|&value| self.binary.is_code(value));
                    loaded = value.map(|value| (value, describe(&line)));
                    continue;
                }
                let (target, direct) = match line.flow {
                    Flow::Call(target) | Flow::Jump(target) => (Some(target), true),
                    Flow::IndirectCall | Flow::IndirectJump => (line.data_ref, false),
                    Flow::Return | Flow::Halt | Flow::Invalid => break,
                    Flow::Next | Flow::ConditionalJump(_) => continue,
                };
                let Some(target) = target else { break };
                let name = self.transfer_name(target, &signatures);
                if let Some((name, by_signature)) = name.as_ref().filter(|(name, _)| is_libc_start_main(name)) {
                    let Some((value, load)) = loaded else { return Ok(None) };
                    let how = if *by_signature { "named by bundled signature" } else { "named by the binary" };
                    trail.extend([load, format!("{} -> `{name}` ({how})", describe(&line))]);
                    return Ok(Some(Candidate {
                        address: value,
                        confidence: if *by_signature { Confidence::Low } else { Confidence::Medium },
                        source: "disassemble",
                        observation: format!(
                            "passed as the first argument to `{name}` in the startup code; by the C runtime ABI \
                             that argument is main (heuristic)"
                        ),
                        evidence: trail,
                    }));
                }
                if !direct {
                    break;
                }
                match (&loaded, &name) {
                    (Some((value, load)), None) => {
                        trail.extend([load.clone(), format!("{} -> unnamed {target:#x}", describe(&line))]);
                        return Ok(Some(Candidate {
                            address: *value,
                            confidence: Confidence::Low,
                            source: "disassemble",
                            observation: "passed as the first argument to an unnamed function that ends the startup \
                                          stub; this matches a stripped __libc_start_main call (heuristic)"
                                .to_owned(),
                            evidence: trail,
                        }));
                    }
                    (None, _) => {
                        trail.push(format!("{} (followed)", describe(&line)));
                        follow = Some(target);
                        break;
                    }
                    (Some(_), Some(_)) => break,
                }
            }
            match follow {
                Some(target) => at = target,
                None => break,
            }
        }
        Ok(None)
    }

    /// The MinGW-w64 CRT calls main and then hands its return value to `_cexit`/`exit`: the nearest internal
    /// call before such a call, in the functions the entry point reaches, is proposed.
    fn mingw_candidates(&self) -> Result<Vec<Candidate>, ApiError> {
        let Some(entry) = self.binary.entry else { return Ok(Vec::new()) };
        let imports: BTreeSet<String> =
            self.binary.imports.iter().map(|import| names::import_stem(&import.name)).collect();
        let internal = |target: u64| {
            self.binary.is_code(target)
                && self.name_at(target).is_none_or(|name| !imports.contains(&names::import_stem(&name)))
                && self.binary.import_slot(target).is_none()
        };
        let mut queue = vec![entry];
        let mut seen = BTreeSet::new();
        let mut candidates = Vec::new();
        while let Some(function) = queue.pop() {
            if !seen.insert(function) || seen.len() > CRT_FUNCTIONS {
                continue;
            }
            let Ok(listing) = self.function_listing(function) else { continue };
            let mut lines: Vec<DisassemblyLine> = listing.blocks.into_iter().flatten().collect();
            lines.sort_by_key(|line| line.address);
            for (index, line) in lines.iter().enumerate() {
                let target = match line.flow {
                    Flow::Call(target) => Some(target),
                    Flow::IndirectCall => line.data_ref,
                    _ => None,
                };
                let exit = target
                    .and_then(|target| self.name_at(target))
                    .filter(|name| EXIT_NAMES.iter().any(|pattern| api_matches(pattern, name)));
                if let Some(exit) = exit {
                    let start = index.saturating_sub(EXIT_LOOKBACK);
                    let call = (start..index).rev().find_map(|at| match lines[at].flow {
                        Flow::Call(callee)
                            if callee != listing.address
                                && internal(callee)
                                && main_arguments_loaded(&lines[at.saturating_sub(3)..at]) =>
                        {
                            Some((at, callee))
                        }
                        _ => None,
                    });
                    if let Some((at, callee)) = call {
                        let mut evidence: Vec<String> = lines[at.saturating_sub(3)..=at].iter().map(describe).collect();
                        evidence.push(describe(line));
                        candidates.push(Candidate {
                            address: callee,
                            confidence: Confidence::Low,
                            source: "function_graph",
                            observation: format!(
                                "called with three loaded arguments (argc, argv, envp shape) shortly before the CRT's \
                                 `{exit}` call in startup function {}; MinGW-w64 calls main there and exits with its \
                                 result (heuristic)",
                                self.function_name(listing.address)
                            ),
                            evidence,
                        });
                    }
                }
                if let Flow::Call(target) | Flow::Jump(target) = line.flow
                    && internal(target)
                    && self.function_containing(target)? == Some(target)
                {
                    queue.insert(0, target);
                }
            }
        }
        Ok(candidates)
    }

    /// With `LC_MAIN`, which modern Apple toolchains emit, a Mach-O executable's entry point is main itself.
    fn macho_entry_candidate(&self) -> Option<Candidate> {
        let Details::MachO(details) = &self.binary.details else { return None };
        let entry = self.binary.entry.filter(|&entry| details.file_type == "execute" && self.binary.is_code(entry))?;
        Some(Candidate {
            address: entry,
            confidence: Confidence::Medium,
            source: "binary_info",
            observation: "entry point of a Mach-O executable: with LC_MAIN this is main itself (heuristic: the \
                          loader does not record whether LC_MAIN or the legacy LC_UNIXTHREAD supplied it)"
                .to_owned(),
            evidence: vec![format!("Mach-O file type execute, entry {entry:#x}")],
        })
    }

    /// The candidate's callees, imports and strings, from its outgoing references.
    fn profile(&self, report: &mut WorkflowReport, address: u64, limits: ReportLimits) -> Result<(), ApiError> {
        let references = match self.xrefs(XrefQuery::From(address), None, Some(PROFILE_REFERENCES)) {
            Ok(references) => references,
            Err(error) => {
                report.limitation(format!("The candidate's references are unavailable: {error}"));
                return Ok(());
            }
        };
        let strings: HashMap<u64, &str> =
            self.scanned_strings().iter().map(|found| (found.address, found.text.as_str())).collect();
        let mut calls = Section::new("Candidate calls", limits);
        let mut texts = Section::new("Candidate strings", limits);
        let mut called = BTreeSet::new();
        for reference in &references.items {
            if let Some(text) = strings.get(&reference.to) {
                texts.push(
                    Finding::new("xrefs", Confidence::High, format!("references string {}", quote(text)))
                        .at(reference.from)
                        .evidence([format!("{:#x} -> {:#x}", reference.from, reference.to)]),
                );
                continue;
            }
            if reference.kind != rampage_analysis::discover::XrefKind::Call || !called.insert(reference.to) {
                continue;
            }
            let name = reference.to_name.clone().unwrap_or_else(|| self.function_name(reference.to));
            let import = self.binary.import_slot(reference.to).is_some()
                || name.ends_with("@plt")
                || self.binary.imports.iter().any(|import| import.name == name);
            let kind = if import { "import" } else { "function" };
            calls.push(
                Finding::new("xrefs", Confidence::High, format!("calls {kind} `{name}`"))
                    .at(reference.from)
                    .evidence([format!("call at {:#x} -> {:#x}", reference.from, reference.to)]),
            );
        }
        if references.total > references.items.len() {
            report.limitation(format!(
                "Only the first {} of the candidate's {} references were profiled.",
                references.items.len(),
                references.total
            ));
        }
        report.summary.push(format!(
            "The candidate makes {} distinct calls and references {} strings.",
            calls.total, texts.total
        ));
        report.sections.push(calls);
        report.sections.push(texts);
        Ok(())
    }

    fn preview(&self, address: u64, limits: ReportLimits) -> Section {
        let mut section = Section::new("Decompilation preview", limits);
        match self.decompile(address) {
            Ok(decompilation) => {
                let lines: Vec<&str> = decompilation.code.lines().collect();
                section.excerpt = Some(Excerpt {
                    source: "decompile",
                    text: lines.iter().take(PREVIEW_LINES).copied().collect::<Vec<_>>().join("\n"),
                    truncated: lines.len() > PREVIEW_LINES,
                });
            }
            Err(error) => section.push(Finding::new(
                "decompile",
                Confidence::High,
                format!("decompilation failed (the rest of the report stands): {error}"),
            )),
        }
        section
    }
}

/// Folds candidates for one address into the most confident one, recording the others as corroboration, and
/// orders the result by confidence, keeping the proposal order (`ENTRY_SYMBOLS` order first) among equals.
fn merge(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut merged: Vec<Candidate> = Vec::new();
    for candidate in candidates {
        match merged.iter_mut().find(|existing| existing.address == candidate.address) {
            Some(existing) => {
                let note = format!("corroborated by {}: {}", candidate.source, candidate.observation);
                if candidate.confidence > existing.confidence {
                    let mut replacement = candidate;
                    replacement.evidence.push(format!("corroborated by {}: {}", existing.source, existing.observation));
                    *existing = replacement;
                } else {
                    existing.evidence.push(note);
                }
            }
            None => merged.push(candidate),
        }
    }
    merged.sort_by_key(|candidate| std::cmp::Reverse(candidate.confidence));
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(address: u64, confidence: Confidence, observation: &str) -> Candidate {
        Candidate { address, confidence, source: "test", observation: observation.to_owned(), evidence: Vec::new() }
    }

    #[test]
    fn merge_keeps_proposal_order_among_equal_confidence() {
        let merged = merge(vec![
            candidate(0x2000, Confidence::High, "main.main"),
            candidate(0x1000, Confidence::High, "main"),
            candidate(0x500, Confidence::Low, "heuristic"),
            candidate(0x1000, Confidence::Medium, "startup"),
        ]);
        let order: Vec<u64> = merged.iter().map(|candidate| candidate.address).collect();
        assert_eq!(order, [0x2000, 0x1000, 0x500]);
        assert!(merged[1].evidence[0].contains("corroborated by test: startup"));
    }
}
