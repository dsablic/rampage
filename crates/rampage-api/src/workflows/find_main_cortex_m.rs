//! `find_main` on a Raw Cortex-M project: the reset handler is followed, through scatter-load's jump into copied
//! code and a trampoline that loads the next code address, to the first call that never returns or the code that
//! starts the scheduler. Every candidate is a heuristic with the instructions it rests on.

use rampage_arch::Flow;

use super::Confidence;
use super::find_main::Candidate;
use crate::{ApiError, DisassemblyLine, Project};

/// SCB Interrupt Control and State Register: writing PENDSVSET (bit 28) pends PendSV, how RTOSes switch tasks.
const SCB_ICSR: u64 = 0xe000_ed04;
/// Calls followed below a candidate when judging whether it returns.
const NEVER_RETURNS_DEPTH: usize = 2;
/// Instructions a function that ends spinning may have to count as a fault or error trap.
const TRAP_INSTRUCTIONS: usize = 8;

/// How a function never comes back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ends {
    /// It starts the scheduler itself.
    Scheduler,
    /// A few instructions, then it spins: a fault or error trap.
    Trap,
    /// It loops forever, or calls something that does.
    Loops,
}

/// Instructions a trampoline (code that only loads the next address and jumps there) may have.
const TRAMPOLINE_INSTRUCTIONS: usize = 16;

fn describe(line: &DisassemblyLine) -> String {
    format!("{:#x}: {}", line.address, line.text)
}

impl Project {
    /// A function's instructions in address order, or none when it has no listing.
    fn ordered_lines(&self, function: u64) -> Vec<DisassemblyLine> {
        let Ok(listing) = self.function_listing_for_frame(function) else { return Vec::new() };
        let mut lines: Vec<DisassemblyLine> = listing.blocks.into_iter().flatten().collect();
        lines.sort_by_key(|line| line.address);
        lines.dedup_by_key(|line| line.address);
        lines
    }

    /// Why the function at `function` never comes back to its caller, read along its instructions in address
    /// order: a scheduler start (`svc`, or PendSV pended through ICSR), an infinite loop, or a call to a function that
    /// never returns, `depth` calls deep, before any return. None when a return comes first or nothing shows it. A
    /// function of a few instructions that ends spinning (`b .`) is a fault or error trap, which code calls on a
    /// failure path; a call to one says nothing about the caller.
    fn never_returns(&self, function: u64, depth: usize) -> Result<Option<(String, Ends)>, ApiError> {
        if self.analysis()?.program.noreturn.binary_search(&function).is_ok() {
            return Ok(Some((format!("discovery found that {function:#x} never returns"), Ends::Loops)));
        }
        let lines = self.ordered_lines(function);
        let mut backward = None;
        for line in &lines {
            if line.text.starts_with("svc") {
                let reason = format!("{} hands control to the scheduler (supervisor call)", describe(line));
                return Ok(Some((reason, Ends::Scheduler)));
            }
            if line.data_ref == Some(SCB_ICSR) && line.accesses && line.text.starts_with("str") {
                let reason = format!("{} writes ICSR, which pends PendSV (a context switch)", describe(line));
                return Ok(Some((reason, Ends::Scheduler)));
            }
            match line.flow {
                Flow::Return => return Ok(None),
                Flow::Jump(target) if target == line.address => {
                    let trap = lines.len() <= TRAP_INSTRUCTIONS;
                    let (what, ends) = if trap {
                        ("spins: a fault or error trap", Ends::Trap)
                    } else {
                        ("is an infinite loop", Ends::Loops)
                    };
                    return Ok(Some((format!("{} {what}", describe(line)), ends)));
                }
                Flow::Jump(target) if self.function_containing(target)? == Some(function) => {
                    if target < line.address && backward.is_none() {
                        backward = Some(describe(line));
                    }
                }
                Flow::Call(target) | Flow::Jump(target) if depth > 0 && target != function => {
                    if let Some((reason, ends)) = self.never_returns(target, depth - 1)?
                        && ends != Ends::Trap
                    {
                        let how = if matches!(line.flow, Flow::Call(_)) { "calls" } else { "jumps to" };
                        return Ok(Some((
                            format!("{} {how} {target:#x}, where {reason}", describe(line)),
                            Ends::Loops,
                        )));
                    }
                    if matches!(line.flow, Flow::Jump(_)) {
                        return Ok(None);
                    }
                }
                _ => {}
            }
        }
        // No instruction returns, and an unconditional branch goes back: a loop that runs forever.
        Ok(backward
            .map(|line| (format!("no instruction of {function:#x} returns, and {line} loops back"), Ends::Loops)))
    }

    /// The function a trampoline at `function` jumps to: a short run without calls that ends in a register jump
    /// after loading a Thumb code address (`ldr r0, =target; bx r0`), with the instruction that loads it.
    fn trampoline_target(&self, function: u64) -> Result<Option<(u64, String)>, ApiError> {
        let lines = self.ordered_lines(function);
        if lines.len() > TRAMPOLINE_INSTRUCTIONS
            || lines.iter().any(|line| matches!(line.flow, Flow::Call(_) | Flow::IndirectCall))
            || !lines.last().is_some_and(|line| line.flow == Flow::IndirectJump)
        {
            return Ok(None);
        }
        for line in lines.iter().rev() {
            let Some(value) = line.immediate.filter(|value| value & 1 == 1) else { continue };
            let target = value & !1;
            if target != function && self.function_containing(target)? == Some(target) {
                return Ok(Some((target, describe(line))));
            }
        }
        Ok(None)
    }

    /// Candidates for the program's own entry logic in a Raw Cortex-M image, from its reset handler.
    pub(super) fn cortex_m_candidates(&self) -> Result<Vec<Candidate>, ApiError> {
        let Some(entry) = self.binary.entry else { return Ok(Vec::new()) };
        let Some(raw) = self.binary.raw_code_image() else { return Ok(Vec::new()) };
        let mut trail = vec![format!("reset handler (the entry) at {entry:#x}")];
        let mut init = Vec::new();
        let mut current = entry;
        let mut jumped = false;
        if let Some(scatter) = raw.scatter_load() {
            if !scatter.copies.is_empty() {
                init.push(format!(
                    "the reset code copies or zeroes {} section{} (binary_info raw.scatter_load)",
                    scatter.copies.len(),
                    if scatter.copies.len() == 1 { "" } else { "s" }
                ));
            }
            if let Some(target) = scatter.continues_at
                && let Some(function) = self.function_containing(target)?
            {
                trail.push(format!(
                    "scatter-load follows the reset code into copied code at {target:#x} (function {function:#x})"
                ));
                current = function;
                jumped = true;
            }
        }
        if jumped && let Some((target, load)) = self.trampoline_target(current)? {
            trail.push(format!("{current:#x} only loads the next code address and jumps there: {load}"));
            current = target;
        }
        let lines = self.ordered_lines(current);
        for (index, line) in lines.iter().enumerate() {
            // An indirect call inside a loop: the walk over a table of init routines (constructors, init hooks).
            if line.flow == Flow::IndirectCall
                && lines[index..].iter().any(|later| match later.flow {
                    Flow::Jump(target) | Flow::ConditionalJump(target) => target <= line.address,
                    _ => false,
                })
            {
                let walk = format!("{} calls through a table in a loop (init routines)", describe(line));
                if !init.contains(&walk) {
                    init.push(walk);
                }
            }
            let Flow::Call(target) = line.flow else { continue };
            let Some((reason, ends)) = self.never_returns(target, NEVER_RETURNS_DEPTH)? else { continue };
            if ends == Ends::Trap {
                continue;
            }
            let scheduler = ends == Ends::Scheduler;
            let mut evidence = trail.clone();
            evidence.extend(init.iter().cloned());
            evidence.push(format!("{} -> {target:#x}, which never returns: {reason}", describe(line)));
            let after_init = !init.is_empty();
            // A callee that itself starts the scheduler is the RTOS's start routine; the code calling it after the
            // init is the program's main, when the startup reached that code by a jump rather than a call.
            if scheduler && jumped {
                return Ok(vec![Candidate {
                    address: current,
                    confidence: if after_init { Confidence::Medium } else { Confidence::Low },
                    source: "disassemble",
                    observation: "the code the startup jumps into calls a routine that starts the scheduler; the \
                                  function that runs the init and then starts the RTOS is firmware main (heuristic)"
                        .to_owned(),
                    evidence,
                }]);
            }
            return Ok(vec![Candidate {
                address: target,
                confidence: if after_init && !scheduler { Confidence::Medium } else { Confidence::Low },
                source: "disassemble",
                observation: format!(
                    "the first call from the startup code that never returns{}; firmware main loops and RTOS starts \
                     look so (heuristic)",
                    if after_init { ", after the C runtime init" } else { "" }
                ),
                evidence,
            }]);
        }
        if jumped {
            let mut evidence = trail.clone();
            evidence.extend(init.iter().cloned());
            let (confidence, observation) = match self.never_returns(current, NEVER_RETURNS_DEPTH)? {
                Some((reason, ends)) if ends != Ends::Trap => {
                    evidence.push(reason);
                    (
                        Confidence::Medium,
                        "the code the startup jumps into after copying it never returns (it runs the init and starts \
                         the scheduler or loops); firmware main looks so (heuristic)",
                    )
                }
                _ => (
                    Confidence::Low,
                    "the code the startup jumps into after copying it; nothing shows that it never returns \
                     (heuristic)",
                ),
            };
            return Ok(vec![Candidate {
                address: current,
                confidence,
                source: "binary_info",
                observation: observation.to_owned(),
                evidence,
            }]);
        }
        Ok(Vec::new())
    }
}
