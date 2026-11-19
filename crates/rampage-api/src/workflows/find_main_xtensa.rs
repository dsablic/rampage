//! `find_main` on Xtensa (ESP32, ESP8266) firmware built with ESP-IDF or the ESP8266 RTOS SDK: there is no
//! `__libc_start_main`, and the startup chain (`call_start_cpu0` -> `start_cpu0` -> the scheduler) reaches the
//! application through a task created by pointer, so it is not followed. The anchor is ESP-IDF's `main_task`,
//! which logs "Calling app_main()" and "Returned from app_main()" around its one call to `app_main`. The candidate
//! is the call between those two log lines whose callee the function calls nowhere else (the logging helpers repeat).

use std::collections::HashMap;

use rampage_arch::{Arch, Flow};

use super::Confidence;
use super::find_main::Candidate;
use crate::{ApiError, Project, StringsQuery};

/// The log lines ESP-IDF's `main_task` prints around its call to `app_main`.
const CALLING: &str = "Calling app_main()";
const RETURNED: &str = "Returned from app_main()";
/// Bytes a log format may start before the text the string scan finds: ESP-IDF's colour escape (`\x1b[0;32m`) ends
/// at a byte the scan does not take as text.
const MAX_PREFIX: u64 = 8;
/// Instructions of `main_task` read.
const MAX_TASK_INSTRUCTIONS: usize = 400;

impl Project {
    pub(super) fn esp_idf_main_candidates(&self) -> Result<Vec<Candidate>, ApiError> {
        if self.binary.arch != Arch::Xtensa {
            return Ok(Vec::new());
        }
        let find = |text: &str| {
            let query = StringsQuery { contains: Some(text.to_owned()), limit: Some(16), ..Default::default() };
            self.strings(&query).items.into_iter().map(|found| found.address).collect::<Vec<u64>>()
        };
        let (calling, returned) = (find(CALLING), find(RETURNED));
        if returned.is_empty() {
            return Ok(Vec::new());
        }
        let analysis = self.analysis()?;
        let mut candidates = Vec::new();
        let mut tasks = Vec::new();
        for &string in &returned {
            for at in string.saturating_sub(MAX_PREFIX)..=string {
                for xref in analysis.program.xrefs_to(at) {
                    tasks.extend(self.function_containing(xref.from)?);
                }
            }
        }
        tasks.sort_unstable();
        tasks.dedup();
        for task in tasks {
            let Some(function) = analysis.program.function_at(task) else { continue };
            let end = function.end();
            let lines = self.disassemble(Some(&format!("{task:#x}")), MAX_TASK_INSTRUCTIONS)?;
            let lines: Vec<_> = lines.into_iter().take_while(|line| line.address < end).collect();
            let refers = |line: &crate::DisassemblyLine, strings: &[u64]| {
                line.data_ref.into_iter().chain(line.immediate).any(|value| {
                    strings.iter().any(|&string| (string.saturating_sub(MAX_PREFIX)..=string).contains(&value))
                })
            };
            let Some(after) = lines.iter().rposition(|line| refers(line, &returned)) else { continue };
            let before = lines[..after].iter().rposition(|line| refers(line, &calling)).map_or(0, |at| at + 1);
            let mut calls: HashMap<u64, usize> = HashMap::new();
            for line in &lines {
                if let Flow::Call(target) = line.flow {
                    *calls.entry(target).or_default() += 1;
                }
            }
            let Some(call) = lines[before..after]
                .iter()
                .rev()
                .find(|line| matches!(line.flow, Flow::Call(target) if calls.get(&target) == Some(&1)))
            else {
                continue;
            };
            let Flow::Call(target) = call.flow else { continue };
            let anchored = if before > 0 { "between the \"Calling app_main()\" and" } else { "before the" };
            candidates.push(Candidate {
                address: target,
                confidence: if before > 0 { Confidence::High } else { Confidence::Medium },
                source: "xrefs",
                observation: format!(
                    "ESP-IDF's main_task calls app_main {anchored} \"Returned from app_main()\" log lines (heuristic)"
                ),
                evidence: vec![
                    format!("main_task at {task:#x} references \"{RETURNED}\""),
                    format!("{:#x}: {} -> {target:#x}, a callee main_task calls only here", call.address, call.text),
                ],
            });
        }
        Ok(candidates)
    }
}
