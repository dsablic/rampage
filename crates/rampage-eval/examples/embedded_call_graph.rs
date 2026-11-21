//! Builds the embedded firmware call graph (`crates/rampage-signatures/data/embedded-callgraph.json.gz`) from the
//! same symbolized training reference ELFs as the embedded signature set (`tools/embedded-signatures/build.py refs`
//! and `compiler-rt`; never the held-out 14.3 builds): each reference function's call sequence, its direct calls and
//! unconditional tail jumps in call-site order, as the callees' symbol names (`rampage_signatures::callgraph`).
//!
//! ```sh
//! cargo build --release -p rampage-eval --example embedded_call_graph
//! target/release/examples/embedded_call_graph \
//!   --output crates/rampage-signatures/data/embedded-callgraph.json.gz WORK/refs/*.elf
//! ```
//!
//! The output is deterministic for the same references (sorted by file name, gzip without a timestamp); its
//! `source` records the references' count and a digest of their names and contents.

use std::path::PathBuf;

use clap::Parser;
use rampage_api::call_sequences;
use rampage_loaders::Binary;
use rampage_signatures::{CallGraph, canonical_functions, canonical_name};
use sha2::Digest;

/// The licences of the code the names are read from: newlib, libgcc, compiler-rt, FreeRTOS, STM32F4 HAL, CMSIS.
const LICENSE: &str = "LicenseRef-newlib AND GPL-3.0-or-later WITH GCC-exception-3.1 AND Apache-2.0 WITH \
                       LLVM-exception AND MIT AND BSD-3-Clause AND Apache-2.0";

#[derive(Parser)]
struct Arguments {
    /// Where to write the gzip call graph.
    #[arg(long)]
    output: PathBuf,
    /// Symbolized training reference ELFs.
    references: Vec<PathBuf>,
}

fn run(arguments: Arguments) -> Result<(), String> {
    let mut references = arguments.references;
    references.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    if references.is_empty() {
        return Err("give at least one reference".to_owned());
    }
    let mut digest = sha2::Sha256::new();
    let mut sequences = Vec::new();
    for path in &references {
        let error = |error: String| format!("{}: {error}", path.display());
        let bytes = std::fs::read(path).map_err(|e| error(e.to_string()))?;
        let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        digest.update(name.as_bytes());
        digest.update([0]);
        digest.update(sha2::Sha256::digest(&bytes));
        let binary = Binary::open(path).map_err(|e| error(e.to_string()))?;
        let program = rampage_analysis::functions::analyze(&binary).map_err(|e| error(e.to_string()))?;
        let calls = call_sequences(&binary, &program);
        let symbols: std::collections::BTreeMap<u64, String> = canonical_functions(&binary)
            .into_iter()
            .map(|(address, symbol)| (address, canonical_name(&symbol.name).into_owned()))
            .collect();
        let arch = binary.arch.to_string();
        for (caller, targets) in &calls {
            let Some(name) = symbols.get(caller) else { continue };
            let callees: Vec<Option<String>> = targets.iter().map(|target| symbols.get(target).cloned()).collect();
            sequences.push((arch.clone(), name.clone(), callees));
        }
    }
    let source = format!(
        "tools/embedded-signatures training references: {} ELFs, sha256 {}",
        references.len(),
        rampage_arch::hex::bytes(&digest.finalize())
    );
    let mut graph = CallGraph::new(&source, LICENSE);
    for (arch, caller, callees) in sequences {
        graph.insert(&arch, &caller, callees, None);
    }
    let graph = graph.without_builds();
    let gzip = graph.to_gzip();
    std::fs::write(&arguments.output, &gzip).map_err(|error| format!("{}: {error}", arguments.output.display()))?;
    let total: usize = graph.arches.values().flat_map(|callers| callers.values()).map(Vec::len).sum();
    eprintln!("{source}: {} callers, {total} sequences, {} bytes gzip", graph.callers(), gzip.len());
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("embedded call graph: {error}");
            std::process::ExitCode::from(2)
        }
    }
}
