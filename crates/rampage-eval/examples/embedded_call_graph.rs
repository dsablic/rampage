//! Builds the embedded firmware call graph (`crates/rampage-signatures/data/embedded-callgraph.json.gz`) from the
//! same symbolized training reference ELFs as the embedded signature set (`tools/embedded-signatures/build.py refs`
//! and `compiler-rt`): each reference function's call sequence, its direct calls and unconditional tail jumps in
//! call-site order, as the callees' symbol names (`rampage_signatures::callgraph`).
//!
//! ```sh
//! cargo build --release -p rampage-eval --example embedded_call_graph
//! target/release/examples/embedded_call_graph \
//!   --output crates/rampage-signatures/data/embedded-callgraph.json.gz WORK/refs/*.elf
//! ```
//!
//! - **Training references only.** A reference built by a held-out toolchain (GCC 14.3, clang 23: `HELD_OUT` and
//!   the held-out compiler-rt build in `build.py`) is refused, so the held-out firmware fixtures stay unseen. The
//!   `source` records the training compilers, the references' count and a digest of their names and contents.
//! - **Override points are not library functions.** A weak function whose whole body is one `bx lr` is either a
//!   link stub (`link_reference` fills every symbol the inputs leave undefined with exactly that, so an application
//!   hook such as `vApplicationGetIdleTaskMemory` or a library routine another archive defines would read as an
//!   empty leaf) or an empty weak default an application overrides (the HAL's `*_MspInit` and `*Callback`). Neither
//!   is ever a caller. A name that is empty and weak in some reference and non-weak in none is an override point
//!   everywhere (the HAL's weak defaults are not empty at -O0): never a caller, and `None` as a callee, so
//!   propagation never names the program's own hooks after it. A stub of a routine another reference defines
//!   non-weak (`memset` in a FreeRTOS reference) keeps that routine's name as a callee.
//!
//! The output is deterministic for the same references (sorted by file name, gzip without a timestamp).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use clap::Parser;
use object::{Object, ObjectSymbol, SymbolKind};
use rampage_api::call_sequences;
use rampage_loaders::Binary;
use rampage_signatures::{CallGraph, canonical_functions, canonical_name};
use sha2::Digest;

/// The licences of the code the names are read from: newlib, libgcc, compiler-rt, FreeRTOS, STM32F4 HAL, CMSIS.
const LICENSE: &str = "LicenseRef-newlib AND GPL-3.0-or-later WITH GCC-exception-3.1 AND Apache-2.0 WITH \
                       LLVM-exception AND MIT AND BSD-3-Clause AND Apache-2.0";

/// Compiler tags in reference file names that mark a held-out build (`build.py`: `HELD_OUT` is Arm GNU Toolchain
/// 14.3.rel1, GCC 14.3.1; the held-out compiler-rt is built by clang 23).
const HELD_OUT: [&str; 2] = ["gcc14.3", "clang23"];

/// Thumb `bx lr`, little-endian.
const BX_LR: [u8; 2] = [0x70, 0x47];

#[derive(Parser)]
struct Arguments {
    /// Where to write the gzip call graph.
    #[arg(long)]
    output: PathBuf,
    /// Symbolized training reference ELFs.
    references: Vec<PathBuf>,
}

/// The compiler tag (`gcc12.3.1`, `clang22.1.8`) in a reference's file name, which `build.py` writes as
/// `<library>-<version>-<compiler><version>-<core>...`.
fn compiler_tag(name: &str) -> Option<String> {
    name.split('-').find_map(|part| {
        ["gcc", "clang"].iter().find_map(|compiler| {
            let version = part.strip_prefix(compiler)?;
            (!version.is_empty() && version.chars().all(|c| c.is_ascii_digit() || c == '.')).then(|| part.to_owned())
        })
    })
}

/// Refuses a reference a held-out toolchain built, or one whose compiler the file name does not record.
fn training_compiler(path: &Path) -> Result<String, String> {
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let tag = compiler_tag(&name).ok_or_else(|| format!("{name}: no compiler tag (gcc<version> or clang<version>)"))?;
    if HELD_OUT.iter().any(|held_out| tag.starts_with(held_out)) {
        return Err(format!("{name}: built by held-out {tag}; give training references only"));
    }
    Ok(tag)
}

/// One reference's weak-symbol facts: the addresses where every function symbol is weak, two bytes long and a
/// `bx lr` (link stubs and empty weak defaults), and the names of its non-weak function symbols.
fn weak_facts(binary: &Binary, elf: &object::File) -> (BTreeSet<u64>, BTreeSet<String>) {
    let mut empty: BTreeMap<u64, bool> = BTreeMap::new();
    let mut strong = BTreeSet::new();
    for symbol in elf.symbols().filter(|symbol| symbol.kind() == SymbolKind::Text && symbol.size() > 0) {
        let address = symbol.address() & !1;
        let is_empty = symbol.is_weak() && symbol.size() == 2 && binary.read(address, 2) == Some(&BX_LR[..]);
        *empty.entry(address).or_insert(true) &= is_empty;
        if !symbol.is_weak()
            && let Ok(name) = symbol.name()
        {
            strong.insert(canonical_name(name).into_owned());
        }
    }
    (empty.into_iter().filter(|(_, empty)| *empty).map(|(address, _)| address).collect(), strong)
}

fn run(arguments: Arguments) -> Result<(), String> {
    let mut references = arguments.references;
    references.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    if references.is_empty() {
        return Err("give at least one reference".to_owned());
    }
    let compilers: BTreeSet<String> =
        references.iter().map(|path| training_compiler(path)).collect::<Result<_, _>>()?;
    let mut digest = sha2::Sha256::new();
    // Per reference: its architecture, call sequences, every function's name and its empty weak functions; and every
    // non-weak function name.
    let mut analysed = Vec::new();
    let mut strong: BTreeSet<String> = BTreeSet::new();
    for path in &references {
        let error = |error: String| format!("{}: {error}", path.display());
        let bytes = std::fs::read(path).map_err(|e| error(e.to_string()))?;
        let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
        digest.update(name.as_bytes());
        digest.update([0]);
        digest.update(sha2::Sha256::digest(&bytes));
        let binary = Binary::open(path).map_err(|e| error(e.to_string()))?;
        let elf = object::File::parse(&*bytes).map_err(|e| error(e.to_string()))?;
        let (empty, strong_here) = weak_facts(&binary, &elf);
        strong.extend(strong_here);
        let program = rampage_analysis::functions::analyze(&binary).map_err(|e| error(e.to_string()))?;
        let calls = call_sequences(&binary, &program);
        let symbols: BTreeMap<u64, String> = canonical_functions(&binary)
            .into_iter()
            .map(|(address, symbol)| (address, canonical_name(&symbol.name).into_owned()))
            .collect();
        analysed.push((binary.arch.to_string(), calls, symbols, empty));
    }
    // Override points by name: empty and weak in some reference, and non-weak in none (application hooks, linker
    // symbols, the HAL's weak defaults, whose -O0 builds are not empty). A stub of a routine another reference
    // defines non-weak (memset in a FreeRTOS reference) is that routine.
    let overrides: BTreeSet<String> = analysed
        .iter()
        .flat_map(|(_, _, symbols, empty)| empty.iter().filter_map(|address| symbols.get(address)))
        .filter(|name| !strong.contains(*name))
        .cloned()
        .collect();
    let excluded = |symbols: &BTreeMap<u64, String>, empty: &BTreeSet<u64>, address: &u64| {
        empty.contains(address) || symbols.get(address).is_some_and(|name| overrides.contains(name))
    };
    let mut excluded_count = 0usize;
    for (_, _, symbols, empty) in &analysed {
        excluded_count += symbols.keys().filter(|address| excluded(symbols, empty, address)).count();
    }
    // The names some reference defines as a real function.
    let defined: BTreeSet<&String> = analysed
        .iter()
        .flat_map(|(_, _, symbols, empty)| {
            symbols.iter().filter(|(address, _)| !excluded(symbols, empty, address)).map(|(_, name)| name)
        })
        .collect();
    let mut sequences = Vec::new();
    for (arch, calls, symbols, empty) in &analysed {
        let callee = |target: &u64| symbols.get(target).filter(|name| defined.contains(name)).cloned();
        for (caller, targets) in calls {
            // An override point's body is no library function's sequence.
            let Some(name) = symbols.get(caller).filter(|_| !excluded(symbols, empty, caller)) else { continue };
            sequences.push((arch.clone(), name.clone(), targets.iter().map(callee).collect::<Vec<_>>()));
        }
    }
    let source = format!(
        "tools/embedded-signatures training references ({}): {} ELFs, sha256 {}",
        compilers.into_iter().collect::<Vec<_>>().join(", "),
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
    eprintln!(
        "{source}: {} callers, {total} sequences, {excluded_count} override points left out, {} bytes gzip",
        graph.callers(),
        gzip.len()
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_out_references_are_refused_and_training_compilers_recorded() {
        let tag = |name: &str| training_compiler(Path::new(name));
        assert_eq!(tag("freertos-V11.1.0-gcc12.3.1-m0-full-Os.elf").unwrap(), "gcc12.3.1");
        assert_eq!(tag("compiler-rt-22.1.8-clang22.1.8-m0-O2.elf").unwrap(), "clang22.1.8");
        assert!(tag("newlib-gcc14.3.1-m4f.elf").unwrap_err().contains("held-out"));
        assert!(tag("compiler-rt-22.1.8-clang23.1.5-m3-Os.elf").unwrap_err().contains("held-out"));
        assert!(tag("unnamed.elf").is_err());
    }
}
