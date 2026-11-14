//! Builds the embedded Thumb signature database (hash scheme 3) from symbolized reference ELFs that
//! `tools/embedded-signatures/build.py refs` links from library archives and sources.
//!
//! Each reference function is hashed over the extents function discovery finds for it, both in the reference and
//! in a stripped copy (discovery in a stripped target cannot tell that a call to an unnamed `abort` never returns,
//! so it can run on past it), and over its symbol size only when discovery finds neither. A masked hash two names
//! share stops answering for good (collision-safe union). Raw exact fallbacks are layout-specific and never match
//! another firmware link, so none ship, nor their tombstones. The one-instruction link stubs the references carry
//! for symbols nothing defines never pass the confidence gate, so they are never signed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use clap::Parser;
use rampage_loaders::Binary;
use rampage_signatures::{LITERAL_POOL_SCHEME, MaskContext, SignatureDb, canonical_functions, function_hash_scheme};

#[derive(Parser)]
struct Arguments {
    /// Where to write the database JSON.
    #[arg(long)]
    output: PathBuf,
    /// Also write the database as deterministic gzip (the bundled asset form).
    #[arg(long)]
    gzip: Option<PathBuf>,
    /// Symbolized reference ELFs.
    references: Vec<PathBuf>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The masked hashes of `binary`'s functions over their symbol sizes (`symbol`) and over the given extents
/// (`discovered`), for functions discovery found.
fn extent_hashes(
    binary: &Binary,
    extents: &[&BTreeMap<u64, u64>],
    symbol: &mut BTreeSet<String>,
    discovered: &mut BTreeSet<String>,
) {
    let target = binary.target();
    let image = MaskContext::from_binary(binary);
    let hash = |address: u64, end: u64| {
        let bytes = binary.read(address, end.checked_sub(address)?)?;
        function_hash_scheme(LITERAL_POOL_SCHEME, &target, &image, bytes, address).map(|hash| hex(&hash))
    };
    for function in canonical_functions(binary).values() {
        let ends: Vec<u64> = extents.iter().filter_map(|extents| extents.get(&function.address).copied()).collect();
        if ends.is_empty() {
            continue;
        }
        symbol.extend(hash(function.address, function.address.saturating_add(function.size)));
        discovered.extend(ends.into_iter().filter_map(|end| hash(function.address, end)));
    }
}

fn run(arguments: Arguments) -> Result<(), String> {
    let mut database: Option<SignatureDb> = None;
    let (mut symbol_hashes, mut discovered_hashes) = (BTreeSet::new(), BTreeSet::new());
    let scratch = arguments.output.with_extension("stripped.tmp");
    for path in &arguments.references {
        let error = |error: String| format!("{}: {error}", path.display());
        let binary = Binary::open(path).map_err(|e| error(e.to_string()))?;
        let symbolized = rampage_eval::discovered_extents(&binary).map_err(|e| error(e.to_string()))?;
        let image = std::fs::read(path).map_err(|e| error(e.to_string()))?;
        std::fs::write(&scratch, rampage_eval::strip(&image, false)?).map_err(|e| error(e.to_string()))?;
        let stripped = Binary::open(&scratch).map_err(|e| error(e.to_string()))?;
        let stripped = rampage_eval::discovered_extents(&stripped).map_err(|e| error(e.to_string()))?;
        extent_hashes(&binary, &[&symbolized, &stripped], &mut symbol_hashes, &mut discovered_hashes);
        match &mut database {
            Some(database) if database.arch() != binary.arch => {
                return Err(error(format!("{} is not the database's {}", binary.arch, database.arch())));
            }
            Some(database) => database.extend_from_binary_with_extents(&binary, &symbolized),
            None => {
                let built = SignatureDb::from_binary_with_extents_in_scheme(&binary, &symbolized, LITERAL_POOL_SCHEME);
                database = Some(built);
            }
        }
        if let Some(database) = &mut database {
            database.extend_from_binary_with_extents(&binary, &stripped);
        }
    }
    let _ = std::fs::remove_file(&scratch);
    let mut database = database.ok_or("give at least one reference")?;
    database.withhold_exact_fallbacks();

    // Identification hashes discovered extents only: a symbol-size answer (one that spans a trailing literal pool)
    // for a function discovery found never matches. Exact tombstones guard only later merges of exact answers,
    // which this database has none of.
    let mut json: serde_json::Value = serde_json::from_str(&database.to_json()).map_err(|error| error.to_string())?;
    let entries = json["entries"].as_object_mut().ok_or("database without entries")?;
    let before = entries.len();
    entries.retain(|hash, _| !symbol_hashes.contains(hash) || discovered_hashes.contains(hash));
    let dropped = before - entries.len();
    json.as_object_mut().ok_or("database is not an object")?.remove("ambiguous_exact");
    let text = serde_json::to_string(&json).map_err(|error| error.to_string())?;
    let database = SignatureDb::from_json(&text).map_err(|error| error.to_string())?;
    std::fs::write(&arguments.output, database.to_json())
        .map_err(|error| format!("{}: {error}", arguments.output.display()))?;
    if let Some(path) = &arguments.gzip {
        let gzip = database.to_gzip().map_err(|error| error.to_string())?;
        std::fs::write(path, gzip).map_err(|error| format!("{}: {error}", path.display()))?;
    }
    eprintln!(
        "{} references: {} signatures, {} callee keys, {dropped} symbol-size answers dropped",
        arguments.references.len(),
        database.len(),
        database.callee_keys()
    );
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("embedded signatures: {error}");
            std::process::ExitCode::from(2)
        }
    }
}
