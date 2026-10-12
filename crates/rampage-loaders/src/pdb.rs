//! Reads function symbols from a Microsoft PDB, so PE binaries built with MSVC gain real names and addresses the
//! way IDA and Ghidra use a PDB. This is a bounded reader of an untrusted file: it never panics, caps what it
//! collects, and turns per-symbol problems into warnings rather than failing the whole read.
//!
//! Addresses are relative virtual addresses (RVAs). A caller adds the image base to get a virtual address, or
//! looks each RVA up in the loaded image's section layout. Names are returned as stored (MSVC-mangled for C++);
//! demangling belongs to the analysis layer, which already handles MSVC names.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ::pdb::{FallibleIterator, PDB, SymbolData};
use serde::Serialize;

use crate::LoadError;
use crate::warnings::CappedWarnings;

/// Caps for an untrusted file: enough for real programs, bounded against a hostile or corrupt PDB.
const MAX_FUNCTIONS: usize = 2_000_000;
const MAX_NAME_BYTES: usize = 4096;
const WARNINGS: CappedWarnings = CappedWarnings::new(1024, "PDB");

#[derive(Debug, Default, Serialize)]
pub struct PdbReport {
    pub functions: Vec<PdbFunction>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PdbFunction {
    /// Relative virtual address (image base not yet added).
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
}

impl PdbReport {
    fn warn(&mut self, warning: String) {
        WARNINGS.push(&mut self.warnings, warning);
    }
}

/// The conventional sidecar PDB path for an image: the image path with a `.pdb` extension.
pub fn sidecar_pdb_path(image_path: &Path) -> PathBuf {
    image_path.with_extension("pdb")
}

/// Reads function symbols from the PDB at `path`. Returns a clean error for a missing or unrecognizable file;
/// a readable PDB with internal problems yields a report whose `warnings` explain what was skipped.
pub fn pdb_symbols(path: &Path) -> Result<PdbReport, LoadError> {
    let file = std::fs::File::open(path).map_err(|source| LoadError::Io { path: path.to_path_buf(), source })?;
    read_pdb(file)
}

/// Reads function symbols from any seekable PDB source (a file, or in-memory bytes for tests).
fn read_pdb<'s, S: ::pdb::Source<'s> + 's>(source: S) -> Result<PdbReport, LoadError> {
    let mut report = PdbReport::default();
    let mut pdb = PDB::open(source).map_err(|error| LoadError::Malformed(format!("not a readable PDB: {error}")))?;
    let address_map = match pdb.address_map() {
        Ok(map) => map,
        // Without the section address map, section:offset cannot become an RVA, so no addresses can be produced.
        Err(error) => {
            report.warn(format!("PDB has no usable address map: {error}"));
            return Ok(report);
        }
    };

    // Keyed by address so a public and a procedure symbol for one function do not both appear; the first
    // name for an address wins (procedures are visited first and carry the truer function name).
    let mut functions: BTreeMap<u64, String> = BTreeMap::new();

    // Per-module procedures carry the most accurate function names and extents.
    match pdb.debug_information() {
        Ok(debug_information) => match debug_information.modules() {
            Ok(mut modules) => {
                let mut module_error_reported = false;
                while functions.len() < MAX_FUNCTIONS {
                    let module = match modules.next() {
                        Ok(Some(module)) => module,
                        Ok(None) => break,
                        Err(error) => {
                            report.warn(format!("stopped reading PDB modules: {error}"));
                            break;
                        }
                    };
                    let info = match pdb.module_info(&module) {
                        Ok(Some(info)) => info,
                        Ok(None) => continue,
                        Err(error) => {
                            if !module_error_reported {
                                report.warn(format!("skipped a PDB module: {error}"));
                                module_error_reported = true;
                            }
                            continue;
                        }
                    };
                    let symbols = match info.symbols() {
                        Ok(symbols) => symbols,
                        Err(error) => {
                            report.warn(format!("skipped a PDB module's symbols: {error}"));
                            continue;
                        }
                    };
                    collect_procedures(symbols, &address_map, &mut functions, &mut report);
                }
            }
            Err(error) => report.warn(format!("PDB module list unavailable: {error}")),
        },
        Err(error) => report.warn(format!("PDB debug information unavailable: {error}")),
    }

    // Global and public symbols fill in functions without per-module debug info (common in stripped-down PDBs).
    match pdb.global_symbols() {
        Ok(globals) => collect_procedures(globals.iter(), &address_map, &mut functions, &mut report),
        Err(error) => report.warn(format!("PDB global symbols unavailable: {error}")),
    }

    report.functions = functions.into_iter().map(|(address, name)| PdbFunction { address, name }).collect();
    Ok(report)
}

/// Records a function RVA and name, honoring the count and name-length caps.
fn insert_function(functions: &mut BTreeMap<u64, String>, report: &mut PdbReport, rva: u32, name: String) {
    if functions.len() >= MAX_FUNCTIONS {
        return;
    }
    if name.len() > MAX_NAME_BYTES {
        report.warn("PDB symbol name too long; skipped".to_owned());
        return;
    }
    functions.entry(u64::from(rva)).or_insert(name);
}

/// Collects procedure and function-public symbols from one symbol stream.
fn collect_procedures(
    mut symbols: ::pdb::SymbolIter<'_>,
    address_map: &::pdb::AddressMap<'_>,
    functions: &mut BTreeMap<u64, String>,
    report: &mut PdbReport,
) {
    loop {
        if functions.len() >= MAX_FUNCTIONS {
            break;
        }
        let symbol = match symbols.next() {
            Ok(Some(symbol)) => symbol,
            Ok(None) => break,
            // A single malformed record should not discard the rest of the stream.
            Err(error) => {
                report.warn(format!("stopped reading a PDB symbol stream: {error}"));
                break;
            }
        };
        match symbol.parse() {
            Ok(SymbolData::Procedure(procedure)) => {
                if let Some(rva) = procedure.offset.to_rva(address_map) {
                    insert_function(functions, report, rva.0, procedure.name.to_string().into_owned());
                }
            }
            Ok(SymbolData::Public(public)) if public.function || public.code => {
                if let Some(rva) = public.offset.to_rva(address_map) {
                    insert_function(functions, report, rva.0, public.name.to_string().into_owned());
                }
            }
            // Other symbol kinds (data, constants, scopes) are not functions.
            Ok(_) => {}
            Err(::pdb::Error::UnimplementedSymbolKind(_)) => {}
            Err(error) => report.warn(format!("skipped a PDB symbol: {error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn non_pdb_bytes_are_a_clean_error_not_a_panic() {
        let bytes = Cursor::new(b"not a pdb file at all".to_vec());
        assert!(matches!(read_pdb(bytes), Err(LoadError::Malformed(_))));
    }

    #[test]
    fn truncated_pdb_magic_is_a_clean_error() {
        // The first bytes of the Microsoft PDB magic, then nothing: must not panic.
        let bytes = Cursor::new(b"Microsoft C/C++ MSF 7.00".to_vec());
        assert!(read_pdb(bytes).is_err());
    }

    #[test]
    fn empty_input_is_a_clean_error() {
        assert!(read_pdb(Cursor::new(Vec::new())).is_err());
    }

    #[test]
    fn missing_file_reports_io_error() {
        let error = pdb_symbols(Path::new("/nonexistent/does-not-exist.pdb")).unwrap_err();
        assert!(matches!(error, LoadError::Io { .. }));
    }

    #[test]
    fn sidecar_path_swaps_the_extension() {
        assert_eq!(sidecar_pdb_path(Path::new("/tmp/app.exe")), PathBuf::from("/tmp/app.pdb"));
    }
}
