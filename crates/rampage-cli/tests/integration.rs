//! The crate's integration tests build into this one test binary, one module per `tests/*.rs` file, so an edit
//! relinks one executable instead of one per file. Select a file's tests with `--test integration <file>::`.

mod analyze;
mod archive;
mod assembly;
mod cli;
mod contract;
#[path = "../../../tests/contract/support.rs"]
mod contract_support;
mod debug_layouts;
mod debugger;
mod decompiler_abi;
mod decompiler_diagnostics;
mod detection;
mod entry_scope;
mod ergonomics;
mod format_compat;
mod hierarchy;
mod inspect_sleigh;
mod packs;
mod patches;
mod pdb;
mod pe_metadata;
mod plugin_triage;
mod pointer_observation;
mod raw_project;
mod relocated;
mod report;
mod runtime_compare;
mod search;
mod signature_import;
mod wasm_pyinstaller;
