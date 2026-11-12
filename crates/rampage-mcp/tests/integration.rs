//! The crate's integration tests build into this one test binary, one module per `tests/*.rs` file, so an edit
//! relinks one executable instead of one per file. Select a file's tests with `--test integration <file>::`.

mod archive;
mod arm_exidx;
mod assembly;
mod build_info;
mod compression;
mod contract;
#[path = "../../../tests/contract/support.rs"]
mod contract_support;
mod debug_control;
mod debug_layouts;
mod debug_types;
mod debugger;
mod decode;
mod entry_scope;
mod ergonomics;
mod file_layout;
mod findings;
mod flywheel;
mod function_frame;
mod inspect_sleigh;
mod local_variables;
mod patches;
mod pdb;
#[path = "../../../tests/fixtures/pdb/support.rs"]
#[allow(dead_code)]
mod pdb_support;
mod pe_metadata;
mod raw_code;
mod raw_project;
mod runtime_compare;
mod search;
mod server;
mod signature_import;
mod signature_paging;
mod type_library;
mod type_propagation;
mod typed_data;
mod wasm_pyinstaller;
