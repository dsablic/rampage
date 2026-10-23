//! The crate's integration tests build into this one test binary, one module per `tests/*.rs` file, so an edit
//! relinks one executable instead of one per file. Select a file's tests with `--test integration <file>::`.

mod abi;
mod be8;
mod context;
mod darwin_abi;
mod darwin_narrow;
mod globals;
mod initialization;
mod layout;
mod local_variables;
mod memory;
mod results;
mod symbols;
mod type_hints;
mod type_library;
