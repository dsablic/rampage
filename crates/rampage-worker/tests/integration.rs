//! The crate's integration tests build into this one test binary, one module per `tests/*.rs` file, so an edit
//! relinks one executable instead of one per file. Select a file's tests with `--test integration <file>::`.

mod api;
mod cli;
mod debug_cpp_layout_acceptance;
mod debug_cpp_virtuals;
mod debug_layout_acceptance;
mod entry_measurements;
mod entry_scope;
mod local_variables;
mod measurements;
mod smoke;
mod type_hints;
mod type_library;
