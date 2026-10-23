//! The crate's integration tests build into this one test binary, one module per `tests/*.rs` file, so an edit
//! relinks one executable instead of one per file. Select a file's tests with `--test integration <file>::`.

mod a64;
mod a64_switch;
mod aarch32;
mod flow;
mod indirect;
mod native_semantics;
mod operands;
mod semantics;
mod support;
mod x86_switch;
