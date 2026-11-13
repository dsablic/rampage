//! The crate's integration tests build into this one test binary, one module per `tests/*.rs` file, so an edit
//! relinks one executable instead of one per file. Select a file's tests with `--test integration <file>::`.

mod capture_identity;
mod classes_named_bounded;
mod code_integrity;
mod compiled_classes;
mod compiled_switches;
mod control;
mod dataflow;
mod diagnostic_candidates;
mod entry_audit;
mod fixtures;
mod integer_families;
mod metadata;
mod objc_dispatch;
mod pseudocode;
mod reaching_store;
mod rtti;
mod rtti_fixture;
mod simplify;
mod ssa;
mod stack_registers;
mod structure;
mod structure_execution;
mod switch_structure;
mod tail_calls;
mod type_evidence;
