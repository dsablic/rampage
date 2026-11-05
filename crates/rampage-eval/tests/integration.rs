//! The crate's integration tests build into this one test binary, one module per `tests/*.rs` file, so an edit
//! relinks one executable instead of one per file. Select a file's tests with `--test integration <file>::`.

mod agent_bench;
mod cli;
mod dwarf_truth;
mod evaluate;
mod parity_agent;
mod parity_cli;
mod parity_graph;
mod parity_health;
mod parity_opencode;
mod parity_tasks;
mod strip_mips;
