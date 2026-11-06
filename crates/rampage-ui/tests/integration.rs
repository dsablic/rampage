//! The crate's integration tests build into this one test binary, one module per `tests/*.rs` file, so an edit
//! relinks one executable instead of one per file. Select a file's tests with `--test integration <file>::`.

mod debug_cpp_virtuals;
mod debug_layout;
mod debugger;
mod debugger_workspace;
mod debugger_workspace_live;
mod module_references;
mod project_workspace;
// The reference images are rendered through Metal; other hosts have no matching renderer.
#[cfg(target_os = "macos")]
mod snapshots;
