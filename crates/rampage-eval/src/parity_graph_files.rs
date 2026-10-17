use std::path::Path;
use std::process::ExitCode;

use rampage_eval::parity_graph::{GraphReceipt, GraphRequest, compare_exports};

pub(super) fn compare(request: &Path, rampage: &Path, ghidra: &Path) -> Result<GraphReceipt, String> {
    let request: GraphRequest =
        serde_json::from_str(&super::read(request)?).map_err(|error| format!("{}: {error}", request.display()))?;
    compare_exports(&request, &super::read(rampage)?, &super::read(ghidra)?).map_err(|error| error.to_string())
}

pub(super) fn print(request: &Path, rampage: &Path, ghidra: &Path) -> Result<ExitCode, String> {
    let report = compare(request, rampage, ghidra)?;
    println!("{}", serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?);
    Ok(ExitCode::SUCCESS)
}
