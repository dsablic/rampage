//! WebAssembly module inspection on any file. The project loaders open native executables only, so a `.wasm` file
//! is read here directly, without a Project.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use rampage_loaders::wasm::{WasmExport, WasmFunction, WasmImport, WasmModule};
use serde::{Deserialize, Serialize};

use crate::ApiError;
use crate::pyinstaller::fit_page;

/// The most list items one page returns.
pub const MAX_WASM_PAGE: usize = 100;

/// Which list a [`wasm_module`] call pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WasmList {
    /// Imports with their module, name, kind and type.
    Imports,
    /// Exports with their name, kind and index.
    Exports,
    /// Functions (imported first) with their type signature, body size and `name`-section name.
    Functions,
}

impl FromStr for WasmList {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        match text {
            "imports" => Ok(Self::Imports),
            "exports" => Ok(Self::Exports),
            "functions" => Ok(Self::Functions),
            _ => Err(format!("unknown list `{text}` (expected imports, exports or functions)")),
        }
    }
}

/// A module summary, with one page of `list` when one was asked for.
#[derive(Debug, Serialize)]
pub struct WasmModulePage {
    pub file_path: PathBuf,
    #[serde(flatten)]
    pub module: WasmModule,
    pub list: Option<WasmList>,
    /// Items of `list` retained by the parse (see `complete`); null without a list.
    pub total: Option<usize>,
    pub offset: usize,
    pub limit: usize,
    pub returned: usize,
    pub more: bool,
    pub next_offset: Option<usize>,
    pub byte_capped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imports: Option<Vec<WasmImport>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exports: Option<Vec<WasmExport>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<Vec<WasmFunction>>,
}

/// Summarises the WebAssembly binary at `path`, paging `list` by `offset` and `limit` (default and at most
/// [`MAX_WASM_PAGE`]); `None` when the file does not start with the `\0asm` magic.
pub fn wasm_module(
    path: &Path,
    list: Option<WasmList>,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<Option<WasmModulePage>, ApiError> {
    let limit = limit.unwrap_or(MAX_WASM_PAGE);
    if !(1..=MAX_WASM_PAGE).contains(&limit) {
        return Err(ApiError::Invalid(format!("limit must be in 1..={MAX_WASM_PAGE}")));
    }
    let Some(mut module) =
        rampage_loaders::wasm::wasm_file(path).map_err(|source| ApiError::Load { path: path.to_owned(), source })?
    else {
        return Ok(None);
    };
    if module.supported {
        module.limitations.push(
            "Parsed, not validated: no type checking, compilation or execution; code bodies are sized, not decoded."
                .to_owned(),
        );
    }
    let (imports, exports, functions) = (
        std::mem::take(&mut module.imports),
        std::mem::take(&mut module.exports),
        std::mem::take(&mut module.functions),
    );
    let offset = offset.unwrap_or(0);
    let mut page = WasmModulePage {
        file_path: path.to_owned(),
        module,
        list,
        total: None,
        offset,
        limit,
        returned: 0,
        more: false,
        next_offset: None,
        byte_capped: false,
        imports: None,
        exports: None,
        functions: None,
    };
    match list {
        None => {}
        Some(WasmList::Imports) => page.imports = Some(page_of(&mut page, &imports)?),
        Some(WasmList::Exports) => page.exports = Some(page_of(&mut page, &exports)?),
        Some(WasmList::Functions) => page.functions = Some(page_of(&mut page, &functions)?),
    }
    page.next_offset = page.more.then_some(offset + page.returned);
    Ok(Some(page))
}

/// One page of `items`, recording its paging facts in `page`.
fn page_of<T: Serialize + Clone>(page: &mut WasmModulePage, items: &[T]) -> Result<Vec<T>, ApiError> {
    let window = fit_page(items, page.offset, page.limit, page)?;
    page.total = Some(items.len());
    (page.returned, page.more, page.byte_capped) = (window.items.len(), window.more, window.byte_capped);
    Ok(window.items)
}
