use std::collections::BTreeMap;

use rampage_loaders::{Binary, SymbolKind};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Function {
    pub address: u64,
    pub size: u64,
    pub name: String,
}

/// Functions known from metadata alone: function symbols, exports into executable memory, and the entry point.
pub fn from_symbols(binary: &Binary) -> Vec<Function> {
    let executable = |address| binary.segment_containing(address).is_some_and(|segment| segment.perms.execute);
    let mut by_address: BTreeMap<u64, Function> = BTreeMap::new();

    let symbols = binary
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Function)
        .map(|symbol| (symbol.address, symbol.size, symbol.name.as_str()));
    let exports = binary.exports.iter().map(|export| (export.address, 0, export.name.as_str()));
    let entry = binary.entry.map(|entry| (entry, 0, "entry"));

    for (address, size, name) in symbols.chain(exports).chain(entry) {
        if !executable(address) {
            continue;
        }
        by_address
            .entry(address)
            .and_modify(|function| function.size = function.size.max(size))
            .or_insert_with(|| Function { address, size, name: name.to_owned() });
    }
    by_address.into_values().collect()
}
