use std::collections::BTreeMap;

use rampage_arch::{UnsupportedArch, decoder_for};
use rampage_loaders::{Binary, SymbolKind};
use serde::Serialize;

use crate::discover::{Program, discover};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Function {
    pub address: u64,
    pub size: u64,
    pub name: String,
}

/// Functions known from metadata alone: function symbols, exports into code, and the entry point.
pub fn from_symbols(binary: &Binary) -> Vec<Function> {
    let mut by_address: BTreeMap<u64, Function> = BTreeMap::new();

    let symbols = binary
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Function)
        .map(|symbol| (symbol.address, symbol.size, symbol.name.as_str()));
    let exports = binary.exports.iter().map(|export| (export.address, 0, export.name.as_str()));
    let entry = binary.entry.map(|entry| (entry, 0, "entry"));

    for (address, size, name) in symbols.chain(exports).chain(entry) {
        if !binary.is_code(address) {
            continue;
        }
        by_address
            .entry(address)
            .and_modify(|function| function.size = function.size.max(size))
            .or_insert_with(|| Function { address, size, name: name.to_owned() });
    }
    by_address.into_values().collect()
}

/// Discovers functions by recursive descent from every metadata seed.
pub fn analyze(binary: &Binary) -> Result<Program, UnsupportedArch> {
    let arch = binary.arch;
    decoder_for(arch)?;
    let mut seeds: Vec<u64> = from_symbols(binary).iter().map(|function| function.address).collect();
    seeds.extend(&binary.function_starts);
    Ok(discover(binary, || decoder_for(arch).expect("architecture checked above"), &seeds))
}

/// Names for addresses: function symbols first, then exports, the entry point and other symbols.
pub struct Names(BTreeMap<u64, String>);

impl Names {
    pub fn new(binary: &Binary) -> Self {
        let mut names: BTreeMap<u64, String> =
            from_symbols(binary).into_iter().map(|function| (function.address, function.name)).collect();
        for symbol in &binary.symbols {
            names.entry(symbol.address).or_insert_with(|| symbol.name.clone());
        }
        Self(names)
    }

    pub fn get(&self, address: u64) -> Option<&str> {
        self.0.get(&address).map(String::as_str)
    }

    pub fn function_name(&self, address: u64) -> String {
        self.get(address).map_or_else(|| format!("sub_{address:x}"), str::to_owned)
    }

    /// Resolves a name back to its address.
    pub fn address_of(&self, name: &str) -> Option<u64> {
        self.0.iter().find(|(_, candidate)| candidate.as_str() == name).map(|(&address, _)| address)
    }
}
