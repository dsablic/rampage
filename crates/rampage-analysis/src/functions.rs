use std::collections::BTreeMap;

use rampage_arch::{Flow, UnsupportedArch, decoder_for};
use rampage_loaders::{Binary, SymbolKind};
use serde::Serialize;

use crate::discover::{Program, discover};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Function {
    #[serde(serialize_with = "rampage_arch::hex::address")]
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

/// Sections that hold one small jump-through-a-slot stub per import.
const STUB_SECTIONS: [&str; 6] = ["__stubs", "__auth_stubs", ".plt", ".plt.sec", ".plt.got", ".iplt"];

/// Names the stubs in stub sections (Mach-O `__stubs`, ELF `.plt`) after the import whose slot each one jumps
/// through. A stub runs from just after the previous one's final jump (skipping NOP padding) to its own.
pub fn stub_names(binary: &Binary) -> Vec<(u64, String)> {
    let Ok(mut decoder) = decoder_for(binary.arch) else { return Vec::new() };
    let slot_name = |address: u64| {
        let index = binary.import_slots.binary_search_by_key(&address, |slot| slot.address).ok()?;
        Some(binary.import_slots[index].name.as_str())
    };
    let mut names = Vec::new();
    for section in binary.sections.iter().filter(|section| STUB_SECTIONS.contains(&section.name.as_str())) {
        let end = section.address.saturating_add(section.size);
        let mut address = section.address;
        let mut stub_start = address;
        let mut named = false;
        decoder.reset();
        while address < end {
            let Some(bytes) = binary.code_from(address) else { break };
            let insn = decoder.decode(bytes, address);
            let next = address + u64::from(insn.len.max(1));
            if stub_start == address && decoder.format(bytes, address).starts_with("nop") {
                stub_start = next;
            } else if let Some(name) = insn.data_ref.and_then(slot_name).filter(|_| !named) {
                names.push((stub_start, name.to_owned()));
                named = true;
            }
            if matches!(insn.flow, Flow::IndirectJump | Flow::Jump(_) | Flow::Return | Flow::Halt | Flow::Invalid) {
                stub_start = next;
                named = false;
                decoder.reset();
            }
            address = next;
        }
    }
    names
}

/// Names import thunks found by analysis outside stub sections: functions that consist of a single jump through
/// an import slot (MinGW and incrementally linked PE images have these in `.text`).
pub fn thunk_names(binary: &Binary, program: &Program) -> Vec<(u64, String)> {
    let Ok(mut decoder) = decoder_for(binary.arch) else { return Vec::new() };
    program
        .functions
        .iter()
        .filter(|function| function.instruction_count == 1)
        .filter_map(|function| {
            let insn = decoder.decode(binary.code_from(function.address)?, function.address);
            if insn.flow != Flow::IndirectJump {
                return None;
            }
            let slot = insn.data_ref?;
            let index = binary.import_slots.binary_search_by_key(&slot, |slot| slot.address).ok()?;
            Some((function.address, binary.import_slots[index].name.clone()))
        })
        .collect()
}

/// Names for addresses: function symbols first, then exports, the entry point and other symbols, then import
/// stubs (named after their import) and import slots (`__imp_` and the import's name).
pub struct Names(BTreeMap<u64, String>);

impl Names {
    pub fn new(binary: &Binary) -> Self {
        let mut names: BTreeMap<u64, String> =
            from_symbols(binary).into_iter().map(|function| (function.address, function.name)).collect();
        for symbol in &binary.symbols {
            names.entry(symbol.address).or_insert_with(|| symbol.name.clone());
        }
        for (address, name) in stub_names(binary) {
            names.entry(address).or_insert(name);
        }
        for slot in &binary.import_slots {
            names.entry(slot.address).or_insert_with(|| format!("__imp_{}", slot.name));
        }
        Self(names)
    }

    /// Adds names for addresses that have none yet.
    pub fn extend(&mut self, names: impl IntoIterator<Item = (u64, String)>) {
        for (address, name) in names {
            self.0.entry(address).or_insert(name);
        }
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
