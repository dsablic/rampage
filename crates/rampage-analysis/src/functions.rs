use std::collections::{BTreeMap, BTreeSet, HashMap};

use rampage_arch::Arch;
use rampage_arch::{Flow, UnsupportedArch};
use rampage_loaders::{Binary, Format, SectionKind, SymbolKind};
use serde::Serialize;

use crate::discover::{Program, discover_with_noreturn};
use crate::noreturn::return_facts;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Function {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub size: u64,
    pub name: String,
}

/// The name analysis makes up for a function that has no other: `sub_` and the lowercase hex address, without
/// leading zeros (`sub_401000`).
pub fn default_name(address: u64) -> String {
    format!("sub_{address:x}")
}

/// Whether `name` is exactly [`default_name`] of `address`. A real symbol that merely starts with `sub_`
/// (`sub_menu_init`), or the default name of another address, is not.
pub fn is_default_name(name: &str, address: u64) -> bool {
    name == default_name(address)
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

/// Discovers functions by recursive descent from every metadata seed, with the callees named in
/// [`crate::noreturn`] known not to return.
pub fn analyze(binary: &Binary) -> Result<Program, UnsupportedArch> {
    binary.decoder()?;
    let mut seeds: Vec<u64> = from_symbols(binary).iter().map(|function| function.address).collect();
    seeds.extend(&binary.function_starts);
    seeds.extend(stub_seeds(binary));
    seeds.extend(thunk_seeds(binary));
    let decoder = || binary.decoder().expect("architecture checked above");
    Ok(discover_with_noreturn(binary, decoder, &seeds, &return_facts(binary)))
}

/// Function entries in the stub sections: each section's first stub (the ELF PLT[0] resolver) and every named
/// import stub. These are real functions even when nothing in the discovered code calls them directly, such as
/// the resolver or a lazily-bound or otherwise unreferenced stub, so seeding them improves discovery recall.
fn stub_seeds(binary: &Binary) -> Vec<u64> {
    let mut seeds: Vec<u64> = binary
        .sections
        .iter()
        .filter(|section| STUB_SECTIONS.contains(&section.name.as_str()) && section.size > 0)
        .map(|section| section.address)
        .collect();
    seeds.extend(stub_names(binary).into_iter().map(|(address, _)| address));
    seeds
}

/// Sections that hold one small jump-through-a-slot stub per import.
const STUB_SECTIONS: [&str; 6] = ["__stubs", "__auth_stubs", ".plt", ".plt.sec", ".plt.got", ".iplt"];

/// Padding before a stub: a nop (s390x spells it `bcr 0, %r0`), or fill of one repeated byte (lld's 0xd4 traps on
/// ARM, int3, zeros).
fn is_padding(code: &[u8], text: &str) -> bool {
    text.starts_with("nop") || text.starts_with("bcr 0,") || code.iter().all(|&byte| Some(&byte) == code.first())
}

/// Names the stubs in stub sections (Mach-O `__stubs`, ELF `.plt`) after the import whose slot each one jumps
/// through. A stub runs from just after the previous one's final jump (skipping NOP padding) to its own.
pub fn stub_names(binary: &Binary) -> Vec<(u64, String)> {
    let Ok(mut decoder) = binary.decoder() else { return Vec::new() };
    let slot_name = |address| binary.import_slot(address).map(|slot| slot.name.as_str());
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
            if stub_start == address
                && is_padding(&bytes[..usize::from(insn.len).min(bytes.len())], &decoder.format(bytes, address))
            {
                stub_start = next;
            } else if let Some(name) = insn.data_ref.and_then(slot_name).filter(|_| !named) {
                // ELF stubs take objdump's `@plt` suffix: in a shared library the import may be one of its own
                // exported functions, whose name the stub must not take.
                let name = if binary.format == Format::Elf { format!("{name}@plt") } else { name.to_owned() };
                names.push((stub_start, name));
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

/// Names PE import thunks outside stub sections after their import: `jmp [slot]` instructions in code
/// (MinGW and incrementally linked images put these in `.text`). Found by scanning, so names never depend on
/// whether analysis has run.
pub fn thunk_names(binary: &Binary) -> Vec<(u64, String)> {
    if binary.format != Format::Pe || !matches!(binary.arch, Arch::X86 | Arch::X86_64) {
        return Vec::new();
    }
    let slot_name = |address| binary.import_slot(address).map(|slot| slot.name.clone());
    let mut names = Vec::new();
    for section in binary.sections.iter().filter(|section| section.kind == SectionKind::Code) {
        let Some(bytes) = binary.read(section.address, section.size) else { continue };
        for (offset, window) in bytes.windows(6).enumerate() {
            // FF 25 disp32: jmp [rip + disp32] on x86-64, jmp [disp32] on x86.
            if window[0] != 0xff || window[1] != 0x25 {
                continue;
            }
            let displacement = i32::from_le_bytes(window[2..6].try_into().unwrap());
            let address = section.address + offset as u64;
            let slot = match binary.arch {
                Arch::X86_64 => address.wrapping_add(6).wrapping_add(displacement as i64 as u64),
                _ => u64::from(displacement as u32),
            };
            if let Some(name) = slot_name(slot) {
                names.push((address, name));
            }
        }
    }
    names
}

/// The PE import thunks that are functions of their own, so a jump to one is a tail call to the import rather than
/// a block of the one function that jumps there. A thunk follows padding (`int3`, `nop`), another thunk or the
/// start of its section; a `jmp [slot]` right after other code ends that code's function instead.
fn thunk_seeds(binary: &Binary) -> Vec<u64> {
    let thunks: BTreeSet<u64> = thunk_names(binary).into_iter().map(|(address, _)| address).collect();
    let starts_function = |address: u64| {
        let previous = address.checked_sub(1).filter(|&previous| binary.is_code(previous));
        match previous.and_then(|previous| binary.read(previous, 1)) {
            None => true,
            Some(&[byte]) => matches!(byte, 0xcc | 0x90) || thunks.contains(&address.wrapping_sub(6)),
            Some(_) => false,
        }
    };
    thunks.iter().copied().filter(|&address| starts_function(address)).collect()
}

/// Names for addresses: function symbols first, then exports, the entry point and other symbols, then import
/// stubs and thunks (named after their import, with `@plt` on ELF) and import slots (`__imp_` and the import's
/// name).
pub struct Names {
    names: BTreeMap<u64, String>,
    /// Each name's lowest address.
    addresses: HashMap<String, u64>,
}

impl Names {
    pub fn new(binary: &Binary) -> Self {
        let mut names: BTreeMap<u64, String> =
            from_symbols(binary).into_iter().map(|function| (function.address, function.name)).collect();
        for symbol in &binary.symbols {
            names.entry(symbol.address).or_insert_with(|| symbol.name.clone());
        }
        for (address, name) in stub_names(binary).into_iter().chain(thunk_names(binary)) {
            names.entry(address).or_insert(name);
        }
        for slot in &binary.import_slots {
            names.entry(slot.address).or_insert_with(|| format!("__imp_{}", slot.name));
        }
        let mut addresses = HashMap::with_capacity(names.len());
        for (&address, name) in &names {
            addresses.entry(name.clone()).or_insert(address);
        }
        let mut display_counts = HashMap::new();
        let displays: BTreeMap<_, _> = names
            .iter()
            .filter_map(|(&address, name)| {
                crate::language::demangle(name).map(|display| {
                    *display_counts.entry(display.clone()).or_insert(0usize) += 1;
                    (address, display)
                })
            })
            .collect();
        for (&address, name) in &names {
            addresses.entry(name.clone()).or_insert(address);
            if let Some(display) = displays.get(&address).filter(|display| {
                display_counts[*display] == 1 && addresses.get(*display).is_none_or(|at| *at == address)
            }) {
                addresses.entry(display.clone()).or_insert(address);
            }
        }
        for (address, name) in &mut names {
            if let Some(display) = displays
                .get(address)
                .filter(|display| display_counts[*display] == 1 && addresses.get(*display) == Some(address))
            {
                *name = display.clone();
            }
        }
        Self { names, addresses }
    }

    pub fn get(&self, address: u64) -> Option<&str> {
        self.names.get(&address).map(String::as_str)
    }

    pub fn function_name(&self, address: u64) -> String {
        self.get(address).map_or_else(|| default_name(address), str::to_owned)
    }

    /// Resolves a name back to its address.
    pub fn address_of(&self, name: &str) -> Option<u64> {
        self.addresses.get(name).copied()
    }
}
