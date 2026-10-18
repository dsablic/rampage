//! Opt-in ELF producer range equivalence, not name normalization or version authentication.
use std::collections::{BTreeMap, BTreeSet};

use object::{Object, ObjectSection, ObjectSymbol};
use rampage_eval::{Outcome, Report, Truth, score};
use rampage_loaders::Binary;
use serde::Serialize;

pub const POLICY: &str = "elf-producer-alias-sets-v3";
pub const REFERENCE_POLICY: &str = "unique-strong-default-with-only-weak-default-aliases-source-callee-context-v3";
pub const CALLEE_CONTEXT_POLICY: &str =
    "original_source_canonical_plus_each_definition_view; answer labels independent";

#[derive(Clone, Debug, Serialize)]
pub struct ProducerName {
    pub raw_name: String,
    pub binding: u8,
    pub visibility: u8,
    pub symbol_index: usize,
    pub table: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct AliasSet {
    pub address: u64,
    pub original_symbol_size: u64,
    pub section_index: usize,
    pub section_name: String,
    pub file_offset: u64,
    pub canonical_name: String,
    pub alias_names: Vec<ProducerName>,
    pub scope: &'static str,
    pub proof: &'static str,
}

impl AliasSet {
    pub fn contains(&self, name: &str) -> bool {
        self.alias_names.iter().any(|alias| alias.raw_name == name)
    }

    pub fn admits_owned(&self, name: &str, linked_artifact: bool) -> bool {
        self.alias_names.iter().any(|alias| {
            alias.raw_name == name
                && (linked_artifact
                    || (alias.binding == object::elf::STB_GLOBAL.0 && alias.visibility == object::elf::STV_DEFAULT.0))
        })
    }
}

pub fn producer_alias_sets(binary: &Binary, truth: &Truth) -> Result<BTreeMap<u64, AliasSet>, String> {
    if binary.format != rampage_loaders::Format::Elf {
        return Ok(BTreeMap::new());
    }
    let file = object::File::parse(binary.image_bytes()).map_err(|error| error.to_string())?;
    if !matches!(file.kind(), object::ObjectKind::Executable | object::ObjectKind::Dynamic) {
        return Ok(BTreeMap::new());
    }
    let canonical = rampage_signatures::canonical_functions(binary);
    let mut groups = BTreeMap::<(u64, u64, usize), AliasSet>::new();
    for (table, symbol) in
        file.symbols().map(|symbol| ("symtab", symbol)).chain(file.dynamic_symbols().map(|symbol| ("dynsym", symbol)))
    {
        let object::SymbolFlags::Elf { st_info, st_other } = symbol.flags() else { continue };
        if st_info.st_type() != object::elf::STT_FUNC || !symbol.is_definition() || symbol.size() == 0 {
            continue;
        }
        if symbol.address().checked_add(symbol.size()).is_none() {
            continue;
        }
        let Some(index) = symbol.section_index() else { continue };
        let section = file.section_by_index(index).map_err(|error| error.to_string())?;
        if !matches!(section.flags(), object::SectionFlags::Elf { sh_flags, sh_type }
            if sh_type == object::elf::SHT_PROGBITS && sh_flags.contains(object::elf::SHF_ALLOC)
                && sh_flags.contains(object::elf::SHF_EXECINSTR))
        {
            continue;
        }
        let Some(offset) = symbol.address().checked_sub(section.address()) else { continue };
        let Some(end) = offset.checked_add(symbol.size()) else { continue };
        let Some((file_start, file_size)) = section.file_range() else { continue };
        let Some(file_end) = file_start.checked_add(end) else { continue };
        if end > section.size() || end > file_size || file_end > binary.image_bytes().len() as u64 {
            continue;
        }
        let file_offset = file_start + offset;
        if binary.read(symbol.address(), symbol.size())
            != binary.image_bytes().get(file_offset as usize..file_end as usize)
        {
            continue;
        }
        let Ok(name) = symbol.name() else { continue };
        if name.is_empty() || name.len() > 4096 || name.contains('\0') {
            continue;
        }
        let Some(selected) = canonical.get(&symbol.address()) else { continue };
        if selected.size != symbol.size() || truth.0.get(&symbol.address()) != Some(&selected.name) {
            continue;
        }
        let set = groups.entry((symbol.address(), symbol.size(), index.0)).or_insert_with(|| AliasSet {
            address: symbol.address(),
            original_symbol_size: symbol.size(),
            section_index: index.0,
            section_name: section.name().unwrap_or("").to_owned(),
            file_offset: file_start + offset,
            canonical_name: selected.name.clone(),
            alias_names: Vec::new(),
            scope: "native_elf_sized_function_same_executable_section",
            proof: "ELF STT_FUNC definitions; identical actual VA, exact nonzero size and section; full file backing",
        });
        set.alias_names.push(ProducerName {
            raw_name: name.to_owned(),
            binding: st_info.st_bind().0,
            visibility: st_other.visibility().0,
            symbol_index: symbol.index().0,
            table,
        });
    }
    let mut sets = BTreeMap::new();
    let mut ambiguous = BTreeSet::new();
    for (_, mut set) in groups {
        set.alias_names
            .sort_by(|a, b| (&a.raw_name, a.table, a.symbol_index).cmp(&(&b.raw_name, b.table, b.symbol_index)));
        let names: BTreeSet<_> = set.alias_names.iter().map(|alias| &alias.raw_name).collect();
        if names.len() < 2 || !set.contains(&set.canonical_name) {
            continue;
        }
        let address = set.address;
        if sets.insert(address, set).is_some() {
            ambiguous.insert(address);
        }
    }
    sets.retain(|address, _| !ambiguous.contains(address));
    Ok(sets)
}

#[derive(Debug, Serialize)]
pub struct AcceptedAlias {
    pub raw_name: String,
    #[serde(flatten)]
    pub producer_alias_set: AliasSet,
}

pub fn score_aliases(
    proposed: &[(u64, Option<String>)],
    full: &Truth,
    aliases: &BTreeMap<u64, AliasSet>,
) -> Result<(Report, Vec<AcceptedAlias>), String> {
    let mut report = score(proposed.iter().cloned(), full);
    let mut accepted = Vec::new();
    report.disagreements.retain(|row| {
        let Some(set) = aliases.get(&row.address) else { return true };
        let Some(raw) = row.proposed.as_deref() else { return true };
        if row.outcome != Outcome::Wrong
            || row.truth.as_deref() != Some(set.canonical_name.as_str())
            || !set.contains(raw)
        {
            return true;
        }
        accepted.push(AcceptedAlias { raw_name: raw.to_owned(), producer_alias_set: set.clone() });
        false
    });
    report.wrong = report.wrong.checked_sub(accepted.len()).ok_or("alias score count underflow")?;
    report.correct += accepted.len();
    let named = report.correct + report.wrong + report.spurious;
    report.precision = if named == 0 { 0.0 } else { report.correct as f64 / named as f64 };
    report.recall = report.correct as f64 / full.0.len().max(1) as f64;
    Ok((report, accepted))
}

#[cfg(test)]
#[path = "alias_truth_tests.rs"]
mod tests;
