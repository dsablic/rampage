use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Bound::{Excluded, Unbounded};

use rampage_analysis::noreturn::{is_noreturn_import, is_noreturn_name};
use rampage_arch::{Arch, Flow};
use rampage_decompiler::worker::WorkerOperation;
use rampage_loaders::{Binary, Format, SectionKind, SymbolKind};
use serde::Serialize;

use super::entry::{DecompileEntryRequest, EntryValidation};
use crate::{ApiError, Project, annotations::Annotations};

const MAX_METADATA_RECORDS: usize = 131_072;
const MAX_METADATA_NAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_NAME_BYTES: usize = 4096;
const MAX_ANNOTATION_RECORDS: usize = 8192;
const MAX_ANNOTATION_BYTES: usize = 8 * 1024 * 1024;
const MAX_INSTRUCTIONS: usize = 4096;
const MAX_BYTES: usize = 64 * 1024;
const MAX_BLOCKS: usize = 256;
const MAX_TARGETS: usize = 256;
const MAX_STUB_INSTRUCTIONS: usize = 1024;
const MAX_NORETURN_WRAPPERS: usize = 32;
const MAX_WRAPPER_INSTRUCTIONS: usize = 32;
const MAX_WRAPPER_BYTES: usize = 128;
const STUB_SECTIONS: [&str; 6] = ["__stubs", "__auth_stubs", ".plt", ".plt.sec", ".plt.got", ".iplt"];

#[derive(Debug)]
pub(super) struct EntryPlan {
    pub address: u64,
    pub name: String,
    pub operations: Vec<WorkerOperation>,
    pub stub_targets: BTreeMap<u64, Vec<u64>>,
    pub origins: Vec<EntryOrigin>,
    pub inside_symbol_extent: bool,
    pub counts: EntryPlanCounts,
    pub omissions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryOrigin {
    FunctionSymbol,
    Export,
    FormatFunctionStart,
    ImageEntry,
    AnalystAssertion,
}

#[derive(Debug, Default, Serialize)]
pub struct EntryPlanCounts {
    pub retained_symbols: usize,
    pub retained_imports: usize,
    pub references: usize,
    pub decoded_instructions: usize,
    pub decoded_bytes: usize,
    pub walk_blocks: usize,
    pub stub_aliases: usize,
    pub context_budget_exhausted: bool,
}

#[derive(Default)]
struct Metadata<'a> {
    function: bool,
    export: bool,
    format_start: bool,
    image_entry: bool,
    identity: Option<&'a str>,
    display: Option<&'a str>,
    symbol_end: Option<u64>,
}

struct MetadataIndex<'a> {
    entries: BTreeMap<u64, Metadata<'a>>,
    data_ends: BTreeMap<u64, u64>,
}

impl MetadataIndex<'_> {
    fn is_data(&self, address: u64) -> bool {
        self.data_ends.range(..=address).next_back().is_some_and(|(_, &end)| address <= end)
    }
}

impl Metadata<'_> {
    fn is_entry(&self) -> bool {
        self.function || self.export || self.format_start || self.image_entry
    }

    fn origins(&self) -> Vec<EntryOrigin> {
        [
            (self.function, EntryOrigin::FunctionSymbol),
            (self.export, EntryOrigin::Export),
            (self.format_start, EntryOrigin::FormatFunctionStart),
            (self.image_entry, EntryOrigin::ImageEntry),
        ]
        .into_iter()
        .filter_map(|(present, origin)| present.then_some(origin))
        .collect()
    }
}

#[derive(Clone, Copy)]
struct Identity<'a> {
    raw: Option<&'a str>,
    import: bool,
}

impl Identity<'_> {
    fn noreturn(self) -> bool {
        self.raw.is_some_and(|name| if self.import { is_noreturn_import(name) } else { is_noreturn_name(name) })
    }

    fn fatal_termination_import(self) -> bool {
        // Normal noreturn identities include throws; local exception handlers can return from those wrappers.
        self.import
            && matches!(
                self.raw,
                Some(
                    "abort"
                        | "_abort"
                        | "__assert_fail"
                        | "___assert_fail"
                        | "__assert_perror_fail"
                        | "___assert_perror_fail"
                        | "__assert_rtn"
                        | "___assert_rtn"
                        | "__stack_chk_fail"
                        | "___stack_chk_fail"
                        | "__stack_chk_fail_local"
                        | "___stack_chk_fail_local"
                        | "__fortify_fail"
                        | "___fortify_fail"
                        | "__chk_fail"
                        | "___chk_fail"
                )
            )
    }
}

fn invalid(message: &str) -> ApiError {
    ApiError::Invalid(message.to_owned())
}

fn canonical(name: &str) -> &str {
    name.strip_suffix("@plt").or_else(|| name.strip_suffix("@got")).unwrap_or(name)
}

fn preflight(
    binary: &Binary,
    annotations: &Annotations,
    check: &impl Fn(&'static str) -> Result<(), ApiError>,
) -> Result<(), ApiError> {
    check("entry metadata preflight")?;
    let records = [
        binary.symbols.len(),
        binary.exports.len(),
        binary.import_slots.len(),
        binary.function_starts.len(),
        binary.sections.len(),
        binary.segments.len(),
        binary.thumb.len(),
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .ok_or_else(|| invalid("exact-entry metadata exceeds the preparation budget"))?;
    if records > MAX_METADATA_RECORDS || binary.segments.len() > 4096 || binary.sections.len() > 4096 {
        return Err(invalid("exact-entry metadata exceeds the preparation budget"));
    }
    for (index, pair) in binary.import_slots.windows(2).enumerate() {
        if index % 256 == 0 {
            check("entry import metadata preflight")?;
        }
        if pair[0].address >= pair[1].address {
            return Err(invalid("exact-entry import slots must have unique, sorted addresses"));
        }
    }
    let mut bytes = 0usize;
    for (index, name) in binary
        .symbols
        .iter()
        .map(|symbol| symbol.name.as_str())
        .chain(binary.exports.iter().map(|export| export.name.as_str()))
        .chain(binary.import_slots.iter().map(|slot| slot.name.as_str()))
        .chain(binary.sections.iter().map(|section| section.name.as_str()))
        .chain(binary.segments.iter().map(|segment| segment.name.as_str()))
        .enumerate()
    {
        if index % 256 == 0 {
            check("entry metadata name preflight")?;
        }
        bytes = bytes.saturating_add(name.len());
        if name.len() > MAX_NAME_BYTES || bytes > MAX_METADATA_NAME_BYTES {
            return Err(invalid("exact-entry metadata names exceed the preparation budget"));
        }
    }
    check("entry annotation preflight")?;
    let records = annotations
        .names()
        .len()
        .saturating_add(annotations.signatures().len())
        .saturating_add(annotations.types().len())
        .saturating_add(annotations.globals().len());
    if records > MAX_ANNOTATION_RECORDS || annotations.signatures().len() > MAX_TARGETS {
        return Err(invalid("required exact-entry annotations exceed the preparation budget"));
    }
    let mut bytes = 0usize;
    for (index, text) in annotations
        .names()
        .values()
        .chain(annotations.signatures().values())
        .chain(annotations.types().values())
        .chain(annotations.globals().values())
        .enumerate()
    {
        if index % 64 == 0 {
            check("entry annotation value preflight")?;
        }
        bytes = bytes.saturating_add(text.len());
        if text.len() > 1024 * 1024 || bytes > MAX_ANNOTATION_BYTES {
            return Err(invalid("required exact-entry annotations exceed the preparation budget"));
        }
    }
    if annotations.names().values().any(|name| name.len() > MAX_NAME_BYTES) {
        return Err(invalid("required exact-entry annotation names exceed the preparation budget"));
    }
    Ok(())
}

fn supported(binary: &Binary, address: u64) -> Result<(), ApiError> {
    let endian_supported = !binary.big_endian && !binary.target().big_endian;
    match binary.arch {
        Arch::X86 | Arch::X86_64 | Arch::Aarch64 if endian_supported => {}
        _ => {
            return Err(ApiError::Unavailable(
                "exact-entry decompilation supports little-endian x86, x86-64 and AArch64 only".to_owned(),
            ));
        }
    }
    if !width_valid(binary, address) {
        return Err(invalid("exact-entry address exceeds the target address width"));
    }
    if binary.arch == Arch::Aarch64 && !address.is_multiple_of(4) {
        return Err(invalid("exact-entry AArch64 address must be four-byte aligned"));
    }
    Ok(())
}

fn width_valid(binary: &Binary, address: u64) -> bool {
    binary.arch != Arch::X86 || u32::try_from(address).is_ok()
}

fn code(binary: &Binary, address: u64) -> Option<&[u8]> {
    if !width_valid(binary, address)
        || binary.arch == Arch::Aarch64 && !address.is_multiple_of(4)
        || binary.import_slot(address).is_some()
        || !binary.segment_containing(address)?.perms.execute
    {
        return None;
    }
    let bytes = binary.code_from(address)?;
    let minimum = if binary.arch == Arch::Aarch64 { 4 } else { 1 };
    (bytes.len() >= minimum).then_some(bytes)
}

fn metadata<'a>(
    binary: &'a Binary,
    address: u64,
    check: &impl Fn(&'static str) -> Result<(), ApiError>,
) -> Result<(MetadataIndex<'a>, bool, Option<u64>), ApiError> {
    let mut entries: BTreeMap<u64, Metadata<'a>> = BTreeMap::new();
    let mut data_ends: BTreeMap<u64, u64> = BTreeMap::new();
    let mut inside = false;
    let mut enclosing_end = None;
    for (index, symbol) in binary.symbols.iter().enumerate() {
        if index % 256 == 0 {
            check("entry function metadata")?;
        }
        let entry = entries.entry(symbol.address).or_default();
        if entry.display.is_none() {
            entry.display = Some(&symbol.name);
        }
        if symbol.kind == SymbolKind::Data {
            let end = symbol
                .address
                .checked_add(symbol.size.saturating_sub(1))
                .ok_or_else(|| invalid("exact-entry data-symbol extent overflows the address space"))?;
            data_ends.entry(symbol.address).and_modify(|previous| *previous = (*previous).max(end)).or_insert(end);
        }
        if symbol.kind != SymbolKind::Function {
            continue;
        }
        if !entry.function {
            entry.identity = Some(&symbol.name);
            entry.display = Some(&symbol.name);
        }
        entry.function = true;
        if symbol.size != 0 {
            let end = symbol
                .address
                .checked_add(symbol.size)
                .ok_or_else(|| invalid("exact-entry function-symbol extent overflows the address space"))?;
            entry.symbol_end = Some(entry.symbol_end.map_or(end, |previous| previous.min(end)));
            if symbol.address < address && address < end {
                inside = true;
                enclosing_end = Some(enclosing_end.map_or(end, |previous: u64| previous.min(end)));
            }
        }
    }
    let mut reach = 0;
    for (index, end) in data_ends.values_mut().enumerate() {
        if index % 256 == 0 {
            check("entry data extent metadata")?;
        }
        reach = reach.max(*end);
        *end = reach;
    }
    for (index, export) in binary.exports.iter().enumerate() {
        if index % 256 == 0 {
            check("entry export metadata")?;
        }
        let entry = entries.entry(export.address).or_default();
        if !entry.function && !entry.export {
            entry.identity = Some(&export.name);
            entry.display = Some(&export.name);
        }
        entry.export = true;
    }
    for (index, &start) in binary.function_starts.iter().enumerate() {
        if index % 256 == 0 {
            check("entry format metadata")?;
        }
        entries.entry(start).or_default().format_start = true;
    }
    if let Some(start) = binary.entry {
        let entry = entries.entry(start).or_default();
        entry.image_entry = true;
        if entry.display.is_none() {
            entry.display = Some("entry");
        }
    }
    Ok((MetadataIndex { entries, data_ends }, inside, enclosing_end))
}

fn display_name(
    entries: &BTreeMap<u64, Metadata<'_>>,
    annotations: &Annotations,
    address: u64,
    fallback: Option<&str>,
) -> String {
    annotations
        .name(address)
        .or_else(|| entries.get(&address).and_then(|entry| entry.display))
        .or(fallback)
        .filter(|name| !name.is_empty())
        .map_or_else(|| format!("sub_{address:x}"), str::to_owned)
}

fn symbol_name(
    binary: &Binary,
    entries: &BTreeMap<u64, Metadata<'_>>,
    annotations: &Annotations,
    address: u64,
    identity: Identity<'_>,
) -> String {
    if binary.format == Format::Elf
        && identity.import
        && annotations.name(address).is_none()
        && entries.get(&address).and_then(|entry| entry.display).is_none()
        && identity.raw.is_some_and(|name| !name.is_empty())
    {
        format!("{}@plt", identity.raw.unwrap_or_default())
    } else {
        display_name(entries, annotations, address, identity.raw)
    }
}

fn omit(omissions: &mut Vec<String>, message: &'static str) {
    if !omissions.iter().any(|existing| existing == message) {
        omissions.push(message.to_owned());
    }
}

fn exhausted(counts: &mut EntryPlanCounts, omissions: &mut Vec<String>, message: &'static str) {
    counts.context_budget_exhausted = true;
    omit(omissions, message);
}

fn stub_slot(
    binary: &Binary,
    instruction: &rampage_arch::Insn,
    bytes: &[u8],
    loaded: Option<(u8, u64)>,
) -> Option<u64> {
    if instruction.flow != Flow::IndirectJump {
        return None;
    }
    match binary.arch {
        Arch::X86 | Arch::X86_64 => instruction.data_ref.filter(|_| instruction.accesses),
        Arch::Aarch64 => {
            let word = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
            let (register, slot) = loaded?;
            (word & 0xffff_fc1f == 0xd61f_0000 && ((word >> 5) & 31) as u8 == register).then_some(slot)
        }
        _ => None,
    }
    .filter(|&slot| binary.import_slot(slot).is_some())
}

fn loaded_slot(binary: &Binary, bytes: &[u8], instruction: &rampage_arch::Insn) -> Option<(u8, u64)> {
    if binary.arch != Arch::Aarch64 || instruction.flow != Flow::Next {
        return None;
    }
    let word = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
    let slot = instruction.data_ref.filter(|&slot| binary.import_slot(slot).is_some())?;
    let pointer_load = word & 0xffc0_0000 == 0xf940_0000 || word & 0xff00_0000 == 0x5800_0000;
    (instruction.accesses && pointer_load).then_some(((word & 31) as u8, slot))
}

fn preserves_loaded(bytes: &[u8], loaded: Option<(u8, u64)>) -> bool {
    let Some((register, _)) = loaded else { return false };
    let Some(bytes) = bytes.get(..4) else { return false };
    let word = u32::from_le_bytes(bytes.try_into().expect("four-byte instruction"));
    word == 0xd503_201f || word & 0xff00_0000 == 0x9100_0000 && (word & 31) as u8 != register
}

fn stub_padding(
    binary: &Binary,
    decoder: &mut dyn rampage_arch::Disassembler,
    instruction: &rampage_arch::Insn,
    bytes: &[u8],
) -> bool {
    if instruction.flow != Flow::Next
        || instruction.conditional
        || instruction.accesses
        || usize::from(instruction.len) != bytes.len()
    {
        return false;
    }
    match binary.arch {
        Arch::X86 | Arch::X86_64 => {
            let operand_size_nop =
                bytes == [0x66, 0x90] && instruction.data_ref.is_none() && instruction.immediate.is_none();
            operand_size_nop
                || decoder.format(bytes, instruction.address).split_ascii_whitespace().next() == Some("nop")
        }
        // Mach-O linker-relaxed stubs can begin with NOP; ELF resolver NOPs are padding instead.
        Arch::Aarch64 => binary.format != Format::MachO && bytes == 0xd503_201fu32.to_le_bytes(),
        _ => false,
    }
}

fn declared_stubs(
    binary: &Binary,
    metadata: &MetadataIndex<'_>,
    annotations: &Annotations,
    required_slots: &BTreeSet<u64>,
    counts: &mut EntryPlanCounts,
    omissions: &mut Vec<String>,
    check: &impl Fn(&'static str) -> Result<(), ApiError>,
) -> Result<BTreeMap<u64, Vec<u64>>, ApiError> {
    if binary.format == Format::Pe {
        omit(omissions, "Undeclared PE text thunks were not scanned for focused context.");
        if !required_slots.is_empty() {
            return Err(invalid("focused replay cannot prove complete PE thunk aliases for an import signature"));
        }
    }
    let mut decoder = binary.decoder()?;
    let mut targets: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let mut aliases = 0usize;
    for section in binary.sections.iter().filter(|section| STUB_SECTIONS.contains(&section.name.as_str())) {
        check("entry declared stub section")?;
        if section.kind != SectionKind::Code {
            continue;
        }
        if section.name == "__auth_stubs" {
            if !required_slots.is_empty() {
                return Err(invalid("focused replay cannot prove authenticated import-stub aliases"));
            }
            omit(omissions, "Authenticated import-stub aliases were not inferred.");
            continue;
        }
        let end = section.address.saturating_add(section.size);
        let mut at = section.address;
        let mut start = at;
        let mut loaded = None;
        let mut touched = BTreeSet::new();
        decoder.begin_run();
        while at < end {
            check("entry declared stub instruction")?;
            if metadata.is_data(at) || metadata.is_data(start) {
                if !required_slots.is_empty() {
                    return Err(invalid("required import-stub aliases overlap a known data-symbol extent"));
                }
                omit(omissions, "A declared import-stub section overlaps a known data-symbol extent.");
                break;
            }
            if counts.decoded_instructions >= MAX_STUB_INSTRUCTIONS || counts.decoded_bytes >= MAX_BYTES {
                if !required_slots.is_empty() {
                    return Err(invalid("required import-stub aliases exceed the focused preparation budget"));
                }
                exhausted(counts, omissions, "Declared import-stub context exceeded its decoding budget.");
                return Ok(targets);
            }
            let Some(bytes) = code(binary, at) else {
                if !required_slots.is_empty() {
                    return Err(invalid("required import-stub aliases include unavailable code"));
                }
                omit(omissions, "A declared import-stub section includes unavailable code.");
                break;
            };
            let available = bytes.len().min((end - at) as usize).min(16);
            let instruction = decoder.decode(&bytes[..available], at);
            counts.decoded_instructions += 1;
            let length = usize::from(instruction.len);
            if length == 0 || length > available || instruction.flow == Flow::Invalid {
                if !required_slots.is_empty() {
                    return Err(invalid("required import-stub aliases include undecodable code"));
                }
                omit(omissions, "A declared import-stub section could not be decoded completely.");
                break;
            }
            counts.decoded_bytes += length;
            let Some(next) = at.checked_add(length as u64).filter(|&next| width_valid(binary, next - 1)) else {
                return Err(invalid("declared import-stub instruction exceeds the target address width"));
            };
            if let Some(slot) =
                instruction.data_ref.filter(|&slot| instruction.accesses && binary.import_slot(slot).is_some())
            {
                touched.insert(slot);
            }
            let alias = stub_slot(binary, &instruction, bytes, loaded);
            if let Some(slot) = alias {
                if aliases >= MAX_TARGETS {
                    if !required_slots.is_empty() {
                        return Err(invalid("required import-stub aliases exceed the focused target budget"));
                    }
                    exhausted(counts, omissions, "Declared import-stub aliases exceeded the focused target budget.");
                    return Ok(targets);
                }
                let entries = targets.entry(slot).or_default();
                if !entries.contains(&start) {
                    entries.push(start);
                    aliases += 1;
                    counts.stub_aliases = aliases;
                }
            }
            if instruction.flow != Flow::Next {
                if touched.iter().any(|slot| Some(*slot) != alias && required_slots.contains(slot)) {
                    return Err(invalid("focused replay could not prove a required import-stub alias"));
                }
                if touched.iter().any(|slot| Some(*slot) != alias) {
                    omit(omissions, "An import-stub transfer could not be linked to its exact import slot.");
                }
                touched.clear();
                loaded = None;
                start = next;
                decoder.reset();
            } else {
                loaded = loaded_slot(binary, bytes, &instruction)
                    .or_else(|| preserves_loaded(bytes, loaded).then_some(loaded).flatten());
                let stable_start = metadata.entries.get(&start).is_some_and(Metadata::is_entry)
                    || annotations.signatures().contains_key(&start);
                if start == at
                    && !stable_start
                    && stub_padding(binary, decoder.as_mut(), &instruction, &bytes[..length])
                {
                    start = next;
                }
            }
            at = next;
        }
        if touched.iter().any(|slot| required_slots.contains(slot)) {
            return Err(invalid("focused replay could not prove a required import-stub alias"));
        }
        if !touched.is_empty() {
            omit(omissions, "An unterminated import-stub sequence was not registered as an alias.");
        }
    }
    for targets in targets.values_mut() {
        targets.sort_unstable();
        targets.dedup();
    }
    counts.stub_aliases = aliases;
    Ok(targets)
}

struct Context<'a> {
    symbols: BTreeMap<u64, Identity<'a>>,
    imports: BTreeSet<u64>,
    references: BTreeSet<u64>,
    noreturn_wrappers: BTreeSet<u64>,
}

impl<'a> Context<'a> {
    fn symbol(
        &mut self,
        address: u64,
        identity: Identity<'a>,
        required: bool,
        counts: &mut EntryPlanCounts,
        omissions: &mut Vec<String>,
    ) -> Result<(), ApiError> {
        if self.symbols.contains_key(&address) {
            return Ok(());
        }
        if self.symbols.len() + self.imports.len() >= MAX_TARGETS {
            if required {
                return Err(invalid("required exact-entry symbols exceed the focused target budget"));
            }
            exhausted(counts, omissions, "Optional referenced symbols exceeded the focused target budget.");
        } else {
            self.symbols.insert(address, identity);
        }
        Ok(())
    }

    fn import(
        &mut self,
        address: u64,
        required: bool,
        counts: &mut EntryPlanCounts,
        omissions: &mut Vec<String>,
    ) -> Result<(), ApiError> {
        if self.imports.contains(&address) {
            return Ok(());
        }
        if self.symbols.len() + self.imports.len() >= MAX_TARGETS {
            if required {
                return Err(invalid("required exact-entry imports exceed the focused target budget"));
            }
            exhausted(counts, omissions, "Optional referenced imports exceeded the focused target budget.");
        } else {
            self.imports.insert(address);
        }
        Ok(())
    }
}

fn identity_at<'a>(
    binary: &Binary,
    metadata: &MetadataIndex<'a>,
    stubs: &BTreeMap<u64, Identity<'a>>,
    address: u64,
) -> Option<Identity<'a>> {
    if metadata.is_data(address) {
        return None;
    }
    code(binary, address)?;
    stubs.get(&address).copied().or_else(|| {
        let entry = metadata.entries.get(&address).filter(|entry| entry.is_entry())?;
        Some(Identity { raw: entry.identity, import: false })
    })
}

fn x86_interrupt(arch: Arch, bytes: &[u8]) -> bool {
    let opcode = bytes.iter().copied().find(|byte| {
        !matches!(byte, 0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 | 0x66 | 0x67)
            && !(arch == Arch::X86_64 && (0x40..=0x4f).contains(byte))
    });
    matches!(opcode, Some(0xcd | 0xcc | 0xf1 | 0xce))
}

#[allow(clippy::too_many_arguments)]
fn noreturn_wrapper(
    binary: &Binary,
    address: u64,
    metadata: &MetadataIndex<'_>,
    stubs: &BTreeMap<u64, Identity<'_>>,
    counts: &mut EntryPlanCounts,
    omissions: &mut Vec<String>,
    check: &impl Fn(&'static str) -> Result<(), ApiError>,
) -> Result<bool, ApiError> {
    check("entry noreturn wrapper")?;
    let Some(entry) = metadata.entries.get(&address).filter(|entry| entry.is_entry()) else {
        return Ok(false);
    };
    let next_entry = metadata
        .entries
        .range((Excluded(address), Unbounded))
        .find_map(|(&address, entry)| entry.is_entry().then_some(address));
    let end = [entry.symbol_end, next_entry]
        .into_iter()
        .flatten()
        .fold(address.saturating_add(MAX_WRAPPER_BYTES as u64), u64::min);
    let mut decoder = binary.decoder()?;
    decoder.begin_run();
    let mut at = address;
    let initial_instructions = counts.decoded_instructions;
    while counts.decoded_instructions - initial_instructions < MAX_WRAPPER_INSTRUCTIONS {
        check("entry noreturn wrapper instruction")?;
        if at.saturating_sub(address) >= MAX_WRAPPER_BYTES as u64 {
            exhausted(counts, omissions, "A referenced callee wrapper exceeded its byte budget without proof.");
            return Ok(false);
        }
        if at >= end || metadata.is_data(at) {
            omit(omissions, "A referenced callee wrapper reached a metadata or byte-window boundary without proof.");
            return Ok(false);
        }
        if counts.decoded_instructions >= MAX_INSTRUCTIONS || counts.decoded_bytes >= MAX_BYTES {
            exhausted(counts, omissions, "Referenced callee wrappers exceeded the shared decoding budget.");
            return Ok(false);
        }
        let Some(bytes) = code(binary, at) else {
            omit(omissions, "A referenced callee wrapper includes unavailable or non-executable code.");
            return Ok(false);
        };
        // AArch64 call-to-next must remain a transfer, not lookahead-reclassified setup.
        let maximum = if binary.arch == Arch::Aarch64 { 4 } else { 15 };
        let available = bytes.len().min((end - at) as usize).min(MAX_BYTES - counts.decoded_bytes).min(maximum);
        let mut instruction = decoder.decode(&bytes[..available], at);
        counts.decoded_instructions += 1;
        let length = usize::from(instruction.len);
        if length == 0 || length > available || instruction.flow == Flow::Invalid {
            if available == MAX_BYTES - counts.decoded_bytes
                || end == address.saturating_add(MAX_WRAPPER_BYTES as u64) && available as u64 == end - at
            {
                exhausted(counts, omissions, "A referenced callee wrapper reached a byte budget without proof.");
            } else {
                omit(omissions, "A referenced callee wrapper includes invalid or incomplete instructions.");
            }
            return Ok(false);
        }
        counts.decoded_bytes += length;
        // Resumable breakpoints and supervisor calls are Flow::Next, not proven wrapper setup.
        if binary.arch == Arch::Aarch64
            && bytes.first_chunk::<4>().is_some_and(|word| u32::from_le_bytes(*word) & 0xff00_0000 == 0xd400_0000)
        {
            return Ok(false);
        }
        if matches!(binary.arch, Arch::X86 | Arch::X86_64) && x86_interrupt(binary.arch, &bytes[..length]) {
            return Ok(false);
        }
        if binary.arch != Arch::Aarch64 && instruction.flow == Flow::Next && length < available {
            if counts.decoded_instructions - initial_instructions >= MAX_WRAPPER_INSTRUCTIONS
                || counts.decoded_instructions >= MAX_INSTRUCTIONS
                || length > MAX_BYTES - counts.decoded_bytes
            {
                exhausted(counts, omissions, "Referenced callee wrapper verification exceeded its decoding budget.");
                return Ok(false);
            }
            // Remove x86 lookahead too: a call-to-next is not permitted wrapper setup.
            decoder.reset();
            instruction = decoder.decode(&bytes[..length], at);
            counts.decoded_instructions += 1;
            counts.decoded_bytes += length;
            if usize::from(instruction.len) != length || instruction.flow == Flow::Invalid {
                return Ok(false);
            }
        }
        let Some(next) = at.checked_add(length as u64).filter(|&next| width_valid(binary, next - 1)) else {
            return Ok(false);
        };
        if instruction.conditional || metadata.data_ends.range((Excluded(at), Excluded(next))).next().is_some() {
            return Ok(false);
        }
        match instruction.flow {
            Flow::Next => at = next,
            Flow::Call(target) | Flow::Jump(target) => {
                return Ok(stubs.get(&target).is_some_and(|identity| identity.fatal_termination_import())
                    && identity_at(binary, metadata, stubs, target).is_some());
            }
            _ => return Ok(false),
        }
    }
    exhausted(counts, omissions, "A referenced callee wrapper exceeded its instruction budget without proof.");
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
fn walk<'a>(
    binary: &'a Binary,
    address: u64,
    end: u64,
    metadata: &MetadataIndex<'a>,
    stubs: &BTreeMap<u64, Identity<'a>>,
    context: &mut Context<'a>,
    counts: &mut EntryPlanCounts,
    omissions: &mut Vec<String>,
    check: &impl Fn(&'static str) -> Result<(), ApiError>,
) -> Result<(), ApiError> {
    let mut decoder = binary.decoder()?;
    let mut pending = VecDeque::from([address]);
    let mut queued = BTreeSet::from([address]);
    let mut decoded: BTreeMap<u64, u64> = BTreeMap::new();
    let mut inspected_wrappers = BTreeSet::new();
    let has_fatal_stubs = stubs.values().any(|identity| identity.fatal_termination_import());
    while let Some(mut at) = pending.pop_front() {
        check("entry reference block")?;
        if counts.walk_blocks >= MAX_BLOCKS {
            exhausted(counts, omissions, "Local reference context exceeded its block budget.");
            break;
        }
        counts.walk_blocks += 1;
        decoder.begin_run();
        loop {
            check("entry reference instruction")?;
            if at < address || at >= end {
                omit(omissions, "Local reference context stopped at a conservative function or byte-window boundary.");
                break;
            }
            if metadata.is_data(at) {
                omit(omissions, "Local reference context stopped at a known data-symbol extent.");
                break;
            }
            if decoded.contains_key(&at) {
                break;
            }
            if decoded.range(..at).next_back().is_some_and(|(_, &previous_end)| at < previous_end) {
                omit(omissions, "An overlapping local branch was not treated as a verified instruction boundary.");
                break;
            }
            if at != address && (metadata.entries.get(&at).is_some_and(Metadata::is_entry) || stubs.contains_key(&at)) {
                if let Some(identity) = identity_at(binary, metadata, stubs, at) {
                    context.symbol(at, identity, false, counts, omissions)?;
                }
                omit(omissions, "Local reference context stopped at an independent metadata entry.");
                break;
            }
            if counts.decoded_instructions >= MAX_INSTRUCTIONS || counts.decoded_bytes >= MAX_BYTES {
                exhausted(counts, omissions, "Local reference context exceeded its instruction or byte budget.");
                break;
            }
            let Some(bytes) = code(binary, at) else {
                omit(omissions, "Local reference context reached unavailable or non-executable code.");
                break;
            };
            let available = bytes.len().min((end - at) as usize).min(MAX_BYTES - counts.decoded_bytes).min(16);
            let instruction = decoder.decode(&bytes[..available], at);
            counts.decoded_instructions += 1;
            let length = usize::from(instruction.len);
            if length == 0 || length > available || instruction.flow == Flow::Invalid {
                omit(omissions, "Local reference context stopped at an invalid or incomplete instruction.");
                break;
            }
            counts.decoded_bytes += length;
            let Some(next) = at.checked_add(length as u64).filter(|&next| width_valid(binary, next - 1)) else {
                omit(omissions, "Local reference context reached the target address-width boundary.");
                break;
            };
            if decoded.range((Excluded(at), Excluded(next))).next().is_some() {
                omit(omissions, "Overlapping local instructions were not treated as verified boundaries.");
                break;
            }
            decoded.insert(at, next);
            let mut import_noreturn = false;
            if let Some(slot) =
                instruction.data_ref.filter(|_| instruction.accesses).and_then(|slot| binary.import_slot(slot))
            {
                context.import(slot.address, false, counts, omissions)?;
                import_noreturn = is_noreturn_import(&slot.name);
            }
            let target = match instruction.flow {
                Flow::Call(target) | Flow::Jump(target) | Flow::ConditionalJump(target) => Some(target),
                _ => None,
            };
            if let Some(target) = target {
                if context.references.len() >= MAX_TARGETS && !context.references.contains(&target) {
                    exhausted(counts, omissions, "Local reference context exceeded its direct-target budget.");
                    break;
                }
                context.references.insert(target);
                if let Some(identity) = identity_at(binary, metadata, stubs, target) {
                    context.symbol(target, identity, false, counts, omissions)?;
                    if has_fatal_stubs
                        && !instruction.conditional
                        && matches!(instruction.flow, Flow::Call(_) | Flow::Jump(_))
                        && target != address
                        && !identity.noreturn()
                        && !stubs.contains_key(&target)
                        && context.symbols.contains_key(&target)
                        && !inspected_wrappers.contains(&target)
                    {
                        if inspected_wrappers.len() >= MAX_NORETURN_WRAPPERS {
                            exhausted(counts, omissions, "Referenced callee wrappers exceeded their candidate budget.");
                        } else {
                            inspected_wrappers.insert(target);
                            if noreturn_wrapper(binary, target, metadata, stubs, counts, omissions, check)? {
                                context.noreturn_wrappers.insert(target);
                            }
                        }
                    }
                } else if metadata.is_data(target) {
                    omit(
                        omissions,
                        "A direct transfer into a known data-symbol extent was not registered as a function.",
                    );
                } else if matches!(instruction.flow, Flow::Call(_)) {
                    omit(
                        omissions,
                        "Direct callees without exact metadata or declared-stub evidence were not registered.",
                    );
                }
            }
            let mut enqueue = |target| {
                if queued.contains(&target) {
                    return;
                }
                if queued.len() >= MAX_BLOCKS {
                    exhausted(counts, omissions, "Local reference context exceeded its queued-block budget.");
                } else {
                    queued.insert(target);
                    pending.push_back(target);
                }
            };
            match instruction.flow {
                Flow::Next => at = next,
                Flow::Call(target) => {
                    if !instruction.conditional
                        && (identity_at(binary, metadata, stubs, target).is_some_and(Identity::noreturn)
                            || context.noreturn_wrappers.contains(&target))
                    {
                        break;
                    }
                    at = next;
                }
                Flow::ConditionalJump(target) => {
                    enqueue(target);
                    enqueue(next);
                    break;
                }
                Flow::Jump(target) => {
                    enqueue(target);
                    break;
                }
                Flow::IndirectCall if instruction.data_ref.and_then(|slot| binary.import_slot(slot)).is_some() => {
                    if import_noreturn {
                        break;
                    }
                    at = next;
                }
                Flow::IndirectCall | Flow::IndirectJump => {
                    omit(omissions, "Local reference context stopped at an unresolved indirect transfer.");
                    break;
                }
                Flow::Return | Flow::Halt | Flow::Invalid => break,
            }
        }
        if counts.decoded_instructions >= MAX_INSTRUCTIONS || counts.decoded_bytes >= MAX_BYTES {
            if !pending.is_empty() {
                exhausted(counts, omissions, "Pending local reference blocks were omitted at the decoding budget.");
            }
            break;
        }
    }
    Ok(())
}

pub(super) fn prepare(
    project: &Project,
    annotations: &Annotations,
    request: &DecompileEntryRequest,
    check: &impl Fn(&'static str) -> Result<(), ApiError>,
) -> Result<EntryPlan, ApiError> {
    check("entry preparation")?;
    let binary = &project.binary;
    preflight(binary, annotations, check)?;
    supported(binary, request.address)?;
    check("entry code validation")?;
    if code(binary, request.address).is_none() {
        return Err(invalid(
            "exact-entry decompilation requires available, backed executable code, not an import slot",
        ));
    }
    let (metadata, inside_symbol_extent, enclosing_end) = metadata(binary, request.address, check)?;
    let entries = &metadata.entries;
    let entry = entries.get(&request.address);
    if metadata.is_data(request.address) {
        return Err(invalid("exact-entry address is explicitly identified as data"));
    }
    let mut origins = entry.map_or_else(Vec::new, Metadata::origins);
    if origins.is_empty() && request.validation == EntryValidation::MetadataBacked {
        return Err(invalid(if inside_symbol_extent {
            "exact-entry address is inside a known symbol extent without independent exact-entry metadata"
        } else {
            "exact-entry address has no function-symbol, code-export, format-start or image-entry metadata"
        }));
    }
    if request.validation == EntryValidation::AnalystAsserted {
        origins.push(EntryOrigin::AnalystAssertion);
    }
    let mut counts = EntryPlanCounts::default();
    let mut omissions = Vec::new();
    if inside_symbol_extent {
        omit(&mut omissions, "The exact requested entry overlaps a known nonzero-sized function-symbol extent.");
    }
    let required_slots: BTreeSet<_> =
        annotations.signatures().keys().copied().filter(|&address| binary.import_slot(address).is_some()).collect();
    check("entry import aliases")?;
    let stub_targets =
        declared_stubs(binary, &metadata, annotations, &required_slots, &mut counts, &mut omissions, check)?;
    let mut stubs = BTreeMap::new();
    for (&slot, targets) in &stub_targets {
        let import = binary.import_slot(slot).expect("validated import slot");
        for &target in targets {
            stubs.insert(target, Identity { raw: Some(&import.name), import: true });
        }
    }
    let mut context = Context {
        symbols: BTreeMap::new(),
        imports: BTreeSet::new(),
        references: BTreeSet::new(),
        noreturn_wrappers: BTreeSet::new(),
    };
    let selected =
        identity_at(binary, &metadata, &stubs, request.address).unwrap_or(Identity { raw: None, import: false });
    context.symbol(request.address, selected, true, &mut counts, &mut omissions)?;
    for &address in annotations.signatures().keys() {
        check("entry required signature symbol")?;
        if binary.import_slot(address).is_some() {
            context.import(address, true, &mut counts, &mut omissions)?;
            if let Some(targets) = stub_targets.get(&address) {
                for &target in targets {
                    context.symbol(target, stubs[&target], true, &mut counts, &mut omissions)?;
                }
            }
        } else {
            if code(binary, address).is_none() || metadata.is_data(address) {
                return Err(invalid("an actual signature requires available executable code or an exact import slot"));
            }
            let identity =
                identity_at(binary, &metadata, &stubs, address).unwrap_or(Identity { raw: None, import: false });
            context.symbol(address, identity, true, &mut counts, &mut omissions)?;
        }
    }
    let next_entry = entries
        .range((Excluded(request.address), Unbounded))
        .find_map(|(&address, entry)| (entry.is_entry() && !metadata.is_data(address)).then_some(address));
    let end = [entry.and_then(|entry| entry.symbol_end), enclosing_end, next_entry]
        .into_iter()
        .flatten()
        .fold(request.address.saturating_add(MAX_BYTES as u64), u64::min);
    check("entry local references")?;
    omit(
        &mut omissions,
        concat!(
            "Noreturn inference is limited to bounded referenced exact-metadata straight-line wrappers ",
            "to exact non-unwinding fatal import stubs; no recursive or whole-program noreturn inference."
        ),
    );
    walk(binary, request.address, end, &metadata, &stubs, &mut context, &mut counts, &mut omissions, check)?;
    for (&address, &identity) in &stubs {
        check("entry optional stub symbol")?;
        context.symbol(address, identity, false, &mut counts, &mut omissions)?;
    }
    check("entry symbol operations")?;
    let mut operations = Vec::new();
    for (&address, identity) in &context.symbols {
        check("entry symbol operation")?;
        let name = symbol_name(binary, entries, annotations, address, *identity);
        operations.push(WorkerOperation::Symbol { address, name });
        if let Some(raw) = identity.raw.filter(|name| !name.is_empty()) {
            let name = canonical(raw).to_owned();
            operations.push(WorkerOperation::RuntimePrototype { address, indirect: false, name, optional: true });
        }
        if identity.noreturn() || context.noreturn_wrappers.contains(&address) {
            operations.push(WorkerOperation::NoReturn { address, indirect: false });
        }
    }
    for &address in &context.imports {
        check("entry import operation")?;
        let import = binary.import_slot(address).expect("retained exact import slot");
        let name = annotations.name(address).unwrap_or(&import.name).to_owned();
        operations.push(WorkerOperation::Import { slot: address, target: None, name });
        operations.push(WorkerOperation::RuntimePrototype {
            address,
            indirect: true,
            name: canonical(&import.name).to_owned(),
            optional: true,
        });
        if is_noreturn_import(&import.name) {
            operations.push(WorkerOperation::NoReturn { address, indirect: true });
        }
    }
    counts.retained_symbols = context.symbols.len();
    counts.retained_imports = context.imports.len();
    counts.references = context.references.len();
    let name = symbol_name(binary, entries, annotations, request.address, selected);
    check("entry plan complete")?;
    Ok(EntryPlan {
        address: request.address,
        name,
        operations,
        stub_targets,
        origins,
        inside_symbol_extent,
        counts,
        omissions,
    })
}

#[cfg(test)]
#[path = "entry_plan_tests.rs"]
mod tests;
