//! `peripheral_map`: which code touches which memory-mapped peripheral, built from load and store instructions only,
//! so literal-pool words and data tables that are never dereferenced do not reach it.
//!
//! The accesses come from discovery's base-plus-offset field references (a load or store through a base register
//! whose value is known, carried across a function's blocks) and from the constant-address access scan the SVD
//! surface uses (constants formed in registers, MOVW/MOVT pairs, direct memory operands). An access counts when its
//! address lies in device space: on 32-bit ARM the Cortex-M peripheral (0x40000000-0x5fffffff), external device
//! (0xa0000000-0xdfffffff) and private peripheral bus (0xe0000000-0xe00fffff) regions, on MIPS32 uncached kseg1, on
//! Xtensa the ESP peripheral windows, and anywhere an imported SVD places a peripheral. Accesses are grouped into
//! peripheral blocks: an imported SVD peripheral, an architectural Cortex-M core block (SCB, NVIC, SysTick, MPU,
//! DWT, ...) or else the 1 KiB-aligned window holding the base register's value.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rampage_arch::Arch;
use rampage_loaders::{Binary, Details, Format};
use serde::Serialize;

use crate::{ApiError, Project};

/// Address-derived blocks are aligned to this; vendor peripherals are rarely closer together.
const BLOCK_ALIGN: u64 = 0x400;
/// How far past its 1 KiB-aligned start a base register's block may reach through offsets.
const BLOCK_REACH: u64 = 0x1000;
const MAX_REGISTERS: usize = 32;
const MAX_REGISTER_FUNCTIONS: usize = 4;
const MAX_BLOCK_FUNCTIONS: usize = 8;
const MAX_FUNCTION_BLOCKS: usize = 16;

#[derive(Debug, Clone, Default)]
pub struct PeripheralMapQuery {
    /// Only accesses made inside this function (any address in it).
    pub function: Option<u64>,
    /// Only accesses to addresses in `[start, end)`.
    pub start: Option<u64>,
    pub end: Option<u64>,
    /// Rows per function instead of per peripheral block.
    pub by_function: bool,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct PeripheralMapCounts {
    pub accesses: usize,
    pub reads: usize,
    pub writes: usize,
    pub blocks: usize,
    pub functions: usize,
}

#[derive(Debug, Serialize)]
pub struct PeripheralRegisterUse {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub offset: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `r`, `w` or `rw`.
    pub access: &'static str,
    /// The widest access in bytes, when known.
    #[serde(skip_serializing_if = "is_zero_u8")]
    pub width: u8,
    pub reads: usize,
    pub writes: usize,
    pub functions: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub more_functions: usize,
}

#[derive(Debug, Serialize)]
pub struct PeripheralBlockRow {
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub base: u64,
    /// Where the name comes from: `svd` (an imported map), `core` (an architectural Cortex-M block) or `address`.
    pub source: &'static str,
    pub reads: usize,
    pub writes: usize,
    pub functions: usize,
    /// The functions with the most accesses here, most first.
    pub accessed_by: Vec<String>,
    pub registers: Vec<PeripheralRegisterUse>,
    #[serde(skip_serializing_if = "is_zero")]
    pub more_registers: usize,
}

#[derive(Debug, Serialize)]
pub struct PeripheralFunctionBlock {
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub base: u64,
    /// One `OFFSET[ NAME] ACCESS` per register, e.g. `0x8 VTOR w`.
    pub offsets: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PeripheralFunctionRow {
    pub function: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub reads: usize,
    pub writes: usize,
    pub blocks: Vec<PeripheralFunctionBlock>,
    #[serde(skip_serializing_if = "is_zero")]
    pub more_blocks: usize,
}

#[derive(Debug, Serialize)]
pub struct PeripheralMapReport {
    pub counts: PeripheralMapCounts,
    pub total: usize,
    pub offset: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub blocks: Vec<PeripheralBlockRow>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<PeripheralFunctionRow>,
    /// Why the map is empty or partial, and how blocks are named.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

fn is_zero_u8(value: &u8) -> bool {
    *value == 0
}

/// Where a target keeps memory-mapped devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceSpace {
    /// 32-bit ARM; `core` names the private peripheral bus blocks (M-profile only).
    Arm {
        core: bool,
    },
    Mips,
    Xtensa,
    /// Only what an imported SVD covers.
    Svd,
}

impl DeviceSpace {
    fn contains(self, address: u64) -> bool {
        match self {
            DeviceSpace::Arm { .. } => {
                (0x4000_0000..0x6000_0000).contains(&address)
                    || (0xa000_0000..0xe000_0000).contains(&address)
                    || (0xe000_0000..0xe010_0000).contains(&address)
            }
            // Uncached kseg1 below the boot ROM, where SoCs map their registers.
            DeviceSpace::Mips => (0xa000_0000..0xbfc0_0000).contains(&address),
            // ESP32 DPORT and peripherals; ESP8266, ESP32-S2/S3 peripherals.
            DeviceSpace::Xtensa => {
                (0x3ff0_0000..0x3ff8_0000).contains(&address) || (0x6000_0000..0x6010_0000).contains(&address)
            }
            DeviceSpace::Svd => false,
        }
    }
}

/// A bare-metal ELF: no interpreter, no shared libraries, no imports.
fn bare_metal_elf(binary: &Binary) -> bool {
    binary.format == Format::Elf
        && binary.imports.is_empty()
        && match &binary.details {
            Details::Elf(details) => details.interpreter.is_none() && details.needed.is_empty(),
            _ => false,
        }
}

/// The device space of a firmware-like target, or why it has none.
fn device_space(binary: &Binary) -> Result<DeviceSpace, String> {
    let firmware = binary.format == Format::Raw || bare_metal_elf(binary);
    match binary.arch {
        Arch::Arm if binary.m_profile() => Ok(DeviceSpace::Arm { core: true }),
        Arch::Arm if firmware => Ok(DeviceSpace::Arm { core: false }),
        Arch::Mips if firmware => Ok(DeviceSpace::Mips),
        Arch::Xtensa if firmware || binary.format == Format::Elf => Ok(DeviceSpace::Xtensa),
        Arch::Arm | Arch::Mips | Arch::Xtensa => Err(format!(
            "this {} image is not firmware-like (it is hosted: it imports or loads shared libraries), so its \
             loads and stores are not read as peripheral accesses",
            binary.arch
        )),
        arch => Err(format!(
            "peripheral_map reads device space on 32-bit ARM (Cortex-M), MIPS32 and Xtensa firmware; this target \
             is {arch}"
        )),
    }
}

/// An architectural Cortex-M block on the private peripheral bus, with its registers by offset.
struct CoreBlock {
    name: &'static str,
    base: u64,
    span: u64,
    registers: &'static [(u64, &'static str)],
}

const CORE_BLOCKS: &[CoreBlock] = &[
    CoreBlock { name: "ITM", base: 0xe000_0000, span: 0x1000, registers: &[(0xe00, "TER"), (0xe80, "TCR")] },
    CoreBlock { name: "DWT", base: 0xe000_1000, span: 0x1000, registers: &[(0x0, "CTRL"), (0x4, "CYCCNT")] },
    CoreBlock { name: "FPB", base: 0xe000_2000, span: 0x1000, registers: &[(0x0, "CTRL"), (0x4, "REMAP")] },
    CoreBlock { name: "SCnSCB", base: 0xe000_e000, span: 0x10, registers: &[(0x4, "ICTR"), (0x8, "ACTLR")] },
    CoreBlock {
        name: "SysTick",
        base: 0xe000_e010,
        span: 0x10,
        registers: &[(0x0, "CTRL"), (0x4, "LOAD"), (0x8, "VAL"), (0xc, "CALIB")],
    },
    // Register names by group: ISER, ICER, ISPR, ICPR, IABR (32 bytes each, 128 apart) and IPR.
    CoreBlock { name: "NVIC", base: 0xe000_e100, span: 0x400, registers: &[] },
    CoreBlock {
        name: "SCB",
        base: 0xe000_ed00,
        span: 0x90,
        registers: &[
            (0x0, "CPUID"),
            (0x4, "ICSR"),
            (0x8, "VTOR"),
            (0xc, "AIRCR"),
            (0x10, "SCR"),
            (0x14, "CCR"),
            (0x18, "SHPR1"),
            (0x1c, "SHPR2"),
            (0x20, "SHPR3"),
            (0x24, "SHCSR"),
            (0x28, "CFSR"),
            (0x2c, "HFSR"),
            (0x30, "DFSR"),
            (0x34, "MMFAR"),
            (0x38, "BFAR"),
            (0x3c, "AFSR"),
            (0x88, "CPACR"),
        ],
    },
    CoreBlock {
        name: "MPU",
        base: 0xe000_ed90,
        span: 0x60,
        registers: &[(0x0, "TYPE"), (0x4, "CTRL"), (0x8, "RNR"), (0xc, "RBAR"), (0x10, "RASR")],
    },
    CoreBlock {
        name: "CoreDebug",
        base: 0xe000_edf0,
        span: 0x10,
        registers: &[(0x0, "DHCSR"), (0x4, "DCRSR"), (0x8, "DCRDR"), (0xc, "DEMCR")],
    },
    CoreBlock { name: "STIR", base: 0xe000_ef00, span: 0x4, registers: &[(0x0, "STIR")] },
    CoreBlock {
        name: "FPU",
        base: 0xe000_ef30,
        span: 0x20,
        registers: &[(0x4, "FPCCR"), (0x8, "FPCAR"), (0xc, "FPDSCR")],
    },
];

fn core_block(address: u64) -> Option<&'static CoreBlock> {
    CORE_BLOCKS.iter().find(|block| (block.base..block.base + block.span).contains(&address))
}

fn core_register(block: &CoreBlock, offset: u64) -> Option<String> {
    if block.name == "NVIC" {
        let groups = [(0x0, "ISER"), (0x80, "ICER"), (0x100, "ISPR"), (0x180, "ICPR"), (0x200, "IABR")];
        if let Some((start, name)) = groups.iter().find(|(start, _)| (*start..start + 0x20).contains(&offset)) {
            return offset.is_multiple_of(4).then(|| format!("{name}{}", (offset - start) / 4));
        }
        return (0x300..0x3f0).contains(&offset).then(|| format!("IPR{}", (offset - 0x300) / 4));
    }
    block.registers.iter().find(|(at, _)| *at == offset).map(|(_, name)| (*name).to_owned())
}

/// Registers by offset, in each block.
type Blocks = BTreeMap<BlockKey, BTreeMap<u64, Register>>;

/// One load or store in device space.
#[derive(Debug, Clone, Copy)]
struct Hit {
    function: u64,
    address: u64,
    write: bool,
    width: u8,
    /// The base register's value, for a field reference.
    base: Option<u64>,
}

/// A peripheral block the accesses are grouped into.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BlockKey {
    base: u64,
    name: String,
    source: &'static str,
}

#[derive(Default)]
struct Register {
    name: Option<String>,
    reads: usize,
    writes: usize,
    width: u8,
    /// Accesses per function.
    functions: BTreeMap<u64, usize>,
}

impl Register {
    fn access(&self) -> &'static str {
        match (self.reads > 0, self.writes > 0) {
            (true, true) => "rw",
            (false, true) => "w",
            _ => "r",
        }
    }
}

impl Project {
    /// The peripheral blocks the code's loads and stores reach, with the registers and functions touching each, or
    /// with `by_function` the blocks each function touches.
    pub fn map_peripherals(&self, query: &PeripheralMapQuery) -> Result<PeripheralMapReport, ApiError> {
        let svd = self.peripheral_map();
        let mut notes = Vec::new();
        let space = match device_space(&self.binary) {
            Ok(space) => space,
            Err(_) if !svd.is_empty() => DeviceSpace::Svd,
            Err(reason) => {
                notes.push(reason);
                return Ok(PeripheralMapReport {
                    counts: PeripheralMapCounts::default(),
                    total: 0,
                    offset: query.offset,
                    blocks: Vec::new(),
                    functions: Vec::new(),
                    notes,
                    next: None,
                });
            }
        };
        let analysis = self.analysis()?;
        let in_code = |address: u64| self.binary.segment_containing(address).is_some_and(|s| s.perms.execute);
        let device = |address: u64| (space.contains(address) || svd.at(address).is_some()) && !in_code(address);
        let function = match query.function {
            None => None,
            Some(address) => Some(
                analysis
                    .program
                    .function_at(address)
                    .map(|function| function.address)
                    .or_else(|| analysis.function_containing(address))
                    .ok_or_else(|| ApiError::NotFound(format!("no discovered function contains {address:#x}")))?,
            ),
        };
        let wanted = |hit: &Hit| {
            function.is_none_or(|function| hit.function == function)
                && query.start.is_none_or(|start| hit.address >= start)
                && query.end.is_none_or(|end| hit.address < end)
        };
        // Field references first: they carry the base register's value.
        let mut hits: Vec<Hit> = Vec::new();
        let mut seen: BTreeSet<(u64, u64)> = BTreeSet::new();
        for field in analysis.program.field_refs.iter().filter(|field| device(field.to)) {
            let Some(owner) = analysis.function_containing(field.from) else { continue };
            seen.insert((field.from, field.to));
            hits.push(Hit {
                function: owner,
                address: field.to,
                write: field.write,
                width: field.width,
                base: Some(field.base),
            });
        }
        // Then the constant-address scan, which also sees device space discovery leaves unmapped outside Raw
        // Cortex-M projects.
        match self.access_index() {
            Ok(index) => {
                if index.incomplete {
                    notes.push("the access scan stopped at its budget, so some accesses may be missing".to_owned());
                }
                for access in index.by_address.iter().filter(|access| device(access.address)) {
                    if seen.insert((access.instruction, access.address)) {
                        hits.push(Hit {
                            function: access.function,
                            address: access.address,
                            write: access.write,
                            width: access.width,
                            base: None,
                        });
                    }
                }
            }
            Err(error) => notes.push(format!("only base-register accesses are listed: {error}")),
        }
        hits.retain(wanted);
        let blocks = assign_blocks(&hits, space, &svd);
        // block -> offset -> register.
        let mut map: Blocks = BTreeMap::new();
        let mut per_function: BTreeMap<u64, Blocks> = BTreeMap::new();
        for (hit, (key, register_name)) in hits.iter().zip(&blocks) {
            let offset = hit.address.wrapping_sub(key.base);
            for register in [
                map.entry(key.clone()).or_default().entry(offset).or_default(),
                per_function
                    .entry(hit.function)
                    .or_default()
                    .entry(key.clone())
                    .or_default()
                    .entry(offset)
                    .or_default(),
            ] {
                register.name.clone_from(register_name);
                if hit.write {
                    register.writes += 1;
                } else {
                    register.reads += 1;
                }
                register.width = register.width.max(hit.width);
                *register.functions.entry(hit.function).or_default() += 1;
            }
        }
        let counts = PeripheralMapCounts {
            accesses: hits.len(),
            reads: hits.iter().filter(|hit| !hit.write).count(),
            writes: hits.iter().filter(|hit| hit.write).count(),
            blocks: map.len(),
            functions: per_function.len(),
        };
        let annotations = self.annotations();
        let name = |address: u64| self.function_name_in(&annotations, address);
        // The function that writes the most registers is the likeliest configuration routine to read first.
        let configurer = per_function
            .iter()
            .map(|(&address, blocks)| {
                let written = blocks.values().flat_map(BTreeMap::values).filter(|register| register.writes > 0);
                (written.count(), blocks.len(), address)
            })
            .filter(|(written, _, _)| *written > 0)
            .max_by_key(|&(written, blocks, address)| (written, blocks, std::cmp::Reverse(address)));
        let next = configurer.map(|(written, blocks, address)| {
            let function = name(address);
            let blocks =
                if blocks == 1 { "1 peripheral block".to_owned() } else { format!("{blocks} peripheral blocks") };
            if query.function.is_some() {
                format!("decompile {function}: it writes {written} registers in {blocks}")
            } else {
                format!(
                    "decompile {function}: it writes the most registers ({written}, in {blocks}); peripheral_map \
                     with function={function} lists them"
                )
            }
        });
        if hits.is_empty() {
            notes.push(
                "no load or store reaches device space: peripheral accesses through pointers passed in arguments \
                 or loaded from memory are not resolved"
                    .to_owned(),
            );
        }
        if svd.is_empty() && !hits.is_empty() {
            notes.push(
                "no SVD is imported: blocks are named by address (core blocks by the architecture); import_svd \
                 names vendor peripherals"
                    .to_owned(),
            );
        }
        let limit = query.limit.max(1);
        if query.by_function {
            let mut rows: Vec<(u64, Blocks)> = per_function.into_iter().collect();
            rows.sort_by_key(|(address, blocks)| {
                let writes: usize = blocks.values().flat_map(BTreeMap::values).map(|register| register.writes).sum();
                (std::cmp::Reverse(blocks.len()), std::cmp::Reverse(writes), *address)
            });
            let page = crate::rows::Page::of(rows, Some(query.offset), Some(limit));
            let functions = page
                .items
                .into_iter()
                .map(|(address, blocks)| {
                    let registers = || blocks.values().flat_map(BTreeMap::values);
                    let more_blocks = blocks.len().saturating_sub(MAX_FUNCTION_BLOCKS);
                    PeripheralFunctionRow {
                        function: name(address),
                        address,
                        reads: registers().map(|register| register.reads).sum(),
                        writes: registers().map(|register| register.writes).sum(),
                        blocks: blocks
                            .iter()
                            .take(MAX_FUNCTION_BLOCKS)
                            .map(|(key, registers)| PeripheralFunctionBlock {
                                name: key.name.clone(),
                                base: key.base,
                                offsets: registers
                                    .iter()
                                    .map(|(offset, register)| match &register.name {
                                        Some(name) => format!("{offset:#x} {name} {}", register.access()),
                                        None => format!("{offset:#x} {}", register.access()),
                                    })
                                    .collect(),
                            })
                            .collect(),
                        more_blocks,
                    }
                })
                .collect();
            return Ok(PeripheralMapReport {
                counts,
                total: page.total,
                offset: page.offset,
                blocks: Vec::new(),
                functions,
                notes,
                next,
            });
        }
        let page = crate::rows::Page::of(map, Some(query.offset), Some(limit));
        let blocks = page
            .items
            .into_iter()
            .map(|(key, registers)| {
                let mut functions: HashMap<u64, usize> = HashMap::new();
                for register in registers.values() {
                    for (&function, &count) in &register.functions {
                        *functions.entry(function).or_default() += count;
                    }
                }
                let mut ranked: Vec<(u64, usize)> = functions.into_iter().collect();
                ranked.sort_by_key(|&(address, count)| (std::cmp::Reverse(count), address));
                let more_registers = registers.len().saturating_sub(MAX_REGISTERS);
                PeripheralBlockRow {
                    reads: registers.values().map(|register| register.reads).sum(),
                    writes: registers.values().map(|register| register.writes).sum(),
                    functions: ranked.len(),
                    accessed_by: ranked.iter().take(MAX_BLOCK_FUNCTIONS).map(|&(address, _)| name(address)).collect(),
                    registers: registers
                        .into_iter()
                        .take(MAX_REGISTERS)
                        .map(|(offset, register)| {
                            let mut functions: Vec<(u64, usize)> =
                                register.functions.iter().map(|(&address, &count)| (address, count)).collect();
                            functions.sort_by_key(|&(address, count)| (std::cmp::Reverse(count), address));
                            PeripheralRegisterUse {
                                offset,
                                access: register.access(),
                                width: register.width,
                                reads: register.reads,
                                writes: register.writes,
                                more_functions: functions.len().saturating_sub(MAX_REGISTER_FUNCTIONS),
                                functions: functions
                                    .iter()
                                    .take(MAX_REGISTER_FUNCTIONS)
                                    .map(|&(address, _)| name(address))
                                    .collect(),
                                name: register.name,
                            }
                        })
                        .collect(),
                    more_registers,
                    name: key.name,
                    base: key.base,
                    source: key.source,
                }
            })
            .collect();
        Ok(PeripheralMapReport {
            counts,
            total: page.total,
            offset: page.offset,
            blocks,
            functions: Vec::new(),
            notes,
            next,
        })
    }
}

/// Each hit's block, and its register's name when an SVD or the architecture gives one.
fn assign_blocks(
    hits: &[Hit],
    space: DeviceSpace,
    svd: &crate::peripherals::PeripheralMap,
) -> Vec<(BlockKey, Option<String>)> {
    let named = |hit: &Hit| -> Option<(BlockKey, Option<String>)> {
        if let Some(found) = svd.at(hit.address) {
            let name = found.name();
            let register = name.strip_prefix(&format!("{}.", found.peripheral.name)).map(str::to_owned);
            let key = BlockKey { base: found.peripheral.base, name: found.peripheral.name.clone(), source: "svd" };
            return Some((key, register));
        }
        if space == (DeviceSpace::Arm { core: true })
            && let Some(block) = core_block(hit.address)
        {
            let key = BlockKey { base: block.base, name: block.name.to_owned(), source: "core" };
            return Some((key, core_register(block, hit.address - block.base)));
        }
        None
    };
    let address_key = |base: u64| BlockKey { base, name: format!("periph_{base:08x}"), source: "address" };
    // Blocks a base register reaches: its 1 KiB-aligned window, when the access lies within reach of it.
    let mut reach: BTreeMap<u64, u64> = BTreeMap::new();
    let based = |hit: &Hit| {
        let base = hit.base? & !(BLOCK_ALIGN - 1);
        (base <= hit.address && hit.address - base < BLOCK_REACH).then_some(base)
    };
    for hit in hits.iter().filter(|hit| named(hit).is_none()) {
        if let Some(base) = based(hit) {
            let end = reach.entry(base).or_insert(base);
            *end = (*end).max(hit.address + u64::from(hit.width.max(1)));
        }
    }
    hits.iter()
        .map(|hit| {
            if let Some(found) = named(hit) {
                return found;
            }
            if let Some(base) = based(hit) {
                return (address_key(base), None);
            }
            // An access with no base register joins a block a base register reaches, else its own window.
            let aligned = hit.address & !(BLOCK_ALIGN - 1);
            let base = reach
                .range(..=hit.address)
                .next_back()
                .filter(|(_, end)| hit.address < **end)
                .map_or(aligned, |(&base, _)| base);
            (address_key(base), None)
        })
        .collect()
}
