//! `peripheral_map`: which code touches which memory-mapped peripheral, built from load and store instructions only,
//! so literal-pool words and data tables that are never dereferenced do not reach it.
//!
//! The accesses come from discovery's base-plus-offset field references (a load or store through a base register
//! whose value is known, carried across a function's blocks) and from the constant-address access scan the SVD
//! surface uses (constants formed in registers, MOVW/MOVT pairs, direct memory operands). An access counts when its
//! address lies in device space: on 32-bit ARM the peripheral (0x40000000-0x5fffffff) and external device
//! (0xa0000000-0xdfffffff) regions, plus the private peripheral bus (0xe0000000-0xe00fffff) on M-profile, on MIPS32
//! uncached kseg1, on Xtensa the ESP peripheral windows, and anywhere an imported SVD places a peripheral. An access
//! misaligned for its width, or made by a "function" whose instructions run over NUL-terminated text (data decoded
//! as code), is dropped. Accesses are grouped into peripheral blocks: an imported SVD peripheral, an architectural
//! Cortex-M core block (SCB, NVIC, SysTick, MPU, DWT, ...) or else the 1 KiB-aligned windows the base registers'
//! values reach, merged where they overlap. Blocks are assigned over every access before any filter applies, so a
//! register keeps its block and offset whatever the query.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::AtomicBool;

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
/// A NUL-terminated printable run this long inside a function's instructions marks it as data decoded as code.
const DATA_TEXT_RUN: usize = 8;
/// Distinct instructions a block needs before `next` may point at a function writing it.
const NEXT_MIN_INSTRUCTIONS: usize = 2;
/// The Cortex-M3/M4 peripheral bit-band alias and the region it maps.
const BIT_BAND_ALIAS: std::ops::Range<u64> = 0x4200_0000..0x4400_0000;
const BIT_BAND_REGION: u64 = 0x4000_0000;

/// `1 block`, `2 blocks`.
pub(crate) fn plural(count: usize, noun: &str) -> String {
    if count == 1 { format!("1 {noun}") } else { format!("{count} {noun}s") }
}

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
    /// Bits set or cleared through the Cortex-M bit-band alias, when the code reaches the register that way.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bit_band: Vec<u8>,
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
pub(crate) enum DeviceSpace {
    /// 32-bit ARM; `core` is M-profile, whose private peripheral bus holds the architectural blocks.
    Arm {
        core: bool,
    },
    Mips,
    Xtensa,
    /// Only what an imported SVD covers.
    Svd,
}

/// ARM external device space, which boards also use for external RAM.
const ARM_EXTERNAL: std::ops::Range<u64> = 0xa000_0000..0xe000_0000;
/// MIPS uncached kseg1 below the boot ROM.
const MIPS_KSEG1: std::ops::Range<u64> = 0xa000_0000..0xbfc0_0000;

impl DeviceSpace {
    pub(crate) fn contains(self, address: u64) -> bool {
        match self {
            DeviceSpace::Arm { core } => {
                (0x4000_0000..0x6000_0000).contains(&address)
                    || ARM_EXTERNAL.contains(&address)
                    || (core && (0xe000_0000..0xe010_0000).contains(&address))
            }
            DeviceSpace::Mips => MIPS_KSEG1.contains(&address),
            // ESP32 DPORT and peripherals; ESP8266, ESP32-S2/S3 peripherals.
            DeviceSpace::Xtensa => {
                (0x3ff0_0000..0x3ff8_0000).contains(&address) || (0x6000_0000..0x6010_0000).contains(&address)
            }
            DeviceSpace::Svd => false,
        }
    }

    /// What the address-derived part of the map may get wrong on this target, given the accesses found.
    fn caveats(self, addresses: impl Iterator<Item = u64> + Clone) -> Vec<String> {
        let mut notes = Vec::new();
        let any = |range: &std::ops::Range<u64>| addresses.clone().any(|address| range.contains(&address));
        match self {
            DeviceSpace::Arm { core: false } if addresses.clone().next().is_some() => notes.push(
                "not an M-profile image: on Cortex-A/R parts 0x40000000 and up may be DRAM rather than peripherals; \
                 import_svd (or the part's memory map) confirms which blocks are devices"
                    .to_owned(),
            ),
            DeviceSpace::Arm { .. } if any(&ARM_EXTERNAL) => notes.push(
                "0xa0000000-0xdfffffff is external device space, which boards also use for external RAM".to_owned(),
            ),
            DeviceSpace::Mips if any(&MIPS_KSEG1) => notes.push(
                "kseg1 is uncached: besides device registers it reaches RAM and flash, so a block there may be \
                 uncached memory"
                    .to_owned(),
            ),
            _ => {}
        }
        notes
    }
}

/// A hosted (operating-system) ELF: an interpreter or shared libraries, an OS ABI in the header or an ABI note, or
/// a C library's start routine.
fn hosted_elf(binary: &Binary) -> bool {
    if binary.format != Format::Elf {
        return false;
    }
    let dynamic = !binary.imports.is_empty()
        || matches!(&binary.details, Details::Elf(details) if details.interpreter.is_some() || !details.needed.is_empty());
    // EI_OSABI: 0 is System V, 97 ARM and 255 standalone; the others name an operating system.
    let osabi = binary.image_bytes().get(7).copied().unwrap_or(0);
    let os_abi = binary.image_bytes().starts_with(b"\x7fELF") && !matches!(osabi, 0 | 97 | 255);
    let abi_note = binary.sections.iter().any(|section| section.name == ".note.ABI-tag");
    let libc = ["__libc_start_main", "__libc_start_call_main", "__uClibc_main"]
        .iter()
        .any(|name| binary.symbol_by_name(name).is_some());
    dynamic || os_abi || abi_note || libc
}

/// The device space of a firmware-like target, or why it has none.
pub(crate) fn device_space(binary: &Binary) -> Result<DeviceSpace, String> {
    let firmware = binary.format == Format::Raw || (binary.format == Format::Elf && !hosted_elf(binary));
    match binary.arch {
        Arch::Arm | Arch::Mips | Arch::Xtensa if !firmware => Err(format!(
            "this {} image is not firmware-like (it is hosted: it loads shared libraries, names an operating system \
             ABI or links a C library's start routine), so its loads and stores are not read as peripheral accesses",
            binary.arch
        )),
        Arch::Arm if binary.m_profile() => Ok(DeviceSpace::Arm { core: true }),
        Arch::Arm => Ok(DeviceSpace::Arm { core: false }),
        Arch::Mips => Ok(DeviceSpace::Mips),
        Arch::Xtensa => Ok(DeviceSpace::Xtensa),
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
pub(crate) struct Hit {
    pub instruction: u64,
    pub function: u64,
    /// The register's address; for a bit-band alias access, the word the bit lies in.
    pub address: u64,
    pub write: bool,
    pub width: u8,
    /// The base register's value, for a field reference.
    base: Option<u64>,
    /// For a bit-band alias access, the bit of the word at `address`.
    bit: Option<u8>,
}

/// Every device-space access the code makes, for `peripheral_map` and `peripheral_access`.
#[derive(Debug, Default)]
pub(crate) struct DeviceHits {
    /// Sorted by address, then instruction.
    pub hits: Vec<Hit>,
    /// The access scan stopped at its budget or could not run.
    pub incomplete: bool,
    pub notes: Vec<String>,
}

impl DeviceHits {
    pub fn in_range(&self, start: u64, end: u64) -> &[Hit] {
        let first = self.hits.partition_point(|hit| hit.address < start);
        let last = self.hits.partition_point(|hit| hit.address < end);
        &self.hits[first..last]
    }
}

/// A peripheral block the accesses are grouped into.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    bits: BTreeSet<u8>,
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
    /// Functions whose instructions run over NUL-terminated text: data that discovery decoded as code.
    fn data_like_functions(&self, analysis: &crate::project::Analysis) -> BTreeSet<u64> {
        analysis
            .program
            .functions
            .iter()
            .filter(|function| {
                function.blocks.iter().any(|block| {
                    let Some(bytes) = self.binary.read(block.start, block.end.saturating_sub(block.start)) else {
                        return false;
                    };
                    rampage_analysis::strings::scan_bytes(bytes, block.start, DATA_TEXT_RUN).iter().any(|string| {
                        let end = (string.address - block.start) as usize + string.text.len();
                        string.encoding == rampage_analysis::strings::Encoding::Ascii && bytes.get(end) == Some(&0)
                    })
                })
            })
            .map(|function| function.address)
            .collect()
    }

    /// The loads and stores whose address `device` admits, from the field references and the access scan, each
    /// once per instruction, address and direction. With `bit_band`, Cortex-M bit-band alias accesses are
    /// mapped to the word and bit they reach.
    pub(crate) fn device_hits(
        &self,
        device: &dyn Fn(u64) -> bool,
        bit_band: bool,
        cancel: Option<&AtomicBool>,
    ) -> Result<DeviceHits, ApiError> {
        let analysis = self.analysis()?;
        let data_like = self.data_like_functions(analysis);
        let mut collected = DeviceHits::default();
        let mut seen: BTreeSet<(u64, u64, bool)> = BTreeSet::new();
        let mut push = |hit: Hit, collected: &mut DeviceHits| {
            let aligned = hit.width == 0 || hit.address.is_multiple_of(u64::from(hit.width));
            if !aligned || data_like.contains(&hit.function) || !seen.insert((hit.instruction, hit.address, hit.write))
            {
                return;
            }
            let mut hit = hit;
            if bit_band && BIT_BAND_ALIAS.contains(&hit.address) {
                let alias = hit.address - BIT_BAND_ALIAS.start;
                let byte = BIT_BAND_REGION + alias / 32;
                let bit = (byte % 4) * 8 + (alias / 4) % 8;
                hit = Hit { address: byte & !3, width: 4, base: None, bit: u8::try_from(bit).ok(), ..hit };
            }
            collected.hits.push(hit);
        };
        // Field references first: they carry the base register's value.
        for field in analysis.program.field_refs.iter().filter(|field| device(field.to)) {
            let Some(function) = analysis.function_containing(field.from) else { continue };
            let hit = Hit {
                instruction: field.from,
                function,
                address: field.to,
                write: field.write,
                width: field.width,
                base: Some(field.base),
                bit: None,
            };
            push(hit, &mut collected);
        }
        // Then the constant-address scan, which also sees device space discovery leaves unmapped.
        match self.access_index_controlled(cancel) {
            Ok(index) => {
                collected.incomplete = index.incomplete;
                if index.incomplete {
                    collected
                        .notes
                        .push("the access scan stopped at its budget, so some accesses may be missing".to_owned());
                }
                for access in index.by_address.iter().filter(|access| device(access.address)) {
                    let hit = Hit {
                        instruction: access.instruction,
                        function: access.function,
                        address: access.address,
                        write: access.write,
                        width: access.width,
                        base: None,
                        bit: None,
                    };
                    push(hit, &mut collected);
                }
            }
            Err(error) if cancel.is_some_and(|cancel| cancel.load(std::sync::atomic::Ordering::Relaxed)) => {
                return Err(error);
            }
            Err(error) => {
                collected.incomplete = true;
                collected.notes.push(format!("only base-register accesses are listed: {error}"));
            }
        }
        let dropped = data_like.len();
        if dropped > 0 {
            collected.notes.push(format!(
                "{} whose instructions run over NUL-terminated text (data decoded as code) left out",
                plural(dropped, "function")
            ));
        }
        collected.hits.sort_by_key(|hit| (hit.address, hit.instruction, hit.write));
        Ok(collected)
    }

    /// The peripheral blocks the code's loads and stores reach, with the registers and functions touching each, or
    /// with `by_function` the blocks each function touches.
    pub fn map_peripherals(&self, query: &PeripheralMapQuery) -> Result<PeripheralMapReport, ApiError> {
        self.map_peripherals_controlled(query, None)
    }

    /// [`Self::map_peripherals`], giving up once `cancel` is set.
    pub fn map_peripherals_controlled(
        &self,
        query: &PeripheralMapQuery,
        cancel: Option<&AtomicBool>,
    ) -> Result<PeripheralMapReport, ApiError> {
        if let (Some(start), Some(end)) = (query.start, query.end)
            && start >= end
        {
            return Err(ApiError::Invalid(format!("start {start:#x} must lie below end {end:#x}")));
        }
        let svd = self.peripheral_map();
        let empty = |notes: Vec<String>| PeripheralMapReport {
            counts: PeripheralMapCounts::default(),
            total: 0,
            offset: query.offset,
            blocks: Vec::new(),
            functions: Vec::new(),
            notes,
            next: None,
        };
        let space = match device_space(&self.binary) {
            Ok(space) => space,
            Err(_) if !svd.is_empty() => DeviceSpace::Svd,
            Err(reason) => return Ok(empty(vec![reason])),
        };
        let analysis = self.analysis()?;
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
        let in_code = |address: u64| self.binary.segment_containing(address).is_some_and(|s| s.perms.execute);
        let device = |address: u64| (space.contains(address) || svd.at(address).is_some()) && !in_code(address);
        let collected = self.device_hits(&device, space == (DeviceSpace::Arm { core: true }), cancel)?;
        let mut notes = collected.notes;
        // Blocks over every access, before any filter, so a register's block never depends on the query.
        let keys = assign_blocks(&collected.hits, space, &svd);
        let mut instructions: HashMap<&BlockKey, BTreeSet<u64>> = HashMap::new();
        for (hit, (key, _)) in collected.hits.iter().zip(&keys) {
            instructions.entry(key).or_default().insert(hit.instruction);
        }
        let wanted = |hit: &Hit| {
            function.is_none_or(|function| hit.function == function)
                && query.start.is_none_or(|start| hit.address >= start)
                && query.end.is_none_or(|end| hit.address < end)
        };
        let selected: Vec<(&Hit, &(BlockKey, Option<String>))> =
            collected.hits.iter().zip(&keys).filter(|(hit, _)| wanted(hit)).collect();
        // block -> offset -> register, overall and per function.
        let mut map: Blocks = BTreeMap::new();
        let mut per_function: BTreeMap<u64, Blocks> = BTreeMap::new();
        for &(hit, (key, register_name)) in &selected {
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
                register.bits.extend(hit.bit);
                *register.functions.entry(hit.function).or_default() += 1;
            }
        }
        let counts = PeripheralMapCounts {
            accesses: selected.len(),
            reads: selected.iter().filter(|(hit, _)| !hit.write).count(),
            writes: selected.iter().filter(|(hit, _)| hit.write).count(),
            blocks: map.len(),
            functions: per_function.len(),
        };
        let annotations = self.annotations();
        let name = |address: u64| self.function_name_in(&annotations, address);
        // The function writing the most registers is the likeliest configuration routine to read first; only
        // blocks more than one instruction touches count, so one stray store does not decide it.
        let configurer = per_function
            .iter()
            .map(|(&address, blocks)| {
                let eligible: Vec<&BTreeMap<u64, Register>> = blocks
                    .iter()
                    .filter(|(key, _)| instructions.get(key).is_some_and(|set| set.len() >= NEXT_MIN_INSTRUCTIONS))
                    .map(|(_, registers)| registers)
                    .collect();
                let written = eligible.iter().flat_map(|registers| registers.values()).filter(|r| r.writes > 0);
                let written_blocks = eligible.iter().filter(|registers| registers.values().any(|r| r.writes > 0));
                (written.count(), written_blocks.count(), address)
            })
            .filter(|(written, _, _)| *written > 0)
            .max_by_key(|&(written, blocks, address)| (written, blocks, std::cmp::Reverse(address)));
        let next = configurer.map(|(written, blocks, address)| {
            let function = name(address);
            let (written, blocks) = (plural(written, "register"), plural(blocks, "peripheral block"));
            if query.function.is_some() {
                format!("decompile {function}: it writes {written} in {blocks}")
            } else {
                format!(
                    "decompile {function}: it writes the most registers ({written} in {blocks}); peripheral_map with \
                     function={function} lists them"
                )
            }
        });
        notes.extend(space.caveats(selected.iter().map(|(hit, _)| hit.address)));
        if selected.is_empty() {
            notes.push(
                "no load or store reaches device space: peripheral accesses through pointers passed in arguments \
                 or loaded from memory are not resolved"
                    .to_owned(),
            );
        } else if svd.is_empty() {
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
            return Ok(PeripheralMapReport { functions, total: page.total, offset: page.offset, ..empty(notes) }
                .with(counts, next));
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
                                bit_band: register.bits.iter().copied().collect(),
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
        Ok(PeripheralMapReport { blocks, total: page.total, offset: page.offset, ..empty(notes) }.with(counts, next))
    }
}

impl PeripheralMapReport {
    fn with(self, counts: PeripheralMapCounts, next: Option<String>) -> Self {
        Self { counts, next, ..self }
    }
}

/// Each hit's block, and its register's name when an SVD or the architecture gives one. A hit no SVD peripheral or
/// core block holds goes to the merged reach of the base registers (each base's 1 KiB-aligned window up to the
/// furthest access through it) that covers its address, else to its own 1 KiB window.
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
    let mut reach: Vec<(u64, u64)> = hits
        .iter()
        .filter(|hit| named(hit).is_none())
        .filter_map(|hit| {
            let base = hit.base? & !(BLOCK_ALIGN - 1);
            (base <= hit.address && hit.address - base < BLOCK_REACH)
                .then(|| (base, hit.address + u64::from(hit.width.max(1))))
        })
        .collect();
    reach.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in reach {
        match merged.last_mut() {
            Some(last) if start < last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    hits.iter()
        .map(|hit| {
            if let Some(found) = named(hit) {
                return found;
            }
            let covering = merged.partition_point(|&(start, _)| start <= hit.address);
            let base = covering
                .checked_sub(1)
                .map(|index| merged[index])
                .filter(|&(_, end)| hit.address < end)
                .map_or(hit.address & !(BLOCK_ALIGN - 1), |(start, _)| start);
            (address_key(base), None)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(address: u64, base: Option<u64>) -> Hit {
        Hit { instruction: address, function: 0, address, write: false, width: 4, base, bit: None }
    }

    #[test]
    fn device_spaces_by_processor() {
        let m = DeviceSpace::Arm { core: true };
        let a = DeviceSpace::Arm { core: false };
        assert!(m.contains(0x4001_0000) && m.contains(0xe000_ed08) && m.contains(0xa000_0000));
        assert!(!m.contains(0x2000_0000) && !m.contains(0x6000_0000) && !m.contains(0xe010_0000));
        // The private peripheral bus is M-profile only.
        assert!(a.contains(0x4001_0000) && !a.contains(0xe000_ed08));
        let mips = DeviceSpace::Mips;
        assert!(mips.contains(0xb800_0000) && !mips.contains(0xbfc0_0000) && !mips.contains(0x8000_0000));
        let xtensa = DeviceSpace::Xtensa;
        assert!(xtensa.contains(0x3ff4_0000) && xtensa.contains(0x6000_0000));
        assert!(!xtensa.contains(0x3ffb_0000) && !xtensa.contains(0x4008_0000) && !xtensa.contains(0x6010_0000));
        assert!(!DeviceSpace::Svd.contains(0x4001_0000));
        assert_eq!(mips.caveats([0xb800_0000].into_iter()).len(), 1);
        assert_eq!(a.caveats([0x4000_0000].into_iter()).len(), 1);
        assert_eq!(m.caveats([0xa000_0000].into_iter()).len(), 1);
        assert!(m.caveats([0x4000_0000].into_iter()).is_empty());
    }

    #[test]
    fn overlapping_base_reaches_merge_into_one_block() {
        let svd = crate::peripherals::PeripheralMap::default();
        let space = DeviceSpace::Arm { core: true };
        // Base 0x50000000 reaches +0x800; base 0x50000800 starts its own window inside that reach, and an access
        // with no base at 0x50000804 lands in the same block, not in a window of its own.
        let hits = [hit(0x5000_0800, Some(0x5000_0000)), hit(0x5000_0804, Some(0x5000_0800)), hit(0x5000_0804, None)];
        let bases: Vec<u64> = assign_blocks(&hits, space, &svd).iter().map(|(key, _)| key.base).collect();
        assert_eq!(bases, [0x5000_0000, 0x5000_0000, 0x5000_0000]);
        // Past every reach, an access gets its own 1 KiB window.
        let keys = assign_blocks(&[hit(0x5000_0000, Some(0x5000_0000)), hit(0x5000_0c00, None)], space, &svd);
        assert_eq!(keys[1].0.base, 0x5000_0c00);
    }

    #[test]
    fn core_registers_are_named() {
        let nvic = core_block(0xe000_e184).unwrap();
        assert_eq!((nvic.name, core_register(nvic, 0x84).as_deref()), ("NVIC", Some("ICER1")));
        assert_eq!(core_register(nvic, 0x304).as_deref(), Some("IPR1"));
        let scb = core_block(0xe000_ed08).unwrap();
        assert_eq!((scb.name, core_register(scb, 0x8).as_deref()), ("SCB", Some("VTOR")));
        assert!(core_block(0xe000_ef10).is_none());
    }

    #[test]
    fn plurals() {
        assert_eq!(plural(1, "peripheral block"), "1 peripheral block");
        assert_eq!(plural(2, "register"), "2 registers");
    }
}
