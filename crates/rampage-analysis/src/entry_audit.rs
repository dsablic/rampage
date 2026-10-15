//! Bounded local evidence at exact addresses, without discovery, graph edits or function verification.

use std::collections::{BTreeMap, BTreeSet};

use rampage_arch::{Arch, Disassembler, Flow, Target};
use rampage_loaders::{Binary, SymbolKind, shannon_entropy};
use serde::Serialize;

pub const MAX_ENTRIES: usize = 64;
pub const MAX_BYTES_PER_ENTRY: usize = 128;
pub const MAX_INSTRUCTIONS_PER_ENTRY: usize = 16;
pub const MAX_TOTAL_BYTES: usize = MAX_ENTRIES * MAX_BYTES_PER_ENTRY;
pub const MAX_TOTAL_DECODE_ATTEMPTS: usize = MAX_ENTRIES * MAX_INSTRUCTIONS_PER_ENTRY;
pub const MAX_METADATA_ITEMS: usize = 16_384;
pub const MAX_DECLARATIONS: usize = 65_536;
pub const MAX_NAME_BYTES: usize = 4096;
pub const MAX_METADATA_NAME_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OUTPUT_NAME_BYTES: usize = 64 * 1024;
pub const MAX_ORIGINS_PER_ENTRY: usize = 16;
pub const MAX_LOOKUP_WORK: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EntryAuditLimits {
    pub max_entries: usize,
    pub bytes_per_entry: usize,
    pub instructions_per_entry: usize,
    pub total_bytes: usize,
    pub total_decode_attempts: usize,
}

impl Default for EntryAuditLimits {
    fn default() -> Self {
        Self {
            max_entries: MAX_ENTRIES,
            bytes_per_entry: MAX_BYTES_PER_ENTRY,
            instructions_per_entry: MAX_INSTRUCTIONS_PER_ENTRY,
            total_bytes: MAX_TOTAL_BYTES,
            total_decode_attempts: MAX_TOTAL_DECODE_ATTEMPTS,
        }
    }
}

impl EntryAuditLimits {
    fn clamped(self) -> Self {
        Self {
            max_entries: self.max_entries.min(MAX_ENTRIES),
            bytes_per_entry: self.bytes_per_entry.min(MAX_BYTES_PER_ENTRY),
            instructions_per_entry: self.instructions_per_entry.min(MAX_INSTRUCTIONS_PER_ENTRY),
            total_bytes: self.total_bytes.min(MAX_TOTAL_BYTES),
            total_decode_attempts: self.total_decode_attempts.min(MAX_TOTAL_DECODE_ATTEMPTS),
        }
    }

    fn disabled(self) -> bool {
        self.max_entries == 0
            || self.bytes_per_entry == 0
            || self.instructions_per_entry == 0
            || self.total_bytes == 0
            || self.total_decode_attempts == 0
    }
}

#[derive(Debug, Serialize)]
pub struct EntryAudit {
    pub status: EntryAuditStatus,
    pub limits: EntryAuditLimits,
    pub usage: EntryAuditUsage,
    /// Sorted by exact address; metadata declarations are not verified function starts.
    pub entries: Vec<EntryEvidence>,
    pub truncation: Vec<EntryAuditTruncation>,
    pub warnings: Vec<&'static str>,
    pub limitations: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryAuditStatus {
    Available,
    Empty,
    Disabled,
    Unavailable,
}

#[derive(Debug, Default, Serialize)]
pub struct EntryAuditUsage {
    /// Combined symbol, export, function-start and optional entry records, before deduplication.
    pub declaration_records: usize,
    pub lookup_work_reserved: usize,
    pub name_bytes_copied: usize,
    pub bytes_sampled: usize,
    /// Public decoder calls; decoder-internal lookahead is also bounded by the sampled window.
    pub decode_attempts: usize,
    pub instructions: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryAuditTruncation {
    RequestedLimitsClamped,
    EntryLimit,
    MetadataLimit,
    DeclarationLimit,
    NameLengthLimit,
    MetadataNameBytes,
    OutputNameBytes,
    OriginLimit,
    LookupWork,
    TotalBytes,
    TotalDecodeAttempts,
    InvalidThumbMetadata,
}

#[derive(Debug, Serialize)]
pub struct EntryEvidence {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub origins: Vec<EntryOrigin>,
    /// Includes duplicate metadata records, even though identical origins are deduplicated.
    pub metadata_records_at_address: usize,
    pub origins_truncated: bool,
    pub status: EntrySampleStatus,
    pub unavailable_reason: Option<&'static str>,
    pub assessment: EntryAssessment,
    pub bytes_sampled: usize,
    pub decoded_bytes: usize,
    pub decode_attempts: usize,
    pub instruction_count: usize,
    pub invalid_count: usize,
    pub indirect_calls: usize,
    /// Counts explicit indirect-jump flows only; conditional transfers encoded as Next stay unclassified.
    pub indirect_jumps: usize,
    /// Entropy of the whole sampled window, including bytes after the observed control transfer.
    pub entropy_bits_per_byte: Option<f64>,
    pub signals: Vec<EntrySignal>,
    pub stop: EntrySampleStop,
    /// Stopped instruction address, or exclusive WindowEnd cursor; a 32-bit end may equal 0x100000000.
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub stop_address: Option<u64>,
    /// Observed decoder flow only; targets are neither followed nor inserted into a graph.
    pub last_flow: Option<Flow>,
    /// The last decoder instruction's conditional-transfer flag, not ordinary conditional data execution.
    /// With last_flow == Next, this records a conditional return or indirect jump without distinguishing them.
    pub last_conditional_transfer: bool,
    pub window_bounds: Vec<EntryWindowBound>,
}

#[derive(Debug, Serialize)]
pub struct EntryOrigin {
    pub kind: EntryOriginKind,
    pub name: Option<String>,
    pub name_omitted: bool,
    pub symbol_kind: Option<SymbolKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryOriginKind {
    Symbol,
    Export,
    FunctionStarts,
    Entry,
    /// An exact address supplied by the caller, not a metadata-backed function assertion.
    CallerAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrySampleStatus {
    BackedExecutableCode,
    NonCode,
    Unavailable,
    Unaligned,
    AddressOutsideTargetWidth,
    UnsupportedArchitecture,
    UnsupportedByteOrder,
    ModeUnavailable,
    BudgetUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryAssessment {
    Unknown,
    Suspicious,
    /// A local decode observation, not executable semantics or a verified function boundary.
    LocallyPlausible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrySignal {
    /// At least 64 sampled bytes with entropy >= 6.5 bits/byte; not encryption/protector evidence.
    HighEntropyWindow,
    DecodeFailure,
    /// The decoder cannot distinguish invalid bytes from an incomplete instruction in this short tail.
    InvalidOrIncompleteTail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrySampleStop {
    NotSampled,
    WindowEnd,
    InstructionLimit,
    TotalDecodeAttempts,
    ControlTransfer,
    InvalidInstruction,
    InvalidOrIncompleteTail,
    IncompleteInstruction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryWindowBound {
    ByteLimit,
    CodeOrBackingBoundary,
    TargetAddressSpaceBoundary,
    ThumbModeBoundary,
    TotalByteBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct OriginRef<'a> {
    kind: EntryOriginKind,
    name: Option<&'a str>,
    symbol_kind: Option<u8>,
}

#[derive(Default)]
struct Seed<'a> {
    origins: BTreeSet<OriginRef<'a>>,
    records: usize,
    truncated: bool,
}

impl<'a> Seed<'a> {
    fn observe(&mut self, origin: OriginRef<'a>) {
        self.records += 1;
        self.origins.insert(origin);
        let named_limit = (MAX_ORIGINS_PER_ENTRY - 2) / 2;
        if matches!(origin.kind, EntryOriginKind::Symbol | EntryOriginKind::Export)
            && self.origins.iter().filter(|item| item.kind == origin.kind).count() > named_limit
        {
            let last = self.origins.iter().rev().find(|item| item.kind == origin.kind).copied();
            if let Some(last) = last {
                self.origins.remove(&last);
            }
            self.truncated = true;
        }
    }
}

impl EntryAudit {
    fn new(requested: EntryAuditLimits) -> Self {
        let limits = requested.clamped();
        let mut result = Self {
            status: if limits.disabled() { EntryAuditStatus::Disabled } else { EntryAuditStatus::Available },
            limits,
            usage: EntryAuditUsage::default(),
            entries: Vec::new(),
            truncation: Vec::new(),
            warnings: Vec::new(),
            limitations: vec![
                "Metadata-declared entries and caller addresses are assertions, not verified functions. Exact-address \
                 origins are retained; no containing-function fallback is used.",
                "Decoder success is not proof of executable semantics or a function boundary. Random fragments and \
                 data can decode, especially on x86; locally plausible means only a bounded local decode.",
                "Entropy describes the sampled byte window, which can include data after a control transfer. High \
                 entropy or decode failure does not establish encryption, a protector or any product identity.",
                "Only one straight-line prefix is decoded, stopping at the first control transfer, including \
                 conditional transfers, or invalid decode. Targets, calls and switches are not followed; no discovery, \
                 edges, annotations or types are added.",
                "At most 64 entries, 128 bytes and 16 decode attempts per entry, 8192 sampled bytes and 1024 public \
                 decoder calls total. Internal decoder lookahead sees only the bounded window.",
                "Preflight refuses over 16384 combined sections/segments/Thumb ranges, 65536 declarations, 4096 bytes \
                 per name or 4 MiB of metadata names. No full metadata vectors are cloned or sorted.",
                "At most three bounded declaration passes, seven symbol and seven export names plus function-start \
                 and entry origins per address, 64 KiB of copied names and one million reserved mapping-lookup visits. \
                 Truncation does not remove input candidates.",
                "Supports x86, x86-64, little-endian AArch64 and explicitly mapped Thumb. ARM outside a declared \
                 Thumb range has unresolved mode and is not guessed as A32. Other architectures are not sampled.",
                "x86 and ARM addresses must fit 32 bits; windows stop at the exclusive 0x100000000 address-space end. \
                 64-bit windows retain a representable, non-wrapping exclusive end at or below u64::MAX.",
                "Reads stay within one executable, file-backed code mapping and declared Thumb mode. Gaps, zero-fill \
                 and non-code mappings are not decoded; captured or on-disk bytes are not runtime behavior proof.",
            ],
        };
        if limits != requested {
            result.note(EntryAuditTruncation::RequestedLimitsClamped, "Requested sampling limits were clamped.");
        }
        result
    }

    fn note(&mut self, reason: EntryAuditTruncation, warning: &'static str) {
        if !self.truncation.contains(&reason) {
            self.truncation.push(reason);
            self.warnings.push(warning);
        }
    }

    fn refuse(&mut self, reason: EntryAuditTruncation, warning: &'static str) -> bool {
        self.status = EntryAuditStatus::Unavailable;
        self.note(reason, warning);
        false
    }
}

/// Samples only `address`, attaching exact-address metadata of every kind, including data symbols.
/// A caller-address assertion is emitted only when the complete bounded metadata scan finds no exact origin.
/// Any preflight refusal returns an unavailable report with no entries, not an ungrounded caller assertion.
pub fn sample_entry(binary: &Binary, address: u64, limits: EntryAuditLimits) -> EntryAudit {
    let mut result = EntryAudit::new(limits);
    if result.limits.disabled() || !preflight(binary, &mut result) {
        return result;
    }
    let mut seeds = BTreeMap::from([(address, Seed::default())]);
    attach_origins(binary, &mut seeds);
    sample_seeds(binary, seeds, &mut result);
    result
}

/// Samples the lowest bounded distinct addresses declared by function symbols, exports, format function starts
/// and the entry point. Exports need not be code. All exact symbol kinds at selected addresses remain evidence.
/// Selection and origin collection use separate bounded passes, never one full metadata scan per seed.
pub fn sample_declared_entries(binary: &Binary, limits: EntryAuditLimits) -> EntryAudit {
    let mut result = EntryAudit::new(limits);
    if result.limits.disabled() || !preflight(binary, &mut result) {
        return result;
    }
    let mut seeds = BTreeMap::new();
    let mut omitted = false;
    let addresses = binary
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Function)
        .map(|symbol| symbol.address)
        .chain(binary.exports.iter().map(|export| export.address))
        .chain(binary.function_starts.iter().copied())
        .chain(binary.entry);
    for address in addresses {
        seeds.entry(address).or_insert_with(Seed::default);
        if seeds.len() > result.limits.max_entries {
            seeds.pop_last();
            omitted = true;
        }
    }
    if omitted {
        result.note(EntryAuditTruncation::EntryLimit, "Declared entry selection reached its distinct-address limit.");
    }
    if seeds.is_empty() {
        result.status = EntryAuditStatus::Empty;
        result.warnings.push("No metadata-declared entries were available; discovery was not run.");
        return result;
    }
    attach_origins(binary, &mut seeds);
    sample_seeds(binary, seeds, &mut result);
    result
}

fn preflight(binary: &Binary, result: &mut EntryAudit) -> bool {
    let metadata_items = binary.sections.len().saturating_add(binary.segments.len()).saturating_add(binary.thumb.len());
    if metadata_items > MAX_METADATA_ITEMS {
        return result.refuse(EntryAuditTruncation::MetadataLimit, "Entry sampling exceeded its metadata-item budget.");
    }
    let declarations = binary
        .symbols
        .len()
        .saturating_add(binary.exports.len())
        .saturating_add(binary.function_starts.len())
        .saturating_add(usize::from(binary.entry.is_some()));
    if declarations > MAX_DECLARATIONS {
        return result.refuse(
            EntryAuditTruncation::DeclarationLimit,
            "Entry sampling exceeded its declaration-count budget before scanning declarations.",
        );
    }
    let mut name_bytes = 0_usize;
    let names =
        binary.symbols.iter().map(|symbol| &symbol.name).chain(binary.exports.iter().map(|export| &export.name));
    for name in names {
        if name.len() > MAX_NAME_BYTES {
            return result.refuse(
                EntryAuditTruncation::NameLengthLimit,
                "Entry sampling refused an oversized metadata name before copying names.",
            );
        }
        name_bytes = name_bytes.saturating_add(name.len());
        if name_bytes > MAX_METADATA_NAME_BYTES {
            return result.refuse(
                EntryAuditTruncation::MetadataNameBytes,
                "Entry sampling exceeded its aggregate metadata-name budget before copying names.",
            );
        }
    }
    if binary.thumb.iter().any(|range| range.start >= range.end)
        || binary.thumb.windows(2).any(|pair| pair[0].end > pair[1].start)
    {
        return result.refuse(
            EntryAuditTruncation::InvalidThumbMetadata,
            "Entry sampling refused unordered, overlapping or empty Thumb-mode ranges.",
        );
    }
    result.usage.declaration_records = declarations;
    true
}

fn attach_origins<'a>(binary: &'a Binary, seeds: &mut BTreeMap<u64, Seed<'a>>) {
    for symbol in &binary.symbols {
        if let Some(seed) = seeds.get_mut(&symbol.address) {
            let symbol_kind = match symbol.kind {
                SymbolKind::Function => 0,
                SymbolKind::Data => 1,
                SymbolKind::Other => 2,
            };
            seed.observe(OriginRef {
                kind: EntryOriginKind::Symbol,
                name: Some(&symbol.name),
                symbol_kind: Some(symbol_kind),
            });
        }
    }
    for export in &binary.exports {
        if let Some(seed) = seeds.get_mut(&export.address) {
            seed.observe(OriginRef { kind: EntryOriginKind::Export, name: Some(&export.name), symbol_kind: None });
        }
    }
    for &address in &binary.function_starts {
        if let Some(seed) = seeds.get_mut(&address) {
            seed.observe(OriginRef { kind: EntryOriginKind::FunctionStarts, name: None, symbol_kind: None });
        }
    }
    if let Some(seed) = binary.entry.and_then(|address| seeds.get_mut(&address)) {
        seed.observe(OriginRef { kind: EntryOriginKind::Entry, name: None, symbol_kind: None });
    }
    for seed in seeds.values_mut().filter(|seed| seed.records == 0) {
        seed.origins.insert(OriginRef { kind: EntryOriginKind::CallerAddress, name: None, symbol_kind: None });
    }
}

fn sample_seeds(binary: &Binary, seeds: BTreeMap<u64, Seed<'_>>, result: &mut EntryAudit) {
    // Binary::target clones Thumb ranges, so all metadata preflights must precede it.
    let target = binary.target();
    let supported = matches!(binary.arch, Arch::X86 | Arch::X86_64 | Arch::Aarch64 | Arch::Arm);
    let mut decoder = supported.then(|| rampage_arch::decoder(&target).ok()).flatten();
    let lookup_work = binary.segments.len() * 4 + binary.sections.len() + binary.thumb.len() + 16;
    for (address, seed) in seeds {
        let mut entry = new_evidence(address, seed, result);
        if matches!(binary.arch, Arch::X86 | Arch::Arm) && address > u64::from(u32::MAX) {
            entry.status = EntrySampleStatus::AddressOutsideTargetWidth;
            entry.unavailable_reason = Some("The exact address exceeds the declared 32-bit target address width.");
        } else if result.usage.bytes_sampled == result.limits.total_bytes {
            entry.status = EntrySampleStatus::BudgetUnavailable;
            entry.unavailable_reason = Some("Cumulative sampled-byte budget exhausted before reading this entry.");
            result
                .note(EntryAuditTruncation::TotalBytes, "Entry sampling exhausted its cumulative sampled-byte budget.");
        } else if result.usage.decode_attempts == result.limits.total_decode_attempts {
            entry.status = EntrySampleStatus::BudgetUnavailable;
            entry.unavailable_reason = Some("Cumulative decode-attempt budget exhausted before reading this entry.");
            result.note(
                EntryAuditTruncation::TotalDecodeAttempts,
                "Entry sampling exhausted its cumulative decode-attempt budget.",
            );
        } else if result.usage.lookup_work_reserved.saturating_add(lookup_work) > MAX_LOOKUP_WORK {
            entry.status = EntrySampleStatus::BudgetUnavailable;
            entry.unavailable_reason = Some("Cumulative mapping-lookup budget exhausted before reading this entry.");
            result.note(EntryAuditTruncation::LookupWork, "Entry sampling exhausted its mapping-lookup work budget.");
        } else {
            result.usage.lookup_work_reserved += lookup_work;
            sample_bytes(binary, &target, &mut decoder, &mut entry, result);
        }
        result.entries.push(entry);
    }
}

fn new_evidence(address: u64, seed: Seed<'_>, result: &mut EntryAudit) -> EntryEvidence {
    if seed.truncated {
        result.note(EntryAuditTruncation::OriginLimit, "Some entries exceeded the distinct-origin limit.");
    }
    let origins = seed
        .origins
        .into_iter()
        .map(|origin| {
            let name_omitted =
                origin.name.is_some_and(|name| result.usage.name_bytes_copied + name.len() > MAX_OUTPUT_NAME_BYTES);
            let name = if name_omitted {
                result.note(
                    EntryAuditTruncation::OutputNameBytes,
                    "Some exact-origin names exceeded the output-name budget.",
                );
                None
            } else {
                origin.name.map(|name| {
                    result.usage.name_bytes_copied += name.len();
                    name.to_owned()
                })
            };
            EntryOrigin {
                kind: origin.kind,
                name,
                name_omitted,
                symbol_kind: origin.symbol_kind.map(|kind| match kind {
                    0 => SymbolKind::Function,
                    1 => SymbolKind::Data,
                    _ => SymbolKind::Other,
                }),
            }
        })
        .collect();
    EntryEvidence {
        address,
        origins,
        metadata_records_at_address: seed.records,
        origins_truncated: seed.truncated,
        status: EntrySampleStatus::Unavailable,
        unavailable_reason: None,
        assessment: EntryAssessment::Unknown,
        bytes_sampled: 0,
        decoded_bytes: 0,
        decode_attempts: 0,
        instruction_count: 0,
        invalid_count: 0,
        indirect_calls: 0,
        indirect_jumps: 0,
        entropy_bits_per_byte: None,
        signals: Vec::new(),
        stop: EntrySampleStop::NotSampled,
        stop_address: None,
        last_flow: None,
        last_conditional_transfer: false,
        window_bounds: Vec::new(),
    }
}

fn sample_bytes(
    binary: &Binary,
    target: &Target,
    decoder: &mut Option<Box<dyn Disassembler>>,
    entry: &mut EntryEvidence,
    result: &mut EntryAudit,
) {
    let (alignment, maximum_instruction_bytes, thumb_end) = match binary.arch {
        Arch::X86 | Arch::X86_64 => (1, 15, None),
        Arch::Aarch64 => (4, 4, None),
        Arch::Arm => {
            let Some(range) = target.thumb.iter().find(|range| range.contains(&entry.address)) else {
                entry.status = EntrySampleStatus::ModeUnavailable;
                entry.unavailable_reason =
                    Some("No declared Thumb range at this exact address; A32 mode is not inferred.");
                return;
            };
            (2, 4, Some(range.end))
        }
        _ => {
            entry.status = EntrySampleStatus::UnsupportedArchitecture;
            entry.unavailable_reason = Some("This local sampler does not support the declared architecture.");
            return;
        }
    };
    if target.big_endian && binary.arch != Arch::Arm {
        entry.status = EntrySampleStatus::UnsupportedByteOrder;
        entry.unavailable_reason = Some("The selected native decoder does not sample big-endian instruction bytes.");
        return;
    }
    if !entry.address.is_multiple_of(alignment) {
        entry.status = EntrySampleStatus::Unaligned;
        entry.unavailable_reason = Some("The exact address is not aligned for its declared instruction mode.");
        return;
    }
    let Some(segment) = binary.segment_containing(entry.address) else {
        entry.unavailable_reason = Some("The exact address is unmapped.");
        return;
    };
    if !segment.perms.execute || !binary.is_code(entry.address) {
        entry.status = EntrySampleStatus::NonCode;
        entry.unavailable_reason = Some("The exact address is not both executable and in a loader code range.");
        return;
    }
    let offset = entry.address - segment.address;
    if offset >= segment.file_size {
        entry.unavailable_reason = Some("The exact address is in a zero-fill or unavailable backing tail.");
        return;
    }
    let Some(code) = binary.code_from(entry.address) else {
        entry.unavailable_reason = Some("No file-backed code bytes are available at the exact address.");
        return;
    };
    let backing_bytes = (segment.size - offset).min(segment.file_size - offset).min(code.len() as u64);
    let mut available = usize::try_from(backing_bytes).unwrap_or(usize::MAX);
    if available < result.limits.bytes_per_entry {
        entry.window_bounds.push(EntryWindowBound::CodeOrBackingBoundary);
    }
    let address_space_bytes = match binary.arch {
        Arch::X86 | Arch::Arm => u64::from(u32::MAX) + 1 - entry.address,
        // A 64-bit exclusive end must remain representable, rather than wrapping to zero.
        _ => u64::MAX - entry.address,
    };
    let address_space_bytes = usize::try_from(address_space_bytes).unwrap_or(usize::MAX);
    if address_space_bytes < available {
        entry.window_bounds.push(EntryWindowBound::TargetAddressSpaceBoundary);
        available = address_space_bytes;
    }
    if let Some(end) = thumb_end {
        let mode_bytes = usize::try_from(end - entry.address).unwrap_or(usize::MAX);
        if mode_bytes < available {
            entry.window_bounds.push(EntryWindowBound::ThumbModeBoundary);
            available = mode_bytes;
        }
    }
    if available > result.limits.bytes_per_entry {
        entry.window_bounds.push(EntryWindowBound::ByteLimit);
    }
    let remaining_bytes = result.limits.total_bytes - result.usage.bytes_sampled;
    let length = available.min(result.limits.bytes_per_entry).min(remaining_bytes);
    if length < available.min(result.limits.bytes_per_entry) {
        entry.window_bounds.push(EntryWindowBound::TotalByteBudget);
        result.note(EntryAuditTruncation::TotalBytes, "Entry sampling exhausted its cumulative sampled-byte budget.");
    }
    if length == 0 {
        entry.status =
            if remaining_bytes == 0 { EntrySampleStatus::BudgetUnavailable } else { EntrySampleStatus::Unavailable };
        entry.unavailable_reason = Some("No bytes remain within the mapping, address-space or sampling budget.");
        return;
    }
    let Some(decoder) = decoder.as_deref_mut() else {
        entry.status = EntrySampleStatus::UnsupportedArchitecture;
        entry.unavailable_reason = Some("No decoder is available for the declared architecture.");
        return;
    };
    let bytes = &code[..length];
    entry.status = EntrySampleStatus::BackedExecutableCode;
    entry.bytes_sampled = length;
    result.usage.bytes_sampled += length;
    let entropy = shannon_entropy(bytes);
    entry.entropy_bits_per_byte = Some(entropy);
    if length >= 64 && entropy >= 6.5 {
        entry.signals.push(EntrySignal::HighEntropyWindow);
    }
    decoder.set_code_modes(&[]);
    decoder.begin_run();
    decode_prefix(decoder, bytes, alignment as usize, maximum_instruction_bytes, entry, result);
    entry.assessment = if entry.signals.contains(&EntrySignal::HighEntropyWindow)
        || entry.signals.contains(&EntrySignal::DecodeFailure)
    {
        EntryAssessment::Suspicious
    } else if entry.invalid_count != 0 || entry.stop == EntrySampleStop::IncompleteInstruction {
        EntryAssessment::Unknown
    } else if entry.instruction_count != 0 {
        EntryAssessment::LocallyPlausible
    } else {
        EntryAssessment::Unknown
    };
}

fn decode_prefix(
    decoder: &mut dyn Disassembler,
    bytes: &[u8],
    minimum_instruction_bytes: usize,
    maximum_instruction_bytes: usize,
    entry: &mut EntryEvidence,
    result: &mut EntryAudit,
) {
    entry.stop = EntrySampleStop::WindowEnd;
    while entry.decoded_bytes < bytes.len() {
        let address = entry.address + entry.decoded_bytes as u64;
        entry.stop_address = Some(address);
        if entry.decode_attempts == result.limits.instructions_per_entry {
            entry.stop = EntrySampleStop::InstructionLimit;
            return;
        }
        if result.usage.decode_attempts == result.limits.total_decode_attempts {
            entry.stop = EntrySampleStop::TotalDecodeAttempts;
            result.note(
                EntryAuditTruncation::TotalDecodeAttempts,
                "Entry sampling exhausted its cumulative decode-attempt budget.",
            );
            return;
        }
        let tail = &bytes[entry.decoded_bytes..];
        if tail.len() < minimum_instruction_bytes {
            entry.stop = EntrySampleStop::IncompleteInstruction;
            return;
        }
        let instruction = decoder.decode(tail, address);
        entry.decode_attempts += 1;
        result.usage.decode_attempts += 1;
        entry.last_flow = Some(instruction.flow);
        entry.last_conditional_transfer = instruction.conditional;
        let length = usize::from(instruction.len);
        if instruction.flow == Flow::Invalid || length == 0 || length > tail.len() {
            entry.invalid_count += 1;
            if tail.len() < maximum_instruction_bytes {
                entry.signals.push(EntrySignal::InvalidOrIncompleteTail);
                entry.stop = EntrySampleStop::InvalidOrIncompleteTail;
            } else {
                entry.signals.push(EntrySignal::DecodeFailure);
                entry.stop = EntrySampleStop::InvalidInstruction;
            }
            return;
        }
        entry.instruction_count += 1;
        result.usage.instructions += 1;
        entry.decoded_bytes += length;
        match instruction.flow {
            Flow::IndirectCall => entry.indirect_calls += 1,
            Flow::IndirectJump => entry.indirect_jumps += 1,
            _ => {}
        }
        if instruction.flow != Flow::Next || instruction.conditional {
            entry.stop = EntrySampleStop::ControlTransfer;
            return;
        }
        entry.stop_address = Some(entry.address + entry.decoded_bytes as u64);
    }
}
