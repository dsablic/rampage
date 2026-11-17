//! Opt-in Cortex-M vector-table reading for the `ARM:LE:32:Cortex` Raw profile. Every word read is reported with
//! its verdict; accepted handlers become the Raw entry and seeds. Nothing here changes the asserted mapping: a
//! base address derived from the handler words is only ever a labelled suggestion.

use serde::Serialize;

use crate::LoadError;

/// ARMv7-M allows up to 496 external interrupts; Cortex-M3/M4/M7 implement at most 240 and ARMv6-M 32.
pub const MAX_EXTERNAL_VECTORS: usize = 240;
const SYSTEM_VECTORS: usize = 16;
const SYSTEM_NAMES: [&str; SYSTEM_VECTORS] = [
    "initial_sp",
    "Reset",
    "NMI",
    "HardFault",
    "MemManage",
    "BusFault",
    "UsageFault",
    "Reserved7",
    "Reserved8",
    "Reserved9",
    "Reserved10",
    "SVCall",
    "DebugMonitor",
    "Reserved13",
    "PendSV",
    "SysTick",
];
/// An erased flash word.
const ERASED: u64 = 0xffff_ffff;

/// System vector slots ARMv7-M reserves.
const fn reserved(index: usize) -> bool {
    matches!(index, 7..=10 | 13)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VectorStatus {
    /// The initial stack pointer: word aligned and nonzero. Never code, never checked against the image.
    StackPointer,
    /// A Thumb handler inside the mapped range, used as the entry (Reset) or a seed.
    Accepted,
    /// Zero: an unused vector.
    Empty,
    /// 0xFFFFFFFF, erased flash: an unused vector, like `empty`.
    Erased,
    /// Not used; `refused_reason` says why.
    Refused,
}

/// Why a vector word was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusedReason {
    /// The initial SP word is not word aligned.
    SpUnaligned,
    /// A reserved system slot (some parts keep a checksum or an ARMv8-M SecureFault handler there).
    Reserved,
    /// Bit 0 is clear: every Cortex-M handler word has the Thumb bit set.
    ThumbBitClear,
    /// The handler lies outside the asserted mapped range.
    OutsideImage,
    /// The handler lies inside the vector table itself.
    InTable,
    /// The initial SP word of a table whose Reset and other handlers check out lies outside RAM (external SDRAM,
    /// a part-specific RAM address): the table is used, the word is flagged. Map that RAM as a `ram` region to
    /// accept it.
    SpOutsideRam,
}

/// Why reading the table stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The image ends inside the table.
    ImageEnd,
    /// The 240-vector external interrupt maximum was read.
    MaxExternal,
    /// The next slot is at or past the lowest accepted handler, so it is code.
    ReachedHandler,
    /// The next word is neither empty, erased nor a handler in the image.
    NonHandlerWord,
}

/// One word of the table and the verdict on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Vector {
    pub index: u16,
    /// `initial_sp`, the ARMv7-M exception name, or `IRQ<n>` for external interrupt n.
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub word: u64,
    pub status: VectorStatus,
    /// The handler's first instruction (the word with its Thumb bit cleared), when accepted.
    #[serde(serialize_with = "rampage_arch::hex::optional_address", skip_serializing_if = "Option::is_none")]
    pub target: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused_reason: Option<RefusedReason>,
}

/// A base address that would place every odd system-handler word inside the image. Never applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BaseAddressSuggestion {
    /// The most aligned base from `lowest_base` to `highest_base`.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub base_address: u64,
    /// Every base from `lowest_base` to `highest_base` inclusive keeps all those handlers inside the image.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub lowest_base: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub highest_base: u64,
    pub note: &'static str,
}

/// What reading the vector table found. `vectors` lists the system vectors read and every external one that is
/// accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VectorTable {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    /// Words read, empty and erased external vectors included.
    pub words_read: usize,
    /// Empty or erased external vectors read but not listed.
    pub empty_external_vectors: usize,
    pub stop_reason: StopReason,
    pub stop_detail: String,
    pub vectors: Vec<Vector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_address_suggestion: Option<BaseAddressSuggestion>,
    /// Set when the words do not look like a reset-time vector table at all (an initial SP outside RAM, or no
    /// usable Reset handler), as when the image starts with code: no handler of it becomes the entry or a seed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused_reason: Option<String>,
}

impl VectorTable {
    /// The accepted Reset handler of a table that was not refused.
    pub fn reset(&self) -> Option<u64> {
        if self.refused_reason.is_some() {
            return None;
        }
        self.vectors.iter().find(|vector| vector.index == 1 && vector.status == VectorStatus::Accepted)?.target
    }

    /// Every accepted handler of a table that was not refused, Reset included, in table order (duplicates kept).
    pub fn handlers(&self) -> impl Iterator<Item = u64> + '_ {
        self.vectors
            .iter()
            .filter(|vector| self.refused_reason.is_none() && vector.status == VectorStatus::Accepted)
            .filter_map(|vector| vector.target)
    }
}

/// Addresses an initial stack pointer may hold without a mapped RAM region: the ARMv7-M SRAM region
/// (0x20000000..0x40000000) and the RAM parts commonly put below it from 0x10000000 (core-coupled RAM, the lower
/// SRAM block), the top of RAM itself included.
const RAM_LIKE: std::ops::RangeInclusive<u64> = 0x1000_0000..=0x4000_0000;
/// Handlers besides Reset a table needs for an SP word outside RAM to be flagged rather than refuse the table.
const MIN_HANDLERS_FOR_SP_EXCEPTION: usize = 2;

/// [`read`], for the table the core reads at reset: the whole candidate is refused, with the reason, when its
/// Reset word is no Thumb handler inside the code, or when its initial SP lies outside RAM (the RAM-like range, or
/// a region `ram` admits, its end included) and fewer than two other handlers check out. A table with a good Reset
/// and enough handlers is kept with only its SP word flagged (`sp_outside_ram`). Individual words are still judged
/// and listed.
pub(crate) fn read_reset_table(
    bytes: &[u8],
    base: u64,
    address: u64,
    ram: &dyn Fn(u64) -> bool,
) -> Result<VectorTable, LoadError> {
    let mut table = read(bytes, base, address)?;
    let word = |index: u16| table.vectors.iter().find(|vector| vector.index == index);
    let sp = word(0).expect("the initial SP word is always read");
    let reset = word(1).expect("the Reset word is always read");
    let sp_reason = match sp.status {
        VectorStatus::StackPointer
            if RAM_LIKE.contains(&sp.word) || ram(sp.word) || sp.word.checked_sub(1).is_some_and(ram) =>
        {
            None
        }
        VectorStatus::StackPointer => Some(format!(
            "initial SP {:#x} lies outside RAM (0x10000000..=0x40000000; map the RAM it names as a `ram` region to \
             accept it)",
            sp.word
        )),
        VectorStatus::Empty | VectorStatus::Erased => Some(format!("initial SP word {:#x} is empty", sp.word)),
        _ => Some(format!("initial SP word {:#x} is not word aligned", sp.word)),
    };
    let reset_reason = match (reset.status, reset.refused_reason) {
        (VectorStatus::Accepted, _) => None,
        (_, Some(RefusedReason::ThumbBitClear)) => {
            Some(format!("Reset word {:#x} has bit 0 clear, so it is no Thumb handler", reset.word))
        }
        (_, Some(RefusedReason::OutsideImage)) => {
            Some(format!("Reset word {:#x} points outside the mapped code", reset.word))
        }
        (_, Some(RefusedReason::InTable)) => {
            Some(format!("Reset word {:#x} points into the vector table itself", reset.word))
        }
        _ => Some(format!("Reset word {:#x} is no handler", reset.word)),
    };
    // A table whose Reset and at least two other handlers check out is a table, whatever its SP word: the SP may
    // name external SDRAM or a part's own RAM. Only that word is flagged then.
    let handlers = table.vectors.iter().filter(|vector| vector.index > 1 && vector.status == VectorStatus::Accepted);
    if reset_reason.is_none() && sp_reason.is_some() && handlers.count() >= MIN_HANDLERS_FOR_SP_EXCEPTION {
        if let Some(sp) = table.vectors.iter_mut().find(|vector| vector.index == 0) {
            sp.status = VectorStatus::Refused;
            sp.refused_reason = Some(RefusedReason::SpOutsideRam);
        }
        return Ok(table);
    }
    let reasons: Vec<String> = sp_reason.into_iter().chain(reset_reason).collect();
    if !reasons.is_empty() {
        table.refused_reason = Some(format!(
            "not a reset vector table: {}; no handler was used. If the image starts with code, open it without \
             vector_table and give entry (its first instruction) instead",
            reasons.join("; ")
        ));
    }
    Ok(table)
}

/// Reads the table at code-space byte `address` of `bytes` mapped at `base`. Refuses a table that is unaligned,
/// outside the image, or too short for the initial SP and Reset words; individual bad words are refused in the
/// evidence instead.
pub(crate) fn read(bytes: &[u8], base: u64, address: u64) -> Result<VectorTable, LoadError> {
    let end = base.saturating_add(bytes.len() as u64);
    read_with(bytes, base, address, &|target| (base..end).contains(&target))
}

/// [`read`], with `in_image` deciding which handler targets lie inside the image (an ELF's code ranges, which can
/// span other segments than the table's bytes).
pub(crate) fn read_with(
    bytes: &[u8],
    base: u64,
    address: u64,
    in_image: &dyn Fn(u64) -> bool,
) -> Result<VectorTable, LoadError> {
    let length = bytes.len() as u64;
    let end = base.saturating_add(length);
    let offset =
        address.checked_sub(base).filter(|&offset| offset < length && address.is_multiple_of(4)).ok_or_else(|| {
            LoadError::Malformed(format!(
                "Raw vector table {address:#x} must be word aligned and inside the mapped range {base:#x}..{end:#x}"
            ))
        })?;
    let word_at = |index: usize| -> Option<u64> {
        let start = usize::try_from(offset).ok()?.checked_add(index.checked_mul(4)?)?;
        let word = bytes.get(start..start.checked_add(4)?)?;
        Some(u64::from(u32::from_le_bytes(word.try_into().ok()?)))
    };
    if word_at(1).is_none() {
        return Err(LoadError::Malformed(
            "Raw vector table needs at least the initial SP and Reset words inside the image".into(),
        ));
    }
    let verdict = |index: usize, word: u64, table_end: u64| -> (VectorStatus, Option<u64>, Option<RefusedReason>) {
        let refused = |reason| (VectorStatus::Refused, None, Some(reason));
        match word {
            0 => return (VectorStatus::Empty, None, None),
            ERASED => return (VectorStatus::Erased, None, None),
            _ => {}
        }
        if index == 0 {
            return if word & 3 != 0 {
                refused(RefusedReason::SpUnaligned)
            } else {
                (VectorStatus::StackPointer, None, None)
            };
        }
        if reserved(index) {
            return refused(RefusedReason::Reserved);
        }
        if word & 1 == 0 {
            return refused(RefusedReason::ThumbBitClear);
        }
        let target = word & !1;
        if !in_image(target) {
            return refused(RefusedReason::OutsideImage);
        }
        if (address..table_end).contains(&target) {
            return refused(RefusedReason::InTable);
        }
        (VectorStatus::Accepted, Some(target), None)
    };
    let name = |index: usize| {
        SYSTEM_NAMES.get(index).map_or_else(|| format!("IRQ{}", index - SYSTEM_VECTORS), |name| (*name).to_owned())
    };
    let vector = |index: usize, word, (status, target, refused_reason)| Vector {
        index: index as u16,
        name: name(index),
        word,
        status,
        target,
        refused_reason,
    };
    let system_end = address.saturating_add(4 * SYSTEM_VECTORS as u64);
    let mut vectors = Vec::new();
    let mut index = 0;
    while index < SYSTEM_VECTORS {
        let Some(word) = word_at(index) else { break };
        vectors.push(vector(index, word, verdict(index, word, system_end)));
        index += 1;
    }
    let mut table = VectorTable {
        address,
        words_read: index,
        empty_external_vectors: 0,
        stop_reason: StopReason::ImageEnd,
        stop_detail: format!("the image ends after {index} system vectors"),
        vectors,
        base_address_suggestion: None,
        refused_reason: None,
    };
    if index == SYSTEM_VECTORS {
        read_external(&mut table, &word_at, &verdict, &vector, end);
    }
    table.base_address_suggestion = suggest_base(&table, length, base);
    Ok(table)
}

type Verdict = (VectorStatus, Option<u64>, Option<RefusedReason>);

/// External interrupt vectors, until the table would run into code it points at, a word that is not a vector,
/// the image end or the 240-vector maximum.
fn read_external(
    table: &mut VectorTable,
    word_at: &dyn Fn(usize) -> Option<u64>,
    verdict: &dyn Fn(usize, u64, u64) -> Verdict,
    vector: &dyn Fn(usize, u64, Verdict) -> Vector,
    end: u64,
) {
    let address = table.address;
    // The lowest accepted handler after the table start bounds it; each accepted external handler lowers it.
    let mut boundary = table.handlers().filter(|&handler| handler >= address).min().unwrap_or(end);
    table.stop_reason = StopReason::MaxExternal;
    table.stop_detail = format!("read the {MAX_EXTERNAL_VECTORS}-vector external interrupt maximum");
    let mut index = SYSTEM_VECTORS;
    while index < SYSTEM_VECTORS + MAX_EXTERNAL_VECTORS {
        let slot = address + 4 * index as u64;
        if slot >= boundary {
            table.stop_reason = StopReason::ReachedHandler;
            table.stop_detail = format!("slot {slot:#x} reaches the lowest handler, {boundary:#x}");
            break;
        }
        let Some(word) = word_at(index) else {
            table.stop_reason = StopReason::ImageEnd;
            table.stop_detail = "the image ends inside the external interrupt vectors".into();
            break;
        };
        let judged = verdict(index, word, slot + 4);
        match judged.0 {
            VectorStatus::Empty | VectorStatus::Erased => table.empty_external_vectors += 1,
            VectorStatus::Accepted => {
                if let Some(target) = judged.1.filter(|&target| target > slot) {
                    boundary = boundary.min(target);
                }
                table.vectors.push(vector(index, word, judged));
            }
            _ => {
                table.stop_reason = StopReason::NonHandlerWord;
                table.stop_detail = format!(
                    "word {word:#x} at slot {slot:#x} is neither empty nor a handler in the image, so the external \
                     interrupt vectors end before it"
                );
                break;
            }
        }
        index += 1;
        table.words_read = index;
    }
}

/// When an odd system-handler word fell outside the image, the most aligned base that would place every odd,
/// non-reserved system-handler word inside it, with the range of all such bases.
fn suggest_base(table: &VectorTable, length: u64, base: u64) -> Option<BaseAddressSuggestion> {
    let outside = table.vectors.iter().any(|vector| vector.refused_reason == Some(RefusedReason::OutsideImage));
    if !outside {
        return None;
    }
    let handlers: Vec<u64> = table
        .vectors
        .iter()
        .filter(|vector| {
            vector.index != 0 && !reserved(usize::from(vector.index)) && vector.word != ERASED && vector.word & 1 == 1
        })
        .map(|vector| vector.word & !1)
        .collect();
    let lowest_handler = *handlers.iter().min()?;
    let highest_handler = *handlers.iter().max()?;
    // base <= lowest_handler and base + length > highest_handler.
    let lowest_base = highest_handler.saturating_sub(length - 1);
    if lowest_base > lowest_handler {
        return None;
    }
    let base_address = (2..32)
        .rev()
        .map(|shift| lowest_handler & !((1u64 << shift) - 1))
        .find(|&candidate| candidate >= lowest_base)
        .unwrap_or(lowest_handler & !1);
    if base_address == base {
        return None;
    }
    Some(BaseAddressSuggestion {
        base_address,
        lowest_base,
        highest_base: lowest_handler,
        note: "a suggestion from the handler words only, not applied: this project keeps the asserted base_address; \
               reopen with base_address set to use it, moving an explicit vector_table address by the same amount",
    })
}

/// Sections GNU and LLVM linker scripts put a Cortex-M vector table in.
const ELF_TABLE_SECTIONS: [&str; 4] = [".isr_vector", ".vectors", ".vector_table", ".isr_vectors"];
/// Most candidate table addresses an ELF is probed at.
const MAX_ELF_CANDIDATES: usize = 8;

/// An M-profile ELF's vector table, for seeding its handlers as functions as a Raw project's `vector_table` does.
/// Probed at a vector-table section, the lowest file-backed read-only mapping and the start of the entry's
/// mapping, in that order; a table counts only when its Reset vector is the ELF entry. Handlers must lie in code. A
/// table section's size bounds the table (the code after it is never read as vectors); otherwise it is bounded as
/// [`read`] bounds it.
pub(crate) fn elf_table(binary: &crate::Binary) -> Option<VectorTable> {
    let entry = binary.entry?;
    let named = binary
        .sections
        .iter()
        .filter(|section| ELF_TABLE_SECTIONS.contains(&section.name.as_str()) && section.file_size > 0)
        .map(|section| (section.address, Some(section.size)));
    let lowest = binary
        .segments
        .iter()
        .filter(|segment| segment.file_size > 0 && !segment.perms.write)
        .map(|segment| segment.address)
        .min();
    let entry_mapping = binary.segments.iter().find(|segment| segment.contains(entry)).map(|segment| segment.address);
    let unbounded = lowest.into_iter().chain(entry_mapping).map(|address| (address, None));
    named.chain(unbounded).take(MAX_ELF_CANDIDATES).find_map(|(address, size)| {
        let bytes = binary.read_to_segment_end(address)?;
        let length = size.map_or(bytes.len(), |size| usize::try_from(size).unwrap_or(usize::MAX).min(bytes.len()));
        let table = read_with(&bytes[..length], address, address, &|target| binary.is_code(target)).ok()?;
        (table.reset() == Some(entry)).then_some(table)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(words: &[u32], length: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        bytes.resize(length, 0);
        bytes
    }

    #[test]
    fn system_vectors_are_judged_one_by_one() {
        let mut words = [0u32; 16];
        words[0] = 0x2000_5000;
        words[1] = 0x0800_0101;
        words[2] = 0x0800_0100; // Thumb bit clear
        words[3] = 0x0900_0101; // outside
        words[4] = 0x0800_0011; // inside the table
        words[5] = 0xffff_ffff; // erased
        words[7] = 0x1234_5678; // reserved checksum
        words[11] = 0x0800_0105;
        let table = read(&image(&words, 0x200), 0x0800_0000, 0x0800_0000).unwrap();
        let status: Vec<_> = table.vectors.iter().map(|vector| vector.status).collect();
        assert_eq!(status[0], VectorStatus::StackPointer);
        assert_eq!(status[1], VectorStatus::Accepted);
        assert_eq!(status[2..5], [VectorStatus::Refused; 3]);
        assert_eq!(status[5], VectorStatus::Erased);
        assert_eq!(status[6], VectorStatus::Empty);
        assert_eq!(status[7], VectorStatus::Refused);
        assert_eq!(table.reset(), Some(0x0800_0100));
        assert_eq!(table.handlers().collect::<Vec<_>>(), [0x0800_0100, 0x0800_0104]);
        let reasons: Vec<_> = table.vectors.iter().filter_map(|vector| vector.refused_reason).collect();
        assert_eq!(
            reasons,
            [
                RefusedReason::ThumbBitClear,
                RefusedReason::OutsideImage,
                RefusedReason::InTable,
                RefusedReason::Reserved
            ]
        );
        // Externals stop at the lowest handler after the table.
        assert_eq!(table.stop_reason, StopReason::ReachedHandler, "{}", table.stop_detail);
        assert_eq!(table.words_read, 0x100 / 4);
    }

    #[test]
    fn externals_end_at_the_first_word_that_is_not_a_handler() {
        let mut words = vec![0x2000_0400u32, 0x101];
        words.resize(16, 0);
        words.extend([0x103, 0, 0xffff_ffff, 0x105, 0xb580_af00]);
        let table = read(&image(&words, 0x400), 0, 0).unwrap();
        assert_eq!(table.words_read, 20);
        assert_eq!(table.empty_external_vectors, 2);
        assert_eq!(table.handlers().collect::<Vec<_>>(), [0x100, 0x102, 0x104]);
        assert_eq!(table.vectors.last().unwrap().name, "IRQ3");
        assert_eq!(table.stop_reason, StopReason::NonHandlerWord, "{}", table.stop_detail);
    }

    /// An external handler right after the table bounds it: the code there (`movs r1, #1; movs r0, r0`, the word
    /// 0x00002101) is not read as another vector.
    #[test]
    fn an_external_handler_right_after_the_table_ends_it() {
        let mut words = vec![0x2000_0400u32, 0x201];
        words.resize(16, 0);
        words.push(0x45);
        words.push(0x0000_2101);
        let table = read(&image(&words, 0x4000), 0, 0).unwrap();
        assert_eq!(table.handlers().collect::<Vec<_>>(), [0x200, 0x44]);
        assert_eq!(table.words_read, 17);
        assert_eq!(table.stop_reason, StopReason::ReachedHandler, "{}", table.stop_detail);
        assert!(table.vectors.iter().all(|vector| vector.name != "IRQ1"));
    }

    #[test]
    fn a_wrong_base_gets_a_labelled_suggestion_and_no_handlers() {
        let mut words = [0u32; 16];
        words[0] = 0x2000_5000;
        words[1] = 0x0800_0241;
        words[2] = 0x0800_01dd;
        words[3] = 0x0800_01e5;
        // Erased words do not hold the suggestion back.
        words[4] = 0xffff_ffff;
        let table = read(&image(&words, 0x320), 0, 0).unwrap();
        assert_eq!(table.reset(), None);
        let suggestion = table.base_address_suggestion.unwrap();
        assert_eq!(suggestion.base_address, 0x0800_0000);
        assert_eq!((suggestion.lowest_base, suggestion.highest_base), (0x0800_0240 - 0x31f, 0x0800_01dc));
        assert!(suggestion.note.contains("not applied"));
        let right = read(&image(&words, 0x320), 0x0800_0000, 0x0800_0000).unwrap();
        assert!(right.base_address_suggestion.is_none());
        assert_eq!(right.reset(), Some(0x0800_0240));
    }

    /// Fifth Haiku run: an image that starts with code was read as a vector table, its first code word reported as
    /// `stack_pointer`. The reset-time table is refused as a whole unless its SP is in RAM and its Reset in code.
    #[test]
    fn an_implausible_reset_table_is_refused_with_the_reason() {
        let no_ram = |_: u64| false;
        let mut words = [0u32; 16];
        words[0] = 0x2000_5000;
        words[1] = 0x0800_0101;
        let good = read_reset_table(&image(&words, 0x200), 0x0800_0000, 0x0800_0000, &no_ram).unwrap();
        assert_eq!(good.refused_reason, None);
        assert_eq!(good.reset(), Some(0x0800_0100));
        // Thumb code at offset 0: `push {r4, lr}; bl ...` read as words.
        let code =
            read_reset_table(&image(&[0xf000_b510, 0xf8bc_f83a], 0x200), 0x6000_0000, 0x6000_0000, &no_ram).unwrap();
        let reason = code.refused_reason.as_deref().unwrap();
        assert!(reason.contains("outside RAM") && reason.contains("bit 0 clear"), "{reason}");
        assert!(reason.contains("give entry"), "{reason}");
        assert_eq!(code.reset(), None);
        assert_eq!(code.handlers().count(), 0);
        // An SP word in a mapped ram region outside the usual range is accepted; its end counts too.
        words[0] = 0x0100_8000;
        let tcm = |address: u64| (0x0100_0000..0x0100_8000).contains(&address);
        let table = read_reset_table(&image(&words, 0x200), 0x0800_0000, 0x0800_0000, &tcm).unwrap();
        assert_eq!(table.refused_reason, None);
        let refused = read_reset_table(&image(&words, 0x200), 0x0800_0000, 0x0800_0000, &no_ram).unwrap();
        assert!(refused.refused_reason.unwrap().contains("initial SP 0x1008000"));
        // A good SP with a Reset word outside the code is refused too.
        words[0] = 0x2000_5000;
        words[1] = 0x0900_0101;
        let outside = read_reset_table(&image(&words, 0x200), 0x0800_0000, 0x0800_0000, &no_ram).unwrap();
        assert!(outside.refused_reason.unwrap().contains("outside the mapped code"));
    }

    /// Review of the vector-table check: the RAM range's edges, an SP in external SDRAM or a part's own RAM with a
    /// table that otherwise checks out (kept, the SP word flagged), and the VTOR path, which is not held to it.
    #[test]
    fn the_reset_table_sp_rule_has_exact_edges_and_spares_tables_that_check_out() {
        let no_ram = |_: u64| false;
        let table = |sp: u32, handlers: usize| {
            let mut words = [0u32; 16];
            words[0] = sp;
            words[1] = 0x0800_0101;
            for slot in 0..handlers {
                words[2 + slot] = 0x0800_0105 + 4 * slot as u32;
            }
            read_reset_table(&image(&words, 0x200), 0x0800_0000, 0x0800_0000, &no_ram).unwrap()
        };
        for sp in [0x1000_0000, 0x4000_0000, 0x2000_5000] {
            let read = table(sp, 0);
            assert_eq!(read.refused_reason, None, "{sp:#x}");
            assert_eq!(read.vectors[0].status, VectorStatus::StackPointer, "{sp:#x}");
        }
        // Just below the range, with only Reset: the whole candidate is refused and the reason names a ram region.
        let below = table(0x0fff_fffc, 0);
        let reason = below.refused_reason.clone().unwrap();
        assert!(reason.contains("initial SP 0xffffffc") && reason.contains("`ram` region"), "{reason}");
        assert_eq!(below.reset(), None);
        // External SDRAM or 0x0800xxxx RAM, with Reset and two more handlers: kept, the SP word flagged.
        for sp in [0x6000_8000, 0x7000_0000, 0x8000_0000, 0xc000_0000, 0x0800_4000] {
            let kept = table(sp, 2);
            assert_eq!(kept.refused_reason, None, "{sp:#x}");
            assert_eq!(kept.vectors[0].refused_reason, Some(RefusedReason::SpOutsideRam), "{sp:#x}");
            assert_eq!(kept.reset(), Some(0x0800_0100), "{sp:#x}");
        }
        // A table VTOR installs is read without the reset-time rule.
        let mut words = [0u32; 16];
        words[0] = 0x0fff_fffc;
        words[1] = 0x0800_0101;
        let vtor = read(&image(&words, 0x200), 0x0800_0000, 0x0800_0000).unwrap();
        assert_eq!(vtor.refused_reason, None);
        assert_eq!(vtor.reset(), Some(0x0800_0100));
    }

    #[test]
    fn tables_must_be_aligned_inside_and_hold_sp_and_reset() {
        let bytes = image(&[0x2000_0000, 0x11], 0x40);
        assert!(read(&bytes, 0, 2).is_err());
        assert!(read(&bytes, 0x10, 0).is_err());
        assert!(read(&bytes, 0, 0x40).is_err());
        assert!(read(&bytes, 0, 0x3c).is_err());
        let short = read(&bytes[..8], 0, 0).unwrap();
        assert_eq!(short.words_read, 2);
        assert_eq!(short.stop_reason, StopReason::ImageEnd);
    }
}
