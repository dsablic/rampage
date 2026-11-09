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
}

impl VectorTable {
    /// The accepted Reset handler.
    pub fn reset(&self) -> Option<u64> {
        self.vectors.iter().find(|vector| vector.index == 1 && vector.status == VectorStatus::Accepted)?.target
    }

    /// Every accepted handler, Reset included, in table order (duplicates kept).
    pub fn handlers(&self) -> impl Iterator<Item = u64> + '_ {
        self.vectors.iter().filter(|vector| vector.status == VectorStatus::Accepted).filter_map(|vector| vector.target)
    }
}

/// Reads the table at code-space byte `address` of `bytes` mapped at `base`. Refuses a table that is unaligned,
/// outside the image, or too short for the initial SP and Reset words; individual bad words are refused in the
/// evidence instead.
pub(crate) fn read(bytes: &[u8], base: u64, address: u64) -> Result<VectorTable, LoadError> {
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
        if !(base..end).contains(&target) {
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
