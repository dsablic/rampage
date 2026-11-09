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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VectorStatus {
    /// The initial stack pointer: word aligned and nonzero. Never code, never checked against the image.
    StackPointer,
    /// A Thumb handler inside the mapped range, used as the entry (Reset) or a seed.
    Accepted,
    /// Zero: an unused vector.
    Empty,
    /// Not used; `reason` says why.
    Refused,
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
    pub reason: Option<String>,
}

/// A base address that would place every odd system-handler word inside the image. Never applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BaseAddressSuggestion {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub suggestion: u64,
    /// Every base from `lowest` to `highest` inclusive keeps all those handlers inside the image; the suggestion
    /// is the most aligned of them.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub lowest: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub highest: u64,
    pub note: &'static str,
}

/// What reading the vector table found. `vectors` lists the system vectors read and every nonzero external one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VectorTable {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    /// Words read, empty external vectors included.
    pub words_read: usize,
    /// Empty external vectors read but not listed.
    pub empty_external_vectors: usize,
    /// Why reading stopped.
    pub stop: String,
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
    let mut table = VectorTable {
        address,
        words_read: 0,
        empty_external_vectors: 0,
        stop: String::new(),
        vectors: Vec::new(),
        base_address_suggestion: None,
    };
    let verdict = |index: usize, word: u64, table_end: u64| -> (VectorStatus, Option<u64>, Option<String>) {
        let refused = |reason: String| (VectorStatus::Refused, None, Some(reason));
        if word == 0 {
            return (VectorStatus::Empty, None, None);
        }
        if index == 0 {
            if word & 3 != 0 {
                return refused("initial SP is not word aligned".into());
            }
            return (VectorStatus::StackPointer, None, None);
        }
        if matches!(index, 7..=10 | 13) {
            return refused(
                "reserved slot: not used as a handler (some parts keep a checksum or an ARMv8-M SecureFault \
                 handler here)"
                    .into(),
            );
        }
        if word & 1 == 0 {
            return refused("Thumb bit clear: a Cortex-M handler word has bit 0 set".into());
        }
        let target = word & !1;
        if !(base..end).contains(&target) {
            return refused(format!("handler {target:#x} is outside the mapped range {base:#x}..{end:#x}"));
        }
        if (address..table_end).contains(&target) {
            return refused(format!("handler {target:#x} lies inside the vector table"));
        }
        (VectorStatus::Accepted, Some(target), None)
    };
    let name = |index: usize| {
        SYSTEM_NAMES.get(index).map_or_else(|| format!("IRQ{}", index - SYSTEM_VECTORS), |name| (*name).to_owned())
    };
    let system_end = address.saturating_add(4 * SYSTEM_VECTORS as u64);
    let mut index = 0;
    while index < SYSTEM_VECTORS {
        let Some(word) = word_at(index) else { break };
        let (status, target, reason) = verdict(index, word, system_end);
        table.vectors.push(Vector { index: index as u16, name: name(index), word, status, target, reason });
        index += 1;
    }
    table.words_read = index;
    if index < SYSTEM_VECTORS {
        table.stop = format!("the image ends after {index} system vectors");
    } else {
        // The table cannot run into code it points at: external vectors end before the lowest handler after it.
        let boundary = table.handlers().filter(|&handler| handler >= address).min().unwrap_or(end);
        table.stop = format!("read the {MAX_EXTERNAL_VECTORS}-vector external interrupt maximum");
        while index < SYSTEM_VECTORS + MAX_EXTERNAL_VECTORS {
            let slot = address + 4 * index as u64;
            if slot >= boundary {
                table.stop = format!("slot {slot:#x} reaches the lowest handler, {boundary:#x}");
                break;
            }
            let Some(word) = word_at(index) else {
                table.stop = "the image ends inside the external interrupt vectors".into();
                break;
            };
            let (status, target, reason) = verdict(index, word, slot + 4);
            match status {
                VectorStatus::Empty => table.empty_external_vectors += 1,
                VectorStatus::Accepted => {
                    table.vectors.push(Vector { index: index as u16, name: name(index), word, status, target, reason })
                }
                _ => {
                    table.stop = format!(
                        "word {word:#x} at slot {slot:#x} is neither empty nor a handler in the image, so the \
                         external interrupt vectors end before it"
                    );
                    break;
                }
            }
            index += 1;
            table.words_read = index;
        }
    }
    table.base_address_suggestion = suggest_base(&table, length, base);
    Ok(table)
}

/// When an odd system-handler word fell outside the image, the most aligned base that would place every odd,
/// non-reserved system-handler word inside it, with the range of all such bases.
fn suggest_base(table: &VectorTable, length: u64, base: u64) -> Option<BaseAddressSuggestion> {
    let outside = table.vectors.iter().any(|vector| {
        vector.status == VectorStatus::Refused && vector.reason.as_deref().is_some_and(|text| text.contains("outside"))
    });
    if !outside {
        return None;
    }
    let handlers: Vec<u64> = table
        .vectors
        .iter()
        .filter(|vector| vector.index != 0 && !matches!(vector.index, 7..=10 | 13) && vector.word & 1 == 1)
        .map(|vector| vector.word & !1)
        .collect();
    let lowest = *handlers.iter().min()?;
    let highest = *handlers.iter().max()?;
    // base <= lowest and base + length > highest; the table is assumed to sit at the same image offset.
    let low = highest.saturating_sub(length - 1);
    if low > lowest {
        return None;
    }
    let suggestion = (2..32)
        .rev()
        .map(|shift| lowest & !((1u64 << shift) - 1))
        .find(|&candidate| candidate >= low)
        .unwrap_or(lowest & !1);
    if suggestion == base {
        return None;
    }
    Some(BaseAddressSuggestion {
        suggestion,
        lowest: low,
        highest: lowest,
        note: "a suggestion from the handler words only, not applied: this project keeps the asserted base_address; \
               reopen with base_address set to use it",
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
        words[7] = 0x1234_5678; // reserved checksum
        words[11] = 0x0800_0105;
        let table = read(&image(&words, 0x200), 0x0800_0000, 0x0800_0000).unwrap();
        let status: Vec<_> = table.vectors.iter().map(|vector| vector.status).collect();
        assert_eq!(status[0], VectorStatus::StackPointer);
        assert_eq!(status[1], VectorStatus::Accepted);
        assert_eq!(status[2..5], [VectorStatus::Refused; 3]);
        assert_eq!(status[5], VectorStatus::Empty);
        assert_eq!(status[7], VectorStatus::Refused);
        assert_eq!(table.reset(), Some(0x0800_0100));
        assert_eq!(table.handlers().collect::<Vec<_>>(), [0x0800_0100, 0x0800_0104]);
        assert!(table.vectors[2].reason.as_deref().unwrap().contains("Thumb bit clear"));
        assert!(table.vectors[3].reason.as_deref().unwrap().contains("outside the mapped range"));
        assert!(table.vectors[4].reason.as_deref().unwrap().contains("inside the vector table"));
        // Externals stop at the lowest handler after the table.
        assert!(table.stop.contains("reaches the lowest handler"), "{}", table.stop);
        assert_eq!(table.words_read, 0x100 / 4);
    }

    #[test]
    fn externals_end_at_the_first_word_that_is_not_a_handler() {
        let mut words = vec![0x2000_0400u32, 0x101];
        words.resize(16, 0);
        words.extend([0x103, 0, 0x105, 0xb580_af00]);
        let table = read(&image(&words, 0x400), 0, 0).unwrap();
        assert_eq!(table.words_read, 19);
        assert_eq!(table.empty_external_vectors, 1);
        assert_eq!(table.handlers().collect::<Vec<_>>(), [0x100, 0x102, 0x104]);
        assert_eq!(table.vectors.last().unwrap().name, "IRQ2");
        assert!(table.stop.contains("neither empty nor a handler"), "{}", table.stop);
    }

    #[test]
    fn a_wrong_base_gets_a_labelled_suggestion_and_no_handlers() {
        let mut words = [0u32; 16];
        words[0] = 0x2000_5000;
        words[1] = 0x0800_0241;
        words[2] = 0x0800_01dd;
        words[3] = 0x0800_01e5;
        let table = read(&image(&words, 0x320), 0, 0).unwrap();
        assert_eq!(table.reset(), None);
        let suggestion = table.base_address_suggestion.unwrap();
        assert_eq!(suggestion.suggestion, 0x0800_0000);
        assert_eq!((suggestion.lowest, suggestion.highest), (0x0800_0240 - 0x31f, 0x0800_01dc));
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
        assert!(short.stop.contains("ends after 2 system vectors"));
    }
}
