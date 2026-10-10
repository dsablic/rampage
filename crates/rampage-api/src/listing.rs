//! Disassembly with names, references and the user's comments.

use rampage_arch::Flow;
use rampage_loaders::Binary;
use serde::Serialize;

use crate::{ApiError, Project};

#[derive(Debug, Serialize)]
pub struct DisassemblyLine {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub bytes: String,
    pub text: String,
    pub flow: Flow,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub data_ref: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "rampage_arch::hex::optional_address")]
    pub immediate: Option<u64>,
    /// Symbol or function name at this address, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// What the instruction refers to: the name of its branch target or data reference, or the string there.
    /// For an immediate it is a guess: the number may only happen to equal an address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// The user's comment on this instruction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A function's instructions grouped by basic block, in address order.
#[derive(Debug, Serialize)]
pub struct FunctionListing {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
    pub blocks: Vec<Vec<DisassemblyLine>>,
}

impl Project {
    /// Disassembles `count` instructions from an address or name, or from the entry point.
    pub fn disassemble(&self, at: Option<&str>, count: usize) -> Result<Vec<DisassemblyLine>, ApiError> {
        let start = match at {
            Some(text) => self.resolve(text)?,
            None => self
                .binary
                .entry
                .ok_or_else(|| ApiError::Invalid("no entry point; pass an address or symbol".to_owned()))?,
        };
        self.decode_lines(start, u64::MAX, count)
    }

    /// The function containing `address`, disassembled block by block in address order.
    pub fn function_listing(&self, address: u64) -> Result<FunctionListing, ApiError> {
        let start = self
            .function_containing(address)?
            .ok_or_else(|| ApiError::NotFound(format!("no function contains {address:#x}")))?;
        let function = self.analysis()?.program.function_at(start).expect("block index names a known function");
        let blocks = function
            .blocks
            .iter()
            .map(|block| self.decode_lines(block.start, block.end, usize::MAX))
            .collect::<Result<_, _>>()?;
        Ok(FunctionListing { address: start, name: self.function_name(start), blocks })
    }

    /// Decodes up to `count` instructions from `start`, stopping before `end`.
    fn decode_lines(&self, start: u64, end: u64, count: usize) -> Result<Vec<DisassemblyLine>, ApiError> {
        let mut decoder = self.binary.decoder()?;
        let code = self
            .binary
            .read_to_segment_end(start)
            .ok_or_else(|| ApiError::Invalid(format!("address {start:#x} is not backed by file data")))?;
        let limit = usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX).min(code.len());

        let mut lines = Vec::with_capacity(count.min(4096));
        let mut offset = 0;
        while lines.len() < count && offset < limit {
            let address = start + offset as u64;
            let insn = decoder.decode(&code[offset..], address);
            let bytes = &code[offset..(offset + usize::from(insn.len)).min(code.len())];
            lines.push(DisassemblyLine {
                address,
                bytes: rampage_arch::hex::bytes(bytes),
                text: decoder.format(bytes, address),
                flow: insn.flow,
                data_ref: insn.data_ref,
                immediate: insn.immediate,
                label: self.name_at(address),
                note: self.comment_at(address),
                comment: self.describe_reference(&insn),
            });
            offset += usize::from(insn.len.max(1));
        }
        Ok(lines)
    }

    /// Names what an instruction refers to: its branch target or data reference by name, or the string stored
    /// at the data reference.
    fn describe_reference(&self, insn: &rampage_arch::Insn) -> Option<String> {
        let target = match insn.flow {
            Flow::Call(target) | Flow::Jump(target) | Flow::ConditionalJump(target) => Some(target),
            _ => None,
        };
        if let Some(name) = target.and_then(|target| self.name_at(target)) {
            return Some(name);
        }
        // A pointer-sized immediate (x86 `mov`/`push`) counts only when it names something or points at a string.
        let data = insn.data_ref.or(insn.immediate)?;
        if let Some(name) = self.name_at(data) {
            return Some(name);
        }
        string_at(&self.binary, data).map(|text| format!("{text:?}"))
    }
}

/// The NUL-terminated printable ASCII string at `address`, if there is one of at least four characters. Long
/// strings are cut at 80 characters.
fn string_at(binary: &Binary, address: u64) -> Option<String> {
    const LIMIT: usize = 80;
    let bytes = binary.read_to_segment_end(address)?;
    let text: Vec<u8> = bytes.iter().copied().take_while(|&byte| byte != 0).take(LIMIT + 1).collect();
    let printable = |byte: u8| byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' || byte == b'\n';
    if text.len() < 4 || !text.iter().all(|&byte| printable(byte)) {
        return None;
    }
    let mut text = String::from_utf8_lossy(&text[..text.len().min(LIMIT)]).into_owned();
    if bytes.len() > LIMIT && bytes[..=LIMIT].iter().all(|&byte| byte != 0) {
        text.push_str("...");
    }
    Some(text)
}
