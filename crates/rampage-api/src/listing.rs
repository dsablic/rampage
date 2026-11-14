//! Disassembly with names, references and the user's comments.

use rampage_analysis::discover::NoreturnEvidence;
use rampage_arch::Flow;
use rampage_loaders::Binary;
use serde::Serialize;

use crate::operand_types::{OperandAnnotationDisplay, OperandListingContext};
use crate::{ApiError, Project};

#[derive(Debug)]
pub struct DisassemblyLine {
    pub address: u64,
    pub bytes: String,
    pub text: String,
    pub flow: Flow,
    /// Present for a valid instruction with unknown successors. `flow == Invalid` is then a legacy STOP
    /// sentinel in Rust only; serialized flow is `unknown`. No fall-through or noreturn claim is permitted.
    pub decode_gate: Option<rampage_arch::DecodeGate>,
    pub data_ref: Option<u64>,
    /// The instruction loads from or stores to `data_ref` rather than forming it, so it is data, not code.
    pub accesses: bool,
    pub immediate: Option<u64>,
    /// ARM and AArch64 only: the decimal `#` immediates of `text` in hex, comma-separated (`0x78e` for
    /// `movt r1, #1934`), as GNU objdump prints them after `;`. `text` itself stays as the decoder renders it.
    pub immediates_hex: Option<String>,
    /// Symbol or function name at this address, when there is one.
    pub label: Option<String>,
    /// What the instruction refers to: the name of its branch target or data reference, or the string there.
    /// For an immediate it is a guess: the number may only happen to equal an address.
    pub comment: Option<String>,
    /// The user's comment on this instruction.
    pub note: Option<String>,
    /// In a function's listing, a call that never returns ends its block, and this says why: its callee is
    /// `listed` by name as never returning, or discovery `inferred` it.
    pub noreturn: Option<NoreturnEvidence>,
    /// Analyst-selected operand interpretations; raw instruction text, bytes and flow remain unchanged.
    pub operand_annotations: Vec<OperandAnnotationDisplay>,
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum PresentedFlow {
    Known(Flow),
    Unknown { kind: &'static str },
}

pub(crate) fn presented_flow(flow: Flow, gate: Option<rampage_arch::DecodeGate>) -> PresentedFlow {
    if gate.is_some() { PresentedFlow::Unknown { kind: "unknown" } } else { PresentedFlow::Known(flow) }
}

impl Serialize for DisassemblyLine {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("address", &format!("{:#x}", self.address))?;
        map.serialize_entry("bytes", &self.bytes)?;
        map.serialize_entry("text", &self.text)?;
        map.serialize_entry("flow", &presented_flow(self.flow, self.decode_gate))?;
        if let Some(gate) = self.decode_gate {
            map.serialize_entry("decode_gate", &gate)?;
        }
        if let Some(address) = self.data_ref {
            map.serialize_entry("data_ref", &format!("{address:#x}"))?;
        }
        if self.accesses {
            map.serialize_entry("accesses", &true)?;
        }
        if let Some(address) = self.immediate {
            map.serialize_entry("immediate", &format!("{address:#x}"))?;
        }
        if let Some(values) = &self.immediates_hex {
            map.serialize_entry("immediates_hex", values)?;
        }
        for (key, value) in [("label", &self.label), ("comment", &self.comment), ("note", &self.note)] {
            if let Some(value) = value {
                map.serialize_entry(key, value)?;
            }
        }
        if let Some(evidence) = self.noreturn {
            map.serialize_entry("noreturn", &evidence)?;
        }
        if !self.operand_annotations.is_empty() {
            map.serialize_entry("operand_annotations", &self.operand_annotations)?;
        }
        map.end()
    }
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
        let operands = self.operand_listing_context()?;
        let mut lines = self.decode_lines(start, u64::MAX, count, operands.as_ref())?;
        self.name_register_accesses(lines.iter_mut());
        Ok(lines)
    }

    /// Adds the imported peripheral registers each line loads or stores, or names as a constant, to its comment.
    fn name_register_accesses<'a>(&self, lines: impl IntoIterator<Item = &'a mut DisassemblyLine>) {
        if self.peripheral_map().is_empty() {
            return;
        }
        for line in lines {
            let mut names: Vec<String> = Vec::new();
            if let Some(name) = line.immediate.and_then(|value| self.immediate_register_name(line.address, value))
                && !line.comment.as_deref().is_some_and(|comment| comment.contains(&name))
            {
                names.push(format!("={name}"));
            }
            if let Some(accessed) = self.register_accesses_at(line.address) {
                names.push(accessed);
            }
            if names.is_empty() {
                continue;
            }
            let parts: Vec<String> = line.comment.take().into_iter().chain(names).collect();
            line.comment = Some(parts.join("; "));
        }
    }

    /// The function containing `address`, disassembled block by block in address order.
    pub fn function_listing(&self, address: u64) -> Result<FunctionListing, ApiError> {
        self.function_listing_with_operands(address, true)
    }

    pub(crate) fn function_listing_for_frame(&self, address: u64) -> Result<FunctionListing, ApiError> {
        self.function_listing_with_operands(address, false)
    }

    fn function_listing_with_operands(&self, address: u64, render_operands: bool) -> Result<FunctionListing, ApiError> {
        let start = self
            .function_containing(address)?
            .ok_or_else(|| ApiError::NotFound(format!("no function contains {address:#x}")))?;
        let function = self.analysis()?.program.function_at(start).expect("block index names a known function");
        let operands = if render_operands { self.operand_listing_context()? } else { None };
        let mut blocks: Vec<Vec<DisassemblyLine>> = function
            .blocks
            .iter()
            .map(|block| self.decode_lines(block.start, block.end, usize::MAX, operands.as_ref()))
            .collect::<Result<_, _>>()?;
        let program = &self.analysis()?.program;
        let objc = self.objc_dispatch_for_function(start)?;
        let flows = &program.resolved_flows;
        for line in blocks.iter_mut().flatten() {
            if line.decode_gate.is_some() {
                continue;
            }
            if let Ok(index) = flows.binary_search_by_key(&(start, line.address), |flow| (flow.function, flow.address))
            {
                line.flow = flows[index].flow;
                let target = match line.flow {
                    Flow::Call(at) | Flow::Jump(at) => Some(at),
                    _ => None,
                };
                if let Some(name) = target.and_then(|at| self.name_at(at)) {
                    line.comment = with_operand_comments(Some(name), &line.operand_annotations);
                }
            }
            let target = match line.flow {
                Flow::Call(at) | Flow::Jump(at) => Some(at),
                _ => None,
            };
            let callees: Vec<u64> = target.into_iter().chain(line.data_ref).collect();
            line.noreturn = program.noreturn_evidence(line.address, &callees);
            if let Some(send) = objc.and_then(|objc| objc.send_at(line.address)).filter(|send| send.function == start)
                && let Some(text) = self.objc_send_comment(send)
            {
                let parts: Vec<String> = line.comment.take().into_iter().chain([format!("objc: {text}")]).collect();
                line.comment = Some(parts.join("; "));
            }
        }
        self.name_register_accesses(blocks.iter_mut().flatten());
        Ok(FunctionListing { address: start, name: self.function_name(start), blocks })
    }

    /// Decodes up to `count` instructions from `start`, stopping before `end`.
    fn decode_lines(
        &self,
        start: u64,
        end: u64,
        count: usize,
        operands: Option<&OperandListingContext>,
    ) -> Result<Vec<DisassemblyLine>, ApiError> {
        let mut decoder = crate::decoder::project_decoder(self)?;
        if self.binary.arch == rampage_arch::Arch::Arm {
            decoder.set_code_modes(&self.analysis()?.program.code_modes);
        }
        let code = self
            .binary
            .read_to_segment_end(start)
            .ok_or_else(|| ApiError::Invalid(format!("address {start:#x} is not backed by file data")))?;
        let limit = usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX).min(code.len());

        // LLVM prints ARM and AArch64 immediates in decimal; their hex goes in a separate field.
        let arm = matches!(self.binary.arch, rampage_arch::Arch::Arm | rampage_arch::Arch::Aarch64);
        let mut lines = Vec::with_capacity(count.min(4096));
        let mut offset = 0;
        while lines.len() < count && offset < limit {
            let address = start + offset as u64;
            let insn =
                decoder.decode_with_memory(&code[offset..], address, &|at, size| self.binary.read_pointer(at, size));
            let decode_gate = decoder.decode_gate();
            let bytes = &code[offset..(offset + usize::from(insn.len)).min(code.len())];
            let operand_annotations =
                operands.map(|context| context.display(self, address, bytes)).transpose()?.unwrap_or_default();
            let comment = with_operand_comments(self.describe_reference(&insn), &operand_annotations);
            let text = if decode_gate.is_some() {
                decoder.format(&code[offset..], address)
            } else {
                decoder.format(bytes, address)
            };
            let immediates_hex = arm.then(|| crate::raw_code::hex_immediates(&text)).flatten();
            lines.push(DisassemblyLine {
                address,
                bytes: rampage_arch::hex::bytes(bytes),
                text,
                flow: insn.flow,
                data_ref: insn.data_ref,
                decode_gate,
                accesses: insn.accesses,
                immediate: insn.immediate,
                immediates_hex,
                label: self.name_at(address),
                note: self.comment_at(address),
                comment,
                noreturn: None,
                operand_annotations,
            });
            offset += usize::from(insn.len.max(1));
            if decode_gate.is_some() {
                break;
            }
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
        // An immediate is only maybe an address: name it by symbol, never as a peripheral register (small
        // constants fall inside peripherals on low-address profiles); name_register_accesses vets those.
        let name = if insn.data_ref.is_some() { self.name_at(data) } else { self.symbolic_name_at(data) };
        if let Some(name) = name {
            return Some(name);
        }
        string_at(&self.binary, data).map(|text| format!("{text:?}"))
    }
}

fn with_operand_comments(comment: Option<String>, annotations: &[OperandAnnotationDisplay]) -> Option<String> {
    if annotations.is_empty() {
        return comment;
    }
    let mut parts: Vec<String> = comment.into_iter().collect();
    parts.extend(annotations.iter().map(|entry| format!("op{}: {}", entry.operand, entry.display)));
    Some(parts.join("; "))
}

/// The NUL-terminated printable ASCII string at `address`, if there is one of at least four characters. Long
/// strings are cut at 80 characters.
pub(crate) fn string_at(binary: &Binary, address: u64) -> Option<String> {
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
