//! Compact, validated binary encoding of a discovered [`Program`].
//!
//! Integers are LEB128 varints; addresses that cluster are stored as zig-zag differences from a nearby address, so
//! any `u64` round-trips exactly. Decoding treats the bytes as untrusted: every count is bounded by the bytes left,
//! enum tags and strings are checked, trailing bytes are refused, and the ordering invariants that lookups rely on
//! (sorted functions, xrefs, gates and noreturn lists) are revalidated.

use rampage_analysis::discover::{
    Block, DiscoveredFunction, InstructionGate, Program, ResolvedFlow, Switch, Xref, XrefKind,
};
use rampage_arch::{DecodeGate, DecodeGateReason, Flow};

const MAGIC: &[u8; 8] = b"RPGANLZ\0";
/// The longest decode-gate text accepted; real ones are one formatted instruction.
const MAX_TEXT: usize = 4096;
/// The most items reserved up front from an untrusted count; longer lists grow as their items actually decode.
const MAX_RESERVE: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Malformed(pub(crate) &'static str);

pub(crate) fn encode(key: &str, program: &Program) -> Vec<u8> {
    let mut out = Writer(Vec::with_capacity(64 + program.functions.len() * 32 + program.xrefs.len() * 6));
    out.0.extend_from_slice(MAGIC);
    out.bytes(key.as_bytes());
    out.uint(program.functions.len() as u64);
    let mut previous = 0u64;
    for function in &program.functions {
        out.delta(previous, function.address);
        previous = function.address;
        let base = function.address;
        out.uint(function.instruction_count as u64);
        out.uint(function.blocks.len() as u64);
        for block in &function.blocks {
            out.delta(base, block.start);
            out.delta(block.start, block.end);
        }
        out.uint(function.switches.len() as u64);
        for switch in &function.switches {
            out.delta(base, switch.jump);
            out.delta(base, switch.guard);
            out.addresses(base, &switch.cases);
            out.addresses(base, &switch.table);
        }
    }
    out.uint(program.xrefs.len() as u64);
    let mut previous = 0u64;
    for xref in &program.xrefs {
        out.delta(previous, xref.to);
        previous = xref.to;
        out.delta(xref.to, xref.from);
        out.0.push(match xref.kind {
            XrefKind::Call => 0,
            XrefKind::Jump => 1,
            XrefKind::Data => 2,
        });
    }
    out.uint(program.code_modes.len() as u64);
    for &(address, thumb) in &program.code_modes {
        out.uint(address);
        out.0.push(u8::from(thumb));
    }
    out.uint(program.resolved_flows.len() as u64);
    for flow in &program.resolved_flows {
        out.uint(flow.function);
        out.delta(flow.function, flow.address);
        let (tag, target) = flow_parts(flow.flow);
        out.0.push(tag);
        if let Some(target) = target {
            out.delta(flow.address, target);
        }
    }
    out.uint(program.decode_gates.len() as u64);
    for gate in &program.decode_gates {
        out.uint(gate.function);
        out.bytes(gate.gate.backend.as_bytes());
        out.bytes(gate.gate.profile.as_bytes());
        out.delta(gate.function, gate.gate.address);
        out.0.push(reason_tag(gate.gate.reason));
        out.0.push(gate.len);
        out.bytes(gate.text.as_bytes());
    }
    for list in [&program.noreturn, &program.inferred_noreturn, &program.noreturn_calls] {
        out.addresses(0, list);
    }
    out.0
}

/// Decodes a payload written by [`encode`] for exactly `key`.
pub(crate) fn decode(key: &str, bytes: &[u8]) -> Result<Program, Malformed> {
    let mut input = Reader { bytes, at: 0 };
    if input.take(MAGIC.len())? != MAGIC {
        return Err(Malformed("bad magic"));
    }
    if input.bytes()? != key.as_bytes() {
        return Err(Malformed("embedded key differs"));
    }
    let mut program = Program::default();
    let count = input.count()?;
    program.functions.reserve(count.min(MAX_RESERVE));
    let mut previous = 0u64;
    for index in 0..count {
        let address = input.delta(previous)?;
        if index > 0 && address <= previous {
            return Err(Malformed("functions out of order"));
        }
        previous = address;
        let instruction_count = usize::try_from(input.uint()?).map_err(|_| Malformed("instruction count"))?;
        let blocks = input.count()?;
        let mut function = DiscoveredFunction {
            address,
            blocks: Vec::with_capacity(blocks.min(MAX_RESERVE)),
            instruction_count,
            switches: Vec::new(),
        };
        for _ in 0..blocks {
            let start = input.delta(address)?;
            let end = input.delta(start)?;
            if end < start {
                return Err(Malformed("block ends before it starts"));
            }
            function.blocks.push(Block { start, end });
        }
        let switches = input.count()?;
        for _ in 0..switches {
            let jump = input.delta(address)?;
            let guard = input.delta(address)?;
            let cases = input.addresses(address)?;
            let table = input.addresses(address)?;
            if function.switches.last().is_some_and(|last: &Switch| last.jump >= jump) {
                return Err(Malformed("switches out of order"));
            }
            function.switches.push(Switch { jump, cases, table, guard });
        }
        program.functions.push(function);
    }
    let count = input.count()?;
    program.xrefs.reserve(count.min(MAX_RESERVE));
    let mut previous = 0u64;
    let mut previous_from = 0u64;
    for index in 0..count {
        let to = input.delta(previous)?;
        let from = input.delta(to)?;
        if index > 0 && (to, from) < (previous, previous_from) {
            return Err(Malformed("xrefs out of order"));
        }
        previous = to;
        previous_from = from;
        let kind = match input.byte()? {
            0 => XrefKind::Call,
            1 => XrefKind::Jump,
            2 => XrefKind::Data,
            _ => return Err(Malformed("xref kind")),
        };
        program.xrefs.push(Xref { to, from, kind });
    }
    let count = input.count()?;
    for _ in 0..count {
        let address = input.uint()?;
        let thumb = match input.byte()? {
            0 => false,
            1 => true,
            _ => return Err(Malformed("code mode")),
        };
        program.code_modes.push((address, thumb));
    }
    let count = input.count()?;
    for _ in 0..count {
        let function = input.uint()?;
        let address = input.delta(function)?;
        let tag = input.byte()?;
        let target = if flow_has_target(tag)? { Some(input.delta(address)?) } else { None };
        let flow = flow_from(tag, target)?;
        program.resolved_flows.push(ResolvedFlow { function, address, flow });
    }
    let count = input.count()?;
    for _ in 0..count {
        let function = input.uint()?;
        let backend = static_backend(input.bytes()?)?;
        let profile = static_profile(input.bytes()?)?;
        let address = input.delta(function)?;
        let reason = reason_from(input.byte()?)?;
        let len = input.byte()?;
        let text = input.bytes()?;
        if text.len() > MAX_TEXT {
            return Err(Malformed("gate text too long"));
        }
        let text = String::from_utf8(text.to_vec()).map_err(|_| Malformed("gate text"))?;
        let gate = InstructionGate { function, gate: DecodeGate { backend, profile, address, reason }, len, text };
        if program
            .decode_gates
            .last()
            .is_some_and(|last| (last.function, last.gate.address) >= (gate.function, gate.gate.address))
        {
            return Err(Malformed("decode gates out of order"));
        }
        program.decode_gates.push(gate);
    }
    program.noreturn = input.addresses(0)?;
    program.inferred_noreturn = input.addresses(0)?;
    program.noreturn_calls = input.addresses(0)?;
    for list in [&program.noreturn, &program.inferred_noreturn, &program.noreturn_calls] {
        if list.windows(2).any(|pair| pair[0] > pair[1]) {
            return Err(Malformed("noreturn list out of order"));
        }
    }
    if input.at != bytes.len() {
        return Err(Malformed("trailing bytes"));
    }
    Ok(program)
}

fn flow_parts(flow: Flow) -> (u8, Option<u64>) {
    match flow {
        Flow::Next => (0, None),
        Flow::Jump(target) => (1, Some(target)),
        Flow::ConditionalJump(target) => (2, Some(target)),
        Flow::Call(target) => (3, Some(target)),
        Flow::IndirectJump => (4, None),
        Flow::IndirectCall => (5, None),
        Flow::Return => (6, None),
        Flow::Halt => (7, None),
        Flow::Invalid => (8, None),
    }
}

fn flow_has_target(tag: u8) -> Result<bool, Malformed> {
    match tag {
        1..=3 => Ok(true),
        0 | 4..=8 => Ok(false),
        _ => Err(Malformed("flow tag")),
    }
}

fn flow_from(tag: u8, target: Option<u64>) -> Result<Flow, Malformed> {
    Ok(match (tag, target) {
        (0, None) => Flow::Next,
        (1, Some(target)) => Flow::Jump(target),
        (2, Some(target)) => Flow::ConditionalJump(target),
        (3, Some(target)) => Flow::Call(target),
        (4, None) => Flow::IndirectJump,
        (5, None) => Flow::IndirectCall,
        (6, None) => Flow::Return,
        (7, None) => Flow::Halt,
        (8, None) => Flow::Invalid,
        _ => return Err(Malformed("flow")),
    })
}

const REASONS: [DecodeGateReason; 9] = [
    DecodeGateReason::IncompletePcode,
    DecodeGateReason::InternalPcodeBranch,
    DecodeGateReason::MultipleExits,
    DecodeGateReason::UnsupportedTargetSpace,
    DecodeGateReason::UserDefinedOperation,
    DecodeGateReason::DelaySlotAggregation,
    DecodeGateReason::MalformedPcode,
    DecodeGateReason::ContextMediatedFlow,
    DecodeGateReason::ProcessorHelperRequired,
];

fn reason_tag(reason: DecodeGateReason) -> u8 {
    REASONS.iter().position(|&known| known == reason).expect("every decode-gate reason is listed") as u8
}

fn reason_from(tag: u8) -> Result<DecodeGateReason, Malformed> {
    REASONS.get(usize::from(tag)).copied().ok_or(Malformed("decode-gate reason"))
}

/// Gates name their backend and profile with static strings, so only the closed sets that produce gates decode.
fn static_backend(bytes: &[u8]) -> Result<&'static str, Malformed> {
    match bytes {
        b"sleigh" => Ok("sleigh"),
        _ => Err(Malformed("decode-gate backend")),
    }
}

fn static_profile(bytes: &[u8]) -> Result<&'static str, Malformed> {
    rampage_decompiler::sleigh_decode::SleighDecoder::registered_profile_ids()
        .find(|id| id.as_bytes() == bytes)
        .ok_or(Malformed("decode-gate profile"))
}

/// Whether every gate of `program` names a backend and profile [`decode`] can restore.
pub(crate) fn encodable(program: &Program) -> bool {
    program.decode_gates.iter().all(|gate| {
        static_backend(gate.gate.backend.as_bytes()).is_ok()
            && static_profile(gate.gate.profile.as_bytes()).is_ok()
            && gate.text.len() <= MAX_TEXT
    })
}

struct Writer(Vec<u8>);

impl Writer {
    fn uint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.0.push(value as u8 | 0x80);
            value >>= 7;
        }
        self.0.push(value as u8);
    }

    /// `value` as the zig-zag of its wrapping difference from `base`.
    fn delta(&mut self, base: u64, value: u64) {
        let difference = value.wrapping_sub(base) as i64;
        self.uint(((difference << 1) ^ (difference >> 63)) as u64);
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.uint(bytes.len() as u64);
        self.0.extend_from_slice(bytes);
    }

    fn addresses(&mut self, base: u64, addresses: &[u64]) {
        self.uint(addresses.len() as u64);
        let mut previous = base;
        for &address in addresses {
            self.delta(previous, address);
            previous = address;
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Malformed> {
        let end = self.at.checked_add(length).filter(|&end| end <= self.bytes.len()).ok_or(Malformed("truncated"))?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }

    fn uint(&mut self) -> Result<u64, Malformed> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.byte()?;
            let bits = u64::from(byte & 0x7f);
            if shift == 63 && bits > 1 {
                return Err(Malformed("varint overflow"));
            }
            value |= bits << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Malformed("varint overflow"))
    }

    fn delta(&mut self, base: u64) -> Result<u64, Malformed> {
        let zigzag = self.uint()?;
        let difference = ((zigzag >> 1) as i64) ^ -((zigzag & 1) as i64);
        Ok(base.wrapping_add(difference as u64))
    }

    /// A count of items each taking at least one byte, so it can never exceed the bytes left.
    fn count(&mut self) -> Result<usize, Malformed> {
        let count = self.uint()?;
        usize::try_from(count)
            .ok()
            .filter(|&count| count <= self.bytes.len() - self.at)
            .ok_or(Malformed("count exceeds payload"))
    }

    fn bytes(&mut self) -> Result<&'a [u8], Malformed> {
        let length = self.count()?;
        self.take(length)
    }

    fn addresses(&mut self, base: u64) -> Result<Vec<u64>, Malformed> {
        let count = self.count()?;
        let mut addresses = Vec::with_capacity(count.min(MAX_RESERVE));
        let mut previous = base;
        for _ in 0..count {
            previous = self.delta(previous)?;
            addresses.push(previous);
        }
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Program {
        Program {
            functions: vec![
                DiscoveredFunction {
                    address: 0x1000,
                    blocks: vec![Block { start: 0x1000, end: 0x1010 }, Block { start: 0x0ff0, end: 0x1000 }],
                    instruction_count: 7,
                    switches: vec![Switch {
                        jump: 0x1008,
                        cases: vec![0x1010, 0x2000],
                        table: vec![0x2000, 0x1010, 0x2000],
                        guard: 0x1004,
                    }],
                },
                DiscoveredFunction { address: u64::MAX, blocks: vec![], instruction_count: 0, switches: vec![] },
            ],
            xrefs: vec![
                Xref { to: 0, from: u64::MAX, kind: XrefKind::Data },
                Xref { to: 0x1000, from: 0x0500, kind: XrefKind::Call },
                Xref { to: 0x1000, from: 0x0600, kind: XrefKind::Jump },
            ],
            code_modes: vec![(0x1000, true), (0x0800, false)],
            resolved_flows: vec![
                ResolvedFlow { function: 0x1000, address: 0x1008, flow: Flow::Jump(0x900) },
                ResolvedFlow { function: 0x1000, address: 0x100a, flow: Flow::IndirectCall },
            ],
            decode_gates: vec![InstructionGate {
                function: 0x1000,
                gate: DecodeGate {
                    backend: "sleigh",
                    profile: "z80:LE:16:default",
                    address: 0x100c,
                    reason: DecodeGateReason::ProcessorHelperRequired,
                },
                len: 2,
                text: "halt".into(),
            }],
            noreturn: vec![0x10, 0x20],
            inferred_noreturn: vec![0x20],
            noreturn_calls: vec![0x1004],
        }
    }

    #[test]
    fn programs_round_trip_exactly() {
        let program = sample();
        assert!(encodable(&program));
        let bytes = encode("k", &program);
        assert_eq!(decode("k", &bytes).unwrap(), program);
        assert_eq!(decode("k", &encode("k", &Program::default())).unwrap(), Program::default());
    }

    #[test]
    fn damaged_payloads_are_refused_without_panicking() {
        let bytes = encode("key", &sample());
        assert_eq!(decode("other", &bytes), Err(Malformed("embedded key differs")));
        for length in 0..bytes.len() {
            assert!(decode("key", &bytes[..length]).is_err(), "truncated to {length}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(decode("key", &longer), Err(Malformed("trailing bytes")));
        // Every single-byte change either fails or decodes to some Program; it never panics or over-allocates.
        for index in 0..bytes.len() {
            for flip in [0x01, 0x80, 0xff] {
                let mut damaged = bytes.clone();
                damaged[index] ^= flip;
                let _ = decode("key", &damaged);
            }
        }
        let mut huge = MAGIC.to_vec();
        huge.extend([3, b'k', b'e', b'y', 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
        assert_eq!(decode("key", &huge), Err(Malformed("count exceeds payload")));
    }

    #[test]
    fn broken_invariants_are_refused() {
        let mut program = sample();
        program.functions[0].blocks[0] = Block { start: 0x1010, end: 0x1000 };
        assert_eq!(decode("k", &encode("k", &program)), Err(Malformed("block ends before it starts")));
        let mut program = sample();
        program.xrefs.swap(1, 2);
        assert_eq!(decode("k", &encode("k", &program)), Err(Malformed("xrefs out of order")));
    }

    #[test]
    fn unknown_gate_strings_are_not_encodable() {
        let mut program = sample();
        program.decode_gates[0].gate.profile = "test:bounded";
        assert!(!encodable(&program));
    }
}
