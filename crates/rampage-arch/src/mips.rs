//! 32-bit MIPS images that hold MIPS16e code beside MIPS32 (most OpenWrt programs). Capstone decodes MIPS32 and
//! [`crate::mips16`] the compressed set. Each instruction's mode comes from what branches have shown (a `jalx`, a
//! jump through a register holding an odd address, a MIPS16e branch), else the loader's MIPS16e ranges, else
//! MIPS32: the interworking rules of [`crate::aarch32`]'s ARM/Thumb decoder, with bit 0 of a code address as the
//! ISA bit. Both modes share one register tracker, so `$gp` and GOT entries resolve across them.

use std::collections::BTreeMap;

use crate::cs::CapstoneDisassembler;
use crate::mips16::{self, Control, Effect};
use crate::track::{Found, Operand, register_named};
use crate::{Disassembler, Flow, Insn, Target, UnsupportedArch};

/// Capstone's names of the MIPS32 registers, by number.
const CAPSTONE_NAMES: [&str; 32] = [
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "s0", "s1", "s2",
    "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
];

pub struct MipsDisassembler {
    inner: CapstoneDisassembler,
    /// Capstone's register id for each MIPS32 register number, as the tracker names registers.
    registers: [u16; 32],
    /// Modes learned at code addresses (`true` is MIPS16e), which the discovery run supplies.
    modes: BTreeMap<u64, bool>,
    /// Modes the instruction just decoded shows at other addresses.
    switches: BTreeMap<u64, bool>,
    /// The address last decoded and its mode.
    decoded_in: Option<(u64, bool)>,
    /// The address straight-line execution reaches next, and its mode.
    sequential_mode: Option<(u64, bool)>,
    /// A MIPS16e jump's delay slot and the jump's address, which PC-relative instructions there take as base.
    delay_slot: Option<(u64, u64)>,
    /// The delay slots of the MIPS16e instruction just decoded.
    delay_slots: Option<u8>,
}

impl MipsDisassembler {
    pub fn new(target: &Target) -> Result<Self, UnsupportedArch> {
        let inner = CapstoneDisassembler::new(target)?;
        let mut registers = [0u16; 32];
        for (number, name) in CAPSTONE_NAMES.iter().enumerate() {
            registers[number] = register_named(&inner.engine, name).unwrap_or(0);
        }
        Ok(Self {
            inner,
            registers,
            modes: BTreeMap::new(),
            switches: BTreeMap::new(),
            decoded_in: None,
            sequential_mode: None,
            delay_slot: None,
            delay_slots: None,
        })
    }

    fn target(&self) -> &Target {
        &self.inner.target
    }

    /// Unlike ARM, where a mapping symbol can switch mode in straight-line code, MIPS changes mode only by a jump,
    /// so straight-line execution keeps its mode whatever the loader's ranges say.
    fn is_mips16(&self, address: u64) -> bool {
        self.modes
            .get(&address)
            .copied()
            .or_else(|| self.sequential_mode.filter(|&(at, _)| at == address).map(|(_, mips16)| mips16))
            .unwrap_or_else(|| self.target().is_thumb(address))
    }

    /// Records that the code at `target` (bit 0 already cleared) runs in `mips16` mode.
    fn note(&mut self, target: u64, mips16: bool) {
        self.modes.entry(target).or_insert(mips16);
        self.switches.insert(target, mips16);
    }

    /// A transfer's target as a code address and its mode: bit 0 is the ISA bit.
    fn interwork(&mut self, target: u64) -> u64 {
        let address = target & !1;
        self.note(address, target & 1 == 1);
        address
    }

    fn decode32(&mut self, bytes: &[u8], address: u64, read: &dyn Fn(u64, u8) -> Option<u64>) -> Insn {
        let mut insn = self.inner.decode_with_memory(bytes, address, read);
        let word = crate::mrs::read_u32(bytes, 0, self.target().big_endian);
        // `jalx` (opcode 0x1d) calls MIPS16e code in the delay slot's 256 MiB region.
        if insn.flow != Flow::Invalid
            && let Some(word) = word.filter(|word| word >> 26 == 0x1d)
        {
            let target = (address.wrapping_add(4) & 0xf000_0000) | u64::from(word & 0x03ff_ffff) << 2;
            insn.flow = Flow::Call(target);
            self.note(target, true);
        } else {
            // A direct target stays in MIPS32; a jump through a register holding an odd address enters MIPS16e.
            insn.flow = match insn.flow {
                Flow::Call(target) => Flow::Call(self.interwork(target)),
                Flow::Jump(target) => Flow::Jump(self.interwork(target)),
                Flow::ConditionalJump(target) => Flow::ConditionalJump(self.interwork(target)),
                flow => flow,
            };
        }
        let next = address.wrapping_add(u64::from(insn.len));
        let after_slot = next.wrapping_add(u64::from(insn.len));
        if matches!(insn.flow, Flow::ConditionalJump(_)) {
            self.note(after_slot, false);
        }
        // The delay slot runs in this mode whatever the branch does.
        self.sequential_mode = Some((next, false));
        insn
    }

    fn decode16(
        &mut self,
        bytes: &[u8],
        address: u64,
        read: &dyn Fn(u64, u8) -> Option<u64>,
        delay_slot_of: Option<u64>,
    ) -> Insn {
        let Some(decoded) = mips16::decode(bytes, address, self.target().big_endian, delay_slot_of) else {
            self.inner.tracker.reset();
            self.sequential_mode = Some((address.wrapping_add(2), true));
            return Insn {
                address,
                len: 2,
                flow: Flow::Invalid,
                data_ref: None,
                accesses: false,
                immediate: None,
                conditional: false,
            };
        };
        let next = address.wrapping_add(u64::from(decoded.len));
        let found = self.track(&decoded, address, read);
        let flow = match decoded.control {
            Control::Next => Flow::Next,
            Control::Branch { target, conditional } => {
                self.note(target, true);
                if conditional {
                    self.note(next, true);
                    Flow::ConditionalJump(target)
                } else {
                    Flow::Jump(target)
                }
            }
            Control::Call { target, exchange } => {
                self.note(target, !exchange);
                Flow::Call(target)
            }
            Control::Register { link, .. } => match found.branch_target {
                Some(target) if link => Flow::Call(self.interwork(target)),
                Some(target) => Flow::Jump(self.interwork(target)),
                None if link => Flow::IndirectCall,
                None => Flow::IndirectJump,
            },
            Control::Return => Flow::Return,
        };
        self.delay_slots = Some(decoded.delay_slots);
        if decoded.delay_slots > 0 {
            self.delay_slot = Some((next, address));
        }
        let falls_through = matches!(flow, Flow::Next | Flow::Call(_) | Flow::IndirectCall | Flow::ConditionalJump(_));
        self.sequential_mode = (falls_through || decoded.delay_slots > 0).then_some((next, true));
        Insn {
            address,
            len: decoded.len,
            flow,
            data_ref: found.data_ref,
            accesses: found.accesses,
            immediate: found.immediate,
            conditional: false,
        }
    }

    /// Follows a MIPS16e instruction in the shared register tracker, through its MIPS32 equivalent where it has one.
    fn track(&mut self, decoded: &mips16::Decoded, address: u64, read: &dyn Fn(u64, u8) -> Option<u64>) -> Found {
        let id = |register: u8| self.registers[usize::from(register & 31)];
        let writes: Vec<u16> = decoded.writes.iter().map(|&register| id(register)).collect();
        let is_call = matches!(decoded.control, Control::Call { .. } | Control::Register { link: true, .. });
        let (mnemonic, operands) = match (decoded.effect, decoded.control) {
            (Effect::Memory { register, base, disp, .. }, _) => (
                decoded.mnemonic,
                vec![Operand::Register(id(register)), Operand::Memory { base: id(base), index: 0, disp }],
            ),
            (Effect::Move { to, from }, _) => ("move", vec![Operand::Register(id(to)), Operand::Register(id(from))]),
            (Effect::AddImmediate { to, from, value }, _) => {
                ("addiu", vec![Operand::Register(id(to)), Operand::Register(id(from)), Operand::Immediate(value)])
            }
            (Effect::Add { to, left, right }, _) => {
                ("addu", vec![Operand::Register(id(to)), Operand::Register(id(left)), Operand::Register(id(right))])
            }
            (_, Control::Register { register, link }) => {
                (if link { "jalr" } else { "jr" }, vec![Operand::Register(id(register))])
            }
            // Effects the tracker has no MIPS32 spelling for are applied after the step.
            _ => ("mips16", Vec::new()),
        };
        let shifted = match decoded.effect {
            Effect::ShiftLeft { from, .. } => self.inner.tracker.value(id(from)),
            _ => None,
        };
        let mut found = self.inner.tracker.step(mnemonic, &operands, &writes, address, is_call);
        match decoded.effect {
            Effect::Constant { to, value } => self.inner.tracker.assign(id(to), value, false),
            Effect::ShiftLeft { to, amount, .. } => {
                if let Some((value, false)) = shifted {
                    self.inner.tracker.assign(id(to), (value << amount) & 0xffff_ffff, false);
                }
            }
            Effect::PcAddress { to, address } => {
                self.inner.tracker.assign(id(to), address, true);
                found.data_ref = Some(address);
                found.accesses = false;
            }
            Effect::PcLoad { to, address } => {
                found.data_ref = Some(address);
                found.accesses = true;
                if let Some(value) = read(address, 4) {
                    let value = value & 0xffff_ffff;
                    self.inner.tracker.assign(id(to), value, false);
                    // A literal holding the global pointer (`__gnu_local_gp`) references nothing.
                    if self.target().global_pointer != Some(value) {
                        found.immediate = Some(value);
                    }
                }
            }
            _ => {}
        }
        if is_call && decoded.delay_slots == 0 {
            self.inner.tracker.call_returned();
        }
        found
    }
}

impl Disassembler for MipsDisassembler {
    fn decode(&mut self, bytes: &[u8], address: u64) -> Insn {
        self.decode_with_memory(bytes, address, &|_, _| None)
    }

    fn decode_with_memory(&mut self, bytes: &[u8], address: u64, read: &dyn Fn(u64, u8) -> Option<u64>) -> Insn {
        self.switches.clear();
        self.delay_slots = None;
        let mips16 = self.is_mips16(address);
        self.decoded_in = Some((address, mips16));
        let delay_slot_of = self.delay_slot.take().filter(|&(at, _)| at == address).map(|(_, jump)| jump);
        if mips16 { self.decode16(bytes, address, read, delay_slot_of) } else { self.decode32(bytes, address, read) }
    }

    fn format(&mut self, bytes: &[u8], address: u64) -> String {
        let mips16 = match self.decoded_in {
            Some((at, mips16)) if at == address => mips16,
            _ => self.is_mips16(address),
        };
        if !mips16 {
            return self.inner.format(bytes, address);
        }
        mips16::decode(bytes, address, self.target().big_endian, None)
            .map_or_else(|| "(bad)".to_owned(), |decoded| decoded.text())
    }

    fn operands(&self, bytes: &[u8], address: u64) -> Option<Vec<crate::OperandEvidence>> {
        if self.is_mips16(address) { None } else { self.inner.operands(bytes, address) }
    }

    fn reset(&mut self) {
        self.inner.reset();
        self.decoded_in = None;
        self.sequential_mode = None;
        self.delay_slot = None;
    }

    fn join(&mut self) {
        self.inner.join();
    }

    fn begin_run(&mut self) {
        self.inner.begin_run();
        self.decoded_in = None;
        self.sequential_mode = None;
        self.delay_slot = None;
    }

    fn begin_function(&mut self, entry: u64) {
        self.inner.begin_function(entry);
        self.decoded_in = None;
        self.sequential_mode = None;
        self.delay_slot = None;
    }

    fn set_code_modes(&mut self, modes: &[(u64, bool)]) {
        self.modes = modes.iter().copied().collect();
        self.switches.clear();
    }

    fn code_modes(&self) -> Vec<(u64, bool)> {
        self.switches.iter().map(|(&address, &mips16)| (address, mips16)).collect()
    }

    fn instruction_mode(&self) -> Option<bool> {
        self.decoded_in.map(|(_, mips16)| mips16)
    }

    fn code_mode_at(&self, address: u64) -> Option<bool> {
        Some(self.is_mips16(address))
    }

    fn delay_slots(&self) -> u8 {
        1
    }

    fn instruction_delay_slots(&self) -> Option<u8> {
        self.delay_slots
    }
}

#[cfg(test)]
#[path = "mips_tests.rs"]
mod tests;
