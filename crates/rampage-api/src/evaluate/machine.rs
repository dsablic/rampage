//! A p-code interpreter: register, unique and other non-memory spaces are byte maps in the target's byte order,
//! and the default data space is a [`Ram`] the caller provides. Nothing runs natively.

use std::collections::HashMap;

use rampage_decompiler::sleigh_decode::{PcodeOp, Varnode};

/// Ghidra's p-code opcode numbers (`opcodes.hh`), checked against the decoder's operation names by [`opcode_name`].
pub(crate) mod op {
    pub const COPY: u32 = 1;
    pub const LOAD: u32 = 2;
    pub const STORE: u32 = 3;
    pub const BRANCH: u32 = 4;
    pub const CBRANCH: u32 = 5;
    pub const BRANCHIND: u32 = 6;
    pub const CALL: u32 = 7;
    pub const CALLIND: u32 = 8;
    pub const CALLOTHER: u32 = 9;
    pub const RETURN: u32 = 10;
    pub const INT_EQUAL: u32 = 11;
    pub const INT_NOTEQUAL: u32 = 12;
    pub const INT_SLESS: u32 = 13;
    pub const INT_SLESSEQUAL: u32 = 14;
    pub const INT_LESS: u32 = 15;
    pub const INT_LESSEQUAL: u32 = 16;
    pub const INT_ZEXT: u32 = 17;
    pub const INT_SEXT: u32 = 18;
    pub const INT_ADD: u32 = 19;
    pub const INT_SUB: u32 = 20;
    pub const INT_CARRY: u32 = 21;
    pub const INT_SCARRY: u32 = 22;
    pub const INT_SBORROW: u32 = 23;
    pub const INT_2COMP: u32 = 24;
    pub const INT_NEGATE: u32 = 25;
    pub const INT_XOR: u32 = 26;
    pub const INT_AND: u32 = 27;
    pub const INT_OR: u32 = 28;
    pub const INT_LEFT: u32 = 29;
    pub const INT_RIGHT: u32 = 30;
    pub const INT_SRIGHT: u32 = 31;
    pub const INT_MULT: u32 = 32;
    pub const INT_DIV: u32 = 33;
    pub const INT_SDIV: u32 = 34;
    pub const INT_REM: u32 = 35;
    pub const INT_SREM: u32 = 36;
    pub const BOOL_NEGATE: u32 = 37;
    pub const BOOL_XOR: u32 = 38;
    pub const BOOL_AND: u32 = 39;
    pub const BOOL_OR: u32 = 40;
    pub const FLOAT_EQUAL: u32 = 41;
    pub const FLOAT_NOTEQUAL: u32 = 42;
    pub const FLOAT_LESS: u32 = 43;
    pub const FLOAT_LESSEQUAL: u32 = 44;
    pub const FLOAT_NAN: u32 = 46;
    pub const FLOAT_ADD: u32 = 47;
    pub const FLOAT_DIV: u32 = 48;
    pub const FLOAT_MULT: u32 = 49;
    pub const FLOAT_SUB: u32 = 50;
    pub const FLOAT_NEG: u32 = 51;
    pub const FLOAT_ABS: u32 = 52;
    pub const FLOAT_SQRT: u32 = 53;
    pub const FLOAT_INT2FLOAT: u32 = 54;
    pub const FLOAT_FLOAT2FLOAT: u32 = 55;
    pub const FLOAT_TRUNC: u32 = 56;
    pub const FLOAT_CEIL: u32 = 57;
    pub const FLOAT_FLOOR: u32 = 58;
    pub const FLOAT_ROUND: u32 = 59;
    pub const PIECE: u32 = 62;
    pub const SUBPIECE: u32 = 63;
    pub const POPCOUNT: u32 = 72;
    pub const LZCOUNT: u32 = 73;
}

/// The name Ghidra gives opcode `code`, for the opcodes this interpreter knows.
pub(crate) fn opcode_name(code: u32) -> Option<&'static str> {
    use op::*;
    Some(match code {
        COPY => "COPY",
        LOAD => "LOAD",
        STORE => "STORE",
        BRANCH => "BRANCH",
        CBRANCH => "CBRANCH",
        BRANCHIND => "BRANCHIND",
        CALL => "CALL",
        CALLIND => "CALLIND",
        CALLOTHER => "CALLOTHER",
        RETURN => "RETURN",
        INT_EQUAL => "INT_EQUAL",
        INT_NOTEQUAL => "INT_NOTEQUAL",
        INT_SLESS => "INT_SLESS",
        INT_SLESSEQUAL => "INT_SLESSEQUAL",
        INT_LESS => "INT_LESS",
        INT_LESSEQUAL => "INT_LESSEQUAL",
        INT_ZEXT => "INT_ZEXT",
        INT_SEXT => "INT_SEXT",
        INT_ADD => "INT_ADD",
        INT_SUB => "INT_SUB",
        INT_CARRY => "INT_CARRY",
        INT_SCARRY => "INT_SCARRY",
        INT_SBORROW => "INT_SBORROW",
        INT_2COMP => "INT_2COMP",
        INT_NEGATE => "INT_NEGATE",
        INT_XOR => "INT_XOR",
        INT_AND => "INT_AND",
        INT_OR => "INT_OR",
        INT_LEFT => "INT_LEFT",
        INT_RIGHT => "INT_RIGHT",
        INT_SRIGHT => "INT_SRIGHT",
        INT_MULT => "INT_MULT",
        INT_DIV => "INT_DIV",
        INT_SDIV => "INT_SDIV",
        INT_REM => "INT_REM",
        INT_SREM => "INT_SREM",
        BOOL_NEGATE => "BOOL_NEGATE",
        BOOL_XOR => "BOOL_XOR",
        BOOL_AND => "BOOL_AND",
        BOOL_OR => "BOOL_OR",
        FLOAT_EQUAL => "FLOAT_EQUAL",
        FLOAT_NOTEQUAL => "FLOAT_NOTEQUAL",
        FLOAT_LESS => "FLOAT_LESS",
        FLOAT_LESSEQUAL => "FLOAT_LESSEQUAL",
        FLOAT_NAN => "FLOAT_NAN",
        FLOAT_ADD => "FLOAT_ADD",
        FLOAT_DIV => "FLOAT_DIV",
        FLOAT_MULT => "FLOAT_MULT",
        FLOAT_SUB => "FLOAT_SUB",
        FLOAT_NEG => "FLOAT_NEG",
        FLOAT_ABS => "FLOAT_ABS",
        FLOAT_SQRT => "FLOAT_SQRT",
        FLOAT_INT2FLOAT => "FLOAT_INT2FLOAT",
        FLOAT_FLOAT2FLOAT => "FLOAT_FLOAT2FLOAT",
        FLOAT_TRUNC => "FLOAT_TRUNC",
        FLOAT_CEIL => "FLOAT_CEIL",
        FLOAT_FLOOR => "FLOAT_FLOOR",
        FLOAT_ROUND => "FLOAT_ROUND",
        PIECE => "PIECE",
        SUBPIECE => "SUBPIECE",
        POPCOUNT => "POPCOUNT",
        LZCOUNT => "LZCOUNT",
        _ => return None,
    })
}

/// Why one instruction could not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Fault {
    UnmappedRead {
        address: u64,
        size: u32,
    },
    UnmappedWrite {
        address: u64,
        size: u32,
    },
    /// A read of the stand-in address an import slot was loaded as: the import's data lies outside the image.
    ExternalRead {
        address: u64,
        name: String,
    },
    Unsupported(String),
    UserOp(String),
    DivisionByZero,
    /// The copy-on-write image pages reached their cap.
    MemoryLimit {
        pages: usize,
    },
    Malformed(String),
}

/// The default data space: the loaded image and any regions the caller maps.
pub(crate) trait Ram {
    fn read(&mut self, address: u64, out: &mut [u8]) -> Result<(), Fault>;
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Fault>;
}

/// How one instruction's p-code ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    Next,
    Jump { target: u64, call: bool },
}

/// The spaces the interpreter treats specially, by the decoder's space index.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SpaceIds {
    pub constant: u32,
    pub unique: u32,
    pub register: u32,
    pub ram: u32,
    /// Bytes in a `ram` address, for wrapping address arithmetic.
    pub address_bytes: u32,
}

/// A user-defined operation the interpreter implements instead of stopping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UserOp {
    /// x86 `segment(selector, offset)`: flat, except FS and GS, which address the thread block.
    Segment {
        thread_selectors: Vec<(u32, u64)>,
        thread_base: u64,
    },
    /// Hints and barriers with no effect on one thread, and ARM's `setISAMode` (the interpreter follows
    /// `TB` itself).
    Nop(String),
    Other(String),
}

pub(crate) const DENSE_LIMIT: u64 = 1 << 24;

/// One byte-addressed scratch space, dense near zero and sparse beyond.
#[derive(Default)]
struct ByteSpace {
    dense: Vec<u8>,
    sparse: HashMap<u64, u8>,
}

impl ByteSpace {
    fn read(&self, offset: u64, out: &mut [u8]) {
        for (index, byte) in out.iter_mut().enumerate() {
            let at = offset.wrapping_add(index as u64);
            *byte = if at < DENSE_LIMIT {
                self.dense.get(at as usize).copied().unwrap_or(0)
            } else {
                self.sparse.get(&at).copied().unwrap_or(0)
            };
        }
    }

    fn write(&mut self, offset: u64, bytes: &[u8]) {
        let end = offset.saturating_add(bytes.len() as u64);
        if end <= DENSE_LIMIT {
            if self.dense.len() < end as usize {
                self.dense.resize(end as usize, 0);
            }
            self.dense[offset as usize..end as usize].copy_from_slice(bytes);
            return;
        }
        // Each byte goes where `read` looks for it, even when an access straddles the dense limit.
        for (index, &byte) in bytes.iter().enumerate() {
            let at = offset.wrapping_add(index as u64);
            if at < DENSE_LIMIT {
                if self.dense.len() <= at as usize {
                    self.dense.resize(at as usize + 1, 0);
                }
                self.dense[at as usize] = byte;
            } else {
                self.sparse.insert(at, byte);
            }
        }
    }
}

pub(crate) struct Machine<R: Ram> {
    pub big_endian: bool,
    ids: SpaceIds,
    registers: ByteSpace,
    unique: ByteSpace,
    other: HashMap<u32, ByteSpace>,
    user_ops: HashMap<u64, UserOp>,
    pub ram: R,
}

fn mask(size: u32) -> u128 {
    if size >= 16 { u128::MAX } else { (1u128 << (size * 8)) - 1 }
}

fn signed(value: u128, size: u32) -> i128 {
    if size >= 16 {
        return value as i128;
    }
    let shift = 128 - size * 8;
    ((value << shift) as i128) >> shift
}

/// Least-significant-first bytes to and from the target's order in storage.
fn to_storage(little: &[u8], big_endian: bool) -> Vec<u8> {
    let mut bytes = little.to_vec();
    if big_endian {
        bytes.reverse();
    }
    bytes
}

impl<R: Ram> Machine<R> {
    pub fn new(ids: SpaceIds, big_endian: bool, ram: R) -> Self {
        Self {
            big_endian,
            ids,
            registers: ByteSpace::default(),
            unique: ByteSpace::default(),
            other: HashMap::new(),
            user_ops: HashMap::new(),
            ram,
        }
    }

    pub fn set_user_op(&mut self, index: u64, op: UserOp) {
        self.user_ops.insert(index, op);
    }

    fn address_mask(&self) -> u64 {
        if self.ids.address_bytes >= 8 { u64::MAX } else { (1u64 << (self.ids.address_bytes * 8)) - 1 }
    }

    fn read_space(&mut self, space: u32, offset: u64, out: &mut [u8]) -> Result<(), Fault> {
        if space == self.ids.ram {
            self.ram.read(offset & self.address_mask(), out)
        } else if space == self.ids.register {
            self.registers.read(offset, out);
            Ok(())
        } else if space == self.ids.unique {
            self.unique.read(offset, out);
            Ok(())
        } else {
            self.other.entry(space).or_default().read(offset, out);
            Ok(())
        }
    }

    fn write_space(&mut self, space: u32, offset: u64, bytes: &[u8]) -> Result<(), Fault> {
        if space == self.ids.ram {
            let address = offset & self.address_mask();
            self.ram.write(address, bytes)
        } else if space == self.ids.register {
            self.registers.write(offset, bytes);
            Ok(())
        } else if space == self.ids.unique {
            self.unique.write(offset, bytes);
            Ok(())
        } else {
            self.other.entry(space).or_default().write(offset, bytes);
            Ok(())
        }
    }

    /// The varnode's value as least-significant-first bytes, of any size.
    fn read_little(&mut self, node: &Varnode) -> Result<Vec<u8>, Fault> {
        let size = node.size as usize;
        let offset = node.offset.ok_or_else(|| Fault::Malformed("value read from a space selector".into()))?;
        if node.space == self.ids.constant {
            let mut bytes = offset.to_le_bytes().to_vec();
            bytes.resize(size, 0);
            return Ok(bytes);
        }
        let mut bytes = vec![0; size];
        self.read_space(node.space, offset, &mut bytes)?;
        if self.big_endian {
            bytes.reverse();
        }
        Ok(bytes)
    }

    fn write_little(&mut self, node: &Varnode, little: &[u8]) -> Result<(), Fault> {
        let offset = node.offset.ok_or_else(|| Fault::Malformed("value written to a space selector".into()))?;
        if node.space == self.ids.constant {
            return Err(Fault::Malformed("write to the constant space".into()));
        }
        let mut bytes = little.to_vec();
        bytes.resize(node.size as usize, 0);
        self.write_space(node.space, offset, &to_storage(&bytes, self.big_endian))
    }

    pub fn read_int(&mut self, node: &Varnode) -> Result<u128, Fault> {
        if node.size as usize > 16 {
            return Err(Fault::Unsupported(format!("integer arithmetic on a {}-byte value", node.size)));
        }
        let bytes = self.read_little(node)?;
        Ok(bytes.iter().rev().fold(0u128, |value, &byte| (value << 8) | u128::from(byte)))
    }

    pub fn write_int(&mut self, node: &Varnode, value: u128) -> Result<(), Fault> {
        let size = (node.size as usize).min(16);
        self.write_little(node, &value.to_le_bytes()[..size])
    }

    /// Reads `size` bytes of ram at `address` as an unsigned integer in the target's byte order.
    #[cfg(test)]
    pub fn read_memory(&mut self, address: u64, size: u32) -> Result<u128, Fault> {
        let mut bytes = vec![0; size as usize];
        self.ram.read(address, &mut bytes)?;
        if !self.big_endian {
            bytes.reverse();
        }
        Ok(bytes.iter().fold(0u128, |value, &byte| (value << 8) | u128::from(byte)))
    }

    pub fn write_memory(&mut self, address: u64, size: u32, value: u128) -> Result<(), Fault> {
        let bytes = to_storage(&value.to_le_bytes()[..size as usize], self.big_endian);
        self.ram.write(address, &bytes)
    }

    /// Runs one instruction's p-code.
    pub fn execute(&mut self, ops: &[PcodeOp]) -> Result<Flow, Fault> {
        let mut index = 0usize;
        let mut budget = 1 << 16;
        while index < ops.len() {
            budget -= 1;
            if budget == 0 {
                return Err(Fault::Malformed("p-code loop within one instruction did not end".into()));
            }
            let current = &ops[index];
            match self.step(current)? {
                Step::Next => index += 1,
                Step::Jump(flow) => return Ok(flow),
                Step::Relative(delta) => {
                    let target = index as i64 + delta;
                    if target == ops.len() as i64 {
                        return Ok(Flow::Next);
                    }
                    if target < 0 || target > ops.len() as i64 {
                        return Err(Fault::Malformed("relative p-code branch leaves the instruction".into()));
                    }
                    index = target as usize;
                }
            }
        }
        Ok(Flow::Next)
    }

    fn input<'a>(&self, op: &'a PcodeOp, index: usize) -> Result<&'a Varnode, Fault> {
        op.inputs.get(index).ok_or_else(|| Fault::Malformed(format!("{} lacks input {index}", op.name)))
    }

    fn output<'a>(&self, op: &'a PcodeOp) -> Result<&'a Varnode, Fault> {
        op.output.as_ref().ok_or_else(|| Fault::Malformed(format!("{} lacks an output", op.name)))
    }

    fn destination(&self, node: &Varnode) -> Result<Destination, Fault> {
        let offset = node.offset.ok_or_else(|| Fault::Malformed("branch to a space selector".into()))?;
        if node.space == self.ids.constant {
            let bits = (node.size * 8).clamp(8, 64);
            let delta = ((offset << (64 - bits)) as i64) >> (64 - bits);
            Ok(Destination::Relative(delta))
        } else {
            Ok(Destination::Absolute(offset))
        }
    }

    fn step(&mut self, current: &PcodeOp) -> Result<Step, Fault> {
        use op::*;
        let code = current.opcode;
        match code {
            COPY => {
                let value = self.read_little(self.input(current, 0)?)?;
                self.write_little(self.output(current)?, &value)?;
            }
            LOAD => {
                let space = self.selected(current)?;
                let address = self.read_int(self.input(current, 1)?)? as u64;
                let output = self.output(current)?;
                let mut bytes = vec![0; output.size as usize];
                self.read_space(space, address, &mut bytes)?;
                self.write_space_node(output, bytes)?;
            }
            STORE => {
                let space = self.selected(current)?;
                let address = self.read_int(self.input(current, 1)?)? as u64;
                let value = self.read_little(self.input(current, 2)?)?;
                self.write_space(space, address, &to_storage(&value, self.big_endian))?;
            }
            BRANCH | CALL => {
                return Ok(match self.destination(self.input(current, 0)?)? {
                    Destination::Relative(delta) => Step::Relative(delta),
                    Destination::Absolute(target) => Step::Jump(Flow::Jump { target, call: code == CALL }),
                });
            }
            CBRANCH => {
                if self.read_int(self.input(current, 1)?)? != 0 {
                    return Ok(match self.destination(self.input(current, 0)?)? {
                        Destination::Relative(delta) => Step::Relative(delta),
                        Destination::Absolute(target) => Step::Jump(Flow::Jump { target, call: false }),
                    });
                }
            }
            BRANCHIND | CALLIND | RETURN => {
                let target = self.read_int(self.input(current, 0)?)? as u64 & self.address_mask();
                return Ok(Step::Jump(Flow::Jump { target, call: code == CALLIND }));
            }
            CALLOTHER => self.user_op(current)?,
            PIECE => {
                let mut value = self.read_little(self.input(current, 1)?)?;
                value.extend(self.read_little(self.input(current, 0)?)?);
                self.write_little(self.output(current)?, &value)?;
            }
            SUBPIECE => {
                let value = self.read_little(self.input(current, 0)?)?;
                let skip = self.input(current, 1)?.offset.unwrap_or(0) as usize;
                let output = self.output(current)?;
                let bytes: Vec<u8> =
                    (0..output.size as usize).map(|index| value.get(skip + index).copied().unwrap_or(0)).collect();
                self.write_little(output, &bytes)?;
            }
            INT_ZEXT | INT_SEXT => {
                let input = self.input(current, 0)?;
                let mut value = self.read_little(input)?;
                let fill = if code == INT_SEXT && value.last().is_some_and(|byte| byte & 0x80 != 0) { 0xff } else { 0 };
                let output = self.output(current)?;
                value.resize(output.size as usize, fill);
                self.write_little(output, &value)?;
            }
            FLOAT_EQUAL..=FLOAT_ROUND => self.float(current)?,
            _ => self.integer(current)?,
        }
        Ok(Step::Next)
    }

    fn write_space_node(&mut self, output: &Varnode, storage_bytes: Vec<u8>) -> Result<(), Fault> {
        let mut little = storage_bytes;
        if self.big_endian {
            little.reverse();
        }
        self.write_little(output, &little)
    }

    fn selected(&self, current: &PcodeOp) -> Result<u32, Fault> {
        let selector = self.input(current, 0)?;
        selector
            .selected_space
            .or_else(|| (selector.space == self.ids.constant).then_some(self.ids.ram))
            .ok_or_else(|| Fault::Malformed(format!("{} lacks a space selector", current.name)))
    }

    fn user_op(&mut self, current: &PcodeOp) -> Result<(), Fault> {
        let index = self.input(current, 0)?.offset.unwrap_or(u64::MAX);
        match self.user_ops.get(&index).cloned() {
            Some(UserOp::Segment { thread_selectors, thread_base }) => {
                let selector = self.input(current, 1)?;
                let offset = self.read_int(self.input(current, 2)?)?;
                let threaded = thread_selectors
                    .iter()
                    .any(|&(space, register)| selector.space == space && selector.offset == Some(register));
                let base = if threaded { u128::from(thread_base) } else { 0 };
                let output = self.output(current)?;
                self.write_int(output, (base + offset) & mask(output.size))
            }
            Some(UserOp::Nop(name)) if current.output.is_some() => Err(Fault::UserOp(name)),
            Some(UserOp::Nop(_)) => Ok(()),
            Some(UserOp::Other(name)) => Err(Fault::UserOp(name)),
            None => Err(Fault::UserOp(format!("user operation {index}"))),
        }
    }

    fn integer(&mut self, current: &PcodeOp) -> Result<(), Fault> {
        use op::*;
        let code = current.opcode;
        let first = self.input(current, 0)?;
        let size = first.size;
        let a = self.read_int(first)?;
        let unary = matches!(code, INT_2COMP | INT_NEGATE | BOOL_NEGATE | POPCOUNT | LZCOUNT);
        let b = if unary { 0 } else { self.read_int(self.input(current, 1)?)? };
        let m = mask(size);
        let bits = size * 8;
        let count = u32::try_from(b).ok().filter(|&count| count < bits);
        let bool_value = |condition: bool| u128::from(condition);
        let result = match code {
            INT_EQUAL => bool_value(a == b),
            INT_NOTEQUAL => bool_value(a != b),
            INT_SLESS => bool_value(signed(a, size) < signed(b, size)),
            INT_SLESSEQUAL => bool_value(signed(a, size) <= signed(b, size)),
            INT_LESS => bool_value(a < b),
            INT_LESSEQUAL => bool_value(a <= b),
            INT_ADD => a.wrapping_add(b) & m,
            INT_SUB => a.wrapping_sub(b) & m,
            INT_CARRY => bool_value(a.checked_add(b).is_none_or(|sum| sum > m)),
            INT_SCARRY => {
                let sum = signed(a.wrapping_add(b) & m, size);
                let (x, y) = (signed(a, size), signed(b, size));
                bool_value((x >= 0) == (y >= 0) && (sum >= 0) != (x >= 0))
            }
            INT_SBORROW => {
                let difference = signed(a.wrapping_sub(b) & m, size);
                let (x, y) = (signed(a, size), signed(b, size));
                bool_value((x >= 0) != (y >= 0) && (difference >= 0) != (x >= 0))
            }
            INT_2COMP => a.wrapping_neg() & m,
            INT_NEGATE => !a & m,
            INT_XOR => a ^ b,
            INT_AND => a & b,
            INT_OR => a | b,
            INT_LEFT => count.map_or(0, |count| (a << count) & m),
            INT_RIGHT => count.map_or(0, |count| a >> count),
            INT_SRIGHT => {
                let count = count.unwrap_or(bits.saturating_sub(1));
                (signed(a, size) >> count) as u128 & m
            }
            INT_MULT => a.wrapping_mul(b) & m,
            INT_DIV | INT_REM | INT_SDIV | INT_SREM if b == 0 => return Err(Fault::DivisionByZero),
            INT_DIV => a / b,
            INT_REM => a % b,
            INT_SDIV => signed(a, size).wrapping_div(signed(b, size)) as u128 & m,
            INT_SREM => signed(a, size).wrapping_rem(signed(b, size)) as u128 & m,
            BOOL_NEGATE => bool_value(a & 1 == 0),
            BOOL_XOR => (a ^ b) & 1,
            BOOL_AND => a & b & 1,
            BOOL_OR => (a | b) & 1,
            POPCOUNT => u128::from(a.count_ones()),
            LZCOUNT => u128::from(a.leading_zeros() - (128 - bits)),
            _ => {
                return Err(Fault::Unsupported(format!("p-code operation {} ({code})", current.name)));
            }
        };
        let output = self.output(current)?;
        self.write_int(output, result & mask(output.size))
    }

    fn float(&mut self, current: &PcodeOp) -> Result<(), Fault> {
        use op::*;
        let code = current.opcode;
        let first = self.input(current, 0)?;
        let output = self.output(current)?;
        let unsupported = |size: u32| Fault::Unsupported(format!("{} on a {size}-byte float", current.name));
        let as_float = |bits: u128, size: u32| -> Result<f64, Fault> {
            match size {
                4 => Ok(f64::from(f32::from_bits(bits as u32))),
                8 => Ok(f64::from_bits(bits as u64)),
                _ => Err(unsupported(size)),
            }
        };
        let from_float = |value: f64, size: u32| -> Result<u128, Fault> {
            match size {
                4 => Ok(u128::from((value as f32).to_bits())),
                8 => Ok(u128::from(value.to_bits())),
                _ => Err(unsupported(size)),
            }
        };
        let raw = self.read_int(first)?;
        if code == FLOAT_INT2FLOAT {
            let value = signed(raw, first.size) as f64;
            let result = from_float(value, output.size)?;
            return self.write_int(output, result);
        }
        let a = as_float(raw, first.size)?;
        let binary = matches!(
            code,
            FLOAT_EQUAL
                | FLOAT_NOTEQUAL
                | FLOAT_LESS
                | FLOAT_LESSEQUAL
                | FLOAT_ADD
                | FLOAT_DIV
                | FLOAT_MULT
                | FLOAT_SUB
        );
        let b = if binary {
            let second = self.input(current, 1)?;
            let raw = self.read_int(second)?;
            as_float(raw, second.size)?
        } else {
            0.0
        };
        // Single-precision arithmetic rounds once in f64 and again to f32, which is exact for +, -, *, / and sqrt.
        let result = match code {
            FLOAT_EQUAL => u128::from(a == b),
            FLOAT_NOTEQUAL => u128::from(a != b),
            FLOAT_LESS => u128::from(a < b),
            FLOAT_LESSEQUAL => u128::from(a <= b),
            FLOAT_NAN => u128::from(a.is_nan()),
            FLOAT_ADD => from_float(a + b, output.size)?,
            FLOAT_SUB => from_float(a - b, output.size)?,
            FLOAT_MULT => from_float(a * b, output.size)?,
            FLOAT_DIV => from_float(a / b, output.size)?,
            FLOAT_NEG => from_float(-a, output.size)?,
            FLOAT_ABS => from_float(a.abs(), output.size)?,
            FLOAT_SQRT => from_float(a.sqrt(), output.size)?,
            FLOAT_FLOAT2FLOAT => from_float(a, output.size)?,
            FLOAT_CEIL => from_float(a.ceil(), output.size)?,
            FLOAT_FLOOR => from_float(a.floor(), output.size)?,
            FLOAT_ROUND => from_float(a.round(), output.size)?,
            FLOAT_TRUNC => {
                if output.size > 8 {
                    return Err(unsupported(output.size));
                }
                (a.trunc() as i64) as u128 & mask(output.size)
            }
            _ => return Err(Fault::Unsupported(format!("p-code operation {} ({code})", current.name))),
        };
        self.write_int(output, result)
    }
}

enum Destination {
    Relative(i64),
    Absolute(u64),
}

enum Step {
    Next,
    Jump(Flow),
    Relative(i64),
}
