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
    /// A vector or other operation [`super::userops`] computes from its operands.
    Computed(String),
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
    /// x86: a float-to-integer conversion out of range (or of NaN) gives the integer indefinite (the minimum signed
    /// value), not a saturated one.
    pub integer_indefinite: bool,
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
            integer_indefinite: false,
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
            Some(UserOp::Computed(name)) => {
                let mut operands = Vec::with_capacity(current.inputs.len().saturating_sub(1));
                for input in current.inputs.iter().skip(1) {
                    let constant = input.space == self.ids.constant;
                    operands.push(super::userops::Operand { bytes: self.read_little(input)?, constant });
                }
                let output = current.output.as_ref().ok_or_else(|| Fault::UserOp(name.clone()))?;
                match super::userops::run(&name, &operands, output.size as usize) {
                    Some(Ok(bytes)) => self.write_little(output, &bytes),
                    Some(Err(what)) => Err(Fault::Unsupported(format!("processor operation {what}"))),
                    None => Err(Fault::UserOp(name)),
                }
            }
            Some(UserOp::Other(name)) => Err(Fault::UserOp(name)),
            None => Err(Fault::UserOp(format!("user operation {index}"))),
        }
    }

    fn integer(&mut self, current: &PcodeOp) -> Result<(), Fault> {
        use op::*;
        let code = current.opcode;
        let first = self.input(current, 0)?;
        let size = first.size;
        if size > 16 {
            return self.wide_integer(current);
        }
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

    /// Integer operations on values wider than 16 bytes (AVX registers), on 64-bit limbs: bitwise, shifts,
    /// addition, subtraction, negation and comparisons. Multiplication and division stay unsupported.
    fn wide_integer(&mut self, current: &PcodeOp) -> Result<(), Fault> {
        use op::*;
        let code = current.opcode;
        let first = self.input(current, 0)?;
        let size = first.size as usize;
        let a = limbs(&self.read_little(first)?);
        let unary = matches!(code, INT_NEGATE | INT_2COMP);
        let b_bytes = if unary { Vec::new() } else { self.read_little(self.input(current, 1)?)? };
        let b = limbs(&b_bytes);
        let bits = 8 * size as u64;
        // A shift count: the second input's value, saturated at the width.
        let count = || {
            let low = b.first().copied().unwrap_or(0);
            if b.iter().skip(1).any(|&limb| limb != 0) { bits } else { low.min(bits) }
        };
        let negative = |value: &[u64]| (value[(size - 1) / 8] >> (8 * ((size - 1) % 8) + 7)) & 1 == 1;
        let boolean = |condition: bool| -> Vec<u8> { vec![u8::from(condition)] };
        let result: Vec<u8> = match code {
            INT_XOR => from_limbs(&zip_limbs(&a, &b, |x, y| x ^ y), size),
            INT_AND => from_limbs(&zip_limbs(&a, &b, |x, y| x & y), size),
            INT_OR => from_limbs(&zip_limbs(&a, &b, |x, y| x | y), size),
            INT_NEGATE => from_limbs(&a.iter().map(|x| !x).collect::<Vec<_>>(), size),
            INT_2COMP => from_limbs(&add_limbs(&a.iter().map(|x| !x).collect::<Vec<_>>(), &[1]), size),
            INT_ADD => from_limbs(&add_limbs(&a, &b), size),
            INT_SUB => {
                let negated = add_limbs(&pad(&b, a.len()).iter().map(|x| !x).collect::<Vec<_>>(), &[1]);
                from_limbs(&add_limbs(&a, &negated), size)
            }
            INT_LEFT => from_limbs(&shift_left(&a, count()), size),
            INT_RIGHT => from_limbs(&shift_right(&a, count(), false, bits), size),
            INT_SRIGHT => from_limbs(&shift_right(&a, count(), negative(&a), bits), size),
            INT_EQUAL | INT_NOTEQUAL => boolean((pad(&a, b.len()) == pad(&b, a.len())) == (code == INT_EQUAL)),
            INT_LESS | INT_LESSEQUAL => {
                let order = compare_limbs(&a, &b);
                boolean(order.is_lt() || (code == INT_LESSEQUAL && order.is_eq()))
            }
            INT_SLESS | INT_SLESSEQUAL => {
                let (x, y) = (negative(&a), negative(&b));
                let order = if x != y {
                    if x { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater }
                } else {
                    compare_limbs(&a, &b)
                };
                boolean(order.is_lt() || (code == INT_SLESSEQUAL && order.is_eq()))
            }
            _ => return Err(Fault::Unsupported(format!("{} on a {size}-byte value", current.name))),
        };
        self.write_little(self.output(current)?, &result)
    }

    fn float(&mut self, current: &PcodeOp) -> Result<(), Fault> {
        use op::*;
        use std::cmp::Ordering;

        use super::float::{self as fp, Rounding};
        let code = current.opcode;
        let first = self.input(current, 0)?;
        let output = self.output(current)?;
        let format = |size: u32| {
            fp::format(size).ok_or_else(|| Fault::Unsupported(format!("{} on a {size}-byte float", current.name)))
        };
        let raw = self.read_int(first)?;
        if code == FLOAT_INT2FLOAT {
            let result = fp::from_integer(signed(raw, first.size), format(output.size)?);
            return self.write_int(output, result);
        }
        let from = format(first.size)?;
        let second = |machine: &mut Self| -> Result<u128, Fault> {
            let input = machine.input(current, 1)?;
            if input.size != first.size {
                return Err(Fault::Malformed(format!("{} on floats of different sizes", current.name)));
            }
            machine.read_int(input)
        };
        let result = match code {
            FLOAT_EQUAL | FLOAT_NOTEQUAL | FLOAT_LESS | FLOAT_LESSEQUAL => {
                let order = fp::compare(raw, second(self)?, from);
                u128::from(match code {
                    FLOAT_EQUAL => order == Some(Ordering::Equal),
                    FLOAT_NOTEQUAL => order != Some(Ordering::Equal),
                    FLOAT_LESS => order == Some(Ordering::Less),
                    _ => matches!(order, Some(Ordering::Less | Ordering::Equal)),
                })
            }
            FLOAT_NAN => u128::from(fp::is_nan(raw, from)),
            FLOAT_NEG => fp::negate(raw, from),
            FLOAT_ABS => fp::absolute(raw, from),
            FLOAT_FLOAT2FLOAT => fp::convert(raw, from, format(output.size)?),
            FLOAT_CEIL => fp::round_integral(raw, from, Rounding::Up),
            FLOAT_FLOOR => fp::round_integral(raw, from, Rounding::Down),
            // Ties to even, as x86 and ARM round in their default mode.
            FLOAT_ROUND => fp::round_integral(raw, from, Rounding::Nearest),
            FLOAT_TRUNC => self.truncate(raw, from, output.size)?,
            FLOAT_ADD | FLOAT_SUB | FLOAT_MULT | FLOAT_DIV | FLOAT_SQRT => {
                let x = fp::to_f64(raw, from);
                let y = if code == FLOAT_SQRT { 0.0 } else { fp::to_f64(second(self)?, from) };
                // binary32 rounds once in f64 and again to f32, which is exact for +, -, *, / and sqrt; x87
                // extended values are computed in f64 (53-bit, not 64-bit, significands).
                let value = match code {
                    FLOAT_ADD => x + y,
                    FLOAT_SUB => x - y,
                    FLOAT_MULT => x * y,
                    FLOAT_DIV => x / y,
                    _ => x.sqrt(),
                };
                fp::from_f64(value, format(output.size)?)
            }
            _ => return Err(Fault::Unsupported(format!("p-code operation {} ({code})", current.name))),
        };
        self.write_int(output, result)
    }

    /// FLOAT_TRUNC of `raw` to a signed `size`-byte integer: toward zero, then saturated (ARM and others) or the
    /// integer indefinite (x86) when out of range; NaN gives 0 (indefinite on x86).
    fn truncate(&self, raw: u128, format: super::float::Format, size: u32) -> Result<u128, Fault> {
        use super::float as fp;
        if size == 0 || size > 16 {
            return Err(Fault::Unsupported(format!("float truncation to a {size}-byte integer")));
        }
        let bits = size * 8;
        let (minimum, maximum) =
            if bits >= 128 { (i128::MIN, i128::MAX) } else { (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1) };
        let value = fp::to_integer(raw, format).filter(|value| (minimum..=maximum).contains(value));
        let value = match value {
            Some(value) => value,
            None if self.integer_indefinite => minimum,
            None if fp::is_nan(raw, format) => 0,
            None if fp::compare(raw, 0, format) == Some(std::cmp::Ordering::Less) => minimum,
            None => maximum,
        };
        Ok(value as u128 & mask(size))
    }
}

/// Little-endian bytes as 64-bit limbs, least significant first.
fn limbs(bytes: &[u8]) -> Vec<u64> {
    bytes.chunks(8).map(|chunk| chunk.iter().rev().fold(0u64, |value, &byte| (value << 8) | u64::from(byte))).collect()
}

fn from_limbs(limbs: &[u64], size: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = limbs.iter().flat_map(|limb| limb.to_le_bytes()).collect();
    bytes.resize(size, 0);
    bytes
}

fn pad(limbs: &[u64], length: usize) -> Vec<u64> {
    let mut padded = limbs.to_vec();
    if padded.len() < length {
        padded.resize(length, 0);
    }
    padded
}

fn zip_limbs(a: &[u64], b: &[u64], f: impl Fn(u64, u64) -> u64) -> Vec<u64> {
    let b = pad(b, a.len());
    a.iter().zip(&b).map(|(&x, &y)| f(x, y)).collect()
}

fn add_limbs(a: &[u64], b: &[u64]) -> Vec<u64> {
    let b = pad(b, a.len());
    let mut carry = false;
    a.iter()
        .zip(&b)
        .map(|(&x, &y)| {
            let (sum, first) = x.overflowing_add(y);
            let (sum, second) = sum.overflowing_add(u64::from(carry));
            carry = first || second;
            sum
        })
        .collect()
}

fn compare_limbs(a: &[u64], b: &[u64]) -> std::cmp::Ordering {
    let length = a.len().max(b.len());
    pad(a, length).iter().rev().cmp(pad(b, length).iter().rev())
}

fn shift_left(value: &[u64], count: u64) -> Vec<u64> {
    let (words, bits) = ((count / 64) as usize, (count % 64) as u32);
    (0..value.len())
        .map(|index| {
            let Some(from) = index.checked_sub(words) else { return 0 };
            let low = if bits > 0 && from > 0 { value[from - 1] >> (64 - bits) } else { 0 };
            (value[from] << bits) | low
        })
        .collect()
}

/// A right shift of a `width`-bit value, filling with ones when `fill`.
fn shift_right(value: &[u64], count: u64, fill: bool, width: u64) -> Vec<u64> {
    let (words, bits) = ((count / 64) as usize, (count % 64) as u32);
    let mut shifted: Vec<u64> = (0..value.len())
        .map(|index| {
            let from = index + words;
            let Some(&word) = value.get(from) else { return 0 };
            let high = if bits > 0 { value.get(from + 1).map_or(0, |&next| next << (64 - bits)) } else { 0 };
            (word >> bits) | high
        })
        .collect();
    if fill {
        // Ones above bit width - count.
        for bit in width.saturating_sub(count)..64 * value.len() as u64 {
            shifted[(bit / 64) as usize] |= 1 << (bit % 64);
        }
    }
    shifted
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
