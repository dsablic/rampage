//! Structured pseudocode for one Dalvik method: registers named as locals (`this` and `p1`, `p2`, ... for the
//! parameters, `vN` for the rest, declared with the type every write gives them or `var`), `if`/`else` and
//! `while (true)` read from the control-flow graph, invokes as Java-like calls, constructors folded into
//! `new T(...)`, results folded into assignments, and const-strings inline. It is not Java decompilation: types
//! are not propagated through expressions, and every jump that does not fit a structure stays a `goto` to a label,
//! so the text keeps the bytecode's meaning. Work is bounded by instructions, nesting and lines.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::dex::{CodeItem, Dex, cut, escape, java_name};
use crate::insn::{Decoded, array_data, decode_all, switch_cases};

/// Bounds of [`pseudocode`].
#[derive(Debug, Clone, Copy)]
pub struct PseudoLimits {
    /// Instructions structured; a longer body is rendered with gotos only.
    pub max_insns: usize,
    /// Nesting of structures; deeper code is rendered with gotos.
    pub max_depth: usize,
    /// Lines produced.
    pub max_lines: usize,
}

impl Default for PseudoLimits {
    fn default() -> Self {
        Self { max_insns: 20_000, max_depth: 48, max_lines: 5000 }
    }
}

/// The pseudocode of one method.
#[derive(Debug, Clone, Default)]
pub struct Pseudo {
    pub lines: Vec<String>,
    /// Whether [`PseudoLimits::max_lines`] cut it.
    pub truncated: bool,
    /// Bounds that made parts render with gotos.
    pub notes: Vec<String>,
}

/// A basic block: instruction indexes `[first, end)`.
#[derive(Debug, Clone, Copy)]
struct Block {
    first: usize,
    end: usize,
}

/// The innermost enclosing loop: its header address and the address just past it.
#[derive(Debug, Clone, Copy)]
struct Loop {
    header: u32,
    exit: u32,
}

struct Writer<'a> {
    dex: &'a Dex,
    insns: &'a [u16],
    decoded: Vec<Decoded>,
    blocks: Vec<Block>,
    /// Block index by its first instruction's address.
    block_at: HashMap<u32, usize>,
    names: HashMap<u32, String>,
    lines: Vec<String>,
    labels: BTreeSet<u32>,
    /// Where each line starts a block (line index to block address), for labels.
    starts: Vec<(usize, u32)>,
    /// Instruction indexes already rendered as part of another (folded move-result, new-instance).
    folded: BTreeSet<usize>,
    /// Block address to the blocks (sorted) whose last instruction jumps back to it.
    back_edges: HashMap<u32, Vec<usize>>,
    limits: PseudoLimits,
    notes: BTreeSet<String>,
    truncated: bool,
    flat: bool,
}

fn is_return(opcode: u8) -> bool {
    matches!(opcode, 0x0e..=0x11 | 0x27)
}

fn is_goto(opcode: u8) -> bool {
    matches!(opcode, 0x28..=0x2a)
}

fn is_if(opcode: u8) -> bool {
    matches!(opcode, 0x32..=0x3d)
}

fn is_switch(opcode: u8) -> bool {
    matches!(opcode, 0x2b | 0x2c)
}

/// `pkg.Class` as `Class` (`byte[]` and primitives as they are).
fn simple(descriptor: &str) -> String {
    let name = java_name(descriptor);
    let (base, dims) = match name.find('[') {
        Some(at) => (&name[..at], &name[at..]),
        None => (name.as_str(), ""),
    };
    format!("{}{dims}", base.rsplit(['.', '$']).next().unwrap_or(base))
}

const BINARY: [&str; 11] = ["+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", ">>>"];
const CONDITIONS: [&str; 6] = ["==", "!=", "<", ">=", ">", "<="];
const NEGATED: [&str; 6] = ["!=", "==", ">=", "<", "<=", ">"];

impl Writer<'_> {
    fn reg(&self, reg: u32) -> String {
        self.names.get(&reg).cloned().unwrap_or_else(|| format!("v{reg}"))
    }

    fn line(&mut self, depth: usize, text: String) {
        if self.lines.len() >= self.limits.max_lines {
            self.truncated = true;
            return;
        }
        self.lines.push(format!("{}{text}", "    ".repeat(depth.min(self.limits.max_depth))));
    }

    fn string(&self, index: u32) -> String {
        self.dex
            .string(index)
            .map_or_else(|_| format!("<string {index}>"), |text| format!("\"{}\"", escape(&cut(&text.text))))
    }

    /// The condition an if-* tests, or its negation.
    fn condition(&self, insn: &Decoded, negate: bool) -> String {
        let table = if negate { &NEGATED } else { &CONDITIONS };
        if insn.opcode <= 0x37 {
            let op = table[usize::from(insn.opcode - 0x32)];
            format!("{} {op} {}", self.reg(insn.regs[0]), self.reg(insn.regs[1]))
        } else {
            let op = table[usize::from(insn.opcode - 0x38)];
            format!("{} {op} 0", self.reg(insn.regs[0]))
        }
    }

    /// A call's text (`Class.name(a, b)`, `x.name(b)`, `super.name(b)`), and the `<init>` target register when it
    /// constructs.
    fn call(&self, insn: &Decoded) -> (String, Option<u32>) {
        let Some(method) = insn.index.and_then(|index| self.dex.method(index).ok()) else {
            return (format!("<method {}>", insn.index.unwrap_or(0)), None);
        };
        let is_static = matches!(insn.opcode, 0x71 | 0x77);
        let mut args: Vec<String> = Vec::new();
        let mut at = usize::from(!is_static);
        for param in &method.proto.parameters {
            if let Some(&reg) = insn.regs.get(at) {
                args.push(self.reg(reg));
            }
            at += if matches!(param.as_str(), "J" | "D") { 2 } else { 1 };
        }
        let args = args.join(", ");
        if is_static {
            return (format!("{}.{}({args})", simple(&method.class), method.name), None);
        }
        let this = insn.regs.first().copied().unwrap_or(0);
        if method.name == "<init>" {
            let target = self.reg(this);
            if target == "this" {
                return (format!("super({args})"), None);
            }
            return (format!("new {}({args})", simple(&method.class)), Some(this));
        }
        if matches!(insn.opcode, 0x6f | 0x75) {
            return (format!("super.{}({args})", method.name), None);
        }
        (format!("{}.{}({args})", self.reg(this), method.name), None)
    }

    /// One instruction as a statement (`None` when it renders as nothing).
    fn statement(&mut self, index: usize) -> Option<String> {
        let insn = self.decoded[index].clone();
        let r = |at: usize| self.reg(insn.regs.get(at).copied().unwrap_or(0));
        let literal = insn.literal.unwrap_or(0);
        let type_text =
            |writer: &Self| insn.index.map_or_else(String::new, |index| simple(&writer.dex.type_text(index)));
        let field = |writer: &Self| {
            insn.index
                .and_then(|index| writer.dex.field(index).ok())
                .map_or_else(|| ("?".to_owned(), "?".to_owned()), |field| (simple(&field.class), field.name))
        };
        Some(match insn.opcode {
            0x00 => return None,
            0x01..=0x09 => format!("{} = {};", r(0), r(1)),
            0x0a..=0x0c => format!("{} = <result>;", r(0)),
            0x0d => format!("{} = <caught exception>;", r(0)),
            0x0e => "return;".to_owned(),
            0x0f..=0x11 => format!("return {};", r(0)),
            0x12..=0x14 | 0x16..=0x18 => format!("{} = {literal};", r(0)),
            0x15 | 0x19 => format!("{} = {literal:#x};", r(0)),
            0x1a | 0x1b => format!("{} = {};", r(0), self.string(insn.index.unwrap_or(u32::MAX))),
            0x1c => format!("{} = {}.class;", r(0), type_text(self)),
            0x1d => format!("synchronized_enter({});", r(0)),
            0x1e => format!("synchronized_exit({});", r(0)),
            0x1f => format!("{0} = ({1}) {0};", r(0), type_text(self)),
            0x20 => format!("{} = {} instanceof {};", r(0), r(1), type_text(self)),
            0x21 => format!("{} = {}.length;", r(0), r(1)),
            0x22 => {
                // Folded into the constructor call when one follows in the block.
                let reg = insn.regs[0];
                let at = self.blocks.partition_point(|block| block.first <= index).saturating_sub(1);
                let block = self.blocks.get(at).copied().filter(|block| (block.first..block.end).contains(&index));
                let initialized = block.is_some_and(|block| {
                    self.decoded[index + 1..block.end].iter().any(|later| {
                        matches!(later.opcode, 0x70 | 0x76)
                            && later.regs.first() == Some(&reg)
                            && later
                                .index
                                .and_then(|method| self.dex.method(method).ok())
                                .is_some_and(|method| method.name == "<init>")
                    })
                });
                if initialized {
                    return None;
                }
                format!("{} = new {} /* not constructed here */;", r(0), type_text(self))
            }
            0x23 => {
                let kind = type_text(self);
                let element = kind.strip_suffix("[]").unwrap_or(&kind).to_owned();
                format!("{} = new {element}[{}];", r(0), r(1))
            }
            0x24 | 0x25 => {
                let items: Vec<String> = insn.regs.iter().map(|&reg| self.reg(reg)).collect();
                format!("<result> = new {} {{{}}};", type_text(self), items.join(", "))
            }
            0x26 => {
                let shown = insn.target.and_then(|target| array_data(self.insns, target)).map_or_else(
                    || "?".to_owned(),
                    |(width, data)| {
                        let count = data.len() / width.max(1);
                        let items: Vec<String> = data
                            .chunks(width.max(1))
                            .take(16)
                            .map(|chunk| {
                                let mut bytes = [0u8; 8];
                                bytes[..chunk.len()].copy_from_slice(chunk);
                                let shift = 64 - 8 * chunk.len() as u32;
                                (((i64::from_le_bytes(bytes)) << shift) >> shift).to_string()
                            })
                            .collect();
                        let more = if count > 16 { format!(", ... {} in all", count) } else { String::new() };
                        format!("{}{more}", items.join(", "))
                    },
                );
                format!("fill({}, {{{shown}}});", r(0))
            }
            0x27 => format!("throw {};", r(0)),
            0x2d..=0x31 => format!("{} = compare({}, {});", r(0), r(1), r(2)),
            0x44..=0x4a => format!("{} = {}[{}];", r(0), r(1), r(2)),
            0x4b..=0x51 => format!("{}[{}] = {};", r(1), r(2), r(0)),
            0x52..=0x58 => {
                let (_, name) = field(self);
                format!("{} = {}.{name};", r(0), r(1))
            }
            0x59..=0x5f => {
                let (_, name) = field(self);
                format!("{}.{name} = {};", r(1), r(0))
            }
            0x60..=0x66 => {
                let (class, name) = field(self);
                format!("{} = {class}.{name};", r(0))
            }
            0x67..=0x6d => {
                let (class, name) = field(self);
                format!("{class}.{name} = {};", r(0))
            }
            0x6e..=0x72 | 0x74..=0x78 => {
                let (call, constructed) = self.call(&insn);
                if let Some(reg) = constructed {
                    return Some(format!("{} = {call};", self.reg(reg)));
                }
                let next = self.decoded.get(index + 1);
                if let Some(next) = next
                    && matches!(next.opcode, 0x0a..=0x0c)
                    && !self.block_at.contains_key(&next.address)
                {
                    self.folded.insert(index + 1);
                    return Some(format!("{} = {call};", self.reg(next.regs[0])));
                }
                format!("{call};")
            }
            0x7b..=0x8f => {
                let op = match insn.opcode {
                    0x7b | 0x7d | 0x7f | 0x80 => "-".to_owned(),
                    0x7c | 0x7e => "~".to_owned(),
                    0x81 | 0x86 | 0x8b => "(long) ".to_owned(),
                    0x82 | 0x85 | 0x8c => "(float) ".to_owned(),
                    0x83 | 0x87 | 0x8a => "(double) ".to_owned(),
                    0x84 | 0x88 | 0x89 => "(int) ".to_owned(),
                    0x8d => "(byte) ".to_owned(),
                    0x8e => "(char) ".to_owned(),
                    _ => "(short) ".to_owned(),
                };
                format!("{} = {op}{};", r(0), r(1))
            }
            0x90..=0xaf => {
                let op = binary_op(insn.opcode - 0x90);
                format!("{} = {} {op} {};", r(0), r(1), r(2))
            }
            0xb0..=0xcf => {
                let op = binary_op(insn.opcode - 0xb0);
                format!("{0} = {0} {op} {1};", r(0), r(1))
            }
            0xd0..=0xe2 => {
                let op = if insn.opcode >= 0xd8 { insn.opcode - 0xd8 } else { insn.opcode - 0xd0 };
                if op == 1 {
                    format!("{} = {literal} - {};", r(0), r(1))
                } else {
                    format!("{} = {} {} {};", r(0), r(1), BINARY[usize::from(op).min(10)], hex_literal(literal, op))
                }
            }
            0xfa..=0xfd => format!("<result> = invoke_dynamic(...); // {}", crate::insn::opcode(insn.opcode).name),
            0xfe | 0xff => format!("{} = <method handle or type>;", r(0)),
            other => format!("/* {} */", crate::insn::opcode(other).name),
        })
    }

    fn render_block(&mut self, block: usize, depth: usize, loops: &[Loop]) -> bool {
        let Block { first, end } = self.blocks[block];
        let address = self.decoded[first].address;
        self.starts.push((self.lines.len(), address));
        for index in first..end {
            if self.folded.contains(&index) {
                continue;
            }
            let insn = &self.decoded[index];
            if index + 1 == end && (is_goto(insn.opcode) || is_if(insn.opcode) || is_switch(insn.opcode)) {
                break;
            }
            if let Some(text) = self.statement(index) {
                self.line(depth, text);
            }
        }
        let last = self.decoded[end - 1].clone();
        if self.folded.contains(&(end - 1)) {
            // A then-branch's closing goto, rendered as the `else`.
            return false;
        }
        if is_goto(last.opcode) {
            let text = self.jump(last.target, loops);
            self.line(depth, text);
            return true;
        }
        if is_if(last.opcode) {
            let text = format!("if ({}) {}", self.condition(&last, false), self.jump(last.target, loops));
            self.line(depth, text);
        } else if is_switch(last.opcode) {
            let cases = last
                .target
                .and_then(|payload| switch_cases(self.insns, last.address, payload, 256))
                .unwrap_or_default();
            let reg = self.reg(last.regs[0]);
            self.line(depth, format!("switch ({reg}) {{"));
            for (key, target) in cases {
                let text = self.jump(Some(target), loops);
                self.line(depth + 1, format!("case {key}: {text}"));
            }
            self.line(depth, "}".to_owned());
        }
        is_return(last.opcode)
    }

    /// A jump to `target` as `continue;`, `break;` or `goto L_xxxx;`.
    fn jump(&mut self, target: Option<u32>, loops: &[Loop]) -> String {
        let Some(target) = target else { return "goto ?;".to_owned() };
        if let Some(inner) = loops.last() {
            if target == inner.header {
                return "continue;".to_owned();
            }
            if target == inner.exit {
                return "break;".to_owned();
            }
        }
        self.labels.insert(target);
        format!("goto L_{target:04x};")
    }

    /// The address of block `index`'s first instruction, or the body's end.
    fn address(&self, block: usize) -> u32 {
        self.blocks.get(block).map_or(self.insns.len() as u32, |block| self.decoded[block.first].address)
    }

    /// Renders blocks `[from, to)` structured; returns whether control cannot fall out of the last one.
    fn region(&mut self, from: usize, to: usize, depth: usize, loops: &mut Vec<Loop>) -> bool {
        let mut at = from;
        let mut ends = false;
        while at < to {
            if self.truncated {
                return true;
            }
            let header = self.address(at);
            // A loop: a later block in the region jumps back here.
            let tail = if self.flat || depth >= self.limits.max_depth {
                None
            } else {
                self.back_edges.get(&header).and_then(|tails| {
                    let below = tails.partition_point(|&tail| tail < to);
                    below.checked_sub(1).map(|index| tails[index]).filter(|&tail| tail >= at)
                })
            };
            if let Some(tail) = tail
                && !loops.iter().any(|outer| outer.header == header)
            {
                let exit = tail + 1;
                self.starts.push((self.lines.len(), header));
                self.line(depth, "while (true) {".to_owned());
                loops.push(Loop { header, exit: self.address(exit) });
                let stops = self.region(at, exit, depth + 1, loops);
                loops.pop();
                // The back jump closing the body is the loop itself.
                if self.lines.last().is_some_and(|line| line.trim() == "continue;") {
                    self.lines.pop();
                }
                if !stops {
                    self.line(depth + 1, "break;".to_owned());
                }
                self.line(depth, "}".to_owned());
                ends = false;
                at = exit;
                continue;
            }
            let block = self.blocks[at];
            let last = self.decoded[block.end - 1].clone();
            let forward = last
                .target
                .and_then(|target| self.block_at.get(&target).copied())
                .filter(|&target| target > at && target <= to);
            if is_if(last.opcode)
                && !self.flat
                && depth < self.limits.max_depth
                && let Some(join) = forward
                && !loops
                    .last()
                    .is_some_and(|inner| Some(inner.exit) == last.target || Some(inner.header) == last.target)
            {
                // if (cond) goto join;  ==  if (!cond) { [at+1, join) } , with an else when the then part ends in a
                // forward goto past join.
                self.render_block_without_branch(at, depth);
                let then_last = self.decoded[self.blocks[join - 1].end - 1].clone();
                let after = then_last
                    .target
                    .and_then(|target| self.block_at.get(&target).copied())
                    .filter(|&after| is_goto(then_last.opcode) && after > join && after <= to && join - 1 > at);
                self.line(depth, format!("if ({}) {{", self.condition(&last, true)));
                match after {
                    Some(after) => {
                        self.folded.insert(self.blocks[join - 1].end - 1);
                        self.region(at + 1, join, depth + 1, loops);
                        self.line(depth, "} else {".to_owned());
                        self.region(join, after, depth + 1, loops);
                        self.line(depth, "}".to_owned());
                        at = after;
                    }
                    None => {
                        self.region(at + 1, join, depth + 1, loops);
                        self.line(depth, "}".to_owned());
                        at = join;
                    }
                }
                ends = false;
                continue;
            }
            ends = self.render_block(at, depth, loops);
            at += 1;
        }
        ends
    }

    fn render_block_without_branch(&mut self, block: usize, depth: usize) {
        let Block { first, end } = self.blocks[block];
        self.starts.push((self.lines.len(), self.decoded[first].address));
        for index in first..end - 1 {
            if self.folded.contains(&index) {
                continue;
            }
            if let Some(text) = self.statement(index) {
                self.line(depth, text);
            }
        }
    }
}

fn binary_op(op: u8) -> &'static str {
    BINARY[usize::from(op % 11).min(10)]
}

fn hex_literal(literal: i64, op: u8) -> String {
    if matches!(op, 5..=7) && literal > 9 { format!("{literal:#x}") } else { literal.to_string() }
}

/// The pseudocode of the method with body `code`, smali text `signature` (`Lpkg/Class;->name(params)ret`) and
/// access flags `access`.
pub fn pseudocode(dex: &Dex, signature: &str, access: u32, code: &CodeItem, limits: PseudoLimits) -> Pseudo {
    let decoded = decode_all(&code.insns);
    let mut leaders: BTreeSet<u32> = BTreeSet::from([0]);
    for (index, insn) in decoded.iter().enumerate() {
        let next = decoded.get(index + 1).map(|next| next.address);
        if is_goto(insn.opcode) || is_if(insn.opcode) || is_switch(insn.opcode) || is_return(insn.opcode) {
            leaders.extend(next);
            if !is_switch(insn.opcode) {
                leaders.extend(insn.target);
            } else if let Some(cases) =
                insn.target.and_then(|payload| switch_cases(&code.insns, insn.address, payload, 256))
            {
                leaders.extend(cases.into_iter().map(|(_, target)| target));
            }
        }
    }
    for range in &code.tries {
        for handler in code.catches(range) {
            leaders.insert(handler.address);
        }
    }
    let addresses: BTreeMap<u32, usize> =
        decoded.iter().enumerate().map(|(index, insn)| (insn.address, index)).collect();
    let starts: Vec<usize> = leaders.iter().filter_map(|address| addresses.get(address).copied()).collect();
    let blocks: Vec<Block> = starts
        .iter()
        .enumerate()
        .map(|(at, &first)| Block { first, end: starts.get(at + 1).copied().unwrap_or(decoded.len()) })
        .filter(|block| block.first < block.end)
        .collect();
    let block_at = blocks.iter().enumerate().map(|(index, block)| (decoded[block.first].address, index)).collect();

    // Parameters: the last `ins` registers; `this` first unless static.
    let mut names = HashMap::new();
    let (params, ret) = signature
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(params, ret)| (split_params(params), ret.to_owned()))
        .unwrap_or_default();
    let mut reg = u32::from(code.registers.saturating_sub(code.ins));
    let mut header_params = Vec::new();
    if access & 0x8 == 0 {
        names.insert(reg, "this".to_owned());
        reg += 1;
    }
    for (index, param) in params.iter().enumerate() {
        let name = format!("p{}", index + 1);
        header_params.push(format!("{} {name}", simple(param)));
        names.insert(reg, name);
        reg += if matches!(param.as_str(), "J" | "D") { 2 } else { 1 };
    }
    let flat = decoded.len() > limits.max_insns;
    let mut back_edges: HashMap<u32, Vec<usize>> = HashMap::new();
    for (index, block) in blocks.iter().enumerate() {
        let last = &decoded[block.end - 1];
        if (is_goto(last.opcode) || is_if(last.opcode))
            && let Some(target) = last.target
            && target <= decoded[block.first].address
        {
            back_edges.entry(target).or_default().push(index);
        }
    }
    let mut writer = Writer {
        dex,
        insns: &code.insns,
        decoded,
        blocks,
        block_at,
        names,
        lines: Vec::new(),
        labels: BTreeSet::new(),
        starts: Vec::new(),
        folded: BTreeSet::new(),
        back_edges,
        limits,
        notes: BTreeSet::new(),
        truncated: false,
        flat,
    };
    if flat {
        writer.notes.insert(format!("more than {} instructions: rendered with gotos only", limits.max_insns));
    }
    let (class, name) = signature
        .split_once("->")
        .map_or(("", signature), |(class, rest)| (class, rest.split('(').next().unwrap_or(rest)));
    let modifiers = if access & 0x8 != 0 { "static " } else { "" };
    let mut header =
        vec![format!("{modifiers}{} {}.{name}({}) {{", simple(&ret), simple(class), header_params.join(", "))];
    let locals = declarations(&writer, u32::from(code.registers.saturating_sub(code.ins)));
    header.extend(locals.into_iter().map(|line| format!("    {line}")));
    for range in &code.tries {
        let catches: Vec<String> = code
            .catches(range)
            .iter()
            .take(8)
            .map(|catch| {
                writer.labels.insert(catch.address);
                format!(
                    "{} -> L_{:04x}",
                    catch.type_idx.map_or_else(|| "any".to_owned(), |index| simple(&dex.type_text(index))),
                    catch.address
                )
            })
            .collect();
        header.push(format!(
            "    // try {:04x}..{:04x} catches {}",
            range.start,
            range.start + u32::from(range.count),
            catches.join(", ")
        ));
    }
    let count = writer.blocks.len();
    let mut loops = Vec::new();
    if count > 0 {
        writer.region(0, count, 1, &mut loops);
    }
    // Labels before the first line of each block a goto names.
    let mut out = header;
    let mut starts = writer.starts.iter().peekable();
    let mut placed = BTreeSet::new();
    for (index, line) in writer.lines.iter().enumerate() {
        while let Some(&&(at, address)) = starts.peek() {
            if at > index {
                break;
            }
            if writer.labels.contains(&address) && placed.insert(address) {
                out.push(format!("  L_{address:04x}:"));
            }
            starts.next();
        }
        out.push(line.clone());
    }
    out.push("}".to_owned());
    for address in writer.labels.difference(&placed) {
        writer.notes.insert(format!("label L_{address:04x} is inside a structure or a payload"));
    }
    Pseudo { lines: out, truncated: writer.truncated, notes: writer.notes.into_iter().collect() }
}

fn split_params(params: &str) -> Vec<String> {
    let bytes = params.as_bytes();
    let mut list = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let start = at;
        while bytes.get(at) == Some(&b'[') {
            at += 1;
        }
        if bytes.get(at) == Some(&b'L') {
            match params[at..].find(';') {
                Some(end) => at += end,
                None => break,
            }
        }
        at += 1;
        list.push(params[start..at.min(params.len())].to_owned());
    }
    list
}

/// `Type vN;` for every local register, with the type every write to it gives, or `var`.
fn declarations(writer: &Writer<'_>, locals: u32) -> Vec<String> {
    let mut types: BTreeMap<u32, Option<String>> = BTreeMap::new();
    let dex = writer.dex;
    let mut note = |reg: u32, kind: Option<String>| {
        if reg >= locals {
            return;
        }
        types
            .entry(reg)
            .and_modify(|seen| {
                if *seen != kind {
                    *seen = None;
                }
            })
            .or_insert(kind);
    };
    for (index, insn) in writer.decoded.iter().enumerate() {
        let Some(&first) = insn.regs.first() else { continue };
        let kind = match insn.opcode {
            0x12..=0x15 => Some("int".to_owned()),
            0x16..=0x19 => Some("long".to_owned()),
            0x1a | 0x1b => Some("String".to_owned()),
            0x1c => Some("Class".to_owned()),
            0x1f | 0x22 | 0x23 => insn.index.map(|index| simple(&dex.type_text(index))),
            0x21 | 0x20 => Some("int".to_owned()),
            0x60..=0x66 | 0x52..=0x58 => {
                insn.index.and_then(|index| dex.field(index).ok()).map(|field| simple(&field.kind))
            }
            0x0a..=0x0c => writer.decoded[..index]
                .last()
                .and_then(|call| call.index.filter(|_| matches!(call.opcode, 0x6e..=0x72 | 0x74..=0x78)))
                .and_then(|method| dex.method(method).ok())
                .map(|method| simple(&method.proto.return_type)),
            0x01..=0x09 | 0x0d | 0x44..=0x4a | 0x2d..=0x31 | 0x7b..=0xe2 => None,
            _ => continue,
        };
        note(first, kind);
    }
    types.into_iter().map(|(reg, kind)| format!("{} v{reg};", kind.unwrap_or_else(|| "var".to_owned()))).collect()
}
