//! String decryption for DEX code: call sites where constant arguments (const-string, const ints) go into a static
//! app method returning `String`, and a small Dalvik interpreter that runs such decoder methods on those inputs.
//!
//! The interpreter models integer and long arithmetic, arrays, `String`, `StringBuilder`, chars, Base64 and the
//! decoder's own static fields (its class's `<clinit>` runs first, under the same budget); calls into other static
//! app methods nest up to a depth. It has no I/O, no reflection, no instance fields and no objects of app classes:
//! any unmodelled instruction or call stops that emulation, as do the step, depth, allocation and string-length
//! budgets. Nothing it reads can make it run longer than its budget.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

use crate::dex::{CodeItem, Dex, InitialValue};
use crate::graph::AppGraph;
use crate::insn::{Decoded, array_data, decode_all, switch_cases};

/// Work bounds of one emulation and of a whole app's decoding.
#[derive(Debug, Clone, Copy)]
pub struct DecodeLimits {
    /// Instructions per emulation (the decoder's `<clinit>` and nested calls included).
    pub max_steps: u64,
    /// Nested static calls.
    pub max_depth: usize,
    /// Elements per array, and array elements plus string units allocated per emulation.
    pub max_array: usize,
    pub max_alloc: usize,
    /// UTF-16 units per string or builder.
    pub max_string: usize,
    /// Code units of decoder bodies kept decoded at once (a larger body is not emulated), and code units the call
    /// site scan reads for the whole app.
    pub max_code_units: usize,
    pub max_scan_units: usize,
    /// Call sites considered, distinct emulations run and instructions run for the whole app.
    pub max_sites: usize,
    pub max_emulations: usize,
    pub max_total_steps: u64,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_steps: 100_000,
            max_depth: 16,
            max_array: 1 << 16,
            max_alloc: 1 << 20,
            max_string: 1 << 16,
            max_code_units: 1 << 20,
            max_scan_units: 64 << 20,
            max_sites: 4096,
            max_emulations: 2048,
            max_total_steps: 8_000_000,
        }
    }
}

/// A value in a register.
#[derive(Debug, Clone)]
pub enum Value {
    Int(i32),
    Long(i64),
    Null,
    Str(Rc<Vec<u16>>),
    Array(Rc<RefCell<Array>>),
    Builder(Rc<RefCell<Vec<u16>>>),
    /// A `java.util.Base64` decoder (URL-safe or not).
    Base64Decoder(bool),
    /// The second half of a long, or a register never written.
    Unset,
    /// A static field whose initial value was not read (a type, enum, method or array constant).
    Unknown,
}

#[derive(Debug, Clone)]
pub enum Array {
    Byte(Vec<i8>),
    Char(Vec<u16>),
    Short(Vec<i16>),
    Int(Vec<i32>),
    Long(Vec<i64>),
    Bool(Vec<bool>),
    Object(Vec<Value>),
}

impl Array {
    fn len(&self) -> usize {
        match self {
            Array::Byte(items) => items.len(),
            Array::Char(items) => items.len(),
            Array::Short(items) => items.len(),
            Array::Int(items) => items.len(),
            Array::Long(items) => items.len(),
            Array::Bool(items) => items.len(),
            Array::Object(items) => items.len(),
        }
    }

    fn bytes(&self) -> Option<Vec<u8>> {
        match self {
            Array::Byte(items) => Some(items.iter().map(|&byte| byte as u8).collect()),
            _ => None,
        }
    }
}

/// Why an emulation stopped without a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// An instruction or call the interpreter does not model.
    Unmodelled(String),
    /// A budget ran out (`steps`, `depth`, `allocation`, `string length`).
    Budget(&'static str),
    /// The code would throw (a null array, an index out of bounds, a division by zero, `throw`), or the body is
    /// malformed.
    Fault(String),
}

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stop::Unmodelled(what) => write!(f, "unmodelled: {what}"),
            Stop::Budget(what) => write!(f, "{what} budget"),
            Stop::Fault(what) => write!(f, "fault: {what}"),
        }
    }
}

type Step<T> = Result<T, Stop>;

fn unmodelled<T>(what: impl Into<String>) -> Step<T> {
    Err(Stop::Unmodelled(what.into()))
}

fn fault<T>(what: impl Into<String>) -> Step<T> {
    Err(Stop::Fault(what.into()))
}

/// A switch table, built once per payload: packed by arithmetic, sparse by binary search.
enum Switch {
    Packed { first: i32, targets: Vec<u32> },
    Sparse { cases: Vec<(i32, u32)> },
}

impl Switch {
    fn target(&self, key: i32) -> Option<u32> {
        match self {
            Switch::Packed { first, targets } => {
                let at = i64::from(key) - i64::from(*first);
                usize::try_from(at).ok().and_then(|at| targets.get(at).copied())
            }
            Switch::Sparse { cases } => cases.binary_search_by_key(&key, |&(case, _)| case).ok().map(|at| cases[at].1),
        }
    }
}

/// A decoded method body with its address index and the switch tables built so far.
struct Body {
    code: CodeItem,
    decoded: Vec<Decoded>,
    index: HashMap<u32, usize>,
    dex: usize,
    switches: RefCell<HashMap<u32, Rc<Switch>>>,
}

/// The interpreter's state across one emulation: the app, the statics of initialized classes, the budgets used.
pub struct Emulator<'a> {
    dexes: &'a [&'a Dex],
    graph: &'a AppGraph,
    limits: DecodeLimits,
    statics: HashMap<String, Value>,
    initialized: HashSet<String>,
    /// Classes whose `<clinit>` stopped: their statics are unknown.
    failed: HashSet<String>,
    /// Decoded bodies by DEX file and code offset, and the code units they hold.
    bodies: HashMap<(usize, u32), Rc<Body>>,
    body_units: usize,
    pub steps: u64,
    alloc: usize,
    depth: usize,
}

/// `(params)ret` split into parameter descriptors and the return type.
fn parse_proto(proto: &str) -> Option<(Vec<String>, String)> {
    let inner = proto.strip_prefix('(')?;
    let (params, ret) = inner.split_once(')')?;
    let bytes = params.as_bytes();
    let mut list = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let start = at;
        while bytes.get(at) == Some(&b'[') {
            at += 1;
        }
        if bytes.get(at) == Some(&b'L') {
            at += params[at..].find(';')?;
        }
        at += 1;
        list.push(params.get(start..at)?.to_owned());
    }
    Some((list, ret.to_owned()))
}

fn wide(descriptor: &str) -> bool {
    matches!(descriptor, "J" | "D")
}

fn text(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

impl<'a> Emulator<'a> {
    pub fn new(dexes: &'a [&'a Dex], graph: &'a AppGraph, limits: DecodeLimits) -> Self {
        Self {
            dexes,
            graph,
            limits,
            statics: HashMap::new(),
            initialized: HashSet::new(),
            failed: HashSet::new(),
            bodies: HashMap::new(),
            body_units: 0,
            steps: 0,
            alloc: 0,
            depth: 0,
        }
    }

    /// Starts a new emulation: budgets reset, and statics forgotten (each emulation runs the `<clinit>`s it needs
    /// itself), so no emulation sees another's writes and memory never accumulates across emulations.
    pub fn reset(&mut self) {
        self.steps = 0;
        self.alloc = 0;
        self.depth = 0;
        self.statics.clear();
        self.initialized.clear();
        self.failed.clear();
    }

    /// Charges `units` of work (a loop over a string or array inside one instruction) to the step budget.
    fn work(&mut self, units: usize) -> Step<()> {
        self.steps = self.steps.saturating_add(units as u64);
        if self.steps > self.limits.max_steps { Err(Stop::Budget("steps")) } else { Ok(()) }
    }

    fn charge(&mut self, elements: usize) -> Step<()> {
        self.alloc = self.alloc.saturating_add(elements);
        if self.alloc > self.limits.max_alloc { Err(Stop::Budget("allocation")) } else { Ok(()) }
    }

    fn string(&mut self, units: Vec<u16>) -> Step<Value> {
        if units.len() > self.limits.max_string {
            return Err(Stop::Budget("string length"));
        }
        self.charge(units.len())?;
        Ok(Value::Str(Rc::new(units)))
    }

    fn body(&mut self, method: u32) -> Step<Rc<Body>> {
        let info = self.graph.method(method);
        if !info.defined || info.code_off == 0 {
            return unmodelled(format!("{} has no body", info.text));
        }
        let key = (info.dex, info.code_off);
        if let Some(body) = self.bodies.get(&key) {
            return Ok(Rc::clone(body));
        }
        let dex = self.dexes.get(info.dex).ok_or_else(|| Stop::Fault("no such DEX file".to_owned()))?;
        let code = dex.code_item(info.code_off).map_err(|error| Stop::Fault(error.to_string()))?;
        let units = code.insns.len();
        if units > self.limits.max_code_units {
            return Err(Stop::Budget("code size"));
        }
        if self.body_units + units > self.limits.max_code_units {
            self.bodies.clear();
            self.body_units = 0;
        }
        self.body_units += units;
        self.work(units / 4)?;
        let decoded = decode_all(&code.insns);
        let index = decoded.iter().enumerate().map(|(index, insn)| (insn.address, index)).collect();
        let body = Rc::new(Body { code, decoded, index, dex: info.dex, switches: RefCell::new(HashMap::new()) });
        self.bodies.insert(key, Rc::clone(&body));
        Ok(body)
    }

    /// The switch table of the switch at `address` (payload `payload`) of `body`, built once and charged.
    fn switch(&mut self, body: &Body, address: u32, payload: u32, packed: bool) -> Step<Rc<Switch>> {
        if let Some(table) = body.switches.borrow().get(&address) {
            return Ok(Rc::clone(table));
        }
        let mut cases = switch_cases(&body.code.insns, address, payload, usize::MAX)
            .ok_or_else(|| Stop::Fault("bad switch payload".to_owned()))?;
        self.work(cases.len())?;
        let table = if packed {
            let first = cases.first().map_or(0, |&(key, _)| key);
            Switch::Packed { first, targets: cases.into_iter().map(|(_, target)| target).collect() }
        } else {
            cases.sort_by_key(|&(key, _)| key);
            Switch::Sparse { cases }
        };
        let table = Rc::new(table);
        body.switches.borrow_mut().insert(address, Rc::clone(&table));
        Ok(table)
    }

    /// Sets `class`'s statics to their `static_values` and runs its `<clinit>`, once, when the app defines it.
    fn initialize(&mut self, class: &str) -> Step<()> {
        if self.failed.contains(class) {
            return unmodelled(format!("{class}-><clinit> stopped earlier"));
        }
        if !self.initialized.insert(class.to_owned()) {
            return Ok(());
        }
        if let Some(defined) = self.graph.classes.get(class)
            && let Some(dex) = self.dexes.get(defined.dex)
            && let Ok(def) = dex.class_def(defined.index)
        {
            let mut budget = 1 << 16;
            if let Ok(data) = dex.class_data(&def, &mut budget) {
                for (field, value) in dex.static_values(&def, &data.static_fields, 1 << 12) {
                    let Ok(field) = dex.field(field) else { continue };
                    let value = match value {
                        InitialValue::Int(value) if field.kind == "J" => Value::Long(value),
                        InitialValue::Int(value) => Value::Int(value as i32),
                        InitialValue::String(text) => self.string(units(&text))?,
                        InitialValue::Null => Value::Null,
                        InitialValue::Other => Value::Unknown,
                    };
                    self.statics.insert(field.text(), value);
                }
            }
        }
        let Some(clinit) = self.graph.id(&format!("{class}-><clinit>()V")) else { return Ok(()) };
        if !self.graph.method(clinit).defined {
            return Ok(());
        }
        match self.invoke(clinit, Vec::new()) {
            Ok(_) => Ok(()),
            Err(stop) => {
                self.failed.insert(class.to_owned());
                Err(stop)
            }
        }
    }

    /// Calls static method `method` with `args` (one value per parameter; a long is one value).
    pub fn call(&mut self, method: u32, args: Vec<Value>) -> Step<Value> {
        let class = self.graph.method(method).class.clone();
        self.initialize(&class)?;
        self.invoke(method, args)
    }

    fn invoke(&mut self, method: u32, args: Vec<Value>) -> Step<Value> {
        if self.depth >= self.limits.max_depth {
            return Err(Stop::Budget("depth"));
        }
        let info = self.graph.method(method);
        if !info.is_static() {
            return unmodelled(format!("instance method {}", info.text));
        }
        let (params, _) = parse_proto(&info.proto).ok_or_else(|| Stop::Fault("bad prototype".to_owned()))?;
        let body = self.body(method)?;
        let code = &body.code;
        let registers = usize::from(code.registers);
        let ins = usize::from(code.ins);
        let width: usize = params.iter().map(|param| if wide(param) { 2 } else { 1 }).sum();
        if width != ins || ins > registers || args.len() != params.len() {
            return fault("arguments do not fit the method's registers");
        }
        let mut regs = vec![Value::Unset; registers];
        let mut at = registers - ins;
        for (param, arg) in params.iter().zip(args) {
            regs[at] = arg;
            at += if wide(param) { 2 } else { 1 };
        }
        self.depth += 1;
        let result = self.run(&body, &mut regs);
        self.depth -= 1;
        result
    }

    fn run(&mut self, body: &Body, regs: &mut [Value]) -> Step<Value> {
        let dex: &'a Dex =
            self.dexes.get(body.dex).copied().ok_or_else(|| Stop::Fault("no such DEX file".to_owned()))?;
        let (insns, decoded, index) = (&body.code.insns[..], &body.decoded[..], &body.index);
        let mut pc = 0usize;
        let mut result = Value::Unset;
        loop {
            self.steps += 1;
            if self.steps > self.limits.max_steps {
                return Err(Stop::Budget("steps"));
            }
            let insn = decoded.get(pc).ok_or_else(|| Stop::Fault("ran off the end of the body".to_owned()))?;
            let mut next = pc + 1;
            let jump = |target: Option<u32>| -> Step<usize> {
                target
                    .and_then(|target| index.get(&target).copied())
                    .ok_or_else(|| Stop::Fault("bad branch".to_owned()))
            };
            let count = regs.len();
            let r = |at: usize| -> Step<usize> {
                let reg = *insn.regs.get(at).ok_or_else(|| Stop::Fault("missing register".to_owned()))? as usize;
                if reg < count { Ok(reg) } else { fault("register out of range") }
            };
            match insn.opcode {
                0x00 => {}
                0x01..=0x03 | 0x07..=0x09 => {
                    let (a, b) = (r(0)?, r(1)?);
                    regs[a] = regs[b].clone();
                }
                0x04..=0x06 => {
                    let (a, b) = (r(0)?, r(1)?);
                    regs[a] = regs[b].clone();
                    if a + 1 < regs.len() {
                        regs[a + 1] = Value::Unset;
                    }
                }
                0x0a..=0x0c => {
                    let a = r(0)?;
                    regs[a] = std::mem::replace(&mut result, Value::Unset);
                    if insn.opcode == 0x0b && a + 1 < regs.len() {
                        regs[a + 1] = Value::Unset;
                    }
                }
                0x0e => return Ok(Value::Null),
                0x0f..=0x11 => return Ok(regs[r(0)?].clone()),
                0x12..=0x15 => regs[r(0)?] = Value::Int(insn.literal.unwrap_or(0) as i32),
                0x16..=0x19 => regs[r(0)?] = Value::Long(insn.literal.unwrap_or(0)),
                0x1a | 0x1b => {
                    let string =
                        dex.string(insn.index.unwrap_or(u32::MAX)).map_err(|error| Stop::Fault(error.to_string()))?;
                    let value = self.string(units(&string.text))?;
                    regs[r(0)?] = value;
                }
                0x1d..=0x1f => {}
                0x21 => {
                    let (a, b) = (r(0)?, r(1)?);
                    regs[a] = match &regs[b] {
                        Value::Array(array) => Value::Int(array.borrow().len() as i32),
                        _ => return fault("array-length of a non-array"),
                    };
                }
                0x22 => {
                    let kind = dex.type_text(insn.index.unwrap_or(u32::MAX));
                    regs[r(0)?] = match kind.as_str() {
                        "Ljava/lang/StringBuilder;" | "Ljava/lang/StringBuffer;" => {
                            Value::Builder(Rc::new(RefCell::new(Vec::new())))
                        }
                        "Ljava/lang/String;" => Value::Str(Rc::new(Vec::new())),
                        other => return unmodelled(format!("new-instance {other}")),
                    };
                }
                0x23 => {
                    let (a, b) = (r(0)?, r(1)?);
                    let Value::Int(size) = regs[b] else { return fault("new-array size is not an int") };
                    if size < 0 {
                        return fault("negative array size");
                    }
                    let size = size as usize;
                    if size > self.limits.max_array {
                        return Err(Stop::Budget("allocation"));
                    }
                    self.charge(size)?;
                    let kind = dex.type_text(insn.index.unwrap_or(u32::MAX));
                    let array = match kind.as_str() {
                        "[B" => Array::Byte(vec![0; size]),
                        "[C" => Array::Char(vec![0; size]),
                        "[S" => Array::Short(vec![0; size]),
                        "[I" => Array::Int(vec![0; size]),
                        "[J" => Array::Long(vec![0; size]),
                        "[Z" => Array::Bool(vec![false; size]),
                        kind if kind.starts_with("[L") || kind.starts_with("[[") => {
                            Array::Object(vec![Value::Null; size])
                        }
                        other => return unmodelled(format!("new-array {other}")),
                    };
                    regs[a] = Value::Array(Rc::new(RefCell::new(array)));
                }
                0x24 => {
                    let kind = dex.type_text(insn.index.unwrap_or(u32::MAX));
                    if kind != "[I" {
                        return unmodelled(format!("filled-new-array {kind}"));
                    }
                    let mut items = Vec::new();
                    for reg in insn.registers() {
                        match regs.get(reg as usize) {
                            Some(Value::Int(value)) => items.push(*value),
                            _ => return fault("filled-new-array of a non-int"),
                        }
                    }
                    self.charge(items.len())?;
                    result = Value::Array(Rc::new(RefCell::new(Array::Int(items))));
                }
                0x26 => {
                    let a = r(0)?;
                    // The header first: the element count is checked before the data is copied.
                    let header = insn
                        .target
                        .and_then(|target| insns.get(target as usize..target as usize + 4))
                        .filter(|header| header[0] == 0x0300)
                        .ok_or_else(|| Stop::Fault("bad fill-array-data payload".to_owned()))?;
                    let declared = (u32::from(header[2]) | (u32::from(header[3]) << 16)) as usize;
                    let Value::Array(array) = &regs[a] else { return fault("fill-array-data of a non-array") };
                    if declared > array.borrow().len() {
                        return fault("fill-array-data past the array's end");
                    }
                    let array = Rc::clone(array);
                    self.work(declared)?;
                    let (width, data) = insn
                        .target
                        .and_then(|target| array_data(insns, target))
                        .ok_or_else(|| Stop::Fault("bad fill-array-data payload".to_owned()))?;
                    let mut array = array.borrow_mut();
                    let count = data.len() / width.max(1);
                    let word = |i: usize| -> i64 {
                        let mut bytes = [0u8; 8];
                        bytes[..width].copy_from_slice(&data[i * width..(i + 1) * width]);
                        let value = i64::from_le_bytes(bytes);
                        let shift = 64 - 8 * width as u32;
                        (value << shift) >> shift
                    };
                    match (&mut *array, width) {
                        (Array::Byte(items), 1) => (0..count).for_each(|i| items[i] = word(i) as i8),
                        (Array::Bool(items), 1) => (0..count).for_each(|i| items[i] = word(i) != 0),
                        (Array::Char(items), 2) => (0..count).for_each(|i| items[i] = word(i) as u16),
                        (Array::Short(items), 2) => (0..count).for_each(|i| items[i] = word(i) as i16),
                        (Array::Int(items), 4) => (0..count).for_each(|i| items[i] = word(i) as i32),
                        (Array::Long(items), 8) => (0..count).for_each(|i| items[i] = word(i)),
                        _ => return fault("fill-array-data width does not match the array"),
                    }
                }
                0x27 => return fault("throw"),
                0x28..=0x2a => next = jump(insn.target)?,
                0x2b | 0x2c => {
                    let a = r(0)?;
                    let Value::Int(key) = regs[a] else { return fault("switch on a non-int") };
                    let payload = insn.target.ok_or_else(|| Stop::Fault("bad switch payload".to_owned()))?;
                    let table = self.switch(body, insn.address, payload, insn.opcode == 0x2b)?;
                    if let Some(target) = table.target(key) {
                        next = jump(Some(target))?;
                    }
                }
                0x31 => {
                    let (a, b, c) = (r(0)?, r(1)?, r(2)?);
                    let (Value::Long(x), Value::Long(y)) = (&regs[b], &regs[c]) else {
                        return fault("cmp-long of non-longs");
                    };
                    regs[a] = Value::Int(x.cmp(y) as i32);
                }
                0x32..=0x37 => {
                    let (a, b) = (r(0)?, r(1)?);
                    let ordering = match (&regs[a], &regs[b]) {
                        (Value::Int(x), Value::Int(y)) => x.cmp(y),
                        (Value::Null, Value::Null) if matches!(insn.opcode, 0x32 | 0x33) => std::cmp::Ordering::Equal,
                        (Value::Null, _) | (_, Value::Null) if matches!(insn.opcode, 0x32 | 0x33) => {
                            std::cmp::Ordering::Less
                        }
                        _ => return unmodelled("if-test of objects"),
                    };
                    if test(insn.opcode - 0x32, ordering) {
                        next = jump(insn.target)?;
                    }
                }
                0x38..=0x3d => {
                    let a = r(0)?;
                    let ordering = match &regs[a] {
                        Value::Int(x) => x.cmp(&0),
                        Value::Null => std::cmp::Ordering::Equal,
                        Value::Unset => return fault("if-testz of an unset register"),
                        _ => std::cmp::Ordering::Greater,
                    };
                    if test(insn.opcode - 0x38, ordering) {
                        next = jump(insn.target)?;
                    }
                }
                0x44..=0x4a => {
                    let (a, b, c) = (r(0)?, r(1)?, r(2)?);
                    let Value::Int(at) = regs[c] else { return fault("array index is not an int") };
                    let Value::Array(array) = &regs[b] else { return fault("aget of a non-array") };
                    let array = array.borrow();
                    if at < 0 || at as usize >= array.len() {
                        return fault("array index out of bounds");
                    }
                    let at = at as usize;
                    let value = match &*array {
                        Array::Byte(items) => Value::Int(i32::from(items[at])),
                        Array::Char(items) => Value::Int(i32::from(items[at])),
                        Array::Short(items) => Value::Int(i32::from(items[at])),
                        Array::Int(items) => Value::Int(items[at]),
                        Array::Bool(items) => Value::Int(i32::from(items[at])),
                        Array::Long(items) => Value::Long(items[at]),
                        Array::Object(items) => items[at].clone(),
                    };
                    drop(array);
                    regs[a] = value;
                }
                0x4b..=0x51 => {
                    let (a, b, c) = (r(0)?, r(1)?, r(2)?);
                    let Value::Int(at) = regs[c] else { return fault("array index is not an int") };
                    let value = regs[a].clone();
                    let Value::Array(array) = &regs[b] else { return fault("aput into a non-array") };
                    let mut array = array.borrow_mut();
                    if at < 0 || at as usize >= array.len() {
                        return fault("array index out of bounds");
                    }
                    let at = at as usize;
                    match (&mut *array, value) {
                        (Array::Byte(items), Value::Int(value)) => items[at] = value as i8,
                        (Array::Char(items), Value::Int(value)) => items[at] = value as u16,
                        (Array::Short(items), Value::Int(value)) => items[at] = value as i16,
                        (Array::Int(items), Value::Int(value)) => items[at] = value,
                        (Array::Bool(items), Value::Int(value)) => items[at] = value != 0,
                        (Array::Long(items), Value::Long(value)) => items[at] = value,
                        (Array::Object(items), value) => items[at] = value,
                        _ => return fault("aput of a mismatched value"),
                    }
                }
                0x60..=0x66 => {
                    let field =
                        dex.field(insn.index.unwrap_or(u32::MAX)).map_err(|error| Stop::Fault(error.to_string()))?;
                    let value = self.get_static(&field.class, &field.name, &field.kind)?;
                    let a = r(0)?;
                    regs[a] = value;
                }
                0x67..=0x6d => {
                    let field =
                        dex.field(insn.index.unwrap_or(u32::MAX)).map_err(|error| Stop::Fault(error.to_string()))?;
                    if !self.graph.classes.contains_key(&field.class) {
                        return unmodelled(format!("sput {}", field.text()));
                    }
                    self.initialize(&field.class)?;
                    let value = regs[r(0)?].clone();
                    self.statics.insert(field.text(), value);
                }
                0x6e..=0x72 | 0x74..=0x78 => {
                    let callee =
                        dex.method(insn.index.unwrap_or(u32::MAX)).map_err(|error| Stop::Fault(error.to_string()))?;
                    let is_static = matches!(insn.opcode, 0x71 | 0x77);
                    let mut values = Vec::new();
                    let mut at = 0usize;
                    let mut take = |wide_value: bool| -> Step<Value> {
                        let reg =
                            insn.register(at).ok_or_else(|| Stop::Fault("too few argument registers".to_owned()))?
                                as usize;
                        at += if wide_value { 2 } else { 1 };
                        regs.get(reg).cloned().ok_or_else(|| Stop::Fault("register out of range".to_owned()))
                    };
                    if !is_static {
                        values.push(take(false)?);
                    }
                    for param in &callee.proto.parameters {
                        values.push(take(wide(param))?);
                    }
                    let text = callee.text();
                    let (value, this) = self.api(&text, &callee.class, is_static, values)?;
                    if let Some(this) = this {
                        // A constructor (String.<init>) replaces the new instance in its register.
                        let reg = insn.regs[0] as usize;
                        regs[reg] = this;
                    }
                    result = value;
                }
                0x7b => self.unop(insn, regs, |value| match value {
                    Value::Int(x) => Some(Value::Int(x.wrapping_neg())),
                    _ => None,
                })?,
                0x7c => self.unop(insn, regs, |value| match value {
                    Value::Int(x) => Some(Value::Int(!x)),
                    _ => None,
                })?,
                0x7d => self.unop(insn, regs, |value| match value {
                    Value::Long(x) => Some(Value::Long(x.wrapping_neg())),
                    _ => None,
                })?,
                0x7e => self.unop(insn, regs, |value| match value {
                    Value::Long(x) => Some(Value::Long(!x)),
                    _ => None,
                })?,
                0x81 => self.unop(insn, regs, |value| match value {
                    Value::Int(x) => Some(Value::Long(i64::from(*x))),
                    _ => None,
                })?,
                0x84 => self.unop(insn, regs, |value| match value {
                    Value::Long(x) => Some(Value::Int(*x as i32)),
                    _ => None,
                })?,
                0x8d => self.unop(insn, regs, |value| match value {
                    Value::Int(x) => Some(Value::Int(i32::from(*x as i8))),
                    _ => None,
                })?,
                0x8e => self.unop(insn, regs, |value| match value {
                    Value::Int(x) => Some(Value::Int(i32::from(*x as u16))),
                    _ => None,
                })?,
                0x8f => self.unop(insn, regs, |value| match value {
                    Value::Int(x) => Some(Value::Int(i32::from(*x as i16))),
                    _ => None,
                })?,
                0x90..=0x9a => {
                    let (a, b, c) = (r(0)?, r(1)?, r(2)?);
                    regs[a] = Value::Int(int_op(insn.opcode - 0x90, int(&regs[b])?, int(&regs[c])?)?);
                }
                0x9b..=0xa5 => {
                    let (a, b, c) = (r(0)?, r(1)?, r(2)?);
                    regs[a] = Value::Long(long_op(insn.opcode - 0x9b, long(&regs[b])?, &regs[c])?);
                }
                0xb0..=0xba => {
                    let (a, b) = (r(0)?, r(1)?);
                    regs[a] = Value::Int(int_op(insn.opcode - 0xb0, int(&regs[a])?, int(&regs[b])?)?);
                }
                0xbb..=0xc5 => {
                    let (a, b) = (r(0)?, r(1)?);
                    regs[a] = Value::Long(long_op(insn.opcode - 0xbb, long(&regs[a])?, &regs[b])?);
                }
                0xd0..=0xe2 => {
                    let (a, b) = (r(0)?, r(1)?);
                    let literal = insn.literal.unwrap_or(0) as i32;
                    let op = if insn.opcode >= 0xd8 { insn.opcode - 0xd8 } else { insn.opcode - 0xd0 };
                    let x = int(&regs[b])?;
                    // Literal forms: add, rsub, mul, div, rem, and, or, xor, shl, shr, ushr.
                    regs[a] = Value::Int(match op {
                        1 => literal.wrapping_sub(x),
                        0 => x.wrapping_add(literal),
                        op => int_op(op, x, literal)?,
                    });
                }
                other => return unmodelled(format!("{} ({other:#04x})", crate::insn::opcode(other).name)),
            }
            pc = next;
        }
    }

    fn unop(&self, insn: &Decoded, regs: &mut [Value], op: impl Fn(&Value) -> Option<Value>) -> Step<()> {
        let (a, b) = (insn.regs[0] as usize, insn.regs[1] as usize);
        if a >= regs.len() || b >= regs.len() {
            return fault("register out of range");
        }
        regs[a] = op(&regs[b]).ok_or_else(|| Stop::Fault("unary operation of the wrong type".to_owned()))?;
        Ok(())
    }

    fn get_static(&mut self, class: &str, name: &str, kind: &str) -> Step<Value> {
        if class == "Ljava/nio/charset/StandardCharsets;" {
            let charset = match name {
                "UTF_8" => "UTF-8",
                "US_ASCII" => "US-ASCII",
                "ISO_8859_1" => "ISO-8859-1",
                "UTF_16" | "UTF_16BE" | "UTF_16LE" => return unmodelled("UTF-16 charsets"),
                _ => return unmodelled(format!("sget {class}->{name}")),
            };
            return self.string(units(charset));
        }
        if !self.graph.classes.contains_key(class) {
            return unmodelled(format!("sget {class}->{name}:{kind}"));
        }
        self.initialize(class)?;
        let key = format!("{class}->{name}:{kind}");
        if matches!(self.statics.get(&key), Some(Value::Unknown)) {
            return unmodelled(format!("sget {key}: its initial value was not read"));
        }
        Ok(self.statics.get(&key).cloned().unwrap_or(match kind {
            "J" => Value::Long(0),
            "I" | "S" | "B" | "C" | "Z" => Value::Int(0),
            "F" | "D" => return unmodelled("floating-point static"),
            _ => Value::Null,
        }))
    }

    /// Runs a call: a modelled library API, or a static method of the app. Returns the result and, for a
    /// constructor that makes a value (`String.<init>`), the new instance.
    fn api(&mut self, text: &str, class: &str, is_static: bool, args: Vec<Value>) -> Step<(Value, Option<Value>)> {
        let (name, proto) = text
            .split_once("->")
            .map(|(_, rest)| rest.split_at(rest.find('(').unwrap_or(rest.len())))
            .unwrap_or((text, ""));
        if let Some(id) = self.graph.id(text)
            && self.graph.method(id).defined
        {
            if !is_static {
                return unmodelled(format!("app instance method {text}"));
            }
            let class = class.to_owned();
            self.initialize(&class)?;
            return Ok((self.invoke(id, args)?, None));
        }
        // A library call loops over its string and array arguments: charge that work to the step budget.
        let work: usize = args
            .iter()
            .map(|value| match value {
                Value::Str(text) => text.len(),
                Value::Builder(builder) => builder.borrow().len(),
                Value::Array(array) => array.borrow().len(),
                _ => 0,
            })
            .sum();
        self.work(work)?;
        let arg = |index: usize| args.get(index).cloned().unwrap_or(Value::Unset);
        let none = |value: Value| Ok((value, None));
        match (class, name) {
            ("Ljava/lang/Object;", "<init>") => none(Value::Unset),
            ("Ljava/lang/String;", "<init>") => {
                let made = match (proto, arg(1)) {
                    ("()V", _) => Vec::new(),
                    ("(Ljava/lang/String;)V", Value::Str(text)) => text.to_vec(),
                    ("([C)V", Value::Array(array)) => match &*array.borrow() {
                        Array::Char(items) => items.clone(),
                        _ => return fault("String(char[]) of another array"),
                    },
                    ("([CII)V", Value::Array(array)) => match &*array.borrow() {
                        Array::Char(items) => slice(items, int(&arg(2))?, int(&arg(3))?)?.to_vec(),
                        _ => return fault("String(char[]) of another array"),
                    },
                    ("([B)V", Value::Array(array)) => decode_bytes(
                        &array
                            .borrow()
                            .bytes()
                            .ok_or_else(|| Stop::Fault("String(byte[]) of another array".to_owned()))?,
                        "UTF-8",
                    )?,
                    ("([BII)V", Value::Array(array)) => {
                        let bytes = array
                            .borrow()
                            .bytes()
                            .ok_or_else(|| Stop::Fault("String(byte[]) of another array".to_owned()))?;
                        decode_bytes(slice(&bytes, int(&arg(2))?, int(&arg(3))?)?, "UTF-8")?
                    }
                    ("([BLjava/lang/String;)V" | "([BLjava/nio/charset/Charset;)V", Value::Array(array)) => {
                        let bytes = array
                            .borrow()
                            .bytes()
                            .ok_or_else(|| Stop::Fault("String(byte[]) of another array".to_owned()))?;
                        let Value::Str(charset) = arg(2) else { return fault("charset is not a string") };
                        decode_bytes(&bytes, &text_of(&charset))?
                    }
                    _ => return unmodelled(text),
                };
                let made = self.string(made)?;
                Ok((Value::Unset, Some(made)))
            }
            ("Ljava/lang/String;", _) => self.string_api(text, name, proto, &args).map(|value| (value, None)),
            ("Ljava/lang/StringBuilder;" | "Ljava/lang/StringBuffer;", _) => {
                self.builder_api(text, name, proto, &args).map(|value| (value, None))
            }
            ("Landroid/util/Base64;", "decode") => {
                let flags = int(&arg(1))?;
                let input = match arg(0) {
                    Value::Str(text) => ascii(&text)?,
                    Value::Array(array) => {
                        array.borrow().bytes().ok_or_else(|| Stop::Fault("Base64 of another array".to_owned()))?
                    }
                    _ => return fault("Base64.decode of a non-string"),
                };
                let bytes = base64(&input, flags & 8 != 0).ok_or_else(|| Stop::Fault("bad Base64".to_owned()))?;
                self.byte_array(bytes).map(|value| (value, None))
            }
            ("Ljava/util/Base64;", "getDecoder" | "getMimeDecoder") => none(Value::Base64Decoder(false)),
            ("Ljava/util/Base64;", "getUrlDecoder") => none(Value::Base64Decoder(true)),
            ("Ljava/util/Base64$Decoder;", "decode") => {
                let Value::Base64Decoder(url) = arg(0) else { return fault("decode on a non-decoder") };
                let input = match arg(1) {
                    Value::Str(text) => ascii(&text)?,
                    Value::Array(array) => {
                        array.borrow().bytes().ok_or_else(|| Stop::Fault("Base64 of another array".to_owned()))?
                    }
                    _ => return fault("Base64 decode of a non-string"),
                };
                let bytes = base64(&input, url).ok_or_else(|| Stop::Fault("bad Base64".to_owned()))?;
                self.byte_array(bytes).map(|value| (value, None))
            }
            ("Ljava/nio/charset/Charset;", "forName") => none(arg(0)),
            ("Ljava/lang/Integer;", "parseInt") => {
                let Value::Str(text) = arg(0) else { return fault("parseInt of a non-string") };
                let radix = if proto.contains("I)") { int(&arg(1))? } else { 10 };
                if !(2..=36).contains(&radix) {
                    return fault("NumberFormatException (radix)");
                }
                // Java neither trims nor accepts an empty sign; from_str_radix agrees on both.
                let parsed = i32::from_str_radix(&text_of(&text), radix as u32)
                    .map_err(|_| Stop::Fault("NumberFormatException".to_owned()))?;
                none(Value::Int(parsed))
            }
            ("Ljava/lang/Math;", "abs") if proto == "(I)I" => none(Value::Int(int(&arg(0))?.wrapping_abs())),
            ("Ljava/lang/System;", "arraycopy") => {
                let (Value::Array(from), Value::Array(to)) = (arg(0), arg(2)) else {
                    return fault("arraycopy of non-arrays");
                };
                let (start, at, count) = (int(&arg(1))?, int(&arg(3))?, int(&arg(4))?);
                if start < 0 || at < 0 || count < 0 {
                    return fault("arraycopy out of bounds");
                }
                let (start, at, count) = (start as usize, at as usize, count as usize);
                macro_rules! copy {
                    ($a:expr, $b:expr) => {{
                        if start + count > $a.len() || at + count > $b.len() {
                            return fault("arraycopy out of bounds");
                        }
                        $b[at..at + count].clone_from_slice(&$a[start..start + count]);
                    }};
                }
                macro_rules! within {
                    ($a:expr) => {{
                        if start + count > $a.len() || at + count > $a.len() {
                            return fault("arraycopy out of bounds");
                        }
                        $a.copy_within(start..start + count, at);
                    }};
                }
                if Rc::ptr_eq(&from, &to) {
                    match &mut *to.borrow_mut() {
                        Array::Byte(a) => within!(a),
                        Array::Char(a) => within!(a),
                        Array::Int(a) => within!(a),
                        Array::Short(a) => within!(a),
                        Array::Long(a) => within!(a),
                        _ => return unmodelled("arraycopy within this array"),
                    }
                    return none(Value::Unset);
                }
                let source = from.borrow();
                let mut target = to.borrow_mut();
                match (&*source, &mut *target) {
                    (Array::Byte(a), Array::Byte(b)) => copy!(a, b),
                    (Array::Char(a), Array::Char(b)) => copy!(a, b),
                    (Array::Int(a), Array::Int(b)) => copy!(a, b),
                    (Array::Short(a), Array::Short(b)) => copy!(a, b),
                    (Array::Long(a), Array::Long(b)) => copy!(a, b),
                    _ => return unmodelled("arraycopy between these arrays"),
                }
                none(Value::Unset)
            }
            _ => unmodelled(text),
        }
    }

    fn byte_array(&mut self, bytes: Vec<u8>) -> Step<Value> {
        if bytes.len() > self.limits.max_array {
            return Err(Stop::Budget("allocation"));
        }
        self.charge(bytes.len())?;
        Ok(Value::Array(Rc::new(RefCell::new(Array::Byte(bytes.into_iter().map(|byte| byte as i8).collect())))))
    }

    fn string_api(&mut self, text: &str, name: &str, proto: &str, args: &[Value]) -> Step<Value> {
        let arg = |index: usize| args.get(index).cloned().unwrap_or(Value::Unset);
        if name == "valueOf" {
            let made = match (proto, arg(0)) {
                ("(C)Ljava/lang/String;", Value::Int(c)) => vec![c as u16],
                ("(I)Ljava/lang/String;", Value::Int(x)) => units(&x.to_string()),
                ("(J)Ljava/lang/String;", Value::Long(x)) => units(&x.to_string()),
                ("([C)Ljava/lang/String;", Value::Array(array)) => match &*array.borrow() {
                    Array::Char(items) => items.clone(),
                    _ => return fault("valueOf(char[]) of another array"),
                },
                ("(Ljava/lang/Object;)Ljava/lang/String;", value) => self.stringify(&value)?,
                _ => return unmodelled(text),
            };
            return self.string(made);
        }
        let Value::Str(this) = arg(0) else { return fault("String method on a non-string") };
        Ok(match (name, proto) {
            ("length", _) => Value::Int(this.len() as i32),
            ("isEmpty", _) => Value::Int(i32::from(this.is_empty())),
            ("charAt", _) => {
                let at = int(&arg(1))?;
                Value::Int(i32::from(
                    *this
                        .get(usize::try_from(at).map_err(|_| Stop::Fault("charAt out of bounds".to_owned()))?)
                        .ok_or_else(|| Stop::Fault("charAt out of bounds".to_owned()))?,
                ))
            }
            ("toCharArray", _) => {
                self.charge(this.len())?;
                Value::Array(Rc::new(RefCell::new(Array::Char(this.to_vec()))))
            }
            ("getBytes", "()[B" | "(Ljava/lang/String;)[B" | "(Ljava/nio/charset/Charset;)[B") => {
                let charset = match arg(1) {
                    Value::Str(charset) => text_of(&charset),
                    _ => "UTF-8".to_owned(),
                };
                let bytes = match charset.to_ascii_uppercase().as_str() {
                    // A lone surrogate encodes as `?` in Java and as U+FFFD here: stop rather than differ.
                    "UTF-8" | "UTF8" => String::from_utf16(&this)
                        .map_err(|_| Stop::Unmodelled("getBytes of a lone surrogate".to_owned()))?
                        .into_bytes(),
                    "ISO-8859-1" | "US-ASCII" | "ASCII" | "LATIN1" => {
                        this.iter().map(|&unit| if unit < 0x100 { unit as u8 } else { b'?' }).collect()
                    }
                    other => return unmodelled(format!("charset {other}")),
                };
                self.byte_array(bytes)?
            }
            ("substring", "(I)Ljava/lang/String;") => {
                let start = int(&arg(1))?;
                let count =
                    (this.len() as i32).checked_sub(start).ok_or_else(|| Stop::Fault("substring".to_owned()))?;
                let made = slice(&this, start, count)?.to_vec();
                self.string(made)?
            }
            ("substring", "(II)Ljava/lang/String;") => {
                let (start, end) = (int(&arg(1))?, int(&arg(2))?);
                let count = end.checked_sub(start).ok_or_else(|| Stop::Fault("substring".to_owned()))?;
                let made = slice(&this, start, count)?.to_vec();
                self.string(made)?
            }
            ("concat", _) => {
                let Value::Str(other) = arg(1) else { return fault("concat of a non-string") };
                let mut made = this.to_vec();
                made.extend_from_slice(&other);
                self.string(made)?
            }
            ("equals", _) => Value::Int(i32::from(matches!(arg(1), Value::Str(other) if *other == *this))),
            ("hashCode", _) => {
                Value::Int(this.iter().fold(0i32, |hash, &unit| hash.wrapping_mul(31).wrapping_add(i32::from(unit))))
            }
            ("indexOf", "(I)I") => {
                let wanted = int(&arg(1))?;
                Value::Int(this.iter().position(|&unit| i32::from(unit) == wanted).map_or(-1, |at| at as i32))
            }
            ("trim", _) => {
                let start = this.iter().position(|&unit| unit > 0x20).unwrap_or(this.len());
                let end = this.iter().rposition(|&unit| unit > 0x20).map_or(start, |at| at + 1);
                self.string(this[start..end].to_vec())?
            }
            ("intern" | "toString", _) => Value::Str(this),
            // Java's case mapping is locale- and Unicode-aware; only ASCII text is modelled.
            ("toLowerCase" | "toUpperCase", _) if this.iter().any(|&unit| unit >= 0x80) => {
                return unmodelled("case conversion of non-ASCII text");
            }
            ("toLowerCase", "()Ljava/lang/String;") => self.string(
                this.iter().map(|&unit| if (0x41..=0x5a).contains(&unit) { unit + 0x20 } else { unit }).collect(),
            )?,
            ("toUpperCase", "()Ljava/lang/String;") => self.string(
                this.iter().map(|&unit| if (0x61..=0x7a).contains(&unit) { unit - 0x20 } else { unit }).collect(),
            )?,
            ("replace", "(CC)Ljava/lang/String;") => {
                let (from, to) = (int(&arg(1))? as u16, int(&arg(2))? as u16);
                self.string(this.iter().map(|&unit| if unit == from { to } else { unit }).collect())?
            }
            _ => return unmodelled(text),
        })
    }

    fn stringify(&self, value: &Value) -> Step<Vec<u16>> {
        Ok(match value {
            Value::Str(text) => text.to_vec(),
            Value::Builder(builder) => builder.borrow().clone(),
            Value::Null => units("null"),
            _ => return unmodelled("toString of this value"),
        })
    }

    fn builder_api(&mut self, text: &str, name: &str, proto: &str, args: &[Value]) -> Step<Value> {
        let arg = |index: usize| args.get(index).cloned().unwrap_or(Value::Unset);
        let Value::Builder(this) = arg(0) else { return fault("StringBuilder method on another value") };
        let grow = |emulator: &mut Self, added: &[u16]| -> Step<()> {
            if this.borrow().len() + added.len() > emulator.limits.max_string {
                return Err(Stop::Budget("string length"));
            }
            emulator.charge(added.len())?;
            this.borrow_mut().extend_from_slice(added);
            Ok(())
        };
        match (name, proto) {
            ("<init>", "()V" | "(I)V") => {}
            ("<init>", "(Ljava/lang/String;)V" | "(Ljava/lang/CharSequence;)V") => {
                grow(self, &self.stringify(&arg(1))?)?
            }
            ("append", "(C)Ljava/lang/StringBuilder;" | "(C)Ljava/lang/StringBuffer;") => {
                grow(self, &[int(&arg(1))? as u16])?
            }
            ("append", "(I)Ljava/lang/StringBuilder;" | "(I)Ljava/lang/StringBuffer;") => {
                grow(self, &units(&int(&arg(1))?.to_string()))?
            }
            ("append", "(J)Ljava/lang/StringBuilder;" | "(J)Ljava/lang/StringBuffer;") => {
                grow(self, &units(&long(&arg(1))?.to_string()))?
            }
            ("append", "([C)Ljava/lang/StringBuilder;" | "([C)Ljava/lang/StringBuffer;") => {
                let Value::Array(array) = arg(1) else { return fault("append(char[]) of a non-array") };
                let added = match &*array.borrow() {
                    Array::Char(items) => items.clone(),
                    _ => return fault("append(char[]) of another array"),
                };
                grow(self, &added)?;
            }
            ("append", _) if proto.starts_with("(Ljava/lang/") => grow(self, &self.stringify(&arg(1))?)?,
            ("toString", _) => {
                let made = this.borrow().clone();
                return self.string(made);
            }
            ("length", _) => return Ok(Value::Int(this.borrow().len() as i32)),
            ("charAt", _) => {
                let at = int(&arg(1))?;
                let builder = this.borrow();
                let unit = usize::try_from(at)
                    .ok()
                    .and_then(|at| builder.get(at).copied())
                    .ok_or_else(|| Stop::Fault("charAt out of bounds".to_owned()))?;
                return Ok(Value::Int(i32::from(unit)));
            }
            ("setCharAt", _) => {
                let (at, unit) = (int(&arg(1))?, int(&arg(2))?);
                let mut builder = this.borrow_mut();
                let slot = usize::try_from(at)
                    .ok()
                    .and_then(|at| builder.get_mut(at))
                    .ok_or_else(|| Stop::Fault("setCharAt out of bounds".to_owned()))?;
                *slot = unit as u16;
                return Ok(Value::Unset);
            }
            ("reverse", _) => this.borrow_mut().reverse(),
            ("deleteCharAt", _) => {
                let at = int(&arg(1))?;
                let mut builder = this.borrow_mut();
                let at = usize::try_from(at)
                    .ok()
                    .filter(|&at| at < builder.len())
                    .ok_or_else(|| Stop::Fault("deleteCharAt out of bounds".to_owned()))?;
                builder.remove(at);
            }
            _ => return unmodelled(text),
        }
        Ok(Value::Builder(this))
    }
}

/// The if-test opcodes' comparisons in order: eq, ne, lt, ge, gt, le.
fn test(op: u8, ordering: std::cmp::Ordering) -> bool {
    use std::cmp::Ordering::{Equal, Greater, Less};
    match op {
        0 => ordering == Equal,
        1 => ordering != Equal,
        2 => ordering == Less,
        3 => ordering != Less,
        4 => ordering == Greater,
        _ => ordering != Greater,
    }
}

fn int(value: &Value) -> Step<i32> {
    match value {
        Value::Int(value) => Ok(*value),
        _ => fault("an int operand is not an int"),
    }
}

fn long(value: &Value) -> Step<i64> {
    match value {
        Value::Long(value) => Ok(*value),
        _ => fault("a long operand is not a long"),
    }
}

/// add, sub, mul, div, rem, and, or, xor, shl, shr, ushr on ints.
fn int_op(op: u8, x: i32, y: i32) -> Step<i32> {
    Ok(match op {
        0 => x.wrapping_add(y),
        1 => x.wrapping_sub(y),
        2 => x.wrapping_mul(y),
        3 | 4 if y == 0 => return fault("division by zero"),
        3 => x.wrapping_div(y),
        4 => x.wrapping_rem(y),
        5 => x & y,
        6 => x | y,
        7 => x ^ y,
        8 => x.wrapping_shl(y as u32 & 31),
        9 => x.wrapping_shr(y as u32 & 31),
        _ => ((x as u32) >> (y as u32 & 31)) as i32,
    })
}

/// The same on longs; shifts take an int count.
fn long_op(op: u8, x: i64, y: &Value) -> Step<i64> {
    if op >= 8 {
        let count = int(y)? as u32 & 63;
        return Ok(match op {
            8 => x.wrapping_shl(count),
            9 => x.wrapping_shr(count),
            _ => ((x as u64) >> count) as i64,
        });
    }
    let y = long(y)?;
    Ok(match op {
        0 => x.wrapping_add(y),
        1 => x.wrapping_sub(y),
        2 => x.wrapping_mul(y),
        3 | 4 if y == 0 => return fault("division by zero"),
        3 => x.wrapping_div(y),
        4 => x.wrapping_rem(y),
        5 => x & y,
        6 => x | y,
        _ => x ^ y,
    })
}

fn slice<T>(items: &[T], start: i32, count: i32) -> Step<&[T]> {
    if start < 0 || count < 0 || start as usize + count as usize > items.len() {
        return fault("index out of bounds");
    }
    Ok(&items[start as usize..start as usize + count as usize])
}

/// A Base64 input string's bytes; Java refuses a non-ASCII character, so it is a fault here.
fn ascii(text: &[u16]) -> Step<Vec<u8>> {
    text.iter()
        .map(|&unit| u8::try_from(unit).ok().filter(u8::is_ascii))
        .collect::<Option<_>>()
        .ok_or_else(|| Stop::Fault("Base64 input is not ASCII".to_owned()))
}

fn text_of(units: &[u16]) -> String {
    text(units)
}

fn decode_bytes(bytes: &[u8], charset: &str) -> Step<Vec<u16>> {
    match charset.to_ascii_uppercase().as_str() {
        "UTF-8" | "UTF8" => Ok(units(&String::from_utf8_lossy(bytes))),
        "ISO-8859-1" | "LATIN1" | "US-ASCII" | "ASCII" => Ok(bytes.iter().map(|&byte| u16::from(byte)).collect()),
        other => unmodelled(format!("charset {other}")),
    }
}

/// Decodes Base64 (standard, or URL-safe with `-` and `_`), skipping whitespace and stopping at padding.
fn base64(input: &[u8], url: bool) -> Option<Vec<u8>> {
    let value = |byte: u8| -> Option<u32> {
        Some(match byte {
            b'A'..=b'Z' => u32::from(byte - b'A'),
            b'a'..=b'z' => u32::from(byte - b'a') + 26,
            b'0'..=b'9' => u32::from(byte - b'0') + 52,
            b'+' if !url => 62,
            b'/' if !url => 63,
            b'-' if url => 62,
            b'_' if url => 63,
            _ => return None,
        })
    };
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0;
    for &byte in input {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            break;
        }
        buffer = (buffer << 6) | value(byte)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// A constant an argument register holds at a call site.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Constant {
    Str(String),
    Int(i32),
}

impl Constant {
    fn render(&self) -> String {
        match self {
            Constant::Str(text) => format!("{text:?}"),
            Constant::Int(value) => value.to_string(),
        }
    }
}

/// A decoder and its constant inputs: one emulation, shared by every call site passing the same.
type Emulation = (u32, Vec<Constant>);

/// One string a decoder produced at one call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedString {
    /// The decoder method (smali text).
    pub decoder: String,
    /// The method holding the call site, its DEX file (index) and the call's address.
    pub caller: String,
    pub dex: usize,
    pub address: u32,
    /// The constant arguments, rendered (`"..."` or a number).
    pub inputs: Vec<String>,
    pub output: String,
    /// Instructions the emulation ran.
    pub steps: u64,
}

/// Everything decoding an app found, with the bounds hit and why emulations stopped.
#[derive(Debug, Default)]
pub struct Decoding {
    pub strings: Vec<DecodedString>,
    /// Call sites considered and emulations run.
    pub sites: usize,
    pub emulations: usize,
    /// Why emulations stopped without a printable result, by reason, with a count.
    pub stops: BTreeMap<String, usize>,
    pub notes: Vec<String>,
}

/// Parameter types a decoder may take: constants an argument register can hold.
fn constant_param(descriptor: &str) -> bool {
    matches!(descriptor, "Ljava/lang/String;" | "I" | "S" | "B" | "C" | "Z")
}

/// Whether a decoded string is worth reporting: printable text of two or more characters.
fn printable(text: &str) -> bool {
    let count = text.chars().count();
    count >= 2 && text.chars().all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r')) && !text.contains('\u{fffd}')
}

/// The addresses that start a basic block: the entry, branch and case targets, exception handlers, and every
/// instruction after a branch, switch, return or throw.
fn leaders(code: &CodeItem, decoded: &[Decoded]) -> HashSet<u32> {
    let mut leaders = HashSet::from([0]);
    for (index, insn) in decoded.iter().enumerate() {
        let transfers = matches!(insn.opcode, 0x0e..=0x11 | 0x27..=0x2c | 0x32..=0x3d);
        if !transfers {
            continue;
        }
        if let Some(next) = decoded.get(index + 1) {
            leaders.insert(next.address);
        }
        match insn.opcode {
            0x2b | 0x2c => {
                if let Some(cases) =
                    insn.target.and_then(|payload| switch_cases(&code.insns, insn.address, payload, usize::MAX))
                {
                    leaders.extend(cases.into_iter().map(|(_, target)| target));
                }
            }
            _ => leaders.extend(insn.target),
        }
    }
    for range in &code.tries {
        leaders.extend(code.catches(range).iter().map(|catch| catch.address));
    }
    leaders
}

/// The call sites where constants go into a static app method returning `String`, each emulated once per distinct
/// input (results are shared between sites).
pub fn decode_strings(dexes: &[&Dex], graph: &AppGraph, limits: DecodeLimits) -> Decoding {
    let mut out = Decoding::default();
    let mut emulator = Emulator::new(dexes, graph, limits);
    let mut cache: HashMap<Emulation, Option<(String, u64)>> = HashMap::new();
    let mut total_steps = 0u64;
    let mut scanned: HashSet<(usize, u32)> = HashSet::new();
    let mut units_left = limits.max_scan_units;
    'methods: for (caller, method) in graph.methods.iter().enumerate() {
        if !method.defined || method.code_off == 0 || !scanned.insert((method.dex, method.code_off)) {
            continue;
        }
        let Some(dex) = dexes.get(method.dex) else { continue };
        let Ok(code) = dex.code_item(method.code_off) else { continue };
        if code.insns.len() > units_left {
            out.notes
                .push(format!("only the first {} code units were scanned for decoder calls", limits.max_scan_units));
            break;
        }
        units_left -= code.insns.len();
        let decoded = decode_all(&code.insns);
        let leaders = leaders(&code, &decoded);
        // Constants are tracked within a basic block only: every leader starts with nothing known.
        let mut known: HashMap<u32, Constant> = HashMap::new();
        for insn in &decoded {
            if leaders.contains(&insn.address) {
                known.clear();
            }
            match insn.opcode {
                0x12..=0x15 => {
                    known.insert(insn.regs[0], Constant::Int(insn.literal.unwrap_or(0) as i32));
                    continue;
                }
                0x1a | 0x1b => {
                    if let Some(string) = insn.index.and_then(|index| dex.string(index).ok()) {
                        known.insert(insn.regs[0], Constant::Str(string.text.clone()));
                    }
                    continue;
                }
                0x71 | 0x77 => {}
                // Instructions that write no register keep what is known; the rest overwrite their first.
                0x0e..=0x11
                | 0x1d
                | 0x1e
                | 0x1f
                | 0x26..=0x2c
                | 0x32..=0x3d
                | 0x4b..=0x51
                | 0x59..=0x5f
                | 0x67..=0x6d
                | 0x6e..=0x70
                | 0x72
                | 0x74..=0x76
                | 0x78
                | 0xfa..=0xfd => continue,
                _ => {
                    if let Some(&reg) = insn.regs.first() {
                        known.remove(&reg);
                        if matches!(insn.opcode, 0x04..=0x06 | 0x0b | 0x16..=0x19 | 0x45 | 0x53 | 0x61 | 0x9b..=0xa5 | 0xbb..=0xc5)
                        {
                            known.remove(&(reg + 1));
                        }
                    }
                    continue;
                }
            }
            let Some(index) = insn.index else { continue };
            let Ok(callee) = dex.method(index) else { continue };
            let Some(id) = graph.id(&callee.text()).and_then(|id| graph.defined_target(id)) else { continue };
            let target = graph.method(id);
            if !target.defined
                || target.code_off == 0
                || !target.is_static()
                || callee.proto.return_type != "Ljava/lang/String;"
            {
                continue;
            }
            if callee.proto.parameters.is_empty() || !callee.proto.parameters.iter().all(|param| constant_param(param))
            {
                continue;
            }
            let inputs: Option<Vec<Constant>> = insn.registers().map(|reg| known.get(&reg).cloned()).collect();
            let Some(inputs) = inputs.filter(|inputs| inputs.len() == callee.proto.parameters.len()) else { continue };
            let typed = callee
                .proto
                .parameters
                .iter()
                .zip(&inputs)
                .all(|(param, input)| (param == "Ljava/lang/String;") == matches!(input, Constant::Str(_)));
            if !typed {
                continue;
            }
            out.sites += 1;
            if out.sites > limits.max_sites {
                out.notes.push(format!("only the first {} decoder call sites were emulated", limits.max_sites));
                break 'methods;
            }
            let key = (id, inputs.clone());
            if !cache.contains_key(&key) {
                if out.emulations >= limits.max_emulations || total_steps >= limits.max_total_steps {
                    out.notes.push(format!(
                        "decoding stopped at {} emulations or {} instructions in all",
                        limits.max_emulations, limits.max_total_steps
                    ));
                    break 'methods;
                }
                out.emulations += 1;
                emulator.reset();
                let args = inputs
                    .iter()
                    .map(|input| match input {
                        Constant::Str(text) => Value::Str(Rc::new(units(text))),
                        Constant::Int(value) => Value::Int(*value),
                    })
                    .collect();
                let found = match emulator.call(id, args) {
                    Ok(Value::Str(units)) => {
                        let decoded = text(&units);
                        if printable(&decoded) && !inputs.contains(&Constant::Str(decoded.clone())) {
                            Some((decoded, emulator.steps))
                        } else {
                            *out.stops
                                .entry("result not printable text, or the input itself".to_owned())
                                .or_default() += 1;
                            None
                        }
                    }
                    Ok(_) => {
                        *out.stops.entry("result not a string".to_owned()).or_default() += 1;
                        None
                    }
                    Err(stop) => {
                        let reason = match &stop {
                            Stop::Unmodelled(_) => "an unmodelled instruction or call".to_owned(),
                            other => other.to_string(),
                        };
                        *out.stops.entry(reason).or_default() += 1;
                        None
                    }
                };
                total_steps += emulator.steps;
                cache.insert(key.clone(), found);
            }
            if let Some(Some((output, steps))) = cache.get(&key) {
                out.strings.push(DecodedString {
                    decoder: target.text.clone(),
                    caller: graph.methods[caller].text.clone(),
                    dex: method.dex,
                    address: insn.address,
                    inputs: inputs.iter().map(Constant::render).collect(),
                    output: output.clone(),
                    steps: *steps,
                });
            }
        }
    }
    out.notes.sort();
    out.notes.dedup();
    out
}
