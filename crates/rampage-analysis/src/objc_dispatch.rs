//! Objective-C message sends resolved to the method implementations they reach.
//!
//! A send is a call (or tail jump) to `objc_msgSend` and its variants, to an arm64 selector stub
//! (`objc_msgSend$selector` in `__objc_stubs`), or to an allocation fast path (`objc_alloc`, `objc_alloc_init`,
//! `objc_opt_new`). Its selector is the `__objc_selrefs` entry loaded into the selector register (x1 / rsi), or the
//! one the stub loads. Its receiver class is what is statically evident in the receiver register (x0 / rdi): a
//! class reference, `self` in a method of a known class, the class of `super`, or the result of `+alloc` / `+new` /
//! `-init…` / `-class` on a known class. Registers are followed by a forward dataflow over each function's blocks;
//! nothing stored to memory is followed.
//!
//! Resolution walks the receiver's class up its superclass chain within the binary, categories before the class's
//! own methods. A receiver whose class is known only as a static type (`self`) may be a subclass, so every
//! override in a local subclass is a target too and the send is `ambiguous`. A receiver of unknown class gets the
//! selector's implementations in the binary as `candidates`, never one guessed target.

use std::collections::{BTreeSet, HashMap, HashSet};

use rampage_arch::registers::{X86Registers, a64_access};
use rampage_arch::{Arch, Disassembler, Flow};
use rampage_loaders::objc::{ObjcRefs, ObjcReport};
use rampage_loaders::{Binary, Format};
use rayon::prelude::*;
use serde::Serialize;

use crate::discover::{DiscoveredFunction, Program};

/// The most implementations a send of unknown receiver lists as candidate targets; more are only counted.
pub const MAX_CANDIDATES: usize = 8;
const MAX_SUPERCLASS_DEPTH: usize = 64;
/// Passes over a function's blocks before its dataflow is taken as settled.
const MAX_PASSES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// The receiver class is known and exactly one implementation in the binary answers the selector.
    Resolved,
    /// The receiver class is known, but a subclass override or several categories make more than one
    /// implementation reachable.
    Ambiguous,
    /// The receiver class is known and no implementation in the binary answers the selector: it is inherited from
    /// a class outside the binary (a framework).
    Framework,
    /// The receiver class is unknown; `targets` lists every implementation of the selector in the binary (when
    /// there are at most [`MAX_CANDIDATES`]).
    Candidates,
    /// The receiver class is unknown and the binary implements no method of that selector.
    UnknownReceiver,
    /// The selector register's value is not statically evident.
    UnknownSelector,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Resolved => "resolved",
            Confidence::Ambiguous => "ambiguous",
            Confidence::Framework => "framework",
            Confidence::Candidates => "candidates",
            Confidence::UnknownReceiver => "unknown_receiver",
            Confidence::UnknownSelector => "unknown_selector",
        }
    }

    /// Whether the send's targets are edges worth drawing: known-class resolutions and bounded candidate sets.
    pub fn has_edges(self) -> bool {
        matches!(self, Confidence::Resolved | Confidence::Ambiguous | Confidence::Candidates)
    }
}

/// What the send's receiver is known to be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Receiver {
    pub class: String,
    /// The receiver is the class object itself, so class (`+`) methods answer.
    pub class_object: bool,
    /// The receiver is of exactly this class, not possibly a subclass.
    pub exact: bool,
    /// Where the class came from: `self`, `super`, `class_ref`, `alloc` (a `+alloc`/`+new`/`-init…` result) or
    /// `class_of` (`-class` / `objc_opt_class` of a known object).
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Send {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub site: u64,
    /// The function containing the site.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub function: u64,
    /// The runtime entry called: `objc_msgSend`, `objc_msgSendSuper2`, `objc_msgSend$` (a selector stub),
    /// `objc_alloc_init`, and so on.
    pub via: &'static str,
    pub selector: Option<String>,
    pub receiver: Option<Receiver>,
    pub confidence: Confidence,
    /// Implementations the send may reach, the statically looked-up one first.
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub targets: Vec<u64>,
    /// For a receiver of unknown class, how many implementations of the selector the binary has (also when there
    /// are too many to list).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidates: Option<usize>,
}

/// Every resolved send in a program, sorted by site, and the selector stubs found.
#[derive(Debug, Default, Clone)]
pub struct Dispatch {
    pub sends: Vec<Send>,
    /// `__objc_stubs` entries and the selector each sends, sorted by address.
    pub stubs: Vec<(u64, String)>,
    pub warnings: Vec<String>,
}

impl Dispatch {
    /// The send at `site`.
    pub fn send_at(&self, site: u64) -> Option<&Send> {
        self.sends.binary_search_by_key(&site, |send| send.site).ok().map(|index| &self.sends[index])
    }

    /// The sends whose sites lie in `[start, end)`.
    pub fn sends_in(&self, start: u64, end: u64) -> &[Send] {
        let first = self.sends.partition_point(|send| send.site < start);
        let last = self.sends.partition_point(|send| send.site < end);
        &self.sends[first..last]
    }
}

/// A runtime entry point a call can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entry {
    Send,
    SendStret,
    Super,
    SuperStret,
    /// A selector stub, with its selector's symbol.
    Stub(u32),
    Alloc,
    AllocInit,
    New,
    ClassOf,
    /// Returns its first argument (`objc_retain`, `objc_claimAutoreleasedReturnValue`, `objc_opt_self`, ...).
    Keep,
}

impl Entry {
    fn named(name: &str) -> Option<Entry> {
        let name = name.strip_prefix('_').unwrap_or(name);
        Some(match name {
            "objc_msgSend" | "objc_msgSend_fpret" | "objc_msgSend_fp2ret" => Entry::Send,
            "objc_msgSend_stret" => Entry::SendStret,
            "objc_msgSendSuper2" | "objc_msgSendSuper" => Entry::Super,
            "objc_msgSendSuper2_stret" | "objc_msgSendSuper_stret" => Entry::SuperStret,
            "objc_alloc" => Entry::Alloc,
            "objc_alloc_init" => Entry::AllocInit,
            "objc_opt_new" => Entry::New,
            "objc_opt_class" => Entry::ClassOf,
            "objc_opt_self"
            | "objc_retain"
            | "objc_retainAutorelease"
            | "objc_retainAutoreleasedReturnValue"
            | "objc_claimAutoreleasedReturnValue"
            | "objc_unsafeClaimAutoreleasedReturnValue"
            | "objc_retainAutoreleaseReturnValue"
            | "objc_autorelease"
            | "objc_autoreleaseReturnValue" => Entry::Keep,
            _ => return None,
        })
    }

    fn via(self) -> &'static str {
        match self {
            Entry::Send => "objc_msgSend",
            Entry::SendStret => "objc_msgSend_stret",
            Entry::Super => "objc_msgSendSuper2",
            Entry::SuperStret => "objc_msgSendSuper2_stret",
            Entry::Stub(_) => "objc_msgSend$",
            Entry::Alloc => "objc_alloc",
            Entry::AllocInit => "objc_alloc_init",
            Entry::New => "objc_opt_new",
            Entry::ClassOf => "objc_opt_class",
            Entry::Keep => "",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    SelfValue,
    ClassRef,
    Alloc,
    ClassOf,
}

impl Origin {
    fn as_str(self) -> &'static str {
        match self {
            Origin::SelfValue => "self",
            Origin::ClassRef => "class_ref",
            Origin::Alloc => "alloc",
            Origin::ClassOf => "class_of",
        }
    }
}

/// A register's statically evident value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value {
    Unknown,
    Selector(u32),
    /// A class object.
    Class { class: u32, exact: bool, origin: Origin },
    /// An instance.
    Object { class: u32, exact: bool, origin: Origin },
    Entry(Entry),
}

const REGISTERS: usize = 32;
type State = [Value; REGISTERS];

/// Where an architecture passes a send's operands.
struct Abi {
    arch: Arch,
    receiver: usize,
    selector: usize,
    stret_receiver: usize,
    stret_selector: usize,
    result: usize,
    /// Registers a call clobbers.
    clobbered: u64,
    /// The general-purpose registers' bits in a [`rampage_arch::registers::RegisterAccess`].
    general: u64,
}

impl Abi {
    fn of(arch: Arch) -> Option<Abi> {
        match arch {
            Arch::Aarch64 => Some(Abi {
                arch,
                receiver: 0,
                selector: 1,
                stret_receiver: 0,
                stret_selector: 1,
                result: 0,
                clobbered: 0x7_ffff | 1 << 30,
                general: 0x7fff_ffff,
            }),
            // RAX 0, RCX 1, RDX 2, RSI 6, RDI 7, R8 to R11.
            Arch::X86_64 => Some(Abi {
                arch,
                receiver: 7,
                selector: 6,
                stret_receiver: 6,
                stret_selector: 2,
                result: 0,
                clobbered: 0b0000_1111_1100_0111,
                general: 0xffff,
            }),
            _ => None,
        }
    }
}

/// Symbols for selector and class names.
#[derive(Default)]
struct Interner {
    ids: HashMap<String, u32>,
    names: Vec<String>,
}

impl Interner {
    fn id(&mut self, name: &str) -> u32 {
        if let Some(&id) = self.ids.get(name) {
            return id;
        }
        let id = self.names.len() as u32;
        self.names.push(name.to_owned());
        self.ids.insert(name.to_owned(), id);
        id
    }

    fn get(&self, name: &str) -> Option<u32> {
        self.ids.get(name).copied()
    }
}

/// One class's own methods and its categories', instance methods at index 0 and class methods at 1.
#[derive(Default)]
struct ClassInfo {
    local: bool,
    superclass: Option<u32>,
    methods: [HashMap<u32, Vec<u64>>; 2],
    categories: [HashMap<u32, Vec<u64>>; 2],
    subclasses: Vec<u32>,
}

impl ClassInfo {
    /// What this class itself (categories first, as the runtime attaches them in front) answers `selector` with.
    fn own(&self, selector: u32, meta: bool) -> Option<&[u64]> {
        let level = usize::from(meta);
        self.categories[level].get(&selector).or_else(|| self.methods[level].get(&selector)).map(Vec::as_slice)
    }
}

struct Model<'a> {
    binary: &'a Binary,
    abi: Abi,
    symbols: Interner,
    classes: HashMap<u32, ClassInfo>,
    /// Every implementation of each selector, instance and class methods alike.
    implementations: HashMap<u32, Vec<u64>>,
    /// The class (and whether as class methods) each method implementation belongs to, when only one.
    owners: HashMap<u64, Option<(u32, bool)>>,
    selectors: HashMap<u64, u32>,
    class_refs: HashMap<u64, u32>,
    /// `__objc_superrefs` slots, which hold the class itself: the linker shares one with a class reference.
    super_refs: HashMap<u64, u32>,
    class_addresses: HashMap<u64, u32>,
    /// Entries reached by a direct call or jump.
    entries: HashMap<u64, Entry>,
    /// Entries whose address an import slot holds.
    slots: HashMap<u64, Entry>,
    /// Imported classes by slot (`_OBJC_CLASS_$_NSString` bound in the GOT).
    class_slots: HashMap<u64, u32>,
}

/// Resolves the Objective-C sends of `program`'s functions. Images that are not Mach-O, or carry no Objective-C
/// selector references or send entry points, yield nothing, without decoding any code.
pub fn resolve<F>(binary: &Binary, program: &Program, report: &ObjcReport, new_decoder: F) -> Dispatch
where
    F: Fn() -> Option<Box<dyn Disassembler>> + Sync,
{
    let mut dispatch = Dispatch::default();
    if binary.format != Format::MachO {
        return dispatch;
    }
    let Some(abi) = Abi::of(binary.arch) else { return dispatch };
    let refs = rampage_loaders::objc::refs(binary);
    let Some(mut model) = Model::new(binary, abi, report, &refs, &new_decoder) else { return dispatch };
    dispatch.warnings = refs.warnings;
    dispatch.stubs = match new_decoder() {
        Some(mut decoder) => model.selector_stubs(decoder.as_mut()),
        None => Vec::new(),
    };
    let model = &model;
    let mut sends: Vec<Send> = program
        .functions
        .par_iter()
        .map_init(&new_decoder, |decoder, function| match decoder {
            Some(decoder) => model.function(program, function, decoder.as_mut()),
            None => Vec::new(),
        })
        .flatten()
        .collect();
    sends.sort_by_key(|send| (send.site, send.function));
    sends.dedup_by_key(|send| send.site);
    dispatch.sends = sends;
    dispatch
}

/// Names for the arm64 selector stubs in `__objc_stubs`, `_objc_msgSend$<selector>` as the linker's own symbols
/// name them, so a stripped image's stubs read as they do unstripped.
pub fn selector_stub_names(binary: &Binary) -> Vec<(u64, String)> {
    let has_stubs = binary.sections.iter().any(|section| section.name == "__objc_stubs" && section.size > 0);
    if binary.format != Format::MachO || !has_stubs {
        return Vec::new();
    }
    let Some(abi) = Abi::of(binary.arch) else { return Vec::new() };
    let refs = rampage_loaders::objc::refs(binary);
    let new_decoder = || binary.decoder().ok();
    let Some(mut model) = Model::new(binary, abi, &ObjcReport::default(), &refs, &new_decoder) else {
        return Vec::new();
    };
    let Some(mut decoder) = new_decoder() else { return Vec::new() };
    let stubs = model.selector_stubs(decoder.as_mut());
    stubs.into_iter().map(|(address, selector)| (address, format!("_objc_msgSend${selector}"))).collect()
}

impl<'a> Model<'a> {
    fn new<F>(
        binary: &'a Binary,
        abi: Abi,
        report: &ObjcReport,
        refs: &ObjcRefs,
        new_decoder: &F,
    ) -> Option<Model<'a>>
    where
        F: Fn() -> Option<Box<dyn Disassembler>>,
    {
        let mut symbols = Interner::default();
        let mut entries = HashMap::new();
        let stubs = match new_decoder() {
            Some(_) => crate::functions::stub_names(binary),
            None => return None,
        };
        for (address, name) in &stubs {
            if let Some(entry) = Entry::named(name) {
                entries.insert(*address, entry);
            }
        }
        let mut slots = HashMap::new();
        let mut class_slots = HashMap::new();
        for slot in &binary.import_slots {
            if let Some(entry) = Entry::named(&slot.name) {
                slots.insert(slot.address, entry);
            }
            let name = slot.name.strip_prefix('_').unwrap_or(&slot.name);
            if let Some(class) = name.strip_prefix("OBJC_CLASS_$_") {
                class_slots.insert(slot.address, symbols.id(class));
            }
        }
        let has_stubs = binary.sections.iter().any(|section| section.name == "__objc_stubs" && section.size > 0);
        if refs.selectors.is_empty() || (entries.is_empty() && slots.is_empty() && !has_stubs) {
            return None;
        }
        let selectors = refs.selectors.iter().map(|(&slot, name)| (slot, symbols.id(name))).collect();
        let class_refs = refs.classes.iter().map(|(&slot, name)| (slot, symbols.id(name))).collect();
        let super_refs = refs.supers.iter().map(|(&slot, name)| (slot, symbols.id(name))).collect();
        let class_addresses = refs.class_addresses.iter().map(|(&at, name)| (at, symbols.id(name))).collect();
        let mut classes: HashMap<u32, ClassInfo> = HashMap::new();
        let mut implementations: HashMap<u32, Vec<u64>> = HashMap::new();
        let mut owners: HashMap<u64, Option<(u32, bool)>> = HashMap::new();
        let mut add = |symbols: &mut Interner,
                       classes: &mut HashMap<u32, ClassInfo>,
                       class: u32,
                       method: &rampage_loaders::objc::ObjcMethod,
                       category: bool| {
            let Some(implementation) = method.implementation else { return };
            let selector = symbols.id(&method.selector);
            let info = classes.entry(class).or_default();
            let level = usize::from(method.class_method);
            let table = if category { &mut info.categories[level] } else { &mut info.methods[level] };
            table.entry(selector).or_default().push(implementation);
            let all = implementations.entry(selector).or_default();
            if !all.contains(&implementation) {
                all.push(implementation);
            }
            // One implementation shared by methods of different classes (identical code folded) has no one owner.
            let owner = (class, method.class_method);
            owners
                .entry(implementation)
                .and_modify(|existing| *existing = existing.filter(|existing| *existing == owner))
                .or_insert(Some(owner));
        };
        for class in &report.classes {
            let id = symbols.id(&class.name);
            let superclass = class.superclass.as_deref().map(|name| symbols.id(name));
            let info = classes.entry(id).or_default();
            info.local = true;
            info.superclass = superclass;
            for method in &class.methods {
                add(&mut symbols, &mut classes, id, method, false);
            }
        }
        for category in &report.categories {
            let Some(class) = category.class.as_deref() else { continue };
            let id = symbols.id(class);
            for method in &category.methods {
                add(&mut symbols, &mut classes, id, method, true);
            }
        }
        let links: Vec<(u32, u32)> =
            classes.iter().filter_map(|(&class, info)| Some((info.superclass?, class))).collect();
        for (superclass, class) in links {
            if let Some(info) = classes.get_mut(&superclass) {
                info.subclasses.push(class);
            }
        }
        for info in classes.values_mut() {
            info.subclasses.sort_unstable();
        }
        for list in implementations.values_mut() {
            list.sort_unstable();
        }
        Some(Model {
            binary,
            abi,
            symbols,
            classes,
            implementations,
            owners,
            selectors,
            class_refs,
            super_refs,
            class_addresses,
            entries,
            slots,
            class_slots,
        })
    }

    /// Finds the selector stubs in `__objc_stubs` (each loads its selector and jumps to `objc_msgSend`) and adds
    /// them as entries.
    fn selector_stubs(&mut self, decoder: &mut dyn Disassembler) -> Vec<(u64, String)> {
        let mut found = Vec::new();
        let sections: Vec<(u64, u64)> = self
            .binary
            .sections
            .iter()
            .filter(|section| section.name == "__objc_stubs")
            .map(|section| (section.address, section.address.saturating_add(section.size)))
            .collect();
        for (start, end) in sections {
            let mut state = [Value::Unknown; REGISTERS];
            let mut stub: Option<u64> = None;
            let mut address = start;
            decoder.reset();
            while address < end {
                let Some(code) = self.binary.code_from(address) else { break };
                let code = &code[..code.len().min((end - address) as usize)];
                let insn = decoder.decode(code, address);
                let bytes = &code[..usize::from(insn.len).min(code.len())];
                let next = address + u64::from(insn.len.max(1));
                if matches!(insn.flow, Flow::Halt | Flow::Invalid) {
                    stub = None;
                    address = next;
                    decoder.reset();
                    continue;
                }
                let first = *stub.get_or_insert(address);
                if matches!(insn.flow, Flow::Jump(_) | Flow::IndirectJump | Flow::Return) {
                    if let Some(Entry::Send) = self.callee(&insn, bytes, &state)
                        && let Value::Selector(selector) = state[self.abi.selector]
                    {
                        found.push((first, selector));
                    }
                    state = [Value::Unknown; REGISTERS];
                    stub = None;
                    decoder.reset();
                } else {
                    self.step(&insn, bytes, &mut state, &mut X86Registers::default());
                }
                address = next;
            }
        }
        for &(address, selector) in &found {
            self.entries.insert(address, Entry::Stub(selector));
        }
        found.into_iter().map(|(address, selector)| (address, self.symbols.names[selector as usize].clone())).collect()
    }

    /// The entry a call or jump instruction reaches, if it is one: a direct target, an import slot it branches
    /// through, or a register holding an entry's address.
    fn callee(&self, insn: &rampage_arch::Insn, bytes: &[u8], state: &State) -> Option<Entry> {
        match insn.flow {
            Flow::Call(target) | Flow::Jump(target) => self.entries.get(&target).copied(),
            Flow::IndirectCall | Flow::IndirectJump => {
                if let Some(slot) = insn.data_ref.filter(|_| insn.accesses) {
                    return self.slots.get(&slot).copied();
                }
                match state[branch_register(self.abi.arch, bytes)?] {
                    Value::Entry(entry) => Some(entry),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Applies one non-branching instruction's effect on the tracked registers.
    fn step(&self, insn: &rampage_arch::Insn, bytes: &[u8], state: &mut State, x86: &mut X86Registers) {
        if let Some((destination, source)) = register_move(self.abi.arch, bytes) {
            state[destination] = state[source];
            return;
        }
        let written = match self.abi.arch {
            Arch::Aarch64 => {
                bytes.get(..4).and_then(|word| a64_access(u32::from_le_bytes(word.try_into().unwrap()))).map(|a| a.writes)
            }
            _ => x86.access(bytes, insn.address).map(|(_, access)| access.writes),
        };
        let Some(written) = written else {
            *state = [Value::Unknown; REGISTERS];
            return;
        };
        let written = written & self.abi.general;
        let value = match insn.data_ref {
            Some(at) if insn.accesses => self.loaded(at),
            Some(at) => self.class_addresses.get(&at).map_or(Value::Unknown, |&class| Value::Class {
                class,
                exact: true,
                origin: Origin::ClassRef,
            }),
            None => Value::Unknown,
        };
        for register in 0..REGISTERS {
            if written & (1 << register) != 0 {
                state[register] = if written.count_ones() == 1 { value } else { Value::Unknown };
            }
        }
    }

    /// What a load from `at` yields.
    fn loaded(&self, at: u64) -> Value {
        if let Some(&selector) = self.selectors.get(&at) {
            return Value::Selector(selector);
        }
        if let Some(&class) =
            self.class_refs.get(&at).or_else(|| self.super_refs.get(&at)).or_else(|| self.class_slots.get(&at))
        {
            return Value::Class { class, exact: true, origin: Origin::ClassRef };
        }
        if let Some(&entry) = self.slots.get(&at) {
            return Value::Entry(entry);
        }
        // A GOT entry the linker made for a local class holds the class's address.
        let target = self.binary.rebase_target(at).or_else(|| {
            let size = self.binary.arch.default_pointer_size()?;
            (!self.binary.has_chained_fixups()).then(|| self.binary.read_pointer(at, size)).flatten()
        });
        match target.and_then(|target| self.class_addresses.get(&target)) {
            Some(&class) => Value::Class { class, exact: true, origin: Origin::ClassRef },
            None => Value::Unknown,
        }
    }

    /// The value `self` has on entry to the method at `function`, if it is one of exactly one class.
    fn entry_self(&self, function: u64) -> Value {
        match self.owners.get(&function) {
            Some(Some((class, true))) => Value::Class { class: *class, exact: false, origin: Origin::SelfValue },
            Some(Some((class, false))) => Value::Object { class: *class, exact: false, origin: Origin::SelfValue },
            _ => Value::Unknown,
        }
    }

    fn function(&self, program: &Program, function: &DiscoveredFunction, decoder: &mut dyn Disassembler) -> Vec<Send> {
        // A stub's jump to the runtime is not a send of its own; its callers' sends are.
        if self.entries.contains_key(&function.address) {
            return Vec::new();
        }
        let blocks = &function.blocks;
        let index: HashMap<u64, usize> = blocks.iter().enumerate().map(|(index, block)| (block.start, index)).collect();
        let Some(&entry) = index.get(&function.address) else { return Vec::new() };
        let mut inputs: Vec<Option<State>> = vec![None; blocks.len()];
        let mut start = [Value::Unknown; REGISTERS];
        start[self.abi.receiver] = self.entry_self(function.address);
        inputs[entry] = Some(start);
        let mut x86 = X86Registers::default();
        let mut any = false;
        for _ in 0..MAX_PASSES {
            let mut changed = false;
            for (position, block) in blocks.iter().enumerate() {
                let Some(mut state) = inputs[position] else { continue };
                let run = Run { program, function, start: block.start, end: block.end };
                let Some(successors) = self.block(&run, &mut state, decoder, &mut x86, None, &mut any) else {
                    continue;
                };
                for successor in successors.into_iter().filter_map(|at| index.get(&at).copied()) {
                    let merged = match inputs[successor] {
                        None => state,
                        Some(previous) => join(&previous, &state),
                    };
                    if inputs[successor] != Some(merged) {
                        inputs[successor] = Some(merged);
                        changed = true;
                    }
                }
            }
            if !any {
                return Vec::new();
            }
            if !changed {
                break;
            }
        }
        // One more pass from the settled inputs records the sends.
        let mut sends = Vec::new();
        for (position, block) in blocks.iter().enumerate() {
            let Some(mut state) = inputs[position] else { continue };
            let run = Run { program, function, start: block.start, end: block.end };
            self.block(&run, &mut state, decoder, &mut x86, Some(&mut sends), &mut any);
        }
        sends
    }

    /// Runs one block from `state`, recording its sends when asked, and returns the block's successors.
    fn block(
        &self,
        run: &Run,
        state: &mut State,
        decoder: &mut dyn Disassembler,
        x86: &mut X86Registers,
        mut record: Option<&mut Vec<Send>>,
        any: &mut bool,
    ) -> Option<Vec<u64>> {
        let Run { program, function, start, end } = *run;
        let code = self.binary.code_from(start)?;
        let code = &code[..code.len().min(end.saturating_sub(start) as usize)];
        decoder.reset();
        let mut offset = 0;
        let mut last = None;
        while offset < code.len() {
            let address = start + offset as u64;
            let insn = decoder.decode(&code[offset..], address);
            let bytes = &code[offset..(offset + usize::from(insn.len)).min(code.len())];
            offset += usize::from(insn.len.max(1));
            last = Some((insn.address, insn.len, insn.flow, insn.conditional));
            match insn.flow {
                Flow::Call(_) | Flow::IndirectCall | Flow::Jump(_) | Flow::IndirectJump => {
                    let jump = matches!(insn.flow, Flow::Jump(_) | Flow::IndirectJump);
                    let entry = self.callee(&insn, bytes, state);
                    if jump && entry.is_none() {
                        continue;
                    }
                    let result = match entry {
                        Some(entry) => {
                            *any = true;
                            let (send, result) = self.send(function.address, address, entry, state);
                            if let (Some(send), Some(sends)) = (send, record.as_deref_mut()) {
                                sends.push(send);
                            }
                            result
                        }
                        None => Value::Unknown,
                    };
                    for register in 0..REGISTERS {
                        if self.abi.clobbered & (1 << register) != 0 {
                            state[register] = Value::Unknown;
                        }
                    }
                    state[self.abi.result] = result;
                }
                Flow::Invalid => return None,
                _ => self.step(&insn, bytes, state, x86),
            }
        }
        let (address, len, flow, conditional) = last?;
        let next = address + u64::from(len.max(1));
        let mut successors = Vec::new();
        match flow {
            Flow::Jump(target) => successors.push(target),
            Flow::ConditionalJump(target) => successors.extend([target, next]),
            Flow::IndirectJump => successors.extend(function.switch_cases(address).unwrap_or_default()),
            Flow::Return | Flow::Halt | Flow::Invalid => {}
            Flow::Call(_) | Flow::IndirectCall if program.is_noreturn_call(address) => {}
            Flow::Next | Flow::Call(_) | Flow::IndirectCall => successors.push(next),
        }
        if conditional {
            successors.push(next);
        }
        Some(successors)
    }

    /// The send `entry` makes from `site` with the registers in `state`, and the value it returns.
    fn send(&self, function: u64, site: u64, entry: Entry, state: &State) -> (Option<Send>, Value) {
        let abi = &self.abi;
        let receiver = state[abi.receiver];
        let selector_value = |register: usize| match state[register] {
            Value::Selector(selector) => Some(selector),
            _ => None,
        };
        let named = |name: &str| self.symbols.get(name);
        let (selector, receiver, result) = match entry {
            Entry::Keep => return (None, receiver),
            Entry::ClassOf => {
                return (None, match receiver {
                    Value::Object { class, exact, .. } => Value::Class { class, exact, origin: Origin::ClassOf },
                    _ => Value::Unknown,
                });
            }
            Entry::Send | Entry::Stub(_) => {
                let selector = match entry {
                    Entry::Stub(selector) => Some(selector),
                    _ => selector_value(abi.selector),
                };
                (selector, receiver, self.result(selector, receiver))
            }
            Entry::SendStret => (selector_value(abi.stret_selector), state[abi.stret_receiver], Value::Unknown),
            Entry::Super | Entry::SuperStret => {
                let register = if entry == Entry::Super { abi.selector } else { abi.stret_selector };
                let selector = selector_value(register);
                let receiver = match self.owners.get(&function) {
                    Some(Some((class, meta))) => match self.classes.get(class).and_then(|info| info.superclass) {
                        Some(superclass) => {
                            let origin = Origin::SelfValue;
                            if *meta {
                                Value::Class { class: superclass, exact: true, origin }
                            } else {
                                Value::Object { class: superclass, exact: true, origin }
                            }
                        }
                        None => Value::Unknown,
                    },
                    _ => Value::Unknown,
                };
                // `[super init…]` returns self, which is still of the method's own (static) class.
                let result = match (selector.map(|s| self.symbols.names[s as usize].as_str()), self.entry_self(function))
                {
                    (Some(name), own @ Value::Object { .. }) if name.starts_with("init") => own,
                    _ => Value::Unknown,
                };
                let mut send = self.resolved(function, site, entry, selector, receiver);
                if let Some(receiver) = send.receiver.as_mut() {
                    receiver.source = "super";
                }
                return (Some(send), result);
            }
            Entry::Alloc => (named("alloc"), receiver, as_object(receiver)),
            Entry::New => (named("new"), receiver, as_object(receiver)),
            Entry::AllocInit => {
                let object = as_object(receiver);
                (named("init"), object, object)
            }
        };
        let mut send = self.resolved(function, site, entry, selector, receiver);
        if send.selector.is_none() {
            // A fast path's selector may not be one the binary names; it is still that selector.
            send.selector = match entry {
                Entry::Alloc => Some("alloc".to_owned()),
                Entry::New => Some("new".to_owned()),
                Entry::AllocInit => Some("init".to_owned()),
                _ => None,
            };
            if send.selector.is_some() {
                send.confidence = match send.receiver {
                    Some(_) => Confidence::Framework,
                    None => Confidence::UnknownReceiver,
                };
            }
        }
        (Some(send), result)
    }

    /// What a send of `selector` to `receiver` returns, where that is evident: `+alloc`/`+new` make an instance of
    /// the class, `-init…` returns the receiver, `-class` its class and `-self`/`-retain`/`-autorelease` itself.
    fn result(&self, selector: Option<u32>, receiver: Value) -> Value {
        let Some(name) = selector.map(|selector| self.symbols.names[selector as usize].as_str()) else {
            return Value::Unknown;
        };
        match (name, receiver) {
            ("alloc" | "new" | "allocWithZone:", Value::Class { .. }) => as_object(receiver),
            (_, Value::Object { .. }) if name.starts_with("init") => receiver,
            ("class", Value::Object { class, exact, .. }) => Value::Class { class, exact, origin: Origin::ClassOf },
            ("self" | "retain" | "autorelease", Value::Object { .. } | Value::Class { .. }) => receiver,
            _ => Value::Unknown,
        }
    }

    fn resolved(&self, function: u64, site: u64, entry: Entry, selector: Option<u32>, receiver: Value) -> Send {
        let via = entry.via();
        let mut send = Send {
            site,
            function,
            via,
            selector: selector.map(|selector| self.symbols.names[selector as usize].clone()),
            receiver: None,
            confidence: Confidence::UnknownSelector,
            targets: Vec::new(),
            candidates: None,
        };
        let known = match receiver {
            Value::Class { class, exact, origin } => Some((class, true, exact, origin)),
            Value::Object { class, exact, origin } => Some((class, false, exact, origin)),
            _ => None,
        };
        if let Some((class, class_object, exact, origin)) = known {
            send.receiver = Some(Receiver {
                class: self.symbols.names[class as usize].clone(),
                class_object,
                exact,
                source: origin.as_str(),
            });
        }
        let Some(selector) = selector else { return send };
        let Some((class, meta, exact, _)) = known else {
            let all = self.implementations.get(&selector).map_or(&[][..], Vec::as_slice);
            send.candidates = Some(all.len());
            if all.is_empty() {
                send.confidence = Confidence::UnknownReceiver;
            } else {
                send.confidence = Confidence::Candidates;
                if all.len() <= MAX_CANDIDATES {
                    send.targets = all.to_vec();
                }
            }
            return send;
        };
        let (found, _) = self.lookup(class, selector, meta);
        let mut targets: Vec<u64> = found.to_vec();
        if !exact {
            for implementation in self.overrides(class, selector, meta) {
                if !targets.contains(&implementation) {
                    targets.push(implementation);
                }
            }
        }
        send.confidence = match (found.len(), targets.len()) {
            (_, 0) => Confidence::Framework,
            (1, 1) => Confidence::Resolved,
            _ => Confidence::Ambiguous,
        };
        send.targets = targets;
        send
    }

    /// The implementations a class's lookup of `selector` finds in the binary, walking up its superclasses, and the
    /// first class outside the binary the walk reached without finding one.
    fn lookup(&self, class: u32, selector: u32, meta: bool) -> (&[u64], Option<u32>) {
        let mut current = class;
        let mut visited = HashSet::new();
        while visited.insert(current) && visited.len() <= MAX_SUPERCLASS_DEPTH {
            let Some(info) = self.classes.get(&current) else { return (&[], Some(current)) };
            if let Some(found) = info.own(selector, meta) {
                return (found, None);
            }
            if !info.local {
                return (&[], Some(current));
            }
            match info.superclass {
                Some(superclass) => current = superclass,
                None => return (&[], None),
            }
        }
        (&[], None)
    }

    /// Implementations of `selector` in local subclasses of `class`, at any depth.
    fn overrides(&self, class: u32, selector: u32, meta: bool) -> BTreeSet<u64> {
        let mut found = BTreeSet::new();
        let mut visited = HashSet::from([class]);
        let mut queue = vec![class];
        while let Some(current) = queue.pop() {
            let Some(info) = self.classes.get(&current) else { continue };
            for &subclass in &info.subclasses {
                if !visited.insert(subclass) {
                    continue;
                }
                if let Some(own) = self.classes.get(&subclass).and_then(|info| info.own(selector, meta)) {
                    found.extend(own);
                }
                queue.push(subclass);
            }
        }
        found
    }
}

/// One block of a function to run.
#[derive(Clone, Copy)]
struct Run<'p> {
    program: &'p Program,
    function: &'p DiscoveredFunction,
    start: u64,
    end: u64,
}

/// An instance of the class `value` is, as `+alloc` makes it.
fn as_object(value: Value) -> Value {
    match value {
        Value::Class { class, exact, .. } => Value::Object { class, exact, origin: Origin::Alloc },
        _ => Value::Unknown,
    }
}

/// Where control flow joins, a register keeps a value only if every path agrees on it.
fn join(left: &State, right: &State) -> State {
    let mut joined = *left;
    for (register, value) in joined.iter_mut().enumerate() {
        if *value != right[register] {
            *value = Value::Unknown;
        }
    }
    joined
}

/// The destination and source of a whole-register move (`mov x19, x0`; `mov rbx, rdi`).
fn register_move(arch: Arch, bytes: &[u8]) -> Option<(usize, usize)> {
    match arch {
        Arch::Aarch64 => {
            let word = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
            // ORR Xd, XZR, Xm (the MOV alias); the zero register reads as zero, not tracked.
            (word & 0xffe0_ffe0 == 0xaa00_03e0 && (word >> 16) & 31 != 31 && word & 31 != 31)
                .then(|| ((word & 31) as usize, ((word >> 16) & 31) as usize))
        }
        Arch::X86_64 => {
            let [rex, opcode, modrm] = bytes else { return None };
            if rex & 0xf8 != 0x48 || modrm >> 6 != 3 {
                return None;
            }
            let reg = usize::from((modrm >> 3) & 7) | usize::from(rex & 4) << 1;
            let rm = usize::from(modrm & 7) | usize::from(rex & 1) << 3;
            match opcode {
                0x89 => Some((rm, reg)),
                0x8b => Some((reg, rm)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The register a register-indirect call or jump branches through (`blr x8`, `call r14`).
fn branch_register(arch: Arch, bytes: &[u8]) -> Option<usize> {
    match arch {
        Arch::Aarch64 => {
            let word = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
            Some(((word >> 5) & 31) as usize)
        }
        Arch::X86_64 => {
            let (rex, rest) = match bytes {
                [rex @ 0x40..=0x4f, rest @ ..] => (*rex, rest),
                rest => (0, rest),
            };
            let [0xff, modrm] = rest else { return None };
            (modrm >> 6 == 3 && matches!((modrm >> 3) & 7, 2 | 4))
                .then(|| usize::from(modrm & 7) | usize::from(rex & 1) << 3)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_moves_and_branch_registers_decode() {
        // mov x19, x0
        assert_eq!(register_move(Arch::Aarch64, &0xaa00_03f3u32.to_le_bytes()), Some((19, 0)));
        // mov x0, xzr is a zeroing, not a copy
        assert_eq!(register_move(Arch::Aarch64, &0xaa1f_03e0u32.to_le_bytes()), None);
        // mov rbx, rdi (48 89 fb); mov rdi, r15 (4c 89 ff); mov r12, rax (49 89 c4)
        assert_eq!(register_move(Arch::X86_64, &[0x48, 0x89, 0xfb]), Some((3, 7)));
        assert_eq!(register_move(Arch::X86_64, &[0x4c, 0x89, 0xff]), Some((7, 15)));
        assert_eq!(register_move(Arch::X86_64, &[0x49, 0x89, 0xc4]), Some((12, 0)));
        // blr x8
        assert_eq!(branch_register(Arch::Aarch64, &0xd63f_0100u32.to_le_bytes()), Some(8));
        // call r14 (41 ff d6); call rbx (ff d3); call [rax] is memory
        assert_eq!(branch_register(Arch::X86_64, &[0x41, 0xff, 0xd6]), Some(14));
        assert_eq!(branch_register(Arch::X86_64, &[0xff, 0xd3]), Some(3));
        assert_eq!(branch_register(Arch::X86_64, &[0xff, 0x10]), None);
    }
}
