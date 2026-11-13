//! Recovers Objective-C classes, categories and their methods from a Mach-O image's runtime metadata
//! (`__objc_classlist`, `__objc_catlist`), so a stripped binary's method implementations gain the
//! `-[Class selector]` names the compiler gave them, the way IDA and Ghidra name them.
//!
//! The metadata is untrusted input: every structure is read through the image's mapped bytes, every count and
//! entry size is checked against what the image holds, the total work is capped, and superclass chains are walked
//! with a visited set. Anything inconsistent is skipped with a warning; nothing here panics or fails a load.
//!
//! Pointers are resolved the way the dynamic loader would: a chained-fixup rebase (including an arm64e
//! authenticated one, whose signing bits are dropped) yields its target, a bind yields the imported symbol, and
//! an image without chained fixups stores plain addresses.

use std::collections::{HashMap, HashSet};

use rampage_arch::bytes::read_uint;
use serde::Serialize;

use crate::model::{Symbol, SymbolKind};
use crate::warnings::CappedWarnings;
use crate::{Binary, Format};

const WARNINGS: CappedWarnings = CappedWarnings::new(256, "Objective-C");
const MAX_CLASSES: u64 = 1 << 16;
const MAX_LIST_ENTRIES: u64 = 1 << 16;
/// Entries read across every list, so a crafted image of many large lists stays bounded.
const MAX_ENTRIES: u64 = 1 << 20;
const MAX_NAME_BYTES: usize = 4096;
const MAX_SUPERCLASS_DEPTH: usize = 64;
/// `method_list_t` flag: entries are 32-bit offsets relative to each field (small methods).
const RELATIVE_METHODS: u32 = 0x8000_0000;
/// `method_list_t` flag: a small method's name offset reaches the selector string rather than a selector ref.
const DIRECT_SELECTORS: u32 = 0x4000_0000;
const ENTRY_SIZE_MASK: u32 = 0xfffc;
const CLASS_PREFIXES: [&str; 2] = ["_OBJC_CLASS_$_", "OBJC_CLASS_$_"];

#[derive(Debug, Default, Serialize)]
pub struct ObjcReport {
    pub classes: Vec<ObjcClass>,
    pub categories: Vec<ObjcCategory>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ObjcClass {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
    /// The direct superclass: a class in this image, or an imported one (`NSObject`). `None` for a root class.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superclass: Option<String>,
    /// The superclass chain from the direct superclass up, ending at the first imported or root class.
    pub superclasses: Vec<String>,
    /// `class_ro_t` flags (`RO_ROOT` 0x2, `RO_HAS_CXX_STRUCTORS` 0x4, ...).
    pub flags: u32,
    pub instance_size: u32,
    /// Instance methods, then the metaclass's methods as class methods.
    pub methods: Vec<ObjcMethod>,
    pub ivars: Vec<ObjcIvar>,
    pub properties: Vec<ObjcProperty>,
    pub protocols: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ObjcCategory {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
    /// The class the category extends; `None` when its pointer cannot be resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    pub methods: Vec<ObjcMethod>,
    pub properties: Vec<ObjcProperty>,
    pub protocols: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ObjcMethod {
    /// The method as the compiler names its implementation: `-[Class selector]`, `+[Class(Category) selector]`.
    pub name: String,
    pub selector: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub types: Option<String>,
    /// The implementation's address, when it lies in code.
    #[serde(serialize_with = "rampage_arch::hex::optional_address", skip_serializing_if = "Option::is_none")]
    pub implementation: Option<u64>,
    pub class_method: bool,
}

#[derive(Debug, Serialize)]
pub struct ObjcIvar {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_encoding: Option<String>,
    /// The ivar's byte offset in an instance, read from its offset variable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    pub size: u32,
}

#[derive(Debug, Serialize)]
pub struct ObjcProperty {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<String>,
}

/// What a pointer-sized field holds once loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pointer<'a> {
    Null,
    Local(u64),
    Import(&'a str),
}

fn objc_pointer_size(width: Option<u8>, report: &mut ObjcReport) -> Option<u8> {
    match width.filter(|width| matches!(width, 4 | 8)) {
        Some(width) => Some(width),
        None => {
            WARNINGS.push(
                &mut report.warnings,
                "Objective-C metadata not inspected: native pointer width is unavailable or unsupported".to_owned(),
            );
            None
        }
    }
}

/// Parses the image's Objective-C metadata. Images without it (or that are not Mach-O) yield an empty report.
pub fn parse(binary: &Binary) -> ObjcReport {
    let mut report = ObjcReport::default();
    if binary.format != Format::MachO {
        return report;
    }
    let Some(size) = objc_pointer_size(binary.arch.default_pointer_size(), &mut report) else {
        return report;
    };
    let mut parser = Parser { binary, size: u64::from(size), budget: MAX_ENTRIES, names: HashMap::new(), report };
    let mut seen = HashSet::new();
    for class in parser.list_section("__objc_classlist") {
        if seen.insert(class)
            && let Some(class) = parser.class(class)
        {
            parser.report.classes.push(class);
        }
    }
    let mut seen = HashSet::new();
    for category in parser.list_section("__objc_catlist") {
        if seen.insert(category)
            && let Some(category) = parser.category(category)
        {
            parser.report.categories.push(category);
        }
    }
    parser.report
}

/// The reference slots code loads a message send's operands from: `__objc_selrefs` (selector strings),
/// `__objc_classrefs` (classes, local or imported) and `__objc_superrefs` (the class whose superclass a `super`
/// send starts at), keyed by slot address. Classes are named as [`ObjcClass::name`] names them, without the
/// `_OBJC_CLASS_$_` prefix of an imported class.
#[derive(Debug, Default)]
pub struct ObjcRefs {
    pub selectors: HashMap<u64, String>,
    pub classes: HashMap<u64, String>,
    pub supers: HashMap<u64, String>,
    /// Local class structures by address, for code that forms a class's address directly (`lea`, `adrp`+`add`).
    pub class_addresses: HashMap<u64, String>,
    pub warnings: Vec<String>,
}

/// Reads the image's selector, class and super reference slots. Images without them yield empty tables.
pub fn refs(binary: &Binary) -> ObjcRefs {
    let mut refs = ObjcRefs::default();
    if binary.format != Format::MachO {
        return refs;
    }
    let mut report = ObjcReport::default();
    let Some(size) = objc_pointer_size(binary.arch.default_pointer_size(), &mut report) else {
        refs.warnings = report.warnings;
        return refs;
    };
    let mut parser = Parser { binary, size: u64::from(size), budget: MAX_ENTRIES, names: HashMap::new(), report };
    for (at, target) in parser.slots("__objc_selrefs") {
        if let Pointer::Local(string) = target
            && let Some(selector) = parser.string(string)
        {
            refs.selectors.insert(at, selector);
        }
    }
    for (at, target) in parser.slots("__objc_classrefs") {
        if let Some(name) = parser.link_name(target) {
            if let Pointer::Local(class) = target {
                refs.class_addresses.insert(class, name.clone());
            }
            refs.classes.insert(at, name);
        }
    }
    for (at, target) in parser.slots("__objc_superrefs") {
        if let Some(name) = parser.link_name(target) {
            refs.supers.insert(at, name);
        }
    }
    for class in parser.list_section("__objc_classlist") {
        if let Some(name) = parser.class_name(class) {
            refs.class_addresses.insert(class, name);
        }
    }
    refs.warnings = parser.report.warnings;
    refs
}

impl Binary {
    /// Names unnamed Objective-C method implementations `-[Class selector]` from the image's class and category
    /// metadata, attaching them as `SymbolKind::Function` symbols. Like [`Binary::recover_go_symbols`] this is
    /// additive: an address that already has a symbol keeps it, so real symbols always win.
    pub fn recover_objc_symbols(&mut self) -> ObjcReport {
        #[cfg(test)]
        crate::load::note_optional_recovery_entry();
        let report = parse(self);
        let mut taken: HashSet<u64> = self.symbols.iter().map(|symbol| symbol.address).collect();
        let methods = report.classes.iter().flat_map(|class| &class.methods);
        let methods = methods.chain(report.categories.iter().flat_map(|category| &category.methods));
        let mut added = false;
        for method in methods {
            let Some(address) = method.implementation else { continue };
            if taken.insert(address) {
                self.symbols.push(Symbol { name: method.name.clone(), address, size: 0, kind: SymbolKind::Function });
                added = true;
            }
        }
        if added {
            self.symbols.sort_by(|a, b| (a.address, &a.name).cmp(&(b.address, &b.name)));
        }
        report
    }
}

struct Parser<'a> {
    binary: &'a Binary,
    size: u64,
    budget: u64,
    /// Class names by class address, so superclass and category lookups read each class once.
    names: HashMap<u64, Option<String>>,
    report: ObjcReport,
}

impl<'a> Parser<'a> {
    fn warn(&mut self, warning: String) {
        WARNINGS.push(&mut self.report.warnings, warning);
    }

    /// The local structures a pointer list section (`__objc_classlist`, `__objc_catlist`) points at.
    fn list_section(&mut self, name: &str) -> Vec<u64> {
        let sections: Vec<_> = self.binary.sections.iter().filter(|section| section.name == name).collect();
        let mut targets = Vec::new();
        for section in sections {
            if section.address % self.size != 0 || section.size % self.size != 0 {
                self.warn(format!("{name} at {:#x} is not a whole number of aligned pointers", section.address));
            }
            let count = section.size / self.size;
            if count > MAX_CLASSES {
                self.warn(format!("{name} lists {count} entries; reading the first {MAX_CLASSES}"));
            }
            let Some(start) = section.address.checked_next_multiple_of(self.size) else {
                self.warn(format!("{name} at {:#x} ends past the address space", section.address));
                continue;
            };
            for index in 0..count.min(MAX_CLASSES) {
                let Some(at) = index.checked_mul(self.size).and_then(|offset| start.checked_add(offset)) else { break };
                match self.pointer(at) {
                    Some(Pointer::Local(target)) => targets.push(target),
                    Some(Pointer::Null) => {}
                    _ => self.warn(format!("{name} entry at {at:#x} does not point into the image")),
                }
            }
        }
        targets
    }

    /// Every pointer slot of the reference sections named `name`, with what each holds once loaded.
    fn slots(&mut self, name: &str) -> Vec<(u64, Pointer<'a>)> {
        let sections: Vec<_> = self.binary.sections.iter().filter(|section| section.name == name).collect();
        let mut slots = Vec::new();
        for section in sections {
            let count = (section.size / self.size).min(MAX_LIST_ENTRIES * 4);
            let Some(start) = section.address.checked_next_multiple_of(self.size) else {
                self.warn(format!("{name} at {:#x} ends past the address space", section.address));
                continue;
            };
            for index in 0..count {
                let Some(at) = index.checked_mul(self.size).and_then(|offset| start.checked_add(offset)) else { break };
                if let Some(target) = self.pointer(at) {
                    slots.push((at, target));
                }
            }
        }
        slots
    }

    fn class(&mut self, address: u64) -> Option<ObjcClass> {
        let ro = self.class_ro(address)?;
        let flags = self.u32(ro)?;
        let instance_size = self.u32(ro.wrapping_add(8))?;
        let name = self.class_name(address)?;
        let fields = ro.wrapping_add(self.ro_fields());
        let mut methods = self.methods(self.field(fields, 2), &name, false);
        match self.pointer(address) {
            Some(Pointer::Local(meta)) => match self.class_ro(meta) {
                Some(meta_ro) => {
                    let at = self.field(meta_ro.wrapping_add(self.ro_fields()), 2);
                    methods.extend(self.methods(at, &name, true));
                }
                None => self.warn(format!("class {name}'s metaclass at {meta:#x} is unreadable")),
            },
            Some(_) => {}
            None => self.warn(format!("class {name}'s isa at {address:#x} is unreadable")),
        }
        let protocols = self.protocols(self.field(fields, 3));
        let ivars = self.ivars(self.field(fields, 4), &name);
        let properties = self.properties(self.field(fields, 6));
        let superclass_link = self.pointer(self.field(address, 1));
        let superclass = superclass_link.and_then(|link| self.link_name(link));
        let superclasses = self.superclasses(address, &name);
        Some(ObjcClass {
            address,
            name,
            superclass,
            superclasses,
            flags,
            instance_size,
            methods,
            ivars,
            properties,
            protocols,
        })
    }

    fn category(&mut self, address: u64) -> Option<ObjcCategory> {
        let Some(name) = self.string_at_pointer(address) else {
            self.warn(format!("category at {address:#x} has no readable name"));
            return None;
        };
        let class = self.pointer(self.field(address, 1)).and_then(|link| self.link_name(link));
        if class.is_none() {
            self.warn(format!("category {name} at {address:#x} names no resolvable class"));
        }
        let owner = format!("{}({name})", class.as_deref().unwrap_or("?"));
        let mut methods = self.methods(self.field(address, 2), &owner, false);
        methods.extend(self.methods(self.field(address, 3), &owner, true));
        let protocols = self.protocols(self.field(address, 4));
        let properties = self.properties(self.field(address, 5));
        Some(ObjcCategory { address, name, class, methods, properties, protocols })
    }

    /// The offset of `class_ro_t`'s pointer fields: three `uint32_t`s, padded to pointer alignment.
    fn ro_fields(&self) -> u64 {
        if self.size == 8 { 16 } else { 12 }
    }

    /// The `class_ro_t` of the class at `address`, from its `data` word with the runtime's flag bits cleared.
    fn class_ro(&mut self, address: u64) -> Option<u64> {
        let data = match self.pointer(self.field(address, 4)) {
            Some(Pointer::Local(data)) => data & !(self.size - 1),
            _ => {
                self.warn(format!("class at {address:#x} has no readable data pointer"));
                return None;
            }
        };
        if self.binary.read(data, self.ro_fields() + 7 * self.size).is_none() {
            self.warn(format!("class at {address:#x} has its class_ro_t outside the image at {data:#x}"));
            return None;
        }
        Some(data)
    }

    fn class_name(&mut self, address: u64) -> Option<String> {
        if let Some(name) = self.names.get(&address) {
            return name.clone();
        }
        // Cache first, so a class whose data points back at itself cannot recurse.
        self.names.insert(address, None);
        let name = self
            .class_ro(address)
            .and_then(|ro| self.string_at_pointer(self.field(ro.wrapping_add(self.ro_fields()), 1)));
        if name.is_none() {
            self.warn(format!("class at {address:#x} has no readable name"));
        }
        self.names.insert(address, name.clone());
        name
    }

    /// The class a superclass or category class pointer reaches.
    fn link_name(&mut self, link: Pointer) -> Option<String> {
        match link {
            Pointer::Null => None,
            Pointer::Import(symbol) => {
                Some(CLASS_PREFIXES.iter().find_map(|prefix| symbol.strip_prefix(prefix)).unwrap_or(symbol).to_owned())
            }
            Pointer::Local(class) => self.class_name(class),
        }
    }

    fn superclasses(&mut self, address: u64, name: &str) -> Vec<String> {
        let mut chain = Vec::new();
        let mut visited = HashSet::from([address]);
        let mut current = address;
        loop {
            let link = match self.pointer(self.field(current, 1)) {
                Some(Pointer::Null) | None => break,
                Some(link) => link,
            };
            if chain.len() == MAX_SUPERCLASS_DEPTH {
                self.warn(format!("class {name}'s superclass chain exceeds {MAX_SUPERCLASS_DEPTH} classes"));
                break;
            }
            if let Pointer::Local(next) = link
                && !visited.insert(next)
            {
                self.warn(format!("class {name}'s superclass chain loops back to {next:#x}"));
                break;
            }
            let Some(superclass) = self.link_name(link) else { break };
            chain.push(superclass);
            match link {
                Pointer::Local(next) => current = next,
                _ => break,
            }
        }
        chain
    }

    /// Reads a list header (`entsize_and_flags`, `count`) whose pointer is stored at `field`, checking the list
    /// is aligned, its entries are at least `min_entry` bytes, and every entry lies in the image.
    fn list(&mut self, field: u64, what: &str, min_entry: u64) -> Option<(u64, u32, u64, u64)> {
        let address = match self.pointer(field)? {
            Pointer::Local(address) => address,
            Pointer::Null => return None,
            Pointer::Import(_) => {
                self.warn(format!("{what} pointer at {field:#x} is bound to an import"));
                return None;
            }
        };
        if address % 4 != 0 {
            self.warn(format!("{what} at {address:#x} is misaligned"));
            return None;
        }
        let (Some(flags), Some(count)) = (self.u32(address), self.u32(address.wrapping_add(4))) else {
            self.warn(format!("{what} at {address:#x} lies outside the image"));
            return None;
        };
        let entry = u64::from(flags & ENTRY_SIZE_MASK);
        let count = u64::from(count);
        if entry < min_entry {
            self.warn(format!("{what} at {address:#x} has entry size {entry}, below {min_entry}"));
            return None;
        }
        if count > MAX_LIST_ENTRIES || self.binary.read(address.wrapping_add(8), count * entry).is_none() {
            self.warn(format!("{what} at {address:#x} claims {count} entries, more than the image holds"));
            return None;
        }
        if count > self.budget {
            if self.budget > 0 {
                self.warn(format!("Objective-C metadata exceeds {MAX_ENTRIES} entries; the rest is skipped"));
                self.budget = 0;
            }
            return None;
        }
        self.budget -= count;
        Some((address.wrapping_add(8), flags, entry, count))
    }

    fn methods(&mut self, field: u64, owner: &str, class_method: bool) -> Vec<ObjcMethod> {
        let mut methods = Vec::new();
        let relative = self.u32_at_pointer(field).is_some_and(|flags| flags & RELATIVE_METHODS != 0);
        let min_entry = if relative { 12 } else { 3 * self.size };
        let Some((start, flags, entry_size, count)) = self.list(field, "method list", min_entry) else {
            return methods;
        };
        for index in 0..count {
            let entry = start + index * entry_size;
            let (selector, types, implementation) = if relative {
                let selector = self.relative(entry).and_then(|target| {
                    if flags & DIRECT_SELECTORS != 0 { self.string(target) } else { self.string_at_pointer(target) }
                });
                let types = self.relative(entry.wrapping_add(4)).and_then(|target| self.string(target));
                let implementation = self.relative(entry.wrapping_add(8));
                (selector, types, implementation.map(Pointer::Local))
            } else {
                let selector = self.string_at_pointer(entry);
                let types = self.string_at_pointer(self.field(entry, 1));
                (selector, types, self.pointer(self.field(entry, 2)))
            };
            let Some(selector) = selector else {
                self.warn(format!("method {index} of {owner} at {entry:#x} has no readable selector"));
                continue;
            };
            let sign = if class_method { '+' } else { '-' };
            let name = format!("{sign}[{owner} {selector}]");
            let implementation = match implementation {
                Some(Pointer::Local(address)) if self.binary.is_code(address) => Some(address),
                Some(Pointer::Null) | None => None,
                Some(_) => {
                    self.warn(format!("{name}'s implementation does not point into code"));
                    None
                }
            };
            methods.push(ObjcMethod { name, selector, types, implementation, class_method });
        }
        methods
    }

    fn ivars(&mut self, field: u64, owner: &str) -> Vec<ObjcIvar> {
        let mut ivars = Vec::new();
        let Some((start, _, entry_size, count)) = self.list(field, "ivar list", 3 * self.size + 8) else {
            return ivars;
        };
        for index in 0..count {
            let entry = start + index * entry_size;
            let Some(name) = self.string_at_pointer(self.field(entry, 1)) else {
                self.warn(format!("ivar {index} of {owner} at {entry:#x} has no readable name"));
                continue;
            };
            let offset = match self.pointer(entry) {
                Some(Pointer::Local(variable)) => self.u32(variable),
                _ => None,
            };
            let type_encoding = self.string_at_pointer(self.field(entry, 2));
            let size = self.u32(self.field(entry, 3).wrapping_add(4)).unwrap_or(0);
            ivars.push(ObjcIvar { name, type_encoding, offset, size });
        }
        ivars
    }

    fn properties(&mut self, field: u64) -> Vec<ObjcProperty> {
        let mut properties = Vec::new();
        let Some((start, _, entry_size, count)) = self.list(field, "property list", 2 * self.size) else {
            return properties;
        };
        for index in 0..count {
            let entry = start + index * entry_size;
            if let Some(name) = self.string_at_pointer(entry) {
                properties.push(ObjcProperty { name, attributes: self.string_at_pointer(self.field(entry, 1)) });
            }
        }
        properties
    }

    /// The names of the protocols in the `protocol_list_t` whose pointer is stored at `field`.
    fn protocols(&mut self, field: u64) -> Vec<String> {
        let mut protocols = Vec::new();
        let Some(Pointer::Local(list)) = self.pointer(field) else { return protocols };
        let Some(count) = self.word(list) else {
            self.warn(format!("protocol list at {list:#x} lies outside the image"));
            return protocols;
        };
        let fits = count.checked_mul(self.size).and_then(|len| self.binary.read(self.field(list, 1), len)).is_some();
        if count > MAX_LIST_ENTRIES || count > self.budget || !fits {
            self.warn(format!("protocol list at {list:#x} claims {count} entries, more than the image holds"));
            return protocols;
        }
        self.budget -= count;
        for index in 0..count {
            let entry = self.field(list, index + 1);
            if let Some(Pointer::Local(protocol)) = self.pointer(entry)
                && let Some(name) = self.string_at_pointer(self.field(protocol, 1))
            {
                protocols.push(name);
            }
        }
        protocols
    }

    /// What the pointer-sized field at `address` holds once loaded; `None` when it is unreadable, or when a
    /// chained-fixup image stores a non-null word there that no fixup describes.
    fn pointer(&self, address: u64) -> Option<Pointer<'a>> {
        if let Some(slot) = self.binary.import_slot(address) {
            return Some(Pointer::Import(&slot.name));
        }
        if let Some(target) = self.binary.rebase_target(address) {
            return Some(Pointer::Local(target));
        }
        match self.word(address)? {
            0 => Some(Pointer::Null),
            _ if self.binary.has_chained_fixups() => None,
            value => Some(Pointer::Local(value)),
        }
    }

    /// The address of pointer-sized field `index` of the structure at `base`. Wrapping, since `base` may be
    /// hostile; a wrapped address is simply unreadable.
    fn field(&self, base: u64, index: u64) -> u64 {
        base.wrapping_add(index.wrapping_mul(self.size))
    }

    fn word(&self, address: u64) -> Option<u64> {
        let size = self.size as usize;
        read_uint(self.binary.read(address, self.size)?, 0, size, self.binary.big_endian)
    }

    fn u32(&self, address: u64) -> Option<u32> {
        read_uint(self.binary.read(address, 4)?, 0, 4, self.binary.big_endian).map(|value| value as u32)
    }

    fn u32_at_pointer(&self, field: u64) -> Option<u32> {
        match self.pointer(field)? {
            Pointer::Local(address) => self.u32(address),
            _ => None,
        }
    }

    /// The target of the signed 32-bit offset stored at `address`, measured from `address`; `None` for zero.
    fn relative(&self, address: u64) -> Option<u64> {
        let offset = self.u32(address)? as i32;
        (offset != 0).then(|| address.checked_add_signed(i64::from(offset))).flatten()
    }

    fn string_at_pointer(&self, field: u64) -> Option<String> {
        match self.pointer(field)? {
            Pointer::Local(address) => self.string(address),
            _ => None,
        }
    }

    /// The non-empty NUL-terminated string at `address`, at most [`MAX_NAME_BYTES`] long.
    fn string(&self, address: u64) -> Option<String> {
        let bytes = self.binary.read_to_segment_end(address)?;
        let bytes = &bytes[..bytes.len().min(MAX_NAME_BYTES + 1)];
        let end = bytes.iter().position(|&byte| byte == 0).filter(|&end| end > 0)?;
        Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }
}

#[cfg(test)]
mod pointer_width_tests {
    /// A reference section placed at the top of the address space, where aligning its start would overflow, is
    /// skipped with a warning rather than panicking.
    #[test]
    fn reference_sections_at_the_top_of_the_address_space_are_skipped() {
        let mut binary = crate::Binary::open(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/bin/objc-dispatch-arm64.macho"),
        )
        .unwrap();
        for section in binary.sections.iter_mut().filter(|section| section.name == "__objc_selrefs") {
            section.address = u64::MAX - 2;
        }
        for section in binary.sections.iter_mut().filter(|section| section.name == "__objc_classlist") {
            section.address = u64::MAX - 2;
        }
        let refs = super::refs(&binary);
        assert!(refs.selectors.is_empty());
        assert!(refs.warnings.iter().any(|warning| warning.contains("__objc_selrefs")), "{:?}", refs.warnings);
        assert!(refs.warnings.iter().any(|warning| warning.contains("__objc_classlist")), "{:?}", refs.warnings);
    }

    #[test]
    fn unknown_objc_width_is_reported_not_a_complete_empty_parse() {
        let mut report = super::ObjcReport::default();
        assert_eq!(super::objc_pointer_size(None, &mut report), None);
        assert!(!report.warnings.is_empty());
        assert!(report.classes.is_empty() && report.categories.is_empty());
    }
}
