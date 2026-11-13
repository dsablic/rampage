//! Go runtime type metadata: the `abi.Type` descriptors every Go program carries for reflection, interface
//! conversion and the garbage collector. They survive `-ldflags "-s -w"`, so a stripped Go binary still knows
//! each reachable type's size, struct fields with offsets, interface method sets and named types' methods.
//!
//! [`go_type_index`] locates `runtime.firstmoduledata` (it begins with a pointer to the pclntab the loader
//! already found), reads the bounds of the types section, and walks every descriptor reachable from the
//! module's roots — `typelinks` and `itablinks` before go1.27, the linear descriptor array from go1.27 — once,
//! keeping only names. A lookup then decodes just the requested type and what its fields name.
//!
//! Layouts covered: pclntab magics go1.16 (go1.16–go1.17), go1.18 (go1.18–go1.19) and go1.20 (go1.20 and
//! later, with the go1.26 `epclntab` and go1.27 `typedesclen` module layouts told apart by shape). The pre-go1.17 name encoding and the
//! pre-go1.19 `offsetEmbed` field encoding are detected from the data. Both byte orders, 4- and 8-byte words.
//!
//! Everything here reads an untrusted image: every offset is checked against the types section, counts are
//! capped before anything is allocated, cycles are cut by a visited set, and each pass has a step budget.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ops::Range;

use serde::Serialize;

use crate::gopclntab::GoTableVersion;
use crate::{Binary, SectionKind};

/// Types the index keeps; generous for real programs (a 26 MB binary has a few tens of thousands).
const MAX_INDEX_TYPES: usize = 1_000_000;
/// Types waiting in the reachability walk's queue.
const MAX_QUEUE: usize = 4 * MAX_INDEX_TYPES;
/// Descriptor, field and method reads one index build may make.
const MAX_BUILD_STEPS: usize = 20_000_000;
/// Total bytes of index keys.
const MAX_KEY_BYTES: usize = 128 * 1024 * 1024;
/// Largest types section the index maps.
const MAX_TYPES_BYTES: u64 = 1 << 30;
/// Roots read from `typelinks` or `itablinks`.
const MAX_ROOTS: u64 = 4_000_000;
/// Longest name decoded; longer names are cut.
const MAX_NAME: usize = 8192;
/// Struct fields, interface methods or function parameters one descriptor may declare.
const MAX_COUNT: u64 = 1 << 16;
/// Index entries of one name a lookup materialises.
pub const MAX_LOOKUP_CANDIDATES: usize = 16;
/// Descriptor, field and method reads one lookup may make, across all of its candidates.
pub const MAX_LOOKUP_STEPS: usize = 200_000;
pub const MAX_LOOKUP_DEPTH: usize = 4;
pub const MAX_LOOKUP_LIMIT: usize = 512;
const MAX_OUTPUT_MEMBERS: usize = 1024;
const MAX_METHODS: usize = 512;
const MAX_SELECTION_DEPTH: usize = 32;
const MAX_SUGGESTIONS: usize = 16;

const TFLAG_UNCOMMON: u8 = 1;
const TFLAG_EXTRA_STAR: u8 = 2;
const TFLAG_NAMED: u8 = 4;

const KIND_ARRAY: u8 = 17;
const KIND_CHAN: u8 = 18;
const KIND_FUNC: u8 = 19;
const KIND_INTERFACE: u8 = 20;
const KIND_MAP: u8 = 21;
const KIND_POINTER: u8 = 22;
const KIND_SLICE: u8 = 23;
const KIND_STRUCT: u8 = 25;
const KIND_UNSAFE_POINTER: u8 = 26;

const CAVEATS: &[&str] = &[
    "names come from Go runtime type metadata (the reflect descriptors), not debug info: no source lines or comments",
    "field names include unexported fields; struct tags are reported when present",
    "only types the program keeps descriptors for are present: those reachable from typelinks, itabs or other \
     descriptors (go1.27+: every emitted descriptor); a type used only by value inside functions may be absent",
    "type_name is the runtime type string, qualified by package name; package gives the full import path of named types",
];

fn kind_name(kind: u8) -> &'static str {
    match kind {
        1 => "bool",
        2 => "int",
        3 => "int8",
        4 => "int16",
        5 => "int32",
        6 => "int64",
        7 => "uint",
        8 => "uint8",
        9 => "uint16",
        10 => "uint32",
        11 => "uint64",
        12 => "uintptr",
        13 => "float32",
        14 => "float64",
        15 => "complex64",
        16 => "complex128",
        KIND_ARRAY => "array",
        KIND_CHAN => "chan",
        KIND_FUNC => "func",
        KIND_INTERFACE => "interface",
        KIND_MAP => "map",
        KIND_POINTER => "pointer",
        KIND_SLICE => "slice",
        24 => "string",
        KIND_STRUCT => "struct",
        KIND_UNSAFE_POINTER => "unsafe.Pointer",
        _ => "invalid",
    }
}

/// Which `moduledata` field layout the image uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoModuleLayout {
    /// go1.16–go1.17: `types, etypes` then `textsectmap, typelinks, itablinks`.
    Go116,
    /// go1.18–go1.19: adds `rodata, gofunc`.
    Go118,
    /// go1.20–go1.25: adds `covctrs, ecovctrs`.
    Go120,
    /// go1.26: adds `epclntab`.
    Go126,
    /// go1.27+: `types, typedesclen, etypes`; descriptors are laid out back to back and typelinks are gone.
    Go127,
}

impl GoModuleLayout {
    /// Word indices of `text`, `types`, `etypes`, and `typelinks` (or `typedesclen` for go1.27).
    fn slots(self) -> (usize, usize, usize, usize) {
        match self {
            Self::Go116 => (22, 35, 36, 40),
            Self::Go118 => (22, 35, 36, 42),
            Self::Go120 => (22, 37, 38, 44),
            Self::Go126 => (22, 37, 38, 45),
            Self::Go127 => (22, 37, 39, 38),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameEncoding {
    /// Before go1.17: a big-endian `uint16` length.
    Fixed16,
    /// go1.17+: a varint length.
    Varint,
}

#[derive(Debug, Clone, Copy)]
struct Layout {
    ptr: usize,
    big_endian: bool,
    names: NameEncoding,
    /// Before go1.19 a field's offset word holds `offset << 1 | embedded`.
    offset_embed: bool,
    module: GoModuleLayout,
    text: u64,
    types: u64,
    etypes: u64,
}

impl Layout {
    /// Size of the `abi.Type` header.
    fn header(&self) -> u64 {
        4 * self.ptr as u64 + 16
    }

    /// Size of the kind-specific descriptor, which the uncommon type follows. `None` for a map, whose layout
    /// changed across releases and is resolved by [`Reader::uncommon`].
    fn base(&self, kind: u8) -> Option<u64> {
        let (t, u) = (self.header(), self.ptr as u64);
        Some(match kind {
            KIND_ARRAY => t + 3 * u,
            KIND_CHAN => t + 2 * u,
            KIND_FUNC | KIND_POINTER | KIND_SLICE => t + u,
            KIND_INTERFACE | KIND_STRUCT => t + 4 * u,
            KIND_MAP => return None,
            _ => t,
        })
    }

    /// Candidate map descriptor sizes: hashmap (to go1.23), swiss map (go1.24–go1.26), go1.27.
    fn map_bases(&self) -> [u64; 3] {
        let (t, u) = (self.header(), self.ptr as u64);
        let swiss = t + 7 * u + 4;
        [t + 4 * u + 8, swiss.div_ceil(u) * u, t + 11 * u]
    }
}

/// What one index build read.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GoIndexStats {
    pub layout: Option<GoModuleLayout>,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub moduledata: u64,
    pub types_section_bytes: u64,
    pub roots: usize,
    pub types: usize,
    pub named_types: usize,
    pub steps: usize,
    /// Some types are missing: a cap was reached or a descriptor could not be decoded.
    pub truncated: bool,
}

#[derive(Debug, Clone)]
struct IndexedType {
    address: u64,
    kind: u8,
    named: bool,
    size: u64,
    name: Box<str>,
    package: Option<Box<str>>,
}

/// The reachable Go runtime types of one image, by name.
#[derive(Debug)]
pub struct GoTypeIndex {
    layout: Layout,
    /// The types section within the image the index was built from.
    types_file: Range<usize>,
    image_len: usize,
    types: Vec<IndexedType>,
    /// Runtime type string and, for named types, the package-path-qualified name → `types` indices.
    names: BTreeMap<String, Vec<u32>>,
    /// Named types sorted by qualified name, for listing.
    listing: Vec<u32>,
    stats: GoIndexStats,
    warnings: Vec<String>,
}

/// Bounded reader over the types section, with a fallback to the whole image for roots outside it.
struct Reader<'a> {
    layout: Layout,
    section: &'a [u8],
    binary: Option<&'a Binary>,
    steps: usize,
    budget: usize,
}

impl<'a> Reader<'a> {
    fn charge(&mut self, steps: usize) -> Option<()> {
        self.steps = self.steps.saturating_add(steps);
        (self.steps <= self.budget).then_some(())
    }

    fn in_types(&self, address: u64) -> bool {
        (self.layout.types..self.layout.etypes).contains(&address)
    }

    fn bytes(&self, address: u64, len: usize) -> Option<&'a [u8]> {
        if self.in_types(address) {
            let start = usize::try_from(address - self.layout.types).ok()?;
            return self.section.get(start..start.checked_add(len)?);
        }
        self.binary?.read(address, len as u64)
    }

    fn uint(&self, address: u64, width: usize) -> Option<u64> {
        rampage_arch::bytes::read_uint(self.bytes(address, width)?, 0, width, self.layout.big_endian)
    }

    fn word(&self, address: u64) -> Option<u64> {
        self.uint(address, self.layout.ptr)
    }

    fn i32(&self, address: u64) -> Option<i32> {
        Some(self.uint(address, 4)? as u32 as i32)
    }

    /// `types + off`, inside the types section.
    fn resolve(&self, off: i32) -> Option<u64> {
        let address = self.layout.types.checked_add_signed(i64::from(off))?;
        self.in_types(address).then_some(address)
    }

    fn name(&mut self, address: u64) -> Option<Name> {
        self.charge(1)?;
        let flags = *self.bytes(address, 1)?.first()?;
        let (len, mut at) = match self.layout.names {
            NameEncoding::Fixed16 => {
                let bytes = self.bytes(address + 1, 2)?;
                (usize::from(bytes[0]) << 8 | usize::from(bytes[1]), address + 3)
            }
            NameEncoding::Varint => self.varint(address + 1)?,
        };
        let text = self.text(at, len)?;
        at += len as u64;
        let tag = if flags & 2 != 0 {
            let (tag_len, tag_at) = match self.layout.names {
                NameEncoding::Fixed16 => {
                    let bytes = self.bytes(at, 2)?;
                    (usize::from(bytes[0]) << 8 | usize::from(bytes[1]), at + 2)
                }
                NameEncoding::Varint => self.varint(at)?,
            };
            self.text(tag_at, tag_len).filter(|tag| !tag.is_empty())
        } else {
            None
        };
        Some(Name { text, exported: flags & 1 != 0, embedded: flags & 8 != 0, tag })
    }

    fn varint(&self, address: u64) -> Option<(usize, u64)> {
        let mut value = 0usize;
        for index in 0..4u64 {
            let byte = *self.bytes(address + index, 1)?.first()?;
            value |= usize::from(byte & 0x7f) << (7 * index);
            if byte & 0x80 == 0 {
                return Some((value, address + index + 1));
            }
        }
        None
    }

    fn text(&self, address: u64, len: usize) -> Option<String> {
        let bytes = self.bytes(address, len.min(MAX_NAME))?;
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    /// The type descriptor header at `address`, validated.
    fn header(&mut self, address: u64) -> Option<Header> {
        self.charge(1)?;
        let u = self.layout.ptr as u64;
        if !self.in_types(address) || !address.is_multiple_of(4) {
            return None;
        }
        let size = self.word(address)?;
        let flags = self.bytes(address + 2 * u + 4, 4)?;
        let (tflag, align, field_align, kind) = (flags[0], flags[1], flags[2], flags[3] & 0x1f);
        if kind == 0 || !align.is_power_of_two() || !field_align.is_power_of_two() || align > 64 {
            return None;
        }
        let str_off = self.i32(address + 4 * u + 8)?;
        let ptr_to_this = self.i32(address + 4 * u + 12)?;
        let str_address = self.resolve(str_off)?;
        let mut name = self.name(str_address)?.text;
        if tflag & TFLAG_EXTRA_STAR != 0 && name.starts_with('*') {
            name.remove(0);
        }
        if name.is_empty() || name.contains('\0') {
            return None;
        }
        let ptr_to_this = (ptr_to_this != 0).then(|| self.resolve(ptr_to_this)).flatten();
        Some(Header { address, size, tflag, align, kind, name, ptr_to_this })
    }

    /// Where the uncommon type of `header` lies, when it has one.
    fn uncommon_at(&mut self, header: &Header) -> Option<u64> {
        if header.tflag & TFLAG_UNCOMMON == 0 {
            return None;
        }
        if let Some(base) = self.layout.base(header.kind) {
            return header.address.checked_add(base);
        }
        header.address.checked_add(self.map_base(header)?)
    }

    /// Size of a map descriptor. Swiss maps (go1.24+) hold `GroupSize == Group.Size_` four words in; the older
    /// hashmap layout has byte-sized key, value and bucket sizes there instead.
    fn map_base(&mut self, header: &Header) -> Option<u64> {
        let (t, u) = (header.address + self.layout.header(), self.layout.ptr as u64);
        let [hashmap, swiss, go127] = self.layout.map_bases();
        let group = self.word(t + 2 * u)?;
        let group_size = self.word(t + 4 * u)?;
        let is_swiss = self.layout.module == GoModuleLayout::Go127
            || self.header(group).is_some_and(|group| group.size == group_size);
        Some(match (is_swiss, self.layout.module) {
            (false, _) => hashmap,
            (true, GoModuleLayout::Go127) => go127,
            (true, _) => swiss,
        })
    }

    /// Decodes an uncommon type: package path and methods (count, exported count, array address).
    fn uncommon(&mut self, at: u64) -> Option<Uncommon> {
        self.charge(1)?;
        let pkg = self.i32(at)?;
        let mcount = self.uint(at + 4, 2)?;
        let xcount = self.uint(at + 6, 2)?;
        let moff = self.uint(at + 8, 4)?;
        let padding = self.uint(at + 12, 4)?;
        if padding != 0 || xcount > mcount || (mcount > 0 && (moff < 16 || !moff.is_multiple_of(4))) {
            return None;
        }
        let methods = at.checked_add(moff)?;
        if mcount > 0 && !self.in_types(methods + mcount * 16 - 1) {
            return None;
        }
        let package = if pkg == 0 { None } else { Some(self.name(self.resolve(pkg)?)?.text) };
        Some(Uncommon { package, mcount, methods })
    }

    /// The kind-specific body of `header`.
    fn body(&mut self, header: &Header) -> Option<Body> {
        let (t, u) = (header.address + self.layout.header(), self.layout.ptr as u64);
        let ty = |reader: &Self, at: u64| reader.word(at).filter(|&address| address != 0);
        Some(match header.kind {
            KIND_ARRAY => Body::Array { elem: ty(self, t)?, len: self.word(t + 2 * u)? },
            KIND_CHAN => Body::Chan { elem: ty(self, t)?, dir: self.word(t + u)? },
            KIND_POINTER | KIND_SLICE => Body::Elem(ty(self, t)?),
            KIND_MAP => Body::Map { key: ty(self, t)?, elem: ty(self, t + u)? },
            KIND_FUNC => {
                let inputs = self.uint(t, 2)?;
                let outputs = self.uint(t + 2, 2)?;
                let mut params = header.address + self.layout.base(KIND_FUNC)?;
                if header.tflag & TFLAG_UNCOMMON != 0 {
                    params += 16;
                }
                let count = inputs + (outputs & 0x7fff);
                self.array(params, count, u)?;
                Body::Func { inputs, outputs: outputs & 0x7fff, variadic: outputs & 0x8000 != 0, params }
            }
            KIND_INTERFACE => {
                let (methods, count) = self.slice(t + u, 8)?;
                Body::Interface { methods, count }
            }
            KIND_STRUCT => {
                let (fields, count) = self.slice(t + u, 3 * u)?;
                Body::Struct { fields, count }
            }
            _ => Body::Basic,
        })
    }

    /// A `[]T` header at `at` whose elements are `stride` bytes: (data, len), checked against the section.
    fn slice(&mut self, at: u64, stride: u64) -> Option<(u64, u64)> {
        let u = self.layout.ptr as u64;
        let data = self.word(at)?;
        let len = self.word(at + u)?;
        let cap = self.word(at + 2 * u)?;
        if len != cap {
            return None;
        }
        self.array(data, len, stride)?;
        Some((data, len))
    }

    fn array(&self, data: u64, len: u64, stride: u64) -> Option<()> {
        if len > MAX_COUNT {
            return None;
        }
        if len > 0 && !(self.in_types(data) && self.in_types(data.checked_add(len * stride - 1)?)) {
            return None;
        }
        Some(())
    }

    fn field(&mut self, fields: u64, index: u64) -> Option<Field> {
        self.charge(1)?;
        let u = self.layout.ptr as u64;
        let at = fields + index * 3 * u;
        let name = self.name(self.word(at)?)?;
        let ty = self.word(at + u).filter(|&ty| ty != 0)?;
        let raw = self.word(at + 2 * u)?;
        let (offset, embedded) = if self.layout.offset_embed { (raw >> 1, raw & 1 != 0) } else { (raw, name.embedded) };
        Some(Field { name, ty, offset, embedded })
    }

    /// Interface method `index`: name and signature type.
    fn imethod(&mut self, methods: u64, index: u64) -> Option<(Name, Option<u64>)> {
        self.charge(1)?;
        let at = methods + index * 8;
        let name = self.name(self.resolve(self.i32(at)?)?)?;
        let ty = self.i32(at + 4)?;
        Some((name, (ty > 0).then(|| self.resolve(ty)).flatten()))
    }

    /// Uncommon method `index`: name, signature type and the text offset of its value-receiver implementation.
    fn method(&mut self, methods: u64, index: u64) -> Option<(Name, Option<u64>, Option<u64>)> {
        self.charge(1)?;
        let at = methods + index * 16;
        let name = self.name(self.resolve(self.i32(at)?)?)?;
        let ty = self.i32(at + 4)?;
        let tfn = self.i32(at + 12)?;
        let ty = (ty > 0).then(|| self.resolve(ty)).flatten();
        let code = (tfn >= 0).then(|| self.layout.text.checked_add(tfn as u64)).flatten();
        Some((name, ty, code))
    }

    /// The types a descriptor names directly, for the reachability walk.
    fn edges(&mut self, header: &Header, out: &mut Vec<u64>) -> Option<()> {
        out.extend(header.ptr_to_this);
        match self.body(header)? {
            Body::Array { elem, .. } | Body::Chan { elem, .. } | Body::Elem(elem) => out.push(elem),
            Body::Map { key, elem } => out.extend([key, elem]),
            Body::Func { inputs, outputs, params, .. } => {
                self.charge((inputs + outputs) as usize)?;
                let u = self.layout.ptr as u64;
                out.extend((0..inputs + outputs).filter_map(|index| self.word(params + index * u)));
            }
            Body::Interface { methods, count } => {
                for index in 0..count {
                    if let Some((_, Some(ty))) = self.imethod(methods, index) {
                        out.push(ty);
                    }
                }
            }
            Body::Struct { fields, count } => {
                for index in 0..count {
                    self.charge(1)?;
                    if let Some(ty) = self.word(fields + index * 3 * self.layout.ptr as u64 + self.layout.ptr as u64) {
                        out.push(ty);
                    }
                }
            }
            Body::Basic => {}
        }
        if let Some(at) = self.uncommon_at(header)
            && let Some(uncommon) = self.uncommon(at)
        {
            for index in 0..uncommon.mcount {
                if let Some((_, Some(ty), _)) = self.method(uncommon.methods, index) {
                    out.push(ty);
                }
            }
        }
        Some(())
    }

    /// Bytes the go1.27 linear walk advances past the descriptor at `header`.
    fn descriptor_size(&mut self, header: &Header) -> Option<u64> {
        let u = self.layout.ptr as u64;
        let base = match self.layout.base(header.kind) {
            Some(base) => base,
            None => self.map_base(header)?,
        };
        let (add, mcount) = match self.body(header)? {
            Body::Func { inputs, outputs, .. } => ((inputs + outputs) * u, 0),
            Body::Interface { count, .. } => (count * 8, 0),
            Body::Struct { count, .. } => (count * 3 * u, 0),
            _ => (0, 0),
        };
        let mut size = base + add + mcount;
        if header.tflag & TFLAG_UNCOMMON != 0 {
            let uncommon = self.uncommon(header.address + base)?;
            size += 16 + uncommon.mcount * 16;
        }
        Some(size)
    }
}

struct Name {
    text: String,
    exported: bool,
    embedded: bool,
    tag: Option<String>,
}

struct Header {
    address: u64,
    size: u64,
    tflag: u8,
    align: u8,
    kind: u8,
    name: String,
    ptr_to_this: Option<u64>,
}

struct Uncommon {
    package: Option<String>,
    mcount: u64,
    methods: u64,
}

enum Body {
    Basic,
    Array { elem: u64, len: u64 },
    Chan { elem: u64, dir: u64 },
    Elem(u64),
    Map { key: u64, elem: u64 },
    Func { inputs: u64, outputs: u64, variadic: bool, params: u64 },
    Interface { methods: u64, count: u64 },
    Struct { fields: u64, count: u64 },
}

struct Field {
    name: Name,
    ty: u64,
    offset: u64,
    embedded: bool,
}

/// `pkgpath.Name` for a named type whose runtime string is `pkg.Name`; generic arguments stay as they are.
fn qualified(name: &str, package: &str) -> Option<String> {
    Some(format!("{package}.{}", qualified_rest(name)?))
}

/// What follows the package name in a runtime type string `pkg.Name`.
fn qualified_rest(name: &str) -> Option<&str> {
    let mut depth = 0usize;
    for (index, ch) in name.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            '.' if depth == 0 => return Some(&name[index + 1..]),
            _ => {}
        }
    }
    None
}

/// Builds the index of an image's Go runtime types. Fails when the image is not a supported Go binary.
pub fn go_type_index(binary: &Binary) -> Result<GoTypeIndex, String> {
    let version = binary.go_table.ok_or("not a Go binary (no pclntab)")?;
    if version == GoTableVersion::Go12 {
        return Err("Go runtime types are read for go1.16 and later; this pclntab is go1.2–go1.15".into());
    }
    let table = binary.go_table_address.ok_or("the pclntab address is unknown")?;
    let ptr =
        binary.arch.default_pointer_size().filter(|width| matches!(width, 4 | 8)).ok_or("unsupported Go word width")?
            as usize;
    let (moduledata, layout) = find_moduledata(binary, table, ptr, version)?;
    let types_len = layout.etypes - layout.types;
    let section = binary
        .read(layout.types, types_len)
        .ok_or_else(|| format!("types section {:#x}..{:#x} is not file-backed", layout.types, layout.etypes))?;
    let image = binary.image_bytes();
    let start = (section.as_ptr() as usize).wrapping_sub(image.as_ptr() as usize);
    let types_file = start..start + section.len();
    if image.get(types_file.clone()).is_none_or(|bytes| bytes.as_ptr() != section.as_ptr()) {
        return Err("types section is not inside the image".into());
    }
    let mut reader = Reader { layout, section, binary: Some(binary), steps: 0, budget: MAX_BUILD_STEPS };
    let mut warnings = Vec::new();
    let roots = roots(&mut reader, binary, moduledata, &mut warnings);
    let roots_capped = roots.len() >= MAX_INDEX_TYPES;
    reader.layout.names = detect_names(&mut reader, &roots, version);
    let mut stats = GoIndexStats {
        layout: Some(layout.module),
        moduledata,
        types_section_bytes: types_len,
        roots: roots.len(),
        ..GoIndexStats::default()
    };
    stats.truncated |= roots_capped;
    let (types, votes) = walk(&mut reader, roots, &mut stats);
    if matches!(version, GoTableVersion::Go116 | GoTableVersion::Go118) {
        reader.layout.offset_embed = votes.old > votes.new;
    }
    stats.steps = reader.steps;
    if reader.steps > reader.budget {
        stats.truncated = true;
        warnings.push("Go type walk reached its step budget; some types are missing".into());
    }
    let mut names: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    let mut key_bytes = 0usize;
    for (index, ty) in types.iter().enumerate() {
        let qualified = ty.package.as_deref().filter(|_| ty.named).and_then(|package| qualified(&ty.name, package));
        for key in std::iter::once(ty.name.to_string()).chain(qualified) {
            key_bytes += key.len();
            if key_bytes > MAX_KEY_BYTES {
                stats.truncated = true;
                break;
            }
            let entry = names.entry(key).or_default();
            if entry.last() != Some(&(index as u32)) {
                entry.push(index as u32);
            }
        }
    }
    let mut listing: Vec<u32> = (0..types.len() as u32).filter(|&index| types[index as usize].named).collect();
    listing.sort_by(|&left, &right| display_key(&types[left as usize]).cmp(display_key(&types[right as usize])));
    stats.types = types.len();
    stats.named_types = listing.len();
    Ok(GoTypeIndex {
        layout: reader.layout,
        types_file,
        image_len: image.len(),
        types,
        names,
        listing,
        stats,
        warnings,
    })
}

/// [`display_name`]'s bytes without building the string: `pkgpath`, `.`, the name after its package.
fn display_key(ty: &IndexedType) -> impl Iterator<Item = u8> + '_ {
    let qualified = ty.package.as_deref().filter(|_| ty.named).and_then(|package| {
        let name = qualified_rest(&ty.name)?;
        Some((package, name))
    });
    let (package, dot, name) = match qualified {
        Some((package, name)) => (package, ".", name),
        None => ("", "", &*ty.name),
    };
    package.bytes().chain(dot.bytes()).chain(name.bytes())
}

fn display_name(ty: &IndexedType) -> String {
    ty.package
        .as_deref()
        .filter(|_| ty.named)
        .and_then(|package| qualified(&ty.name, package))
        .unwrap_or_else(|| ty.name.to_string())
}

/// Finds `runtime.firstmoduledata`: a pointer-aligned word equal to the pclntab address in a data section,
/// whose text, types and typelinks fields are consistent under the layout this pclntab version implies.
fn find_moduledata(binary: &Binary, table: u64, ptr: usize, version: GoTableVersion) -> Result<(u64, Layout), String> {
    let modules: &[GoModuleLayout] = match version {
        GoTableVersion::Go116 => &[GoModuleLayout::Go116],
        GoTableVersion::Go118 => &[GoModuleLayout::Go118],
        _ => &[GoModuleLayout::Go120, GoModuleLayout::Go126, GoModuleLayout::Go127],
    };
    let needle =
        if binary.big_endian { table.to_be_bytes()[8 - ptr..].to_vec() } else { table.to_le_bytes()[..ptr].to_vec() };
    for section in &binary.sections {
        if !matches!(section.kind, SectionKind::Data | SectionKind::ReadOnlyData) {
            continue;
        }
        // A PE `.data` also spans its zero-fill tail; only the file-backed part can hold moduledata.
        let Some(bytes) = binary.read(section.address, section.size.min(section.file_size)) else { continue };
        let word = |at: usize, index: usize| {
            rampage_arch::bytes::read_uint(bytes, at.checked_add(index * ptr)?, ptr, binary.big_endian)
        };
        for at in (0..bytes.len().saturating_sub(ptr)).step_by(ptr) {
            if bytes[at..at + ptr] != needle[..] {
                continue;
            }
            for &module in modules {
                let (text, types, etypes, links) = module.slots();
                let (Some(text), Some(minpc), Some(types), Some(etypes)) =
                    (word(at, text), word(at, 20), word(at, types), word(at, etypes))
                else {
                    continue;
                };
                if text > minpc || types >= etypes || etypes - types > MAX_TYPES_BYTES {
                    continue;
                }
                let links_ok = match module {
                    GoModuleLayout::Go127 => word(at, links).is_some_and(|len| len > 0 && len <= etypes - types),
                    _ => [(links, 4), (links + 3, ptr as u64)].iter().all(|&(slot, stride)| {
                        word(at, slot + 1).zip(word(at, slot + 2)).is_some_and(|(len, cap)| {
                            len == cap
                                && len <= MAX_ROOTS
                                && word(at, slot)
                                    .is_some_and(|data| len == 0 || binary.read(data, len * stride).is_some())
                        })
                    }),
                };
                if !links_ok {
                    continue;
                }
                let layout = Layout {
                    ptr,
                    big_endian: binary.big_endian,
                    names: NameEncoding::Varint,
                    offset_embed: false,
                    module,
                    text,
                    types,
                    etypes,
                };
                return Ok((section.address + at as u64, layout));
            }
        }
    }
    Err("Go moduledata not found (no data word points at the pclntab with a consistent layout)".into())
}

/// The walk's starting points: typelinks and itab types, or every descriptor of the go1.27 linear array.
fn roots(reader: &mut Reader<'_>, binary: &Binary, moduledata: u64, warnings: &mut Vec<String>) -> Vec<u64> {
    let layout = reader.layout;
    let u = layout.ptr as u64;
    let (_, _, _, links) = layout.module.slots();
    let word = |reader: &Reader<'_>, index: usize| reader.word(moduledata + index as u64 * u);
    let mut roots = Vec::new();
    if layout.module == GoModuleLayout::Go127 {
        let Some(len) = word(reader, links) else { return roots };
        let end = layout.types.saturating_add(len).min(layout.etypes);
        let mut at = layout.types + u;
        while at < end && roots.len() < MAX_INDEX_TYPES {
            at = at.div_ceil(u) * u;
            let Some(header) = reader.header(at) else {
                warnings.push(format!("Go type descriptor walk stopped at {at:#x}: undecodable descriptor"));
                break;
            };
            let Some(size) = reader.descriptor_size(&header).filter(|&size| size > 0) else {
                warnings.push(format!("Go type descriptor walk stopped at {at:#x}: undecodable body"));
                break;
            };
            roots.push(at);
            at += size;
        }
        return roots;
    }
    if let (Some(data), Some(len)) = (word(reader, links), word(reader, links + 1))
        && let Some(bytes) = binary.read(data, len * 4)
    {
        roots.extend(bytes.as_chunks::<4>().0.iter().filter_map(|chunk| {
            let raw = rampage_arch::bytes::read_uint(chunk, 0, 4, layout.big_endian)? as u32 as i32;
            reader.resolve(raw)
        }));
    }
    if let (Some(data), Some(len)) = (word(reader, links + 3), word(reader, links + 4))
        && len <= MAX_ROOTS
    {
        for index in 0..len {
            let Some(itab) = binary.read_pointer_any(data + index * u, layout) else { continue };
            roots.extend([itab, itab + u].iter().filter_map(|&at| binary.read_pointer_any(at, layout)));
        }
    }
    roots
}

trait ReadPointer {
    fn read_pointer_any(&self, address: u64, layout: Layout) -> Option<u64>;
}

impl ReadPointer for Binary {
    fn read_pointer_any(&self, address: u64, layout: Layout) -> Option<u64> {
        rampage_arch::bytes::read_uint(self.read(address, layout.ptr as u64)?, 0, layout.ptr, layout.big_endian)
            .filter(|&value| value != 0)
    }
}

/// go1.16 and go1.17 share a pclntab magic but not a name encoding: a short name's first length byte is zero
/// under the old fixed 16-bit length, and is the (nonzero) length itself under the varint one.
fn detect_names(reader: &mut Reader<'_>, roots: &[u64], version: GoTableVersion) -> NameEncoding {
    if version != GoTableVersion::Go116 {
        return NameEncoding::Varint;
    }
    let u = reader.layout.ptr as u64;
    let (mut fixed, mut varint) = (0, 0);
    for &root in roots.iter().take(64) {
        let Some(off) = reader.i32(root + 4 * u + 8) else { continue };
        let Some(bytes) = reader.resolve(off).and_then(|at| reader.bytes(at, 3)) else { continue };
        if bytes[1] == 0 && bytes[2] != 0 {
            fixed += 1;
        } else if bytes[1] != 0 {
            varint += 1;
        }
    }
    if fixed > varint { NameEncoding::Fixed16 } else { NameEncoding::Varint }
}

#[derive(Default)]
struct EmbedVotes {
    old: usize,
    new: usize,
}

/// Breadth-first walk from `roots` over every type a descriptor names, keeping each type's name once.
fn walk(reader: &mut Reader<'_>, roots: Vec<u64>, stats: &mut GoIndexStats) -> (Vec<IndexedType>, EmbedVotes) {
    let mut seen: HashSet<u64> = HashSet::new();
    let mut queue: VecDeque<u64> = roots.into_iter().collect();
    let mut types = Vec::new();
    let mut votes = EmbedVotes::default();
    let mut edges = Vec::new();
    let mut name_bytes = 0usize;
    while let Some(address) = queue.pop_front() {
        if !seen.insert(address) {
            continue;
        }
        if types.len() >= MAX_INDEX_TYPES || reader.steps > reader.budget {
            stats.truncated = true;
            break;
        }
        let Some(header) = reader.header(address) else { continue };
        let package = reader.uncommon_at(&header).and_then(|at| reader.uncommon(at)).and_then(|u| u.package);
        // The name is kept, keyed by itself and (named types) by its qualified spelling: charge every copy.
        name_bytes = name_bytes.saturating_add(3 * (header.name.len() + package.as_ref().map_or(0, String::len)));
        if name_bytes > MAX_KEY_BYTES {
            stats.truncated = true;
            break;
        }
        if header.kind == KIND_STRUCT && votes.old + votes.new < 256 {
            vote(reader, &header, &mut votes);
        }
        edges.clear();
        reader.edges(&header, &mut edges);
        if queue.len() + edges.len() > MAX_QUEUE {
            stats.truncated = true;
        } else {
            queue.extend(edges.iter().copied().filter(|edge| !seen.contains(edge)));
        }
        types.push(IndexedType {
            address,
            kind: header.kind,
            named: header.tflag & TFLAG_NAMED != 0,
            size: header.size,
            name: header.name.into_boxed_str(),
            package: package.map(String::into_boxed_str),
        });
    }
    if reader.steps > reader.budget {
        stats.truncated = true;
    }
    types.sort_by_key(|ty| ty.address);
    (types, votes)
}

/// Votes on the pre-go1.19 `offsetEmbed` encoding: a field's end must fit in its struct under the right one.
fn vote(reader: &mut Reader<'_>, header: &Header, votes: &mut EmbedVotes) {
    let Some(Body::Struct { fields, count }) = reader.body(header) else { return };
    if count < 2 {
        return;
    }
    let u = reader.layout.ptr as u64;
    let last = fields + (count - 1) * 3 * u;
    let (Some(raw), Some(ty)) = (reader.word(last + 2 * u), reader.word(last + u)) else { return };
    let Some(size) = reader.header(ty).map(|field| field.size) else { return };
    let fits = |offset: u64| offset.checked_add(size).is_some_and(|end| end <= header.size);
    match (fits(raw), fits(raw >> 1) && raw >> 1 != raw) {
        (true, false) => votes.new += 1,
        (false, true) => votes.old += 1,
        _ if raw & 1 == 1 => votes.old += 1,
        _ => {}
    }
}

/// One lookup: a type name, optionally a member path or byte offset to select, and a page of fields.
#[derive(Debug, Clone, Default)]
pub struct GoTypeRequest {
    /// The runtime type string (`restic.Snapshot`, `*restic.Node`, `[]string`) or a named type qualified by
    /// its package path (`github.com/restic/restic/internal/restic.Snapshot`).
    pub name: String,
    /// A dotted field path such as `Summary.DataAddedPacked` or `Buckets[2]`.
    pub member: Option<String>,
    /// A byte offset into the type; the innermost field covering it is selected.
    pub byte_offset: Option<u64>,
    /// How many levels of by-value struct fields to expand inline.
    pub depth: usize,
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct GoLookupWork {
    /// Descriptor, name, field and method reads.
    pub steps: usize,
}

#[derive(Debug, Serialize)]
pub struct GoTypeLookup {
    pub source: &'static str,
    pub name: String,
    /// Indexed types with this name.
    pub matches: usize,
    /// More than one type carries this name (same runtime string in different packages).
    pub ambiguous: bool,
    pub definitions: Vec<GoTypeDefinition>,
    pub caveats: &'static [&'static str],
    pub work: GoLookupWork,
    pub index: GoIndexStats,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GoTypeDefinition {
    /// `struct`, `interface`, `map`, `pointer`, `slice`, `array`, `chan`, `func`, or the basic kind.
    pub kind: &'static str,
    /// The runtime type string.
    pub type_name: String,
    /// Full import path of a named type's package.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualified_name: Option<String>,
    pub named: bool,
    pub byte_size: u64,
    pub align: u8,
    /// Virtual address of the type descriptor.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub descriptor: u64,
    /// Pointer, slice, array, chan and map element type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub len: Option<u64>,
    /// Channel direction: `recv`, `send` or `both`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<GoSignature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection: Option<GoMemberSelection>,
    /// Struct fields in this page; offsets are relative to the parent struct.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<GoMember>,
    /// Struct fields in all.
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// Interface methods, or a named type's methods (value and pointer receivers are separate types).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<GoMethod>,
    #[serde(skip_serializing_if = "is_zero")]
    pub methods_total: usize,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Serialize)]
pub struct GoSignature {
    pub params: Vec<String>,
    pub results: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub variadic: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GoMember {
    pub name: String,
    pub offset: u64,
    pub byte_size: Option<u64>,
    pub type_name: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub embedded: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub exported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<GoMember>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GoMethod {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub exported: bool,
    /// The implementation's entry address, when the linker kept it.
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "hex_option")]
    pub address: Option<u64>,
}

fn hex_option<S: serde::Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_str(&format!("{value:#x}")),
        None => serializer.serialize_none(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GoMemberSelection {
    pub path: String,
    /// Offset from the start of the requested type.
    pub offset: u64,
    pub byte_size: u64,
    pub type_name: String,
    /// For a byte_offset query: how far into the selected member the offset falls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub within: Option<u64>,
    /// For a byte_offset query: the offset lies in padding after the selected member.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub padding: bool,
}

#[derive(Debug, Serialize)]
pub struct GoTypePage {
    pub source: &'static str,
    pub types: Vec<GoTypeSummary>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub caveats: &'static [&'static str],
}

#[derive(Debug, Serialize)]
pub struct GoTypeSummary {
    pub name: String,
    pub type_name: String,
    pub kind: &'static str,
    pub byte_size: u64,
}

impl GoTypeIndex {
    pub fn stats(&self) -> &GoIndexStats {
        &self.stats
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    fn reader<'a>(&self, image: &'a [u8]) -> Result<Reader<'a>, String> {
        if image.len() != self.image_len {
            return Err("Go type index was built for a different image".into());
        }
        let section = image.get(self.types_file.clone()).ok_or("Go types section is outside the image")?;
        Ok(Reader { layout: self.layout, section, binary: None, steps: 0, budget: MAX_LOOKUP_STEPS })
    }

    /// Named types whose qualified or runtime name contains `contains`, sorted by qualified name.
    pub fn list(&self, contains: Option<&str>, offset: usize, limit: usize) -> GoTypePage {
        let mut total = 0;
        let mut types = Vec::new();
        for &index in &self.listing {
            let ty = &self.types[index as usize];
            let name = display_name(ty);
            if contains.is_some_and(|text| !name.contains(text) && !ty.name.contains(text)) {
                continue;
            }
            if total >= offset && types.len() < limit {
                types.push(GoTypeSummary {
                    name,
                    type_name: ty.name.to_string(),
                    kind: kind_name(ty.kind),
                    byte_size: ty.size,
                });
            }
            total += 1;
        }
        let end = offset.saturating_add(types.len());
        GoTypePage {
            source: "go_runtime",
            types,
            total,
            offset,
            limit,
            next_offset: (end < total).then_some(end),
            caveats: CAVEATS,
        }
    }

    /// Up to [`MAX_SUGGESTIONS`] indexed names containing the last path element of `name`.
    pub fn suggestions(&self, name: &str) -> Vec<String> {
        let needle = name.rsplit(['.', '/']).next().unwrap_or(name);
        if needle.is_empty() {
            return Vec::new();
        }
        let needle = needle.to_lowercase();
        self.listing
            .iter()
            .map(|&index| &self.types[index as usize])
            .filter(|ty| ty.name.to_lowercase().contains(&needle))
            .take(MAX_SUGGESTIONS)
            .map(display_name)
            .collect()
    }

    /// Reads one type's layout from `image` (the image the index was built from).
    pub fn lookup(&self, image: &[u8], request: &GoTypeRequest) -> Result<GoTypeLookup, String> {
        if request.depth > MAX_LOOKUP_DEPTH {
            return Err(format!("depth must be 0..={MAX_LOOKUP_DEPTH}"));
        }
        if request.limit > MAX_LOOKUP_LIMIT {
            return Err(format!("limit must be at most {MAX_LOOKUP_LIMIT}"));
        }
        if request.member.is_some() && request.byte_offset.is_some() {
            return Err("give member or byte_offset, not both".into());
        }
        let mut reader = self.reader(image)?;
        let name = request.name.trim();
        let name = name.strip_prefix("type ").unwrap_or(name).trim();
        let found = self.names.get(name).map(Vec::as_slice).unwrap_or_default();
        let mut lookup = GoTypeLookup {
            source: "go_runtime",
            name: name.to_owned(),
            matches: found.len(),
            ambiguous: found.len() > 1,
            definitions: Vec::new(),
            caveats: CAVEATS,
            work: GoLookupWork::default(),
            index: self.stats.clone(),
            warnings: Vec::new(),
        };
        for &index in found.iter().take(MAX_LOOKUP_CANDIDATES) {
            let address = self.types[index as usize].address;
            match define(&mut reader, address, request) {
                Ok(definition) => lookup.definitions.push(definition),
                Err(reason) => lookup.warnings.push(format!("{name} at {address:#x}: {reason}")),
            }
        }
        if reader.steps > reader.budget {
            lookup.warnings.push(format!("lookup reached its {MAX_LOOKUP_STEPS}-step budget; output is partial"));
        }
        lookup.work.steps = reader.steps;
        Ok(lookup)
    }
}

fn type_name(reader: &mut Reader<'_>, address: u64) -> String {
    reader.header(address).map_or_else(|| format!("<type {address:#x}>"), |header| header.name)
}

fn define(reader: &mut Reader<'_>, address: u64, request: &GoTypeRequest) -> Result<GoTypeDefinition, String> {
    let header = reader.header(address).ok_or("undecodable type descriptor")?;
    let body = reader.body(&header).ok_or("undecodable type body")?;
    let uncommon = reader.uncommon_at(&header).and_then(|at| reader.uncommon(at));
    let package = uncommon.as_ref().and_then(|uncommon| uncommon.package.clone());
    let mut definition = GoTypeDefinition {
        kind: kind_name(header.kind),
        qualified_name: package
            .as_deref()
            .filter(|_| header.tflag & TFLAG_NAMED != 0)
            .and_then(|package| qualified(&header.name, package)),
        type_name: header.name.clone(),
        package,
        named: header.tflag & TFLAG_NAMED != 0,
        byte_size: header.size,
        align: header.align,
        descriptor: address,
        elem: None,
        key: None,
        len: None,
        dir: None,
        signature: None,
        selection: None,
        members: Vec::new(),
        total: 0,
        next_offset: None,
        methods: Vec::new(),
        methods_total: 0,
    };
    match body {
        Body::Array { elem, len } => {
            definition.elem = Some(type_name(reader, elem));
            definition.len = Some(len);
        }
        Body::Chan { elem, dir } => {
            definition.elem = Some(type_name(reader, elem));
            definition.dir = Some(match dir {
                1 => "recv",
                2 => "send",
                _ => "both",
            });
        }
        Body::Elem(elem) => definition.elem = Some(type_name(reader, elem)),
        Body::Map { key, elem } => {
            definition.key = Some(type_name(reader, key));
            definition.elem = Some(type_name(reader, elem));
        }
        Body::Func { inputs, outputs, variadic, params } => {
            definition.signature = Some(signature(reader, inputs, outputs, variadic, params));
        }
        Body::Interface { methods, count } => {
            definition.methods_total = count as usize;
            for index in 0..count.min(MAX_METHODS as u64) {
                let (name, ty) = reader.imethod(methods, index).ok_or("undecodable interface method")?;
                let type_name = ty.map(|ty| type_name(reader, ty));
                definition.methods.push(GoMethod {
                    name: name.text,
                    type_name,
                    exported: name.exported,
                    address: None,
                });
            }
        }
        Body::Struct { count, .. } => {
            definition.total = count as usize;
            let end = request.offset.saturating_add(request.limit).min(count as usize);
            let mut budget = MAX_OUTPUT_MEMBERS;
            let mut next = end;
            for index in request.offset..end {
                if budget == 0 {
                    next = index;
                    break;
                }
                let member = member(reader, &header, index as u64, request.depth, &mut budget)
                    .ok_or("undecodable struct field")?;
                definition.members.push(member);
            }
            definition.next_offset = (next < count as usize && request.limit > 0).then_some(next);
        }
        Body::Basic => {}
    }
    if let Some(uncommon) = uncommon {
        definition.methods_total += uncommon.mcount as usize;
        for index in 0..uncommon.mcount.min(MAX_METHODS as u64) {
            let Some((name, ty, code)) = reader.method(uncommon.methods, index) else { break };
            let type_name = ty.map(|ty| type_name(reader, ty));
            definition.methods.push(GoMethod { name: name.text, type_name, exported: name.exported, address: code });
        }
    }
    if let Some(path) = request.member.as_deref() {
        definition.selection = Some(select_path(reader, &header, path)?);
    } else if let Some(offset) = request.byte_offset {
        definition.selection = Some(select_offset(reader, &header, offset)?);
    }
    Ok(definition)
}

fn signature(reader: &mut Reader<'_>, inputs: u64, outputs: u64, variadic: bool, params: u64) -> GoSignature {
    let u = reader.layout.ptr as u64;
    let mut names = |range: Range<u64>| -> Vec<String> {
        range
            .take(MAX_METHODS)
            .map(|index| match reader.word(params + index * u) {
                Some(ty) => type_name(reader, ty),
                None => "<unreadable>".to_owned(),
            })
            .collect()
    };
    let params = names(0..inputs);
    let results = names(inputs..inputs + outputs);
    GoSignature { params, results, variadic }
}

fn member(reader: &mut Reader<'_>, parent: &Header, index: u64, depth: usize, budget: &mut usize) -> Option<GoMember> {
    *budget = budget.checked_sub(1)?;
    let Body::Struct { fields, .. } = reader.body(parent)? else { return None };
    let field = reader.field(fields, index)?;
    let header = reader.header(field.ty);
    let mut member = GoMember {
        name: field.name.text,
        offset: field.offset,
        byte_size: header.as_ref().map(|header| header.size),
        type_name: header.as_ref().map_or_else(|| format!("<type {:#x}>", field.ty), |header| header.name.clone()),
        embedded: field.embedded,
        exported: field.name.exported,
        tag: field.name.tag,
        members: Vec::new(),
    };
    if depth > 0
        && let Some(header) = header.filter(|header| header.kind == KIND_STRUCT)
        && let Some(Body::Struct { count, .. }) = reader.body(&header)
    {
        for index in 0..count {
            if *budget == 0 {
                break;
            }
            member.members.push(self::member(reader, &header, index, depth - 1, budget)?);
        }
    }
    Some(member)
}

/// Selects `path` (`a.b`, `a[2].b`) from the struct at `root`.
fn select_path(reader: &mut Reader<'_>, root: &Header, path: &str) -> Result<GoMemberSelection, String> {
    let mut current = reader.header(root.address).ok_or("undecodable type")?;
    let mut offset = 0u64;
    let mut steps = 0;
    let mut parts = Vec::new();
    for segment in path.split('.') {
        let (field, indices) = match segment.find('[') {
            Some(at) => (&segment[..at], &segment[at..]),
            None => (segment, ""),
        };
        parts.push((field, indices));
    }
    for (field_name, indices) in parts {
        steps += 1;
        if steps > MAX_SELECTION_DEPTH {
            return Err("member path is too deep".into());
        }
        if !field_name.is_empty() {
            let Some(Body::Struct { fields, count }) = reader.body(&current) else {
                return Err(format!("{} is not a struct; cannot select {field_name:?}", current.name));
            };
            let (field_offset, ty) = find_field(reader, fields, count, field_name)?
                .ok_or_else(|| format!("{} has no field {field_name:?}", current.name))?;
            offset = offset.checked_add(field_offset).ok_or("member offset overflows")?;
            current = reader.header(ty).ok_or("undecodable field type")?;
        }
        let mut rest = indices;
        while let Some(stripped) = rest.strip_prefix('[') {
            let close = stripped.find(']').ok_or("unclosed [ in member path")?;
            let index: u64 = stripped[..close].trim().parse().map_err(|_| "array index is not a number")?;
            rest = &stripped[close + 1..];
            let Some(Body::Array { elem, len }) = reader.body(&current) else {
                return Err(format!("{} is not an array", current.name));
            };
            if index >= len {
                return Err(format!("index {index} is past the end of {}", current.name));
            }
            let elem = reader.header(elem).ok_or("undecodable element type")?;
            offset = index
                .checked_mul(elem.size)
                .and_then(|delta| offset.checked_add(delta))
                .ok_or("member offset overflows")?;
            current = elem;
        }
        if !rest.is_empty() {
            return Err(format!("unexpected {rest:?} in member path"));
        }
    }
    Ok(GoMemberSelection {
        path: path.to_owned(),
        offset,
        byte_size: current.size,
        type_name: current.name,
        within: None,
        padding: false,
    })
}

/// The offset and type of field `name`, directly or promoted through embedded structs. Like Go's selector
/// resolution this is breadth-first: the shallowest depth with a match wins, and two matches at that depth are
/// ambiguous.
fn find_field(reader: &mut Reader<'_>, fields: u64, count: u64, name: &str) -> Result<Option<(u64, u64)>, String> {
    let mut level = vec![(0u64, fields, count)];
    for _ in 0..=MAX_LOOKUP_DEPTH {
        let mut found = Vec::new();
        let mut next = Vec::new();
        for &(base, fields, count) in &level {
            for index in 0..count {
                let field = reader.field(fields, index).ok_or("undecodable struct field")?;
                let offset = base.checked_add(field.offset).ok_or("field offset overflows")?;
                if field.name.text == name {
                    found.push((offset, field.ty));
                } else if field.embedded
                    && let Some(header) = reader.header(field.ty)
                    && let Some(Body::Struct { fields, count }) = reader.body(&header)
                {
                    next.push((offset, fields, count));
                }
            }
        }
        match found.len() {
            0 if next.is_empty() => return Ok(None),
            0 => level = next,
            1 => return Ok(found.pop()),
            _ => return Err(format!("field {name:?} is ambiguous: promoted from {} embedded fields", found.len())),
        }
    }
    Ok(None)
}

/// Selects the innermost field of `root` covering `target`.
fn select_offset(reader: &mut Reader<'_>, root: &Header, target: u64) -> Result<GoMemberSelection, String> {
    if target >= root.size {
        return Err(format!("byte_offset {target:#x} is past the end of {} ({} bytes)", root.name, root.size));
    }
    let mut current = reader.header(root.address).ok_or("undecodable type")?;
    let (mut base, mut path, mut padding) = (0u64, String::new(), false);
    for _ in 0..MAX_SELECTION_DEPTH {
        match reader.body(&current) {
            Some(Body::Struct { fields, count }) => {
                let mut chosen = None;
                for index in 0..count {
                    let field = reader.field(fields, index).ok_or("undecodable struct field")?;
                    let start = base.checked_add(field.offset).ok_or("field offset overflows")?;
                    if start > target {
                        break;
                    }
                    chosen = Some((field, start));
                }
                let Some((field, start)) = chosen else { break };
                let header = reader.header(field.ty).ok_or("undecodable field type")?;
                if target >= start.checked_add(header.size).ok_or("field size overflows")? {
                    if !path.is_empty() {
                        path.push('.');
                    }
                    path.push_str(&field.name.text);
                    base = start;
                    current = header;
                    padding = true;
                    break;
                }
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(&field.name.text);
                base = start;
                current = header;
            }
            Some(Body::Array { elem, len }) if len > 0 => {
                let elem = reader.header(elem).ok_or("undecodable element type")?;
                if elem.size == 0 {
                    break;
                }
                let index = ((target - base) / elem.size).min(len - 1);
                path.push_str(&format!("[{index}]"));
                base = index
                    .checked_mul(elem.size)
                    .and_then(|delta| base.checked_add(delta))
                    .ok_or("element offset overflows")?;
                current = elem;
            }
            _ => break,
        }
    }
    if path.is_empty() {
        return Err(format!("{} has no field at byte_offset {target:#x}", root.name));
    }
    Ok(GoMemberSelection {
        path,
        offset: base,
        byte_size: current.size,
        type_name: current.name,
        within: Some(target - base),
        padding,
    })
}

#[cfg(test)]
#[path = "gotypes_tests.rs"]
mod tests;
