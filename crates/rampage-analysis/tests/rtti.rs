//! Parser tests over hand-built synthetic RTTI structures, in the style of the signatures crate's hand-built
//! instruction bytes: little-endian 32- and 64-bit blobs, with no real binary required.

use rampage_analysis::rtti::{Image, MappedRange, recover_itanium, recover_msvc};

/// Appends little-endian RTTI structures at a chosen base virtual address, tracking emitted addresses.
struct Blob {
    base: u64,
    pointer_size: u8,
    bytes: Vec<u8>,
}

impl Blob {
    fn new(base: u64, pointer_size: u8) -> Self {
        Blob { base, pointer_size, bytes: Vec::new() }
    }

    fn here(&self) -> u64 {
        self.base + self.bytes.len() as u64
    }

    fn ptr(&mut self, value: u64) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes()[..usize::from(self.pointer_size)]);
        self
    }

    fn u32(&mut self, value: u32) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    fn zeros(&mut self, count: usize) -> &mut Self {
        self.bytes.resize(self.bytes.len() + count, 0);
        self
    }

    fn cstr(&mut self, text: &str) -> u64 {
        let address = self.here();
        self.bytes.extend_from_slice(text.as_bytes());
        self.bytes.push(0);
        address
    }

    fn align(&mut self) {
        let width = usize::from(self.pointer_size);
        while !self.bytes.len().is_multiple_of(width) {
            self.bytes.push(0);
        }
    }

    fn image(&self) -> Image<'_> {
        Image::new(vec![MappedRange { vaddr: self.base, bytes: &self.bytes }], self.pointer_size, false)
    }
}

/// Finds a recovered class by name, failing with the full set when it is missing.
fn class<'a>(classes: &'a [rampage_analysis::rtti::RttiClass], name: &str) -> &'a rampage_analysis::rtti::RttiClass {
    classes
        .iter()
        .find(|class| class.name == name)
        .unwrap_or_else(|| panic!("missing {name}; got {:?}", classes.iter().map(|c| &c.name).collect::<Vec<_>>()))
}

#[test]
fn itanium_single_inheritance_64bit() {
    let mut blob = Blob::new(0x4000, 8);
    let vtable = blob.here();
    blob.zeros(16); // a mapped stand-in for a typeinfo category vtable (not a name string)
    let name_base = blob.cstr("4Base");
    let name_derived = blob.cstr("7Derived");
    blob.align();
    let base = blob.here();
    blob.ptr(vtable).ptr(name_base); // __class_type_info: [vtable, name]
    let derived = blob.here();
    blob.ptr(vtable).ptr(name_derived).ptr(base); // __si_class_type_info: [vtable, name, base]

    let classes = recover_itanium(&blob.image());
    assert_eq!(classes.len(), 2, "{classes:?}");
    assert!(class(&classes, "Base").bases.is_empty());
    let derived_class = class(&classes, "Derived");
    assert_eq!(derived_class.bases, ["Base"]);
    assert_eq!(derived_class.type_info, derived);
    assert_eq!(derived_class.abi, "itanium");
}

#[test]
fn itanium_multiple_inheritance_32bit() {
    let mut blob = Blob::new(0x8000, 4);
    let vtable = blob.here();
    blob.zeros(12);
    let name_a = blob.cstr("1A");
    let name_b = blob.cstr("1B");
    let name_multi = blob.cstr("5Multi");
    blob.align();
    let base_a = blob.here();
    blob.ptr(vtable).ptr(name_a);
    let base_b = blob.here();
    blob.ptr(vtable).ptr(name_b);
    let multi = blob.here();
    // __vmi_class_type_info: [vtable, name, flags, base_count, (base_ti, offset_flags) * count]
    blob.ptr(vtable).ptr(name_multi).u32(0).u32(2);
    blob.ptr(base_a).ptr(0x0002_0000);
    blob.ptr(base_b).ptr(0x0004_0002);

    let classes = recover_itanium(&blob.image());
    assert_eq!(classes.len(), 3, "{classes:?}");
    assert_eq!(class(&classes, "Multi").bases, ["A", "B"]);
    assert_eq!(class(&classes, "Multi").type_info, multi);
    assert!(class(&classes, "A").bases.is_empty());
}

#[test]
fn itanium_shared_vtable_fallback_recovers_externally_bound_records() {
    // Stripped dynamic images leave the typeinfo category vtable pointer unresolved (zero on disk). Records are
    // then anchored by sharing that pointer value rather than by dereferencing it.
    let mut blob = Blob::new(0x5000, 8);
    let names: Vec<u64> = ["5Alpha", "4Beta", "5Gamma"].iter().map(|n| blob.cstr(n)).collect();
    blob.align();
    for &name in &names {
        blob.ptr(0).ptr(name); // [vtable = 0 (unbound), name]
    }
    let classes = recover_itanium(&blob.image());
    let mut recovered: Vec<&str> = classes.iter().map(|c| c.name.as_str()).collect();
    recovered.sort_unstable();
    assert_eq!(recovered, ["Alpha", "Beta", "Gamma"]);
}

#[test]
fn itanium_lone_unbound_record_is_not_guessed() {
    // A single [vtable = 0, name] shape, with neither a mapped vtable nor shared support, stays unrecovered.
    let mut blob = Blob::new(0x6000, 8);
    let name = blob.cstr("4Solo");
    blob.align();
    blob.ptr(0).ptr(name);
    assert!(recover_itanium(&blob.image()).is_empty());
}

/// Writes an MSVC `TypeDescriptor` and returns its address; `vftable` must be a mapped, non-zero pointer.
fn type_descriptor(blob: &mut Blob, vftable: u64, name: &str) -> u64 {
    blob.align();
    let address = blob.here();
    blob.ptr(vftable).ptr(0);
    blob.bytes.extend_from_slice(name.as_bytes());
    blob.bytes.push(0);
    address
}

/// Writes a `BaseClassDescriptor` whose only field this parser reads is its type descriptor cross-reference.
fn base_descriptor(blob: &mut Blob, type_descriptor_ref: u32) -> u64 {
    blob.align();
    let address = blob.here();
    blob.u32(type_descriptor_ref).u32(0).u32(0).u32(0).u32(0).u32(0); // pTD, numContained, PMD(3), attributes
    address
}

#[test]
fn msvc_single_inheritance_32bit_pointers() {
    // Signature 0: all cross-references are full 32-bit virtual-address pointers.
    let mut blob = Blob::new(0x0040_1000, 4);
    let vftable = blob.here();
    blob.zeros(8);
    let td_base = type_descriptor(&mut blob, vftable, ".?AVBase@@");
    let td_derived = type_descriptor(&mut blob, vftable, ".?AVDerived@@");
    let bcd_derived = base_descriptor(&mut blob, td_derived as u32);
    let bcd_base = base_descriptor(&mut blob, td_base as u32);
    blob.align();
    let array = blob.here();
    blob.u32(bcd_derived as u32).u32(bcd_base as u32); // first entry is the class itself
    blob.align();
    let chd = blob.here();
    blob.u32(0).u32(0).u32(2).u32(array as u32); // signature, attributes, numBaseClasses, pBaseClassArray
    let base_chd = {
        blob.align();
        let base_array = blob.here();
        blob.u32(bcd_base as u32);
        blob.align();
        let address = blob.here();
        blob.u32(0).u32(0).u32(1).u32(base_array as u32);
        address
    };
    blob.align();
    blob.u32(0).u32(0).u32(0).u32(td_derived as u32).u32(chd as u32); // Complete Object Locator for Derived
    blob.align();
    blob.u32(0).u32(0).u32(0).u32(td_base as u32).u32(base_chd as u32); // and for Base

    let classes = recover_msvc(&blob.image());
    assert_eq!(classes.len(), 2, "{classes:?}");
    assert_eq!(class(&classes, "Derived").bases, ["Base"]);
    assert_eq!(class(&classes, "Derived").abi, "msvc");
    assert_eq!(class(&classes, "Derived").type_info, td_derived);
    assert!(class(&classes, "Base").bases.is_empty());
}

#[test]
fn msvc_single_inheritance_64bit_image_relative() {
    // Signature 1: cross-references are 32-bit RVAs, resolved against the image base recovered from the
    // locator's self RVA. The type descriptor vftable stays a full 64-bit pointer.
    let image_base = 0x1_4000_0000;
    let mut blob = Blob::new(image_base + 0x1000, 8);
    let rva = |address: u64| (address - image_base) as u32;
    let vftable = blob.here();
    blob.zeros(16);
    let td_base = type_descriptor(&mut blob, vftable, ".?AUBase@@");
    let td_derived = type_descriptor(&mut blob, vftable, ".?AUDerived@@");
    let bcd_derived = base_descriptor(&mut blob, rva(td_derived));
    let bcd_base = base_descriptor(&mut blob, rva(td_base));
    blob.align();
    let array = blob.here();
    blob.u32(rva(bcd_derived)).u32(rva(bcd_base));
    blob.align();
    let chd = blob.here();
    blob.u32(1).u32(0).u32(2).u32(rva(array));
    blob.align();
    let col = blob.here();
    blob.u32(1).u32(0).u32(0).u32(rva(td_derived)).u32(rva(chd)).u32(rva(col)); // last field is the self RVA

    let classes = recover_msvc(&blob.image());
    assert_eq!(classes.len(), 1, "{classes:?}");
    assert_eq!(class(&classes, "Derived").bases, ["Base"]);
    assert_eq!(class(&classes, "Derived").type_info, td_derived);
}

#[test]
fn non_rtti_bytes_recover_nothing() {
    let base = 0x3000;
    let bytes: Vec<u8> = (0..4096).map(|index| (index * 37 + 11) as u8).collect();
    let image = Image::new(vec![MappedRange { vaddr: base, bytes: &bytes }], 8, false);
    assert!(recover_itanium(&image).is_empty());
    assert!(recover_msvc(&image).is_empty());

    let image32 = Image::new(vec![MappedRange { vaddr: base, bytes: &bytes }], 4, false);
    assert!(recover_itanium(&image32).is_empty());
    assert!(recover_msvc(&image32).is_empty());
}
