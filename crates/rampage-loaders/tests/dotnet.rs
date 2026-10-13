use std::path::PathBuf;

use rampage_loaders::dotnet::{self, BodyKind, ClauseKind, EntryPoint, IlError, IlHeader, MethodSelector};
use rampage_loaders::{Binary, LoadError};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
}

/// Knobs for the synthetic assembly; the default is a small, well-formed one.
#[derive(Debug, Clone, Default)]
struct Spec {
    wide_strings: bool,
    wide_guids: bool,
    wide_blobs: bool,
    /// Extra TypeRef rows, to push coded indexes that can select TypeRef past their 2-byte limit.
    extra_type_refs: u32,
    /// Replaces the TypeDef row count in the table stream header.
    declared_type_defs: Option<u32>,
    /// Bytes cut from the end of the `#~` stream (its header size shrinks; the data stays put).
    table_stream_cut: u32,
    /// Points the first method's name past the end of `#Strings`.
    bad_method_name: bool,
    signature: Option<u32>,
    /// Replaces the metadata RVA in the CLI header.
    metadata_rva: Option<u32>,
    /// Replaces the MethodList column of the three TypeDef rows.
    method_lists: Option<[u32; 3]>,
    /// Puts an empty `#~` and a junk `#Strings` before the real streams, the decoys obfuscators plant.
    decoy_streams: bool,
    /// An uncompressed `#-` table stream beside a `#JTD` stream, which makes every index 4 bytes wide.
    jtd: bool,
    /// Replaces Main's method signature blob.
    main_signature: Option<Vec<u8>>,
    /// Replaces the custom attribute's value blob.
    attribute_value: Option<Vec<u8>>,
    /// HasCustomAttribute values, one attribute row each; empty means one attribute on the Module.
    attribute_parents: Vec<u32>,
    /// Replaces the ResolutionScope of the extra TypeRef rows (AssemblyRef 1).
    pad_scope: Option<u32>,
    /// Replaces the base type of Inner (TypeRef 1).
    inner_extends: Option<u32>,
}

const SECTION_RVA: u32 = 0x2000;
const SECTION_FILE: usize = 0x200;
const IMAGE_BASE: u32 = 0x1000_0000;

struct Heap {
    bytes: Vec<u8>,
}

impl Heap {
    fn new() -> Self {
        Self { bytes: vec![0] }
    }

    fn string(&mut self, text: &str) -> u32 {
        let offset = self.bytes.len() as u32;
        self.bytes.extend_from_slice(text.as_bytes());
        self.bytes.push(0);
        offset
    }

    fn blob(&mut self, data: &[u8]) -> u32 {
        let offset = self.bytes.len() as u32;
        assert!(data.len() < 0x80, "builder writes only 1-byte blob lengths");
        self.bytes.push(data.len() as u8);
        self.bytes.extend_from_slice(data);
        offset
    }
}

struct Rows {
    bytes: Vec<u8>,
}

impl Rows {
    fn put(&mut self, value: u32, width: usize) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes()[..width]);
        self
    }
}

fn pad4(bytes: &mut Vec<u8>) {
    while !bytes.len().is_multiple_of(4) {
        bytes.push(0);
    }
}

/// Builds a managed PE32 DLL byte by byte: a CLI header (II.25.3.3), two IL method bodies (II.25.4), and a
/// metadata root (II.24.2.1) with `#~`, `#Strings`, `#US`, `#GUID` and `#Blob` streams. The tables follow
/// II.22, with column widths chosen by the II.24.2.6 rules the reader must reproduce.
fn build(spec: &Spec) -> Vec<u8> {
    let mut strings = Heap::new();
    let mut blobs = Heap::new();
    let field_signature = blobs.blob(&[0x06, 0x08]);
    // Main(string[]), Compute<T>(T, T) returning int32, Helper(), Run(native int) returning int32.
    let main_signature = blobs.blob(spec.main_signature.as_deref().unwrap_or(&[0x00, 1, 0x01, 0x1D, 0x0E]));
    let compute_signature = blobs.blob(&[0x10, 1, 2, 0x08, 0x1E, 0, 0x1E, 0]);
    let helper_signature = blobs.blob(&[0x00, 0, 0x01]);
    let run_signature = blobs.blob(&[0x00, 1, 0x08, 0x18]);
    // Object::.ctor(string, int32) as an instance method, and an attribute value calling it with ("abc", 42).
    let ctor_signature = blobs.blob(&[0x20, 2, 0x01, 0x0E, 0x08]);
    let attribute_value =
        blobs.blob(spec.attribute_value.as_deref().unwrap_or(&[0x01, 0x00, 3, b'a', b'b', b'c', 42, 0, 0, 0, 0, 0]));
    let token_blob = blobs.blob(&[0xb0, 0x3f, 0x5f, 0x7f, 0x11, 0xd5, 0x0a, 0x3a]);
    // Compute's locals (int32, T) and the instantiation Compute<int32>.
    let locals_signature = blobs.blob(&[0x07, 2, 0x08, 0x1E, 0]);
    let instantiation = blobs.blob(&[0x0A, 1, 0x08]);
    let guids: Vec<u8> = (1..=16).collect();
    let mut user_strings = vec![0u8, 11];
    for unit in "hello".encode_utf16() {
        user_strings.extend_from_slice(&unit.to_le_bytes());
    }
    user_strings.push(0);

    let wide = |set: bool| if set || spec.jtd { 4 } else { 2 };
    let (s, g, b, i) = (wide(spec.wide_strings), wide(spec.wide_guids), wide(spec.wide_blobs), wide(false));
    let type_refs = 1 + spec.extra_type_refs;
    // TypeDefOrRef and ResolutionScope have 2 tag bits, MemberRefParent 3, HasCustomAttribute 5.
    let coded = |tag_bits: u32| wide(type_refs >= (1 << (16 - tag_bits)));
    let (tdor, scope, mrp, hca) = (coded(2), coded(2), coded(3), coded(5));

    // Bodies live after the 72-byte CLI header.
    let tiny_rva = SECTION_RVA + 72;
    let tiny = [0x0E, 0x16, 0x26, 0x2A];
    let fat_rva = tiny_rva + 4;
    // Fat, locals StandAloneSig 1, code `call Compute<int32>` (MethodSpec 1).
    let fat = [0x13, 0x30, 0x02, 0x00, 0x05, 0, 0, 0, 0x01, 0, 0, 0x11, 0x28, 0x01, 0x00, 0x00, 0x2B];
    let native_rva = fat_rva + 20;
    let metadata_rva = native_rva + 4;

    let mut tables = Rows { bytes: Vec::new() };
    // Module
    let module_name = strings.string("Demo.dll");
    tables.put(0, 2).put(module_name, s).put(1, g).put(0, g).put(0, g);
    // TypeRef: row 1 is System.Object in AssemblyRef 1 (ResolutionScope tag 2).
    let (object_name, system) = (strings.string("Object"), strings.string("System"));
    tables.put((1 << 2) | 2, scope).put(object_name, s).put(system, s);
    let pad_name = strings.string("Pad");
    for _ in 0..spec.extra_type_refs {
        tables.put(spec.pad_scope.unwrap_or((1 << 2) | 2), scope).put(pad_name, s).put(system, s);
    }
    // TypeDef: <Module>, Demo.Program extends TypeRef 1 (TypeDefOrRef tag 1), and Inner nested in Program.
    let (module_type, program, demo, inner) =
        (strings.string("<Module>"), strings.string("Program"), strings.string("Demo"), strings.string("Inner"));
    let method_lists = spec.method_lists.unwrap_or([1, 1, 5]);
    tables.put(0, 4).put(module_type, s).put(0, s).put(0, tdor).put(1, i).put(method_lists[0], i);
    tables.put(0x0010_0001, 4).put(program, s).put(demo, s).put((1 << 2) | 1, tdor).put(1, i).put(method_lists[1], i);
    let inner_extends = spec.inner_extends.unwrap_or((1 << 2) | 1);
    tables.put(0x0010_0002, 4).put(inner, s).put(0, s).put(inner_extends, tdor).put(2, i).put(method_lists[2], i);
    // Field
    let counter = strings.string("counter");
    tables.put(0x0001, 2).put(counter, s).put(field_signature, b);
    // MethodDef: Main (tiny IL), Compute (fat IL), Helper (native), Run (abstract, no body).
    let main = if spec.bad_method_name { 0xFFFF } else { strings.string("Main") };
    let (compute, helper, run) = (strings.string("Compute"), strings.string("Helper"), strings.string("Run"));
    tables.put(tiny_rva, 4).put(0, 2).put(0x0016, 2).put(main, s).put(main_signature, b).put(1, i);
    tables.put(fat_rva, 4).put(0, 2).put(0x0006, 2).put(compute, s).put(compute_signature, b).put(2, i);
    tables.put(native_rva, 4).put(0x0001, 2).put(0x0016, 2).put(helper, s).put(helper_signature, b).put(5, i);
    // Run is static pinvokeimpl (0x2000) and has no body.
    tables.put(0, 4).put(0, 2).put(0x2096, 2).put(run, s).put(run_signature, b).put(5, i);
    // Param: Main(args); Compute's return row (sequence 0) and its parameters stored out of order.
    let (args, x, y) = (strings.string("args"), strings.string("x"), strings.string("y"));
    tables.put(0, 2).put(1, 2).put(args, s);
    tables.put(0, 2).put(0, 2).put(0, s);
    tables.put(0, 2).put(2, 2).put(y, s);
    tables.put(0, 2).put(1, 2).put(x, s);
    // MemberRef: Object::.ctor (MemberRefParent tag 1 = TypeRef).
    let ctor = strings.string(".ctor");
    tables.put((1 << 3) | 1, mrp).put(ctor, s).put(ctor_signature, b);
    // CustomAttribute on the Module (HasCustomAttribute tag 7) by default, constructed by MemberRef 1 (tag 3).
    let attribute_parents =
        if spec.attribute_parents.is_empty() { vec![(1 << 5) | 7] } else { spec.attribute_parents.clone() };
    for &parent in &attribute_parents {
        tables.put(parent, hca).put((1 << 3) | 3, i).put(attribute_value, b);
    }
    // StandAloneSig: Compute's locals.
    tables.put(locals_signature, b);
    // EventMap and PropertyMap give Program (TypeDef 2) the event Changed (of type Object) and the property Count.
    let (changed, count) = (strings.string("Changed"), strings.string("Count"));
    tables.put(2, i).put(1, i);
    tables.put(0, 2).put(changed, s).put((1 << 2) | 1, tdor);
    tables.put(2, i).put(1, i);
    tables.put(0, 2).put(count, s).put(field_signature, b);
    // ModuleRef, and ImplMap binding Run (MemberForwarded tag 1 = MethodDef) to native.dll!RunNative.
    let (native_dll, run_native) = (strings.string("native.dll"), strings.string("RunNative"));
    tables.put(native_dll, s);
    tables.put(0x0100, 2).put((4 << 1) | 1, i).put(run_native, s).put(1, i);
    // Assembly
    let demo_assembly = strings.string("Demo");
    tables.put(0x8004, 4).put(1, 2).put(2, 2).put(3, 2).put(4, 2).put(0, 4).put(0, b).put(demo_assembly, s).put(0, s);
    // AssemblyRef
    let mscorlib = strings.string("mscorlib");
    tables.put(4, 2).put(0, 2).put(0, 2).put(0, 2).put(0, 4).put(token_blob, b).put(mscorlib, s).put(0, s).put(0, b);
    // NestedClass: Inner (TypeDef 3) inside Program (TypeDef 2).
    tables.put(3, i).put(2, i);
    // GenericParam: Compute's T (TypeOrMethodDef tag 1 = MethodDef 2).
    let t = strings.string("T");
    tables.put(0, 2).put(0, 2).put((2 << 1) | 1, i).put(t, s);
    // MethodSpec: Compute (MethodDefOrRef tag 0 = MethodDef 2) instantiated with int32.
    tables.put(2 << 1, i).put(instantiation, b);

    let present: [(u8, u32); 20] = [
        (0x00, 1),
        (0x01, type_refs),
        (0x02, spec.declared_type_defs.unwrap_or(3)),
        (0x04, 1),
        (0x06, 4),
        (0x08, 4),
        (0x0A, 1),
        (0x0C, attribute_parents.len() as u32),
        (0x11, 1),
        (0x12, 1),
        (0x14, 1),
        (0x15, 1),
        (0x17, 1),
        (0x1A, 1),
        (0x1C, 1),
        (0x20, 1),
        (0x23, 1),
        (0x29, 1),
        (0x2A, 1),
        (0x2B, 1),
    ];
    let heap_sizes = u8::from(spec.wide_strings) | (u8::from(spec.wide_guids) << 1) | (u8::from(spec.wide_blobs) << 2);
    let mut table_stream = vec![0, 0, 0, 0, 2, 0, heap_sizes, 1];
    let valid = present.iter().fold(0u64, |mask, &(id, _)| mask | (1 << id));
    table_stream.extend_from_slice(&valid.to_le_bytes());
    table_stream.extend_from_slice(&0u64.to_le_bytes());
    for &(_, rows) in &present {
        table_stream.extend_from_slice(&rows.to_le_bytes());
    }
    table_stream.extend_from_slice(&tables.bytes);
    pad4(&mut table_stream);
    pad4(&mut strings.bytes);
    pad4(&mut blobs.bytes);
    pad4(&mut user_strings);

    let version = b"v4.0.30319\0\0";
    let empty_tables = [0, 0, 0, 0, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let decoys: [(&str, &[u8]); 2] = [("#~", &empty_tables), ("#Strings", b"\0Decoy\0\0")];
    let mut streams: Vec<(&str, &[u8])> = if spec.decoy_streams { decoys.to_vec() } else { Vec::new() };
    if spec.jtd {
        streams.push(("#JTD", &[]));
    }
    streams.extend([
        (if spec.jtd { "#-" } else { "#~" }, table_stream.as_slice()),
        ("#Strings", &strings.bytes),
        ("#US", &user_strings),
        ("#GUID", &guids),
        ("#Blob", &blobs.bytes),
    ]);
    let header_len = 16
        + version.len()
        + 4
        + streams.iter().map(|(name, _)| 8 + (name.len() + 1).next_multiple_of(4)).sum::<usize>();
    let mut root = Vec::new();
    root.extend_from_slice(&spec.signature.unwrap_or(0x424A_5342).to_le_bytes());
    root.extend_from_slice(&[1, 0, 1, 0, 0, 0, 0, 0]);
    root.extend_from_slice(&(version.len() as u32).to_le_bytes());
    root.extend_from_slice(version);
    root.extend_from_slice(&[0, 0]);
    root.extend_from_slice(&(streams.len() as u16).to_le_bytes());
    let mut offset = header_len;
    for (name, data) in &streams {
        let cut = if data.as_ptr() == table_stream.as_ptr() { spec.table_stream_cut } else { 0 };
        let size = data.len() as u32 - cut;
        root.extend_from_slice(&(offset as u32).to_le_bytes());
        root.extend_from_slice(&size.to_le_bytes());
        root.extend_from_slice(name.as_bytes());
        root.push(0);
        pad4(&mut root);
        offset += data.len();
    }
    assert_eq!(root.len(), header_len);
    for (_, data) in &streams {
        root.extend_from_slice(data);
    }

    let mut section = Vec::new();
    // CLI header: cb, runtime 2.5, metadata directory, flags (IL only), entry point token (Main).
    section.extend_from_slice(&72u32.to_le_bytes());
    section.extend_from_slice(&[2, 0, 5, 0]);
    section.extend_from_slice(&spec.metadata_rva.unwrap_or(metadata_rva).to_le_bytes());
    section.extend_from_slice(&(root.len() as u32).to_le_bytes());
    section.extend_from_slice(&1u32.to_le_bytes());
    section.extend_from_slice(&0x0600_0001u32.to_le_bytes());
    section.resize(72, 0);
    section.extend_from_slice(&tiny);
    section.extend_from_slice(&fat);
    pad4(&mut section);
    section.extend_from_slice(&[0xC3, 0, 0, 0]);
    assert_eq!(section.len() as u32, metadata_rva - SECTION_RVA);
    section.extend_from_slice(&root);
    let raw_size = section.len().next_multiple_of(0x200);
    section.resize(raw_size, 0);

    pe32(&section, SECTION_RVA)
}

/// Wraps one section in a minimal PE32 DLL whose COM descriptor directory points at the section start.
fn pe32(section: &[u8], cli_rva: u32) -> Vec<u8> {
    let mut image = vec![0u8; SECTION_FILE];
    image[0..2].copy_from_slice(b"MZ");
    image[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    let mut nt = Vec::new();
    nt.extend_from_slice(b"PE\0\0");
    // COFF: i386, one section, 0xE0-byte optional header, executable DLL.
    for (value, width) in [(0x14C, 2), (1, 2), (0, 4), (0, 4), (0, 4), (0xE0, 2), (0x2102, 2)] {
        nt.extend_from_slice(&u32::to_le_bytes(value)[..width]);
    }
    let image_size = (SECTION_RVA as usize + section.len()).next_multiple_of(0x1000) as u32;
    let optional: [(u32, usize); 30] = [
        (0x10B, 2),
        (0x0008, 2),
        (section.len() as u32, 4),
        (0, 4),
        (0, 4),
        (0, 4),
        (SECTION_RVA, 4),
        (0, 4),
        (IMAGE_BASE, 4),
        (0x1000, 4),
        (0x200, 4),
        (4, 2),
        (0, 2),
        (0, 2),
        (0, 2),
        (4, 2),
        (0, 2),
        (0, 4),
        (image_size, 4),
        (SECTION_FILE as u32, 4),
        (0, 4),
        (3, 2),
        (0x8540, 2),
        (0x10_0000, 4),
        (0x1000, 4),
        (0x10_0000, 4),
        (0x1000, 4),
        (0, 4),
        (16, 4),
        (0, 0),
    ];
    for (value, width) in optional {
        nt.extend_from_slice(&value.to_le_bytes()[..width]);
    }
    for directory in 0..16 {
        let (rva, size) = if directory == 14 { (cli_rva, 72u32) } else { (0, 0) };
        nt.extend_from_slice(&rva.to_le_bytes());
        nt.extend_from_slice(&size.to_le_bytes());
    }
    nt.extend_from_slice(b".text\0\0\0");
    for value in [section.len() as u32, SECTION_RVA, section.len() as u32, SECTION_FILE as u32, 0, 0, 0] {
        nt.extend_from_slice(&value.to_le_bytes());
    }
    nt.extend_from_slice(&0x6000_0020u32.to_le_bytes());
    image[0x40..0x40 + nt.len()].copy_from_slice(&nt);
    image.extend_from_slice(section);
    image
}

fn parse(spec: &Spec) -> Result<Option<dotnet::DotNetMetadata>, LoadError> {
    dotnet::parse_image(&build(spec))
}

fn program(metadata: &dotnet::DotNetMetadata) -> &dotnet::TypeDef {
    metadata.types.iter().find(|ty| ty.name == "Program").expect("Program type")
}

#[test]
fn reads_a_synthetic_assembly() {
    let metadata = parse(&Spec::default()).unwrap().expect("managed image");
    assert!(metadata.warnings.is_empty(), "unexpected warnings: {:?}", metadata.warnings);
    assert_eq!((metadata.cli.runtime_major, metadata.cli.runtime_minor), (2, 5));
    assert_eq!(metadata.cli.flag_names, ["il_only"]);
    assert_eq!(metadata.runtime_version, "v4.0.30319");
    let names: Vec<&str> = metadata.streams.iter().map(|stream| stream.name.as_str()).collect();
    assert_eq!(names, ["#~", "#Strings", "#US", "#GUID", "#Blob"]);

    let module = metadata.module.as_ref().unwrap();
    assert_eq!(module.name, "Demo.dll");
    assert_eq!(module.mvid.as_deref(), Some("04030201-0605-0807-090a-0b0c0d0e0f10"));
    let assembly = metadata.assembly.as_ref().unwrap();
    assert_eq!((assembly.name.as_str(), assembly.version.as_str()), ("Demo", "1.2.3.4"));
    assert_eq!(assembly.hash_algorithm, 0x8004);
    assert_eq!(assembly.public_key, None);
    assert_eq!(metadata.assembly_refs.len(), 1);
    let mscorlib = &metadata.assembly_refs[0];
    assert_eq!((mscorlib.name.as_str(), mscorlib.version.as_str()), ("mscorlib", "4.0.0.0"));
    assert_eq!(mscorlib.public_key_or_token.as_deref(), Some("b03f5f7f11d50a3a"));
    assert!(!mscorlib.full_public_key);

    assert_eq!(metadata.type_refs[0].name, "Object");
    assert_eq!(metadata.type_refs[0].scope.as_deref(), Some("mscorlib"));
    assert_eq!(metadata.member_refs[0].parent.as_deref(), Some("System.Object"));
    assert_eq!(metadata.member_refs[0].name, ".ctor");
    assert_eq!(metadata.user_strings, ["hello"]);

    assert_eq!(metadata.types.len(), 3);
    assert_eq!(metadata.types[0].name, "<Module>");
    assert!(metadata.types[0].methods.is_empty());
    let program = program(&metadata);
    assert_eq!((program.namespace.as_str(), program.token, program.flags), ("Demo", 0x0200_0002, 0x0010_0001));
    assert_eq!(program.extends.as_deref(), Some("System.Object"));
    let fields: Vec<(&str, &str)> =
        program.fields.iter().map(|field| (field.name.as_str(), field.signature.as_str())).collect();
    assert_eq!(fields, [("counter", "int32 counter")]);
    assert_eq!(program.fields[0].token, 0x0400_0001);
    let signatures: Vec<&str> = program.methods.iter().map(|method| method.signature.as_str()).collect();
    assert_eq!(
        signatures,
        ["void Main(string[])", "int32 Compute<T>(T, T)", "void Helper()", "int32 Run(native int)"],
        "MVAR takes its name from GenericParam"
    );
    assert_eq!(metadata.member_refs[0].signature, "instance void .ctor(string, int32)");
    assert_eq!(metadata.pinvokes.len(), 1);
    let pinvoke = &metadata.pinvokes[0];
    assert_eq!((pinvoke.method_token, pinvoke.method.as_deref()), (0x0600_0004, Some("Demo.Program::Run")));
    assert_eq!((pinvoke.module.as_deref(), pinvoke.import_name.as_str()), (Some("native.dll"), "RunNative"));
    assert_eq!(pinvoke.flags, 0x0100);
    assert_eq!(metadata.custom_attributes.len(), 1);
    let attribute = &metadata.custom_attributes[0];
    assert_eq!((attribute.parent_token, attribute.parent.as_deref()), (0x0000_0001, Some("Demo.dll")));
    assert_eq!(
        (attribute.attribute_type.as_deref(), attribute.constructor_token),
        (Some("System.Object"), 0x0A00_0001)
    );
    assert_eq!(attribute.arguments.as_deref(), Some(&["\"abc\"".to_owned(), "42".to_owned()][..]));
    assert_eq!(attribute.blob_length, 12);
    let methods: Vec<(&str, BodyKind)> =
        program.methods.iter().map(|method| (method.name.as_str(), method.body)).collect();
    assert_eq!(
        methods,
        [("Main", BodyKind::Il), ("Compute", BodyKind::Il), ("Helper", BodyKind::Native), ("Run", BodyKind::None)]
    );

    let main = &program.methods[0];
    assert_eq!((main.token, main.rva, main.flags), (0x0600_0001, SECTION_RVA + 72, 0x0016));
    let tiny = main.il.unwrap();
    assert_eq!((tiny.header, tiny.header_size, tiny.code_size, tiny.max_stack), (IlHeader::Tiny, 1, 3, 8));
    assert_eq!(main.params, ["args"]);

    let compute = &program.methods[1];
    let fat = compute.il.unwrap();
    assert_eq!((fat.header, fat.header_size, fat.code_size, fat.max_stack), (IlHeader::Fat, 12, 5, 2));
    assert_eq!(fat.local_var_sig_token, 0x1100_0001);
    assert_eq!(compute.params, ["x", "y"], "parameters are ordered by sequence, and the return row is dropped");

    let helper = &program.methods[2];
    assert_eq!((helper.impl_flags, helper.il), (0x0001, None), "a native body is not read as IL");
    assert_eq!(program.methods[3].rva, 0);

    let inner = metadata.types.iter().find(|ty| ty.name == "Inner").unwrap();
    assert_eq!(inner.enclosing, Some(0x0200_0002));
    assert!(inner.fields.is_empty() && inner.methods.is_empty());

    assert_eq!(
        metadata.entry_point,
        Some(EntryPoint::Method { token: 0x0600_0001, method: Some("Demo.Program::Main".into()) })
    );
    let rows: Vec<(&str, u32)> = metadata.tables.iter().map(|table| (table.table.as_str(), table.rows)).collect();
    assert!(rows.contains(&("CustomAttribute", 1)) && rows.contains(&("NestedClass", 1)));
    serde_json::to_string(&metadata).unwrap();
}

#[test]
fn attribute_targets_and_nested_types_name_their_owners() {
    // TypeDef 3, Param 1 and 2, GenericParam 1, Property 1, Event 1 (HasCustomAttribute tags 3, 4, 19, 9, 10).
    let attribute_parents = vec![(3 << 5) | 3, (1 << 5) | 4, (2 << 5) | 4, (1 << 5) | 19, (1 << 5) | 9, (1 << 5) | 10];
    let metadata = parse(&Spec { attribute_parents, ..Spec::default() }).unwrap().unwrap();
    assert!(metadata.warnings.is_empty(), "{:?}", metadata.warnings);
    let parents: Vec<&str> =
        metadata.custom_attributes.iter().filter_map(|attribute| attribute.parent.as_deref()).collect();
    assert_eq!(
        parents,
        [
            "Demo.Program/Inner",
            "Demo.Program::Main/args",
            "Demo.Program::Compute/return",
            "Demo.Program::Compute<T>",
            "Demo.Program::Count",
            "Demo.Program::Changed",
        ]
    );

    // The extra TypeRef is nested in TypeRef 1 (ResolutionScope tag 3), and Inner derives from it.
    let nested = Spec {
        extra_type_refs: 1,
        pad_scope: Some((1 << 2) | 3),
        inner_extends: Some((2 << 2) | 1),
        ..Spec::default()
    };
    let metadata = parse(&nested).unwrap().unwrap();
    assert_eq!(metadata.type_refs[1].scope.as_deref(), Some("System.Object"));
    let inner = metadata.types.iter().find(|ty| ty.name == "Inner").unwrap();
    assert_eq!(inner.extends.as_deref(), Some("System.Object/System.Pad"));
    // A TypeRef scoped to itself stops at the nesting cap.
    let cyclic = Spec { pad_scope: Some((2 << 2) | 3), ..nested };
    let metadata = parse(&cyclic).unwrap().unwrap();
    let inner = metadata.types.iter().find(|ty| ty.name == "Inner").unwrap();
    assert_eq!(inner.extends.as_deref().unwrap().matches("System.Pad").count(), 17);
}

#[test]
fn heap_size_flags_widen_heap_indexes() {
    let narrow = parse(&Spec::default()).unwrap().unwrap();
    for (wide_strings, wide_guids, wide_blobs) in [(true, false, false), (false, true, false), (false, false, true)] {
        let spec = Spec { wide_strings, wide_guids, wide_blobs, ..Spec::default() };
        let wide = parse(&spec).unwrap().unwrap();
        assert!(wide.warnings.is_empty(), "{spec:?}: {:?}", wide.warnings);
        assert_eq!(wide.types, narrow.types, "{spec:?}");
        assert_eq!(wide.assembly, narrow.assembly, "{spec:?}");
        assert_eq!(wide.assembly_refs, narrow.assembly_refs, "{spec:?}");
        assert_eq!(wide.module, narrow.module, "{spec:?}");
        assert_eq!(wide.pinvokes, narrow.pinvokes, "{spec:?}");
        assert_eq!(wide.custom_attributes, narrow.custom_attributes, "{spec:?}");
    }
    let all = Spec { wide_strings: true, wide_guids: true, wide_blobs: true, ..Spec::default() };
    assert_eq!(parse(&all).unwrap().unwrap().types, narrow.types);
}

#[test]
fn coded_indexes_widen_at_the_tag_limit() {
    // TypeDefOrRef and ResolutionScope have 2 tag bits, so they stay 2 bytes up to 16383 rows (II.24.2.6).
    // MemberRefParent and HasCustomAttribute already switched to 4 bytes at 8192 and 2048 rows.
    let narrow = parse(&Spec::default()).unwrap().unwrap();
    for extra_type_refs in [16_382, 16_383] {
        let metadata = parse(&Spec { extra_type_refs, ..Spec::default() }).unwrap().unwrap();
        assert!(metadata.warnings.is_empty(), "{extra_type_refs}: {:?}", metadata.warnings);
        assert_eq!(metadata.type_refs.len() as u32, extra_type_refs + 1);
        assert_eq!(metadata.type_refs.last().unwrap().name, "Pad");
        assert_eq!(metadata.types, narrow.types, "{extra_type_refs}");
        assert_eq!(metadata.member_refs, narrow.member_refs, "{extra_type_refs}");
        assert_eq!(metadata.assembly_refs, narrow.assembly_refs, "{extra_type_refs}");
        assert_eq!(metadata.pinvokes, narrow.pinvokes, "{extra_type_refs}");
        assert_eq!(metadata.custom_attributes, narrow.custom_attributes, "{extra_type_refs}");
    }
}

#[test]
fn loads_through_binary_open() {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("dotnet-synthetic.dll");
    std::fs::write(&path, build(&Spec::default())).unwrap();
    let binary = Binary::open(&path).unwrap();
    let metadata = dotnet::metadata(&binary).unwrap().unwrap();
    assert_eq!(program(&metadata).methods[0].name, "Main");
    // IL is not native code: no method body may become a function start or a symbol.
    let bodies: Vec<u64> = program(&metadata).methods.iter().map(|method| u64::from(IMAGE_BASE + method.rva)).collect();
    assert!(binary.function_starts.iter().all(|start| !bodies.contains(start)));
    assert!(binary.symbols.iter().all(|symbol| !bodies.contains(&symbol.address)));
}

#[test]
fn malformed_variants_degrade_without_panicking() {
    let bad_name = parse(&Spec { bad_method_name: true, ..Spec::default() }).unwrap().unwrap();
    assert_eq!(program(&bad_name).methods[0].name, "");
    assert!(bad_name.warnings.iter().any(|warning| warning.contains("outside #Strings")));

    let absurd = parse(&Spec { declared_type_defs: Some(u32::MAX), ..Spec::default() }).unwrap().unwrap();
    assert!(absurd.warnings.iter().any(|warning| warning.contains("TypeDef table declares")));
    assert!(absurd.assembly.is_none(), "tables after an unlocatable one are not guessed at");

    let cut = parse(&Spec { table_stream_cut: 40, ..Spec::default() }).unwrap().unwrap();
    assert!(!cut.warnings.is_empty());
    assert_eq!(cut.module.as_ref().unwrap().name, "Demo.dll", "tables before the cut still decode");

    let signature = parse(&Spec { signature: Some(0x1234_5678), ..Spec::default() });
    assert!(matches!(signature, Err(LoadError::Malformed(_))));
    let unmapped = parse(&Spec { metadata_rva: Some(0x7000_0000), ..Spec::default() });
    assert!(matches!(unmapped, Err(LoadError::Malformed(_))));
}

#[test]
fn out_of_order_member_lists_hand_out_each_member_once() {
    // A naive reader gives <Module> rows 1..5, Program nothing (5 > 1), then Inner rows 1..5 again: repeated
    // across many TypeDefs, the output grows as types times methods from a tiny file.
    let metadata = parse(&Spec { method_lists: Some([1, 5, 1]), ..Spec::default() }).unwrap().unwrap();
    let methods: Vec<u32> = metadata.types.iter().flat_map(|ty| &ty.methods).map(|method| method.token).collect();
    assert_eq!(methods, [0x0600_0001, 0x0600_0002, 0x0600_0003, 0x0600_0004]);
    assert!(metadata.warnings.iter().any(|warning| warning.contains("out of order")), "{:?}", metadata.warnings);
}

#[test]
fn the_last_of_duplicate_streams_wins_as_in_the_clr() {
    let normal = parse(&Spec::default()).unwrap().unwrap();
    let decoyed = parse(&Spec { decoy_streams: true, ..Spec::default() }).unwrap().unwrap();
    assert_eq!(decoyed.types, normal.types);
    assert_eq!(decoyed.module, normal.module);
    assert_eq!(decoyed.streams.len(), 7);
    let duplicates: Vec<&String> = decoyed.warnings.iter().filter(|warning| warning.contains("duplicate")).collect();
    assert_eq!(duplicates.len(), 2, "{:?}", decoyed.warnings);
    assert_eq!(decoyed.warnings.len(), 2, "{:?}", decoyed.warnings);
}

#[test]
fn a_jtd_stream_widens_every_index_of_an_uncompressed_table_stream() {
    let normal = parse(&Spec::default()).unwrap().unwrap();
    let jtd = parse(&Spec { jtd: true, ..Spec::default() }).unwrap().unwrap();
    assert!(jtd.warnings.is_empty(), "{:?}", jtd.warnings);
    assert_eq!(jtd.types, normal.types);
    assert_eq!(jtd.assembly_refs, normal.assembly_refs);
    assert_eq!(jtd.member_refs, normal.member_refs);
    assert_eq!(jtd.module, normal.module);
    assert_eq!(jtd.pinvokes, normal.pinvokes);
    assert_eq!(jtd.custom_attributes, normal.custom_attributes);
}

#[test]
fn malformed_signature_and_attribute_blobs_are_reported_not_guessed() {
    let normal = parse(&Spec::default()).unwrap().unwrap();
    // Truncated, an unknown element type, a parameter count past the blob's end, and a dangling TypeRef.
    let blobs: [&[u8]; 5] = [&[], &[0x00, 1], &[0x00, 0, 0x99], &[0x00, 0x7F, 0x01, 0x08], &[0x00, 0, 0x12, 0x7D]];
    for blob in blobs {
        let spec = Spec { main_signature: Some(blob.to_vec()), ..Spec::default() };
        let metadata = parse(&spec).unwrap().unwrap();
        let methods = &program(&metadata).methods;
        assert_eq!(methods[0].signature, "<unreadable>", "{blob:02x?}");
        assert_eq!(methods[0].params, ["args"], "{blob:02x?}: the Param rows still decode");
        assert_eq!(methods[1..], program(&normal).methods[1..], "{blob:02x?}");
        assert!(metadata.warnings.iter().any(|warning| warning.contains("MethodDef row 1: signature")), "{blob:02x?}");
    }
    for value in [vec![0x01, 0x00, 3, b'a'], vec![0x02, 0x00], vec![0x01, 0x00, 0xFF, 42, 0, 0, 0]] {
        let metadata = parse(&Spec { attribute_value: Some(value.clone()), ..Spec::default() }).unwrap().unwrap();
        let attribute = &metadata.custom_attributes[0];
        assert_eq!(attribute.blob_length, value.len());
        let expected = (value.len() == 7).then(|| vec!["null".to_owned(), "42".to_owned()]);
        assert_eq!(attribute.arguments, expected, "{value:02x?}");
        assert_eq!(attribute.attribute_type.as_deref(), Some("System.Object"));
    }
}

#[test]
fn every_truncation_and_corruption_is_survived() {
    let image = build(&Spec::default());
    for length in 0..image.len() {
        let _ = dotnet::parse_image(&image[..length]);
    }
    // Deterministic xorshift, flipping bytes past the PE headers where the CLI structures live.
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..4000 {
        let mut mutated = image.clone();
        for _ in 0..1 + next() % 8 {
            let index = SECTION_FILE + (next() as usize % (image.len() - SECTION_FILE));
            mutated[index] = next() as u8;
        }
        if let Ok(Some(metadata)) = dotnet::parse_image(&mutated) {
            assert!(metadata.warnings.len() <= 256);
        }
    }
}

#[test]
fn native_images_are_not_managed() {
    for name in ["hello-x64.exe", "hello-x64.elf", "hello-x64.macho", "tls-x64.exe"] {
        let binary = Binary::open(fixture(name)).unwrap();
        assert!(dotnet::metadata(&binary).unwrap().is_none(), "{name}");
    }
}

#[test]
fn reads_a_real_assembly() {
    // Microsoft.Bcl.HashCode 1.1.1, lib/netstandard2.0 (MIT; provenance in the .LICENSE.txt beside it).
    let binary = Binary::open(fixture("Microsoft.Bcl.HashCode.dll")).unwrap();
    let metadata = dotnet::metadata(&binary).unwrap().expect("a managed assembly");
    assert!(metadata.warnings.is_empty(), "unexpected warnings: {:?}", metadata.warnings);
    assert_eq!(metadata.runtime_version, "v4.0.30319");
    assert_eq!(metadata.cli.flag_names, ["il_only", "strong_name_signed"]);
    assert_eq!(metadata.entry_point, None, "a library has no entry point");

    let assembly = metadata.assembly.as_ref().unwrap();
    assert_eq!((assembly.name.as_str(), assembly.version.as_str()), ("Microsoft.Bcl.HashCode", "1.0.0.0"));
    assert_eq!(metadata.module.as_ref().unwrap().mvid.as_deref(), Some("d56bb6e7-5667-4a1a-89c0-cdd2b2a4b04e"));
    let netstandard = &metadata.assembly_refs[0];
    assert_eq!((netstandard.name.as_str(), netstandard.version.as_str()), ("netstandard", "2.0.0.0"));
    assert_eq!(netstandard.public_key_or_token.as_deref(), Some("cc7b13ffcd2ddd51"));

    let hash_code = metadata.types.iter().find(|ty| ty.namespace == "System" && ty.name == "HashCode").unwrap();
    assert_eq!(hash_code.extends.as_deref(), Some("System.ValueType"));
    assert!(hash_code.fields.iter().any(|field| field.signature == "uint32 _queue1"));
    let signatures: Vec<&str> = hash_code.methods.iter().map(|method| method.signature.as_str()).collect();
    for expected in [
        "int32 Combine<T1>(T1)",
        "int32 Combine<T1, T2, T3, T4, T5, T6, T7, T8>(T1, T2, T3, T4, T5, T6, T7, T8)",
        "void Initialize(uint32&, uint32&, uint32&, uint32&)",
        "instance void Add<T>(T, System.Collections.Generic.IEqualityComparer<T>)",
        "instance bool Equals(object)",
    ] {
        assert!(signatures.contains(&expected), "{expected} not in {signatures:#?}");
    }
    let interop = metadata.types.iter().find(|ty| ty.name == "Interop").unwrap();
    assert_eq!(interop.methods[0].signature, "void GetRandomBytes(uint8*, int32)");
    let sr = metadata.types.iter().find(|ty| ty.namespace == "System" && ty.name == "SR").unwrap();
    assert_eq!(sr.fields[0].signature, "System.Resources.ResourceManager s_resourceManager");
    assert!(metadata.pinvokes.is_empty(), "the assembly has no ImplMap rows");

    assert_eq!(metadata.custom_attributes.len(), 76);
    let attribute = |name: &str| {
        let full = format!("System.Reflection.{name}");
        metadata.custom_attributes.iter().find(move |attribute| attribute.attribute_type.as_deref() == Some(&full))
    };
    let title = attribute("AssemblyTitleAttribute").unwrap();
    assert_eq!((title.parent_token, title.parent.as_deref()), (0x2000_0001, Some("Microsoft.Bcl.HashCode")));
    assert_eq!(title.arguments.as_deref(), Some(&["\"Microsoft.Bcl.HashCode\"".to_owned()][..]));
    let obsolete = metadata
        .custom_attributes
        .iter()
        .find(|attribute| attribute.parent.as_deref() == Some("System.HashCode::Equals") && attribute.blob_length == 83)
        .unwrap();
    assert_eq!(obsolete.attribute_type.as_deref(), Some("System.ObsoleteAttribute"));
    assert_eq!(obsolete.arguments.as_ref().unwrap()[1], "true");
    // DebuggableAttribute takes an enum, whose underlying type lives in another assembly: reported, not guessed.
    let debuggable = metadata
        .custom_attributes
        .iter()
        .find(|attribute| attribute.attribute_type.as_deref() == Some("System.Diagnostics.DebuggableAttribute"))
        .unwrap();
    assert_eq!((debuggable.arguments.as_ref(), debuggable.blob_length), (None, 8));
    assert_eq!(hash_code.methods.iter().filter(|method| method.name == "Combine").count(), 8);
    // Checked against the raw bytes: fat header 0x3013 at file offset 0x504, code size 0xE1.
    let combine5 = hash_code.methods.iter().find(|method| method.token == 0x0600_000D).unwrap();
    assert_eq!((combine5.name.as_str(), combine5.rva), ("Combine", 0x2304));
    assert_eq!(combine5.params, ["value1", "value2", "value3", "value4", "value5"]);
    let fat = combine5.il.unwrap();
    assert_eq!((fat.header, fat.code_size, fat.max_stack), (IlHeader::Fat, 225, 4));
    assert_eq!(fat.local_var_sig_token, 0x1100_0007);
    // A tiny header: 0x1E at file offset 0x250 is a 7-byte constructor body.
    let ctor = &metadata.types.iter().find(|ty| ty.name == "EmbeddedAttribute").unwrap().methods[0];
    assert_eq!((ctor.name.as_str(), ctor.rva), (".ctor", 0x2050));
    assert_eq!(ctor.il.map(|body| (body.header, body.code_size)), Some((IlHeader::Tiny, 7)));
    let methods: Vec<&dotnet::MethodDef> = metadata.types.iter().flat_map(|ty| &ty.methods).collect();
    assert_eq!(methods.len(), 48);
    assert!(methods.iter().all(|method| method.body == BodyKind::Il && method.il.is_some()));

    assert!(metadata.user_strings.iter().any(|literal| literal == "HashCode_EqualityNotSupported"));
    assert!(metadata.member_refs.iter().any(|member| member.name == ".ctor"));

    // IL bodies are bytecode: none may appear as native function starts or symbols. A PE image base is
    // 64 KiB aligned, so masking the lowest section address recovers it.
    let image_base = binary.segments.iter().map(|segment| segment.address).min().unwrap() & !0xFFFF;
    for method in methods {
        let address = image_base + u64::from(method.rva);
        assert!(!binary.function_starts.contains(&address), "{} seeded as a function start", method.name);
        assert!(binary.symbols.iter().all(|symbol| symbol.address != address), "{} named as a symbol", method.name);
    }
}

const HASH_CODE: &str = "Microsoft.Bcl.HashCode.dll";
/// HashCode.Combine<T1..T5>: fat header at file offset 0x504 (RVA 0x2304), 225 bytes of code from 0x510.
const COMBINE5: u32 = 0x0600_000D;
const COMBINE5_HEADER: usize = 0x504;
/// The fixture's one section maps RVA 0x2000 at file offset 0x200.
const FIXTURE_RVA_TO_FILE: usize = 0x1E00;

fn listing(image: &[u8], method: MethodSelector) -> dotnet::MethodIl {
    dotnet::image_method_il(image, method).unwrap().expect("a managed image")
}

fn texts(il: &dotnet::MethodIl) -> Vec<String> {
    il.instructions.iter().map(dotnet::Instruction::text).collect()
}

#[test]
fn disassembles_real_methods() {
    let image = std::fs::read(fixture(HASH_CODE)).unwrap();
    // Hand-decoded from the bytes at 0x510 (III.1.2.1 opcodes, branch targets relative to the next instruction):
    // 02 | 8C 1B000001 | 2D 03 | 16 | 2B 0D | 0F 00 | FE16 1B000001 | 6F 0A00001C | 0A
    let combine = listing(&image, MethodSelector::Token(COMBINE5));
    assert_eq!(combine.method, "System.HashCode::Combine");
    assert_eq!(combine.signature, "int32 Combine<T1, T2, T3, T4, T5>(T1, T2, T3, T4, T5)");
    assert_eq!(
        texts(&combine)[..9],
        [
            "IL_0000: ldarg.0",
            "IL_0001: box !!0",
            "IL_0006: brtrue.s IL_000b",
            "IL_0008: ldc.i4.0",
            "IL_0009: br.s IL_0018",
            "IL_000b: ldarga.s 0",
            "IL_000d: constrained. !!0",
            "IL_0013: callvirt instance int32 System.Object::GetHashCode()",
            "IL_0018: stloc.0",
        ]
    );
    assert_eq!(combine.instructions[2].targets, [0x0B]);
    assert_eq!(combine.instructions[7].token, Some(0x0A00_001C));
    assert_eq!(texts(&combine).last().unwrap(), "IL_00e0: ret");
    assert!(combine.init_locals && !combine.truncated && combine.warnings.is_empty(), "{:?}", combine.warnings);
    assert_eq!(combine.locals, vec!["uint32"; 10]);

    let ctor = listing(&image, MethodSelector::Name("Microsoft.CodeAnalysis.EmbeddedAttribute::.ctor"));
    let expected = ["IL_0000: ldarg.0", "IL_0001: call instance void System.Attribute::.ctor()", "IL_0006: ret"];
    assert_eq!(texts(&ctor), expected);
    assert_eq!(ctor.body.header, IlHeader::Tiny);

    let signature = "instance void Add<T>(T, System.Collections.Generic.IEqualityComparer<T>)";
    let metadata = dotnet::parse_image(&image).unwrap().unwrap();
    let methods = metadata.types.iter().flat_map(|ty| &ty.methods);
    let token = methods.filter(|method| method.signature == signature).map(|method| method.token).next().unwrap();
    let add = listing(&image, MethodSelector::Token(token));
    let call = "IL_0020: callvirt instance int32 System.Collections.Generic.IEqualityComparer<!!0>::GetHashCode(!0)";
    assert!(texts(&add).contains(&call.to_owned()), "{:#?}", texts(&add));

    let seed = listing(&image, MethodSelector::Name("get_UseNonRandomizedHashSeed"));
    assert_eq!(
        texts(&seed)[..2],
        [
            "IL_0000: ldstr \"Switch.System.Data.UseNonRandomizedHashSeed\"",
            "IL_0005: ldsflda int32 System.LocalAppContextSwitches::s_useNonRandomizedHashSeed",
        ]
    );

    // Exception sections checked against the bytes: 01 10 0000 | 0000 1000 0E 1E00 03 1E000001 at 0xCD4.
    let resource = listing(&image, MethodSelector::Name("System.SR::GetResourceString"));
    assert_eq!(resource.locals, ["string"]);
    let clauses: Vec<String> = resource.exception_clauses.iter().map(dotnet::ExceptionClause::text).collect();
    assert_eq!(
        clauses,
        [".try IL_0010 to IL_001e catch System.Resources.MissingManifestResourceException handler IL_001e to IL_0021"]
    );
    assert_eq!(resource.exception_clauses[0].catch_token, Some(0x0100_001E));
    // 01 10 0000 | 0200 0D00 1E 2B00 0A at 0x2E4: a finally around the RandomNumberGenerator.
    let random = listing(&image, MethodSelector::Name("Interop::GetRandomBytes"));
    let finally = &random.exception_clauses[0];
    assert_eq!((finally.kind, finally.try_start, finally.try_end), (ClauseKind::Finally, 0x0D, 0x2B));
    assert_eq!((finally.handler_start, finally.handler_end), (0x2B, 0x35));
    assert_eq!(random.locals, ["System.Security.Cryptography.RandomNumberGenerator", "uint8[]"]);
    serde_json::to_string(&random).unwrap();
}

#[test]
fn selects_methods_by_token_or_unambiguous_name() {
    let image = std::fs::read(fixture(HASH_CODE)).unwrap();
    let error = dotnet::image_method_il(&image, MethodSelector::Name("System.HashCode::Combine")).unwrap_err();
    let IlError::Ambiguous { candidates, .. } = &error else { panic!("{error}") };
    assert_eq!(candidates.len(), 8);
    let five = "0x0600000d System.HashCode::Combine int32 Combine<T1, T2, T3, T4, T5>(T1, T2, T3, T4, T5)";
    assert!(candidates.contains(&five.to_owned()), "{candidates:#?}");
    assert_eq!(listing(&image, MethodSelector::Name("MixFinal")).method, "System.HashCode::MixFinal");
    let missing =
        [MethodSelector::Name("System.HashCode::Nope"), MethodSelector::Token(0x0600_0100), MethodSelector::Token(1)];
    for selector in missing {
        let result = dotnet::image_method_il(&image, selector);
        assert!(matches!(result, Err(IlError::NotFound(_))), "{selector:?}");
    }
    let native = Binary::open(fixture("hello-x64.exe")).unwrap();
    assert!(dotnet::method_il(&native, MethodSelector::Token(0x0600_0001)).unwrap().is_none());
}

#[test]
fn resolves_method_specs_and_generic_locals() {
    let image = build(&Spec::default());
    let compute = listing(&image, MethodSelector::Name("Demo.Program::Compute"));
    assert_eq!(texts(&compute), ["IL_0000: call int32 Demo.Program::Compute<int32>(!!0, !!0)"]);
    assert_eq!(compute.locals, ["int32", "T"]);
    assert_eq!(compute.instructions[0].token, Some(0x2B00_0001));
    let main = listing(&image, MethodSelector::Token(0x0600_0001));
    assert_eq!(texts(&main), ["IL_0000: ldc.i4.0", "IL_0001: pop", "IL_0002: ret"]);
    for (method, body) in [("Helper", BodyKind::Native), ("Run", BodyKind::None)] {
        let error = dotnet::image_method_il(&image, MethodSelector::Name(method)).unwrap_err();
        assert!(matches!(error, IlError::NoBody { body: found, .. } if found == body), "{error}");
    }
}

#[test]
fn unreadable_tables_name_the_method_as_given() {
    let mut image = build(&Spec::default());
    let stream = image.windows(3).position(|name| name == b"#~\0").unwrap();
    image[stream + 1] = b'X';
    let selectors = [
        (MethodSelector::Token(0x0600_0002), "0x06000002"),
        (MethodSelector::Name("Demo.Program::Compute"), "Demo.Program::Compute"),
    ];
    for (selector, shown) in selectors {
        let error = dotnet::image_method_il(&image, selector).unwrap_err();
        let IlError::Unreadable { method, reason } = &error else { panic!("{error}") };
        assert_eq!(method, shown);
        assert!(reason.contains("no #~ table stream"), "{reason}");
    }
}

#[test]
fn decodes_crafted_operands_and_exception_sections() {
    let mut image = std::fs::read(fixture(HASH_CODE)).unwrap();
    let ldstr = listing(&image, MethodSelector::Name("get_UseNonRandomizedHashSeed")).instructions[0].token.unwrap();
    let mut code = vec![0x1F, 0xFE, 0x22, 0x00, 0x00, 0x80, 0x3F, 0x45, 2, 0, 0, 0, 0, 0, 0, 0, 0xFB, 0xFF, 0xFF, 0xFF];
    code.extend([0x24, 0xFE, 0x08, 0xFE, 0x0C, 0x03, 0x01, 0x72]);
    code.extend(ldstr.to_le_bytes());
    code.extend([0x28, 0xFF, 0xFF, 0xFF, 0x0A, 0xD0, 0x01, 0x00, 0x00, 0x1B, 0x2B, 0x7F]);
    let header = COMBINE5_HEADER;
    // Set MoreSects (0x08) in the fat flags and shrink the code.
    image[header] |= 0x08;
    image[header + 4..header + 8].copy_from_slice(&(code.len() as u32).to_le_bytes());
    image[header + 12..header + 12 + code.len()].copy_from_slice(&code);
    // At the next 4-byte aligned RVA after the code: a small EH section (one catch of TypeRef 1) chained to a fat
    // one (a filter and a fault).
    let mut sections = vec![0x81, 16, 0, 0, 0, 0, 0, 0, 0x10, 0x10, 0x00, 0x08, 0x01, 0x00, 0x00, 0x01];
    sections.extend([0x41, 52, 0, 0]);
    for value in [1u32, 0x20, 0x10, 0x30, 0x08, 0x2B, 4, 0, 4, 4, 4, 0] {
        sections.extend(value.to_le_bytes());
    }
    let start = (0x2304 + 12 + code.len()).next_multiple_of(4) - 0x2304 + header;
    image[start..start + sections.len()].copy_from_slice(&sections);

    let il = listing(&image, MethodSelector::Token(COMBINE5));
    assert_eq!(
        texts(&il),
        [
            "IL_0000: ldc.i4.s -2",
            "IL_0002: ldc.r4 1.0",
            "IL_0007: switch (IL_0014, IL_000f)",
            "IL_0014: .byte 0x24",
            "IL_0015: .byte 0xfe, 0x08",
            "IL_0017: ldloc V_259",
            "IL_001b: ldstr \"Switch.System.Data.UseNonRandomizedHashSeed\"",
            "IL_0020: call <token 0x0affffff>",
            "IL_0025: ldtoken !!0",
            "IL_002a: br.s IL_00ab",
        ]
    );
    assert_eq!(
        il.warnings,
        [
            "br.s at IL_002a targets IL_00ab past the body",
            "exception clause 2 try IL_0020 to IL_0030 runs past the 44-byte body",
            "exception clause 2 handler IL_0030 to IL_0038 runs past the 44-byte body",
        ]
    );
    let clauses: Vec<String> = il.exception_clauses.iter().map(dotnet::ExceptionClause::text).collect();
    assert_eq!(
        clauses,
        [
            ".try IL_0000 to IL_0010 catch System.Runtime.CompilerServices.CompilationRelaxationsAttribute handler \
             IL_0010 to IL_0018",
            ".try IL_0020 to IL_0030 filter IL_002b handler IL_0030 to IL_0038",
            ".try IL_0000 to IL_0004 fault handler IL_0004 to IL_0008",
        ]
    );
}

/// Every IL method of the fixture with the file offset of its body header.
fn fixture_bodies(image: &[u8]) -> Vec<(u32, usize, dotnet::IlBody)> {
    let metadata = dotnet::parse_image(image).unwrap().unwrap();
    let methods = metadata.types.iter().flat_map(|ty| &ty.methods);
    methods.map(|method| (method.token, method.rva as usize - FIXTURE_RVA_TO_FILE, method.il.unwrap())).collect()
}

#[test]
fn every_truncated_body_disassembles_without_panicking() {
    let image = std::fs::read(fixture(HASH_CODE)).unwrap();
    // Each cut re-parses the whole image, so the methods run on their own threads.
    std::thread::scope(|scope| {
        for (token, header, body) in fixture_bodies(&image) {
            let image = &image;
            scope.spawn(move || {
                let mut cut = image.clone();
                for length in 0..body.code_size {
                    match body.header {
                        IlHeader::Tiny => cut[header] = ((length as u8) << 2) | 0x02,
                        IlHeader::Fat => cut[header + 4..header + 8].copy_from_slice(&length.to_le_bytes()),
                    }
                    let il = listing(&cut, MethodSelector::Token(token));
                    assert!(il.instructions.len() <= length as usize, "{token:#x} cut to {length}");
                    assert!(il.warnings.len() <= 256);
                }
            });
        }
    });
}

#[test]
fn random_body_corruption_is_survived() {
    let image = std::fs::read(fixture(HASH_CODE)).unwrap();
    let bodies = fixture_bodies(&image);
    let start = bodies.iter().map(|&(_, header, _)| header).min().unwrap();
    let end = bodies.iter().map(|&(_, header, body)| header + (body.header_size + body.code_size) as usize).max();
    let span = end.unwrap() + 64 - start;
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..300 {
        let mut mutated = image.clone();
        for _ in 0..1 + next() % 16 {
            mutated[start + next() as usize % span] = next() as u8;
        }
        for _ in 0..3 {
            let (token, _, _) = bodies[next() as usize % bodies.len()];
            if let Ok(Some(il)) = dotnet::image_method_il(&mutated, MethodSelector::Token(token)) {
                assert!(il.instructions.len() <= dotnet::MAX_INSTRUCTIONS);
                assert!(il.warnings.len() <= 256);
                serde_json::to_string(&il).unwrap();
            }
        }
    }
}
