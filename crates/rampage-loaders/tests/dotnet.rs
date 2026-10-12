use std::path::PathBuf;

use rampage_loaders::dotnet::{self, BodyKind, EntryPoint, IlHeader};
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
    let signature = blobs.blob(&[0x00, 0x00, 0x01]);
    let token_blob = blobs.blob(&[0xb0, 0x3f, 0x5f, 0x7f, 0x11, 0xd5, 0x0a, 0x3a]);
    let guids: Vec<u8> = (1..=16).collect();
    let mut user_strings = vec![0u8, 11];
    for unit in "hello".encode_utf16() {
        user_strings.extend_from_slice(&unit.to_le_bytes());
    }
    user_strings.push(0);

    let s = if spec.wide_strings { 4 } else { 2 };
    let g = if spec.wide_guids { 4 } else { 2 };
    let b = if spec.wide_blobs { 4 } else { 2 };
    let type_refs = 1 + spec.extra_type_refs;
    // TypeDefOrRef and ResolutionScope have 2 tag bits, MemberRefParent 3, HasCustomAttribute 5.
    let coded = |tag_bits: u32| if type_refs < (1 << (16 - tag_bits)) { 2 } else { 4 };
    let (tdor, scope, mrp, hca) = (coded(2), coded(2), coded(3), coded(5));

    // Bodies live after the 72-byte CLI header.
    let tiny_rva = SECTION_RVA + 72;
    let tiny = [0x0E, 0x16, 0x26, 0x2A];
    let fat_rva = tiny_rva + 4;
    let fat = [0x13, 0x30, 0x02, 0x00, 0x05, 0, 0, 0, 0x01, 0, 0, 0x11, 0x00, 0x00, 0x00, 0x00, 0x2A];
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
        tables.put((1 << 2) | 2, scope).put(pad_name, s).put(system, s);
    }
    // TypeDef: <Module>, Demo.Program extends TypeRef 1 (TypeDefOrRef tag 1), and Inner nested in Program.
    let (module_type, program, demo, inner) =
        (strings.string("<Module>"), strings.string("Program"), strings.string("Demo"), strings.string("Inner"));
    tables.put(0, 4).put(module_type, s).put(0, s).put(0, tdor).put(1, 2).put(1, 2);
    tables.put(0x0010_0001, 4).put(program, s).put(demo, s).put((1 << 2) | 1, tdor).put(1, 2).put(1, 2);
    tables.put(0x0010_0002, 4).put(inner, s).put(0, s).put((1 << 2) | 1, tdor).put(2, 2).put(5, 2);
    // Field
    let counter = strings.string("counter");
    tables.put(0x0001, 2).put(counter, s).put(signature, b);
    // MethodDef: Main (tiny IL), Compute (fat IL), Helper (native), Run (abstract, no body).
    let main = if spec.bad_method_name { 0xFFFF } else { strings.string("Main") };
    let (compute, helper, run) = (strings.string("Compute"), strings.string("Helper"), strings.string("Run"));
    tables.put(tiny_rva, 4).put(0, 2).put(0x0016, 2).put(main, s).put(signature, b).put(1, 2);
    tables.put(fat_rva, 4).put(0, 2).put(0x0006, 2).put(compute, s).put(signature, b).put(2, 2);
    tables.put(native_rva, 4).put(0x0001, 2).put(0x0016, 2).put(helper, s).put(signature, b).put(5, 2);
    tables.put(0, 4).put(0, 2).put(0x0446, 2).put(run, s).put(signature, b).put(5, 2);
    // Param: Main(args); Compute's return row (sequence 0) and its parameters stored out of order.
    let (args, x, y) = (strings.string("args"), strings.string("x"), strings.string("y"));
    tables.put(0, 2).put(1, 2).put(args, s);
    tables.put(0, 2).put(0, 2).put(0, s);
    tables.put(0, 2).put(2, 2).put(y, s);
    tables.put(0, 2).put(1, 2).put(x, s);
    // MemberRef: Object::.ctor (MemberRefParent tag 1 = TypeRef).
    let ctor = strings.string(".ctor");
    tables.put((1 << 3) | 1, mrp).put(ctor, s).put(signature, b);
    // CustomAttribute: never decoded, but its width depends on HasCustomAttribute and must be skipped right.
    tables.put((1 << 5) | 7, hca).put((1 << 3) | 3, 2).put(0, b);
    // Assembly
    let demo_assembly = strings.string("Demo");
    tables.put(0x8004, 4).put(1, 2).put(2, 2).put(3, 2).put(4, 2).put(0, 4).put(0, b).put(demo_assembly, s).put(0, s);
    // AssemblyRef
    let mscorlib = strings.string("mscorlib");
    tables.put(4, 2).put(0, 2).put(0, 2).put(0, 2).put(0, 4).put(token_blob, b).put(mscorlib, s).put(0, s).put(0, b);
    // NestedClass: Inner (TypeDef 3) inside Program (TypeDef 2).
    tables.put(3, 2).put(2, 2);

    let present: [(u8, u32); 11] = [
        (0x00, 1),
        (0x01, type_refs),
        (0x02, spec.declared_type_defs.unwrap_or(3)),
        (0x04, 1),
        (0x06, 4),
        (0x08, 4),
        (0x0A, 1),
        (0x0C, 1),
        (0x20, 1),
        (0x23, 1),
        (0x29, 1),
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
    let streams: [(&str, &[u8]); 5] = [
        ("#~", &table_stream),
        ("#Strings", &strings.bytes),
        ("#US", &user_strings),
        ("#GUID", &guids),
        ("#Blob", &blobs.bytes),
    ];
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
        let size = if *name == "#~" { data.len() as u32 - spec.table_stream_cut } else { data.len() as u32 };
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
    assert_eq!(program.fields, ["counter"]);
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
    assert!(hash_code.fields.iter().any(|field| field == "_queue1"));
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
