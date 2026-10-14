use rampage_arch::Arch;
use rampage_decompiler::layout::{
    LayoutField, LayoutOrganization, LayoutScalar, LayoutType, MAX_LAYOUT_FIELDS, MAX_LAYOUT_NAME_BYTES,
    MAX_LAYOUT_SIZE, PlainStructLayout, ScalarKind,
};
use rampage_decompiler::{Decompiler, DecompilerOptions, MemoryRegion, Platform};

const DECLARATION: &str = "struct layout_flat { char tag; int4 count; uint2 flags; float8 weight; \
                          int4 *value; uint1 tail; };";

fn open(bytes: &[u8]) -> Decompiler {
    Decompiler::open_with_options(
        Arch::X86_64,
        false,
        &[MemoryRegion {
            base: 0x1000,
            bytes,
            size: bytes.len() as u64,
            readable: true,
            writable: false,
            executable: true,
        }],
        &DecompilerOptions::default(),
    )
    .unwrap()
}

fn scalar(name: &str, kind: ScalarKind, size: u32) -> LayoutScalar {
    LayoutScalar { name: name.to_owned(), kind, size, alignment: size }
}

fn field(name: &str, offset: u32, scalar: LayoutScalar) -> LayoutField {
    LayoutField { name: name.to_owned(), offset, size: scalar.size, ty: LayoutType::Scalar { scalar } }
}

// Independently specified natural SysV layout; the compiled-C oracle below is the authoritative comparison.
fn expected() -> PlainStructLayout {
    PlainStructLayout {
        name: "layout_flat".to_owned(),
        size: 40,
        alignment: 8,
        organization: LayoutOrganization {
            pointer_size: 8,
            int_size: 4,
            long_size: 8,
            scalar_alignments: [1, 2, 4, 8],
        },
        fields: vec![
            field("tag", 0, scalar("char", ScalarKind::SignedCharacter, 1)),
            field("count", 4, scalar("int4", ScalarKind::SignedInteger, 4)),
            field("flags", 8, scalar("uint2", ScalarKind::UnsignedInteger, 2)),
            field("weight", 16, scalar("float8", ScalarKind::Float, 8)),
            LayoutField {
                name: "value".to_owned(),
                offset: 24,
                size: 8,
                ty: LayoutType::Pointer {
                    name: String::new(),
                    size: 8,
                    alignment: 8,
                    pointee: scalar("int4", ScalarKind::SignedInteger, 4),
                },
            },
            field("tail", 32, scalar("uint1", ScalarKind::UnsignedInteger, 1)),
        ],
    }
}

#[test]
fn natural_flat_struct_is_inspected_and_asserted_with_tail_padding() {
    let mut engine = open(&[0x31, 0xc0, 0xc3]);
    engine.parse_c(DECLARATION).unwrap();
    assert_eq!(engine.inspect_plain_struct("layout_flat").unwrap(), expected());
    engine.assert_plain_struct_layout(&expected()).unwrap();
    engine.set_symbol(0x1000, "fixture").unwrap();
    engine.apply_prototype(0x1000, false, "int4 fixture(layout_flat *item);").unwrap();
    assert!(engine.decompile(0x1000, "fixture", false).unwrap().contains("layout_flat"));
}

#[test]
fn complete_schema_mismatches_are_read_only_and_do_not_poison_the_engine() {
    let mut engine = open(&[0x31, 0xc0, 0xc3]);
    engine.parse_c(DECLARATION).unwrap();
    engine.decompile(0x1000, "before_failures", false).unwrap();
    let prior_tokens = engine.tokens();
    let prior_result = serde_json::to_value(engine.structured_result().unwrap()).unwrap();
    let mut variants = Vec::new();
    let mut wrong = expected();
    wrong.fields[1].name = "other".to_owned();
    variants.push(wrong);
    let mut wrong = expected();
    wrong.fields.swap(0, 1);
    variants.push(wrong);
    let mut wrong = expected();
    wrong.fields[1].offset = 12;
    variants.push(wrong);
    let mut wrong = expected();
    wrong.fields[2].offset = 10;
    wrong.validate().unwrap();
    variants.push(wrong);
    let mut wrong = expected();
    wrong.fields[1].size = 2;
    variants.push(wrong);
    let mut wrong = expected();
    wrong.size = 48;
    variants.push(wrong);
    let mut wrong = expected();
    wrong.alignment = 4;
    variants.push(wrong);
    let mut wrong = expected();
    wrong.fields.pop();
    variants.push(wrong);
    let mut wrong = expected();
    if let LayoutType::Scalar { scalar } = &mut wrong.fields[0].ty {
        scalar.kind = ScalarKind::SignedInteger;
    }
    variants.push(wrong);
    let mut wrong = expected();
    if let LayoutType::Scalar { scalar } = &mut wrong.fields[3].ty {
        scalar.alignment = 4;
    }
    variants.push(wrong);
    for kind in [ScalarKind::UnsignedInteger, ScalarKind::Float] {
        let mut wrong = expected();
        if let LayoutType::Scalar { scalar } = &mut wrong.fields[1].ty {
            scalar.kind = kind;
        }
        variants.push(wrong);
    }
    let mut wrong = expected();
    if let LayoutType::Scalar { scalar } = &mut wrong.fields[1].ty {
        scalar.name = "uint4".to_owned();
    }
    variants.push(wrong);
    let mut wrong = expected();
    if let LayoutType::Pointer { size, .. } = &mut wrong.fields[4].ty {
        *size = 4;
    }
    variants.push(wrong);
    for pointee in [
        scalar("uint4", ScalarKind::UnsignedInteger, 4),
        scalar("int8", ScalarKind::SignedInteger, 8),
        scalar("float4", ScalarKind::Float, 4),
    ] {
        let mut wrong = expected();
        if let LayoutType::Pointer { pointee: leaf, .. } = &mut wrong.fields[4].ty {
            *leaf = pointee;
        }
        variants.push(wrong);
    }
    let mut wrong = expected();
    wrong.organization.scalar_alignments[3] = 4;
    variants.push(wrong);
    for wrong in variants {
        assert!(engine.assert_plain_struct_layout(&wrong).is_err(), "accepted {wrong:?}");
        assert_eq!(engine.inspect_plain_struct("layout_flat").unwrap(), expected());
        engine.assert_plain_struct_layout(&expected()).unwrap();
    }
    assert_eq!(engine.tokens(), prior_tokens);
    assert_eq!(serde_json::to_value(engine.structured_result().unwrap()).unwrap(), prior_result);
    assert!(engine.decompile(0x1000, "after_failures", false).unwrap().contains("return"));
}

#[test]
fn input_budgets_and_malformed_shapes_are_rejected_without_native_access() {
    let mut cases = Vec::new();
    for name in ["", "1bad", "bad name", "bad\0name", "námé"] {
        let mut wrong = expected();
        wrong.name = name.to_owned();
        cases.push(wrong);
    }
    let mut wrong = expected();
    wrong.name = "x".repeat(MAX_LAYOUT_NAME_BYTES + 1);
    cases.push(wrong);
    for size in [0, MAX_LAYOUT_SIZE + 1, u32::MAX] {
        let mut wrong = expected();
        wrong.size = size;
        cases.push(wrong);
    }
    let mut wrong = expected();
    wrong.fields.clear();
    cases.push(wrong);
    let mut wrong = expected();
    wrong.fields = vec![wrong.fields[0].clone(); MAX_LAYOUT_FIELDS + 1];
    cases.push(wrong);
    let mut wrong = expected();
    wrong.fields[1].offset = 0;
    cases.push(wrong);
    let mut wrong = expected();
    wrong.fields[0].offset = u32::MAX;
    cases.push(wrong);
    let mut wrong = expected();
    wrong.fields[5].offset = 40;
    cases.push(wrong);
    let mut wrong = expected();
    wrong.fields[1].name = "tag".to_owned();
    cases.push(wrong);
    let mut wrong = expected();
    if let LayoutType::Scalar { scalar } = &mut wrong.fields[1].ty {
        scalar.name = "invalid type*".to_owned();
    }
    cases.push(wrong);
    let mut wrong = expected();
    if let LayoutType::Scalar { scalar } = &mut wrong.fields[1].ty {
        scalar.kind = ScalarKind::Void;
        scalar.size = 0;
    }
    cases.push(wrong);
    let mut wrong = expected();
    wrong.fields = (0..MAX_LAYOUT_FIELDS)
        .map(|index| LayoutField {
            name: format!("f{index:03}{}", "x".repeat(124)),
            offset: index as u32 * 8,
            size: 8,
            ty: LayoutType::Pointer {
                name: "p".repeat(128),
                size: 8,
                alignment: 8,
                pointee: scalar(&"i".repeat(128), ScalarKind::SignedInteger, 4),
            },
        })
        .collect();
    wrong.size = MAX_LAYOUT_FIELDS as u32 * 8;
    cases.push(wrong);
    for wrong in cases {
        assert!(wrong.validate().is_err(), "accepted {wrong:?}");
    }
}

#[test]
fn unsupported_registered_shapes_are_refused_without_poisoning() {
    let mut engine = open(&[0x31, 0xc0, 0xc3]);
    engine.parse_c(DECLARATION).unwrap();
    for (name, declaration) in [
        ("not_struct", "typedef int4 not_struct;"),
        ("a_union", "union a_union { int4 x; uint4 y; };"),
        ("an_array", "struct an_array { int4 x[2]; };"),
        ("nested", "struct nested { layout_flat inner; };"),
        ("aggregate_pointer", "struct aggregate_pointer { layout_flat *p; };"),
        ("bits", "struct bits { uint4 x:3; uint4 y:5; };"),
        ("callback", "struct callback { int4 (*fn)(int4 x); };"),
        ("ptrptr", "struct ptrptr { int4 **p; };"),
        ("ptrarray", "struct ptrarray { int4 (*p)[2]; };"),
        ("unknown", "struct unknown { xunknown4 x; };"),
    ] {
        engine.parse_c(declaration).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(engine.inspect_plain_struct(name).is_err(), "accepted {name}");
        engine.assert_plain_struct_layout(&expected()).unwrap();
    }
    let _ = engine.parse_c("struct recursive { struct recursive *next; };");
    assert!(engine.inspect_plain_struct("recursive").is_err());
    // This C parser may itself refuse forward declarations; neither path may accept a complete layout.
    let _ = engine.parse_c("struct forward;");
    assert!(engine.inspect_plain_struct("forward").is_err());
    assert!(engine.inspect_plain_struct("missing").is_err());
    engine.assert_plain_struct_layout(&expected()).unwrap();
    assert!(engine.decompile(0x1000, "still_valid", false).unwrap().contains("return"));
}

#[test]
fn void_pointer_bool_and_named_scalar_aliases_retain_real_leaf_descriptors() {
    let mut engine = open(&[0xc3]);
    engine.parse_c("typedef uint4 layout_word;").unwrap();
    engine.parse_c("struct layout_leaves { bool flag; layout_word word; void *opaque; };").unwrap();
    let layout = engine.inspect_plain_struct("layout_leaves").unwrap();
    assert_eq!(layout.fields[0].ty, LayoutType::Scalar { scalar: scalar("bool", ScalarKind::Bool, 1) });
    assert_eq!(
        layout.fields[1].ty,
        LayoutType::Scalar { scalar: scalar("layout_word", ScalarKind::UnsignedInteger, 4) }
    );
    assert_eq!(
        layout.fields[2].ty,
        LayoutType::Pointer {
            name: String::new(),
            size: 8,
            alignment: 8,
            pointee: LayoutScalar { name: "void".to_owned(), kind: ScalarKind::Void, size: 0, alignment: 1 },
        }
    );
    engine.assert_plain_struct_layout(&layout).unwrap();
}

#[test]
fn native_field_string_count_and_cumulative_budgets_are_enforced_atomically() {
    let mut engine = open(&[0xc3]);
    engine.parse_c(DECLARATION).unwrap();
    let declaration = format!("struct layout_name_budget {{ int4 {}; }};", "f".repeat(MAX_LAYOUT_NAME_BYTES + 1));
    engine.parse_c(&declaration).unwrap();
    assert!(engine.inspect_plain_struct("layout_name_budget").is_err());
    let fields = (0..=MAX_LAYOUT_FIELDS).map(|index| format!("int4 field_{index};")).collect::<String>();
    engine.parse_c(&format!("struct layout_count_budget {{ {fields} }};")).unwrap();
    assert!(engine.inspect_plain_struct("layout_count_budget").is_err());
    let scalar_name = "s".repeat(MAX_LAYOUT_NAME_BYTES);
    let pointer_name = "p".repeat(MAX_LAYOUT_NAME_BYTES);
    engine.parse_c(&format!("typedef int4 {scalar_name};")).unwrap();
    engine.parse_c(&format!("typedef {scalar_name} *{pointer_name};")).unwrap();
    let fields = (0..90).map(|index| format!("{pointer_name} f{index:03}{};\n", "x".repeat(124))).collect::<String>();
    engine.parse_c(&format!("struct layout_text_budget {{ {fields} }};")).unwrap();
    assert!(engine.inspect_plain_struct("layout_text_budget").is_err());
    let scalar_name = "s".repeat(MAX_LAYOUT_NAME_BYTES + 1);
    engine.parse_c(&format!("typedef int4 {scalar_name};")).unwrap();
    engine.parse_c(&format!("struct layout_type_budget {{ {scalar_name} field; }};")).unwrap();
    assert!(engine.inspect_plain_struct("layout_type_budget").is_err());
    assert_eq!(engine.inspect_plain_struct("layout_flat").unwrap(), expected());
    engine.assert_plain_struct_layout(&expected()).unwrap();
}

#[test]
fn other_compiler_families_are_explicitly_refused() {
    let region =
        MemoryRegion { base: 0x1000, bytes: &[0xc3], size: 1, readable: true, writable: false, executable: true };
    let mut engine = Decompiler::open_with_options(
        Arch::X86_64,
        false,
        &[region],
        &DecompilerOptions { platform: Platform::Windows, ..Default::default() },
    )
    .unwrap();
    assert_eq!(engine.language_id(), "x86:LE:64:default:windows");
    engine.parse_c(DECLARATION).unwrap();
    let error = engine.inspect_plain_struct("layout_flat").unwrap_err();
    assert!(error.to_string().contains("unsupported processor/compiler specification"), "{error}");
}

#[test]
fn serde_visitors_reject_invalid_schema_values_after_visitation() {
    let mut value = serde_json::to_value(expected()).unwrap();
    value["name"] = serde_json::Value::String("x".repeat(MAX_LAYOUT_NAME_BYTES + 1));
    assert!(serde_json::from_value::<PlainStructLayout>(value).is_err());
    let mut value = serde_json::to_value(expected()).unwrap();
    let field = value["fields"][0].clone();
    value["fields"] = serde_json::Value::Array(vec![field; MAX_LAYOUT_FIELDS + 1]);
    assert!(serde_json::from_value::<PlainStructLayout>(value).is_err());
    for bad_size in [serde_json::json!(-1), serde_json::json!(4294967296_u64)] {
        let mut value = serde_json::to_value(expected()).unwrap();
        value["size"] = bad_size;
        assert!(serde_json::from_value::<PlainStructLayout>(value).is_err());
    }
    let mut value = serde_json::to_value(expected()).unwrap();
    value["fields"][0]["ty"]["scalar"]["kind"] = serde_json::json!("unknown");
    assert!(serde_json::from_value::<PlainStructLayout>(value).is_err());
}

// Independently reviewed SysV facts in layout_constants.c's documented array order. Nothing here is
// generated from DWARF, native inspection, or a previously accepted producer layout.
const REVIEWED_LAYOUT_CONSTANTS: [u32; 47] = [
    0x31594c52, 1, 47, // magic, version, words
    8, 1, // CHAR_BIT, signed char
    8, 8, 4, 4, 8, 8, // void pointer, int, long: size/alignment
    1, 1, 2, 2, 4, 4, 8, 8, // unsigned primitives: size/alignment
    40, 8, // struct: size/alignment
    0, 1, 1, 1, // tag: offset/member-size/type-size/type-alignment
    4, 4, 4, 4, // count
    8, 2, 2, 2, // flags
    16, 8, 8, 8, // weight
    24, 8, 8, 8, // value
    32, 1, 1, 1, // tail
    4, 4, // pointed-to scalar: size/alignment
];

fn constants_layout(bytes: &[u8]) -> Result<PlainStructLayout, String> {
    let expected_bytes = REVIEWED_LAYOUT_CONSTANTS.len() * 4;
    if bytes.len() != expected_bytes {
        return Err(format!("layout constant section must be exactly {expected_bytes} bytes, got {}", bytes.len()));
    }
    let mut words = [0u32; REVIEWED_LAYOUT_CONSTANTS.len()];
    for (index, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
        words[index] = u32::from_le_bytes(*chunk);
    }
    for (index, (&actual, &reviewed)) in words.iter().zip(&REVIEWED_LAYOUT_CONSTANTS).enumerate() {
        if actual != reviewed {
            return Err(format!("layout constant {index} differs: target {actual}, reviewed {reviewed}"));
        }
    }
    let scalar_field = |index: usize, name: &str, type_name: &str, kind| LayoutField {
        name: name.to_owned(),
        offset: words[index],
        size: words[index + 1],
        ty: LayoutType::Scalar {
            scalar: LayoutScalar {
                name: type_name.to_owned(),
                kind,
                size: words[index + 2],
                alignment: words[index + 3],
            },
        },
    };
    let oracle = PlainStructLayout {
        name: "layout_flat".to_owned(),
        size: words[19],
        alignment: words[20],
        organization: LayoutOrganization {
            pointer_size: words[5],
            int_size: words[7],
            long_size: words[9],
            scalar_alignments: [words[12], words[14], words[16], words[18]],
        },
        fields: vec![
            scalar_field(21, "tag", "char", ScalarKind::SignedCharacter),
            scalar_field(25, "count", "int4", ScalarKind::SignedInteger),
            scalar_field(29, "flags", "uint2", ScalarKind::UnsignedInteger),
            scalar_field(33, "weight", "float8", ScalarKind::Float),
            LayoutField {
                name: "value".to_owned(),
                offset: words[37],
                size: words[38],
                ty: LayoutType::Pointer {
                    name: String::new(),
                    size: words[39],
                    alignment: words[40],
                    pointee: LayoutScalar {
                        name: "int4".to_owned(),
                        kind: ScalarKind::SignedInteger,
                        size: words[45],
                        alignment: words[46],
                    },
                },
            },
            scalar_field(41, "tail", "uint1", ScalarKind::UnsignedInteger),
        ],
    };
    oracle.validate().map_err(|error| error.to_string())?;
    Ok(oracle)
}

#[test]
fn constant_oracle_decoding_rejects_missing_truncated_extra_and_every_malformed_measurement() {
    let bytes = REVIEWED_LAYOUT_CONSTANTS.iter().flat_map(|word| word.to_le_bytes()).collect::<Vec<_>>();
    assert_eq!(constants_layout(&bytes).unwrap(), expected());
    assert!(constants_layout(&[]).is_err());
    assert!(constants_layout(&bytes[..bytes.len() - 1]).is_err());
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(constants_layout(&extra).is_err());
    let big_endian = REVIEWED_LAYOUT_CONSTANTS.iter().flat_map(|word| word.to_be_bytes()).collect::<Vec<_>>();
    assert!(constants_layout(&big_endian).is_err());
    for index in 0..REVIEWED_LAYOUT_CONSTANTS.len() {
        let mut malformed = bytes.clone();
        malformed[index * 4] ^= 1;
        let error = constants_layout(&malformed).unwrap_err();
        assert!(error.contains(&format!("layout constant {index} differs")), "{error}");
    }
}

#[test]
#[ignore = "requires centrally cross-compiled layout_constants.c .rampage_layout section; no target execution"]
fn independent_compiled_c_oracle_matches_native_layout() {
    use std::io::Read;

    let path = std::env::var_os("RAMPAGE_LAYOUT_CONSTANTS").expect("required extracted constant section path");
    let file = std::fs::File::open(path).expect("open extracted constant section");
    let expected_bytes = REVIEWED_LAYOUT_CONSTANTS.len() * 4;
    let mut bytes = Vec::with_capacity(expected_bytes + 1);
    file.take(expected_bytes as u64 + 1).read_to_end(&mut bytes).expect("read bounded constant section");
    let oracle = constants_layout(&bytes).expect("independently reviewed exact little-endian target constants");
    assert_eq!(oracle, expected(), "independent C compiler layout differs from the authored SysV schema");
    let mut engine = open(&[0xc3]);
    engine.parse_c(DECLARATION).unwrap();
    engine.assert_plain_struct_layout(&oracle).unwrap();
}

#[test]
#[ignore = "requires centrally compiled layout_use.c .text (see the fixture build recipe)"]
fn actual_c_field_use_uses_real_types_and_assertion_does_not_change_semantics() {
    let bytes = std::fs::read(std::env::var_os("RAMPAGE_LAYOUT_TEXT").expect("compiled .text path")).unwrap();
    let mut checked = open(&bytes);
    checked.parse_c(DECLARATION).unwrap();
    checked.assert_plain_struct_layout(&expected()).unwrap();
    checked.set_symbol(0x1000, "layout_use").unwrap();
    checked.apply_prototype(0x1000, false, "int4 layout_use(layout_flat *item);").unwrap();
    let text = checked.decompile(0x1000, "layout_use", false).unwrap();
    for field in ["count", "value", "tail"] {
        assert!(text.contains(&format!("->{field}")), "missing actual C field use {field}: {text}");
    }
    let mut control = open(&bytes);
    control.parse_c(DECLARATION).unwrap();
    control.set_symbol(0x1000, "layout_use").unwrap();
    control.apply_prototype(0x1000, false, "int4 layout_use(layout_flat *item);").unwrap();
    assert_eq!(control.decompile(0x1000, "layout_use", false).unwrap(), text);
}
