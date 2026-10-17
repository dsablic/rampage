use rampage_arch::Arch;
use rampage_decompiler::{Decompiler, DecompilerOptions, MemoryRegion, NamedTypeKind, Platform};

fn engine(arch: Arch, platform: Platform) -> Decompiler {
    Decompiler::open_with_options(
        arch,
        false,
        &[MemoryRegion { base: 0x1000, bytes: &[0xc3], size: 1, readable: true, writable: false, executable: true }],
        &DecompilerOptions { platform, compiler: None, arm_be8: false },
    )
    .unwrap()
}

#[test]
fn native_inventory_preserves_alias_enum_union_callback_and_dependency_evidence() {
    let mut engine = engine(Arch::X86_64, Platform::Default);
    let roots = engine
        .parse_type_library(
            "typedef unsigned int Count;
             enum Mode { Idle, Busy = 3, Done };
             union Payload { unsigned int number; unsigned char bytes[4]; };
             typedef int (*Callback)(struct Packet *packet, Count count);
             struct Packet { Count count; enum Mode mode; union Payload payload;
                             Callback callback; struct Packet *next; };",
            None,
        )
        .unwrap();
    assert_eq!(
        roots.iter().map(|ty| ty.name.as_str()).collect::<Vec<_>>(),
        ["Count", "Mode", "Payload", "Callback", "Packet"]
    );
    let count = engine.get_type("Count").unwrap();
    assert_eq!(count.kind, NamedTypeKind::Typedef);
    assert_eq!(count.target.as_deref(), Some("uint4"));
    assert_eq!(count.size, Some(4));
    let mode = engine.get_type("Mode").unwrap();
    let values: std::collections::BTreeMap<_, _> =
        mode.enum_values.iter().map(|entry| (entry.name.as_str(), entry.value.as_str())).collect();
    assert_eq!(values["Idle"], "0");
    assert_eq!(values["Busy"], "3");
    assert_eq!(values["Done"], "4");
    let payload = engine.get_type("Payload").unwrap();
    assert_eq!(payload.kind, NamedTypeKind::Union);
    assert_eq!(payload.size, Some(4));
    assert!(payload.fields.iter().all(|field| field.offset == 0));
    let callback = engine.get_type("Callback").unwrap();
    assert_eq!(callback.size, Some(8));
    let signature = callback.callback.unwrap();
    assert_eq!(signature.return_type, "int4");
    assert_eq!(signature.parameters[0].type_name, "Packet *");
    assert_eq!(signature.parameters[1].type_name, "Count");
    assert_eq!(callback.dependencies, ["Count", "Packet"]);
    assert!(callback.by_value_dependencies.is_empty());
    let packet = engine.get_type("Packet").unwrap();
    assert_eq!(packet.fields.iter().map(|field| field.offset).collect::<Vec<_>>(), [0, 4, 8, 16, 24]);
    assert_eq!(packet.size, Some(32));
    assert_eq!(packet.dependencies, ["Callback", "Count", "Mode", "Packet", "Payload"]);
    assert!(!packet.by_value_dependencies.iter().any(|name| name == "Packet"));
    assert!(engine.type_inventory().unwrap().iter().all(|ty| ty.name != "int4"));
}

#[test]
fn tags_aliases_forward_completion_and_nested_arrays_are_native() {
    let mut engine = engine(Arch::X86_64, Platform::Default);
    let roots = engine
        .parse_type_library(
            "typedef struct Same { int value; } Same;
             typedef struct Tag { Same inner; } Alias;
             typedef unsigned short Matrix[2][3];
             struct Outer { struct Nested { int value; } nested; Matrix matrix; };",
            None,
        )
        .unwrap();
    assert_eq!(
        roots.iter().map(|ty| ty.name.as_str()).collect::<Vec<_>>(),
        ["Same", "Tag", "Alias", "Matrix", "Outer"]
    );
    assert_eq!(engine.get_type("Tag").unwrap().size, Some(4));
    assert_eq!(engine.get_type("Alias").unwrap().target.as_deref(), Some("Tag"));
    assert_eq!(engine.get_type("Nested").unwrap().size, Some(4));
    assert_eq!(engine.get_type("Matrix").unwrap().size, Some(12));
    let outer = engine.get_type("Outer").unwrap();
    assert_eq!(outer.fields[1].size, Some(12));
    assert_eq!(outer.dependencies, ["Matrix", "Nested"]);
    engine.parse_type_library("struct Forward; typedef struct Forward ForwardAlias;", None).unwrap();
    let incomplete = engine.get_type("Forward").unwrap();
    assert!(incomplete.incomplete);
    assert_eq!(incomplete.size, None);
    assert_eq!(incomplete.alignment, None);
    engine.parse_type_library("struct Forward { int value; }; struct Uses { ForwardAlias value; };", None).unwrap();
    assert_eq!(engine.get_type("ForwardAlias").unwrap().size, Some(4));
    assert_eq!(engine.get_type("Uses").unwrap().size, Some(4));
    let void = engine.get_type("void").unwrap();
    assert_eq!(void.size, None);
    assert_eq!(void.alignment, None);
    engine.parse_type_library("typedef void Function(void);", None).unwrap();
    assert_eq!(engine.get_type("Function").unwrap().size, None);
    assert!(engine.get_type("missing").is_err());
    assert!(engine.get_type("Same").is_ok(), "read-only query errors must not poison the handle");
}

#[test]
fn target_compiler_layout_does_not_use_the_host_abi() {
    for (arch, platform, long_size, pointer_offset, total_size) in [
        (Arch::X86_64, Platform::Default, 8, 16, 24),
        (Arch::X86_64, Platform::Windows, 4, 8, 16),
        (Arch::Aarch64, Platform::Default, 8, 16, 24),
        (Arch::Aarch64, Platform::Windows, 4, 8, 16),
    ] {
        let mut engine = engine(arch, platform);
        engine.parse_type_library("struct Abi { char tag; long value; void *pointer; };", None).unwrap();
        let ty = engine.get_type("Abi").unwrap();
        assert_eq!(ty.fields[1].size, Some(long_size), "{arch}/{platform:?}");
        assert_eq!(ty.fields[2].offset, pointer_offset, "{arch}/{platform:?}");
        assert_eq!(ty.size, Some(total_size), "{arch}/{platform:?}");
    }
}

#[test]
fn packing_is_applied_before_nested_and_dependent_native_layouts() {
    for (packing, offset, inner_size, outer_offset, outer_size) in
        [(1, 1, 5, 1, 6), (2, 2, 6, 2, 8), (4, 4, 8, 4, 12), (8, 4, 8, 4, 12), (16, 4, 8, 4, 12)]
    {
        let mut engine = engine(Arch::X86_64, Platform::Default);
        engine
            .parse_type_library(
                "struct Inner { char prefix; int value; }; struct Outer { char prefix; struct Inner value; };
             struct Inline { char prefix; struct { char tag; int value; } nested; };
             union PackedUnion { char bytes[3]; unsigned short word; };",
                Some(packing),
            )
            .unwrap();
        let inner = engine.get_type("Inner").unwrap();
        assert_eq!(inner.fields[1].offset, offset);
        assert_eq!(inner.size, Some(inner_size));
        assert_eq!(inner.packing, Some(packing));
        let outer = engine.get_type("Outer").unwrap();
        assert_eq!(outer.fields[1].offset, outer_offset);
        assert_eq!(outer.size, Some(outer_size));
        assert_eq!(engine.get_type("Inline").unwrap().size, Some(outer_size));
        let union = engine.get_type("PackedUnion").unwrap();
        assert_eq!(union.size, Some(if packing == 1 { 3 } else { 4 }));
    }
}

#[test]
fn malformed_duplicate_nontype_incomplete_byvalue_and_budget_inputs_fail_closed() {
    let many_fields =
        format!("struct TooMany {{ {} }};", (0..257).map(|i| format!("int field{i};")).collect::<String>());
    let many_enums =
        format!("enum TooMany {{ {} }};", (0..257).map(|i| format!("entry{i} = {i}")).collect::<Vec<_>>().join(","));
    let many_names = (0..257).map(|i| format!("typedef int Name{i};")).collect::<String>();
    for source in [
        "struct Broken { int value;",
        "struct Bad { void value; };",
        "struct Duplicate { int value; }; struct Duplicate { int other; };",
        "typedef int Alias; typedef int Alias;",
        "enum E { A }; enum E { B };",
        "struct Bad { int repeated; int repeated; };",
        "enum Bad { Repeated = 1, Repeated = 2 };",
        "extern int function(int value);",
        "int object;",
        "struct Defined { int value; } object;",
        "struct Missing; struct Bad { struct Missing value; };",
        "struct Bad { int bits:3; };",
        "typedef int Overflow[65536][65536];",
        &many_fields,
        &many_enums,
        &many_names,
    ] {
        let mut engine = engine(Arch::X86_64, Platform::Default);
        assert!(engine.parse_type_library(source, None).is_err(), "unexpectedly accepted {source}");
    }
    let mut engine = engine(Arch::X86_64, Platform::Default);
    assert!(engine.parse_type_library(&" ".repeat(65537), None).is_err());
    assert!(engine.parse_type_library("typedef int Value;", Some(3)).is_err());
    assert!(engine.parse_type_library("typedef int Value;", None).is_ok());
}

#[test]
fn excessive_direct_callback_dependencies_fail_without_truncating_or_reusing_the_engine() {
    let mut engine = engine(Arch::X86_64, Platform::Default);
    let declarations = (0..256).map(|i| format!("struct Dependency{i};")).collect::<String>();
    engine.parse_type_library(&declarations, None).unwrap();
    let parameters = (0..256).map(|i| format!("struct Dependency{i} *parameter{i}")).collect::<Vec<_>>().join(",");
    let callback = format!("typedef struct FinalDependency *(*OverBudget)({parameters});");
    let error = engine.parse_type_library(&callback, None).unwrap_err().to_string();
    assert!(error.contains("256"), "{error}");
    assert!(engine.get_type("Dependency0").is_err(), "failed native transactions must poison the engine");
}

#[test]
fn variadic_callback_and_signed_enum_values_survive_native_inspection() {
    let mut engine = engine(Arch::X86_64, Platform::Default);
    engine
        .parse_type_library(
            "typedef int (*Fixed)(char *format); typedef int (*Variadic)(char *format, ...);
             enum SignedValues { Negative = -1, Zero, Positive };",
            None,
        )
        .unwrap();
    assert!(engine.get_type("Variadic").unwrap().callback.unwrap().variadic);
    assert!(!engine.get_type("Fixed").unwrap().callback.unwrap().variadic);
    let values = engine.get_type("SignedValues").unwrap().enum_values;
    assert_eq!(values.iter().find(|value| value.name == "Zero").unwrap().value, "0");
    assert_eq!(values.iter().find(|value| value.name == "Positive").unwrap().value, "1");
    let negative = &values.iter().find(|value| value.name == "Negative").unwrap().value;
    assert_eq!(negative, "-1");
}

#[test]
fn c_enum_width_alignment_and_negative_values_follow_the_selected_integer_organization() {
    for (arch, platform) in [
        (Arch::X86_64, Platform::Default),
        (Arch::X86_64, Platform::Windows),
        (Arch::Aarch64, Platform::Default),
        (Arch::Aarch64, Platform::Windows),
    ] {
        let mut engine = engine(arch, platform);
        engine
            .parse_type_library(
                "enum Signed { Negative = -3, Positive = 7 };
             struct EnumRecord { uint4 prefix; enum Signed mode; uint4 payload; void *callback; void *next; };",
                None,
            )
            .unwrap();
        let enumeration = engine.get_type("Signed").unwrap();
        assert_eq!(enumeration.size, Some(u64::from(engine.data_organization().int)), "{arch}/{platform:?}");
        assert_eq!(enumeration.alignment, Some(4), "{arch}/{platform:?}");
        assert_eq!(enumeration.enum_values.iter().find(|value| value.name == "Negative").unwrap().value, "-3");
        assert_eq!(enumeration.enum_values.iter().find(|value| value.name == "Positive").unwrap().value, "7");
        let record = engine.get_type("EnumRecord").unwrap();
        assert_eq!(
            record.fields.iter().map(|field| field.offset).collect::<Vec<_>>(),
            [0, 4, 8, 16, 24],
            "{arch}/{platform:?}"
        );
        assert_eq!(record.size, Some(32), "{arch}/{platform:?}");
    }
}

#[test]
fn c_enums_accept_signed_integer_extremes_and_refuse_overflow_without_truncating() {
    let mut valid = engine(Arch::X86_64, Platform::Default);
    valid.parse_type_library("enum Limits { Min = -2147483648, Max = 2147483647 };", None).unwrap();
    let values = valid.get_type("Limits").unwrap().enum_values;
    assert_eq!(values.iter().find(|value| value.name == "Min").unwrap().value, "-2147483648");
    assert_eq!(values.iter().find(|value| value.name == "Max").unwrap().value, "2147483647");
    for declaration in [
        "enum Overflow { Value = 2147483648 };",
        "enum Overflow { Value = -2147483649 };",
        "enum Overflow { Max = 2147483647, ImplicitOverflow };",
        "enum Overflow { Value = 9223372036854775808 };",
        "enum Overflow { Value = 18446744073709551615 };",
        "enum Overflow { Value = -9223372036854775809 };",
    ] {
        let mut engine = engine(Arch::X86_64, Platform::Default);
        assert!(engine.parse_type_library(declaration, None).is_err(), "accepted {declaration}");
    }
}

#[test]
fn forward_callback_and_same_tag_definition_complete_within_one_batch() {
    let mut engine = engine(Arch::X86_64, Platform::Default);
    let roots = engine
        .parse_type_library(
            "struct Record; typedef int4 (*Cb)(struct Record *p);
         typedef struct Record { uint1 tag; Cb cb; struct Record *next; } Record;",
            None,
        )
        .unwrap();
    assert_eq!(roots.iter().map(|ty| ty.name.as_str()).collect::<Vec<_>>(), ["Record", "Cb"]);
    assert!(!roots[0].incomplete);
    assert_eq!(roots[0].size, Some(24));
    assert_eq!(roots[0].fields.iter().map(|field| field.offset).collect::<Vec<_>>(), [0, 8, 16]);
    assert_eq!(roots[0].dependencies, ["Cb", "Record"]);
    assert!(roots[0].by_value_dependencies.is_empty());
    let roots = engine
        .parse_type_library("typedef struct ReturnOnly *(*OtherCallback)(struct ParameterOnly *p);", None)
        .unwrap();
    assert_eq!(roots.iter().map(|ty| ty.name.as_str()).collect::<Vec<_>>(), ["OtherCallback"]);
    assert!(engine.get_type("ReturnOnly").unwrap().incomplete);
    assert!(engine.get_type("ParameterOnly").unwrap().incomplete);
}

#[test]
fn callbacks_keep_declared_aggregate_types_names_and_models_before_abi_lowering() {
    for (arch, platform) in [
        (Arch::X86_64, Platform::Default),
        (Arch::X86_64, Platform::Windows),
        (Arch::Aarch64, Platform::Default),
        (Arch::Aarch64, Platform::Windows),
    ] {
        let mut engine = engine(arch, platform);
        engine
            .parse_type_library(
                "struct Large { int8 first; int8 second; int8 third; };
             typedef struct Large (*ReturnLarge)(struct Large value, int4 marker);
             typedef struct Large *(*ReturnPointer)(struct Large *value, int4 marker);",
                None,
            )
            .unwrap();
        let callback = engine.get_type("ReturnLarge").unwrap();
        let signature = callback.callback.unwrap();
        assert_eq!(signature.return_type, "Large", "{arch}/{platform:?}");
        assert_eq!(signature.parameters.len(), 2, "hidden return parameters must not be exported");
        assert_eq!(signature.parameters[0].name, "value");
        assert_eq!(signature.parameters[0].type_name, "Large", "{arch}/{platform:?}");
        assert_eq!(signature.parameters[1].name, "marker");
        assert_eq!(signature.parameters[1].type_name, "int4");
        assert!(signature.calling_convention.is_some());
        assert_eq!(callback.dependencies, ["Large"]);
        let pointer = engine.get_type("ReturnPointer").unwrap().callback.unwrap();
        assert_eq!(pointer.return_type, "Large *");
        assert_eq!(pointer.parameters[0].type_name, "Large *");
    }
}

#[test]
fn c_integer_specifiers_accept_interleaved_qualifiers_and_reject_contradictions() {
    let mut valid = engine(Arch::X86_64, Platform::Default);
    valid
        .parse_type_library(
            "typedef unsigned const int Count; typedef int volatile unsigned OtherCount;
         typedef signed const char Byte; typedef long volatile long int Wide;
         struct Qualified { Count count; OtherCount other; Byte byte; Wide wide; };",
            None,
        )
        .unwrap();
    assert_eq!(valid.get_type("Count").unwrap().target.as_deref(), Some("uint4"));
    assert_eq!(valid.get_type("OtherCount").unwrap().target.as_deref(), Some("uint4"));
    assert_eq!(valid.get_type("Byte").unwrap().target.as_deref(), Some("int1"));
    assert_eq!(valid.get_type("Wide").unwrap().size, Some(8));
    for specifiers in [
        "signed unsigned int",
        "unsigned const signed int",
        "unsigned unsigned int",
        "int volatile int",
        "short long int",
        "long long long",
        "char int",
        "unsigned float",
        "int double",
        "short short",
    ] {
        let mut engine = engine(Arch::X86_64, Platform::Default);
        let declaration = format!("typedef {specifiers} Invalid;");
        assert!(engine.parse_type_library(&declaration, None).is_err(), "accepted {declaration}");
    }
}

#[test]
fn nonobject_arrays_and_hidden_oversized_types_are_rejected_before_publication() {
    for declaration in [
        "typedef int Function(void); typedef Function Functions[2];",
        "typedef int Function(void); struct Invalid { Function members[2]; };",
        "typedef void Void; typedef Void Invalid[2];",
        "typedef struct Huge { char a[65536][16]; char b[65536][16]; } *Handle;",
        "typedef struct Outer { struct { char a[65536][16]; char b[65536][16]; } hidden; } *Handle;",
        "typedef char (*Handle)[65536][32];",
    ] {
        let mut engine = engine(Arch::X86_64, Platform::Default);
        assert!(engine.parse_type_library(declaration, None).is_err(), "accepted {declaration}");
    }
    let nested = (0..256).map(|i| format!("struct Nested{i} {{ int4 value; }} field{i};")).collect::<String>();
    let mut engine = engine(Arch::X86_64, Platform::Default);
    assert!(engine.parse_type_library(&format!("struct Container {{ {nested} }};"), None).is_err());
}

#[test]
fn anonymous_callback_identity_preserves_nested_signatures_and_calling_conventions() {
    for (left, right) in [
        ("struct S { int4 (*cb)(int4); };", "struct S { void (*cb)(float8); };"),
        ("struct S { int4 (**cb)(int4); };", "struct S { int4 (**cb)(float8); };"),
        ("struct S { int4 (*cb[2])(int4); };", "struct S { int4 (*cb[2])(float8); };"),
        ("struct S { struct { int4 (*cb)(int4); } nested; };", "struct S { struct { int4 (*cb)(float8); } nested; };"),
    ] {
        let mut left_engine = engine(Arch::X86_64, Platform::Default);
        left_engine.parse_type_library(left, None).unwrap();
        let left_type = left_engine.get_type("S").unwrap();
        let mut right_engine = engine(Arch::X86_64, Platform::Default);
        right_engine.parse_type_library(right, None).unwrap();
        let right_type = right_engine.get_type("S").unwrap();
        assert_eq!(left_type.fields[0].size, right_type.fields[0].size);
        assert_ne!(left_type.fields[0].identity, right_type.fields[0].identity);
        assert_ne!(left_type, right_type);
    }
    let mut cdecl = engine(Arch::X86, Platform::Windows);
    cdecl.parse_type_library("struct S { int4 __cdecl (*cb)(int4 value); };", None).unwrap();
    let mut stdcall = engine(Arch::X86, Platform::Windows);
    stdcall.parse_type_library("struct S { int4 __stdcall (*cb)(int4 value); };", None).unwrap();
    assert_ne!(cdecl.get_type("S").unwrap().identity, stdcall.get_type("S").unwrap().identity);
}

#[test]
fn native_prototypes_globals_and_member_names_accept_existing_aggregate_and_typedef_names() {
    let mut engine = Decompiler::open_with_options(
        Arch::X86_64,
        false,
        &[
            MemoryRegion { base: 0x1000, bytes: &[0xc3], size: 1, readable: true, writable: false, executable: true },
            MemoryRegion { base: 0x2000, bytes: &[0; 16], size: 16, readable: true, writable: true, executable: false },
        ],
        &DecompilerOptions::default(),
    )
    .unwrap();
    engine
        .parse_type_library(
            "struct State { int4 value; }; typedef int4 String;
         struct Holder { int4 String; }; typedef int4 (*Named)(int4 String, struct State *State);",
            None,
        )
        .unwrap();
    let holder = engine.get_type("Holder").unwrap();
    assert_eq!(holder.fields[0].name, "String");
    assert!(holder.dependencies.is_empty(), "field identifiers are not type dependency edges");
    let parameters = engine.get_type("Named").unwrap().callback.unwrap().parameters;
    assert_eq!(parameters[0].name, "String");
    assert_eq!(parameters[1].name, "State");
    engine.set_symbol(0x1000, "subject").unwrap();
    engine.apply_prototype(0x1000, false, "int4 subject(struct State *String);").unwrap();
    engine.add_global(0x2000, "struct State data;").unwrap();
    engine.parse_c("typedef struct State *StatePointer;").unwrap();
    assert_eq!(engine.get_type("StatePointer").unwrap().size, Some(8));
}
