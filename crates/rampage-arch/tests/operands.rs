use rampage_arch::{Arch, OperandEvidence, OperandKind, decoder_for};

fn x64(bytes: &[u8]) -> Vec<OperandEvidence> {
    decoder_for(Arch::X86_64).unwrap().operands(bytes, 0x1000).unwrap()
}

fn a64(word: u32) -> Vec<OperandEvidence> {
    decoder_for(Arch::Aarch64).unwrap().operands(&word.to_le_bytes(), 0x1000).unwrap()
}

#[test]
fn x64_comparison_exposes_memory_and_logical_immediate_widths() {
    let operands = x64(&[0x83, 0x3f, 0x07]); // cmp dword ptr [rdi], 7
    assert_eq!(operands.len(), 2);
    assert_eq!(operands[0].index, 0);
    assert_eq!(operands[0].kind, OperandKind::Memory);
    assert_eq!(operands[0].width_bits, Some(32));
    let memory = operands[0].memory.as_ref().unwrap();
    assert_eq!(memory.base.as_deref(), Some("rdi"));
    assert_eq!(memory.displacement, 0);
    assert_eq!(memory.access_size, Some(4));
    assert!(!memory.relative);
    assert_eq!(operands[1].index, 1);
    assert_eq!(operands[1].kind, OperandKind::Immediate);
    assert_eq!(operands[1].immediate, Some(7));
    assert_eq!(operands[1].signed_value, Some(7));
    assert_eq!(operands[1].width_bits, Some(32));
}

#[test]
fn x64_memory_indices_follow_explicit_intel_order() {
    let operands = x64(&[0x8b, 0x47, 0x04]); // mov eax, [rdi + 4]
    assert_eq!(operands[0].kind, OperandKind::Register);
    assert_eq!(operands[0].width_bits, Some(32));
    assert_eq!(operands[1].index, 1);
    let memory = operands[1].memory.as_ref().unwrap();
    assert_eq!(memory.base.as_deref(), Some("rdi"));
    assert_eq!(memory.index, None);
    assert_eq!(memory.displacement, 4);
    assert_eq!(memory.access_size, Some(4));
}

#[test]
fn x86_immediates_use_semantic_sign_extension_and_width_truncation() {
    for (bytes, width, raw) in [
        (&[0x83, 0xf8, 0xfd][..], 32, 0xffff_fffd),             // cmp eax, -3 (imm8)
        (&[0x3d, 0xfd, 0xff, 0xff, 0xff][..], 32, 0xffff_fffd), // cmp eax, -3 (imm32)
        (&[0x48, 0x83, 0xf8, 0xfd][..], 64, 0xffff_ffff_ffff_fffd), // cmp rax, -3
        (&[0x66, 0x83, 0xf8, 0xfd][..], 16, 0xfffd),            // cmp ax, -3
        (&[0x3c, 0xfd][..], 8, 0xfd),                           // cmp al, -3
    ] {
        let operand = &x64(bytes)[1];
        assert_eq!(operand.immediate, Some(raw), "{bytes:02x?}");
        assert_eq!(operand.signed_value, Some(-3), "{bytes:02x?}");
        assert_eq!(operand.width_bits, Some(width), "{bytes:02x?}");
    }
    let operands = decoder_for(Arch::X86).unwrap().operands(&[0x83, 0xf8, 0xfd], 0x1000).unwrap();
    assert_eq!(operands[1].immediate, Some(0xffff_fffd));
    assert_eq!(operands[1].signed_value, Some(-3));
}

#[test]
fn x64_memory_displacements_keep_scale_sign_and_relative_address_identity() {
    let operands = x64(&[0x8b, 0x44, 0x8f, 0xfc]); // mov eax, [rdi + rcx*4 - 4]
    let memory = operands[1].memory.as_ref().unwrap();
    assert_eq!(memory.base.as_deref(), Some("rdi"));
    assert_eq!(memory.index.as_deref(), Some("rcx"));
    assert_eq!(memory.scale, 4);
    assert_eq!(memory.displacement, -4);
    assert!(!memory.relative);

    let operands = x64(&[0x8b, 0x05, 0xfc, 0xff, 0xff, 0xff]); // mov eax, [rip - 4]
    let memory = operands[1].memory.as_ref().unwrap();
    assert_eq!(memory.base.as_deref(), Some("rip"));
    assert_eq!(memory.displacement, -4);
    assert!(memory.relative);

    let operands = x64(&[0x67, 0x8b, 0x05, 0xfc, 0xff, 0xff, 0xff]); // mov eax, [eip - 4]
    let memory = operands[1].memory.as_ref().unwrap();
    assert_eq!(memory.base.as_deref(), Some("eip"));
    assert_eq!(memory.displacement, -4);
    assert!(memory.relative);

    let operands = x64(&[0x8b, 0x04, 0x25, 0x04, 0x10, 0x00, 0x00]); // absolute [0x1004]
    let memory = operands[1].memory.as_ref().unwrap();
    assert_eq!(memory.base, None);
    assert_eq!(memory.displacement, 0x1004);
    assert!(!memory.relative);
}

#[test]
fn x64_unsupported_operands_keep_their_indices_and_address_formation_is_not_an_access() {
    let operands = x64(&[0x64, 0x83, 0x3f, 0x07]); // cmp dword ptr fs:[rdi], 7
    assert_eq!(operands[0].kind, OperandKind::Unsupported);
    assert_eq!(operands[0].index, 0);
    assert_eq!(operands[1].index, 1);
    assert_eq!(operands[1].immediate, Some(7));
    let operands = x64(&[0x48, 0x8d, 0x47, 0x04]); // lea rax, [rdi + 4]
    assert_eq!(operands[1].memory.as_ref().unwrap().access_size, None);
    assert_eq!(operands[1].width_bits, None);
}

#[test]
fn a64_memory_placeholders_collapse_to_one_explicit_memory_operand() {
    for (word, displacement, access_size, register_width) in [
        (0xb940_0400, 4, 4, 32),  // ldr w0, [x0, #4]
        (0xb900_0400, 4, 4, 32),  // str w0, [x0, #4]
        (0xf940_0400, 8, 8, 64),  // ldr x0, [x0, #8]
        (0x3940_0400, 1, 1, 32),  // ldrb w0, [x0, #1]
        (0xb85f_c000, -4, 4, 32), // ldur w0, [x0, #-4]
        (0xb81f_c000, -4, 4, 32), // stur w0, [x0, #-4]
    ] {
        let operands = a64(word);
        assert_eq!(operands.len(), 2, "{word:08x}");
        assert_eq!(operands[0].index, 0);
        assert_eq!(operands[0].kind, OperandKind::Register);
        assert_eq!(operands[0].width_bits, Some(register_width));
        assert_eq!(operands[1].index, 1);
        assert_eq!(operands[1].kind, OperandKind::Memory);
        assert_eq!(operands[1].width_bits, Some(access_size * 8));
        let memory = operands[1].memory.as_ref().unwrap();
        assert_eq!(memory.base.as_deref(), Some("x0"));
        assert_eq!(memory.displacement, displacement);
        assert_eq!(memory.access_size, Some(access_size));
        assert!(!memory.relative);
    }
}

#[test]
fn a64_aliases_preserve_the_rendered_immediate_index_and_semantic_width() {
    let operands = a64(0x7100_1c3f); // cmp w1, #7
    assert_eq!(operands.len(), 2);
    assert_eq!(operands[0].kind, OperandKind::Register);
    assert_eq!(operands[1].index, 1);
    assert_eq!(operands[1].kind, OperandKind::Immediate);
    assert_eq!(operands[1].immediate, Some(7));
    assert_eq!(operands[1].width_bits, Some(32));

    let operands = a64(0x1280_0040); // mov w0, #-3 (MOVN)
    assert_eq!(operands[1].index, 1);
    assert_eq!(operands[1].immediate, Some(0xffff_fffd));
    assert_eq!(operands[1].signed_value, Some(-3));
    assert_eq!(operands[1].width_bits, Some(32));

    let operands = a64(0x9240_1c20); // and x0, x1, #0xff
    assert_eq!(operands[2].index, 2);
    assert_eq!(operands[2].immediate, Some(0xff));
    assert_eq!(operands[2].width_bits, Some(64));

    let operands = a64(0x5280_00e0); // mov w0, #7 (MOVZ)
    assert_eq!(operands[1].index, 1);
    assert_eq!(operands[1].immediate, Some(7));
    assert_eq!(operands[1].width_bits, Some(32));
}

#[test]
fn a64_add_immediate_proves_base_offset_but_not_a_memory_access() {
    let operands = a64(0x9100_1020); // add x0, x1, #4
    assert_eq!(operands.len(), 3);
    assert_eq!(operands[2].index, 2);
    assert_eq!(operands[2].kind, OperandKind::Immediate);
    assert_eq!(operands[2].immediate, Some(4));
    let memory = operands[2].memory.as_ref().unwrap();
    assert_eq!(memory.base.as_deref(), Some("x1"));
    assert_eq!(memory.displacement, 4);
    assert_eq!(memory.access_size, None);

    let operands = a64(0x9140_0420); // add x0, x1, #1, lsl #12
    assert_eq!(operands[2].immediate, Some(4096));
    assert_eq!(operands[2].memory.as_ref().unwrap().displacement, 4096);
    assert_eq!(operands[3].index, 3);
    assert_eq!(operands[3].kind, OperandKind::Unsupported);

    let operands = a64(0x1100_1020); // add w0, w1, #4 is not a 64-bit pointer-base addition
    assert_eq!(operands[2].immediate, Some(4));
    assert_eq!(operands[2].memory, None);
}

#[test]
fn invalid_truncated_trailing_or_unsupported_instructions_do_not_prove_selectors() {
    let x86 = decoder_for(Arch::X86_64).unwrap();
    for bytes in [&[][..], &[0x0f][..], &[0x8b, 0x47][..], &[0x90, 0x90][..], &[0x60][..]] {
        assert_eq!(x86.operands(bytes, 0x1000), None, "{bytes:02x?}");
    }
    let arm = decoder_for(Arch::Aarch64).unwrap();
    for bytes in [&[][..], &[0, 4, 0x40][..], &[0; 4][..], &[0; 8][..]] {
        assert_eq!(arm.operands(bytes, 0x1000), None, "{bytes:02x?}");
    }
    assert_eq!(arm.operands(&0xb940_0400u32.to_le_bytes(), 0x1001), None);
    // Literal, register-offset, pre-index and SIMD loads have no object-base offset evidence yet.
    for word in [0x1800_0020u32, 0xb861_6800, 0xb840_4c00, 0x3dc0_0400] {
        assert_eq!(arm.operands(&word.to_le_bytes(), 0x1000), None, "{word:08x}");
    }
    assert_eq!(decoder_for(Arch::Arm).unwrap().operands(&[0, 0, 0xa0, 0xe1], 0x1000), None);
}

#[test]
fn operand_queries_do_not_change_decoder_flow_state() {
    let mut queried = decoder_for(Arch::Aarch64).unwrap();
    let mut untouched = decoder_for(Arch::Aarch64).unwrap();
    let page = 0x9000_0000u32.to_le_bytes(); // adrp x0, current page
    assert_eq!(queried.decode(&page, 0x1000), untouched.decode(&page, 0x1000));
    assert!(queried.operands(&0x9100_1020u32.to_le_bytes(), 0x2000).is_some());
    let add = 0x9100_1000u32.to_le_bytes(); // add x0, x0, #4
    assert_eq!(queried.decode(&add, 0x1004), untouched.decode(&add, 0x1004));
}

#[test]
fn absolute_memory_displacements_serialize_losslessly_as_decimal_strings() {
    for (arch, bytes, expected) in [
        (Arch::X86_64, &[0x48, 0xa1, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00][..], 9_007_199_254_740_993i64),
        (Arch::X86_64, &[0x48, 0xa1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xdf, 0xff][..], -9_007_199_254_740_993),
        (Arch::X86_64, &[0x48, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80][..], i64::MIN),
        (Arch::X86_64, &[0x48, 0xa1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f][..], i64::MAX),
        (Arch::X86, &[0xa1, 0x01, 0x00, 0x00, 0x80][..], 2_147_483_649),
        (Arch::X86, &[0xa1, 0xff, 0xff, 0xff, 0xff][..], 4_294_967_295),
    ] {
        let operands = decoder_for(arch).unwrap().operands(bytes, 0x1000).unwrap();
        let memory = operands[1].memory.as_ref().unwrap();
        assert_eq!(memory.displacement, expected, "{bytes:02x?}");
        assert_eq!(memory.base, None);
        assert!(!memory.relative);
        let json = serde_json::to_string(&operands).unwrap();
        let json: serde_json::Value = serde_json::from_str(&json).unwrap();
        let displacement = json[1]["memory"]["displacement"].as_str().unwrap();
        assert_eq!(displacement, expected.to_string());
        assert_eq!(displacement.parse::<i64>().unwrap(), expected);
        assert!(json[1]["index"].is_number());
        assert!(json[1]["width_bits"].is_number());
        assert!(json[1]["memory"]["scale"].is_number());
        assert!(json[1]["memory"]["access_size"].is_number());
    }
}

#[test]
fn signed_immediate_json_keeps_decimal_strings_alongside_hexadecimal_raw_bits() {
    let operands = x64(&[0x83, 0xf8, 0xfd]); // cmp eax, -3
    let json = serde_json::to_string(&operands).unwrap();
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(json[1]["immediate"].as_str(), Some("0xfffffffd"));
    assert_eq!(json[1]["signed_value"].as_str(), Some("-3"));
    assert!(json[1]["memory"].is_null());
    assert!(json[0]["signed_value"].is_null());
}
