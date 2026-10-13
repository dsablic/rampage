use rampage_arch::{Arch, Disassembler, Flow, JumpTable, MAX_JUMP_TABLE_ENTRIES, decoder_for};

// call next; pop eax; add eax, 0x2ffb: eax holds 0x4000.
const PC_BASE: [u8; 11] = [0xe8, 0, 0, 0, 0, 0x58, 0x05, 0xfb, 0x2f, 0, 0];
const BOUND: [u8; 5] = [0x83, 0xfa, 3, 0x77, 0x60];
// add eax, [eax + edx*4 - 0x2000]
const ADD_MEMORY: [u8; 7] = [0x03, 0x84, 0x90, 0, 0xe0, 0xff, 0xff];
const JUMP: [u8; 2] = [0xff, 0xe0];

fn step(decoder: &mut dyn Disassembler, bytes: &[u8], address: &mut u64) {
    let mut offset = 0;
    while offset < bytes.len() {
        let instruction = decoder.decode(&bytes[offset..], *address);
        assert_ne!(instruction.flow, Flow::Invalid);
        offset += usize::from(instruction.len);
        *address += u64::from(instruction.len);
    }
    assert_eq!(offset, bytes.len());
}

fn dispatch(prefix: &[u8], bound: &[u8], gap: &[u8], add: &[u8], after: &[u8]) -> Option<JumpTable> {
    let mut decoder = decoder_for(Arch::X86).unwrap();
    let mut address = 0x1000;
    for bytes in [prefix, bound, gap, add, after, &JUMP] {
        step(decoder.as_mut(), bytes, &mut address);
    }
    decoder.jump_table()
}

#[test]
fn i386_memory_add_keeps_the_prewrite_base_and_signed_displacements() {
    let table = dispatch(&PC_BASE, &BOUND, &[], &ADD_MEMORY, &[]).unwrap();
    assert_eq!(table.guard, 0x100b);
    assert_eq!((table.table, table.base, table.entry_size, table.entries), (0x2000, Some(0x4000), 4, 4));
    assert!(table.signed);
    assert_eq!(table.target(0xffff_d234), Some(0x1234));
    assert_eq!(table.target(0x20), Some(0x4020));
    // Memory entries are offsets added to eax, not absolute target pointers.
    assert_eq!(table.target(0x1234), Some(0x5234));
}

#[test]
fn i386_relative_targets_use_modulo_32_for_high_bits_carry_and_negative_offsets() {
    for (base, raw, target) in [
        (0x4000u32, 0x8000_1234, 0x8000_5234),
        (0x4000, 0x7fff_e000, 0x8000_2000),
        (0x4000, 0xffff_8000, 0xffff_c000),
        (0x4000, 0xffff_d234, 0x1234),
        (0xffff_f000, 0x2000, 0x1000),
        (0xffff_f000, 0xffff_f000, 0xffff_e000),
        (0xffff_ffff, 1, 0),
    ] {
        let mut prefix = PC_BASE;
        prefix[7..].copy_from_slice(&base.wrapping_sub(0x1005).to_le_bytes());
        let displacement = 0x2000u32.wrapping_sub(base).to_le_bytes();
        let add = [&[0x03, 0x84, 0x90][..], &displacement].concat();
        let combined = dispatch(&prefix, &BOUND, &[], &add, &[]).unwrap();
        // Separate mov ecx, [eax + edx*4 + displacement]; add eax, ecx uses the same target width.
        let load_add = [&[0x8b, 0x8c, 0x90][..], &displacement, &[0x01, 0xc8]].concat();
        let separate = dispatch(&prefix, &BOUND, &[], &load_add, &[]).unwrap();
        for table in [combined, separate] {
            assert_eq!(table.table, 0x2000);
            assert_eq!(table.target(raw), Some(target), "base={base:#x} entry={raw:#x}");
        }
    }
}

#[test]
fn i386_table_entries_require_a_native_width_register_jump() {
    let forms: &[&[u8]] =
        &[&ADD_MEMORY, &[0x8b, 0x8c, 0x90, 0, 0xe0, 0xff, 0xff, 0x01, 0xc8], &[0x8b, 0x04, 0x95, 0, 0x20, 0, 0]];
    for &form in forms {
        let table = dispatch(&PC_BASE, &BOUND, &[], form, &[]).expect("jmp eax");
        let native_target = table.target(0x11234).unwrap();
        assert_ne!(native_target, native_target & 0xffff);
        let mut decoder = decoder_for(Arch::X86).unwrap();
        let mut address = 0x1000;
        for bytes in [&PC_BASE[..], &BOUND, form, &[0x66, 0xff, 0xe0]] {
            step(decoder.as_mut(), bytes, &mut address);
        }
        assert_eq!(decoder.jump_table(), None, "jmp ax after {form:x?}");
    }
}

#[test]
fn x64_relative_targets_keep_64_bit_arithmetic_even_with_a_low_base() {
    let mut decoder = decoder_for(Arch::X86_64).unwrap();
    let mut address = 0x1000;
    for bytes in [
        &[0x48, 0x8d, 0x05, 0xf9, 0x2f, 0, 0][..], // lea rax, [rip + 0x4000]
        &[0x48, 0x83, 0xfa, 3, 0x77, 0x60],
        &[0x48, 0x63, 0x8c, 0x90, 0, 0xe0, 0xff, 0xff], // movsxd rcx, [rax + rdx*4 - 0x2000]
        &[0x48, 0x01, 0xc8, 0xff, 0xe0],
    ] {
        step(decoder.as_mut(), bytes, &mut address);
    }
    let table = decoder.jump_table().unwrap();
    assert_eq!(table.base, Some(0x4000));
    assert_eq!(table.target(0x8000_1234), Some(0xffff_ffff_8000_5234));
    assert_eq!(table.target(0xffff_8000), Some(0xffff_ffff_ffff_c000));
    assert_eq!(table.target(0xffff_d234), Some(0x1234));
}

#[test]
fn memory_add_uses_known_base_and_bounded_index_copies() {
    // mov ebx, eax; add eax, [ebx + edx*4 - 0x2000]
    let aliased_base = [0x03, 0x84, 0x93, 0, 0xe0, 0xff, 0xff];
    let expected = dispatch(&PC_BASE, &BOUND, &[], &ADD_MEMORY, &[]);
    assert_eq!(dispatch(&PC_BASE, &BOUND, &[0x89, 0xc3], &aliased_base, &[]), expected);
    // Copy the target to ecx before clobbering eax, then restore it for the jump.
    assert_eq!(dispatch(&PC_BASE, &BOUND, &[], &ADD_MEMORY, &[0x89, 0xc1, 0x31, 0xc0, 0x89, 0xc8]), expected);
    // mov ecx, edx; cmp ecx, 3; ja: the bound reaches the unchanged edx copy.
    let copied_index = [&[0x89, 0xd1][..], &[0x83, 0xf9, 3, 0x77, 0x60]].concat();
    let table = dispatch(&PC_BASE, &copied_index, &[], &ADD_MEMORY, &[]).unwrap();
    assert_eq!((table.table, table.base, table.entries), (0x2000, Some(0x4000), 4));
}

#[test]
fn memory_add_preserves_get_pc_thunk_and_cross_block_evidence() {
    let mut decoder = decoder_for(Arch::X86).unwrap();
    let thunk = |address, size| (address == 0x3000 && size == 4).then_some(0xc324_048b);
    assert_eq!(decoder.decode_with_memory(&[0xe8, 0xfb, 0x1f, 0, 0], 0x1000, &thunk).flow, Flow::Call(0x3000));
    let mut address = 0x1005;
    step(decoder.as_mut(), &[0x05, 0xfb, 0x2f, 0, 0], &mut address);
    step(decoder.as_mut(), &BOUND, &mut address);
    let bounded = decoder.facts().unwrap();
    let unbounded = decoder.taken_facts().unwrap();
    for (facts, expected_entries) in [(&bounded, Some(4)), (&unbounded, None), (&bounded.meet(&unbounded), None)] {
        decoder.reset();
        decoder.assume(facts);
        let mut dispatch_address = 0x1100;
        step(decoder.as_mut(), &ADD_MEMORY, &mut dispatch_address);
        step(decoder.as_mut(), &JUMP, &mut dispatch_address);
        assert_eq!(decoder.jump_table().map(|table| table.entries), expected_entries);
    }
}

#[test]
fn memory_add_does_not_revive_clobbered_bases_indices_or_targets() {
    type ClobberedDispatch<'a> = (&'a str, &'a [u8], &'a [u8], &'a [u8]);
    let aliased_base = [0x03, 0x84, 0x93, 0, 0xe0, 0xff, 0xff];
    let cases: &[ClobberedDispatch<'_>] = &[
        ("destination", &[0x31, 0xc0], &ADD_MEMORY, &[]),
        ("destination partial write", &[0xb0, 0], &ADD_MEMORY, &[]),
        ("index", &[0x42], &ADD_MEMORY, &[]),
        ("base alias", &[0x89, 0xc3, 0x31, 0xdb], &aliased_base, &[]),
        ("unknown destination with known alias", &[0x89, 0xc3, 0x31, 0xc0], &aliased_base, &[]),
        ("target", &[], &ADD_MEMORY, &[0x31, 0xc0]),
        ("target partial write", &[], &ADD_MEMORY, &[0xb0, 0]),
        ("caller-saved target", &[], &ADD_MEMORY, &[0xe8, 0, 0, 0, 0]),
    ];
    for &(name, gap, add, after) in cases {
        assert_eq!(dispatch(&PC_BASE, &BOUND, gap, add, after), None, "{name}");
    }
    // A copied base survives a write to its former alias when the destination uses the remaining known copy.
    let copied = [&PC_BASE[..], &[0x89, 0xc3, 0x31, 0xc0]].concat();
    let add_ebx = [0x03, 0x9c, 0x93, 0, 0xe0, 0xff, 0xff];
    let table = dispatch(&copied, &BOUND, &[], &add_ebx, &[0x89, 0xd8]).unwrap();
    assert_eq!((table.table, table.base), (0x2000, Some(0x4000)));
}

#[test]
fn memory_add_requires_a_dense_unsigned_index_bound() {
    for bound in [
        &[][..],
        &[0x83, 0xfa, 3, 0x7f, 0x60],       // jg: signed indices may be negative.
        &[0x83, 0xf9, 3, 0x77, 0x60],       // Bounds ecx instead of edx.
        &[0x83, 0xfa, 3, 0x90, 0x77, 0x60], // cmp must immediately precede the branch.
        &[0x83, 0xfa, 0, 0x73, 0x60],       // jae zero has no bounded fall-through.
        &[0x83, 0xe2, 5],                   // A sparse mask does not describe a dense table.
    ] {
        assert_eq!(dispatch(&PC_BASE, bound, &[], &ADD_MEMORY, &[]), None, "{bound:x?}");
    }
    for (bound, entries) in [(&[0x83, 0xfa, 4, 0x73, 0x60][..], 4), (&[0x83, 0xe2, 3], 4)] {
        assert_eq!(dispatch(&PC_BASE, bound, &[], &ADD_MEMORY, &[]).unwrap().entries, entries);
    }
    let limits = [(MAX_JUMP_TABLE_ENTRIES - 1, Some(MAX_JUMP_TABLE_ENTRIES)), (MAX_JUMP_TABLE_ENTRIES, None)];
    for (limit, expected) in limits {
        let bound = [&[0x81, 0xfa][..], &(limit as u32).to_le_bytes(), &[0x77, 0x60]].concat();
        assert_eq!(dispatch(&PC_BASE, &bound, &[], &ADD_MEMORY, &[]).map(|table| table.entries), expected);
    }
}

#[test]
fn memory_add_rejects_unknown_loads_and_unsupported_operand_forms() {
    for add in [
        &[0x03, 0x00][..],                              // No bounded index.
        &[0x03, 0x84, 0x50, 0, 0xe0, 0xff, 0xff],       // Index scale 2, not 4.
        &[0x03, 0x84, 0x88, 0, 0xe0, 0xff, 0xff],       // Unbounded ecx index.
        &[0x03, 0x84, 0x93, 0, 0xe0, 0xff, 0xff],       // Unknown ebx base.
        &[0x66, 0x03, 0x84, 0x90, 0, 0xe0, 0xff, 0xff], // Word arithmetic.
        &[0x64, 0x03, 0x84, 0x90, 0, 0xe0, 0xff, 0xff], // FS-relative memory.
        &[0x65, 0x03, 0x84, 0x90, 0, 0xe0, 0xff, 0xff], // GS-relative memory.
        &[0x67, 0x03, 0x00],                            // 16-bit address mode.
        &[0x2b, 0x84, 0x90, 0, 0xe0, 0xff, 0xff],       // Subtraction is not the supported dispatch.
    ] {
        assert_eq!(dispatch(&PC_BASE, &BOUND, &[], add, &[]), None, "{add:x?}");
    }
    assert_eq!(dispatch(&[], &BOUND, &[], &ADD_MEMORY, &[]), None);
    // An already loaded absolute table pointer is not a known displacement base.
    let loaded = [0x8b, 0x04, 0x95, 0, 0x20, 0, 0];
    assert_eq!(dispatch(&PC_BASE, &BOUND, &loaded, &ADD_MEMORY, &[]), None);
}

#[test]
fn memory_add_does_not_enable_64_bit_or_address_overridden_dispatches() {
    // lea rax, [rip + 0x4000]; cmp rdx, 3; ja; add rax, [rax + rdx*8 - 0x2000]; jmp rax.
    let base = [0x48, 0x8d, 0x05, 0xf9, 0x2f, 0, 0];
    let bound = [0x48, 0x83, 0xfa, 3, 0x77, 0x60];
    for add in [
        &[0x48, 0x03, 0x84, 0xd0, 0, 0xe0, 0xff, 0xff][..],
        &ADD_MEMORY[..],
        &[0x67, 0x03, 0x84, 0x90, 0, 0xe0, 0xff, 0xff],
    ] {
        let mut decoder = decoder_for(Arch::X86_64).unwrap();
        let mut address = 0x1000;
        for bytes in [&base[..], &bound[..], add, &JUMP] {
            step(decoder.as_mut(), bytes, &mut address);
        }
        assert_eq!(decoder.jump_table(), None, "{add:x?}");
    }
}
