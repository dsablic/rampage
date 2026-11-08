//! Which bytes of a function body are operand fields, by class: the bytes a byte pattern can wildcard so it still
//! matches when a library's next version changes a constant, a structure offset or a stack slot but not the code
//! around it. Used by the flywheel's deterministic arm (docs/flywheel.md, "The deterministic arm").
//!
//! Classes are per byte, because PAT patterns wildcard whole bytes. On x86 fields are whole bytes. On AArch64 a
//! byte gets a field's class only when every bit of it belongs to the field or to a register number, so opcode
//! bits sharing a byte with a field stay fixed (a wildcarded `ldr` must not match a `str`); the field's other
//! bits stay fixed too. [`OperandClass::Relocation`] (a field scheme 2 masks) takes precedence over the others. Only
//! x86, x86-64 and little-endian AArch64 are classified.

use std::ops::Range;

use iced_x86::{Decoder, DecoderOptions, Instruction};
use rampage_arch::{Arch, Target};
use serde::{Deserialize, Serialize};

use super::{AdrpPages, MAX_INSTRUCTIONS, MaskContext, is_relative_branch, x86_masked_ranges};

/// The kind of operand field a byte belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperandClass {
    /// A field scheme 2 masks (relative branch and call targets, RIP-relative and absolute image addresses, ADRP
    /// pages and their low halves). Masking zeroes it, so a masked byte whose value is already the masked value
    /// reads as fixed; wildcarding the whole field lets it match whatever the layout puts there.
    Relocation,
    /// An x86 one-byte displacement (`[rbp-0x18]`, `[rdi+0x10]`): stack slots and structure field offsets.
    Disp8,
    /// An x86 displacement of two or more bytes that is not an image address.
    DispWide,
    /// An x86 one-byte immediate.
    Imm8,
    /// An x86 immediate of two or more bytes that is not an image address.
    ImmWide,
    /// An AArch64 data immediate: ADD/SUB (immediate), logical (immediate), MOVZ/MOVN/MOVK.
    A64Immediate,
    /// An AArch64 load/store offset: unsigned scaled, unscaled and pre/post-indexed, and pair.
    A64Offset,
}

impl OperandClass {
    pub const ALL: [OperandClass; 7] = [
        OperandClass::Relocation,
        OperandClass::Disp8,
        OperandClass::DispWide,
        OperandClass::Imm8,
        OperandClass::ImmWide,
        OperandClass::A64Immediate,
        OperandClass::A64Offset,
    ];

    /// The class's name as serialized (`disp8`, `a64-offset`).
    pub fn name(self) -> &'static str {
        match self {
            OperandClass::Relocation => "relocation",
            OperandClass::Disp8 => "disp8",
            OperandClass::DispWide => "disp-wide",
            OperandClass::Imm8 => "imm8",
            OperandClass::ImmWide => "imm-wide",
            OperandClass::A64Immediate => "a64-immediate",
            OperandClass::A64Offset => "a64-offset",
        }
    }

    /// The class named `name` ([`OperandClass::name`]).
    pub fn parse(name: &str) -> Option<OperandClass> {
        OperandClass::ALL.into_iter().find(|class| class.name() == name)
    }
}

/// The operand class of each byte of `bytes`, a function at `address`, with scheme 2's masking over `image`; `None`
/// for a byte in no field. Bytes after the first undecodable instruction are in no field. `None` overall for an
/// architecture this does not classify.
pub fn operand_classes(
    target: &Target,
    image: &MaskContext,
    bytes: &[u8],
    address: u64,
) -> Option<Vec<Option<OperandClass>>> {
    match target.arch {
        Arch::X86 => Some(x86_classes(32, image, bytes, address)),
        Arch::X86_64 => Some(x86_classes(64, image, bytes, address)),
        Arch::Aarch64 if !target.big_endian => Some(aarch64_classes(bytes)),
        _ => None,
    }
}

fn x86_classes(bitness: u32, image: &MaskContext, bytes: &[u8], address: u64) -> Vec<Option<OperandClass>> {
    let mut classes = vec![None; bytes.len()];
    let mut decoder = Decoder::with_ip(bitness, bytes, address, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut count = 0;
    while decoder.can_decode() && count < MAX_INSTRUCTIONS {
        let start = decoder.position();
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() || start + instruction.len() > bytes.len() {
            break;
        }
        count += 1;
        let offsets = decoder.get_constant_offsets(&instruction);
        let mut set = |range: Range<usize>, class: OperandClass| {
            for slot in &mut classes[start + range.start..start + range.end] {
                slot.get_or_insert(class);
            }
        };
        // Relocations first, so they take precedence.
        for range in x86_masked_ranges(&instruction, &offsets, Some(image)) {
            set(range, OperandClass::Relocation);
        }
        if offsets.has_displacement() {
            let size = offsets.displacement_size();
            let class = if size == 1 { OperandClass::Disp8 } else { OperandClass::DispWide };
            set(offsets.displacement_offset()..offsets.displacement_offset() + size, class);
        }
        if !is_relative_branch(&instruction) {
            for (has, offset, size) in [
                (offsets.has_immediate(), offsets.immediate_offset(), offsets.immediate_size()),
                (offsets.has_immediate2(), offsets.immediate_offset2(), offsets.immediate_size2()),
            ] {
                if has {
                    let class = if size == 1 { OperandClass::Imm8 } else { OperandClass::ImmWide };
                    set(offset..offset + size, class);
                }
            }
        }
    }
    classes
}

fn aarch64_classes(bytes: &[u8]) -> Vec<Option<OperandClass>> {
    let mut classes = vec![None; bytes.len()];
    let mut pages = AdrpPages::default();
    let (words, _) = bytes.as_chunks::<4>();
    for (index, word) in words.iter().enumerate().take(MAX_INSTRUCTIONS as usize) {
        let word = u32::from_le_bytes(*word);
        let relocation = pages.bits(word);
        let (operand, class) = aarch64_operand_bits(word);
        let registers = aarch64_register_bits(word);
        for byte in 0..4 {
            // A byte is wildcarded only when every bit of it is the field's or a register number's: AArch64 fields
            // do not align to bytes, and a byte that also holds opcode bits (load or store, MOVZ or EOR, the
            // branch kind, the condition) must stay fixed.
            let byte_of = |bits: u32| (bits >> (byte * 8)) & 0xff;
            let qualifies = |field: u32| byte_of(field) != 0 && byte_of(field | registers) == 0xff;
            classes[index * 4 + byte] = if qualifies(relocation) {
                Some(OperandClass::Relocation)
            } else if qualifies(operand) {
                Some(class)
            } else {
                None
            };
        }
    }
    classes
}

/// The register-number fields (Rd/Rt, Rn, Rt2) of the AArch64 encodings [`aarch64_classes`] knows a field of; none
/// for others.
fn aarch64_register_bits(word: u32) -> u32 {
    const RD: u32 = 0x1f;
    const RD_RN: u32 = 0x3ff;
    let pc_relative_with_rt = word & 0x1f00_0000 == 0x1000_0000 // ADR/ADRP
        || word & 0x7e00_0000 == 0x3400_0000 // CBZ/CBNZ
        || word & 0x7e00_0000 == 0x3600_0000 // TBZ/TBNZ
        || word & 0x3b00_0000 == 0x1800_0000; // literal loads
    if pc_relative_with_rt || word & 0x1f80_0000 == 0x1280_0000 {
        RD // and move wide
    } else if word & 0x3a00_0000 == 0x2800_0000 {
        RD_RN | 0x1f << 10 // pair: Rt2 too
    } else if word & 0x1f00_0000 == 0x1100_0000 // ADD/SUB (immediate)
        || word & 0x1f80_0000 == 0x1200_0000 // logical (immediate)
        || word & 0x3b00_0000 == 0x3900_0000 // load/store, unsigned offset
        || word & 0x3b20_0000 == 0x3800_0000
    {
        RD_RN // load/store, unscaled and indexed
    } else {
        0
    }
}

/// The data-immediate or load/store-offset field of an AArch64 instruction word, and its class (no bits for
/// anything else).
fn aarch64_operand_bits(word: u32) -> (u32, OperandClass) {
    // ADD/SUB (immediate): imm12 in bits 21:10.
    if word & 0x1f00_0000 == 0x1100_0000 {
        return (0xfff << 10, OperandClass::A64Immediate);
    }
    // Logical (immediate): N, immr, imms in bits 22:10.
    if word & 0x1f80_0000 == 0x1200_0000 {
        return (0x1fff << 10, OperandClass::A64Immediate);
    }
    // Move wide (immediate): imm16 in bits 20:5.
    if word & 0x1f80_0000 == 0x1280_0000 {
        return (0xffff << 5, OperandClass::A64Immediate);
    }
    // Load/store register, unsigned offset: imm12 in bits 21:10.
    if word & 0x3b00_0000 == 0x3900_0000 {
        return (0xfff << 10, OperandClass::A64Offset);
    }
    // Load/store register, unscaled, unprivileged and pre/post-indexed immediate: imm9 in bits 20:12.
    if word & 0x3b20_0000 == 0x3800_0000 {
        return (0x1ff << 12, OperandClass::A64Offset);
    }
    // Load/store pair (all indexings): imm7 in bits 21:15.
    if word & 0x3a00_0000 == 0x2800_0000 {
        return (0x7f << 15, OperandClass::A64Offset);
    }
    (0, OperandClass::A64Immediate)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(arch: Arch) -> Target {
        Target {
            arch,
            big_endian: false,
            data_big_endian: false,
            thumb: std::sync::Arc::new([]),
            global_pointer: None,
            got: None,
        }
    }

    #[test]
    fn x86_classes_split_displacements_immediates_and_relocations() {
        // mov rax, [rdi+0x10]; mov ecx, 0x12345678; add rsp, 8; call rel32; ret
        let bytes = [
            0x48, 0x8b, 0x47, 0x10, // mov rax, [rdi+0x10]
            0xb9, 0x78, 0x56, 0x34, 0x12, // mov ecx, 0x12345678
            0x48, 0x83, 0xc4, 0x08, // add rsp, 8
            0xe8, 0x00, 0x00, 0x00, 0x00, // call rel32
            0xc3,
        ];
        let classes = operand_classes(&target(Arch::X86_64), &MaskContext::default(), &bytes, 0x1000).unwrap();
        use OperandClass::*;
        let expected = [
            None,
            None,
            None,
            Some(Disp8),
            None,
            Some(ImmWide),
            Some(ImmWide),
            Some(ImmWide),
            Some(ImmWide),
            None,
            None,
            None,
            Some(Imm8),
            None,
            Some(Relocation),
            Some(Relocation),
            Some(Relocation),
            Some(Relocation),
            None,
        ];
        assert_eq!(classes, expected);
    }

    #[test]
    fn x86_image_addresses_are_relocations_not_immediates() {
        // mov eax, 0x401000 (an image address under scheme 2)
        let bytes = [0xb8, 0x00, 0x10, 0x40, 0x00, 0xc3];
        let image = MaskContext::new(std::iter::once(0x40_0000..0x50_0000));
        let classes = operand_classes(&target(Arch::X86_64), &image, &bytes, 0x40_1000).unwrap();
        assert_eq!(classes[1..5], [Some(OperandClass::Relocation); 4]);
    }

    #[test]
    fn aarch64_classes_wildcard_only_bytes_of_field_and_register_bits() {
        let words: [u32; 9] = [
            0x9100_4000, // add x0, x0, #0x10: byte 1 is Rn and imm12; byte 2 holds sh and opcode bits
            0xf940_0820, // ldr x0, [x1, #0x10]: byte 2 holds opc (load or store)
            0xa9bf_7bfd, // stp x29, x30, [sp, #-16]!: byte 1 is Rn, Rt2 and imm7; byte 2 holds L
            0x5280_0020, // movz w0, #1: bytes 0 and 1 are Rd and imm16; byte 2 holds the MOVZ/EOR bit
            0xf81f_03e0, // stur x0, [sp, #-16]: byte 1 holds the indexing kind, byte 2 opc: nothing
            0x9400_0000, // bl: byte 3 holds the opcode
            0x5400_0040, // b.eq: byte 0 holds the condition
            0x9000_0000, // adrp x0: byte 3 holds immlo and the opcode
            0xd65f_03c0, // ret: nothing
        ];
        let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let classes = operand_classes(&target(Arch::Aarch64), &MaskContext::default(), &bytes, 0x1000).unwrap();
        use OperandClass::*;
        let expected: [[Option<OperandClass>; 4]; 9] = [
            [None, Some(A64Immediate), None, None],
            [None, Some(A64Offset), None, None],
            [None, Some(A64Offset), None, None],
            [Some(A64Immediate), Some(A64Immediate), None, None],
            [None; 4],
            [Some(Relocation), Some(Relocation), Some(Relocation), None],
            [None, Some(Relocation), Some(Relocation), None],
            [Some(Relocation), Some(Relocation), Some(Relocation), None],
            [None; 4],
        ];
        for (index, (word, expected)) in words.iter().zip(expected).enumerate() {
            assert_eq!(classes[index * 4..index * 4 + 4], expected, "{word:#010x}");
        }
    }

    #[test]
    fn names_round_trip() {
        for class in OperandClass::ALL {
            assert_eq!(OperandClass::parse(class.name()), Some(class));
            assert_eq!(serde_json::to_value(class).unwrap(), class.name());
        }
    }
}
