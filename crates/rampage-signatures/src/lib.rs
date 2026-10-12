//! Library-function identification by signature, in the spirit of IDA's FLIRT and Ghidra's Function ID: a
//! content hash of a function's instructions, with position-dependent bytes masked out, so the same library
//! function matches across binaries despite being linked at different addresses.
//!
//! The hash covers opcodes, registers and ordinary immediates (which discriminate functions) but masks the bytes
//! that change purely with layout or load address: relative branch/call targets and RIP-relative displacements.
//! A [`SignatureDb`] maps such a hash to a name; build one from binaries whose functions are named (a static
//! library, or a copy with symbols) and use it to name the matching functions in a stripped binary.
//!
//! x86 and x86-64 use iced-x86, which reports the exact displacement and immediate byte ranges. The fixed-width
//! architectures -- AArch64, 32-bit ARM (A32 and Thumb), MIPS/MIPS64 and PowerPC/PowerPC64 -- mask the
//! position-dependent fields of each instruction word by hand, reading words in the target's instruction byte
//! order (MIPS and PowerPC ship in both endiannesses). Only genuinely PC-relative branch/call targets are masked;
//! data immediates are kept because they discriminate functions. Other architectures return `None`.

use std::collections::BTreeMap;

use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};
use rampage_arch::{Arch, Target};
use rampage_loaders::{Binary, SymbolKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The most instructions hashed from one function, a bound against runaway or malformed input.
const MAX_INSTRUCTIONS: u32 = 100_000;

/// A 32-byte masked content hash of a function body.
pub type FunctionHash = [u8; 32];

/// The x86 bitness for an architecture, or `None` when it is not an x86 target.
fn x86_bitness(arch: Arch) -> Option<u32> {
    match arch {
        Arch::X86 => Some(32),
        Arch::X86_64 => Some(64),
        _ => None,
    }
}

/// Whether signature hashing is supported for an architecture.
fn supported(arch: Arch) -> bool {
    matches!(
        arch,
        Arch::X86
            | Arch::X86_64
            | Arch::Aarch64
            | Arch::Arm
            | Arch::Mips
            | Arch::Mips64
            | Arch::PowerPc
            | Arch::PowerPc64
    )
}

/// Masks the position-dependent immediate bits of a little-endian AArch64 instruction word, leaving opcode and
/// registers. Covers the PC-relative forms: B/BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, ADR/ADRP and literal loads.
fn mask_aarch64(word: u32) -> u32 {
    // Unconditional branch/branch-with-link: 26-bit relative offset.
    if word & 0x7c00_0000 == 0x1400_0000 {
        return word & !0x03ff_ffff;
    }
    // ADR/ADRP: page/byte relative, split into immlo (bits 30:29) and immhi (bits 23:5).
    if word & 0x1f00_0000 == 0x1000_0000 {
        return word & !0x60ff_ffe0;
    }
    // B.cond, CBZ/CBNZ and literal loads: a 19-bit offset in bits 23:5.
    let imm19 = 0x7ffffu32 << 5;
    if word & 0xff00_0010 == 0x5400_0000 // B.cond
        || word & 0x7e00_0000 == 0x3400_0000 // CBZ/CBNZ
        || word & 0x3b00_0000 == 0x1800_0000
    // LDR/LDRSW literal, PRFM literal
    {
        return word & !imm19;
    }
    // TBZ/TBNZ: a 14-bit offset in bits 18:5.
    if word & 0x7e00_0000 == 0x3600_0000 {
        return word & !(0x3fffu32 << 5);
    }
    word
}

/// Hashes a stream of fixed 4-byte instruction words, reading each in `big_endian` order and applying `mask` to
/// drop its position-dependent fields. The masked value is hashed in a fixed byte order, so the same logical
/// function hashes equal whether the build is big- or little-endian.
fn fixed_word_hash(bytes: &[u8], big_endian: bool, mask: impl Fn(u32) -> u32) -> Option<FunctionHash> {
    let mut hasher = Sha256::new();
    let mut count = 0u32;
    let (words, _) = bytes.as_chunks::<4>();
    for word in words {
        let value = if big_endian { u32::from_be_bytes(*word) } else { u32::from_le_bytes(*word) };
        hasher.update(mask(value).to_le_bytes());
        count += 1;
        if count >= MAX_INSTRUCTIONS {
            break;
        }
    }
    (count > 0).then(|| hasher.finalize().into())
}

/// Masks the position-dependent offset of an ARM A32 (4-byte word) branch. B, BL and BLX(imm) share the branch
/// class (bits [27:25] == 0b101, any condition); their 24-bit signed PC-relative offset sits in bits [23:0].
fn mask_arm_a32(word: u32) -> u32 {
    if (word >> 25) & 0b111 == 0b101 {
        return word & !0x00ff_ffff;
    }
    word
}

/// Masks the imm fields of a 16-bit Thumb branch, leaving opcode and condition. Covers the unconditional B
/// (bits [15:11] == 0b11100, 11-bit imm) and the conditional B (bits [15:12] == 0b1101 with a real condition,
/// 8-bit imm; conditions 0b1110/0b1111 are undefined/SVC, not branches).
fn mask_thumb16(hw: u16) -> u16 {
    if hw >> 11 == 0b11100 {
        return hw & !0x07ff;
    }
    if hw >> 12 == 0b1101 {
        let cond = (hw >> 8) & 0xf;
        if cond != 0b1110 && cond != 0b1111 {
            return hw & !0x00ff;
        }
    }
    hw
}

/// Masks the imm fields of a 32-bit Thumb BL/BLX/B.W, whose first halfword is `0b11110 S imm10` and whose second
/// is `0b11 J1 x J2 imm11`. Bit 12 of the second halfword distinguishes BL from BLX, so it is kept; the S, J1, J2
/// and imm bits are masked in both halfwords. Any other 32-bit instruction passes through unchanged.
fn mask_thumb32(hw1: u16, hw2: u16) -> (u16, u16) {
    if hw1 >> 11 == 0b11110 && hw2 >> 14 == 0b11 {
        return (hw1 & !0x07ff, hw2 & !0x2fff);
    }
    (hw1, hw2)
}

/// Hashes a Thumb (T32) function, decoding halfword-by-halfword from the start. A first halfword with
/// bits [15:11] in {0b11101, 0b11110, 0b11111} begins a 32-bit instruction (two halfwords), else it is 16-bit.
fn thumb_hash(bytes: &[u8], big_endian: bool) -> Option<FunctionHash> {
    let read_hw = |pair: &[u8]| {
        let raw = [pair[0], pair[1]];
        if big_endian { u16::from_be_bytes(raw) } else { u16::from_le_bytes(raw) }
    };
    let mut hasher = Sha256::new();
    let mut count = 0u32;
    let mut index = 0;
    while index + 2 <= bytes.len() && count < MAX_INSTRUCTIONS {
        let hw1 = read_hw(&bytes[index..index + 2]);
        if matches!(hw1 >> 11, 0b11101..=0b11111) {
            if index + 4 > bytes.len() {
                break;
            }
            let hw2 = read_hw(&bytes[index + 2..index + 4]);
            let (m1, m2) = mask_thumb32(hw1, hw2);
            hasher.update(m1.to_le_bytes());
            hasher.update(m2.to_le_bytes());
            index += 4;
        } else {
            hasher.update(mask_thumb16(hw1).to_le_bytes());
            index += 2;
        }
        count += 1;
    }
    (count > 0).then(|| hasher.finalize().into())
}

/// Masks the position-dependent target of a MIPS branch. J/JAL (opcode 0b000010/0b000011) carry a 26-bit
/// instr_index; the conditional branches BEQ/BNE/BLEZ/BGTZ (opcodes 0x04..=0x07) and REGIMM (opcode 0x01,
/// BLTZ/BGEZ) carry a 16-bit PC-relative offset. Generic I-type immediates (addiu/lui/ori) are left intact.
///
/// Conservative choice: a `lui`/`addiu` HI/LO address pair is a genuine data immediate here, so it is not masked
/// and will differ across differently based links. That lowers the cross-link match rate but never mismatches;
/// recovering those pairs needs relocation/dataflow analysis, left for a later version.
fn mask_mips(word: u32) -> u32 {
    match word >> 26 {
        0b000010 | 0b000011 => word & !0x03ff_ffff,
        0b000001 | 0b000100 | 0b000101 | 0b000110 | 0b000111 => word & !0x0000_ffff,
        _ => word,
    }
}

/// Masks the position-dependent target of a PowerPC branch. The I-form branch (primary opcode 18) has a 24-bit LI
/// field in bits [25:2]; the B-form conditional branch (opcode 16) has a 14-bit BD field in bits [15:2]. Both are
/// PC-relative only when AA (bit 1) is 0, so absolute branches and all data immediates are left intact.
fn mask_ppc(word: u32) -> u32 {
    let absolute = (word >> 1) & 1 == 1;
    match word >> 26 {
        18 if !absolute => word & !0x03ff_fffc,
        16 if !absolute => word & !0x0000_fffc,
        _ => word,
    }
}

/// Hashes an x86 or x86-64 function, masking RIP-relative displacements and relative branch targets.
fn x86_hash(bitness: u32, bytes: &[u8], address: u64) -> Option<FunctionHash> {
    let mut decoder = Decoder::with_ip(bitness, bytes, address, DecoderOptions::NONE);
    let mut hasher = Sha256::new();
    let mut instruction = Instruction::default();
    let mut count = 0u32;
    while decoder.can_decode() && count < MAX_INSTRUCTIONS {
        let start = decoder.position();
        decoder.decode_out(&mut instruction);
        if instruction.is_invalid() {
            break;
        }
        let Some(raw) = bytes.get(start..start + instruction.len()) else { break };
        let mut masked = raw.to_vec();
        let offsets = decoder.get_constant_offsets(&instruction);
        // A RIP-relative displacement encodes an absolute address that moves with the function.
        if instruction.memory_base() == Register::RIP && offsets.has_displacement() {
            zero_range(&mut masked, offsets.displacement_offset(), offsets.displacement_size());
        }
        // A near branch or call encodes its target as a relative immediate that moves with layout.
        if is_relative_branch(&instruction) && offsets.has_immediate() {
            zero_range(&mut masked, offsets.immediate_offset(), offsets.immediate_size());
        }
        hasher.update(&masked);
        count += 1;
    }
    (count > 0).then(|| hasher.finalize().into())
}

/// Whether the instruction transfers control to a relative target, whose encoded offset is position-dependent.
fn is_relative_branch(instruction: &Instruction) -> bool {
    (0..instruction.op_count())
        .any(|op| matches!(instruction.op_kind(op), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64))
}

fn zero_range(bytes: &mut [u8], offset: usize, size: usize) {
    if let Some(slice) = bytes.get_mut(offset..offset + size) {
        slice.fill(0);
    }
}

/// The masked content hash of the function whose bytes start at `address`, or `None` for an unsupported
/// architecture or input with no decodable instructions. `target` supplies the architecture, the instruction
/// byte order (used by the fixed-width paths), and, for 32-bit ARM, whether `address` holds Thumb code.
pub fn function_hash(target: &Target, bytes: &[u8], address: u64) -> Option<FunctionHash> {
    match target.arch {
        Arch::X86 | Arch::X86_64 => x86_hash(x86_bitness(target.arch)?, bytes, address),
        // x86 and AArch64 are fixed little-endian; their behavior is unchanged by the endianness threading.
        Arch::Aarch64 => fixed_word_hash(bytes, false, mask_aarch64),
        Arch::Arm if target.is_thumb(address) => thumb_hash(bytes, target.big_endian),
        Arch::Arm => fixed_word_hash(bytes, target.big_endian, mask_arm_a32),
        Arch::Mips | Arch::Mips64 => fixed_word_hash(bytes, target.big_endian, mask_mips),
        Arch::PowerPc | Arch::PowerPc64 => fixed_word_hash(bytes, target.big_endian, mask_ppc),
        _ => None,
    }
}

/// A set of function signatures mapping a masked hash to a function name.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SignatureDb {
    /// The architecture the signatures were built for; matches are refused across architectures.
    pub arch: String,
    /// Masked hash (lowercase hex) to function name. Hashes that mapped to more than one name are dropped, so a
    /// match is never ambiguous.
    entries: BTreeMap<String, String>,
}

/// Names seen for a hash while building; used to drop ambiguous hashes.
#[derive(Default)]
struct Builder {
    names: BTreeMap<String, Option<String>>,
}

impl Builder {
    fn add(&mut self, hash: FunctionHash, name: &str) {
        let key = hex(&hash);
        match self.names.get_mut(&key) {
            None => {
                self.names.insert(key, Some(name.to_owned()));
            }
            Some(slot @ Some(_)) if slot.as_deref() != Some(name) => *slot = None, // ambiguous
            Some(_) => {}
        }
    }

    fn finish(self, arch: Arch) -> SignatureDb {
        let entries = self.names.into_iter().filter_map(|(hash, name)| Some((hash, name?))).collect();
        SignatureDb { arch: arch.to_string(), entries }
    }
}

impl SignatureDb {
    /// Builds signatures from every named function in `binary` whose bytes are available. Functions whose bodies
    /// are byte-identical after masking but have different names are treated as ambiguous and left unmatchable.
    pub fn from_binary(binary: &Binary) -> SignatureDb {
        let mut builder = Builder::default();
        if supported(binary.arch) {
            let target = binary.target();
            for symbol in &binary.symbols {
                if symbol.kind != SymbolKind::Function || symbol.size == 0 || symbol.name.is_empty() {
                    continue;
                }
                if let Some(bytes) = binary.read(symbol.address, symbol.size)
                    && let Some(hash) = function_hash(&target, bytes, symbol.address)
                {
                    builder.add(hash, &symbol.name);
                }
            }
        }
        builder.finish(binary.arch)
    }

    /// Adds every named function from `binary` to this database, so one database can span several libraries.
    pub fn extend_from_binary(&mut self, binary: &Binary) {
        let additions = SignatureDb::from_binary(binary);
        if additions.arch == self.arch {
            for (hash, name) in additions.entries {
                // A hash already present with a different name becomes ambiguous and is removed.
                match self.entries.get(&hash) {
                    Some(existing) if existing != &name => {
                        self.entries.remove(&hash);
                    }
                    Some(_) => {}
                    None => {
                        self.entries.insert(hash, name);
                    }
                }
            }
        }
    }

    /// The name for the function whose bytes start at `address`, if its masked hash is in the database and the
    /// architecture matches. `target` carries the architecture and instruction byte order (see [`function_hash`]).
    pub fn identify(&self, target: &Target, bytes: &[u8], address: u64) -> Option<&str> {
        if self.arch != target.arch.to_string() {
            return None;
        }
        let hash = function_hash(target, bytes, address)?;
        self.entries.get(&hex(&hash)).map(String::as_str)
    }

    /// The number of unambiguous signatures.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_owned())
    }

    pub fn from_json(text: &str) -> Result<SignatureDb, serde_json::Error> {
        serde_json::from_str(text)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap());
        text.push(char::from_digit(u32::from(byte & 0xf), 16).unwrap());
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    // call rel32 (+0); mov rax, [rip+0]; add eax, 0x1234; ret.
    fn sample() -> Vec<u8> {
        vec![
            0xe8, 0x00, 0x00, 0x00, 0x00, // call rel32
            0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00, // mov rax, [rip+0x0]
            0x05, 0x34, 0x12, 0x00, 0x00, // add eax, 0x1234
            0xc3, // ret
        ]
    }

    fn raw_sha(bytes: &[u8]) -> FunctionHash {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.finalize().into()
    }

    /// A bare target: just an architecture and instruction byte order, no Thumb ranges.
    fn target(arch: Arch, big_endian: bool) -> Target {
        Target {
            arch,
            big_endian,
            data_big_endian: big_endian,
            thumb: std::sync::Arc::new([]),
            global_pointer: None,
            got: None,
        }
    }

    /// A 32-bit ARM target that reports every address as Thumb code.
    fn thumb_target(big_endian: bool) -> Target {
        let everywhere = 0..u64::MAX;
        Target { thumb: std::sync::Arc::from([everywhere]), ..target(Arch::Arm, big_endian) }
    }

    /// Packs 32-bit instruction words into bytes in the given order.
    fn words_to_bytes(words: &[u32], big_endian: bool) -> Vec<u8> {
        words
            .iter()
            .flat_map(|word| if big_endian { word.to_be_bytes() } else { word.to_le_bytes() })
            .collect()
    }

    /// Packs 16-bit Thumb halfwords into bytes in the given order.
    fn halfwords_to_bytes(halfwords: &[u16], big_endian: bool) -> Vec<u8> {
        halfwords
            .iter()
            .flat_map(|hw| if big_endian { hw.to_be_bytes() } else { hw.to_le_bytes() })
            .collect()
    }

    #[test]
    fn masking_makes_the_hash_independent_of_relative_targets_and_rip_displacements() {
        let base = sample();
        let mut relinked = base.clone();
        relinked[1..5].copy_from_slice(&0x1111_2222u32.to_le_bytes()); // different call target
        relinked[8..12].copy_from_slice(&0x3333_4444u32.to_le_bytes()); // different rip displacement

        // The masked hash ignores those position-dependent bytes...
        let x64 = target(Arch::X86_64, false);
        assert_eq!(function_hash(&x64, &base, 0x1000), function_hash(&x64, &relinked, 0x4000));
        // ...while a naive hash of the raw bytes does not, so the masking is doing real work.
        assert_ne!(raw_sha(&base), raw_sha(&relinked));
    }

    #[test]
    fn masking_keeps_ordinary_immediates_and_opcodes() {
        let base = sample();
        let x64 = target(Arch::X86_64, false);
        let mut changed_constant = base.clone();
        changed_constant[13..17].copy_from_slice(&0x9999u32.to_le_bytes()); // different add immediate
        assert_ne!(function_hash(&x64, &base, 0x1000), function_hash(&x64, &changed_constant, 0x1000));

        let mut changed_opcode = base.clone();
        changed_opcode[17] = 0x90; // ret -> nop
        assert_ne!(function_hash(&x64, &base, 0x1000), function_hash(&x64, &changed_opcode, 0x1000));
    }

    #[test]
    fn unsupported_architecture_has_no_hash() {
        assert!(function_hash(&target(Arch::Riscv64, false), &sample(), 0x1000).is_none());
    }

    #[test]
    fn aarch64_masking_ignores_pc_relative_targets_but_keeps_opcodes() {
        let a64 = target(Arch::Aarch64, false);
        // bl #0x40; adrp x0, page; add x0, x0, #off; ret.
        let base = words_to_bytes(&[0x9400_0010, 0x9000_0000, 0x9100_0000, 0xd65f_03c0], false);
        // Relink: different bl target and a different adrp page immediate.
        let relinked = words_to_bytes(&[0x9400_1234, 0x9000_00e0, 0x9100_0000, 0xd65f_03c0], false);
        assert_eq!(function_hash(&a64, &base, 0x1000), function_hash(&a64, &relinked, 0x8000));

        // A different add immediate (not PC-relative) must change the hash.
        let changed = words_to_bytes(&[0x9400_0010, 0x9000_0000, 0x9140_0400, 0xd65f_03c0], false);
        assert_ne!(function_hash(&a64, &base, 0x1000), function_hash(&a64, &changed, 0x1000));
    }

    fn fixture(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)
    }

    #[test]
    fn signatures_name_a_function_across_a_differently_linked_build() {
        // Build a database from one binary, then name a function in a separately linked build of the same
        // program. A leaf function has identical bytes once relative targets are masked, so it matches.
        let named = Binary::open(fixture("hello-x64.elf")).unwrap();
        let db = SignatureDb::from_binary(&named);
        assert!(!db.is_empty());
        let other = Binary::open(fixture("hello-x64-dyn.elf")).unwrap();
        let add = other.symbols.iter().find(|symbol| symbol.name == "add").expect("add symbol");
        let bytes = other.read(add.address, add.size).expect("add bytes");
        assert_eq!(db.identify(&other.target(), bytes, add.address), Some("add"));
    }

    #[test]
    fn database_drops_ambiguous_hashes_and_round_trips() {
        let mut builder = Builder::default();
        let x64 = target(Arch::X86_64, false);
        let hash = function_hash(&x64, &sample(), 0x1000).unwrap();
        builder.add(hash, "first");
        builder.add(hash, "first");
        let mut other = [0u8; 32];
        other[0] = 1;
        builder.add(other, "unique");
        // A second name for the same hash makes it ambiguous.
        builder.add(hash, "second");
        let db = builder.finish(Arch::X86_64);
        assert_eq!(db.identify(&x64, &sample(), 0x1000), None); // ambiguous dropped
        assert_eq!(db.len(), 1);

        let restored = SignatureDb::from_json(&db.to_json()).unwrap();
        assert_eq!(restored.arch, "x86_64");
        assert_eq!(restored.len(), 1);
    }

    /// Builds a database from a fixture and confirms at least one named function identifies back to its own name
    /// in the same binary, exercising the whole from_binary -> identify path for that architecture.
    fn assert_fixture_round_trips(name: &str) {
        let binary = Binary::open(fixture(name)).unwrap();
        let db = SignatureDb::from_binary(&binary);
        assert!(!db.is_empty(), "{name}: empty database");
        let target = binary.target();
        let hits = binary
            .symbols
            .iter()
            .filter(|symbol| symbol.kind == SymbolKind::Function && symbol.size > 0 && !symbol.name.is_empty())
            .filter(|symbol| {
                binary.read(symbol.address, symbol.size).is_some_and(|bytes| {
                    db.identify(&target, bytes, symbol.address) == Some(symbol.name.as_str())
                })
            })
            .count();
        assert!(hits > 0, "{name}: no function identified back to its own name");
    }

    #[test]
    fn arm_a32_masks_branch_targets_but_keeps_data_and_opcodes() {
        let arm = target(Arch::Arm, false);
        // add r0, r0, #1; bl <t>; b <t>; bx lr.
        let base = words_to_bytes(&[0xe280_0001, 0xeb00_0000, 0xea00_0000, 0xe12f_ff1e], false);
        // Relink: only the bl and b offsets change.
        let relinked = words_to_bytes(&[0xe280_0001, 0xeb12_3456, 0xea00_abcd, 0xe12f_ff1e], false);
        assert_eq!(function_hash(&arm, &base, 0), function_hash(&arm, &relinked, 0));

        // A changed destination register (opcode field) must differ.
        let changed_reg = words_to_bytes(&[0xe281_0001, 0xeb00_0000, 0xea00_0000, 0xe12f_ff1e], false);
        assert_ne!(function_hash(&arm, &base, 0), function_hash(&arm, &changed_reg, 0));
        // A changed real data immediate (the add's #1 -> #2, not PC-relative) must differ.
        let changed_imm = words_to_bytes(&[0xe280_0002, 0xeb00_0000, 0xea00_0000, 0xe12f_ff1e], false);
        assert_ne!(function_hash(&arm, &base, 0), function_hash(&arm, &changed_imm, 0));
    }

    #[test]
    fn arm_a32_endianness_reads_the_same_logical_words() {
        let words = [0xe280_0001u32, 0xeb00_0000, 0xea00_0000, 0xe12f_ff1e];
        let le = function_hash(&target(Arch::Arm, false), &words_to_bytes(&words, false), 0);
        let be = function_hash(&target(Arch::Arm, true), &words_to_bytes(&words, true), 0);
        assert_eq!(le, be);
    }

    #[test]
    fn thumb_masks_branch_targets_but_keeps_data_and_opcodes() {
        let thumb = thumb_target(false);
        // movs r0, #1; beq <t>; b <t>; bl <t> (32-bit); bx lr.
        let base = halfwords_to_bytes(&[0x2001, 0xd0fe, 0xe7fe, 0xf000, 0xf800, 0x4770], false);
        // Relink: only the three branch targets change; opcodes and the movs immediate stay.
        let relinked = halfwords_to_bytes(&[0x2001, 0xd000, 0xe7f0, 0xf00f, 0xf900, 0x4770], false);
        assert_eq!(function_hash(&thumb, &base, 0), function_hash(&thumb, &relinked, 0));

        // A changed destination register (movs r0 -> r1) must differ.
        let changed_reg = halfwords_to_bytes(&[0x2101, 0xd0fe, 0xe7fe, 0xf000, 0xf800, 0x4770], false);
        assert_ne!(function_hash(&thumb, &base, 0), function_hash(&thumb, &changed_reg, 0));
        // A changed real data immediate (movs #1 -> #2) must differ.
        let changed_imm = halfwords_to_bytes(&[0x2002, 0xd0fe, 0xe7fe, 0xf000, 0xf800, 0x4770], false);
        assert_ne!(function_hash(&thumb, &base, 0), function_hash(&thumb, &changed_imm, 0));
    }

    #[test]
    fn thumb_endianness_reads_the_same_logical_halfwords() {
        let halfwords = [0x2001u16, 0xd0fe, 0xe7fe, 0xf000, 0xf800, 0x4770];
        let le = function_hash(&thumb_target(false), &halfwords_to_bytes(&halfwords, false), 0);
        let be = function_hash(&thumb_target(true), &halfwords_to_bytes(&halfwords, true), 0);
        assert_eq!(le, be);
    }

    #[test]
    fn mips_masks_branch_targets_but_keeps_data_and_opcodes() {
        let mips = target(Arch::Mips, true);
        // lui $v0,1; addiu $v0,$v0,0x20; jal <t>; beq $v0,$zero,<t>; nop.
        let base = words_to_bytes(&[0x3c02_0001, 0x2442_0020, 0x0c10_0000, 0x1040_0005, 0x0000_0000], true);
        // Relink: only the jal index and the beq offset change.
        let relinked = words_to_bytes(&[0x3c02_0001, 0x2442_0020, 0x0c12_3456, 0x1040_abcd, 0x0000_0000], true);
        assert_eq!(function_hash(&mips, &base, 0), function_hash(&mips, &relinked, 0));

        // A changed register (lui target $v0 -> $v1) must differ.
        let changed_reg = words_to_bytes(&[0x3c03_0001, 0x2442_0020, 0x0c10_0000, 0x1040_0005, 0x0000_0000], true);
        assert_ne!(function_hash(&mips, &base, 0), function_hash(&mips, &changed_reg, 0));
        // A changed I-type immediate (addiu 0x20 -> 0x40), which we deliberately do NOT mask, must differ.
        let changed_imm = words_to_bytes(&[0x3c02_0001, 0x2442_0040, 0x0c10_0000, 0x1040_0005, 0x0000_0000], true);
        assert_ne!(function_hash(&mips, &base, 0), function_hash(&mips, &changed_imm, 0));
    }

    #[test]
    fn mips_endianness_matches_mipsel_encoding() {
        // The same logical words, stored big-endian (mips) and little-endian (mipsel), must hash equal.
        let words = [0x3c02_0001u32, 0x2442_0020, 0x0c10_0000, 0x1040_0005, 0x0000_0000];
        let be = function_hash(&target(Arch::Mips, true), &words_to_bytes(&words, true), 0);
        let le = function_hash(&target(Arch::Mips, false), &words_to_bytes(&words, false), 0);
        assert_eq!(be, le);
    }

    #[test]
    fn ppc_masks_relative_branch_targets_but_keeps_data_and_absolute_branches() {
        let ppc = target(Arch::PowerPc, true);
        // addi r3,r3,0x10; b <t> (I-form, AA=0); bc <t> (B-form, AA=0); blr.
        let base = words_to_bytes(&[0x3863_0010, 0x4800_0100, 0x4182_0010, 0x4e80_0020], true);
        // Relink: only the two relative branch displacements change.
        let relinked = words_to_bytes(&[0x3863_0010, 0x4800_1234, 0x4182_4560, 0x4e80_0020], true);
        assert_eq!(function_hash(&ppc, &base, 0), function_hash(&ppc, &relinked, 0));

        // A changed register (addi target r3 -> r4) must differ.
        let changed_reg = words_to_bytes(&[0x3883_0010, 0x4800_0100, 0x4182_0010, 0x4e80_0020], true);
        assert_ne!(function_hash(&ppc, &base, 0), function_hash(&ppc, &changed_reg, 0));
        // A changed real data immediate (addi 0x10 -> 0x20) must differ.
        let changed_imm = words_to_bytes(&[0x3863_0020, 0x4800_0100, 0x4182_0010, 0x4e80_0020], true);
        assert_ne!(function_hash(&ppc, &base, 0), function_hash(&ppc, &changed_imm, 0));
        // An absolute branch's target (AA=1) is left in the hash, so changing it must differ.
        let abs_base = words_to_bytes(&[0x4800_0102, 0x4e80_0020], true);
        let abs_other = words_to_bytes(&[0x4800_1232, 0x4e80_0020], true);
        assert_ne!(function_hash(&ppc, &abs_base, 0), function_hash(&ppc, &abs_other, 0));
    }

    #[test]
    fn ppc_endianness_matches_ppc64le_encoding() {
        let words = [0x3863_0010u32, 0x4800_0100, 0x4182_0010, 0x4e80_0020];
        let be = function_hash(&target(Arch::PowerPc, true), &words_to_bytes(&words, true), 0);
        let le = function_hash(&target(Arch::PowerPc, false), &words_to_bytes(&words, false), 0);
        assert_eq!(be, le);
    }

    #[test]
    fn arm_fixture_round_trips() {
        assert_fixture_round_trips("hello-arm.elf");
    }

    #[test]
    fn thumb_fixture_round_trips() {
        assert_fixture_round_trips("hello-thumb.elf");
    }

    #[test]
    fn mips_fixture_round_trips() {
        assert_fixture_round_trips("hello-mips.elf");
        assert_fixture_round_trips("hello-mipsel.elf");
    }

    #[test]
    fn ppc_fixture_round_trips() {
        assert_fixture_round_trips("hello-ppc.elf");
        assert_fixture_round_trips("hello-ppc64le.elf");
    }
}
