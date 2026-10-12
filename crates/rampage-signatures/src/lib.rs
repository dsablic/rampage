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
//!
//! Hashes are versioned. Scheme 1 ([`function_hash`]) is the masking above. Scheme 2 ([`function_hash_in`]) also
//! masks constants that are layout-dependent addresses: on x86/x86-64, displacements and immediates pointing into
//! the image ([`MaskContext`]), as non-PIE code embeds them; on AArch64, the low 12 bits completing an ADRP page
//! address. A [`SignatureDb`] records its scheme and [`SignatureDb::identify_in`] hashes with it, so databases saved
//! under scheme 1 keep matching exactly as before.
//!
//! A confidence gate rejects non-discriminating bodies so they are neither stored nor matched: a body whose
//! masked form carries too little content (a single-branch thunk masks to almost nothing, all-nop padding is one
//! repeated word) would collide with many unrelated functions, making a "match" meaningless. [`function_hash`]
//! returns `None` unless the body clears all of: a minimum instruction count, a minimum number of non-masked
//! (content-bearing) bytes remaining after masking, and a minimum number of distinct instruction encodings (so
//! constant padding is rejected). The thresholds are heuristic but conservative -- tuned to keep genuine small
//! leaf functions while dropping trivial/degenerate bodies.

mod bundled;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

pub use bundled::bundled;
use iced_x86::{ConstantOffsets, Decoder, DecoderOptions, Instruction, OpKind, Register};
use rampage_arch::{Arch, Target};
use rampage_loaders::{Binary, SymbolKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The most instructions hashed from one function, a bound against runaway or malformed input.
const MAX_INSTRUCTIONS: u32 = 100_000;

/// Fewest decoded instructions a body must have to be a discriminating fingerprint. Below this it is a stub or
/// thunk that many unrelated functions share.
const MIN_INSTRUCTIONS: u32 = 4;

/// Fewest non-masked (content-bearing) bytes a body must retain after masking. A pure branch/thunk masks to a
/// lone opcode byte, so it falls far below this; genuine instructions keep registers and data immediates.
const MIN_CONTENT_BYTES: usize = 6;

/// Fewest distinct masked instruction encodings a body must have, so constant padding (an all-nop body is one
/// repeated word) is rejected even when it is long.
const MIN_DISTINCT: usize = 3;

/// A 32-byte masked content hash of a function body.
pub type FunctionHash = [u8; 32];

/// Hash scheme 1: [`function_hash`], which masks only relative branch targets and PC-relative displacements.
/// Databases saved without a `scheme` field are scheme 1.
pub const LEGACY_SCHEME: u32 = 1;

/// Hash scheme 2: [`function_hash_in`], which also masks absolute addresses into the image. New databases use it.
pub const CURRENT_SCHEME: u32 = 2;

/// Images mapped below this address are position-independent (ELF PIE/shared objects and relocatable objects
/// start at 0), so their code cannot embed absolute addresses, and treating their small offsets as addresses
/// would mask ordinary constants.
const MIN_IMAGE_BASE: u64 = 0x1_0000;

/// The address ranges an image occupies once mapped, which tell scheme-2 hashing which constants are absolute
/// addresses of the image's own code and data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaskContext {
    /// Sorted, non-overlapping, non-empty ranges.
    ranges: Vec<Range<u64>>,
}

impl MaskContext {
    /// A context over `ranges`, normalized (sorted, empty ranges dropped, overlaps merged).
    pub fn new(ranges: impl IntoIterator<Item = Range<u64>>) -> MaskContext {
        let mut sorted: Vec<Range<u64>> = ranges.into_iter().filter(|range| range.start < range.end).collect();
        sorted.sort_by_key(|range| range.start);
        let mut merged: Vec<Range<u64>> = Vec::with_capacity(sorted.len());
        for range in sorted {
            match merged.last_mut() {
                Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
                _ => merged.push(range),
            }
        }
        MaskContext { ranges: merged }
    }

    /// The mapped, non-empty segments of `binary` (its sections when it has no segments, as for an object file).
    /// Inaccessible segments such as Mach-O's `__PAGEZERO` are guard regions, not image contents. An image based
    /// below [`MIN_IMAGE_BASE`] is position-independent and gets an empty context.
    pub fn from_binary(binary: &Binary) -> MaskContext {
        let segments = binary
            .segments
            .iter()
            .filter(|segment| segment.perms.read || segment.perms.write || segment.perms.execute)
            .map(|segment| segment.address..segment.address.saturating_add(segment.size));
        let sections =
            binary.sections.iter().map(|section| section.address..section.address.saturating_add(section.size));
        let context = if binary.segments.is_empty() { MaskContext::new(sections) } else { MaskContext::new(segments) };
        match context.ranges.first() {
            Some(lowest) if lowest.start >= MIN_IMAGE_BASE => context,
            _ => MaskContext::default(),
        }
    }

    /// The normalized address ranges.
    pub fn ranges(&self) -> &[Range<u64>] {
        &self.ranges
    }

    /// Whether `address` lies inside the image.
    pub fn contains(&self, address: u64) -> bool {
        let next = self.ranges.partition_point(|range| range.start <= address);
        next > 0 && address < self.ranges[next - 1].end
    }
}

/// Accumulates a function's masked instruction stream and measures whether it carries enough discriminating
/// content to be worth storing or matching. Each path feeds one instruction's masked encoding (with the
/// position-dependent fields already zeroed); [`Fingerprint::finish`] applies the confidence gate and either
/// yields the hash or `None`. Hashing is unchanged for accepted bodies, so a body that passes hashes exactly as
/// before the gate existed.
struct Fingerprint {
    hasher: Sha256,
    instructions: u32,
    content_bytes: usize,
    /// Folds of distinct masked encodings, stopped once [`MIN_DISTINCT`] is reached so it stays small.
    distinct: BTreeSet<u64>,
}

impl Fingerprint {
    fn new() -> Fingerprint {
        Fingerprint { hasher: Sha256::new(), instructions: 0, content_bytes: 0, distinct: BTreeSet::new() }
    }

    /// Feeds one instruction's masked encoding into the hash and the content measures.
    fn push(&mut self, masked: &[u8]) {
        self.hasher.update(masked);
        self.instructions += 1;
        self.content_bytes += masked.iter().filter(|&&byte| byte != 0).count();
        if self.distinct.len() < MIN_DISTINCT {
            self.distinct.insert(fold(masked));
        }
    }

    /// Whether the instruction cap has been reached, so a caller can stop feeding.
    fn full(&self) -> bool {
        self.instructions >= MAX_INSTRUCTIONS
    }

    /// The masked content hash, or `None` when the body fails the confidence gate.
    fn finish(self) -> Option<FunctionHash> {
        let discriminating = self.instructions >= MIN_INSTRUCTIONS
            && self.content_bytes >= MIN_CONTENT_BYTES
            && self.distinct.len() >= MIN_DISTINCT;
        discriminating.then(|| self.hasher.finalize().into())
    }
}

/// A cheap 64-bit FNV-1a fold of a masked instruction, used only to count distinct encodings without storing the
/// instructions themselves. Collisions merely undercount diversity, which the gate treats conservatively.
fn fold(bytes: &[u8]) -> u64 {
    let mut acc = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        acc ^= u64::from(byte);
        acc = acc.wrapping_mul(0x0000_0100_0000_01b3);
    }
    acc
}

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

/// Scheme 2's AArch64 masking: on top of [`mask_aarch64`], the 12-bit low part that completes an ADRP page address
/// (`add xd, xn, #:lo12:sym` or a load/store `[xn, #:lo12:sym]`) is masked, because it moves with layout just like
/// the page. Registers holding an ADRP page are tracked over a linear scan; tracking ignores control flow, so it
/// can occasionally mask an ordinary offset, which only costs content and is deterministic for identical code.
#[derive(Default)]
struct AdrpPages {
    /// Bitset of the general registers last written by an ADRP.
    registers: u32,
}

impl AdrpPages {
    fn mask(&mut self, word: u32) -> u32 {
        let masked = mask_aarch64(word);
        let destination = word & 0x1f;
        let source = (word >> 5) & 0x1f;
        if word & 0x9f00_0000 == 0x9000_0000 {
            // Register 31 is xzr here, which holds nothing.
            if destination != 31 {
                self.registers |= 1 << destination;
            }
            return masked;
        }
        let add_unshifted = word & 0x7fc0_0000 == 0x1100_0000;
        let load_store_unsigned = word & 0x3b00_0000 == 0x3900_0000;
        let completes = (add_unshifted || load_store_unsigned) && self.registers & (1 << source) != 0;
        let call = word & 0xfc00_0000 == 0x9400_0000 || word & 0xffff_fc1f == 0xd63f_0000;
        if call {
            // A call clobbers the caller-saved x0..x18.
            self.registers &= !0x7_ffff;
        } else {
            self.registers &= !(1 << destination);
        }
        if completes { masked & !(0xfff << 10) } else { masked }
    }
}

/// Hashes a stream of fixed 4-byte instruction words, reading each in `big_endian` order and applying `mask` to
/// drop its position-dependent fields. The masked value is hashed in a fixed byte order, so the same logical
/// function hashes equal whether the build is big- or little-endian.
fn fixed_word_hash(bytes: &[u8], big_endian: bool, mut mask: impl FnMut(u32) -> u32) -> Option<FunctionHash> {
    let mut fingerprint = Fingerprint::new();
    let (words, _) = bytes.as_chunks::<4>();
    for word in words {
        let value = if big_endian { u32::from_be_bytes(*word) } else { u32::from_le_bytes(*word) };
        fingerprint.push(&mask(value).to_le_bytes());
        if fingerprint.full() {
            break;
        }
    }
    fingerprint.finish()
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
    let mut fingerprint = Fingerprint::new();
    let mut index = 0;
    while index + 2 <= bytes.len() && !fingerprint.full() {
        let hw1 = read_hw(&bytes[index..index + 2]);
        if matches!(hw1 >> 11, 0b11101..=0b11111) {
            if index + 4 > bytes.len() {
                break;
            }
            let hw2 = read_hw(&bytes[index + 2..index + 4]);
            let (m1, m2) = mask_thumb32(hw1, hw2);
            // One push of the two halfwords concatenated hashes identically to two sequential updates.
            let mut encoding = [0u8; 4];
            encoding[..2].copy_from_slice(&m1.to_le_bytes());
            encoding[2..].copy_from_slice(&m2.to_le_bytes());
            fingerprint.push(&encoding);
            index += 4;
        } else {
            fingerprint.push(&mask_thumb16(hw1).to_le_bytes());
            index += 2;
        }
    }
    fingerprint.finish()
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

/// Hashes an x86 or x86-64 function, masking RIP-relative displacements and relative branch targets, plus (scheme
/// 2, when `image` is given) absolute displacements and immediates that point into the image.
fn x86_hash(bitness: u32, bytes: &[u8], address: u64, image: Option<&MaskContext>) -> Option<FunctionHash> {
    let mut decoder = Decoder::with_ip(bitness, bytes, address, DecoderOptions::NONE);
    let mut fingerprint = Fingerprint::new();
    let mut instruction = Instruction::default();
    while decoder.can_decode() && !fingerprint.full() {
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
        if let Some(image) = image {
            mask_absolute(&instruction, &offsets, image, &mut masked);
        }
        fingerprint.push(&masked);
    }
    fingerprint.finish()
}

/// Zeroes the displacement and immediate fields of `instruction` whose value is an address inside `image`. Non-PIE
/// code embeds the absolute addresses of its own globals and functions this way, and they move with layout. Only
/// fields of at least 4 bytes can hold such an address. A displacement is masked whatever its base/index registers:
/// besides `[abs]` and 64-bit moffs, non-PIE code indexes global arrays and jump tables as `[reg*s + abs]` and
/// `[reg + abs]`.
fn mask_absolute(instruction: &Instruction, offsets: &ConstantOffsets, image: &MaskContext, masked: &mut [u8]) {
    let relative_memory = matches!(instruction.memory_base(), Register::RIP | Register::EIP);
    // fs:/gs: displacements are thread-local or OS-structure offsets, not image addresses.
    let segment_relative = matches!(instruction.segment_prefix(), Register::FS | Register::GS);
    if offsets.has_displacement()
        && offsets.displacement_size() >= 4
        && !relative_memory
        && !segment_relative
        && image.contains(instruction.memory_displacement64())
    {
        zero_range(masked, offsets.displacement_offset(), offsets.displacement_size());
    }
    if offsets.has_immediate() && offsets.immediate_size() >= 4 && !is_relative_branch(instruction) {
        let value = (0..instruction.op_count()).find_map(|op| instruction.try_immediate(op).ok());
        if value.is_some_and(|value| image.contains(value)) {
            zero_range(masked, offsets.immediate_offset(), offsets.immediate_size());
        }
    }
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

/// The sort key that picks one spelling among aliases of a function at the same address (musl exports
/// `strchrnul` as a weak alias of `__strchrnul`; zig's libc also exports `memcpy` as
/// `compiler_rt.memcpy.memcpyFast`): no leading underscore first, then the shortest, then alphabetical.
pub fn alias_rank(name: &str) -> (bool, usize, &str) {
    (name.starts_with('_'), name.len(), name)
}

/// The masked content hash of the function whose bytes start at `address`, or `None` for an unsupported
/// architecture or input with no decodable instructions. `target` supplies the architecture, the instruction
/// byte order (used by the fixed-width paths), and, for 32-bit ARM, whether `address` holds Thumb code.
///
/// This is hash scheme 1 ([`LEGACY_SCHEME`]), which the bundled databases and older saved ones use; new databases
/// use [`function_hash_in`].
pub fn function_hash(target: &Target, bytes: &[u8], address: u64) -> Option<FunctionHash> {
    hash(target, bytes, address, None)
}

/// The scheme 2 ([`CURRENT_SCHEME`]) hash: [`function_hash`] plus masking of layout-dependent constants. On x86 and
/// x86-64, displacements and immediates whose value lies inside `image` (absolute addresses of the image's own
/// code and data, as non-PIE code embeds them) are masked. On AArch64, the low 12 bits that complete an ADRP page
/// address are masked (this needs no context). 32-bit ARM, MIPS and PowerPC hash as in scheme 1: their absolute
/// addresses (ARM literal pools, MIPS `lui`/`addiu` pairs) are not masked yet.
pub fn function_hash_in(target: &Target, image: &MaskContext, bytes: &[u8], address: u64) -> Option<FunctionHash> {
    hash(target, bytes, address, Some(image))
}

/// The hash of a function under `scheme` (see [`LEGACY_SCHEME`] and [`CURRENT_SCHEME`]), or `None` for an unknown
/// scheme or a body [`function_hash`] would reject. `image` is ignored by scheme 1.
pub fn function_hash_scheme(
    scheme: u32,
    target: &Target,
    image: &MaskContext,
    bytes: &[u8],
    address: u64,
) -> Option<FunctionHash> {
    match scheme {
        LEGACY_SCHEME => function_hash(target, bytes, address),
        CURRENT_SCHEME => function_hash_in(target, image, bytes, address),
        _ => None,
    }
}

/// `image` selects the scheme: `None` is scheme 1, `Some` is scheme 2 with that image's address ranges.
fn hash(target: &Target, bytes: &[u8], address: u64, image: Option<&MaskContext>) -> Option<FunctionHash> {
    match target.arch {
        Arch::X86 | Arch::X86_64 => x86_hash(x86_bitness(target.arch)?, bytes, address, image),
        Arch::Aarch64 if image.is_some() => {
            let mut pages = AdrpPages::default();
            fixed_word_hash(bytes, false, |word| pages.mask(word))
        }
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
#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureDb {
    /// The architecture the signatures were built for; matches are refused across architectures.
    pub arch: String,
    /// The hash scheme the entries were made with ([`LEGACY_SCHEME`] or [`CURRENT_SCHEME`]). Databases saved
    /// before schemes existed have no field and are scheme 1.
    #[serde(default = "legacy_scheme")]
    scheme: u32,
    /// Masked hash (lowercase hex) to function name. Hashes that mapped to more than one name are dropped, so a
    /// match is never ambiguous.
    entries: BTreeMap<String, String>,
}

fn legacy_scheme() -> u32 {
    LEGACY_SCHEME
}

impl Default for SignatureDb {
    fn default() -> SignatureDb {
        SignatureDb { arch: String::new(), scheme: CURRENT_SCHEME, entries: BTreeMap::new() }
    }
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

    fn finish(self, arch: Arch, scheme: u32) -> SignatureDb {
        let entries = self.names.into_iter().filter_map(|(hash, name)| Some((hash, name?))).collect();
        SignatureDb { arch: arch.to_string(), scheme, entries }
    }
}

impl SignatureDb {
    /// Builds [`CURRENT_SCHEME`] signatures from every named function in `binary` whose bytes are available, masking
    /// with the binary's own [`MaskContext`]. Functions whose bodies are byte-identical after masking but have
    /// different names are treated as ambiguous and left unmatchable.
    pub fn from_binary(binary: &Binary) -> SignatureDb {
        SignatureDb::from_binary_with_scheme(binary, CURRENT_SCHEME)
    }

    /// Builds signatures from `binary` under a specific hash `scheme`, e.g. [`LEGACY_SCHEME`] to extend or compare
    /// against an older database. An unknown scheme yields an empty database.
    pub fn from_binary_with_scheme(binary: &Binary, scheme: u32) -> SignatureDb {
        let mut builder = Builder::default();
        if supported(binary.arch) {
            let target = binary.target();
            let image = MaskContext::from_binary(binary);
            // Several names at one address are aliases of one function, not a collision: keep one spelling, or
            // the builder would drop the hash as ambiguous and the function could never be identified.
            let mut by_address = BTreeMap::new();
            for symbol in &binary.symbols {
                if symbol.kind != SymbolKind::Function || symbol.size == 0 || symbol.name.is_empty() {
                    continue;
                }
                by_address
                    .entry(symbol.address)
                    .and_modify(|best: &mut &rampage_loaders::Symbol| {
                        if alias_rank(&symbol.name) < alias_rank(&best.name) {
                            *best = symbol;
                        }
                    })
                    .or_insert(symbol);
            }
            for symbol in by_address.into_values() {
                if let Some(bytes) = binary.read(symbol.address, symbol.size)
                    && let Some(hash) = function_hash_scheme(scheme, &target, &image, bytes, symbol.address)
                {
                    builder.add(hash, &symbol.name);
                }
            }
        }
        builder.finish(binary.arch, scheme)
    }

    /// Adds every named function from `binary` to this database, hashed under this database's scheme, so one
    /// database can span several libraries.
    pub fn extend_from_binary(&mut self, binary: &Binary) {
        let additions = SignatureDb::from_binary_with_scheme(binary, self.scheme);
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

    /// Overlays `other` onto this database, letting `other`'s names win on any shared hash (so a user database
    /// takes precedence over a bundled one). Databases for different architectures or hash schemes do not mix
    /// (their hashes are not comparable), so a mismatched `other` is ignored; [`SignatureDb::can_merge`] tells.
    pub fn merge(&mut self, other: &SignatureDb) {
        if !self.can_merge(other) {
            return;
        }
        for (hash, name) in &other.entries {
            self.entries.insert(hash.clone(), name.clone());
        }
    }

    /// Whether [`SignatureDb::merge`] would take `other`'s entries: same architecture and hash scheme.
    pub fn can_merge(&self, other: &SignatureDb) -> bool {
        self.arch == other.arch && self.scheme == other.scheme
    }

    /// The hash scheme of this database's entries.
    pub fn scheme(&self) -> u32 {
        self.scheme
    }

    /// The name for the function whose bytes start at `address`, hashed without knowledge of the image's layout.
    /// `target` carries the architecture and instruction byte order (see [`function_hash`]).
    ///
    /// For a scheme 1 database this is exact. For a scheme 2 database it hashes with an empty [`MaskContext`], so
    /// absolute addresses stay in the hash and a function that embeds any will not match: it finds a subset of
    /// what [`SignatureDb::identify_in`] finds, never different names. Prefer `identify_in`.
    pub fn identify(&self, target: &Target, bytes: &[u8], address: u64) -> Option<&str> {
        self.identify_in(target, &MaskContext::default(), bytes, address)
    }

    /// The name for the function whose bytes start at `address` in the image described by `image` (see
    /// [`MaskContext::from_binary`]), hashed under this database's own scheme. The architecture must match.
    pub fn identify_in(&self, target: &Target, image: &MaskContext, bytes: &[u8], address: u64) -> Option<&str> {
        if self.arch != target.arch.to_string() {
            return None;
        }
        let hash = function_hash_scheme(self.scheme, target, image, bytes, address)?;
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
        words.iter().flat_map(|word| if big_endian { word.to_be_bytes() } else { word.to_le_bytes() }).collect()
    }

    /// Packs 16-bit Thumb halfwords into bytes in the given order.
    fn halfwords_to_bytes(halfwords: &[u16], big_endian: bool) -> Vec<u8> {
        halfwords.iter().flat_map(|hw| if big_endian { hw.to_be_bytes() } else { hw.to_le_bytes() }).collect()
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
        let db = builder.finish(Arch::X86_64, LEGACY_SCHEME);
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
                binary
                    .read(symbol.address, symbol.size)
                    .is_some_and(|bytes| db.identify(&target, bytes, symbol.address) == Some(symbol.name.as_str()))
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
        // An absolute branch's target (AA=1) is left in the hash, so changing it must differ. Real content
        // surrounds the branch so the body clears the discriminating-content gate (a bare branch pair does not).
        let abs_base = words_to_bytes(&[0x3863_0010, 0x4800_0102, 0x3884_0020, 0x4e80_0020], true);
        let abs_other = words_to_bytes(&[0x3863_0010, 0x4800_1232, 0x3884_0020, 0x4e80_0020], true);
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

    /// sub sp,sp,#16; str w0,[sp,#12]; ldr w0,[sp,#12]; add w0,w0,#1; add sp,sp,#16; ret -- a real AArch64 leaf.
    fn aarch64_leaf() -> [u32; 6] {
        [0xd100_43ff, 0xb900_0fe0, 0xb940_0fe0, 0x1100_0400, 0x9100_43ff, 0xd65f_03c0]
    }

    #[test]
    fn gate_rejects_empty_input() {
        assert!(function_hash(&target(Arch::X86_64, false), &[], 0x1000).is_none());
        assert!(function_hash(&target(Arch::Aarch64, false), &[], 0).is_none());
    }

    #[test]
    fn gate_rejects_a_single_branch_thunk() {
        // x86 jmp rel32 masks to a lone opcode byte: one non-discriminating instruction.
        assert!(function_hash(&target(Arch::X86_64, false), &[0xe9, 0x00, 0x00, 0x00, 0x00], 0x1000).is_none());
        // AArch64 unconditional branch: a one-word thunk.
        let branch = words_to_bytes(&[0x1400_0000], false);
        assert!(function_hash(&target(Arch::Aarch64, false), &branch, 0).is_none());
    }

    #[test]
    fn gate_rejects_an_all_nop_body() {
        // Many instructions but one repeated encoding carries no discriminating content.
        assert!(function_hash(&target(Arch::X86_64, false), &[0x90; 16], 0x1000).is_none());
        let nops = words_to_bytes(&[0xd503_201f; 16], false);
        assert!(function_hash(&target(Arch::Aarch64, false), &nops, 0).is_none());
    }

    #[test]
    fn gate_accepts_a_normal_small_function() {
        // A real x86 leaf (the shared sample) and a real AArch64 leaf both clear the gate.
        assert!(function_hash(&target(Arch::X86_64, false), &sample(), 0x1000).is_some());
        let leaf = words_to_bytes(&aarch64_leaf(), false);
        assert!(function_hash(&target(Arch::Aarch64, false), &leaf, 0x1000).is_some());
    }

    #[test]
    fn gate_tolerates_a_truncated_trailing_instruction() {
        // A trailing partial instruction (a lone REX prefix) decodes as invalid and is dropped; the valid
        // leading instructions still hash to the untruncated body's value.
        let x64 = target(Arch::X86_64, false);
        let mut truncated = sample();
        truncated.push(0x48); // REX.W with no following opcode
        assert_eq!(function_hash(&x64, &truncated, 0x1000), function_hash(&x64, &sample(), 0x1000));
    }

    #[test]
    fn gate_handles_unaligned_fixed_width_input() {
        let a64 = target(Arch::Aarch64, false);
        // Fewer than one full word: no instruction decodes and nothing panics.
        assert!(function_hash(&a64, &[0x01, 0x02, 0x03], 0).is_none());
        // A length that is not a multiple of 4: the trailing partial word is ignored, the whole words still hash.
        let whole = words_to_bytes(&aarch64_leaf(), false);
        let mut odd = whole.clone();
        odd.push(0x5a); // one stray byte -> length 25
        assert_eq!(function_hash(&a64, &odd, 0), function_hash(&a64, &whole, 0));
        assert!(function_hash(&a64, &odd, 0).is_some());
    }

    #[test]
    fn scheme_1_hash_is_pinned() {
        // SHA-256 of the sample with its call target and RIP displacement zeroed, as scheme 1 always hashed it.
        let expected = "84607e3e3071cf92e225c1205434ed2d623bb50d2abe1836e8985fe4651dfafe";
        let x64 = target(Arch::X86_64, false);
        assert_eq!(hex(&function_hash(&x64, &sample(), 0x1000).unwrap()), expected);
        let image = MaskContext::new(std::iter::once(0..u64::MAX));
        let legacy = function_hash_scheme(LEGACY_SCHEME, &x64, &image, &sample(), 0x1000).unwrap();
        assert_eq!(hex(&legacy), expected);
    }

    /// The image of the absolute-address samples below.
    fn image() -> MaskContext {
        MaskContext::new([0x40_0000..0x40_8000, 0x40_8000..0x41_0000])
    }

    /// An x86-64 body with four absolute references into the image: `mov edi, imm32`, `mov rax, [abs32]`,
    /// `mov eax, [rdi*4 + abs32]` and `movabs rax, [moffs64]`, then `add eax, 0x1234` and `ret`.
    fn absolute_sample(addresses: [u32; 4]) -> Vec<u8> {
        let mut bytes = vec![0xbf];
        bytes.extend(addresses[0].to_le_bytes());
        bytes.extend([0x48, 0x8b, 0x04, 0x25]);
        bytes.extend(addresses[1].to_le_bytes());
        bytes.extend([0x8b, 0x04, 0xbd]);
        bytes.extend(addresses[2].to_le_bytes());
        bytes.extend([0x48, 0xa1]);
        bytes.extend(u64::from(addresses[3]).to_le_bytes());
        bytes.extend([0x05, 0x34, 0x12, 0x00, 0x00, 0xc3]);
        bytes
    }

    #[test]
    fn scheme_2_masks_absolute_addresses_inside_the_image() {
        let x64 = target(Arch::X86_64, false);
        let base = absolute_sample([0x40_a2c8, 0x40_b000, 0x40_c000, 0x40_d000]);
        let relinked = absolute_sample([0x40_02c8, 0x40_f010, 0x40_1000, 0x40_0008]);
        assert_eq!(
            function_hash_in(&x64, &image(), &base, 0x1000),
            function_hash_in(&x64, &image(), &relinked, 0x1000)
        );
        assert!(function_hash_in(&x64, &image(), &base, 0x1000).is_some());
        // Scheme 1 keeps them, so the relinked copy hashes differently there.
        assert_ne!(function_hash(&x64, &base, 0x1000), function_hash(&x64, &relinked, 0x1000));
    }

    #[test]
    fn scheme_2_keeps_constants_outside_the_image() {
        let x64 = target(Arch::X86_64, false);
        let base = absolute_sample([0x50_a2c8, 0x40_b000, 0x40_c000, 0x40_d000]);
        let changed = absolute_sample([0x50_a2c9, 0x40_b000, 0x40_c000, 0x40_d000]);
        assert_ne!(function_hash_in(&x64, &image(), &base, 0x1000), function_hash_in(&x64, &image(), &changed, 0x1000));
        // The ordinary 0x1234 immediate is below the image, so it still discriminates.
        let mut other_add = base.clone();
        let immediate = other_add.len() - 5;
        other_add[immediate] = 0x35;
        assert_ne!(
            function_hash_in(&x64, &image(), &base, 0x1000),
            function_hash_in(&x64, &image(), &other_add, 0x1000)
        );
        // With no context nothing extra is masked: in-range addresses still discriminate.
        let relinked = absolute_sample([0x40_02c8, 0x40_b000, 0x40_c000, 0x40_d000]);
        let empty = MaskContext::default();
        assert_ne!(function_hash_in(&x64, &empty, &base, 0x1000), function_hash_in(&x64, &empty, &relinked, 0x1000));
    }

    #[test]
    fn scheme_2_keeps_thread_local_displacements() {
        let x64 = target(Arch::X86_64, false);
        // mov rax, fs:[disp32]; add eax, 0x1234; add eax, 0x1234; ret -- an fs: offset is never an image address.
        let body = |disp: u32| {
            let mut bytes = vec![0x64, 0x48, 0x8b, 0x04, 0x25];
            bytes.extend(disp.to_le_bytes());
            bytes.extend([0x05, 0x34, 0x12, 0x00, 0x00, 0x05, 0x34, 0x12, 0x00, 0x00, 0xc3]);
            bytes
        };
        assert_ne!(
            function_hash_in(&x64, &image(), &body(0x40_0010), 0),
            function_hash_in(&x64, &image(), &body(0x40_0018), 0)
        );
    }

    #[test]
    fn scheme_2_masks_the_low_half_of_an_aarch64_adrp_pair() {
        let a64 = target(Arch::Aarch64, false);
        let image = MaskContext::default();
        // adrp x0, page; add x0, x0, #lo12; ldr w1, [x0, #8]; ret.
        let body = |lo12: u32, field: u32| {
            words_to_bytes(
                &[0x9000_0000, 0x9100_0000 | (lo12 << 10), 0xb940_0001 | (field / 4) << 10, 0xd65f_03c0],
                false,
            )
        };
        assert_eq!(
            function_hash_in(&a64, &image, &body(0x123, 8), 0),
            function_hash_in(&a64, &image, &body(0x456, 8), 0)
        );
        assert_ne!(function_hash(&a64, &body(0x123, 8), 0), function_hash(&a64, &body(0x456, 8), 0));
        // x0 holds the full address after the add, so the load's field offset is real content.
        assert_ne!(
            function_hash_in(&a64, &image, &body(0x123, 8), 0),
            function_hash_in(&a64, &image, &body(0x123, 12), 0)
        );
    }

    #[test]
    fn mask_context_normalizes_and_answers_membership() {
        let context = MaskContext::new([0x30..0x40, 0x10..0x20, 0x18..0x28, 0x50..0x50]);
        assert_eq!(context.ranges(), &[0x10..0x28, 0x30..0x40]);
        assert!(context.contains(0x10) && context.contains(0x27) && context.contains(0x3f));
        assert!(!context.contains(0x0f) && !context.contains(0x28) && !context.contains(0x40));
        assert!(!MaskContext::default().contains(0));
    }

    #[test]
    fn mask_context_covers_fixed_images_only() {
        let fixed = MaskContext::from_binary(&Binary::open(fixture("musl-static-x86_64.elf")).unwrap());
        assert!(!fixed.ranges().is_empty());
        // A shared object is mapped from 0: its code holds no absolute addresses, so nothing is masked.
        assert!(MaskContext::from_binary(&Binary::open(fixture("libhelper-x64.so")).unwrap()).ranges().is_empty());
        // Mach-O's inaccessible __PAGEZERO (0..4 GiB) is not part of the image.
        let macho = MaskContext::from_binary(&Binary::open(fixture("hello-x64.macho")).unwrap());
        assert!(!macho.ranges().is_empty() && !macho.contains(0x1000));
    }

    #[test]
    fn databases_record_their_scheme_and_do_not_mix() {
        let legacy = SignatureDb::from_json(r#"{"arch":"x86_64","entries":{}}"#).unwrap();
        assert_eq!(legacy.scheme(), LEGACY_SCHEME);
        let mut current = SignatureDb::from_binary(&Binary::open(fixture("hello-x64.elf")).unwrap());
        assert_eq!(current.scheme(), CURRENT_SCHEME);
        assert_eq!(SignatureDb::from_json(&current.to_json()).unwrap().scheme(), CURRENT_SCHEME);
        let before = current.len();
        let mut older = Builder::default();
        older.add([7; 32], "older");
        let older = older.finish(Arch::X86_64, LEGACY_SCHEME);
        assert!(!current.can_merge(&older));
        current.merge(&older);
        assert_eq!(current.len(), before);
        let mut newer = Builder::default();
        newer.add([7; 32], "newer");
        current.merge(&newer.finish(Arch::X86_64, CURRENT_SCHEME));
        assert_eq!(current.len(), before + 1);
        let mut unknown = SignatureDb::from_json(r#"{"arch":"x86_64","scheme":99,"entries":{}}"#).unwrap();
        assert!(SignatureDb::from_binary_with_scheme(&Binary::open(fixture("hello-x64.elf")).unwrap(), 99).is_empty());
        unknown.extend_from_binary(&Binary::open(fixture("hello-x64.elf")).unwrap());
        assert!(unknown.is_empty());
    }

    #[test]
    fn scheme_2_identify_without_context_never_renames() {
        let x64 = target(Arch::X86_64, false);
        let body = absolute_sample([0x40_a2c8, 0x40_b000, 0x40_c000, 0x40_d000]);
        let mut builder = Builder::default();
        builder.add(function_hash_in(&x64, &image(), &body, 0x1000).unwrap(), "uses_globals");
        builder.add(function_hash_in(&x64, &image(), &sample(), 0x1000).unwrap(), "leaf");
        let db = builder.finish(Arch::X86_64, CURRENT_SCHEME);
        assert_eq!(db.identify_in(&x64, &image(), &body, 0x1000), Some("uses_globals"));
        // Without the image's layout the absolute addresses stay in the hash, so it cannot match...
        assert_eq!(db.identify(&x64, &body, 0x1000), None);
        // ...while a body with none matches either way.
        assert_eq!(db.identify(&x64, &sample(), 0x1000), Some("leaf"));
    }
}
