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
//! address. It also masks relative fields scheme 1 missed or over-masked on Thumb and MIPS (see
//! [`function_hash_in`]); scheme 1's hashes stay frozen. A [`SignatureDb`] records its scheme and
//! [`SignatureDb::identify_in`] hashes with it, so databases saved under scheme 1 keep matching exactly as before.
//! New databases, the bundled ones included, are scheme 2.
//!
//! A confidence gate rejects non-discriminating bodies so they are neither stored nor matched: a body whose
//! masked form carries too little content (a single-branch thunk masks to almost nothing, all-nop padding is one
//! repeated word) would collide with many unrelated functions, making a "match" meaningless. [`function_hash`]
//! returns `None` unless the body clears all of: a minimum instruction count, a minimum number of non-masked
//! (content-bearing) bytes remaining after masking, and a minimum number of distinct instruction encodings (so
//! constant padding is rejected). The thresholds are heuristic but conservative -- tuned to keep genuine small
//! leaf functions while dropping trivial/degenerate bodies.
//!
//! Two lookups recover functions the masked hash alone cannot name. [`identify_program`] keys a body several
//! functions share by the names of the functions it branches to (x86 and AArch64), which it names first: `fprintf`
//! and `sscanf` differ only in calling `vfprintf` or `vsscanf`. Only a body that passes the gate, even without its
//! landing pads and final branch, gets such a key, so a thunk is never named after what it forwards to (a user
//! `strtod(s, 0)` wrapper is byte-identical to musl's `atof`). And a database built with
//! [`SignatureDb::from_binary_with_extents`] also hashes each function over the extent discovery finds for it in
//! the reference: identification hashes discovered bodies and discovery stops short of a jump table it cannot
//! follow, so this matches a stripped target where discovery stops at the same place in both.

mod bundled;
mod compressed;
mod diagnostics;
pub mod fid;
pub mod fuzzy;
mod operands;
mod pat;

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

pub use bundled::{BundledMetadata, BundledProfile, FLYWHEEL_PROFILE_PREFIX, bundled, bundled_counts, bundled_ref};
pub use compressed::{CombineError, SignatureDbError};
pub use diagnostics::{
    CalleeNameInput, CalleeNameSource, FingerprintStatus, GateDiagnostics, KeyDiagnostics, LookupState,
    MatchDiagnostics, MatchVia,
};
use iced_x86::{ConstantOffsets, Decoder, DecoderOptions, Instruction, OpKind, Register};
pub use operands::{OperandClass, operand_classes};
pub use pat::{PatError, PatErrorKind, PatternByte, PatternDb, PatternMatch, PatternName, PatternRecord};
use rampage_arch::{Arch, Target};
use rampage_loaders::{Binary, Symbol, SymbolKind};
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

/// Most rounds of [`identify_program`] that name functions by their callees, each building on the names the
/// previous one found; real wrapper chains are a few deep.
const MAX_CALLEE_ROUNDS: usize = 16;

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
/// yields the hash or `None`. The gate only accepts or rejects: it never changes an accepted body's hash.
struct Fingerprint {
    hasher: Sha256,
    measure: Measure,
    /// The same measures without landing pads (`endbr64`, `bti`) and the last instruction, which
    /// [`Fingerprint::callee_key`] gates on when that instruction is a branch.
    core: Measure,
    /// The last non-landing-pad instruction's fold and content, and whether it is a direct branch: not yet in
    /// `core`.
    last: Option<(u64, usize, bool)>,
    /// Targets of the direct branches and calls, in instruction order (x86 and AArch64 only).
    branch_targets: Vec<u64>,
    /// The masked encodings fed so far, concatenated: [`masked_body_in`] compares them with the raw bytes.
    stream: Vec<u8>,
}

/// What the confidence gate measures of a masked instruction stream.
#[derive(Clone, Default)]
struct Measure {
    instructions: u32,
    content_bytes: usize,
    /// Folds of distinct masked encodings, stopped once [`MIN_DISTINCT`] is reached so it stays small.
    distinct: BTreeSet<u64>,
}

impl Measure {
    fn add(&mut self, fold: u64, content: usize) {
        self.instructions += 1;
        self.content_bytes += content;
        if self.distinct.len() < MIN_DISTINCT {
            self.distinct.insert(fold);
        }
    }

    fn discriminating(&self) -> bool {
        self.instructions >= MIN_INSTRUCTIONS && self.has_content()
    }

    /// The content and distinct-encoding parts of the gate.
    fn has_content(&self) -> bool {
        self.content_bytes >= MIN_CONTENT_BYTES && self.distinct.len() >= MIN_DISTINCT
    }
}

/// Whether a masked instruction is a branch-target landing pad: x86 `endbr64`/`endbr32` or an AArch64 `bti`. They
/// carry none of the function's content and make a thunk look like more than a bare branch.
fn is_landing_pad(masked: &[u8]) -> bool {
    match *masked {
        [0xf3, 0x0f, 0x1e, 0xfa | 0xfb] => true,
        [a, b, c, d] => u32::from_le_bytes([a, b, c, d]) & 0xffff_ff3f == 0xd503_241f,
        _ => false,
    }
}

impl Fingerprint {
    fn new() -> Fingerprint {
        Fingerprint {
            hasher: Sha256::new(),
            measure: Measure::default(),
            core: Measure::default(),
            last: None,
            branch_targets: Vec::new(),
            stream: Vec::new(),
        }
    }

    /// The hash of the masked body together with the names of the functions it branches to outside `body`, which
    /// tells apart bodies whose masked hash several functions share: `fprintf` and `sscanf` differ only in calling
    /// `vfprintf` or `vsscanf`. `None` unless the body passes the confidence gate, and its content and
    /// distinct-encoding parts even without its landing pads and final branch (so a thunk such as
    /// `endbr64; jmp vfprintf`, which any function forwarding there shares, never keys a match, while a frame set up
    /// around a tail call, as `fmodl` and `__addtf3`, does); it must also branch outside itself at least once, and
    /// `name` must name every such target.
    fn callee_key<'n>(&self, body: Range<u64>, name: impl Fn(u64) -> Option<&'n str>) -> Option<FunctionHash> {
        if !self.measure.discriminating() || !self.callee_core().has_content() {
            return None;
        }
        let callees = self.branch_targets.iter().filter(|target| !body.contains(target));
        let names: Vec<&str> = callees.map(|&target| name(target)).collect::<Option<_>>()?;
        if names.is_empty() {
            return None;
        }
        let mut hasher = Sha256::new();
        hasher.update(b"rampage callees\0");
        hasher.update(self.hasher.clone().finalize());
        for name in names {
            hasher.update(name.as_bytes());
            hasher.update([0]);
        }
        Some(hasher.finalize().into())
    }

    fn callee_core(&self) -> Measure {
        let mut core = self.core.clone();
        if let Some((fold, content, false)) = self.last {
            core.add(fold, content);
        }
        core
    }

    /// Feeds one instruction's masked encoding into the hash and the content measures, with its target when it is
    /// a direct branch or call.
    fn push(&mut self, masked: &[u8], branch: Option<u64>) {
        self.hasher.update(masked);
        let fold = fold(masked);
        let content = masked.iter().filter(|&&byte| byte != 0).count();
        self.measure.add(fold, content);
        if !is_landing_pad(masked) {
            if let Some((fold, content, _)) = self.last.take() {
                self.core.add(fold, content);
            }
            self.last = Some((fold, content, branch.is_some()));
        }
        self.branch_targets.extend(branch);
        self.stream.extend_from_slice(masked);
    }

    /// Whether the instruction cap has been reached, so a caller can stop feeding.
    fn full(&self) -> bool {
        self.measure.instructions >= MAX_INSTRUCTIONS
    }

    /// The masked content hash, or `None` when the body fails the confidence gate.
    fn finish(self) -> Option<FunctionHash> {
        self.measure.discriminating().then(|| self.hasher.finalize().into())
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

/// Masks the position-dependent immediate bits of a little-endian AArch64 instruction word, leaving opcode and
/// registers. Covers the PC-relative forms: B/BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, ADR/ADRP and literal loads.
fn mask_aarch64(word: u32) -> u32 {
    word & !aarch64_relative_bits(word)
}

/// The bits [`mask_aarch64`] clears from `word`: its PC-relative offset field, or none.
fn aarch64_relative_bits(word: u32) -> u32 {
    // Unconditional branch/branch-with-link: 26-bit relative offset.
    if word & 0x7c00_0000 == 0x1400_0000 {
        return 0x03ff_ffff;
    }
    // ADR/ADRP: page/byte relative, split into immlo (bits 30:29) and immhi (bits 23:5).
    if word & 0x1f00_0000 == 0x1000_0000 {
        return 0x60ff_ffe0;
    }
    // B.cond, CBZ/CBNZ and literal loads: a 19-bit offset in bits 23:5.
    let imm19 = 0x7ffffu32 << 5;
    if word & 0xff00_0010 == 0x5400_0000 // B.cond
        || word & 0x7e00_0000 == 0x3400_0000 // CBZ/CBNZ
        || word & 0x3b00_0000 == 0x1800_0000
    // LDR/LDRSW literal, PRFM literal
    {
        return imm19;
    }
    // TBZ/TBNZ: a 14-bit offset in bits 18:5.
    if word & 0x7e00_0000 == 0x3600_0000 {
        return 0x3fffu32 << 5;
    }
    0
}

/// The target of an AArch64 B or BL at `address`, the direct branches that leave a function (calls and tail calls).
fn aarch64_branch_target(word: u32, address: u64) -> Option<u64> {
    (word & 0x7c00_0000 == 0x1400_0000).then(|| {
        let offset = i64::from(((word & 0x03ff_ffff) << 6) as i32 >> 6) * 4;
        address.wrapping_add_signed(offset)
    })
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
        word & !self.bits(word)
    }

    /// The bits [`AdrpPages::mask`] clears from `word`, updating the tracked page registers.
    fn bits(&mut self, word: u32) -> u32 {
        let relative = aarch64_relative_bits(word);
        let destination = word & 0x1f;
        let source = (word >> 5) & 0x1f;
        if word & 0x9f00_0000 == 0x9000_0000 {
            // Register 31 is xzr here, which holds nothing.
            if destination != 31 {
                self.registers |= 1 << destination;
            }
            return relative;
        }
        let add_unshifted = word & 0x7fc0_0000 == 0x1100_0000;
        let load_store_unsigned = word & 0x3b00_0000 == 0x3900_0000;
        let completes = (add_unshifted || load_store_unsigned) && self.registers & (1 << source) != 0;
        self.registers &= !written_registers(word);
        if completes { relative | 0xfff << 10 } else { relative }
    }
}

/// The general registers, as a bitset, that an AArch64 instruction may write. Branches, stores and other
/// instructions whose bits 4:0 are not a destination write none. Where the encoding does not say cheaply (SIMD&FP
/// moves to a general register, exclusives, unusual load/store forms) every candidate field counts as written:
/// forgetting a page register only leaves a low half unmasked.
fn written_registers(word: u32) -> u32 {
    let rt = 1u32 << (word & 0x1f);
    match (word >> 25) & 0xf {
        0b1000 | 0b1001 => rt, // data processing, immediate
        0b0101 | 0b1101 => rt, // data processing, register
        0b0111 | 0b1111 => rt, // SIMD and floating point
        0b1010 | 0b1011 => {
            let call = word & 0xfc00_0000 == 0x9400_0000 || word & 0xffff_fc1f == 0xd63f_0000;
            let system_read = word & 0xffe0_0000 == 0xd520_0000; // MRS, SYSL
            if call {
                // x0..x18 are caller-saved and the link register x30 takes the return address.
                0x7_ffff | 1 << 30
            } else if system_read {
                rt
            } else {
                0
            }
        }
        0b0100 | 0b0110 | 0b1100 | 0b1110 => load_store_writes(word),
        _ => 0,
    }
}

/// [`written_registers`] for the load/store class: a general-register load writes Rt (and Rt2 for a pair), and a
/// pre- or post-indexed access writes its base Rn back.
fn load_store_writes(word: u32) -> u32 {
    let rt = 1u32 << (word & 0x1f);
    let rn = 1u32 << ((word >> 5) & 0x1f);
    let rt2 = 1u32 << ((word >> 10) & 0x1f);
    let rs = 1u32 << ((word >> 16) & 0x1f);
    let only = |condition: bool, registers: u32| if condition { registers } else { 0 };
    let vector = word & 0x0400_0000 != 0;
    let opc = (word >> 22) & 0b11;
    if word & 0x3800_0000 == 0x2800_0000 {
        // Pair: L is bit 22; bits 24:23 are 01 (post-index) or 11 (pre-index) with write-back.
        let load = word & 0x0040_0000 != 0 && !vector;
        return only(load, rt | rt2) | only(word & 0x0080_0000 != 0, rn);
    }
    if word & 0x3b00_0000 == 0x1800_0000 {
        // Literal: opc (bits 31:30) 0b11 is PRFM, which writes nothing.
        return only(!vector && word >> 30 != 0b11, rt);
    }
    if word & 0x3800_0000 == 0x3800_0000 {
        let unsigned_offset = word & 0x0100_0000 != 0;
        let register_form = word & 0x0020_0000 != 0;
        let low = (word >> 10) & 0b11;
        if !unsigned_offset && register_form && low != 0b10 {
            // Atomic memory operations (bits 11:10 == 00) and pointer-authenticated loads, which may write back.
            return rt | only(low == 0b11, rn);
        }
        let prefetch = word >> 30 == 0b11 && opc == 0b10;
        let load = !vector && opc != 0 && !prefetch;
        // Pre- and post-indexed immediates (bit 10 set) write the base back.
        let write_back = !unsigned_offset && !register_form && low & 1 == 1;
        return only(load, rt) | only(write_back, rn);
    }
    if word & 0xbe00_0000 == 0x0c00_0000 {
        // SIMD structure loads and stores touch only vector registers, plus the base when post-indexed.
        return only(word & 0x0080_0000 != 0, rn);
    }
    // Exclusive, ordered, compare-and-swap, memory tagging and other forms.
    rt | rt2 | rs
}

/// Hashes a stream of fixed 4-byte instruction words, reading each in `big_endian` order and applying `mask` to
/// drop its position-dependent fields. The masked value is hashed in a fixed byte order, so the same logical
/// function hashes equal whether the build is big- or little-endian. `branch` gives the target of a direct branch
/// word at an address, where the architecture records them.
fn fixed_word_fingerprint(
    bytes: &[u8],
    address: u64,
    big_endian: bool,
    mut mask: impl FnMut(u32) -> u32,
    branch: impl Fn(u32, u64) -> Option<u64>,
) -> Fingerprint {
    let mut fingerprint = Fingerprint::new();
    let (words, _) = bytes.as_chunks::<4>();
    for (index, word) in words.iter().enumerate() {
        let value = if big_endian { u32::from_be_bytes(*word) } else { u32::from_le_bytes(*word) };
        fingerprint.push(&mask(value).to_le_bytes(), branch(value, address.wrapping_add(index as u64 * 4)));
        if fingerprint.full() {
            break;
        }
    }
    fingerprint
}

/// For the fixed-width architectures whose direct branches are not recorded.
fn no_branch(_: u32, _: u64) -> Option<u64> {
    None
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
/// 8-bit imm; conditions 0b1110/0b1111 are undefined/SVC, not branches). Scheme 2 (`current`) also masks CBZ/CBNZ
/// (`1011 o0i1 imm5 Rn`), whose i:imm5 offset is relative too; scheme 1 keeps it so its hashes never change.
fn mask_thumb16(hw: u16, current: bool) -> u16 {
    if hw >> 11 == 0b11100 {
        return hw & !0x07ff;
    }
    if hw >> 12 == 0b1101 {
        let cond = (hw >> 8) & 0xf;
        if cond != 0b1110 && cond != 0b1111 {
            return hw & !0x00ff;
        }
    }
    if current && hw & 0xf500 == 0xb100 {
        return hw & !0x02f8;
    }
    hw
}

/// Masks the imm fields of a 32-bit Thumb branch, whose first halfword is `0b11110 S ...` and whose second is
/// `0b1 J1 x J2 imm11`. BL/BLX (second halfword `0b11 ...`, bit 12 telling them apart and so kept) mask S, imm10,
/// J1, J2 and imm11. Scheme 2 (`current`) also masks B.W (T4, `0b10 J1 1 J2`) the same way and the conditional
/// B<c>.W (T3, `0b10 J1 0 J2`), keeping its condition (first halfword bits 9:6; 0b111x there is not a branch).
/// Any other 32-bit instruction passes through unchanged.
fn mask_thumb32(hw1: u16, hw2: u16, current: bool) -> (u16, u16) {
    if hw1 >> 11 != 0b11110 {
        return (hw1, hw2);
    }
    if hw2 >> 14 == 0b11 || (current && hw2 & 0xd000 == 0x9000) {
        return (hw1 & !0x07ff, hw2 & !0x2fff);
    }
    if current && hw2 & 0xd000 == 0x8000 && (hw1 >> 6) & 0xf < 0b1110 {
        return (hw1 & !0x043f, hw2 & !0x2fff);
    }
    (hw1, hw2)
}

/// Hashes a Thumb (T32) function, decoding halfword-by-halfword from the start. A first halfword with
/// bits [15:11] in {0b11101, 0b11110, 0b11111} begins a 32-bit instruction (two halfwords), else it is 16-bit.
/// `current` selects scheme 2's masking.
fn thumb_fingerprint(bytes: &[u8], big_endian: bool, current: bool) -> Fingerprint {
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
            let (m1, m2) = mask_thumb32(hw1, hw2, current);
            // One push of the two halfwords concatenated hashes identically to two sequential updates.
            let mut encoding = [0u8; 4];
            encoding[..2].copy_from_slice(&m1.to_le_bytes());
            encoding[2..].copy_from_slice(&m2.to_le_bytes());
            fingerprint.push(&encoding, None);
            index += 4;
        } else {
            fingerprint.push(&mask_thumb16(hw1, current).to_le_bytes(), None);
            index += 2;
        }
    }
    fingerprint
}

/// Masks the position-dependent target of a MIPS branch. J/JAL (opcode 0b000010/0b000011) carry a 26-bit
/// instr_index; the conditional branches BEQ/BNE/BLEZ/BGTZ (opcodes 0x04..=0x07) and the REGIMM branches (opcode
/// 0x01: BLTZ/BGEZ and their -L, -AL, -ALL forms) carry a 16-bit PC-relative offset. Generic I-type immediates
/// (addiu/lui/ori) are left intact.
///
/// Scheme 1 masks the 16-bit field of every REGIMM instruction, including the traps and SYNCI whose field is data,
/// and misses the branch-likely opcodes; its hashes are frozen, so scheme 2 (`current`) fixes both.
///
/// Conservative choice: a `lui`/`addiu` HI/LO address pair is a genuine data immediate here, so it is not masked
/// and will differ across differently based links. That lowers the cross-link match rate but never mismatches;
/// recovering those pairs needs relocation/dataflow analysis, left for a later version.
fn mask_mips(word: u32, current: bool) -> u32 {
    let regimm_branch = matches!((word >> 16) & 0x1f, 0x00..=0x03 | 0x10..=0x13);
    match word >> 26 {
        0b000010 | 0b000011 => word & !0x03ff_ffff,
        0b000001 if regimm_branch || !current => word & !0x0000_ffff,
        0b000100..=0b000111 => word & !0x0000_ffff,
        // BEQL/BNEL/BLEZL/BGTZL.
        0b010100..=0b010111 if current => word & !0x0000_ffff,
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
fn x86_fingerprint(bitness: u32, bytes: &[u8], address: u64, image: Option<&MaskContext>) -> Fingerprint {
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
        for range in x86_masked_ranges(&instruction, &offsets, image) {
            zero_range(&mut masked, range.start, range.len());
        }
        let branch =
            (is_relative_branch(&instruction) && offsets.has_immediate()).then(|| instruction.near_branch_target());
        fingerprint.push(&masked, branch);
    }
    fingerprint
}

/// The byte ranges, within one instruction, that the fingerprint masks (`image` selects scheme 2):
/// - a RIP-relative displacement encodes an absolute address that moves with the function;
/// - a near branch or call encodes its target as a relative immediate that moves with layout;
/// - under scheme 2, the displacements and immediates [`mask_absolute`] finds.
fn x86_masked_ranges(
    instruction: &Instruction,
    offsets: &ConstantOffsets,
    image: Option<&MaskContext>,
) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut push = |offset: usize, size: usize| ranges.push(offset..offset + size);
    if instruction.memory_base() == Register::RIP && offsets.has_displacement() {
        push(offsets.displacement_offset(), offsets.displacement_size());
    }
    if is_relative_branch(instruction) && offsets.has_immediate() {
        push(offsets.immediate_offset(), offsets.immediate_size());
    }
    if let Some(image) = image {
        mask_absolute(instruction, offsets, image, &mut push);
    }
    ranges
}

/// Reports the displacement and immediate fields of `instruction` whose value is an address inside `image`. Non-PIE
/// code embeds the absolute addresses of its own globals and functions this way, and they move with layout. Only
/// fields of at least 4 bytes can hold such an address. A displacement is masked whatever its base/index registers:
/// besides `[abs]` and 64-bit moffs, non-PIE code indexes global arrays and jump tables as `[reg*s + abs]` and
/// `[reg + abs]`.
fn mask_absolute(
    instruction: &Instruction,
    offsets: &ConstantOffsets,
    image: &MaskContext,
    masked: &mut impl FnMut(usize, usize),
) {
    let relative_memory = matches!(instruction.memory_base(), Register::RIP | Register::EIP);
    // fs:/gs: displacements are thread-local or OS-structure offsets, not image addresses.
    let segment_relative = matches!(instruction.segment_prefix(), Register::FS | Register::GS);
    if offsets.has_displacement()
        && offsets.displacement_size() >= 4
        && !relative_memory
        && !segment_relative
        && image.contains(instruction.memory_displacement64())
    {
        masked(offsets.displacement_offset(), offsets.displacement_size());
    }
    if offsets.has_immediate() && offsets.immediate_size() >= 4 && !is_relative_branch(instruction) {
        let value = (0..instruction.op_count()).find_map(|op| instruction.try_immediate(op).ok());
        if value.is_some_and(|value| image.contains(value)) {
            masked(offsets.immediate_offset(), offsets.immediate_size());
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

/// Every named function symbol with a nonzero size, aliases included: the functions a symbol table delimits.
pub fn named_functions(binary: &Binary) -> impl Iterator<Item = &Symbol> {
    binary
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Function && symbol.size > 0 && !symbol.name.is_empty())
}

/// One of [`named_functions`] per address, the spelling [`alias_rank`] prefers. Several names at one address are
/// aliases of one function, not different functions.
pub fn canonical_functions(binary: &Binary) -> BTreeMap<u64, &Symbol> {
    let mut by_address: BTreeMap<u64, &Symbol> = BTreeMap::new();
    for symbol in named_functions(binary) {
        let best = by_address.entry(symbol.address).or_insert(symbol);
        if alias_rank(&symbol.name) < alias_rank(&best.name) {
            *best = symbol;
        }
    }
    by_address
}

/// The masked content hash of the function whose bytes start at `address`, or `None` for an unsupported
/// architecture or input with no decodable instructions. `target` supplies the architecture, the instruction
/// byte order (used by the fixed-width paths), and, for 32-bit ARM, whether `address` holds Thumb code.
///
/// This is hash scheme 1 ([`LEGACY_SCHEME`]), which databases saved before scheme 2 use, and the exact hash a
/// scheme-2 database falls back to for functions whose masked hash is ambiguous. New databases, the bundled ones
/// included, use [`function_hash_in`].
pub fn function_hash(target: &Target, bytes: &[u8], address: u64) -> Option<FunctionHash> {
    hash(target, bytes, address, None)
}

/// The scheme 2 ([`CURRENT_SCHEME`]) hash: [`function_hash`] plus masking of layout-dependent constants. On x86 and
/// x86-64, displacements and immediates whose value lies inside `image` (absolute addresses of the image's own
/// code and data, as non-PIE code embeds them) are masked. On AArch64, the low 12 bits that complete an ADRP page
/// address are masked (this needs no context). Thumb also masks B.W, B<c>.W and CBZ/CBNZ offsets, and MIPS the
/// branch-likely offsets while keeping REGIMM trap immediates, relative fields scheme 1 handled wrongly but cannot
/// change. Absolute addresses on 32-bit ARM, MIPS and PowerPC (ARM literal pools, MIPS `lui`/`addiu` pairs) are
/// not masked yet.
pub fn function_hash_in(target: &Target, image: &MaskContext, bytes: &[u8], address: u64) -> Option<FunctionHash> {
    hash(target, bytes, address, Some(image))
}

/// The bytes of the function at `address` as scheme 2 ([`function_hash_in`]) sees them, with `None` for every
/// byte its masking changed: the position-dependent fields a byte pattern for this body must leave as wildcards
/// to match a copy linked elsewhere. Bytes after the last decoded instruction are kept as they are. A field whose
/// value happens to equal its masked form here (a zero displacement) reads as fixed, so a pattern built from one
/// copy can be narrower than the hash. `None` for an unsupported architecture, a big-endian target (whose masked
/// words are hashed in another byte order than they are stored), or a body that fails the confidence gate.
pub fn masked_body_in(target: &Target, image: &MaskContext, bytes: &[u8], address: u64) -> Option<Vec<Option<u8>>> {
    if target.big_endian {
        return None;
    }
    let print = fingerprint(target, bytes, address, Some(image))?;
    if !print.measure.discriminating() || print.stream.len() > bytes.len() {
        return None;
    }
    let decoded = print.stream.len();
    let mut body: Vec<Option<u8>> =
        bytes.iter().zip(&print.stream).map(|(&raw, &masked)| (raw == masked).then_some(raw)).collect();
    body.extend(bytes[decoded..].iter().map(|&raw| Some(raw)));
    Some(body)
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
    fingerprint_scheme(scheme, target, image, bytes, address)?.finish()
}

/// `image` selects the scheme: `None` is scheme 1, `Some` is scheme 2 with that image's address ranges.
fn hash(target: &Target, bytes: &[u8], address: u64, image: Option<&MaskContext>) -> Option<FunctionHash> {
    fingerprint(target, bytes, address, image)?.finish()
}

/// The ungated fingerprint [`hash`] gates, or `None` for an unsupported architecture.
fn fingerprint(target: &Target, bytes: &[u8], address: u64, image: Option<&MaskContext>) -> Option<Fingerprint> {
    let big_endian = target.big_endian;
    Some(match target.arch {
        Arch::X86 => x86_fingerprint(32, bytes, address, image),
        Arch::X86_64 => x86_fingerprint(64, bytes, address, image),
        Arch::Aarch64 if image.is_some() => {
            let mut pages = AdrpPages::default();
            fixed_word_fingerprint(bytes, address, false, |word| pages.mask(word), aarch64_branch_target)
        }
        Arch::Aarch64 => fixed_word_fingerprint(bytes, address, false, mask_aarch64, aarch64_branch_target),
        Arch::Arm if target.is_thumb(address) => thumb_fingerprint(bytes, big_endian, image.is_some()),
        Arch::Arm => fixed_word_fingerprint(bytes, address, big_endian, mask_arm_a32, no_branch),
        Arch::Mips | Arch::Mips64 => {
            fixed_word_fingerprint(bytes, address, big_endian, |word| mask_mips(word, image.is_some()), no_branch)
        }
        Arch::PowerPc | Arch::PowerPc64 => fixed_word_fingerprint(bytes, address, big_endian, mask_ppc, no_branch),
        _ => return None,
    })
}

/// [`fingerprint`] under `scheme`, or `None` for an unknown scheme or unsupported architecture.
fn fingerprint_scheme(
    scheme: u32,
    target: &Target,
    image: &MaskContext,
    bytes: &[u8],
    address: u64,
) -> Option<Fingerprint> {
    match scheme {
        LEGACY_SCHEME => fingerprint(target, bytes, address, None),
        CURRENT_SCHEME => fingerprint(target, bytes, address, Some(image)),
        _ => None,
    }
}

/// A set of function signatures mapping a masked hash to a function name.
#[derive(Debug, Clone, Serialize)]
pub struct SignatureDb {
    /// The architecture the signatures were built for; matches are refused across architectures.
    #[serde(with = "arch_name")]
    arch: Arch,
    /// The hash scheme the entries were made with ([`LEGACY_SCHEME`] or [`CURRENT_SCHEME`]). Databases saved
    /// before schemes existed have no field and are scheme 1.
    #[serde(default = "legacy_scheme")]
    scheme: u32,
    /// Masked hash (lowercase hex) to function name. Hashes that mapped to more than one name are dropped, so a
    /// match is never ambiguous.
    entries: BTreeMap<String, String>,
    /// Exact (scheme 1) hash to name, kept only for functions whose masked hash was ambiguous. Two functions that
    /// differ only in which global they touch (`gmtime`/`localtime`) mask to one hash, but their exact bytes still
    /// tell them apart within the same layout. Consulted only when the masked hash has no entry.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    exact: BTreeMap<String, String>,
    /// Masked hashes seen with more than one name, remembered so that adding one of the names again (from another
    /// binary or database) cannot make the hash answer.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    ambiguous: BTreeSet<String>,
    /// Exact hashes seen with more than one name.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    ambiguous_exact: BTreeSet<String>,
    /// Callee-keyed hash (the masked body plus the names of the functions it branches to, see
    /// [`identify_program`]) to name, kept only for functions whose masked hash is ambiguous. Consulted only for a
    /// body whose masked hash is ambiguous here and that neither the exact hash nor any entry answers: it tells
    /// apart bodies that differ only in what they call.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    calls: BTreeMap<String, String>,
    /// Callee-keyed hashes seen with more than one name.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    ambiguous_calls: BTreeSet<String>,
    /// Optional versioned native-pattern namespace. Omitted for hash-only databases, preserving their
    /// original JSON bytes. Stores bounded canonical PAT text chunks and withheld record indices;
    /// loading reparses every constraint rather than trusting an unchecked serialized AST.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pat: Option<PatternDb>,
    /// Real Ghidra FID records are a separate namespace, never SHA-256 scheme-1/2 keys. Matching
    /// requires an explicit trusted semantic adapter; v1 rejects mixed native/PAT/FID databases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fid: Option<fid::FidNamespace>,
    /// The exact hashes behind each entry, known for databases built in this process: when a later binary makes the
    /// masked hash ambiguous, the earlier function still gets its exact fallback. Not saved, as it would double
    /// the file for what only building needs; a loaded entry that becomes ambiguous simply stops answering.
    #[serde(skip)]
    entry_exact: BTreeMap<String, BTreeSet<String>>,
    /// The callee keys behind each entry, kept the same way as `entry_exact` for when the masked hash becomes
    /// ambiguous.
    #[serde(skip)]
    entry_calls: BTreeMap<String, Vec<String>>,
}

// Deserialize only behind the bounded JSON/gzip admission paths. A public Deserialize implementation
// would let callers bypass preflight before serde allocates escaped strings and collection nodes.
#[derive(Deserialize)]
struct JsonDb {
    #[serde(with = "arch_name")]
    arch: Arch,
    #[serde(default = "legacy_scheme")]
    scheme: u32,
    entries: BTreeMap<String, String>,
    #[serde(default)]
    exact: BTreeMap<String, String>,
    #[serde(default)]
    ambiguous: BTreeSet<String>,
    #[serde(default)]
    ambiguous_exact: BTreeSet<String>,
    #[serde(default)]
    calls: BTreeMap<String, String>,
    #[serde(default)]
    ambiguous_calls: BTreeSet<String>,
    #[serde(default, deserialize_with = "pat::deserialize_namespace")]
    pat: Option<PatternDb>,
    #[serde(default, deserialize_with = "fid::deserialize_namespace")]
    fid: Option<fid::FidNamespace>,
}

/// Maximum direct signature-database JSON input, checked before parsing or allocating decoded data.
pub const MAX_SIGNATURE_DB_BYTES: usize = 64 * 1024 * 1024;

fn legacy_scheme() -> u32 {
    LEGACY_SCHEME
}

/// An [`Arch`] saved as its name (`"x86_64"`), the format databases have always used.
mod arch_name {
    use rampage_arch::Arch;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(arch: &Arch, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(arch)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Arch, D::Error> {
        String::deserialize(deserializer)?.parse().map_err(serde::de::Error::custom)
    }
}

impl SignatureDb {
    /// Imports user-supplied PAT text under a separate exact-pattern namespace, not fabricated hashes.
    /// The caller supplies architecture (PAT has no architecture header). Parsing is atomic and bounded
    /// to 16 MiB, 100,000 physical lines and 4096 fields/bytes per field. See [`PatternDb`] for the v1
    /// subset and explicit unsupported constraints. JSON/gzip persist every matching constraint.
    /// File admission and preserving analyst names remain the caller's responsibilities.
    pub fn from_pat(arch: Arch, bytes: &[u8]) -> Result<Self, PatError> {
        let patterns = PatternDb::parse(arch, bytes)?;
        let mut db = Self::empty(arch, CURRENT_SCHEME);
        db.pat = Some(patterns);
        Ok(db)
    }

    /// Number of PAT module-constraint records, including suppressed/ambiguous/unknown records.
    /// This is not a count of identified functions or public names.
    pub fn pat_records(&self) -> usize {
        self.pat.as_ref().map_or(0, |pat| pat.records().len())
    }

    /// The PAT namespace, when the database has one.
    pub fn patterns(&self) -> Option<&PatternDb> {
        self.pat.as_ref()
    }

    /// Replaces the PAT namespace (`None` removes it), leaving every hash entry as it is. The patterns must be for
    /// this database's architecture, and a PAT namespace needs the current hash scheme.
    pub fn set_patterns(&mut self, patterns: Option<PatternDb>) -> Result<(), CombineError> {
        if let Some(patterns) = &patterns {
            if patterns.arch() != self.arch {
                return Err(CombineError::ArchitectureMismatch);
            }
            if self.scheme != CURRENT_SCHEME {
                return Err(CombineError::SchemeMismatch);
            }
        }
        self.pat = patterns;
        Ok(())
    }

    fn merged_patterns(&self, other: &Self) -> Result<Option<PatternDb>, PatError> {
        match (&self.pat, &other.pat) {
            (Some(left), Some(right)) => {
                let mut patterns = left.clone();
                patterns.merge(right)?;
                Ok(Some(patterns))
            }
            (Some(patterns), None) | (None, Some(patterns)) => Ok(Some(patterns.clone())),
            (None, None) => Ok(None),
        }
    }

    fn empty(arch: Arch, scheme: u32) -> SignatureDb {
        SignatureDb {
            arch,
            scheme,
            entries: BTreeMap::new(),
            exact: BTreeMap::new(),
            ambiguous: BTreeSet::new(),
            ambiguous_exact: BTreeSet::new(),
            calls: BTreeMap::new(),
            ambiguous_calls: BTreeSet::new(),
            pat: None,
            fid: None,
            entry_exact: BTreeMap::new(),
            entry_calls: BTreeMap::new(),
        }
    }

    /// Records the function `name` with masked hash `hash` and, when known, exact hash `exact` and callee key
    /// `callees`. A masked hash seen with a second name is ambiguous for good, and every function behind it falls
    /// back to its exact hash and callee key.
    fn add(&mut self, hash: FunctionHash, exact: Option<FunctionHash>, callees: Option<FunctionHash>, name: &str) {
        let hash = hex(&hash);
        let exact = exact.map(|exact| hex(&exact));
        let callees = callees.map(|key| hex(&key));
        if !self.ambiguous.contains(&hash) {
            match self.entries.get(&hash) {
                Some(existing) if existing == name => {
                    self.entry_exact.entry(hash.clone()).or_default().extend(exact);
                    self.entry_calls.entry(hash).or_default().extend(callees);
                    return;
                }
                Some(_) => self.make_ambiguous(hash),
                None => {
                    if let Some(exact) = exact {
                        self.entry_exact.entry(hash.clone()).or_default().insert(exact);
                    }
                    self.entry_calls.entry(hash.clone()).or_default().extend(callees);
                    self.entries.insert(hash, name.to_owned());
                    return;
                }
            }
        }
        if let Some(exact) = exact {
            self.add_exact(exact, name.to_owned());
        }
        if let Some(key) = callees {
            add_unambiguous(&mut self.calls, &mut self.ambiguous_calls, key, name.to_owned());
        }
    }

    /// Marks a masked hash ambiguous, moving its entry's function (if any) to the exact and callee fallbacks.
    fn make_ambiguous(&mut self, hash: String) {
        let exact = self.entry_exact.remove(&hash);
        let callees = self.entry_calls.remove(&hash).unwrap_or_default();
        if let Some(name) = self.entries.remove(&hash) {
            for exact in exact.into_iter().flatten() {
                self.add_exact(exact, name.clone());
            }
            for key in callees {
                add_unambiguous(&mut self.calls, &mut self.ambiguous_calls, key, name.clone());
            }
        }
        self.ambiguous.insert(hash);
    }

    fn add_exact(&mut self, exact: String, name: String) {
        add_unambiguous(&mut self.exact, &mut self.ambiguous_exact, exact, name);
    }

    /// Builds [`CURRENT_SCHEME`] signatures from every named function in `binary` whose bytes are available, masking
    /// with the binary's own [`MaskContext`]. Functions whose bodies are byte-identical after masking but have
    /// different names are treated as ambiguous and left unmatchable.
    pub fn from_binary(binary: &Binary) -> SignatureDb {
        SignatureDb::from_binary_with_scheme(binary, CURRENT_SCHEME)
    }

    /// Builds signatures from `binary` under a specific hash `scheme`, e.g. [`LEGACY_SCHEME`] to extend or compare
    /// against an older database. An unknown scheme yields an empty database.
    pub fn from_binary_with_scheme(binary: &Binary, scheme: u32) -> SignatureDb {
        let mut db = SignatureDb::empty(binary.arch, scheme);
        db.add_binary(binary, &BTreeMap::new());
        db
    }

    /// [`SignatureDb::from_binary`], also hashing each function over the extent function discovery found for it
    /// in this reference (`extents` maps a start to its exclusive end, as `DiscoveredFunction::end` gives it).
    /// Identification hashes what discovery finds in the target, and discovery can stop short of a function's
    /// symbol size (at a jump table it cannot follow), so a database built from symbol sizes alone could never
    /// match that function. The reference's extent matches a stripped target's only when discovery stops at the
    /// same place in both, which it does for the same code but need not where symbols or layout steer it.
    pub fn from_binary_with_extents(binary: &Binary, extents: &BTreeMap<u64, u64>) -> SignatureDb {
        let mut db = SignatureDb::empty(binary.arch, CURRENT_SCHEME);
        db.add_binary(binary, extents);
        db
    }

    /// Builds function answers from `binary` while qualifying calls with an independent source name map.
    /// This lets a producer-definition view select existing function names without losing the original
    /// source's callee-qualified negative evidence. The map is borrowed only during construction; callers
    /// supply its source provenance. Ordinary constructors keep using `binary`'s canonical callee names.
    pub fn from_binary_with_extents_and_callees(
        binary: &Binary,
        extents: &BTreeMap<u64, u64>,
        source_callees: &BTreeMap<u64, String>,
    ) -> SignatureDb {
        let mut db = SignatureDb::empty(binary.arch, CURRENT_SCHEME);
        db.add_binary_with_callees(binary, extents, Some(source_callees));
        db
    }

    fn add_binary(&mut self, binary: &Binary, extents: &BTreeMap<u64, u64>) {
        self.add_binary_with_callees(binary, extents, None);
    }

    fn add_binary_with_callees(
        &mut self,
        binary: &Binary,
        extents: &BTreeMap<u64, u64>,
        source_callees: Option<&BTreeMap<u64, String>>,
    ) {
        let target = binary.target();
        let image = MaskContext::from_binary(binary);
        // One spelling per address: aliases hashed under each name would make the hash ambiguous.
        let functions = canonical_functions(binary);
        let name = |address: u64| match source_callees {
            Some(names) => names.get(&address).map(String::as_str),
            None => functions.get(&address).map(|symbol| symbol.name.as_str()),
        };
        for symbol in functions.values() {
            let end = symbol.address.saturating_add(symbol.size);
            let discovered = extents.get(&symbol.address).copied().filter(|&found| found != end);
            for end in std::iter::once(end).chain(discovered) {
                let Some(length) = end.checked_sub(symbol.address).filter(|&length| length > 0) else { continue };
                let Some(bytes) = binary.read(symbol.address, length) else { continue };
                let Some(print) = fingerprint_scheme(self.scheme, &target, &image, bytes, symbol.address) else {
                    continue;
                };
                let callees = print.callee_key(symbol.address..end, name);
                if let Some(hash) = print.finish() {
                    // Under the legacy scheme the masked hash already is the exact one.
                    let exact =
                        (self.scheme != LEGACY_SCHEME).then(|| function_hash(&target, bytes, symbol.address)).flatten();
                    self.add(hash, exact, callees, &symbol.name);
                }
            }
        }
    }

    /// Adds every named function from `binary` to this database, hashed under this database's scheme, so one
    /// database can span several libraries. Names collide across binaries exactly as within one: a masked hash
    /// with two names stops answering and the functions behind it fall back to their exact hashes. A binary for
    /// another architecture is ignored.
    ///
    /// # Panics
    /// A FID namespace requires the explicit trusted-host API, not native byte-hash construction.
    pub fn extend_from_binary(&mut self, binary: &Binary) {
        self.extend_from_binary_with_extents(binary, &BTreeMap::new());
    }

    /// Checked native extension without explicit discovery extents.
    pub fn try_extend_from_binary(&mut self, binary: &Binary) -> Result<(), fid::FidError> {
        self.try_extend_from_binary_with_extents(binary, &BTreeMap::new())
    }

    /// [`SignatureDb::extend_from_binary`] with discovered extents, as [`SignatureDb::from_binary_with_extents`].
    ///
    /// # Panics
    /// A FID namespace is not a native training database. Use the checked variant for external inputs.
    pub fn extend_from_binary_with_extents(&mut self, binary: &Binary, extents: &BTreeMap<u64, u64>) {
        self.try_extend_from_binary_with_extents(binary, extents)
            .expect("FID namespaces do not support native byte-hash construction");
    }

    /// Checked native construction: incompatible semantic namespaces reject before mutation.
    pub fn try_extend_from_binary_with_extents(
        &mut self,
        binary: &Binary,
        extents: &BTreeMap<u64, u64>,
    ) -> Result<(), fid::FidError> {
        self.ensure_byte_matching_supported()?;
        if binary.arch == self.arch {
            self.add_binary(binary, extents);
        }
        Ok(())
    }

    /// Overlays `other` onto this database, letting `other`'s names win on any shared hash (so a user database
    /// takes precedence over a bundled one); a hash `other` knows to be ambiguous stops answering here too.
    /// Databases for different architectures or hash schemes do not mix (their hashes are not comparable), so a
    /// mismatched `other` is ignored; [`SignatureDb::can_merge`] tells.
    /// PAT records use collision-safe union instead of name precedence: constraints/negative evidence
    /// are never discarded. Exceeding PAT composition limits leaves the entire database unchanged.
    ///
    /// # Panics
    /// Unsupported FID composition rejects explicitly. Admission-sensitive callers must use
    /// [`Self::try_merge`] or collision-safe [`Self::combine`]. Native-only mismatch no-ops are unchanged.
    pub fn merge(&mut self, other: &SignatureDb) {
        let result = self.try_merge(other);
        if self.requires_fid_adapter() || other.requires_fid_adapter() {
            result.expect("unsupported FID composition; use SignatureDb::try_merge for external databases");
        }
    }

    /// Checked user-priority overlay, preserving every namespace constraint and refusing incompatible
    /// semantic domains, architectures, schemes or composition budgets before mutation.
    pub fn try_merge(&mut self, other: &SignatureDb) -> Result<(), CombineError> {
        if self.arch != other.arch {
            return Err(CombineError::ArchitectureMismatch);
        }
        if self.scheme != other.scheme {
            return Err(CombineError::SchemeMismatch);
        }
        let patterns = self.merged_patterns(other).map_err(|_| CombineError::PatLimitExceeded)?;
        let fid = self.merged_fid(other).map_err(|_| CombineError::UnsupportedFidComposition)?;
        for hash in &other.ambiguous {
            self.entries.remove(hash);
            self.entry_exact.remove(hash);
            self.entry_calls.remove(hash);
            self.ambiguous.insert(hash.clone());
        }
        for (hash, name) in &other.entries {
            self.ambiguous.remove(hash);
            match other.entry_exact.get(hash) {
                Some(exact) => self.entry_exact.insert(hash.clone(), exact.clone()),
                None => self.entry_exact.remove(hash),
            };
            match other.entry_calls.get(hash) {
                Some(keys) => self.entry_calls.insert(hash.clone(), keys.clone()),
                None => self.entry_calls.remove(hash),
            };
            self.entries.insert(hash.clone(), name.clone());
        }
        for hash in &other.ambiguous_exact {
            self.exact.remove(hash);
            self.ambiguous_exact.insert(hash.clone());
        }
        for (hash, name) in &other.exact {
            self.ambiguous_exact.remove(hash);
            self.exact.insert(hash.clone(), name.clone());
        }
        for key in &other.ambiguous_calls {
            self.calls.remove(key);
            self.ambiguous_calls.insert(key.clone());
        }
        for (key, name) in &other.calls {
            self.ambiguous_calls.remove(key);
            self.calls.insert(key.clone(), name.clone());
        }
        self.pat = patterns;
        self.fid = fid;
        Ok(())
    }

    /// Whether [`SignatureDb::merge`] would take `other`'s entries: same architecture/hash scheme and
    /// combined PAT inputs within their resource limits.
    pub fn can_merge(&self, other: &SignatureDb) -> bool {
        self.arch == other.arch
            && self.scheme == other.scheme
            && self.merged_fid(other).is_ok()
            && match (&self.pat, &other.pat) {
                (Some(left), Some(right)) => left.can_merge(right),
                _ => true,
            }
    }

    /// Selects the names to export after building against all reference functions, including negative
    /// counterexamples. Removes every other masked, exact and callee-key answer and its ephemeral entry
    /// evidence. All ambiguity tombstones remain: removing a conflicting name never restores an answer.
    /// PAT constraints are retained, with other answers persistently suppressed as negative evidence.
    /// In a PAT-mixed database, removed native answers and their latent fallback keys also become
    /// tombstones, so a PAT answer cannot revive a native contradiction after filtering or reload.
    /// Native-only retention is unchanged.
    pub fn retain_names(&mut self, allowed: &BTreeSet<String>) {
        if self.pat.is_some() {
            for (hash, name) in &self.entries {
                if !allowed.contains(name) {
                    self.ambiguous.insert(hash.clone());
                    self.ambiguous_exact.extend(self.entry_exact.get(hash).into_iter().flatten().cloned());
                    self.ambiguous_calls.extend(self.entry_calls.get(hash).into_iter().flatten().cloned());
                }
            }
            self.ambiguous_exact
                .extend(self.exact.iter().filter(|(_, name)| !allowed.contains(*name)).map(|(key, _)| key.clone()));
            self.ambiguous_calls
                .extend(self.calls.iter().filter(|(_, name)| !allowed.contains(*name)).map(|(key, _)| key.clone()));
            self.exact.retain(|key, _| !self.ambiguous_exact.contains(key));
            self.calls.retain(|key, _| !self.ambiguous_calls.contains(key));
            for keys in self.entry_exact.values_mut() {
                keys.retain(|key| !self.ambiguous_exact.contains(key));
            }
            for keys in self.entry_calls.values_mut() {
                keys.retain(|key| !self.ambiguous_calls.contains(key));
            }
        }
        self.entries.retain(|_, name| allowed.contains(name));
        self.exact.retain(|_, name| allowed.contains(name));
        self.calls.retain(|_, name| allowed.contains(name));
        self.entry_exact.retain(|hash, _| self.entries.contains_key(hash));
        self.entry_calls.retain(|hash, _| self.entries.contains_key(hash));
        if let Some(patterns) = &mut self.pat {
            patterns.retain_names(allowed);
        }
        if let Some(fid) = &mut self.fid {
            fid.retain_names(allowed);
        }
    }

    /// The architecture this database's signatures were built for.
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// The hash scheme of this database's entries.
    pub fn scheme(&self) -> u32 {
        self.scheme
    }

    /// The name for the function whose bytes start at `address`, hashed without knowledge of the image's layout.
    /// `target` carries the architecture and instruction byte order (see [`function_hash`]).
    ///
    /// For a scheme 1 database this is the same as [`SignatureDb::identify_in`]. For a scheme 2 database it hashes
    /// with an empty [`MaskContext`], so absolute addresses stay in the hash and a function that embeds any will not
    /// match. When the target's image covers the same address ranges as the reference's, it finds a subset of what
    /// `identify_in` finds, under the same names; with other layouts a constant can be an image address in one and
    /// not the other, and the two lookups can disagree. Prefer `identify_in`.
    pub fn identify(&self, target: &Target, bytes: &[u8], address: u64) -> Option<&str> {
        self.identify_in(target, &MaskContext::default(), bytes, address)
    }

    /// The name for the function whose bytes start at `address` in the image described by `image` (see
    /// [`MaskContext::from_binary`]), hashed under this database's own scheme. The architecture must match.
    pub fn identify_in(&self, target: &Target, image: &MaskContext, bytes: &[u8], address: u64) -> Option<&str> {
        self.identify_with_callees(target, image, bytes, address, |_| None)
    }

    /// [`SignatureDb::identify_in`], falling back to the body together with the names of the functions it branches
    /// to outside itself (`bytes` is the whole body), as `callee` names them in the target. [`identify_program`]
    /// supplies the names it has found so far.
    pub fn identify_with_callees<'n>(
        &self,
        target: &Target,
        image: &MaskContext,
        bytes: &[u8],
        address: u64,
        callee: impl Fn(u64) -> Option<&'n str>,
    ) -> Option<&str> {
        match self.lookup(target, image, bytes, address, callee) {
            Lookup::Named(name) => Some(name),
            Lookup::AwaitsCallees | Lookup::Unknown => None,
        }
    }

    fn lookup<'n>(
        &self,
        target: &Target,
        image: &MaskContext,
        bytes: &[u8],
        address: u64,
        callee: impl Fn(u64) -> Option<&'n str>,
    ) -> Lookup<'_> {
        // The legacy Option-returning byte API cannot supply Ghidra semantics. Admission-sensitive
        // callers must use ensure_byte_matching_supported/identify_in_checked before this path.
        if self.requires_fid_adapter() {
            return Lookup::Unknown;
        }
        let native = self.lookup_native(target, image, bytes, address, callee);
        let Some(patterns) = &self.pat else { return native.into_lookup() };
        if self.scheme != CURRENT_SCHEME || self.arch != target.arch {
            return Lookup::Unknown;
        }
        match patterns.match_in(target, image, bytes, address) {
            PatternMatch::NoMatch => native.into_lookup(),
            PatternMatch::Unique { name: pattern_name, .. } => match native {
                NativeLookup::Named(name) if name != pattern_name => Lookup::Unknown,
                NativeLookup::Named(name) => Lookup::Named(name),
                NativeLookup::AwaitsCallees => Lookup::AwaitsCallees,
                NativeLookup::Ambiguous => Lookup::Unknown,
                NativeLookup::Unknown => Lookup::Named(pattern_name),
            },
            PatternMatch::Ambiguous { .. } | PatternMatch::RejectedByGate => Lookup::Unknown,
        }
    }

    fn lookup_native<'n>(
        &self,
        target: &Target,
        image: &MaskContext,
        bytes: &[u8],
        address: u64,
        callee: impl Fn(u64) -> Option<&'n str>,
    ) -> NativeLookup<'_> {
        if self.arch != target.arch {
            return NativeLookup::Unknown;
        }
        let Some(print) = fingerprint_scheme(self.scheme, target, image, bytes, address) else {
            return NativeLookup::Unknown;
        };
        let body = address..address.saturating_add(bytes.len() as u64);
        let key = (!self.calls.is_empty() || !self.ambiguous_calls.is_empty())
            .then(|| print.callee_key(body.clone(), callee))
            .flatten();
        let keyable = !self.calls.is_empty() && print.callee_key(body, |_| Some("")).is_some();
        let Some(hash) = print.finish().map(|hash| hex(&hash)) else { return NativeLookup::Unknown };
        if let Some(name) = self.entries.get(&hash) {
            return NativeLookup::Named(name);
        }
        let exact = (!self.exact.is_empty() || !self.ambiguous_exact.is_empty())
            .then(|| function_hash(target, bytes, address).map(|hash| hex(&hash)))
            .flatten();
        if let Some(name) = exact.as_ref().and_then(|exact| self.exact.get(exact)) {
            return NativeLookup::Named(name);
        }
        let ambiguous = self.ambiguous.contains(&hash)
            || exact.as_ref().is_some_and(|exact| self.ambiguous_exact.contains(exact))
            || key.as_ref().is_some_and(|key| self.ambiguous_calls.contains(&hex(key)));
        // A callee key is evidence only where the body alone is a known collision.
        if !self.ambiguous.contains(&hash) {
            return if ambiguous { NativeLookup::Ambiguous } else { NativeLookup::Unknown };
        }
        match key {
            Some(key) => self.calls.get(&hex(&key)).map_or(NativeLookup::Ambiguous, |name| NativeLookup::Named(name)),
            None if keyable => NativeLookup::AwaitsCallees,
            None => NativeLookup::Ambiguous,
        }
    }

    /// Number of masked/exact hash answers plus PAT module-constraint records (not unique functions).
    /// PAT records include suppressed/ambiguous/unknown evidence; [`Self::pat_records`] reports that
    /// portion separately. Callee keys are counted by [`SignatureDb::callee_keys`]. Native-only counts
    /// and generated bundled indices are unchanged.
    pub fn len(&self) -> usize {
        self.entries.len() + self.exact.len() + self.pat_records() + self.fid_records()
    }

    /// The number of unambiguous callee keys.
    pub fn callee_keys(&self) -> usize {
        self.calls.len()
    }

    /// Whether the database holds nothing to match: no function signatures and no callee keys.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
            && self.exact.is_empty()
            && self.calls.is_empty()
            && self.pat_records() == 0
            && self.fid_records() == 0
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("string maps and plain fields always serialize")
    }

    /// Parses a saved database. A hash scheme this version does not know is an error: none of its hashes could
    /// ever match. Direct JSON is capped at 64 MiB and allocation-driving tokens are preflighted
    /// before serde runs. Load through this method or [`Self::from_gzip`], not a generic deserializer.
    pub fn from_json(text: &str) -> Result<SignatureDb, serde_json::Error> {
        compressed::preflight_direct_json(text.as_bytes()).map_err(serde::de::Error::custom)?;
        let wire: JsonDb = serde_json::from_str(text)?;
        let mut db = Self::empty(wire.arch, wire.scheme);
        db.entries = wire.entries;
        db.exact = wire.exact;
        db.calls = wire.calls;
        db.ambiguous = wire.ambiguous;
        db.ambiguous_exact = wire.ambiguous_exact;
        db.ambiguous_calls = wire.ambiguous_calls;
        db.pat = wire.pat;
        db.fid = wire.fid;
        db.validate_fid_namespace().map_err(serde::de::Error::custom)?;
        if ![LEGACY_SCHEME, CURRENT_SCHEME].contains(&db.scheme) {
            let message = format!("unknown signature hash scheme {} (this version knows 1 and 2)", db.scheme);
            return Err(serde::de::Error::custom(message));
        }
        if let Some(patterns) = &db.pat
            && (patterns.arch() != db.arch || db.scheme != CURRENT_SCHEME)
        {
            return Err(serde::de::Error::custom("PAT namespace architecture/scheme mismatch"));
        }
        Ok(db)
    }
}

/// Records `key` as `name` in `map`, unless `key` is already known for another name: then it stops answering for
/// good, remembered in `ambiguous`.
fn add_unambiguous(map: &mut BTreeMap<String, String>, ambiguous: &mut BTreeSet<String>, key: String, name: String) {
    if ambiguous.contains(&key) {
        return;
    }
    match map.get(&key) {
        Some(existing) if *existing != name => {
            map.remove(&key);
            ambiguous.insert(key);
        }
        Some(_) => {}
        None => {
            map.insert(key, name);
        }
    }
}

/// Names the discovered `functions` of one binary (each its start and its body bytes) against `databases`, the
/// first database to name a function winning, so a user database can be layered over a bundled one. Every round
/// tries each database in order with all its lookups, and a database that could still name a function once its
/// callees are named holds it back from the databases after it, so a lower-priority database never names a
/// function a higher one can.
///
/// A function the body alone cannot name because its masked body collides with another function's (bodies the
/// confidence gate rejects are never named) is then tried with the names of the functions it branches to, from the
/// names found so far
/// ([`SignatureDb::identify_with_callees`]). This repeats while it finds new names, so a wrapper is named once its
/// callee is, up to [`MAX_CALLEE_ROUNDS`] rounds. A callee-keyed name rests on its callees' names being right.
///
/// Names come out as [`canonical_name`] spells them.
pub fn identify_program<'d>(
    databases: &[&'d SignatureDb],
    target: &Target,
    image: &MaskContext,
    functions: &[(u64, &[u8])],
) -> BTreeMap<u64, Cow<'d, str>> {
    identify_program_sources(databases, target, image, functions)
        .into_iter()
        .map(|(address, (_, name))| (address, name))
        .collect()
}

/// [`identify_program`], with the index in `databases` of the database that named each function.
pub fn identify_program_sources<'d>(
    databases: &[&'d SignatureDb],
    target: &Target,
    image: &MaskContext,
    functions: &[(u64, &[u8])],
) -> BTreeMap<u64, (usize, Cow<'d, str>)> {
    let mut names: BTreeMap<u64, (usize, &'d str)> = BTreeMap::new();
    let mut pending = functions.to_vec();
    // A database below one still waiting on a function's callees does not name it, until no round finds more.
    let mut defer = true;
    for _ in 0..MAX_CALLEE_ROUNDS + 2 {
        let found: Vec<(u64, (usize, &str))> = pending
            .iter()
            .filter_map(|&(address, bytes)| {
                let callee = |at: u64| names.get(&at).map(|&(_, name)| name);
                for (index, database) in databases.iter().enumerate() {
                    match database.lookup(target, image, bytes, address, callee) {
                        Lookup::Named(name) => return Some((address, (index, name))),
                        Lookup::AwaitsCallees if defer => return None,
                        Lookup::AwaitsCallees | Lookup::Unknown => {}
                    }
                }
                None
            })
            .collect();
        if found.is_empty() {
            if !defer {
                break;
            }
            defer = false;
            continue;
        }
        names.extend(found);
        pending.retain(|(address, _)| !names.contains_key(address));
    }
    // Callee keys were built over the databases' own spellings, so names are canonicalized only on the way out.
    names.into_iter().map(|(address, (index, name))| (address, (index, canonical_name(name)))).collect()
}

/// The kinds of Zig's generated declaration names, which end in a build-local counter (`ldexp__func_40`,
/// `qsort__struct_61.wrap`).
const ZIG_COUNTED: [&str; 6] = ["func", "anon", "struct", "enum", "union", "opaque"];

/// `name` without the counters Zig numbers its generated declarations with: `math.ldexp.ldexp__func_40` is
/// `math.ldexp.ldexp__func`, `c.stdlib.qsort__struct_61.wrap` is `c.stdlib.qsort__struct.wrap`. The counter
/// depends on everything else the compiler instantiated in that build (zig 0.17.0 and 0.17.1 number the same
/// `ldexp` instance 37 and 40), so it is no part of what a function is. Instances of one generic declaration then
/// share a name, as C++ templates do without their arguments. Identification reports names this way and the
/// evaluations score them against truth spelled the same way. Every other name is returned unchanged.
pub fn canonical_name(name: &str) -> Cow<'_, str> {
    let mut out = String::new();
    let mut copied = 0;
    let mut search = 0;
    while let Some(found) = name[search..].find("__") {
        let start = search + found;
        let rest = &name[start + 2..];
        let counted = ZIG_COUNTED.iter().find_map(|kind| {
            let digits = rest.strip_prefix(kind)?.strip_prefix('_')?;
            let count = digits.bytes().take_while(u8::is_ascii_digit).count();
            let after = digits.as_bytes().get(count);
            (count > 0 && !after.is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_'))
                .then_some((kind.len(), count))
        });
        match counted {
            Some((kind, count)) => {
                // Keep `__kind`, drop `_count`.
                let kept = start + 2 + kind;
                out.push_str(&name[copied..kept]);
                copied = kept + 1 + count;
                search = copied;
            }
            None => search = start + 1,
        }
    }
    if copied == 0 {
        return Cow::Borrowed(name);
    }
    out.push_str(&name[copied..]);
    Cow::Owned(out)
}

/// What one database says about one body.
enum Lookup<'a> {
    Named(&'a str),
    /// The body collides with others here, and its callee key could name it once all its callees are named.
    AwaitsCallees,
    Unknown,
}

/// Internal native evidence keeps absence separate from a known collision. The production native
/// priority order is unchanged; PAT may fill an absent key, never a rejected native collision.
enum NativeLookup<'a> {
    Named(&'a str),
    Ambiguous,
    AwaitsCallees,
    Unknown,
}

impl<'a> NativeLookup<'a> {
    fn into_lookup(self) -> Lookup<'a> {
        match self {
            Self::Named(name) => Lookup::Named(name),
            Self::AwaitsCallees => Lookup::AwaitsCallees,
            Self::Ambiguous | Self::Unknown => Lookup::Unknown,
        }
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
    fn the_masked_body_wildcards_exactly_the_bytes_the_hash_masks() {
        let mut bytes = sample();
        bytes[1..5].copy_from_slice(&0x1111_2222u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&0x3333_4444u32.to_le_bytes());
        let image = MaskContext::default();
        let masked = masked_body_in(&target(Arch::X86_64, false), &image, &bytes, 0x1000).unwrap();
        let wildcards: Vec<usize> = (0..masked.len()).filter(|&index| masked[index].is_none()).collect();
        assert_eq!(wildcards, [1, 2, 3, 4, 8, 9, 10, 11], "the call target and the RIP displacement");
        assert_eq!(masked[12..], bytes[12..].iter().map(|&byte| Some(byte)).collect::<Vec<_>>());
        assert!(masked_body_in(&target(Arch::X86_64, false), &image, &[0xc3], 0x1000).is_none(), "below the gate");
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
    fn canonical_names_drop_zig_declaration_counters_only() {
        for (name, canonical) in [
            ("math.ldexp.ldexp__func_40", "math.ldexp.ldexp__func"),
            ("c.stdlib.qsort__struct_61.wrap", "c.stdlib.qsort__struct.wrap"),
            ("a__enum_3.getName__anon_12", "a__enum.getName__anon"),
            ("Thread__func_7.Instance.entryFn", "Thread__func.Instance.entryFn"),
        ] {
            assert_eq!(canonical_name(name), canonical, "{name}");
        }
        // Not a counter: other kinds, no digits, digits run into a word, or a plain C name.
        for name in ["memcpy", "__func_", "x__func_12ab", "x__funcs_1", "x__thing_4", "__libc_start_main", "f__func_1_"] {
            assert!(matches!(canonical_name(name), Cow::Borrowed(same) if same == name), "{name}");
        }
    }

    #[test]
    fn database_drops_ambiguous_hashes_and_round_trips() {
        let mut db = SignatureDb::empty(Arch::X86_64, LEGACY_SCHEME);
        let x64 = target(Arch::X86_64, false);
        let hash = function_hash(&x64, &sample(), 0x1000).unwrap();
        db.add(hash, None, None, "first");
        db.add(hash, None, None, "first");
        let mut other = [0u8; 32];
        other[0] = 1;
        db.add(other, None, None, "unique");
        // A second name for the same hash makes it ambiguous, and a later copy of either name cannot revive it.
        db.add(hash, None, None, "second");
        db.add(hash, None, None, "first");
        assert_eq!(db.identify(&x64, &sample(), 0x1000), None);
        assert_eq!(db.len(), 1);

        let mut restored = SignatureDb::from_json(&db.to_json()).unwrap();
        assert_eq!(restored.arch(), Arch::X86_64);
        assert!(db.to_json().starts_with(r#"{"arch":"x86_64","#), "{}", db.to_json());
        assert_eq!(restored.len(), 1);
        restored.add(hash, None, None, "second");
        assert_eq!(restored.identify(&x64, &sample(), 0x1000), None);
    }

    /// Two layouts of one masked body, as `gmtime`/`localtime` or one function in two different binaries.
    fn colliding_pair() -> (Vec<u8>, Vec<u8>) {
        (
            absolute_sample([0x40_a000, 0x40_b000, 0x40_c000, 0x40_d000]),
            absolute_sample([0x40_a100, 0x40_b100, 0x40_c100, 0x40_d100]),
        )
    }

    /// Adds `body` as `name` the way building from a binary does.
    fn add_function(db: &mut SignatureDb, body: &[u8], name: &str) {
        let x64 = target(Arch::X86_64, false);
        let masked = function_hash_in(&x64, &image(), body, 0x1000).unwrap();
        db.add(masked, function_hash(&x64, body, 0x1000), None, name);
    }

    /// The corpus reference keeping only the function symbols named in `names`.
    fn reference_with(names: &[&str]) -> Binary {
        let mut binary = Binary::open(fixture("eval-ref-x86_64.elf")).unwrap();
        binary.symbols.retain(|symbol| symbol.kind != SymbolKind::Function || names.contains(&symbol.name.as_str()));
        binary
    }

    /// `gmtime` and `localtime` differ only in their static result buffer, so they share a scheme-2 hash.
    #[test]
    fn extending_tracks_collisions_across_binaries() {
        let both = reference_with(&["gmtime", "localtime"]);
        let name_of = |db: &SignatureDb, function: &str| {
            let symbol = both.symbols.iter().find(|symbol| symbol.name == function).unwrap();
            let bytes = both.read(symbol.address, symbol.size).unwrap();
            db.identify_in(&both.target(), &MaskContext::from_binary(&both), bytes, symbol.address).map(str::to_owned)
        };
        let alone = SignatureDb::from_binary(&reference_with(&["gmtime"]));
        assert_eq!(name_of(&alone, "localtime").as_deref(), Some("gmtime"), "the pair no longer collides");

        // The other name arrives from a second binary: both fall back to their exact hashes.
        let mut db = SignatureDb::from_binary(&reference_with(&["gmtime"]));
        db.extend_from_binary(&reference_with(&["localtime"]));
        assert_eq!(name_of(&db, "gmtime").as_deref(), Some("gmtime"));
        assert_eq!(name_of(&db, "localtime").as_deref(), Some("localtime"));
        // A third binary naming one of them again does not revive the masked hash.
        db.extend_from_binary(&reference_with(&["gmtime"]));
        assert_eq!(name_of(&db, "localtime").as_deref(), Some("localtime"));

        // A binary ambiguous inside does not leave the earlier entry shadowing the exact fallback.
        let mut db = SignatureDb::from_binary(&reference_with(&["gmtime"]));
        db.extend_from_binary(&both);
        assert_eq!(name_of(&db, "localtime").as_deref(), Some("localtime"));
    }

    #[test]
    fn merging_an_ambiguity_drops_the_old_entry() {
        let x64 = target(Arch::X86_64, false);
        let (first, second) = colliding_pair();
        let mut db = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        add_function(&mut db, &first, "gmtime");
        let mut other = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        add_function(&mut other, &first, "gmtime");
        add_function(&mut other, &second, "localtime");
        // Merging the ambiguity in must stop the old masked entry from shadowing the exact fallback.
        db.merge(&other);
        assert_eq!(db.identify_in(&x64, &image(), &second, 0x1000), Some("localtime"));
        let relinked = absolute_sample([0x40_a300, 0x40_b300, 0x40_c300, 0x40_d300]);
        assert_eq!(db.identify_in(&x64, &image(), &relinked, 0x1000), None);
        // The same holds for a database loaded from JSON, which carries the ambiguity with it.
        let mut bundled = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        add_function(&mut bundled, &first, "gmtime");
        bundled.merge(&SignatureDb::from_json(&other.to_json()).unwrap());
        assert_eq!(bundled.identify_in(&x64, &image(), &relinked, 0x1000), None);
        assert_eq!(bundled.identify_in(&x64, &image(), &second, 0x1000), Some("localtime"));
    }

    /// Builds a database from a fixture and confirms at least one named function identifies back to its own name
    /// in the same binary, exercising the whole from_binary -> identify path for that architecture.
    fn assert_fixture_round_trips(name: &str) {
        let binary = Binary::open(fixture(name)).unwrap();
        let db = SignatureDb::from_binary(&binary);
        assert!(!db.is_empty(), "{name}: empty database");
        let target = binary.target();
        let hits = named_functions(&binary)
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

    /// movs r0, #1; `branch`; movs r1, #2; bx lr.
    fn thumb_body(branch: &[u16]) -> Vec<u8> {
        let halfwords: Vec<u16> = [&[0x2001], branch, &[0x2102, 0x4770]].concat();
        halfwords_to_bytes(&halfwords, false)
    }

    /// Whether scheme 2 hashes `base` and `relinked` (Thumb branches) alike while scheme 1, whose hashes are
    /// frozen, still tells them apart.
    fn thumb_relinks_under_scheme_2_only(base: &[u16], relinked: &[u16]) {
        let thumb = thumb_target(false);
        let current = |branch| function_hash_in(&thumb, &MaskContext::default(), &thumb_body(branch), 0);
        assert!(current(base).is_some());
        assert_eq!(current(base), current(relinked), "{base:x?} vs {relinked:x?}");
        let legacy = |branch| function_hash(&thumb, &thumb_body(branch), 0);
        assert_ne!(legacy(base), legacy(relinked), "{base:x?} vs {relinked:x?}");
    }

    #[test]
    fn thumb_scheme_2_masks_wide_unconditional_branches() {
        // B.W (T4): 11110 S imm10, 10 J1 1 J2 imm11.
        thumb_relinks_under_scheme_2_only(&[0xf000, 0xb800], &[0xf412, 0x99ab]);
    }

    #[test]
    fn thumb_scheme_2_masks_wide_conditional_branches_but_keeps_the_condition() {
        // B<c>.W (T3): 11110 S cond imm6, 10 J1 0 J2 imm11; beq here.
        thumb_relinks_under_scheme_2_only(&[0xf000, 0x8000], &[0xf43f, 0xafff]);
        let thumb = thumb_target(false);
        let hash = |branch| function_hash_in(&thumb, &MaskContext::default(), &thumb_body(branch), 0);
        assert_ne!(hash(&[0xf000, 0x8000]), hash(&[0xf040, 0x8000]), "beq.w and bne.w must differ");
    }

    #[test]
    fn thumb_scheme_2_masks_compare_and_branch_offsets() {
        // CBZ r0 (1011 o0i1 imm5 Rn) with offsets 0 and the maximum.
        thumb_relinks_under_scheme_2_only(&[0xb100], &[0xb3f8]);
        let thumb = thumb_target(false);
        let hash = |branch| function_hash_in(&thumb, &MaskContext::default(), &thumb_body(branch), 0);
        assert_ne!(hash(&[0xb100]), hash(&[0xb900]), "cbz and cbnz must differ");
        assert_ne!(hash(&[0xb100]), hash(&[0xb101]), "the tested register must count");
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
    fn mips_scheme_2_masks_regimm_branches_and_branch_likely_but_not_trap_immediates() {
        let mips = target(Arch::Mips, true);
        // addiu $v0, $v0, 0x20; `word`; lui $v0, 1; jr $ra.
        let body = |word: u32| words_to_bytes(&[0x2442_0020, word, 0x3c02_0001, 0x03e0_0008], true);
        let current = |word| function_hash_in(&mips, &MaskContext::default(), &body(word), 0);
        let legacy = |word| function_hash(&mips, &body(word), 0);
        // BLTZAL $v0 (REGIMM rt 0x10) and BEQL $v0, $zero (opcode 0x14): relative offsets.
        assert_eq!(current(0x0450_0005), current(0x0450_abcd));
        assert_eq!(current(0x5040_0005), current(0x5040_abcd));
        assert_ne!(legacy(0x5040_0005), legacy(0x5040_abcd), "scheme 1 hashes are frozen");
        // TGEI $v0, imm (REGIMM rt 0x08): a data immediate, which scheme 1 masked.
        assert_ne!(current(0x0448_0010), current(0x0448_0020));
        assert_eq!(legacy(0x0448_0010), legacy(0x0448_0020), "scheme 1 hashes are frozen");
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
    fn exact_hashes_disambiguate_functions_that_differ_only_in_their_globals() {
        // Like gmtime/localtime: identical code reaching different static buffers masks to one hash.
        let x64 = target(Arch::X86_64, false);
        let (gmtime, localtime) = colliding_pair();
        let masked = function_hash_in(&x64, &image(), &gmtime, 0x1000).unwrap();
        assert_eq!(Some(masked), function_hash_in(&x64, &image(), &localtime, 0x1000));
        let mut db = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        add_function(&mut db, &gmtime, "gmtime");
        add_function(&mut db, &localtime, "localtime");
        assert_eq!(db.identify_in(&x64, &image(), &gmtime, 0x1000), Some("gmtime"));
        assert_eq!(db.identify_in(&x64, &image(), &localtime, 0x1000), Some("localtime"));
        // A relinked copy matches neither exactly: no name rather than a guessed one.
        let relinked = absolute_sample([0x40_a200, 0x40_b200, 0x40_c200, 0x40_d200]);
        assert_eq!(db.identify_in(&x64, &image(), &relinked, 0x1000), None);
        let restored = SignatureDb::from_json(&db.to_json()).unwrap();
        assert_eq!(restored.identify_in(&x64, &image(), &localtime, 0x1000), Some("localtime"));
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
    fn adrp_tracking_survives_instructions_that_write_no_register() {
        let a64 = target(Arch::Aarch64, false);
        // adrp x8, page; b.hi +8; ldr w0, [x8, #lo12]; ret. B.cond's bits 4:0 are its condition (hi = 8).
        let body =
            |lo12: u32| words_to_bytes(&[0x9000_0008, 0x5400_0048, 0xb940_0100 | (lo12 / 4) << 10, 0xd65f_03c0], false);
        let image = MaskContext::default();
        assert_eq!(function_hash_in(&a64, &image, &body(0x10), 0), function_hash_in(&a64, &image, &body(0x24), 0));
        // str w0, [x8, #lo12] in place of the branch: a store reads its bits 4:0, so x8 still holds the page.
        let store =
            |lo12: u32| words_to_bytes(&[0x9000_0008, 0xb900_0100 | (lo12 / 4) << 10, 0xb940_0100, 0xd65f_03c0], false);
        assert_eq!(function_hash_in(&a64, &image, &store(0x10), 0), function_hash_in(&a64, &image, &store(0x24), 0));
    }

    #[test]
    fn adrp_tracking_forgets_registers_written_as_a_second_destination() {
        let a64 = target(Arch::Aarch64, false);
        let image = MaskContext::default();
        // adrp x1, page; ldp x0, x1, [sp]; add x2, x1, #imm; ret. The LDP overwrites x1 through Rt2.
        let pair = |imm: u32| words_to_bytes(&[0x9000_0001, 0xa940_07e0, 0x9100_0022 | imm << 10, 0xd65f_03c0], false);
        assert_ne!(function_hash_in(&a64, &image, &pair(0x10), 0), function_hash_in(&a64, &image, &pair(0x20), 0));
        // adrp x1, page; ldr x0, [x1], #8; add x2, x1, #imm; ret. The post-index writes x1 back.
        let post = |imm: u32| words_to_bytes(&[0x9000_0001, 0xf840_8420, 0x9100_0022 | imm << 10, 0xd65f_03c0], false);
        assert_ne!(function_hash_in(&a64, &image, &post(0x10), 0), function_hash_in(&a64, &image, &post(0x20), 0));
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
        let mut older = SignatureDb::empty(Arch::X86_64, LEGACY_SCHEME);
        older.add([7; 32], None, None, "older");
        assert!(!current.can_merge(&older));
        current.merge(&older);
        assert_eq!(current.len(), before);
        let mut newer = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        newer.add([7; 32], None, None, "newer");
        current.merge(&newer);
        assert_eq!(current.len(), before + 1);
        let unknown = SignatureDb::from_json(r#"{"arch":"x86_64","scheme":99,"entries":{}}"#).unwrap_err();
        assert!(unknown.to_string().contains("unknown signature hash scheme 99"), "{unknown}");
        assert!(SignatureDb::from_binary_with_scheme(&Binary::open(fixture("hello-x64.elf")).unwrap(), 99).is_empty());
    }

    #[test]
    fn scheme_2_identify_without_context_never_renames() {
        let x64 = target(Arch::X86_64, false);
        let body = absolute_sample([0x40_a2c8, 0x40_b000, 0x40_c000, 0x40_d000]);
        let mut db = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        db.add(function_hash_in(&x64, &image(), &body, 0x1000).unwrap(), None, None, "uses_globals");
        db.add(function_hash_in(&x64, &image(), &sample(), 0x1000).unwrap(), None, None, "leaf");
        assert_eq!(db.identify_in(&x64, &image(), &body, 0x1000), Some("uses_globals"));
        // Without the image's layout the absolute addresses stay in the hash, so it cannot match...
        assert_eq!(db.identify(&x64, &body, 0x1000), None);
        // ...while a body with none matches either way.
        assert_eq!(db.identify(&x64, &sample(), 0x1000), Some("leaf"));
    }

    /// The symbol named `name` in `binary`.
    fn symbol<'b>(binary: &'b Binary, name: &str) -> &'b Symbol {
        binary.symbols.iter().find(|symbol| symbol.name == name).unwrap_or_else(|| panic!("no {name}"))
    }

    #[test]
    fn explicit_source_callee_constructor_preserves_native_and_latent_evidence() {
        let reference = Binary::open(fixture("eval-ref-x86_64.elf")).unwrap();
        let names = canonical_functions(&reference)
            .into_iter()
            .map(|(address, symbol)| (address, symbol.name.clone()))
            .collect();
        let pop_arg = symbol(&reference, "pop_arg");
        let extents = BTreeMap::from([(pop_arg.address, pop_arg.address + 236)]);
        let expected = SignatureDb::from_binary_with_extents(&reference, &extents);
        let actual = SignatureDb::from_binary_with_extents_and_callees(&reference, &extents, &names);
        assert_eq!(actual.to_json(), expected.to_json());
        assert_eq!(actual.entry_calls, expected.entry_calls);
        assert_eq!(actual.entry_exact, expected.entry_exact);
        assert!(!actual.entry_calls.is_empty());
        assert!(actual.callee_keys() > 0);
    }

    #[test]
    fn discovered_extents_name_a_function_discovery_cuts_short() {
        let reference = Binary::open(fixture("eval-ref-x86_64.elf")).unwrap();
        let (target, image) = (reference.target(), MaskContext::from_binary(&reference));
        let pop_arg = symbol(&reference, "pop_arg");
        // Discovery cannot follow pop_arg's jump table, so its body ends at the first `ret`, 236 of 448 bytes in.
        let discovered = reference.read(pop_arg.address, 236).unwrap();
        let extents = BTreeMap::from([(pop_arg.address, pop_arg.address + 236)]);
        assert_eq!(
            SignatureDb::from_binary(&reference).identify_in(&target, &image, discovered, pop_arg.address),
            None
        );
        let db = SignatureDb::from_binary_with_extents(&reference, &extents);
        assert_eq!(db.identify_in(&target, &image, discovered, pop_arg.address), Some("pop_arg"));
        let whole = reference.read(pop_arg.address, pop_arg.size).unwrap();
        assert_eq!(db.identify_in(&target, &image, whole, pop_arg.address), Some("pop_arg"));
        let mut extended = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        extended.extend_from_binary_with_extents(&reference, &extents);
        assert_eq!(extended.identify_in(&target, &image, discovered, pop_arg.address), Some("pop_arg"));
    }

    /// Names every named function of `binary` over its symbol extent, as [`identify_program`] does.
    fn identify_own_functions<'d>(db: &'d SignatureDb, binary: &Binary) -> BTreeMap<u64, Cow<'d, str>> {
        let bodies: Vec<(u64, &[u8])> = canonical_functions(binary)
            .values()
            .map(|symbol| (symbol.address, binary.read(symbol.address, symbol.size).unwrap()))
            .collect();
        identify_program(&[db], &binary.target(), &MaskContext::from_binary(binary), &bodies)
    }

    #[test]
    fn callee_names_tell_apart_bodies_that_differ_only_in_their_calls() {
        let reference = Binary::open(fixture("eval-ref-x86_64.elf")).unwrap();
        let (target, image) = (reference.target(), MaskContext::from_binary(&reference));
        let db = SignatureDb::from_binary(&reference);
        let names = identify_own_functions(&db, &reference);
        // mbstowcs/wcstombs and fprintf/sscanf are the same code calling mbsrtowcs/wcsrtombs and vfprintf/vsscanf.
        for name in ["mbstowcs", "wcstombs", "fprintf", "sscanf"] {
            let function = symbol(&reference, name);
            let body = reference.read(function.address, function.size).unwrap();
            assert_eq!(db.identify_in(&target, &image, body, function.address), None, "{name} alone");
            assert_eq!(names.get(&function.address).map(AsRef::as_ref), Some(name));
        }
        let restored = SignatureDb::from_json(&db.to_json()).unwrap();
        assert_eq!(identify_own_functions(&restored, &reference), names);
    }

    #[test]
    fn callee_names_name_frame_thunks_but_never_bodies_the_gate_rejects() {
        let reference = Binary::open(fixture("eval-ref-aarch64.elf")).unwrap();
        let (target, image) = (reference.target(), MaskContext::from_binary(&reference));
        let db = SignatureDb::from_binary(&reference);
        let names = identify_own_functions(&db, &reference);
        // Two- and three-instruction tail calls: `mov x1, xzr; b strtod` is also any user `strtod(s, 0)` wrapper.
        for name in ["atof", "gmtime", "localtime", "strftime", "__stdio_seek", "__lctrans"] {
            let function = symbol(&reference, name);
            let body = reference.read(function.address, function.size).unwrap();
            assert_eq!(function_hash_in(&target, &image, body, function.address), None, "{name} passes the gate");
            assert_eq!(names.get(&function.address).map(AsRef::as_ref), None, "{name}");
        }
        // `stp x29, x30, [sp, #-16]!; mov x29, sp; ldp x29, x30, [sp], #16; b ...` is shared by both, and names them
        // by where it goes.
        for name in ["fmodl", "compiler_rt.addf3.__addtf3"] {
            let function = symbol(&reference, name);
            let body = reference.read(function.address, function.size).unwrap();
            assert_eq!(db.identify_in(&target, &image, body, function.address), None, "{name} alone");
            assert_eq!(names.get(&function.address).map(AsRef::as_ref), Some(name));
        }
    }

    #[test]
    fn a_callee_key_needs_content_besides_its_branches_and_every_external_target_named() {
        let x64 = target(Arch::X86_64, false);
        let key = |bytes: &[u8], name: &dyn Fn(u64) -> Option<&'static str>| {
            let print = fingerprint(&x64, bytes, 0x1000, Some(&image())).unwrap();
            print.callee_key(0x1000..0x1000 + bytes.len() as u64, name)
        };
        // call 0x2000; add eax, 0x1234; mov ecx, eax; ret.
        let call = [0xe8, 0xfb, 0x0f, 0, 0, 0x05, 0x34, 0x12, 0, 0, 0x89, 0xc1, 0xc3];
        let named = |at: u64| (at == 0x2000).then_some("callee");
        let other = |at: u64| (at == 0x2000).then_some("other");
        assert!(key(&call, &named).is_some());
        assert_ne!(key(&call, &named), key(&call, &other));
        assert_eq!(key(&call, &|_| None), None);
        // endbr64; jmp 0x2000: a thunk whatever forwards there shares.
        assert_eq!(key(&[0xf3, 0x0f, 0x1e, 0xfa, 0xe9, 0xf7, 0x0f, 0, 0], &named), None);
        // endbr64; add eax, 0x1234; mov ecx, eax; jmp 0x2000: the body passes the gate only with its landing pad
        // and final branch.
        let padded = [0xf3, 0x0f, 0x1e, 0xfa, 0x05, 0x34, 0x12, 0, 0, 0x89, 0xc1, 0xe9, 0xf0, 0x0f, 0, 0];
        assert!(function_hash_in(&x64, &image(), &padded, 0x1000).is_some());
        assert_eq!(key(&padded, &named), None);
        // call 0x1005 (the next instruction, inside the body); add; mov; ret: nothing outside to name.
        assert_eq!(key(&[0xe8, 0, 0, 0, 0, 0x05, 0x34, 0x12, 0, 0, 0x89, 0xc1, 0xc3], &named), None);
        // A database consults a callee key only through the callee lookup, and only for a body whose masked hash
        // it knows to be ambiguous.
        let mut db = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        db.calls.insert(hex(&key(&call, &named).unwrap()), "wrapper".to_owned());
        assert_eq!(db.identify_with_callees(&x64, &image(), &call, 0x1000, named), None);
        db.ambiguous.insert(hex(&function_hash_in(&x64, &image(), &call, 0x1000).unwrap()));
        assert_eq!(db.identify_in(&x64, &image(), &call, 0x1000), None);
        assert_eq!(db.identify_with_callees(&x64, &image(), &call, 0x1000, named), Some("wrapper"));
        assert_eq!(db.identify_with_callees(&x64, &image(), &call, 0x1000, other), None);
    }

    #[test]
    fn only_functions_with_ambiguous_bodies_keep_callee_keys() {
        let x64 = target(Arch::X86_64, false);
        let call = [0xe8, 0xfb, 0x0f, 0, 0, 0x05, 0x34, 0x12, 0, 0, 0x89, 0xc1, 0xc3];
        let print = || fingerprint(&x64, &call, 0x1000, Some(&image())).unwrap();
        let key = |name: &'static str| print().callee_key(0x1000..0x100d, move |_| Some(name));
        let hash = print().finish().unwrap();
        let mut db = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        db.add(hash, None, key("vfprintf"), "fprintf");
        assert!(db.calls.is_empty());
        // A second name makes the body ambiguous; both functions then answer by their callees.
        db.add(hash, None, key("vsscanf"), "sscanf");
        assert_eq!(db.calls.len(), 2);
        // Callee keys are not function signatures, though they still make the database worth matching against.
        assert_eq!((db.len(), db.callee_keys(), db.is_empty()), (0, 2, false));
        let named = |callee: &'static str| move |_: u64| Some(callee);
        assert_eq!(db.identify_with_callees(&x64, &image(), &call, 0x1000, named("vfprintf")), Some("fprintf"));
        assert_eq!(db.identify_with_callees(&x64, &image(), &call, 0x1000, named("vsscanf")), Some("sscanf"));
    }

    #[test]
    fn a_higher_priority_database_names_by_callees_before_a_lower_one_by_body() {
        let x64 = target(Arch::X86_64, false);
        // 0x1000: call 0x2000; add eax, 0x1234; mov ecx, eax; ret. 0x2000: add eax, 0x1234; mov ecx, eax;
        // mov edx, ecx; ret.
        let wrapper = [0xe8, 0xfb, 0x0f, 0, 0, 0x05, 0x34, 0x12, 0, 0, 0x89, 0xc1, 0xc3];
        let leaf = [0x05, 0x34, 0x12, 0, 0, 0x89, 0xc1, 0x89, 0xca, 0xc3];
        let print = || fingerprint(&x64, &wrapper, 0x1000, Some(&image())).unwrap();
        let wrapper_hash = print().finish().unwrap();
        let mut user = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        user.add(wrapper_hash, None, print().callee_key(0x1000..0x100d, |_| Some("callee")), "user_wrapper");
        user.add(wrapper_hash, None, None, "user_other");
        let mut bundled = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        bundled.add(wrapper_hash, None, None, "bundled_wrapper");
        let functions: [(u64, &[u8]); 2] = [(0x1000, &wrapper), (0x2000, &leaf)];
        let names = identify_program(&[&user, &bundled], &x64, &image(), &functions);
        assert_eq!(names.get(&0x1000).map(AsRef::as_ref), Some("bundled_wrapper"), "nothing names the callee");

        bundled.add(function_hash_in(&x64, &image(), &leaf, 0x2000).unwrap(), None, None, "callee");
        let names = identify_program(&[&user, &bundled], &x64, &image(), &functions);
        assert_eq!(names.get(&0x1000).map(AsRef::as_ref), Some("user_wrapper"));
        assert_eq!(names.get(&0x2000).map(AsRef::as_ref), Some("callee"));
    }

    #[test]
    fn aarch64_branch_targets_decode_both_directions() {
        // b +8 and bl -4.
        assert_eq!(aarch64_branch_target(0x1400_0002, 0x1000), Some(0x1008));
        assert_eq!(aarch64_branch_target(0x97ff_ffff, 0x1000), Some(0xffc));
        // ret is not a direct branch.
        assert_eq!(aarch64_branch_target(0xd65f_03c0, 0x1000), None);
        // A branch near the top of the address space wraps instead of overflowing.
        assert_eq!(aarch64_branch_target(0x1400_0002, u64::MAX - 3), Some(4));
    }

    fn explain_checked(
        db: &SignatureDb,
        target: &Target,
        bytes: &[u8],
        address: u64,
        callees: &BTreeMap<u64, String>,
    ) -> MatchDiagnostics {
        let before = db.to_json();
        let diagnostics = db.explain_in(target, &image(), bytes, address, callees);
        let actual =
            db.identify_with_callees(target, &image(), bytes, address, |at| callees.get(&at).map(String::as_str));
        assert_eq!(diagnostics.named_result.as_deref(), actual);
        assert_eq!(db.to_json(), before);
        diagnostics
    }

    #[test]
    fn explanation_preserves_masked_exact_and_gate_results() {
        let x64 = target(Arch::X86_64, false);
        let names = BTreeMap::new();
        let (first, second) = colliding_pair();
        let mut db = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        add_function(&mut db, &first, "first");
        let masked = explain_checked(&db, &x64, &first, 0x1000, &names);
        assert_eq!(masked.named_result.as_deref(), Some("first"));
        assert_eq!(masked.via, MatchVia::Masked);
        assert!(masked.masked_key.present && !masked.masked_key.ambiguous);
        add_function(&mut db, &second, "second");
        let exact = explain_checked(&db, &x64, &second, 0x1000, &names);
        assert_eq!(exact.named_result.as_deref(), Some("second"));
        assert_eq!(exact.via, MatchVia::Exact);
        assert!(!exact.masked_key.present && exact.masked_key.ambiguous);
        assert!(exact.exact_key.present && !exact.exact_key.ambiguous);
        let relinked = absolute_sample([0x40_a200, 0x40_b200, 0x40_c200, 0x40_d200]);
        let unknown = explain_checked(&db, &x64, &relinked, 0x1000, &names);
        assert_eq!(unknown.lookup_state, LookupState::Unknown);
        assert!(!unknown.exact_key.present && !unknown.exact_key.ambiguous);
        let rejected = explain_checked(&db, &x64, &[0x90; 16], 0x1000, &names);
        assert_eq!(rejected.fingerprint_status, FingerprintStatus::LowContent);
        assert!(rejected.body_hash.is_none());
        let gate = rejected.gates.unwrap();
        assert!(gate.instructions_pass && gate.content_bytes_pass && !gate.distinct_encodings_pass);
        let invalid = explain_checked(&db, &x64, &[0x48], 0x1000, &names);
        assert_eq!(invalid.fingerprint_status, FingerprintStatus::NoDecodedInstructions);
        assert_eq!(invalid.gates.unwrap().instruction_count, 0);
        let internal = explain_checked(&db, &x64, &sample(), 0x1000, &names);
        assert_eq!(internal.external_target_count, 0);
        assert!(internal.missing_callee_targets.is_empty() && internal.callee_key.is_none());
        let mut legacy = SignatureDb::empty(Arch::X86_64, LEGACY_SCHEME);
        legacy.add(function_hash(&x64, &sample(), 0x1000).unwrap(), None, None, "legacy");
        let named = explain_checked(&legacy, &x64, &sample(), 0x1000, &names);
        assert_eq!(named.via, MatchVia::Masked);
        assert_eq!(named.body_hash, named.scheme1_fallback_hash);
    }

    #[test]
    fn explanation_tracks_actual_callee_waits_rounds_and_tombstones() {
        let x64 = target(Arch::X86_64, false);
        let call = [0xe8, 0xfb, 0x0f, 0, 0, 0x05, 0x34, 0x12, 0, 0, 0x89, 0xc1, 0xc3];
        let leaf = [0x05, 0x34, 0x12, 0, 0, 0x89, 0xc1, 0x89, 0xca, 0xc3];
        let print = || fingerprint(&x64, &call, 0x1000, Some(&image())).unwrap();
        let key = print().callee_key(0x1000..0x100d, |_| Some("callee")).unwrap();
        let hash = print().finish().unwrap();
        let mut db = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        db.add(hash, None, Some(key), "wrapper");
        db.add(hash, None, None, "other");
        let waiting = explain_checked(&db, &x64, &call, 0x1000, &BTreeMap::new());
        assert_eq!(waiting.lookup_state, LookupState::AwaitsCallees);
        assert_eq!(waiting.missing_callee_targets, ["0x2000"]);
        assert!(waiting.callee_key.is_none());
        db.add(function_hash_in(&x64, &image(), &leaf, 0x2000).unwrap(), None, None, "callee");
        let functions: [(u64, &[u8]); 2] = [(0x1000, &call), (0x2000, &leaf)];
        let names = identify_program(&[&db], &x64, &image(), &functions)
            .into_iter()
            .map(|(at, name)| (at, name.into_owned()))
            .collect();
        let named = explain_checked(&db, &x64, &call, 0x1000, &names);
        assert_eq!(named.named_result.as_deref(), Some("wrapper"));
        assert_eq!(named.via, MatchVia::Callees);
        assert!(named.callee_key_state.present && !named.callee_key_state.ambiguous);
        db.add(hash, None, Some(key), "conflict");
        let conflict = explain_checked(&db, &x64, &call, 0x1000, &names);
        assert_eq!(conflict.lookup_state, LookupState::Unknown);
        assert!(!conflict.callee_key_state.present && conflict.callee_key_state.ambiguous);
        let exact = function_hash(&x64, &call, 0x1000).unwrap();
        db.add_exact(hex(&exact), "first".into());
        db.add_exact(hex(&exact), "second".into());
        assert!(explain_checked(&db, &x64, &call, 0x1000, &names).exact_key.ambiguous);
    }

    #[test]
    fn explanation_keeps_the_core_callee_content_gate_separate() {
        let x64 = target(Arch::X86_64, false);
        let padded = [0xf3, 0x0f, 0x1e, 0xfa, 0x05, 0x34, 0x12, 0, 0, 0x89, 0xc1, 0xe9, 0xf0, 0x0f, 0, 0];
        let mut db = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        db.ambiguous.insert(hex(&function_hash_in(&x64, &image(), &padded, 0x1000).unwrap()));
        db.calls.insert(hex(&[7; 32]), "unrelated".into());
        let evidence = explain_checked(&db, &x64, &padded, 0x1000, &BTreeMap::from([(0x2000, "callee".into())]));
        assert!(evidence.gates.unwrap().discriminating);
        assert!(!evidence.core_callee_gate.unwrap().has_content);
        assert!(evidence.callee_key.is_none());
        assert_eq!(evidence.lookup_state, LookupState::Unknown);
    }

    #[test]
    fn explanation_bounds_native_missing_targets_and_serializes_addresses_losslessly() {
        let x64 = target(Arch::X86_64, false);
        let address = 0x20_0000_0000_1000;
        let mut bytes = Vec::new();
        for _ in 0..20 {
            bytes.extend([0xe8, 0, 0x10, 0, 0]);
        }
        bytes.extend([0x05, 0x34, 0x12, 0, 0, 0x89, 0xc1, 0xc3]);
        let db = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        let evidence = explain_checked(&db, &x64, &bytes, address, &BTreeMap::new());
        assert_eq!(evidence.external_target_count, 20);
        assert_eq!(evidence.missing_callee_targets.len(), 16);
        assert_eq!(evidence.missing_callee_targets_omitted, 4);
        let first = format!("{:#x}", address + 5 + 0x1000);
        assert_eq!(evidence.missing_callee_targets[0], first);
        let json = serde_json::to_value(&evidence).unwrap();
        assert_eq!(json["missing_callee_targets"][0], first);
        let named = explain_checked(&db, &x64, &bytes, address, &BTreeMap::from([(address + 5 + 0x1000, "c".into())]));
        assert_eq!(named.external_target_count, 20);
        assert_eq!(named.missing_callee_targets_omitted, 3);
    }

    #[test]
    fn explanation_distinguishes_unsupported_scheme_target_and_architecture_mismatch() {
        let x64 = target(Arch::X86_64, false);
        let db = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        let unsupported = explain_checked(&db, &target(Arch::Riscv64, false), &sample(), 0x1000, &BTreeMap::new());
        assert!(!unsupported.target_supported && unsupported.scheme_supported && !unsupported.arch_matches);
        assert_eq!(unsupported.fingerprint_status, FingerprintStatus::UnsupportedTarget);
        assert!(unsupported.gates.is_none());
        let unknown_scheme = SignatureDb::empty(Arch::X86_64, 99);
        let unsupported = explain_checked(&unknown_scheme, &x64, &sample(), 0x1000, &BTreeMap::new());
        assert!(unsupported.target_supported && !unsupported.scheme_supported && unsupported.arch_matches);
        assert_eq!(unsupported.fingerprint_status, FingerprintStatus::UnsupportedScheme);
        assert!(unsupported.body_hash.is_none());
        let other_arch = SignatureDb::empty(Arch::X86, CURRENT_SCHEME);
        let mismatch = explain_checked(&other_arch, &x64, &sample(), 0x1000, &BTreeMap::new());
        assert!(!mismatch.arch_matches && mismatch.target_supported);
        assert_eq!(mismatch.fingerprint_status, FingerprintStatus::Ready);
        assert_eq!(mismatch.lookup_state, LookupState::Unknown);
    }

    #[test]
    fn explanation_preserves_known_external_occurrence_order_duplicates_and_independent_bounds() {
        let x64 = target(Arch::X86_64, false);
        let address = 0x1000u64;
        let mut bytes = Vec::new();
        for index in 0..40 {
            let at = if index % 2 == 0 { if index % 4 == 0 { 0x3000 } else { 0x2000 } } else { 0x4000 + index };
            let next = address + bytes.len() as u64 + 5;
            bytes.push(0xe8);
            bytes.extend(((at as i64 - next as i64) as i32).to_le_bytes());
        }
        bytes.extend([0x05, 0x34, 0x12, 0, 0, 0x89, 0xc1, 0xc3]);
        let mut names = BTreeMap::from([(0x2000, "second".into()), (0x3000, "first".into())]);
        let mut db = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        let evidence = explain_checked(&db, &x64, &bytes, address, &names);
        assert_eq!(evidence.external_target_count, 40);
        assert_eq!(evidence.known_callee_inputs.len(), 16);
        assert_eq!(evidence.known_omitted, 4);
        assert_eq!(evidence.missing_callee_targets.len(), 16);
        assert_eq!(evidence.missing_callee_targets_omitted, 4);
        assert_eq!(evidence.missing_callee_targets[0], "0x4001");
        for (index, input) in evidence.known_callee_inputs.iter().enumerate() {
            let (at, name) = if index % 2 == 0 { ("0x3000", "first") } else { ("0x2000", "second") };
            assert_eq!(input.source, CalleeNameSource::CallerSupplied);
            assert_eq!(input.address, at);
            assert_eq!(input.name_preview, name);
            assert_eq!(input.name_bytes, name.len());
            assert_eq!(input.name_sha256, hex(&raw_sha(name.as_bytes())));
            assert!(!input.name_truncated);
        }
        let json = serde_json::to_value(&evidence).unwrap();
        assert_eq!(json["known_callee_inputs"][0]["source"], "caller_supplied");
        names.extend((1..40).step_by(2).map(|index| (0x4000 + index, "later".into())));
        let print = fingerprint(&x64, &bytes, address, Some(&image())).unwrap();
        let key =
            print.callee_key(address..address + bytes.len() as u64, |at| names.get(&at).map(String::as_str)).unwrap();
        let hash = print.finish().unwrap();
        db.add(hash, None, Some(key), "ordered");
        db.add(hash, None, None, "other");
        let all_known = explain_checked(&db, &x64, &bytes, address, &names);
        assert_eq!(all_known.named_result.as_deref(), Some("ordered"));
        assert_eq!(all_known.callee_key, Some(hex(&key)));
        assert_eq!(all_known.known_omitted, 24);
        assert_eq!(all_known.known_callee_inputs[0].address, all_known.known_callee_inputs[4].address);
        assert!(all_known.missing_callee_targets.is_empty());
        assert_eq!(all_known.missing_callee_targets_omitted, 0);
    }

    #[test]
    fn explanation_unicode_preview_never_replaces_full_names_in_callee_keys() {
        let x64 = target(Arch::X86_64, false);
        let call = [0xe8, 0xfb, 0x0f, 0, 0, 0x05, 0x34, 0x12, 0, 0, 0x89, 0xc1, 0xc3];
        let name = format!("{}e\u{301}tail", "界".repeat(255));
        let preview: String = name.chars().take(256).collect();
        let print = || fingerprint(&x64, &call, 0x1000, Some(&image())).unwrap();
        let key = print().callee_key(0x1000..0x100d, |_| Some(name.as_str())).unwrap();
        let hash = print().finish().unwrap();
        let mut db = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        db.add(hash, None, Some(key), "wrapper");
        db.add(hash, None, None, "other");
        let names = BTreeMap::from([(0x2000, name.clone())]);
        let evidence = explain_checked(&db, &x64, &call, 0x1000, &names);
        assert_eq!(evidence.named_result.as_deref(), Some("wrapper"));
        assert_eq!(evidence.via, MatchVia::Callees);
        assert_eq!(evidence.callee_key, Some(hex(&key)));
        let input = &evidence.known_callee_inputs[0];
        assert_eq!(input.name_preview, preview);
        assert_eq!(input.name_preview.chars().count(), 256);
        assert_eq!(input.name_bytes, name.len());
        assert!(input.name_bytes > input.name_preview.len());
        assert_eq!(input.name_sha256, hex(&raw_sha(name.as_bytes())));
        assert_ne!(input.name_sha256, hex(&raw_sha(preview.as_bytes())));
        assert!(input.name_truncated);
        let shortened = explain_checked(&db, &x64, &call, 0x1000, &BTreeMap::from([(0x2000, preview.clone())]));
        assert_eq!(shortened.known_callee_inputs[0].name_preview, preview);
        assert!(!shortened.known_callee_inputs[0].name_truncated);
        assert_ne!(shortened.callee_key, evidence.callee_key);
        assert!(shortened.named_result.is_none());
        assert_eq!(names[&0x2000], name);
    }

    #[test]
    fn explanation_reports_the_existing_prefix_instruction_cap() {
        let x64 = target(Arch::X86_64, false);
        let mut bytes = sample();
        bytes.resize(bytes.len() + MAX_INSTRUCTIONS as usize, 0x90);
        let prefix_length = sample().len() + (MAX_INSTRUCTIONS - 4) as usize;
        let mut db = SignatureDb::empty(Arch::X86_64, CURRENT_SCHEME);
        let hash = function_hash_in(&x64, &image(), &bytes[..prefix_length], 0x1000).unwrap();
        db.add(hash, None, None, "prefix");
        let evidence = explain_checked(&db, &x64, &bytes, 0x1000, &BTreeMap::new());
        assert_eq!(evidence.named_result.as_deref(), Some("prefix"));
        assert!(evidence.instruction_cap_reached);
        assert_eq!(evidence.gates.unwrap().instruction_count, MAX_INSTRUCTIONS);
        assert_eq!(evidence.body_hash, Some(hex(&hash)));
    }
}
