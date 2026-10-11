//! Library-function identification by signature, in the spirit of IDA's FLIRT and Ghidra's Function ID: a
//! content hash of a function's instructions, with position-dependent bytes masked out, so the same library
//! function matches across binaries despite being linked at different addresses.
//!
//! The hash covers opcodes, registers and ordinary immediates (which discriminate functions) but masks the bytes
//! that change purely with layout or load address: relative branch/call targets and RIP-relative displacements.
//! A [`SignatureDb`] maps such a hash to a name; build one from binaries whose functions are named (a static
//! library, or a copy with symbols) and use it to name the matching functions in a stripped binary.
//!
//! v1 covers x86 and x86-64, where iced-x86 reports the exact displacement and immediate byte ranges. Other
//! architectures return `None` until equivalent masking is added.

use std::collections::BTreeMap;

use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};
use rampage_arch::Arch;
use rampage_loaders::{Binary, SymbolKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The most instructions hashed from one function, a bound against runaway or malformed input.
const MAX_INSTRUCTIONS: u32 = 100_000;

/// A 32-byte masked content hash of a function body.
pub type FunctionHash = [u8; 32];

/// The x86 bitness for an architecture, or `None` when signature hashing is not supported for it.
fn bitness(arch: Arch) -> Option<u32> {
    match arch {
        Arch::X86 => Some(32),
        Arch::X86_64 => Some(64),
        _ => None,
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

/// The masked content hash of the function whose bytes start at `address`, or `None` for an unsupported
/// architecture or input with no decodable instructions.
pub fn function_hash(arch: Arch, bytes: &[u8], address: u64) -> Option<FunctionHash> {
    let bitness = bitness(arch)?;
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
        if bitness(binary.arch).is_some() {
            for symbol in &binary.symbols {
                if symbol.kind != SymbolKind::Function || symbol.size == 0 || symbol.name.is_empty() {
                    continue;
                }
                if let Some(bytes) = binary.read(symbol.address, symbol.size)
                    && let Some(hash) = function_hash(binary.arch, bytes, symbol.address)
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
    /// architecture matches.
    pub fn identify(&self, arch: Arch, bytes: &[u8], address: u64) -> Option<&str> {
        if self.arch != arch.to_string() {
            return None;
        }
        let hash = function_hash(arch, bytes, address)?;
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

    #[test]
    fn masking_makes_the_hash_independent_of_relative_targets_and_rip_displacements() {
        let base = sample();
        let mut relinked = base.clone();
        relinked[1..5].copy_from_slice(&0x1111_2222u32.to_le_bytes()); // different call target
        relinked[8..12].copy_from_slice(&0x3333_4444u32.to_le_bytes()); // different rip displacement

        // The masked hash ignores those position-dependent bytes...
        assert_eq!(function_hash(Arch::X86_64, &base, 0x1000), function_hash(Arch::X86_64, &relinked, 0x4000));
        // ...while a naive hash of the raw bytes does not, so the masking is doing real work.
        assert_ne!(raw_sha(&base), raw_sha(&relinked));
    }

    #[test]
    fn masking_keeps_ordinary_immediates_and_opcodes() {
        let base = sample();
        let mut changed_constant = base.clone();
        changed_constant[13..17].copy_from_slice(&0x9999u32.to_le_bytes()); // different add immediate
        assert_ne!(function_hash(Arch::X86_64, &base, 0x1000), function_hash(Arch::X86_64, &changed_constant, 0x1000));

        let mut changed_opcode = base.clone();
        changed_opcode[17] = 0x90; // ret -> nop
        assert_ne!(function_hash(Arch::X86_64, &base, 0x1000), function_hash(Arch::X86_64, &changed_opcode, 0x1000));
    }

    #[test]
    fn unsupported_architecture_has_no_hash() {
        assert!(function_hash(Arch::Aarch64, &sample(), 0x1000).is_none());
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
        assert_eq!(db.identify(other.arch, bytes, add.address), Some("add"));
    }

    #[test]
    fn database_drops_ambiguous_hashes_and_round_trips() {
        let mut builder = Builder::default();
        let hash = function_hash(Arch::X86_64, &sample(), 0x1000).unwrap();
        builder.add(hash, "first");
        builder.add(hash, "first");
        let mut other = [0u8; 32];
        other[0] = 1;
        builder.add(other, "unique");
        // A second name for the same hash makes it ambiguous.
        builder.add(hash, "second");
        let db = builder.finish(Arch::X86_64);
        assert_eq!(db.identify(Arch::X86_64, &sample(), 0x1000), None); // ambiguous dropped
        assert_eq!(db.len(), 1);

        let restored = SignatureDb::from_json(&db.to_json()).unwrap();
        assert_eq!(restored.arch, "x86_64");
        assert_eq!(restored.len(), 1);
    }
}
