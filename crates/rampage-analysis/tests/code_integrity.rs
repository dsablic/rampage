//! Encrypted or packed code regions: synthetic images whose code is random bytes are judged and not explored, and
//! no fixture in the repository is.

use std::path::{Path, PathBuf};

use rampage_analysis::code_integrity::{self, MAX_VALID_SHARE, MIN_ENTROPY, MIN_REGION_BYTES};
use rampage_analysis::functions;
use rampage_arch::Arch;
use rampage_loaders::Binary;

/// Deterministic noise standing in for encrypted bytes (xorshift64*).
fn noise(len: usize, mut state: u64) -> Vec<u8> {
    (0..len)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            (state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

const ARM64: u32 = 0x0100_000c;
const BASE: u64 = 0x1_0000_0000;

/// A minimal arm64 Mach-O executable: `__TEXT,__text` holding `text` at file offset 0x1000.
fn macho(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for word in [0xfeed_facf_u32, ARM64, 0, 2, 1, 72 + 80, 0, 0] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    let name = |text: &str| {
        let mut field = [0u8; 16];
        field[..text.len()].copy_from_slice(text.as_bytes());
        field
    };
    let size = 0x1000 + text.len() as u64;
    out.extend_from_slice(&0x19u32.to_le_bytes());
    out.extend_from_slice(&(72u32 + 80).to_le_bytes());
    out.extend_from_slice(&name("__TEXT"));
    for word in [BASE, size, 0, size] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    for word in [5u32, 5, 1, 0] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.extend_from_slice(&name("__text"));
    out.extend_from_slice(&name("__TEXT"));
    out.extend_from_slice(&(BASE + 0x1000).to_le_bytes());
    out.extend_from_slice(&(text.len() as u64).to_le_bytes());
    for word in [0x1000u32, 2, 0, 0, 0x8000_0400, 0, 0, 0] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.resize(0x1000, 0);
    out.extend_from_slice(text);
    out
}

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

/// `name` with its code section's bytes replaced by noise.
fn with_noisy_code(name: &str, section: &str, arch: Arch) -> Binary {
    let path = fixtures_root().join("bin").join(name);
    let binary = Binary::open(&path).unwrap();
    let text = binary.sections.iter().find(|candidate| candidate.name == section).unwrap();
    let offset = text.file_offset.unwrap() as usize;
    let mut bytes = std::fs::read(&path).unwrap();
    let len = text.file_size as usize;
    bytes[offset..offset + len].copy_from_slice(&noise(len, 0x9e37_79b9_7f4a_7c15));
    Binary::from_owned_native_bytes(bytes, arch).unwrap()
}

fn assert_judged_and_unexplored(binary: &Binary, section: &str) {
    let regions = code_integrity::assess(binary, || binary.decoder());
    let region = regions.iter().find(|region| region.name == section).expect("code section measured");
    assert_eq!(region.verdict, Some(code_integrity::Verdict::LikelyEncryptedOrPacked), "{}", region.explain());
    let program = functions::analyze(binary).unwrap();
    let inside: Vec<_> = program.functions.iter().filter(|function| region.contains(function.address)).collect();
    assert!(inside.is_empty(), "{} functions discovered in {section}", inside.len());
}

#[test]
fn random_macho_code_is_judged_and_not_explored() {
    let binary = Binary::from_owned_native_bytes(macho(&noise(64 * 1024, 7)), Arch::Aarch64).unwrap();
    assert_judged_and_unexplored(&binary, "__text");
}

#[test]
fn random_elf_and_pe_code_is_judged_and_not_explored() {
    for (name, section, arch) in [
        ("musl-static-x86_64.elf", ".text", Arch::X86_64),
        ("musl-static-aarch64.elf", ".text", Arch::Aarch64),
        ("hello-x64.exe", ".text", Arch::X86_64),
    ] {
        assert_judged_and_unexplored(&with_noisy_code(name, section, arch), section);
    }
}

#[test]
fn ordinary_code_regions_are_measured_without_a_verdict() {
    let binary = Binary::open(fixtures_root().join("bin/musl-static-x86_64.elf")).unwrap();
    let regions = code_integrity::assess(&binary, || binary.decoder());
    let text = regions.iter().find(|region| region.name == ".text").unwrap();
    assert!(text.verdict.is_none() && text.entropy < MIN_ENTROPY, "{}", text.explain());
}

/// Every loadable fixture's code regions stay clear of the thresholds. Prints the closest approach to each, so
/// the margin can be read off `--nocapture`.
#[test]
fn no_fixture_code_region_is_judged() {
    let mut files = Vec::new();
    let mut pending = vec![fixtures_root()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    let (mut measured, mut highest_entropy, mut lowest_share) = (0, (0.0, String::new()), (1.0, String::new()));
    let mut both = (0.0f64, String::new());
    for path in files {
        let Ok(binary) = Binary::open(&path) else { continue };
        let judged = code_integrity::assess(&binary, || binary.decoder());
        let flagged: Vec<_> = judged.iter().filter(|region| region.verdict.is_some()).map(|r| r.explain()).collect();
        assert!(flagged.is_empty(), "{}: {flagged:?}", path.display());
        for region in code_integrity::measure(&binary, || binary.decoder()) {
            measured += 1;
            let label = format!("{} {}", path.file_name().unwrap().to_string_lossy(), region.name);
            if region.entropy > highest_entropy.0 {
                highest_entropy = (region.entropy, label.clone());
            }
            if region.valid_share < lowest_share.0 {
                lowest_share = (region.valid_share, label.clone());
            }
            // How close a region comes to both thresholds at once: the smaller of its two normalized distances.
            let closeness = (region.entropy / MIN_ENTROPY).min(MAX_VALID_SHARE / region.valid_share.max(1e-9));
            if closeness > both.0 {
                both = (closeness, format!("{label} (entropy {:.2}, valid {:.3})", region.entropy, region.valid_share));
            }
        }
    }
    assert!(measured > 50, "only {measured} code regions of at least {MIN_REGION_BYTES} bytes measured");
    println!("measured {measured} code regions");
    println!("highest entropy {:.2} ({}) vs threshold {MIN_ENTROPY}", highest_entropy.0, highest_entropy.1);
    println!("lowest valid share {:.3} ({}) vs threshold {MAX_VALID_SHARE}", lowest_share.0, lowest_share.1);
    println!("closest to both: {}", both.1);
}
