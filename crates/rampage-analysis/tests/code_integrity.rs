//! Encrypted or packed code: random bytes in code are judged and not explored, the clear code beside them (a
//! packer's stub, a firmware loader) still is, and no fixture in the repository is judged.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use rampage_analysis::code_integrity::{self, CodeRegion, MAX_VALID_SHARE, MIN_ENTROPY};
use rampage_analysis::functions;
use rampage_arch::Arch;
use rampage_loaders::{Binary, RawCodeOptions, RawProfile};

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

/// A minimal arm64 Mach-O executable: `__TEXT,__text` holding `text` at file offset 0x1000, with an `LC_MAIN`
/// entry at `entry` bytes into it when given.
fn macho(text: &[u8], entry: Option<u64>) -> Vec<u8> {
    let commands = 1 + u32::from(entry.is_some());
    let size_of_commands = 72 + 80 + if entry.is_some() { 24 } else { 0 };
    let mut out = Vec::new();
    for word in [0xfeed_facf_u32, ARM64, 0, 2, commands, size_of_commands, 0, 0] {
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
    if let Some(entry) = entry {
        out.extend_from_slice(&0x8000_0028u32.to_le_bytes());
        out.extend_from_slice(&24u32.to_le_bytes());
        out.extend_from_slice(&(0x1000 + entry).to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
    }
    out.resize(0x1000, 0);
    out.extend_from_slice(text);
    out
}

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn section_bytes(binary: &Binary, name: &str) -> Vec<u8> {
    let section = binary.sections.iter().find(|section| section.name == name).unwrap();
    binary.section_file_bytes(section).unwrap().to_vec()
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

/// The judged regions, after checking that discovery found no function inside any of them.
fn judged_and_unexplored(binary: &Binary) -> (Vec<CodeRegion>, BTreeSet<u64>) {
    let regions = code_integrity::assess(binary, || binary.decoder());
    let starts: BTreeSet<u64> =
        functions::analyze(binary).unwrap().functions.iter().map(|function| function.address).collect();
    for region in &regions {
        assert_eq!(region.verdict, Some(code_integrity::Verdict::LikelyEncryptedOrPacked));
        let inside = starts.iter().filter(|&&start| region.contains(start)).count();
        assert_eq!(inside, 0, "functions discovered in {}", region.explain());
    }
    (regions, starts)
}

fn covered(regions: &[CodeRegion]) -> u64 {
    regions.iter().map(|region| region.size).sum()
}

#[test]
fn random_macho_code_is_judged_and_not_explored() {
    let binary = Binary::from_owned_native_bytes(macho(&noise(64 * 1024, 7), None), Arch::Aarch64).unwrap();
    let (regions, _) = judged_and_unexplored(&binary);
    assert_eq!(covered(&regions), 64 * 1024, "{regions:?}");
}

#[test]
fn random_elf_and_pe_code_is_judged_and_not_explored() {
    for (name, arch) in [
        ("musl-static-x86_64.elf", Arch::X86_64),
        ("musl-static-aarch64.elf", Arch::Aarch64),
        ("hello-x64.exe", Arch::X86_64),
    ] {
        let binary = with_noisy_code(name, ".text", arch);
        let (regions, _) = judged_and_unexplored(&binary);
        let text = binary.sections.iter().find(|section| section.name == ".text").unwrap();
        // All but the entry point's block and the edge blocks that random bytes leave below the edge threshold.
        assert!(covered(&regions) + 2048 >= text.file_size, "{name}: {regions:?}");
    }
}

/// A packer's layout: a compressed payload and the clear stub that unpacks it, in one code section.
#[test]
fn a_clear_stub_beside_a_random_payload_is_still_explored() {
    let binary = Binary::open(fixtures_root().join("bin/musl-static-aarch64.elf")).unwrap();
    let stub = section_bytes(&binary, ".text");
    let payload = noise(48 * 1024, 11);
    let mut text = payload.clone();
    text.extend_from_slice(&stub);
    let packed = Binary::from_owned_native_bytes(macho(&text, Some(payload.len() as u64)), Arch::Aarch64).unwrap();
    let (regions, starts) = judged_and_unexplored(&packed);
    let entry = packed.entry.unwrap();
    assert!(starts.contains(&entry), "entry {entry:#x} lost: {regions:?}");
    let [region] = regions.as_slice() else { panic!("{regions:?}") };
    assert!(region.address == BASE + 0x1000 && region.range().end <= entry, "{region:?}");
    assert!(region.size + 1024 >= payload.len() as u64, "{region:?}");
}

/// Real UPX output, packed from the repository's own fixtures (tests/fixtures/packed/build.sh).
#[test]
fn upx_packed_images_keep_their_unpacking_stub() {
    for (name, arch) in [("upx-musl-static-x86_64.elf", Arch::X86_64), ("upx-hello-x64.exe", Arch::X86_64)] {
        let binary = Binary::open_with(fixtures_root().join("packed").join(name), Some(arch)).unwrap();
        let (regions, starts) = judged_and_unexplored(&binary);
        assert!(!regions.is_empty(), "{name}: payload not judged");
        let entry = binary.entry.unwrap();
        assert!(starts.contains(&entry), "{name}: entry {entry:#x} lost; {regions:?}");
    }
}

/// A raw Cortex-M image whose loader (vector table, reset path) is followed by a compressed stage.
#[test]
fn a_raw_loader_in_front_of_a_random_stage_keeps_its_functions() {
    const FLASH: u64 = 0x0800_0000;
    let options = || RawCodeOptions {
        profile: RawProfile::CortexM,
        base: FLASH,
        entry: None,
        seeds: vec![],
        vector_table: Some(FLASH),
        pointer_tables: false,
    };
    let loader = std::fs::read(fixtures_root().join("firmware/raw-cortex-m.bin")).unwrap();
    let clear = Binary::from_raw_code(loader.clone(), options()).unwrap();
    let mut image = loader.clone();
    image.resize(loader.len().next_multiple_of(4096), 0xff);
    image.extend(noise(32 * 1024, 5));
    let mixed = Binary::from_raw_code(image, options()).unwrap();
    let (regions, starts) = judged_and_unexplored(&mixed);
    assert!(!regions.is_empty(), "the random stage is not judged");
    for region in &regions {
        assert!(region.address >= FLASH + loader.len() as u64, "loader judged: {region:?}");
    }
    let expected: BTreeSet<u64> =
        functions::analyze(&clear).unwrap().functions.iter().map(|function| function.address).collect();
    assert!(!expected.is_empty() && expected.is_subset(&starts), "{expected:x?} vs {starts:x?}");
}

/// Adds a section named `name` holding `data`, with `characteristics`, to a PE image.
fn add_pe_section(mut image: Vec<u8>, name: &[u8; 8], data: &[u8], characteristics: u32) -> Vec<u8> {
    let u16_at = |image: &[u8], at: usize| usize::from(u16::from_le_bytes([image[at], image[at + 1]]));
    let u32_at = |image: &[u8], at: usize| u32::from_le_bytes(image[at..at + 4].try_into().unwrap());
    let pe = u32_at(&image, 0x3c) as usize;
    let sections = u16_at(&image, pe + 6);
    let optional = pe + 24;
    let (section_alignment, file_alignment) = (u32_at(&image, optional + 32), u32_at(&image, optional + 36));
    let size_of_image = u32_at(&image, optional + 56);
    let header = optional + u16_at(&image, pe + 20) + 40 * sections;
    let raw = (image.len() as u32).next_multiple_of(file_alignment);
    let raw_size = (data.len() as u32).next_multiple_of(file_alignment);
    // Name, VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, relocations/line numbers (12 bytes).
    let mut row = name.to_vec();
    for word in [data.len() as u32, size_of_image, raw_size, raw, 0, 0, 0] {
        row.extend_from_slice(&word.to_le_bytes());
    }
    row.extend_from_slice(&characteristics.to_le_bytes());
    assert!(image[header..header + 40].iter().all(|&byte| byte == 0), "no room for another section header");
    image[header..header + 40].copy_from_slice(&row);
    image[pe + 6..pe + 8].copy_from_slice(&(sections as u16 + 1).to_le_bytes());
    let grown = size_of_image + (data.len() as u32).next_multiple_of(section_alignment);
    image[optional + 56..optional + 60].copy_from_slice(&grown.to_le_bytes());
    image.resize(raw as usize, 0);
    image.extend_from_slice(data);
    image.resize((raw + raw_size) as usize, 0);
    image
}

/// A protector's executable section without the code flag, beside an ordinary `.text`, is measured too.
#[test]
fn an_executable_pe_section_without_the_code_flag_is_measured() {
    let image = std::fs::read(fixtures_root().join("bin/hello-x64.exe")).unwrap();
    let protected = add_pe_section(image, b".prot\0\0\0", &noise(32 * 1024, 3), 0xe000_0040);
    let binary = Binary::from_owned_native_bytes(protected, Arch::X86_64).unwrap();
    let (regions, starts) = judged_and_unexplored(&binary);
    let [region] = regions.as_slice() else { panic!("{regions:?}") };
    assert_eq!(region.name, ".prot");
    assert!(!starts.is_empty());
}

/// Every loadable fixture's code stays clear of the thresholds. Prints the closest approach to each, so the margin
/// can be read off `--nocapture`.
#[test]
fn no_fixture_code_region_is_judged() {
    let mut files = Vec::new();
    let mut pending = vec![fixtures_root()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.ends_with("packed") {
                continue;
            }
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    let (mut measured, mut highest_entropy, mut lowest_share) = (0, (0.0, String::new()), (1.0, String::new()));
    for path in files {
        let Ok(binary) = Binary::open(&path) else { continue };
        let judged = code_integrity::assess(&binary, || binary.decoder());
        assert!(
            judged.is_empty(),
            "{}: {:?}",
            path.display(),
            judged.iter().map(CodeRegion::explain).collect::<Vec<_>>()
        );
        for section in code_integrity::measure(&binary, || binary.decoder()) {
            measured += 1;
            let label = format!("{} {}", path.file_name().unwrap().to_string_lossy(), section.name);
            if section.max_window_entropy > highest_entropy.0 {
                highest_entropy = (section.max_window_entropy, label.clone());
            }
            if section.valid_share < lowest_share.0 {
                lowest_share = (section.valid_share, label);
            }
        }
    }
    assert!(measured > 50, "only {measured} code sections measured");
    assert!(highest_entropy.0 < MIN_ENTROPY - 0.3, "{highest_entropy:?}");
    println!("measured {measured} code sections");
    println!("highest window entropy {:.2} ({}) vs threshold {MIN_ENTROPY}", highest_entropy.0, highest_entropy.1);
    println!("lowest valid share {:.3} ({}) vs threshold {MAX_VALID_SHARE}", lowest_share.0, lowest_share.1);
}
