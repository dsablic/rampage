//! M-profile (Cortex-M) ELF recognition from the build attributes, and vector-table seeding for stripped M-profile
//! ELF firmware. Ordinary ARM ELFs (A-profile Linux programs) must stay untouched.

use std::path::PathBuf;

use rampage_arch::Arch;
use rampage_loaders::Binary;

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures").join(path)
}

fn owned(bytes: Vec<u8>) -> Binary {
    Binary::from_owned_native_bytes(bytes, Arch::Arm).unwrap()
}

/// The file offset of `.ARM.attributes`' first byte, found by its contents: the format version `A` followed by an
/// `aeabi` vendor subsection.
fn attributes_offset(bytes: &[u8]) -> usize {
    let at = bytes.windows(6).position(|window| window == b"aeabi\0").unwrap();
    assert_eq!(bytes[at - 5], b'A');
    at - 5
}

#[test]
fn m_profile_comes_from_the_build_attributes() {
    for path in [
        "firmware/cortex-m3.elf",
        "firmware/embedded-libs-m0.elf",
        "firmware/embedded-libs-m4f.elf",
        "firmware/raw-cortex-m-decompile.elf",
        "firmware/tail-calls-stripped.elf",
        "bench-v4/twins/boot-cm4.elf",
    ] {
        let binary = Binary::open(fixture(path)).unwrap();
        assert!(binary.m_profile(), "{path}");
        assert!(binary.target().m_profile, "{path}");
        assert!(binary.warnings.iter().all(|warning| !warning.contains("attributes")), "{path}: {:?}", binary.warnings);
    }
    // A-profile ARM Linux programs (ARM and Thumb), and other architectures.
    for path in ["bin/hello-arm.elf", "bin/hello-thumb.elf", "bench-v3/bin/semantics-arm32.elf", "bin/hello-arm64.elf"]
    {
        let binary = Binary::open(fixture(path)).unwrap();
        assert!(!binary.m_profile(), "{path}");
        assert!(!binary.target().m_profile, "{path}");
    }
}

/// Load addresses decide nothing: the same Cortex-M ELF with its profile byte changed to 'A' is not M-profile.
#[test]
fn the_profile_tag_decides_not_the_load_address() {
    let bytes = std::fs::read(fixture("firmware/raw-cortex-m-decompile.elf")).unwrap();
    let offset = attributes_offset(&bytes);
    // Tag_CPU_arch_profile (7) followed by 'M'.
    let profile = offset + bytes[offset..].windows(2).position(|window| window == [7, b'M']).unwrap();
    let mut a_profile = bytes.clone();
    a_profile[profile + 1] = b'A';
    let binary = owned(a_profile);
    assert!(!binary.m_profile());
    assert!(binary.warnings.is_empty(), "{:?}", binary.warnings);
    assert!(owned(bytes).m_profile());
}

/// A malformed attributes section is a warning, and the image is treated as ordinary ARM.
#[test]
fn malformed_attributes_are_a_warning_not_m_profile() {
    let bytes = std::fs::read(fixture("firmware/raw-cortex-m-decompile.elf")).unwrap();
    let offset = attributes_offset(&bytes);
    let mut corrupt = bytes.clone();
    corrupt[offset + 1..offset + 5].copy_from_slice(&0xffff_u32.to_le_bytes());
    let binary = owned(corrupt);
    assert!(!binary.m_profile());
    assert!(binary.warnings.iter().any(|warning| warning.contains(".ARM.attributes")), "{:?}", binary.warnings);
}

fn word(binary: &Binary, address: u64) -> u64 {
    u64::from(u32::from_le_bytes(binary.read(address, 4).unwrap().try_into().unwrap()))
}

/// A stripped ELF with its table at the start of `.text`: the handler only the table names is seeded.
#[test]
fn stripped_elf_seeds_vector_table_handlers() {
    let binary = Binary::open(fixture("firmware/tail-calls-stripped.elf")).unwrap();
    assert!(binary.symbols.is_empty());
    let entry = binary.entry.unwrap();
    assert_eq!(word(&binary, 0x0800_0004) & !1, entry);
    let default_handler = word(&binary, 0x0800_0008) & !1;
    assert_ne!(default_handler, entry);
    assert!(binary.function_starts.contains(&default_handler), "{:x?}", binary.function_starts);

    // Corroboration: once the ELF entry no longer matches the Reset vector, the table is not trusted.
    let mut bytes = std::fs::read(fixture("firmware/tail-calls-stripped.elf")).unwrap();
    bytes[0x18..0x1c].copy_from_slice(&(u32::try_from(default_handler).unwrap() | 1).to_le_bytes());
    let moved = owned(bytes);
    assert!(moved.m_profile());
    assert!(!moved.function_starts.contains(&(entry)), "{:x?}", moved.function_starts);
}

/// A stripped ELF with an `.isr_vector` section before `.text`: every system handler is seeded, and the table ends
/// with its section, so `.text`'s first words are never read as vectors.
#[test]
fn isr_vector_section_seeds_handlers_within_its_bounds() {
    let binary = Binary::open(fixture("firmware/embedded-libs-m0.elf")).unwrap();
    let section = binary.sections.iter().find(|section| section.name == ".isr_vector").unwrap();
    let entry = binary.entry.unwrap();
    assert_eq!(word(&binary, section.address + 4) & !1, entry);
    let mut handlers: Vec<u64> = (2..section.size / 4)
        .map(|index| word(&binary, section.address + 4 * index))
        .filter(|&word| word & 1 == 1)
        .map(|word| word & !1)
        .collect();
    handlers.sort_unstable();
    handlers.dedup();
    assert!(handlers.len() >= 4, "{handlers:x?}");
    for handler in &handlers {
        assert!(binary.function_starts.contains(handler), "{handler:#x} not in {:x?}", binary.function_starts);
    }
    let text = binary.sections.iter().find(|section| section.name == ".text").unwrap();
    let first_text_word = word(&binary, text.address) & !1;
    assert!(
        handlers.contains(&first_text_word) || !binary.function_starts.contains(&first_text_word),
        "{first_text_word:#x}"
    );
}

/// The A-profile Thumb Linux program becomes M-profile only when its attributes say so.
#[test]
fn an_a_profile_elf_is_m_profile_only_by_its_attributes() {
    let bytes = std::fs::read(fixture("bin/hello-thumb.elf")).unwrap();
    let offset = attributes_offset(&bytes);
    let profile = offset + bytes[offset..].windows(2).position(|window| window == [7, b'A']).unwrap();
    let mut m_profile = bytes.clone();
    m_profile[profile + 1] = b'M';
    assert!(owned(m_profile).m_profile());
    assert!(!owned(bytes).m_profile());
}
