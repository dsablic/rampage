use std::path::PathBuf;

use rampage_arch::Arch;
use rampage_loaders::{Binary, ImageAt};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rampage-slice-probe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn write(&self, bytes: &[u8]) -> PathBuf {
        let path = self.0.join("image");
        std::fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn universal() -> Vec<u8> {
    std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-universal.macho"))
        .unwrap()
}

#[test]
fn declared_architectures_survive_a_malformed_preferred_slice() {
    let scratch = Scratch::new();
    let mut bytes = universal();
    assert_eq!(&bytes[..4], &0xcafe_babeu32.to_be_bytes());
    let count = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let entry = (0..count)
        .map(|index| 8 + index * 20)
        .find(|&entry| u32::from_be_bytes(bytes[entry..entry + 4].try_into().unwrap()) == 0x0100_0007)
        .unwrap();
    let offset = u32::from_be_bytes(bytes[entry + 8..entry + 12].try_into().unwrap()) as usize;
    bytes[offset..offset + 4].fill(0);
    let path = scratch.write(&bytes);
    let arches = Binary::architecture_slices(&path, None).unwrap();
    assert_eq!(arches.len(), 2);
    assert!(arches.contains(&Arch::X86_64) && arches.contains(&Arch::Aarch64));
    assert!(Binary::open_with(&path, Some(Arch::X86_64)).is_err());
    assert_eq!(Binary::open_with(&path, Some(Arch::Aarch64)).unwrap().arch, Arch::Aarch64);
}

#[test]
fn offset_probes_are_bounded_to_the_explicit_view() {
    let scratch = Scratch::new();
    let image = universal();
    let mut bytes = vec![0; 16];
    bytes.extend_from_slice(&image);
    let path = scratch.write(&bytes);
    assert_eq!(Binary::architecture_slices(&path, Some(ImageAt::new(16, Some(image.len() as u64)))).unwrap().len(), 2);
    for view in [
        ImageAt::new(u64::MAX, None),
        ImageAt::new(16, Some(0)),
        ImageAt::new(16, Some(u64::MAX)),
        ImageAt::new(16, Some(8)),
    ] {
        assert!(Binary::architecture_slices(&path, Some(view)).is_err());
    }
}

#[test]
fn ambiguous_architectures_and_excessive_tables_are_rejected_before_loading() {
    let scratch = Scratch::new();
    let mut bytes = universal();
    let cpu = bytes[8..12].to_vec();
    bytes[28..32].copy_from_slice(&cpu);
    let error = Binary::architecture_slices(scratch.write(&bytes), None).unwrap_err();
    assert!(error.to_string().contains("multiple"), "{error}");
    let mut bytes = vec![0; 8 + 65 * 20];
    bytes[..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
    bytes[4..8].copy_from_slice(&65u32.to_be_bytes());
    let error = Binary::architecture_slices(scratch.write(&bytes), None).unwrap_err();
    assert!(error.to_string().contains("64-slice limit"), "{error}");
}

#[test]
fn invalid_unselected_ranges_do_not_block_an_explicit_healthy_slice() {
    for unsupported in [false, true] {
        let scratch = Scratch::new();
        let mut bytes = universal();
        let entry = (0..u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize)
            .map(|index| 8 + index * 20)
            .find(|&entry| u32::from_be_bytes(bytes[entry..entry + 4].try_into().unwrap()) == 0x0100_0007)
            .unwrap();
        bytes[entry + 8..entry + 12].copy_from_slice(&u32::MAX.to_be_bytes());
        if unsupported {
            bytes[entry..entry + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        }
        let path = scratch.write(&bytes);
        let arches = Binary::architecture_slices(&path, None).unwrap();
        assert!(arches.contains(&Arch::Aarch64));
        assert_eq!(Binary::open_with(&path, Some(Arch::Aarch64)).unwrap().arch, Arch::Aarch64);
        assert!(Binary::open_with(&path, Some(Arch::X86_64)).is_err());
        assert!(Binary::open(&path).is_err());
    }
}

#[test]
fn an_embedded_universal_can_open_a_valid_selected_slice_independently() {
    let scratch = Scratch::new();
    let mut image = universal();
    let entry = (0..u32::from_be_bytes(image[4..8].try_into().unwrap()) as usize)
        .map(|index| 8 + index * 20)
        .find(|&entry| u32::from_be_bytes(image[entry..entry + 4].try_into().unwrap()) == 0x0100_0007)
        .unwrap();
    let offset = u32::from_be_bytes(image[entry + 8..entry + 12].try_into().unwrap()) as usize;
    image[offset..offset + 4].fill(0);
    let mut bytes = vec![0; 16];
    bytes.extend_from_slice(&image);
    let path = scratch.write(&bytes);
    for length in [None, Some(image.len() as u64)] {
        let binary = Binary::open_at_with(&path, 16, length, Some(Arch::Aarch64)).unwrap();
        assert_eq!(binary.arch, Arch::Aarch64);
        assert!(binary.warnings.iter().any(|warning| warning.contains("loaded independently")));
        assert!(Binary::open_at_with(&path, 16, length, Some(Arch::X86_64)).is_err());
    }
}

#[test]
fn explicit_slices_still_require_macho_magic_alignment_and_table_separation() {
    let scratch = Scratch::new();
    let image = std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64.elf"))
        .unwrap();
    let mut fat = vec![0; 4096];
    for (offset, value) in
        [(0, 0xcafe_babeu32), (4, 1), (8, 0x0100_0007), (12, 3), (16, 4096), (20, image.len() as u32), (24, 12)]
    {
        fat[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    fat.extend_from_slice(&image);
    let path = scratch.write(&fat);
    assert!(Binary::open_with(&path, Some(Arch::X86_64)).unwrap_err().to_string().contains("not a Mach-O"));
    let mut embedded = vec![0; 16];
    embedded.extend_from_slice(&fat);
    let path = scratch.write(&embedded);
    assert!(
        Binary::open_at_with(&path, 16, None, Some(Arch::X86_64)).unwrap_err().to_string().contains("not a Mach-O")
    );

    for malformed_alignment in [true, false] {
        let mut bytes = universal();
        let entry = (0..u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize)
            .map(|index| 8 + index * 20)
            .find(|&entry| u32::from_be_bytes(bytes[entry..entry + 4].try_into().unwrap()) == 0x0100_0007)
            .unwrap();
        if malformed_alignment {
            bytes[entry + 16..entry + 20].copy_from_slice(&31u32.to_be_bytes());
        } else {
            bytes[entry + 8..entry + 12].copy_from_slice(&4u32.to_be_bytes());
        }
        let path = scratch.write(&bytes);
        assert!(Binary::open_with(&path, Some(Arch::X86_64)).is_err());
    }
}
