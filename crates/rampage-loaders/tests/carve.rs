use std::path::{Path, PathBuf};

use rampage_loaders::carve::{self, Candidate, Confidence, Kind, Limits};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin").join(name)).unwrap()
}

/// Deterministic filler with no format magic in it.
fn junk(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (state >> 16) as u8
        })
        .collect()
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn gzip() -> Vec<u8> {
    let mut bytes = vec![0x1f, 0x8b, 0x08, 0x08, 0, 0, 0, 0, 0, 3];
    bytes.extend(b"inner.bin\0");
    bytes.extend([0x4b, 0x4c, 0x4a, 0x06, 0x00]);
    bytes
}

fn xz() -> Vec<u8> {
    vec![0xfd, b'7', b'z', b'X', b'Z', 0, 0, 4, 0xe6, 0xd6, 0xb4, 0x46]
}

fn zstd() -> Vec<u8> {
    vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, 42, 0x11, 0, 0, b'h', b'i']
}

fn squashfs() -> Vec<u8> {
    let mut bytes = vec![0u8; 96];
    bytes[..4].copy_from_slice(b"hsqs");
    bytes[12..16].copy_from_slice(&131_072u32.to_le_bytes());
    bytes[20..22].copy_from_slice(&4u16.to_le_bytes());
    bytes[22..24].copy_from_slice(&17u16.to_le_bytes());
    bytes[28..30].copy_from_slice(&4u16.to_le_bytes());
    bytes[40..48].copy_from_slice(&96u64.to_le_bytes());
    bytes
}

fn cpio() -> Vec<u8> {
    let mut bytes = Vec::new();
    for (name, data) in [(&b"hello"[..], &b"hi\n"[..]), (b"TRAILER!!!", b"")] {
        bytes.extend(b"070701");
        for (index, value) in [0usize; 13].iter().enumerate() {
            let value = match index {
                6 => data.len(),
                11 => name.len() + 1,
                _ => *value,
            };
            bytes.extend(format!("{value:08x}").bytes());
        }
        bytes.extend(name);
        bytes.push(0);
        bytes.resize(bytes.len().next_multiple_of(4), 0);
        bytes.extend(data);
        bytes.resize(bytes.len().next_multiple_of(4), 0);
    }
    bytes
}

fn zip() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(b"PK\x03\x04");
    bytes.extend([20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend(2u32.to_le_bytes());
    bytes.extend(2u32.to_le_bytes());
    bytes.extend(5u16.to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes.extend(b"a.txt");
    bytes.extend(b"hi");
    let central = bytes.len();
    bytes.extend(b"PK\x01\x02");
    bytes.extend([0u8; 24]);
    bytes.extend(5u16.to_le_bytes());
    bytes.extend([0u8; 16]);
    bytes.extend(b"a.txt");
    let central_size = bytes.len() - central;
    bytes.extend(b"PK\x05\x06");
    bytes.extend([0, 0, 0, 0, 1, 0, 1, 0]);
    bytes.extend((central_size as u32).to_le_bytes());
    bytes.extend((central as u32).to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes
}

fn uimage() -> Vec<u8> {
    let mut bytes = vec![0u8; 64 + 16];
    bytes[..4].copy_from_slice(&0x2705_1956u32.to_be_bytes());
    bytes[12..16].copy_from_slice(&16u32.to_be_bytes());
    bytes[29] = 2;
    bytes[32..38].copy_from_slice(b"kernel");
    let crc = crc32(&bytes[..64]);
    bytes[4..8].copy_from_slice(&crc.to_be_bytes());
    bytes
}

fn android_boot() -> Vec<u8> {
    let mut bytes = vec![0u8; 1632];
    bytes[..8].copy_from_slice(b"ANDROID!");
    bytes[8..12].copy_from_slice(&100u32.to_le_bytes());
    bytes[36..40].copy_from_slice(&2048u32.to_le_bytes());
    bytes
}

fn summary(candidate: &Candidate) -> (u64, Kind, Confidence, Option<&str>, Option<u64>) {
    (candidate.offset, candidate.kind, candidate.confidence, candidate.arch.as_deref(), candidate.extent)
}

struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_file(name: &str, bytes: &[u8]) -> TempFile {
    let path = std::env::temp_dir().join(format!("rampage-carve-{}-{name}", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    TempFile(path)
}

#[test]
fn carves_fixtures_and_containers_at_odd_offsets_inside_junk() {
    let parts: Vec<Vec<u8>> = vec![
        fixture("hello-x64-dyn.elf"),
        fixture("hello-mips.elf"),
        fixture("Microsoft.Bcl.HashCode.dll"),
        fixture("hello-x64.exe"),
        fixture("hello-x64.macho"),
        fixture("hello-universal.macho"),
        gzip(),
        xz(),
        zstd(),
        squashfs(),
        cpio(),
        zip(),
        uimage(),
        android_boot(),
    ];
    let mut file = junk(1001, 0);
    let mut offsets = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        offsets.push(file.len() as u64);
        file.extend(part);
        file.extend(junk(2 * index + 333, index as u32 + 1));
    }
    let android_tail = 4096 - parts[13].len();
    file.extend(junk(android_tail, 99));
    let temp = temp_file("odd-offsets", &file);
    let carving = carve::carve_file(&temp.0, &Limits::default()).unwrap();

    let validated = Confidence::Validated;
    let length = |index: usize| Some(parts[index].len() as u64);
    let expected = vec![
        (offsets[0], Kind::Elf, validated, Some("x86_64"), length(0)),
        (offsets[1], Kind::Elf, validated, Some("mips"), length(1)),
        (offsets[2], Kind::Pe, validated, Some("x86"), length(2)),
        (offsets[3], Kind::Pe, validated, Some("x86_64"), length(3)),
        (offsets[4], Kind::MachO, validated, Some("x86_64"), length(4)),
        (offsets[5], Kind::MachOFat, validated, None, length(5)),
        (offsets[5] + 0x1000, Kind::MachO, validated, Some("x86_64"), Some(0x2110)),
        (offsets[5] + 0x4000, Kind::MachO, validated, Some("aarch64"), Some(33_456)),
        (offsets[6], Kind::Gzip, validated, None, None),
        (offsets[7], Kind::Xz, validated, None, None),
        (offsets[8], Kind::Zstd, validated, None, None),
        (offsets[9], Kind::Squashfs, validated, None, length(9)),
        (offsets[10], Kind::Cpio, validated, None, length(10)),
        (offsets[11], Kind::Zip, validated, None, length(11)),
        (offsets[12], Kind::UImage, validated, Some("arm"), length(12)),
        (offsets[13], Kind::AndroidBoot, validated, None, Some(4096)),
    ];
    assert_eq!(carving.candidates.iter().map(summary).collect::<Vec<_>>(), expected);
    assert!(!carving.truncated);
    assert_eq!(carving.file_size, file.len() as u64);
    assert_eq!(carving.scanned_bytes, file.len() as u64);

    let by_kind = |kind| carving.candidates.iter().find(|candidate| candidate.kind == kind).unwrap();
    let elf = &carving.candidates[1];
    assert_eq!((elf.bits, elf.endianness), (Some(32), Some(carve::Endianness::Big)));
    let fat = by_kind(Kind::MachOFat);
    let slices: Vec<_> = fat.slices.iter().map(|slice| (slice.arch.as_str(), slice.offset, slice.size)).collect();
    assert_eq!(slices, [("x86_64", offsets[5] + 0x1000, 0x2110), ("aarch64", offsets[5] + 0x4000, 33_456)]);
    assert_eq!(by_kind(Kind::Zstd).uncompressed_size, Some(42));
    assert_eq!(by_kind(Kind::Squashfs).declared_size, Some(96));
    assert_eq!(by_kind(Kind::UImage).declared_size, Some(80));
    assert!(by_kind(Kind::Gzip).notes.iter().any(|note| note.contains("inner.bin")));
    assert_eq!(by_kind(Kind::Pe).extent_source, Some("PE headers, section table and certificate table"));
}

#[test]
fn malformed_and_truncated_headers_are_magic_only_or_absent() {
    let at_zero = |bytes: &[u8]| -> Vec<(Kind, Confidence)> {
        let carving = carve::scan(bytes, &Limits::default());
        carving.candidates.iter().filter(|c| c.offset == 0).map(|c| (c.kind, c.confidence)).collect()
    };
    let magic_only = |kind| vec![(kind, Confidence::MagicOnly)];

    let elf = fixture("hello-x64-dyn.elf");
    assert_eq!(at_zero(&elf[..0x30]), magic_only(Kind::Elf));
    assert_eq!(at_zero(&elf[..0x800]), magic_only(Kind::Elf), "section header table past the end");
    let mut bad = elf.clone();
    bad[0x34] = 0x99;
    assert_eq!(at_zero(&bad), magic_only(Kind::Elf), "wrong e_ehsize");
    let mut bad = elf.clone();
    bad[4] = 7;
    assert_eq!(at_zero(&bad), vec![], "invalid ELF class");

    let pe = fixture("Microsoft.Bcl.HashCode.dll");
    let lfanew = u32::from_le_bytes(pe[0x3c..0x40].try_into().unwrap()) as usize;
    assert_eq!(at_zero(&pe[..lfanew + 10]), magic_only(Kind::Pe));
    assert_eq!(at_zero(&pe[..lfanew + 2]), vec![], "MZ without a PE signature");
    let mut bad = pe.clone();
    bad[0x3c..0x40].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
    assert_eq!(at_zero(&bad), vec![]);

    let macho = fixture("hello-x64.macho");
    assert_eq!(at_zero(&macho[..20]), magic_only(Kind::MachO));
    let body_cut = carve::scan(&macho[..4096], &Limits::default());
    let header = &body_cut.candidates[0];
    assert_eq!((header.confidence, header.extent), (Confidence::Validated, Some(0x2110)));
    assert!(header.notes.iter().any(|note| note.contains("past the end of the file")));

    let universal = fixture("hello-universal.macho");
    assert_eq!(at_zero(&universal[..0x2000]), magic_only(Kind::MachOFat));
    let java = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0, 0x1d, 0x0a, 0, 2, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(at_zero(&java), vec![], "a Java class file is not a universal Mach-O");

    let mut image = uimage();
    image[40] ^= 1;
    assert_eq!(at_zero(&image), magic_only(Kind::UImage));
    let mut stream = xz();
    stream[8] ^= 1;
    assert_eq!(at_zero(&stream), magic_only(Kind::Xz));
    let mut superblock = squashfs();
    superblock[22] = 16;
    assert_eq!(at_zero(&superblock), vec![]);
    assert_eq!(at_zero(&squashfs()[..40]), magic_only(Kind::Squashfs));
    let mut archive = zip();
    archive[8] = 77;
    assert_eq!(at_zero(&archive), magic_only(Kind::Zip));
    let mut boot = android_boot();
    boot[36..40].copy_from_slice(&1000u32.to_le_bytes());
    assert_eq!(at_zero(&boot), magic_only(Kind::AndroidBoot));
    assert_eq!(at_zero(b"070701zz"), vec![], "cpio header fields must be hexadecimal");
    let mut stream = gzip();
    stream[20] = 0x07;
    assert_eq!(at_zero(&stream), vec![], "a reserved deflate block type");
    let stored = [0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 3, 0x01, 2, 0, 0xfd, 0xff, b'h', b'i'];
    assert_eq!(at_zero(&stored), vec![(Kind::Gzip, Confidence::Validated)]);
    let mut stored = stored;
    stored[13] = 0;
    assert_eq!(at_zero(&stored), vec![], "a stored block length without its complement");
    let mut frame = zstd();
    frame[6] = 0x07;
    assert_eq!(at_zero(&frame), magic_only(Kind::Zstd), "a reserved zstd block type");
    assert_eq!(at_zero(&zstd()[..7]), magic_only(Kind::Zstd));

    let member = &zip()[..37];
    let members = [member, member].concat();
    let carving = carve::scan(&members, &Limits::default());
    assert_eq!(
        carving.candidates.iter().map(summary).collect::<Vec<_>>(),
        [(0, Kind::Zip, Confidence::Validated, None, None)]
    );
    assert!(carving.candidates[0].notes.iter().any(|note| note.contains("past the end")));
    assert!(carving.candidates[0].notes.contains(&"2 members walked".to_owned()));

    // Every prefix and a byte flipped at every header position: no panics, only bounded results.
    let samples =
        [elf, pe, macho, universal, gzip(), xz(), zstd(), squashfs(), cpio(), zip(), uimage(), android_boot()];
    for sample in &samples {
        let head = &sample[..sample.len().min(2048)];
        for len in 0..=head.len() {
            carve::scan(&head[..len], &Limits::default());
        }
        for position in 0..head.len().min(512) {
            let mut mutated = head.to_vec();
            mutated[position] ^= 0xff;
            carve::scan(&mutated, &Limits::default());
        }
    }
}

/// A 64-bit little-endian Mach-O header with one load command `command` of `command_size` bytes, `body` long.
fn macho_with_command(command: u32, command_size: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xcf, 0xfa, 0xed, 0xfe];
    for field in [0x0100_0007, 3, 2, 1, command_size, 0, 0] {
        bytes.extend(u32::to_le_bytes(field));
    }
    bytes.extend(command.to_le_bytes());
    bytes.extend(command_size.to_le_bytes());
    bytes.extend(body);
    bytes
}

#[test]
fn overflowing_or_truncated_tables_are_magic_only() {
    let at_zero = |bytes: &[u8]| {
        let carving = carve::scan(bytes, &Limits::default());
        carving.candidates.iter().filter(|c| c.offset == 0).map(|c| (c.kind, c.confidence, c.extent)).collect::<Vec<_>>()
    };
    let mut elf = fixture("hello-x64-dyn.elf");
    let phoff = u64::from_le_bytes(elf[32..40].try_into().unwrap()) as usize;
    elf[phoff + 8..phoff + 16].copy_from_slice(&(u64::MAX - 0x10).to_le_bytes());
    elf[phoff + 32..phoff + 40].copy_from_slice(&0x100u64.to_le_bytes());
    assert_eq!(at_zero(&elf), [(Kind::Elf, Confidence::MagicOnly, None)]);

    let mut segment = vec![0u8; 64];
    segment[32..40].copy_from_slice(&(u64::MAX - 0x10).to_le_bytes());
    segment[40..48].copy_from_slice(&0x100u64.to_le_bytes());
    assert_eq!(at_zero(&macho_with_command(0x19, 72, &segment)), [(Kind::MachO, Confidence::MagicOnly, None)]);
    let truncated = macho_with_command(0x19, 8, &[]);
    assert_eq!(at_zero(&truncated), [(Kind::MachO, Confidence::MagicOnly, None)], "segment fields past the file");
    let carving = carve::scan(&truncated, &Limits::default());
    assert!(carving.candidates[0].notes[0].contains("truncated"), "{:?}", carving.candidates);
}

#[test]
fn the_candidate_and_scan_caps_are_enforced_and_reported() {
    let file: Vec<u8> = (0..10).flat_map(|_| xz()).collect();
    let capped = carve::scan(&file, &Limits { max_candidates: 3, ..Limits::default() });
    assert_eq!(capped.candidates.iter().map(|c| c.offset).collect::<Vec<_>>(), [0, 12, 24]);
    assert!(capped.truncated);
    assert!(capped.limitations[0].contains("candidate cap (3) at offset 0x24"), "{:?}", capped.limitations);

    let prefix = carve::scan(&file, &Limits { max_scan_bytes: 30, ..Limits::default() });
    assert_eq!(prefix.candidates.len(), 3);
    assert_eq!(prefix.scanned_bytes, 30);
    assert!(prefix.truncated);
    assert!(prefix.limitations[0].contains("first 0x1e of 0x78 bytes"));

    let whole = carve::scan(&file, &Limits::default());
    assert_eq!((whole.candidates.len(), whole.truncated), (10, false));
    assert_eq!(carve::MAX_CANDIDATES, 4096);
}

#[test]
fn only_regular_files_are_carved() {
    let empty = temp_file("empty", &[]);
    let carving = carve::carve_file(&empty.0, &Limits::default()).unwrap();
    assert_eq!((carving.file_size, carving.candidates.len()), (0, 0));
    assert!(carve::carve_file(&std::env::temp_dir(), &Limits::default()).is_err());
    assert!(carve::carve_file(Path::new("/dev/zero"), &Limits::default()).is_err());
}
