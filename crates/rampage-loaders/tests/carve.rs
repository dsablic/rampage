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

/// A SquashFS superblock of a `used`-byte image: inode table at 96, directory table at 120, id table at 160.
fn squashfs_of(used: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; 96];
    bytes[..4].copy_from_slice(b"hsqs");
    bytes[12..16].copy_from_slice(&131_072u32.to_le_bytes());
    bytes[20..22].copy_from_slice(&4u16.to_le_bytes());
    bytes[22..24].copy_from_slice(&17u16.to_le_bytes());
    bytes[28..30].copy_from_slice(&4u16.to_le_bytes());
    bytes[40..48].copy_from_slice(&used.to_le_bytes());
    for (at, table) in [(48, 160), (56, u64::MAX), (64, 96), (72, 120), (80, u64::MAX), (88, u64::MAX)] {
        bytes[at..at + 8].copy_from_slice(&table.to_le_bytes());
    }
    bytes
}

fn squashfs() -> Vec<u8> {
    let mut bytes = squashfs_of(200);
    bytes.resize(200, 0);
    bytes
}

fn cpio() -> Vec<u8> {
    cpio_of(&[(&b"hello"[..], &b"hi\n"[..]), (b"TRAILER!!!", b"")])
}

fn cpio_member(bytes: &mut Vec<u8>, name: &[u8], size: usize) {
    bytes.extend(b"070701");
    for index in 0..13 {
        let value = match index {
            6 => size,
            11 => name.len() + 1,
            _ => 0,
        };
        bytes.extend(format!("{value:08x}").bytes());
    }
    bytes.extend(name);
    bytes.push(0);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
}

fn cpio_of(members: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (name, data) in members {
        cpio_member(&mut bytes, name, data.len());
        bytes.extend(*data);
        bytes.resize(bytes.len().next_multiple_of(4), 0);
    }
    bytes
}

/// A zip local file header for an empty stored member named `name`, recording `compressed` bytes of data.
fn zip_local(bytes: &mut Vec<u8>, name: &[u8], compressed: u32) {
    bytes.extend(b"PK\x03\x04");
    bytes.extend([20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend(compressed.to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend((name.len() as u16).to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes.extend(name);
}

/// A stored zip of `members` empty members, with its end of central directory when `terminated`.
fn many_member_zip(members: usize, terminated: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..members {
        zip_local(&mut bytes, b"a", 0);
    }
    let central = bytes.len();
    for _ in 0..members {
        bytes.extend(b"PK\x01\x02");
        bytes.extend([0u8; 24]);
        bytes.extend(1u16.to_le_bytes());
        bytes.extend([0u8; 16]);
        bytes.push(b'a');
    }
    if terminated {
        let central_size = bytes.len() - central;
        bytes.extend(b"PK\x05\x06");
        bytes.extend([0u8; 8]);
        bytes.extend((central_size as u32).to_le_bytes());
        bytes.extend((central as u32).to_le_bytes());
        bytes.extend(0u16.to_le_bytes());
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
    bytes[16..20].copy_from_slice(&0x8006_0000u32.to_be_bytes());
    bytes[20..24].copy_from_slice(&0x8006_0040u32.to_be_bytes());
    bytes[29] = 2;
    bytes[31] = 3;
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
    assert_eq!(by_kind(Kind::Squashfs).declared_size, Some(200));
    assert_eq!(by_kind(Kind::UImage).declared_size, Some(80));
    assert_eq!(
        by_kind(Kind::UImage).notes[0],
        r#"image name "kernel", load address 0x80060000, entry 0x80060040, data size 16 bytes, compression lzma"#
    );
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
        carving
            .candidates
            .iter()
            .filter(|c| c.offset == 0)
            .map(|c| (c.kind, c.confidence, c.extent))
            .collect::<Vec<_>>()
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

fn kinds_and_extents(bytes: &[u8]) -> Vec<(u64, Kind, Option<u64>)> {
    carve::scan(bytes, &Limits::default()).candidates.iter().map(|c| (c.offset, c.kind, c.extent)).collect()
}

#[test]
fn an_archive_past_its_walk_cap_is_one_candidate_to_its_end() {
    let archive = many_member_zip(9000, true);
    let carving = carve::scan(&archive, &Limits::default());
    assert_eq!(kinds_and_extents(&archive), [(0, Kind::Zip, Some(archive.len() as u64))]);
    assert!(carving.candidates[0].notes.iter().any(|note| note.contains("cap (8192 records)")), "{carving:?}");

    // Without an end of central directory the rest of the file is taken as the archive's.
    let mut unterminated = many_member_zip(9000, false);
    unterminated.extend(zip());
    let carving = carve::scan(&unterminated, &Limits::default());
    assert_eq!(kinds_and_extents(&unterminated), [(0, Kind::Zip, None)]);
    assert!(carving.candidates[0].notes[0].starts_with("no extent: the member walk stopped at its cap"));

    let mut members: Vec<(&[u8], &[u8])> = vec![(b"a", b""); 5000];
    members.push((b"TRAILER!!!", b""));
    let archive = cpio_of(&members);
    let carving = carve::scan(&archive, &Limits::default());
    assert_eq!(kinds_and_extents(&archive), [(0, Kind::Cpio, Some(archive.len() as u64))]);
    assert!(carving.candidates[0].notes.iter().any(|note| note.contains("cap (4096 members)")), "{carving:?}");
    let unterminated = &archive[..archive.len() - 120];
    let carving = carve::scan(unterminated, &Limits::default());
    assert_eq!(kinds_and_extents(unterminated), [(0, Kind::Cpio, None)]);
    assert!(carving.candidates[0].notes[0].starts_with("no extent: the member walk stopped at its cap"));
}

#[test]
fn a_declared_member_size_past_the_file_hides_no_later_archive() {
    let mut bytes = Vec::new();
    zip_local(&mut bytes, b"x", 0xffff_fff0);
    let real = bytes.len() as u64;
    bytes.extend(zip());
    assert_eq!(kinds_and_extents(&bytes), [(0, Kind::Zip, None), (real, Kind::Zip, Some(zip().len() as u64))]);

    let mut bytes = Vec::new();
    cpio_member(&mut bytes, b"x", 0xffff_fff0);
    let real = bytes.len() as u64;
    bytes.extend(cpio());
    assert_eq!(kinds_and_extents(&bytes), [(0, Kind::Cpio, None), (real, Kind::Cpio, Some(cpio().len() as u64))]);
}

#[test]
fn gzip_header_field_searches_share_one_budget() {
    // Plausible headers announcing a file name, with no NUL anywhere to end it.
    let mut file: Vec<u8> = [0x1f, 0x8b, 0x08, 0x08, 1, 1, 1, 1, 2, 3].repeat(20_000);
    file.extend(gzip());
    let whole = carve::scan(&file, &Limits::default());
    assert_eq!(kinds_and_extents(&file), [(200_000, Kind::Gzip, None)]);
    assert!(!whole.truncated, "{:?}", whole.limitations);

    let limits = Limits { max_probe_bytes: 100_000, ..Limits::default() };
    let capped = carve::scan(&file, &limits);
    assert!(capped.candidates.is_empty(), "{:?}", capped.candidates);
    assert!(capped.truncated);
    assert!(capped.limitations[0].contains("0x186a0-byte budget at offset 0x"), "{:?}", capped.limitations);
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

fn fs_fixture(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/fsimages").join(name)).unwrap()
}

/// A bzip2 stream's first 18 bytes, then filler: magic, 900k blocks, block magic, CRC and origin pointer 5.
fn bzip2() -> Vec<u8> {
    let mut bytes = b"BZh91AY&SY".to_vec();
    bytes.extend([0x12, 0x34, 0x56, 0x78]);
    bytes.extend((5u32 << 7).to_be_bytes());
    bytes.extend(junk(30, 7));
    bytes
}

/// A ustar header for a regular file `name` of `size` bytes, its checksum filled in.
fn tar_header(name: &[u8], size: usize) -> Vec<u8> {
    let mut header = vec![0u8; 512];
    header[..name.len()].copy_from_slice(name);
    header[100..108].copy_from_slice(b"0000644\0");
    header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[148..156].fill(b' ');
    let sum: u32 = header.iter().map(|&byte| u32::from(byte)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    header
}

fn tar_of(members: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (name, data) in members {
        bytes.extend(tar_header(name, data.len()));
        bytes.extend(*data);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
    }
    bytes.extend([0u8; 1024]);
    bytes
}

#[test]
fn carves_file_system_images_and_skips_their_contents() {
    // The extents leave out the padding after a SquashFS image's bytes_used and a tar archive's end blocks.
    let images = [
        ("ext2.img", Kind::Ext, None),
        ("ext4.simg", Kind::AndroidSparse, None),
        ("holes.ext4", Kind::Ext, None),
        ("payload.bin", Kind::OtaPayload, None),
        ("deep-8000.sqfs", Kind::Squashfs, Some(424_274)),
        ("rootfs.tar", Kind::Tar, Some(28_672)),
        ("squashfs-xz.img", Kind::Squashfs, Some(2978)),
        ("rootfs.cpio", Kind::Cpio, None),
        ("pattern.simg", Kind::AndroidSparse, None),
        ("ext4.img", Kind::Ext, None),
    ];
    let names: Vec<&str> = images.iter().map(|image| image.0).collect();
    let mut file = junk(777, 1);
    let mut expected = Vec::new();
    for (index, &(name, kind, extent)) in images.iter().enumerate() {
        let image = fs_fixture(name);
        let extent = extent.unwrap_or(image.len() as u64);
        expected.push((file.len() as u64, kind, Confidence::Validated, None, Some(extent)));
        file.extend(image);
        file.extend(junk(101 + index, index as u32 + 50));
    }
    let offsets: Vec<u64> = expected.iter().map(|entry| entry.0).collect();
    expected.push((file.len() as u64, Kind::Bzip2, Confidence::Validated, None, None));
    file.extend(bzip2());
    let tail = file.len() as u64;
    let elf = fixture("hello-x64.elf");
    expected.push((tail, Kind::Elf, Confidence::Validated, Some("x86_64"), Some(elf.len() as u64)));
    file.extend(elf);
    let carving = carve::scan(&file, &Limits::default());

    // Inside the ext, tar and cpio images the validated files are reported; inside the others, only executables.
    let is_inside = |c: &&Candidate| c.notes.iter().any(|note| note.starts_with("inside the "));
    let outside: Vec<_> = carving.candidates.iter().filter(|c| !is_inside(c)).map(summary).collect();
    assert_eq!(outside, expected);
    let inside: Vec<_> = carving.candidates.iter().filter(is_inside).collect();
    assert!(inside.iter().any(|c| c.kind == Kind::Elf));
    for candidate in inside {
        let image = offsets.iter().rposition(|&offset| offset < candidate.offset).unwrap();
        assert_eq!(candidate.confidence, Confidence::Validated, "{candidate:?}");
        let stored = ["ext2.img", "holes.ext4", "rootfs.tar", "rootfs.cpio", "ext4.img"].contains(&names[image]);
        assert!(stored || candidate.kind == Kind::Elf, "{candidate:?} inside {}", names[image]);
        if candidate.kind == Kind::Elf {
            assert!(candidate.extent.is_some_and(|extent| extent < 0x10000), "{candidate:?}");
        }
    }
    let at = |offset| carving.candidates.iter().find(|c| c.offset == offset).unwrap();
    assert!(at(offsets[0]).notes[0].starts_with("ext2, 1024-byte blocks, 512 blocks"), "{:?}", at(offsets[0]));
    assert!(at(offsets[4]).notes[0].starts_with("no compression"), "{:?}", at(offsets[4]));
    let note = |index: usize| at(offsets[index]).notes.last().unwrap().clone();
    assert!(note(5).starts_with("inside it only candidates whose headers validate are reported"), "{}", note(5));
    assert!(note(6).contains("executables whose headers validate are reported; "), "{}", note(6));
    assert!(note(6).contains("; left out inside it: ") && note(6).contains(" xz"), "{}", note(6));
    let mut seen = std::collections::BTreeSet::new();
    assert!(carving.candidates.iter().all(|c| seen.insert(c.offset)), "an offset is listed twice");
    assert!(!carving.truncated, "{:?}", carving.limitations);
}

#[test]
fn an_executable_whose_section_table_is_not_its_own_keeps_its_program_header_extent() {
    // As in an ext image whose file's later blocks lie elsewhere: the section header table reads other bytes.
    let mut elf = fixture("hello-mips.elf");
    let shoff = u32::from_be_bytes(elf[32..36].try_into().unwrap()) as usize;
    elf[shoff..shoff + 200].fill(0xff);
    let carving = carve::scan(&elf, &Limits::default());
    let candidate = &carving.candidates[0];
    assert_eq!((candidate.kind, candidate.confidence), (Kind::Elf, Confidence::Validated));
    assert_eq!(candidate.extent_source, Some("ELF header and program header table"));
    assert!(candidate.extent.unwrap() <= elf.len() as u64, "{candidate:?}");
    assert!(candidate.notes.iter().any(|note| note.contains("section header table does not check out")));
}

#[test]
fn new_kinds_reject_inconsistent_headers() {
    let at_zero = |bytes: &[u8]| -> Vec<(Kind, Confidence)> {
        let carving = carve::scan(bytes, &Limits::default());
        carving.candidates.iter().filter(|c| c.offset == 0).map(|c| (c.kind, c.confidence)).collect()
    };
    let ext = fs_fixture("ext2.img");
    let mut bad = ext.clone();
    bad[0x400 + 40] ^= 1;
    assert_eq!(at_zero(&bad), [(Kind::Ext, Confidence::MagicOnly)], "inodes per group disagree with the count");
    let mut bad = ext.clone();
    bad[0x400 + 60] = 9;
    assert_eq!(at_zero(&bad), [], "an unknown error policy");
    assert_eq!(at_zero(&ext[..0x440]), [(Kind::Ext, Confidence::MagicOnly)]);

    let mut sparse = fs_fixture("ext4.simg");
    sparse[28] = 0x99;
    let carving = carve::scan(&sparse, &Limits::default());
    assert_eq!((carving.candidates[0].kind, carving.candidates[0].extent), (Kind::AndroidSparse, None));
    assert!(carving.candidates[0].notes.iter().any(|note| note.contains("unknown type")));

    let mut stream = bzip2();
    stream[14] = 0x7f;
    assert_eq!(at_zero(&stream), [(Kind::Bzip2, Confidence::MagicOnly)], "origin pointer past 900k");
    assert_eq!(at_zero(&b"BZh91AY&SX".repeat(3)), []);

    let mut archive = tar_of(&[(b"a", b"hi")]);
    archive[0] = b'b';
    assert_eq!(at_zero(&archive), [], "a wrong tar checksum");
    let archive = tar_of(&[(b"a", b"hi"), (b"b", &[7; 600])]);
    assert_eq!(kinds_and_extents(&archive), [(0, Kind::Tar, Some(archive.len() as u64))]);
    let cut = &archive[..archive.len() - 1500];
    let carving = carve::scan(cut, &Limits::default());
    assert_eq!(kinds_and_extents(cut), [(0, Kind::Tar, None)]);
    assert!(carving.candidates[0].notes[0].contains("past the end of the file"), "{:?}", carving.candidates[0]);

    let payload = fs_fixture("payload.bin");
    let mut bad = payload.clone();
    bad[11] = 3;
    assert_eq!(at_zero(&bad), [(Kind::OtaPayload, Confidence::MagicOnly)], "major version 3");
    assert_eq!(at_zero(&payload[..200]), [(Kind::OtaPayload, Confidence::MagicOnly)], "manifest past the end");
}

#[test]
fn repeated_magics_of_the_new_kinds_stay_bounded() {
    // Each file repeats one plausible header: the scan stops at its caps or budgets instead of walking each far.
    let sparse = fs_fixture("ext4.simg")[..40].repeat(100_000);
    assert_eq!(carve::scan(&sparse, &Limits::default()).candidates.len(), carve::MAX_CANDIDATES);
    let streams = bzip2()[..18].repeat(100_000);
    assert_eq!(carve::scan(&streams, &Limits::default()).candidates.len(), carve::MAX_CANDIDATES);
    let payloads = fs_fixture("payload.bin")[..200].repeat(20_000);
    assert_eq!(carve::scan(&payloads, &Limits::default()).candidates.len(), carve::MAX_CANDIDATES);

    // Headers inside a walked archive are its members, not new archives.
    let headers = tar_header(b"a", 0).repeat(20_000);
    let carving = carve::scan(&headers, &Limits::default());
    assert_eq!(kinds_and_extents(&headers), [(0, Kind::Tar, None)]);
    assert!(carving.candidates[0].notes[0].contains("past the end"), "{:?}", carving.candidates[0]);

    // A ustar magic every 512 bytes whose checksum fails: each costs a checksum, charged to the walk budget.
    let mut forged = tar_header(b"a", 0);
    forged[0] = b'b';
    let forged = forged.repeat(20_000);
    let limits = Limits { max_walk_bytes: 1 << 20, ..Limits::default() };
    let carving = carve::scan(&forged, &limits);
    assert!(carving.candidates.is_empty());
    // Each walked format has its own budget: the tar walks spent theirs, a sparse image after them is still walked.
    let mut then_sparse = forged.clone();
    let sparse = fs_fixture("pattern.simg");
    then_sparse.extend(&sparse);
    let carving = carve::scan(&then_sparse, &limits);
    let found: Vec<_> = carving.candidates.iter().map(|c| (c.offset, c.kind, c.extent)).collect();
    assert_eq!(found, [(forged.len() as u64, Kind::AndroidSparse, Some(sparse.len() as u64))]);
    assert!(carving.truncated);
    assert!(
        carving.limitations[0].contains("tar header walks ran out of their 0x100000-byte budget"),
        "{:?}",
        carving.limitations
    );
}

/// Kind, confidence and the enclosing-image note of each candidate after the first.
fn nested(bytes: &[u8]) -> Vec<(Kind, Option<String>)> {
    let carving = carve::scan(bytes, &Limits::default());
    let inside = |c: &Candidate| c.notes.iter().find(|note| note.starts_with("inside the ")).cloned();
    carving.candidates.iter().skip(1).map(|c| (c.kind, inside(c))).collect()
}

#[test]
fn archives_report_the_validated_files_they_store() {
    let image = uimage();
    let stream = gzip();
    let tar = tar_of(&[(b"kernel.uimg", &image), (b"rootfs.gz", &stream)]);
    let inside_tar = Some("inside the tar at 0x0".to_owned());
    assert_eq!(nested(&tar), [(Kind::UImage, inside_tar.clone()), (Kind::Gzip, inside_tar)]);
    let carving = carve::scan(&tar, &Limits::default());
    assert!(carving.candidates[0].notes.last().unwrap().starts_with("inside it only candidates whose headers"));

    let cpio = cpio_of(&[(b"kernel.uimg", &image), (b"rootfs.gz", &stream), (b"TRAILER!!!", b"")]);
    let inside_cpio = Some("inside the cpio at 0x0".to_owned());
    assert_eq!(nested(&cpio), [(Kind::UImage, inside_cpio.clone()), (Kind::Gzip, inside_cpio)]);

    // A stored zip member holding a gzip stream and a magic-only xz header: the latter is counted, not reported.
    let mut member = gzip();
    let mut broken = xz();
    broken[8] ^= 1;
    member.extend(broken);
    let mut zip = Vec::new();
    zip_local(&mut zip, b"a.gz", member.len() as u32);
    zip.extend(&member);
    let central = zip.len();
    zip.extend(b"PK\x01\x02");
    zip.extend([0u8; 24]);
    zip.extend(4u16.to_le_bytes());
    zip.extend([0u8; 16]);
    zip.extend(b"a.gz");
    let central_size = zip.len() - central;
    zip.extend(b"PK\x05\x06");
    zip.extend([0, 0, 0, 0, 1, 0, 1, 0]);
    zip.extend((central_size as u32).to_le_bytes());
    zip.extend((central as u32).to_le_bytes());
    zip.extend(0u16.to_le_bytes());
    assert_eq!(nested(&zip), [(Kind::Gzip, Some("inside the zip at 0x0".to_owned()))]);
    let carving = carve::scan(&zip, &Limits::default());
    let note = carving.candidates[0].notes.last().unwrap();
    assert!(note.contains("left out inside it: 1 candidate (1 xz)"), "{note}");
}

#[test]
fn a_forged_image_hides_nothing() {
    let rest = [vec![0; 64], gzip(), vec![0; 64]].concat();
    // An OTA header whose metadata signature size claims the rest of the file, with no manifest.
    let mut ota = vec![0xff; 16];
    ota.extend(b"CrAU");
    ota.extend(2u64.to_be_bytes());
    ota.extend(0u64.to_be_bytes());
    ota.extend((rest.len() as u32).to_be_bytes());
    ota.extend(&rest);
    let carving = carve::scan(&ota, &Limits::default());
    assert_eq!(kinds_and_extents(&ota), [(16, Kind::OtaPayload, None), (16 + 24 + 64, Kind::Gzip, None)]);
    assert!(carving.candidates[0].notes.iter().any(|note| note.contains("no operation data")));

    // A SquashFS superblock whose bytes_used claims the rest of the file, its table offsets left zero.
    let mut squash = vec![0xff; 16];
    let mut superblock = squashfs_of(96 + rest.len() as u64);
    superblock[48..96].fill(0);
    squash.extend(superblock);
    squash.extend(&rest);
    let carving = carve::scan(&squash, &Limits::default());
    let found: Vec<_> = carving.candidates.iter().map(|c| (c.offset, c.kind, c.confidence)).collect();
    assert_eq!(found, [(16, Kind::Squashfs, Confidence::MagicOnly), (16 + 96 + 64, Kind::Gzip, Confidence::Validated)]);

    // A sparse image whose chunks cover fewer blocks than its header declares gets no extent either.
    let mut sparse = fs_fixture("pattern.simg");
    sparse[16] = sparse[16].wrapping_add(1);
    let carving = carve::scan(&sparse, &Limits::default());
    assert_eq!(carving.candidates[0].extent, None);
    assert!(carving.candidates[0].notes.iter().any(|note| note.contains("the header declares")));
}

#[test]
fn truncated_headers_of_the_new_kinds_are_magic_only() {
    let first = |bytes: &[u8]| {
        let carving = carve::scan(bytes, &Limits::default());
        carving.candidates.first().map(|c| (c.offset, c.kind, c.confidence))
    };
    let sparse = fs_fixture("ext4.simg");
    for len in 4..28 {
        assert_eq!(first(&sparse[..len]), Some((0, Kind::AndroidSparse, Confidence::MagicOnly)), "{len} bytes");
    }
    let stream = bzip2();
    for len in 10..18 {
        assert_eq!(first(&stream[..len]), Some((0, Kind::Bzip2, Confidence::MagicOnly)), "{len} bytes");
    }
    let payload = fs_fixture("payload.bin");
    for len in 20..24 {
        assert_eq!(first(&payload[..len]), Some((0, Kind::OtaPayload, Confidence::MagicOnly)), "{len} bytes");
    }
}

#[test]
fn an_out_of_range_string_table_index_alone_rejects_the_section_table() {
    let mut elf = fixture("hello-mips.elf");
    let shnum = u16::from_be_bytes(elf[48..50].try_into().unwrap());
    elf[50..52].copy_from_slice(&shnum.to_be_bytes());
    let carving = carve::scan(&elf, &Limits::default());
    let candidate = &carving.candidates[0];
    assert_eq!(candidate.extent_source, Some("ELF header and program header table"));
    assert!(candidate.notes.iter().any(|note| note.contains("section header table does not check out")));
}

#[test]
fn a_64bit_ext_block_count_takes_its_high_word() {
    // 64 KiB blocks, one inode per group of 2^19 blocks: the block count needs its high word at 0x150.
    let superblock = |inodes: u32, blocks: u64| {
        let mut bytes = vec![0u8; 0x400 + 0x400];
        let mut put = |at: usize, value: u32| bytes[0x400 + at..0x400 + at + 4].copy_from_slice(&value.to_le_bytes());
        put(0, inodes);
        put(4, blocks as u32);
        put(24, 6);
        put(32, 1 << 19);
        put(40, 1);
        put(76, 1);
        put(96, 0xc0);
        put(0x150, (blocks >> 32) as u32);
        bytes[0x438..0x43e].copy_from_slice(&[0x53, 0xef, 1, 0, 1, 0]);
        bytes
    };
    let blocks = 0x1_0000_0000 + (1 << 19);
    let image = superblock(8193, blocks);
    let carving = carve::scan(&image, &Limits::default());
    let candidate = &carving.candidates[0];
    assert_eq!(
        (candidate.kind, candidate.confidence, candidate.extent),
        (Kind::Ext, Confidence::Validated, Some(blocks << 16))
    );
    assert!(candidate.notes[0].starts_with("ext4, 65536-byte blocks, 4295491584 blocks"), "{:?}", candidate.notes);

    // The most groups 32-bit inode counts allow: the byte size passes 2^64, so there is no extent.
    let image = superblock(u32::MAX, u64::from(u32::MAX) << 19);
    let carving = carve::scan(&image, &Limits::default());
    let candidate = &carving.candidates[0];
    assert_eq!((candidate.kind, candidate.confidence, candidate.extent), (Kind::Ext, Confidence::Validated, None));
    assert!(candidate.notes.iter().any(|note| note.contains("exceeds 2^64")), "{:?}", candidate.notes);
}

/// The reflected CRC-32 register after `bytes` from `state`, with no inversion before or after.
fn crc_register(mut state: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        state ^= u32::from(byte);
        for _ in 0..8 {
            state = if state & 1 != 0 { (state >> 1) ^ 0xedb8_8320 } else { state >> 1 };
        }
    }
    state
}

fn put32(bytes: &mut [u8], at: usize, value: u32, big: bool) {
    bytes[at..at + 4].copy_from_slice(&if big { value.to_be_bytes() } else { value.to_le_bytes() });
}

/// The first candidate at offset 0: its kind, confidence and extent.
fn first(bytes: &[u8]) -> Option<(Kind, Confidence, Option<u64>)> {
    let carving = carve::scan(bytes, &Limits::default());
    carving.candidates.first().filter(|c| c.offset == 0).map(|c| (c.kind, c.confidence, c.extent))
}

const PEB: usize = 0x4000;

/// One UBI erase block: an erase counter header (VID header at 0x200, data at 0x800, image sequence 0x1234), a
/// volume header unless `unmapped`, then `data` and 0xff.
fn ubi_block(data: &[u8], unmapped: bool) -> Vec<u8> {
    let mut block = vec![0xff; PEB];
    block[..64].fill(0);
    block[..5].copy_from_slice(b"UBI#\x01");
    put32(&mut block, 16, 0x200, true);
    put32(&mut block, 20, 0x800, true);
    put32(&mut block, 24, 0x1234, true);
    let crc = crc_register(!0, &block[..60]);
    put32(&mut block, 60, crc, true);
    if !unmapped {
        block[0x200..0x240].fill(0);
        block[0x200..0x206].copy_from_slice(b"UBI!\x01\x01");
        let crc = crc_register(!0, &block[0x200..0x23c]);
        put32(&mut block, 0x23c, crc, true);
    }
    block[0x800..0x800 + data.len()].copy_from_slice(data);
    block
}

/// A UBIFS superblock node of `lebs` LEBs of 0x3800 bytes.
fn ubifs_superblock(lebs: u32) -> Vec<u8> {
    let mut node = vec![0u8; 4096];
    put32(&mut node, 0, 0x0610_1831, false);
    put32(&mut node, 16, 4096, false);
    node[20] = 6;
    put32(&mut node, 32, 0x800, false);
    put32(&mut node, 36, 0x3800, false);
    put32(&mut node, 40, lebs, false);
    put32(&mut node, 44, 2048, false);
    put32(&mut node, 80, 4, false);
    node[84] = 1;
    let crc = crc_register(!0, &node[8..]);
    put32(&mut node, 4, crc, false);
    node
}

#[test]
fn carves_ubi_and_ubifs_images() {
    // Four erase blocks, the third erased: the extent runs through the fourth. Volumes store their contents whole,
    // so a gzip stream and an ELF in LEBs are reported; a magic-only xz header is left out.
    let elf = fixture("hello-mips.elf");
    let mut broken = xz();
    broken[8] ^= 1;
    let first_leb = [gzip(), broken].concat();
    let blocks = [ubi_block(&first_leb, false), ubi_block(&elf, false), vec![0xff; PEB], ubi_block(b"", true)];
    let mut image = blocks.concat();
    image.extend(junk(1000, 3));
    let carving = carve::scan(&image, &Limits::default());
    let found: Vec<_> = carving.candidates.iter().map(|c| (c.offset, c.kind, c.extent)).collect();
    let elf_extent = carve::executable(&elf).unwrap().extent;
    let expected =
        [(0, Kind::Ubi, Some(4 * PEB as u64)), (0x800, Kind::Gzip, None), (PEB as u64 + 0x800, Kind::Elf, elf_extent)];
    assert_eq!(found, expected);
    let notes = &carving.candidates[0].notes;
    assert!(notes[0].starts_with("4 erase blocks of 0x4000 bytes (2 with a volume header)"), "{notes:?}");
    assert!(notes[1].starts_with("inside it only candidates whose headers validate are reported"), "{notes:?}");
    assert!(notes[1].contains("left out inside it: 1 candidate (1 xz); fs_list lists its contents"), "{notes:?}");
    assert_eq!(carving.candidates[2].notes.last().unwrap(), "inside the ubi at 0x0");

    // With the second block erased, the erase block size still comes from the headers after it.
    let blocks = [ubi_block(b"", false), vec![0xff; PEB], ubi_block(b"", false), ubi_block(b"", false)];
    let image = blocks.concat();
    let carving = carve::scan(&image, &Limits::default());
    assert_eq!(kinds_and_extents(&image), [(0, Kind::Ubi, Some(4 * PEB as u64))]);
    assert!(carving.candidates[0].notes[0].starts_with("4 erase blocks of 0x4000 bytes"), "{carving:?}");
    // A block whose header alone is erased is not erased: the image ends before it, and what it holds is reported.
    let mut hiding = vec![0xff; PEB];
    hiding[0x100..0x100 + gzip().len()].copy_from_slice(&gzip());
    let blocks = [ubi_block(b"", false), ubi_block(b"", false), hiding, ubi_block(b"", false)];
    let image = blocks.concat();
    let found = kinds_and_extents(&image);
    assert_eq!(found[..2], [(0, Kind::Ubi, Some(2 * PEB as u64)), (2 * PEB as u64 + 0x100, Kind::Gzip, None)]);

    // One block alone has no erase block size, so no extent; a wrong CRC is magic_only; truncated, magic_only.
    let one = ubi_block(b"", false);
    let carving = carve::scan(&one, &Limits::default());
    assert_eq!((carving.candidates[0].kind, carving.candidates[0].extent), (Kind::Ubi, None));
    assert!(carving.candidates[0].notes[0].contains("no second erase counter header"), "{:?}", carving.candidates);
    let mut forged = image.clone();
    forged[8] ^= 1;
    assert_eq!(first(&forged), Some((Kind::Ubi, Confidence::MagicOnly, None)));
    assert_eq!(first(&image[..40]), Some((Kind::Ubi, Confidence::MagicOnly, None)));
    assert_eq!(first(b"UBI#\x02 and so on"), None);

    // Acceptance (an OpenWrt NAND factory image): its last erase blocks carry "EOF" in the erase counter header's
    // padding, OpenWrt's end-of-image marker. They are part of the image, and the notes say what they mean.
    let mut marked = ubi_block(b"", true);
    marked[5..8].copy_from_slice(b"EOF");
    let crc = crc_register(!0, &marked[..60]);
    put32(&mut marked, 60, crc, true);
    let image = [ubi_block(b"", false), ubi_block(b"", false), marked.clone(), marked].concat();
    let carving = carve::scan(&image, &Limits::default());
    assert_eq!(kinds_and_extents(&image), [(0, Kind::Ubi, Some(4 * PEB as u64))]);
    assert!(carving.candidates[0].notes[1].starts_with("2 of them carry OpenWrt's end-of-image marker"), "{carving:?}");

    let superblock = ubifs_superblock(3);
    let mut fs = superblock.clone();
    fs.resize(3 * 0x3800, 0);
    assert_eq!(first(&fs), Some((Kind::Ubifs, Confidence::Validated, Some(3 * 0x3800))));
    let carving = carve::scan(&fs, &Limits::default());
    assert!(carving.candidates[0].notes[0].contains("3 LEBs of 0x3800 bytes, lzo compression"), "{:?}", carving);
    let mut forged = fs.clone();
    forged[40] = 4;
    assert_eq!(first(&forged), Some((Kind::Ubifs, Confidence::MagicOnly, None)), "a LEB count the CRC does not cover");
    assert_eq!(first(&fs[..4000]), Some((Kind::Ubifs, Confidence::MagicOnly, None)));
    let mut other_node = fs.clone();
    other_node[20] = 1;
    assert_eq!(first(&other_node), None, "only the superblock node starts a file system");
}

/// A JFFS2 node header of `kind` and `size` bytes, padded to its size.
fn jffs2_node(kind: u16, size: u32, big: bool) -> Vec<u8> {
    let mut node = vec![0u8; size as usize];
    let half = |value: u16| if big { value.to_be_bytes() } else { value.to_le_bytes() };
    node[..2].copy_from_slice(&half(0x1985));
    node[2..4].copy_from_slice(&half(kind));
    put32(&mut node, 4, size, big);
    let crc = crc_register(0, &node[..8]);
    put32(&mut node, 8, crc, big);
    node
}

/// A JFFS2 directory entry named `name`, its node CRC filled in.
fn jffs2_dirent(name: &[u8], big: bool) -> Vec<u8> {
    let mut node = jffs2_node(0xe001, 40 + name.len() as u32, big);
    node[28] = name.len() as u8;
    node[40..].copy_from_slice(name);
    let crc = crc_register(0, &node[..32]);
    put32(&mut node, 32, crc, big);
    node
}

/// A JFFS2 inode with `data` as its compressed data, its node CRC filled in.
fn jffs2_inode(data: &[u8], big: bool) -> Vec<u8> {
    let mut node = jffs2_node(0xe002, 68 + data.len() as u32, big);
    put32(&mut node, 48, data.len() as u32, big);
    node[68..].copy_from_slice(data);
    let crc = crc_register(0, &node[..60]);
    put32(&mut node, 64, crc, big);
    node
}

#[test]
fn carves_jffs2_images_by_walking_their_nodes() {
    for big in [false, true] {
        // A clean marker, an inode, 100 bytes of erased padding, a directory entry (size not a multiple of 4).
        let mut image = jffs2_node(0x2003, 12, big);
        image.extend(jffs2_inode(b"data", big));
        image.extend([0xff; 100]);
        image.extend(jffs2_dirent(b"a", big));
        image.extend([0xff; 3]);
        let end = image.len() as u64;
        image.extend(gzip());
        let carving = carve::scan(&image, &Limits::default());
        let found: Vec<_> = carving.candidates.iter().map(|c| (c.offset, c.kind, c.extent)).collect();
        assert_eq!(found, [(0, Kind::Jffs2, Some(end)), (end, Kind::Gzip, None)], "big-endian {big}");
        assert_eq!(carving.candidates[0].notes[0], "3 nodes walked, 2 of them directory entries or inodes");
        assert!(carving.candidates[0].notes[1].ends_with("; fs_list does not read it"), "{:?}", carving.candidates[0]);
        assert_eq!(
            carving.candidates[0].endianness.unwrap().to_string(),
            if big { "big-endian" } else { "little-endian" }
        );
    }
    // Two nodes are not an image; a wrong header or node CRC is nothing; a truncated header, magic_only.
    let two = [jffs2_dirent(b"a", false), jffs2_inode(b"", false)].concat();
    assert_eq!(first(&two), Some((Kind::Jffs2, Confidence::MagicOnly, None)));
    let mut forged = [two.clone(), jffs2_inode(b"", false)].concat();
    forged[8] ^= 1;
    assert_eq!(first(&forged), None);
    let mut forged = [two.clone(), jffs2_inode(b"", false)].concat();
    forged[20] ^= 1;
    assert_eq!(first(&forged), None, "a directory entry whose node CRC does not match");
    assert_eq!(first(&two[..8]), Some((Kind::Jffs2, Confidence::MagicOnly, None)));

    // Header-only nodes claiming a megabyte each hide nothing: they have no node CRC, so they extend nothing.
    let mut hiding =
        [jffs2_dirent(b"abcd", false), jffs2_node(0x2004, 1 << 20, false), jffs2_node(0x2004, 1 << 20, false)].concat();
    hiding[0x1000..0x1000 + gzip().len()].copy_from_slice(&gzip());
    let found = kinds_and_extents(&hiding);
    assert_eq!(found, [(0, Kind::Jffs2, Some(44)), (0x1000, Kind::Gzip, None)]);
    // Nor do directory entries claiming more than a node may hold.
    let mut huge = jffs2_dirent(b"a", false);
    huge.resize(4 << 20, 0);
    put32(&mut huge, 4, 4 << 20, false);
    let crc = crc_register(0, &huge[..8]);
    put32(&mut huge, 8, crc, false);
    assert_eq!(first(&huge), None);
}

/// A little-endian CramFS image of `size` bytes with its CRC, the root inode a directory.
fn cramfs_image(size: usize) -> Vec<u8> {
    let mut image = vec![0u8; size];
    put32(&mut image, 0, 0x28cd_3d45, false);
    put32(&mut image, 4, size as u32, false);
    put32(&mut image, 8, 3, false);
    image[16..32].copy_from_slice(b"Compressed ROMFS");
    put32(&mut image, 40, 1, false);
    put32(&mut image, 44, 1, false);
    image[64..66].copy_from_slice(&0x41edu16.to_le_bytes());
    let crc = crc32(&image);
    put32(&mut image, 32, crc, false);
    image
}

#[test]
fn carves_cramfs_images_checking_their_crc() {
    let image = cramfs_image(4096);
    assert_eq!(first(&image), Some((Kind::Cramfs, Confidence::Validated, Some(4096))));
    let mut forged = image.clone();
    put32(&mut forged, 4, 2048, false);
    assert_eq!(first(&forged), Some((Kind::Cramfs, Confidence::MagicOnly, None)), "a size the CRC does not cover");
    let carving = carve::scan(&image[..1000], &Limits::default());
    let candidate = &carving.candidates[0];
    assert_eq!((candidate.confidence, candidate.extent), (Confidence::Validated, Some(4096)));
    assert!(candidate.notes.iter().any(|note| note.contains("CRC was not checked")), "{candidate:?}");
    assert_eq!(first(&image[..40]), Some((Kind::Cramfs, Confidence::MagicOnly, None)));
    // Without the version 2 identifier there is no CRC, so no extent.
    let mut old = image.clone();
    old[8] = 2;
    assert_eq!(first(&old), Some((Kind::Cramfs, Confidence::Validated, None)));
    // Big-endian: the same fields, swapped.
    let mut big = vec![0u8; 512];
    put32(&mut big, 0, 0x28cd_3d45, true);
    put32(&mut big, 4, 512, true);
    put32(&mut big, 8, 1, true);
    big[16..32].copy_from_slice(b"Compressed ROMFS");
    big[64..66].copy_from_slice(&0x41edu16.to_be_bytes());
    let crc = crc32(&big);
    put32(&mut big, 32, crc, true);
    assert_eq!(first(&big), Some((Kind::Cramfs, Confidence::Validated, Some(512))));
    // Each CRC is charged to the checksum budget.
    let limits = Limits { max_walk_bytes: 10_000, ..Limits::default() };
    let carving = carve::scan(&image.repeat(4), &limits);
    let confidences: Vec<_> = carving.candidates.iter().map(|c| c.confidence).collect();
    assert_eq!(confidences[..3], [Confidence::Validated, Confidence::Validated, Confidence::MagicOnly]);
    assert!(carving.limitations.iter().any(|text| text.starts_with("CramFS checksums ran out")), "{carving:?}");
}

/// A version 1 TRX of `len` bytes, partitions at `offsets`, with its CRC.
fn trx_image(len: usize, offsets: [u32; 3]) -> Vec<u8> {
    let mut image = vec![0u8; len];
    image[..4].copy_from_slice(b"HDR0");
    put32(&mut image, 4, len as u32, false);
    put32(&mut image, 12, 1 << 16, false);
    for (index, offset) in offsets.into_iter().enumerate() {
        put32(&mut image, 16 + 4 * index, offset, false);
    }
    let crc = crc_register(!0, &image[12..]);
    put32(&mut image, 8, crc, false);
    image
}

#[test]
fn carves_trx_containers_and_reports_everything_inside() {
    // A TRX holding an LZMA kernel (magic_only) and a SquashFS image: both are reported, marked with the TRX.
    let mut payload = vec![0x5d, 0, 0, 0x80, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0];
    payload.resize(100, 0x11);
    payload.extend(squashfs());
    let mut image = trx_image(28 + payload.len(), [28, 128, 0]);
    image[28..].copy_from_slice(&payload);
    let crc = crc_register(!0, &image[12..]);
    put32(&mut image, 8, crc, false);
    let carving = carve::scan(&image, &Limits::default());
    let found: Vec<_> = carving.candidates.iter().map(|c| (c.offset, c.kind, c.confidence)).collect();
    assert_eq!(
        found,
        [
            (0, Kind::Trx, Confidence::Validated),
            (28, Kind::Lzma, Confidence::MagicOnly),
            (128, Kind::Squashfs, Confidence::Validated)
        ]
    );
    assert_eq!(carving.candidates[0].notes, ["version 1, partitions at 0x1c, 0x80"]);
    assert_eq!(carving.candidates[1].notes.last().unwrap(), "inside the trx at 0x0");

    let mut forged = image.clone();
    forged[200] ^= 1;
    assert_eq!(first(&forged), Some((Kind::Trx, Confidence::MagicOnly, None)), "a wrong CRC");
    assert_eq!(first(&trx_image(100, [28, 10, 0])), None, "partitions out of order");
    assert_eq!(first(&image[..20]), Some((Kind::Trx, Confidence::MagicOnly, None)));
    let carving = carve::scan(&image[..100], &Limits::default());
    assert!(carving.candidates[0].notes.iter().any(|note| note.contains("CRC was not checked")));
}

/// A device tree of one empty root node.
fn dtb() -> Vec<u8> {
    let mut tree = vec![0u8; 72];
    for (at, value) in [(0, 0xd00d_feed), (4, 72), (8, 56), (12, 72), (16, 40), (20, 17), (24, 16), (36, 16)] {
        put32(&mut tree, at, value, true);
    }
    for (at, token) in [(56, 1), (64, 2), (68, 9)] {
        put32(&mut tree, at, token, true);
    }
    tree
}

#[test]
fn carves_device_trees_and_ignores_their_magic_alone() {
    let tree = dtb();
    assert_eq!(first(&tree), Some((Kind::Dtb, Confidence::Validated, Some(72))));
    let mut wrong = tree.clone();
    wrong[71] = 8;
    assert_eq!(first(&wrong), None, "no end token");
    let mut wrong = tree.clone();
    wrong[23] = 16;
    assert_eq!(first(&wrong), None, "version 16");
    assert_eq!(first(&tree[..60]), Some((Kind::Dtb, Confidence::MagicOnly, None)));
    assert_eq!(first(&tree[..30]), None);
    assert_eq!(first(&[0xd0, 0x0d, 0xfe, 0xed, 0, 0, 0, 0].repeat(10)), None);
}

#[test]
fn carves_lz4_and_lzop_headers_by_their_checksums() {
    // Frame headers as the lz4 tool writes them: default flags, then with the content size.
    let frame = [0x04, 0x22, 0x4d, 0x18, 0x64, 0x50, 0x08, 0x8a, 0xbc, 0x01];
    assert_eq!(first(&frame), Some((Kind::Lz4, Confidence::Validated, None)));
    let sized = [0x04, 0x22, 0x4d, 0x18, 0x6c, 0x50, 0x40, 0x0d, 0x03, 0, 0, 0, 0, 0, 0x5e, 0x8a];
    let carving = carve::scan(&sized, &Limits::default());
    assert_eq!(carving.candidates[0].uncompressed_size, Some(200_000));
    assert_eq!(carving.candidates[0].notes, ["256 KiB maximum block size"]);
    let mut forged = frame;
    forged[6] = 0x09;
    assert_eq!(first(&forged), Some((Kind::Lz4, Confidence::MagicOnly, None)));
    assert_eq!(first(&frame[..6]), Some((Kind::Lz4, Confidence::MagicOnly, None)));
    let mut constant = frame;
    constant[4] = 0xa4;
    assert_eq!(first(&constant), None, "version bits other than 01: the magic as a program constant");

    let mut header = vec![0x89, b'L', b'Z', b'O', 0, 0x0d, 0x0a, 0x1a, 0x0a];
    header.extend([0x10, 0x30, 0x20, 0xa0, 0x09, 0x40, 0x01, 0x05]);
    header.extend([0x03, 0, 0, 0x01]);
    header.extend([0, 0, 0x81, 0xa4, 0, 0, 0, 0, 0, 0, 0, 0]);
    header.push(5);
    header.extend(b"a.txt");
    let (mut low, mut high) = (1u32, 0u32);
    for &byte in &header[9..] {
        low = (low + u32::from(byte)) % 65521;
        high = (high + low) % 65521;
    }
    header.extend(((high << 16) | low).to_be_bytes());
    let carving = carve::scan(&header, &Limits::default());
    assert_eq!(summary(&carving.candidates[0]), (0, Kind::Lzop, Confidence::Validated, None, None));
    assert_eq!(carving.candidates[0].notes, ["LZO1X-1, original name \"a.txt\""]);
    let mut forged = header.clone();
    forged[30] ^= 1;
    assert_eq!(first(&forged), Some((Kind::Lzop, Confidence::MagicOnly, None)));
    assert_eq!(first(&header[..30]), Some((Kind::Lzop, Confidence::MagicOnly, None)));
}

/// A FAT16 boot sector of a `sectors`-sector volume labelled "BOOT".
fn fat16(sectors: u16) -> Vec<u8> {
    let mut sector = vec![0u8; 512];
    sector[..3].copy_from_slice(&[0xeb, 0x3c, 0x90]);
    sector[3..11].copy_from_slice(b"mkfs.fat");
    sector[11..13].copy_from_slice(&512u16.to_le_bytes());
    sector[13] = 4;
    sector[14..16].copy_from_slice(&1u16.to_le_bytes());
    sector[16] = 2;
    sector[17..19].copy_from_slice(&512u16.to_le_bytes());
    sector[19..21].copy_from_slice(&sectors.to_le_bytes());
    sector[21] = 0xf8;
    sector[22..24].copy_from_slice(&64u16.to_le_bytes());
    sector[0x26] = 0x29;
    sector[0x2b..0x36].copy_from_slice(b"BOOT       ");
    sector[0x36..0x3e].copy_from_slice(b"FAT16   ");
    sector[510..].copy_from_slice(&[0x55, 0xaa]);
    sector
}

/// An MBR with one bootable partition of `count` sectors at sector `start`, of `kind`.
fn mbr(partitions: &[(u8, u32, u32)]) -> Vec<u8> {
    let mut sector = vec![0u8; 512];
    sector[..2].copy_from_slice(&[0xfa, 0x33]);
    for (index, &(kind, start, count)) in partitions.iter().enumerate() {
        let entry = 446 + 16 * index;
        sector[entry] = 0x80;
        sector[entry + 4] = kind;
        put32(&mut sector, entry + 8, start, false);
        put32(&mut sector, entry + 12, count, false);
    }
    sector[510..].copy_from_slice(&[0x55, 0xaa]);
    sector
}

#[test]
fn carves_mbr_disks_and_fat_volumes() {
    // A disk with one FAT16 partition at sector 4 holding an ELF: disk, volume and ELF are reported, nested.
    let elf = fixture("hello-mips.elf");
    let mut disk = mbr(&[(0x06, 4, 20_000)]);
    disk.resize(4 * 512, 0);
    disk.extend(fat16(20_000));
    disk.resize(40 * 1024, 0);
    disk.extend(&elf);
    disk.resize(4 * 512 + 20_000 * 512, 0);
    let carving = carve::scan(&disk, &Limits::default());
    let found: Vec<_> = carving.candidates.iter().map(|c| (c.offset, c.kind, c.extent)).collect();
    let elf_extent = carve::executable(&elf).unwrap().extent;
    assert_eq!(
        found,
        [(0, Kind::Mbr, Some(20_004 * 512)), (2048, Kind::Fat, Some(20_000 * 512)), (40 * 1024, Kind::Elf, elf_extent)]
    );
    assert_eq!(carving.candidates[0].notes[0], "1 partitions: type 0x06 at 0x800");
    assert_eq!(carving.candidates[1].notes[0], "FAT16, 512-byte sectors, 4959 clusters, volume label \"BOOT\"");
    assert_eq!(carving.candidates[1].notes[1], "inside the mbr at 0x0");
    assert_eq!(carving.candidates[2].notes.last().unwrap(), "inside the fat at 0x800");

    // An MBR only at a sector-aligned offset, with sane non-overlapping entries.
    let mut shifted = vec![0u8; 100];
    shifted.extend(mbr(&[(0x83, 4, 20)]));
    assert!(carve::scan(&shifted, &Limits::default()).candidates.is_empty());
    assert_eq!(first(&mbr(&[(0x83, 4, 20), (0x83, 10, 20)])), None, "overlapping partitions");
    assert_eq!(first(&mbr(&[(0x83, 0, 20)])), None, "a partition over the MBR");
    let mut flagged = mbr(&[(0x83, 4, 20)]);
    flagged[446] = 0x81;
    assert_eq!(first(&flagged), None, "a boot flag other than 0 or 0x80");
    assert_eq!(first(&[0x55, 0xaa].repeat(256)), None);
    assert_eq!(first(&[0u8; 510].iter().copied().chain([0x55, 0xaa]).collect::<Vec<_>>()), None, "no partitions");

    // FAT: the "FAT" type string and the layout must check out.
    let mut volume = fat16(20_000);
    volume.resize(20_000 * 512, 0);
    assert_eq!(first(&volume), Some((Kind::Fat, Confidence::Validated, Some(20_000 * 512))));
    let mut untyped = volume.clone();
    untyped[0x36..0x39].copy_from_slice(b"XYZ");
    assert_eq!(first(&untyped), None);
    assert_eq!(first(&fat16(100)), None, "a FAT larger than the volume");
    assert_eq!(first(&volume[..300]), None);

    // A FAT32 volume's backup boot sector (sector 6) is part of it, not a second volume.
    let mut boot = fat16(0);
    boot[17..21].fill(0);
    boot[22..24].fill(0);
    boot[32..36].copy_from_slice(&20_000u32.to_le_bytes());
    boot[36..40].copy_from_slice(&100u32.to_le_bytes());
    boot[50..52].copy_from_slice(&6u16.to_le_bytes());
    boot[0x36..0x3e].fill(0);
    boot[0x47..0x52].copy_from_slice(b"NO NAME    ");
    boot[0x52..0x5a].copy_from_slice(b"FAT32   ");
    let mut volume = boot.clone();
    volume.resize(6 * 512, 0);
    volume.extend(&boot);
    volume.resize(20_000 * 512, 0);
    let carving = carve::scan(&volume, &Limits::default());
    let found: Vec<_> = carving.candidates.iter().map(|c| (c.offset, c.kind, c.extent)).collect();
    assert_eq!(found, [(0, Kind::Fat, Some(20_000 * 512))]);
    assert_eq!(carving.candidates[0].notes[0], "FAT32, 512-byte sectors, 4949 clusters");
}

/// A GPT disk of 100 sectors: protective MBR, header, 128 entries at LBA 2 (one partition "data" at 34..=90).
fn gpt_disk() -> Vec<u8> {
    let mut disk = mbr(&[(0xee, 1, 99)]);
    disk[446] = 0;
    disk.resize(100 * 512, 0);
    let mut entries = vec![0u8; 128 * 128];
    entries[..16].copy_from_slice(&[
        0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4,
    ]);
    entries[16] = 1;
    entries[32..40].copy_from_slice(&34u64.to_le_bytes());
    entries[40..48].copy_from_slice(&90u64.to_le_bytes());
    for (index, unit) in "data".encode_utf16().enumerate() {
        entries[56 + 2 * index..58 + 2 * index].copy_from_slice(&unit.to_le_bytes());
    }
    disk[1024..1024 + entries.len()].copy_from_slice(&entries);
    let header = &mut disk[512..1024];
    header[..8].copy_from_slice(b"EFI PART");
    put32(header, 8, 0x0001_0000, false);
    put32(header, 12, 92, false);
    header[24..32].copy_from_slice(&1u64.to_le_bytes());
    header[32..40].copy_from_slice(&99u64.to_le_bytes());
    header[40..48].copy_from_slice(&34u64.to_le_bytes());
    header[48..56].copy_from_slice(&66u64.to_le_bytes());
    header[72..80].copy_from_slice(&2u64.to_le_bytes());
    put32(header, 80, 128, false);
    put32(header, 84, 128, false);
    put32(header, 88, crc32(&entries), false);
    let crc = crc32(&header[..92]);
    put32(header, 16, crc, false);
    disk
}

#[test]
fn carves_gpt_disks_behind_their_protective_mbr() {
    let disk = gpt_disk();
    let carving = carve::scan(&disk, &Limits::default());
    assert_eq!(summary(&carving.candidates[0]), (0, Kind::Gpt, Confidence::Validated, None, Some(100 * 512)));
    assert_eq!(carving.candidates[0].notes, ["1 partitions: data at 0x4400"]);
    // A header CRC that does not match leaves the protective MBR, noted.
    let mut forged = disk.clone();
    forged[512 + 40] = 35;
    let carving = carve::scan(&forged, &Limits::default());
    assert_eq!(summary(&carving.candidates[0]), (0, Kind::Mbr, Confidence::Validated, None, Some(100 * 512)));
    assert!(carving.candidates[0].notes[1].contains("GPT header after it does not check out"));
    let mut forged = disk.clone();
    forged[1024 + 40] = 91;
    assert_eq!(first(&forged).unwrap().0, Kind::Mbr, "a partition array the CRC does not cover");
    assert_eq!(first(&disk[..1000]).unwrap().0, Kind::Mbr);
}

/// A UEFI firmware volume of `blocks` 0x1000-byte blocks (FFS version 2), its header checksum filled in.
fn firmware_volume(blocks: u32) -> Vec<u8> {
    let mut volume = vec![0xffu8; blocks as usize * 0x1000];
    volume[..0x48].fill(0);
    volume[0x10..0x20].copy_from_slice(&[
        0x78, 0xe5, 0x8c, 0x8c, 0x3d, 0x8a, 0x1c, 0x4f, 0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3,
    ]);
    volume[0x20..0x28].copy_from_slice(&(u64::from(blocks) * 0x1000).to_le_bytes());
    volume[0x28..0x2c].copy_from_slice(b"_FVH");
    put32(&mut volume, 0x2c, 0x0004_feff, false);
    volume[0x30..0x32].copy_from_slice(&0x48u16.to_le_bytes());
    volume[0x37] = 2;
    put32(&mut volume, 0x38, blocks, false);
    put32(&mut volume, 0x3c, 0x1000, false);
    let sum = volume[..0x48].chunks(2).fold(0u16, |sum, word| sum.wrapping_add(u16::from_le_bytes([word[0], word[1]])));
    volume[0x32..0x34].copy_from_slice(&0u16.wrapping_sub(sum).to_le_bytes());
    volume
}

#[test]
fn carves_uefi_volumes_and_capsules() {
    // A capsule holding a firmware volume holding a PE: all three are reported, nested.
    let pe = fixture("hello-x64.exe");
    let mut volume = firmware_volume(0x40);
    volume[0x100..0x100 + pe.len()].copy_from_slice(&pe);
    let mut capsule =
        vec![0xbd, 0x86, 0x66, 0x3b, 0x76, 0x0d, 0x30, 0x40, 0xb7, 0x0e, 0xb5, 0x51, 0x9e, 0x2f, 0xc5, 0xa0];
    capsule.extend(28u32.to_le_bytes());
    capsule.extend(0x0005_0000u32.to_le_bytes());
    capsule.extend((28 + volume.len() as u32).to_le_bytes());
    capsule.extend(&volume);
    let carving = carve::scan(&capsule, &Limits::default());
    let found: Vec<_> = carving.candidates.iter().map(|c| (c.offset, c.kind, c.confidence)).collect();
    assert_eq!(
        found,
        [
            (0, Kind::UefiCapsule, Confidence::Validated),
            (28, Kind::UefiVolume, Confidence::Validated),
            (28 + 0x100, Kind::Pe, Confidence::Validated)
        ]
    );
    assert_eq!(carving.candidates[0].extent, Some(capsule.len() as u64));
    assert_eq!(carving.candidates[1].notes[0], "revision 2, FFS version 2");
    assert_eq!(carving.candidates[2].notes.last().unwrap(), "inside the uefi_volume at 0x1c");

    let mut forged = volume.clone();
    forged[0x2c] ^= 1;
    assert_eq!(first(&forged), Some((Kind::UefiVolume, Confidence::MagicOnly, None)), "a wrong header checksum");
    let mut forged = volume.clone();
    forged[0x20] = 0x10;
    assert_eq!(first(&forged), None, "a length the block map does not cover");
    assert_eq!(first(&volume[..0x40]), Some((Kind::UefiVolume, Confidence::MagicOnly, None)));
    // "_FVH" alone, as code comparing with it carries it, is nothing.
    assert!(carve::scan(&b"\x81\x7e\x28_FVH".repeat(100), &Limits::default()).candidates.is_empty());
    let mut forged = capsule.clone();
    forged[24..28].copy_from_slice(&20u32.to_le_bytes());
    assert_eq!(first(&forged), Some((Kind::UefiCapsule, Confidence::MagicOnly, None)));
    // A firmware management capsule.
    let mut fmp = capsule.clone();
    fmp[..16].copy_from_slice(&[
        0xed, 0xd5, 0xcb, 0x6d, 0x2d, 0xe8, 0x44, 0x4c, 0xbd, 0xa1, 0x71, 0x94, 0x19, 0x9a, 0xd9, 0x2a,
    ]);
    let carving = carve::scan(&fmp, &Limits::default());
    assert_eq!(carving.candidates[0].notes[0], "firmware management capsule, header size 0x1c");
}

#[test]
fn repeated_headers_of_wave_two_kinds_stay_bounded() {
    let cap = |bytes: &[u8]| {
        let carving = carve::scan(bytes, &Limits::default());
        (carving.candidates.len(), carving.truncated)
    };
    // Headers that report each time stop at the candidate cap.
    for (name, unit) in [
        ("dtb", dtb()),
        ("lz4", vec![0x04, 0x22, 0x4d, 0x18, 0x64, 0x50, 0x08, 0x8a]),
        (
            "capsule",
            [&CAPSULE_HEAD[..], &28u32.to_le_bytes(), &0u32.to_le_bytes(), &32u32.to_le_bytes(), &[0; 4]].concat(),
        ),
        ("fat", fat16(20_000)),
        ("mbr", mbr(&[(0x83, 4, 20)])),
        ("cramfs", cramfs_image(256)),
        ("trx", trx_image(64, [28, 0, 0])),
    ] {
        let copies = 40_000_000 / unit.len() / 10;
        assert_eq!(cap(&unit.repeat(copies)), (carve::MAX_CANDIDATES, true), "{name}");
    }
    // Each UBIFS superblock is checked once; those inside an earlier one's extent are left out.
    let mut superblock = ubifs_superblock(1);
    superblock.resize(0x3800, 0);
    let carving = carve::scan(&superblock.repeat(300), &Limits::default());
    assert_eq!(carving.candidates.len(), 300);
    // Walked images take the repeats as their own blocks or nodes: one candidate.
    let nodes = jffs2_dirent(b"abcd", false).repeat(30_000);
    assert_eq!(kinds_and_extents(&nodes), [(0, Kind::Jffs2, Some(nodes.len() as u64))]);
    let blocks = ubi_block(b"", false).repeat(200);
    assert_eq!(kinds_and_extents(&blocks), [(0, Kind::Ubi, Some(blocks.len() as u64))]);
    // A TRX whose length claims 1 MiB each time: the checksums spend their budget, then each is magic_only.
    let mut claims = trx_image(64, [28, 0, 0]);
    claims[4..8].copy_from_slice(&(1u32 << 20).to_le_bytes());
    let limits = Limits { max_walk_bytes: 4 << 20, ..Limits::default() };
    let carving = carve::scan(&claims.repeat(100_000), &limits);
    assert_eq!(carving.candidates.len(), carve::MAX_CANDIDATES);
    assert!(carving.candidates.iter().all(|c| c.kind == Kind::Trx));
    assert!(
        carving.limitations.iter().any(|text| text.starts_with("TRX checksums ran out")),
        "{:?}",
        carving.limitations
    );
}

const CAPSULE_HEAD: [u8; 16] =
    [0xbd, 0x86, 0x66, 0x3b, 0x76, 0x0d, 0x30, 0x40, 0xb7, 0x0e, 0xb5, 0x51, 0x9e, 0x2f, 0xc5, 0xa0];

#[test]
fn checksums_of_wave_two_kinds_are_charged_to_their_budgets() {
    let kinds = |bytes: &[u8], limits: &Limits| -> Vec<(Kind, Confidence)> {
        carve::scan(bytes, limits).candidates.iter().map(|c| (c.kind, c.confidence)).collect()
    };
    let limitation = |bytes: &[u8], limits: &Limits, text: &str| {
        let carving = carve::scan(bytes, limits);
        assert!(carving.limitations.iter().any(|line| line.starts_with(text)), "{:?}", carving.limitations);
    };
    let (valid, magic_only) = (Confidence::Validated, Confidence::MagicOnly);

    let mut superblock = ubifs_superblock(1);
    superblock.resize(0x3800, 0);
    let file = superblock.repeat(4);
    let limits = Limits { max_walk_bytes: 3 * 4096, ..Limits::default() };
    assert_eq!(
        kinds(&file, &limits),
        [(Kind::Ubifs, valid), (Kind::Ubifs, valid), (Kind::Ubifs, valid), (Kind::Ubifs, magic_only)]
    );
    limitation(&file, &limits, "UBIFS superblock checksums ran out");

    let file = gpt_disk().repeat(2);
    let limits = Limits { max_walk_bytes: 20_000, ..Limits::default() };
    assert_eq!(kinds(&file, &limits), [(Kind::Gpt, valid), (Kind::Mbr, valid)]);
    limitation(&file, &limits, "GPT checksums ran out");

    let file = firmware_volume(1).repeat(2);
    let limits = Limits { max_walk_bytes: 0x50, ..Limits::default() };
    assert_eq!(kinds(&file, &limits), [(Kind::UefiVolume, valid), (Kind::UefiVolume, magic_only)]);
    limitation(&file, &limits, "UEFI firmware volume header checksums ran out");

    // TRX checksums run over the whole container.
    let file = trx_image(4096, [28, 0, 0]).repeat(3);
    let limits = Limits { max_walk_bytes: 2 * 4096, ..Limits::default() };
    assert_eq!(kinds(&file, &limits), [(Kind::Trx, valid), (Kind::Trx, valid), (Kind::Trx, magic_only)]);
    limitation(&file, &limits, "TRX checksums ran out");
}

#[test]
fn an_image_enclosing_endless_decoys_is_skipped_past_the_left_out_cap() {
    // A SquashFS image enclosing more LZ4 frame headers than the cap: each would be checked and left out.
    let frame = [0x04, 0x22, 0x4d, 0x18, 0x64, 0x50, 0x08, 0x8a];
    let decoys = carve::MAX_LEFT_OUT + 1000;
    let mut file = squashfs_of(96 + 8 * decoys as u64 + 64);
    file.extend(frame.repeat(decoys));
    file.resize(96 + 8 * decoys + 64, 0);
    let elf = fixture("hello-mips.elf");
    file.extend(&elf);
    let carving = carve::scan(&file, &Limits::default());
    let found: Vec<_> = carving.candidates.iter().map(|c| (c.offset, c.kind)).collect();
    assert_eq!(found, [(0, Kind::Squashfs), ((96 + 8 * decoys + 64) as u64, Kind::Elf)]);
    assert!(carving.truncated);
    let text = &carving.limitations[0];
    assert!(text.contains("candidates were left out inside images") && text.contains("squashfs at 0x0"), "{text}");
}

#[test]
fn a_magic_only_match_does_not_hide_a_tar_header_at_the_same_offset() {
    let archive = tar_of(&[(b"UBI#\x01 not an erase block", b"hi")]);
    assert_eq!(first(&archive), Some((Kind::Tar, Confidence::Validated, Some(archive.len() as u64))));
}
