//! UBI and UBIFS: the mtd-utils fixtures (tests/fixtures/build-ubi-fsimages.sh) listed, extracted and nested; a
//! journal replayed; forged, cyclic and truncated images refused; and CRC-preserving mutation fuzzing, which gets
//! past the node and header checksums into the structure readers.

use std::sync::Arc;

use rampage_unpack::{At, Budget, EntryKind, Format, Limits, Source, extract, list, open_chain};
use sha2::{Digest, Sha256};

use crate::support::{Scratch, check_tree, fixture};

const LEB: usize = 15360;
const PEB: usize = 16384;
const MAGIC: [u8; 4] = [0x31, 0x18, 0x10, 0x06];

fn crc(bytes: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(bytes);
    !crc.sum()
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())
}

/// The 24 KiB incompressible file the fixture script writes: SHA-256 in counter mode.
fn large() -> Vec<u8> {
    (0..768).flat_map(|i| Sha256::digest(format!("large {i}").as_bytes()).to_vec()).collect()
}

fn read_out(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The checks every UBIFS fixture passes: the shared tree, the hard link, the multi-LEB file and the device.
fn check_ubifs(path: &std::path::Path, inner: &[String], compression: &str) {
    let listing = list(path, At::default(), inner, Limits::default()).unwrap();
    let layer = listing.layers.last().unwrap();
    assert_eq!(layer.format, Format::Ubifs);
    assert!(layer.notes.contains(&format!("default compression {compression}")), "{:?}", layer.notes);
    let entry = |path: &str| listing.entries.iter().find(|entry| entry.path == path).unwrap();
    assert_eq!(entry("bin/hello").mode, 0o4755, "listing reports the setuid bit as stored");
    assert_eq!(entry("bin/sh").link.as_deref(), Some("hello"));
    assert_eq!(entry("dev/console").kind, EntryKind::CharDevice);
    assert_eq!(entry("dev/console").note.as_deref(), Some("device 5:1"));
    assert_eq!(entry("usr/share/demo/nested").kind, EntryKind::Dir);
    // One of the two names of the hard-linked inode is noted as a link to the other.
    let (link, text) = (entry("usr/share/demo/readme.link"), entry("usr/share/demo/readme.txt"));
    assert!(link.note.is_some() != text.note.is_some(), "{link:?} {text:?}");
    let scratch = Scratch::new("ubifs");
    let out = scratch.join("out");
    let extraction = extract(path, At::default(), inner, &out, &[], Limits::default()).unwrap();
    check_tree(&out, &extraction.report, true);
    assert_eq!(read_out(&out.join("usr/share/demo/large.bin")), large());
    assert_eq!(read_out(&out.join("usr/share/demo/readme.link")), b"An invented filesystem for rampage tests.\n");
    assert_eq!(extraction.report.skipped_total, 1, "only the device: {:?}", extraction.report.skipped);
}

#[test]
fn bare_ubifs_with_lzo_zstd_and_no_compression() {
    for codec in ["lzo", "zstd", "none"] {
        check_ubifs(&fixture(&format!("ubifs-{codec}.ubifs")), &[], codec);
    }
}

#[test]
fn ubi_volumes_list_extract_and_open_as_nested_images() {
    let path = fixture("ubi.img");
    let listing = list(&path, At::default(), &[], Limits::default()).unwrap();
    assert_eq!(listing.layers[0].format, Format::Ubi);
    assert!(listing.layers[0].notes.contains(&"eraseblock size 16384".to_owned()), "{:?}", listing.layers[0].notes);
    let names: Vec<&str> = listing.entries.iter().map(|entry| entry.path.as_str()).collect();
    assert_eq!(names, ["rootfs.img", "squash.img"]);
    assert!(listing.entries.iter().all(|entry| entry.kind == EntryKind::Image));
    let note = |index: usize| listing.entries[index].note.as_deref().unwrap();
    assert!(note(0).starts_with("dynamic volume 0") && note(0).contains("holds ubifs"), "{}", note(0));
    assert!(note(1).starts_with("static volume 1, 2 LEBs") && note(1).contains("holds squashfs"), "{}", note(1));

    // UBI → UBIFS (zlib) → files, and UBI → static volume → SquashFS → files.
    check_ubifs(&path, &["rootfs.img".to_owned()], "zlib");
    let scratch = Scratch::new("ubi");
    let squash = scratch.join("squash");
    let extraction =
        extract(&path, At::default(), &["squash.img".to_owned()], &squash, &[], Limits::default()).unwrap();
    check_tree(&squash, &extraction.report, false);
    assert_eq!(read_out(&squash.join("usr/share/demo/large.bin")), large());

    // The volumes themselves: the static one at its exact size, the dynamic one up to its last mapped LEB.
    let volumes = scratch.join("volumes");
    extract(&path, At::default(), &[], &volumes, &[], Limits::default()).unwrap();
    let squashfs = read_out(&volumes.join("squash.img"));
    assert_eq!(&squashfs[..4], b"hsqs");
    assert_eq!(squashfs.len() as u64, listing.entries[1].size);
    assert_eq!(read_out(&volumes.join("rootfs.img")).len() % LEB, 0);

    // At an offset inside a larger file, the eraseblock size is still found.
    let blob = scratch.join("dump.bin");
    std::fs::write(&blob, [vec![0x5a; 4096], std::fs::read(&path).unwrap()].concat()).unwrap();
    let at = At { offset: 4096, length: None };
    assert_eq!(list(&blob, at, &["rootfs.img".to_owned()], Limits::default()).unwrap().layers[1].format, Format::Ubifs);
}

/// A UBIFS node with a fresh common header and CRC.
fn node(kind: u8, sqnum: u64, body: &[u8]) -> Vec<u8> {
    let mut node = MAGIC.to_vec();
    node.extend([0; 4]);
    node.extend(sqnum.to_le_bytes());
    node.extend((24 + body.len() as u32).to_le_bytes());
    node.extend([kind, 0, 0, 0]);
    node.extend(body);
    refresh(&mut node);
    node
}

fn refresh(node: &mut [u8]) {
    let crc = crc(&node[8..]);
    node[4..8].copy_from_slice(&crc.to_le_bytes());
}

/// Every node in a UBIFS image: (offset, type, length), found at 8-byte-aligned offsets.
fn nodes(image: &[u8]) -> Vec<(usize, u8, usize)> {
    let mut found = Vec::new();
    let mut at = 0;
    while at + 24 <= image.len() {
        let len = le32(image, at + 16) as usize;
        if image[at..at + 4] == MAGIC && len >= 24 && at % LEB + len <= LEB && at + len <= image.len() {
            found.push((at, image[at + 20], len));
            at += len.div_ceil(8) * 8;
        } else {
            at += 8;
        }
    }
    found
}

/// The directory entry node named `name`: (offset, parent inode, target inode).
fn dent(image: &[u8], name: &[u8]) -> (usize, u32, u32) {
    nodes(image)
        .into_iter()
        .filter(|(_, kind, _)| *kind == 2)
        .map(|(at, _, len)| (at, &image[at..at + len]))
        .find(|(_, node)| &node[56..56 + usize::from(u16::from_le_bytes([node[50], node[51]]))] == name)
        .map(|(at, node)| (at, le32(node, 24), le32(node, 40)))
        .unwrap_or_else(|| panic!("no entry {}", String::from_utf8_lossy(name)))
}

/// The node of `kind` (inode 0, data 1) whose key names inode `inum`.
fn keyed(image: &[u8], kind: u8, inum: u32) -> (usize, usize) {
    nodes(image)
        .into_iter()
        .find(|(at, found, _)| *found == kind && le32(image, at + 24) == inum)
        .map(|(at, _, len)| (at, len))
        .unwrap()
}

fn write_image(scratch: &Scratch, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = scratch.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn key(inum: u32, kind: u32, value: u32) -> Vec<u8> {
    [inum.to_le_bytes(), (kind << 29 | value).to_le_bytes(), [0; 4], [0; 4]].concat()
}

#[test]
fn the_journal_is_replayed_over_the_index() {
    let mut image = std::fs::read(fixture("ubifs-none.ubifs")).unwrap();
    let (_, _, conf) = dent(&image, b"device.conf");
    let (_, _, blocks) = dent(&image, b"blocks.txt");
    let inode_with_size = |image: &[u8], inum: u32, size: u64, sqnum: u64| {
        let (at, len) = keyed(image, 0, inum);
        let mut inode = image[at..at + len].to_vec();
        inode[8..16].copy_from_slice(&sqnum.to_le_bytes());
        inode[48..56].copy_from_slice(&size.to_le_bytes());
        refresh(&mut inode);
        inode
    };
    let dentry = |parent: u32, name: &[u8], inum: u64, sqnum: u64| {
        let mut body = key(parent, 2, 0x1234);
        body.extend(inum.to_le_bytes());
        body.extend([0, 0]);
        body.extend((name.len() as u16).to_le_bytes());
        body.extend([0; 4]);
        body.extend(name);
        body.push(0);
        node(2, sqnum, &body)
    };
    let data = |inum: u32, block: u32, bytes: &[u8], sqnum: u64| {
        let mut body = key(inum, 1, block);
        body.extend((bytes.len() as u32).to_le_bytes());
        body.extend([0; 4]);
        body.extend(bytes);
        node(1, sqnum, &body)
    };
    let mut new_inode = key(1000, 0, 0);
    new_inode.resize(136, 0);
    new_inode[24..32].copy_from_slice(&6u64.to_le_bytes());
    new_inode[68..72].copy_from_slice(&1u32.to_le_bytes());
    new_inode[80..84].copy_from_slice(&0o100_644u32.to_le_bytes());
    let mut truncation = blocks.to_le_bytes().to_vec();
    truncation.extend([0; 12]);
    truncation.extend(14_000u64.to_le_bytes());
    truncation.extend(100u64.to_le_bytes());
    // Written to the empty garbage-collection LEB 14, in sequence after the commit (whose start node is 88).
    let bud = [
        dentry(1, b"journal.txt", 1000, 1001),
        node(0, 1002, &new_inode),
        data(1000, 0, b"fresh\n", 1003),
        dentry(1, b"var", 0, 1004),
        data(conf, 0, b"replayed\n", 1005),
        inode_with_size(&image, conf, 9, 1006),
        node(4, 1007, &truncation),
        inode_with_size(&image, blocks, 100, 1008),
        node(3, 1009, &{
            let mut body = key(1, 3, 0x55);
            body.extend([0; 16]);
            body
        }),
    ];
    let mut at = 14 * LEB;
    for node in &bud {
        image[at..at + node.len()].copy_from_slice(node);
        at += node.len().div_ceil(8) * 8;
    }
    // A node cut short by a power loss ends the bud.
    let mut torn = data(1000, 1, b"lost", 1010);
    torn[30] ^= 0xff;
    image[at..at + torn.len()].copy_from_slice(&torn);
    // The log's commit start node and its padding fill LEB 3 up to 512: the reference to the bud goes there.
    let mut reference = 14u32.to_le_bytes().to_vec();
    reference.extend([0; 4]);
    reference.extend(1u32.to_le_bytes());
    reference.extend([0; 28]);
    let reference = node(8, 1000, &reference);
    image[3 * LEB + 512..3 * LEB + 512 + 64].copy_from_slice(&reference);

    let scratch = Scratch::new("journal");
    let path = write_image(&scratch, "journal.ubifs", &image);
    let listing = list(&path, At::default(), &[], Limits::default()).unwrap();
    let notes = &listing.layers[0].notes;
    assert!(notes.iter().any(|note| note.starts_with("journal replayed: 9 nodes from 1 LEBs")), "{notes:?}");
    assert!(notes.iter().any(|note| note.contains("damaged node")), "{notes:?}");
    assert!(notes.contains(&"1 extended attributes not read".to_owned()), "{notes:?}");
    assert!(!listing.entries.iter().any(|entry| entry.path.starts_with("var")), "the deleted entry is gone");
    let out = scratch.join("out");
    extract(&path, At::default(), &[], &out, &[], Limits::default()).unwrap();
    assert_eq!(read_out(&out.join("journal.txt")), b"fresh\n");
    assert_eq!(read_out(&out.join("etc/device.conf")), b"replayed\n");
    let lines: String = (0..400).map(|i| format!("line {i:05} of the multi-block file\n")).collect();
    assert_eq!(read_out(&out.join("usr/share/demo/blocks.txt")), &lines.as_bytes()[..100]);
}

/// The root index node of a UBIFS image: (offset, length), from the master node in LEB 1.
fn root(image: &[u8]) -> (usize, usize) {
    let master = LEB;
    let (lnum, offs, len) = (le32(image, master + 48), le32(image, master + 52), le32(image, master + 56));
    (lnum as usize * LEB + offs as usize, len as usize)
}

fn listed(path: &std::path::Path) -> Result<rampage_unpack::Listing, String> {
    list(path, At::default(), &[], Limits::default()).map_err(|error| error.to_string())
}

#[test]
fn cyclic_and_shared_index_nodes_are_refused() {
    let original = std::fs::read(fixture("ubifs-lzo.ubifs")).unwrap();
    let (at, len) = root(&original);
    assert!(le32(&original, at + 24) & 0xffff >= 2, "the root has several children");
    assert!(original[at + 26] >= 1, "the root is above the leaves");
    let scratch = Scratch::new("ubifs-cycle");
    // Two branches naming the same child.
    let mut shared = original.clone();
    let first = shared[at + 28..at + 40].to_vec();
    let branch = (len - 28) / usize::from(u16::from_le_bytes([shared[at + 24], shared[at + 25]]));
    shared[at + 28 + branch..at + 40 + branch].copy_from_slice(&first);
    refresh(&mut shared[at..at + len]);
    let error = listed(&write_image(&scratch, "shared.ubifs", &shared)).unwrap_err();
    assert!(error.contains("twice (a cycle)"), "{error}");
    // A branch naming the root itself: refused by its level before it could loop.
    let mut looped = original.clone();
    let (lnum, offs) = ((at / LEB) as u32, (at % LEB) as u32);
    looped[at + 28..at + 32].copy_from_slice(&lnum.to_le_bytes());
    looped[at + 32..at + 36].copy_from_slice(&offs.to_le_bytes());
    looped[at + 36..at + 40].copy_from_slice(&(len as u32).to_le_bytes());
    refresh(&mut looped[at..at + len]);
    let error = listed(&write_image(&scratch, "loop.ubifs", &looped)).unwrap_err();
    assert!(error.contains("out of place") || error.contains("twice"), "{error}");
}

#[test]
fn a_directory_entry_naming_an_ancestor_is_skipped() {
    let mut image = std::fs::read(fixture("ubifs-lzo.ubifs")).unwrap();
    let (at, demo, _) = dent(&image, b"nested");
    // usr/share/demo/nested now names usr/share/demo itself.
    image[at + 40..at + 48].copy_from_slice(&u64::from(demo).to_le_bytes());
    let len = le32(&image, at + 16) as usize;
    refresh(&mut image[at..at + len]);
    let scratch = Scratch::new("ubifs-dircycle");
    let listing = listed(&write_image(&scratch, "dircycle.ubifs", &image)).unwrap();
    assert!(!listing.entries.iter().any(|entry| entry.path.contains("nested")));
    assert!(listing.layers[0].notes.iter().any(|note| note.contains("linked twice")), "{:?}", listing.layers[0].notes);
}

#[test]
fn forged_nodes_are_refused_without_losing_the_rest() {
    let original = std::fs::read(fixture("ubifs-zstd.ubifs")).unwrap();
    let scratch = Scratch::new("ubifs-forged");
    let (_, _, conf) = dent(&original, b"device.conf");
    let (data_at, data_len) = keyed(&original, 1, conf);
    // A data node whose bytes no longer match its CRC: that file is skipped, the others extracted.
    let mut flipped = original.clone();
    flipped[data_at + data_len - 1] ^= 0x55;
    let path = write_image(&scratch, "flipped.ubifs", &flipped);
    let report = extract(&path, At::default(), &[], &scratch.join("a"), &[], Limits::default()).unwrap().report;
    let skip = report.skipped.iter().find(|skip| skip.path == "etc/device.conf").expect("device.conf skipped");
    assert!(skip.reason.contains("CRC"), "{}", skip.reason);
    assert_eq!(read_out(&scratch.join("a/usr/share/demo/large.bin")), large());
    // A data node claiming more than a block, CRC intact.
    let mut oversized = original.clone();
    oversized[data_at + 40..data_at + 44].copy_from_slice(&(1u32 << 20).to_le_bytes());
    refresh(&mut oversized[data_at..data_at + data_len]);
    let path = write_image(&scratch, "oversized.ubifs", &oversized);
    let report = extract(&path, At::default(), &[], &scratch.join("b"), &[], Limits::default()).unwrap().report;
    assert!(report.skipped.iter().any(|skip| skip.path == "etc/device.conf"), "{:?}", report.skipped);
    // An inode claiming a terabyte: listed as stored, refused by the per-file limit when read.
    let (inode_at, inode_len) = keyed(&original, 0, conf);
    let mut huge = original.clone();
    huge[inode_at + 48..inode_at + 56].copy_from_slice(&(1u64 << 40).to_le_bytes());
    refresh(&mut huge[inode_at..inode_at + inode_len]);
    let path = write_image(&scratch, "huge.ubifs", &huge);
    let selection = ["etc/device.conf".to_owned()];
    let error = extract(&path, At::default(), &[], &scratch.join("c"), &selection, Limits::default()).unwrap_err();
    assert!(error.to_string().contains("max_file_bytes"), "{error}");
    // The superblock's CRC, and a master node pointing outside the image.
    let mut superblock = original.clone();
    superblock[100] ^= 1;
    let error = listed(&write_image(&scratch, "sb.ubifs", &superblock)).unwrap_err();
    assert!(error.contains("superblock fails its CRC"), "{error}");
    let mut master = original.clone();
    for copy in [LEB, 2 * LEB] {
        master[copy + 48..copy + 52].copy_from_slice(&9999u32.to_le_bytes());
        refresh(&mut master[copy..copy + 512]);
    }
    let error = listed(&write_image(&scratch, "master.ubifs", &master)).unwrap_err();
    assert!(error.contains("outside the LEBs"), "{error}");
}

#[test]
fn truncated_ubi_and_ubifs_images_are_never_clean() {
    let scratch = Scratch::new("ubi-truncated");
    for (name, keep) in [
        ("ubifs-lzo.ubifs", 3000),
        ("ubifs-lzo.ubifs", 2 * LEB + 100),
        ("ubifs-lzo.ubifs", 12 * LEB),
        ("ubifs-none.ubifs", 15 * LEB),
        ("ubi.img", 100),
        ("ubi.img", 2 * PEB),
        ("ubi.img", 18 * PEB),
    ] {
        let bytes = std::fs::read(fixture(name)).unwrap();
        let path = write_image(&scratch, &format!("{keep}-{name}"), &bytes[..keep]);
        let chain: &[&[String]] = if name == "ubi.img" { &[&[], &["rootfs.img".to_owned()]] } else { &[&[]] };
        let mut clean = true;
        for (index, inner) in chain.iter().enumerate() {
            let out = scratch.join(&format!("{keep}-{name}-{index}.out"));
            let listed = list(&path, At::default(), inner, Limits::default());
            let extracted = extract(&path, At::default(), inner, &out, &[], Limits::default());
            // A UBIFS extraction always skips its device node.
            let expected = u64::from(name.ends_with(".ubifs") || !inner.is_empty());
            clean &= listed.is_ok() && extracted.is_ok_and(|extraction| extraction.report.skipped_total <= expected);
        }
        assert!(!clean, "{name} truncated to {keep} bytes was accepted");
    }
}

/// `image` with every UBI header and volume table record given a fresh CRC.
fn refresh_ubi(image: &mut [u8]) {
    for peb in (0..image.len() / PEB).map(|index| index * PEB) {
        for (at, magic) in [(peb, b"UBI#"), (peb + 512, b"UBI!")] {
            if &image[at..at + 4] == magic {
                let crc = crc(&image[at..at + 60]);
                image[at + 60..at + 64].copy_from_slice(&crc.to_be_bytes());
            }
        }
        if &image[peb + 512..peb + 516] == b"UBI!" && be32(image, peb + 520) == 0x7fff_efff {
            for record in (0..LEB / 172).map(|index| peb + 1024 + index * 172) {
                let crc = crc(&image[record..record + 168]);
                image[record + 168..record + 172].copy_from_slice(&crc.to_be_bytes());
            }
        }
    }
}

/// [`refresh_ubi`], with the UBIFS nodes inside each eraseblock and the data CRCs of static LEBs repaired first.
fn refresh_ubi_deep(image: &mut [u8]) {
    for peb in (0..image.len() / PEB).map(|index| index * PEB) {
        refresh_ubifs(&mut image[peb + 1024..peb + PEB]);
        if &image[peb + 512..peb + 516] == b"UBI!" && (image[peb + 517] == 2 || image[peb + 518] != 0) {
            let size = (be32(image, peb + 532) as usize).min(LEB);
            let crc = crc(&image[peb + 1024..peb + 1024 + size]);
            image[peb + 544..peb + 548].copy_from_slice(&crc.to_be_bytes());
        }
    }
    refresh_ubi(image);
}

fn refresh_ubifs(image: &mut [u8]) {
    for (at, _, len) in nodes(image) {
        refresh(&mut image[at..at + len]);
    }
}

#[test]
fn a_newer_copy_of_a_leb_wins_unless_its_data_is_damaged() {
    let original = std::fs::read(fixture("ubi.img")).unwrap();
    // The PEB holding LEB 0 of the static volume.
    let peb = (0..original.len() / PEB)
        .map(|index| index * PEB)
        .find(|peb| {
            &original[peb + 512..peb + 516] == b"UBI!"
                && be32(&original, peb + 520) == 1
                && be32(&original, peb + 524) == 0
        })
        .unwrap();
    let squash = |image: &[u8]| {
        let scratch = Scratch::new("ubi-dup");
        let path = write_image(&scratch, "dup.img", image);
        let out = scratch.join("out");
        extract(&path, At::default(), &[], &out, &["squash.img".to_owned()], Limits::default()).unwrap();
        (read_out(&out.join("squash.img")), listed(&path).unwrap().layers[0].notes.clone())
    };
    let (expected, _) = squash(&original);
    let copy = |sqnum_bump: u64, change: &dyn Fn(&mut [u8])| {
        let mut block = original[peb..peb + PEB].to_vec();
        let sqnum = u64::from_be_bytes(block[512 + 40..512 + 48].try_into().unwrap()) + sqnum_bump;
        block[512 + 40..512 + 48].copy_from_slice(&sqnum.to_be_bytes());
        change(&mut block);
        block
    };
    // A newer copy whose data fails its CRC: the older copy is read.
    let damaged = copy(1000, &|block| block[2000] ^= 0xff);
    let mut image = [original.clone(), damaged.clone()].concat();
    refresh_ubi(&mut image);
    let (content, notes) = squash(&image);
    assert_eq!(content, expected);
    assert!(notes.iter().any(|note| note.contains("1 older copies of a LEB")), "{notes:?}");
    // A newer intact copy wins over both.
    let newer = copy(2000, &|block| {
        block[2000] ^= 0xff;
        let size = u32::from_be_bytes(block[512 + 20..512 + 24].try_into().unwrap()) as usize;
        let crc = crc(&block[1024..1024 + size]);
        block[512 + 32..512 + 36].copy_from_slice(&crc.to_be_bytes());
    });
    let mut image = [original.clone(), damaged, newer].concat();
    refresh_ubi(&mut image);
    let (content, _) = squash(&image);
    assert_eq!(content.len(), expected.len());
    assert_eq!(content[2000 - 1024], expected[2000 - 1024] ^ 0xff);
}

#[test]
fn ubi_forgeries_are_refused_or_bounded() {
    let original = std::fs::read(fixture("ubi.img")).unwrap();
    let scratch = Scratch::new("ubi-forged");
    let layout = |image: &[u8]| -> Vec<usize> {
        (0..image.len() / PEB).map(|index| index * PEB).filter(|peb| be32(image, peb + 520) == 0x7fff_efff).collect()
    };
    // Both copies of the volume table damaged.
    let mut table = original.clone();
    for peb in layout(&table) {
        table[peb + 1024 + 20] ^= 1;
    }
    let error = listed(&write_image(&scratch, "table.img", &table)).unwrap_err();
    assert!(error.contains("volume table"), "{error}");
    // A static volume claiming 4 billion LEBs: bounded by the table's reservation.
    let mut used = original.clone();
    for peb in (0..used.len() / PEB).map(|index| index * PEB) {
        if be32(&used, peb + 520) == 1 {
            used[peb + 512 + 24..peb + 512 + 28].copy_from_slice(&u32::MAX.to_be_bytes());
        }
    }
    refresh_ubi(&mut used);
    let path = write_image(&scratch, "used.img", &used);
    let listing = listed(&path).unwrap();
    assert!(
        listing.entries[1].note.as_deref().unwrap().contains("more than the 2 reserved"),
        "{:?}",
        listing.entries[1]
    );
    assert_eq!(listing.entries[1].size, listed(&fixture("ubi.img")).unwrap().entries[1].size);
    // A first eraseblock whose header is damaged (a bad block at the start of a raw dump): the size is found from
    // the next intact one, and the second copy of the volume table serves.
    let mut first = original.clone();
    first[10] ^= 1;
    let listing = listed(&write_image(&scratch, "first.img", &first)).unwrap();
    assert_eq!(listing.entries.len(), 2);
    assert!(
        listing.layers[0].notes.iter().any(|note| note.contains("1 with damaged headers")),
        "{:?}",
        listing.layers[0].notes
    );
    let mut erased = original.clone();
    erased[..PEB].fill(0xff);
    erased[..4].copy_from_slice(b"UBI#");
    assert_eq!(
        listed(&write_image(&scratch, "erased.img", &erased)).unwrap().layers[0].notes[0],
        "eraseblock size 16384"
    );
    // A header whose data offset leaves no room.
    let mut offsets = original.clone();
    for peb in (0..offsets.len() / PEB).map(|index| index * PEB) {
        offsets[peb + 20..peb + 24].copy_from_slice(&15_000u32.to_be_bytes());
    }
    refresh_ubi(&mut offsets);
    assert!(listed(&write_image(&scratch, "offsets.img", &offsets)).is_err());
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }
}

/// Mutates `original` a few bytes and fields at a time, then repairs the checksums, so the mutations reach the
/// structure behind them; every mutated image is opened, descended into and read in full.
fn fuzz(name: &str, inner: &[String], cases: usize, seed: u64, repair: fn(&mut [u8])) {
    let original = std::fs::read(fixture(name)).unwrap();
    let mut rng = Rng(seed);
    let limits = Limits { max_total_bytes: 64 << 20, max_file_bytes: 16 << 20, ..Limits::default() };
    let mut opened = 0;
    for _ in 0..cases {
        let mut bytes = original.clone();
        for _ in 0..1 + rng.below(4) {
            let at = rng.below(bytes.len() - 8);
            match rng.below(4) {
                0 => bytes[at] ^= 1 << rng.below(8),
                1 => bytes[at] = rng.next() as u8,
                2 => {
                    let value = [0u32, 1, 0x7fff_ffff, 0xffff_ffff, 0x8000_0000, 4096][rng.below(6)];
                    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
                }
                _ => {
                    let value = [0u32, 1, 0x7fff_ffff, 0xffff_ffff, 16384][rng.below(5)];
                    bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
                }
            }
        }
        if rng.below(3) == 0 {
            // Shorten one UBIFS node's length field; the repair gives it a matching CRC, so the readers see a
            // well-formed node too short for its type.
            let starts: Vec<usize> =
                (0..bytes.len() - 24).step_by(8).filter(|at| bytes[*at..*at + 4] == MAGIC).collect();
            if !starts.is_empty() {
                let at = starts[rng.below(starts.len())];
                let len = le32(&bytes, at + 16) as usize;
                if len > 24 {
                    let shorter = (24 + rng.below(len - 24)) as u32;
                    bytes[at + 16..at + 20].copy_from_slice(&shorter.to_le_bytes());
                }
            }
        }
        if rng.below(10) == 0 {
            bytes.truncate(rng.below(bytes.len()).max(1));
        }
        repair(&mut bytes);
        let source: Source = Arc::new(bytes);
        let mut budget = Budget::new(limits);
        let Ok(image) = open_chain(source, inner, &mut budget) else { continue };
        opened += 1;
        for index in 0..image.image.entries().len() {
            let mut total = 0u64;
            let _ = image.image.read(index, &mut budget, &mut |chunk| {
                total += chunk.len() as u64;
                Ok(())
            });
            assert!(total <= limits.max_file_bytes);
        }
    }
    assert!(opened > cases / 10, "{name}: only {opened} of {cases} mutated images opened");
}

#[test]
fn ubifs_survives_crc_preserving_mutation() {
    fuzz("ubifs-lzo.ubifs", &[], 300, 21, refresh_ubifs);
    fuzz("ubifs-zstd.ubifs", &[], 150, 22, refresh_ubifs);
    fuzz("ubifs-none.ubifs", &[], 150, 23, refresh_ubifs);
}

#[test]
fn ubi_survives_crc_preserving_mutation() {
    fuzz("ubi.img", &[], 300, 24, refresh_ubi);
    fuzz("ubi.img", &[], 150, 25, refresh_ubi_deep);
    // Through the volumes into the UBIFS and the SquashFS inside them.
    fuzz("ubi.img", &["rootfs.img".to_owned()], 200, 26, refresh_ubi_deep);
    fuzz("ubi.img", &["squash.img".to_owned()], 100, 27, refresh_ubi_deep);
    fuzz("ubi.img", &[], 100, 28, |_| {});
}

/// Eraseblock size of the synthetic UBIFS images: 8 LEBs of 16 KiB.
const SYNTH_LEB: usize = 16384;

/// A minimal UBIFS image: a superblock with `flags`, a master node in LEB 1 naming `root`, a commit start node in
/// the log (LEB 3), and `nodes` placed at (LEB, offset).
fn synthetic(flags: u32, root: (u32, u32, u32), nodes: &[(usize, usize, Vec<u8>)]) -> Vec<u8> {
    let mut image = vec![0xff; SYNTH_LEB * 8];
    let mut sb = vec![0u8; 4096 - 24];
    sb[28 - 24..32 - 24].copy_from_slice(&flags.to_le_bytes());
    for (at, value) in [(32, 8u32), (36, SYNTH_LEB as u32), (40, 8), (44, 8), (56, 1), (80, 4)] {
        sb[at - 24..at - 20].copy_from_slice(&value.to_le_bytes());
    }
    let mut master = vec![0u8; 512 - 24];
    for (at, value) in [(44, 3u32), (48, root.0), (52, root.1), (56, root.2)] {
        master[at - 24..at - 20].copy_from_slice(&value.to_le_bytes());
    }
    let mut placed = vec![(0, 0, node(6, 1, &sb)), (1, 0, node(7, 2, &master)), (3, 0, node(10, 3, &[0; 8]))];
    placed.extend(nodes.iter().cloned());
    for (lnum, offs, bytes) in placed {
        let at = lnum * SYNTH_LEB + offs;
        image[at..at + bytes.len()].copy_from_slice(&bytes);
    }
    image
}

fn inode(inum: u32, mode: u32, size: u64, data: &[u8]) -> Vec<u8> {
    let mut body = key(inum, 0, 0);
    body.resize(160 - 24, 0);
    body[48 - 24..56 - 24].copy_from_slice(&size.to_le_bytes());
    body[92 - 24..96 - 24].copy_from_slice(&1u32.to_le_bytes());
    body[104 - 24..108 - 24].copy_from_slice(&mode.to_le_bytes());
    body[112 - 24..116 - 24].copy_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend(data);
    node(0, 10, &body)
}

fn entry(parent: u32, name: &[u8], inum: u32) -> Vec<u8> {
    let mut body = key(parent, 2, name.len() as u32);
    body.extend(u64::from(inum).to_le_bytes());
    body.extend([0, 0]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend([0; 4]);
    body.extend(name);
    body.push(0);
    node(2, 11, &body)
}

/// An index branch: (LEB, offset, the node it names, key inode, key type, key value).
type Branch<'a> = (u32, u32, &'a [u8], u32, u32, u32);

/// A level-0 index node over `branches`.
fn index(branches: &[Branch]) -> Vec<u8> {
    let mut body = (branches.len() as u16).to_le_bytes().to_vec();
    body.extend(0u16.to_le_bytes());
    for (lnum, offs, node, inum, kind, value) in branches {
        body.extend(lnum.to_le_bytes());
        body.extend(offs.to_le_bytes());
        body.extend((node.len() as u32).to_le_bytes());
        body.extend(&key(*inum, *kind, *value)[..8]);
    }
    node(9, 20, &body)
}

/// Writes `image` and lists it, on a thread so a panic is reported as one.
fn list_synthetic(name: &str, image: &[u8]) -> Result<rampage_unpack::Listing, String> {
    let scratch = Scratch::new("synthetic");
    let path = write_image(&scratch, name, image);
    std::thread::spawn(move || list(&path, At::default(), &[], Limits::default()).map_err(|error| error.to_string()))
        .join()
        .expect("listing must not panic")
}

/// A root directory holding one regular file `f` of `size` bytes whose block 0 is `data`, plus `extra` index
/// branches and nodes.
fn one_file(flags: u32, data: Vec<u8>, size: u64) -> Vec<u8> {
    let (root_dir, file, dent) = (inode(1, 0o40755, 0, &[]), inode(2, 0o100644, size, &[]), entry(1, b"f", 2));
    let idx = index(&[
        (4, 0, &root_dir, 1, 0, 0),
        (4, 512, &dent, 1, 2, 1),
        (4, 1024, &file, 2, 0, 0),
        (4, 2048, &data, 2, 1, 0),
    ]);
    let nodes = [
        (4, 0, root_dir.clone()),
        (4, 512, dent.clone()),
        (4, 1024, file.clone()),
        (4, 2048, data),
        (5, 0, idx.clone()),
    ];
    synthetic(flags, (5, 0, idx.len() as u32), &nodes)
}

#[test]
fn an_index_node_too_short_for_its_branches_is_refused() {
    let short = node(9, 3, &[]);
    let image = synthetic(0, (4, 0, 24), &[(4, 0, short)]);
    let error = list_synthetic("short-idx.ubifs", &image).unwrap_err();
    assert!(error.contains("outside 28"), "{error}");
}

#[test]
fn short_data_nodes_are_refused_in_the_journal_and_the_index() {
    // Indexed: a 24-byte data node is refused when the file is read, not when its fields are.
    let image = one_file(0, node(1, 12, &[]), 10);
    let scratch = Scratch::new("short-data");
    let path = write_image(&scratch, "short.ubifs", &image);
    // Its only file failing, the extraction is an error naming the reason.
    let error = extract(&path, At::default(), &[], &scratch.join("out"), &[], Limits::default()).unwrap_err();
    assert!(error.to_string().contains("outside 48"), "{error}");
    // In the journal: a log reference to a bud whose first node is a 24-byte data node.
    let mut reference = 6u32.to_le_bytes().to_vec();
    reference.extend([0; 36]);
    let mut image = one_file(
        0,
        {
            let mut body = key(2, 1, 0);
            body.extend([0; 8]);
            node(1, 12, &body)
        },
        0,
    );
    for (at, bytes) in [(3 * SYNTH_LEB + 32, node(8, 30, &reference)), (6 * SYNTH_LEB, node(1, 31, &[]))] {
        image[at..at + bytes.len()].copy_from_slice(&bytes);
    }
    let listing = list_synthetic("short-journal.ubifs", &image).unwrap();
    assert!(listing.layers[0].notes.iter().any(|note| note.contains("damaged node")), "{:?}", listing.layers[0].notes);
}

#[test]
fn index_branches_repeating_a_leaf_are_refused_quickly() {
    // 700 branches naming one 4 KiB inode would read and sum it 700 times (52,000 in a 1 MiB index node).
    let big = inode(1, 0o40755, 0, &[0x41; 4096]);
    let branches: Vec<_> = (0..700).map(|_| (4u32, 0u32, big.as_slice(), 1u32, 0u32, 0u32)).collect();
    let idx = index(&branches);
    let image = synthetic(0, (5, 0, idx.len() as u32), &[(4, 0, big.clone()), (5, 0, idx)]);
    let started = std::time::Instant::now();
    let error = list_synthetic("fanout.ubifs", &image).unwrap_err();
    assert!(error.contains("reaches the leaf node at LEB 4 offset 0 twice"), "{error}");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn a_master_slot_of_the_wrong_length_is_not_read_whole() {
    let file = node(1, 12, &{
        let mut body = key(2, 1, 0);
        body.extend(4u32.to_le_bytes());
        body.extend([0; 4]);
        body.extend(b"data");
        body
    });
    let mut image = one_file(0, file, 4);
    let good = image[SYNTH_LEB..SYNTH_LEB + 512].to_vec();
    // LEB 1 starts with a 4 KiB "master" node; LEB 2 holds the real one.
    let mut long = good[24..].to_vec();
    long.resize(4096 - 24, 0);
    let long = node(7, 99, &long);
    image[SYNTH_LEB..SYNTH_LEB + long.len()].copy_from_slice(&long);
    image[2 * SYNTH_LEB..2 * SYNTH_LEB + 512].copy_from_slice(&good);
    let listing = list_synthetic("master.ubifs", &image).unwrap();
    assert_eq!(listing.entries[0].path, "f");
    image[2 * SYNTH_LEB..2 * SYNTH_LEB + 512].fill(0xff);
    assert!(list_synthetic("no-master.ubifs", &image).unwrap_err().contains("no intact master node"));
}

#[test]
fn superblock_flags_follow_ubifs_media_h() {
    let data = node(1, 12, &{
        let mut body = key(2, 1, 0);
        body.extend([0; 8]);
        body
    });
    let notes =
        |flags| list_synthetic("flags.ubifs", &one_file(flags, data.clone(), 0)).unwrap().layers[0].notes.clone();
    let has = |notes: &[String], text: &str| notes.iter().any(|note| note.contains(text));
    // 0x08 is double hashing, which changes nothing here.
    let plain = notes(0x08);
    assert!(!has(&plain, "encryption") && !has(&plain, "authenticated"), "{plain:?}");
    assert!(has(&notes(0x10), "encryption enabled"));
    assert!(has(&notes(0x20), "authenticated"));
}

#[test]
fn directory_entries_with_unsafe_names_are_skipped() {
    let (root_dir, file) = (inode(1, 0o40755, 0, &[]), inode(2, 0o100644, 0, &[]));
    let names: [&[u8]; 5] = [b"ok", b"a/b", b"..", b".", b"nul\0x"];
    let dents: Vec<Vec<u8>> = names.iter().map(|name| entry(1, name, 2)).collect();
    let mut branches = vec![(4u32, 0u32, root_dir.as_slice(), 1u32, 0u32, 0u32), (4, 512, file.as_slice(), 2, 0, 0)];
    let mut nodes = vec![(4, 0, root_dir.clone()), (4, 512, file.clone())];
    for (index, dent) in dents.iter().enumerate() {
        let offs = 1024 + index * 128;
        branches.push((4, offs as u32, dent.as_slice(), 1, 2, index as u32));
        nodes.push((4, offs, dent.clone()));
    }
    let idx = index(&branches);
    nodes.push((5, 0, idx.clone()));
    let listing = list_synthetic("names.ubifs", &synthetic(0, (5, 0, idx.len() as u32), &nodes)).unwrap();
    let paths: Vec<&str> = listing.entries.iter().map(|entry| entry.path.as_str()).collect();
    assert_eq!(paths, ["ok"]);
    assert!(
        listing.layers[0].notes.iter().any(|note| note.starts_with("4 directory entries skipped")),
        "{:?}",
        listing.layers[0].notes
    );
}

#[test]
fn ubi_volume_names_stay_unique_and_used_ebs_disagreements_are_noted() {
    let mut image = std::fs::read(fixture("ubi.img")).unwrap();
    // Volume 0 named "volume1" and volume 1 unnamed: both would fall back to volume1.img.
    for peb in (0..image.len() / PEB).map(|index| index * PEB) {
        if be32(&image, peb + 520) == 0x7fff_efff {
            let (first, second) = (peb + 1024, peb + 1024 + 172);
            image[first + 14..first + 16].copy_from_slice(&7u16.to_be_bytes());
            image[first + 16..first + 24].copy_from_slice(b"volume1\0");
            image[second + 14..second + 16].copy_from_slice(&0u16.to_be_bytes());
            image[second + 16..second + 24].fill(0);
        }
        // LEB 1 of the static volume says it is the only one.
        if be32(&image, peb + 520) == 1 && be32(&image, peb + 524) == 1 {
            image[peb + 512 + 24..peb + 512 + 28].copy_from_slice(&1u32.to_be_bytes());
        }
    }
    refresh_ubi(&mut image);
    let listing = list_synthetic("names.img", &image).unwrap();
    let paths: Vec<&str> = listing.entries.iter().map(|entry| entry.path.as_str()).collect();
    assert_eq!(paths, ["volume1.img", "volume1-2.img"]);
    assert!(listing.entries[1].note.as_deref().unwrap().contains("disagree"), "{:?}", listing.entries[1]);
}
