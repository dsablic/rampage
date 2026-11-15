//! Listing and extraction round trips for every format, and the nesting chains.

use rampage_unpack::{At, EntryKind, Format, Limits, extract, list};

use crate::support::{Scratch, check_tree, fixture};

fn kind_of(listing: &rampage_unpack::Listing, path: &str) -> EntryKind {
    listing.entries.iter().find(|entry| entry.path == path).unwrap_or_else(|| panic!("no {path}")).kind
}

/// Lists and extracts `name`, checking the shared tree.
fn round_trip(name: &str, format: Format, has_device: bool) {
    let path = fixture(name);
    let listing = list(&path, At::default(), &[], Limits::default()).unwrap();
    assert_eq!(listing.layers.last().unwrap().format, format);
    assert_eq!(kind_of(&listing, "etc"), EntryKind::Dir);
    assert_eq!(kind_of(&listing, "bin/hello"), EntryKind::File);
    assert_eq!(kind_of(&listing, "bin/sh"), EntryKind::Symlink);
    assert_eq!(kind_of(&listing, "usr/share/demo/nested/deep.txt"), EntryKind::File);
    let sh = listing.entries.iter().find(|entry| entry.path == "bin/sh").unwrap();
    assert_eq!(sh.link.as_deref(), Some("hello"));
    let hello = listing.entries.iter().find(|entry| entry.path == "bin/hello").unwrap();
    assert_eq!(hello.size, crate::support::hello_elf().len() as u64);
    if has_device {
        assert_eq!(kind_of(&listing, "dev/console"), EntryKind::CharDevice);
        assert_eq!(hello.mode, 0o4755, "listing reports the setuid bit as stored");
    }
    let scratch = Scratch::new(name);
    let out = scratch.join("out");
    let extraction = extract(&path, At::default(), &[], &out, &[], Limits::default()).unwrap();
    check_tree(&out, &extraction.report, has_device);
}

#[test]
fn squashfs_with_every_mksquashfs_codec() {
    for codec in ["gzip", "xz", "lzo", "lz4", "zstd"] {
        round_trip(&format!("squashfs-{codec}.img"), Format::Squashfs, true);
        let listing = list(&fixture(&format!("squashfs-{codec}.img")), At::default(), &[], Limits::default()).unwrap();
        let expected = if codec == "gzip" { "compression gzip".to_owned() } else { format!("compression {codec}") };
        assert!(listing.layers[0].notes.contains(&expected), "{:?}", listing.layers[0].notes);
    }
}

#[test]
fn squashfs_with_legacy_lzma_from_the_test_generator() {
    let scratch = Scratch::new("lzma");
    let image = scratch.join("squashfs-lzma.img");
    std::fs::write(&image, crate::generator::squashfs_lzma()).unwrap();
    let listing = list(&image, At::default(), &[], Limits::default()).unwrap();
    assert!(listing.layers[0].notes.contains(&"compression lzma".to_owned()), "{:?}", listing.layers[0].notes);
    let out = scratch.join("out");
    extract(&image, At::default(), &[], &out, &[], Limits::default()).unwrap();
    assert_eq!(std::fs::read(out.join("etc/hostname")).unwrap(), b"demo-device\n");
    assert_eq!(std::fs::read(out.join("data/blocks.bin")).unwrap(), crate::generator::blocks());
}

#[test]
fn ext4_and_ext2() {
    round_trip("ext4.img", Format::Ext, true);
    round_trip("ext2.img", Format::Ext, true);
}

#[test]
fn cpio_and_tar() {
    round_trip("rootfs.cpio", Format::Cpio, false);
    round_trip("rootfs.tar", Format::Tar, false);
}

#[test]
fn android_sparse_unwraps_to_the_ext4_inside() {
    let listing = list(&fixture("ext4.simg"), At::default(), &[], Limits::default()).unwrap();
    let formats: Vec<Format> = listing.layers.iter().map(|layer| layer.format).collect();
    assert_eq!(formats, [Format::AndroidSparse, Format::Ext]);
    assert_eq!(listing.layers[0].size, 512 * 1024);
    round_trip("ext4.simg", Format::Ext, true);
}

#[test]
fn a_sparse_image_of_no_filesystem_lists_the_unsparsed_image() {
    let listing = list(&fixture("pattern.simg"), At::default(), &[], Limits::default()).unwrap();
    assert_eq!(listing.entries.len(), 1);
    assert_eq!(listing.entries[0].kind, EntryKind::Image);
    let scratch = Scratch::new("pattern");
    let out = scratch.join("out");
    extract(&fixture("pattern.simg"), At::default(), &[], &out, &[], Limits::default()).unwrap();
    let mut expected: Vec<u8> = (0..=255u8).cycle().take(8192).collect();
    expected.extend([0u8; 8192]);
    expected.extend([0x5a, 0xa5].repeat(2048));
    assert_eq!(std::fs::read(out.join("unsparsed.img")).unwrap(), expected);
}

#[test]
fn ota_payload_partitions_and_the_filesystems_inside_them() {
    let payload = fixture("payload.bin");
    let listing = list(&payload, At::default(), &[], Limits::default()).unwrap();
    assert_eq!(listing.layers[0].format, Format::OtaPayload);
    assert!(listing.layers[0].notes[0].starts_with("full payload"), "{:?}", listing.layers[0].notes);
    let names: Vec<&str> = listing.entries.iter().map(|entry| entry.path.as_str()).collect();
    assert_eq!(names, ["system.img", "vendor.img"]);
    // OTA → partition → ext4, and OTA → partition → SquashFS.
    let system = list(&payload, At::default(), &["system.img".to_owned()], Limits::default()).unwrap();
    let formats: Vec<Format> = system.layers.iter().map(|layer| layer.format).collect();
    assert_eq!(formats, [Format::OtaPayload, Format::Ext]);
    assert_eq!(system.layers[1].entry.as_deref(), Some("system.img"));
    let vendor = list(&payload, At::default(), &["vendor.img".to_owned()], Limits::default()).unwrap();
    assert_eq!(vendor.layers[1].format, Format::Squashfs);

    let scratch = Scratch::new("ota");
    let partitions = scratch.join("partitions");
    extract(&payload, At::default(), &[], &partitions, &[], Limits::default()).unwrap();
    assert_eq!(std::fs::read(partitions.join("system.img")).unwrap(), std::fs::read(fixture("ext4.img")).unwrap());
    let out = scratch.join("system");
    let extraction =
        extract(&payload, At::default(), &["system.img".to_owned()], &out, &[], Limits::default()).unwrap();
    check_tree(&out, &extraction.report, true);
}

#[test]
fn nesting_reaches_an_image_inside_an_image_inside_a_payload() {
    // tar → payload.bin → system.img → ext4: three nested layers below the archive.
    let scratch = Scratch::new("chain");
    let tar = scratch.join("update.tar");
    let mut header = [0u8; 512];
    let payload = std::fs::read(fixture("payload.bin")).unwrap();
    header[..11].copy_from_slice(b"payload.bin");
    header[100..107].copy_from_slice(b"0000644");
    header[124..135].copy_from_slice(format!("{:011o}", payload.len()).as_bytes());
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[148..156].copy_from_slice(b"        ");
    let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    let mut archive = header.to_vec();
    archive.extend(&payload);
    archive.resize(archive.len().div_ceil(512) * 512 + 1024, 0);
    std::fs::write(&tar, archive).unwrap();
    let inner = ["payload.bin".to_owned(), "system.img".to_owned()];
    let listing = list(&tar, At::default(), &inner, Limits::default()).unwrap();
    let formats: Vec<Format> = listing.layers.iter().map(|layer| layer.format).collect();
    assert_eq!(formats, [Format::Tar, Format::OtaPayload, Format::Ext]);
    let out = scratch.join("out");
    let selection = ["etc".to_owned(), "/bin/hello".to_owned()];
    let extraction = extract(&tar, At::default(), &inner, &out, &selection, Limits::default()).unwrap();
    assert_eq!(std::fs::read(out.join("etc/hostname")).unwrap(), b"demo-device\n");
    assert!(out.join("bin/hello").exists());
    assert!(!out.join("usr").exists(), "only the chosen paths are written");
    assert_eq!(extraction.report.files, 3);
    // The depth limit counts every layer.
    let shallow = Limits { max_depth: 2, ..Limits::default() };
    let refused = list(&tar, At::default(), &inner, shallow).unwrap_err().to_string();
    assert!(refused.contains("nested deeper"), "{refused}");
}

#[test]
fn an_image_at_an_offset_inside_a_larger_file() {
    let scratch = Scratch::new("offset");
    let blob = scratch.join("firmware.bin");
    let mut bytes = b"vendor header ".repeat(37);
    let offset = bytes.len() as u64;
    bytes.extend(std::fs::read(fixture("squashfs-xz.img")).unwrap());
    bytes.extend(b"trailer");
    std::fs::write(&blob, bytes).unwrap();
    let listing = list(&blob, At { offset, length: None }, &[], Limits::default()).unwrap();
    assert_eq!(listing.layers[0].format, Format::Squashfs);
    let image = std::fs::metadata(fixture("squashfs-xz.img")).unwrap().len();
    let exact = At { offset, length: Some(image) };
    assert_eq!(list(&blob, exact, &[], Limits::default()).unwrap().layers[0].size, image);
    assert!(list(&blob, At { offset, length: Some(image + 8) }, &[], Limits::default()).is_err());
    assert!(list(&blob, At::default(), &[], Limits::default()).is_err());
    assert!(rampage_unpack::sniff(&blob).is_none());
    assert_eq!(rampage_unpack::sniff(&fixture("squashfs-xz.img")), Some(Format::Squashfs));
}
