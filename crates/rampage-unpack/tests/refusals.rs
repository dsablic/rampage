//! Hostile input: traversal, symlink escapes, device nodes, decompression bombs, truncation, delta payloads and
//! limits.

use rampage_unpack::{At, Limits, extract, list};

use crate::support::{Scratch, fixture};

/// One ustar member.
fn member(name: &str, kind: u8, link: &str, data: &[u8], mode: u32) -> Vec<u8> {
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..107].copy_from_slice(format!("{mode:07o}").as_bytes());
    header[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
    header[156] = kind;
    header[157..157 + link.len()].copy_from_slice(link.as_bytes());
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[148..156].copy_from_slice(b"        ");
    let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    let mut out = header.to_vec();
    out.extend(data);
    out.resize(out.len().div_ceil(512) * 512, 0);
    out
}

fn tar(members: &[Vec<u8>]) -> Vec<u8> {
    let mut out: Vec<u8> = members.concat();
    out.extend([0u8; 1024]);
    out
}

#[test]
fn traversal_absolute_paths_and_special_files_are_contained() {
    let scratch = Scratch::new("traversal");
    let archive = scratch.join("evil.tar");
    std::fs::write(
        &archive,
        tar(&[
            member("../escape.txt", b'0', "", b"outside", 0o644),
            member("a/../../escape2.txt", b'0', "", b"outside", 0o644),
            member("/abs/inside.txt", b'0', "", b"inside", 0o4755),
            member("fifo", b'6', "", b"", 0o644),
            member("node", b'3', "", b"", 0o644),
        ]),
    )
    .unwrap();
    let out = scratch.join("out");
    let report = extract(&archive, At::default(), &[], &out, &[], Limits::default()).unwrap().report;
    assert!(!scratch.join("escape.txt").exists() && !scratch.0.parent().unwrap().join("escape2.txt").exists());
    assert_eq!(std::fs::read(out.join("abs/inside.txt")).unwrap(), b"inside");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(out.join("abs/inside.txt")).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o755);
    }
    let reasons: Vec<(&str, &str)> =
        report.skipped.iter().map(|skip| (skip.path.as_str(), skip.reason.as_str())).collect();
    assert!(reasons.iter().filter(|(_, reason)| reason.contains("traversal")).count() == 2, "{reasons:?}");
    assert!(reasons.contains(&("fifo", "FIFO not written")), "{reasons:?}");
    assert!(reasons.contains(&("node", "device node not written")), "{reasons:?}");
    assert!(!out.join("fifo").exists() && !out.join("node").exists());
    assert_eq!(report.files, 1);
}

#[test]
fn symlinks_never_escape_and_are_never_written_through() {
    let scratch = Scratch::new("symlinks");
    let archive = scratch.join("links.tar");
    std::fs::write(
        &archive,
        tar(&[
            member("up", b'2', "../../outside", b"", 0o777),
            member("abs", b'2', "/etc/passwd", b"", 0o777),
            member("here", b'2', ".", b"", 0o777),
            // `here` is a symlink, so this link would land at the root with a target leaving it.
            member("here/x/climb", b'2', "../../escaped", b"", 0o777),
            member("here/sneak", b'2', "../outside", b"", 0o777),
            // A file below a name that is also a symlink: the file comes first, then the symlink is refused.
            member("dir", b'5', "", b"", 0o755),
            member("dir/file", b'0', "", b"data", 0o644),
            member("dir", b'2', "/tmp", b"", 0o777),
        ]),
    )
    .unwrap();
    let out = scratch.join("out");
    let report = extract(&archive, At::default(), &[], &out, &[], Limits::default()).unwrap().report;
    let skipped = |path: &str| report.skipped.iter().find(|skip| skip.path == path).map(|skip| skip.reason.clone());
    assert!(skipped("up").unwrap().contains("escapes"));
    // Absolute targets are rewritten relative to the root: never the host's /etc/passwd.
    assert_eq!(std::fs::read_link(out.join("abs")).unwrap(), std::path::Path::new("etc/passwd"));
    assert_eq!(std::fs::read_link(out.join("here")).unwrap(), std::path::Path::new("."));
    assert!(skipped("here/x/climb").is_some(), "{:?}", report.skipped);
    assert!(skipped("here/sneak").is_some(), "{:?}", report.skipped);
    assert!(!out.join("sneak").exists() && !out.join("climb").exists());
    assert_eq!(std::fs::read(out.join("dir/file")).unwrap(), b"data");
    assert!(skipped("dir").is_some());
    assert!(std::fs::symlink_metadata(out.join("dir")).unwrap().is_dir());
}

#[test]
fn output_must_be_new_or_empty() {
    let scratch = Scratch::new("output");
    let out = scratch.join("out");
    std::fs::create_dir(&out).unwrap();
    std::fs::write(out.join("planted"), b"x").unwrap();
    let error = extract(&fixture("rootfs.tar"), At::default(), &[], &out, &[], Limits::default()).unwrap_err();
    assert!(error.to_string().contains("new or empty"), "{error}");
    let missing = extract(&fixture("rootfs.tar"), At::default(), &[], &scratch.join("a/b"), &[], Limits::default());
    assert!(missing.is_err(), "the parent of output_dir must exist");
}

#[test]
fn a_decompression_bomb_is_refused() {
    // 80 MiB of zeros in one REPLACE_XZ operation of a few kilobytes.
    let payload = fixture("bomb.bin");
    assert!(std::fs::metadata(&payload).unwrap().len() < 80 << 10);
    let scratch = Scratch::new("bomb");
    let error =
        extract(&payload, At::default(), &[], &scratch.join("out"), &[], Limits::default()).unwrap_err().to_string();
    assert!(error.contains("decompression bomb"), "{error}");
    let error = list(&payload, At::default(), &["bomb.img".to_owned()], Limits::default()).unwrap_err().to_string();
    assert!(error.contains("decompression bomb"), "{error}");
    // A ratio limit high enough lets the same payload through.
    let generous = Limits { max_ratio: 100_000, ..Limits::default() };
    let report = extract(&payload, At::default(), &[], &scratch.join("ok"), &[], generous).unwrap().report;
    assert_eq!(report.bytes, 80 << 20);
}

#[test]
fn size_and_count_limits_refuse_the_extraction() {
    let scratch = Scratch::new("limits");
    let few = Limits { max_files: 3, ..Limits::default() };
    let error = extract(&fixture("rootfs.tar"), At::default(), &[], &scratch.join("a"), &[], few).unwrap_err();
    assert!(error.to_string().contains("max_files"), "{error}");
    let small = Limits { max_total_bytes: 1000, ..Limits::default() };
    let error = extract(&fixture("rootfs.tar"), At::default(), &[], &scratch.join("b"), &[], small).unwrap_err();
    assert!(error.to_string().contains("max_bytes"), "{error}");
    let per_file = Limits { max_file_bytes: 100, ..Limits::default() };
    let error =
        extract(&fixture("squashfs-zstd.img"), At::default(), &[], &scratch.join("c"), &[], per_file).unwrap_err();
    assert!(error.to_string().contains("max_file_bytes"), "{error}");
}

#[test]
fn truncated_images_are_errors_not_partial_successes() {
    let scratch = Scratch::new("truncated");
    for (name, keep) in [
        ("squashfs-gzip.img", 1500),
        ("squashfs-xz.img", 2000),
        ("squashfs-lz4.img", 4000),
        ("rootfs.tar", 9000),
        ("rootfs.cpio", 9000),
        ("ext4.simg", 40_000),
        ("payload.bin", 5000),
        ("ext4.img", 3000),
    ] {
        let bytes = std::fs::read(fixture(name)).unwrap();
        let path = scratch.join(name);
        std::fs::write(&path, &bytes[..keep]).unwrap();
        let listed = list(&path, At::default(), &[], Limits::default());
        let extracted =
            extract(&path, At::default(), &[], &scratch.join(&format!("{name}.out")), &[], Limits::default());
        assert!(listed.is_err() || extracted.is_err(), "{name} truncated to {keep} bytes was accepted");
    }
}

#[test]
fn delta_payloads_are_listed_but_refused_clearly() {
    let delta = fixture("delta.bin");
    let listing = list(&delta, At::default(), &[], Limits::default()).unwrap();
    assert!(listing.layers[0].notes[0].starts_with("delta payload"), "{:?}", listing.layers[0].notes);
    assert!(listing.entries[0].note.as_deref().unwrap().contains("SOURCE_COPY"));
    let scratch = Scratch::new("delta");
    let error =
        extract(&delta, At::default(), &[], &scratch.join("out"), &[], Limits::default()).unwrap_err().to_string();
    assert!(error.contains("delta update") && error.contains("only full payloads"), "{error}");
    let error = list(&delta, At::default(), &["system.img".to_owned()], Limits::default()).unwrap_err().to_string();
    assert!(error.contains("SOURCE_COPY"), "{error}");
}

#[test]
fn ubi_is_recognised_and_refused_as_not_yet_read() {
    let scratch = Scratch::new("ubi");
    let path = scratch.join("ubi.img");
    std::fs::write(&path, [b"UBI#".to_vec(), vec![0; 60]].concat()).unwrap();
    let error = list(&path, At::default(), &[], Limits::default()).unwrap_err().to_string();
    assert!(error.contains("UBI images are recognised but not read yet"), "{error}");
}
