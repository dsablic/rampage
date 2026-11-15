//! Deterministic mutation fuzzing of every reader: corrupted fixtures must give errors, never panics, hangs or
//! unbounded output. Each case opens the mutated image in memory and reads every entry it lists.

use std::sync::Arc;

use rampage_unpack::{Budget, Limits, Source, open_chain};

use crate::support::fixture;

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

fn mutate(rng: &mut Rng, original: &[u8]) -> Vec<u8> {
    let mut bytes = original.to_vec();
    for _ in 0..1 + rng.below(4) {
        if bytes.len() < 8 {
            break;
        }
        // Most structure is near the start; bias mutations there.
        let span = if rng.below(3) == 0 { bytes.len() } else { bytes.len().min(4096) };
        match rng.below(6) {
            0 => {
                let at = rng.below(span);
                bytes[at] ^= 1 << rng.below(8);
            }
            1 => {
                let at = rng.below(span);
                bytes[at] = rng.next() as u8;
            }
            2 => {
                // A 32-bit field set to an extreme value.
                let at = rng.below(span.saturating_sub(4));
                let value = [0u32, 1, 0x7fff_ffff, 0xffff_ffff, 0x8000_0000][rng.below(5)];
                bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            3 => {
                let keep = rng.below(bytes.len());
                bytes.truncate(keep.max(1));
            }
            4 => {
                let at = rng.below(span.saturating_sub(4));
                let value = [0u32, 1, 0x7fff_ffff, 0xffff_ffff][rng.below(4)];
                bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
            }
            _ => {
                let at = rng.below(span);
                let len = rng.below(64).min(bytes.len() - at);
                bytes[at..at + len].fill(0xff);
            }
        }
    }
    bytes
}

fn fuzz(name: &str, cases: usize, seed: u64) {
    let original = std::fs::read(fixture(name)).unwrap();
    let mut rng = Rng(seed);
    let limits = Limits { max_total_bytes: 64 << 20, max_file_bytes: 16 << 20, ..Limits::default() };
    let (mut opened, mut read) = (0, 0);
    for _ in 0..cases {
        let bytes = mutate(&mut rng, &original);
        let source: Source = Arc::new(bytes);
        let mut budget = Budget::new(limits);
        let Ok(image) = open_chain(source, &[], &mut budget) else { continue };
        opened += 1;
        for index in 0..image.image.entries().len() {
            let mut total = 0u64;
            if image
                .image
                .read(index, &mut budget, &mut |chunk| {
                    total += chunk.len() as u64;
                    Ok(())
                })
                .is_ok()
            {
                read += 1;
            }
            assert!(total <= limits.max_file_bytes);
        }
    }
    // Most mutations leave a readable image: the fuzzing reaches the readers, not only the magic check.
    assert!(opened > 0, "{name}: no mutated image opened");
    let _ = read;
}

#[test]
fn squashfs_survives_mutation() {
    fuzz("squashfs-gzip.img", 400, 1);
    fuzz("squashfs-xz.img", 200, 2);
    fuzz("squashfs-lz4.img", 150, 3);
    fuzz("squashfs-lzo.img", 150, 4);
    fuzz("squashfs-zstd.img", 150, 5);
}

#[test]
fn ext_survives_mutation() {
    fuzz("ext4.img", 300, 6);
    fuzz("ext2.img", 150, 7);
}

#[test]
fn android_sparse_survives_mutation() {
    fuzz("ext4.simg", 300, 8);
    fuzz("pattern.simg", 200, 9);
}

#[test]
fn ota_payload_survives_mutation() {
    fuzz("payload.bin", 400, 10);
    fuzz("delta.bin", 200, 11);
}

#[test]
fn cpio_and_tar_survive_mutation() {
    fuzz("rootfs.cpio", 400, 12);
    fuzz("rootfs.tar", 400, 13);
}
