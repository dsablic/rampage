# Firmware unpacking: listing and extracting filesystem images (2026-11-15)

First slice of the smart-device privacy track (todo.md): device owners can open the filesystems inside their own
firmware so the binaries and configuration in them can be analysed. Without this, nothing else on the privacy list
applies to a TV, camera or speaker.

## Scope of this slice

| Format | Status |
| --- | --- |
| SquashFS 4.0, little-endian: gzip, xz, lzma, lzo, lz4, zstd | done |
| SquashFS 4.0 big-endian | read (backhand's `BE_V4_0`); no fixture, not claimed |
| ext2/3/4 read-only, extents | done |
| Android sparse images, unsparsed virtually, inner filesystem recognised | done |
| Android OTA `payload.bin` (major version 2), full payloads: REPLACE, REPLACE_BZ, REPLACE_XZ, ZERO, DISCARD | done; delta operations refused by name |
| cpio newc/crc, tar (ustar, GNU long names, pax `path`/`linkpath`/`size`) | done |
| UBI volumes (volume table, LEB mapping, duplicate LEBs by sequence number and data CRC) | done (2026-11-18) |
| UBIFS in a UBI volume or a bare LEB dump: index walk, journal replay, none/LZO/zlib/zstd | done (2026-11-18); xattrs and fscrypt not read |
| Vendor-variant SquashFS (AVM, LZMA variants, 3.x) | open |

Nesting works through an `inner` chain of entry paths: sparse → ext4 is automatic, OTA → partition → ext4 or
SquashFS, UBI → volume → UBIFS or SquashFS, an image file inside an archive inside an archive, up to 4 layers.

## Borrow before building

| Need | Choice | Licence | Why |
| --- | --- | --- | --- |
| SquashFS | `backhand` 0.25 with `default-features = false` (+ `error-strings`) | MIT OR Apache-2.0 | Maintained, already guards directory cycles (visited inodes) and table offsets. Its default codecs build liblzma and zstd from C; instead rampage plugs its own pure-Rust codecs in through `CompressionAction`, which also lets every codec call be bounded and metered. Brings `deku` (+ `bitvec`). |
| ext2/3/4 | `ext4-view` 1.0 | MIT OR Apache-2.0 | Read-only by design, "invalid data must never panic or loop", no `unsafe`; deps `bitflags`, `crc`. Not `Send` (uses `Rc`), so images are used on one thread per call. |
| zlib | `flate2` (miniz_oxide) | MIT OR Apache-2.0 | Already in the tree. |
| xz, legacy lzma | `lzma-rust2` 0.25 (`std`, `xz`; no `optimization`, so `forbid(unsafe_code)`) | Apache-2.0 | Maintained port of XZ for Java with BCJ filters and a memory limit (128 MiB here). |
| lz4 block | `lz4_flex` 0.11 (`safe-decode`) | MIT | Safe decoder into a bounded buffer. |
| zstd | `ruzstd` 0.9 | MIT | Already in the tree (via `object`). |
| LZO1X | `lzo` 0.1 | Apache-2.0 | `forbid(unsafe_code)`, bounds-checked, fuzz-hardened decoder. Chosen over `rust-lzo` (machine-translated C with `unsafe`) and `lzokay-native` (`unsafe`). |
| bzip2 | `bzip2-rs` 0.1 | MIT OR Apache-2.0 | Small pure-Rust decoder. `bzip2` 0.6's pure-Rust backend (`libbz2-rs-sys`) is heavier and under the bzip2 licence. |
| Android sparse | own (≈200 lines) | — | `android-sparse-image` has headers only; the format is a chunk list. |
| OTA payload | own (≈450 lines with a protobuf field reader) | — | `payload_dumper` brings tokio, prost and a CLI; the manifest needs five messages. |
| cpio, tar | own | — | Listing and slicing needs a few hundred lines; `tar` and `cpio` add `filetime`/writers. |
| UBI, UBIFS | own (≈450 and ≈650 lines) | — | Written from the `ubi-media.h`/`ubifs-media.h` layouts; no code from ubi_reader (GPL-3.0) or the kernel. The `ubifs` crate (MIT, 0.1) was not taken: new and unproven, and the reader needs rampage's bounds, ratio metering and journal replay. CRC-32 through flate2's `Crc`; codecs already in the tree. |

binwalk v3 (MIT, Rust) recognises far more formats but extracts by running external tools; rampage does not
depend on anything being installed. It stays a recognition reference. Nothing here builds or links C.
Evaluated as a library dependency on 2026-11-18 and rejected: it always pulls in C (`bzip2-sys`, `lzma-sys`) and
font/graphics crates, needs the whole file in memory, and has no time budget. It is slow on repeated magics
(11.8 s for 20 MB of gzip headers). The details are in todo.md under "Binwalk and unblob".

## Design

- Crate `rampage-unpack`: a `ReadAt` source (file range, temporary file, memory, sparse view), an `Image` trait
  (entries plus streamed content), one reader per format, and the safe extractor. `rampage-api` adds the JSON
  layer (`fs_image.rs`).
- Nested images are spooled into unlinked temporary files, never held whole in memory. Sparse images are not
  materialised at all: reads map through the chunk list. OTA partitions are rebuilt into a temporary file with
  every operation's data SHA-256 and the partition SHA-256 checked.
- MCP: two tools in the existing `carve` group rather than a new group, with short descriptions (the catalog is
  near the harness budget): `fs_list` and `fs_extract`. Extracted files are ordinary paths, so every binary tool
  opens them; `fs_extract` returns the executables it wrote. Opening a filesystem image as a binary now answers
  with the filesystem tools instead of the headerless-image guidance.

## Hostile input

- Paths: components `..`, empty and NUL are refused per entry (skipped with a reason); a leading `/` is dropped.
  Every directory on the way must be a real directory, files are created `O_CREAT | O_EXCL` (never through an
  existing name or symlink), and `output_dir` must be new or empty.
- Symlinks are created last, only when their target resolves lexically inside the output root (absolute targets
  are rewritten relative to it) and no parent component is a symlink. They are never followed.
- Device nodes, FIFOs and sockets are never written; files are 0644 or 0755, never setuid, setgid or sticky.
- Caps: total output (4 GiB default, 64 GiB ceiling), entries written (100,000), per file (2 GiB), compression
  ratio over a call (1000:1 once more than 64 MiB came out), nesting depth (4 layers), entries listed (500,000),
  directory depth (128), OTA manifest (64 MiB), sparse chunks (4,000,000), SquashFS tables decompressed while
  opening (256 MiB). Every codec call has an output limit
  (8 KiB SquashFS metadata, the block size for data, the extent size for OTA operations).
- Header arithmetic is checked; each reader has a deterministic mutation-fuzz test that must not panic.

## Security review fixes (2026-11-15)

A fresh-context review found the extraction escape-safe and these gaps, fixed in a follow-up commit:

- backhand builds the SquashFS tree recursively, one frame per directory level; an 8,000-level image aborted the
  process on a 2 MiB thread. rampage now walks the directory table first with an explicit stack (depth 128,
  directory count capped, cycles refused) and only then lets backhand build the tree.
- OTA ZERO extents could overlap and were never charged: a 554-byte payload wrote 4 GiB. Extents of a partition
  must not overlap, operation and extent counts are capped by the partition's blocks (checked before any operation
  is kept), and the rebuild is charged to `max_bytes`.
- Synthesised bytes (sparse fills, OTA zeros, SquashFS sparse blocks, ext holes) count against the ratio with a
  nominal input; `max_ratio` is an `fs_extract` argument.
- A corrupt file is skipped with its reason instead of aborting; only limits abort. ext files must read to their
  size. The SquashFS table budget is reset by a drop guard. Off Unix, `\` and `:` in names are refused.
- `fs_extract` needs an absolute `output_dir`, refuses a symlinked one by name, and is annotated through
  `Effect::FileWrite` on its tool definition.

## Open

- UBIFS extended attributes and fscrypt content; UBI fastmap is ignored (the full scan reads every header, so it is
  not needed); eraseblock sizes that are not powers of two. UBI fixtures come from mtd-utils in a Debian container
  (tests/fixtures/build-ubi-fsimages.sh).
- Vendor SquashFS variants and SquashFS 3.x; carve-driven discovery of images inside vendor containers.
- `carve` does not yet tag ext4, sparse or OTA candidates; `fs_list` with `image_offset` works once an offset is
  known.
- A CLI route (`rampage binary fs-list`/`fs-extract`).
