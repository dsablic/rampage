# Firmware filesystem images

Device firmware usually ships its programs and configuration inside filesystem images: SquashFS on routers and
cameras, UBI and UBIFS on raw NAND flash, ext4 and Android sparse images on TVs and set-top boxes, an Android OTA
`payload.bin` for system updates, cpio for an initramfs, ZIP for an Android app (APK) or a packaged update. `fs_list` lists such an image and
`fs_extract` writes its files to a directory, so the binaries inside open as ordinary analysis targets. Both are
file tools in the `carve` group: they take any file path and open no project.

## Formats

| Format | Read |
| --- | --- |
| SquashFS 4.0 | gzip (zlib), xz, lzma, lzo, lz4 and zstd; little-endian (big-endian is read but untested) |
| ext2, ext3, ext4 | read-only, extents included |
| Android sparse image | unsparsed on the fly; the filesystem inside is opened directly. Content that is no filesystem lists as one entry, `unsparsed.img` |
| Android OTA `payload.bin` | major version 2, full payloads: REPLACE, REPLACE_BZ, REPLACE_XZ, ZERO, DISCARD. Partitions list as `<name>.img` |
| cpio | newc (`070701`) and crc (`070702`) |
| tar | ustar, GNU long names, pax `path`, `linkpath` and `size` |
| UBI | raw flash dumps and `ubinize` output, eraseblock size found from the headers (powers of two, 4 KiB to 16 MiB). Volumes list as `<name>.img` (type `image`, noted static or dynamic and with the format inside) and open through `inner`. A LEB written more than once is read from its newest copy whose data CRC checks out; a static volume reads at its data size, a dynamic one up to its last mapped LEB, unmapped LEBs before that as 0xFF |
| UBIFS | in a UBI volume or as a bare dump of its LEBs back to back. The index tree from the newest master node, then the journal written since the last commit replayed over it; data uncompressed, LZO, zlib or zstd; symlinks, hard links (noted, written as copies) and device nodes (`device major:minor`). Extended attributes are not read; fscrypt-encrypted files are listed and not decrypted; authenticated images are read without checking their HMACs |
| ZIP (APK, AAB, JAR) | stored and deflate members, ZIP64; the central directory is authoritative, and inflation stops at a member's declared size; encrypted members and other methods are listed with a note and not read; members whose data overlap another's are noted. [`dex_metadata`](android.md) reads an APK's manifest and DEX files |

A delta OTA payload lists its partitions, each
noted with the first operation that needs the previous build (SOURCE_COPY, BSDIFF, PUFFDIFF, ...); rebuilding one
is refused with that reason, since the payload alone cannot reproduce it. Partition and operation SHA-256 hashes in
the manifest are checked, and a mismatch is an error.

Nothing external runs: every codec is pure Rust, and no extractor needs to be installed.

## Listing

```json
{"path":"update.bin","image_offset":"0x4000","inner":["system.img"],"prefix":"/etc","offset":0,"limit":200}
```

- `image_offset` (default 0) reads an image embedded in a larger file, such as one `carve` or `file_layout`
  found. Hex strings or integers.
- `inner` descends into nested images, outermost first: a partition of an OTA payload (`["system.img"]`), a UBI
  volume (`["rootfs.img"]`, then the UBIFS or SquashFS inside it is listed), an image file inside an archive (`["payload.bin", "vendor.img"]`). Each entry named is spooled into an unlinked temporary
  file. An Android sparse image needs no `inner`: its filesystem is opened directly.
- `prefix` keeps entries at or below one path; `offset`/`limit` page them (limit 1–1000, default 200; a page also
  stops at about 50,000 JSON bytes, with `byte_capped`).

The result has `layers` (each image on the way, outermost first: `format`, `size`, the `entry` it came from, and
`notes` such as the compression, block size or whether a payload is full or delta), `counts` by entry type over
the whole image, `total` entries matching `prefix`, `entries` and `next_offset`. Each entry has its `path` inside
the image (no leading `/`, as stored, not sanitised), `type` (`file`, `dir`, `symlink`, `char_device`,
`block_device`, `fifo`, `socket`, `image` for a partition or volume, `other`), `size`, `mode` (permission bits including
setuid, setgid and sticky, as stored), `uid`, `gid`, `link` (a symlink's target) and `note`.

## Extracting

```json
{"path":"payload.bin","inner":["system.img"],"output_dir":"/tmp/system","paths":["etc","bin/busybox"]}
```

`fs_extract` takes the image as `fs_list` selects it, an absolute `output_dir` that must not exist yet (its parent
must) or be an empty directory (not a symlink to one), and optionally `paths`: entries or directories to write,
default all. The result counts `files`, `dirs`,
`symlinks` and `bytes`, lists `executables` (absolute paths with `format` `elf`, `pe`, `macho`, `dex`, `wasm`, at
most 200; `executables_total` counts all) and `skipped` entries with their reason (at most 200; `skipped_total`),
and echoes the `limits` used. Open an executable by its path with `triage_report` or any binary tool.

Every image is treated as hostile:

- **Paths.** An entry whose path has a `..`, an empty or NUL component is skipped as path traversal; a leading `/`
  is dropped, so absolute paths land under `output_dir`. Every directory on the way must be a real directory, and
  files are created exclusively (`O_CREAT|O_EXCL`), so nothing is written through an existing name or symlink.
  A duplicate name, or one that clashes on a case-insensitive filesystem, is skipped.
- **Symlinks** are created after everything else, only when their target resolves inside `output_dir`; absolute
  targets are rewritten relative to it (`/etc/hostname` from `var/hostname` becomes `../etc/hostname`). A symlink
  below another symlink, or one escaping the root, is skipped. Symlinks are never followed.
- **Special files.** Device nodes, FIFOs and sockets are skipped. Files are written 0755 when any execute bit was
  set, else 0644; directories 0755. No setuid, setgid or sticky bit is ever written.
- **Limits.** `max_bytes` (total written, default 4 GiB, at most 64 GiB; nested images spooled to temporary files
  and OTA partitions rebuilt on the way count too), `max_files` (files, directories and links written, default
  100,000, at most 1,000,000), `max_file_bytes` (any one file or nested image, default 2 GiB, at most 16 GiB) and
  `max_ratio` (default 1000, at most 100,000): once more than 64 MiB has come out, more than `max_ratio` output bytes
  per input byte is refused as a decompression bomb. Bytes that are synthesised rather than decompressed count too,
  against a nominal input: Android sparse fill and don't-care chunks (their 16-byte header), OTA ZERO and DISCARD
  extents (16 bytes each), SquashFS sparse blocks (their 4-byte block-list entry), ext and UBIFS holes (4 KiB per
  file) and unmapped LEBs of a UBI volume (64 bytes each).
  Fixed: at most 4 image layers, 500,000 entries per image, 128 directory levels (checked before backhand builds a
  SquashFS tree), 256 MiB of SquashFS tables, 4,000,000 UBI eraseblocks, and for UBIFS 64 index levels, 4,000,000
  index nodes and 8,000,000 inodes, directory entries and data blocks. Exceeding a limit stops the extraction with an error; files written
  before it stay.
- **Malformed input.** Truncated or inconsistent images are errors, not partial listings. A file whose content
  turns out corrupt (a bad OTA data hash, a broken SquashFS block) is skipped with its reason and its partial file
  removed; when every file fails, the extraction is an error. OTA operations must exactly fill their extents, no two
  extents of a partition may overlap, and a partition declares at most one operation and one extent per block.
  UBI headers, volume table records and UBIFS nodes are CRC-checked: a damaged UBIFS index node, inode or directory
  entry is an error, and a damaged data node or static-volume LEB skips its file. The UBIFS index is walked without
  recursion, each child one level below its parent, and a node reached twice is refused as a cycle; a directory
  linked twice is skipped with a note. A journal that ends in a damaged node (a write cut short by power loss) is
  read up to it, with a note. Every size and offset is range-checked.

## Opening an image as a binary

`triage_report` or any binary tool given a filesystem image answers that the file is a SquashFS, ext, Android
sparse, OTA payload, cpio, tar, UBI or UBIFS image and names `fs_list` and `fs_extract`, instead of the headerless-image
guidance. Given a ZIP, it names `dex_metadata` for an APK, AAB or JAR, and `fs_list` and `fs_extract` for its
members.

## Next: the endpoints inside

`endpoint_inventory` with `path` set to an extraction's `output_dir` lists the hosts, URLs, IPs and certificates the
tree's programs and configuration name, grouped by domain, and `endpoint_blocklist` turns them into a router
blocklist. See [endpoint inventory and blocklists](endpoint-inventory.md).

## Not supported yet

Vendor SquashFS variants and SquashFS 3.x; UBIFS extended attributes and fscrypt-encrypted content; UBI images
whose eraseblock size is not a power of two; delta OTA payloads (by design: they need the previous
build); compressed tar (`.tar.gz`: decompress it first); opening images inside vendor containers automatically
(`carve` finds the offset of a SquashFS, ext, Android sparse, OTA payload, cpio, tar or ZIP image, but not of UBI or
UBIFS; pass it as `image_offset`). The design and its trade-offs are in [the plan](plans/2026-11-15-firmware-unpacking.md).
