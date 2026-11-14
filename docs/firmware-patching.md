# Firmware patching round trip

An owner who repairs or adapts a device's firmware needs more than a patched byte: the bootloader verifies a
checksum or CRC over part of the image, and the programming tool expects the image back in its original container.
`integrity_checks` and `export_image` (group `formats`) close that loop together with the
[checked byte patches](patching.md):

1. Open the image: a native file, or a Raw project (`raw` selector) of a flat binary, Intel HEX or S-record file.
2. `integrity_checks` finds the checksum fields and the ranges they cover, and returns a patch receipt.
3. `patch_bytes` changes what you need (Raw code regions directly; data and RAM regions with `allow_data`).
4. `integrity_checks` reports which checks no longer hold and, in `fix.writes`, the values that would correct them.
   With `fix: true` and the receipt's `source_sha256` and `expected_revision`, it writes them as further patch
   records, undoable with `revert_patch` like any other.
5. `export_image` writes the patched image to a new file in its original format.

```json
{"tool": "integrity_checks", "path": "fw.hex", "raw": {"profile": "cortex-m3", "format": "ihex", "vector_table": true}}
{"tool": "patch_bytes", "path": "fw.hex", "raw": {...}, "at": "0x8000434", "original_hex": "11",
 "replacement_hex": "42", "allow_data": false, "source_sha256": "...", "expected_revision": "..."}
{"tool": "integrity_checks", "path": "fw.hex", "raw": {...}, "fix": true, "source_sha256": "...", "expected_revision": "..."}
{"tool": "export_image", "path": "fw.hex", "raw": {...}, "destination": "fw-patched.hex", "expected_revision": "..."}
```

Raw patches live in memory for the session, like other Raw annotations, so run the steps in one server session.

## Finding checks

Checks are found in the original image, where a stored value matches its range by construction; each is then
measured on the patched image (`valid`, `stored_hex`, `computed_hex`).

- **Algorithms.** CRC-32 (IEEE `crc32`, `crc32_bzip2`, `crc32_mpeg2`, `crc32_jamcrc`, `crc32c`, and
  `crc32_mpeg2_words`: 32-bit words fed most significant byte first, as STM32-style CRC units compute it), CRC-16
  (`ccitt_false`, `xmodem`, `kermit`, `modbus`, `arc`), CRC-8 (`smbus`, `maxim`), Adler-32, Fletcher-16/32, byte
  sums into 8, 16 and 32 bits and 16/32-bit word sums (each also as a two's complement, which makes the range plus
  the value sum to zero), byte and word XOR, and unkeyed SHA-256 and MD5 digests. Each check reports its
  parameters (width, polynomial, init, reflection, final XOR).
- **Brute force.** Stored-value candidates are the last value of each region and of its content before trailing
  0xff/0x00 padding, the value before each interior padding run, the first 16 words of each region and after each
  padding run (headers, Cortex-M vector-table words), and addresses code references. Ranges start at a region's
  start, after a padding run, at a code-referenced address or right after a header value, and end at any of those
  points. Each algorithm streams once per range start, and its value is compared at every candidate end. A 32-bit
  CRC, Adler-32, Fletcher-32 or digest may be stored anywhere; the weaker ones (16- and 8-bit values, sums, XOR) only
  right after or right before a range of at least 64 bytes whose other end is a layout boundary, since chance
  matches are otherwise common. Uniform ranges and erased (all 0x00 or 0xff) values are skipped.
- **Code.** Functions that reference a CRC table (from `find_crypto`'s constants), load a 32-bit polynomial literal,
  or form one with a Thumb `movw`/`movt` pair are reported in `routines` with their callers; the addresses they and
  their callers reference become candidates, and a match whose algorithm the code implements gains confidence.
- **Emulation.** With `emulate` (the default), the routine is run with `evaluate_function` on `(start, length)` and
  then `(start, end)` of each matched range up to 64 KiB, at most four runs; a result equal to the computed value
  marks the check `confirmed_by_emulation`.
- **Confidence.** One best match per stored value (others counted in `alternatives`), scored from the algorithm's
  strength, adjacency, code evidence (a routine counts only when it or a caller references the value or range)
  and emulation. A value inside a higher-scored check's range is dropped as a chance match unless code references it: `high` at 0.75, `medium` at 0.5. `evidence` lists each reason.
- **PE.** A PE's optional-header CheckSum is reported as a `file`-space check (zero means unset). Fix it with
  `export_image` and `pe_checksum: true`, not with a patch.

## Fixing

By default a fix writes only checks with independent evidence: confirmed by emulation, or whose stored value or
range bound the code references. Other invalid checks appear in `fix.writes` as `preview_only` with the reason;
pass their `ids` to fix them. Writes go in dependency order: a check whose range covers another's stored value is
computed after it, and a cycle refuses. Each write is a patch over the original bytes at the stored value, or a
`revert` of the record that covers exactly those bytes when the original bytes are correct again. Every write is
validated before the first is committed (admission, preimage, the patch budget, and any user patch overlapping the
value without matching it exactly, which refuses the whole fix); if a write still fails, the earlier ones are undone.

## Exporting

`export_image` never replaces a file (it stages privately and publishes with create-new semantics, like
`export_patched`) and needs `expected_revision` when patches are active, checked against the authoritative patch log
under the annotation lock. It reports the path, SHA-256, size and
regions.

- `format: original` (default): Intel HEX and S-record files are rewritten record by record. Only data records whose
  bytes changed are re-encoded, with a recomputed checksum and the original hex-digit case; extended address,
  header, count and start-address records, record lengths, line endings and order stay as written. A Raw project of
  a binary file rewrites the mapped ranges inside a copy of the whole file. A native file is written with its
  patched bytes (`pe_checksum: true` recomputes a PE's CheckSum). The source file must still hold the bytes the
  project admitted.
- `format: binary`: the bytes of the region holding `region`, or every non-RAM region laid out flat from the lowest
  address with `fill` (default 0xff) in the gaps, at most 64 MiB.

An unpatched export is byte-identical to the input for HEX, S-record and binary files.

Limits: the search is bounded to 16 regions, 256 MiB of hashing and 4,194,304 value lookups (candidate values are
indexed by their bytes, so each computed value is one lookup; `search.budget_exhausted` and `skipped_items` say when
it stopped), 32 reported checks and 8 CRC routines. Checks whose value is stored inside its own range, that
skip the value's bytes, cover several discontiguous ranges, or use a keyed MAC or signature are not found;
hardware CRC units are found by their result, not their registers. Native patches cover only the
[supported ELF64 profile](patching.md); other native files export unpatched. Decoded Raw regions cannot be patched.
