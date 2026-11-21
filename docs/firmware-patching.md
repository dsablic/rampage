# Firmware patching round trip

An owner who repairs or adapts a device's firmware needs more than a patched byte: the bootloader verifies a
checksum or CRC over part of the image, and the programming tool expects the image back in its original container.
`integrity_checks` and `export_image` (group `formats`) close that loop together with the
[checked byte patches](patching.md):

1. Open the image: a native file (a static ARM firmware ELF is patched in place), or a Raw project (`raw` selector)
   of a flat binary, Intel HEX or S-record file. A Cortex-M HEX or S-record file whose records start with its
   vector table also opens by path alone, and over MCP later calls may leave out `path` and `raw` once it is the
   session's only open binary.
2. `integrity_checks` finds the checksum fields and the ranges they cover, and returns a patch receipt.
3. `patch_bytes` changes what you need (code directly; data, RAM regions and ELF data sections with `allow_data`).
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
measured on the patched image (`valid`, `stored_hex`, `computed_hex`, and `stored_value`/`computed_value`: the
same values as the integers read at the field's width and byte order, absent for digests).

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
  or form one (or a table's address) with a Thumb `movw`/`movt` pair are reported in `routines` with their callers.
  So are table-less CRC-16 loops in ARM code whose polynomial (0xa001 and 0x8408 reflected, 0x1021) is one
  immediate (a Thumb or A32 `movw` that no `movt` completes, or a `mov` modified immediate) or a literal word read by
  a PC-relative load; these small values count after the other evidence, at most 16 sites;
  the addresses they and their callers reference, form with `movw`/`movt`, or load and store through a constant
  base (`mov r1, #0x840; ldrh r1, [r1]` reading a stored value) become candidates, and a match whose algorithm the
  code implements gains confidence. A weak value (16 bits or less, a sum, an XOR) counts code evidence only at its
  own stored address, and no match counts a range bound that is another match's stored value. A routine with no
  matching check is named in `notes`.
- **Emulation.** With `emulate` (the default), the routine is run with `evaluate_function` on `(start, length)` and
  then `(start, end)` of each matched range up to 64 KiB, at most four runs; a result equal to the computed value
  marks the check `confirmed_by_emulation`.
- **Confidence.** One best match per stored value (others counted in `alternatives`), scored from the algorithm's
  strength, adjacency, code evidence (a routine counts only when it or a caller references the value or range)
  and emulation: `high` at 0.75, `medium` at 0.5. A value inside a higher-scored check's range is dropped as a
  chance match unless code references it or the image's routine computes it (emulation is tried on those too), so
  nested checks, such as a CRC-16 over a configuration block inside an image CRC-32, are both kept. `evidence` lists
  each reason.
- **Raw firmware.** On a Raw project the code evidence comes from the discovered functions, pointer tables and
  scatter-load copies included. On Cortex-M a polynomial literal that no discovered code references is followed to
  the `ldr` that loads it, and the routine around it is listed with `inferred_range`. With `pointer_tables`
  unset (the default) the session seeds such a routine into discovery when it opens the project
  (`raw.inferred_seeds`), so it is then a function.
- **Containers.** On a Raw project mapped over a whole update file, each compressed stream behind a record is
  listed in `container_streams`; a record word holding the byte sum or CRC-32 of the compressed bytes becomes a
  check, and `open_as_raw` and `next` give the decoded image's selector, whose own checks are found by running
  `integrity_checks` again with it. See [MCP](mcp.md) for the bounds and the
  [firmware walkthrough](firmware-walkthrough.md#6-read-the-code-and-check-the-sums).
- **PE.** A PE's optional-header CheckSum is reported as a `file`-space check (zero means unset). Fix it with
  `export_image` and `pe_checksum: true`, not with a patch.

## Fixing

By default a fix writes only checks with independent evidence: confirmed by emulation, or whose stored value or
range bound the code references. Other invalid checks appear in `fix.writes` as `preview_only` with the reason;
pass their `ids` to fix them. Writes go in dependency order: a check whose range covers another's stored value is
computed after it (inner values first), over the image as the earlier planned writes leave it, so a preview without
`fix` shows the values a fix writes. A check whose range covers another check's value that would still be stale
(not chosen, or itself blocked) is not written: it appears as `blocked`, naming that check, since its new value would
cover a stale one. A value dropped as a chance match inside the range, whose algorithm the image's code implements and
which no longer matches, only adds a warning to `notes`: it has no id to fix it by. Each write is a patch over the
original bytes at the stored value, or a
`revert` of the record that covers exactly those bytes when the original bytes are correct again. Every write is
validated before the first is committed (admission, preimage, the patch budget, and any user patch overlapping the
value without matching it exactly, which refuses the whole fix); if a write still fails, the earlier ones are undone.

With `emulate` (the default), each value a fix writes, or would write in a preview, is also checked by the device's
own code: the routine whose run confirmed the check is run again with `evaluate_function`, in the same argument
form, over the range as the fix leaves it (the fix's earlier values passed as memory writes). `device_check` on the
write says `agrees`, `disagrees` (also named in `notes`) or `unconfirmed` with the reason: no routine confirmed the
check (one known from code references alone), or the run did not return a value (an unsupported operation, the step
budget, a timeout). The run confirms the value, not the byte order it is stored in. The check never blocks a write,
and is skipped for an image that takes no patches.

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
  address with `fill` (default 0xff) in the gaps, at most 64 MiB. A little-endian ELF32 image (patchable or not)
  lays out its allocated sections with file contents at their load addresses, as `objcopy -O binary` and a flash
  programmer do: each section's offset is mapped through its `PT_LOAD` segment to `p_paddr` when the segments'
  physical ranges are disjoint (else to `p_vaddr`), so `.data` initial values follow the code in flash, headers and
  bytes outside sections are left out, and `region` names a load address. An ELF32 without section headers, and
  ELF64 and other native images, lay out file-backed segments at their run addresses.

When an ELF32 section is loaded at another address than it runs at, `integrity_checks` says so in `notes`: checks are
searched at run addresses, so a check over the flash image that covers `.data` initial values is not found, and
patching those values can leave such a check stale.

An unpatched export is byte-identical to the input for HEX, S-record and binary files.

Limits: the search is bounded to 16 regions, 256 MiB of hashing and 4,194,304 value lookups (candidate values are
indexed by their bytes, so each computed value is one lookup; `search.budget_exhausted` and `skipped_items` say when
it stopped), 32 reported checks and 8 CRC routines. Checks whose value is stored inside its own range, that
skip the value's bytes, cover several discontiguous ranges, or use a keyed MAC or signature are not found;
hardware CRC units are found by their result, not their registers. Native patches cover only the
[supported static ELF64 and ELF32 ARM profiles](patching.md); other native files export unpatched. Decoded Raw
regions cannot be patched.
