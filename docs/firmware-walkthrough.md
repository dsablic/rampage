# How to read the code in a firmware update file

A vendor's update file for a microcontroller is rarely a plain flash image. It is usually a container: a header,
then one or more compressed images, each behind a small record giving its size, checksum and load address. This
guide takes such a file to decompiled code with rampage's MCP tools: find the compressed image, decode it, open
it as a Cortex-M Raw project at the right address, let rampage map what the startup code copies, then read the
functions, checksums and lock mechanisms.

Each step names the tool call an agent makes. You can give an agent the folder and the goal and let it choose its
own calls; the steps show what to expect. For filesystem images (SquashFS, ext4, OTA payloads) inside an update,
see [firmware filesystem images](firmware-images.md) instead.

## A sample update file

To follow along, build a small update file from a committed fixture. This script compresses the scatter-load
fixture `raw-cortex-m-scatter-table.bin` (a Cortex-M4 image at 0x08000000 whose startup code copies code to
0x10000000 and data to 0x20000000) with LZSS and puts it behind a 40-byte header and a six-word record: address,
payload offset, compressed length, byte sum, address, decoded size. Run it from a checkout:

```sh
python3 - /work/update <<'EOF'
import os, runpy, struct, sys
fixtures = "tests/fixtures/firmware"
lzss = runpy.run_path(f"{fixtures}/gen-stages.py")["lzss"]
image = open(f"{fixtures}/raw-cortex-m-scatter-table.bin", "rb").read()
stream = lzss(image)
record = struct.pack("<6I", 0x08000000, 0x40, len(stream), sum(stream) & 0xFFFFFFFF, 0x08000000, len(image))
os.makedirs(sys.argv[1], exist_ok=True)
open(f"{sys.argv[1]}/update.bin", "wb").write(b"UPDT" + bytes(36) + record + stream)
EOF
```

The results below are from that file, condensed; paths are shortened to `/work/update`.

## 1. List the folder

When all you have is a folder, `list_dir` shows what is in it, with a format sniffed from each file's first bytes:

```json
{"path": "/work/update"}
```

```json
{"total": 1, "entries": [{"name": "update.bin", "kind": "file", "size": 673, "format": "unknown"}],
 "next": "Open an executable by its path with binary_info or triage_report; a headerless image with file_layout; a filesystem image (squashfs, ext, cpio, tar) with fs_list."}
```

An executable opens directly by its path, and a filesystem image with `fs_list`. A file with no recognised format,
like this one, goes to `file_layout`.

## 2. Find the compressed image

`file_layout` maps any file: padding, entropy, string clusters, and hints. A `compressed_component_candidate` hint is
a header whose words agree with the bytes after it:

```json
{"path": "/work/update/update.bin"}
```

```json
{"kind": "compressed_component_candidate", "offset": 48,
 "evidence": ["little-endian word at 0x30 equals the 609-byte payload length from 0x40",
              "word at 0x34 equals the payload's byte_sum16 0xea79",
              "word at 0x3c (840) is a candidate decoded size for probe_compression or decode_file_range"],
 "container": {"payload_offset": 64, "payload_length": 609, "decoded_size_candidates": [{"offset": 60, "value": 840}]}}
```

Hand the payload range and decoded size to `probe_compression`, which tries LZSS and LZ4-block parameter sets and
ranks the ones that decode the range to that size:

```json
{"path": "/work/update/update.bin", "offset": "0x40", "length": 609, "expected_output_size": 840}
```

The first candidate (of 40 found) is classic 4 KiB-ring LZSS, `plausible`, `decode_check: reproduced`, with all its
checks passed. If `file_layout` gives no hint, probe ranges with high entropy; see
[probing an unknown variant](decoding.md#probing-an-unknown-variant).

## 3. Read the container record

Each reproduced candidate also returns `container_record`: the words just before the stream, each with the role its
value suggests.

```json
{"fields": [
   {"offset": "0x28", "value": "0x8000000", "role": "address"},
   {"offset": "0x2c", "value": "0x40", "role": "payload_offset"},
   {"offset": "0x30", "value": "0x261", "role": "compressed_length"},
   {"offset": "0x34", "value": "0xea79", "role": "byte_sum32"},
   {"offset": "0x38", "value": "0x8000000", "role": "address"},
   {"offset": "0x3c", "value": "0x348", "role": "decoded_size"}],
 "base_hints": [{"base_address": "0x8000000", "field_offsets": ["0x28", "0x38"]}]}
```

Roles are inferred from values, not known: the length and size words are found by value, the checksum word is
tested as a byte sum and a CRC-32 of the compressed bytes, and address words become `base_hints`.

## 4. Open the decoded image at its load address

The candidate's `open_as_raw` is a `raw` selector for the decoded bytes, missing only the processor and the load
address. Its `base_candidates` rank load addresses for the decoded bytes as Thumb code:

```json
{"base_address": "0x8000000", "confidence": "plausible",
 "methods": ["vector_table", "pointer_vote", "literal_pool", "hint"],
 "evidence": {"function_pointers": 2, "code_pointers_inside": 4, "literal_pointers_inside": 2,
              "reset_constants_inside": 2, "vector_table": true,
              "hints": ["container record fields at 0x28, 0x38"]}}
```

The record's address, a vector table at offset 0 and the pointer vote agree on 0x08000000. Add `profile`,
`base_address` and `vector_table` to `open_as_raw` and pass it as `raw` to `binary_info`:

```json
{
  "path": "/work/update/update.bin",
  "raw": {
    "profile": "cortex-m", "offset": "0x40", "length": 609, "base_address": "0x8000000", "vector_table": true,
    "decode": { "codec": "lzss-4k", "expected_output_size": 840, "initial_write_offset": 4078, "dictionary_fill": 0 }
  }
}
```

(`lzss-4k` names the same parameters the probe listed one by one; either form works.) `raw.regions` shows the
primary region with `source.type: decoded` and the decoder's receipt, and `raw.base_check` agrees:

```json
{"base_address": "0x8000000", "verdict": "consistent", "pointer_share": 1.0,
 "reset_constants_in_regions": 7, "reset_constants": 9}
```

Had you opened it at 0x10000000 (the address the code is copied to), the Reset and other handler words would be
refused as `outside_image`, `vector_table.base_address_suggestion` would name 0x8000000, and `base_check` would be
`unknown`. Reopen with the suggested base before going on. See [choose the base address](raw-code.md#choose-the-base-address).

## 5. Let scatter-load map the copied code

The same `binary_info` reports `raw.scatter_load`: rampage followed the reset code from the entry and recorded what
it copied and zeroed.

```json
{"entry": "0x800015c", "steps": 356, "stop": "jumped_into_copied_code", "continues_at": "0x100000e0",
 "copies": [
   {"kind": "copy", "destination": "0x10000000", "length": 292, "source": "0x8000200",
    "routine": "0x800005c", "executed": true, "status": "mapped", "region": "raw.code.1"},
   {"kind": "copy", "destination": "0x20000000", "length": 36, "source": "0x8000324",
    "routine": "0x800005c", "written_after_jump": true, "status": "mapped", "region": "raw.ram.2"},
   {"kind": "zero", "destination": "0x20000024", "length": 100,
    "routine": "0x80000f4", "status": "mapped", "region": "raw.ram.3"}],
 "last_vtor_store": {"value": "0x10000000", "site": "0x1000010c"}}
```

The copied code is mapped as code at 0x10000000, the data as RAM at 0x20000000 (the code writes it after the jump)
and `.bss` as zeroed RAM. The jump target 0x100000e0 is seeded, and the vector table the copied code installs
through VTOR at 0x10000000 is read and its handlers seeded. Nothing else is needed: the mapping is the default.
`"scatter_load": false` reports the copies without mapping them; on this file discovery then stops at 3 functions
instead of 6. See [scatter-load](raw-code.md#let-scatter-load-map-the-startup-copies) for when a copy is not mapped.

## 6. Read the code and check the sums

With the same `raw` selector, `list_functions` lists the startup code and the copied code at their run addresses:

```json
{"total": 6, "items": [
  {"address": "0x8000040", "name": "sub_8000040"}, {"address": "0x8000048", "name": "sub_8000048"},
  {"address": "0x800015c", "name": "entry"}, {"address": "0x10000040", "name": "sub_10000040"},
  {"address": "0x10000060", "name": "sub_10000060"}, {"address": "0x100000e0", "name": "sub_100000e0"}]}
```

`decompile` at `entry` shows the startup code walking its region table and calling each entry's handler:

```c
  pxVar2 = (xunknown4 *)0x8000188;
  do {
    xVar1 = *pxVar2;
    pxVar3 = pxVar2 + 1;
    pxVar4 = pxVar2 + 2;
    pxVar5 = pxVar2 + 3;
    pxVar2 = pxVar2 + 4;
    (*(code *)*pxVar5)(xVar1,*pxVar3,*pxVar4);
  } while (pxVar2 < (xunknown4 *)0x80001b8);
```

and at `0x100000e0`, the code that runs from TCM, which sets VTOR and loops:

```c
void sub_100000e0(void)
{
  xunknown4 xVar1;

  ppb_e000ed08 = 0x10000000;
  do {
    xVar1 = sub_10000060(*(uint4 *)((ram_20000024 & 7) * 4 + 0x20000028));
    periph_40011004 = xVar1;
  } while( true );
}
```

To check the container's own checksum, run `integrity_checks` on a Raw project over the whole file (any profile
and base: the container is data):

```json
{"path": "/work/update/update.bin",
 "raw": {"profile": "cortex-m", "offset": 0, "length": 673, "base_address": "0x60000000", "pointer_tables": false}}
```

It finds the record's byte sum as a valid `sum32` check over the stream and lists the stream in
`container_streams`:

```json
{"stream_offset": "0x40", "record_offset": "0x28", "compressed_length": 609, "decoded_size": 840,
 "checksum": "byte_sum32 at file offset 0x34 verifies", "decode_check": "reproduced",
 "open_as_raw": {"offset": "0x40", "length": 609, "profile": "ARM:LE:32:Cortex", "base_address": "0x8000000",
                 "decode": {"codec": "lzss-4k", "expected_output_size": 840, "initial_write_offset": 4078, "dictionary_fill": 0}}}
```

Its `next` says to run `integrity_checks` again with that selector, since the routines that check the image's own
CRCs are in the decoded code. On an image with CRC routines it finds their tables and polynomial literals, and on
Cortex-M names a routine around a polynomial literal even when discovery missed it (`inferred_range`); this sample
has none. After patching, the same tool recomputes the checks; see
[firmware patching](firmware-patching.md).

If another tool needs the decoded bytes as a file, `write_decoded_range` writes them to a new file at an absolute
`output_path`.

## 7. Look for lock mechanisms

`lock_mechanisms` with the same selector looks for signature checks, parts pairing, anti-rollback counters and
debug locks. On this sample it analyses nothing and says why: none of the 6 functions references a crypto
constant, a CRC routine, a known verify or MAC API, or a register with a role. Without an SVD map only DHCSR,
DAUTHCTRL and AIRCR writes are known; import the part's SVD with `import_svd` first so that unique-ID, OTP and
option-byte registers are recognised. See [lock mechanisms](lock-mechanisms.md) and
[CMSIS-SVD peripheral maps](peripheral-maps.md).

## When a step does not work

- **No `compressed_component_candidate` hint.** The record may be elsewhere or absent. Look at `file_layout`'s
  high-entropy spans and run `probe_compression` on each, with a decoded size if you know one.
- **`probe_compression` finds nothing plausible.** The codec may be one it does not try (deflate, LZMA, LZ4
  frames) or the stream may be encrypted; its `not_tried` list says what was not attempted.
- **`base_check` is `looks_wrong`.** Reopen with `better_candidate`; `next` names it.
- **Few functions.** Check `raw.scatter_load.stop` and each copy's `not_mapped_reason`, and
  `raw.pointer_tables.automatic` for whether the pointer-table scan ran. See [Raw code](raw-code.md).
- **More than one image.** Each stream has its own record; open each with its own selector and base.
