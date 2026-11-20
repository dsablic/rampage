# Firmware version diffing

*Experimental.* You have two update files for the same device, the one it runs and the one the vendor now offers,
and want to know what the update changes before you install it. `diff_firmware` (MCP `carve` group) answers in
one call: what the files hold and how their layout changed, which components and files were added, removed or
changed, and for each changed program the functions, strings, version identifiers, network endpoints, lock
mechanisms, integrity checks and capture sources that differ. The result names the calls that read further: one
component in full, one list paged, or one function instruction by instruction.

```json
{"tool": "diff_firmware", "path": "/work/fw-2.0.7.bin", "other": "/work/fw-2.1.0.bin"}
```

`path` is the older version and `other` the newer one: "added" means only in `other`. Swap them and every addition
reads as a removal.

## What it reads

Each side is taken apart into components, whatever form it has:

| Input | Components |
| --- | --- |
| An executable (ELF, PE, Mach-O; any architecture a loader opens) | `image` |
| A headerless Cortex-M flash image (vector table at offset 0) | `image`, a Raw project at the best load address |
| An update container whose header describes compressed payloads | `stream:0`, `stream:1`, ...: each decoded (LZSS, LZ4 block) and opened as Cortex-M code at the best load address |
| An ESP32/ESP8266 flash dump | `esp:bootloader`, `esp:partition_table`, and one `esp:LABEL` per partition; app partitions are read as Xtensa code. A dump saved from flash 0x1000 (it starts with an ESP32 or ESP32-S2 bootloader) has its partition offsets mapped 0x1000 bytes lower in the file |
| An ESP app image | `image` |
| A filesystem image `fs_list` reads (SquashFS, ext2/3/4, UBI/UBIFS, Android sparse and OTA payloads, cpio, tar, ZIP) | `fs`, then each changed file inside it as `fs::PATH::ID` |
| An APK | `fs`, with its manifest, permissions, components, native libraries, classes and capture APIs compared |
| A DEX file | `dex`, its Android facts |
| A directory, such as an `fs_extract` output | `tree`, then each changed file inside it as `tree::PATH::ID` |
| Images `carve` validates inside a container | `embedded:KIND#N` |
| Anything else | `file`, compared by digest |

For a selection the detection does not make, give it per side as the other tools take it: `image_offset` and
`image_length` for an embedded image, `inner` for a nested filesystem chain (as `fs_list`), or `as_raw` with a
Raw selector for headerless code (as `raw` on `binary_info`). The `other_` forms (`other_image_offset`,
`other_inner`, `other_as_raw`) select in the newer file; `other_as_raw` defaults to `as_raw` only when that names no
`length`, since two versions are rarely the same size.

Components pair by id: files by path, ESP partitions by label, compressed streams by their order in the file (a
stream whose count changed pairs with the next one of similar size), and the only code image or filesystem left on
each side with the other's (a plain image against the same image compressed, an extracted directory against an
image), with the id `OLD~NEW`. `paired_by` says which rule made each pair (`id`, `stream_order_size`,
`only_remaining_code` or `only_remaining_tree`); a code pair whose roles differ carries a note. A stream in the newer file is decoded with the older one's codec parameters and load
address first, so both are read alike.

## What a result says

On the Cortex-M update pair in `tests/fixtures/firmware` (`raw-cortex-m-update-v1.bin` and `-v2.bin`, wrapped in an
LZSS update container), condensed:

```json
{"old": {"kind": "container", "size": 1892}, "new": {"kind": "container", "size": 1922},
 "identical": false,
 "summary": [
   "1 components: 1 changed, 0 added, 0 removed, 0 unchanged, 0 not compared.",
   "Container: size: 1892 -> 1922 bytes; occupied_bytes: 1124 -> 1154.",
   "`stream:0` (changed): functions 2 changed, 2 added, 1 removed; endpoints +1 -0; version strings +1 -1; lock mechanisms +1 -0; integrity checks +0 -0 ~1."],
 "components": [{
   "id": "stream:0", "status": "changed", "role": "compressed_stream",
   "old": {"payload_offset": "0x110", "payload_length": 1108, "checksum": "byte_sum32", "codec": "lzss",
           "decoded_size": 3072, "base_address": "0x8000000", "sha256": "faeb7ad9..."},
   "new": {"payload_length": 1138, "checksum": "byte_sum32", "decoded_size": 3584,
           "decoded_with": "the other version's parameters", "sha256": "d7265220..."},
   "changes": ["decoded_size: 3072 -> 3584", "decoded_size_field: 3072 -> 3584", "payload_length: 1108 -> 1138"],
   "code": {
     "functions": {"old": 9, "new": 10, "unchanged": 6, "changed": 2, "added": 2, "removed": 1,
                   "by_method": {"exact_bytes": 4, "identical_body": 1, "symbol_name": 1, "unique_string": 2}},
     "changed": [{"name": "sub_80002c0", "old": "0x80002c0", "new": "0x8000264", "method": "unique_string",
                  "confidence": 0.8, "old_size": 32, "new_size": 52},
                 {"name": "entry", "old": "0x80002e8", "new": "0x80002a0", "method": "symbol_name", "confidence": 0.95}],
     "added": [{"name": "sub_8000238", "new": "0x8000238", "size": 20}, {"name": "sub_800024c", "new": "0x800024c", "size": 22}],
     "removed": [{"name": "sub_8000238", "old": "0x8000238", "size": 136}],
     "strings": {"added": ["https://telemetry.example.net/v2/upload", "fw-version 2.1.0"],
                 "removed": ["fw-version 2.0.7", "selftest failed", "selftest passed"]},
     "versions": {"added": ["fw-version 2.1.0"], "removed": ["fw-version 2.0.7"]},
     "endpoints": {"added": [{"kind": "local", "value": "https://telemetry.example.net/v2/upload",
                              "local": "documentation name (RFC 2606)"}]},
     "locks": {"added": [{"category": "debug_lock", "function": "entry", "decision": "0x80002a8",
                          "failure_path": "branch", "summary": "Debugger detection: behaviour depends on the debug status (DHCSR). ..."}]},
     "integrity": {"changed": [{"old": {"algorithm": "crc32", "stored": "0x8000bfc", "ranges": ["0x8000800..0x8000bfc"], "covered_bytes": 1020, "valid": true},
                                "new": {"algorithm": "crc32", "stored": "0x8000dfc", "ranges": ["0x8000800..0x8000dfc"], "covered_bytes": 1532, "valid": true},
                                "what": ["covered bytes 1020 -> 1532"]}]},
     "capture": {"applies": false}}}],
 "not_compared": [],
 "budget": {"elapsed_ms": 3039, "images_diffed": 1, "bytes_read": 7628, "functions_matched": 8, "stopped": null},
 "next": [{"tool": "diff_firmware", "arguments": {"path": "...", "other": "...", "component": "stream:0", "function": "0x80002c0"},
           "why": "the first changed function, instruction by instruction with addresses normalised"}]}
```

Read it top down:

- **`old`, `new`:** what each file is (`kind`), its size and SHA-256, and layout facts.
- **`container`:** layout-level differences: kind, size, occupied bytes, the component list.
- **`components`:** each pair with `status` (`unchanged`, `changed`, `added`, `removed`, `not_compared`), its
  facts per side, `changes` (facts that differ: sizes, offsets, checksum kinds, ESP app versions, partition table
  rows added, removed or resized), and what applies:
  - **`code`:** `functions` with counts per match method; `changed`, `added`, `removed` and `unchanged` function
    rows (each match with its method and confidence, the methods of [build matching](build-diffing.md#matching)
    plus those below); `strings`, `versions`, `endpoints`, `locks`, `integrity` and `capture`, each with
    `added`, `removed` (and `changed`) and their totals.
  - **`files`:** for a filesystem or directory, `changed` (by size, else by SHA-256), `added`, `removed` and
    `metadata_changed` (type, link target, mode) rows with the sniffed `format` of each file read, `unchanged`
    and `endpoints` the changed, added and removed files name (`path`, `kind`, `value`).
  - **`android`:** for an APK or DEX file, the facts that differ: `version`, `permissions`, `components`,
    `native_libs`, `classes`, `capture_apis`, `dex_files`.
- **`not_compared`:** everything left out, with the reason: a budget that ran out, a payload no decoder
  reproduced, files over the read limits.
- **`budget`:** time spent, images analysed and skipped, bytes read, files hashed, functions matched, and `stopped`
  (`time`, `images`, `bytes` or null).

On the SquashFS pair (`tests/fixtures/fsimages/update-v1.sqfs` and `-v2.sqfs`), the tree and the program inside it
that changed:

```json
{"components": [
  {"id": "fs", "status": "changed", "role": "filesystem",
   "files": {"entries": {"old": 10, "new": 10}, "unchanged": 4,
             "changed": [{"path": "bin/controller", "old_size": 4292, "new_size": 4852, "format": "elf"}],
             "added": [{"path": "etc/cloud.conf", "type": "file", "size": 52, "format": "text"}],
             "removed": [{"path": "etc/legacy.conf", "type": "file", "size": 17, "format": "text"}],
             "endpoints": {"added": [{"path": "etc/cloud.conf", "kind": "local", "value": "https://cloud.example.net/v2/ingest"}]}}},
  {"id": "fs::bin/controller::image", "status": "changed", "role": "executable",
   "changes": ["entry: 0x80002e8 -> 0x80002a0"],
   "code": {"functions": {"unchanged": 6, "changed": 2, "added": 2, "removed": 1},
            "changed": [{"name": "report_status", ...}, {"name": "reset_handler", ...}],
            "added": [{"name": "debugger_attached", ...}, {"name": "halt", ...}],
            "removed": [{"name": "legacy_selftest", ...}], ...}}]}
```

On the ESP32 flash fixture against its next version (a new SPIFFS partition, the factory app at 1.5.0):

```json
{"components": [
  {"id": "esp:bootloader", "status": "unchanged"},
  {"id": "esp:factory", "status": "changed", "role": "esp_app",
   "changes": ["length: 66672 -> 66656", "partition_size: 983040 -> 786432", "version: 1.4.2 -> 1.5.0"],
   "code": {"functions": {"unchanged": 18, "changed": 2, "added": 1, "removed": 1},
            "endpoints": {"added": [{"value": "https://ota.example.com/v2/firmware"}]},
            "versions": {"added": ["1.5.0"], "removed": ["1.4.2"]}, "locks": {"supported": false}}},
  {"id": "esp:nvs", "status": "unchanged"},
  {"id": "esp:partition_table", "status": "changed",
   "changes": ["partition changed: factory app/factory at 0x10000, 0xf0000 bytes -> factory app/factory at 0x10000, 0xc0000 bytes",
               "partition added: storage data/spiffs at 0xd0000, 0x30000 bytes"]},
  {"id": "esp:phy_init", "status": "unchanged"},
  {"id": "esp:storage", "status": "added", "role": "partition"}]}
```

On an APK and its next version, `android` names what the manifest and code gained:

```json
{"android": {"permissions": {"added": ["android.permission.CAMERA"]},
             "native_libs": {"added": ["lib/arm64-v8a/libnet.so"]}}}
```

## Only real changes

Two builds of one program differ in addresses everywhere: code moves, literal pools point elsewhere, branches
reach their targets by other offsets, padding realigns. A function is reported changed only when its instructions
differ once those are set aside. Functions are matched as [`transfer_annotations`](build-diffing.md#matching) does,
then:

- leftover functions with identical bytes or an identical masked hash pair as a multiset (`identical_body`,
  `identical_masked_body`): twins and stubs carry no change however they pair, and only a count difference is an
  addition or removal;
- leftovers with identical normalised listings pair (`identical_normalised_body`, confidence 0.9), repeated while
  newly paired callees make their callers comparable;
- leftovers that alone reference one string in each version pair (`unique_string`, 0.8); strings here include the
  NUL-terminated ones firmware keeps beside its code;
- a pair the matcher calls changed is unchanged (`same_after_normalisation`) when its normalised listings are
  equal;
- a pair the matcher calls unchanged is changed when it loads from a literal pool and its normalised listings
  differ: a pool after the body is not part of the bytes the matcher compares, so a constant changed there (a
  timeout, a limit, a key length) shows only through the load.

A normalised listing reads the function block by block (so padding and literals between blocks are skipped),
names call and branch targets by the older version's function names (a callee that only moved reads the same; one
only in the newer version reads `new:NAME`), turns other mapped addresses into `<addr>`, appends to each
literal load the value it loads (`ldr r2, <addr> = 0x54321`; a function by its label, a string by its text, another
address as `<addr>`), and reads a `movw`/`movt` pair that forms an address as that address with the string
there. Width suffixes (`.n`, `.w`) are dropped. Strings, endpoints and version identifiers are compared as sets, so
moving one is no change.

## One function, side by side

`component` with `function` diffs one pair: an old address or name, or `new:` and an address or name in the newer
version (a function only there is listed alone, `only_in: new`).

```json
{"tool": "diff_firmware", "path": "/work/v1.elf", "other": "/work/v2.elf", "component": "image", "function": "reset_handler"}
```

```json
{"function": {"name": "reset_handler", "old": "0x80002e8", "new": "0x80002a0", "method": "symbol_name",
              "confidence": 0.95, "changed": true},
 "old_instructions": 21, "new_instructions": 23, "differing_rows": 14,
 "rows": [
   {"same": 2, "old": "0x80002e8", "new": "0x80002a0"},
   {"op": "+", "new": "0x80002a4", "text": "bl new:debugger_attached"},
   {"op": "+", "new": "0x80002a8", "text": "cbnz r0, <addr>"},
   {"same": 1, "old": "0x80002ec", "new": "0x80002aa"},
   {"op": "-", "old": "0x80002f0", "text": "mov r1, #1020"},
   {"op": "+", "new": "0x80002ae", "text": "movw r1, #1532"},
   ...
   {"op": "-", "old": "0x8000316", "text": "movw r0, #lo(<addr> \"fw-version 2.0.7\")"},
   {"op": "+", "new": "0x80002d0", "text": "movw r0, #lo(<addr> \"fw-version 2.1.0\")"},
   ...],
 "decompile": [{"tool": "decompile", "arguments": {"path": "/work/v1.elf", "at": "0x80002e8"}},
               {"tool": "decompile", "arguments": {"path": "/work/v2.elf", "at": "0x80002a0"}}]}
```

The CRC length grew from 1020 to 1532 bytes, a debugger check was added before it, the version string changed and
the call to `legacy_selftest` is gone; the calls to `crc32_compute` and `uart_puts` read the same although the code
around them moved. Each call recomputes the matching of the image pair, so it costs about what the summary spent on
that image. `decompile` names both sides when they open by path; a program inside a filesystem image must be extracted with `fs_extract` first.

## Paging and drill-down

The summary keeps 20 rows per list, each list with its total, and names at most 20 components (the rest are
counted). `components_total` and `not_compared_total` count those lists before any cut. `component` alone returns that pair in full, with
everything taken apart inside it as `inside`. With `list` it pages one list with `offset` and `limit` (default 100,
at most 500): `changed`, `added`, `removed` or `unchanged` functions, `strings`, `endpoints` (with a `change` of
`added` or `removed` on each row) or `files`. Each call recomputes just the path to that component; no state is kept
between calls, so a page is the same whenever it is asked for. A result is cut to 56,000 JSON bytes by halving its
longest lists first, and says so in `truncated`; a page cut that way gives the `next_offset` just after its last
row, so paging on from it skips nothing.

## Budgets

| Argument | Default | At most | What it bounds |
| --- | --- | --- | --- |
| `timeout_ms` | 60000 | 600000 | the call, checked before each image, file, decode and stage (soft: see below) |
| `max_images` | 8 | 64 | changed code images analysed |

and fixed, not arguments: 2 GiB read from the inputs (digests, decoding, listing and reading filesystem entries), the first 64 MiB
of a file searched for components, 16 compressed streams and 16 embedded images per side, 2000 changed files read
per filesystem pair, changed files over 256 MiB not taken apart, three filesystem levels, images over 64 MiB not
analysed, 4000 functions per side compared by listing, 50 lock mechanisms per side, 20,000 scratch files and
2,000 component pairs per call. Filesystems are read through the
same readers as `fs_list`, with one compression-ratio meter per image, so a decompression bomb stops at 1000:1. The deadline is soft: one
image's analysis is not interrupted once it has started, so a large image begun just before the deadline overruns it
by its analysis time (tens of seconds for a 20 MB program in a debug build); decodes and probes get what is left of
the deadline as their own. Whatever a budget left out is in `not_compared`; ask for it
with `component`, or raise the budget.

Files from inside an image are written to a private scratch directory (named by the tool, never by the image's
paths) and removed when the call ends.

## Limits

- Added and removed programs are listed (and their endpoints read), not analysed.
- Lock mechanisms and capture sources are compared by what they are and which (matched) function decides them;
  `lock_mechanisms` traces ARM/Thumb, AArch64 and x86-64 (`supported: false` elsewhere), and without an SVD map
  knows only architectural registers.
- Integrity checks of medium or high confidence are compared per algorithm in address order: added, removed, and
  changed in covered length, stored field size, parameters or validity. A range that only moved is no change.
- Headerless code other than Cortex-M (MIPS, Xtensa without an ESP header, other Sleigh profiles) needs `as_raw`.
- Between two ESP32 application builds, Xtensa code that only moved is still reported as changed (on a public
  MicroPython point release, 546 functions changed where about a dozen changed size), so the changed list is an
  upper bound there. MIPS16e and microMIPS programs compare no functions, since that code is not decoded.
- Container payloads decode with the codecs `probe_compression` tries (LZSS variants, LZ4 block); other codecs or
  encrypted payloads compare by digest. When the ring fill of an LZSS stream cannot be told apart, the decoded bytes
  that read best as a Cortex-M image are taken; the stream says `dictionary_fill_ambiguous`, and `fill_choice`
  lists each fill tried with its scores and the one chosen.
- When the images differ but no compared function, string, endpoint, lock or check does, the component and the
  summary say the change lies outside the compared functions (data, padding, or code discovery did not reach).
- Secure-boot signatures are not verified; ESP image checksums, SHA-256 digests and the partition table MD5 are.
- Directories compare regular files; symlinks are not followed or listed.

See also [build matching](build-diffing.md), [firmware filesystem images](firmware-images.md),
[reading a firmware update file](firmware-walkthrough.md) and [known limits](known-limits.md).
