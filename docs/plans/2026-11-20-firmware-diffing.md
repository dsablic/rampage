# Firmware version diffing (2026-11-20)

Track 3 of the agreed queue (todo.md, "Next up"): an owner has two update files for one device, version N and N+1
as the vendor ships them, and asks what changed. One call should answer at every level the files have, and the
result should name the next calls for detail.

## Decision: a new tool, `diff_firmware`, in the `carve` group

`diff_builds` stays the per-image report and `transfer_annotations` the matcher that moves work. A firmware update
is not one image: it is a container of compressed streams, a flash dump of partitions, a filesystem of hundreds of
programs, an APK. `diff_builds` is a project tool (its `path` must open as one executable, both in one
architecture) and its result is a workflow report about functions; extending it to take two arbitrary files,
decode them, take them apart and recurse would change what a stable `core` tool means. So:

- `diff_firmware` is a file tool (no project is opened for `path`), like `fs_list` and `carve`. It lives in `carve`,
  the group that already holds unpacking, endpoints and privacy, so the default catalog grows only by the group
  description's few words (the default list stays at ~102.1 KB of its 104.4 KB budget).
- It reuses rather than reimplements: `file_layout` hints, `probe_compression` and the Raw `decode` path for
  containers, the ESP loader's flash layout, `rampage-unpack` for filesystems, `build_match` (the
  `transfer_annotations` matcher) for functions, and `endpoint_inventory`, `lock_mechanisms`, `integrity_checks`,
  `privacy_surface` and the Android facts for what each version names or checks.
- It is experimental (docs/stability.md): its name and arguments are pinned in the contract snapshot, its result
  fields are not yet.

## Shape

Arguments follow the existing selector shapes per side: `path` and `other` (a file or a directory), then for each
side `image_offset`/`image_length` (an embedded image, as `fs_list` and `binary_info` take it), `inner` (a nested
image chain, as `fs_list`), and `as_raw`/`other_as_raw` (a Raw selector, as `raw` on the project tools; the name
avoids the MCP layer's own `raw` handling). `other_as_raw` defaults to `as_raw` only when that names no `length`
(an ESP, Intel HEX or S-record selector), since two versions rarely have one size.

The result has `old`/`new` (what each side is), `identical`, `summary` sentences, `container` (layout-level facts
that differ), `components` (each pair with its `id`, `status`, `role`, facts per side, `changes`, and `code`,
`files` or `android` as it applies), `not_compared` (what was left out and why), `budget` (what was spent and why
work stopped) and `next` (calls for detail).

Drill-down stays stateless: `component` (an `id` from a result) returns that pair in full; with `list`
(`changed`, `added`, `removed`, `unchanged`, `strings`, `endpoints`, `files`) it pages one list with
`offset`/`limit`; with `function` (an old address or name, or `new:` and a new one) it diffs one function. Every
drill-down call recomputes only the path to that component, so no session state is kept and results do not depend
on call order. A cache was considered and left out: a single component pair is cheap to recompute, and a cache
keyed by two files would have to be invalidated on rewrite.

## Taking a side apart

In order, the first that applies:

| Input | Components |
| --- | --- |
| directory | `tree`: its regular files |
| `as_raw` | `image`: that Raw project |
| a filesystem image at the selection (`inner`, `image_offset`) | `fs` (`android_package` for an APK) |
| `image_offset` | `image`: the executable embedded there |
| a bare DEX | `dex`: its Android facts |
| an executable a loader opens (ELF, PE, Mach-O, ...) | `image` |
| an ESP flash dump | `esp:bootloader`, `esp:partition_table`, `esp:LABEL` per partition (app partitions as Xtensa Raw projects) |
| an ESP app image | `image` |
| `file_layout` compressed-component candidates | `stream:N`: probed, decoded, opened as Cortex-M at the best base candidate |
| a Cortex-M vector table at offset 0 | `image`: a Cortex-M Raw project at the best base candidate |
| `carve`-validated images inside it | `embedded:KIND#N` |
| anything else | `file`: bytes compared by digest |

A stream on the newer side is decoded first with the older side's codec parameters and base (the probe runs only if
they fail), so both versions are read the same way. When the probe's best candidates differ only in an exercised
ring fill (a tie it cannot break), each is decoded and the one whose bytes read best as a Cortex-M image wins
(plausible vector-table words, then the base-candidate score); the component says `dictionary_fill_ambiguous`.

## Pairing components

By id first: filesystem entries by path (`PARENT::PATH::ID`), ESP partitions by label, streams by order, the
partition table and bootloader by role. Streams whose count changed pair in order with the next one of comparable
decoded size (within 2x). Then the only code image left on each side pairs with the other (a plain image and the
same image compressed), and likewise the only filesystem (an extracted directory and an image); such pairs get the
id `OLD~NEW`. The rest are added or removed.

## Functions: only real changes

`build_match` pairs by unique evidence and leaves ambiguity unmatched. Reported as is, a moved twin, a stub, a
function whose literal pool now points elsewhere or one whose padding realigned would all read as changes. So:

1. Leftovers pair as multisets by identical bytes, then identical masked hash: identical bodies carry no change
   however they pair, and a count difference is a real addition or removal.
2. Leftovers pair by identical normalised listings, repeated while new pairs make callers comparable.
3. Leftovers pair by a string (six characters or more, found anywhere in the image, including NUL-terminated
   strings beside the code) that exactly one leftover function references in each version.
4. A pair `build_match` calls changed is unchanged when its normalised listings are equal.

Normalisation reads each function block by block (padding and literals between blocks are skipped; a listing stops
at a string discovery ran into), drops `.n`/`.w` width suffixes, names call and branch targets by the older
version's function names (a callee that only moved reads the same), turns other mapped addresses into `<addr>`,
replaces a PC-relative operand by what it loads (the string or name), and reads a `movw`/`movt` pair that forms an
address as that address. The function view uses the same normalisation, so what it shows is what made a function
changed.

## Bounds

Every call has a time budget (`timeout_ms`, default 60 s, at most 600 s), a number of changed code images it
analyses (`max_images`, default 8, at most 64) and a byte budget for reading (2 GiB: file digests, decoding,
listing and reading filesystem entries). Filesystem reads go through `rampage-unpack` with one budget and one
compression-ratio meter per image, so a decompression bomb stops at the 1000:1 limit. Further caps: 16 compressed
streams and 16 embedded images per side, 64 MiB read per side for layouts, 2000 files written to scratch space per
filesystem pair, changed files over 256 MiB not taken apart, three filesystem levels, 64 MiB per analysed image,
4000 functions per side compared by listing, 50 lock mechanisms per side, result JSON halved list by list until it
fits 56,000 bytes (each list keeps its total). A single image's analysis is not interrupted; the deadline is checked
between images, files and stages. Everything skipped is in `not_compared` with the reason, and `budget.stopped` says
which budget ran out.

Scratch files live in a private directory created for the call (mode 0700 on Unix) and removed when it ends;
filesystem entries are written there under names the tool chooses, never under paths from the image.

Results are deterministic for the same inputs and budgets: components, files and functions are sorted, sets are
ordered, and pairing never depends on hash-map order. Only `budget.elapsed_ms` varies, and work cut by the time
budget depends on the machine.

## Tests

`crates/rampage-api/tests/firmware_diff.rs`, on fixtures built for it: a Cortex-M3 pair from one source
(`tests/fixtures/firmware/raw-cortex-m-update.c`; v2 adds an endpoint, grows the CRC-covered region, adds a debugger
check and drops a function) as flat binaries, as ELF and wrapped in the LZSS container the triage tests use; a
SquashFS pair (`build-fsimages-update.sh`) and the same trees as directories; the ESP32 flash fixture and its next
version (`esp32-app-v2.bin` placed in a copy with a new partition); an APK pair from the DEX test kit. Each is also
compared with itself and the other way round. Hostile inputs: random bytes, mutated and truncated images, a
decompression bomb against a sparse file, and each budget at its smallest.

## Open

- Added and removed executables are listed, not analysed; their endpoints are.
- Headerless images other than Cortex-M (MIPS, Xtensa without an ESP header, others) need `as_raw`.
- The probe's codecs bound what containers decode (LZSS, LZ4 block); vendor containers with other codecs or
  encryption compare by digest.
- Bootloader and partition signatures (secure boot) are not verified; ESP image checksums and digests are reported.
- A CLI command.
