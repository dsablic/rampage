# File layout

MCP `file_layout` and `binary layout` map any regular file in one call, without a loader, header or mapping.
They are the first look at headerless firmware or an unknown blob: where the padding is, which parts look
packed, where the text is, and what the occupied parts hash to. Nothing is decoded, extracted or executed.

```sh
rampage binary layout firmware.bin
rampage --json binary layout firmware.bin --offset 0x8000 --length 0x40000 --block-size 1024 --utf16
```

MCP takes the same fields with `path`: `{"path": "firmware.bin", "offset": "0x8000", "length": "0x40000"}`.

## Requests

| Argument | CLI flag | Default | Meaning |
| --- | --- | --- | --- |
| `offset` | `--offset` | 0 | Original-file offset where the selection starts. |
| `length` | `--length` | rest of file, at most 64 MiB | Selected bytes, 1..=64 MiB. |
| `min_fill_run` | `--min-fill-run` | 64 | Shortest run of one repeated byte reported as fill, 8..=16 MiB. |
| `block_size` | `--block-size` | 4096 | Entropy block size, 512..=16 MiB. Blocks start at `offset`. |
| `min_string_length` | `--min-string-length` | 6 | Shortest printable run counted as a string, 4..=64. |
| `cluster_gap` | `--cluster-gap` | 64 | Largest gap between strings of one cluster, 1..=4096 bytes. |
| `cluster_min_strings` | `--cluster-min-strings` | 3 | Fewest strings a cluster needs, 1..=64. |
| `utf16` | `--utf16` | false | Also cluster UTF-16LE strings of ASCII-range characters. |
| `hints` | `--no-hints` | true | Report heuristic hints. |
| `region_limit` | `--region-limit` | 128 | Regions returned, 1..=256. |
| `block_limit` | `--block-limit` | 1024 | Per-block entropy values returned, 1..=4096. |
| `cluster_limit` | `--cluster-limit` | 16 | String clusters returned, 1..=128. |

An explicit zero length, an offset at or past the end of the file and a range outside the file are refused. Offsets
and lengths accept integers, hex (`0x...`) or decimal strings.

## Results

Every `offset` and `length` in the result is an integer count of original-file bytes, as in `inspect_raw_code`,
`decode_file_range` and `carve`. Hint values that are addresses (`initial_sp`, `reset_handler`) are hex strings.

- `source_offset`, `source_length`, `source_size` and `source_range_sha256`: the selection, the file's size and the
  SHA-256 of the selected bytes. `source_observation` says the file was revalidated around a non-atomic read, as
  for `inspect_raw_code`.
- `summary`: occupied bytes and regions, fill bytes by kind (`0xff`, `0x00`, other), high- and low-entropy bytes,
  string and cluster counts. Totals cover the whole selection, including list items that were cut off.
- `regions`: the selection as contiguous runs. `kind` is `fill_ff`, `fill_zero`, `fill_other` (with `fill_byte`)
  or `occupied`. A fill region is a run of one byte at least `min_fill_run` long; everything between fill runs,
  shorter runs included, is occupied. Occupied regions carry `sha256` and `entropy_bits_per_byte` of their bytes.
  A fill run of any length is one region.
- `entropy`: Shannon entropy in bits per byte, rounded to two decimals, for the whole range (`whole_range`) and
  per block. `entropy.blocks` is an array of numbers, one per block, where block `i` starts at
  `source_offset + i * block_size`; `last_block_bytes` is the size of the last, possibly short, block. `spans`
  merges adjacent blocks that are high (at least 7.2) or low (at most 2.0), with their `block_count`, minimum and
  maximum; medium blocks are not listed. Entropy measured on a small sample is biased low: uniformly random
  256-byte blocks average about 7.2 bits per byte, so half of them would miss the high threshold, while 512-byte
  blocks average about 7.6. The block size is therefore at least 512, and a last block shorter than 512 bytes is
  not classified. High entropy is typical of compressed or encrypted data and low entropy of padding or tables,
  but the flags are statistics, not identifications.
- `string_clusters`: dense areas of printable strings (bytes 0x20..0x7e and tab, as `list_strings` counts them),
  from the first string's start to the last one's end, where consecutive strings are at most `cluster_gap` bytes
  apart. Each has its `encoding` (`ascii` or `utf16_le`), string count, string bytes, `density` and up to three
  previews. A preview's `length` is the string's size in bytes, `characters` its length in characters, and `text`
  at most 48 characters, with `truncated` set when cut. `list_strings` returns every string; this is a map of
  where they are.
- `hints`: heuristic candidates, labelled by `hint_interpretation: heuristic_candidates_not_mappings`. Each has a
  `kind`, an `offset`, its `evidence` and an object named for the kind. Vector-table and compressed-component
  hints share the cap of 8, in offset order.

  `cortex_m_vector_table_candidate` has a `cortex_m` object (`initial_sp`, `reset_handler`,
  `handler_words_checked`, `handler_words_plausible`). It is checked at the start of each occupied region and at
  the word-aligned offset just before it, since a table whose first byte equals the preceding fill byte starts
  inside the fill run. It needs a word-aligned initial SP in the SRAM (0x20000000..0x3ffffffc) or CCM
  (0x10000000..0x11000000) range, followed by an odd reset address below 0x20000000, and at least 4 of the next 14
  exception words inside the range, at least half of them zero or odd code-region addresses. Only region starts
  are checked, so a table that follows padding shorter than `min_fill_run`, or that sits inside occupied bytes,
  gets no hint; lower `min_fill_run`, or open the range as a Cortex-M Raw Project with `vector_table` set to its
  address. A candidate establishes no architecture, load base or entry point; [raw-code windows](raw-code.md) and
  [Sleigh decoding](sleigh-decoding.md) take those as explicit analyst assertions.

  `compressed_component_candidate` is a header-checked compressed-component candidate: a small header whose
  words agree with the bytes after it. Its `container` object has `header_offset` (the first field matched; the
  header may start earlier), `payload_offset`, `payload_length`, `payload_entropy_bits_per_byte`, `byte_order`
  of the matched words, `size_field` (the word equal to the payload length), `checksum_field` when one verifies
  (`kind` `byte_sum32`, `byte_sum16` or `crc32`, with its `offset` and `value`), `payload_end` (`range_end`,
  `fill_run`, `next_candidate` or `none`), `decoded_size_candidates` (header words 1 to 128 times the payload
  length), `other_header_words` (uninterpreted; a load address or flags may be among them) and `checks_passed`.
  Headers are looked for where a payload starts at most 128 bytes after the start of the range, of an occupied
  region (the first 4096), or of the previous candidate's payload end (so back-to-back components chain). Fields are 32-bit words,
  little or big endian, within the 64 bytes before the payload. A candidate needs a size word of at least 64 that
  fits in the range, and either a checksum over exactly the payload (a 16-bit sum also needs a boundary or a
  packed payload) or a payload of at least 6.5 bits per byte that ends at the range end or a fill run, with a
  decoded-size word. No codec is named and nothing is decoded: hand `payload_offset`, `payload_length` and a
  decoded-size candidate to `probe_compression` ([decoding](decoding.md#probing-an-unknown-variant)). Not
  checked: checksums over the header or the decoded bytes, checksums other than these three, and fields wider
  or narrower than 32 bits other than 16-bit sums. Payload entropy is measured over its first 64 KiB. CRC-32 is
  tried only for payloads that end at a boundary or are at most 64 KiB, and over at most 64 MiB per call. On
  64 MiB of concatenated executables the search adds about 0.1 s of CPU to the layout (release build, 2026-11-12).

## Bounds and continuation

The selection is at most 64 MiB, read into memory once. A request without `length` on a larger file covers the
first 64 MiB from `offset`.

`bounds` has, for each list, the `total`, the number `returned` and `next_offset`, the offset of the first item
left out; returned items are a prefix in offset order. Regions, blocks and clusters are capped by `region_limit`,
`block_limit` and `cluster_limit`. When one of them was cut, or the 64 MiB cap stopped a whole-file request,
`continuation` gives the `offset` and `length` of a follow-up call and names what was `truncated` (`regions`,
`blocks`, `string_clusters` or `range`). The follow-up restarts every list at that offset, so items after it may
repeat, and its entropy blocks are aligned to the new offset. Following continuations until there is none covers
the whole selection.

Two lists do not move the continuation. Entropy spans are capped at `block_limit` and at most 128: they summarise
`entropy.blocks`, which is complete up to its own cut, so spans past their cap can be read from the block values.
Hints are a sample of at most 8: `bounds.hints` says how many there were and where the first omitted one is;
call again from that offset to see more.

When the blocks were cut off, `entropy.suggested_block_size` is the smallest power of two that fits every block in
`block_limit`, or 16 MiB, the largest block size, when none does (only a 64 MiB selection with a `block_limit`
under 4 is in that case).

The whole JSON result is at most 60000 bytes or refused, naming the limits to lower. The defaults fit even when
every list is full of long entries, such as escape-heavy string previews and alternating entropy spans.

## Limits

- Unix regular files only, with the same checks as the other file-range tools: no symlinks or special files, and
  the file must not change during the read.
- One read of the selection into memory, then linear passes. A 16 MiB image of alternating 1 MiB random and 0xff
  blocks takes about 0.6 s end to end with a development build of the CLI (2026-11-09, Apple silicon).
- Random data contains short printable runs by chance, so high-entropy regions show chance string clusters (of
  short strings, density up to about 0.5 with the defaults). Read clusters against the entropy spans, or raise
  `min_string_length`.
- No format, architecture or codec detection (a compressed-component candidate names no codec): [`carve`](cli-reference.md) finds embedded headers,
  [explicit decoding](decoding.md) decompresses a range with supplied or probed parameters, and `binary triage` reports
  whole-file entropy of loadable formats.
