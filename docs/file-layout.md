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
| `block_size` | `--block-size` | 4096 | Entropy block size, 256..=16 MiB. Blocks start at `offset`. |
| `min_string_length` | `--min-string-length` | 6 | Shortest printable run counted as a string, 4..=64. |
| `cluster_gap` | `--cluster-gap` | 64 | Largest gap between strings of one cluster, 0..=4096 bytes. |
| `cluster_min_strings` | `--cluster-min-strings` | 3 | Fewest strings a cluster needs, 1..=64. |
| `utf16` | `--utf16` | false | Also cluster UTF-16LE strings of ASCII-range characters. |
| `hints` | `--no-hints` | true | Report heuristic hints. |
| `region_limit` | `--region-limit` | 128 | Regions returned, 1..=256. |
| `block_limit` | `--block-limit` | 1024 | Per-block entropy values returned, 1..=4096. |
| `cluster_limit` | `--cluster-limit` | 32 | String clusters returned, 1..=128. |

An explicit zero length, an offset at or past the end of the file and a range outside the file are refused. Offsets
and lengths accept integers, hex (`0x...`) or decimal strings.

## Results

All offsets are original-file byte offsets, as hex strings.

- `sha256`: SHA-256 of the whole selected range. `source_observation` says the file was revalidated around a
  non-atomic read.
- `summary`: occupied bytes and regions, fill bytes by kind (`0xff`, `0x00`, other), high- and low-entropy bytes,
  string and cluster counts. Totals cover the whole selection, including list items that were cut off.
- `regions`: the selection as contiguous runs. `kind` is `fill_ff`, `fill_zero`, `fill_other` (with `fill_byte`)
  or `occupied`. A fill region is a run of one byte at least `min_fill_run` long; everything between fill runs,
  shorter runs included, is occupied. Occupied regions carry `sha256` and `entropy` of their bytes. A fill run of
  any length is one region.
- `entropy`: Shannon entropy in bits per byte for the whole range (`whole_range`) and per block (`blocks`, block
  `i` at `offset + i * block_size`; `last_block_bytes` is the size of the last, possibly short, block). `spans`
  merges adjacent blocks that are high (at least 7.2) or low (at most 2.0), with their minimum and maximum;
  medium blocks are not listed. A block shorter than 256 bytes is not classified, since its entropy cannot reach
  8. High entropy is typical of compressed or encrypted data and low entropy of padding or tables, but the flags
  are statistics, not identifications.
- `string_clusters`: dense areas of printable strings (bytes 0x20..0x7e and tab), from the first string's start
  to the last one's end, where consecutive strings are at most `cluster_gap` apart. Each has its `encoding`,
  string count, string bytes, `density` and up to three previews of at most 48 characters. `list_strings` returns
  every string; this is a map of where they are.
- `hints`: heuristic candidates, labelled by `hint_interpretation: heuristic_candidates_not_mappings`. The one
  kind so far is `cortex_m_vector_table_candidate`, checked at the start of each occupied region (and at the
  word-aligned offset just before it, since a table whose first byte equals the preceding fill byte starts inside
  the fill run): a word-aligned initial SP in the SRAM (0x20000000..0x3ffffffc) or CCM (0x10000000..0x11000000)
  range, followed by an odd reset address below 0x20000000, with at least half of the next 14 exception words
  zero or odd code-region addresses. Each lists its evidence. A candidate establishes no architecture, load base
  or entry point; [raw-code windows](raw-code.md) and [Sleigh decoding](sleigh-decoding.md) take those as
  explicit analyst assertions.

## Bounds and continuation

The selection is at most 64 MiB, read into memory once. A request without `length` on a larger file covers the
first 64 MiB from `offset`.

Lists are capped by `region_limit`, `block_limit` and `cluster_limit`, and entropy spans at 64 and hints at 16.
`bounds` has, for each list, the `total`, the number `returned` and `next_offset`, the offset of the first item
left out. Returned items are always a prefix in offset order. When anything was left out, `continuation` gives the
`offset` and `length` of a follow-up call and names what was `truncated` (the lists, or `range` for the 64 MiB
cap). The follow-up restarts every list at that offset, so items after it may repeat, and its entropy blocks are
aligned to the new offset. When the blocks were cut off, `entropy.suggested_block_size` is a power of two that
fits every block within `block_limit`.

The whole JSON result is at most 60000 bytes or refused, naming the limits to lower; the defaults fit.

## Limits

- Unix regular files only, with the same checks as the other file-range tools: no symlinks or special files, and
  the file must not change during the read.
- One read of the selection into memory, then linear passes. A 16 MiB image of alternating 1 MiB random and 0xff
  blocks takes about 0.6 s end to end with a development build of the CLI (2026-11-09, Apple silicon).
- Random data contains short printable runs by chance, so high-entropy regions show chance string clusters (of
  short strings, density up to about 0.5 with the defaults). Read clusters against the entropy spans, or raise
  `min_string_length`.
- No format, architecture or compression detection: [`carve`](cli-reference.md) finds embedded headers,
  [explicit decoding](decoding.md) decompresses a range with supplied parameters, and `binary triage` reports
  whole-file entropy of loadable formats.
