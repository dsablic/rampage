# Explicit content decoding

`binary decode` and MCP `decode_file_range` decode a selected regular-file range without requiring an
executable header. The API returns an owned `DecodedContent` buffer and a separate bounded `DecodeReceipt`.
CLI/MCP return only the receipt and a requested preview; the full content stays transient.

When the variant is unknown, `binary probe-compression` and MCP `probe_compression` sweep the built-in families
over the range and return ranked parameter sets that `decode_file_range` accepts unchanged
([probing an unknown variant](#probing-an-unknown-variant)).

## Decoder providers

The internal `Decoder` interface accepts bytes, options and a cooperative cancellation callback. A provider
returns decoded bytes, consumed input bytes and work steps. The host supplies file access, source checks,
hashing, resource ceilings and previews. There is no dynamic provider loading, public plugin SDK or new
permission granted to the triage-report WASM ABI.

| Codec | Variant |
| --- | --- |
| `lzss-4k` | The classic 4096-byte ring: LSB-first flags, one means literal, 12-bit ring position (first byte, then the second byte's high nibble), length nibble plus three. Ring start default 4078 (`0xfee`), fill default zero. |
| `lzss` | Every LZSS parameter explicit in an `lzss` object (below). `lzss-4k` is the `lzss` variant with window 12, minimum match 3, `lsb_first`, literal bit 1, `split_byte` and `ring_position`. |
| `lz4-block` | The LZ4 block format: token, literals, 16-bit little-endian distance, match of at least four. No frame header, checksum or external dictionary. |

The `lzss` object:

| Field | Values | Meaning |
| --- | --- | --- |
| `window_bits` | 10..=13 | Offset bits (a 1, 2, 4 or 8 KiB window); the length field has the other `16 - window_bits` bits. |
| `min_match` | 2, 3 | Added to the length field. |
| `flag_order` | `lsb_first`, `msb_first` | Which bit of a flag byte describes the first of its eight tokens. |
| `literal_bit` | 0, 1 | The flag bit value that means a literal. |
| `reference_layout` | `split_byte`, `le16_offset_low`, `le16_length_low`, `be16_offset_low`, `be16_length_low` | How the two reference bytes split into offset and length. `split_byte`: offset is the first byte plus the second byte's high bits; length is the second byte's low bits. The others read a 16-bit word in the named byte order with the offset or the length in the low bits. |
| `offset_mode` | `ring_position`, `distance`, `distance_minus_one` | An absolute position in a ring (with `initial_write_offset` and `dictionary_fill`), or a distance back from the next output byte (optionally biased by one). Distances past the output start refuse. |

`initial_write_offset` and `dictionary_fill` are top-level arguments, used only by ring offsets; they must be
zero (their default for `lzss` and `lz4-block`) otherwise. `lzss` parameters are refused for the other codecs.

No codec is guessed by the decoder. A reference that would exceed the expected output size refuses instead of
being shortened to fit. Trailing encoded input is reported, not silently treated as padding or certified as part
of a complete stream.

## CLI

An owned literal example:

```sh
printf '\007ABC' > sample.lzss
rampage --json binary decode sample.lzss --codec lzss-4k \
  --offset 0 --length 4 --expected-output-size 3
```

The output preview is `ABC`. To inspect another decoded window, set `--preview-offset` and `--preview-size`.
Offsets and lengths accept hexadecimal or decimal. A zero preview size requests hashes and metadata only.
There is deliberately no output-file argument, automatic extraction, native loading or execution.

| Argument | Meaning |
| --- | --- |
| `--codec` | Required; `lzss-4k`, `lzss` or `lz4-block` |
| `--lzss` | Codec `lzss` only: the `lzss` object as JSON, as `probe-compression` prints it |
| `--offset`, `--length` | Required original-file range |
| `--expected-output-size` | Required analyst-supplied stopping size, not a discovered boundary |
| `--initial-write-offset` | Ring write position below the window; default 4078 for `lzss-4k`, zero otherwise |
| `--dictionary-fill` | Ring initialization byte in 0 through 255, default zero |
| `--timeout-ms` | Cooperative decode-phase timeout, default 3000, at most 10000 |
| `--preview-offset` | Decoded byte offset, default zero |
| `--preview-size` | 0 through 1024 bytes, default 256 |

Native-image `--arch`, `--image-offset` and `--image-length` selectors do not apply and are rejected.

## MCP

`decode_file_range` belongs to the default core group. Its arguments use `path`, `codec`, `offset`, `length`
and `expected_output_size`, with `lzss` and underscore spellings for the optional CLI parameters above. File
offsets and lengths may be nonnegative JSON integers or hexadecimal/decimal strings. Unknown selectors and missing
codec selection refuse before source access.

Preview paging repeats the bounded decode rather than retaining a hidden payload cache. Compare source-range
and output hashes across observations; matching hashes are content evidence, not authenticity or atomicity.

## Receipts and limits

Receipts retain the selected source range and file size, SHA-256 of selected bytes, their additive byte sum,
the codec and its exact parameters (`lzss` for that codec), dictionary size, expected/actual output sizes, output
SHA-256, consumed/trailing input counts and work/deadline settings. Completion is labelled
`expected_output_size_reached`, never an inferred stream end. Decoded offsets are a distinct coordinate space:
they are not original-file offsets or load addresses.

| Resource | Ceiling |
| --- | --- |
| Selected encoded input | 8 MiB |
| Decoded output | 16 MiB |
| Expansion | 128:1 against the entire selected input, including trailing input |
| Decoder work | 64 Mi steps: one per token plus one per emitted byte |
| Preview | 1024 bytes |
| Encoded JSON receipt | 16384 bytes; errors refuse rather than truncate JSON |

The built-in Rust decoders cooperate with cancellation and allocation/work budgets; this is not a sandbox
for untrusted third-party provider code. Source reading and hash computation are not forcibly timed out.
File-range access requires Unix regular-file checks; other platforms refuse that operation.
Final symlinks, special files, out-of-range reads and observable descriptor/path changes are rejected.
Metadata is revalidated around reading/decoding, but file reads are not atomic with concurrent modification.

Neither a successful decode, a size match, a hash nor an additive checksum authenticates the content or proves
container-field meanings. No commercial decoded payloads, container templates or captures are bundled with
this facility; test vectors are independently owned.

## Probing an unknown variant

```sh
rampage binary probe-compression image.bin --offset 0x1110 --length 0x9c40 --expected-output-size 0x10000
```

MCP: `probe_compression` (core) with `path`, `offset`, `length` and optionally `expected_output_size`,
`candidate_limit` (1..=16, default 5), `timeout_ms` (1..=30000, default 15000) and `preview_size` (0..=128, default
48). A [file layout](file-layout.md) `compressed_component_candidate` hint supplies the payload range and
decoded-size candidates.

The sweep, within 768 Mi work steps and the deadline:

1. With an expected size, a token walk over the whole input (no copying) for each of the 160 parses (window,
   minimum match, flag order, literal bit, reference layout) keeps those that reach the size exactly.
2. Each remaining LZSS variant decodes the first 16 KiB of input, in distance, biased-distance and ring modes. For
   ring offsets, the starts tried are `window - max_match` and zero, plus the starts that best explain the first
   references when neither does. Each is scored on parse statistics: skewed length fields, references close
   behind the output end, references that read written data, and an entropy drop.
3. The best variants decode the whole range. A ring variant whose output reads the initial fill is also decoded
   with fills 0x00, 0x20 and 0xff. The LZ4 block format is tried once on the whole range.

Each candidate has a `verdict`, `score`, `decode_arguments` (pass to `decode_file_range` with `path`), output
size and SHA-256, consumed and trailing input, `stream_end`, literal and reference counts, `metrics`, named
`checks`, `parse_equivalents`, `same_output_variants` and a short preview. `decode_check` says whether
`decode_file_range`'s provider, with its budgets, reproduced the bytes.

| Check | Passes when |
| --- | --- |
| `enough_references` | At least 16 references decoded |
| `input_consumed` | At most 3 trailing bytes, or trailing bytes that are one repeated byte (padding) |
| `output_entropy_below_input` | Output entropy at least 0.1 bits per byte below the input's |
| `expected_output_size_reached` | With an expected size: decoding reached it exactly |
| `length_fields_skewed`, `references_mostly_near`, `references_read_written_data` | LZSS parse statistics look like an encoder's, not noise |
| `block_ends_with_input` | LZ4: the block's last literals end at the input's end |

Variants that decode the same bytes from the same input fold into the simplest (`same_output_variants`).
Variants that split the input into the same tokens but decode different bytes, such as another minimum match,
distance bias, ring start or fill, are parse-equivalent. They are ordered by `extendable_matches`, short
references whose next output byte equals the byte after their source, which a greedy or lazy encoder would
have extended. The right parameters have almost none, and shifted ones have many. Output entropy breaks ties.

`confident` needs every check, the supplied size and a first candidate with clearly fewer extendable matches
than any parse-equivalent rival: at least two fewer and less than half as many. Otherwise passing candidates are
`plausible` and the others `weak`. Without an expected size nothing is confident. An exercised ring fill is
often undecidable from the stream, since every fill decodes self-consistently; the first is then `plausible`
and its rivals are listed.

`sweep` reports the families and parameter space, counts of variants, walks, sample and full decodes, size
mismatches, steps, and `stopped_early` (`work_budget` or `cancelled`) when the space was not fully tried.
`not_tried` lists what is outside the sweep: other LZSS token shapes and end markers; variable-length LZ77 codes,
LZO, LZMA, deflate, zstd, Brotli and LZ4 frames; streams not starting at the offset; and architecture-aware
plausibility.

Measured on owned inputs (`cargo run --release -p rampage-decode --example probe_sweep`, Apple silicon,
2026-11-12): seven LZSS variants and LZ4 over generated firmware-like content, a 4.9 KiB Thumb image and a
252 KiB executable. With the decoded size, every `confident` first candidate decoded the original exactly
(18 of 32 cases). The other 14 were `plausible`, 13 of them with the right parameters first; most were an
undecidable ring fill over zero-heavy content. In the 14th the right fill was a listed rival. Uncompressed and random inputs got only `weak` candidates. A 1 MiB stream takes
0.3 to 0.5 s with the size and 0.4 to 1.5 s without; 1 MiB of uncompressed or random input takes 1.3 to 2.1 s.
