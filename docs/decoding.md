# Explicit content decoding

`binary decode` and MCP `decode_file_range` decode a selected regular-file range without requiring an
executable header. The API returns an owned `DecodedContent` buffer and a separate bounded `DecodeReceipt`.
CLI/MCP return only the receipt and a requested preview; the full content stays transient.

## Decoder providers

The internal `Decoder` interface accepts bytes, options and a cooperative cancellation callback. A provider
returns decoded bytes, consumed input bytes and work steps. The host supplies file access, source checks,
hashing, resource ceilings and previews. There is no dynamic provider loading, public plugin SDK or new
permission granted to the triage-report WASM ABI.

The built-in provider is `lzss-4k`:

| Property | Interpretation |
| --- | --- |
| Dictionary | 4096-byte circular buffer |
| Initial write position | Explicit parameter; CLI/MCP default 4078 (`0xfee`) |
| Initial contents | Explicit fill byte; default zero |
| Flags | Least-significant bit first; one means literal |
| Reference offset | First byte OR the second byte's high nibble shifted left four bits |
| Reference length | Second byte's low nibble plus three |
| Copying | Overlap and dictionary wraparound are supported |
| Stopping condition | Caller-supplied expected output size; no end marker |

This names one precise variant, not every format called LZSS. No codec is guessed. A reference that would
exceed the expected output size refuses instead of being shortened to fit. Trailing encoded input is reported,
not silently treated as padding or certified as part of a complete stream.

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
| `--codec` | Required; `lzss-4k` is the only codec |
| `--offset`, `--length` | Required original-file range |
| `--expected-output-size` | Required analyst-supplied stopping size, not a discovered boundary |
| `--initial-write-offset` | Dictionary write position in 0 through 4095, default 4078 |
| `--dictionary-fill` | Initialization byte in 0 through 255, default zero |
| `--timeout-ms` | Cooperative decode-phase timeout, default 3000, at most 10000 |
| `--preview-offset` | Decoded byte offset, default zero |
| `--preview-size` | 0 through 1024 bytes, default 256 |

Native-image `--arch`, `--image-offset` and `--image-length` selectors do not apply and are rejected.

## MCP

`decode_file_range` belongs to the default core group. Its arguments use `path`, `codec`, `offset`, `length`
and `expected_output_size`, with underscore spellings for the optional CLI parameters above. File offsets
and lengths may be nonnegative JSON integers or hexadecimal/decimal strings. Unknown selectors and missing
codec selection refuse before source access.

Preview paging repeats the bounded decode rather than retaining a hidden payload cache. Compare source-range
and output hashes across observations; matching hashes are content evidence, not authenticity or atomicity.

## Receipts and limits

Receipts retain the selected source range and file size, SHA-256 of selected bytes, their additive byte sum,
the exact codec parameters, expected/actual output sizes, output SHA-256, consumed/trailing input counts and
work/deadline settings. Completion is labelled `expected_output_size_reached`, never an inferred stream end.
Decoded offsets are a distinct coordinate space: they are not original-file offsets or load addresses.

| Resource | Ceiling |
| --- | --- |
| Selected encoded input | 8 MiB |
| Decoded output | 16 MiB |
| Expansion | 128:1 against the entire selected input, including trailing input |
| Decoder work | 64 Mi steps: one per token plus one per emitted byte |
| Preview | 1024 bytes |
| Encoded JSON receipt | 16384 bytes; errors refuse rather than truncate JSON |

The built-in Rust decoder cooperates with cancellation and allocation/work budgets; this is not a sandbox
for untrusted third-party provider code. Source reading and hash computation are not forcibly timed out.
File-range access requires Unix regular-file checks; other platforms refuse that operation.
Final symlinks, special files, out-of-range reads and observable descriptor/path changes are rejected.
Metadata is revalidated around reading/decoding, but file reads are not atomic with concurrent modification.

Neither a successful decode, a size match, a hash nor an additive checksum authenticates the content or proves
container-field meanings. No commercial decoded payloads, container templates or captures are bundled with
this facility; test vectors are independently owned.
