# Native-image data inspection

`binary inspect-data`, MCP `inspect_data`, and `inspect_native_data` inspect a bounded range of native-image
bytes and candidate words without function discovery, annotation sidecar access, or edits.
The CLI and MCP use the lightweight retained-binary API, not a Project's eager stub/thunk naming indexes.
Native metadata opening also skips optional Go/Objective-C symbol-recovery scans; normal loading retains them.
An existing Project also exposes `inspect_data` as a convenience wrapper.

## Requests

```sh
rampage --json binary inspect-data example.dylib --at 0x4020 --size 32
rampage --arch aarch64 binary inspect-data example.dylib --at _owned_blocks --size 8
```

MCP accepts the ordinary `path`, `arch`, `image_offset` and `image_length` selectors plus:

| Argument | Meaning |
| --- | --- |
| `at` | Required image VA or existing metadata name; not an outer-file offset or runtime address. |
| `size` | 1 through 1024 bytes, default 128. |
| `word_size` | 4 or 8 bytes; omitted uses the image architecture's pointer width. |

Words start exactly at `at`. No alignment, table boundary, field layout or pointer interpretation is inferred
from the request. Any remainder shorter than a word is counted in `trailing_bytes` and retained in byte spans.
Native ELF, PE and Mach-O images are accepted. Captured snapshots use the separate runtime inspection tools;
this operation does not make unrecognized firmware loadable.

## Results

The result includes the selected image's architecture, format, optional Mach-O UUID, source-file slice offset
and size. Byte spans distinguish `stored`, `zero_fill`, `unavailable`, `unmapped` and `unreadable` states.
Only stored bytes have hexadecimal/ASCII contents. Zero-fill declarations are not returned as observed zeros.
ELF mapped zero-fill follows load-segment extents, not TLS NOBITS section ranges that may overlap stored data.

Span `image_offset` is relative to the selected image; `file_offset` is relative to its outer file, including
universal-binary and embedded-image selection. Addresses remain image VAs. Neither offset is a runtime address.

Each complete word retains its raw value when all bytes are available. Interpretations distinguish:

- `raw_word_candidate`: the raw word can be inspected as a candidate address, not a proven pointer.
- `macho_chained_rebase`: the loader retained an exact chained-rebase target for this native-width slot.
- `import_binding`: bounded name and library metadata identify the slot; binding words are not followed as code targets.
- `partial_pointer_metadata`: grouping overlaps only part of a known native import/rebase slot, or crosses its
  boundary; raw bytes remain visible but encoded fragments are not followed.
- `zero_word` and `unavailable`: no target is suggested.

Mapped candidate targets include permissions, code-range metadata, declared function-start evidence, up to two
exact symbol/export labels, and an optional printable ASCII preview. Previews read at most 64 stored bytes;
`ascii_terminated` distinguishes a captured terminator from a cut prefix. Labels are display-limited to
96 characters, with an explicit truncation suffix. For ARM callbacks, bit zero is cleared only when declared
Thumb mode and code-range metadata corroborate it; `address_adjustment` records that change and the word's raw
value is preserved. Arbitrary odd data addresses are not changed. UTF-16 strings and other tagged/authenticated
pointer decoding are not supplied by this view. Other relocations are not applied.

These links do not insert functions, CFG edges, names, types or annotations. A code-range match is not verified
instruction decoding, a descriptor layout, a callback association, or evidence of execution. Writable source
slots remain on-disk observations, not loaded pointer values.

Any retained loader warning suppresses all pointer target links, including native-width rebases and partial
words. Raw bytes/words and retained import identities remain visible. Diagnostics retain exact warning totals
and omitted counts, with display caps of 16 messages, 512 bytes per message and 4096 message bytes total.
No warnings does not prove pointer-metadata completeness.

## Bounds and source checks

Requests refuse overlapping/overflowing mappings, over 4096 segments, sections or Thumb ranges, and over 131072
combined symbol/export/function-start/import-slot/rebase records. Exact metadata-name lookup is bounded and
rejects ambiguous names; it does not discover import stubs or consult annotation sidecars.
Results are whole JSON under a 48000-byte encoded budget;
oversized results refuse with a request to reduce `size` instead of truncating JSON or hiding individual entries.

Original mapped-file metadata is checked before and after inspection when available. Owned test inputs have
no original-file proof. Metadata checks do not make mapped reads atomic with concurrent changes or truncation;
the UUID and slice metadata are not content hashes or authenticity evidence. Only inspect files whose backing
is kept stable for the query.

## Owned compiled acceptance fixture

The descriptor fixture contains an independently authored gain block with initialization, update and processing
callbacks. Compile it centrally and run the explicit opt-in test without loading or executing the dylib:

```sh
scratch="$(mktemp -d)"
trap 'rm -r "$scratch"' EXIT
clang -O2 -dynamiclib tests/fixtures/src/data-navigation.c -o "$scratch/owned.dylib"
strip -x "$scratch/owned.dylib"
RAMPAGE_DATA_FIXTURE="$scratch/owned.dylib" cargo test --locked -j 2 -p rampage-api --lib \
  compiled_stripped_descriptor -- --ignored
```

Local acceptance covers optimized, local-symbol-stripped ARM64 and x86-64 Mach-O fixtures, including an ARM64
chained-fixup fixture. Synthetic regressions cover byte order, gaps, zero-fill, unavailable backing, unreadable
ranges, import identities, partial encoded slots, Thumb callbacks, output bounds and invalid ranges. A separate
compiled ELF regression exercises TLS NOBITS overlapping stored initializers. That coverage does not establish
general descriptor recovery, other relocation families or unknown-firmware loading.
