# ZIP32 metadata inventory reference

Archive inventory describes the central-directory declarations of an explicit standalone, single-disk ZIP32
file. It does not load an image, discover functions, read annotation sidecars or open members.

## CLI and shared tool

```sh
rampage binary archive-inventory package.zip --limit 20
rampage --json binary archive-inventory package.zip --contains manifest --offset 0 --limit 20
```

The `archive_inventory` file tool belongs to the `carve` group:

```json
{"path":"package.zip","offset":0,"limit":20,"contains":"manifest"}
```

`offset` skips matching directory records, not file bytes. `limit` defaults to 100 and accepts 1–100; the JSON
byte budget can shorten a page further. `contains` is a case-sensitive substring of the full raw name, using
the query's UTF-8 bytes before retention truncation, with a 1,024-byte query cap. Unknown arguments are refused.

The CLI has no root-level compatibility alias. Architecture and native-image offset/length arguments are
unsupported and rejected before I/O. The input must be a regular file with a JSON-representable path; native
non-UTF-8 paths return an error rather than being converted lossily or causing a serialization panic.

## Results and member references

Successful pages retain:

- `archive_ref`: file size, central-directory offset/size, EOCD offset, and `metadata_sha256`.
- Independent `declared`, `examined`, `validated`, `retained`, `matched` and `returned` record counts.
- `members`: declarations with distinct directory ordinals, flags, compression method, CRC32, compressed and
  uncompressed sizes, and local-header offsets. Encryption and data-descriptor flags are reported as metadata.
- Raw-name hex, encoding/UTF-8 status, optional UTF-8 display text, original byte length and truncation flags.
- Warning totals/truncation, work/read counts, `more`, `next_offset`, and `byte_capped`.

`validated` means structurally checked directory records, not validated local headers, member contents or payload
extents. `payload_validated` is false. Successful inventories cover the complete bounded directory; structural
or aggregate-budget exhaustion rejects the operation instead of returning a partial success. Name and page
truncation are separate from inventory completeness. An offset past the end retains inventory-wide counts.

`ArchiveMemberRef` pairs `ArchiveRef` with a central-directory ordinal. Duplicate names remain distinct; display
names are not member identities, filesystem paths or extraction-safe names. Absolute, traversal and backslash
names remain metadata and are never followed. Listing a reference does not make that member openable as a native
image or imply support for nested archives.

SHA-256 covers the validated central-directory bytes followed by EOCD fields and the complete raw archive comment.
It is not a whole-archive hash, authentication or payload-integrity proof. Descriptor-backed metadata spans and file
metadata are revalidated, but the observation remains `revalidated_non_atomic_metadata`, not an atomic snapshot.

## Limits and errors

| Boundary | Limit |
| --- | ---: |
| EOCD tail search | 65,557 bytes |
| Central directory | 8 MiB |
| Directory records / EOCD candidates | 4,096 each |
| Retained raw-hex and display-name bytes | 1 MiB |
| Per-name raw prefix | 1,024 bytes |
| Retained warnings | 64, with full total/truncation evidence |
| Examined extra fields | 65,536 |
| Cumulative reads | 24 MiB |
| Successful JSON page | 60,000 bytes, at most 100 rows |
| Shared-tool error text | 4,096 bytes, including any truncation marker |

Unix opens refuse final-component symlinks and use nonblocking descriptor checks; devices and pipes are refused. ZIP64,
multi-disk archives, SFX offset inference, central-directory gaps and digital signatures are unsupported.
Ambiguous header-plausible EOCD candidates are conservatively refused before their directories are validated.

Reads are limited to bounded prefix, tail and directory spans. Tail search can overlap member data; no member or
local-header offset is followed for inspection. There is no decompression, extraction, CRC verification, member
format probing, automatic member opening, nested inspection or execution. Sizes and CRCs remain declarations.
Malformed ranges, truncated records, changed metadata and exhausted budgets return errors, not proof of absent members.
