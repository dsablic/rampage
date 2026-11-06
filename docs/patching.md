# Checked byte patches and export

## Supported inputs

Patches are annotation-log entries, not writes to the source executable. The supported profile is
whole-file, little-endian, static `ET_EXEC` ELF64 images for x86-64 and AArch64. Dynamic/interpreter metadata,
snapshots/captures, embedded/fat images, relocatable objects, ambiguous mappings, zero-fill, headers and
loader-control metadata reject. Unsupported relocation/control encodings also reject explicitly.

Mapped code payload is the default. Non-code payload additionally requires explicit `allow_data: true`.
Every admitted range must have unique virtual and file backing and preserve the loader layout after reparse.
Data permission does not authorize changes to loader metadata hidden inside nominal payload sections.

## Review and mutation

The Core MCP tools are `list_patches`, `patch_bytes`, `revert_patch` and `export_patched`. Their common
`path` selects the original image. Patch requests contain:

- `at`: an address or resolvable function/symbol name.
- `original_hex` and equal-length `replacement_hex`.
- Explicit `allow_data`.
- `source_sha256` and `expected_revision` from the reviewed patch receipt.

Revert requires `at`, `source_sha256` and `expected_revision`. The core APIs validate identity and
revision consent inside the authoritative annotation transaction, not merely in frontend preflight.

Original bytes always refer to the original file—not an earlier replacement. Overlapping active ranges and
file-offset aliases reject; an exact-key update retains its original range/preimage. Limits are 4,096 bytes
per range, 256 active ranges, 64 KiB total replacement bytes and a 256 MiB original image.

Receipts distinguish original source, effective-byte and patch-revision SHA-256 values, active ranges and
changed bytes. Owned effective bytes are not original mapped-file or producer-authentication evidence.
Patch-list rows and their receipt describe the same held view; listing does not silently claim authority
freshness.

## Effective views and history

Each effective project has immutable bytes and a corresponding frozen annotation view. Discovery, listing,
strings, triage, native/worker decompilation and other byte-derived caches are fresh for that project.

The Rust patch methods use `&Arc<Project>` and return `PatchOutcome`. Subsequent reads use its returned
`project`. Reacquire `effective_snapshot()` after undo/redo, external refresh or any ordinary annotation
mutation. Earlier held effective views remain paired with their original bytes/annotations. An original
project without a frozen map may still observe its authoritative annotation map.

Writes and publication checks use authoritative state, not frozen presentation tokens. Byte-dependent
native mutations reject stale byte contexts or validate an exact candidate context. Checked debug-layout
and operand metadata is refused when incompatible; patching does not waive or rebind its proof requirements.

Undo/redo use annotation transactions and same-process history. Cross-process logs replay checked
state, but do not restore in-process undo history. Invalid patch records reject atomically rather than
falling back to unpatched output. Complete log records must be exactly one JSON object; ingestion and line
budgets apply from the first byte, including newline-free tails.

## Export

Export requires `destination`, reviewed `source_sha256` and `expected_revision`. It stages a complete,
validated image privately, writes/syncs it, then publishes with exclusive create-new semantics. Existing
destinations are never replaced, and original input bytes are never modified. Failed staging does not
publish a partial executable. Staging cleanup is identity-checked and best-effort after successful publication.

Export/reopen does not reuse the source's patch sidecar. A new session opens the exported bytes as their own
image. Source stability checks detect observed changes but do not provide atomicity against arbitrary
external file writes, truncation or path replacement.

## Assistant lifecycle

Shared dispatch carries effective projects between operations. Before/after annotation witnesses are
process-local identities captured under the core transaction lock, not serialized user assertions. A run
advances only when the committed transition is attributable to its expected state. External or opaque
unattributable transitions end the run while preserving completed-operation evidence.

Cancellation blocks subsequent model/tool admission and stale text/navigation/conversation restoration.
An already-admitted synchronous tool is not interrupted or rolled back. Completed mutation outcomes have
a one-shot delivery path independent of ordinary conversation cancellation. Closing the workspace discards
undelivered in-memory UI evidence—not committed edits.

An unavailable post-commit refresh is not reported as a rolled-back mutation. Oversized success receipts use
complete bounded summaries with explicit omissions and original-result hash/length, not truncated JSON.

[Assembly](assembly.md) is a separate pure operation: review its bytes, then explicitly submit a checked patch.
Neither assembly nor patch/export verification executes the target.
