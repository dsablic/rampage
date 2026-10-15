# Historical function inventory cache

The desktop's **Cached function inventory** window displays bounded historical candidates separately from
current functions. Opening the window does not read a cache, start discovery or initialize a native engine.
Load and save require an explicit path. Save requires separately completed global analysis; it never starts it.
Cache operations share the workspace file-operation lease, including while a cancelled operation finishes.

## Trust and invalidation

Every loaded row remains **cached / unverified**. Rows contain a raw hexadecimal address, historical display
name, byte count, block count and instruction count. They do not restore blocks, graphs, types, signatures,
solver state, current function boundaries or decompiler-entry eligibility. Inspecting a selected raw address
is separate from requesting decompilation. Fresh function, triage and string views remain independent.

The dependency key includes original source and selected-image hashes, actual loader/target/mapping context,
loader names, analyst names and decoder/discovery/naming versions. SHA-256 checksums check consistency, not
authorship: a forged cache with a recomputed key and checksum still grants no authority.

A view binds the exact open Project and its names-only revision, independently of navigation and active module
selection. Comments, types and native compiler settings do not invalidate this pure inventory. Real name changes,
including rename-and-restore, project replacement and original-source changes invalidate it. No-op name replay
and comment-only log creation/restart preserve it. Adoption and raw-address inspection recheck source metadata;
paint does not hash the source. Metadata checks do not make concurrent external writes safe: keep input files
quiescent while mapped data is being read.

## Limits and publication

- Mapped original files only; owned runtime snapshots are unsupported.
- Default capture: 2,048 rows, with total count and explicit truncation; maximum document row count: 8,192.
- Document: 1 MiB; depth: 8; structural elements: 65,536; encoded string: 4 KiB.
- Source-key input: 256 MiB, with bounded context/name metadata.
- Unknown/duplicate fields, trailing input, numeric addresses and malformed or oversized input are rejected
  before adoption. Rejection or cache miss never falls back to discovery.
- Private same-user directory/file modes, retained descriptors, no symlink following and no-clobber publication.
  No overwrite, autoscan, eviction or automatic cleanup. Publication notices retain uncertain destinations and
  staging paths even if cancellation or a stale binding prevents adopting an operation's result.

## Measured scope

On the owned generated 2,301-function ELF, three fresh-Project full reopens had a median of **93.86 ms** with
discovery and **22.41 ms** with the usable cache (2,048 historical rows). The selected predeclared 2x threshold
passed at **4.19x**. Full cached reopen includes loading, dependency hashing, private reading, preflight and parsing.

The two-function control was **slower** with a cache: median **0.294 ms** fresh versus **1.083 ms** cached.
Filesystem/spec caches were uncontrolled; RSS was unavailable. These results are fixture-specific, not a claim
that caching helps small inputs or improves analysis/decompilation. No target fixture was executed.
