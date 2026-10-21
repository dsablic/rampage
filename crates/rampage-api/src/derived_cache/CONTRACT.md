# FunctionInventoryCacheV0 API contract

## Operations and outcomes

`capture_function_inventory(Arc<Project>, &mut ProjectWorkspaceTaskControl)` returns
`Result<PreparedFunctionInventory, ApiError>`. It requires already completed successful
`Project::cached_analysis_checked()`, with current backing/interpretation checks and typed cached errors.
It never initializes analysis, scans for functions or initializes a native decoder.

`read_function_inventory(Arc<Project>, &Path, &mut control)` returns
`Result<InventoryCacheReadOutcome, ApiError>`, with these outcomes:

- `Hit(CachedFunctionInventory)`: dependency-consistent historical rows, permanently cached/unverified.
- `Miss`: absent explicit cache, or a supported valid document with different dependencies.
- `Rejected`: malformed, over-budget, unsupported, checksum-invalid or privately unreadable document.
- `SourceChanged`: current original-source or names binding failed validation.

Cancellation, unavailable annotation locks and unsupported/over-budget current key inputs return `ApiError`.
Diagnostics contain constant descriptions, not attacker JSON values. No fallback discovery or write occurs.

`publish_function_inventory(&PreparedFunctionInventory, &Path, &mut control)` returns
`Result<InventoryCachePublication, ApiError>`. The publication alias preserves private workspace publication
semantics, including PublishedUncertain after commit and typed retained-staging failures before commit. It uses
private 0700 parent/0600 file, no-clobber publication and original-source/names checks at every publication phase.
There is no overwrite, eviction, autoscan, startup read or analysis fallback. Cancellation is cooperative.

Two explicit background-only measurement helpers are exposed: `function_inventory_dependency_key` hashes
dependencies without discovery; `completed_function_inventory_rows` performs the exact capture projection on
already completed analysis, without hashing. It returns display-only DTOs, not an opaque authority. The fresh
baseline explicitly starts discovery through `Project::functions(limit=0)` before calling that projection.
The reader preflights/parses its explicit private document before source hashing, so missing/rejected documents
do not scan source bytes. A usable hit's FULL REOPEN still includes the complete dependency key. Phase boundaries
separate private read, raw preflight/parse/checksum, source key and final current-metadata validation.

## Display-only objects and UI binding

Opaque prepared/view objects retain the exact current project Arc, dependency key and process-local names-only
nonce. The nonce is only for Arc::ptr_eq, not authentication. Adoption checks names and original source metadata
again. Comments, types, signatures and native compiler settings do not invalidate pure inventory. UI binds
module ID plus exact Arc plus names nonce independently of selection/navigation; no native status comes from a
DTO. An explicit raw-address inspection requires current source metadata; that check is not source evidence,
cache authenticity, function-entry validation, native eligibility or analyst consent. Existing exact-entry
metadata validation remains independent and cannot accept this cache as an origin. Analyst assertions remain
explicit separate actions.

`FunctionInventoryCacheRow` contains a canonical hex address, historical name, summed block byte lengths, block
count and instruction count. Those are hints only, with no blocks, graphs, signatures, solver state or geometry
validity restored. `CachedFunctionInventory::provenance()` is always `cached_unverified_historical`, independently
of every wire field. There is no serde constructor for the opaque view or prepared object. Deserializable DTOs
and keys cannot initialize Project analysis or establish fresh authority.

## Key and wire envelope

The strict envelope fields are `version`, `key`, `total_functions`, `truncated`, `rows` and `payload_sha256`.
The only schema version is `FunctionInventoryCacheV0`. Counts/order/truncation are checked; duplicates, unknown
fields, trailing JSON and unsupported algorithms are rejected. No source paths, frame imports or native-origin
flags exist in the envelope. Explicit publication paths remain outside the document.

The key contains source/image/context/names SHA-256 strings and explicit decoder/discovery/naming versions:
`rampage-decoder-target-v1`, `rampage-recursive-global-noreturn-v1`, `rampage-default-namer-rendered-v1`.
Changing these algorithms requires a version change. Context covers actual normalized embedded/fat selection,
format, architecture, code/data endian, mapping addresses/backed/virtual extents/permissions, public loader
symbol/import/export/function-start inputs, actual constructor-rendered names, private code ranges/rebases and
actual Target modes/global pointer/GOT. Names-only annotation hashing uses canonical address order; no comments,
types, signatures or native compiler options enter it. Counters/text lengths are checked before copying/hashing.

`payload_sha256` covers a domain-separated, length-prefixed encoding of every key field, total count, truncation,
row count and every row field. Integer encodings are little-endian u64 except the one-byte truncation flag.
SHA checksums detect damage, not authorship: an attacker can recompute the checksum and matching source key
without acquiring authority. No MAC, secret key, keychain or host-origin stamp is claimed.

Limits: 1 MiB document, depth 8, 65,536 structural elements, 4 KiB per encoded string, 1 MiB total string data,
8,192 rows maximum, 2,048 captured rows by default, 256 whitespace bytes per run. Raw allocation-free preflight
occurs before Value/tagged-enum/row-vector allocation. Addresses are canonical lowercase hexadecimal strings
within u64, never JSON numeric addresses. Key metadata has 65,536 counted items, 4 KiB/string and 1 MiB named
data, with bounded streaming context hashing and a 256 MiB source cap. Projection limits aggregate block visits
to 65,536 and checks each borrowed name before cloning it.

## Original-source boundary

Source snapshots/owned inputs are unsupported in milestone 1 because no retained original descriptor exists.
A future SourceOwned design requires a new explicit source-document guard, not reopening an untrusted path.
Source identity uses original mapped bytes plus actual constructor selection/context, mutable public metadata
and actual loader names. Native backing validation returns true before and after mapped reads, including error
exits. Metadata checks cannot make mapped reads atomic against concurrent external writes/truncation; the host
keeps the source quiescent. Source/names bindings are checked before return even on cache misses/rejections.

## Integration helpers

- `Project::names_revision() -> Result<Arc<()>, ApiError>`: nonblocking names-only token, rotated by actual name
  value changes or clearing nonempty names on restart. Comment replay and no-op name replay preserve it;
  meaningful name A-to-B-to-A changes do not. Detached snapshots retain it. The all-annotation token is separate.
- `Project::inventory_loader_names() -> impl ExactSizeIterator<Item = (u64, &str)>`: implemented borrowed actual
  constructor map via the added `Names::entries()` accessor; it does not rebuild the namer.
- `Project::inventory_function_name_in(&Annotations, u64) -> Option<&str>`: implemented borrowed annotation name,
  then actual `self.names.get(address)`; the bounded caller generates the `sub_<hex>` fallback.
- `Binary::inventory_source_context() -> (Range<usize>, &[Range<u64>], &[(u64, u64)])`: read-only helper for
  actual private `image`, `code_ranges` and `rebases`, borrowed without cloning.
- `debugger_capture::read_private_document(&Path, usize) -> Result<Vec<u8>, ApiError>`: parent-supplied retained
  descriptor reader without expected SHA, bounded before allocation, compatible with retained staging links.
  It checks same-user/private modes, regular file/no symlink, descriptor/path stability before and after reads.

Cache-specific progress phases share workspace cancellation and publication semantics. The module is exposed
through the API; the desktop uses its existing single workspace-I/O execution lease. The
[measurement protocol and observations](METHODOLOGY.md) distinguish the generated-fixture GO from the slower
small control.
