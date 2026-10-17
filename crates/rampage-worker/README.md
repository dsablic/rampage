# Decompiler worker

`rampage-worker` consumes one versioned JSON request on stdin, writes one JSON response to stdout, and exits.
Use `rampage_decompiler::worker::run_supervised` rather than starting it directly: supervision provides deadline,
cancellation, resource limits, and child reaping without initializing Ghidra in the calling process.

The executable is resolved from `WorkerConfig::executable`, then `RAMPAGE_WORKER`, then `rampage-worker` beside the
calling application's executable. Missing workers are explicit errors; there is no in-process fallback.

## Protocol version 5

Protocol 5 adds storage-keyed native local/parameter overrides. It retains flat-struct layout assertions,
explicit `no_return` setup and structured results;
incompatible request/response versions are rejected rather than silently mixed. Install callers and workers together.

Requests own all data. Function/mapping addresses and mapping sizes are JSON integers; `hex_bytes` contains
consecutive hexadecimal pairs with no prefix. Mapping permissions and zero-fill size are preserved.
`options.platform` is `default`, `windows`, or `darwin`; an optional compiler ID overrides platform selection.

```json
{
  "version": 5,
  "arch": "x86_64",
  "big_endian": false,
  "options": { "platform": "default", "compiler": null },
  "mappings": [{
    "base": 4096,
    "hex_bytes": "31c0c3",
    "size": 3,
    "readable": true,
    "writable": false,
    "executable": true
  }],
  "code_modes": [],
  "operations": [],
  "decompile": { "address": 4096, "name": "fixture", "thumb": false },
  "tokens": true
}
```

The worker installs initial `code_modes`, then replays `operations` in their supplied order:

| `op` | Fields |
| --- | --- |
| `symbol` | `address`, `name` |
| `import` | `slot`, optional `target`, `name` |
| `parse_types` | `declarations` |
| `assert_plain_struct_layout` | `layout`: complete bounded descriptor; optional `expected_context` manifest SHA-256 |
| `prototype` | `address`, `indirect`, `declaration` |
| `runtime_prototype` | `address`, `indirect`, canonical runtime `name`, optional `optional` boolean |
| `mode` | `modes`: objects with `address` and `thumb` |
| `no_return` | `address`, `indirect`: registered function or import-slot function marked non-returning |
| `local_variables` | function `address`, replacement `overrides`: exact `storage`, optional `name`/`data_type` |

`runtime_prototype` resolves the declaration using the worker's compiler data model. An unavailable prototype or
failed setup operation is a structured error identifying the operation index. `optional: true` skips unknown
runtime identities while preserving other setup errors. Unknown fields and versions are
rejected.

Responses are `{ "version": 5, "status": "ok", "output": ... }` or
`{ "version": 5, "status": "error", "message": ... }`. Successful output includes C `text`, `language_id`,
`data_organization` (`pointer`, `int`, `long` byte widths), and optional semantic `tokens` with `text`, `kind`, and
optional numeric `address`.
The CLI uses `rampage function decompile ... --isolated`; flat `decompile` remains accepted. Batch
`rampage binary analyze` also requires supervision for explicit decompilations and workflow previews.

`validate_only: true` checks mappings, modes and ordered setup operations without requiring any function to
decompile. It returns empty text; typed annotation transactions use this to validate entryless images.

Local storage keys contain `kind` (`processor` or `spacebase`), `space`, `address`, `size`, and exact inclusive
`use_ranges` (`space`, `start`, `end`). Addresses/range endpoints accept unsigned JSON integers or hexadecimal
strings and serialize as hexadecimal strings. Empty use ranges select unrestricted mappings, not wildcard matches.
Only one whole mapping on the owning symbol is supported; dynamic, internal, join, piece, missing and ambiguous
selectors are refused. Types are scalar/pointer abstract C declarations, such as `struct PhaseState *`, referencing
already loaded types and preserving storage size. Batches are limited to 256 overrides, 256 use ranges per selector,
128 bytes per name/space, 4 KiB per type and 64 KiB cumulative text, in addition to request preflight limits.
Registration parses types; exact symbol resolution happens when that function decompiles. Validation-only setup
does not establish that a local selector matches. Native analysis locks apply during decompilation and are restored
after results are copied. Empty override lists remove registered overrides without retaining prior names or types.

`assert_plain_struct_layout` checks an already parsed complete flat struct against independent layout facts before
dependent prototypes are installed. It is supported only for `x86:LE:64:default:gcc`; it measures the selected native
organization rather than host layout. Struct size/alignment, ordered fields, offsets, sizes and semantic leaf types
must all agree. Limits are 128 fields, 128 bytes per name, 32 KiB cumulative text, one MiB size and alignment at most
eight bytes. Nested aggregates, unions, arrays, retained bitfields, enums, callbacks and pointer chains are refused.
Assertions are read-only and ephemeral, including in validation-only requests: they do not import debug layouts or
persist proof across a new engine/compiler selection. Ordinary mismatches preserve prior native types/results;
inspection exceptions are contained. Failure while storing an error diagnostic poisons the handle and clears results.

Checked project replay supplies `expected_context`: a canonical embedded-manifest SHA-256. The worker compares its
own bundle and actual native context before initialization. `None` is omitted on the wire for ordinary manual or
external-spec assertions. Older strict protocol-4 workers reject checked requests with this additional field;
install callers and workers together. A digest does not authenticate an arbitrary replacement executable.

Raw requests are preflighted before Serde buffers internally tagged operations. A complete layout-assertion operation
is limited to 384 KiB encoded data, 64 KiB decoded text, 2,048 nodes and depth 12, regardless of member order or escaped
keys. Layout strings/keys are at most 128 decoded bytes, tags 32 bytes, arrays 128 entries and objects 32 keys.
Operations and layout records require object representation, and enum tags require strings; positional Serde
representations and enum-object tags are refused.
General requests retain the 128 MiB byte cap and also cap depth at 32, total nodes at 1,048,576 and nodes per operation
at 65,536. Ordinary strings are at most 4 KiB; legacy mapping hex and declaration fields retain the request-byte
budget. Malformed schema diagnostics are constant-size rather than echoes of offending strings.

## Resource boundary

- Default wall-clock deadline: 30 seconds, covering request encoding, execution, and response decoding;
  cancellation accepts an `AtomicBool` and interrupts all three phases.
- Hard protocol caps: 128 MiB request, 16 MiB stdout, 64 KiB stderr. Configuration may lower these caps.
- Default worker memory budget: 1 GiB. Linux uses hard `RLIMIT_AS`/`RLIMIT_DATA` limits. Darwin samples native
  resident-memory usage; this is not a strict allocation cap and may overshoot between checks.
- Native instruction budget: Ghidra's existing 100,000 instructions per function.
- Core dumps are disabled; the worker process group is killed and the direct child is reaped on every exit path.
- Supervision supports 64-bit Linux and macOS. Unsupported hosts return an explicit error.

This isolates native crashes and runaway work, but does not sandbox an arbitrary replacement executable.

## Tests

```sh
cargo test -p rampage-decompiler worker::tests
cargo test -p rampage-worker
```

Supervisor tests use disposable executable fixtures and check cancellation, blocked stdin, timeout, output overflow,
crashes, inherited pipe holders, and reaping. Worker integration tests exercise bundled specifications, semantic
tokens, ordered type/symbol/prototype setup, imports, target ABI selection, and ARM Thumb context.
