# Decompiler worker

`rampage-worker` consumes one versioned JSON request on stdin, writes one JSON response to stdout, and exits.
Use `rampage_decompiler::worker::run_supervised` rather than starting it directly: supervision provides deadline,
cancellation, resource limits, and child reaping without initializing Ghidra in the calling process.

The executable is resolved from `WorkerConfig::executable`, then `RAMPAGE_WORKER`, then `rampage-worker` beside the
calling application's executable. Missing workers are explicit errors; there is no in-process fallback.

## Protocol version 3

Protocol 3 adds explicit `no_return` setup operations. Structured result schemas came with protocol 2;
incompatible request/response versions are rejected rather than silently mixed.

Requests own all data. Addresses and mapping sizes are JSON integers; `hex_bytes` contains consecutive hexadecimal
pairs with no prefix. Mapping permissions and zero-fill size are preserved. `options.platform` is `default`,
`windows`, or `darwin`; an optional compiler ID overrides platform selection.

```json
{
  "version": 3,
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
| `prototype` | `address`, `indirect`, `declaration` |
| `runtime_prototype` | `address`, `indirect`, canonical runtime `name`, optional `optional` boolean |
| `mode` | `modes`: objects with `address` and `thumb` |
| `no_return` | `address`, `indirect`: registered function or import-slot function marked non-returning |

`runtime_prototype` resolves the declaration using the worker's compiler data model. An unavailable prototype or
failed setup operation is a structured error identifying the operation index. `optional: true` skips unknown
runtime identities while preserving other setup errors. Unknown fields and versions are
rejected.

Responses are `{ "version": 3, "status": "ok", "output": ... }` or
`{ "version": 3, "status": "error", "message": ... }`. Successful output includes C `text`, `language_id`,
`data_organization` (`pointer`, `int`, `long` byte widths), and optional semantic `tokens` with `text`, `kind`, and
optional numeric `address`.
The CLI uses `rampage function decompile ... --isolated`; flat `decompile` remains accepted. Batch
`rampage binary analyze` also requires supervision for explicit decompilations and workflow previews.

`validate_only: true` checks mappings, modes and ordered setup operations without requiring any function to
decompile. It returns empty text; typed annotation transactions use this to validate entryless images.

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
