# Decompiler worker

`rampage-worker` consumes one versioned JSON request on stdin, writes one JSON response to stdout, and exits.
Use `rampage_decompiler::worker::run_supervised` rather than starting it directly: supervision provides deadline,
cancellation, resource limits, and child reaping without initializing Ghidra in the calling process.

The executable is resolved from `WorkerConfig::executable`, then `RAMPAGE_WORKER`, then `rampage-worker` beside the
calling application's executable. Missing workers are explicit errors; there is no in-process fallback.

## Protocol version 7

`type_hints` replaces the pending unlocked native evidence for one function:

```json
{"op":"type_hints","address":4096,"hints":[{"kind":"parameter","index":0,"data_type":"struct State *"}]}
```

Hint kinds are `parameter` (zero-based `index`), `return`, and `local` (the existing complete
`VariableStorage` selector). All carry an abstract `data_type` declaration resolved with the worker's named
type library and selected data organization. An empty hint array clears the batch. A maximum of 256 hints
and 64 KiB of hint text is accepted per batch. Hints never set analyst name/type locks or replace the ABI,
other prototype components, or unknown types. Analyst types win. Native whole-mapping resolution, width
checks and retention checks occur during decompilation; unsupported aggregate/variadic/indirect shapes or
unlocked types that do not survive analysis fail explicitly rather than hard-locking a type.

Structured calls optionally include `arguments`, `result`, and `evidence_unavailable`. Argument
`input_index` is the native CALL input slot (1 is the first argument); `parameter_index` is present only
when the declared destination parameter mapping is unambiguous. Values contain native `data_type`,
`raw_storage`, `display_name`, `type_locked`, optional `global_address` and a canonical `storage` only
for one whole owning local/parameter symbol. `status` distinguishes `unknown`, `constant`, `computed`,
`variable`, `global` (loaded value), and `global_address` (address of an object). For `global_address`,
`data_type` is the native pointer-to-object type, `symbol_type` is absent, and `type_locked` is false.
The optional `global_object_type` and defaulted `global_type_locked` describe the addressed object's
analyst type without pretending that object owns the pointer argument. For `global` loads, owning
`symbol_type`/`type_locked` still describe the actual argument value. Temporary parameter-preservation
or rename-only size locks do not count as analyst types. Result `direct_return` requires every normal native
return to use the call
output through at most 16 same-width COPY/CAST nodes (at most 256 return operations are inspected).
There is a limit of 256 exported call argument records per function. Evidence is complete per call:
the first call that cannot fit, and subsequent calls, omit both `arguments` and `result` and report
an explicit budget reason in `evidence_unavailable`. Earlier complete call evidence, basic call records,
and ordinary C output remain available. The existing complete structured output budgets still apply.
No rendered C is parsed or replaced.

For caller bootstrap, registering hints on a callee also supplies native context when decompiling another
function. The worker follows the requested function's native direct CALL edges and analyzes only relevant
registered hinted targets (at most 32), checks their actual whole-register
parameter mappings and native return width/storage, then seeds CALL recovery trials and the unlocked type
lattice. It does not manufacture or lock a full prototype. Unknown/unhinted components remain native
inference; existing explicit caller/callee prototypes take precedence. Stack, join, hidden, aggregate,
variadic and incompatible calling-convention shapes refuse explicitly. Contexts are direct-call evidence,
not an automatic recursive/fixed-point propagation framework; the API owns bounded graph iteration.

Return-only wrappers also use native evidence without requiring an initial return hint. A known scalar/pointer
callee output can keep a caller return-recovery trial alive only when every normal return carries that same
CALL output through at most 16 same-width COPY/CAST nodes. For an explicitly typed caller, a single-block
post-call P-code suffix can request the mapped callee's actual storage context; final exported return flow
still requires SSA proof. This does not lock a caller signature or assign a type to the callee prototype.
Register overwrites, joined/aggregate outputs, hidden storage and unsupported control flow do not establish
the edge. Refusal messages include the specific guard and raw output/prototype widths, spaces and metadata.

Protocol 6 adds native named-type inspection and bounded type-library batches. It retains local/parameter overrides,
flat-struct layout assertions,
explicit `no_return` setup and structured results;
incompatible request/response versions are rejected rather than silently mixed. Install callers and workers together.

Requests own all data. Function/mapping addresses and mapping sizes are JSON integers; `hex_bytes` contains
consecutive hexadecimal pairs with no prefix. Mapping permissions and zero-fill size are preserved.
`options.platform` is `default`, `windows`, or `darwin`; an optional compiler ID overrides platform selection.

```json
{
   "version": 7,
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
| `type_library` | type-only `declarations`, optional `packing` (1, 2, 4, 8, or 16) |
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

Responses are `{ "version": 7, "status": "ok", "output": ... }` or
`{ "version": 7, "status": "error", "message": ... }`. Successful output includes C `text`, `language_id`,
`data_organization` (`pointer`, `int`, `long` byte widths), and optional semantic `tokens` with `text`, `kind`, and
optional numeric `address` and byte `span`. Native struct/union field identifiers use kind `field`; their
spans match the current C text and their addresses identify the originating P-code operation when available.
The CLI uses `rampage function decompile ... --isolated`; flat `decompile` remains accepted. Batch
`rampage binary analyze` also requires supervision for explicit decompilations and workflow previews.

`validate_only: true` checks mappings, modes and ordered setup operations without requiring any function to
decompile. It returns empty text; typed annotation transactions use this to validate entryless images.

`type_query: {"query":"inventory"}` returns non-core named types;
`type_query: {"query":"get","name":"Record"}` inspects exactly one name, including a builtin.
Queries run after setup even with `validate_only`, return empty `text` and no `structure`, and never decompile.
`output.type_inventory` contains the resulting `NamedType` array; the field is absent on ordinary requests.
The required `decompile` placeholder remains in the request for compatibility with existing request construction.

`output.type_declarations` is present whenever setup includes `type_library` operations, even without a query or
with `validate_only`. It contains one array of named top-level roots per such operation, in request order. Each
array describes the final native types after that whole batch, so a forward declaration completed later in the
same batch is returned complete. Incidental forwards in callback signatures and nested aggregate names are not
roots; they remain discoverable through `type_inventory`. Aggregate response size remains subject to the worker's
16 MiB output budget; oversized root collections fail rather than truncate.

After a type-library operation, its roots and newly introduced native names are protected against later setup
mutations. Type parsing, globals, prototypes, local-variable overrides, further type-library batches and runtime
prototypes are followed by exact native metadata checks. Completing a protected forward in a later operation is
rejected; frontends must coalesce its forward and definition into one batch. Completed names cannot be overwritten
through legacy anonymous-struct typedef renaming, including equivalent-looking definitions.

Native metadata includes kind, optional size/alignment, incomplete status, explicit packing, ordered fields
(`name`, byte `offset`, `type_name`, optional `size`), enumerators (decimal-string values), typedef/pointer/array
`target`, array length, and callback return/parameter types. `dependencies` are sorted direct named references,
excluding core builtins; `by_value_dependencies` excludes pointer/callback edges. Self-pointer edges remain in
`dependencies` and do not imply illegal by-value cycles. Void, function, and incomplete sizes are null, not zero.
`identity` on named types and fields is a bounded structural native JSON value. Named references terminate with
their native name; anonymous pointers, arrays, aggregates and functions retain their structure, including nested
callback signatures and calling-convention models. Equality checks therefore do not rely on display text such
as `function *`. `NamedFunctionType.calling_convention` is the native model name, or null when unavailable.
Callback return/argument types and names come from retained native declaration pieces before ABI lowering,
not hidden-return parameters or indirect storage parameters. Native types without retained declaration evidence
have null `callback` and explicit `signature_known: false` in their structural function identity.
For those unknown declarations only, `abi_signature` records observed native lowered parameter types/flags;
it is not presented as a recovered C signature. Parameter names follow Ghidra's canonical type interning, so
equivalent previously interned signatures may retain the first native declaration's names.

Type-library batches accept preprocessed C typedefs, structs, unions, enums, arrays and function-pointer typedefs;
extern function signatures, object declarations, bitfields, preprocessing directives, and unsupported grammar are
errors, not partial successes. Comments/pragmas should be removed by the header frontend; packing is an explicit
batch option. Ghidra computes native layout with capped field alignment before constructing dependents, including
nested anonymous aggregates. No host-layout estimates or plain-struct assertion shortcuts are used. C `int`/`long`
widths come from the selected compiler data organization. Native enum duplicate values remain unsupported.
C enum creation uses that compiler's `int` size/alignment, not Ghidra's architecture-default enum width. The
supported enum subset requires every explicit and implicit value to fit signed target `int`; larger unsigned
or widened enums are rejected rather than truncated or assigned a guessed representation. Negative enum values
are retained as signed decimal strings. Integer literal overflow and unsupported literal suffixes are errors.

Limits are 64 KiB declarations per batch; 256 returned names, fields, enumerators, dependencies or parameters;
32 levels of braces/reference traversal; 256 bytes per token/query name; 1 MiB per registered type/field and
native JSON. Ghidra's existing array bound limit is 65,536 elements per dimension;
overflowing/incomplete arrays are rejected. Limits fail closed,
without truncation. Batch results contain named top-level declarations, including new tags and typedef aliases,
not every internal type created by parsing. Nested named types can be queried separately. Failed native parsing
may poison the engine: persistent transactions must replay into a fresh engine and commit only after success.
The one-MiB type bound also applies to pointed-to, nested and anonymous aggregate/array types, not just root
declarators. The retained non-core inventory is limited to 256 named types; reachable type graphs and individual
structural identities are bounded to 4,096 nodes and 32 reference levels. Arrays require object element types;
function and void arrays are rejected. C integer-specifier sequences allow interleaved qualifiers but reject
contradictory signs and duplicate/incompatible ranks. Native parsing accepts known aggregate tags in prototypes
and globals, and typedef names reused as member/parameter identifiers.

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
