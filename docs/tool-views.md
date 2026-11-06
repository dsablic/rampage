# Tool views and atomic annotation batches

## Read-result views

`decompile`, `function_summary`, `disassemble`, `function_graph`, `binary_info` and standalone `inspect_data`
accept `view: "full" | "summary" | "code"`. Full is the default. Binary-info and data-inspection tools reject
code view because their results are metadata/data evidence, not recovered code.

| View | Result |
| --- | --- |
| `full` | Original complete response, provided its serialized JSON fits the result budget |
| `summary` | Identity, counts, required diagnostics/status/context and explicit omission receipts |
| `code` | Complete available C or addressed native instruction/control evidence, with nonessential bulk omitted |

Summary does not invent a semantic description. Structural pseudocode is not relabelled as recovered C.
Decompilation views retain native variable-storage evidence, including address-space widths, join pieces,
use ranges and missing mappings. Diagnostics, recovery status, specification and exact-entry context remain
explicit. Instruction projections preserve addresses, interpretation annotations and control-flow evidence.

Reduced views validate the required native response shape; missing or wrongly typed fields are errors, not
zero counts. Valid optional/null fields and empty collections remain supported. Omission sizes count exact
serialized JSON bytes without materializing the omitted payload as a second string.

Views return complete JSON within 60,000 bytes or refuse explicitly. They never cut a string to fit.
Changing view does not broaden analysis scope, grant source authenticity, or hide an incomplete recovery.

The CLI exposes `--view` on the corresponding routes. Choose summary for structural counts and status,
code for the actual reconstruction/instructions, and full when detailed native structures are needed.

## Atomic annotation operations

Core MCP `batch` and CLI `function batch` compose typed `rename`, `comment`, `signature`, `types` and
`global` operations in the annotation transaction/history path. `annotate_batch` keeps its names/comments-only
contract.

```json
{
  "entries": [
    {"operation":"rename","at":"existing_name","value":"reviewed_name"},
    {"operation":"comment","at":"existing_name","value":null}
  ]
}
```

MCP also takes the common binary `path`. CLI accepts `--entries REQUEST.json` or `--entries-json JSON`.
Each operation requires `at` and `value`; explicit null clears, while a missing value is invalid. Targets
resolve against the prebatch state, so an earlier rename does not change a later selector's meaning.

The whole candidate is checked against authoritative annotation state, byte context, declarations and
protected metadata before one append/history publication. An invalid later operation does not commit a
valid prefix. Signature/type/global strings use the individual public declaration-input guard; internal
checked-import encodings are not accepted through ordinary batches. Response-budget preflight runs before
append, including no-op batches.

Patch/export operations and raw internal annotation fields are not batch operations, and this interface
cannot bypass their own admission paths. Undo/redo treats a batch as one history step; it is not a separate
persistence ledger.

Opaque batch transitions have no invented post-hoc attribution witness. A bound assistant retains the
committed outcome but ends conservatively if it cannot attribute the transition to its expected state.
