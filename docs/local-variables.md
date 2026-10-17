# Local variables and parameters

Types-group MCP `edit_variable` renames or retypes one current native local or parameter. It returns refreshed
complete C, diagnostics and variable descriptors in the same call. Native scope symbols and type locks drive
the result; rendered text is not substituted.

## Inputs

- `at`: function address or existing name.
- Exactly one of `variable` (current display name) or `storage` (complete returned storage object).
- `name` and/or `data_type`, or `clear_name` / `clear_type`. Setting and clearing one field together is invalid.
- `data_type`: a same-size abstract scalar/pointer declaration. Declare named aggregates with existing `set_types`.

For the owned fixture, after declaring `struct PhaseState { int4 gain; int4 bias; };`:

```json
{
  "path": "tests/data/local-variables-x64.snapshot.json",
  "at": "0x4000ae",
  "variable": "piStack_10",
  "name": "state",
  "data_type": "struct PhaseState *"
}
```

The edit result contains `decompilation.code` with `state->gain` and `state->bias`, along with the selected
storage and changed-field receipts. Code-view decompilation also returns `variables`: names, kinds, types,
canonical storage keys and explicit editability/refusal information.

## Storage and persistence

Persisted local names/types are keyed by function address plus native storage, not generated display names.
Copy `variables[].storage` exactly. A stack address is an address-space offset encoded as unsigned hex, not
a file offset; inclusive `use_ranges` are definition/use selectors, not variable live ranges.

One edit atomically logs its name/type changes. `undo`, `redo`, shared-log refresh and reopening replay them;
invalid edits or oversized responses leave the log unchanged. Annotation collection values are omitted from
the edit receipt; `list_annotations` includes `local_names` and `local_types` for inspection.

Limits: initially one whole processor/register or stack mapping; dynamic, internal, joined, partial, ambiguous
or stale selectors are refused. Retypes preserve native mapping size; inline array/function-pointer declarators
are unsupported. Analyst types change interpretation, not producer-layout truth. No cross-call propagation or
project-level type library is added here. Rebuild CLI and worker together for worker protocol 5.
