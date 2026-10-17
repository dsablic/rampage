# Project type-library reference

The Types-group tools manage named declarations in the selected project's annotation log. Layouts are measured
by the native decompiler using that target's data organization; analyst declarations are not producer-layout proof.

| Tool | Inputs | Result |
| --- | --- | --- |
| `declare_types` | `declarations`/`header`, `profiles`, `packing`, `replace` | Atomic edit receipt |
| `list_types` | Optional `contains`, `offset`, `limit` | Paged project inventory |
| `get_type` | Exact type `name` | Native layout, fields, aliases and related type details |
| `delete_type` | Exact project type `name` | Dependency-checked deletion receipt |

## Declaration inputs

```json
{
  "path": "tests/data/local-variables-x64.snapshot.json",
  "declarations": "struct State { int4 gain; int4 bias; }; typedef State *StatePtr;"
}
```

Definitions are project-wide rather than associated with one instruction address. Existing address-bound
`set_types` annotations remain readable. `edit_variable`, signatures and globals can refer to library names.
Library definitions are self-contained; existing legacy/native names are inspectable but are not silently
adopted or replaced by the library tools.
Native inspection reports incomplete types explicitly rather than inventing an opaque type's layout.
When inputs are combined, profiles are prepared first, then `declarations`, then inline-header units.
The inventory's `contains` filter is case-sensitive.

Headers are supplied as inline text. Supported bundled includes resolve to shipped minimal type profiles;
there is no filesystem include search or host-preprocessor execution. Explicit profiles select their declared
ABI, not an inferred operating system. Packed declarations retain their packing with replay.
Packing options apply to user declarations; bundled profiles retain their stated ABI.

## Edits and persistence

Declarations, replacements and deletions validate the complete prospective library and its consumers before
appending an annotation edit. `undo`, `redo`, shared-log refresh and reopening restore the same declarations.
Read queries use bounded detached snapshots and do not create annotation or writer-lock files beside inputs.
Deletion does not cascade silently. A multi-name declaration requires explicit `definition_group=true`;
its receipt names every removed type, and references from outside that group still refuse deletion.
Invalid declarations, broken dependencies and oversized receipts do not
persist. The tools return structured MCP errors for refused requests.

Limits: bounded C type declarations and minimal header profiles, not arbitrary C/C++ preprocessing or a full SDK;
bundled includes inside active packing scopes are refused rather than imported with the wrong layout.
No binary bytes are patched, and type import does not execute the analyzed program.
