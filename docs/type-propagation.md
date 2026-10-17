# Type-propagation reference

`propagate_types` previews bounded cross-call candidates for a selected function; `apply=true` stores accepted
candidates as separate lower-priority hints. It does not rewrite analyst signatures or variable/global types.

Inputs: `at`, optional `apply`, `max_functions` and `max_candidates`. Preview is read-only. Candidate records
identify the source, call site, target storage/parameter/return, proposed type, conflicts and skipped cases.

```json
{
  "path": "tests/data/type-propagation-x64.snapshot.json",
  "at": "0x201170",
  "apply": false,
  "max_functions": 4,
  "max_candidates": 32
}
```

`max_functions` is bounded to 1–32; `max_candidates` to 1–256. Invalid bounds, native retention failures and
unsafe storage mappings return MCP errors without appending hints. A successful preview with no candidates
is not evidence that all requested types were recovered; inspect its skips and limitations.

Explicit analyst annotations take priority. Conflicting sources do not produce an arbitrary winner. Computed
arguments, unsupported ABI mappings and unavailable storage remain unknown rather than becoming guessed
parameter links. Hints bind to a source fingerprint; stale or overridden hints are not silently reused.

Applying hints validates the complete prospective native context and response before appending annotations.
`hint_edits` records each complete old/new function payload, including removals and provenance-only updates.
Preview reports planned edits; `persisted` and the edit counts distinguish durable writes from candidate counts.
An empty `applied` candidate list alone does not imply that no old hints were cleared.
Undo, redo and reopening replay the separate hint state. Target-model import declarations are installed before
analyst signatures, preserving user control over import typing.

Ordinary decompilation may derive an ephemeral bounded context from current explicit inputs. Undoing an applied
hint removes the durable annotation; it does not disable this automatic inference, so the same displayed type
may be derived again. Exact-entry replay uses only its admitted context and does not launch whole-program
propagation. Unsupported multi-hop wrappers remain explicit limitations rather than forced signatures.

Portable `memcpy` uses the selected pointer/size widths. `recv` distinguishes explicit POSIX context from the
Windows socket/length model, and Windows `CreateFileW` uses 16-bit filename elements and the selected x86/x64
calling model. A default compiler or ELF container alone is not a POSIX assertion. Analyst import signatures
remain authoritative; unsupported target/convention combinations are not guessed.

Limits: bounded proven direct-call scalar/pointer evidence, not whole-program type proof, arbitrary alias
analysis, automatic source-layout reconstruction or forced analyst-type replacement.
