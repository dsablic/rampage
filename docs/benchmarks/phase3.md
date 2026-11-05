# Phase 3 benchmark reports

Part of the [accuracy benchmarks](../benchmarks.md).

## Phase 3.3 compactness and one live helper observation

The [ergonomics supplement](phase3-3-ergonomics-2026-10-19.json) preserves both prescribed first
experiments. On the owned snapshot, actual MCP full/summary responses contain equivalent selected facts,
diagnostics and limitations: **3,842 → 2,195 serialized bytes, saving 1,647 bytes (42.9%)**. JSON bodies are
3,259 → 1,878 bytes. These are byte measurements, not provider-token estimates or the planned 50% target.

One unchanged canonical helper question used the same `github-copilot/gpt-6.1-sol`, `default` route and answered
`{"return_value":22}` correctly, with zero model/tool errors. That OpenCode route is retired; these numbers are
history, not comparable with the [head-to-head agent runs](agent-h2h-2026-11-05.md):

| Metric | Frozen helper baseline | Current first attempt |
| --- | ---: | ---: |
| MCP calls | 5 | 5 |
| Input tokens | 23,904 | 21,518 |
| Output / reasoning tokens | 500 / 92 | 463 / 122 |
| Model turns | 4 | 3 |
| Cache read / creation | 0 / 0 | 0 / 0 |

**Improvement acceptance is withheld.** Both retained catalogs are cut at 32,768 bytes (original sizes
44,076 and 65,486), failing the predeclared completeness gate. The observed 2,386-input-token decrease is not
accepted token-efficiency evidence; calls did not fall. The model used no compact view or new batch tool,
so neither feature receives causal credit. No retry, task/question change, patch-task regrade, provider/auth
change or target execution occurred. The other 19 tasks remain unmeasured. Phase 1 live/N and Phase 2 recall
gates are unchanged, and full Phase 3.3 acceptance remains open.

## Phase 3.2 owned patch/export round trip

The [owned x86-64 round trip](phase3-2-patches-2026-10-19.json) uses real MCP transport, a frozen
host collector and independently verified original bytes. Exact native C bodies verify **5 → reviewed patch 7
→ undo 5 → redo 7 → fresh exported reopen 7**. Effective disassembly agrees. The exported image matches the
reviewed bytes, opens in a new server/session with no active patches or sidecar, and leaves originals unchanged.

The experiment made **43 MCP calls: 38 successful and five expected errors, zero unexpected errors**. Stale
patch consent, wrong preimage/source identity, stale export consent and an existing destination all preserved
patch receipts, annotations and directory hashes; no partial output or staging residue was published.

All 815 source files / 20,406,057 bytes remained unchanged through build and execution. The collector was
frozen read-only before measurement. Provider calls are zero and tokens null. **Target instructions were never
executed.** This is one owned static x86-64 experiment, not AArch64 MCP coverage, Phase 0 regrading, live/N,
Phase 2 recall, or Phase 3.3 token/call acceptance. Separate core tests cover an explicitly generated static AArch64
fixture; the existing dynamically linked AArch64 greeting remains unsupported and was not relabelled.

## Phase 3.1 owned search comparison

The [owned search supplement](phase3-1-search-2026-10-18.json) compares two scripted arms over
byte-identical, independently verified copies of the greeting ELF. Real MCP `list_strings` plus `xrefs`
took **two calls**, while string `functions_referencing` search took **one** and preserved the literal,
reference site and uniquely identified `main` function. Both arms produced complete equivalent answer evidence.

| Arm | MCP requests | Serialized response bytes | Observed arm time |
| --- | ---: | ---: | ---: |
| Manual strings + xrefs | 2 | 383 | 63.497 ms |
| Search | 1 | 2,586 | 147.502 ms |

**Only call count improved.** Search returned more data and took longer in this single observation.
Times exclude setup/catalog/evaluator work, response bytes exclude JSON-RPC envelopes and catalogs, and OS
file caches were not flushed. Provider tokens are unmeasured/null: this is a new scripted known-literal
workload, not a Phase 0 token/call improvement, live acceptance or Phase 1 completion N.

The host collector was built offline with locked dependencies, frozen before use and unchanged afterward.
All 800 source files / 20,095,735 bytes matched across build and measurement. Original bytes/native listing
established truth before either arm; expected addresses were not supplied to the search request. The
accepted Phase 0 task definitions, transcript and unsupported patch/export contract remain unchanged.
