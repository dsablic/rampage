# Parity scorecard

`rampage-eval run --suite parity` wraps the existing static slice evaluator and the owned checkable task set
in one JSON report. Supply `--manifest` for a generated static corpus and `--corpus-inventory` to retain its
build/availability evidence. Defaults use the existing committed evaluation manifest and task definitions.
Repeat `--manifest` to combine corpora in one report; duplicate slice names are refused before evaluation,
and `static_manifests` records every manifest's path and digest.

```sh
bash tools/parity-corpus.sh target/parity/RUN --only types-a64-elf-zig-o2 --only core-thumb-elf-zig-o2
target/debug/rampage-eval run --suite parity --manifest target/parity/RUN/manifest.json \
  --corpus-inventory target/parity/RUN/corpus.json > target/parity/RUN/scorecard.json
```

The report records actual static scores, selected metric status, independent task-fixture hashes, evaluator
digest/revision/dirty state and unmeasured categories. Task contracts and implementation inventory are separate
from observed answer correctness. Without an explicit model, task outcomes remain unmeasured and usage fields
null. `acceptance.checks` records the Phase 0 completion criteria and `phase0_complete` is true only when
the required corpus, metrics and canonical fixed-model task run have measured evidence. `--require-complete`
exits nonzero for missing evidence; wrong task answers are baseline results, with accuracy gates reported separately.

Type-recovery slices also record each actual decompile call's requested/returned entry, C byte count, nullable
diagnostics and elapsed microseconds. Timing excludes project construction; the first call can include analysis
and native initialization, while later calls share caches. Zero attempts are not measured health. Returned C,
including warning-bearing output, is not a correctness verdict. `--health-sample N` adds the first N sorted truth
entries for other targets (1..64); aliases share a canonical target and original paths remain in the receipt.

Graph agreement accepts `--graph-request`, `--rampage-graph` and `--ghidra-graph` together. The request binds
both exact export hashes to a common image digest, architecture and address context, and records exporter
identities. A standalone `graph-agreement --request ... --rampage-export ... --ghidra-export ...` uses the same
comparison. Exact addressed sets are scored on common functions; one-sided functions remain coverage evidence.
Raw and chain-normalized CFG metrics are separate. Unresolved Ghidra computed calls are excluded from scored
call denominators but retained as raw disagreements. Limits: caller-supplied provenance is not authenticated,
no automatic rebasing occurs, and agreement with Ghidra does not establish correctness.

Opt-in live tasks require `--agent-model MODEL_ID`; select tasks with repeatable `--agent-task ID` and bound
them with `--agent-max-tasks` (default one). The existing Anthropic transport reads its key from the local
environment, never from a command-line argument or report. No provider means unrun/null metrics and a nonzero
exit for the requested live measurement. The runner uses actual MCP JSON-RPC discovery/calls against an
in-memory server, isolates fixture copies and restricts read-only inspection. Requested/returned models,
provider usage, errors and truncation are retained. Limits: scripted-model tests are plumbing checks, not AI
success. Anthropic retains its existing transport; OpenCode uses the metered route below.

Each discovered catalog snapshot is retained up to the discovery bound (1,000,000 serialized bytes, beyond which
discovery fails rather than truncating), not the 32,768-byte default per-record bound that still applies to tool
inputs/outputs and model turns. Catalogs draw from the same total retained budget (default 512,000 bytes) but
together may use at most half of it (256,000 by default), so repeated `enable_tools` refreshes cannot starve later
tool outputs and model turns; a catalog cut by that share is still marked `truncated`. Every discovery records the
SHA-256 of its complete snapshot in `catalog_sha256`. A refresh identical to an earlier discovery is not stored
again: `catalog_repeat_of` names that discovery's index, and the repeat's `catalogs` entry keeps only
`original_bytes`, with empty text marked `truncated` (readers unaware of the field therefore never mistake it for a
complete catalog). `catalog_tool_names` stays complete for every discovery. The earlier per-record cut truncated
every catalog: as measured at `c8f44b9`, the core catalog was 70,736 bytes and the all-group catalog 146,583 (77 tools), above even
the 65,536-byte maximum per-record setting. With default bounds, a core-plus-all-groups run retains both
untruncated; a third distinct catalog (for example core plus detection, 85,410 bytes, before all groups) exceeds
the catalogs' share, and the all-group snapshot is then retained as a labeled truncated prefix. Earlier reports,
including the Phase 3.3 supplement, keep their truncated records and lack the two new fields.

`--agent-provider opencode --agent-model github-copilot/gpt-6.1-sol` reuses the local authenticated OpenCode API,
with the explicit `default` variant. A temporary, one-step agent has host tools disabled; generated JSON intents
are executed only by the benchmark's real MCP client. Actual returned model, reported input/output/reasoning/cache
tokens and timing are retained. CLI operations and capture output are bounded, and owned sessions are deleted.
Limits: this is a JSON-intent adapter, not native provider function calling; informational schema annotations,
opaque provider state and repeated prompt/page bodies are omitted explicitly. No credentials enter the report.

A complete live run selects the full canonical task set with `--agent-max-tasks 20`, adds corpus and graph
receipts, enables health samples, and uses `--require-complete`. Custom `--tasks` runs remain valid measurements
but cannot substitute a different question set for the required task-definition hashes.
The accepted result and its collector revision are recorded in [benchmarks](benchmarks.md). A publication view
can be generated with `jq --arg source_sha256 HASH -f tools/parity-scorecard-summary.jq REPORT.json`; it omits
model answers, arbitrary reason text, transcripts and absolute paths while preserving outcomes and error counts.

The report's `processor_roster` section measures every Sleigh roster fixture through the ordinary Raw `Project`
path: per language id, fixture paths and digests, truth and Ghidra seeded-function counts, entries retained and
exact extents for manual and call-only seeding, misses grouped by decode-gate reason, and whether Raw
decompilation returns C or refuses. `rampage-eval processor-roster` prints the same section alone. Limits: the
Ghidra oracle is seeded function creation (autonomous auto-analysis not run, so per-processor autonomous
discovery recall stays in `unmeasured`), and fixtures are hand-assembled byte ledgers, not compiled code.
The recorded result is in [benchmarks](benchmarks.md).

Corpus recipes compile once, strip a copy, check observed headers and stripped symbol/debug metadata, and
verify truth-function byte identity before scoring. Failed commands retain exit codes; missing prerequisites
and successful-but-empty applicable truth remain unavailable. No target binaries execute or sources download.
`artifact-info` is the evaluator's metadata check for this recipe, not an agent-task measurement.
MIPS ABIFlags support additionally refuses changed program headers or mapped bytes outside the explicit
ELF section-table bookkeeping fields. Generic stripping still relies on separate function-byte twin checks.

The corpus also has C++/exceptions, Go and Rust source workloads. Go compilation is offline (`GOTOOLCHAIN=local`,
proxy disabled); Rust requires a direct local compiler and disables rustup automatic installation. Explicit
`LLVM_OBJCOPY` selects `--strip-all` without fallback. Mach-O header markers outside their declared text section
are reported separately from function symbols. Limits: successful builds with no usable truth remain unscored;
Go runtime metadata may retain function boundaries/names, so its discovery result is not a metadata-blind test.

Profiles can explicitly select `truth_source: embedded_dwarf`. `truth --dwarf` checks retained concrete
subprogram code ranges in both images at identical VAs, rather than inventing sizes for zero-sized symbols.
Limits: only embedded, contiguous `low_pc`/`high_pc` truth is supported; range-list functions and unavailable
names are omitted with counts/notes. Empty truth cannot produce a scored profile.
`truth --dwarf-file FILE` accepts an explicit standalone thin Mach-O debug file with the same nonzero UUID,
exact CPU type/subtype and byte order as the executable and twin; complete UUID command evidence is checked.
Limits: identity equality is not authentication; no debug file is discovered or applied automatically.

`tools/parity-lua.sh OUT_DIR ARCHIVE` builds the pinned MIT Lua 5.4.8 interpreter from a caller-supplied archive
whose checksum is verified, without downloading or running it. Its generated manifest measures discovery and
same-build stripped-twin naming, including the linked runtime. Limits: this best-case name recall is not
cross-program or cross-build recognition; source and binary artifacts remain local.
