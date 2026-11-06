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
success.

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

The accepted Phase 0 baseline and the Phase 1 and 3.3 live results were collected through an OpenCode JSON-intent
adapter with `github-copilot/gpt-6.1-sol`. That adapter is retired; those results stay published as history and
are not comparable with runs through the agent runner below (different model, client and prompts). The six live
examples that used that adapter (`local_typing`, `function_frame`, `debug_type_import`, `type_library`,
`type_propagation`, `typed_data`) now use the in-process Anthropic transport with a pinned `claude-sonnet-5-5`
and need `ANTHROPIC_API_KEY`. They stay in process rather than moving to the agent runner because they rely on
the parity agent's per-argument write policy (for example, edits only on the owned fixture), which a
`claude -p` session cannot enforce.

### Head-to-head agent runs

`rampage-eval agent-bench` runs the canonical tasks through an external agent runner against one MCP server at a
time and scores the answers against the same manifest contracts. The default runner,
`tools/agent-bench/claude-runner.py`, drives `claude -p` with only the one server's tools and `ToolSearch` (Claude
Code's loader for deferred MCP tool schemas) allowed, every other built-in tool removed and denied, no setting
sources (or `--bare` when `ANTHROPIC_API_KEY` is set), `MAX_MCP_OUTPUT_TOKENS` set the same for every server
(200,000 by default), and checks the stream's init event: any extra tool, MCP server, plugin outside Claude
Code's pinned built-ins, skill, agent, slash command, hook or non-empty memory directory fails the run, as does
a call outside the server that ran. It deletes Claude Code's per-project directory for the run's working
directory afterwards. It writes a normalized result (answer, tool calls with byte sizes, timings and truncation
or refusal flags, turns, token usage, cost, wall time, exit kind, runner identity) that names no Claude Code
format, so another agent CLI needs only another runner script with the same output; `--runner` selects it.

```sh
rampage-eval agent-bench --label NAME --servers rampage,rea --tasks all --repeat 3 --model claude-sonnet-5-5 \
  --report-json docs/benchmarks/agent-h2h-DATE.json --report-md target/bench/h2h/NAME/tables.md
```

`--report-md` receives only the generated tables; the published `agent-h2h-DATE.md` is written by hand around
them. `--rescore` recomputes a finished run from its recorded transcripts without model calls, keeping the
measured run's versions, time and protocol and recording what changed in a `rescore` block.

`--suite v2` runs [suite v2](benchmarks/agent-h2h-v2-2026-11-05.md) instead: the manifests in
`crates/rampage-eval/tasks/v2/` with prompts, categories, scoring rules and per-task turn and time limits in
`tasks/h2h/neutral-v2.toml`, fixtures from `tests/fixtures/bench-v2/build.sh` and
`tools/agent-bench/v2/build-scale.sh`, and truth from `tools/agent-bench/v2/derive-truth.py`. `--cost-cap-usd`
(with `--spent-usd` for earlier passes) stops before the next run once spend reaches the cap;
`--rea-ghidra-startup-timeout-ms` and `--rea-ghidra-maxmem` set REA's Ghidra deadline and heap and are recorded;
`--attach NAME=FILE` embeds measurements made outside the agent runs; `--rerun TASK:SERVER:REP` reruns runs a
harness fault affected, keeping the originals as `superseded_runs`.

Prompts come from `crates/rampage-eval/tasks/h2h/neutral.toml`: tool-neutral wording for each canonical task,
with the reason for every change from the frozen question. Capability probes ask about the connected server's
own tools, so their truth is per server, with its evidence. Runs are sequential, the servers alternating which
goes first per repetition; each gets a fresh private directory outside the repository holding its own copy of
the fixture as `fixture.bin`. Raw streams stay in
`target/bench/h2h/` (mode 0600); reports hold measurements and outcomes, never answers or transcripts. The
`rea` server is REA (morluto/rea) over headless Ghidra, built from a pinned commit under `target/bench/rea/` and
described by its `install.json`; results are in [benchmarks](benchmarks.md).

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
The recorded result is in [benchmarks](benchmarks/phase4-1.md#phase-41-raw-project-processor-roster).

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
