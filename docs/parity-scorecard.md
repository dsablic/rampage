# Parity scorecard pilot

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
null. `phase0_complete` is false, and a successful static gate is not parity acceptance.

Type-recovery slices also record each actual decompile call's requested/returned entry, C byte count, nullable
diagnostics and elapsed microseconds. Timing excludes project construction; the first call can include analysis
and native initialization, while later calls share caches. Zero attempts are not measured health. Returned C,
including warning-bearing output, is not a correctness verdict; the sample is limited to type-truth entries.

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
success; no live-model baseline has been recorded, and provider I/O retains the existing transport timeouts.

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
names are omitted with counts/notes. Empty truth cannot produce a scored profile, and no external dSYM is inferred.

`tools/parity-lua.sh OUT_DIR ARCHIVE` builds the pinned MIT Lua 5.4.8 interpreter from a caller-supplied archive
whose checksum is verified, without downloading or running it. Its generated manifest measures discovery and
same-build stripped-twin naming, including the linked runtime. Limits: this best-case name recall is not
cross-program or cross-build recognition; source and binary artifacts remain local.
