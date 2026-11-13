# To do

## Status (2026-11-09)

- Release: 1.0.0-rc.1 (2026-11-06) and rc.2 (2026-11-09) are published as pre-releases; 1.0.0 is being prepared.
  Contract snapshots pin every stable MCP group. Linux ARM64 host support shipped in rc.1 (archived).
- Parity roadmap: Phases 0–3 and 4.1 implemented; live Phase 1 sign-off, the Phase 2 recall target and the
  Phase 3.3 live improvement gate are open. Phase 4.2 is next in roadmap order.
- Debugger (Phase 9): 9.1–9.5 done (9.5's live macOS `debugserver` acceptance passed 2026-11-11); 9.6a (Windows through
  RSP stubs) implemented, live acceptance pending (experimental in 1.0). See `docs/plans/2026-10-29-debugger-control.md`.
- REA gap-closing wave 1 (2026-10-29): `formats` tools and the findings ledger done; log compaction open.
- Head-to-head with REA: suite v1 and suite v2 published (`docs/benchmarks/`); follow-ups below. Suite v3
  (tasks where Ghidra is strong) and a second model or client are not run yet.
- Flywheel fast loop (`docs/plans/2026-11-05-flywheel-fast-loop.md`): the deterministic arm (exact rows, operand
  wildcarding) and call-graph propagation ship in the bundled databases; fuzzy matching failed the final split on
  both corpora and stays suggestion-only. The AI proposer has made no promotion a deterministic generator could
  not; whether it proposes code next (`docs/plans/2026-11-08-flywheel-code-candidates.md`, steps 2–4) is
  undecided. Open: an arm rule for rows that match another library's body (fixed by name for now); regenerating
  the bundled hash databases with callee keys for forwarders (needs the signature-corpus caches).

This file holds open items. Done sections, including every completed parity phase, are archived verbatim in
[docs/plans/todo-archive.md](docs/plans/todo-archive.md); each section below that lost done items links to them.

## Proposed tracks (2026-11-08, not started)

Queued behind the flywheel work, one at a time; each needs its own design and go-ahead.

- [ ] **Windows corpus for the flywheel.** x86 and x64 PE builds with clang-cl and lld-link against the MSVC CRT
  and SDK fetched locally by `xwin`, which asks the builder to accept Microsoft's licence. Truth comes from PDBs,
  and MSVC CRT versions give the train/final split. The recipe pins origins only and nothing is committed.
  Microsoft's public symbol server and research datasets (BinKit, Cisco Talos `binary_function_similarity`,
  Assemblage) can serve as outside evaluation sets on the same terms.
- [ ] **Malware-analysis workflow** (defensive analysis and detection):
  - dump a decrypted stage or module from a debug session and open it as a linked analysis target, instead of
    a classic OEP/import-rebuilding unpacker;
  - extract indicators (C2, keys, decoded strings) with evidence links;
  - draft YARA rules gated against a goodware corpus, a candidate flywheel family after compiler/tool
    identification.
  Samples run only in disposable QEMU or VM guests reached through the debug stubs, never on the host. Needs a
  real packed fixture.

## Head-to-head agent benchmark follow-ups (2026-11-05)

Observations from [the rampage vs REA runs](docs/benchmarks/agent-h2h-2026-11-05.md); rampage was not tuned
during the benchmark.

- [ ] The model sometimes calls a bare tool name (`enable_tools`, `list_strings`) and the client refuses it: 4
  of 6 C++ runs in the first run, 2 in the second. Check whether tool descriptions or `enable_tools` output name
  tools in a way that invites unprefixed calls.
- [x] The second run's one rampage miss (`objc-superclasses`) never enabled the `types` group for
  `language_metadata`. Done: `language_metadata` and `class_evidence` moved to `core` (2 tools, about 2.3 KB of
  tools/list) instead of enabling `types` by default (20 tools, about 35 KB).
- [x] Results over Claude Code's 50,000-character limit are spilled to an unreadable file. Done: every tool
  declares `anthropic/maxResultSizeChars` = `RESULT_LIMIT_CHARS` (61,024).
- [x] Add harder, less-saturated agent tasks. Done as [suite v2](docs/benchmarks/agent-h2h-v2-2026-11-05.md).
- [ ] Repeat the head-to-head with a second model or client before drawing conclusions beyond this one.

## Benchmark suite v2 follow-ups (2026-11-05)

From [suite v2](docs/benchmarks/agent-h2h-v2-2026-11-05.md). Fixed: `function_summary` fitting, linear exact-text
search with a resume cursor, Go string-run match addresses, raw-profile aliases and headerless guidance, hex ARM
immediates in `inspect_raw_code`, one-line argument errors and unknown-argument refusal, chained-fixup RTTI.

- [x] `search` `functions_referencing` a string stops on `match_work_budget` with nothing scanned on the 50 MB
  Hugo image (all 4 scale-string runs): `prepare_search` charges a B-tree insert for every discovered block of
  the whole program before decoding, then decodes every instruction to compare its references. For string
  references, find the string's addresses first (the now-linear text search) and walk the retained xrefs to
  them, decoding only the referencing sites; until then agents fall back to text search + `xrefs`.
  Done 2026-11-13 (restic 26 MB: budget stop → 1 exact hit; Go literals bounded by the next referenced literal).
- [x] Byte patterns with wildcards still charge their length per candidate start; a 50 MB image needs a
  literal-prefix prefilter or a larger default budget.
- [x] ARM immediates are printed in LLVM's decimal (`movt r1, #1934`) by the shared native renderer, used by
  `disassemble` and search operand globs too. Only `inspect_raw_code` appends hex now; adding it to the native
  listing needs its own field or comment so CLI/UI comment columns and operand-glob matching stay unchanged.
- [x] No Raw Project profile for ARM/Thumb (Cortex-M): firmware runs needed `inspect_raw_code`, which has no
  functions, xrefs or decompilation. A reviewed ARM/Thumb Raw profile would let `raw` serve them. Done:
  experimental `ARM:LE:32:Cortex` (aliases `cortex-m*`, `thumb`, `armv7m`, ...), native Thumb decoder, ARM v8
  decompilation, 4 MiB cap ([Cortex-M profile](docs/sleigh-decoding.md#cortex-m-profile)).
- [x] Go string literals referenced only through static `{ptr, len}` headers in data (not by code) get no
  `go_literal` start, since data-to-data references are not retained; reading headers would bound them too.
- [x] `function_graph` refuses oversized views like `function_summary` did; page its blocks the same way (edges
  index whole-function block positions, so paging keeps them valid).

## Suite v3 Haiku pass follow-ups (2026-11-13)

- [x] DWARF types at scale: `import_debug_types`/`import_debug_layouts` previews stopped on whole-file budgets on a
  7.9 MB SQLite build, so struct layouts were unreachable. Done: `get_type` DWARF fallback with per-request bounds.
- [ ] Whole-file DWARF import previews still return nothing at this size; make them return partial results.
- [ ] DWARF lookup: C++ types nested in classes, DWARF 5 type units / `.debug_types`, zstd-compressed sections.
- [x] Persistent analysis store (roadmap 6.2, first half): SQLite cache of discovery, keyed by every analysis
  input and the rampage build, with an `ANALYSIS_VERSION` golden test. Open: caching signatures and strings if they
  matter, incremental re-analysis after edits, deleting a rejected store automatically.
- [x] `switch-pic-x86-so` took 12–20 rampage calls: unnamed i386 PIC PLT stubs. Done (named through the GOT base).
- [x] Recurring argument-name errors cost a retry per call. Done (unambiguous aliases, numeric strings).
- [x] `go-nested-field` took 20–26 rampage calls against REA's 14: no Go runtime type metadata. Done (`get_type`
  Go source). Open: Go before 1.16, position-independent Go ELF (pointers filled in at load time).

## Protected and packed code (2026-11-13)

- [x] Encrypted/packed code regions detected per window; discovery skips them; PACE protector signature; real
  UPX-packed fixtures in `tests/fixtures/packed/`.
- [ ] List the named entry points inside a skipped stretch as stubs instead of only counting them.
- [ ] The x86 decode-share margin is thin (random bytes decode ~95% against the 97% threshold); entropy carries x86.

## Build diffing and annotation transfer (roadmap Phase 7, 2026-11-13)

- [x] One-to-one build matching with per-method confidence and `transfer_annotations` (preview/apply, provenance,
  conflicts). zlib 1.2.13 → 1.3 acceptance met with zero false matches.
- [ ] Switch `diff_builds` to the new matcher; CFG-shape similarity for changed functions; a single undo for
  transfers larger than one batch.

## Head-to-head suite v3: tasks where Ghidra is strong (not run yet)

The suite-v2 fairness review found that its categories lean towards what rampage was built around (RTTI evidence,
pclntab names, `diff_builds`). Suite v3 should balance that with tasks where Ghidra is known to be strong. Keep v2's
rules: truth independent of both servers, tool-neutral prompts, owned or pinned fixtures, strict and partial
scores defined before any run.

- [ ] A symbol-rich C or C++ release binary (pinned sqlite or openssl from upstream sources, checksummed), with
  questions answered from its own symbols and DWARF: callers of an internal function, a struct field's use.
- [ ] Decompiler-heavy semantics: what a function computes for given inputs (loops, bit tricks, 64-bit
  arithmetic on 32-bit targets), with truth from host runs of the owned source.
- [ ] Type propagation: apply one struct type and answer a question that needs it carried through several
  functions.
- [ ] Switch tables: the case value that reaches a given block, for jump tables in PIC and non-PIC code.
- [ ] MSVC-built PE C++: RTTI hierarchy, vtables and exception handlers (needs a pinned MSVC-built binary with
  a PDB as truth).
- [ ] 32-bit x86 (cdecl/stdcall/fastcall), including calling-convention questions.
- [ ] Go inside Ghidra's supported range (Go 1.15–1.26 for Ghidra 12.2), stripped and at scale, so its Go
  analyzers apply.
- [ ] Rizin installed on the host, or REA's Rizin-backed tools declared out of scope in the prompt-independent
  setup, so REA's advertised catalog matches what can run.

## Open acceptance gate: live Phase 1 completion

- [ ] Genuine live checked import → central C++ struct retype → owner-linked field verification and fresh replay.
- [ ] Record successful reconstruction call bound N and independent DWARF agreement; execution caps are not N.
- [ ] Diagnose the model-side failure only with new evidence; keep first attempts and prior publications frozen.
- [ ] Do not claim full Phase 1 acceptance from controlled test success alone. The maintainer approved
  proceeding through Phases 2–6 while this live acceptance gate remains open; frozen results are unchanged.
- [ ] Carry forward the native C++ class-evidence limit: stripped exceptions workload currently yields no class
  rows; symbolized vtables are skipped as not mapped read-only. Do not relax evidence rules to inflate scores.

## Audio/firmware investigation acceptance workloads

The workload: explain a third-party audio plugin or firmware image you are authorized to analyse.
The batches below track investigation outcomes and remaining blockers, not a competing feature queue.
The goal is to answer: what features exist, where their code lives, how parameters reach processing, and
which links are static candidates versus observed execution. Ship reusable improvements driven by actual
investigation obstacles, not a plugin-specific analyzer or another extension framework.

### Next three execution batches

#### Batch 2 / P0: explain one complete named effect

Question: how does one simple user-visible effect turn its parameters and input buffers into output?
Choose a small, self-contained effect (EQ, filter or delay sized), not an entire effect suite.

- [x] Match the selected catalogue ID and parameter metadata to code/data evidence, keeping resource
  declarations distinct from binary associations and runtime availability.
  One simple mono/stereo catalogue pair is corroborated by symbolic indices and native model records.
  A separately registered matching primitive is located; their composition link remains unproven.
- [ ] Trace the host/core entry, model creation, parameter-update path, processing schedule and sample kernel.
  Record buffer shapes, state, coefficient updates, bypass and sample-rate/block-size behavior where supported.
- [ ] Produce an evidence-linked feature map using existing annotations/workflows where sufficient:
  feature, module/slice identity, address, role, supporting references, confidence and unresolved links.
  Keep third-party inputs local; repository examples use owned inputs and generic descriptions.
- [ ] Fix only the highest-impact blockers on that path. Current candidates are an unresolved bounded ARM64
  parameter-routing jump table and incorrect/missing recovered signatures or mixed integer/float storage types.
  Diagnose the specific shape before choosing a recovery change; warnings remain visible until actually resolved.
  - [x] Bounded fatal-wrapper recognition prevents a real primitive-update function from absorbing adjacent code
    after its assertion wrapper. Re-tested through MCP; throwing imports, conditional/unknown transfers and
    resumable/system traps are excluded, and wrapper reads consume shared preparation budgets.
- [ ] For each fix, show the failing owned case, corrected result and repeated real investigation. Check the
  important arithmetic/control flow against assembly; use source-known fixtures for independent ground truth.

Done: a reader can follow one named effect from controls to sample processing, locate the relevant code in MCP,
and see exactly which associations remain uncertain. A primitive alone or a plausible decompilation is not enough.

#### Batch 3 / P0: transfer to an independent implementation before expanding scope

- [ ] Apply the same catalogue -> descriptor -> code workflow to a second plugin from a different developer that
  you are authorized to analyse. Do not add developer-specific conditions to make the case pass.
- [ ] Find a meaningful processing or parameter/state path, not just exports or a factory forwarding wrapper.
  If a candidate cannot be inspected statically, record the boundary and select another accessible candidate;
  no installer execution or security-setting changes.
- [ ] Compare manual handoffs, critical unresolved links and query cost against the starting investigation.
  Record regressions as well as gains; an explicit refusal is honest reporting, not transfer success.

Done: the improvements support a second independent implementation and produce another useful code map.
If they do not transfer, fix the demonstrated general limitation before starting another feature family.

### P1: confirm selected links at runtime (after the first static effect map)

- [ ] Add bounded read-only stack-frame enumeration to the existing stop-token-pinned LLDB protocol and
  API/CLI/MCP; include thread/frame identity and qualified module/image/load addresses with explicit failures.
- [ ] Replace the custom stack-walk script in the authorized disposable-host experiment with rampage queries.
- [ ] Observe one selected processing callback and one parameter/state path when safely reachable, then compare
  them with the static map. Keep registered, reachable and observed-execution claims separate.
- [ ] Preserve the stop identity and DATA-order evidence requirements; ARM64 order remains unknown without
  affirmative stop-bound evidence. No automatic launch/attach/resume/stepping/breakpoints/expressions/writes.

Done: an explicitly operator-stopped disposable host can confirm selected links through rampage alone,
without audio-device output, DAW/project changes or unsupported capture claims. This is not full flow coverage.

### Parallel track: efficient unknown-firmware/binary investigation

Decoder-provider implementation and static investigations can run independently from the plugin queue.
Shared API/CLI/MCP edits and builds remain coordinated; each parallel worker owns a disjoint file scope.

- [x] Initial read-only inventory found a raw update header, an updater label, plausible Thumb instructions
  and readable effect/preset names. Standard executable carving found no validated embedded image; this is
  partial visibility, not a recovered container, proven architecture or evidence of encryption.
- [x] Corroborate two compressed component extents and decode both in memory with explicit LZSS parameters:
  exact declared input consumption/output lengths and matching stored additive checksums; no payload files.
  Traceable initial-vector/startup evidence supports a local Thumb mapping, not a proven physical device map.
- [x] Reproduce the actual tool gap: unknown-file inspect/triage/strings and explicit-offset disassembly refuse
  before useful inspection because they require native executable headers. Zero carve candidates missed the
  proprietary components; it did not establish that the image was empty or encrypted.
- [x] First enabling slice: format-independent byte/ASCII-string triage on explicit file ranges, with offsets,
  bounded previews, fill/occupied-region summaries and range hashes; no native loader or extraction required.
  Done: `file_layout` / `binary layout` ([file layout](docs/file-layout.md)).
- [x] Second enabling slice: explicit raw-code windows with file range, address base, architecture, code mode
  and byte order supplied as analyst assertions. Use the existing decoder; no guessed executable layout or seeds.
  MCP and CLI expose bounded original-file windows; owned compiler/IT/literal/boundary cases and a real loader
  window passed. Unknown backward literals and prior out-of-window IT context remain explicit limitations.
- [ ] Use that raw Thumb view to corroborate the initial loader's decode loop, callers and component address
  fields, then follow one decoded startup/control path. Exact chip, field roles and full memory map remain open.
  - [x] Corroborate the ring start, flags, reference assembly and ring wrapping through MCP raw inspection.
- [x] Promote the corroborated codec experiment into an explicit internal decoder-provider interface with
  a built-in LZSS-4K variant, not a public SDK or triage-plugin ABI change. Shared API/CLI/MCP accept an explicit
  file range, codec, dictionary parameters and supplied output size, returning transient bytes/receipts only.
  Source-range/output hashes, consumed/trailing counts and decoded-offset previews remain separate from
  container authentication, source offsets and load addresses. No file publication or execution is supplied.
  Both real components reproduced the independent decoded hashes, exact input/output lengths and stored
  byte sums through the CLI; raw-code loading and the complete loader contract are still open.
- Static only: no updater/installer execution, flashing, emulator execution or security changes. Do not turn
  this into an automatic unpacker or a generic firmware framework before the first traced loader path.

### Firmware gaps seen in an agent run on a Cortex-M image (2026-11-09, done 2026-11-12 except follow-ups)

An agent analysing a headerless ARM Thumb (Cortex-M) firmware image fell back to
`strings`/`xxd`, a Python wrapper around the rampage CLI for range disassembly, an entropy/0xFF-run map, and an
LZ parameter brute force. Each is a candidate MCP tool; one at a time, each needing its own design and go-ahead.
Verify first which of these the existing raw-window and decoder-provider slices above already cover.

- [x] **Firmware layout tool.** Regions, 0xFF/0x00 padding runs, per-block entropy (packed areas), string
  clusters and range hashes in one call. Extends the byte/ASCII triage slice above. Done: `file_layout` (MCP
  `core`) and `binary layout`, up to 64 MiB per call with capped lists and a continuation range, plus labelled
  Cortex-M vector-table candidate hints (evidence only; the Raw selector's `vector_table` does the seeding).
- [x] **Unknown-compression probe.** Try LZSS/LZ4/LZ77 variants and a bit-order/length-encoding sweep against a
  supplied or expected output size or an entropy drop, and return candidate decoder-provider parameters. Builds
  on the explicit LZSS-4K provider; the agent re-derived this by hand.
  Done: `probe_compression` (LZ4 block + 160 LZSS variants; confident only with an expected size). Open: ring fill
  byte often undecidable, deflate/LZMA/LZO/LZ4 frames, arch-aware output checks, a run on a real image.
- [x] **Cortex-M vector table and entry detection.** Reset/SP/handler candidates with evidence, so the first
  load needs no trial and error. Pairs with the ARM/Thumb Raw profile item under the benchmark follow-ups. Done:
  `raw.vector_table` seeds entry and handlers and reports each word's verdict in `binary_info`, with a labelled
  base-address suggestion it never applies.
- [x] **Raw ingest in one call.** Blob plus arch, mode and base address returns a ready project (see the
  ARM/Thumb Raw profile item), so agents need not read `cli-reference.md` and `sleigh-decoding.md` to learn it.
  Done: `"raw":{"profile":"cortex-m","offset":0,"length":N,"base_address":...,"vector_table":true}` on any
  raw-capable tool; the server instructions and headerless-file guidance show it.
- [x] **Range disassembly to text**, native in `inspect_raw_code`, replacing wrapper scripts. Done through the
  Cortex-M Raw Project instead: `disassemble` with `raw`, `count` up to 1000 and `view: "code"` pages over the whole
  image (tested end to end on the owned fixture).
- [x] **Thumb-2 MSR decode bug.** `msr basepri, r0` (`80 f3 11 88`) decoded as invalid, stopping discovery and
  `inspect_raw_code`. Done for the Cortex-M Raw profile, the documented path for Cortex-M code: M-profile
  decoding adds hand-written `MRS`/`MSR` encodings (UNPREDICTABLE forms refused) and makes A-profile-only
  instructions (BLX to A32, Advanced SIMD, SETEND, ERET, ...) UNDEFINED, llvm-mc-checked. `inspect_raw_code`
  `thumb` stays A-profile and its docs point Cortex-M users at the Raw profile.
- [x] **Tail-call splits without symbols.** A function first reached by a tail call (`b.w f`) before its own
  call is seen splits at internal join points: 1,773 of 6,030 starts on a generated 1 MiB Cortex-M image, the same
  on its stripped ELF. Discovery should drop the caller's stale exploration once `f` becomes a function. Done: callers are re-explored
  once a later start appears, before shared tails are counted (generated 6,000-function image: 8,234 → 6,002
  starts, exact; other binaries unchanged). Still open: a function reached only by one tail call stays in its caller.
- [x] **Multi-stage images.** Load a decoded bootloader payload as a second region at its RAM base, linked to the
  source range. Overlaps the dump-as-linked-target idea in the malware-analysis track.
  Done as `raw.regions` (file-range, decoded or unbacked code/data/ram regions) plus `format` `ihex`/`srec`.
  Open: HEX run addresses, regions from a second file, vector/pointer-table scans beyond the primary region.
- [x] **Function discovery from pointer tables.** Discovery seeds only the entry point. Seed from tables of code
  pointers, with evidence per seed, so a raw image needs no hand-built symbol list (the Cortex-M vector table
  is done through `raw.vector_table`). Done: opt-in `raw.pointer_tables` (needs two strong targets per table;
  fixture 17/17 precision, 17/18 recall). Leaf-only tables are refused; adjacent tables report as one run.
- [x] **Decompiler accuracy on a raw Thumb image:**
  - a `bl` checksum call dropped its length argument (a stale `r1` from earlier code);
  - a shift-and-mask rendered as `&0xfff << 4`, which hid the real operation; compare against the disassembly
    on an owned case before changing anything;
  - literal-pool addresses showed as unnamed `iRam…`/`pxRam…` variables, so name or annotate them.
  Done for Cortex-M Raw images: pool folding, region names, IPRA-aware callee effects and parameter-only callee
  prototypes; the shift-and-mask is correct Ghidra output (documented). Open: `--exact-entry` path, other
  architectures, pool constants printed as numbers, callees whose return is used still print `void`.
- [x] **Performance at about 5k symbols.** Listing 5,182 seeded symbols took about 22 seconds, and `xrefs --to`
  ran past 2 minutes on the same image. Profile both and fix the slow path (likely a scan per query rather than
  an index). Done: the slow path was a full-image hash per xref row (binding check); now once per query. The
  22 s listing did not reproduce on the Cortex-M profile; re-time the original Sleigh workflow. Open: one image
  hash per call remains (cache the raw identity in `rampage-loaders`). Done 2026-11-13: hashed once per open.
- [x] **Container recognition.** Triage and `carve` do not flag a proprietary compressed container, i.e. a
  header with load address, sizes and a byte-sum around an LZSS stream. Report "header-checked
  compressed-component candidate" with extents, so the compression probe has a starting range.
  Done as the `file_layout` hint `compressed_component_candidate` (size + byte-sum/CRC-32 or packed payload at a
  boundary with a decoded-size word); triage and `carve` unchanged.
- [x] **MCP tools in subagent sessions.** The agent had no rampage MCP tools and fell back to the CLI. Find out
  why (server config, permissions or startup), and document how to expose them to agents. Done: configuration, not
  a server fault. On the machine that ran it, `rampage` was neither installed on `PATH` nor registered at any
  Claude Code scope, so no session there could start the server.
  [MCP](docs/mcp.md#agents-subagents-and-scripted-sessions) now covers scope, subagent `tools` lists, `claude -p`
  flags and startup checks.

### Execution rules for speed

- One active slice per independent track; shared-file edits and the central build queue stay serialized.
  Each batch ends with a usable investigation result and a short next blocker.
- Use MCP first. Scripts are for genuinely necessary host/process coordination, not routine JSON consumption.
- Timebox an unproductive investigation to 60-90 minutes; record the exact missing evidence or failing query,
  then choose the smallest enabling fix or another accessible target rather than expanding the framework.
- Run changed-area regressions and a real before/after first; expand validation for the touched consumers
  before publication. Use shared `target/`, two build jobs and the existing low-debug/non-incremental profiles.
  Review nontrivial diffs independently; retain timeout/failure limits instead of reporting an unearned pass.
- Keep commercial binaries, payloads, extracted code, captures and secrets out of git. Commit only generic
  implementation, owned fixtures and generic documentation. No release tags or CI dispatch for ordinary work.
- Defer general resource-import frameworks, broad C++ reconstruction, new component-plugin infrastructure,
  raw-firmware support and UI expansion unless the active investigation demonstrates they are the next blocker.

## IDA/Ghidra gap-closing wave 1 (done earlier)

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#idaghidra-gap-closing-wave-1-done-earlier).

### Pending follow-ups from this wave

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#pending-follow-ups-from-this-wave).

- [ ] MIPS signatures: mask `lui`/`addiu` HI/LO address pairs. Needs relocation/dataflow to avoid false matches
  (without it, a masked constant could collide two different functions); do it relocation-gated, not heuristic.
- [x] Verify the MSVC RTTI path against a real PE. Done 2026-11-12 on owned clang-cl x86/x64 fixtures with PDB truth
  (`tests/fixtures/msvc-cpp`): RTTI already correct; vftables, `__CxxFrameHandler3` EH tables and PDB names added.
- [ ] MSVC follow-ups, most valuable first: decode `__CxxFrameHandler4` (cl.exe x64 default; needs a real cl.exe
  FH4 fixture, e.g. via msvc-wine: clang-cl always emits FH3); fold catch-resume points back into parents; x86 SEH
  (`_except_handler3/4`) and ARM64 tables; PDB types; virtual calls through virtual bases or vftables stored by a
  constructor in the caller. Done 2026-11-13: virtual call → vftable slot in decompilation, paged `rtti_classes`
  with base-only rows, `/OPT:ICF` in debug-type import.
- [ ] C++ class LAYOUT reconstruction (fields/sizes), building on the RTTI name/hierarchy recovery now in place.

## Heuristic-database layer (pluggable detection DBs)

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#heuristic-database-layer-pluggable-detection-dbs).

- [x] A real packed fixture: UPX-packed ELF and PE in `tests/fixtures/packed/` (2026-11-13).
- [x] Detect It Easy signatures imported (544, exact conversions only). Open: an alias table to merge DIE and rampage
  names (e.g. "MSVC" vs "Microsoft Visual C/C++"); DIE's UPX scripts (helpers/loops) are not converted, and UPX-packed
  ELF is not detected yet; a Linux userland false-positive sweep.
- [ ] Later DB kinds: Ghidra FidDb import (Apache, library-function ID, format conversion); ClamAV `.ndb/.ldb`
  as a user-supplied runtime input (GPL data -- never bundled); richer capa features once disasm extraction lands.

## Heuristic flywheel (propose -> measure -> gate -> promote)

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#heuristic-flywheel-propose---measure---gate---promote).

- [ ] Additional bound/comparison forms (including `BC.cond`) and broader compiled scheduling acceptance.
- [ ] Masking for 32-bit ARM literal pools and MIPS `lui`/`addiu` pairs, once a cross-program fixture exists.
- [ ] Tool-ID remaining: Zig on stripped builds and PEs, Clang on Mach-O/PE (no producer record), the whole-file
  "rustc version" rule (tentative; scope or drop), real NSIS/Inno Setup installer fixtures, a Zig-language Mach-O
  fixture.
- [ ] PDB-backed type truth and automated proposal/gate/promote stages with held-out provenance and rollback.

## Ideas from adjacent projects (REA, Ghidra-MCP)

### REA gap-closing wave 1 (2026-10-29)

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#rea-gap-closing-wave-1-2026-10-29).

- [ ] Annotation log compaction. Without it, a log at its limits can only be read: renames, undo and the ledger
  are refused. Compaction would also close the remaining gap: a log whose checked state was cleared is still
  replayed checked on open, but ordinary sessions don't apply the checked cache budget, so more than about 2,000
  names there would make the checked open fail.
- [ ] Ledger: deleting entries, clearing optional fields, appending evidence on update.

- [ ] APK (JADX) and Electron unpacking are lower-priority follow-ons; carving is not archive extraction.
- [ ] .NET external or assembly-qualified enums, symbolic enum-attribute names, resource payloads,
  and comparison of `dotnet_il` with ildasm/ILSpy once available. Metadata bindings do not establish accessor behavior.
- [ ] Per-path pointer-comparison offsets. Nontrivial image selection
  does not load embedded snapshot JSON; pointer-peer flags alone would not establish usable support.

## Plugin system (later)

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#plugin-system-later).

- [ ] WASM component plugins (wasmtime is already a dependency via yara-x): sandboxed, language-agnostic code for
  detectors, format loaders and workflows behind a WIT interface; bytes plus read-only analysis queries in,
  findings out. The output schema enforces the evidence/confidence/limitations contract.
  The bounded triage-component milestone below implements the first explicit executable lane and genuine guest
  composition, not general detector/loader plugins, automatic discovery, or a stable public SDK. Static builtin
  registries remain separate. Broader capabilities and module migration require independent acceptance.

### Experimental triage component milestone

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#experimental-triage-component-milestone).

- [ ] Linux component gate is wired but not locally executed; cancellation inside compilation and uninstrumented
  guest-cancellation latency,
  broader source loading and component grammar, other workflow migrations, MCP/UI providers and a stable SDK
  remain unearned. The follow-up below adds opt-in installation and an instrumented activation checkpoint.

## Decompiler: embedded Ghidra (the decompilation path)

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#decompiler-embedded-ghidra-the-decompilation-path).

- [ ] C++ class recovery: typed vtables/RTTI and `this` pointers in the decompiler. The embedded library reads
  types from C declarations or XML, not Ghidra `.gdt` archives, so this needs a header/type pipeline, not a
  `.gdt` import. Larger, separate effort.
- [ ] Richer automatic `main`/entry signature recovery without debug metadata.

### Integration acceptance order

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#integration-acceptance-order).

3. [x] Compiler ABI selection: PE Windows and Darwin PowerPC defaults, explicit API/CLI overrides, strict
   compiler-ID/data-model validation and target-sized runtime declarations. Reviewed coverage includes
   ILP32/LP64/LLP64, Windows x86 cdecl, clangwindows aliases and all 13 bundled processor targets.
   - [x] ARM BE8 mixed instruction/data endian selection, preserved by compiler overrides.
   - [x] Darwin ARM64 fixed stack packing and explicit variadic slot allocator/compiler model.
   - [x] OS/library-specific typedefs: off_t/time_t/mode_t/pid_t prototypes sized by width placeholders, with the
     POSIX I/O and time functions that use them (documented 32-bit Linux off_t and 32-bit Darwin time_t edges).
    - [x] Declared Darwin ARM64 narrow integer input extension to 32 bits, preserving unknown upper bits and
      existing return rules. Owned compiled/recompiled C covers 58 comparisons; input-window controls include
      cloned models, packing, promotions and conservative malformed-spec refusals.
    - [ ] Remaining ABI-specific work: general Darwin ARM64 variadic call recovery and broader ABI/call correctness.
5. [x] Portable specification packaging and supervised resource/cancellation integration,
   including allocation-failure containment at the C ABI. This is not an OS sandbox or native memory-safety proof.
   - [x] Embed specifications, versioned verified cache and relocated executable regression without Ghidra.
   - [x] Bound text/token output; contain standard exceptions during decompilation.
   - [x] Opt-in supervised worker with wall-clock cancellation, bounded concurrent pipe I/O and memory enforcement
     (Linux hard limits; macOS sampled RSS), API/CLI/session integration without native fallback.
   - [x] Packaged sessions automatically select a sibling worker; install script ships worker and CLI together.
   - [x] Complete C ABI exception containment with allocation-free fallback and poisoned-state handling.
   - [ ] Other supervisor platforms and native upstream memory-safety remediation.
6. [ ] Persistent user types/signatures/calling conventions and typed globals, then debug-type imports and
   class recovery.
   - [x] Validated persistent signatures and type declarations, API/MCP tools and shared-log dependency checks.
   - [x] Validated persistent typed globals with complete mapped-data storage and dependency checks.
   - [x] Bounded embedded-DWARF scalar/pointer signature preview/import with non-overwriting application.
    - [x] Bounded named Itanium vtable/RTTI/code-slot class evidence; no asserted object layouts.
    - [x] Bounded read-only verification of parsed flat-struct layouts and ordered worker assertions for x86-64 GCC;
      independent compiled size/alignment/offset and field-use gates. Assertions are ephemeral, not debug imports.
    - [x] Separate checked embedded-DWARF flat-struct pointer import: explicit producer struct alignment, bounded
      C metadata, identity-qualified types, persistent assertions, frozen consent and one atomic dependency batch.
   - [ ] Exact aggregate/debug-layout import, external PDB/dSYM support and automatic class-layout recovery.
8. [ ] Versioned differential benchmarks: precision/recall, thunks, signatures/calls/strings/switches, warnings,
   coverage and time/memory across stripped/symbolized compiler/optimization/ABI corpora.
   - [x] Discovery precision/recall and installed Ghidra version instead of a hard-coded version.
   - [x] Versioned bounded corpus runner with explicit signature/call/string/switch assertions, failure coverage,
     timing and resource diagnostics; not an equivalence score.
   - [ ] Matched-setting differential decompilation corpus and coverage/runtime/memory metrics.

**This supersedes the hand-written "Deep ARM64 track" below as the route to decompiled output.** That native
IR/SSA/pseudocode work stays as complementary, evidence-bounded diagnostics (and feeds the function list the
decompiler works from); it is no longer the path to source recovery, so it is not worth hand-reimplementing what
Ghidra already provides (types, structuring, FP/SIMD, every architecture). Keep only the parts that improve
rampage's own discovery and CFG, which the decompiler depends on.

## Current status (native analysis track, now complementary)

Deep ARM64 support is **in progress**, not IDA/Ghidra parity or complete typed-source recovery.
Checked items below describe bounded, tested capabilities; sections marked partial still have acceptance work remaining.

### Darwin narrow inputs and aggregate-verification bridge

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#darwin-narrow-inputs-and-aggregate-verification-bridge).

- [ ] Full-workspace release gate: interrupted during compilation after an excessive optimized test-link rebuild;
  this is neither a suite pass nor an assertion failure. Focused release validation above passed with unchanged
  profiles.

### Verified-DWARF layout batch — initial bounded scope

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#verified-dwarf-layout-batch--initial-bounded-scope).

- [ ] Initial layout-batch optimized acceptance: the selected API/worker fixture build hit its five-minute cap
  while linking, before assertions. No optimized-suite success is claimed;
  release ThinLTO/codegen settings are unchanged.

### Usable typed-decompilation push

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#usable-typed-decompilation-push).

- [ ] Broader matched-setting C/C++ differential decompilation corpus and runtime/memory metrics. These initial
  independent compiler/source oracles are not that benchmark or general class-layout/virtual-dispatch acceptance.

### Bounded virtual-method evidence

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#bounded-virtual-method-evidence).

- [ ] Broad C++ differential/corpus/performance acceptance, typed virtual dispatch, inheritance and adjusting thunks.
  The owned source/compiler oracles and exact slot correlations do not earn these broader capabilities.

### Exact-entry analysis and local debugger workspace

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#exact-entry-analysis-and-local-debugger-workspace).

- [ ] New live end-to-end LLDB workspace acceptance, broader ABI/platform coverage and performance measurements.
  Owned protocol mocks and image fixtures do not establish arbitrary-host or third-party-runtime acceptance.
  The owned x86-64 live gate compiled but Apple LLDB refused launch with `Bad CPU type in executable` on the
  arm64 host, before UI observations. No Rosetta installation or ARM64 data-order guess bypassed that blocker.
- [ ] Larger matched-setting corpora; bounded host context does not promise constant latency, complete discovery
  context or cropped-image behavior.
- [ ] Windows debugging (9.6a): implemented through RSP stubs; live acceptance on a Windows host is open. The GDB
  remote backend is done (9.1).

### Deferred exact-entry UI and reviewed static workspaces

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#deferred-exact-entry-ui-and-reviewed-static-workspaces).

- [ ] Broader derived analysis caches and runtime cross-module resolution; the historical inventory and static PE
  declaration slices below do not complete these. Broader ABI/type recovery and affirmative
  ARM64 runtime DATA-order evidence remain open. The GDB backend and execution control landed in Phase 9.1–9.4 and
  Windows (live acceptance pending) in 9.6a; see `docs/plans/2026-10-29-debugger-control.md`.

### Static references, responsive file operations and historical inventory

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#static-references-responsive-file-operations-and-historical-inventory).

- [ ] Runtime/converted executable plugins, broader recovery and remaining TODOs are not part of this milestone.

### Validation and external blockers

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#validation-and-external-blockers).

- [ ] Resolve the local `rust-objcopy` missing-`libLLVM.dylib` stripping warning; release tests still execute.
  - Command-local `DYLD_LIBRARY_PATH=<rustc-sysroot>/lib` resolves the installed tool's library lookup;
    permanent managed-toolchain repair remains open rather than patching rustup-owned executables.

## Deep ARM64 track and remaining work

### 1. Instruction semantics — partial

- [x] Immediate, shifted and extended ADD/SUB; logical operations; wide moves; multiply/divide; variable shifts.
- [x] NZCV, B.cond, CBZ/CBNZ/TBZ/TBNZ, CSEL/CSINC/CSINV/CSNEG, ADR/ADRP and plain BL/BLR/BR/RET.
- [x] Common non-wrapping bitfield aliases; 8/16/32/64-bit scalar memory with separate result/access widths.
- [x] Literal/register/unsigned/unscaled/pre/post addressing; 32/64-bit pairs and signed LDPSW.
- [x] Remaining common integer families: carry arithmetic (ADC/ADCS/SBC/SBCS, NGC/NGCS), conditional compares
  (CCMP/CCMN register/immediate), wrapping bitfields (SBFIZ/UBFIZ/BFI/BFXIL/BFC), long/high multiply
  (S/UMADDL, S/UMSUBL, SMULH/UMULH), EXTR/ROR immediate, CLZ/CLS/RBIT/REV/REV16/REV32, each with native
  boundary regressions (all 16 NZCV inputs for flag-dependent families, also through SSA/dataflow) and
  natively recorded expected values that replay on any host. FEAT_CSSC, RMIF and SETF8/16 remain barriers.
- [x] Valid no-writeback pair loads with base/destination overlap; capture both original addresses before
  assignments for LDP X/W and LDPSW. Writeback overlaps and duplicate destinations remain barriers.
- [ ] FP/SIMD, atomic/exclusive and selected system semantics, with effects and memory ordering explicit.
- [ ] PAC/authenticated flow, exceptions and platform-specific behavior; unsupported forms must remain barriers.

### 2. Stack, memory and signatures — partial

- [x] Integer AAPCS64 caller clobbers/callee preservation; X8 result-buffer and SP call dependencies.
- [x] Entry-SP-relative slots, conflicting-path unknowns, per-RET X0/X1 candidates and input-use argument evidence.
- [x] Exact-width constant-store forwarding with source IDs and all-path agreement; conservative alias boundaries.
- [x] Exact-width nonconstant entry-SP spill/reload aliases when all reaching paths agree. Original load
  observations and recovered-load provenance remain explicit; recovered pointers cannot restart stack-memory
  inference. Source clobbers, width/sign extension, aliases and budgets have behavioral regressions.
- [ ] Partial-width overlap reconstruction, safe cyclic-memory fixpoints and broader alias proofs. Calls,
  unknown aliases, conflicting paths and cyclic proofs remain unresolved.
- [ ] Stack-frame boundaries, outgoing stack arguments, saved-register roles and escaped-stack alias handling.
- [ ] Interprocedural signatures: argument count/types, void versus value, aggregate returns, varargs and FP/SIMD ABI.
- [ ] Propagate type constraints and reconstruct pointer/struct/class layouts; local operand roles alone are not types.

### 3. SSA and pseudocode — partial

- [x] Bounded register/memory SSA, predecessor-indexed phis, constants/affine stack reasoning and semantic gaps.
- [x] Redundant phi aliases, dominators, natural-loop evidence and conservative sequence/branch/single-body regions.
- [x] Labeled and `--structured` SSA pseudocode with explicit predecessor tokens and simultaneous phi bindings.
- [x] Execution comparisons cover both diamond arms, repeated loops and both loop-condition polarities.
- [ ] Minimal phi placement, dead-definition elimination and broader expression simplification without amplification.
- [x] Bounded non-fall-through switch regions with retained table entries and guard evidence; unsupported
  switch shapes preserve labelled SSA diagnostics rather than invented structure.
- [ ] Nested/multi-block loops, broader branch joins, fall-through switch regions and irreducible-flow handling.
- [ ] Typed variables, source-level expressions/returns and readable decompiler output distinct from SSA diagnostics.

### 4. Jump tables and indirect flow — partial

- [x] Conservative ADR/ADRP/ADD/MOV/LDR/BR/BLR discovery; calls/stores invalidate captured-memory assumptions.
- [x] Explicit bounded absolute64/signed-relative32 table inspection, without guessed dispatch bounds.
- [x] Image-validated SSA target evidence, including a spilled constant target.
- [x] Bounded AArch64 and x86/x86-64 dispatch recognition with proven unsigned bounds, read-only backed tables,
  validated destinations and branch-site evidence. Cross-block facts are revalidated after graph expansion.
- [x] Proven immutable switch cases feed discovery/CFG/xrefs as case edges, not function seeds, retaining table
  order and guard evidence. Other indirect-flow forms remain separate acceptance work.
- [ ] Mutable pointers only after alias/reaching-store proof; authenticated or unmapped targets remain unresolved.
- [ ] Fixtures for relative tables, duplicate targets, joins, loops, truncation, overflow and hostile index bounds.

### 5. Controlled runtime capture — initial gate complete

- [x] Successful permitted stopped-process capture, module UUIDs/bases, register provenance and original correlation.
- [x] Mapping-aware snapshot identity and durable identity-scoped annotation persistence, including addresses,
  permissions and endianness. Per-file provenance/register observations are not conflated by identity reuse.
- [x] Persist explicit decompiler configuration, module/source identities and navigation in reviewed workspace files.
- [ ] Persist derived analysis caches and broader reproducible analysis state; the manifest is not an engine cache.
- [ ] Multiple modules/threads and stripped/relocated images; module-qualified navigation and cross-module references.
- [ ] Broader debugger/platform integration, capture failure handling and provenance validation on larger fixtures.

### 6. Accuracy benchmark — partial

- [x] Synthetic snapshots, native instruction oracles, compiled fixtures and malformed-input/resource regressions.
- [x] Versioned, hash-/architecture-matched function-start reference imports; snapshot comparisons reject
  ambiguous identity.
- [x] Versioned x86-64/AArch64 matched-pair corpus for library ID, discovery, tool detection and DWARF-backed
  signature recovery. The committed 13-slice baseline gate passes at `6122f64`.
- [ ] Broader compiler/optimization/ABI coverage with instruction/stack/semantic and time/memory metrics.
- [x] Pinned read-only CI workflow: format, warnings-denied Clippy, ordinary macOS workspace/UI tests and selected
  opt-ins, the 13-slice evaluation gate, an explicit Linux core subset, and redacted HEAD/full merge-history
  secret scans that cannot silently inherit repository allowlists. Hosted gates passed at `ffc84e7`.
- [ ] Quantitative unsupported-coverage and per-analysis time/memory gates; CI job/step timeouts are not substitutes.
  - [x] Explicit corpus recovery-status/flag/count assertions and configurable elapsed-time assertions, with missing
    diagnostics/measurements and identity mismatches retained as unavailable. Controlled fixture recovery gates
    and runner regressions are wired into CI; these do not measure unsupported coverage or per-case peak memory.
  - [x] Three owned compiled-switch fixtures are included in tool-ID truth. The expanded slice measures 129/163
    correct expected tools (recall 0.791411, precision 1.0); its floor is raised to 0.7914, not weakened. This is a
    corpus-denominator change, not a detector improvement or a rewrite of historical measurements.
- [x] Ghidra exports compare function starts, blocks, CFG edges and calls on 18 fixtures; reference output is
  not ground truth, and normalized chain agreement is not decompiler or semantic equivalence.
- [ ] IDA exports/comparisons once an installation is available.
- [ ] Expand beyond current CFG/call and signature metrics to dispatch truth, stack evidence and semantics.

### Next execution order

1. [x] Resolve the earlier full-debug timeout and complete debug/release workspace validation.
2. Extend common integer semantics and nonconstant spill recovery, keeping alias boundaries conservative.
3. Recover bounded dispatch tables and integrate proven targets into CFG/discovery with regression fixtures.
4. Broaden structuring and type/signature propagation; keep SSA diagnostics separate from recovered source.
5. Build the versioned accuracy corpus/CI gates and complete persistence/cross-module runtime work.

Native IR/SSA remains complementary to the embedded Ghidra decompiler above. Vendored Ghidra implementation
and specifications retain their Apache-2.0 license and attribution; any additional copied/ported components
require their applicable license and attribution.

## General-purpose reverse-engineering roadmap

### Transformed static code and runtime analysis

Successful loading, discovery and C emission do not establish usable recovery. High entropy, invalid decoding,
unresolved wrapper jumps, missing debug types and absent named vtables need explicit diagnostics. These are
evidence and limitations, not proof of encryption or verified function counts.

Work in this order, with synthetic regressions and independent review for each increment:

1. [x] Structured recovery diagnostics: export engine warnings, bad-data/unimplemented flags and unresolved
   calls/jump tables. Surface warnings in CLI/API/MCP/UI and separate successful output from usable recovery in
   benchmarks; no unqualified "complete" or "clean implies correct" label.
2. [x] Discovery-confidence summaries: relate candidates to bounded sampled regions and preserve evidence for
   suspicious tiny fragments, invalid decode and code/data ambiguity. Do not silently delete candidate functions
   or infer encryption from entropy alone. Use cached discovery modes; whole-program discovery is an explicit
   opt-in (`audit --include-discovery` / MCP `include_discovery`), not a hidden prerequisite for sampling.
3. [ ] Authorized capture workflow: bounded module/range selection and actual memory-permission checks in the
   stopped-process LLDB exporter, capture failures and provenance. No automatic plugin launch, installation,
   debugger attachment or target-memory writes; controlled live tests use our own fixtures.
   - [x] Exact mapping permissions, bounded inspection, complete reads, expression-stop identity checks and
     atomic no-clobber publication; breakpoint normalization recorded in provenance.
   - [x] Explicit UUID/original-address range and seed selection with checked slides, section coverage and
     conflicting-mapping rejection; controlled live fixture validation.
   - [ ] Broader multi-thread/module capture acceptance and module-specific byte-order context.
   - [x] Explicit bounded thread selectors/all-thread register capture, stop-context and module-provenance
     revalidation; controlled live acceptance covers two owned modules and two threads.
4. [ ] Runtime target identity: persist platform/compiler context, mapping-aware capture identity and module/
   thread provenance so an ARM64 macOS capture does not silently use generic AAPCS64 decompilation defaults.
   - [x] Validated optional platform/compiler context, exported by LLDB and used by native/worker defaults.
   - [x] Canonical mapping-aware triage identity and normalized UUID-duplicate validation.
   - [ ] Broader thread/module provenance consistency checks, module-specific code/data endian validation
     (including ARM BE8), and persisted session reuse by capture identity.
   - [x] Identity-scoped annotation persistence and snapshot revalidation; equal captures can share logs without
     conflating per-file provenance/register observations. Legacy unscoped logs are reported, not migrated.
5. [ ] UUID-validated static/runtime comparison: compare explicit matching captured ranges, retain byte-change
   and unavailable-range evidence, transfer only justified symbol/type information with checked ASLR slides.
   - [x] Bounded API/CLI byte comparison with equal/changed/unavailable spans and capture/original identities;
     annotation-free explicit inputs and controlled live comparison.
   - [ ] Reviewed symbol/type-transfer policy and runtime comparison navigation/agent integration.
   - [x] Shared agent/MCP byte comparisons with paginated spans, full-range totals and identities;
     fresh explicit MCP inputs bypass annotation sidecars and discovery.
6. [ ] Captured indirect-call evidence: show wrapper slot/value/target observations separately from proven flow;
   writable, authenticated, unmapped or incomplete pointers remain unresolved without additional evidence.
   - [x] Explicit API/CLI/MCP pointer-slot observations with raw values, permissions and mapping identity;
     no edge insertion, no authentication/high-bit stripping and checked ARM mode tags.
   - [ ] Link observations to decoded branch sites, module-qualified targets and before/after capture evidence.
   - [x] Bounded explicit ARM64 branch-window links to decoded slot loads, retaining indirect flow and
     raw observations; unsupported/control-flow/authenticated/incomplete cases remain explicit.
   - [x] Explicit API/CLI/MCP paired-slot comparisons across captures with raw equal/changed/unavailable outcomes,
     independent mapping/target assessments and capture identities; no inferred chronology or module ownership.
7. [ ] Authorized runtime acceptance: an analyst supplies an already-loaded/stopped instance in a legitimate host;
   capture selected code and referenced data, correlate the original UUID, rerun diagnostics/decompilation and
   report before/after warning/coverage metrics. This is blocked on an authorized host capture, not static parsing.

Third-party plugin bytes and captured process contents are local investigation inputs, not committed fixtures.
Patching is not part of this work.

Acceptance gate for each milestone: behavioral regressions, malformed-input tests, `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, workspace tests, and independent review. Third-party samples are
read-only triage inputs, never patch fixtures. Runtime tests use programs we build ourselves.

- [x] Initial runtime images: validated sparse snapshot format, CLI/API/UI loading, explicit code seeds, provenance,
  virtual-address handling and controlled LLDB export/correlation. Persistence and cross-module work remain above.
- [ ] Indirect flow: the conservative AArch64 ADR/ADRP/ADD/MOV/LDR/BR/BLR foundation is done (below). Remaining:
  other architectures, and proven targets feeding discovery/CFG (Deep ARM64 track 4). Unknown, authenticated,
  mutable and unmapped targets must remain unresolved.
- [x] Analysis confidence: `audit`/`analysis_diagnostics` explain decode coverage and unreliable-code evidence over
  sparse memory without asserting encryption (below).
- [x] Language metadata: C++/Rust demangling with original lookup names, named/stripped Itanium/MSVC RTTI,
  and bounded Objective-C classes/categories/methods/ivars/properties/protocols with malformed-pointer tests.
  Objective-C metadata handles relative methods and static chained-fixup rebases; it is not runtime PAC recovery
  or automatic C++ object-layout reconstruction.
- [x] Data-flow/decompilation: structured function summaries shipped, and decompilation comes from the embedded
  Ghidra decompiler. The native IR/SSA work continues as diagnostics in the Deep ARM64 track; it is never
  labelled a decompiler.
- [ ] Containers and workspaces: bundle discovery and inventory of already-extracted packages are done (below).
  Remaining: nested-archive inspection with extraction budgets (never executing installers) and cross-module
  navigation with address/module identities.

### Next acceptance-driven milestones

1. **Runtime integration:** extend the verified controlled capture to persistence, mapping-aware identities,
   multiple modules/threads and module-qualified navigation.
2. **Data-flow:** extend exact constant-store forwarding to nonconstant values, partial overlaps and safe loops;
   establish alias proofs before enabling mutable snapshot pointer inference.
3. **IR and SSA:** extend semantics/calling conventions, minimal phi placement and expression simplification;
   compare lifted execution with native fixtures at overflow, width, zero-register and flag boundaries.
4. **Language recovery:** stripped Itanium/MSVC vtables, class layouts, Objective-C method/class references,
   relative/authenticated pointers, DWARF/PDB integration and fixture-based malformed metadata validation.
5. **Decompilation:** expressions, conditions, loops, returns and typed variables over SSA; output must explicitly
   show semantic gaps and must not present unsupported paths as recovered source.
6. **Containers/workspaces:** safe archive indexing/extraction budgets, module-qualified names/addresses,
   dependencies, cross-module references and UI/MCP navigation; never execute installer scripts.
7. **CLI batch workflow:** first-class multi-architecture analysis reports with bounded function selection,
   per-command timeouts, recovery diagnostics and comparison summaries; avoid external orchestration for routine
   static/runtime retests. Keep candidate counts, weak signature proposals and recovered code distinct.
   - [x] Single-image guided reports through `rampage report` and the shared workflow registry, with bounded
     findings, evidence/confidence, explicit truncation and next-step tool calls.
   - [x] `rampage binary analyze` composes selected workflows and supervised function decompilations across supported
     declared architectures; slice failures, identities, warnings and output-limit outcomes are retained in
     bounded valid JSON. Text output includes workflow findings and failed previews, not just query completion.
   - [ ] Runtime comparison report composition and workflow-wide wall-clock/memory supervision. The current
     deadline bounds each supervised decompilation request; workflows retain their existing work/output budgets.
   - [x] Noun/verb command hierarchy with shared argument definitions and typed normalization; flat spellings
     remain hidden compatibility commands. Nested pack ordering and cross-level image dependencies are validated.
8. **Debugger integration:** plan an LLDB-first read-only bridge after static acceptance, with explicit session/
   stop identities, module/thread navigation, quiescent capture manifests and agent/UI queries. Attach, resume,
   breakpoint insertion and target writes require separately reviewed controls; no automatic host or plugin launch.
   Superseded for execution control by Phase 9 (`docs/plans/2026-10-29-debugger-control.md`): resume, step,
   breakpoints and writes now go through the reviewed `debug` tools; rampage still never attaches or launches.
   - [x] In-session `rampage-query` foundation for session/module/thread, fresh-register and raw-memory queries,
     with bounded JSON, stale stop tokens, exact known permissions and honest endian/stop evidence. Controlled
     owned-fixture acceptance covers Apple LLDB; no command passthrough, attach/resume/evaluation/writes/listener.
    - [x] Explicit local Unix transport, typed API/CLI/MCP and local-only UI window, with reviewed cancellation safety;
      EOF before querying, bounded framing/I/O, stale tokens and structured errors retained. Endpoint paths remain
      for operator cleanup; no automatic attach/resume/expression/target-write controls.
     - [x] Stop-pinned UUID-qualified image/load address observations via bounded section/ancestor evidence,
       surfaced in typed queries and a manual local UI template. No basename/slide fallback or automatic navigation.
     - [x] Explicit local navigation to an already-open matching static Mach-O's file address, with typed
       request/result/workspace bindings, UUID/variant/width/endian/backing/permission gates and input invalidation.
       Original mapping-descriptor identity guards observable source changes; debugger painting avoids mapped reads.
       This is neither atomic source reading nor equal-byte/current-stop/flow/layout proof.
     - [ ] Broader static-format navigation and SDK/platform acceptance.
      Query observations remain non-atomic. A disposable-host experiment subsequently exercised live read-only
      queries; broader external-plugin runtime acceptance remains open (see the active investigation queue above).

Committed-foundation validation includes full debug/release suites, warnings-denied Clippy, UI snapshots,
CLI/API/MCP regressions, malformed-input bounds, native/compiled fixtures, exporter tests, the opt-in live
capture test, debugger-cleanup regressions, Ruff/ty and independent reviews. The earlier full-debug timeout
was the one-time vendored C++ build; subsequent debug/release workspace suites passed.
