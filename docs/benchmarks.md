# Accuracy benchmarks

rampage's analysis is measured against Ghidra as a reference. Ghidra's output is a reference, not ground truth:
a matching function start does not establish a matching CFG, types or decompilation, and either tool can be
wrong. The point is to catch regressions and large gaps in rampage's own analysis.
The results below are recorded measurements, not a fresh run of the current working tree. Implementation
descriptions may include later bounded improvements; those do not imply that the benchmark was rerun.

## Phase 1.6 — checked PDB and nested DWARF type import

**Run:** 2026-10-18, committed implementation/collector `02e6173`. The
[measurement](benchmarks/phase1-6-2026-10-18.json) preserves the first live attempt. **Live Phase 1 sign-off is
not earned:** the model stopped after preview/paging, before apply or retyping.

| Measurement | Before | Implementation / controlled fixture result |
| --- | --- | --- |
| PDB type import | Identity-matched function names only | Bounded TPI/IPI graphs, explicit aliases, enums and scalar/pointer signatures |
| Nested checked DWARF layouts | Zero admitted types on the owned nested fixture | Nested aggregates, arrays and callbacks in the project library |
| AArch64 checked import | Rejected by the old x64/GCC-only path | Target-aware native counterpart assertions and replay |
| Central C++ structure | Pointer arithmetic, no source field paths | Controlled MCP import/retype exposes owner-linked cell fields and bias |
| Wrapper agreement against DWARF | 0/3 components in the measured baseline | Controlled fixture verification: 3/3; live after-result unavailable |
| First live reconstruction task | New workload | **Failed: one model-side error; no apply/retype completed** |

The first `github-copilot/gpt-6.1-sol` attempt, variant `default`, made **4 successful MCP calls / 2 model turns**
with zero tool errors, then recorded one model-side error. Agent wall time was 10.933 s. Token totals are unknown,
and the bounded report does not retain the error reason, so no provider/format/transport diagnosis is asserted.
There was no retry or regrading. Workflow, native-state and task verification remain false. The collected
preview covered 20 producer types, but applied/import counts and after-agreement remain null—not success or
measured zero. The successful completion-call bound **N is unearned**; the 32-call cap is not a result.

Separate scripted tests exercised real MCP transports, not model answers: five generated-fixture cases passed,
covering reviewed whole-batch apply, rollback, undo/redo, stale-source refusal, cold replay and deletion guards.
The owned C++ collector test independently verified a 48-byte Owner, 16-byte Cell stride, member offsets, exact
annotation maps, owner-linked native field access and 3/3 wrapper signature agreement against the DWARF DTO.
That one-wrapper controlled result is not the live task result, a Phase 0 regrade, or corpus-wide agreement gain.

The checked path retains producer facts separately from consumer measurements. Native alignment does not fill
missing producer alignment. Unsupported bitfields preserve their bit-size/offset evidence; qualified types and
unsupported ABIs remain preview-only rather than becoming complete assertions. Review hashes bind the entire
proposal, image, target/specifications, evidence and edits; pages never select writes. Proofs and library units
are cross-validated at complete annotation boundaries, with sealed signatures and cache-independent replay
witnesses. The legacy flat/projected layout and names-only PDB workflows remain unchanged.

PDB identity checks include GUID/age and same-buffer DBI/PE machine compatibility. Forward completion requires
producer unique identity, not same-named C tags; the original C fixture remains a negative control. The positive
control retains C function linkage while supplying CodeView C++ unique names. Explicit `S_UDT` aliases retain
their exact TypeIndex relationships. Source-name preservation, signed enum wire forms, array occupied versus
allocation extents and unknown-versus-absent bounds/strides have independent producer regressions.

API and the other six changed-crate suites passed in named runs after correcting the explicit Win32 convention
declarator; scoped all-target Clippy, actual MCP fixtures, collector tests and independent reviews passed.
This is not full-workspace/release acceptance. Static investigation revalidation preserved 892 C bytes and six
descriptors with warnings on an installed ARM64 core, without annotation changes. An original firmware window
returned eight decoder observations without execution or new device/full-map claims.

**Remaining phase-end gate:** obtain a genuine live completion of checked import → analyst retype → verified
central-struct fields, record successful N, and report independent agreement. This failed first attempt stays
frozen; controlled test success is not substituted for it. Earlier publications remain unchanged.

```sh
tests/fixtures/debug-types/build.sh target/phase1-6
cargo run --locked -j 2 -p rampage-eval --example debug_type_import -- target/phase1-6/debug-cpp-x64.elf
```

## Phase 1.5 — bounded unlocked type propagation

**Run:** 2026-10-18, committed source `321ea28`. The
[measurement](benchmarks/phase1-5-2026-10-18.json) preserves the first live result, source/executable/fixture
identities, bounded catalog evidence, and the failed agent outcome.

| Measurement | Before | After |
| --- | --- | --- |
| Provenance-bearing preview/apply | Missing | `propagate_types`, with conflicts, source fingerprints and full payload edits |
| Callee body-local pointer edit | Fields readable only in callee; caller had no arguments | Bounded native callee-shape bootstrap recovers caller arguments |
| Explicit callee signature | Forward native flow already available | Preserved; not counted as a new capability |
| Analyst priority | Hard annotations only | Separate unlocked hints; analyst types and names remain authoritative |
| Durable state and fresh-server checks | Missing workflow | Verified exact hints, current sources, unchanged hard types and bytes |
| First live agent task | Unmeasured | **Failed: one model-side error**, despite a verified native tool workflow |

The first `github-copilot/gpt-6.1-sol` run, variant `default`, made **9 actual MCP calls / 4 model turns** with
zero tool errors, then failed with one model-side error. `task_verified=false` remains recorded; there was no
retry or regrading. The bounded summary does not retain the error reason, so this publication does not assert
a provider, format or transport diagnosis. Usage totals are **unknown**, not zero. Agent wall time was 43.394 s;
11 preparation calls and two six-call verifier passes are counted separately.

The model completed the preview/apply/inspection workflow. Independent checks confirmed the exact durable
hints and current source fingerprint, unchanged analyst maps/library/fixture, and native caller/callee types
on both initial and fresh servers. Ordinary decompilation already supplied ephemeral recovery after seeding;
durable apply was therefore graded by stored hints and provenance, not by demanding another C-text change.
The complete compact inventory contains 48 tools; the raw 77061-byte catalog exceeded retention, so its schema
and hash remain explicitly unavailable. The agent's offered allowlist contained 30 tools.

Native/API tests demonstrate both parameter directions; worker tests cover hint replay, bootstrap, return
evidence, global value/address distinctions and analyst precedence. Native field tokens now
retain real emission spans/addresses instead of disappearing from token output. Unknown, joined, hidden,
variadic and unsupported mappings remain explicit. Some multi-hop contexts and generic-pointer refinement
combinations remain unsupported; optional inference cannot suppress otherwise valid ordinary C.

Apply receipts expose complete old/new hint payloads, including clears and provenance-only updates. The
transaction validates all retained fresh targets within the combined function budget; a partial clear cannot
silently invalidate another function's selector. Preview, preflight rollback, independent clear/undo/redo,
shared-client changes and outside-context rejection are covered. Fatal worker/source/attestation failures are
not converted into partial success. External-spec selection without stored hints is handled separately from
strict fingerprint errors; no worker-to-inline fallback is introduced.

Target-model import prototypes cover portable `memcpy`, explicitly selected POSIX `recv`, corrected Windows
`recv` and x86/x64 `CreateFileW`, with native-parser width/convention tests. Default/ELF is not Linux proof.
An installed ARM64 core revalidation still returned 892 C bytes and six descriptors, preserving warnings and
leaving annotations unchanged.

API, decompiler, evaluator, MCP and UI suites passed in the broad run. That run reached an outdated worker
redaction-test expectation after adding a new error category; the corrected **full worker suite** then passed.
Scoped all-target Clippy, collector regressions and independent reviews passed. These are changed-crate checks,
not full-workspace/release acceptance. The live task grades direct pointer propagation only, not the broader
return/multi-hop test coverage or blind recovery. Earlier published measurements remain unchanged.

```sh
cargo run --locked -j 2 -p rampage-eval --example type_propagation -- tests/data/type-propagation-x64.snapshot.json
```

## Phase 1.4 — native and tracked function-frame evidence

**Run:** 2026-10-17, committed source `8fdfb2b`. The
[measurement](benchmarks/phase1-4-2026-10-17.json) retains exact source/executable/fixture/report identities.

| Measurement | Before | After |
| --- | --- | --- |
| Per-function frame MCP surface | No `function_frame` | Paged native variables and separate tracker evidence |
| Native stack offsets | Raw offsets without address-space widths | Actual native widths and lossless signed-offset interpretation |
| Register preservation | Separate stack accesses only | Entry stores, proven matches or conditional reload candidates |
| Seeded read-only live task | Missing query | **Passed: 1 MCP query / 2 turns** |
| Frame coordinates | Separate underlying APIs | Explicit native-spacebase versus tracker entry-SP origins; no merger |

The first `github-copilot/gpt-6.1-sol` run, variant `default`, passed in **19.577 s** task wall time with
18770 reported input / 207 output / 46 reasoning tokens and no model/tool/transport errors. Seven preparation
calls seed user annotations and baseline evidence; eight verifier calls are separate from the single agent
query. Current native names/types, exact storage, actual address-space widths, five source-known stack offsets,
conditional x19 reload evidence and coordinate separation passed both initial and fresh-server checks.
The fixture bytes and identity-scoped annotation log remained unchanged. No retry/regrading was used.

The owned Clang AArch64 fixture subtracts 48 from SP and stores at entry-SP offsets -48/-40/-32/-24/-16.
Its intervening call prevents original-value proof for the reloads: matching addresses alone do not establish
callee-save preservation. Native spacebase offsets are independently reported even when numerically equal.
The selected native local is not asserted to be an original source variable. Its retained type is the
post-seeding baseline; a parameter retype may legitimately alter local inference during preparation.

Native context comes directly from Ghidra address spaces and configured spacebase registers. AArch64 SSA uses
bounded entry-value provenance and reaching stores, with linear recovered-load mapping rather than repeated
quadratic searches. Header metadata has independent text/count bounds so large warnings/signatures do not
make every page unusable; omissions are explicit. Tracker IR collection skips typed annotation rendering,
and infrastructure errors are not silently downgraded to unsupported tracking.

All seven changed-crate suites, scoped all-target Clippy, frame/worker/MCP tests and six collector regressions
passed, with independent reviews. An installed ARM64 core query returned six native variables, six tracker
slots and six register-evidence rows, preserving its recovery warnings and making no annotation changes.
Limits: recovered inventory and static candidates, not a complete frame-size bound, ABI proof or runtime capture.
Earlier publications, including the failed Phase 1.2 summary contract, remain unchanged.

```sh
cargo run --locked -j 2 -p rampage-eval --example function_frame -- tests/data/function-frame-arm64.snapshot.json
```

## Phase 1.3 — typed data ranges and instruction operands

**Run:** 2026-10-17, committed collector/implementation `24ba0dd`. The
[measurement](benchmarks/phase1-3-2026-10-17.json) binds the source, executable, fixture and original raw report.

| Measurement | Before | After |
| --- | --- | --- |
| Typed range/operand MCP surface | 0/4 required tools | `apply_data_type`, `read_data`, `apply_enum`, `apply_offset` |
| Owned struct-array data | Raw words only | Native paths, signed values and exact enum labels |
| Compare immediate / memory offset | Numeric `7` / `+4` | `TypedMode::MODE_READY` / `TypedRecord.value` |
| Raw instructions and fixture | Original bytes/text | Independently verified unchanged |
| Explicit Unicode and exact scalars | Raw byte inspection | Strict UTF-8/UTF-16; exact integers, NaN/Inf raw bits |
| Live task and fresh-server persistence | Missing tools | **Passed**, exact final annotations and native state |

The first live `github-copilot/gpt-6.1-sol` run (variant `default`) passed in **7 MCP calls / 3 model turns**,
24.223 s task wall time, with 28454 reported input / 709 output / 92 reasoning tokens. There were no model,
tool or transport errors and no retries/regrading. Six preparation calls seeded the supplied type library and
captured baseline evidence; ten independent verifier calls checked native state and a fresh server. These
calls and their timings are recorded separately rather than folded into the agent-call headline.

The task binds two source-known records and an explicit seven-byte UTF-8 string, then annotates native-decoded
enum and struct-offset operands. The grader checks actual fields and negative enum labels, original string
bytes, raw instruction text/bytes, exact identity-scoped logs, unchanged fixture/library and relevant ordered
MCP receipts. A matching model summary alone cannot pass. Out-of-task selectors fail permanently, even if
subsequent calls erase the extra annotation.

Clang-built x64/AArch64 fixtures and the source recipe distinguish explicit operand indices, semantic immediate
widths and memory displacements. Native/worker/MCP tests cover arrays of structs in real decompiled C, ordinary
and exact-entry replay, UTF-16 surrogate pairs, invalid encodings, integers beyond JSON float precision, NaNs,
partial/zero-fill bytes, and shared-client rename conflicts. The first typed-log transition checks the complete
legacy prefix before append; malformed old logs are refused without rewriting them. An installed ARM64 image
revalidation returned stored bytes and explicit zero-fill without creating commercial annotations or assigning
unproved layouts.

All seven changed-crate suites, scoped all-target Clippy, 11 grader regressions and fresh-context reviews passed.
Limits: supported decoder-native instruction operands, bounded data windows, no arbitrary decompiler-token
rewriting, pointer traversal or producer-layout inference. Earlier accepted measurements remain unchanged.

```sh
cargo run --locked -j 2 -p rampage-eval --example typed_data -- tests/data/typed-data-x64.snapshot.json
```

## Phase 1.2 — project type library and native layout inspection

**Run:** 2026-10-17, collector sources committed at `e01d0bd`, with documentation and machine-local files still
dirty/untracked. The [measurement](benchmarks/phase1-2-2026-10-17.json) retains exact source, executable, fixture
and raw-report hashes, numeric execution bounds and complete compact catalog evidence.

| Measurement | Before | After |
| --- | --- | --- |
| Project-library MCP surface | 0/4 required tools | `declare_types`, `list_types`, `get_type`, `delete_type` |
| Owned x64 native layouts | No project inspection surface | 15/15 size/offset facts match compiler data |
| Packing and target widths | Address-bound declarations only | Explicit packing; C/POSIX and 32-/64-bit Windows profiles |
| Callback metadata | No query surface | Declared types/names and calling model, not hidden ABI storage parameters |
| Live MCP workflow | Not runnable through the missing tools | Correct exact retained types, scratch deletion and persistence |
| Strict live final-answer contract | Unmeasured | **Failed**; not counted as task success |

The first live run used `github-copilot/gpt-6.1-sol`, variant `default`: **10 MCP calls, 6 model turns**, 56878
reported input / 935 output / 211 reasoning tokens, 55.442 s task wall time, no model/tool errors. Native checks
and a fresh server verified the exact retained struct, pointer alias and enum, deletion of the independent
scratch declaration, and an unchanged persisted library. The model's final summary failed the strict answer
contract, so `task_verified=false` remains published. No live retry or regrading was used to improve that result.
The two evaluator tool errors are deliberate missing-scratch checks, not transport failures.

Source-built Clang 23.1.3 x64/x86 fixtures provide `sizeof`/`offsetof` tables inspected through MCP without target
execution. They distinguish 32-/64-bit record sizes, nested packing and restored natural alignment. Additional
compiler IR shows hidden return storage and Windows indirect aggregate arguments; native/worker/MCP tests ensure
callback inspection reports the declared C signature instead. New enum construction uses the selected C `int`
width rather than the earlier 8-byte default exposed during implementation.

API, decompiler, worker, MCP, evaluator and UI suites, scoped all-target Clippy, grader regressions and independent
reviews passed. Ordinary oversized comments/long histories remain undoable; blocked legacy undo still displays
other clients' refreshed edits. A real installed ARM64 query found that read-only inspection incorrectly tried
to create a writer lock beside a protected image. A subsequent detached-read fix preserved bounds and returned
the native 4-byte integer layout without creating commercial annotations or lock files; the live measurement
remains bound to its original source revision.

Limits: bounded type-only C/header preparation and explicit minimal ABI profiles, not arbitrary preprocessing,
a full SDK or blind producer-layout recovery. Bitfields and widened/unsigned C enums outside signed target `int`
remain unsupported. Phase 0 and Phase 1.1 evidence stays frozen; Phase 1 acceptance still needs its later milestones.

```sh
cargo run --locked -j 2 -p rampage-eval --example type_library -- tests/data/local-variables-x64.snapshot.json
```

## Phase 1.1 — storage-keyed local and parameter typing

**Run:** 2026-10-17, collector sources committed at `1a75371` (based on `0551311`), with documentation and
machine-local files still dirty/untracked. The
[measurement](benchmarks/phase1-1-2026-10-17.json) records fixture/report hashes and measured example executable
SHA-256 `9700168ede705d14cb7e83f3ae7367710596e1dcf9648f3ca62e4a2a1b5500bf`; this is not a clean-worktree rebuild.
The collector embeds its source hash and hashes its own running executable. The published source hash matches
the committed example; later dependency-feature rebuilds can produce different executables.

| Measurement | Before | After |
| --- | --- | --- |
| MCP local edit surface | No variable edit tool at the source baseline | Types-group `edit_variable` |
| Owned stack-pointer C | Offset/index dereferences, zero named field accesses | `state->gain` and `state->bias` |
| Native storage identity | Whole stack mapping, offset `0xfffffffffffffff0`, 8 bytes | Same canonical storage key |
| Persistence | No local name/type binding | Both bindings verified in the snapshot-identity log |
| Live supplied-layout typing task | Not runnable through the missing tool | Native state verified, 4 MCP calls / 4 model turns |
| Undo/redo/reopen | No local edit path | Native and supervised API/MCP tests pass |

The live model was `github-copilot/gpt-6.1-sol`, variant `default`: 37054 reported input, 451 output and 168
reasoning tokens, 24.232 s task wall time, no model/tool errors. The evaluator independently checked actual
local storage/type/name, refreshed C, MCP annotations and the persisted log; the model's summary alone cannot
pass. This is a paired owned fixture with a user-supplied struct, not blind layout inference or whole-program RE.
The initial collector used the ordinary-file log suffix for a snapshot; it was corrected to use validated capture
identity and the complete task rerun. Another successful probe added self-recorded provenance. The final run
also retains complete compact catalog names before transcript truncation; its snapshots confirm the initially
disabled Types tools and their presence after enabling. That committed-source run is published; the three
earlier probes were not regraded or merged into its totals. The 12-turn/20-call execution bounds are retained.

Owned native tests cover x64/AArch64 register parameters, addressable x64 stack locals, register reuse selectors,
replacement/clearing and refusal without partial renames. Invalid declarations, keywords, stale/ambiguous storage
and oversized refreshed results leave annotations unchanged. Sequential renames can reuse names vacated by the
same replay batch; native swaps, fresh-engine replay and final-name collision refusal have regression coverage.
A real installed ARM64 core revalidation returned
six variable descriptors (three editable, three explicitly unsupported); no commercial annotations were changed.
The Phase 0 publication stays frozen; the current local-rename inventory probe now expects the implemented tool.
Limits: single whole mappings and same-size types; no project type library, cross-call propagation or UI editor.
Changed-crate API, decompiler, worker, MCP, evaluator and UI suites and scoped all-target Clippy passed;
existing opt-in tests remain skipped. This is not full-workspace/release acceptance.

To repeat only this supplied-layout task, using existing OpenCode authentication and the pinned model:

```sh
cargo run --locked -j 2 -p rampage-eval --example local_typing -- tests/data/local-variables-x64.snapshot.json
```

The runner admits only the checked owned snapshot, copies it into an isolated directory, allows `set_types`
and `edit_variable` there, verifies real state, emits bounded JSON and removes its copy/context/log on exit.
Default parity-agent runs remain read-only. This example is not added to the frozen Phase 0 task totals.

## Parity scorecard — accepted Phase 0 baseline

**Run:** 2026-10-17 07:44:31 UTC. **Collector commit:** `65a7e99`. The
[machine-readable publication](benchmarks/phase0-2026-10-17.json) binds the private full report and evaluator
SHA-256 `7248d6e31c3394fb44ffcafc1181a67114822637247ce82c793866ee99deacc4`. The report retains
`worktree_dirty=true`: collector sources were committed; documentation and local untracked files were present.

| Metric | Baseline |
| --- | --- |
| Required corpus | 12 verified compiler/target profiles plus pinned Lua; 13 scored artifacts, 29 metric slices |
| Function starts vs retained symbol/DWARF truth | 5346 matched, 0 missed, 234 extra candidates |
| Lua CFG agreement vs Ghidra 12.1.4 | 890 common functions; raw edge precision 0.9834, recall 0.9849 |
| Lua chain-normalized CFG | 17183 shared edges; precision 0.9974, recall 1.0 |
| Lua call graph / call-site pairs | 2890 / 4373 shared; one Rampage-only item in each metric |
| Matched-twin library naming, Lua plus linked runtime | 849/892 names, 0 wrong/spurious; recall 0.9518 |
| Argument counts across five compiler builds | 180 correct, 15 wrong out of 195 functions |
| Eligible void/value-return agreement | 164 correct, 6 missed; precision 1.0, recall 0.9647 |
| Parameter type classes | 224 correct, 108 wrong, 13 missed, 13 extra; precision/recall 0.6493 |
| Decompiler health | 247/247 exact-entry C returns across 13 targets; 14 warning-bearing, 0 API errors |
| Decompiler timing | 9.45 s summed call timings; individual measurements retained in JSON |
| Fixed-model analysis contracts | 17/17 matched on the canonical owned task set |
| Three capability probes, reported separately | 1 match, 1 unknown, 1 control-format failure |
| Actual MCP/model activity | 38 MCP tool calls, 49 model turns; 0 tool errors or model-transport errors |
| Reported provider usage | 286183 input, 4347 output, 1555 reasoning tokens; cache read/write both 0 |
| Task / end-to-end wall time | 208.045 s / 224.913 s |
| Ghidra MCP task comparison | Unavailable in configured project; Rampage-only task baseline |
| Phase 0 evidence completeness | 22/22 checks met; `phase0_complete=true` |

The fixed model was `github-copilot/gpt-6.1-sol`, variant `default`, through the explicitly labeled OpenCode
JSON-intent adapter. Host tools were disabled; actual analysis used MCP against copied fixtures. Contract
matches are not claims of general reverse-engineering parity. The unknown capability probe reflects limited
visibility of write-tool definitions; the other failed probe mixed answer and unsupported-control fields.

The corpus includes genuine GCC 16.2.0 `-O0/-O2` freestanding x64 ELF, Clang x64 ELF, AArch64 ELF/Mach-O,
x64 PE, Thumb ELF, MIPS32 BE ELF, C++ virtuals/exceptions, Go, Rust and Lua. C++/Rust debug-file UUIDs and
retained code ranges match their twins. Extra candidates are relative to partial metadata truth, not confirmed
false functions. Go runtime metadata remains present; matched-twin naming is not cross-build recognition.
Health sampling is address-sorted, not random, and timings mix initialization and cache states.

An initial collection exposed a SIGCHLD interaction in the CLI wait helper. The committed collector removes
that handler dependency and passes a CLI-wait-to-MCP-decompile regression. This table uses the full rerun with
unchanged task definitions and fixtures, not selective retries or regrading. Totals exclude setup probes.
No analyzed target was executed. The raw-firmware acceptance window also revalidated through MCP: 218 bytes,
84 instruction rows, no unconsumed bytes; its mapping remains an analyst assertion, with no new memory-map claim.

## Raw-window workflow acceptance (2026-10-16)

| Workload | Before | Reviewed raw-window slice |
| --- | --- | --- |
| Local raw-firmware code range, no bundled input | Native-header refusal | One MCP query: 218 bytes, 84 rows, no unconsumed bytes |
| Owned Thumb assembly and literal pool | No raw-file MCP route | Compiled source fixture: three instructions, exact literal and source offsets checked |

The firmware query corroborated decoder parameters through static instructions. Its base/mode remain analyst
assertions; row counts are not instruction-accuracy or execution measurements. No commercial bytes, addresses
or payloads are included here. Broader parity metrics belong to the Phase 0 scorecard, not this acceptance check.

## Parity scorecard pilot (2026-10-17)

Local working-tree baseline based on `6fcdae2`; generated artifacts and the evaluator digest/dirty state are
recorded in `target/parity/phase0-20261017-matrix/scorecard.json`, not bundled binaries. These are pilot measurements,
not completed Phase 0 acceptance or a comparison with an IDA/Ghidra agent.

| Metric | Pilot result |
| --- | --- |
| AArch64 ELF `-O2` function starts | 39 correct, 0 missed, 0 spurious |
| Thumb ELF `-O2` function starts | 4 correct, 0 missed, 0 spurious |
| MIPS32 big-endian ELF `-O2` function starts | 4 correct, 0 missed, 0 spurious |
| AArch64 parameter counts | 38 correct, 1 wrong; precision/recall 0.9744 |
| AArch64 parameter type classes | 42 correct, 26 wrong, 1 missed; precision 0.6176, recall 0.6087 |
| AArch64 eligible void/value returns | 34 correct; precision/recall 1.0 on that eligible set |
| Agent task definitions | 17 analysis questions and 3 capability probes; all 10 fixture digests matched |
| Fixed-model MCP tasks and usage | Not run; no success, call or token numbers inferred |
| Type-selected AArch64 decompiler health | 39 exact-entry returns, 0 API errors or diagnostic warnings |
| Owned Thumb graph reference | Ghidra 12.1.4: 4 common functions, 12 shared raw CFG edges (13/14 totals) |
| Thumb chain-normalized CFG / calls | 13/13 edges and 3/3 source-instruction call pairs match |

The initial `--suite parity` command failed with unsupported `--suite`; the pilot now emits combined JSON.
Selected failed runs retain evidence: local clang lacked the requested linker; a bad Zig Thumb CPU spelling
was corrected; the original strip path rejected MIPS section type `0x7000002a`, now handled with mapped-byte
refusal checks. The nine-profile matrix records three available, three unavailable and three failed selections;
missing GCC/strip/linker support and a PE linker argument remain visible rather than counting as coverage.
Cross-program library ID, broad graph/health coverage and model comparisons remain unmeasured in this pilot.
The health sample's 39 calls totalled about 275 ms on one local run; initialization/cache state is not controlled,
so this is not a warm/cold or per-function performance baseline. Per-entry timings remain in the local report.

### Broader source-built baseline

Working-tree measurements based on `950bac2`; receipts retain executable/source hashes and actual tool versions.
The Lua 5.4.8 MIT archive is pinned to the upstream published checksum; no downloaded sources or binaries are
committed. Full reports are local `target/parity/lua-20261017-01`, `coverage-20261017-02` and
`coverage-languages-20261017-03` outputs. No target programs were executed.
The expanded combined receipt is `target/parity/expanded-20261017/scorecard.json`: 19 metric slices across
the verified profiles and Lua, with both manifest digests and the Lua graph binding retained.

| Workload / metric | Measured result |
| --- | --- |
| System-Clang x64 ELF function starts | 39 correct, no misses or extra starts |
| System-Clang x64 parameter counts / classes | 36 correct, 3 wrong / 43 correct, 23 wrong, 3 missed |
| Zig/embedded-Clang x64 ELF | Same counts on this fixture; a separate profile, not GCC coverage |
| Owned Go x64 ELF function starts | 1815 correct, no misses, 1 extra; runtime metadata retained |
| Owned compressed Go arm64 Mach-O starts | 1898 DWARF starts found, no misses, 44 extra candidates |
| Owned x64 PE starts | 4 DWARF starts found, no misses or extra candidates |
| Lua AArch64 ELF function starts | 892 correct, no misses, 6 extra; precision 0.9933 |
| Lua matched-twin naming, including static runtime | 849 correct, 43 missed, no wrong/spurious names; recall 0.9518 |
| Lua/Ghidra 12.1.4 function coverage | 890 common, 8 Rampage-only, none Ghidra-only |
| Lua raw CFG edges | 16947 shared; totals 17233 / 17207 (Rampage / Ghidra) |
| Lua chain-normalized CFG edges | 17183 shared; totals 17228 / 17183 |
| Lua call-site pairs / call-graph edges | 4373 / 2890 shared; one Rampage-only item in each metric |

Matched-twin naming is best-case same-build evaluation. Graph agreement is limited to common functions and
does not establish correctness. Explicit contiguous DWARF truth now checks all retained ranges in both PE
and compressed Go Mach-O twins; unsupported range-list functions and unavailable names remain omitted.
The 14-profile matrix has 8 scored, 5 unavailable and 1 failed profile. Native C++/exceptions, Rust and the
basic Mach-O build still lack supported truth; Linux C++ lacks a local target runtime; genuine GCC is absent.
Extra candidates are relative to the retained truth, not independently confirmed false function starts.

## Function discovery vs Ghidra

`tools/benchmark.sh` runs Ghidra headless to list function starts, builds a reference in rampage's format
(matching the image SHA-256 and architecture), and runs the accepted legacy `rampage compare` route against it.
The canonical route is `rampage function compare`.

```
tools/benchmark.sh target/debug/rampage "$(brew --prefix ghidra)/libexec" \
  tests/fixtures/bin/hello-x64.elf x86_64  tests/fixtures/bin/hello-arm64.elf aarch64
```

`recall` is matched/reference starts; `precision` is matched/rampage starts. Extra starts are now counted against
precision, including thunks excluded from the reference. Empty denominators are reported as `null`/`N/A`, not
zero. The reference records the installed Ghidra version. These policies must match before comparisons across
versions or corpora are interpreted.

### Earlier function-start measurements (Ghidra 12.1.4, fixtures in `tests/fixtures/bin`)

This table originated in `a74b679` (2026-10-11); the ARM/Thumb counts were updated in `b4c5b3f` (2026-10-13).
It is not one synchronized current-build run. Later discovery changes are reflected in the separately recorded
CFG/call benchmark below; counts and misses from this earlier table must not be read as current limitations.

| binary            | arch     | ghidra | rampage | matched | recall |
|-------------------|----------|-------:|--------:|--------:|-------:|
| hello-x64.elf     | x86_64   |     41 |      41 |      41 | 100.0% |
| hello-x64-dyn.elf | x86_64   |      6 |       6 |       5 |  83.3% |
| hello-x64.exe     | x86_64   |    497 |     525 |     497 | 100.0% |
| hello-arm64.elf   | aarch64  |      6 |       8 |       5 |  83.3% |
| hello-arm.elf     | arm      |      4 |       8 |       4 | 100.0% |
| hello-thumb.elf   | arm      |     44 |      43 |      43 |  97.7% |
| hello-mips.elf    | mips     |      3 |       5 |       3 | 100.0% |
| hello-ppc.elf     | powerpc  |     42 |      42 |      42 | 100.0% |
| hello-riscv64.elf | riscv64  |      8 |       8 |       8 | 100.0% |

The larger PE sample matched every Ghidra function in these measurements. The 83–98% cases are small fixtures
where a single miss is a large percentage; startup/stub entries were among the gaps at that stage. The later
CFG table records all six Ghidra starts matched for both hello-x64-dyn.elf and hello-arm64.elf. Discovery
agreement remains separate from the embedded decompiler's integration accuracy.

## Basic blocks, CFG edges and call edges vs Ghidra

`tools/cfg-benchmark.py` compares, on the functions both tools find (same entry address), each function's
basic-block starts, its intra-function successor edges and its call edges. Ghidra is the reference here, not ground
truth: "precision" is the share of rampage's items Ghidra also has, "recall" the share of Ghidra's items rampage
also has, and the analysis below shows disagreements where rampage is right and Ghidra is not.

```
tools/cfg-benchmark.py target/release/rampage "$(brew --prefix ghidra)/libexec" \
  tests/fixtures/bin/hello-x64.elf tests/fixtures/bin/hello-x64.exe --out cfg-report
```

- Ghidra side: headless auto-analysis, then `tools/ghidra_cfg_export.java` writes each non-thunk function's
  `BasicBlockModel` blocks, successors that stay inside the function body, and call references.
- rampage side: `rampage export-cfg FILE` (hidden subcommand) writes the same `function_graph` blocks and edges and
  `rampage function xrefs FILE --from ADDRESS` references the MCP tools return, without the 60k-character
  tool-output bound.
- Normalisation: a rampage jump to another function's entry counts as a call, because Ghidra records tail calls as
  call references. Ghidra `COMPUTED_CALL*` targets (every computed-call reference kind) count only when rampage
  found the same call; the rest are listed in their own column. These targets come from memory reads, and some are
  garbage (see below).
- Totals pool items per function, keyed by (function entry, address), so a block or edge that two functions share
  counts in each of them.
- `block J` is the Jaccard index of all block starts. `chain J` and `chain edge` merge straight-line chains, where a
  block is its predecessor's only successor, on both sides before comparing. This removes Ghidra's extra splits at
  labelled instructions.
- `--out DIR` writes each fixture's full report, named after the fixture plus a digest of its path. It lists, per
  function, blocks, edges and calls found by only one tool. The ten worst functions per fixture also go to stderr.
  `--ghidra-cache DIR` reuses Ghidra exports, keyed by image SHA-256, Ghidra version and a digest of the export
  script. When the export is missing or truncated, the script exits with the end of Ghidra's output and logs.
- `python3 -m unittest tools.test_cfg_benchmark` tests the comparison and caching logic without Ghidra.

### Results

Ghidra 12.1.4 (headless, default analysers, OpenJDK 21.0.12.1); rampage 0.1.0 at `207c45c`; macOS 27.0.1 arm64.
Ghidra's analysis takes 4–23 s per fixture, about 2.5 min for all 18 fixtures, so all of them are covered. A second
run at `af40350` (regenerated signature databases), with Ghidra's exports cached, gave the same numbers. The x86-64
rows (hello-x64.exe, eval-ref-x86_64, musl-static-x86_64, hello-go-x64) were re-measured with x86 switch tables
resolved, from the same cached exports; the other x86-64 rows did not change. The hello-x64.exe, ARM, Thumb, MIPS,
PPC and RISC-V rows were re-measured the same way after the get-PC, import-thunk and undecodable-start fixes.
Adding noreturn analysis changed only the hello-x64.exe and hello-go-x64 rows (re-measured the same way). Every
row below was re-measured at `7c03e5c`, from the same cached exports, after switch resolution started
forgetting facts at joins ahead of the comparison and stopped accepting 16-bit `movsxd` and non-contiguous masks;
no row changed. They were re-measured again at `41e1224`, from the same cached exports, after the noreturn review
fixes (conditional calls and returns, resumable traps, incremental inference, case-sensitive names, more get-PC
idioms); no row changed. Re-measured again, from the same cached exports, after the address a load reads stopped
counting as a code pointer: only the hello-arm.elf (10 to 8 rampage functions) and hello-thumb.elf (44 to 43) rows
changed. Inferring noreturn through mutual tail calls then changed no row. Resolving switches whose facts are set up
in an earlier block (measured against `77d6709` from the same cached exports) changed only the hello-x64.exe,
eval-ref-x86_64 and musl-static-x86_64 rows; every other fixture's functions, blocks and switches are identical.
The cross-block update was recorded in `b01f074` (2026-10-13). No new measurements are added here for later
working-tree changes, including inverse/scheduled AArch64 guards or nonconstant native SSA spill recovery.

Function and block agreement:

| binary | funcs G/R/both | same blocks | block J | chain J |
|---|---|--:|--:|--:|
| hello-x64.elf | 41/41/41 | 41/41 | 100.0% | 100.0% |
| hello-x64-dyn.elf | 6/7/6 | 6/6 | 100.0% | 100.0% |
| hello-x64.exe | 497/537/497 | 463/497 | 99.4% | 100.0% |
| hello-x64.macho | 2/3/2 | 2/2 | 100.0% | 100.0% |
| hello-arm64.elf | 6/9/6 | 6/6 | 100.0% | 100.0% |
| hello-arm64.macho | 2/3/2 | 2/2 | 100.0% | 100.0% |
| hello-arm.elf | 4/8/4 | 4/4 | 100.0% | 100.0% |
| hello-thumb.elf | 44/43/43 | 36/43 | 96.3% | 97.9% |
| hello-mips.elf | 3/3/3 | 2/3 | 80.0% | 100.0% |
| hello-mipsel.elf | 3/3/3 | 2/3 | 80.0% | 100.0% |
| hello-ppc.elf | 42/42/42 | 42/42 | 100.0% | 100.0% |
| hello-ppc64le.elf | 7/7/4 | 4/4 | 100.0% | 100.0% |
| hello-riscv64.elf | 8/9/8 | 5/8 | 57.9% | 100.0% |
| eval-ref-x86_64.elf | 176/176/176 | 172/176 | 99.9% | 100.0% |
| eval-ref-aarch64.elf | 194/195/194 | 189/194 | 99.8% | 100.0% |
| musl-static-x86_64.elf | 67/67/67 | 67/67 | 100.0% | 100.0% |
| musl-static-aarch64.elf | 82/83/82 | 79/82 | 99.7% | 100.0% |
| hello-go-x64.elf | 1358/1806/1357 | 1321/1357 | 98.6% | 98.8% |

CFG edge agreement:

| binary | edge P / R | chain edge P / R |
|---|--:|--:|
| hello-x64.elf | 100.0% / 100.0% | 100.0% / 100.0% |
| hello-x64-dyn.elf | 100.0% / 100.0% | 100.0% / 100.0% |
| hello-x64.exe | 97.9% / 97.5% | 100.0% / 100.0% |
| hello-x64.macho | N/A / N/A | N/A / N/A |
| hello-arm64.elf | 100.0% / 100.0% | 100.0% / 100.0% |
| hello-arm64.macho | N/A / N/A | N/A / N/A |
| hello-arm.elf | N/A / N/A | N/A / N/A |
| hello-thumb.elf | 95.9% / 94.9% | 97.8% / 99.6% |
| hello-mips.elf | 50.0% / 33.3% | 100.0% / 100.0% |
| hello-mipsel.elf | 50.0% / 33.3% | 100.0% / 100.0% |
| hello-ppc.elf | 100.0% / 100.0% | 100.0% / 100.0% |
| hello-ppc64le.elf | N/A / N/A | N/A / N/A |
| hello-riscv64.elf | 0.0% / 0.0% | 100.0% / 100.0% |
| eval-ref-x86_64.elf | 99.0% / 99.0% | 100.0% / 100.0% |
| eval-ref-aarch64.elf | 98.5% / 98.4% | 100.0% / 100.0% |
| musl-static-x86_64.elf | 100.0% / 100.0% | 100.0% / 100.0% |
| musl-static-aarch64.elf | 98.1% / 97.9% | 100.0% / 100.0% |
| hello-go-x64.elf | 99.3% / 96.9% | 100.0% / 97.7% |

Call agreement:

| binary | call P / R | callgraph P / R | G-only computed calls |
|---|--:|--:|--:|
| hello-x64.elf | 100.0% / 100.0% | 100.0% / 100.0% | 0 |
| hello-x64-dyn.elf | 100.0% / 100.0% | 100.0% / 100.0% | 1 |
| hello-x64.exe | 100.0% / 100.0% | 100.0% / 100.0% | 1 |
| hello-x64.macho | 100.0% / 100.0% | 100.0% / 100.0% | 0 |
| hello-arm64.elf | 100.0% / 100.0% | 100.0% / 100.0% | 1 |
| hello-arm64.macho | 100.0% / 100.0% | 100.0% / 100.0% | 0 |
| hello-arm.elf | 100.0% / 100.0% | 100.0% / 100.0% | 0 |
| hello-thumb.elf | 100.0% / 100.0% | 100.0% / 100.0% | 2 |
| hello-mips.elf | N/A / N/A | N/A / N/A | 2 |
| hello-mipsel.elf | N/A / N/A | N/A / N/A | 2 |
| hello-ppc.elf | 100.0% / 100.0% | 100.0% / 100.0% | 3 |
| hello-ppc64le.elf | N/A / N/A | N/A / N/A | 0 |
| hello-riscv64.elf | 100.0% / 100.0% | 100.0% / 100.0% | 3 |
| eval-ref-x86_64.elf | 100.0% / 100.0% | 100.0% / 100.0% | 1 |
| eval-ref-aarch64.elf | 99.8% / 100.0% | 99.7% / 100.0% | 2 |
| musl-static-x86_64.elf | 100.0% / 100.0% | 100.0% / 100.0% | 0 |
| musl-static-aarch64.elf | 99.5% / 100.0% | 99.1% / 100.0% | 1 |
| hello-go-x64.elf | 99.7% / 97.9% | 99.5% / 98.5% | 57 |

`N/A` means an empty denominator: the shared functions are single-block, or have no calls. The MIPS, RISC-V and
small Mach-O/ARM fixtures share only 2–8 functions, so their percentages move a lot with a single decision.

### Main disagreement classes

These come from inspecting the per-function reports (`--out`) and the disassembly at the listed addresses.

- **x86-64 jump tables (resolved in the measured cases).** The index needs an unsigned bound,
  from a `cmp` directly followed by `ja`/`jae` or from an
  `and r, mask`, covering the whole register (a 32-bit write or `mov e, e` zero-extends it). No branch may join
  the straight-line run that proves the bound, the zero extension and the table base, and the table must be
  read-only data. This covers absolute
  `jmp [rax*8+0x1001a68]` (eval-ref-x86_64 `0x100e148`) and relative
  `lea rcx,[table]; movsxd rax,[rcx+rax*4]; add rax,rcx; jmp rax` (hello-x64.exe `0x1400170f4`, bounded by
  `and eax, 3`). Ghidra-only blocks fell from 239 to 44 in hello-x64.exe, 328 to 8 in eval-ref-x86_64, 82 to 4 in
  musl-static-x86_64 and 1245 to 330 in Go. Most of what remains is the jump itself: as on AArch64, Ghidra starts a
  block at its `switchD` label, which also accounts for the lower raw edge precision.

  Switches whose facts are set up in an earlier block are resolved by carrying the decoder's register facts across
  the function's blocks: a must-dataflow whose facts at a block's start are only those that hold at the end of every
  edge into it, with nothing known at the entry or where a branch from another function lands. It also tracks
  register copies, so `printf_core`'s bound on `r12d` holds for `r13`, the copy it jumps through
  (eval-ref-x86_64 `0x1008e60`, musl-static-x86_64 `0x1003d75`), and keeps the registers every x86 calling convention
  preserves across calls, so hello-x64.exe `0x140001aca` finds the table base loaded into `r15` before its loop. A
  bound holds only on the fall-through of the `ja` that proved it, and two paths keep a bound only from the same
  comparison. A table found this way adds case edges that may join the paths it was proven on, so discovery explores
  the function again assuming it and drops it for good unless the larger graph still proves the same table. That
  took Ghidra-only blocks from 44 to 34 in hello-x64.exe, 8 to 4 in eval-ref-x86_64 and 4 to 0 in
  musl-static-x86_64; chain Jaccard and chain edges now agree completely on all three, and no other fixture changed.
  hello-x64.exe discovery takes about 24 ms instead of 18 (the extra exploration), hello-go-x64 57 instead of 53. The
  same dataflow carries AArch64 facts. PIC i386 tables (`call __x86.get_pc_thunk.bx` or `call 1f; 1: pop ebx`,
  `add ebx, GOT`, `mov eax, [ebx + eax*4 + off]; add eax, ebx; jmp eax`) are recognized too, but no benchmark
  fixture exercises them; compiled acceptance remains separate work.
- **AArch64 jump tables (resolved in the measured cases).** The recorded fixtures use an unsigned bound from
  `cmp` followed by `b.hi`/`b.hs` and read-only table data. The straight-line recognizer forgets facts at joins;
  cross-block recovery retains only facts agreed on by every incoming path and revalidates added case edges.
  That covers the compact
  `adr; ldrb/ldrh; add x, x, w, lsl #2; br` tables (musl-static-aarch64 `0x10149dc`, eval-ref-aarch64 `0x10184a0`)
  and `ldrsw` with an unrelated `movk` scheduled in between (eval-ref-aarch64 `0x102386c`). Each case gets a
  `switch` edge from the dispatch block. The remaining Ghidra-only blocks (3 in musl-static-aarch64, 6 in
  eval-ref-aarch64) are all the `br` itself: Ghidra starts a block at its `switchD` label, so its case edges leave
  from there, while rampage's leave from the block that ends in the `br`. Chain Jaccard and chain edges, which
  merge that split, agree completely.
- **Noreturn calls (terminal in rampage; Ghidra retains some fall-throughs).** rampage ends a block at a call that never
  returns: one in its curated list (`exit`, `abort`, `__stack_chk_fail`, `_CxxThrowException`, Rust
  `core::panicking::*`, Go `runtime.throw`/`runtime.gopanic`/`runtime.panic*`, ...), called directly, through a
  PLT/IAT stub or through an import slot, or one inferred because every path through it ends in such a call or a
  trap. Before, rampage fell through after every call. Go's rampage-only edges drop from 1536 to 206 (edge
  precision 95.3% to 99.3%), and hello-x64.exe loses its 7 fall-throughs after `exit`, `abort` and the MinGW error
  reporter `0x140001d20` (`0x1400013f7`, `0x1400013fc`, `0x140001cdd`). Go edge recall falls from 98.0% to 96.9%:
  330 edges Ghidra keeps after calls that never return, such as `runtime.gopanic`, `runtime.panicshift`,
  `runtime.panicunsafeslicelen` and the dead code after `runtime.fatalthrow` in `runtime.fatal` (`0x444054`).
  Ghidra lists most of these callees as non-returning itself but does not end every such block. Go's
  `runtime.mcall` and `runtime.morestack*` end every path in a trap or a noreturn call yet resume their caller
  through a saved context, so they are never inferred noreturn. A conditional call (`blne abort`, Thumb `it ne;
  bl`) never ends its block, and a conditional return or register jump (`bxeq lr`, `popne {r7, pc}`, PowerPC
  `beqlr`) counts as a way out, so neither makes its function look noreturn. Only traps that cannot resume (`ud2`,
  `udf`, AArch64 `brk #1`/`#0x3e8`, RISC-V `unimp`, SPARC `illtrap`, PowerPC `trap`) count as evidence; debugger
  and semihosting traps (`bkpt`, `hlt`, other `brk`s, MIPS `break`, RISC-V `ebreak`) fall through. Inference
  re-explores only the callers of newly inferred functions, so hello-go-arm64 discovery takes 48 ms instead of
  150 ms (hello-go-x64: 41 instead of 70 ms) with the same CFGs. `function_graph` and `export-cfg` mark each such
  call `listed` or `inferred`. Functions that only tail-call each other are inferred together, by a greatest
  fixpoint over the tail-call graph, when some path among them ends in such a call or trap; a tail-call cycle with
  no such path is an infinite loop, which Ghidra calls non-returning but rampage leaves unknown for lack of
  evidence.
- **Get-PC idioms (resolved).** A call whose target is the instruction after it (after the delay slot on MIPS and
  SPARC) reads the PC only when the code there takes the return address: `bal 1f; nop; 1: ... addu $gp, $gp, $ra`
  (hello-mips/mipsel `__start`), `bl 1f; 1: mflr r30`, `bl 1f; 1: mov r0, lr` (ARM, Thumb, AArch64),
  `call 1f; 1: pop ebx` or `mov ebx, [esp]`, a MIPS delay slot or `$ra`-based load. rampage treats those as plain flow
  and every other call to the next instruction as a call, so `bl _Exit` (hello-thumb `0x20800`) and `bl _start_c`
  (hello-ppc `0x2078c`) keep their call edges. Ghidra instead treats MIPS `bal 1f` as a branch and starts a block
  at `0x203fc`. That is the remaining MIPS block and edge difference; chain Jaccard and chain edges agree.
- **Literal pools (resolved).** Every decoder says whether an instruction loads from or stores to its data
  reference or only forms it (`lea`, `adr`, ADRP plus ADD, the MIPS, RISC-V, PowerPC and SPARC address pairs,
  s390x `larl`). Memory read or written is a data reference and never a code pointer, even in a literal pool
  inside code; a formed address into code may be one, as may the word an ARM or AArch64 PC-relative literal load
  reads from read-only memory (`ldr r0, =func`). An address a function forms and also loads from is data, as
  `_start`'s `adr r3` to its own pool shows. hello-arm.elf `sub_20338` and `sub_2033c` (`_start`'s literals, which
  happen to decode) are no longer functions, nor is one rampage-only start in hello-thumb.elf.
- **Tail jumps to import thunks (resolved).** PE `jmp [slot]` thunks that follow padding or another thunk are
  functions, so `jmp 0x140028d50` (`fflush`) at hello-x64.exe `0x140001447` is a tail call rather than a block of
  its only caller. ELF PLT and Mach-O stubs were already functions. Unreferenced thunks are now listed too, which
  is why rampage's hello-x64.exe function count rose; Ghidra's export leaves thunks out.
- **Ghidra's label splits (not a CFG difference).** `BasicBlockModel` starts a block at every labelled
  instruction. On RISC-V the `.Lpcrel_hi*` local symbols split straight-line code, so raw block Jaccard is 57.9% and
  chain Jaccard is 100%.
- **Ghidra-side disagreements where rampage is right.**
  - Go ABI0 wrappers (`runtime.schedinit` at `0x480660` jumps to `0x448860`): Ghidra has no function at the
    pclntab-listed target, so it folds the whole target body into the wrapper. These 19 functions account for
    311 Ghidra-only blocks.
  - musl-static-aarch64 `0x1012690`: `adr x3, 0x1012694; ...; br x3` is a tail call that rampage resolves and
    Ghidra does not.
  - Ghidra `COMPUTED_CALL` targets read through unrelocated memory, for example `0x10102464c457f`, which is the ELF
    header bytes, on hello-arm64 and eval-ref-aarch64.
  - On Thumb, Ghidra leaves the reachable `udf` trap block out after `bgt` (hello-thumb `0x204fa`, `0x207aa`);
    rampage keeps it.

### Analysis follow-ups found by this benchmark

The working implementation now accepts inverse AArch64 `b.ls`/`b.lo` bounds on the taken edge and scheduled
immediate comparisons across audited NZCV/index-preserving instructions and agreeing joins. Native SSA locates
the actual flag-consuming branch to recover the default. These increments have bounded regressions, but the
recorded benchmark fixtures do not exercise them, and no new measurements are claimed here.

Remaining acceptance includes `BC.cond`/other comparison forms, broader compiled scheduling cases and a
compiled PIC i386 table fixture. See [Deep ARM64 analysis](arm64-development.md) for the proof boundaries.

## Decompilation

rampage uses Ghidra's decompiler engine, but identical engines do not guarantee identical results. Memory mappings,
processor context, compiler specifications, relocation handling, symbols/types and analysis options all affect output.
Differential decompilation must compare equivalent inputs and settings rather than assuming agreement.

Remaining metrics include success/warning coverage, inferred signatures, typed calls, recovered strings and switch
targets, and time/memory use. Function-start recall alone does not establish decompiler accuracy or tool parity.

`tools/decompile-benchmark.sh RAMPAGE GHIDRA IMAGE FUNCTION` runs a bounded single-function reference probe and
reports image identity, engine/compiler selection, normalized text equality and warning lines in emitted C.
It explicitly reports that mappings/types/options are not yet matched; equality is diagnostic rather than a
semantic score. On `hello-x64-dyn.elf`/`main`, Ghidra 12.1.4 produced 77 bytes and rampage produced 79 bytes, both
without emitted warning lines. The differing display names/signatures require matched-setting comparison before
an accuracy conclusion is drawn.

The versioned integration corpus runs with
`python3 tools/decompiler_corpus.py target/debug/rampage --manifest tests/data/decompiler-corpus.json --isolated`.
Its four controlled cases passed 15 selected assertions (x64/ARM64 greeting calls, BE8 instructions and Windows
x64 arguments). That pass is bounded integration coverage, not a general decompilation accuracy percentage.
This is the previously recorded integration result, not a rerun during this documentation review. See the
[corpus runner reference](decompiler-corpus.md) for identity scope, assertion denominators and resource limits.
