# Phase 1 benchmark reports

Part of the [accuracy benchmarks](../benchmarks.md).

## Phase 1.6 — checked PDB and nested DWARF type import

**Run:** 2026-10-18, committed implementation/collector `02e6173`. The
[measurement](phase1-6-2026-10-18.json) preserves the first live attempt. **Live Phase 1 sign-off is
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
[measurement](phase1-5-2026-10-18.json) preserves the first live result, source/executable/fixture
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
[measurement](phase1-4-2026-10-17.json) retains exact source/executable/fixture/report identities.

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
[measurement](phase1-3-2026-10-17.json) binds the source, executable, fixture and original raw report.

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
dirty/untracked. The [measurement](phase1-2-2026-10-17.json) retains exact source, executable, fixture
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
[measurement](phase1-1-2026-10-17.json) records fixture/report hashes and measured example executable
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

The run above used the since-retired OpenCode adapter. The example now uses the in-process Anthropic transport
(`ANTHROPIC_API_KEY`) with its pinned model, so a repeat is a new measurement, not comparable with the one above:

```sh
cargo run --locked -j 2 -p rampage-eval --example local_typing -- tests/data/local-variables-x64.snapshot.json
```

The runner admits only the checked owned snapshot, copies it into an isolated directory, allows `set_types`
and `edit_variable` there, verifies real state, emits bounded JSON and removes its copy/context/log on exit.
Default parity-agent runs remain read-only. This example is not added to the frozen Phase 0 task totals.
