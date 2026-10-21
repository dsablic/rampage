# IDA/Ghidra parity roadmap (execution plan)

**Date:** 2026-10-16. **Status:** active plan. Supersedes the "IDA/Ghidra gap-closing" sections of `todo.md` as
the ordering authority for parity work; `todo.md` remains the place to track individual checkboxes.

## Goal

rampage is an AI-first reverse engineering tool. Agents are the primary users and **MCP is the product
surface**. "Parity with IDA/Ghidra" therefore means:

> An AI agent connected only to rampage's MCP server can complete the reverse engineering tasks an analyst
> would do in IDA Pro or Ghidra, on the same binaries, with comparable or better accuracy, in fewer tool calls
> and tokens than an agent driving Ghidra/IDA through their MCP bridges.

Consequences for every milestone below:

- A capability is not done until it is an MCP tool (or an option of an existing tool) with a schema, bounded
  output, pagination where output can be large, and an MCP integration test in `crates/rampage-mcp/tests`.
- The Rust library API is an internal implementation layer for MCP, CLI and UI. Do not design public library
  APIs, language bindings or a scripting runtime for their own sake. No Python/IDAPython-style API is planned.
- The CLI follows MCP where it is cheap (it shares the tool registry). The desktop UI is a secondary client:
  it gets features after MCP, and only in Phase 7.
- Tool outputs are read by models: prefer compact, addressed, evidence-linked results over exhaustive dumps;
  every result must say what was omitted and which call fetches more.

## Where we are (assessment, 2026-10-16)

Roughly 25-35% of the way to an IDA/Ghidra replacement, but already ahead on agent ergonomics.

Strong: ELF/PE/Mach-O loading; x86/x64 (iced) and native spec-generated AArch64/A32/Thumb; Capstone for
MIPS/PPC/RISC-V/SPARC/s390x/m68k; embedded Ghidra decompiler (C output roughly equal to Ghidra for embedded
processors); discovery/CFG/xrefs/import naming; Go pclntab; RTTI class names; triage/YARA/capa/constants;
guided MCP workflows.

Main gaps, by impact on an agent's ability to finish real tasks:

1. **Interactive typing loop.** Annotations (`crates/rampage-api/src/annotations.rs`, `Field`) cover only
   `Name`, `Comment`, `Signature`, `Types`, `Global`. There are no local-variable renames/retypes, no stack
   frame variables, no struct applied to data or to a pointer-typed variable, no enum application to operands,
   and no type propagation across calls. The decompiler shim (`crates/rampage-decompiler/src/shim.cc`) has no
   local-symbol override path. This is the core IDA/Ghidra workflow and the largest gap.
2. **Library recognition at scale.** Mechanism exists; bundled databases are only musl x64/arm64.
3. **Search and patching.** No byte/immediate/instruction-pattern search tool, no byte patching or patched
   file export.
4. **Processor breadth.** About 12 families. Only 8 Ghidra processor spec directories are embedded
   (`crates/rampage-decompiler/specs/Ghidra/Processors`). Sleigh is used only for decompilation.
5. **Formats.** No raw/firmware loader, object files/static archives, Intel HEX/SREC, core dumps; no DEX/JVM.
6. **Analysis depth.** C++ layouts, ObjC/Swift metadata, exception tables, auto data typing, cross-function
   type inference are partial or missing.
7. **Debugger.** Read-only stopped-session LLDB only; no execution control.
8. **Scale.** No validation on large (50-200 MB) binaries; full-workspace gate currently times out.
9. **Desktop UI** lacks type/struct editors and in-pseudocode editing.

## Execution rules (apply to every phase)

1. **One active milestone at a time.** Finish, review and commit a milestone before starting the next. The
   only allowed parallelism is independent slices *inside* the current milestone, run as a wave, each wave
   followed by a fresh-context review whose findings are fixed before commit.
2. **Measure first.** Every milestone starts by adding or extending a scorecard measurement (Phase 0) that
   fails or is low, and ends with that measurement improved and recorded in `docs/benchmarks.md`. No
   measurement, no "done".
3. **Scope guard against hardening drift.** Recent work went heavily into supervision, cleanup proofs,
   admission gating and quarantine. That infrastructure is sufficient for now. Do not add new supervision,
   sandboxing, admission, plugin-runtime or cleanup-proof machinery unless a parity milestone is concretely
   blocked by a reproducible crash or hang on an input in its corpus. Keep the existing bounds; do not
   extend them speculatively.
4. **Documentation stays proportional.** Each milestone updates `docs/features.md`, `docs/mcp.md` and the
   relevant reference doc with what the tool does and its main limits, in a few sentences. Do not write
   long caveat paragraphs; one "Limits" line per feature is enough.
5. **Tests.** TDD for each slice: an owned fixture (built from source in `tests/fixtures/src`, via `zig cc`
   or `clang`) that fails before and passes after, plus an MCP-level test. Run changed-crate tests and the
   MCP test suite before commit; record any timeout honestly rather than claiming a full-workspace pass.
6. **Licensing.** Only permissively licensed inputs (Apache/MIT/BSD/zlib/PD) in the repo. Signature DBs are
   generated from open-source libraries we build ourselves. Do not ship IDA `.sig`/`.til` files or anything
   extracted from commercial binaries. Commercial binaries may be used locally for evaluation only and never
   committed.
7. **Commits.** One commit per reviewed slice, imperative subject. No release tags and no CI dispatch.
8. **Relationship to the audio-plugin investigation in `todo.md`.** Close its "Current baseline" batch first
   (it is mid-flight). After that, this roadmap is the active priority, and the audio-plugin and
   unknown-firmware investigations become *acceptance workloads*: at the end of each phase, re-run one real
   investigation through MCP and note which blockers the phase removed. (The user should confirm this ordering;
   if they prefer to finish Batches 2-3 first, start Phase 0 after Batch 3.)

---

## Phase 0: parity scorecard (do first, ~1 milestone)

Without a scorecard, "parity" is opinion. Build it on the existing `rampage-eval` crate and
`tools/benchmark.sh`.

**0.1 Reference corpus.** `tests/fixtures/corpus/` manifest (sources + build script, binaries generated, not
committed if large). At minimum: x86-64 ELF (gcc -O0/-O2, clang -O2), AArch64 ELF and Mach-O, PE x64 (via
`zig cc -target x86_64-windows-gnu`), ARM Thumb ELF, MIPS32 BE ELF, and one each stripped/unstripped. Programs:
existing fixtures plus a few realistic open-source programs (e.g. sqlite3 shell, zlib minigzip, lua
interpreter, a small C++ program with classes/virtuals/exceptions, a Go and a Rust binary).

**0.2 Static accuracy metrics** (symbols/DWARF of the unstripped twin are truth; Ghidra headless is a second
reference, not truth): function-start precision/recall, CFG edge agreement, call-graph agreement, library
function naming recall on stripped twins, signature (arg count/return) agreement, and decompiler
health (functions decompiled without error, time per function, warnings). `rampage-eval` already has
discovery, library-ID, tool-ID and type-recovery slices; extend rather than re-create.

**0.3 Agent task suite (the headline metric).** A set of ~20 task files (`crates/rampage-eval/tasks/*.toml`)
each with a binary, a question and a machine-checkable answer, e.g.:
"what XOR key decodes the string at 0x...", "which function parses the config file and what is the struct
layout", "list the commands the network handler accepts", "what does function X return when the license check
fails", "which library version is statically linked", "rename and retype the main state struct and show the
cleaned-up decompilation of its init function". Runner: an MCP client loop (reuse `rampage-agent`) driving
the rampage MCP server with a fixed model, recording success, tool calls, input/output tokens and wall time.
If a Ghidra MCP bridge (e.g. GhidraMCP) is available locally, run the same tasks against it for comparison;
otherwise record rampage-only numbers.

**0.4 Scorecard doc.** A table in `docs/benchmarks.md` ("Parity scorecard") with one row per metric and the
date/commit of the last run. Every later milestone updates its rows.

**Acceptance:** `rampage-eval run --suite parity` produces the static metrics and agent-task results in one
JSON report; the scorecard table is filled with the baseline.

**Prerequisite:** a local Ghidra (`brew install --cask ghidra`) for reference numbers; zig is already present.

---

## Phase 1: the interactive typing loop (largest gap, ~4-5 milestones)

This is what turns "readable C" into "understood program", and what agents will spend most of their calls on.
Every edit is an annotation-log entry with the existing undo/redo and replay semantics, and every edit is
visible on the next `decompile` call.

**1.1 Local variables and parameters.** New annotation fields (extend `Field` in `annotations.rs`):
`LocalName` and `LocalType`, keyed by function address + storage identity (register / stack offset / the
storage mapping the decompiler already reports in results) rather than by the decompiler's generated name, so
they survive re-decompilation. Shim: before `decompile`, install name/type overrides into the function's local
scope (Ghidra `ScopeLocal` symbol entries with type locks; see how `renameSymbol`/`addSymbol` are used around
`shim.cc:566` and `:673`). MCP: `rename_variable`, `set_variable_type` (or one `edit_variable` tool), both
accepting the decompiler's displayed name *or* storage, returning the new decompilation snippet so the agent
does not need a second call. Fixture: function whose local struct pointer is retyped and fields render as
`p->field`.

**1.2 Type library.** Promote the per-address `Types` field into a project-level type library: named
struct/union/enum/typedef/function-pointer declarations with sizes, packing and field offsets, stored in the
annotation log. MCP: `declare_types` (C declarations, bounded parser already exists in the decompile `types`
module), `list_types`, `get_type` (layout with offsets), `delete_type`. Include C header import for common
platform headers (bundled minimal libc/POSIX/Win32 core type sets, generated from permissively licensed
headers such as musl and mingw-w64) so `FILE *`, `struct sockaddr`, `HANDLE` etc. exist out of the box.

**1.3 Apply types to data and operands.** `set_global` already types a data address; extend it to arrays of
structs, and add: operand enum/offset display (`apply_enum` on an instruction operand or a decompiler
constant token), struct-offset operands in disassembly, and string/array typing of data ranges. Disassembly and
`read_data` views render typed data as fields.

**1.4 Stack frames.** Per-function frame view from the decompiler's storage map plus the analysis stack
tracker: locals, saved registers, arguments, with names/types from 1.1. MCP: `function_frame`.

**1.5 Type propagation.** When a signature or variable type is set, propagate along calls: callee parameter
types flow into caller argument variables and vice versa; return types flow to call-site results; global
types flow to all xrefs. Implement as "derive candidate types and apply as low-priority (non-locked)
annotations" so analyst/agent edits always win. Include automatic import-signature typing from the bundled
header sets (every `memcpy`, `recv`, `CreateFileW` call gets correct prototypes without user action).

**1.6 PDB and DWARF type import.** Extend the checked PDB path (names only today) to TPI types: structs,
enums, function prototypes, applied as type-library entries plus function signatures. Widen the checked DWARF
layout import beyond flat x86-64 structs to nested aggregates, arrays, bitfields (best effort), and AArch64.
Fixture: build a PE+PDB with `zig cc -target x86_64-windows-msvc` if it emits PDB, else use clang-cl/lld-link
when available; otherwise generate a minimal PDB in a test helper.

**Phase 1 acceptance:** scorecard agent tasks that require retyping succeed; on the C++/sqlite fixtures an
agent can reconstruct one central struct end to end with ≤ N calls (record N); signature agreement vs DWARF
improves from the Phase 0 baseline.

---

## Phase 2: library recognition at scale (~2 milestones)

**2.1 Signature corpus pipeline.** Extend `tools/gen-signatures.sh` into a reproducible pipeline that builds,
with zig/clang, several versions and optimization levels of: musl, glibc static pieces where licensing allows
(LGPL: generating hashes is fine, but keep the DB data-only and record provenance), libc++/libc++abi/libunwind,
compiler-rt, zlib, libpng, sqlite, lz4/zstd, mbedTLS, OpenSSL/BoringSSL, curl, lua; for x86-64, AArch64, i386,
ARM Thumb, and x86-64 Windows (mingw-w64 CRT). Rust std/core per recent stable versions (rustup targets).
Output into `crates/rampage-signatures/data/` as compressed DBs, loaded lazily per architecture.

**2.2 Import formats.** Import Ghidra FunctionID `.fidbf` databases (Apache-2.0, user-supplied or built from
Ghidra's distribution) and user-supplied FLIRT `.pat` files into `SignatureDb`. Do not ship IDA databases.

**2.3 Fuzzy matching.** For near-misses (different compiler flags), add a secondary matcher on CFG shape +
constant/call features with a confidence score; results below the gate are reported as candidates, not names.

**Acceptance:** library naming recall on stripped corpus binaries measured per library/arch in the scorecard;
target ≥ 80% on matched-version builds, with near-miss candidates reported for others.

---

## Phase 3: search, patching and agent ergonomics (~2 milestones)

**3.1 Search tools.** `search` MCP tool with modes: byte pattern with wildcards (`48 8B ?? ?? 89`), text
(ASCII/UTF-16, regex), immediate value, instruction mnemonic/operand pattern, and "functions referencing X"
(string/import/constant). Paginated, address-sorted, each hit with function context.

**3.2 Patching.** Byte patches as annotation-log entries (`patch_bytes`, `revert_patch`), visible to
disassembly/decompilation; `assemble` for x86/x64 via iced's encoder and for AArch64 via a small encoder over the
generated decoder tables (start with branches, NOP, MOV/CMP immediates); `export_patched` writes a new file
(never in place).

**3.3 Agent ergonomics.** Review the tool set against the Phase 0 agent-task transcripts: merge tools that are
always called together, add a `view` parameter (summary/code/full) consistently, make every tool accept names
as well as addresses, and add a `batch` tool for applying many annotations at once. Track tokens per task.

**Acceptance:** agent-task token/call counts drop measurably vs Phase 0; patch round-trip test (patch, export,
re-open, decompile shows change).

---

## Phase 4: processor and format breadth (~3 milestones)

**4.1 Sleigh disassembly backend.** The embedded Ghidra library already contains the Sleigh engine. Expose
Sleigh instruction decoding (mnemonic, operands, length, flow type, pcode) through the shim as a generic
disassembler backend, used for any processor without a native or Capstone decoder. Then embed more Ghidra
processor specs (Apache-2.0): AVR8, 8051, MSP430, PIC, SuperH, V850, TriCore, Xtensa, 6502, Z80, HCS12, 6805,
CR16, eBPF, Loongarch, Hexagon where present in the vendored Ghidra version. Keep spec size in check: compile
`.sla` lazily into the HOME cache as today. Flow information from Sleigh feeds the existing discovery.
This single step brings breadth to IDA's range. Decompilation follows per processor once its C model is
reviewed; processors without one are disassembly/discovery only and refuse C explicitly.
*Status (2026-10-21): complete.* Sixteen families decode through `inspect_sleigh` and open as ordinary Raw
Projects through MCP (`raw` selector) and CLI, with per-processor recall in the scorecard
(`docs/benchmarks/phase4-1-roster-2026-10-21.json`) and the published set in `docs/sleigh-decoding.md`. MSP430
and AVR8 decompile; the other fourteen refuse C until their models are reviewed.

**4.2 Raw and firmware loader.** Explicit base address/arch/endianness/entry points; multiple memory regions
(flash/RAM/MMIO) from a small TOML memory map; Intel HEX and Motorola SREC; vector-table-based entry seeding for
Cortex-M. This also completes the "raw-code windows" slice of the unknown-firmware track in `todo.md`.
*Status (2026-10-21):* the single-image Raw slice (explicit base, profile, entry and seeds for one code region)
shipped with 4.1. Multi-region memory maps, Intel HEX/SREC and vector-table seeding are open.

**4.3 Object files and archives.** ELF relocatable `.o`, COFF `.obj`, `.a`/`.lib` archives with relocation
application (also improves signature building: relocations give exact masks, fixing MIPS HI/LO masking).
ELF core dumps and Mach-O cores as snapshot sources.

**4.4 Later (only after the above):** DEX/APK and JVM class files (likely via a separate decompiler such as an
external JADX/Vineflower process), WebAssembly modules (the decompiler path does not cover them; disassembly
plus function/import/export structure first).

**Acceptance:** each new processor has an owned fixture (compiled where a compiler exists, else hand-assembled
bytes compared with Ghidra's disassembly); discovery recall vs Ghidra recorded in the scorecard.

---

## Phase 5: analysis depth (~3-4 milestones)

Order by what the agent-task suite shows as failures; default order:

1. **Auto data typing:** pointer arrays, string tables, vtables, function-pointer tables, jump tables on all
   decompiled architectures (reuse Ghidra's jump-table recovery results to seed discovery).
2. **C++:** class layouts from constructor/vtable usage (building on RTTI recovery), typed `this`, virtual
   call resolution to vtable slots, adjustor thunks; Itanium and MSVC exception tables (`.gcc_except_table`,
   `FuncInfo`) to restore catch/cleanup edges.
3. **Objective-C and Swift:** class/method/selector/protocol metadata into names and signatures; `objc_msgSend`
   call resolution to method implementations; Swift type metadata and demangling.
4. **Rust:** demangling everywhere (dependency already exists in rampage-analysis), panic/location strings
   as evidence, common std layout types (`String`, `Vec`, `&str`) in the bundled type library.
5. **Interprocedural signatures without debug info:** argument count/types and void-vs-value via
   cross-function usage (the Go ABI caller-inference already does this for Go; generalize).
6. **Indirect flow:** resolve more indirect calls via constant propagation and vtables; mark the remainder
   explicitly as unresolved.

**Acceptance:** per-item scorecard rows (e.g. vtable call resolution rate on the C++ corpus, ObjC selector
resolution rate on Mach-O fixtures).

---

## Phase 6: scale and persistence (~2 milestones)

**6.1 Large-binary targets.** Add 2-3 large open-source binaries to the corpus (e.g. a release build of
clang/lld or a browser engine shared library; ≥ 50 MB). Measure open time, full auto-analysis time, peak RSS,
and per-tool latency. Targets: auto-analysis within 2x of Ghidra's time on the same machine; MCP queries
(names, xrefs, listing pages) under 100 ms after analysis.

**6.2 Persistent analysis database.** Persist discovery/xrefs/types derived state so re-opening a large binary
is near-instant (the existing derived caches and function-inventory cache are the starting point). Analysis
runs incrementally after annotation edits instead of from scratch.

**6.3 Parallelism.** Parallel function analysis and batched decompilation across workers.

**Acceptance:** scorecard rows for the large binaries; full-workspace test gate completes within its time
budget (fix the currently recorded timeout).

---

## Phase 7: build diffing and annotation transfer (~1-2 milestones)

Agents often analyze version N+1 of something they already analyzed. Build on the existing `diff_builds`:
function matching across builds (exact hash, signature hash, CFG/call-graph propagation, BinDiff-style),
`transfer_annotations` from an analyzed project to a new build with per-match confidence, and a report of
changed functions. This replaces IDA's Lumina/BinDiff and Ghidra Version Tracking for the agent use case.

**Acceptance:** on two versions of an open-source library (e.g. zlib 1.2.13 vs 1.3), ≥ 90% of unchanged
functions matched and their annotations transferred.

---

## Phase 8: desktop UI catch-up (~2 milestones)

The UI follows MCP; it exposes what Phases 1-7 built: rename/retype in the pseudocode view (keyboard
`N`/`Y` like IDA), type library and struct editor, frame view, search panel, patch view, synchronized
listing/pseudocode highlighting, bookmarks. Use `egui_kittest` snapshot tests as today.

---

## Phase 9: debugger execution control (separate design first)

`todo.md` already requires a separate design/review before any execution control. Write that design as
`docs/plans/<date>-debugger-control.md` covering: GDB remote serial protocol first (covers gdbserver, QEMU,
OpenOCD/embedded probes, many emulators) then LLDB, then Windows; breakpoints, step, register/memory read and
write, module tracking; MCP tools with explicit operator consent per session. Do not start implementation until
the user approves the design.

---

## Summary of order

| Phase | Theme | Why this position |
|---|---|---|
| 0 | Parity scorecard + agent task suite | Needed to measure everything else |
| 1 | Interactive typing loop | Largest gap; core of every RE task |
| 2 | Library recognition at scale | Cheap, large win on stripped binaries |
| 3 | Search, patching, agent ergonomics | Missing basics; reduces agent cost |
| 4 | Sleigh disassembly, firmware/object loaders | Breadth to IDA's range for little code |
| 5 | Analysis depth (C++, ObjC/Swift, Rust, data typing) | Driven by Phase 0 task failures |
| 6 | Scale and persistence | Real-world binaries are large |
| 7 | Build diffing and annotation transfer | High agent value once 1-6 exist |
| 8 | Desktop UI catch-up | Secondary client |
| 9 | Debugger control | Needs separate approved design |

At the end of each phase: update the scorecard, re-run one real investigation (audio plugin or firmware)
through MCP, record removed and remaining blockers in `todo.md`, and get a fresh-context review of the phase as
a whole before starting the next.
