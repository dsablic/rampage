# To do

## IDA/Ghidra gap-closing wave 2 (done this round)

- [x] Signatures extended to the fixed-width sets: 32-bit ARM (A32 and Thumb), MIPS/MIPS64 and PowerPC/PowerPC64,
  masking PC-relative branch/call targets in the target's byte order (`function_hash`/`identify` take a `Target`).
  Conservative: MIPS HI/LO address pairs are left unmasked (lowers match rate, never a false match).
- [x] Stripped C++ RTTI recovery: `rampage_analysis::rtti` scans Itanium type_info chains and MSVC RTTI (COL /
  TypeDescriptor / class hierarchy) to recover class names and base-class edges with no symbols, bounded and
  image-backed, surfaced via `ClassRecovery.rtti_classes` (de-duplicated against the symbol path). Pointer
  arithmetic is overflow-hardened. MSVC path is synthetic-tested only (no MSVC toolchain locally).
- [x] Go binaries: `rampage_loaders::gopclntab` recovers function names from the pclntab
  (go1.2/1.16/1.18/1.20+ magics, either endianness) and `Binary::open` attaches them automatically, so stripped
  Go names surface everywhere. Section-based (`.gopclntab`/`__gopclntab`); no full-image magic scan yet.

## IDA/Ghidra gap-closing wave 1 (done earlier)

- [x] Library identification (FLIRT/Function-ID style): `rampage-signatures` masks position-dependent bytes
  (relative branch/call targets, x86 RIP-relative displacements, AArch64 PC-relative encodings) and matches a
  function across differently linked builds. `SignatureDb` build/apply; `rampage signatures`/`identify` CLI;
  `build_signatures`/`identify_functions` agent tools. x86, x86-64, AArch64.
- [x] MSVC name demangling and C++ class names recovered from Itanium/MSVC vtables (analysis metadata).
- [x] Discovery recall: PLT resolver and stub functions are seeded (closes the dynamic-fixture recall gap).
- [x] Decompiler: flaky worker-timeout test made deterministic; prototype table expanded (C++ runtime, Win32);
  jump-table recovery confirmed surfaced in structured results.
- [x] PDB reader: `rampage_loaders::pdb::pdb_symbols` reads MSVC procedure/public symbols to names+RVAs,
  bounded and panic-free (error paths tested).
- [x] Capability detection: `rampage-capabilities` tags behaviors (networking, injection, anti-debug, crypto,
  filesystem, registry, input capture, dynamic loading) from imports/symbols/strings. `capabilities` tool + CLI.

### Pending follow-ups from this wave

- [ ] Apply PDB names in the API (VA = RVA + PE ImageBase, name only unnamed functions). Deferred: unverifiable
  without a real `.pdb` fixture, and no `lld-link` locally to generate one. Wire + test once a PDB fixture exists.
- [x] Bundled starter signature databases: `rampage identify` applies a bundled musl libc database for the
  binary's architecture (x86-64, aarch64) out of the box; a user `--db` overlays on top, `--no-bundled` opts out.
  Generated reproducibly by `tools/gen-signatures.sh` (pinned zig). Follow-ups: more libs (libstdc++/libc++),
  more arches, and glibc/other musl versions; a database matches only the exact library build it was made from.
- [ ] MIPS signatures: mask `lui`/`addiu` HI/LO address pairs. Needs relocation/dataflow to avoid false matches
  (without it, a masked constant could collide two different functions); do it relocation-gated, not heuristic.
- [ ] Verify the MSVC RTTI path against a real PE (no MSVC toolchain locally; synthetic-tested only).
- [x] PE enrichment: TLS callbacks seed function starts and delay-load imports surface as slots (bounded,
  panic-free on malformed PEs).
- [x] Go pclntab: bounded full-image magic-scan fallback when the section is absent or renamed.
- [ ] C++ class LAYOUT reconstruction (fields/sizes), building on the RTTI name/hierarchy recovery now in place.

### Capability-detection rules (capa-style, defensive triage)

These are static metadata indicators, not proof of execution or malicious intent. New rules require independent
corroborating groups; aliases and duplicate inputs cannot replace missing groups. Each has positive and benign
negative regressions. Existing rules retain their detection thresholds and canonical evidence contract.

- [x] Bounded persistence indicators: anchored registry Run/RunOnce keys, string-corroborated task registration,
  and service installation APIs.
- [x] Process discovery / enumeration (snapshot + first/next-process walk APIs).
- [ ] Code-injection refinements (extend the existing process-injection rule; section-map + remote-thread APIs).
- [x] Token / privilege indicators (token-open + privilege lookup/adjust APIs, corroborated SeDebugPrivilege).
- [ ] Anti-VM / sandbox evasion (hypervisor-vendor strings, cpuid probing).
- [x] Bounded GDI capture, clipboard read and registered raw-input indicators with independent API groups.
- [x] Credential-access indicators: marker-corroborated LSA private-data access and protected-registry
  open/query/path groups with optional recognized machine-hive prefixes; no extraction or execution attribution.
- [ ] Service control, named-pipe/IPC, DNS resolution / C2-comms refinements.
  - [x] Corroborated service control, named-pipe client/server and DNS-plus-network indicators; no C2 attribution.
- [x] Narrow ransomware indicators requiring encryption, enumeration start/walk, file writes and two ransom-note
  string groups; ordinary encryption/file access is insufficient.
- [ ] Shutdown/reboot and environment/system-info gathering.
  - [x] Corroborated system-information/host-name/environment indicators; shutdown/reboot remains open.

### Licensing

- [x] Adopt Apache-2.0 project-wide (all crates and the workspace). Added a root `LICENSE` (Apache-2.0 text,
  previously missing) and a `NOTICE` attributing the vendored Ghidra decompiler (Apache-2.0) and the Arm AARCHMRS
  decoder tables (BSD-3-Clause). The audit found no copyleft blocker: deps are permissive except `colored`
  (MPL-2.0, dev-dependency only, not shipped) and a few `... OR GPL/LGPL` multi-licenses where the permissive
  option is elected. Trade-off accepted: Apache-2.0-only is one-way incompatible with GPLv2-only downstreams,
  which the former `MIT OR Apache-2.0` dual avoided.
- [ ] Optional: a generated `THIRD-PARTY-NOTICES` aggregating Cargo dependency licenses (e.g. via cargo-about)
  for binary distributions, and surface the bundled UI font's license (OFL-1.1/Ubuntu-font) in the UI about path.


## Decompiler: embedded Ghidra (the decompilation path)

Decompilation is provided by `rampage-decompiler`, which embeds Ghidra's decompiler (Apache-2.0) in process and
exposes it through `Project::decompile`, the `decompile` tool (API/MCP/assistant) and `rampage decompile`. It
covers every architecture rampage decodes except s390x, renders calls by rampage's own names, applies common
libc prototypes (so string arguments show), and decodes Thumb in Thumb mode.

- [x] Embed the library, build from vendored sources, in-memory image, language-id mapping.
- [x] Decompile to C on demand over all executable segments; read-only data mapped for string folding.
- [x] Feed rampage's function names; apply libc prototypes; Thumb mode for 32-bit ARM.
- [x] Vendor the SLEIGH specs so no external Ghidra install is required (prefer bundled, override with
  `GHIDRA_INSTALL_DIR`).
- [x] Expand the library prototype set to the common C runtime (~130 stdio/string/memory/stdlib/ctype/POSIX/
  math/pthread functions), applied per present symbol, with a test that every prototype parses.
- [x] Function-discovery accuracy benchmark against Ghidra (`tools/benchmark.sh`, `docs/benchmarks.md`).
- [ ] C++ class recovery: typed vtables/RTTI and `this` pointers in the decompiler. The embedded library reads
  types from C declarations or XML, not Ghidra `.gdt` archives, so this needs a header/type pipeline, not a
  `.gdt` import. Larger, separate effort.
- [x] Apply user-set types/signatures to the decompiler and import bounded embedded debug signatures.
- [ ] Richer automatic `main`/entry signature recovery without debug metadata.
- [x] Bundle for relocated/installed binaries (embed specs or install them), so a `cargo install` binary that is
   moved away from its build tree still finds specs without `GHIDRA_INSTALL_DIR`.

### Integration acceptance order

Each increment requires regressions, review and targeted simplification. Sharing Ghidra's engine does not
guarantee identical output: memory mappings, ABI, mode context, symbols/types and options must agree too.

1. [x] Memory correctness: explicit backed/zero-fill/unavailable mappings, read/execute permissions, strict
   instruction-range checks after speculative SLEIGH lookahead and real string terminators. Review fixes cover
   partial-flow retries, target-width bounds, wrapped reads and UTF-16 boundary terminators.
2. [x] Mode correctness: ARM/Thumb transitions independent of request order; merge loader and discovery context,
   preserve equal-valued barriers and accept padding/end boundaries. Each image owns its translator; caches
   invalidate safely. Reviewed regressions cover corrupt specs, interleaved images and a million mode points.
3. [x] Compiler ABI selection: PE Windows and Darwin PowerPC defaults, explicit API/CLI overrides, strict
   compiler-ID/data-model validation and target-sized runtime declarations. Reviewed coverage includes
   ILP32/LP64/LLP64, Windows x86 cdecl, clangwindows aliases and all 13 bundled processor targets.
   - [x] ARM BE8 mixed instruction/data endian selection, preserved by compiler overrides.
   - [x] Darwin ARM64 fixed stack packing and explicit variadic slot allocator/compiler model.
   - [ ] Remaining ABI-specific work: general Darwin ARM64 variadic call recovery and narrow caller extension,
     and OS/library-specific typedefs such as off_t/time_t rather than guessed automatic declarations.
4. [x] Symbol/type synchronization: address-bound prototypes, independent import slots, metadata identity
   separate from display spelling, reported failures, cached engine refresh on name/type edits and undo/redo.
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
   - [ ] Exact aggregate/debug-layout import, external PDB/dSYM support and automatic class-layout recovery.
7. [x] Address-linked structured results and clickable pseudocode, including engine-derived flow evidence.
   - [x] Semantic address-linked tokens and background UI pseudocode/navigation panel.
   - [x] Variable/storage/block/signature schemas and recovered call/jump-table destinations.
   - [x] Rendered-byte spans, inline pseudocode navigation and raw jump-table labels with absent-label nulls.
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

### Committed milestones

- `ce8d78c`: integer/NZCV semantics, AAPCS64 calls, constant/stack evidence, dominance/natural loops,
  labeled pseudocode, explicit jump-table inspection, snapshot metadata and comparison foundations.
- `e5adb73`: conservative control regions, conditional selects and common bitfield aliases.
- `94d0936`: checked X0/X1 return candidates, without inferring a signature or inventing argument uses.
- `35508ff`: successful controlled live LLDB capture with ASLR enabled and UUID/header-slide correlation.
- `07110f5`: phi-alias simplification without expression expansion; bounded long-chain allocation regression.
- `d969847`: extended-register ADD/SUB, including SP/ZR and signed/unsigned extension rules.
- `1c9c737`: scalar memory widths/extensions, proven constant-store forwarding and complete phi-path validation.
- `a2c9ec0`: word-sized STP/LDP and signed LDPSW pairs with full-width SP writeback.
- `1556f22`: opt-in structured SSA pseudocode, parallel phi bindings and CFG-versus-region execution tests.

### Latest increment — reviewed and committed

- [x] Local operand-use evidence: integer widths, address/code operands, signed/unsigned operation roles.
  This is not source-type inference; shift counts do not inherit pointer roles. Traversal is bounded.
- [x] Explicit indirect-branch target observations in IR/SSA and constant-target evidence from dataflow.
- [x] Image validation requires an entire aligned instruction in backed, readable executable code.
  Evidence does not insert CFG edges or function seeds; mutable snapshot-pointer inference stays disabled.
- [x] Independent reviews completed; reported bugs fixed and retained as regressions.
- [x] Latest release workspace suite and warnings-denied Clippy passed.
- [x] Full debug workspace run completes (~1m45s); the earlier timeout was the one-time vendored C++ build of
  the decompiler, now cached. Suite is green with the decompiler integrated.
- [x] Final formatting/diff checks, line-length cleanup and commit of this increment.

### Validation and external blockers

- [x] LLVM-checked encodings and native ARM64 boundary comparisons, including all 16 conditions × 16 NZCV states.
- [x] Opt-in optimized C fixtures: native execution plus evaluated lifted arithmetic/selects and recovered byte spills.
- [x] Controlled live export on Apple LLDB `2103.0.34.103`: executable bytes, module identities and registers;
  explicit original Mach-O correlation verified with ASLR enabled. Capture artifacts were removed.
- [x] Previous committed milestones passed full debug/release suites and fresh-context review.
- [ ] Actual IDA/Ghidra comparisons for rampage's own analysis (discovery/CFG/xrefs). Ghidra is now installed
  locally (used by the decompiler), so this is unblocked; IDA is still absent. No comparative claim yet.
- [ ] Resolve the local `rust-objcopy` missing-`libLLVM.dylib` stripping warning; release tests still execute.
  - Command-local `DYLD_LIBRARY_PATH=<rustc-sysroot>/lib` resolves the installed tool's library lookup;
    permanent managed-toolchain repair remains open rather than patching rustup-owned executables.

## Deep ARM64 track and remaining work

### 1. Instruction semantics — partial

- [x] Immediate, shifted and extended ADD/SUB; logical operations; wide moves; multiply/divide; variable shifts.
- [x] NZCV, B.cond, CBZ/CBNZ/TBZ/TBNZ, CSEL/CSINC/CSINV/CSNEG, ADR/ADRP and plain BL/BLR/BR/RET.
- [x] Common non-wrapping bitfield aliases; 8/16/32/64-bit scalar memory with separate result/access widths.
- [x] Literal/register/unsigned/unscaled/pre/post addressing; 32/64-bit pairs and signed LDPSW.
- [ ] Remaining common integer families: carry arithmetic, conditional compares, wrapping bitfields,
  long/high multiply, extracts and other scalar operations. Add native boundary regressions per family.
- [x] Valid no-writeback pair loads with base/destination overlap; capture both original addresses before
  assignments for LDP X/W and LDPSW. Writeback overlaps and duplicate destinations remain barriers.
- [ ] FP/SIMD, atomic/exclusive and selected system semantics, with effects and memory ordering explicit.
- [ ] PAC/authenticated flow, exceptions and platform-specific behavior; unsupported forms must remain barriers.

### 2. Stack, memory and signatures — partial

- [x] Integer AAPCS64 caller clobbers/callee preservation; X8 result-buffer and SP call dependencies.
- [x] Entry-SP-relative slots, conflicting-path unknowns, per-RET X0/X1 candidates and input-use argument evidence.
- [x] Exact-width constant-store forwarding with source IDs and all-path agreement; conservative alias boundaries.
- [ ] Recover nonconstant spills/reloads, partial-width overlaps and safe cyclic-memory fixpoints.
- [ ] Stack-frame boundaries, outgoing stack arguments, saved-register roles and escaped-stack alias handling.
- [ ] Interprocedural signatures: argument count/types, void versus value, aggregate returns, varargs and FP/SIMD ABI.
- [ ] Propagate type constraints and reconstruct pointer/struct/class layouts; local operand roles alone are not types.

### 3. SSA and pseudocode — partial

- [x] Bounded register/memory SSA, predecessor-indexed phis, constants/affine stack reasoning and semantic gaps.
- [x] Redundant phi aliases, dominators, natural-loop evidence and conservative sequence/branch/single-body regions.
- [x] Labeled and `--structured` SSA pseudocode with explicit predecessor tokens and simultaneous phi bindings.
- [x] Execution comparisons cover both diamond arms, repeated loops and both loop-condition polarities.
- [ ] Minimal phi placement, dead-definition elimination and broader expression simplification without amplification.
- [ ] Nested/multi-block loops, broader branch joins, switch regions and explicit irreducible-flow fallback.
- [ ] Typed variables, source-level expressions/returns and readable decompiler output distinct from SSA diagnostics.

### 4. Jump tables and indirect flow — partial

- [x] Conservative ADR/ADRP/ADD/MOV/LDR/BR/BLR discovery; calls/stores invalidate captured-memory assumptions.
- [x] Explicit bounded absolute64/signed-relative32 table inspection, without guessed dispatch bounds.
- [x] Image-validated SSA target evidence, including a spilled constant target.
- [ ] Automatic dispatch recognition, proven index bounds and validated table entries tied to the branch site.
- [ ] Feed proven targets into discovery/CFG/xrefs with deterministic closure and retained source evidence.
- [ ] Mutable pointers only after alias/reaching-store proof; authenticated or unmapped targets remain unresolved.
- [ ] Fixtures for relative tables, duplicate targets, joins, loops, truncation, overflow and hostile index bounds.

### 5. Controlled runtime capture — initial gate complete

- [x] Successful permitted stopped-process capture, module UUIDs/bases, register provenance and original correlation.
- [ ] Reproducible session persistence and mapping-aware snapshot identity, including addresses/permissions/endianness.
- [ ] Multiple modules/threads and stripped/relocated images; module-qualified navigation and cross-module references.
- [ ] Broader debugger/platform integration, capture failure handling and provenance validation on larger fixtures.

### 6. Accuracy benchmark — partial; external comparisons blocked

- [x] Synthetic snapshots, native instruction oracles, compiled fixtures and malformed-input/resource regressions.
- [x] Versioned, hash-/architecture-matched function-start reference imports; snapshot comparisons reject
  ambiguous identity.
- [ ] A reproducible compiler/optimization corpus with recorded tool versions and instruction/CFG/xref/semantic metrics.
- [ ] CI gates for accuracy regressions, unsupported coverage, false positives and analysis time/memory bounds.
- [ ] IDA/Ghidra exports and comparisons once installations are available; reference output is not ground truth.
- [ ] Expand comparisons beyond function starts to CFGs, dispatch targets, stack/signature evidence and semantics.

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

Work in this order, with synthetic regressions and fresh-context review for each increment:

1. [x] Structured recovery diagnostics: export engine warnings, bad-data/unimplemented flags and unresolved
   calls/jump tables. Surface warnings in CLI/API/MCP/UI and separate successful output from usable recovery in
   benchmarks; no unqualified "complete" or "clean implies correct" label.
2. [x] Discovery-confidence summaries: relate candidates to bounded sampled regions and preserve evidence for
   suspicious tiny fragments, invalid decode and code/data ambiguity. Do not silently delete candidate functions
   or infer encryption from entropy alone. Use cached discovery modes; whole-program discovery is an explicit
   opt-in (`audit --include-discovery` / MCP `include_discovery`), not a hidden prerequisite for sampling.
3. [ ] Authorized capture workflow: bounded module/range selection and actual memory-permission checks in the
   stopped-process LLDB exporter, capture failures and provenance. No automatic plugin launch, installation,
   debugger attachment, licensing changes or target-memory writes; controlled live tests use our own fixtures.
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
7. [ ] Authorized runtime acceptance: user supplies an already-loaded/stopped instance in a legitimate host;
   capture selected code and referenced data, correlate the original UUID, rerun diagnostics/decompilation and
   report before/after warning/coverage metrics. This is blocked on an authorized host capture, not static parsing.

Commercial plugin bytes and captured process contents are local investigation inputs, not committed fixtures.
No protection bypass, patching or claims of license-state recovery are part of this work.

Acceptance gate for each milestone: behavioral regressions, malformed-input tests, `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, workspace tests, and independent review. Commercial samples are
read-only triage inputs, never bypass or patch fixtures. Runtime tests use programs we build ourselves.

- [x] Initial runtime images: validated sparse snapshot format, CLI/API/UI loading, explicit code seeds, provenance,
  virtual-address handling and controlled LLDB export/correlation. Persistence and cross-module work remain above.
- [ ] Indirect flow: conservative known-register and readable-pointer resolution, starting with AArch64
  ADR/ADRP/ADD/MOV/LDR/BR/BLR. Unknown, authenticated, mutable and unmapped targets must remain unresolved.
- [ ] Analysis confidence: explain suspected encoded code and decode coverage without presenting random bytes
  as trustworthy functions; support sparse memory and retain evidence rather than asserting encryption.
- [ ] Language metadata: C++/Rust demangling while preserving original lookup names, bounded Itanium vtable/RTTI
  discovery, and Objective-C class/method/selector metadata with malformed-pointer tests.
- [ ] Data-flow/decompilation: first ship an explicitly limited, structured function summary with CFG and
  references; then build a typed instruction IR, SSA, calling conventions, structuring and decompiler coverage.
  Do not label a disassembly rewrite or model-generated prose a decompiler.
- [ ] Containers and workspaces: bundle executable discovery, inventory of nested binaries, safe package
  inspection without executing installers, and cross-module navigation with address/module identities.

### Implemented foundations

- [x] Sparse snapshot loader with virtual addresses, region/seed validation, provenance and resource bounds.
- [x] Snapshot loading through CLI/API/MCP/UI and controlled integration fixtures.
- [x] Read-only LLDB snapshot export command with preflight validation and no-overwrite behavior.
  Mocked export tests and the opt-in controlled live ARM64 capture pass with ASLR left enabled. Module UUID/header
  mapping and selected-thread register provenance are verified against the explicitly supplied original image.
- [x] AArch64 conservative ADR/ADRP/ADD/MOV/LDR/BR/BLR tracking with stores/calls invalidating memory inference.
  Writable capture regions remain excluded from pointer evidence. Exact-store forwarding exists in summaries,
  but is not a general alias proof or a reason to enable mutable-pointer discovery.
- [x] Final discovery closure and retained per-function resolved flows, keeping CFGs/listings consistent.
- [x] `audit`/`analysis_diagnostics`: bounded coverage and unreliable-code evidence, not proof of encryption.
- [x] Bounded C++/Rust demangling; original lookup aliases and collision-safe display names.
- [x] Sized, named Itanium vtable targets/RTTI labels and Objective-C selector string inventory.
- [x] Plist-authoritative bundle opening and bounded inventory of already-extracted packages/directories.
- [x] Structural function summaries with paginated references, CFG and explicit non-decompiler limitations.
- [x] Partial typed AArch64 IR for the integer/NZCV/scalar-memory families listed in track 1 above.
  Unsupported instructions remain explicit barriers; no source-level reconstruction is claimed.
- [x] Bounded register/memory SSA with block-entry phi nodes, entry/backedge inputs, unreachable-block handling,
  zero-extended 32-bit results and full semantic barriers; exposed through structural function summaries.
  Memory access widths and conditional polarity/tested bits are retained. Generated-definition and input-node
  budgets reject amplification before SSA allocation.
  Minimal phi placement, alias analysis and decompilation remain open; bounded dominance queries are available.

Full instruction semantics, production decompilation, arbitrary debugger control and multi-module runtime
resolution have separate acceptance cases. The embedded decompiler is implemented above; full native semantics,
arbitrary debugger control and multi-module runtime resolution must not be inferred from those foundations.

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

Committed-foundation validation includes full debug/release suites, warnings-denied Clippy, UI snapshots,
CLI/API/MCP regressions, malformed-input bounds, native/compiled fixtures, exporter tests, the opt-in live
capture test, debugger-cleanup regressions, Ruff/ty and fresh-context reviews. The earlier full-debug timeout
was the one-time vendored C++ build; subsequent debug/release workspace suites passed.

Checklist from the second code-review round. Most of it is in `crates/rampage-arch/src/aarch32/flow.rs`.
After each group: `cargo fmt`, `cargo clippy --all-targets`, `cargo test`, and the AArch32 golden tests
(`tests/data/{a32,t16,t32}_golden.tsv`; current rates A32 97.95%, T16 100%, T32 97.49%). Add cases to
`crates/rampage-arch/tests/flow.rs` with encodings checked against llvm-mc.

## Prerequisites

- [x] `Target::data_big_endian`, set by `Binary::target()` and read by literal-pool tracking.
- [x] PowerPC64 `addis` starts an address; the TOC-pair regression reports only the completed sum.

## AArch32 flow and tracking bugs

- [x] **Thumb high registers.** T16 encodings split the destination into `D:Rd`, `DN:Rdn` or `DM:Rdm`, but `kind()`
   and `track()` read only the low 3 bits. So `mov pc, lr` (f746), `mov pc, r0` (8746) and `add pc, r3` (9f44)
   are classified as `Next`, and `mov r8, r1` (8846) and `add r8, pc` (f844) track the wrong register.
   Fix: one helper that reads a register operand by name (`<Rd>`, `<Rdn>`, `<Rdm>`, `<Rm>`, ...) through
   `Encoding::operand_bits`, which concatenates all of the operand's fields; fall back to the plain field.
- [x] **PC writers.** `subs pc, lr, #4` (A32 04f05ee2, T32 def3048f) is `Next`: SUBS is missing from the PC-writer
   list, and the `SUBS_PC_LR` name prefix never matches (the T32 encoding is `SUBS_PC_T5_AS`). It should be a
   return, as `movs pc, lr` is. Shifted moves such as `lsl pc, r0, #2` (A32 00f1a0e1) are also `Next`. Accept the
   S-suffixed and shift mnemonics (LSL, LSR, ASR, ROR, RRX) when the destination is PC.
- [x] **Unclear destinations.** Registers written as RdLo/RdHi (UMULL), Rt (MRC, VMOV to core registers, loads) and
   STREX's status Rd are never cleared. Clear every destination operand, treating Rt/Rt2 as written except for
   stores, MCR and PUSH. Over-clearing only loses tracking.
- [x] **LDRD.** T32 LDRD's Rt2 is not cleared (covered by 3). A32 literal LDRD doesn't clear Rt, or Rt+1.
- [x] **16-bit LDM/STM writeback.** T16 LDM/STM have no W field but write back the base (LDM unless the base is in the
   list). Clear Rn for them.
- [x] **Offset scaling.** T32 LDRD/STRD/LDREX imm8 is a word offset (x4). The T16 imm5 forms are not tracked at all:
   LDR/STR imm5 scales x4, LDRH/STRH x2, LDRB/STRB x1; SP-relative imm8 x4.
- [x] **ADD (register).** It ignores the shift (`add r0, pc, r1, lsl #2`, 01018fe0), and RRX encodings. Track only
   unshifted forms. It also reports data references for conditional ADDs (`addeq r0, pc, r1`, 01008f00); report
   only unconditional ones.
- [x] **Literal pools.** Read in instruction byte order, which is wrong for BE8 images (code little-endian, data
   big-endian). Read them with `Target::data_big_endian`.
- [x] **Over-strong classifications.**
   - `ldm r0, {r1, pc}` (A32 028090e8, T32 90e80280) is a `Return`; only a POP or SP-based LDM should be. Others
     are `IndirectJump`.
   - `ldr pc, [pc, #x]` should jump to the literal's value when the pool is readable (keeping the Thumb bit's
     meaning: even in A32, odd in T32), not be an `IndirectJump`.
   - Thumb `blx label` switches to A32, but `Target::thumb` is a fixed set of ranges, so the target decodes in the
      wrong mode. Decoders now report mode hints; discovery merges them between rounds and records instruction
      modes for listing/graph decoding, including when the target was already seeded.
- [x] **Overflow.** `address + size` overflows (and panics in debug builds) near `u64::MAX`: flow.rs `flow()`,
    `track()`'s `pc`, `decode()`'s `next`, and cs.rs:241. Use `wrapping_add`.

## AArch32 rendering bugs

- [x] The `hint` alias renders as `clrbhb`.
- [x] VCVT_is shows u32 where it should be s32.
- [x] VCVT_xs prints the wrong types and fbits.

## DRY and refactors (behaviour must not change)

- [x] One mnemonic helper instead of three: `aarch32/mod.rs` `mnemonic`, mrs `root_mnemonic`, operands
  `Context::mnemonic`.
- [x] Remove the `field()` wrapper in flow.rs; call `Decoded::field`.
- [x] One destination-register helper in flow.rs (from bug 1), used by `kind()` and `track()`.
- [x] The LDM/POP mnemonic list appears twice in flow.rs; make it one constant or function.
- [x] A `wide_immediate` helper for the MOVW/MOVT imm4:i:imm3:imm8 (T32) and imm4:imm12 (A32) values.
- [x] `is_non_canonical` should reuse `operands::canonical_rotation`.
- [x] One `read_u32(bytes, offset, big_endian)` for the A32 word, literal pools and similar reads.
- [x] Share the kind-to-`Flow` mapping (conditions applied) between flow.rs and cs.rs.
- [x] An `or()` helper in track.rs for the MIPS/PowerPC/SPARC `ori`/`or` arms.
- [x] Move `sign_extend`, `ones` and `Field::mask` into mrs; `a64/helpers.rs` and `aarch32/spec_types.rs` duplicate
  them. Keep A64 armgen output byte-identical (hash 9814543386b94709d07f666db386d8bdede961c3 over
  scratchpad `words.txt`). The original scratchpad is unavailable; a 500,000-word deterministic rendering sweep
  is byte-identical to HEAD (SHA-1 `e5ac54acb63f7e70a31d5a9bb2965f48b984ea75`), and generated tables are unchanged.
- [x] Consolidate the `.w` qualifier handling and the chain of text `.replace` passes in `aarch32::format`.

## Smaller, outside rampage-arch (optional)

- [x] The UI assistant (`rampage-ui/src/assistant.rs`) recognises effects by tool-name strings ("rename",
  "set_comment", "show_address"); have the tool registry say which tools change annotations or move the view.
- [x] `rampage-api/src/graph.rs` recomputes block ends from line bytes; it could use the analysis `Block.end`.
- [x] The `binary_info` tool serializes its result twice.
- [x] The graph view computes row widths twice.

## Verification

- Debug/release workspace tests, including unchanged UI snapshots; Clippy with warnings denied; format/diff checks.
- The ignored Chrome large-binary UI test passes (debug build; subsequent frames 5–9 ms).
- Debug and release decoder suites, llvm-mc-checked regressions, and the A32/T16/T32 golden corpora.
- Interworking tested in both directions, with one/four threads and pre-existing/new call-target seeds.
- Review regressions cover stale mode hints, conditional fall-through calls, BLX-to-next, formatting and boundaries.
- Mode changes rebuild discovery from original seeds; contradictory mode cycles terminate without phantom functions.
- SP implicit writes, split DM operands, comparison/vector source preservation and graph layer centering are covered.
- Known seeds inherit incoming modes; cycle handling preserves downstream modes; invalid bytes retain decode mode.
- Invalid instructions advance IT slots; backward/interior interworking cycles have bounded termination regressions.
- Every Thumb halfword tested at the top of the address space in both byte orders; all 32 VCVT fraction widths.
- Literal pools tested with all code/data byte-order combinations and truncated reads.
- A64 rendering compared against the pre-change code on 500,000 deterministic words (identical SHA-1 above).
- Release builds report a local `rust-objcopy`/`libLLVM.dylib` stripping warning; the tests still pass.
