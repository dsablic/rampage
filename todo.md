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
  Go names surface everywhere. Section-based (`.gopclntab`/`__gopclntab`), with a bounded magic-scan fallback
  over read-only/relro sections when the dedicated section is absent or renamed; a text-section anchor is required.

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

- [x] Explicit PDB name preview/apply API with matching PE/PDB GUID and age, checked RVA/VA arithmetic and
  readable executable backing. Names only discovered unnamed entries, preserving labels in one undoable batch;
  real owned LLVM/LLD PE/PDB fixture. OMAP, types/layouts and CLI/MCP/UI import exposure remain separate.
- [x] Bundled starter signature databases: `rampage identify` applies a bundled musl libc database for the
  binary's architecture (x86-64, aarch64) out of the box; a user `--db` overlays on top, `--no-bundled` opts out.
  Generated reproducibly by `tools/gen-signatures.sh` (pinned zig). Follow-ups: more libs (libstdc++/libc++),
  more arches, and glibc/other musl versions; a database matches only the exact library build it was made from.
- [ ] MIPS signatures: mask `lui`/`addiu` HI/LO address pairs. Needs relocation/dataflow to avoid false matches
  (without it, a masked constant could collide two different functions); do it relocation-gated, not heuristic.
- [ ] Verify the MSVC RTTI path against a real PE (no MSVC toolchain locally; synthetic-tested only).
- [x] Signature confidence: `function_hash` gates out non-discriminating bodies (single-branch thunks, all-nop
  padding, too-few-instruction stubs) by minimum instruction count, non-masked content bytes and distinct
  encodings, so such bodies are neither stored nor matched. Malformed/truncated/unaligned regressions added;
  hashing is unchanged for accepted bodies. Thresholds are conservative heuristics (only ever stricter).
- [x] PE enrichment: TLS callbacks seed function starts and delay-load imports surface as slots (bounded,
  panic-free on malformed PEs).
- [x] Go pclntab: bounded magic-scan fallback over read-only/relro sections when the dedicated section is
  absent or renamed; absent section headers/text anchors remain unsupported.
- [ ] C++ class LAYOUT reconstruction (fields/sizes), building on the RTTI name/hierarchy recovery now in place.

### Capability-detection rules (capa-style, defensive triage)

These are static metadata indicators, not proof of execution or malicious intent. New rules require independent
corroborating groups; aliases and duplicate inputs cannot replace missing groups. Each has positive and benign
negative regressions. Existing rules retain their detection thresholds and canonical evidence contract.

- [x] Bounded persistence indicators: anchored registry Run/RunOnce keys, string-corroborated task registration,
  and service installation APIs.
- [x] Process discovery / enumeration (snapshot + first/next-process walk APIs).
- [x] Code-injection refinements: corroborated `remote-process-injection` rule (remote-process access, remote
  code placement incl. section mapping, and remote execution-start groups), alongside the legacy threshold rule.
- [x] Token / privilege indicators (token-open + privilege lookup/adjust APIs, corroborated SeDebugPrivilege).
- [x] VM/sandbox fingerprinting: firmware-table/adapter reads corroborated by a hypervisor artifact string.
  Import-based only; CPUID-based detection is an instruction, not an import, so it is out of reach here.
- [x] Bounded GDI capture, clipboard read and registered raw-input indicators with independent API groups.
- [x] Credential-access indicators: marker-corroborated LSA private-data access and protected-registry
  open/query/path groups with optional recognized machine-hive prefixes; no extraction or execution attribution.
- [x] Service control, named-pipe/IPC, DNS resolution / network-communication refinements.
  - [x] Corroborated service control, named-pipe client/server and DNS-plus-network indicators. C2 attribution
    is deliberately out of scope: static metadata cannot establish it.
- [x] Narrow ransomware indicators requiring encryption, enumeration start/walk, file writes and two ransom-note
  string groups; ordinary encryption/file access is insufficient.
- [x] Shutdown/reboot and environment/system-info gathering.
  - [x] Corroborated system-information/host-name/environment indicators.
  - [x] Corroborated `system-shutdown` rule: a shutdown/reboot API with a shutdown-privilege indicator.

### Licensing

- [x] Adopt Apache-2.0 project-wide (all crates and the workspace). Added a root `LICENSE` (Apache-2.0 text,
  previously missing) and a `NOTICE` attributing the vendored Ghidra decompiler (Apache-2.0) and the Arm AARCHMRS
  decoder tables (BSD-3-Clause). The audit found no copyleft blocker: deps are permissive except `colored`
  (MPL-2.0, dev-dependency only, not shipped) and a few `... OR GPL/LGPL` multi-licenses where the permissive
  option is elected. Trade-off accepted: Apache-2.0-only is one-way incompatible with GPLv2-only downstreams,
  which the former `MIT OR Apache-2.0` dual avoided.
- [x] Generated `THIRD-PARTY-NOTICES` for binary distributions (`python3 -I tools/third-party-notices.py`): the
  crates linked into `rampage`/`rampage-worker`/`rampage-ui` (no dev, build or proc-macro crates), deduplicated
  texts, plus the vendored Ghidra and Arm texts. Crates that publish no licence file are covered from the
  upstream file (yara-x), a same-repository package under the identical licence, or the standard text of the
  elected licence with holders from package metadata -- each labelled with its source. No copyleft-only crate.
  Regenerate whenever Cargo.lock changes.
- [x] UI About window (click the brand label): version, Apache-2.0, NOTICE, the bundled egui fonts' licences
  (UFL-1.0, OFL-1.1, MIT/Bitstream Vera, MIT) and THIRD-PARTY-NOTICES; snapshot `about.png`.


## Heuristic-database layer (pluggable detection DBs)

One pluggable detection layer: each database is a data file, permissive defaults bundled in-tree, everything
else user-supplied at runtime; every hit is a tagged finding (kind, name, confidence, evidence), not proof.
Licensing discipline: bundle only permissive, author our own starter sets, load the rest at runtime.

- [x] Packer/compiler/protector/installer/linker identification (`rampage-detect`): EP byte-pattern + section +
  import + overlay/entropy signatures with Strong/Tentative confidence, an authored Apache-clean starter DB, and a
  user-supplied PEiD `userdb.txt` parser. Packer path is synthetic-tested only (no packed fixture: no UPX here).
- [x] YARA engine (`rampage-yara`): `yara-x` 1.21 (BSD-3-Clause) runs user-supplied rule files/directories or
  inline source; per-rule matched-string capture is bounded. Rule corpora stay user-supplied.
- [x] capa-rules import (`rampage-capabilities::capa`): file-scope import/string/substring/section/export subset
  with and/or/not/optional/N-or-more; disasm features, `match:` references and non-file scopes are skipped.
  `Capability` now owns its strings (`Cow`), so loading rules repeatedly does not leak.
- [x] Integration: `Project::{detect_tools, yara_scan, yara_scan_path, detect_capa}`, CLI `detect`/`yara`/`capa`,
  MCP `detect_tools`/`yara_scan`/`capa_detect`. NOTICE unchanged: nothing upstream is vendored.
- [x] Confidence tuning: a `UniqueSectionName` condition marks tool-branded section names (`.gopclntab`, `.vmp0`,
  `.themida`, `.MPRESS1`, ...) as distinctive, so a lone match reports Strong; shared names stay corroborating.
- [x] Crypto/compression constants (`rampage-constants`): 74 spec-derived constants (AES, DES, Blowfish,
  Twofish, MD5, SHA-1/2/3, RIPEMD-160, ChaCha/Salsa, GHASH, CRC families, Deflate, Base64/32, P-256,
  secp256k1, Ed25519), most generated in code; both byte orders; min-length and information guards. Not
  detectable by constants: RC4, Adler-32, HMAC, TEA, Poly1305. Misses SIMD-interleaved and immediate-encoded
  constants.
- [x] `find_crypto` workflow: constants (crypto vs checksum/compression/encoding), crypto library APIs, the
  functions referencing either via xrefs, and crypto capability tags. Links Go's ChaCha constant to
  `internal/chacha8rand.block` on the arm64 fixture. No committed fixture carries AES/SHA tables yet.
- [ ] A real packed fixture (UPX or similar) once a packer is available, to test the packer path end to end.
- Won't do: `yara-x` feature trimming. Its build weight is `wasmtime`/cranelift, a mandatory dependency on
  native targets (rules compile to WebAssembly); disabling modules would not remove it and would break user
  rules that `import` those modules.
- [ ] Later DB kinds: Ghidra FidDb import (Apache, library-function ID, format conversion); ClamAV `.ndb/.ldb`
  as a user-supplied runtime input (GPL data -- never bundled); richer capa features once disasm extraction lands.

## Heuristic flywheel (propose -> measure -> gate -> promote)

Strategy: `docs/plans/2026-10-12-heuristic-self-improvement-flywheel.md`. The model proposes heuristic edits, a
corpus with ground truth judges them, and the versioned DBs hold what passes. The gate is the boss: promote only
on held-out, per-slice improvement with provenance and rollback.

- [x] Phase 1 (`docs/plans/2026-10-12-flywheel-phase1-execution.md`): `rampage-eval` crate and binary,
  strip-and-compare matched-pair corpus (`tools/eval-corpus.sh`), precision/recall and a disagreement set for
  library identification per slice, gate = no wrong and no spurious names, committed baselines.
- [x] First turn of the loop: the disagreement set showed aliased functions (`malloc`/`c.malloc.malloc`) being
  dropped as ambiguous hashes. Fixed in `SignatureDb::from_binary` (one spelling per address, shared
  `alias_rank` with the eval truth): recall 0.400 -> 0.723 (x86_64), 0.296 -> 0.580 (aarch64), precision 1.000;
  bundled musl DBs regenerated (96 -> 166, 98 -> 173 signatures). Correction: an earlier note here called the
  Phase 1 target a stripped twin of the reference; it was always a different program (`signatures-target.c`),
  so these gains were already cross-program (with a truth that still counted program code such as `main`).
- [x] Slices: `libid-twin-*` (stripped copy of the reference), `libid-cross-*` (a different program, truth limited
  to identifiable library code via `truth --library --program`), `discovery-*` (function starts vs symbols).
  Per-slice gates: no wrong names, no spurious library names, recall floors.
- [x] Second turn: absolute-address masking (hash scheme 2). x86/x86-64 displacements and immediates pointing
  into the image, and AArch64 ADRP low-12-bit offsets, are masked; databases carry their scheme so legacy ones
  keep matching exactly; ambiguous masked hashes fall back to exact hashes (gmtime/localtime). Measured:
  libid-cross recall 0.746 -> 0.921 (x86_64), 0.595 -> 0.823 (aarch64), precision 1.000, twins unchanged.
  (An earlier note here claimed 47 names from `rampage identify` on each musl fixture; re-measured after the
  review fixes it was 58 and 66, and is now 59 and 71 -- see below.)
- [x] Discovery false positives on aarch64: AArch64 switch jump-table bases (`adr` + `add ..., lsl` + `br`) inside
  a function no longer seed functions (they cascaded into interior blocks of `printf_core`/`vfscanf`); every other
  in-body code address still seeds (callbacks, code after noreturn calls). Precision 0.737 -> 0.990; the two left
  (`_start`, `__set_thread_area`) are real functions the truth omits (no symbol size).
- [x] AArch64 switch jump tables resolved in discovery: a `cmp` immediately followed by `b.hi`/`b.hs` bounds the
  index; byte/half/word/doubleword tables (signed and unsigned) through `adr`/`adrp+add` with lsl/extends, plus the
  absolute 64-bit form; entries only from read-only file-backed data; every target aligned decodable code; at most
  4096 entries; no branch may join between the `cmp` and the `br`. Cases are `switch` CFG edges (function_graph,
  SSA, summaries, export-cfg) and jump xrefs, not seeds. Bounds survive only instructions whose register writes are
  fully modelled. aarch64 reference extents equal to symbol size: 188 -> 193 of 193; AArch64 chain agreement with
  Ghidra 100% on blocks and edges.
- [x] Resolved switches retain table-order entries and the guard address; native SSA pseudocode prints cases
  and recovers the index operand when available. Bounded non-fall-through switch regions structure explicitly;
  unsupported shapes retain the
  labelled fallback (`ddeed9c`, `a5a07e2`).
- [x] AArch64 inverse `b.ls`/`b.lo` bounds are applied only on the taken edge; scheduled immediate comparisons
  survive audited NZCV/index-preserving instructions and agreeing joins. Weaker/incomparable proofs retain the
  original bound/guard; native SSA consumers locate the actual flag-consuming branch and bounded successor.
- [ ] Additional bound/comparison forms (including `BC.cond`) and broader compiled scheduling acceptance.
- [x] x86/x86-64 switch jump tables: absolute `jmp [reg*8+table]` (i386 `[reg*4+table]`), `mov`+`jmp`, relative
  `lea`/`movsxd`/`add`, MSVC image-base form; bounds from unsigned `cmp`+`ja`/`jae` or a low-bits `and` mask; the
  same join, read-only-table and 4096-entry rules. Register facts are forgotten where a branch joins the run
  (`Disassembler::join`, all architectures). Ghidra-only blocks: eval-ref-x86_64 328 -> 8, hello-x64.exe 239 -> 44.
- [x] Cross-block switch facts: must-dataflow carries only facts agreed on by every incoming edge; added cases
  are revalidated against the expanded graph. The earlier eval-ref-x86_64 and hello-x64.exe dispatches resolve
  (`e8622fd`); the updated x86-64 chain-block/edge benchmark agrees with Ghidra on the affected fixtures.
- [x] Real compiler-generated PIC i386 acceptance fixture, including combined memory-source addition,
  native-width dispatch and modulo-32-bit target arithmetic. Case-order/default and malformed-table regressions
  pass; this is not acceptance of all compiler or dispatch variants.
- [x] Noreturn analysis: a curated, case-sensitive list (C/POSIX, C++ ABI, Win32/CRT, Rust, Go; stubs, thunks and
  slots by name) plus incremental all-paths inference; conditional calls/returns and resumable traps handled; noreturn
  calls are terminal in structure/pseudocode, marked for the decompiler, and carry `listed`/`inferred` evidence in
  function_graph and export-cfg. Go edge precision vs Ghidra 95.3% -> 99.3%; go-arm64 structured functions 578 -> 755.
- [x] Noreturn inference through mutual tail calls (`3f0eeaf`): a greatest fixpoint over the tail-call graph,
  requiring a path to an evidenced non-returning call or trap. Cycles without that evidence remain unknown.
- [x] Get-PC call-to-next only when the following code reads the return address (delay-slot aware; x86, MIPS, PPC,
  SPARC, ARM/Thumb/AArch64); PE import thunks seeded so tail jumps stay tail calls; undecodable starts dropped in
  discovery phase 2; RISC-V branch targets rendered absolute.
- [x] Memory read/write addresses are data, not code-pointer seeds (`b4c5b3f`). Formed code addresses and loaded
  read-only pointer values remain separate evidence; the hello-arm literal-pool phantom functions are gone.
- [x] Library-ID misses explained and mostly fixed: signatures also hash the extent discovery finds (it stops at
  unresolved jump tables), and callee-name keys (`identify_program`, iterated) separate bodies that differ only in
  their callee (`mbstowcs`/`wcstombs`, `fprintf`/`sscanf`, `fmodl`/`__addtf3`). Callee keys apply only to bodies
  that pass the confidence gate (ignoring landing pads and the final branch) and whose masked hash is ambiguous; a
  user database's lookups outrank the bundled one's. Recall: twin x86_64 0.920 -> 0.977, cross x86_64 0.921 ->
  0.937, twin aarch64 0.876 -> 0.927, cross aarch64 0.848 -> 0.886; precision 1.000. (A first version also named
  gate-rejected tail-call stubs -- `atof`, `gmtime`, `localtime`, `strftime`, `__stdio_seek` -- and briefly reached
  0.953/0.899; review found it would misname user thunks and wrappers, so those floors were set back.)
  Remaining: musl `dummy` stubs (ambiguous), gate-rejected 2-3 instruction stubs and leaves (`__errno_location`,
  `difftime`, the above), `__lctrans`. Rebuild the bundled DBs whenever discovery extents change.
- [ ] Masking for 32-bit ARM literal pools and MIPS `lui`/`addiu` pairs, once a cross-program fixture exists.
- [x] Tool-identification slice (`toolid`, `tests/fixtures/data/eval-truth-toolid.json`): `detect_tools` against
  the build-script toolchains of 46 committed fixtures; recall 0.4397, precision 0.9538.
- [x] Tool-ID flywheel turn 1: a runtime kind (MinGW-w64/glibc/musl), MinGW/GCC -> MinGW-w64 runtime, LLD on PE from
  the CodeView record, Apple ld/LLD from Mach-O `LC_BUILD_VERSION`, Zig from `compiler_rt.` symbols. Rules are scoped
  to their format and region (no whole-file strong matches; overlay excluded; PeID entries PE-only). toolid recall
  0.4397 -> 0.7872, precision 0.9538 -> 1.0; out of sample (1,354 system binaries) no implausible strong detection.
- [ ] Tool-ID remaining: Zig on stripped builds and PEs, Clang on Mach-O/PE (no producer record), the whole-file
  "rustc version" rule (tentative; scope or drop), real NSIS/Inno Setup installer fixtures, a Zig-language Mach-O
  fixture.
- [x] DWARF-backed type-recovery evaluation: freestanding stripped twins per architecture, scoring parameter
  count, void/value returns and parameter type classes against bounded debug truth, with per-metric gates.
  This measures signature recovery, not aggregate/class-layout recovery or general type correctness.
- [ ] PDB-backed type truth and automated proposal/gate/promote stages with held-out provenance and rollback.

## Ideas from adjacent projects (REA, Ghidra-MCP)

REA ("Reverse Engineer Anything") is an open CLI+MCP orchestrator over external engines (Ghidra/Hopper/IDA) with
multi-format front-ends and guided workflows. rampage builds its own engine and embeds Ghidra, so the value is
in UX/workflow ideas, not the multi-engine dispatch:

- [x] Guided investigation workflows (`crates/rampage-api/src/workflows/`): `triage_report`, `find_main`,
  `network_surface`, `find_crypto`, `diff_builds`. Uniform bounded report (findings with evidence, source tool and
  confidence; truncation stated; next-step tool calls; limitations); MCP tools, `rampage report`, and the MCP
  instructions now point clients at `triage_report` first. Follow-ups: MSVC CRT startup chain in `find_main`
  (no MSVC fixture), startup heuristics beyond x86-64/AArch64 ELF, more workflows (e.g. persistence, unpacking
  triage, string decoding).
- [x] .NET/ECMA-335 metadata (`rampage_loaders::dotnet`): CLI header, streams, Module/TypeRef/TypeDef/Field/
  MethodDef/Param/MemberRef/Assembly/AssemblyRef/NestedClass with every other table sized; IL body headers;
  never seeded as native code. API `dotnet_metadata` (paged, filterable), `rampage dotnet`, MCP tool, and
  `triage_report` routes managed assemblies to it. Validated on Microsoft.Bcl.HashCode 1.1.1 (MIT, committed with
  its licence). Signatures/generics, primitive attributes, P/Invoke and IL/exception decoding were added below;
  remaining metadata includes events, resources and richer attribute arguments.
- [x] Embedded-binary carving (`rampage carve`, MCP `carve`, `rampage_api::carve`): bounded scan for ELF, PE,
  Mach-O (thin and universal) and zip/gzip/xz/zstd/LZMA/squashfs/cpio/uImage/Android boot, with validated header
  facts, header-derived extents, validated or magic-only confidence and a 4096-candidate cap.
- [x] Open an embedded executable: `Binary::open_at`, `Session::open_at`, global `--image-offset` / MCP
  `image_offset`, offset-keyed sidecars, triage reports the image's own hashes and where it sits.
  `--image-length`/`image_length`, `Embedded.trailing` with a triage hint, `.rampage-image` sidecars that cannot
  collide with plain ones, offset 0 without a length is the plain file.
- [x] Open embedded images in the UI (`a8ac21e`): Carve window, validated executable candidates, explicit offsets
  and optional lengths, including files that do not open as a whole image. Sessions reload changed binaries;
  diff-builds supports `--other-image-offset`.
- [ ] APK (JADX) and Electron unpacking are lower-priority follow-ons; carving is not archive extraction.
- [x] .NET: ECMA-335 blob signatures (method/field/MemberRef, TypeSpec, GenericParam names) rendered ILAsm-style
  with depth/node/text caps and an `<unreadable>` fallback; ImplMap P/Invoke (DLL + import per method);
  CustomAttribute rows with type, target and primitive/string/Type fixed arguments; nested types as `Outer/Inner`.
  In dotnet_metadata/CLI/MCP with a `list` selector (types/pinvokes/attributes). Decode work (blob bytes and text)
  is charged to one image-wide budget; array shapes are bounded by rank.
- [x] CIL disassembler: `dotnet_il` (API, `rampage dotnet --il`, MCP in the dotnet group): all Partition III
  opcodes with resolved tokens and signatures, generic instantiations, escaped capped `ldstr`, branch/switch labels,
  LocalVarSig locals, small and fat exception clauses; bounded and fuzzed; hand-verified (no ildasm locally).
- [x] .NET property signatures, including ref returns, generic/index parameters and bounded same-owner accessor
  tokens, with PropertyPtr order preserved. Fixed/named primitive/string/type, single-dimensional arrays and
  verified local integral enums decode within shared budgets; named failures retain valid fixed arguments.
- [ ] .NET boxed/jagged values, external or assembly-qualified/escaped enums, enum constant names, events/resources,
  and comparison of `dotnet_il` with ildasm/ILSpy once available. Metadata bindings do not establish accessor behavior.
- [x] Agent batch annotation: `annotate_batch` (all-or-nothing, at most 1000 entries, one undo step, per-entry
  outcomes) and the read-only `check_names` pre-flight, over MCP and CLI. Undo/redo return the step's edits. Name
  checks run under the cross-process log lock; batches are logged under a header line and replay all-or-nothing;
  undo/redo refuse to restore a name another client has taken.
- [x] `discard_undo` drops an undo step another client blocks (refuses unblocked steps unless forced). Reloads keep
  undo history; annotation logs record the image SHA-256 and warn when annotations were made on different bytes.
- [x] UI action for discarding a blocked undo step (`ab31d28`), showing the conflict without forcing the undo.
- [ ] Per-path image offsets for compare-pointers/compare-runtime.
- [x] MCP tool groups: every registry tool has a group; `rampage mcp` lists core + `enable_tools` (lists groups,
  enables them, sends tools/list_changed); `--all-tools` / `RAMPAGE_MCP_TOOLS` for clients without list_changed;
  calls to disabled tools error naming the group. The in-app agent and UI assistant still offer every tool.
- [x] `persistence_surface` workflow: autostart-location strings (Windows Run/services/tasks/Startup, launchd,
  systemd, cron, XDG autostart, rc/init), service/registry-write APIs, referencing functions, capability tags.
- [x] `string_decoding` workflow: static candidate decoders (bounded byte load/transform/store loops), call sites
  and the encoded-looking blobs passed to them; no emulation.

## Plugin system (later)

Native `.so`/`.dylib` plugins are out: Rust has no stable ABI, and a tool that reads hostile input should not load
unsandboxed native code. Three layers instead, in this order:

- [x] Data packs: `rampage-pack.toml` packs (signatures/peid/yara/capa) loaded strictly with contained paths and
  size caps via `--pack`/`RAMPAGE_PACKS`; applied to identify (before bundled, in pack order), detect, yara and
  capa; `rampage packs list|check` and MCP `list_packs` with licence/provenance and per-content status.
  Review fixes: YARA `include` refused in every rule set; files opened without following links and checked against
  what was budgeted; running per-pack and overall budgets, at most 64 packs, lazy loading; signature matches carry
  their `source`; pack problems reach detection `warnings` and the MCP instructions.
- [x] Constants packs (`f5eecda`), UI pack loading/status (`d769e82`), pack-only `identify --no-bundled`
  (`8379e5d`) and single-reporting of pack PeID problems (`8e7de84`). Constants retain information guards and
  pack provenance; packs remain bounded data inputs, not executable extensions.
- [x] Internal trait registries: guided workflows implement `Workflow` and are listed once in `WORKFLOWS`; the
  tool list (MCP, assistant) and `rampage report` enumerate it, with tests that each is unique, a tool of its group,
  served by MCP, named in the instructions and parsed by the CLI (docs/plugins.md). CLI and MCP output unchanged
  byte for byte. Not done, because nothing hand-dispatches over them: `Detector` (detectors take different inputs
  and return different evidence; packs extend them), `Loader` (ELF/PE/Mach-O already load through `object`; worth
  it when a format `object` cannot parse arrives) and a separate `ToolProvider` (workflows contribute their tools
  through their registry).
- [ ] WASM component plugins (wasmtime is already a dependency via yara-x): sandboxed, language-agnostic code for
  detectors, format loaders and workflows behind a WIT interface; bytes plus read-only analysis queries in,
  findings out. The output schema enforces the evidence/confidence/limitations contract.
- Freeze a public plugin API only after the internal traits settle. Many extensions need no in-process plugin:
  another MCP server composes with rampage at the agent level.


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
   - [x] OS/library-specific typedefs: off_t/time_t/mode_t/pid_t prototypes sized by width placeholders, with the
     POSIX I/O and time functions that use them (documented 32-bit Linux off_t and 32-bit Darwin time_t edges).
   - [ ] Remaining ABI-specific work: general Darwin ARM64 variadic call recovery and narrow caller extension.
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

### Earlier native-analysis increment — reviewed and committed

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

### Previous todo-wave validation (`ffc84e7`)

- [x] Ordinary release workspace suite, including CLI hierarchy, UI snapshots and the unchanged evaluation gate.
- [x] Focused debug API/CLI and core regressions, plus controlled LLDB query/capture tests and merge-history
  secret-scanner regression. Ignored scale/performance gates are not implied by an ordinary suite pass.
- [x] Hosted CI at `ffc84e7`: formatting/full-history secrets, Linux core subset and ordinary macOS debug
  workspace/UI/accuracy gates, including both selected opt-ins. This does not cover later uncommitted work.
- [x] Standard full debug workspace rerun completed after artifact regeneration with the smaller profiles.
  The earlier artifact stalled at `_dyld_start`; the underlying host launch-policy/cache cause is not established.
  No security settings changed. The current run includes unchanged UI snapshots and the 13-slice gate with its
  newly raised tool-ID floor.

### Build footprint and current validation

- [x] Dev/test debug information and incremental compilation disabled without disabling assertions or overflow
  checks. One coordinated target directory is used; 10 completed, clean, integrated old agent worktrees retired.
  Their reported build caches totaled about 190 GiB; branches, commits and source work were preserved.
- [x] Cold CLI/worker/UI build passed; its target directory measured 2.9 GiB afterward. This is an observation,
  not a disk quota or full-workspace size guarantee.
- [x] Ordinary debug workspace suite, warnings-denied Clippy, Rust formatting, and selected corpus regressions.
- [x] Controlled live transport plus complete Python suite: 571 tests and 108 subtests passed; scoped Ruff/ty pass.
  Actual Rust CLI queries also passed against a stopped owned native fixture, with target identity unchanged.
- [x] Full ordinary release workspace suite, including PDB arithmetic/corruption, compiled switch routing,
  debugger API/CLI/MCP/UI and unchanged UI snapshots. Ignored scale/performance tests are separate gates.
- [x] Selected opt-ins: native compiled ARM64 fixture and isolated CLI/worker acceptance passed on the final source.

### Validation and external blockers

- [x] LLVM-checked encodings and native ARM64 boundary comparisons, including all 16 conditions × 16 NZCV states.
- [x] Opt-in optimized C fixtures: native execution plus evaluated lifted arithmetic/selects and recovered byte spills.
- [x] Controlled live export on Apple LLDB `2103.0.34.103`: executable bytes, module identities and registers;
  explicit original Mach-O correlation verified with ASLR enabled. Capture artifacts were removed.
- [x] Previous committed milestones passed full debug/release suites and fresh-context review.
- [x] Ghidra comparisons for rampage's own analysis: `tools/cfg-benchmark.py` (+ `tools/ghidra_cfg_export.java`,
  hidden `rampage export-cfg`) compares blocks, CFG edges and call edges on 18 fixtures (docs/benchmarks.md), Ghidra
  as reference, not ground truth. IDA is still absent.
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
- [ ] Persist derived analysis caches and decompiler configuration as reproducible sessions.
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
   - [x] In-session `rampage-query` foundation for session/module/thread, fresh-register and raw-memory queries,
     with bounded JSON, stale stop tokens, exact known permissions and honest endian/stop evidence. Controlled
     owned-fixture acceptance covers Apple LLDB; no command passthrough, attach/resume/evaluation/writes/listener.
    - [x] Explicit local Unix transport, typed API/CLI/MCP and local-only UI window, with reviewed cancellation safety;
      EOF before querying, bounded framing/I/O, stale tokens and structured errors retained. Endpoint paths remain
      for operator cleanup; no automatic attach/resume/expression/target-write controls.
    - [ ] Module-qualified navigation and broader SDK/platform acceptance.
     Query observations remain non-atomic and external-plugin runtime acceptance remains blocked on an authorized host.

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
