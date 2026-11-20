# Incremental analysis and a fuller analysis store (2026-11-20)

Track 5 of the queue agreed on 2026-11-19 (todo.md, "Next up"): the IDA-database-like gap. Status: first slice
implemented, experimental. The reference is [Persistent analysis store](../mcp.md#persistent-analysis-store).

## Starting point

The persistent store (roadmap 6.2, first half) kept one thing: each binary's function discovery (functions,
blocks, switches, cross-references, noreturn facts, code modes), keyed by the input bytes, the image selection, the
Raw interpretation, `ANALYSIS_VERSION` and the executable. Everything else was computed again in every process.

What an annotation edit did to analysis, before this work:

- **On an ordinary project, nothing.** Discovery reads no annotation. Decompilation is not cached at all: the
  in-process engine is rebuilt when a decompiler-relevant annotation map changed, and the supervised worker (the
  default for an installed MCP server) builds a fresh engine for every call anyway.
- **On an effective view, a full recomputation.** Once an image has been through patch authority (a patch, or
  `integrity_checks`, which takes a patch receipt), every MCP tool call reads an effective view, and every edit
  (a comment included) builds a new view with empty caches. Views were never stored, so each one rediscovered
  every function, without the store. This applies to static non-PIE ELF (x86-64, AArch64, ARM) and Raw images:
  most firmware.

## Measurements

Method: a fresh `rampage server serve --all-tools` per run, with the release worker, driven over stdio; each tool
call timed end to end by a small JSON-RPC driver (not committed). Three server runs per input: store off, cold
(empty store) and warm (the store the cold run filled), each starting without an annotation log. One sample each;
this Mac is noisy, so differences under about 10% are not meaningful.

Inputs:

- **Go 26 MB:** `restic-x64-stripped.elf` (suite v3), static, 31,318 functions. The 49 MB suite-v2 binary was no
  longer on disk; this is the largest Go binary available.
- **ELF 7.9 MB:** `sqlite3-x64.elf` (suite v3), 2,026 functions.
- **Cortex-M Raw 3.7 MB:** synthesised, since the fixtures are all under 70 KB: three Thumb builds of the SQLite
  amalgamation for `thumb-linux-musleabi -mcpu=cortex_m4` (feature-rich `-O1 -fno-inline`, plain `-O1`, `-Os`),
  their loadable segments laid out flat one after another with a vector table (SP, reset = the first build's
  entry) at the start; opened as `{"profile": "cortex-m4", "base_address": "0x10000", "vector_table": true}`.
  5,269 functions are discovered, most in the first build.

Decompiled functions: one at the 2nd percentile of size, one at the 25th and one at the median.

### Before (store as it was: discovery only)

| Stage | Go 26 MB: cold / warm (ms) | ELF 7.9 MB: cold / warm (ms) | Cortex-M Raw 3.7 MB: cold / warm (ms) |
|---|---|---|---|
| load (binary_info) | 47 / 44 | 7 / 7 | 18,775 / 427 |
| discovery (list_functions) | 997 / 64 | 178 / 11 | 11 / 16 |
| xrefs to a function | 1 / 0 | 0 / 0 | 9 / 11 |
| strings (first page) | 107 / 105 | 7 / 6 | 25 / 30 |
| strings contains | 5 / 5 | 1 / 1 | 7 / 13 |
| identify_functions | 1,655 / 1,646 | 377 / 373 | 708 / 1,007 |
| capabilities | 29 / 24 | 2 / 2 | 9 / 22 |
| find_main | 8,510 / 8,470 | 1,061 / 1,023 | 2,583 / 3,138 |
| triage_report | 1,749 / 1,731 | 340 / 335 | 673 / 955 |
| lock_mechanisms | 844 / 838 | 195 / 198 | 3,034 / 5,340 |
| integrity_checks | 920 / 912 | 633 / 635 | 899 / 1,131 |
| function_summary | 493 / 487 | 306 / 301 | 18,748 / 32,217 |
| endpoint_inventory | 397 / 396 | 26 / 25 | – |
| list_types | 6,196 / 6,139 | 809 / 791 | – |
| decompile f0 | 6,238 / 6,319 | 963 / 956 | 20,603 (failed) / 35,903 (failed) |
| decompile f1 | 6,286 / 6,200 | 774 / 794 | 20,827 (failed) / 24,583 (failed) |
| decompile f2 | 6,174 / 6,446 | 776 / 750 | 21,006 (failed) / 22,194 (failed) |
| decompile f0 again | 6,238 / 6,302 | 976 / 979 | 36,376 (failed) / 22,244 (failed) |

The Cortex-M warm column ran beside a compile and is inflated. "Failed" is the worker refusing the request (below);
the Go and ELF f0 rows also end in a response-size error, after the full decompilation.

### What the numbers say

- **Discovery was already handled.** The store saves 0.9 s (Go), 0.17 s (ELF) and 18 s (Raw, where `binary_info`
  runs discovery) on every later open. Cross-references are part of that entry; the by-source index is rebuilt
  from it in milliseconds. Strings take 0.1 s on 26 MB. Neither is worth a store entry of its own.
- **Decompilation dominates warm query time,** and nothing reused it: 0.8 s per function on the ELF, 6.2 s on Go
  (the worker request carries every Go type and prototype, rebuilt per call), and asking for the same function
  again costs the same. `find_main`'s 8.5 s on Go is its decompiled preview of `main`.
- **Effective views recomputed everything.** After `integrity_checks`, `function_summary` on the Raw image took
  18 s, because the view rediscovered every function; so does the next call after every edit.
- **Every Raw Cortex-M decompile failed.** The request listed 413,022 code-mode points (one per discovered run;
  one was ARM, the end of the Thumb range), 1.2 M JSON nodes against the worker's 1 M bound, after 2.5 s (18 s
  through an unstored view) of preparation. A first fix that kept only each executable segment's start when every
  point inside is Thumb was withdrawn: a request at an undiscovered even address can still be ARM (`mode_at` falls
  back to `Target::is_thumb`), and the in-process engine keeps a request's `TMode` up to the next point, so with
  fewer points later requests could decode differently. Worker protocol 15 instead packs the points, unchanged,
  into one string (below).
- Then, in order: `list_types` 6.2 s on Go (building the Go type index, once per process), `triage_report` 1.7 s,
  `identify_functions` 1.6 s, `integrity_checks` 0.9 s, `lock_mechanisms` 0.85 s (3 s on the Raw image).
- **A per-call cost after patch authority:** every tool call validates the effective view, which copied the whole
  source, re-loaded it and hashed it: about 450 ms per call on the 26 MB Go binary, 140 ms on the 7.9 MB ELF.

## Decisions

| Candidate | Value | Cost and risk | Decision |
|---|---|---|---|
| Per-function decompilations | 0.8–6.2 s per call, repeated by agents and inside `find_main`, `function_frame` | Key must cover every decompiler input; results must equal fresh ones | **Done** |
| Key effective views by their own bytes | 1–18 s per call and per edit on firmware and static ELF | A view's `Binary` is a function of its bytes, but not the same function as an ordinary open's (no Go symbol recovery), so views are keyed apart from the original | **Done** |
| Code-mode points on large M-profile images | Decompilation of large Raw Cortex-M images through the worker at all | Must not change any decompilation | **Done:** worker protocol 15 packs the same points into one string |
| Skip re-loading a view with no active patch | 300 ms per tool call on Go 26 MB (450 to 151 ms), 90 ms on the ELF | Patch-authority code: keep every check that can fail | **Done** |
| Store inspection and clearing | Operability | Small | **Done:** `rampage server store [--clear]` (CLI only; the default MCP catalog has ~1 KB left) |
| Xref index, string table | ≤0.1 s | – | Not needed (xrefs are already in the discovery entry) |
| Workflow results (`triage_report`, `identify_functions`, `integrity_checks`, `lock_mechanisms`) | 0.2–1.8 s each | Each tool needs an audited key (packs, arguments, annotations it reads, files it reads) | Next slice |
| Go and DWARF type indexes | 6.2 s once per process on Go | A large structure to encode and validate | Next slice |
| Per-function invalidation after a rename or prototype change | Keeps most stored decompilations after an edit | Needs the engine to report what it read (below) | Later slice |

## Stored decompilations

Kept in a new `derived` table of the same SQLite file, beside `analysis`, sharing its size bound and its LRU
eviction (one ordered pass over both tables). A derived key is `<kind>:<hex>`, so `server store` can count per kind.
The schema (and file name) moves to `rampage-analysis-store-v2`, so a version 1 build, whose eviction would not
count decompilations, never writes this file; creating the default v2 file removes the v1 file beside it. Each
write keeps a running total of payload bytes in `meta`, in the same transaction, and evicts only when it passes
the bound, oldest first through an index on `last_used` in each table: a write that fits costs one row update,
not a scan (a cold pass that decompiles every function was O(N² log N) with a scan per write). A missing or
unreadable total is recounted from the rows.

**Key** (`crates/rampage-api/src/decompile_cache.rs`): SHA-256 over

- `DECOMPILE_CACHE_VERSION`, golden-tested like `ANALYSIS_VERSION`: digests of the decompiled C of six functions
  from each of seven fixtures (x86-64, AArch64, Thumb, MIPS, Cortex-M ELF and Raw), recorded per operating system
  (libc++ and libstdc++ builds need not print identical C), fail the suite when they change without a bump; a
  function that fails to decompile is recorded as an error, and an OS without a recording is only reported;
- the discovery key (input bytes, image, format, Raw interpretation, rampage version, executable), which fixes the
  analysis the decompiler reads (function bounds, code modes);
- the function's start;
- the decompiler options (`{:?}` of compiler, platform, BE8; the executable is in the key, so its formatting cannot
  drift);
- where it runs: in process, or the worker with its limits and its resolved executable's path, size and mtime;
- `Annotations::decompile_fingerprint`: names, signatures, types, type libraries, debug types, globals, local
  names and types, type hints, data and operand types, patches and peripherals. It destructures `Annotations`
  field by field, so a new annotation field fails to compile until someone decides whether it belongs.

Also checked before every lookup and write: the binary's file has not changed in place since it was opened
(`validate_available_backing_source`). The key hashed the bytes as loaded; a changed file is decompiled as without
a store, which refuses it where a fresh decompilation would.

Not in the key, on purpose: comments and the findings ledger (no decompiler input reads them; checked by
grepping the planners and by the equivalence tests) and data packs (no decompiler input reads them).
`GHIDRA_INSTALL_DIR` disables the cache, since external specifications can change without rampage knowing.

**What is stored:** the function's name, C, language id, tokens and structured result. `recovery_status` and
`variables` are recomputed from the structure, as both paths compute them. The Objective-C send and register-field
comments are added after the lookup, as before. Only successful results are stored; errors are recomputed.

**Placement:** the lookup in `Project::decompile_guarded` comes after every validation that can refuse the call
(replay sources, encrypted regions, file-backed code, debug-type options) and before automatic type propagation,
the most expensive preparation step. A hit is returned as is. The write happens after the result is built, outside
the decompiler lock in process, and waits at most 200 ms for another writer.

**Untrusted rows:** the store's checksum; the framing (magic, kind tag, the entry's own key, so a valid row copied
under another key is refused); a strict serde shape (`deny_unknown_fields`); the function address; every token
span inside the code and on a character boundary; at most 32 MiB. Anything else counts as `rejected` in
`binary_info`'s `analysis_store.decompilations` (with `last_rejection`) and decompiles afresh.

## Incremental re-analysis after edits

### What this slice does

Invalidation by key, per binary:

| Edit | Discovery | Stored decompilations |
|---|---|---|
| Comment, finding | Kept (never depended on annotations) | All still hit |
| Rename, signature, type, global, local, type hint, data/operand type, peripheral map | Kept | None hit; each recomputed when next asked for and stored under the new key |
| Patch | A new key (new bytes): rediscovered once, then stored | New keys |
| Undo/redo back to an earlier state | Kept | The earlier state's results hit again |

On an effective view, an edit builds a new view over the same bytes, which now reuses the stored discovery (and,
after a comment, the decompilations) instead of starting over. The first view over some bytes still analyses once:
views are keyed apart from the original, because their loader skips the stripped-Go symbol recovery an ordinary
open runs. That entry is stored, so later sessions hit it.

### Why not finer yet

A finer rule would keep the decompilations an edit cannot change. Without knowing what the engine read, no rule
is sound:

- **Renames** are not labels only. Names select library prototypes (`symbols::specialize_imports` matches import
  names against the type libraries), the compiler specification's call fix-ups match callee names (`__chkstk`,
  `_alloca_probe`), a `::` in a name makes a namespace, and a global name can collide with a local's. A caller
  shows the callee's name, but also a constant the decompiler resolved through a pointer table, whose address
  appears in no cross-reference of the caller.
- **Prototype changes** reach callers (argument recovery) and, through automatic type propagation
  (`propagation::lazy_context`, up to eight functions), callees and siblings.
- **Types** (`types`, `type_library`, `debug_types`) are global declarations any function may use.

### Design for the per-function slice

1. **Record what the engine read.** rampage fills the engine's scope and type factory before decompiling
   (`symbols::apply`), and the engine looks symbols, prototypes and types up there while it works. Instrument those
   lookups: record, per decompilation, the addresses whose symbol or prototype was looked up and the type names
   resolved, and return them with the result (worker protocol and in-process alike).
2. **Key on what was read.** Store the decompilation under a coarse key that leaves out names and prototypes, plus
   a dependency set: (address, name, prototype) for every queried address, and the names of the types used. On
   lookup, recompute the dependency fingerprint from the current annotations; a match is a hit. A rename then
   misses only for the functions that looked the renamed address up.
3. **Re-render instead of re-decompiling** a rename whose only effect is a label: allowed when the dependency set
   shows the address was looked up for display only, the old and new names select no prototype or fix-up, and
   neither has a `::`. Substitute the token text by span and shift later spans. The equivalence tests compare the
   re-rendered result with a fresh decompilation.
4. **Propagation** stays inside the key: the propagation context's own fingerprint (the functions and hints it
   derived) becomes part of the dependency set.

Function bounds: no annotation defines or moves a function today, so discovery never depends on an edit. If one
is added (an analyst-asserted start, a bound), discovery becomes keyed by those annotations, and re-discovery can
be local: re-run discovery from the new start with the existing functions as barriers, then recompute the
cross-references of the functions whose blocks changed, and invalidate the decompilations of those functions and
of their callers. The equivalence rule below still applies.

### Correctness rule

An incremental result must equal a from-scratch analysis with the same annotations. The tests
(`crates/rampage-api/tests/decompile_cache.rs`):

- `stored_decompilations_equal_fresh_ones`: on seven fixtures (x86-64, AArch64, Thumb, MIPS, x86-64 with types,
  Cortex-M ELF and Raw), a storeless project decompiling in reverse order, a cold store in order, and a warm store
  from another session all produce identical results (errors included), and the warm one entirely from the store;
  the `decompile` tool's output matches too.
- `edits_invalidate_exactly_the_decompilations_they_can_change`: after a comment, a rename and a signature, each
  result equals a fresh storeless project with the same edits in the same order; the comment keeps every hit, the
  others recompute; undoing returns to the earlier hits.
- `effective_views_reuse_stored_analysis_across_edits`: a patched view gets its own entries and answers as a
  storeless patched view; with the patch undone, the view is keyed apart from the original and answers as a
  storeless view; a comment builds a new view that reuses its discovery and decompilation; patching again returns
  to the patched entries.
- `a_decompilation_does_not_depend_on_what_the_engine_decompiled_before`: on the seven fixtures, each function
  decompiled alone in a fresh project equals the same function decompiled after all the others in one engine,
  also with a signature on one of them. A stored result is served to every later process, so a history-dependent
  engine would spread its first answer.
- Review fixes: `a_file_changed_in_place_is_decompiled_as_without_a_store` (with and without a signature),
  `an_oversized_row_is_refused_unread`, `a_damaged_running_total_is_recounted`, the running total equal to the
  rows after writes and eviction, `clear_refuses_a_file_that_is_not_a_rampage_store`, and
  `history_validation_projects_never_use_the_analysis_store` (patch history validation builds a throwaway
  project over materialized bytes; it no longer files its analysis under the plain key of those bytes).
- Worker path (`crates/rampage-worker/tests/decompile_store.rs`, always run: the crate's tests have this build's
  worker): cold then warm stores through the supervised worker equal a storeless worker project on an ELF and a
  Raw Cortex-M image, the warm one entirely from the store, and an in-process project never reads the worker's
  entries.
- Protocol 15 (`worker::packed_code_mode_tests`, `crates/rampage-worker/tests/raw_code_modes.rs`): any point list,
  in order and with repeats, decodes back to exactly itself; malformed packing is refused; a 500,000-point request
  passes the preflight; the worker decompiles with 400,000 points exactly as the engine does in process. An ignored
  test runs the same comparison on a large Raw image named by `RAMPAGE_TEST_LARGE_RAW`.
- `the_worker_setting_and_decompiler_options_are_part_of_the_key`: an in-process result is never served to a
  project whose worker cannot start, and other options never reuse the default options' result.
- Corruption: `damaged_misfiled_and_foreign_rows_are_refused_and_decompiled_afresh` (a flipped byte, truncated or
  extended JSON behind a matching checksum, a body for another function, a whole valid row filed under another key,
  a foreign schema) and `truncated_and_garbage_store_files_fall_back_to_fresh_decompilation`; unit tests of the
  framing and the body decoder.
- `the_size_bound_counts_stored_decompilations_with_discovery`, and a CLI test of `server store` and `--clear`.
- The existing discovery equivalence tests (`analysis_cache.rs`) are unchanged and pass.

## Concurrency, untrusted files and size

Unchanged in kind from discovery: SQLite WAL, a read is one statement, writes are immediate transactions that wait
at most 200 ms and are skipped when the store stays busy, use-time refreshes never wait. Several MCP servers, CLI
calls and the UI share one file. Store files are untrusted: any inconsistency is a miss that recomputes, never an
error or a partial result. One bound (`RAMPAGE_ANALYSIS_CACHE_MAX_MB`, default 1 GiB) covers both tables; eviction
drops least recently used rows of either kind. A decompilation row is its JSON (135 KB for a large Go function);
rows over 32 MiB or half the bound are not stored. `rampage server store` reports entries and bytes per kind,
`--clear` deletes the file and its WAL.

## Results

After this slice, same method and functions, all commits in, worker protocol 15 included (the "edit" rows are
new; "(err)" on f0 is the response-size limit after a full decompilation, and `function_summary` on Go is refused
for that address before and after):

| Stage | Go 26 MB: cold / warm (ms) | ELF 7.9 MB: cold / warm (ms) | Cortex-M Raw 3.7 MB: cold / warm (ms) |
|---|---|---|---|
| load (binary_info) | 45 / 45 | 6 / 6 | 15,344 / 285 |
| discovery (list_functions) | 942 / 64 | 166 / 11 | 11 / 11 |
| xrefs to a function | 0 / 0 | 0 / 0 | 9 / 9 |
| strings (first page) | 106 / 105 | 6 / 6 | 24 / 24 |
| strings contains | 5 / 5 | 0 / 0 | 7 / 7 |
| identify_functions | 1,582 / 1,592 | 355 / 361 | 688 / 678 |
| capabilities | 22 / 22 | 2 / 2 | 9 / 9 |
| find_main | 8,392 / 67 | 978 / 32 | 1,466 / 75 |
| triage_report | 1,699 / 1,722 | 330 / 323 | 671 / 687 |
| lock_mechanisms | 820 / 816 | 190 / 191 | 3,031 / 3,074 |
| integrity_checks | 909 / 895 | 615 / 616 | 893 / 898 |
| function_summary | 217 (err) / 158 (err) | 213 / 60 | 15,089 / 91 |
| endpoint_inventory | 395 / 392 | 24 / 24 | – |
| list_types | 5,954 / 5,800 | 544 / 534 | – |
| decompile f0 | 6,106 (err) / 170 (err) | 724 (err) / 67 (err) | 1,503 / 30 |
| decompile f1 | 6,390 / 166 | 544 / 59 | 1,577 / 27 |
| decompile f2 | 6,397 / 166 | 538 / 56 | 1,489 / 27 |
| decompile f0 again | 176 / 170 | 65 / 63 | 31 / 29 |
| edit: set_comment f1 | 255 / 256 | 79 / 79 | 13 / 13 |
| decompile f1 after comment | 173 / 171 | 58 / 58 | 28 / 27 |
| edit: rename f2 | 262 / 269 | 82 / 82 | 13 / 13 |
| decompile f1 after rename | 5,995 / 168 | 573 / 57 | 1,506 / 27 |
| edit: undo rename | 265 / 261 | 84 / 82 | 14 / 13 |
| decompile f1 after undo | 167 / 166 | 58 / 57 | 29 / 27 |
| binary_info (store status) | 150 / 152 | 46 / 45 | 14 / 14 |

In short:

- **A repeated decompilation**, in this process or a later one, costs 27–30 ms (Raw), 57–67 ms (ELF) and 166–176 ms
  (Go) instead of 0.5–6.4 s; `find_main` drops from 8.4 s to 67 ms on Go, 1.0 s to 32 ms on the ELF and 1.5 s to
  75 ms on the Raw image. On the ELF and Go inputs most of what remains is the per-call validation of the effective
  view that `integrity_checks` switched on earlier in the run (the closing `binary_info` costs 45 ms and 150 ms
  alone); the lookup itself is a few milliseconds.
- **Raw Cortex-M decompilation works through the worker** (protocol 15): 1.5 s cold, 27 ms from the store, where
  every call failed before. With the store off, each still costs 19 s, because every call after `integrity_checks`
  builds an effective view that rediscovers.
- **Edits:** a comment keeps every stored decompilation; a rename recomputes the one asked for (6.0 s on Go, 1.5 s
  on Raw) and stores it; undo returns to the stored results. In the warm run every post-edit decompilation was
  already stored. With the store off, every decompile in these rows costs 5.8 s (Go), 0.7 s (ELF), 19 s (Raw).
- **Effective views:** with the store, the first view over the original bytes analyses once (15.1 s for
  `function_summary` on Raw, stored) and every later view, after each edit, hits (91 ms).
- **Per-call validation after patch authority** fell from 450 ms to 150 ms on the Go binary and from 140 ms to
  46 ms on the ELF, from the two no-patch shortcuts. Edits there fell from 760–810 ms to 255–270 ms (Go) and
  235–250 ms to 79–84 ms (ELF). Raw images validate by interpretation identity and pay almost nothing (14 ms).
- Unchanged, and next in line: `list_types` (5.8–6.0 s on Go), `triage_report` (1.7 s), `identify_functions`
  (1.6 s), `lock_mechanisms` (0.8 s; 3.0 s on Raw), `integrity_checks` (0.9 s).

## Later slices

1. **Per-function invalidation** as designed above (engine read sets, dependency fingerprints, label-only
   re-rendering).
2. **Workflow results** with audited keys: `triage_report`, `identify_functions` (no `apply`, no external
   `database` files, keyed by the pack set's contents), `integrity_checks` without `fix`, `lock_mechanisms`.
   Each needs the annotations it reads (names, for most) in its key.
3. **The Go and DWARF type indexes** (6.2 s per process on the Go binary): encode the index, or keep it in the
   worker.
4. **The per-call effective-view validation:** hash the source once per mapping identity rather than on every
   call, or let a view with no active patch be the original project. This is patch-authority code; it needs its
   own review.
5. **A cheaper first decompilation on Go:** the worker request carries every Go type and prototype each time
   (6 s); a persistent worker, or a request that sends only what the function references, would cut the cold
   cost that the store cannot.
6. **Views that share the original's entries:** load views with the same recovery as an ordinary open (which
   also gives patched stripped-Go views their recovered names), then key a view with no active patch like the
   original. Until then the first view over some bytes analyses once per store.
7. **Per-revision annotation fingerprints:** `decompile_fingerprint` hashes every decompiler-relevant annotation
   on each lookup; cache it per annotation revision if large annotation sets make that visible.
8. **Linux decompile digests:** record `decompile_cache_golden` on Linux (CI or the gcc image) so the version
   discipline is checked there too; today only the macOS digests are recorded.
