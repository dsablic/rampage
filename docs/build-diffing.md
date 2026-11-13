# Build matching and annotation transfer

`transfer_annotations` (MCP, `core` group) and `rampage annotation transfer` (CLI) carry the annotations of a build
you have already analyzed over to another build of the same program: version N+1, a rebuild, a patched copy.
Functions are matched one-to-one across the two builds, each match with a method and a confidence, and every
saved annotation of the source build is placed at its counterpart in the target or reported as not transferred
with the reason. `diff_builds` remains the quick report of what changed; this is the tool that moves your work.

## Matching

Stages run in order; each only considers functions no earlier stage matched, and each pairs only evidence that is
unique on both sides. Evidence that fits more than one counterpart (two identical wrappers, a hash shared by
stubs) leaves the functions unmatched and listed under `ambiguous`: nothing is guessed.

| Method | Confidence | Evidence |
| --- | --- | --- |
| `exact_bytes` | 1.0 | identical body bytes (at least 8 bytes) |
| `symbol_name` | 0.95 | a symbol, export or stub name found once in each build (user names are not used) |
| `masked_hash` | 0.9 | the same masked signature hash: instructions equal once addresses and relative operands are wildcarded |
| `unique_string` | 0.8 | a string (6+ characters) referenced by exactly one unmatched function in each build |
| `call_graph` | 0.75 | call-graph propagation from matched callers by call-site position, two-sided and anchored (`rampage_signatures::CallGraph`, as the flywheel uses), bodies within a factor of two in size |
| `call_position` | 0.6 | the same propagation, for a callee that makes no calls and whose masked hash differs: only its position supports it, and a replaced helper sits at the same position |
| `neighbourhood` | 0.6 | the same matched callers and callees, found once in each build, bodies within a factor of two in size |

Strings and propagation repeat until they match nothing; then one neighbourhood pass runs and, if it matched
anything, the loop starts again (at most 16 rounds). A derived stage builds only on matches at least as confident
as itself: strings are unique among functions not matched at 0.8 or better, and propagation starts only from
matches at 0.75 or better. So a 0.6 match never yields a match scored above 0.6. A match is `changed` when neither its
bytes nor its masked hash agree; that is the changed-function report (`list: "changed"`), with `added` (only in
the target) and `removed` (only in the source).

## Transfer

The source build is opened read-only with its saved log (`<file>.rampage`). Names, comments, signatures, types and
globals are placed as follows:

- at a matched function's entry: at its counterpart's entry;
- inside a function: by offset, only when the matched bodies have the same size and the same bytes or masked hash;
- on data: through a symbol of the same name in both builds, else through the data references that same-layout
  matched functions make at the same instruction offset, when all of them agree on one target (`via:
  "data_reference"`).

Each source annotation gets a status: `transfer`, `already_present` (the target has the same value, or the name is
already its symbol), `conflict` (the target has a different value there, a name would hide a different symbol of
the target, the name is used elsewhere, or two annotations land on one address), `below_threshold` (matched under
`min_confidence`) or `not_transferred` (with a reason). Local names and types, type hints, data and operand types,
type libraries, debug types and patches are listed as not transferred.

The call previews by default. `apply: true` writes the `transfer` rows as ordinary annotation batches of at most
1000, each one undo step (N batches take N undos); the first batch also records a findings-ledger entry with the
source SHA-256, the threshold and the counts per method and field. Each batch re-checks under the log lock that its
targets still hold no other value, so an edit made after matching is never overwritten: that batch is refused.
A refused first batch writes nothing and is an error; a refused later batch leaves the earlier ones written, and
the result says `partially_applied` with `applied.error`, `batches` against `batches_needed`, and which rows were
not written. `min_confidence` (default 0.7) selects the methods; the default leaves out `call_position` and
`neighbourhood` matches.

The source build's analysis and the matching are kept for the latest pair of builds (keyed by this build's image
hash and the source file's path and hash; the source log is re-read each call), so paging and a following apply
cost little; `reused_matching` says when they were reused.

## Arguments and result

| Argument | Meaning |
| --- | --- |
| `from` | path of the analyzed source build (same architecture) |
| `apply` | write the transfers (default false: preview) |
| `min_confidence` | 0 to 1, default 0.7 |
| `list` | `transfers` (default), `matches`, `changed`, `added`, `removed` or `ambiguous` |
| `offset`, `limit` | paging, limit 1 to 1000 (default 100); pages also stop at 48000 JSON bytes |

The result always carries `matching` (functions per side, matched by method, unchanged, changed, added, removed,
ambiguous, rounds), `annotations` (counts per status, transfers per field and method), `applied` after a write
(`changed`, `batches`, `batches_needed`, `provenance_finding`, `error`), `reused_matching`, the selected page (`rows`, `total`, `next_offset`, `byte_capped`)
and `notes` on what matching does not establish.

CLI:

```sh
rampage annotation transfer new.so --from old.so                  # preview
rampage annotation transfer new.so --from old.so --list changed    # changed-function report
rampage annotation transfer new.so --from old.so --apply           # write, then `annotation list`
```

## Acceptance: zlib 1.2.13 to 1.3

`tools/transfer-acceptance.py` downloads both pinned releases (SHA-256 checked), builds them with zig cc `-O2` for
x86-64 and AArch64 as a shared library (stripped to its dynamic exports) and as a static executable (every zlib and
musl function linked, no symbols at all), names every function of the stripped 1.2.13 build through its log from
the unstripped twin's symbols, transfers to stripped 1.3 and scores against 1.3's symbols. Unchanged functions are
those with an identical body in both sources after comments and whitespace (1.3 rewrote every K&R header, so
headers are not compared). Results (2026-11-13, default threshold; unchanged after the derived-confidence and
call-position rules, which turned 5 AArch64 call-graph matches into `call_position`):

| Build | Unchanged | Matched correctly | Names transferred correctly | False matches |
| --- | --- | --- | --- | --- |
| x86-64 shared | 112 | 100% | 100% | 0 of 171 |
| AArch64 shared | 112 | 100% | 100% | 0 of 171 |
| x86-64 static, no symbols | 113 | 90.3% | 90.3% | 0 of 849 |
| AArch64 static, no symbols | 113 | 90.3% | 89.4% | 0 of 964 |

Ten of the eleven unchanged functions missed in the static builds are byte-identical twins nothing calls
(`adler32_combine`/`adler32_combine64`, `crc32_combine`/`crc32_combine64`, `crc32_combine_gen`/`..64`,
`gzoffset`/`gzoffset64`, `gztell`/`gztell64`): no evidence tells the two apart, so they are reported as ambiguous
rather than guessed. The AArch64 gap between matched and transferred is one correct `neighbourhood` match below the
default threshold. In the shared builds the exports anchor most matches; the static builds show the stages
without any symbol (exact bytes 605/793, masked hash 227/137, call graph 9/6, call position 0/5, neighbourhood
6/21, unique string 1). No match of any method was false, and no wrong name was written.

Run it with `tools/transfer-acceptance.py --rampage target/debug/rampage` (zig 0.17, llvm-strip); `--json OUT`
writes per-method counts, the missed functions and any false matches.
