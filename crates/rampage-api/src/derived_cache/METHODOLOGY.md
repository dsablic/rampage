# FunctionInventoryCacheV0: frozen experiment

This is historical candidate browsing, not a Program, solver, native-engine, call, xref, type or layout cache.
Reads and publication are explicit. No cached field establishes current function eligibility or authority.

## Decision fixed before measurement

GO requires the median of **three** usable cached FULL REOPEN attempts to be at least **2x faster** than the median
of **three** fresh-discovery attempts on the generated fixture. FULL REOPEN includes fresh project loading, the
complete source dependency key, private cache reading, raw preflight, typed parsing and usable bounded rows.
Fresh includes fresh project loading, global discovery and the **same** bounded row projection. A warm OnceLock
lookup is neither path. No silent retries, tuning before baseline, dropped failures or timing only JSON parsing.

The owned generated ELF contains 2,300 deterministic noinline C functions with conditionals and loops, and
`_start` directly calls every function. The small hello ELF is a control, not a substitute for the generated
fixture. Both use clang's x86_64 Linux freestanding target, no debug info/CRT and Rust's GNU-flavor lld, with no
dynamic dependencies, build ID or ELF timestamp. The source recipe is `tools/ci/function-inventory-oracle.sh`.
Its `--check command [arguments...]` form requires a private TMPDIR, exposes only its owned scratch directory via
`RAMPAGE_FUNCTION_INVENTORY_FIXTURES`, and removes only that directory on exit. Never execute either target ELF.
The count is fixed before the first baseline to exercise default row truncation as well as usable cached rows.

Report each attempt, row counts, truncation and errors. Separately report source-key hashing, discovery,
bounded projection/capture, private publication, private reading/preflight/parsing and full reopen. Capture
includes its source-key check, so its total must not be mislabeled projection-only. RSS is optional; unavailable
is absent, never zero. OS filesystem caches are uncontrolled and must be stated; fresh means project state,
not a claim of cold disk caches. Alternate fresh/cached attempts after the initial explicit publication.

Any failed attempt, missing owned fixture/toolchain, unusable rows or unavailable prerequisite makes the
experiment inconclusive, not a performance success. NO-GO retains only the narrow bounded foundation and
this report; it does not become a performance feature or an invented optimizer.

## Observed result

The selected generated fixture passed the frozen GO threshold. A central integration run measured fresh full
reopen at 92.392333/93.231375/91.928292 ms and cached full reopen at 22.480833/22.047334/21.937167 ms. The medians
were 92.392333 and 22.047334 ms, respectively (4.19x). All three attempts succeeded, with 2,048 retained rows
of 2,301 functions and explicit truncation. The earlier baseline also passed (92.892250 versus 22.562791 ms).

The small two-function control was slower through the cache: fresh 0.303875/0.264625/0.253500 ms versus cached
1.072167/1.106541/1.103709 ms. Its medians were 0.264625 and 1.103709 ms. This is not a generic speedup claim.

Generated-fixture setup discovery was 98.254750 ms; dependency hashing 9.784708 ms; bounded projection
0.892209 ms; capture including its key 19.300834 ms; private publication 29.875750 ms. OS caches were
uncontrolled, all Projects were fresh, and RSS was unavailable. The reader retained the complete key/read/parse
cost. No target ELF was executed. These observations support only the historical-inventory browsing slice.

The [API contract](CONTRACT.md) defines display-only semantics, dependencies, limits and integration prerequisites.

After the annotation-contention corrections, the final three-attempt gate again passed: generated-fixture
medians were 93.860750 ms fresh and 22.412208 ms cached (4.19x). The small control remained slower cached:
0.294333 versus 1.082958 ms. No attempt failed or was retried; this does not establish a general performance gain.
