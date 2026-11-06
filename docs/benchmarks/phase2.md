# Phase 2 benchmark reports

Part of the [accuracy benchmarks](../benchmarks.md).

## Phase 2.3 fuzzy candidates — no qualified recognition gain

The [pinned fuzzy measurement](phase2-3-fuzzy-2026-10-18.json) inspects three owned checksum/runlength
functions and three unrelated discovered functions in a freestanding x64 ELF corpus. Exact signatures recognize
none. Secondary unique-top candidates are **two correct and two incorrect: 50% top-candidate precision**.
**Zero correct and zero incorrect candidates qualify**, so combined owned recall remains 0/3, not a qualified
recognition gain or 80% acceptance. Correct candidates remain unqualified; no names are automatically applied.

| Held-out function | Top candidate | Score | Result |
| --- | --- | ---: | --- |
| `corpus_crc32` | `corpus_crc32` | 0.443092 | Correct, below threshold |
| `corpus_adler32` | None | — | Insufficient feature evidence |
| `corpus_runlength` | `corpus_runlength` | 0.728846 | Correct, below threshold |
| `application_crc_like` | `corpus_crc32` | 0.373514 | **Incorrect**, below threshold |
| `application_scan` | `corpus_crc32` | 0.363917 | **Incorrect**, below threshold |
| `_start` | None | — | Insufficient feature evidence |

Separate O1 calibration has two positive/two negative samples: threshold **0.75**, margin **0.15**, one correct
and zero incorrect eligible observations. That is calibration, not held-out success or a false-positive guarantee.
Two runs are recorded. The first, zero-gain run stays frozen. The second excludes nonallocated metadata at
address zero from pointer ranges (a mapped-layout fix) and **reuses the same heldout**, not a fresh blind restart. Weights, grids, source
and compiler flags were unchanged between runs. Reference O2, calibration O1 and heldout Os variance was fixed
before scoring. Predictions were frozen before held-out gold was opened. The two correct tops are code-novel
against prior cohorts by the recorded masked instruction-identity check, not qualified or semantic novelty gains.

An additive controlled repeat with a captured existing host collector returned 0 in 1.2279 s: collector and all
nine inputs stayed unchanged, and outputs reproduced run two's 2 correct/2 incorrect tops and zero qualified names.
It used the **same seen holdout**, not a blind restart; source snapshots do not attest the captured binary's build
source, and the missing collector digest of the earlier runs stays explicitly unattested.
The historical API source witness has no retained matching snapshot, so independent source verification is
unavailable; the receipt-time and later byte-pinned API witnesses are separate, not compiled-source attestation.

A separate actual native ELF Project API check used memory-only instances, opened no gold and left source/target
annotation revisions unchanged. Exact candidates retain priority; fuzzy scores are similarities, not identity
probabilities. The source corpus is owned, with no commercial payload, target execution or hardware/plugin claim.
138 signature tests and three focused API tests passed before concurrent FID additions, which then broke
compilation of the post-fix attempts. The [final implementation validation](phase2-validation-2026-10-18.json)
records the passing signature/API libraries, configured FID host workflow, API/CLI/MCP integration,
pack/paging regressions and Clippy. **The bounded Phase 2 implementation is complete; the recall acceptance
target is not met.** Candidate-stage validation fields stay in the measured JSON as measured, not retroactively
changed. The 2.1 sections below are not revised.

## Phase 2.1 bounded SDK/Rust data delivery

The [SDK/Rust delivery evidence](phase2-1-sdk-delivery-2026-10-18.json) accompanies three reviewed
database/index pairs. **Bounded 2.1 delivery is complete**: gzip/index/lazy-loading tests and an independent
publication audit passed. This is not release/CI acceptance or completion of all Phase 2. The original author rows,
raw failures and the 87/80/31-case sections below are not revised; a separate metadata block records the prepared
assets.

| Architecture | Masked entries | Callee keys | Profiles | Revalidated cases | Compressed bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| x86-64 | 11,369 | 822 | 40 | 39 | 825,951 |
| AArch64 | 7,037 | 402 | 28 | 27 | 453,180 |
| i386 | 2,123 | 90 | 15 | 15 | 132,968 |
| ARM/Thumb, unchanged historical asset | 2,117 | 0 | 14 | Not rerun: 14 historical cases | 112,076 |

The three reloaded exports have **zero owned/full wrong or spurious names across 81 freshly revalidated cases**.
Together with 14 unchanged historical Thumb cases, **95 cases are accounted for, not 95 freshly rerun**.
The x64/AArch64/i386 raw recall gates fail in 16/13/5 cases respectively. Low recall remains visible and
does not block this bounded 2.1 delivery; no full Phase 2 recall acceptance is claimed.

| Added native profile | Raw owned correct / truth | Curated owned correct / truth |
| --- | ---: | ---: |
| Zig compiler runtime, x64 | 429/455 | 40/455 |
| Installed musl, x64 | 1,317/1,512 | 1,183/1,512 |
| Zig compiler runtime, AArch64 | 554/559 | 45/559 |
| Zig compiler runtime, i386 | 445/456 | 41/456 |
| Rust core 1.87.0, x64 | 362/499 | 298/499 |
| Rust core 1.99.0, x64 | 353/543 | 302/543 |
| Rust std 1.87.0, x64 | 843/1,183, plus one wrong | 675/1,183 |
| Rust std 1.99.0, x64 | 876/1,235 | 713/1,235 |

All four original Rust databases/cases are included. The raw std 1.87 wrong answer is retained; generic atomic
training-reference conflict rejection and raw exact-fallback withholding remove unsafe answers from the final
union. There is no per-name blacklist, target-gold-driven matching or deletion from owned gold. All previously
recorded profile records are unchanged, including x64's 32 historical and two portable LLVM/glibc records.

SDK O2 and Rust O1 describe harnesses, not native library optimization. Zig compiler runtime is distinct from
the existing LLVM eight-C-unit profile. Generated Zig-cache native archives are byte-pinned, not published
upstream source archive pins; musl's installed header reports 1.2.5, but source revisions remain unknown.
Rust compiler release strings record 1.87.0 and 1.99.0; Linux-musl binary component archives, selected members and
native-input snapshots are verified without installers. Dependency objects are not owned component signatures,
and rlib metadata is excluded from native code without changing archive ordinals. These are captured identities,
not publisher authentication, source-to-binary reproduction or language-version identification guarantees.

The [technical disposition](phase2-1-sdk-disposition-2026-10-18.json) retains eight SDK quarantines:

| Profile | Target | Native diagnostic |
| --- | --- | --- |
| musl | AArch64 Linux-musl | Unsupported ELF text relocation `Aarch64/311`; ownership refused |
| libc++ | x64 Linux-musl | Unsupported ELF text relocation `X86_64/42`; ownership refused |
| libc++ | AArch64 Linux-musl | Unsupported ELF text relocation `Aarch64/311`; ownership refused |
| libc++abi | x64 Linux-musl | Unsupported ELF text relocation `X86_64/42`; ownership refused |
| libc++abi | AArch64 Linux-musl | Unsupported ELF text relocation `Aarch64/311`; ownership refused |
| libunwind | x64 Linux-musl | Unsupported ELF text relocation `X86_64/42`; ownership refused |
| libunwind | AArch64 Linux-musl | Unsupported ELF text relocation `Aarch64/311`; ownership refused |
| Zig compiler runtime | Thumb Linux-musleabi | Capture refuses LLVM `-target-abi=aapcs` and `-float-abi=soft` |

These are native relocation/capture refusals, not recall exclusions;
no further LLVM/ABI repairs are part of this delivery.
Legal texts are copied byte-for-byte; only the two Rust library notice HTML files retain declared upstream
whitespace exceptions. No native archive, binary or private code data is bundled.

The independent live Phase 1 gate is not met. The sections below are earlier, frozen Phase 2.1 checkpoints:
their asset counts and cohort sizes are those of each checkpoint, not of the delivered corpus above.

## Phase 2.1 portable supplement — finite LLVM and glibc source profiles

The [reviewed portable supplement](phase2-1-portable-delivery-2026-10-18.json) passed parent asset tests,
pack integration, Clippy and independent provenance reconciliation—not release/CI acceptance. It preserves retained
measurements and runs no new benchmark. At this checkpoint the x64 pair contains **7,575 masked entries,
670 callee keys and 34 recorded profiles** in 487,527 compressed bytes. Other architectures are unchanged.
The delivery cohort is **87 cases: x64 33 + AArch64 26 + i386 14 + Thumb 14**.

All 33 retained x64 v3 cases have zero wrong/spurious names against full producer-sized twin truth, with
precision 1.0. **Ten cases fail the 80% owned-recall gate**: six LZ4, two OpenSSL and two zstd cases.
The aggregate therefore fails overall; precision-clean delivery is not complete Phase 2 acceptance.

| Portable source profile | Original per-profile owned result | v3 aggregate owned result |
| --- | ---: | ---: |
| LLVM compiler-rt 22.1.8, eight original generic C units | 8/8 | 8/8 |
| glibc 2.40, original `strverscmp.c`, strong `__strverscmp` | 1/1 | 1/1 |

Both profiles use host Clang 22.1.8 at O2, targeting `x86_64-unknown-linux-musl`, freestanding with no CRT and
no target execution. LLVM coverage is not Zig runtime or whole compiler-rt. glibc retains the real weak
`strverscmp` alias under a finite standalone configuration and exact header-byte pins; the vendored musl
header revision is unknown. This is not native configured glibc, full glibc ABI or whole-library coverage.
Archive, source, harness, dependency and tool identities are pinned in the supplement and provenance index.

The explicit `--producer-alias-sets` v3 policy admits verified exact native ELF producer aliases for full-target
grading and unique-strong/weak-alias reference groups, preserving original and selected-definition callee contexts.
Raw proposals are retained verbatim and original owned gold stays strict; strict behavior remains the default. The
glibc 1/1 follows producer facts, not a silent regrade of the frozen strict refusal or v1 glibc 0/1 result.
All 32 historical profile records remain unchanged; nine signature keys were added and 58 conservatively retired
by source-context curation. Generic matching, hash schemes, thresholds and PE/PDB alias policy are unchanged.
Alias metadata does not authenticate a publisher or establish runtime object identity.

The 80-case core and 31-case Windows sections below stay frozen. At this checkpoint **Phase 2.1 is open**,
pending broader SDK/runtime delivery and the Rust/asset validation gate. The independent live Phase 1 gate is
unchanged.

## Phase 2.1 Windows supplement — explicit PDB truth and a declared CRT subset

The [frozen Windows supplement](phase2-1-windows-delivery-2026-10-18.json) extends x64 delivery to
31 mixed ELF/PE cases, all with zero wrong/spurious named proposals after reloading the final exported gzip.
At this checkpoint the x64 asset has **7,624 masked entries, 670 callee keys and 32 recorded profiles** in 487,601
compressed bytes. Together with the unchanged other architectures, the delivery cohort contains 85 cases.

Windows zlib is 54/62 and LZ4 80/104 for both requested harness optimizations; LZ4's recall failure stays
a failure. The added MinGW profile is exactly nine GLOBAL procedures from the declared `pesect.c` unit: 9/9 correct,
zero wrong/spurious, with the selected archive member/object hash checked against the collector's one-object receipt.
This is not whole-CRT coverage or coverage of imported Windows DLL implementations. The header identity is
15.0.0 alpha; no source-release commit is inferred. An attempted indiscriminate CRT whole-archive link failed and
was not substituted for this predetermined compatible subset.

Both PE reference and target PDBs are explicit, hash-bound and image-identity checked. Stripped matching targets
receive no PDB names. Every nonlegacy database has a validated case association. The exact frozen musl input is
the only x64 legacy exception; its original source provenance is unavailable, so the report deliberately does
**not** claim completely attested historical training provenance. All case reference inputs are checked separately.
The sections below stay frozen. At this checkpoint Phase 2.1 awaits the remaining SDK/runtime corpus delivery;
the live Phase 1 gate and Phase 2 recall failures are unchanged.

## Phase 2.1 delivery slice — four-architecture default corpus

The [frozen delivery evidence](phase2-1-delivery-2026-10-18.json) records 92 raw attempts and
80 final ELF aggregate cases. The default assets at this checkpoint are data-only compressed databases with
per-architecture provenance indexes. **At this checkpoint 2.1 is open for the remaining SDK/runtime and Windows
bundle delivery.** The 80% recall target is a Phase 2 acceptance target; a recorded recall failure is not relabeled as a pass.

| Default architecture | Masked entries | Callee keys | Build profiles | Compressed bytes |
| --- | ---: | ---: | ---: | ---: |
| x86-64 | 7,489 | 664 | 27 | 479,033 |
| AArch64 | 7,066 | 404 | 27 | 433,155 |
| i386 | 2,082 | 90 | 14 | 114,556 |
| ARM/Thumb | 2,117 | 0 | 14 | 112,076 |

These are index-key counts, not unique-function counts or version-identification results. Promoted profiles
cover nine public-library families across the matrix; the x64/AArch64 profiles include reduced OpenSSL and HTTP-only
curl builds. The frozen musl starter files remain unchanged, with their missing historical archive identity explicit.
Requested O1/O2 variants can have identical stripped code/databases and do not establish optimizer diversity.

All 80 final cases have **zero wrong/spurious named proposals against full sized twin truth** after reloading the
actual exported gzip. Input-order and gzip round-trip checks passed. This is bounded evidence, not a universal
precision claim. Per-library and aggregate recall failures remain in the machine-readable evidence.

Unfiltered x64 unions exposed cross-library false names, including Lua's `pairscont` being called
`ZSTD_defaultCLevel`. Full training-reference conflict checks remove those collisions without exporting reference
answers. The hardened per-profile AArch64 OpenSSL run has two wrong names through raw exact fallbacks;
those raw results remain frozen. The final corpus withholds raw exact fallback answers across all profiles,
preserving masked/callee-qualified answers and leaving generic matching schemes and user database priority unchanged.
It removes 21, 198, 23 and 70 exact answer keys from the respective x64, AArch64, i386 and Thumb candidates.

One zstd attempt had collector executable hash drift during a local rebuild. Its raw verdict is retained but
invalidated; the replacement uses frozen tools. Pre-hardening configured-script attempts are also retained and not
used for promotion. The final validation uses a global held-out image split and complete atomic reference batches.

Live MCP samples loaded hash-checked JSON views of these gzip artifacts, with no writes: the four zlib targets
returned 79/92/52/39 total names, including runtime names. These are whole-result totals with two detail rows sampled,
not owned-library recall or independent MCP precision scoring. The running server's built-in corpus was not restarted;
compiled default-loader/index tests and 17 pack integration tests separately exercise the new registrations.
The first attempt to pass a gzip directly as a user database failed because that live path accepts JSON; it remains
recorded rather than omitted. Full API library tests passed with two test threads after a separate 120-second timeout.

Windows x64 producer validation separately measures zlib at 54/62 and LZ4 at 80/104 for both requested optimizations,
all zero wrong/spurious. These rows do not claim Windows profiles in the promoted indexes. No target programs,
commercial inputs, release tags or CI dispatches are involved. The independent live Phase 1 gate remains unchanged.
See the [corpus reference](../signature-corpus.md) for ownership, curation and reproducibility limits.

## Phase 2.1 parallel slice — SQLite, aggregate precision and Thumb discovery

**Source slices:** corpus/diagnostics `5f5a7e4`, EHABI discovery `1b67d7c`.
The [pinned evidence](phase2-1-parallel-2026-10-18.json) binds the existing raw reports and their
embedded collector/helper/executable hashes. Read-only hashing of the committed collector sources matches
those embedded source hashes; this is not an independent rebuild or attestation of every executable dependency.
**This slice does not complete Phase 2.1 and promotes no default database.** It revises no other published
measurement.

| Owned-library profile, O1 | Correct / truth | Missed | Wrong / spurious | 80% recall gate |
| --- | --- | --- | --- | --- |
| SQLite 3.46.1, x64 | 243/262 (92.7481%) | 19 | 0 / 0 | Pass |
| SQLite 3.46.1, AArch64 | 201/262 (76.7176%) | 61 | 0 / 0 | **Fail** |
| LZ4 1.10.0, i386 | 83/104 (79.80769%) | 21 | 0 / 0 | **Fail**, not rounded to 80% |
| LZ4 1.10.0, Thumb before EHABI | 2/104 (1.9231%) | 102 | 0 / 0 | **Fail** |
| LZ4 1.10.0, Thumb after reviewed EHABI | 73/104 (70.1923%) | 31 | 0 / 0 | **Fail** |

SQLite is the single-threaded, no-load-extension amalgamation (`SQLITE_THREADSAFE=0`,
`SQLITE_OMIT_LOAD_EXTENSION`), not full SQLite SDK coverage. Truth is externally visible strong ELF functions;
local, hidden and weak functions remain excluded. No bundled database is available for i386/Thumb; the raw
reports nevertheless measure an empty-database baseline: 0 correct, 104 missed, 0 wrong/spurious, precision and
recall both 0.0. This is not bundled-database recognition coverage. The Thumb rows are paired on identical
reference, target and database digests, with zero callee keys: neither target gold-name seeding nor a
confidence-threshold change explains the gain.

### Same-architecture serialized aggregate

SQLite + LZ4 + the existing musl database are combined as a collision-preserving union, not a priority overlay.
Both runs score the reloaded gzip artifact. Forward, reversed and rotated input orders export identically, and
gzip round trips preserve the export; these are three checked orders, not every possible permutation.

| Aggregate / target | Owned correct / truth | All named proposals correct / proposed | Full sized-twin truth | Target gate |
| --- | --- | --- | --- | --- |
| x64 / LZ4 | 80/104 | 154/154 | 866 | **Fail** |
| x64 / SQLite | 243/262 | 342/342 | 2288 | Pass |
| AArch64 / LZ4 | 68/104 | 160/160 | 971 | **Fail** |
| AArch64 / SQLite | 201/262 | 304/304 | 2387 | **Fail** |

Every case has all-named precision **1.0**, with zero wrong/spurious names against canonical sized symbols from
its verified stripped/symbolized twin. That is precision of actual proposals, not complete library or runtime
coverage. **Both aggregate runs fail overall.** No averaging overrides a failed target. The x64 LZ4 aggregate
loses one name (`LZ4_versionString`) to a cross-library collision, reducing its per-library 81/104 to 80/104.
Case receipts bind the actual reference/object/collector hashes and load-image-equivalent twins. Reference and
object provenance remains a recorded builder assertion, not independently rebuilt source proof. Unsized functions
and alias-set reconciliation are outside this full-twin gold scope.

### Paired discovery evidence and limits

The full pre-EHABI Thumb trace has 100/104 owned target starts unavailable. A pre-final-review EHABI
matrix has 0/104 unavailable; the final reviewed 73/104 report omits the matrix, so that earlier diagnostic is not
silently represented as a final-review full trace. Start recovery does not establish correct complete boundaries
or guarantee a name: the final recall still fails.

Actual paired MCP `entry_diagnostics` receipts on an owned stripped Thumb fixture change the distinct entry from
zero metadata records / `caller_address` to one record / `function_starts`. A coalesced interior remains at zero
records / `caller_address`; EHABI range interiors are not expanded into invented starts. The baseline MCP binary
revision is **unattested** (`runtime_binary_revision_attested=false`), and the after receipt records a worktree
measurement after rebuild/reconnect, not an exact-source binary attestation. Metadata candidates are evidence,
not complete boundary proof. No target execution or live model task is claimed.

The remaining roster/version/optimization/Windows matrix, failing recall profiles, broader aggregate evaluation
and reviewed bundle promotion are not covered by this slice. This report performs no new builds, tests or
model runs and does not earn Phase 1 live sign-off.

## Phase 2.1 pilot — library corpus and compressed databases

**Implementation slice:** `198c024`; [pinned measurements](phase2-1-pilot-2026-10-18.json).
**This pilot does not complete Phase 2.1.** These are generated, source-known public-function experiments, not live agent
tasks, version attribution or completion of the roadmap library/version/architecture matrix.

| Library/build | x64 correct / truth | AArch64 correct / truth | Gate |
| --- | --- | --- | --- |
| zlib 1.3.1, Z_SOLO units, O1 | 56/62 (90.3%) | 51/62 (82.3%) | Both pass |
| Lua 5.4.7, O1 | 152/154 (98.7%) | 145/154 (94.2%) | Both pass |
| LZ4 1.10.0, LZ4/HC/xxHash units, O1 | 81/104 (77.9%) | 68/104 (65.4%) | **Both fail** |

All six after-results have zero wrong and zero spurious names. The bundled musl baseline correctly names none
of these owned library functions; it makes one wrong proposal each on the x64 Lua/LZ4 targets. Baseline recall
uses the owned addresses, counting unrelated runtime proposals separately. After scoring penalizes every
non-truth proposal. The pipeline exits 1 because both LZ4 profiles miss the 80% floor; no aggregate average
overrides those failures, and no pilot DB is promoted into default identification.

The offline pipeline checks source archive hashes and Zig 0.17.0, records exact commands/tool/artifact identities,
builds distinct harnesses and verifies stripped load-image equivalence. Truth covers externally visible strong
ELF definitions only; local, hidden and weak coverage is excluded. Reference-only non-library bodies retain
negative collision evidence but cannot become exported names. Scoring reloads the actual gzip artifact.

Diagnostic runs before the pinned run had a report-key mismatch, linker GC despite whole-archive extraction,
and hidden globals localized at link time. GC-enabled linked-subset results have different denominators and are not
silently regraded as full-library results. The pinned run disables GC, refuses missing public definitions and
retains both LZ4 failures. Additional versions, libraries, optimization profiles, i386/Thumb/Windows coverage,
aggregate-DB evaluation and bundle promotion are not covered by this pilot.

The existing musl recognition data is unchanged. Compressed starter assets total **16,539 bytes**, versus
29,338 JSON bytes, with parsed per-architecture caches and metadata-only pack listing. User overlay precedence
is unchanged; corpus union instead preserves ambiguity. Changed-crate suites, MCP regression, scoped Clippy,
15 Python tests, Ruff/ty and independent reviews passed. Five cache/capture path tests fail without the canonical
`TMPDIR`; with it, those five and the full suite passed, with no related production change. This pilot does not
revise the Phase 0/1 measurements or live Phase 1 sign-off.

See [signature corpus pipeline](../signature-corpus.md) for reproduction. The runner never executes target code
or downloads sources; only public-source inputs belong in this corpus.
