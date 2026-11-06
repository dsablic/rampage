# Signature corpus reference

The built-in function databases contain hash/name data from declared public-library builds. They recognize
compatible builds; a match does not identify a library version, authenticate source, or establish complete SDK coverage.

## Shipped artifacts

The default databases pass gzip, index and lazy-loading tests and an independent publication audit. They do not
meet the 80% matched-version recall target. The x86-64, AArch64 and i386 counts below are revalidated; the Thumb
database is not rerun.

| Architecture | Masked signature entries | Callee keys | Recorded build profiles |
| --- | ---: | ---: | ---: |
| x86-64 | 11,369 | 822 | 40 |
| AArch64 | 7,037 | 402 | 28 |
| i386 | 2,123 | 90 | 15 |
| ARM/Thumb | 2,117 | 0 | 14 |

Counts describe index keys, not unique recognized functions. The ARM profiles are Thumb builds. The x64/AArch64
indexes include the frozen musl starter inputs; their original source archive identity is unrecorded and
explicitly unavailable. The other profiles record archive digests, compiler identity, requested optimization,
license declarations, recipe fingerprints and an aggregate measurement witness.

Each architecture has a compressed database and a small provenance index. Metadata listing does not decompress
databases. Database loading is cached separately per architecture and checks the index's digest, lengths, target,
scheme and counts. User databases and data packs retain priority over the built-in corpus.
Upstream notices are retained with source/archive and excerpt digests in the data notice index; they are textual
license declarations, not source authentication or a legal determination.

The promoted Linux profiles cover zlib, LZ4, Lua, SQLite, zstd, mbedTLS and libpng; x64/AArch64 additionally include
the reduced OpenSSL and HTTP-only curl profiles. Several libraries have second versions. x64 also includes the
validated Windows zlib/LZ4 builds and exactly nine GLOBAL functions from MinGW's `pesect.c`; this is not whole-CRT
or Windows DLL implementation coverage. The observed MinGW header identity is 15.0.0 alpha, not an attested release
commit. Broader SDK/runtime coverage is not included.

Two portable x64 profiles cover LLVM compiler-rt 22.1.8's eight original generic C units and glibc 2.40's original
`strverscmp.c` translation unit. Their source archive pins, exact compiler/header/harness identities, finite alias
configuration and dependency receipts are recorded in the
[portable supplement](benchmarks/phase2-1-portable-delivery-2026-10-18.json) and the
[`corpus-x86_64.index.json` provenance index](../crates/rampage-signatures/data/corpus-x86_64.index.json).
The portable supplement keeps all 32 earlier x64 records while adding nine and retiring 58 signature keys through
conservative source-callee-context curation. The SDK/Rust delivery keeps all 34 resulting x64 records exactly, plus
all 27 AArch64 and 14 i386 records, and adds installed musl and Zig compiler runtime on x64, Zig compiler runtime
on AArch64/i386, and Rust std/core 1.87.0 and 1.99.0 on x64. See the
[SDK/Rust delivery evidence](benchmarks/phase2-1-sdk-delivery-2026-10-18.json) for current hashes and raw/curated rows.

For installed SDK profiles, index `archive_sha256` fields identify generated native Zig-cache archives, **not
published upstream source archive pins**. Exact installed source/header inventories are retained; musl's header
reports 1.2.5, but source revisions remain unknown. Rust fields identify verified Linux-musl binary target-component
archives, not rust-src; the owned native rlib identities remain in each recipe. Compiler release strings record
1.87.0 and 1.99.0, not authenticated language-version identification from matched signatures. SDK O2 and Rust O1
are harness labels only; native runtime optimization is not inferred. Zig runtime is not the portable LLVM profile.

## Recognition policy

Corpus composition uses collision-safe union, not priority overlay. Full named training references supply negative
collision evidence without exporting their runtime, local or harness names. A global image-hash split rejects
training references that are also held-out targets anywhere in the aggregate.
The exact frozen musl inputs are a separately reported legacy exception: their original source-image provenance
is unavailable, so their inclusion does not earn a complete historical training-provenance attestation.

Promoted corpora withhold raw exact fallback answers. Such keys can accidentally coincide across different linked
layouts, even when their masked bodies are already ambiguous. Masked and callee-qualified answers remain available;
withholding does not affect the generic matcher, hash schemes or explicitly supplied user databases. Withholding creates
persistent tombstones for known keys. Composition that introduces new keys requires applying the curation policy again.

The shipped corpus accounts for **95 cases: 39 x64 + 27 AArch64 + 15 i386 revalidated, and 14 Thumb not rerun**.
The 81 revalidated cases have zero owned/full wrong or spurious names after reloading the exact three exports.
Raw recall gates fail in 16 x64, 13 AArch64 and five i386 cases. All four Rust
profiles are included despite low recall; the raw evidence retains std 1.87's original one-wrong result.
Generic source-reference conflict rejection and exact-fallback withholding remove unsafe answers, not per-name
blacklists or gold deletion. PE truth uses checked PDB procedure ranges, not guessed PUBLIC-name sizes.
This is bounded corpus evidence, not a universal precision guarantee.
Per-library and aggregate recall failures remain recorded. Low recall against the 80% matched-version target does
not block shipping precision-checked databases, and does not replace the precision checks for default artifacts.

Strict canonical-name behavior is the default. Explicit `--producer-alias-sets` enables the revalidated aggregates'
`elf-producer-alias-sets-v3` policy: full-target grading accepts only verified exact native ELF same-range aliases;
reference admission requires a unique default-visible strong definition with only weak default-visible aliases.
Original source-canonical and selected-definition callee contexts remain separate from answer labels. Original
strict owned gold and raw proposals are preserved; the policy does not change PE/PDB alias handling, generic
matching, hash schemes or thresholds. Alias metadata is neither publisher authentication nor runtime object identity.
The strict policy's alias refusal and the v1 policy's glibc 0/1 remain frozen records; v3's actual 1/1 is separate
producer-backed evidence.

Requested O1/O2 variants can produce identical signature databases and stripped images. Those cases remain separate
measurements but do not establish independent optimizer diversity. Bare compiler flags are not evidence of a
prebuilt runtime library's optimization level.

## Producers

`tools/signature-corpus.py` consumes an explicit offline cache of pinned source archives. It checks and extracts the
same bounded regular-file snapshot, records actual commands and artifacts, freezes evaluator/collector executables,
and never runs generated target programs. Configured host scripts run with a clean recorded environment and isolated
home directory. Supported host build tools still execute; this is not an arbitrary-source execution sandbox.

```sh
python3 tools/signature-corpus.py --list
python3 tools/signature-corpus.py \
  --only libpng-1.6.44 --target aarch64-linux-musl --optimization O1 \
  --source-cache "$SOURCE_CACHE" \
  --output-dir target/signature-corpus/libpng-aarch64 \
  --eval target/debug/rampage-eval \
  --builder target/debug/examples/signature_corpus
```

The default ownership cohort consists of externally visible strong ELF definitions or public executable COFF
definitions with checked global PDB procedure ranges. Local/hidden/weak functions are excluded before scoring.
PE production requires separate explicit identity-matched PDBs for both programs and recorded native linker replay
with GC/ICF disabled. Public PDB aliases are not a substitute for sized producer procedure records.

`tools/signature_portable.py` supplies the two finite source profiles through the pinned
[`portable-compiler-rt-fragment.json`](../tests/fixtures/signatures/portable-compiler-rt-fragment.json) and
[`portable-glibc-fragment.json`](../tests/fixtures/signatures/portable-glibc-fragment.json) recipes. Host Clang
22.1.8 compiles original C at O2 for `x86_64-unknown-linux-musl`, freestanding with no CRT; targets are never run.
LLVM's eight-unit subset is not Zig runtime or whole builtins coverage. glibc owns only strong `__strverscmp`;
the weak `strverscmp` alias is retained, not counted as a second owned function. Its finite standalone alias
configuration and exact target-header bytes are pinned, but the Zig-vendored musl header revision is unknown.
This does not establish native configured glibc, distribution libc.a or full native ABI coverage. Complete upstream
legal texts and their source/archive/copied digests are retained in the
[`notices/index.json` notice index](../crates/rampage-signatures/data/notices/index.json).

The installed-runtime producer offers a separate explicit ELF linked-artifact scope. It binds archive members and
actual kept linker-map inputs to raw names, producer ranges and instruction bytes, allowing only supported native
relocation bits to differ. Unsupported relocations, ambiguous ownership and empty truth refuse the scope. This is
not source authentication or general object/archive project loading.

Rust target components can be materialized as data under the ignored target directory without executing installers.
Their archive snapshots, expanded metadata, selected file membership and materialized file hashes are bounded and
checked; receipt file hashes alone do not establish archive membership.

SDK/Rust measured outputs use a clean recorded environment, frozen native input snapshots and explicit native
linker replay with GC/ICF disabled. Only selected component members supply owned signature inputs; unselected
archives and dependency objects do not. Rust metadata members are not native code, but their original archive
ordinals remain part of member identity. Source hashes and native snapshots do not independently reproduce a build.
Complete installed public musl/Zig, related LLVM and Rust MIT/Apache/library notices are retained byte-for-byte;
the two Rust library HTML notices preserve declared upstream trailing-whitespace exceptions without normalization.

Eight technical refusals stay quarantined in the
[SDK disposition](benchmarks/phase2-1-sdk-disposition-2026-10-18.json): AArch64 musl, x64/AArch64 libc++, libc++abi
and libunwind, and Thumb compiler runtime. Their native relocation/capture limits are not recall failures or shipped
coverage. Provisional C++ results and all raw failed attempts are kept separately; the delivery attempts no further
LLVM repairs.

The `tools/gen-signatures.sh` wrapper accepts the same corpus arguments. `ZIG`, `RAMPAGE_EVAL` and
`RAMPAGE_SIGNATURE_CORPUS` select existing producer executables; `--only`, `--target` and `--optimization` are
repeatable. A native tool build is available with:

```sh
cargo build --locked -j 2 -p rampage-eval --bin rampage-eval --example signature_corpus
tools/gen-signatures.sh --list
```

| Producer output | Contents |
| --- | --- |
| `inventory.json` | Profiles, outcomes, commands, source/tool/artifact identities and measurements |
| `builder-report.json` | Owned truth, baseline/after metrics, disagreements and the original gate result |
| `db.json`, `db.json.gz` | The same ordered database as JSON and deterministic gzip |
| `truth.json` | Original library-owned truth, not a newly filtered denominator |

The original gate requires at least 80% recall and zero wrong/spurious names. Failed gates retain their
measurements as `measured_failed` and return failure; unsupported targets are not successful coverage.

SQLite's public-domain amalgamation profile disables thread safety and extension loading. Its license-containing
source file is hashed in full; the distributed notice is a verbatim disclaimer excerpt rather than the amalgamation.
zstd extracts only declared library/license roots and does not follow unrelated test symlinks; global path, byte
and entry checks still cover the archive. mbedTLS uses its unmodified default configuration, including library
self-tests, not a claim about typical production configurations. libpng uses the unchanged prebuilt configuration
header with SIMD options disabled and a separately owned, fixed zlib dependency that is excluded from PNG truth.

## Aggregate validation

`signature_aggregate` requires hash-bound case reports and their stripped/symbolized twins. Repeated images may
share a digest, but every case and every supplied input identity remains accounted for. All named proposals are
graded against full twin truth, not only addresses owned by the library under test.

Default-corpus validation additionally supplies every original training reference and enables raw-exact withholding:

```sh
target/debug/examples/signature_aggregate \
  --database "$DATABASE" --case "$CASE_REPORT" \
  --target "$STRIPPED_TARGET" --symbolized "$SYMBOLIZED_TARGET" \
  --reference "$TRAINING_REFERENCE" --withhold-exact-fallbacks \
  --output target/candidate.json.gz --report target/candidate-report.json
```

Reports distinguish reference-conflict removals from raw exact fallback removals. Forward, reverse and rotated
input orders must produce identical compressed output. A nonzero recall-gate exit retains the artifact and all case
measurements; it does not authorize promotion when wrong/spurious proposals remain.
PE aggregate cases additionally require the actual reference image and explicit `--pdb` inputs for both paired
producer PDBs. Every nonlegacy database must be associated with a validated case; only the two exact frozen musl
digests are admitted as separately disclosed legacy inputs without original case provenance.

The builder's optional `--diagnostic-limit` (0–512, default 0) emits bounded, address-sorted symbol/discovery evidence.
It preserves actual gates, ambiguity tombstones and missing-callee evidence, counts omitted rows, and keeps supplied
reference labels separate from final target proposals. Diagnostics do not change matches or establish execution,
complete function boundaries or semantic identity. Case reports lacking the shared-validator source hash are
not accepted as current aggregate evidence.

The no-argument starter generator rebuilds musl JSON/gzip/count inputs. It does not rebuild the composed default
corpora; deliberately changing those frozen legacy inputs requires a separately reviewed baseline update.
Ordinary user/pack database inputs remain JSON. FLIRT/FIDBF import, near-miss matching and authorization to publish
signatures derived from private binaries are outside this corpus pipeline.

Generated native programs, PDBs, archives and runtime captures are evaluation inputs, not bundled outputs. Only
reviewed hash/name databases and their provenance data belong in the default signature assets. Raw attempts and
frozen baseline reports are never overwritten by a new consumer replay or acceptance decision.

Broader SDK coverage and the recall target are not claimed. User-supplied
[PAT and FunctionID inputs](signature-imports.md) and [fuzzy candidates](fuzzy-signatures.md) are documented
separately.
