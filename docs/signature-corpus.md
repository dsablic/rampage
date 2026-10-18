# Signature corpus reference

The built-in function databases contain hash/name data from declared public-library builds. They recognize
compatible builds; a match does not identify a library version, authenticate source, or establish complete SDK coverage.

## Shipped artifacts

| Architecture | Masked signature entries | Callee keys | Recorded build profiles |
| --- | ---: | ---: | ---: |
| x86-64 | 7,624 | 670 | 32 |
| AArch64 | 7,066 | 404 | 27 |
| i386 | 2,082 | 90 | 14 |
| ARM/Thumb | 2,117 | 0 | 14 |

Counts describe index keys, not unique recognized functions. The ARM profiles are Thumb builds. The x64/AArch64
indexes include the frozen musl starter inputs; their original source archive identity was not recorded and is
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
commit. Broader SDK/runtime coverage remains separately tracked.

## Recognition policy

Corpus composition uses collision-safe union, not priority overlay. Full named training references supply negative
collision evidence without exporting their runtime, local or harness names. A global image-hash split rejects
training references that are also held-out targets anywhere in the aggregate.
The exact frozen musl inputs are a separately reported legacy exception: their original source-image provenance
is unavailable, so their inclusion does not earn a complete historical training-provenance attestation.

Promoted corpora withhold raw exact fallback answers. Such keys can accidentally coincide across different linked
layouts, even when their masked bodies are already ambiguous. Masked and callee-qualified answers remain available;
the generic matcher, hash schemes, and explicitly supplied user databases are unchanged. Withholding creates
persistent tombstones for known keys. Composition that introduces new keys requires applying the curation policy again.

All 85 current cases used for these four assets have zero wrong/spurious named proposals against full producer-sized
twin truth after reloading the final gzip. PE truth uses checked PDB procedure ranges, not guessed PUBLIC-name sizes.
This is bounded corpus evidence, not a universal precision guarantee.
Per-library and aggregate recall failures remain recorded. The 80% matched-version recall target belongs to Phase 2
acceptance; it is not substituted for the precision checks used to select default artifacts.

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

The installed-runtime producer offers a separate explicit ELF linked-artifact scope. It binds archive members and
actual kept linker-map inputs to raw names, producer ranges and instruction bytes, allowing only supported native
relocation bits to differ. Unsupported relocations, ambiguous ownership and empty truth refuse the scope. This is
not source authentication or general object/archive project loading.

Rust target components can be materialized as data under the ignored target directory without executing installers.
Their archive snapshots, expanded metadata, selected file membership and materialized file hashes are bounded and
checked; receipt file hashes alone do not establish archive membership.

The existing `tools/gen-signatures.sh` wrapper accepts the same corpus arguments. `ZIG`, `RAMPAGE_EVAL` and
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

The original gate still requires at least 80% recall and zero wrong/spurious names. Failed gates retain their
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
complete function boundaries or semantic identity. Old case reports lacking the shared-validator source hash are
not accepted as current aggregate evidence.

The no-argument starter generator still rebuilds musl JSON/gzip/count inputs. It does not rebuild the composed default
corpora; deliberately changing those frozen legacy inputs requires a separately reviewed baseline update.
Ordinary user/pack database inputs remain JSON. FLIRT/FIDBF import, near-miss matching and authorization to publish
signatures derived from private binaries are outside this corpus pipeline.

Generated native programs, PDBs, archives and runtime captures are evaluation inputs, not bundled outputs. Only
reviewed hash/name databases and their provenance data belong in the default signature assets. Existing raw attempts
and frozen baseline reports are not overwritten by a new consumer replay or a later acceptance decision.
