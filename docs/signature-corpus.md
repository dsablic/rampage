# Signature corpus pipeline

The offline pilot builds pinned zlib, LZ4, Lua, SQLite, zstd and mbedTLS references and distinct target
programs. It never executes target code or downloads sources. Generated artifacts go into an empty, explicit
`target/signature-corpus/RUN` directory; the pilot does not overwrite the bundled databases.

```sh
cargo build --locked -j 2 -p rampage-eval --bin rampage-eval --example signature_corpus
tools/gen-signatures.sh --list
tools/gen-signatures.sh --source-cache target/phase2-1/sources \
  --output-dir target/signature-corpus/lua-pilot --only lua \
  --target x86_64-linux-musl --optimization O1
```

Supply archives listed by the recipe manifest in the read-only cache. Profiles select exact versions and
allowlisted family harnesses; original IDs/defaults remain unchanged. Archive digests and the exact
Zig 0.17.0 version are checked before compilation. `--only`, `--target` and `--optimization` are repeatable.
`ZIG`, `RAMPAGE_EVAL` and `RAMPAGE_SIGNATURE_CORPUS` select existing producer executables.

| Output | Contents |
| --- | --- |
| `inventory.json` | Selected profiles, outcomes, commands, source/tool/artifact identities and measurements. |
| `builder-report.json` | Library-owned truth, baseline/after precision and recall, disagreements and gate result. |
| `db.json`, `db.json.gz` | The same ordered database in ordinary JSON and deterministic gzip form. |
| `truth.json` | The builder's library-owned truth, not a separately filtered denominator. |

Only externally visible strong function definitions from the explicitly compiled library objects enter measured
truth. Local, hidden, weak and unresolved ownership are not counted as covered. Non-library functions in the reference
provide collision evidence but cannot become exported answers. Scoring reloads the serialized gzip artifact.
Reference/target self-identity is rejected; stripping must preserve load mappings, retained section metadata and
load-image bytes, except the ELF section-table header fields that stripping updates.

The gate requires at least 80% recall and zero wrong/spurious names. Gate failures retain their measurements,
are marked `measured_failed`, and return failure. Unsupported targets are not successful coverage. The Windows
profile is explicitly unsupported by this pilot's ELF strip/truth path; broader versions, libraries and targets
remain required before Phase 2.1 acceptance.

SQLite uses its public-domain amalgamation with thread safety and extension loading disabled. The recipe hashes
the complete license-containing `sqlite3.c`, not a separate license document; this profile is not full SQLite coverage.

zstd materializes only its declared library/license roots; unrelated test symlinks are not extracted or followed.
Global archive validation and byte/entry budgets still apply. mbedTLS uses its unmodified default configuration,
including library self-test entrypoints; that is not typical production-configuration coverage. These profiles
do not execute compression, crypto, networking, or other target code.

## Aggregate validation

The `signature_aggregate` evaluator example accepts repeated `--database` gzip files, `--case` builder reports,
`--target` stripped images and `--symbolized` twins, plus new `--output` and `--report` paths. Associations use
content hashes, not argument order. Inputs must share architecture/scheme; old reports without the shared
validator source hash require regeneration.

It reloads the collision-safe aggregate before scoring each frozen library truth. Every proposed name is also
checked against full verified twin truth, so correct names from other libraries are distinguished from false
positives. Forward/reverse/rotation exports must agree. Failed gates retain all cases and return failure; they
do not promote the database or silently change alias names or recall denominators.

The builder's optional `--diagnostic-limit` (0–512, default 0) emits address-sorted symbol/discovery evidence for
truth rows. It reports actual production gate measures, ambiguity tombstones and bounded missing-callee lists;
omitted rows remain counted. Reference labels and final target proposals are separate inputs. Diagnostics do
not modify matches or establish execution, function boundaries or semantic identity.

The existing no-argument starter generator still rebuilds musl. It now refreshes gzip and small count indexes
together with JSON. Builtin identification lazily decodes each selected architecture once; listing packs reads
only the index. Ordinary user/pack database inputs remain JSON. Corpus combination preserves collisions;
explicit user overlays retain their existing precedence.

Limits: exact-build public-function pilot, not complete library coverage, version attribution, near-miss
matching, FLIRT/FIDBF import or authorization to publish signatures derived from private binaries.
