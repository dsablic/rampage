# Signature corpus pipeline

The offline pilot builds checksum-pinned zlib 1.3.1, LZ4 1.10.0 and Lua 5.4.7 references and distinct target
programs. It never executes target code or downloads sources. Generated artifacts go into an empty, explicit
`target/signature-corpus/RUN` directory; the pilot does not overwrite the bundled databases.

```sh
cargo build --locked -j 2 -p rampage-eval --bin rampage-eval --example signature_corpus
tools/gen-signatures.sh --list
tools/gen-signatures.sh --source-cache target/phase2-1/sources \
  --output-dir target/signature-corpus/lua-pilot --only lua \
  --target x86_64-linux-musl --optimization O1
```

Supply the source archives listed by the recipe manifest in the read-only cache. Archive digests and the exact
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

The existing no-argument starter generator still rebuilds musl. It now refreshes gzip and small count indexes
together with JSON. Builtin identification lazily decodes each selected architecture once; listing packs reads
only the index. Ordinary user/pack database inputs remain JSON. Corpus combination preserves collisions;
explicit user overlays retain their existing precedence.

Limits: exact-build public-function pilot, not complete library coverage, version attribution, near-miss
matching, FLIRT/FIDBF import or authorization to publish signatures derived from private binaries.
