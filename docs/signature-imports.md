# Signature database input formats

## Native JSON and gzip

The native/PAT user database is consulted before data packs and bundled signatures. Native JSON uses `.json` or an
extensionless filename. `.gz` selects compressed native JSON, not compressed PAT text. Imported namespaces
remain separate from native function hashes; loading a foreign format does not reinterpret its fingerprints
as native hashes.

Inputs must be bounded regular files. The final path component cannot be a symbolic link. Selecting a
database does not execute its metadata or follow source paths recorded in it.

CLI/MCP file admission caps direct native JSON at 64 MiB, PAT at 16 MiB, and compressed gzip input at
16 MiB. Gzip expansion is capped at 256 MiB. The direct core gzip API permits 64 MiB compressed input;
that does not increase the CLI/MCP file-admission limit.

## User-supplied FLIRT PAT

The CLI accepts `.pat` through `identify --db`, and `identify_functions` accepts the same filename through
its `database` argument. PAT text has no architecture header: the target binary supplies the architecture.
Only user-supplied or independently generated patterns are supported; no IDA databases are bundled.

Supported records contain:

- A 32-byte initial pattern with whole-byte `..` wildcards.
- A hexadecimal CRC-window length, CRC16 value and module length.
- Public/local symbol declarations and an optional contiguous tail pattern.
- A final `---` terminator.

The CRC is CRC-16/IBM-SDLC with its final value byte-swapped for PAT. Its window starts at byte 32;
the contiguous tail starts at `32 + CRC length`. Exact module-length equality does not mean every module
byte is constrained: wildcard and uncovered bytes remain unconstrained.

References, negative offsets, unsupported symbol flags and dumpsig tail tuples reject the entire import.
Errors identify the PAT line and reason; a valid prefix is not partially imported after a later error.

Matching requires the complete independently discovered function extent, every pattern/CRC/tail constraint,
the native instruction/content confidence gate, at least six fixed bytes and at least half of the explicit
pattern positions fixed. Only public offset-zero names can name a discovered function. Conflicting names
withhold an answer rather than selecting the first record. These restrictions can reduce recall, especially
for multi-function PAT modules and wildcard-heavy patterns.

CRC-window bytes do not count toward the fixed-byte gate. Wildcard padding beyond a short module is
excluded from the coverage denominator.

Loading and identification are read-only unless exact identification is explicitly applied. Applying a
match does not replace an existing function or analyst name. Native JSON/gzip persistence retains PAT
constraints and suppressed answers without converting them to native hash keys.

### Rust API

```rust,ignore
let database = SignatureDb::from_pat(architecture, pattern_bytes)?;
let json = database.to_json();
let restored = SignatureDb::from_json(&json)?;
```

Use these bounded constructors rather than deserializing `SignatureDb` or `PatternDb` directly through
Serde. Direct `Deserialize` implementations are not exposed because they would bypass input admission.

Corpus-training curation of PAT-bearing databases is unsupported. The checked curation APIs return an
error rather than dropping pattern constraints. User-input consumers should use the checked APIs.

## Ghidra FunctionID

Raw `.fidbf` schema-6 databases use an explicit trusted-host API, not native hash conversion. Packed
`.fidb`, unknown schemas, unsupported table/index layouts and unknown flags reject. Only independently
generated test databases are included; no upstream FunctionID distribution databases are bundled.

`Project::import_fid_signatures` accepts a `FidReader` with explicit absolute JVM, Ghidra installation and
temporary-root paths plus a timeout. It reads the database through a fixed owned bridge, validates the
result, and returns a `SignatureDb` with a separate FID namespace. That namespace survives bounded native
JSON/gzip persistence. No recorded domain/source path is opened. Mixed native/PAT/FID composition is
unsupported rather than silently discarding a namespace or its constraints.

The reader accepts at most 128 MiB of raw database input and a timeout of at most 120 seconds. Namespace
construction also enforces the native JSON persistence budget, so an otherwise readable database can be
too large to import. Failures are transactional; no partial database is returned.

FID hashes require Ghidra instruction masks, operand/register identities, extent ordering and skipper
decisions. Raw p-code and native function hashes are not substitutes. `requires_fid_adapter()` identifies
databases that need the separate consumer.

`Project::query_fid_signatures` uses an explicitly configured `FidHostAdapter` and Ghidra 12.1.4 static
analysis. The target executable is never launched. The host installation and JVM are trusted executable
code, not a sandbox. The adapter binds exported features to the exact input SHA-256 and requires native
discovery extents and confidence gates to agree. Its initial query profile supports standalone x86/x86-64
ELF images without debug/external-debug metadata; unsupported profiles return an error.

Matching checks both FID hashes, both sizes, language/version/compiler identity, thunk/confidence gates
and mandatory relations. Ambiguous and suppressed records remain visible. Hashes are non-cryptographic
and omit some scalar values: a match is not proof of semantic identity, source authenticity or an exact
library release. Queries return paginated read-only suggestions; they never apply names or write project
annotations.

Host analysis has a maximum 600-second timeout. API pages contain 1–256 rows, with offsets at most 100,000
and a 1 MiB report budget. Whole-result totals and continuation offsets remain explicit.

The generic CLI/MCP database loader does not launch external tools. A `.fidbf` filename there returns an
explicit configuration error; use the trusted-host import/query API. A persisted FID namespace is not
silently treated as an empty native database.
