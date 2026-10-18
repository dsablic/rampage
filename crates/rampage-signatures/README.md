# Signature database storage

The starter `data/musl-*.json` files remain the source records. Their deterministic
`.json.gz` companions contain exactly the same bytes (gzip mtime zero, no filename).
Compression changes storage and loading only: it does not change recognition,
hash schemes 1 or 2, architecture checks, or the native identification confidence gate.
Each architecture's parsed starter database is cached separately on first use.
`bundled_ref` borrows that cache; `bundled` returns an owned clone for compatibility.
`bundled_counts` lists the frozen asset counts without parsing or decompressing.

`SignatureDb::from_gzip` accepts one complete gzip member and validates the checksum,
length, strict JSON fields, unique keys, canonical lowercase SHA-256 hashes and
nonempty names (at most 4096 UTF-8 bytes, without NUL). It rejects trailing data,
concatenated members, truncation, unknown schemes, and keys that are both ambiguous
and answered. The limits are 64 MiB compressed, 256 MiB uncompressed and one million
total keys across all maps and ambiguity sets. Empty databases are valid; empty
gzip payloads are not databases. `to_gzip` uses the same limits and deterministic
ordered JSON with gzip mtime zero. Ordinary `from_json` semantics are unchanged.

Use `combine` for a corpus union: conflicts remove answers permanently, including
exact and callee-key conflicts. It requires the same architecture and scheme and
leaves the receiver unchanged on mismatch. In-memory fallback evidence survives a
union; evidence omitted from a saved database cannot be reconstructed. Use `merge`
only for intentional user-priority overlays, where the incoming database wins.

## Read-only match diagnostics

`explain_in` reports the existing matcher's gates, key tombstones and lookup result without changing matches
or the database. Callee labels remain caller-supplied: bounded previews, full-name hashes and omitted counts
preserve their limits. Diagnostic names are not independent function-identity or execution proof.

## License and provenance

The crate retains the workspace Apache-2.0 license. Compression does not add a new
signature source or alter the existing starter databases' provenance or applicable
licenses. The compressed copies are not a new recognition corpus. Source catalog
and provenance metadata belong outside the data-only JSON schema.
