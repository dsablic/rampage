# Data-pack reference

A data pack is a directory extending heuristic databases with data only: nothing is downloaded or executed.
Use `--pack DIR` repeatedly, or `RAMPAGE_PACKS` as a platform path list loaded after command-line packs.
A directory supplied twice loads once. Packs load on first use, so CLI commands that consult no database do
not read them. MCP startup can load configured packs to report their status.

`rampage pack list` (compatibility `packs list`) shows effective packs in precedence order and each content's
status. `rampage pack check DIR` (compatibility `packs check DIR`) validates one pack and fails if anything
does not load. MCP `list_packs` belongs to `detection`; detection results retain relevant problems in `warnings`.
The [desktop UI](desktop-ui.md) lists pack status in About and counts problems in its status bar.

## Manifest

Each directory holds `rampage-pack.toml`; unknown fields are rejected.

```toml
name = "example-library"              # letters, digits, -, _ and .; not rampage-builtin or default
version = "1.2.0"
license = "CC-BY-4.0"                  # SPDX expression
source = "https://example.com/library" # provenance
description = "Signatures and rules for an example library"

[[contents]]
kind = "signatures"                   # JSON from function build-signatures / build_signatures
path = "sigs/x86_64.json"
arch = "x86_64"                       # optional, signatures only; must match the database

[[contents]]
kind = "yara"                         # .yar/.yara file or directory
path = "yara"
```

| Kind | Content |
| --- | --- |
| `signatures` | Library-identification JSON database |
| `peid` | PeID `userdb.txt` overlaid for producing-tool detection |
| `yara` | Rule file/directory, compiled in a namespace named after the pack |
| `capa` | Mandiant capa rule file or directory tree; file-scope feature subset |
| `constants` | JSON algorithm tables used by `find_crypto` alongside bundled constants |

## Precedence and validation

For library identification, the first database to name a function wins: user `--db`, then packs in supplied
order, then bundled `rampage-builtin`. Each match names its `source`. PeID, YARA and capa content runs alongside
bundled and user-supplied content. See [library identification](features.md#library-identification) for signature
architecture coverage, confidence gates and library-build specificity.

Every path, including symbolic links, must stay within the pack. Each file is read once with a size cap and
within per-pack/overall budgets; at most 64 packs load. Failed content is reported without preventing other
content from loading. YARA `include` statements are refused in user, pack and agent rule sets: each rule file
must stand alone. A manifest's provenance/license fields describe its data, not authorization to disclose a binary.

## Constant databases

A constants file holds `{"constants": [...]}`. Each entry has:

- `name`, distinct from names in the bundled set and other packs.
- `algorithm` and `kind`: `block_cipher`, `stream_cipher`, `hash`, `mac`, `checksum`, `compression`, `encoding`
  or `public_key`.
- Optional `source`, and exactly one of `bytes` (hex; spaces allowed), `u32` or `u64`.
- For numeric arrays, numbers or `0x` hex strings and `endian`: `little`, `big` or `both`.
- Optional `min_len` in bytes, at least 16, admitting a match on a table's head.

Constants must pass the bundled set's information guards: at least 16 required bytes with 8 distinct byte
values or 32 distinct 4-byte windows. All-zero and short runs are refused. Any invalid entry rejects its file,
naming the entry. Files are capped at 4 MiB, individual constants at 4 KiB, and 10,000 constants load overall.
`find_crypto` names the pack in each hit's evidence. Hits locate candidate tables, not proof an algorithm executes.
