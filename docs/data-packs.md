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

Each directory holds `rampage-pack.toml`.

```toml
format_version = 1                    # optional; absent means 1
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

### Format versions

Every pack format declares or implies a version, and a reader follows the same rule for each:

- **Same major, newer minor:** a field this rampage does not know is ignored and reported as a warning
  (`pack list`, `pack check` and `list_packs` show it; detection results list it in `warnings`). A content
  `kind` it does not know is reported as `unsupported` while the pack's other contents load.
- **Newer major:** the pack (or the content) is refused with an error naming the version and asking for a newer
  rampage.

| Format | Version marker | This release reads |
| --- | --- | --- |
| `rampage-pack.toml` | `format_version` (absent means 1) | 1 |
| Constants JSON | `format_version` (absent means 1); unknown fields and kinds are skipped with a warning | 1 |
| Signature JSON | `scheme` (absent means 1); unknown hash schemes are refused | schemes 1 and 2 |
| `.rpack` archive | `format_version`, plus `min_rampage_version` | 1 |
| PeID `userdb.txt`, YARA, capa rules | the upstream text formats; entries this rampage cannot parse are skipped (PeID) or reported as a content error (YARA, capa) | upstream syntax |

A pack written for this release must keep loading in every later 1.x release. The committed fixtures under
`tests/fixtures/packs/` pin that: the `compat-v1` pack and an `.rpack` archive exported by rampage 0.1.0.

## Precedence and validation

For library identification, the first database to name a function wins: user `--db`, then packs in supplied
order, then bundled `rampage-builtin`, then the bundled call graph (`rampage-builtin call graph`), which only names
functions no database named. Each match names its `source`, an open-ended set of names. PeID, YARA and capa content runs alongside
bundled and user-supplied content. See [library identification](features.md#library-identification) for signature
architecture coverage, confidence gates and library-build specificity.

Every path, including symbolic links, must stay within the pack. Each file is read once with a size cap and
within per-pack/overall budgets; at most 64 packs load. Failed content is reported without preventing other
content from loading. YARA `include` statements are refused in user, pack and agent rule sets: each rule file
must stand alone. A manifest's provenance/license fields describe its data, not authorization to disclose a binary.

## Export and import

A pack moves between machines as one `.rpack` archive, so installing a pack someone else made (for example the
[flywheel's](flywheel.md) promoted signatures) is a copy and a check, not a conversion.

```sh
rampage pack export target/flywheel/promoted/libid -o libid.rpack
rampage pack diff libid.rpack --against ~/packs/libid      # what an import would change
rampage pack import libid.rpack --into ~/packs/libid       # default: ./<pack name>
rampage --pack ~/packs/libid function identify stripped.elf
```

An archive is one gzip member holding one JSON document: the pack's files in the formats above
(`rampage-pack.toml`, every file its contents name, and a flywheel pack's `entries.json`), and a manifest with:

- the archive `format` and `format_version` (1), and `min_rampage_version`: the oldest rampage that reads
  everything the archive uses. There is no upper bound: a reader accepts every archive of a format version it
  supports. Archives exported by rampage 0.1.x carry a `rampage_version` range instead; it is ignored, so they
  keep loading. Preview builds before 1.0 refuse archives with `min_rampage_version` as having an unknown field;
- the pack's declarations (name, version, licence, source, description) and its `families` (`libid` for a
  flywheel pack, otherwise its content kinds);
- each file's SHA-256 and size, and `content_sha256` over every manifest field except itself and `exported_by`
  (keys sorted), including fields a newer rampage added, so they cannot change undetected;
- for a flywheel pack, one summary per promoted entry: its revert id, family, candidate hash, row count, corpus
  version and split, what it was gated against (`arm:<hash>` or `bundled`), both gate verdicts and the held-out
  delta. `entries.json` keeps the full provenance.

Export refuses a pack that does not load cleanly, or whose contents are directories (YARA or capa rule trees):
an archive carries files only. Import refuses, before writing anything, an archive whose format version is
newer than it reads (an error asking for a newer rampage), whose `min_rampage_version` is newer than this rampage,
whose file list, file hashes, content hash or entry summaries do not
match, whose paths leave the pack, whose pack name is not a plain identifier, whose declarations differ from its
`rampage-pack.toml`, or whose entries lack a passing gate result. For a flywheel pack it also refuses signature
databases that are not exactly what the entries' rows produce, and entries whose rows lack their candidate
hash. It then writes the pack to a
staging directory beside the destination, loads it as `--pack` would, and moves it into place only if every
content loads. The destination must not exist or must be empty. `diff` runs the same checks and lists files,
entries and signature rows added or removed against a pack directory (or an empty one); `--json` gives each.

Nothing in an archive is executed. The hashes are integrity checks, not a signature: they catch damage and
inconsistent edits, but anyone can rewrite an archive and recompute them, so they say nothing about who made it
or whether its data is right. To take imported flywheel entries into rampage's bundled databases,
`rampage-eval bundle` reruns the flywheel gate on them first ([flywheel](flywheel.md#bundle-a-promotion)).

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
The file may declare `format_version` (absent means 1); see [format versions](#format-versions).
