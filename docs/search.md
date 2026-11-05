# Search reference

## Scope

`Project::search` queries retained mapped bytes or production-discovered instruction/reference evidence.
Ranges are half-open virtual addresses. Unmapped file overlays, virtual gaps and zero-fill are not searchable
byte content. Analysis does not execute the target or write annotations.

Byte/text API queries default to no function context to avoid initializing native analysis unnecessarily.
Set `include_context` for a bounded function name, address and annotation/loader/synthetic name provenance.
Native searches use independently discovered instruction boundaries, retained instruction modes and resolved
flows; they do not sweep arbitrary bytes as instructions.

## CLI and MCP

The Core MCP tool is `search`. Its request uses the mode and paging fields directly, alongside the common
binary `path`; there is no `query` envelope. Transport requests default `include_context` to true.

The CLI routes are:

```text
rampage binary search FILE --query REQUEST.json
rampage search FILE --query-json '{"mode":{"kind":"bytes","pattern":"48 8B ??"}}'
```

Request files and inline JSON are capped at 1 MiB. File loading uses checked regular-file descriptors and
source revalidation; it is currently Unix-only. Inline JSON remains available on other platforms.
Transport ranges and address-reference selectors accept numeric VAs, address strings or resolvable names.
Immediates remain numeric typed values, never symbol lookups.

Responses retain complete rows within 60,000 JSON bytes. A too-large first row or header rejects instead
of cutting strings or dropping evidence silently. Continuation offsets page the observed hit set, including
when the underlying scan is incomplete; they do not imply that a scan budget can be bypassed by paging.

## Query modes

The native request contains a tagged `mode` object:

| Kind | Fields | Meaning |
| --- | --- | --- |
| `bytes` | `pattern` | Hex bytes with byte/nibble wildcards; all-wildcard patterns reject |
| `text` | `pattern`, `encoding`, `regex` | ASCII or Unicode UTF-16LE/BE text; optional bounded regex |
| `immediate` | `immediate` | Structured signed/unsigned operand value with optional semantic width |
| `instruction` | `mnemonic`, `operands` | Whole-field case-insensitive ASCII globs |
| `references` | `target` | Retained references to the exact target VA |
| `functions_referencing` | `reference` | Distinct native functions with matching retained evidence |

Example byte request:

```json
{
  "mode": {"kind": "bytes", "pattern": "48 8B ?F ??"},
  "range": {"start": 4096, "end": 8192},
  "offset": 0,
  "limit": 100,
  "include_context": true
}
```

An immediate is typed explicitly:

```json
{
  "mode": {
    "kind": "immediate",
    "immediate": {
      "value": {"kind": "signed", "value": -1},
      "width_bits": 32,
      "include_displacements": false,
      "include_addresses": false
    }
  }
}
```

Displacements and address candidates are excluded by default. Unsupported native operand evidence is
reported rather than recovered by parsing formatted instruction text. Width means semantic operand width,
not merely the encoded immediate field width.

Instruction globs use `*` for zero or more bytes and `?` for one byte; other characters, including backslash,
are literal. Whitespace collapses to one space. These are not regex. An operand-only query uses the implicit
mnemonic `*`.

Function-reference selectors include:

```json
{"kind":"address","target":12288}
```

```json
{"kind":"string","text":"水😀","encoding":"utf16_le"}
```

```json
{"kind":"import","name":"puts","library":"libA"}
```

```json
{"kind":"constant","immediate":{"value":{"kind":"unsigned","value":42}}}
```

Reference-string encodings are `utf8`, `utf16_le` and `utf16_be`; ordinary text encodings are `ascii`,
`utf16_le` and `utf16_be`. Import selectors use retained names and optional library identity, not arbitrary
analyst aliases or inferred unnamed forwarding chains. Exact-address references use the same target index as
the xref API, not an immediate-value search.

## Unicode and regex

UTF-16 matches bind Unicode scalars back to their actual source-byte positions, including surrogate pairs.
Invalid surrogates divide valid runs; no replacement characters are invented as searchable content.
Zero-length regex matches reject. Regex compilation, nesting and DFA cache are bounded.

Regex evaluates complete virtual text runs within the declared search scope. Oversized decoded runs or runs
cut short by a scan budget are not submitted as artificial complete strings; this avoids invented anchor
matches. A decoded UTF-16 regex run is limited to 1 MiB of UTF-8 text.

## Paging, budgets and evidence

Hits are address-sorted and deduplicated. `offset` and `limit` select rows, not how much content is scanned.
Limits are 1–1,000 rows per page. An interrupted scan reports a lower-bound total and an explicit stop reason,
not a complete negative result.

Default/public maxima are 256 MiB of scanned bytes, 64 Mi conservative matching-work units, 1,000,000
instructions and 100,000 results. Byte patterns contain at most 4,096 bytes; regex compiled size and DFA
cache are each capped at 1 MiB. Mappings are also bounded. Reports distinguish instruction, source-byte,
reference and matching-work counters rather than presenting them as physical I/O measurements.

Exact text (ASCII or UTF-16) is matched with a linear substring search and charged one matching-work unit per
candidate start, so the default budget covers about 64 MB of mapped bytes; byte patterns with wildcards are
charged their length per candidate start. When a budget or cancellation stops a byte/text scan, the report
gives `resume_at`, the first address whose matches were not searched, and the first 32 `unscanned_ranges` with
`unscanned_range_count` and `unscanned_bytes`; searching again with `range.start` at `resume_at` continues the
scan. A regex scan resumes at the start of the domain it stopped in, which may repeat that domain's earlier hits.
A result-cap or text-run-limit stop gives no `resume_at`: a range cannot skip retained hits, and the same run
would stop the scan again.

Decoder windows and required semantic lookahead are charged before use. Pointer/literal probes consume
the same inspection budget; duplicate probes within one instruction can reuse checked bytes. Unaccepted
decoder windows still count as inspected source. `inspected_code_bytes` is supplementary evidence and must
not be added again to decoded/source totals.

Native analysis/cache initialization is not interruptible. Cancellation and scan budgets govern subsequent
search work; reports disclose this distinction. Unresolved indirect flow and unsupported evidence remain
limitations, not proof that no reference exists.

File offsets are returned only when justified by retained backing. Packed image offsets in owned memory
captures are not represented as offsets in the original capture document.
