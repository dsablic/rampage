# Explicit Sleigh decoding

## Instruction evidence

The bounded Sleigh decoder returns instruction length, mnemonic, operand display text, conservative flow
and raw p-code. Operand text is not structured operand/type evidence. Decoding does not execute instructions,
admit an executable image, establish a C ABI or prove that every translated instruction supports decompilation.

Each decode binds a supplied byte window and base address. Rebinding clears translation caches; unread or
zero-padded lookahead cannot count as backed instruction bytes. Results distinguish invalid, truncated,
unavailable, unimplemented-p-code, budget and internal-error outcomes. When padding prevents a definitive
invalid/truncated verdict, the ambiguity remains explicit.

Address-space identity is retained separately from numeric offset. Varnodes report address size and word
size; LOAD/STORE selectors identify their selected space without exposing native engine pointer encodings.
Internal p-code branch offsets are not machine-code branch targets. Multiple exits, unsupported spaces,
user-defined operations and delay-slot aggregation can leave conservative flow unknown.

## Address units

The native bridge uses internal byte offsets. A space's word size describes its addressable/display units;
callers must not multiply an already-normalized offset again. In AVR8, `code`, `mem` and `codebyte` remain
distinct spaces even when their numeric offsets are equal. The code-window loader does not serve unrelated
data spaces from code bytes.

## Specification provenance

Specifications are pinned compiled SLA data and their processor/compiler metadata, not target executables.
The bundle materializes already-compiled SLA files; it does not compile SLASPEC lazily. Source/include hashes
do not establish rebuild equivalence or publisher authentication.
Adding resources changes the bundled specification identity. Existing checked metadata bound to an older
identity is not automatically resealed or treated as proof for the new bundle; required review/import
checks remain in force.

Language/compiler admission is explicit. Sibling resources retained to close an unchanged language-definition
file's dependencies are not automatically selectable profiles. Unknown ABI facts remain unknown: in particular,
the reviewed 6502 compiler metadata supplies no C integer/pointer organization, so host widths are not substituted.

The native library has closed selections for all sixteen resource-admitted processor families. Thirteen of these
profiles (all but the three in the frozen MCP measurement) are compared against 104 independent Java oracle rows;
lengths, mnemonics and raw p-code match. CR16 conditional recovery keeps its original comparator and failure
record. Hexagon reports a helper-required gate: matching raw fixture p-code is not general packet support.
These finite fixtures do not establish full-ISA, C-ABI or ordinary-project acceptance.

## Ordinary Raw Projects

A Raw Project is one explicit, headerless code image analysed like an ordinary binary. MCP opens one through the
`raw` selector of raw-capable tools ([MCP Raw projects](mcp.md#raw-projects)); the CLI uses
`--raw-json`/`--raw-request` ([CLI reference](cli-reference.md#raw-projects)); the library entry point is
`Binary::from_raw_code(bytes, RawCodeOptions { profile, base, entry, seeds })`. Input is 1..=128 KiB with at most
8192 seeds. Base, entry and seeds must be aligned to the profile and backed by code bytes, and the last byte must
stay within the profile's code-space highest byte. Header-driven `Binary::open` never falls back to Raw or infers
an entry.

### Published processor set

All sixteen selected families are admitted. Profiles other than MSP430 (`default`) and AVR8 (`gcc`), the two with
reviewed C models, are *experimental* (see the [stability policy](stability.md)). Each row's code-space facts and byte order are checked against the
verified native translator before any decoder is used. Recall is measured on owned fixtures through the ordinary
Project path (`rampage-eval processor-roster`, [benchmarks](benchmarks/phase4-1.md)): each fixture has two truth functions;
"manual" seeds every truth entry, "caller" seeds only the base entry.

| Profile | Byte order | Entries manual / caller | Exact extents manual / caller | Gates on misses | C |
| --- | --- | ---: | ---: | --- | --- |
| `TI_MSP430:LE:16:default` | LE | 2/2 / 2/2 | 2/2 / 2/2 | — | yes |
| `avr8:LE:16:default` | LE | 2/2 / 2/2 | 2/2 / 2/2 | — | yes |
| `6502:LE:16:default` | LE | 2/2 / 2/2 | 2/2 / 2/2 | — | no |
| `8051:BE:16:default` | BE | 2/2 / 2/2 | 0/2 / 0/2 | user-defined operation | no |
| `PIC-16:LE:16:PIC-16` | LE | 2/2 / 1/2 | 1/2 / 0/2 | context-mediated flow | no |
| `SuperH:BE:32:SH-2` | BE | 2/2 / 1/2 | 0/2 / 0/2 | delay-slot aggregation | no |
| `V850:LE:32:default` | LE | 2/2 / 2/2 | 2/2 / 2/2 | — | no |
| `tricore:LE:32:default` | LE | 2/2 / 1/2 | 1/2 / 0/2 | user-defined operation | no |
| `Xtensa:LE:32:default` | LE | 2/2 / 2/2 | 2/2 / 2/2 | — | no |
| `z80:LE:16:default` | LE | 2/2 / 2/2 | 2/2 / 2/2 | — | no |
| `HCS-12:BE:24:default` | BE | 2/2 / 1/2 | 1/2 / 0/2 | user-defined operation | no |
| `6805:BE:16:default` | BE | 2/2 / 2/2 | 2/2 / 2/2 | — | no |
| `CR16C:LE:16:default` | LE | 2/2 / 2/2 | 2/2 / 2/2 | — | no |
| `eBPF:LE:64:default` | LE | 2/2 / 2/2 | 2/2 / 2/2 | — | no |
| `Loongarch:LE:64:lp64d` | LE | 2/2 / 2/2 | 2/2 / 2/2 | — | no |
| `Hexagon:LE:32:default` | LE | 2/2 / 1/2 | 0/2 / 0/2 | processor helper required | no |

Totals: manual 32/32 entries and 23/32 exact extents; caller-only 27/32 entries and 20/32 exact extents. Every
miss is attributed to a decode gate. Limits: fixtures are hand-assembled byte ledgers, not cross-compiler
output; the Ghidra oracle is seeded function creation, and Ghidra's autonomous auto-analysis recall per
processor is not measured. Hexagon is admitted only with its declared parallel-instruction helper, whose gate is
reported on every instruction.

### Behaviour

Discovery, listing and code search use one Sleigh decoder factory. Valid instructions with unknown successors
serialize `flow: "unknown"` with a `decode_gate`; they stop successor discovery and are never reported as
fall-through, return or noreturn. A helper-gated Hexagon entry stays a valid function with an unresolved exit;
SuperH's delay-slot gate inside a body stops successors there. Cached analysis and decompiler engines are bound to
a `rampage-raw-interpretation-v2` identity covering bytes, profile, byte order, mapping, entry and seeds; edited
loader fields or a failed specification recheck refuse the cache instead of serving it stale.

Decompilation is available for profiles with a reviewed C model: MSP430 (`default`) and AVR8 (`gcc`). It maps
exactly one read-only RX code region, bounded by the translator's code space; AVR data, register and I/O spaces are
never served from the code mapping. Every other profile refuses with "no reviewed C model for <profile>".

Raw Projects also refuse immediate/constant code search (no typed operands), patch V1, capture identity and
backing-source proofs. Annotations are memory-only, even when a persistent log is supplied. The sixteen
architectures have no legacy pointer width (`pointer_size()` is `None`) and no native/Capstone decoder.
Multi-region maps, MMIO, HEX/SREC and vector seeding are not supported.

## Window and discovery contract

The standalone Core tool is `inspect_sleigh`; it does not open a native executable project first.
Its request includes the common `path` and these explicit fields:

```json
{
  "path": "tests/fixtures/sleigh/msp430.bin",
  "profile": "TI_MSP430:LE:16:default",
  "offset": 0,
  "length": 30,
  "base_address": "0x4400",
  "discover": true,
  "seeds": ["0x4400"],
  "include_pcode": false,
  "listing_limit": 100
}
```

The CLI route is `binary inspect-sleigh FILE --request REQUEST.json` or `--request-json JSON`; the request
document excludes the CLI's positional file path. Numeric addresses and hexadecimal strings describe raw
coordinates, not resolvable symbols. Unknown fields and arbitrary profile/specification paths reject.

The tool schema enumerates the closed registry directly: sixteen selected processor-family profiles and
four x86/AArch64 profiles. It does not enumerate every sibling language in the bundled `.ldefs`.
Examples include `TI_MSP430:LE:16:default`, `avr8:LE:16:default`, `6502:LE:16:default`,
`SuperH:BE:32:SH-2`, `CR16C:LE:16:default` and `Loongarch:LE:64:lp64d`. Arbitrary profile/spec paths reject.

The owned sixteen-profile discovery matrix retains all 32 manual functions in each denominator:

| Seed policy | Entries retained/recovered | Exact byte extents |
| --- | ---: | ---: |
| Every manual entry supplied | 32/32 | 23/32 |
| Caller entries only | 27/32 | 20/32 |

Supplying all entries measures retention, not autonomous entry discovery. Computed calls and context,
delay-slot, user-operation and helper gates explain remaining misses; they are not omitted from the matrix.
Hexagon helper-gated entries remain valid instructions/functions but do not establish packet or CFG support.
Transport tests verify the shared interface; the frozen three-profile MCP measurement is separate and does not
cover this roster.

Explicit windows select an original regular-file range, a bundled language profile and an internal-byte
base address. There is no executable-header inference, extraction or automatic publication of decoded data.
Seeded discovery is opt-in and uses the ordinary recursive-descent engine within that window.
This explicit-window path is not an ordinary `Project` decoder fallback. It does not relabel raw bytes as
ELF/snapshot images or substitute an existing architecture identity for an unsupported processor. Ordinary
loading, consistent listing/search routing and ABI-checked decompilation come from
[Raw Projects](#ordinary-raw-projects), not from this path.

Listing pagination does not reset analysis work or change its seeds. Decode attempts, native decoder
creation, retained instruction addresses and output are separately bounded. Factory failures, exhausted
discovery budgets and deadlines reject the operation rather than returning a successful partial program.
Native calls themselves are not interruptible; cooperative deadlines are not hard process timeouts.

Valid instructions with unknown flow produce explicit stop evidence, not an invalid-opcode verdict.
In particular, context-mediated control flow cannot be inferred from the absence of a branch in one
instruction's isolated p-code. The compatibility adapter stops conservatively at those sites; it does not
establish complete function/CFG coverage or recover data references from operand display strings.

Selected source bytes are hashed before and after analysis and their descriptor/path identity is rechecked.
These observations detect measured changes; they do not make file reads atomic against arbitrary external
writes. Results retain source-file offsets separately from asserted code-space addresses.
