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

The native library has closed selections for all sixteen resource-admitted roadmap families. The additional
thirteen profiles were compared against 104 independent Java oracle rows; lengths, mnemonics and raw p-code
matched. CR16 conditional recovery was improved without changing its comparator or original failure record.
Hexagon still reports a helper-required gate: matching raw fixture p-code is not general packet support.
These finite fixtures do not establish full-ISA, C-ABI or ordinary-project acceptance.

## Ordinary Raw Projects (library pilot)

`Binary::from_raw_code(bytes, RawCodeOptions { profile, base, entry, seeds })` admits one owned RX code
image for exactly three profiles: `TI_MSP430:LE:16:default`, `avr8:LE:16:default` and `6502:LE:16:default`
(`Arch::Msp430`, `Arch::Avr8`, `Arch::Mos6502`). Input is 1..=128 KiB with at most 8192 seeds. Base, entry and
seeds must be aligned to the profile and backed by code bytes. The last byte must stay within the profile's
code-space highest byte. Header-driven `Binary::open` never falls back to Raw or infers an entry.

A Raw `Project` routes discovery, listing and code search through one Sleigh decoder factory. That factory
checks the admitted code-space facts against the verified native translator before use. Valid instructions
with unknown successors serialize `flow: "unknown"` with a `decode_gate`. They stop successor discovery and
are never reported as fall-through, return or noreturn. The cached analysis is bound to a
`rampage-raw-interpretation-v1` identity covering bytes, profile, mapping, entry and seeds. Edited loader
fields or a failed specification recheck refuse the cache instead of serving it stale.

Raw Projects refuse immediate/constant code search (no typed operands) and native decompiler memory images
(no translator-space binding yet). They also refuse patch V1, capture identity and backing-source proofs.
Annotations are memory-only, even when a persistent log is supplied. The three pilot architectures have no
legacy pointer width (`pointer_size()` is `None`) and no native/Capstone decoder. The CLI opens Raw
Projects with `--raw-json`/`--raw-request` ([CLI reference](cli-reference.md#raw-projects)). Multi-region maps, HEX/SREC and vector seeding remain Phase 4.2 work.

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
four existing x86/AArch64 profiles. It does not enumerate every sibling language in the bundled `.ldefs`.
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
Transport tests verify the shared interface; the earlier frozen MCP experiment remains a separate three-profile
measurement rather than being retroactively expanded to this roster.

Explicit windows select an original regular-file range, a bundled language profile and an internal-byte
base address. There is no executable-header inference, extraction or automatic publication of decoded data.
Seeded discovery is opt-in and uses the existing recursive-descent engine within that window.
This explicit-window path is not an ordinary `Project` decoder fallback. It does not relabel raw bytes as
ELF/snapshot images or substitute an existing architecture identity for an unsupported processor. Ordinary
image loading, consistent listing/search routing and ABI-checked decompilation require their own integration.

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
