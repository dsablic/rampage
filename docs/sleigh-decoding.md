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
`Binary::from_raw_code(bytes, RawCodeOptions { profile, base, entry, seeds, vector_table, pointer_tables })`. Input is 1..=128 KiB
(4 MiB for the [Cortex-M profile](#cortex-m-profile)) with at most 8192 seeds. Base, entry and seeds must be
aligned to the profile and backed by code bytes, and the last byte must stay within the profile's code-space highest
byte. Header-driven `Binary::open` never falls back to Raw or infers an entry.

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
a `rampage-raw-interpretation-v5` identity covering bytes, profile, byte order, every region (kind, mapping,
where its bytes lie and its stated source, including a decode receipt), entry, seeds, the requested vector-table
address, whether pointer tables were scanned, and a record file's format, record count and start address; edited
loader fields or a failed specification recheck refuse the cache instead of serving it stale.

Decompilation is available for profiles with a reviewed C model: MSP430 (`default`) and AVR8 (`gcc`). It maps
exactly one read-only RX code region, bounded by the translator's code space; AVR data, register and I/O spaces are
never served from the code mapping. Every other profile refuses with "no reviewed C model for <profile>".

Sleigh-decoded Raw Projects also refuse immediate/constant code search (no typed operands); every Raw Project
refuses patch V1, capture identity and backing-source proofs. Annotations are memory-only, even when a persistent
log is supplied. The sixteen Sleigh architectures have no legacy pointer width (`pointer_size()` is `None`) and no
native/Capstone decoder. Sleigh profiles map exactly one code region; Intel HEX and S-record input is accepted
when its data form one contiguous run. Multiple regions (code, constant data, RAM and unbacked RAM/MMIO, from file
ranges, decoder output or record runs) are Cortex-M only; see [Raw projects](mcp.md#multiple-regions-intel-hex-and-s-records).

### Cortex-M profile

`ARM:LE:32:Cortex` (aliases `cortex-m`, `cortex-m0`, `cortex-m0+`, `cortex-m3`, `cortex-m4`, `cortex-m7`,
`thumb`, `thumb2`, `armv6m`, `armv7m`, `armv7em`, `thumbv6m`, `thumbv7m`, `thumbv7em`, ...) is little-endian
ARMv6-M/ARMv7-M(E) Thumb. It is *experimental* ([stability policy](stability.md)). ARMv8-M is not reviewed: the
Mainline system-register names (`msplim`, `psplim`, the `_ns` registers) decode because they are harmless names,
but ARMv8-M-only instructions are not reviewed, and `cortex-m33`/`cortex-m55` are not aliases. Design choices:

- **Decoder.** Discovery, listing and search use rampage's native ARM decoder, the one ARM ELF uses, with the
  whole mapped range in Thumb mode (the binary's Thumb ranges are exactly the mapping and are part of the
  retained interpretation). It gives typed operands, `movw`/`movt` and literal-pool data references and IT-block
  conditions, which the Sleigh path does not. One M-profile flag (`RawProfile::m_profile`, carried in the
  decoder target) selects the M-profile instruction set: the `MRS`/`MSR` special registers (`msp`, `psp`,
  `primask`, `basepri`, `basepri_max`, `faultmask`, `control`, ...) decode, UNPREDICTABLE forms do not (an empty
  mask, SP or PC as the register); there is no A32 state, so nothing switches modes and no A32 hint is emitted;
  and the A-profile-only groups are UNDEFINED: BLX to A32, Advanced SIMD data processing and loads/stores,
  SETEND, SRS/RFE, ERET and SUBS PC, LR, SMC/HVC, banked-register MRS/MSR, LDREXD/STREXD, 32-bit CPS and
  `cpsie a`. The FP extension's VFP instructions (Cortex-M4F/M7) still decode. Odd Thumb pointers given as
  `entry` or `seeds` name the even instruction. A formed address is a function start only when odd and not the
  start of a printable NUL-terminated run (an odd-aligned string literal); even ones (strings, switch tables) are
  data. ELF Thumb code and `inspect_raw_code` keep A-profile decoding.
- **Decompilation.** Ghidra's `ARM:LE:32:Cortex` uses `ARM7_le.sla` with `ARMCortex.pspec`; neither is bundled.
  The bundled `ARM8_le.sla` defines `VERSION_7M` as `ARM7_le.slaspec` does (it adds `VERSION_8`), so it decodes
  the M-profile constructors; the decompiler runs `ARM:LE:32:v8` with its reviewed `default` C model (pointer,
  int and long 4 bytes, matching AAPCS) and TMode set explicitly at every function, as for ARM ELF Thumb code.
  Only the code mapping is served, read-only, and on Cortex-M Raw images (only: other Raw profiles' images are
  often RAM the program writes) the decompiler folds loads from it, so a literal-pool word reads as the address it
  holds. A global with no other name is named by its architectural
  ARMv6-M/ARMv7-M region and address (`code_`, `ram_`, `periph_`, `extram_`, `extdev_`, `ppb_`, `vendor_sys_`:
  `ram_20000004`, `periph_40021000`); an analyst's `rename` of the address wins. The data type stays inferred.
- **Callees.** Raw images carry no prototypes, so for a Cortex-M Raw image (only; headered ARM binaries keep
  Ghidra's defaults) rampage tells the decompiler two things about each direct callee before decompiling a
  function. The call-clobbered registers (r0-r3, r12) that the callee and everything it calls never write are
  preserved across the call: GCC's `-fipa-ra` (on at `-O2`/`-Os`) and LLVM's IPRA keep a caller's value in such a
  register across the call, and without this the next call's argument read as `extraout_r1` or disappeared. A
  callee with an indirect call or jump, a supervisor call, recursion or code that does not decode keeps the
  convention's effects. And each callee's parameters are committed from its own decompilation, leaves first, as
  Ghidra's Decompiler Parameter ID does, so `f(g(x))` no longer prints as `g(x); f();` and an argument passed
  through untouched still reaches the call. Return types stay inferred: a locked return changes how Ghidra
  recovers a caller's own return. A callee is left as Ghidra infers it when its code has an indirect call or jump,
  a supervisor call (`svc`, which passes registers its p-code never shows), a branch into another function (a
  thunk or tail call, conditional or not), a recursive cycle, or a callee that cannot be derived; at most 64 callee
  decompilations per request. A branch into the middle of another function is not recognised (the decompiler knows
  entries, not extents). Before each decompilation the engine puts back every derived lock and effect and forgets
  what it learned, so the result never depends on what was decompiled before, and matches the isolated worker,
  which opens a fresh engine per request. Keeping one engine costs about 10 ms per decompilation (dev build) on a
  generated 680 KiB image (50 functions in 0.49 s, against 0.32 s without callee inference; reopening the engine
  each time took 13.7 s).
- **Bit fields.** `ubfx r0, r0, #4, #12` reads as `(x & 0xffff) >> 4` and `lsls #4; uxth` as `(int2)x << 4`:
  Ghidra keeps the mask beside the operand it applies to, which is equivalent to `(x >> 4) & 0xfff`. Compare
  against the disassembly; the expression is right, only its grouping differs.
- **Input cap.** 4 MiB (`MAX_RAW_NATIVE_BYTES`); Sleigh profiles keep 128 KiB. A generated 1,039,864-byte
  Cortex-M3 image (4,700 C functions, Reset as the only seed) lists its functions in 0.6 s wall (3.8 s CPU) with
  92 MiB peak RSS in a release build on an otherwise idle Apple-silicon Mac. A session keeps at most 32 Raw
  projects and 64 MiB of their input bytes.
- **Vector table.** `vector_table` (an address, `true` for `base_address` in MCP/CLI) reads the initial SP and
  up to 16 system and 240 external vectors as little-endian words. A handler is accepted when its word is odd,
  inside the mapped range and outside the table; zero is `empty` and 0xFFFFFFFF (erased flash) `erased`;
  reserved slots 7-10 and 13 are never handlers (some parts keep a checksum there). Each refusal has a
  `refused_reason`. External vectors stop (`stop_reason`) at the first word that is neither empty, erased nor a
  handler, at the lowest accepted handler address after the table (system or external), at the image end or
  after 240. Reset becomes the entry unless
  `entry` is given; other accepted handlers become seeds. Each word is reported with its verdict. The base address
  is never inferred: when handler words fall outside the mapping, a `base_address_suggestion` gives the most
  aligned base in the range that would hold them, labelled as not applied.
- **Pointer tables.** `pointer_tables` (off by default) scans every word-aligned word outside the vector table
  for Thumb code pointers: odd, inside the mapping, and whose target's first instruction decodes. Each target's
  evidence is `push_lr` (a `push {..., lr}`, `push.w` or `str lr, [sp, #-4]!` among its first four
  instructions), `call_target` (a 32-bit `bl` at any halfword targets it, counted only when the decoder reads it as that call
  and the instruction after it decodes) or `reaches_exit` (its
  straight-line decode, up to 256 instructions, reaches an unconditional return, branch or halt); a target with
  none is not a code pointer, which drops string pointers. Runs of at least three code pointers are found at a
  4-byte stride first, then 8, 12 and 16 over what is left (arrays of `{name, handler}` structs), with up to 8
  empty slots between entries. A run is accepted when two distinct targets have strong evidence (`push_lr` or
  `call_target`), so one coincidental prologue or `bl`-shaped word cannot promote a run of weak entries; a switch
  table of case labels or constants pointing into a function have only `reaches_exit` and are refused, and so is
  a table of leaf functions only. Accepted targets become seeds (deduplicated before the 8192-seed cap); every
  table is reported with its verdict. It is opt-in because it adds guesses beyond what the analyst asserted and
  changes the interpretation identity. Every Raw tool call admits its request again, so the last 8 scans are
  memoized by image SHA-256, base and skipped range: on a generated 1.8 MiB Cortex-M3 image (6,000 functions,
  1,099 table targets, all real) the first scan takes about 42 ms in a release build and a repeated call about
  1 ms, where each call used to rescan (about 30-50 ms).

Owned fixture: `tests/fixtures/firmware/raw-cortex-m.bin` is the flash image of `raw-cortex-m.elf`, built from
`raw-cortex-m.c` by `build-raw-cortex-m.sh` (zig 0.17.1, `-mcpu=cortex_m3 -O1`, llvm-objcopy). Opened with base
`0x8000000` and the vector table only, it recovers all 11 functions the ELF names (6 from vectors, 5 through
calls); its strings and switch tables are at even addresses and give no start. One extra start is `dispatch`'s
join point, split because the UART handler tail-calls `dispatch` (see [known limits](known-limits.md#analysis)).
`raw-cortex-m-decompile.bin` (same script, built without `movw`/`movt` and with LLVM's IPRA) holds the decompiler
cases above: literal-pool globals, an argument kept in r1 or r2 across a call, and a call's result passed on.
The stripped ELF, which has only its entry, finds 6 of them (Reset and the 5 it calls), a loop-head split and 6
string or table starts. `raw-cortex-m-strings.bin`, from the same script, has the odd-aligned literals `"Cde"` and
`"Bc"`; exactly its 6 ELF functions are found. `raw-cortex-m-tables.bin` (`-mcpu=cortex_m0`) reaches 11 of its 18
functions only through a `{name, handler}` command table, a callback table with an empty slot and a state-handler
array, and holds decoys: a string-pointer array, odd constants pointing into a function and a clang ARMv6-M switch
table of absolute case-label addresses. With the vector table only, discovery finds 4 functions, all real
(precision 4/4, recall 4/18); with `pointer_tables` it finds 17, all real (precision 17/17, recall 17/18; the miss
is `run_command`, inlined into Reset and unreferenced), and refuses the switch table and the constants with
`no_strong_evidence`.

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
