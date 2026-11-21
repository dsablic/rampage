# MIPS16e and section-less ELF files: router userland (2026-11-21)

Status: design for track 2 of the queue in `todo.md`. The [acceptance pass](../benchmarks/acceptance-2026-11-20.md)
(check M5) found that 76 of the 87 programs in an OpenWrt root filesystem, `busybox` among them, are MIPS16e, and
that 5 of the 6 other shared libraries list no functions because OpenWrt's `sstrip` removes the section headers and
rampage read dynamic symbols only through a `.dynsym` section. Both are needed before rampage is useful on a router.

## 1. Dynamic symbols from `PT_DYNAMIC`

Loaders use the program headers, never the section headers, so everything the dynamic linker needs is reachable
from `PT_DYNAMIC`. When an ELF file of any architecture has no `.dynsym` section, rampage reads the table the
dynamic section describes:

- `DT_SYMTAB` and `DT_STRTAB` are addresses, mapped to file offsets through the file-backed part of a `PT_LOAD`
  segment. `DT_STRSZ` bounds every name. `DT_SYMENT`, when present, must be the class's symbol size (16 or 24).
- The table has no length of its own. The count comes from `DT_MIPS_SYMTABNO` (MIPS), else `DT_HASH`'s `nchain`,
  else `DT_GNU_HASH`: one past the highest symbol reached from its buckets, walking the last chain to the entry
  whose hash has the low bit set. Without any of them the table is not read; rampage does not guess a count from
  the distance to the string table.
- Defined symbols become symbols (functions when `STT_FUNC`) and, when global or weak with default or protected
  visibility, exports. Undefined named symbols become imports.
- Import slots: relocations in `DT_REL`/`DT_RELA` and `DT_JMPREL` that name an undefined symbol (64-bit MIPS's
  split `r_info` is not read), and on MIPS the global GOT entries: after `DT_MIPS_LOCAL_GOTNO` local entries at
  `DT_PLTGOT`, one per dynamic symbol from `DT_MIPS_GOTSYM` to the count above. The same count completes the MIPS
  GOT layout, so global GOT entries of the image's own functions are bound to them as with section headers.
- Constructors and destructors seed function starts in every ELF file, with or without sections: `DT_INIT`,
  `DT_FINI`, and the pointers in `DT_PREINIT_ARRAY`, `DT_INIT_ARRAY` and `DT_FINI_ARRAY` (sizes from the matching
  `*SZ` tags). A slot holding 0 or all ones is skipped. Where the file stores 0 because the pointer is a `RELA`
  relative relocation (x86-64, AArch64, RISC-V), its addend is the pointer. Every seed must lie in code.

The input is hostile. Every address-to-offset mapping, multiplication and addition is checked; every read is
bounded by the segment's file size and the file; counts are capped (at most 2^20 symbols, 2^20 relocations, 4096
array entries, the chain walk by the symbol cap) and by the bytes actually present. A malformed table yields no
symbols and a warning, never a panic or an unbounded loop.

## 2. MIPS16e

### How the ISA mode is represented

MIPS16e code runs in a second instruction-set mode of a MIPS32 processor. Its function addresses are odd: the ISA
bit is bit 0 of a code address, as ARM's Thumb bit is. GNU tools give MIPS16e function symbols odd values (older
ones also set `STO_MIPS16`, 0xf0, in `st_other`), GOT entries and function pointers hold odd values, and `jalr`
or `jr` to an odd address switches to MIPS16e.

rampage reuses the ARM interworking machinery rather than adding a second one:

- **Loader.** For a 32-bit MIPS ELF whose header has `EF_MIPS_ARCH_ASE_M16` and not `EF_MIPS_MICROMIPS`, odd
  function symbols, exports and the entry point have bit 0 cleared, and `Binary::mips16` records the MIPS16e
  ranges (a symbol's size, or up to the next function), as `Binary::thumb` does for ARM. `Target::thumb` carries
  these ranges (the "alternate instruction set" of either architecture) and `Target::mips16` says MIPS16e
  decoding is on. `Binary::thumb` stays ARM-only, since ARM-specific readers use it.
- **Discovery.** Code modes are already `(address, alternate)` points learned from branches and merged to a
  fixpoint; for MIPS `true` means MIPS16e. An odd code pointer (a GOT local entry, a literal-pool word) seeds
  a MIPS16e function at the even address; an address that is 2 modulo 4 is not a code pointer. Symbols whose
  instruction set is not decoded (a microMIPS image) keep the 2026-11-20 rule and seed nothing.
- **Decoder.** `rampage_arch::decoder` returns a MIPS decoder that holds Capstone for MIPS32 and a native MIPS16e
  decoder, and chooses per instruction: a mode learned from a branch, else the loader's ranges, else MIPS32. This
  is the shape of `Aarch32Disassembler`.

### Native decoder or Sleigh

Discovery uses a native MIPS16e decoder in `rampage-arch`. Capstone has no MIPS16 mode (only microMIPS). Sleigh's
MIPS languages decode MIPS16e under the `ISA_MODE` context, but its decoder gives p-code without the `$gp`/GOT
tracking discovery needs, and runs behind the FFI lock. MIPS16e is small (about 60 encodings plus `EXTEND`), and a
native decoder can feed the MIPS32 register tracker that already follows `$gp`, GOT entries and `$gp` spills.
Sleigh stays the decompiler's and `evaluate_function`'s decoder. GNU objdump's MIPS16 disassembly is the oracle
for the native decoder's tests.

### `jalx`, mode switches, delay slots

- MIPS32 `jalx` calls a MIPS16e target; MIPS16e `jalx` calls a MIPS32 one; MIPS16e `jal` stays in MIPS16e.
- A `jalr` or `jr` through a register whose value the tracker knows (a GOT entry, a formed address) goes to the
  even address and records the mode from bit 0, in both directions. `jr $ra` and `jrc $ra` return.
- `jal`, `jalx`, `jr` and `jalr` have one 16-bit delay slot; `jrc`, `jalrc` and every MIPS16e branch have none.
  The decoder reports each instruction's delay slots, so discovery no longer assumes one per MIPS transfer: the
  literal pool after a `jrc $ra` is not decoded as a delay slot.

### Extended instructions and PC-relative loads

`EXTEND` is decoded with the instruction after it as one 4-byte instruction, as GNU objdump shows it: the 11
prefix bits widen the immediate to 16 bits (15 for `addiu ry, rx`, the shift amount to 5 bits). An `EXTEND`
before `jal`, `jalx` or another `EXTEND` is invalid. `addiu rx, $pc, imm` and `lw rx, imm($pc)` take as base the
address of the instruction (its `EXTEND` when extended) with the low two bits cleared, or the jump's address in a
delay slot. `lw rx, imm($pc)` reads a literal-pool word, which is an access (data), and its value is an immediate
that may be a pointer (`ldr r0, =func` on ARM is the same case).

### `$gp` in MIPS16e code

MIPS16e code cannot use `$gp` as a base register. GCC computes it without `$t9`:
`li $2, %hi(_gp_disp); addiu $3, $pc, %lo(_gp_disp); sll $2, 16; addu $2, $3; move $gp, $2` in PIC code, or
`lw $2, <literal __gnu_local_gp>($pc); move $gp, $2` in non-PIC abicalls code. It then copies `$gp` into a
MIPS16e register (`move $16, $gp`) and loads GOT entries through it (`lw $2, %call16(f)($16); jalr $2`), and
spills the computed value to the stack around calls. The tracker reads `$gp` as the image's global pointer
(`_gp`, or `DT_PLTGOT + 0x7ff0` without sections), follows `move` between the 32 registers and the 8 MIPS16e
ones, and keeps the stack-slot rule it has for MIPS32, so these GOT loads resolve as in MIPS32 code.

### Decompiler

Ghidra's `MIPS:BE:32:default` and `MIPS:LE:32:default` include `mips16.sinc`; the bundled `mips32.pspec` sets
`RELP=1`, which makes the alternate instruction set MIPS16e. The decompiler needs `ISA_MODE=1` at a MIPS16e
function's entry and at the other code-mode points. The worker's existing `code_modes` and per-function `thumb`
flag mean "alternate instruction set"; the shim sets whichever of `TMode` and `ISA_MODE` the language has. An
older worker would silently decompile MIPS16e as MIPS32, so the worker protocol version is bumped.

### microMIPS: out of scope

microMIPS would use the same mechanism (odd addresses, `jalx`, `ISA_MODE`), but it is left out: no sample in the
acceptance set or in OpenWrt uses it (it targets microcontrollers such as PIC32MM/MZ rather than Linux routers),
the decompiler would need the microMIPS processor specification (`RELP=0`), which is not bundled, and Capstone's
microMIPS mode would need its own port of the tracker. microMIPS images keep the "not decoded" warning and note,
and their odd symbols seed nothing. 64-bit MIPS16e (MIPS64 with the ASE flag) is also left out: its 64-bit
opcodes are not decoded, and it keeps the warning.

### Added during acceptance

`busybox` listed 38 functions with decoding alone. Its applets are reached only through `applet_main`, a table of
odd function pointers, and musl's dynamic `_start` reaches `_start_c` only through a word after its `bal`. So: runs
of at least four odd code pointers (none at a string) seed MIPS16e functions, each marking only its first
instruction as MIPS16e; straight-line MIPS code keeps its mode whatever the ranges say (unlike ARM, a mode changes
only at a jump); every code pointer in a MIPS16e image names its mode; and `_start_c` is seeded from the entry.

After review, a table must hold at least four distinct targets spread over 0x80 bytes or more (a switch's label
table, `.word L|1`, keeps its targets inside one function), each target must lie past the program headers and
outside the tables the dynamic section names (hash buckets and symbol indices are small odd words, which in an
image based at 0 point into its first executable segment), and it must decode as a MIPS16e instruction. Those
tables are not scanned either. A MIPS16e `_start_c` (an odd word) is accepted.

### Remaining after review

- Library fingerprints exclude MIPS16e functions in the loader's MIPS16e ranges (they have no masking of their
  own); a MIPS16e function found only by discovery is still masked as MIPS32 words.
- Fuzzy signatures accept the MIPS16e mode, but refuse every MIPS function for its delay slots, MIPS32 included.
- Label tables spread over more than 0x80 bytes can still pass for function tables and split a function.
- A function whose first bytes read as three printable characters and a NUL is not taken from a table.

## Versions and tests

- `ANALYSIS_VERSION` is bumped: constructor seeds change function lists of existing fixtures.
- Fixtures: GCC 12 `-mips16` programs (big-endian PIE, little-endian non-PIC) mixing MIPS16e and MIPS32 functions
  so `jalx` runs both ways, with `-sym` truth twins, and a section-less MIPS shared library whose section headers
  a documented script removes. Generic tests also strip the section headers of existing fixtures in memory and
  require the same exports, imports and import slots from `PT_DYNAMIC`.
- Acceptance: check M5 on the 87 OpenWrt programs and M1 on zlib, reported in a dated section of the acceptance
  report.
