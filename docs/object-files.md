# Object files and static libraries

rampage opens an ELF relocatable object (`.o`) the way IDA does: it lays the object out at addresses of its own,
applies the relocations and gives every undefined symbol a named slot, so functions, cross-references, strings,
disassembly and decompiled C all work on code that has never been linked. A member of a static library (`.a`) opens
the same way, named in the path.

## Opening an object

Any binary tool takes a `.o` file as its `path`:

```sh
rampage binary inspect foo.o
rampage function list foo.o
rampage function decompile --at main foo.o
rampage function xrefs --to printf foo.o
```

`binary_info` (`binary inspect`) reports the layout under `relocatable`: the base address, how many externs and
relocations there are, and the relocation types left unapplied.

**Layout.** The allocated sections (`SHF_ALLOC`) are placed in file order from `0x10000`, each at the alignment it
asks for, so no two overlap; non-allocated sections (symbol tables, relocations, debug information) keep address
0 and are not mapped. A section whose size or alignment would take the layout past 2^48 is not placed, with a
warning. After them come the segments the loader adds:

- `COMMON` (`.common` when the compiler emitted a section of that name), zero-filled and writable, for common
  symbols (`int x;` built with `-fcommon`).
- `extern`, one 8-byte slot per undefined symbol, named after it. An extern a call or branch relocation reaches
  (or that the object types as a function) is a function symbol; the others are data. A function extern's slot
  holds a branch to itself, which the decompiler takes as a call to the extern followed by a return, so a jump to
  one, conditional or not, decompiles as a call; a data extern's slot is zero. The segment is writable, so an
  extern variable never folds to a value, and it is no code section, so discovery never enters it. Externs are
  the object's imports; its global definitions are its exports.
- `.got`, read-only, one entry per symbol the code reaches through a GOT (position-independent code), holding the
  symbol's address (a GOT reference with a nonzero addend, which would need an entry for the symbol plus the
  addend, is left unapplied). Entries holding an extern are import slots (`__imp_printf`); entries holding a function the
  object defines are bound to it, so calls through them decompile by name. MIPS gets `$gp` at the GOT plus 0x7ff0,
  and local `%got` page entries.

**Relocations.** Each relocation is applied into a loaded copy of the file; the file itself is never changed, and
file offsets of section bytes stay the file's own. Supported types:

| Architecture | Types |
| --- | --- |
| x86-64 | `64`, `PC32`, `PLT32`, `32`, `32S`, `16`, `PC16`, `8`, `PC8`, `PC64`, `GOTPCREL`, `GOTPCRELX`, `REX_GOTPCRELX`, `CODE_4_GOTPCRELX`, `GOT32`, `GOTOFF64`, `GOTPC32`, `GOTPC64`, `SIZE32`, `SIZE64` |
| x86 | `32`, `PC32`, `PLT32`, `16`, `PC16`, `8`, `PC8`, `GOT32`, `GOT32X`, `GOTOFF`, `GOTPC` |
| AArch64 | `ABS64/32/16`, `PREL64/32/16`, `PLT32`, `CALL26`, `JUMP26`, `CONDBR19`, `TSTBR14`, `LD_PREL_LO19`, `ADR_PREL_LO21`, `ADR_PREL_PG_HI21(_NC)`, `ADD_ABS_LO12_NC`, `LDST8/16/32/64/128_ABS_LO12_NC`, `MOVW_UABS_G0`–`G3` (not the signed `MOVW_SABS`), `ADR_GOT_PAGE`, `LD64_GOT_LO12_NC`, `LD64_GOTPAGE_LO15`, `GOT_LD_PREL19` |
| ARM and Thumb | `ABS32`, `TARGET1`, `REL32`, `ABS16`, `ABS8`, `PC24`, `CALL`, `JUMP24`, `PLT32`, `THM_CALL`, `THM_JUMP24`, `THM_JUMP19`, `THM_JUMP11`, `THM_JUMP8`, `MOVW_ABS_NC`, `MOVT_ABS`, `MOVW_PREL_NC`, `MOVT_PREL` and their `THM_` forms, `PREL31`, `BASE_PREL`, `GOTOFF32`, `GOT_BREL`, `GOT_PREL`, `V4BX` |
| MIPS | `32`, `REL32`, `16`, `64`, `26`, `HI16`/`LO16` (paired, `_gp_disp` included), `GOT16` (global, and local page entries paired with their `LO16`), `CALL16`, `GOT_DISP`, `GOT_HI16`/`LO16`, `CALL_HI16`/`LO16`, `GPREL16`, `GPREL32`, `PC16`, `PC32`, `JALR` |
| RISC-V | `32`, `64`, `32_PCREL`, `BRANCH`, `JAL`, `CALL`, `CALL_PLT`, `PCREL_HI20`, `PCREL_LO12_I/S`, `GOT_HI20`, `HI20`, `LO12_I/S`, `RVC_BRANCH`, `RVC_JUMP`, `ADD8`–`64`, `SUB6`–`64`, `SET6`–`32`; `ALIGN` and `RELAX` are hints (nothing is relaxed) |

REL and RELA sections are both read: a REL type's addend is the value its field stores, decoded per encoding
(Thumb branches, `movw`/`movt`, MIPS `%hi`/`%lo` pairs). An ARM `bl` to a Thumb function the object defines
becomes `blx`, and a Thumb `bl` to an ARM one `blx`, as a linker makes them; a call to an extern keeps the form the
object gives it. A type outside the table is reported once per type in the warnings and in
`relocatable.unsupported` (with how many sites and the first), and its fields keep the file's bytes; the
decompiler treats those fields in data as volatile, so they never fold. TLS relocations and 64-bit MIPS's composite
types are among them. Applied fields match what `ld.lld` writes when linking the object at the same addresses on
the test fixtures of every architecture above.

**Evidence.** `xrefs` rows in an object carry `relocation`: the relocation applied in the referencing instruction,
with its type, symbol (a section's name for a section symbol), addend and value (`S + A`, so an x86 call's field
reads `printf - 4`). A RISC-V `call` is relocated at its `auipc` while the call is recorded at the `jalr`, and a
`PCREL_LO12` names its `auipc`: both report the relocation there. Another instruction's relocation is never
borrowed.

**Modes.** `$a`, `$t` and `$d` mapping symbols and Thumb function symbols mark Thumb code, as they do in an
executable; an M-profile object is all Thumb.

**Decompiling.** Read-only data folds to the values it holds once relocated (literal pools, the GOT, pointer
tables), so loads read as the globals and strings they reach. Externs are functions: calls render by name with
the libc prototype when the name has one, and a jump to an extern (a tail call) is a call followed by a return.

## Static libraries

`archive_inventory` (group `carve`; CLI `binary archive-inventory`) lists a library's members, GNU or BSD `ar`
format, with the symbols the library's index gives each and the path that opens one:

```sh
rampage binary archive-inventory libfoo.a --contains memcpy
```

```json
{"path": "libfoo.a", "contains": "memcpy"}
```

`contains` matches a member's name or one of its index symbols, so it answers "which member defines this". Pass a
row's `open` as the path of any binary tool:

```sh
rampage function decompile --at memcpy 'libfoo.a(memcpy.o)'
```

```json
{"path": "libfoo.a(memcpy.o)", "at": "memcpy"}
```

`#N` picks member N (from 0, in archive order) where names repeat: `libfoo.a(init.o#7)`, or `libfoo.a(#7)`. A
member whose name holds `(`, `)` or `#` is listed with `#N` alone. A name
that several members share is refused with the indexes to choose from, and opening the library itself is refused
with a list of its members. A member is the image at its location in the library, exactly as `image_offset` and
`image_length` would select it: it is its own project, with its own annotation sidecar and analysis store entry, and
an `image_offset` at a member's start opens that member too. Thin archives are refused.

## Limits

- ELF only. COFF objects and `.lib` libraries, Mach-O `MH_OBJECT` and ELF core dumps are not loaded this way yet
  (the layout reads sections, symbols and relocations through a format-independent interface, so they plug in
  beside the ELF relocation types).
- One member at a time: a whole library is not opened as one project, so calls between members reach externs, not
  the other member's function. COMDAT groups are laid out as they are (one object holds no duplicates).
- DWARF in an object is not imported (its addresses are relocated too).
- No linker relaxation: `GOTPCRELX` loads keep going through the GOT.
- Building signatures from a library is not covered here.
