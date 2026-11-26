# Object files and static libraries

rampage opens a relocatable object the way IDA does: an ELF `.o`, a COFF `.obj` (MSVC, clang-cl, MinGW; big
objects too) or a Mach-O `MH_OBJECT` `.o`. It lays the object out at addresses of its own, applies the relocations
and gives every undefined symbol a named slot, so functions, cross-references, strings, disassembly and decompiled
C all work on code that has never been linked. A member of a static library (`.a`, an MSVC `.lib`, a Mach-O
universal `.a`) opens the same way, named in the path, and a whole library builds a signature database.

## Opening an object

Any binary tool takes an object file as its `path`:

```sh
rampage binary inspect foo.o
rampage function list foo.o
rampage function decompile --at main foo.o
rampage function xrefs --to printf foo.o
```

`binary_info` (`binary inspect`) reports the layout under `relocatable`: the base address, how many externs and
relocations there are, the relocation types left unapplied, the COMDAT sections (`comdats`) and a COFF object's
linker directives (`directives`, from `.drectve`: `/DEFAULTLIB:kernel32.lib`, `/EXPORT:...`). A COFF object's
format is `pe` (it is Windows code: the decompiler uses the Windows conventions), a Mach-O object's `macho`.

**Layout.** The allocated sections (`SHF_ALLOC`) are placed in file order from `0x10000`, each at the alignment it
asks for, so no two overlap; non-allocated sections (symbol tables, relocations, debug information) keep address
0 and are not mapped. A COFF object's sections are placed the same way, except linker directives (`.drectve`),
debug sections (`.debug$S`, `.debug$T`) and other discardable or `LNK_REMOVE` ones (`.llvm_addrsig`); COMDAT
sections (each inline function or `selectany` variable's own `.text$mn`, with its associative `.pdata`/`.xdata`)
are laid out like the others, since one object holds no duplicates. The image base is 0, so an image-relative
(`ADDR32NB`) field, as in `.pdata`, holds the same address an absolute one does. A Mach-O object's sections keep the
addresses the object gives them, moved by `0x10000` (the object already lays them out, and one distance between
every section and its place lets a field relocated against a section keep its value), leaving out debug sections
and `__LD` (compact unwind, which the linker consumes). A section whose size or alignment would take the layout past 2^48 is not placed, with a
warning. After them come the segments the loader adds:

- `COMMON` (`.common` when the compiler emitted a section of that name), zero-filled and writable, for common
  symbols (`int x;` built with `-fcommon`).
- `extern`, one 8-byte slot per undefined symbol, named after it. An extern a call or branch relocation reaches
  (or that the object types as a function) is a function symbol; the others are data. A function extern's slot
  holds a branch to itself, which the decompiler takes as a call to the extern followed by a return, so a jump to
  one, conditional or not, decompiles as a call; a data extern's slot is zero. The segment is writable, so an
  extern variable never folds to a value, and it is no code section, so discovery never enters it. Externs are
  the object's imports; its global definitions are its exports.
- `.got` (Mach-O `__got`), read-only, one entry per symbol the code reaches through a GOT (position-independent code), holding the
  symbol's address (a GOT reference with a nonzero addend, which would need an entry for the symbol plus the
  addend, is left unapplied). Entries holding an extern are import slots (`__imp_printf`); entries holding a function the
  object defines are bound to it, so calls through them decompile by name. MIPS gets `$gp` at the GOT plus 0x7ff0,
  and local `%got` page entries.
- `.idata`, a COFF object's import table: one pointer slot per `__imp_X` symbol (what `__declspec(dllimport)` code
  calls through), holding the address of the extern `X`. The slots are import slots named `X` and the symbols
  `__imp_X`, so `call [__imp_GetTickCount]` decompiles as `GetTickCount()`. `X` is a function where code calls or
  jumps through the slot (and on ARM, which loads the pointer first); a data import otherwise.

COFF weak externals (`__attribute__((weak))`, `/ALTERNATENAME`-style aliases) resolve to their default symbol when
the object defines it, named for what they define (not LLVM's `.weak.NAME.default.X` label); an undefined weak
function with an absolute-zero default is null, as a linker leaves it.

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
| COFF AMD64 | `ADDR64`, `ADDR32`, `ADDR32NB`, `REL32`, `REL32_1`–`REL32_5`, `SECTION`, `SECREL` |
| COFF I386 | `DIR16`, `DIR32`, `DIR32NB`, `REL32`, `SECTION`, `SECREL` |
| COFF ARM64 | `ADDR32`, `ADDR32NB`, `ADDR64`, `BRANCH26`, `BRANCH19`, `BRANCH14`, `PAGEBASE_REL21`, `REL21`, `PAGEOFFSET_12A`, `PAGEOFFSET_12L`, `SECREL`, `SECREL_LOW12A`, `SECREL_HIGH12A`, `SECREL_LOW12L`, `SECTION`, `REL32` |
| COFF ARM (Thumb-2) | `ADDR32`, `ADDR32NB` (code pointers with the Thumb bit), `MOV32T`, `BRANCH20T`, `BRANCH24T`, `BLX23T`, `REL32`, `SECTION`, `SECREL` |
| Mach-O x86-64 | `UNSIGNED` (with `SUBTRACTOR` pairs), `SIGNED`, `SIGNED_1`/`2`/`4`, `BRANCH`, `GOT_LOAD`, `GOT` |
| Mach-O arm64 | `UNSIGNED` (with `SUBTRACTOR` pairs), `BRANCH26`, `PAGE21`, `PAGEOFF12` (scaled by the load or store's size), `GOT_LOAD_PAGE21`, `GOT_LOAD_PAGEOFF12`, `POINTER_TO_GOT`, each with its `ADDEND` |

REL and RELA sections are both read: a REL type's addend is the value its field stores, decoded per encoding
(Thumb branches, `movw`/`movt`, MIPS `%hi`/`%lo` pairs). COFF addends are always the field's (an `adrp`'s stored
immediate is bytes, a scaled load's offset is in units of its size), as `lld-link` reads them; Mach-O's too, except
arm64's, which come from an `ADDEND` relocation before the one they belong to. A COFF or Mach-O site's `value` is
the address the field references (`S + A` with `A` the offset from the symbol, so a call reads `printf`, not
`printf - 4` as an ELF site does). An ARM `bl` to a Thumb function the object defines
becomes `blx`, and a Thumb `bl` to an ARM one `blx`, as a linker makes them; a call to an extern keeps the form the
object gives it. A type outside the table is reported once per type in the warnings and in
`relocatable.unsupported` (with how many sites and the first), and its fields keep the file's bytes; the
decompiler treats those fields in data as volatile, so they never fold. ELF TLS and Mach-O `TLV*` relocations,
64-bit MIPS's composite types, COFF `TOKEN` and `SECREL7` and arm64e `AUTHENTICATED_POINTER` are among them (COFF
thread-local variables are reached through `SECREL`, which is applied: the offset in the object's own `.tls$`). Applied ELF fields match what `ld.lld` writes when linking the object
at the same addresses on the test fixtures of every architecture above. COFF and Mach-O linkers choose their own
layout, so those fixtures are checked by meaning: every relocation of the COFF (x64, x86, ARM64, Thumb) and
Mach-O (x86-64, arm64) fixtures references the same symbol plus addend in rampage's image as in `lld-link`'s or
`ld64.lld`'s output (with fixup chains and optimization hints off, which would rewrite the fields).

**Evidence.** `xrefs` rows in an object carry `relocation`: the relocation applied in the referencing instruction,
with its type, symbol (a section's name for a section symbol), addend and value (`S + A`, so an x86 call's field
reads `printf - 4`). A RISC-V `call` is relocated at its `auipc` while the call is recorded at the `jalr`, and a
`PCREL_LO12` names its `auipc`: both report the relocation there. Another instruction's relocation is never
borrowed.

**Functions.** COFF and Mach-O symbols carry no size, so in an object each function symbol runs to the next
function or data symbol in its section, or to the section's end (labels such as COFF `$LN5` are no boundary).
A COFF object's `.pdata` entries seed function starts, so SEH funclets (`$fin$0`, `$dtor$0`,
`$filt$0`), which only the exception tables reach, are functions too.

**Measured** (2026-11-26, on libraries the fixtures were not built from): every symbol-table function of every
loadable member was found as a function, and every call relocation reaches a named target, with no relocation type
left unapplied: Microsoft's `libucrt.lib` (x64 8050 functions in 722 members, ARM64 7898 in 692), `libcpmt.lib`
(x64 11,685, ARM64 23,926), `libvcruntime.lib` (x64 902, ARM64 2243) and `libcmt.lib` (x64 1208 in the 1060 members
with code; the other 130 are machine-independent alias objects); compiler-rt's universal `libclang_rt.osx.a`
(x86-64 134, arm64 293) and Homebrew's `libcapstone.a` (1475 functions, 23,070 calls), `libbrotlidec.a` and
`libb2.a`. Decompiling the first function of every 4th to 25th member succeeded for 117 of 118 (one capstone
function reaches an instruction the decompiler cannot read); ARM64 `libucrt.lib`'s `strtok`, outside the sample,
fails a callee type-hint check in the decompiler.

**Modes.** `$a`, `$t` and `$d` mapping symbols and Thumb function symbols mark Thumb code, as they do in an
executable; an M-profile object is all Thumb.

**Decompiling.** Read-only data folds to the values it holds once relocated (literal pools, the GOT, pointer
tables), so loads read as the globals and strings they reach. Externs are functions: calls render by name with
the libc prototype when the name has one, and a jump to an extern (a tail call) is a call followed by a return.

## Static libraries

`archive_inventory` (group `carve`; CLI `binary archive-inventory`) lists a library's members, GNU or BSD `ar`
format (`__.SYMDEF SORTED` too), an MSVC `.lib` (its `/` linker members and `//` long names) or a Mach-O universal
library, with the symbols the library's index gives each and the path that opens one:

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

An MSVC library's member names are often the full path of the build machine's object
(`d:\...\qsort.obj`); the row's `open` spells it, and `lib.lib(#215)` names the same member shorter.
Machine-independent members (`IMAGE_FILE_MACHINE_UNKNOWN`, which only alias symbols) are listed as
`coff relocatable unknown` and refused, as holding no code, when opened.

**Import libraries.** A member that is a short import object (an `IMPORT_OBJECT_HEADER`, what `kernel32.lib` holds)
is listed as `coff import` with its `import`: the DLL, the symbol, its kind (`code`, `data`, `const`), how the DLL's
export is found (`by`: `ordinal`, or a form of `name`) and the export name or the ordinal (`ordinal_or_hint`):

```json
{"index": 147, "name": "KERNEL32.dll", "format": "coff import x86_64",
 "import": {"dll": "KERNEL32.dll", "symbol": "CreateFileW", "kind": "code", "by": "name",
            "import": "CreateFileW", "ordinal_or_hint": 235},
 "symbols": ["CreateFileW", "__imp_CreateFileW"]}
```

Opening one is refused with what it imports, since it holds no code.

**Universal libraries.** A Mach-O universal `.a` holds one archive per architecture; `archive_inventory` lists every
slice's members (format `universal ar`, each row with its `arch`), and a member path opens the member of the slice
`arch` picks (x86-64, then arm64, without one):

```sh
rampage function decompile --arch aarch64 --at _bump 'libobjects-macho.a(objects.o)'
```

## Signatures from a library

`build_signatures` (group `detection`; CLI `function build-signatures`) takes a static library as its `path` and
builds one database from every relocatable object in it, in archive order (`arch` picks a universal library's
slice; import objects and other architectures' members are skipped and counted):

```sh
rampage function build-signatures libfoo.a --output libfoo.json
rampage function identify --db libfoo.json --no-bundled stripped-program
```

```json
{"path": "libfoo.a", "output": "libfoo.json"}
```

Each function adds the masked-hash signatures a binary's would (over its symbol size and its discovered extent),
and a pattern record (the [PAT namespace](signature-imports.md)) whose wildcards are exactly the bytes its
relocations patched: the field's bytes, or for a MIPS `%hi`/`%lo`, GOT or GP-relative relocation the instruction's
16-bit immediate alone, and every field left unapplied. The hashes can only mask what an instruction's form says
may move, and keep MIPS `lui`/`addiu` address pairs, which differ between an object and the program it is linked
into; the patterns leave those out and nothing else. A record whose fixed bytes are under half of what it covers
is not written, since it would only withhold names. The receipt counts members used and skipped, functions,
signatures, callee keys and `pat_records`.

Members are judged by their format before loading: short import objects, machine-independent alias objects and
other non-objects are counted under `skipped` by kind, a member that loads but names no sized function as `no named
functions`, and a library none of whose objects names one is refused. A cancelled MCP call stops between members
and writes nothing.

On the fixtures, a database built from a two-member MIPS library names all seven of its functions in a stripped
program statically linked against it; the same objects' hashes alone name two (the ones with no relocation). One
built from the COFF `.lib` names all ten functions of the program `lld-link` links from it (x64), and one from the
universal library's arm64 slice the four of `ld64.lld`'s program that pass the hash gate's four instructions and
keep their bytes (`_bump`'s GOT load is relaxed by the linker); the patterns alone, with every hash taken out of the
database, name the functions with relocations in both. That program is linked without arm64 optimization hints:
with them, `ld64.lld` rewrites `adrp`/`ldr` pairs no relocation names, and those functions do not match.

## Limits

- ELF, COFF and 64-bit Mach-O objects (32-bit Mach-O objects and their scattered relocations are not laid out);
  ELF core dumps are not snapshot sources.
- One member at a time: a whole library is not opened as one project, so calls between members reach externs, not
  the other member's function. COMDAT groups are laid out as they are (one object holds no duplicates).
- DWARF in an object is not imported (its addresses are relocated too).
- No linker relaxation: `GOTPCRELX` loads keep going through the GOT.
- Signature patterns from a library match a function only where the linked copy has the object's bytes outside
  the relocated fields: a linker that relaxes an instruction (`GOTPCRELX` to `lea`, a TLS sequence, an arm64 GOT
  load turned into an address computation, arm64 optimization hints) changes bytes no relocation names, and the
  pattern does not match there (the hash may). A pattern also
  needs the target's discovered extent to equal the function's length in the object or its discovered extent there.
