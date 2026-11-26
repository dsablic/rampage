# Raw code

Headerless code (a flash dump, a decoded firmware image, a ROM) has no file header saying where it loads, what
processor runs it or where it starts. rampage reads it in two ways:

- a **Raw project**: the `raw` selector, accepted by the Raw-capable tools, maps the bytes at an asserted base
  address with a processor profile, and discovery, decompilation, strings, patches and the rest run as on an
  ordinary binary;
- a **raw-code window**: `inspect_raw_code` decodes a few instructions of x86, x64, ARM or AArch64 linearly, with
  no functions or references ([below](#raw-code-windows)).

This page is the workflow for Raw projects. The field-by-field reference is [Raw projects in MCP](mcp.md#raw-projects),
the processor profiles are in [Sleigh decoding](sleigh-decoding.md#ordinary-raw-projects) and the Cortex-M
specifics in [the Cortex-M profile](sleigh-decoding.md#cortex-m-profile). For a whole vendor update file, start
with [the firmware walkthrough](firmware-walkthrough.md).

## Open a Raw project

Pass `raw` instead of a native image: `profile` (a Raw language ID or an alias such as `cortex-m4`, `msp430` or
`avr`), `offset` and `length` (the bytes in the file) and `base_address`. For Cortex-M firmware add
`"vector_table": true` to read the vector table at the base: Reset becomes the entry and the other handlers seeds.
The table is refused as a whole, with `raw.vector_table.refused_reason`, when its Reset word is no Thumb address in
the code, or when its initial SP lies outside RAM (0x10000000 to 0x40000000, or a `ram` region you map) and fewer
than two other handlers check out: an image that starts with code (many decoded updates do) is then not misread,
and you open it with `entry` instead. A table with an SP in external SDRAM is kept, its SP word flagged
`sp_outside_ram`; map that RAM as a `ram` region to accept it.

```json
{
  "path": "tests/fixtures/firmware/raw-cortex-m.bin",
  "raw": { "profile": "cortex-m3", "offset": 0, "length": 800, "base_address": "0x8000000", "vector_table": true }
}
```

Start with `binary_info`, which reports the interpretation under `raw` (regions, vector table, pointer tables,
startup copies, the base check), then `list_functions` and `decompile`. Use `"view": "summary"` when the full
report is large: `raw` lists keep their first rows with counts. The session keeps the project, with its
annotations, for that exact interpretation. Over MCP, once it is the only binary the connection has opened, later
calls may leave out `path` and `raw` (or give the path alone) and reach the same project; with more than one open,
repeat the `raw` object (see [the session target](mcp.md#inputs-paging-and-decompiler-tokens)). The CLI takes the same object as
`--raw-json` ([CLI reference](cli-reference.md#raw-projects)).

Only MSP430, AVR8, Cortex-M, MIPS32 and Xtensa decompile; the other Sleigh profiles disassemble. On Cortex-M, `decompile` with
`"exact_entry": true` decompiles from an address you assert (an odd address is read as the Thumb code at the even
one, with a `note`), discovered or not, with its context
counts and omissions; plain `decompile` also takes any code address. Multiple regions, decoded
regions, scatter-load and pointer tables are Cortex-M only, except a decoded primary region, which any profile
takes, and further regions, which MIPS32 and Xtensa take too.

## MIPS boot ROMs and bare-metal MIPS

A MIPS32 boot ROM, bootloader or bare-metal image (router and camera SoCs, PIC32 in MIPS32 mode) opens with the
`MIPS:BE:32:default` profile (aliases `mips`, `mips32`, `mipseb`) or `MIPS:LE:32:default` (`mipsel`), decoded
natively like Cortex-M: up to 4 MiB, further `regions` (a second stage at its RAM address, for example), typed
operands and data references, `decompile` with the MIPS o32 C model and `evaluate_function`. Without `entry` the
entry is `base_address`: a MIPS32 boot ROM starts at the reset vector, 0xbfc00000 (uncached kseg1), and copies or
jumps to code in cached kseg0 (0x80000000 up). Map the image where it runs:

```json
{
  "path": "tests/fixtures/mips/boot-mips.bin",
  "raw": { "profile": "mips", "offset": 0, "length": 1186, "base_address": "0xbfc00000" }
}
```

Absolute `lui`/`addiu` pairs give string and data references, and `find_main` follows the reset code to its C entry
(see [find main](#find-main)). The exception vectors at 0xbfc00200 and 0xbfc00380 (BEV set) are not
seeded on their own; add them to `seeds` when the image has handlers there. A Raw MIPS image is read as MIPS32
only: microMIPS and MIPS16e code, MIPS64 and the vector table, pointer-table and scatter-load options of Cortex-M
have no MIPS equivalent. A Linux userland or kernel ELF needs no Raw project: open it directly
(position-independent code resolves its GOT through `$gp`, and MIPS16e code is decoded when the ELF header marks
it, as OpenWrt's programs do). An ELF whose header marks microMIPS code gets a `binary_info` warning and a
`list_functions` note that only its MIPS32 code is analysed.

## ESP32 and ESP8266 firmware

Espressif firmware is Xtensa code: the ESP32, ESP32-S2 and ESP32-S3 (LX6/LX7 cores, windowed register ABI) and
the ESP8266 (LX106, call0 ABI). The `Xtensa:LE:32:default` profile (aliases `xtensa`, `esp32`, `esp8266`, `lx6`,
`lx7`, `lx106`) is decoded natively, as Cortex-M and MIPS are: up to 4 MiB, further regions, typed operands and
data references, `decompile` and `evaluate_function`. An app image (the `.bin` a build writes, magic 0xE9) opens
with `"format": "esp"`, which takes every address from its segment headers: give the image's file `offset`
(default 0) and no `length` or `base_address`.

```json
{
  "path": "tests/fixtures/xtensa/esp32-flash.bin",
  "raw": { "profile": "esp32", "format": "esp", "offset": "0x10000" }
}
```

Each segment becomes a region at its load address by the chip's memory map: IRAM and flash-mapped IROM code,
flash-mapped DROM constants, DRAM and RTC memory as RAM with their initial bytes, and the rest of the chip's DRAM
(`.bss`, the heap) as RAM without bytes, so globals there resolve and `evaluate_function` can use them. A valid
image needs its checksum and, when one is appended, its SHA-256 to match. esptool's padding segments and
addresses outside the map are reported and not mapped; segment counts above 16, lengths past the file and
overlapping segments are refused. The header's entry (`call_start_cpu0` on ESP-IDF) is the entry. `binary_info`
reports the image under `raw.esp`: chip, ABI, flash mode, size and frequency, every segment with its memory, the
checksum and appended SHA-256 (each with `valid`), and `esp_app_desc` (project name, version, ESP-IDF version,
build date and time, secure version, the ELF's SHA-256). An ESP8266 image at the start of a flash dump also maps
the rest of the flash as IROM at 0x40200000 plus its offset, as the cache does, so its flash code (NONOS SDK
`irom0` at flash 0x10000, 0x40210000) is in the project; the cache maps only the first 1 MiB, and `raw.esp.notes`
says when flash past it (or past the profile's 4 MiB) is left out. Plain `binary` bytes of Xtensa code with no
image header are taken as call0 when their 4-byte aligned frame allocations outnumber `entry` prologues four to
one, else as windowed. ESP32-family chips without Xtensa cores (C2, C3, C6, H2,
P4: RISC-V) are refused.

A whole flash dump is not opened as one project. `binary_info` on it (with no `raw`) names what it holds: the
bootloader image at 0x1000 (0 on the ESP32-S3), the partition table at 0x8000 (or another 4 KiB boundary below
0x10000) with each partition's label, type, subtype and offset, and the `raw` selector of each application
partition's image. `file_layout` hints the same structure, `carve` reports `esp_image` and `esp_partition_table`
candidates (the table's MD5 entry checked), and `list_dir` names `esp_image` and `esp_flash` files. Open the
bootloader with its offset as you would an app.

Some dumps start at flash 0x1000 rather than 0: a file that begins with an ESP32 or ESP32-S2 bootloader image (as
MicroPython's ESP32 `.bin` does) is read that way, as is one whose partition table at file 0x7000 points at
application images 0x1000 bytes early when the bootloader fails its digest. Partition offsets are then mapped
through that base, so the `factory` app at flash 0x10000 is at file 0xf000, and the selectors `binary_info`,
`file_layout`, `carve` and `diff_firmware` give are file offsets; the open error says that the dump starts at flash
0x1000.

Discovery seeds windowed functions from their `entry a1, N` prologue and call0 ones from their stack adjustment
(`addi a1, a1, -N`, with the argument moves GCC schedules before it), so task entries and handlers reached only
through pointers are found. Strings, globals, constants and far call targets are `l32r` literals: references go to
what the literal holds, `-mlongcalls`' `l32r` + `callx8` is a call to its target (ROM functions included),
`disassemble` comments each `l32r` with the string or function it loads, and constant search matches it
(`loaded_constant`). The decompiler folds literals (flash is read-only), so calls and strings read as addresses
rather than literal-pool variables, and code from an ESP8266 image or an ELF whose `.xtensa.info` says call0 gets
the call0 model. The decompiler does not model zero-overhead loops (`loop` bodies read as running once), which
`evaluate_function` does. ROM functions are not named. `find_main` finds `app_main` from ESP-IDF's `main_task` (see
[find main](#find-main)).

## Choose the base address

The base is your assertion, and a wrong one quietly ruins a Cortex-M project: the vector table is refused, literal
pool pointers point nowhere and the reset-code follow fetches outside the image. rampage suggests bases and checks
the one you chose, but never changes it:

- `decode_file_range` and `probe_compression` return `base_candidates` for decoded bytes: up to five bases ranked by
  pointers that land on function prologues and strings, literal-pool constants, reset-code constants, a vector
  table at offset 0 and hints from a container record. When one is clearly strongest, `next` names it.
- When handler words in the vector table fall outside the mapping, `raw.vector_table.base_address_suggestion`
  gives the most aligned base that would hold them.
- `raw.base_check` in `binary_info` judges the base you gave: `consistent`, `looks_wrong` (with
  `better_candidate` and a `next` naming the base to reopen with) or `unknown`.

See [load-address candidates and `base_check`](mcp.md#load-address-candidates-and-base_check) for the evidence and
the rules.

## Open a compressed image

A firmware update often stores its application compressed. Put `decode` in the selector and the decoded bytes
become the primary code region: `offset` and `length` then select the encoded bytes (at most 8 MiB), and
`decode.expected_output_size` is the mapped size. The vector table, pointer tables, entry and seeds address the
decoded bytes.

You rarely write `decode` by hand. `decode_file_range` and each reproduced `probe_compression` candidate return
`open_as_raw`, the selector without `profile` and `base_address`: add those two and pass it as `raw`.
`write_decoded_range` (CLI: `binary decode --output PATH`) writes the decoded bytes to a new file when another
tool needs one, such as a scanner that reads files. See
[a compressed image as the code region](mcp.md#a-compressed-image-as-the-code-region) and
[decoding](decoding.md).

## Code that runs from RAM

A compressed application cannot run from flash: a bootloader decodes it into RAM and jumps there, and its globals
sit in the same bytes as its code. Mapped read-only, as flash is, that image misleads the decompiler: every store to
a global carries `WARNING: Read-only address (ram,0x…) is written`, and a read of a global the program changes can
be folded into the value the image held (`return 3;` for a mode set at run time). On Cortex-M a primary region the
program writes is therefore writable for the decompiler:

- mapped in SRAM (`base_address` 0x20000000 to 0x3fffffff), it is writable by its address;
- decoded (`decode`) anywhere else, it is writable once discovery finds code storing into at least two of its words;
- `"writable": true` or `false` on the selector says so yourself, for any profile, such as for a plain dump of an
  image that runs from RAM at a non-SRAM address. A further `code` region takes `"writable": true` the same way.

Its function bodies, literal pools and strings stay read-only, so calls, switches, strings and constants read as
before; only its globals stop folding. Check
the verdict in `binary_info`: `raw.regions[0].writable` and `writable_reason` (`ram_address`, `stores` or
`stated`). An image that runs from flash stays read-only, so its constants keep folding. See
[writable code regions](mcp.md#writable-code-regions).

## Map further regions

A Cortex-M project takes up to 15 `regions` beside the primary one, each `code`, `data` or `ram`, so a second
stage or RAM is analysed at the address it runs from. A region takes its bytes from one of:

- a range of the same file (`offset` and `length`);
- a decoder's output over a range (`decode`, as above);
- a slice of an earlier region (`from: {region, offset}`), for code or data that startup copies from its load
  address to its run address. `"region": "primary"` slices the primary region, decoded bytes included;
- nothing: a `ram` region without `offset` is zero-filled or uninitialised RAM, or memory-mapped I/O.

Backed regions together hold at most 4 MiB. A patch to a slice goes to its source region.
[Multiple regions](mcp.md#multiple-regions-intel-hex-and-s-records) has the fields; Intel HEX and S-record files
(`"format": "ihex"` or `"srec"`) map their record runs as regions instead.

## Let scatter-load map the startup copies

Startup code usually copies code and initialised data from flash to TCM or SRAM, zeroes `.bss`, then jumps into
the copied code, so discovery from the entry stops in the startup code. On Cortex-M, rampage follows the reset
code from the entry with a bounded interpreter (nothing runs on the host) and records what it copies and zeroes.
By default each copy is mapped at its run address and the jump into it is seeded, so `list_functions` and
`decompile` reach the copied code without hand-written `regions`.

A copy is mapped only when it is safe to:

- the part of the follow that made it finished (a copy cut off by a skipped call or an unclean stop is
  `incomplete`), and nothing overwrote it;
- its source lies wholly in one backed region and its destination is unmapped (a region you state yourself always
  wins);
- the 16-region and 4 MiB caps hold.

Copied code that ran and was not stored into afterwards maps as `code`; other copies map as writable `ram` with
their initial bytes; zero fills map as unbacked `ram`. Every copy, mapped or not, is listed in
`raw.scatter_load` with its source, destination, store sites and routine, and an unmapped one says why in
`not_mapped_reason`. A patch inside a mapped copy is refused with the load address to patch instead.

After the jump the follow goes on, bounded, for stores to the Vector Table Offset Register: the table at the last
value is read when a mapped region holds it, and its handlers are seeded, so interrupt handlers that only a
relocated vector table names are discovered.

To see the copies without mapping them, pass `"scatter_load": false`. When that leaves discovery sparse,
`list_functions` says so in `next`. See [scatter-load copies](mcp.md#scatter-load-copies) for every field and
stop reason.

## Functions named only in data

Discovery follows calls, jumps and code addresses the code loads. Firmware also names functions only in data:
an RTOS thread definition (`{name, entry, stack size, priority}`) passed by address, a driver descriptor, a table
of init routines. On Cortex-M, after discovery the words just past each address the code references are read;
an odd word that points at code outside every discovered function, not at text, becomes a function start when
its target opens with `push {..., lr}` or follows the end of another function (a return, a branch, padding), and
decodes straight to a return or branch, for up to three more rounds. A word among three or more code pointers in a
row (an array) needs the `push {..., lr}`, so an init or handler table counts and a switch's case labels do not.
So a task's code, and the strings it loads, are found although nothing calls the task. The work is bounded across
rounds; `binary_info`'s `raw.record_seeds` says what was seeded and whether the budget ran out.

## Pointer tables

Handlers reached only through tables of function pointers (command tables, callback arrays) are not found from
the entry. On Cortex-M, `pointer_tables` controls a scan for such tables in every code region (the primary one,
startup copies and your `regions`), each table's targets in the region holding it:

- unset (the default): automatic. The scan runs only when discovery from the entry, seeds, vector table,
  scatter-load jump and data records finds fewer than one function per 16 KiB of code, or functions covering less
  than an eighth of its code-like bytes (runs of one repeated byte, such as erased flash, do not count), and
  `binary_info` reports what happened under `raw.pointer_tables.automatic` (`applied`,
  `found_none` or `refused`, with `covered_bytes`); `list_functions` adds a `note`;
- `true`: always scan;
- `false`: never scan.

A table is accepted only when at least two distinct targets look like real functions; switch tables and stray
constants are reported as refused. See [Raw projects](mcp.md#raw-projects) for the evidence rules.

## CRC routines discovery missed

When a Cortex-M project opens with `pointer_tables` unset (the default), a CRC routine that no discovered code reaches (called only through a computed
pointer) is looked for the way `integrity_checks` infers it: a CRC-32 polynomial literal nothing references, the
PC-relative `ldr` of it outside every function, and a `push {..., lr}` prologue before the load. Each such start is
seeded into discovery, so `decompile`, `lock_mechanisms` and `integrity_checks` see the routine as a function, and
`binary_info` lists it in `raw.inferred_seeds` with that evidence. Code outside every discovered function that calls
the routine with a Thumb `bl`, inside a `push {..., lr}` routine, is seeded too (and its callers, three rounds deep),
so `xrefs` to the routine finds the check that uses it.

## Who reads a structure field

Firmware keeps its state in structures in RAM and reaches a field through a base register: `ldr r1, =0x20001234`
(a literal-pool load) or a MOVW/MOVT pair, then `ldrb r0, [r1, #11]`. `xrefs` `to` the field's address (0x2000123f
here) lists every load and store that reaches it so, with `access` (`read` or `write`) and `base`: `site` (the
instruction that set the base), `address`, `offset` and `width` in bytes. A row without `base` is a direct
reference. `search` with `references` carries the same `base` on its hits.

The base is followed through the function: along each straight-line run, and across branches and loops when every
path into the access sets the same base (a structure pointer loaded once into a callee-saved register and read in
a loop counts). A register written in between, a base set on only some paths, and stack-pointer-relative slots
give no reference. RAM, peripherals and the private peripheral bus (0x10000000 to 0xe0100000) need not be mapped:
a field there is listed when its base is mapped or lies in that space too. The rows show the structure's layout
from the code: `xrefs` `from` a function lists each field it touches with its offset from the base.

## Where to start reading

Once discovery has run (a Cortex-M request with `pointer_tables` unset runs it at open), `binary_info` lists
`raw.starting_points`: at most eight functions worth reading first, each with its reasons. They are the reset
handler, the function scatter-load's jump lands in and a trampoline's target, `find_main`'s candidate, the
largest init routines the startup calls through its table, and the CRC routines in `raw.inferred_seeds`. The
summary view keeps the whole list.

## Find main

`find_main` on a Cortex-M project follows the reset handler: through scatter-load's jump into copied code, and a
short trampoline that only loads the next code address and jumps there, to the first call that never returns (an
infinite loop, a scheduler start by `svc` or by pending PendSV through ICSR, or a call to such a function). After
the C runtime init (copies and zero fills, a loop of indirect calls over an init table) that call is the candidate
at medium confidence. When the startup jumps into copied code that itself calls the scheduler start, that copied
function is main. Each candidate lists the instructions it rests on; a reset handler that only calls a few
functions and loops gets no candidate. A main that returns, or a scheduler started another way, is not found.

On a MIPS project `find_main` follows the reset code at the entry. The usual `b reset` at the vector, which jumps
over the exception vectors, and other jumps taken before the stack pointer is set are followed (up to three); the
first forward jump after `$sp` is set, or one from uncached kseg1 into cached kseg0 (`la $t0, f; jr $t0`), is the
boot ROM's C entry, at medium confidence when discovery found a function there. Reset code that reaches its C code
by a call, sets the stack after its last jump, or jumps through a table is not followed.

On Xtensa (an ESP image or an Xtensa ELF) `find_main` takes `app_main` from ESP-IDF's `main_task`, the function
that logs "Returned from app_main()": the call between that line and "Calling app_main()" whose callee
`main_task` calls nowhere else, at high confidence (medium when only the "Returned" line is there). The startup
chain (`call_start_cpu0`, `start_cpu0`, the scheduler) creates that task through a pointer and is not followed,
so firmware without those log lines (the ESP8266 NONOS SDK's `user_init`, builds with logging off) gets no
candidate.

## Raw-capable tools

These tools take the `raw` selector:

| Area | Tools |
| --- | --- |
| Overview and triage | `binary_info`, `triage`, `triage_report`, `find_main`, `function_summary`, `capabilities` |
| Functions and code | `list_functions`, `disassemble`, `function_graph`, `decompile`, `xrefs`, `search`, `analysis_diagnostics`, `entry_diagnostics` |
| Data | `list_strings`, `inspect_data` (a file tool) |
| Annotations | `rename`, `set_comment`, `annotate_batch`, `list_annotations`, `undo`, `redo` |
| Execution | `evaluate_function` (processors the interpreter supports, Cortex-M, MIPS32 and Xtensa among them) |
| Peripherals | `import_svd`, `peripheral_access` |
| Patching | `patch_bytes`, `revert_patch`, `list_patches`, `integrity_checks`, `export_image` |
| Detection | `identify_functions`, `find_crypto`, `lock_mechanisms` |

Other tools refuse a `raw` selector by name. Annotations on a Raw project live in the session only: no sidecar or
log is written. On a Raw project `triage` and `triage_report` say which file-format facts (imports, build time,
hardening) do not apply.

## Raw-code windows

`inspect_raw_code` inspects a bounded original-file range without an executable header. Supply `path`,
`offset`, `length`, `arch`, `mode`, `code_byte_order`, `data_byte_order` and `base_address`; `instruction_limit`
defaults to 64. Architecture/mode/order/base are analyst assertions, not detection or validated load mappings.

The result binds the selected bytes to a range hash, preserves original-file offsets separately from asserted
VAs, and returns linear decoder observations with a stop reason, consumed/remaining counts and continuation
parameters. It does not follow targets or create functions, annotations, sidecars or extracted files.

CLI uses the same request fields, excluding the positional path:

```sh
request='{"offset":0,"length":4,"arch":"arm","mode":"thumb",
"code_byte_order":"little","data_byte_order":"little","base_address":"0x1000"}'
rampage --json binary inspect-raw input.bin --request "$request"
```

Limits: 4096 input bytes, 256 instructions, x86/x64/ARM/AArch64 and little-endian code/data only; ARM requires
`arm` or `thumb`, other architectures `native`. `thumb` is A-profile Thumb: M-profile system-register moves (`msr
basepri, r0`) are invalid here. Open Cortex-M code as the `ARM:LE:32:Cortex` Raw profile instead ([Cortex-M
profile](sleigh-decoding.md#cortex-m-profile)), which decodes them. Invalid/incomplete instructions remain
unconsumed. ARM literal reads use complete words in the supplied suffix; backward literals and prior IT context
outside the window remain unknown. JSON is bounded and complete or refused. File access uses the Unix regular-file
checks; reads are non-atomic. `inspect_raw_code` does not decode compressed input; use a Raw project with `decode`
for that.

Owned acceptance assembles `tests/fixtures/src/raw-window.s` for Thumb, extracts its `.text` centrally, and
runs `compiler_owned_thumb_window` with `RAMPAGE_RAW_FIXTURE` set to those bytes. No target execution is needed.
