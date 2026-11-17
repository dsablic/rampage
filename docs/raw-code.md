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

```json
{
  "path": "tests/fixtures/firmware/raw-cortex-m.bin",
  "raw": { "profile": "cortex-m3", "offset": 0, "length": 800, "base_address": "0x8000000", "vector_table": true }
}
```

Start with `binary_info`, which reports the interpretation under `raw` (regions, vector table, pointer tables,
startup copies, the base check), then `list_functions` and `decompile`. Use `"view": "summary"` when the full
report is large: `raw` lists keep their first rows with counts. Repeat the same `raw` object on every call; the
session keeps the project, with its annotations, for that exact interpretation. The CLI takes the same object as
`--raw-json` ([CLI reference](cli-reference.md#raw-projects)).

Only MSP430, AVR8 and Cortex-M decompile; the other Sleigh profiles disassemble. Multiple regions, decoded
regions, scatter-load and pointer tables are Cortex-M only, except a decoded primary region, which any profile
takes.

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
`write_decoded_range` writes the decoded bytes to a new file when another tool needs one. See
[a compressed image as the code region](mcp.md#a-compressed-image-as-the-code-region) and
[decoding](decoding.md).

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
an odd word that points at code outside every discovered function and decodes like code (a `push {..., lr}`
first, or a straight run that reaches a return or branch), and not at text, becomes a function start, for up to
three more rounds. So a task's code, and the strings it loads, are found although nothing calls the task.

## Pointer tables

Handlers reached only through tables of function pointers (command tables, callback arrays) are not found from
the entry. On Cortex-M, `pointer_tables` controls a scan for such tables in every code region (the primary one,
startup copies and your `regions`), each table's targets in the region holding it:

- unset (the default): automatic. The scan runs only when discovery from the entry, seeds, vector table,
  scatter-load jump and data records finds fewer than one function per 16 KiB of code, or functions covering less
  than an eighth of it, and `binary_info` reports what happened under `raw.pointer_tables.automatic` (`applied`,
  `found_none` or `refused`, with `covered_bytes`); `list_functions` adds a `note`;
- `true`: always scan;
- `false`: never scan.

A table is accepted only when at least two distinct targets look like real functions; switch tables and stray
constants are reported as refused. See [Raw projects](mcp.md#raw-projects) for the evidence rules.

## Find main

`find_main` on a Cortex-M project follows the reset handler: through scatter-load's jump into copied code, and a
short trampoline that only loads the next code address and jumps there, to the first call that never returns (an
infinite loop, a scheduler start by `svc` or by pending PendSV through ICSR, or a call to such a function). After
the C runtime init (copies and zero fills, a loop of indirect calls over an init table) that call is the candidate
at medium confidence. When the startup jumps into copied code that itself calls the scheduler start, that copied
function is main. Each candidate lists the instructions it rests on; a reset handler that only calls a few
functions and loops gets no candidate. A main that returns, or a scheduler started another way, is not found.

## Raw-capable tools

These tools take the `raw` selector:

| Area | Tools |
| --- | --- |
| Overview and triage | `binary_info`, `triage`, `triage_report`, `find_main`, `function_summary`, `capabilities` |
| Functions and code | `list_functions`, `disassemble`, `function_graph`, `decompile`, `xrefs`, `search`, `analysis_diagnostics`, `entry_diagnostics` |
| Data | `list_strings`, `inspect_data` (a file tool) |
| Annotations | `rename`, `set_comment`, `annotate_batch`, `list_annotations`, `undo`, `redo` |
| Execution | `evaluate_function` (processors the interpreter supports, Cortex-M among them) |
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
