# CMSIS-SVD peripheral maps

Firmware reaches hardware through memory-mapped registers, so decompiled Cortex-M code is full of writes such as
`*(uint32_t *)0x40021018 |= 4`. A CMSIS-SVD file describes the device's peripherals, registers and bit fields;
importing one names them on every surface.

## Importing

`import_svd` (group `types`) takes the binary (or a `raw` selector) and `svd`, the path of the `.svd` file. It
previews by default: the device, counts, the changes it would make and the reader's warnings. With `apply: true` it
stores each peripheral as an annotation at its base address, replacing any earlier import, in one undo step. A
native binary keeps them in its annotation log beside the binary; a Raw project keeps them in memory for the
session and interpretation, like its other annotations, so import again with the same `raw` selector after a
restart.

The reader handles `derivedFrom` (peripherals, registers, clusters and fields), `dim` arrays with `dimIncrement` and
`dimIndex` lists or ranges, clusters (flattened: `CH0_CR`), register `size`, `access` and `resetValue` inherited
from device to peripheral to cluster to register, field positions as `bitOffset`/`bitWidth`, `lsb`/`msb` or
`bitRange`, and enumerated values. A register array whose elements are contiguous keeps C subscripts
(`RELOAD[2]`); other arrays number their elements (`DATA0`, `DATAA`).

## What changes

- **Decompilation.** Each peripheral becomes a struct global at its base (`struct TIMER0_regs TIMER0;`), with
  padding for gaps, so register accesses read `TIMER0.CR = TIMER0.CR | 0x21;`. A peripheral the image does not
  map gets a writable, zero-filled region of its own, so reads never fold to constants. On a line that touches
  one register, each constant gets a comment naming the fields it sets or clears:
  `/* CR: EN|MODE=Single_MATCH */`, `/* CR: ~(EN) */`. Shift counts and subscripts are not decoded.
- **Names.** Any address inside a peripheral is named `TIMER0.CR` (`TIMER0.CR+2` inside a register,
  `TIMER0+0x30` in a gap) in disassembly comments, xref rows and `evaluate_function` faults, and `TIMER0` or
  `TIMER0.CR` is accepted wherever a tool takes an address.
- **Accesses.** A p-code scan of every function finds the loads and stores whose address is a constant: through
  literal pools, `movw`/`movt` pairs and base-plus-offset addressing, across blocks within a function, keeping
  only the registers a call preserves (r4-r11 on ARM). Disassembly comments name the register each line loads or
  stores. `xrefs` with `to` a register lists those instructions with `access: read|write`; `to` a peripheral's
  name covers all its registers.
- **`peripheral_access`** lists the imported peripherals with read, write and function counts, or, with
  `peripheral`, that peripheral's registers with their bit fields (`MODE[6:4]`), reset value, read and write counts
  and up to eight accessing functions. Both page with `offset`/`limit`.
- **`evaluate_function`** names the register in an `unmapped_read` or `unmapped_write`, and takes `mmio`: up to
  64 `{at, value}` pairs, `at` an address or `PERIPHERAL.REGISTER`. Each maps its 4 KiB page as RAM and stores the
  value at the register's width, so a routine polling a status register runs to completion.

## Limits

The SVD file is at most 64 MiB, with at most 4,000,000 XML elements nested at most 64 deep, 4096 peripherals,
131,072 registers, 4096 elements per `dim`, 256 fields per register and 256 enumerated values per field; clusters
nest at most 16 deep and `derivedFrom` chains at most 16 links. No XML entity other than the predefined and
character references is expanded and no DTD is read. Descriptions are cut to 96 characters, and dropped if the
stored map would pass 4 MiB; past that the import is refused. Peripherals that duplicate an earlier name or base
are skipped with a warning.

A peripheral is typed for decompilation only when its struct does not overlap another peripheral, an analyst
global or typed data, code, or the edge of a mapped range; the import lists the untyped ones, whose addresses are
still named. Overlapping registers (alternates) take the first declared in the struct and in names. Registers
whose width is not 1, 2, 4 or 8 bytes, or that are misaligned, are named but left out of the struct. Bit fields
are comments, not C bit-fields, and a constant is decoded only on a line that names exactly one register. The
access scan follows constants within a function only (not through memory, stack slots or callers' arguments),
decodes at most 4,000,000 instructions and keeps at most 1,048,576 accesses; past either, results say
`incomplete`. It needs the target's Sleigh p-code decoder, as `evaluate_function` does. Peripheral annotations
are not carried by `transfer_annotations`; import the map again on the new build.

Test data: `tests/fixtures/svd/ARM_Example.svd` is Arm's CMSIS-SVD example (BSD-3-Clause, notice kept in the
file and in `ARM_Example.svd.LICENSE.txt`); `edge-cases.svd` is synthetic. `tests/fixtures/firmware/raw-cortex-m-svd.c`
drives the example's timers.
