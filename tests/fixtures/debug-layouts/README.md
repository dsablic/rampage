# Debug flat-layout fixture contract

These workspace-owned Apache-2.0 inputs are generic test data for bounded,
pointer-only flat-struct debug import. They are not class recovery fixtures and
contain no investigation artifacts. No generated binary is committed by this
recipe. The ELF files are analysis inputs, never executables to run.

## Positive layout

`flat.h` declares the complete `debug_flat` tag and typedef with explicit
`aligned(8)`, equal to its natural x86_64 alignment. This annotation supplies
alignment evidence for Clang's DWARF; it does not change the measured layout.

| Field | C type | Offset | Size | Type alignment |
| --- | --- | ---: | ---: | ---: |
| `tag` | `signed char` | 0 | 1 | 1 |
| `count` | `int` | 4 | 4 | 4 |
| `flags` | `unsigned short` | 8 | 2 | 2 |
| `weight` | `double` | 16 | 8 | 8 |
| `value` | `int *` | 24 | 8 | 8 |
| `tail` | `unsigned char` | 32 | 1 | 1 |

The complete struct is 40 bytes, aligned to 8 bytes. Internal padding occupies
half-open byte ranges `[1,4)` and `[10,16)`; tail padding occupies `[33,40)`.
Static `sizeof`, `_Alignof`, and `__builtin_offsetof` assertions bind the source
to these target facts. No target headers or libc are needed.

Every function in `flat_use.c` is noinline. Its first parameter is exactly
`debug_flat *item`, not `void *`, an integer, or a by-value aggregate. Prototypes
are in `flat.h`. The independent semantic field-access pairs are:

| Symbol | Required field access |
| --- | --- |
| `debug_flat_read_first` | Read `item->tag` with signed widening |
| `debug_flat_read_interior` | Read `item->count` |
| `debug_flat_read_flags` | Read `item->flags` with unsigned widening |
| `debug_flat_read_weight` | Read `item->weight` as floating point |
| `debug_flat_read_pointer` | Read `item->value` as an ordinary scalar pointer |
| `debug_flat_read_final` | Read `item->tail` with unsigned widening |
| `debug_flat_write_first` | Write `item->tag` |
| `debug_flat_write_interior` | Write `item->count` |
| `debug_flat_write_final` | Write `item->tail` |

Acceptance checks must prove these actual `->field` accesses after approved
import. Merely finding a struct name or signature is insufficient. They should
compare semantic accesses, not exact assembly or register allocation.

## Independent constant oracle

`flat_constants.c` supplies the allocated, read-only `.rampage_debug_layout`
section and global `debug_flat_layout_constants` symbol. The section contains
exactly 25 little-endian unsigned 64-bit words (200 bytes), with no relocations:

| Word indices | Meaning |
| --- | --- |
| 0 | Magic `0x52414d5044424731` |
| 1 | Format version `1` |
| 2 | Target pointer width `8` |
| 3 | Little-endian tag `1` |
| 4 | Compiler-measured complete `sizeof(debug_flat)` |
| 5 | Compiler-measured `_Alignof(debug_flat)` |
| 6 | Field count `6` |
| 7–24 | Six `(offset, actual member size, C type alignment)` triples in declaration order |

`oracle.json` is the source-static expected oracle. `verify_oracle.py` compares
it with compiler-emitted constants and verifies independent ELF, symbol, and
debug-version facts; it does not consult production DWARF type parsing. Thus a
loader that associates the wrong type, guesses an alignment, or invents an
offset cannot define its own expected result.

The identity/collision constant sections contain six LE u64 words each:
`(struct size, struct alignment, first offset, first size, tail offset, tail size)`.
Their exact expected values are in `oracle.json` under `groups.extra_constants`.

## Identity and refusal groups

* `identity-compatible`: separate CUs `identity_a.c` and `identity_b.c` both
  define `debug_identity`: size 8, alignment 8, tail offset 4.
* `identity-incompatible`: adds a third CU with the same tag, size 16 and tail
  offset 8; parameters must retain their CU/DIE identities.
* `collisions`: Clang's `$` identifier extension supplies
  `debug_collision$slot` and `debug_collision_slot`. They sanitize to the same
  declaration spelling but have different sizes and tail offsets.
* `refusals`: missing explicit alignment, packed, overaligned, union, bitfield,
  nested, recursive, array, flexible array, incomplete type, by-value argument,
  and by-value return.
* `inheritance`: explicit opt-in C++ inheritance and virtual-base location
  expression controls.

Compatible layouts may be deduplicated or kept separately if parameters remain
correctly bound. Same-name incompatible layouts and sanitized-name collisions
must never be attached by name alone. A consumer may safely refuse an ambiguous
candidate rather than incorrectly attach a layout. Refusals must not receive an
invented layout or turn unproved memory accesses into struct field accesses.

`debug_missing_alignment` has the same natural size and alignment as the
positive layout but intentionally lacks `aligned(8)`. The parent loader lane
must inspect the emitted attribute before using this as a missing-evidence test:
if a compiler supplies natural alignment unasked, remove that attribute in a
separate synthetic negative instead of treating a valid attribute as missing.
Ordinary expression-based member offsets, unknown layout attributes, malformed
references, and budget/cycle cases are also loader-lane synthetic mutations;
the compiler recipe does not pretend to emit malformed DWARF.

## Build recipe interface

`bash tools/ci/debug-layout-oracle.sh [--check command arguments...]` delegates
to `build.sh`. Fixture generation cross-compiles, links, and inspects without executing
target code. Generation invokes neither Cargo nor rustc and installs no tools;
the optional check hook may invoke them for validation afterward.

| Variable | Meaning / default |
| --- | --- |
| `CLANG` | Target-capable Clang executable; default `clang` |
| `LD` | ELF LLD executable; default `ld.lld`, or sysroot `rust-lld` |
| `OBJCOPY` | LLVM objcopy executable; default `llvm-objcopy`, or sysroot `rust-objcopy` |
| `PYTHON` | Python 3.9+ executable; default `python3` |
| `RUST_SYSROOT` | Optional explicit Rust sysroot for existing linker/objcopy tools |
| `RUST_HOST` | Required host directory name when `RUST_SYSROOT` is set |
| `DEBUG_LAYOUT_CPP` | `0` (default) or `1` to build and require the C++ refusal group |
| `TMPDIR` / `RUNNER_TEMP` | Parent for the recipe-owned temporary directory |

The Rust-toolchain tool paths are
`$RUST_SYSROOT/lib/rustlib/$RUST_HOST/bin/{rust-lld,rust-objcopy}`. `rust-lld`
receives `-flavor gnu`. On macOS, linker and objcopy invocations receive command-local
`DYLD_LIBRARY_PATH=$RUST_SYSROOT/lib` (plus an existing value). Xcode's system
linker is not a supported ELF linker. Native host `cc` is not a target oracle.

Each configuration uses `--target=x86_64-linux-gnu -ffreestanding -g`:
`dwarf4-o1` adds `-gdwarf-4 -O1`; `dwarf5-o2` adds `-gdwarf-5 -O2`. Link output
is explicitly fixed-address ELF64 ET_EXEC, image base `0x400000`, entry symbol
`entry`, without a runtime, system libraries, PIE, or target execution.

For each enabled group the temporary directory contains:

* `{configuration}/{group}.debug.elf`: full symbols plus DWARF.
* `{configuration}/{group}.symbols.elf`: explicit `--strip-debug` negative
  control, retaining function symbols and the constant oracle.
* `{configuration}/{group}.constants.bin`: extracted 200-byte constant section.
* `{configuration}/*.o`: centrally built relocatable object inputs.
* `{configuration}/flat_use.text`: independent compiled field-use text bytes.
* `provenance.txt`, `source-sha256.txt`, `artifact-sha256.txt`: normalized
  commands, tool versions, target/link context, and SHA-256 hashes.

Repo and temporary source paths are prefix-mapped to `/rampage` and
`/rampage-build`; Rust sysroot paths in provenance become `/rust-toolchain`.
Provenance and hashes are printed before the check command. The recipe never
copies artifacts into tracked fixture directories. A future binary publication
requires the parent's explicit review of these hashes and provenance.

The optional check command runs from the repository root with
`RAMPAGE_DEBUG_LAYOUT_FIXTURES` pointing to the owned temporary directory and
`RAMPAGE_DEBUG_LAYOUT_ORACLE` pointing to `oracle.json`. Consumers must use them
synchronously; cleanup occurs on success, failure, interrupt, and termination.
A missing tool or required artifact is a failure, never a passing skip. C++
refusals are omitted only through the explicit default opt-out.

## Bounds and end-to-end acceptance

The oracle requires little-endian x86_64 ELF64, 8-byte pointers, at most 1 MiB
per binary, 128 sections, 256 symbols, 64 DWARF32 CUs, and 128 bytes per required
function. It requires bounded function symbols inside executable load segments,
read-only nonexecutable constant load segments, exact compiler facts, and the
selected DWARF version in every emitted CU.

The parent-owned acceptance harness must separately establish read-only preview,
approval-bound atomic application, undo and persistent reopen, field accesses,
refusal behavior, and native/worker parity. These are not claimed by a successful
source/constant oracle check. The API acceptance source is authored only after
the parent supplies the checked API contract; worker tests remain parent-owned.
