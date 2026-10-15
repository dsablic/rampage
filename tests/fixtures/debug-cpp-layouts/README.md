# C++ initial flat-record fixture contract

These workspace-owned Apache-2.0 inputs cover the initial C++ first slice:
**non-polymorphic, base-free, standard-layout records with scalar/scalar-pointer
fields and mutable explicit-this methods only**. The projected interface is an
ordinary record pointer plus explicit scalar arguments, not a recovered C++ ABI.
No generated binary is committed. ELF files are analysis inputs, never run.

There is no RTTI recovery, vptr projection, inheritance import, aggregate-by-value
import, or class-layout inference. A vtable never proves an admitted layout.
The polymorphic and inherited inputs are refusal controls, not a broader feature
promise. All C++ inputs disable RTTI and exceptions and require no target headers,
runtime, constructors, destructors, templates, or system libraries.

## Positive records and methods

`class alignas(8) CheckedRecord` has public fields and nonvirtual, nonstatic,
noinline methods declared in the record and defined out of line. Its explicitly
annotated alignment equals the natural x86_64 alignment. It has no base classes
or user-declared constructor/destructor. Standard-layout and triviality assertions
guard use of `__builtin_offsetof` without assuming that methods make a class
non-standard-layout.

| Field | C-compatible scalar type | Offset | Size | Type alignment |
| --- | --- | ---: | ---: | ---: |
| `tag` | `signed char` | 0 | 1 | 1 |
| `count` | `int` | 4 | 4 | 4 |
| `flags` | `unsigned short` | 8 | 2 | 2 |
| `weight` | `double` | 16 | 8 | 8 |
| `value` | `int *` | 24 | 8 | 8 |
| `tail` | `unsigned char` | 32 | 1 | 1 |

Complete size is 40, alignment 8, with padding `[1,4)`, `[10,16)`, `[33,40)`.
Static assertions bind all offsets and member sizes to these target facts.
`struct alignas(8) CompanionRecord` has the same fields and a `readCount()` method,
exercising `DW_TAG_structure_type` independently from `DW_TAG_class_type`.

| Actual ELF linkage symbol | Projected object argument | Semantic access |
| --- | --- | --- |
| `_ZN13CheckedRecord7readTagEv` | `CheckedRecord *` | Read `tag`, signed widening |
| `_ZN13CheckedRecord9readCountEv` | `CheckedRecord *` | Read `count` |
| `_ZN13CheckedRecord8readTailEv` | `CheckedRecord *` | Read `tail`, unsigned widening |
| `_ZN13CheckedRecord10writeCountEi` | `CheckedRecord *`, then `int` | Write `count` |
| `_ZN15CompanionRecord9readCountEv` | `CompanionRecord *` | Read `count` |

C-linkage noinline wrappers reference every method. The recipe does not use LTO
or section garbage collection. `-fstandalone-debug` requests full type emission.
The parent must inspect actual compiler output with its existing LLVM tools:

* Complete record DIEs retain explicit alignment and ordinary constant offsets.
* The in-record method declarations and out-of-line subprogram definitions exist.
* `DW_AT_specification` joins each definition to its exact method declaration.
* `DW_AT_object_pointer` resolves to an artificial `this` formal parameter with
  the correct record-pointer type; mutable method `this` is not pointer-to-const.
* Linkage names identify exact ELF functions, including distinct overloads.

Finding function names, constant sections, or CU headers alone does not establish
these relationships. The independent verifier intentionally does not parse type
DWARF and cannot certify method emission. A compiler that omits required method
facts must fail the parent gate, not silently downgrade the contract.

## Independent oracle

Each debug ELF and its symbols-only twin contains two 200-byte read-only,
allocated, relocation-free sections: `.rampage_cpp_checked` and
`.rampage_cpp_companion`. Their global C-linkage object symbols are
`debug_cpp_checked_constants` and `debug_cpp_companion_constants`.
The unaligned group additionally contains `.rampage_cpp_unaligned` and
`debug_cpp_unaligned_constants`, proving that its natural layout still agrees.

Every section contains exactly 25 little-endian unsigned 64-bit words:

| Word indices | Meaning |
| --- | --- |
| 0 | Magic `0x52414d5043505031` |
| 1 | Format version `1` |
| 2 | Target pointer width `8` |
| 3 | Little-endian tag `1` |
| 4–6 | Compiler-measured `sizeof(record)`, `alignof(record)`, field count `6` |
| 7–24 | `(offset, actual member size, scalar type alignment)` per field, in declaration order |

`oracle.json` independently records static expectations and exact mangled symbols.
The new verifier explicitly imports only the sibling C fixture's independent ELF
helpers, not the production loader or its DWARF parser. It compares extracted
bytes and in-ELF words to the C++ oracle, verifies exact global constant-symbol
extent and spelling, and requires every listed function including mangled methods
and C wrappers in both twins. No demangling or source-name joining supplies
expected linkage names. The imported helper source is included in source hashes.

Reads are bounded before parsing: oracle JSON at 64 KiB, each ELF at 1 MiB,
extracted constants at 200 bytes. ELF bounds are 128 sections, 256 symbols,
128 bytes per required function and 64 DWARF32 CUs. `.debug_info` must be at most
128 KiB, with the requested version in every CU. Compressed debug sections are
rejected, including legacy `.zdebug_*` names in symbols-only controls. Constant
ranges must be file-backed read-only nonexecutable loads without writable or
executable aliases; functions must be inside file-backed executable loads.

Small standard-library Python regressions cover wrong/duplicate/mangled constant
symbols, incorrect extents and binding, pre-traversal debug-info limits,
compressed-debug bypasses, retained DWARF in symbols-only controls, and word
encoding. They create no temporary files and need no compiler or production code.

## Refusal and identity controls

All groups are mandatory; there is no optional C++ opt-out.

| Group | Contract |
| --- | --- |
| `records` | Positive class and struct with complete explicit-this proof |
| `unaligned` | Same six fields, size 40 and alignment 8, but no explicit record alignment annotation |
| `const-method` | Const-qualified object method is outside the mutable-this slice |
| `reference-argument` | `int &` is not an ordinary scalar-pointer argument |
| `byvalue` | Independently refuse by-value aggregate argument and aggregate return |
| `virtual` | Polymorphic record: never project a vptr or infer layout from a vtable |
| `inherited` | Nonvirtual inheritance is still outside the base-free slice |
| `static-method` | No implicit object pointer: never invent `this` for a static member |
| `overloads` | Admit separately or refuse, at the parent's choice; never join by `readCount` alone |

The unaligned control is a missing-evidence test only if actual compiler DWARF
omits the alignment attribute. If natural alignment is emitted unasked, the parent
must remove that attribute in a separate synthetic mutation rather than refuse
valid evidence. The constant oracle does not decide whether DWARF proved alignment.
The static member may still be analyzed as an ordinary function where applicable;
this fixture forbids pretending that its explicit argument is an implicit object.

The overloads have distinct required symbols `_ZN14OverloadRecord9readCountEv`
and `_ZN14OverloadRecord9readCountEi`. Refusals must not attach invented record
layouts or turn unproved memory accesses into field accesses. Wrapper signatures
are not substitutes for inspecting the member function itself.

## Recipe interface

From the repository root:

```bash
bash tools/ci/debug-cpp-layout-oracle.sh
bash tools/ci/debug-cpp-layout-oracle.sh --check command arguments...
python3 -B tests/fixtures/debug-cpp-layouts/test_verify_cpp_oracle.py
python3 -B tests/fixtures/debug-cpp-layouts/test_recipe_paths.py
```

The first two commands generate temporary cross-compiled analysis inputs; the
last two run only verifier and shell-path regressions. The path regressions use
temporary executable stubs without invoking them and clean them up afterward.
Generation installs no tools and invokes neither Cargo nor rustc. An optional explicit check hook may
invoke parent-owned validation commands afterward. Target code is never executed.

| Variable | Meaning / default |
| --- | --- |
| `CLANG` | Existing target-capable Clang executable, default `clang` |
| `LD` | Existing ELF LLD, default `ld.lld` or explicit sysroot `rust-lld` |
| `OBJCOPY` | Existing LLVM objcopy, default `llvm-objcopy` or explicit sysroot `rust-objcopy` |
| `PYTHON` | Existing Python 3.10+ executable, default `python3` |
| `RUST_SYSROOT` | Optional explicit existing Rust toolchain sysroot; never auto-discovered with rustc |
| `RUST_HOST` | Required host directory name when `RUST_SYSROOT` is set |
| `TMPDIR` / `RUNNER_TEMP` | Parent of the recipe-owned temporary directory |

Relative explicit executable paths and sysroots are anchored to the invocation
directory before entering scratch. Bare executable names are resolved through
the initial `PATH`, including relative entries. Executable basenames are retained
for linker flavor selection; tool resolution does not rewrite caller environment
variables. The canonical sysroot supplies derived tools, library lookup and
provenance normalization.

Sysroot tools are resolved under `lib/rustlib/$RUST_HOST/bin`. `rust-lld` receives
`-flavor gnu`. On macOS, linker and objcopy receive command-local
`DYLD_LIBRARY_PATH=$RUST_SYSROOT/lib` plus any existing value. The host system
linker is not an ELF oracle. Tool absence or any missing required artifact is a
failure, not a passing skip.

Both configurations use `--target=x86_64-linux-gnu -ffreestanding -g` and C++17,
with `dwarf4-o1` adding `-gdwarf-4 -O1` and `dwarf5-o2` adding `-gdwarf-5 -O2`.
ELF output is fixed-address `ET_EXEC`, base `0x400000`, entry `entry`. Compiler
and linker are invoked directly without target execution or system libraries.

Each configuration contains group `.debug.elf` files, explicit `--strip-debug`
`.symbols.elf` twins retaining names, `.checked.constants.bin` and
`.companion.constants.bin` extracts, the additional unaligned extract, and input
`.o` files. The temporary root contains normalized tool versions/commands in
`provenance.txt`, source/dependency SHA-256 values in `source-sha256.txt`, and
generated-input SHA-256 values in `artifact-sha256.txt`. These are printed before
the optional check. Source/debug paths are mapped to `/rampage` and
`/rampage-build`; provenance maps the optional sysroot to `/rust-toolchain`.

The optional check runs synchronously from the repository root with:

* `RAMPAGE_DEBUG_CPP_LAYOUT_FIXTURES`: recipe-owned temporary artifact directory.
* `RAMPAGE_DEBUG_CPP_LAYOUT_ORACLE`: source-static C++ oracle JSON.

The scratch directory is removed on success, failure, HUP, interrupt and
termination. It is not a publication directory. No generated outputs are copied
into source directories. The parent owns compilation, LLVM inspection, product
acceptance and any later artifact-publication decision. Approval/apply/undo,
persistent reopen, field-access semantics, native/worker parity and refusal
behavior remain parent acceptance obligations, not verifier success claims.
