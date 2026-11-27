# Parameter types: measured headroom and slice plan (queue item 6)

Status: measured on `main` at 5a28782 (1.20.0 changes included), 2026-11-27. No analysis code has changed.

## Confirmed numbers

Same method as `docs/benchmarks/flywheel-headroom-2026-11-21.md` section (c): `rampage-eval type-truth` for DWARF truth,
the `types` family with the `classes` metric (every truth function decompiled in the stripped build, each declared
parameter position scored by class), `types_headroom` for the miss classes. Dev set: LZ4 1.10.0 and cJSON 1.7.18, static
against Zig's musl, `zig cc -g`, x86-64 and AArch64, O0 and O2, truth restricted to the functions the library's own
objects define. Rebuilt with `tools/types-dev/build.sh`; truth is committed under `tests/fixtures/types-dev/`.

| | 2026-11-21 | now (5a28782) |
| --- | ---: | ---: |
| Declared positions | 3,221 | 2,915 |
| Functions | 1,207 | 1,079 |
| Correct | 1,450 (45.0%) | 1,360 (46.7%) |
| Misses | 1,771 | 1,555 |
| `dead` (parameter never read) | 27 | 27 |
| `register_class` | 121 | 116 |
| `ambiguous` | 1,623 | 1,412 |
| Spurious extra positions | 1 | 1 |

The two sets are not identical: the original lost its build scripts and sources list, and this rebuild has 306 fewer
positions (the 1,207 vs 1,079 functions are the difference; the likely cause is which library sources and static
helpers were counted). The rate moved from 45.0% to 46.7%, which is within what the set difference explains, so the
honest reading is **no measurable change in parameter-type recovery between the two dates**. The shape is the same.

The committed probe fixtures (`eval-types-{x86_64,aarch64}.elf`) also reproduce exactly: 43 and 42 correct of 69.

## Breakdown (dev, 1,555 misses)

| Class | Positions | Share of misses |
| --- | ---: | ---: |
| `pointer` recovered as `int64` | 667 | 43% |
| `struct_pointer` recovered as `int64` | 503 | 32% |
| `struct_pointer` recovered as `pointer` | 214 | 14% |
| Position missing (`int32`/`pointer`/`struct_pointer`/`int64` -> none, in `register_class`) | 102 | 7% |
| Parameter never read (`dead`) | 27 | 2% |
| `float64` -> `int64`; `struct_pointer` -> `float64` | 14 | 1% |
| Width and the rest (`int32`<->`int64`, struct vs pointer) | 28 | 2% |

So pointers recovered as 8-byte integers are 1,170 of 1,555 (75%); the old report said 1,350 of 1,771 (76%).
Signedness is not a class in this metric (no signed/unsigned miss exists); narrow-integer width errors are 13
positions here. By architecture: x86-64 has 699 `ambiguous` and 71 `register_class`, AArch64 713 and 45. By opt level the
O0 builds hold most of the ambiguous misses (cJSON O0 is 152 of 199 positions) because O0 spills every argument to
the stack and the decompiler types the spill slot, not the use.

By cause: `dead` is 27 (no callee evidence, only call sites could type it). Of the `register_class` positions 102 are
"fewer parameters recovered than declared", mostly wrappers that forward their register arguments to a callee
(`LZ4_compress_destSize_extState` #1 to #5 are never read before the tail call). The rest of the misses are
`ambiguous`: the callee has evidence a better analysis could use.

## Examples and the evidence they hold

Raw spellings: the recovered type is Ghidra's `int8` (an 8-byte integer) or `xunknown8`, not a pointer.

- `cJSON_GetNumberValue #0` (`struct_pointer`, recovered `int64`): the body loads `[p+0x14]` (type) and `[p+0x18]`
  (`valuedouble`). A base register used only as `[base + constant]` loads and stores, with constants that differ,
  is a struct pointer.
- `cJSON_GetStringValue #0`, `cJSON_Delete #0` (`struct_pointer`, `int64` or `pointer`): same shape; `cJSON_Delete` loops
  `item = item->next` (load at one offset feeds the same register), the classic list-walk evidence.
- `cJSON_AddItemToObject #1`, `cJSON_HasObjectItem #1` (`pointer`, `int64`): the parameter is passed to `cJSON_strdup`,
  `strlen`, `strcmp`-like callees; a callee whose own parameter is a known pointer (a library signature, or a
  recovered pointer in an earlier pass) types the argument.
- `LZ4_compress_destSize #0 #1 #2` (`pointer`, `int64`): passed straight into `LZ4_compress_destSize_extState` and the
  stream internals, which dereference them; evidence comes from the callee, found by interprocedural propagation.
- `LZ4_resetStream_fast #0`, `LZ4_freeStream #0`, `LZ4_loadDict #0` (`struct_pointer`, `int64`): `LZ4_freeStream` passes the
  argument to `free` (a known imported pointer) and compares it with null; `LZ4_resetStream_fast` stores fields at offsets
  from it.
- `LZ4_compress_destSize_extState #1` to `#5` (missed): not read here; only the callee reads them. Recoverable only by
  adopting the callee's signature through the tail call.
- `struct_pointer` -> `pointer` (214, for example the `cJSON *` parameters decompiled as `int8 *`): the pointee is
  accessed at several distinct offsets of different widths; a layout-shaped pointee (`xunknown8 *` with field accesses)
  says struct.

## Where parameter types come from today

- Recovered natively: the Ghidra decompiler's own prototype; the eval reads it through
  `decompiled_signature_batch` / `decompiled_signatures` and scores it with `score_types`
  (`crates/rampage-eval/src/types.rs`). **The eval calls the decompiler directly, not the API path**, so annotations,
  library prototypes and propagation are invisible to it.
- Library prototypes: `import_prototype` (`crates/rampage-api/src/import_types.rs`), applied as
  `WorkerOperation::RuntimePrototype` while setting up the decompile (`crates/rampage-api/src/decompile/symbols.rs`, the
  operations built around lines 33 to 135).
- Hints: `TypeHint::Parameter` (`crates/rampage-decompiler/src/type_hints.rs`, `Decompiler::set_type_hints`), produced by
  explicit-source propagation in `crates/rampage-api/src/propagation.rs` (`seed_function`, `hint_operations`,
  `call_context`; limits 32 functions and 256 edges) and applied through `WorkerOperation::TypeHints`.
- User and imported types: `annotations.rs` type hints, `debug_type_import.rs` signature entries.

Today nothing derives a pointer or struct-pointer parameter type from the callee's own use of the register, and nothing
derives a type from callers. A fix touches `type_hints.rs` and `propagation.rs` first, then the eval entry.

## Slice plan

Slice 0 (prerequisite, small). The eval must go through the API path (propagation and hints) before interprocedural slices
can be measured: today `decompiled_signature_batch` bypasses them. Add an eval mode that opens an ordinary project and
reads signatures after the same decompile the product does. Target: the 1,360 correct figure reproduces unchanged through
the API path (no regression, no gain), and the harness takes the acceptance input below.

Slice 1. Pointer evidence inside one function: a parameter whose register is dereferenced (`[reg+disp]` loads and stores,
pointer arithmetic, passed to a known pointer parameter of an imported or library-identified callee) becomes a pointer; with
two or more distinct displacements, or a list-walk load, a struct pointer. Emit it as a derived `TypeHint::Parameter`, never
an analyst lock. Target on the dev set: recover at least 600 of the 1,170 pointer-as-`int64` positions (correct 1,360 ->
1,960 or more, 67%) with fewer than 50 correct positions broken.

Slice 2. Interprocedural: callee-only evidence (tail-call and forwarding wrappers: adopt the callee's parameter types by
position) and caller evidence for `dead` positions (types of the values callers pass). Target: of the 102 missing and 27
dead positions, recover at least 60 with no new spurious positions (spurious stays at 1), and `struct_pointer` -> `pointer`
(214) cut by a third.

Slice 3 (only if 1 and 2 move the dev set): width and float register classes (`float64` -> `int64`, the 28 width errors),
verified on the same set. Skip if the gain is under 20 positions.

Rule for done: a slice counts as done only after a run on the acceptance input below, with the same targets scaled by its
position count, and no regression of the dev correct figure.

## Acceptance input (not built from)

Nothing in this plan was derived from zstd, inih or tinyexpr. Use **zstd 1.5.5** (`lib/common`, `lib/compress`,
`lib/decompress`; about 10 times the functions of cJSON, `ZSTD_DISABLE_ASM`), x86-64 and AArch64 at O2, plus **inih r58** and
**tinyexpr 1.1.1** at O2 as small extras, built with the same recipe as `tools/types-dev/build.sh` (all three tarballs are in
`target/flywheel/sources`; the script needs a source list and include path per library, a ten-line extension). LZ4 and cJSON
are the dev set only; do not tune on the acceptance set. If a real DWARF-carrying binary is preferred, any Homebrew library
built with `-g` works the same way through `type-truth`.

## Reproduce

```sh
tools/types-dev/build.sh target/flywheel/sources OUT_DIR      # about 15 s; truth equals tests/fixtures/types-dev/*.truth.json
cargo build --release -p rampage-eval --example types_headroom
target/release/examples/types_headroom out.json dev:OUT_DIR/lz4-x86_64-O2.debug.elf:OUT_DIR/lz4-x86_64-O2.elf:OUT_DIR/lz4-x86_64-O2.truth.json ...
```

The decompile of the eight binaries takes about 25 minutes, mostly the x86-64 O0 builds.
