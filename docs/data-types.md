# Data and operand typing reference

Types-group annotations interpret existing bytes; they do not patch the file or establish producer intent.
Named layouts come from the selected native target and the [project type library](type-library.md).

| Tool | Interpretation |
| --- | --- |
| `apply_data_type` | Complete element type plus array count, or explicit string encoding and byte length |
| `read_data` | Bounded byte window with raw backing status and typed field/element values |
| `apply_enum` | A named enum on one decoder-native immediate operand |
| `apply_offset` | A named struct field for a decoder-native base-register memory displacement |

## Data ranges

An element type and count specify the range's footprint. Named arrays of structs feed native globals and typed
views; `set_global` declarations remain available for manually named globals. Conflicting bindings
are refused rather than silently replacing user work.

String encoding is explicit: `utf8`, `utf16_le`, `utf16_be`, or `ascii`. Byte lengths are not character counts.
Original bytes remain available; invalid or partial encoding is reported without replacement text or normalization.
Integer displays preserve all bits, non-finite floats remain explicit, and pointer words are not followed.
Unmapped, unavailable and zero-fill spans are not manufactured as stored bytes.

## Instruction operands

Operand indices are zero-based native-decoder indices, not positions found by splitting formatted assembly.
The stored selector includes the complete instruction bytes. Enum values use the operand's logical width,
including native sign extension. Exact enumerator matches receive a symbolic label; unmatched values remain
numeric under the asserted enum type.

Struct offsets require a known object-base register, a nonnegative displacement at a native field start, and
a fitting memory access. PC-relative, absolute, indexed and unknown forms are refused. Disassembly retains its
raw text and bytes, with separate structured annotations and readable comments.

Edits validate before persistence and support `undo`, `redo`, shared logs and reopening. Type deletion cannot
silently strand a data or operand binding. Oversized edit responses do not persist.

Limits: bounded stored-data windows and supported x86/x64/AArch64 instruction forms; no automatic runtime object
identification, pointer traversal, byte patching, or decompiler-text substitution.
