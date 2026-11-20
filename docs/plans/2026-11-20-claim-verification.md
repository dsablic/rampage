# Claim verification (`check_claim`)

Track 4 of the queue agreed on 2026-11-19. Status: implemented, experimental. The user guide is
[claim-checking.md](../claim-checking.md).

## Problem

Agents state claims about binaries and often get them wrong: they misread pseudocode, guess an algorithm from one
constant, or overlook a call through a pointer. Nothing in IDA, Ghidra or REA checks such a claim mechanically.
One tool should take a structured claim and answer verified, refuted or unknown, with the evidence, the method and
what would decide an unknown.

## Decisions

- **One core tool, `check_claim`, with a compact schema.** The tool belongs in core: the server instructions tell
  agents to check claims before reporting them, which only works if no group has to be enabled first. The default
  catalog had about 2.3 KB of headroom. A schemars schema of eight claim structs would have cost several KB, so the
  input schema is hand-written:
  - an array of objects with a required `kind`, the grammar in one description, and the full grammar in the guide;
  - each claim is still read strictly (`deny_unknown_fields`) by its kind, so a wrong field name is reported.

  The tool costs 2,289 bytes, mostly the binary-path and `raw` selector arguments every raw-capable tool carries.
  The default listing is 104,375 of its 104,400-byte budget, so the budget was not raised. The tool is raw-capable,
  so it works on Cortex-M Raw projects.
- **Claims are structured JSON, not free text.** There are eight kinds, each resting on existing machinery:

  | Kind | Machinery |
  |---|---|
  | `returns`, `computes` | `evaluate_function` |
  | `calls` | The function graph, call xrefs and stub following |
  | `references` | xrefs |
  | `constant` | Code search |
  | `region` | Recomputation and `integrity_checks` |
  | `lock` | `lock_mechanisms` |
  | `layout` | The type library, DWARF and Go type metadata |

  `not: true` negates any claim by swapping verified and refuted.
- **Confidence names what the method proves:** `exact`, `sampled`, `static` or `heuristic`. A verdict is never
  stronger than its method. The two failure modes are not treated alike:
  - A wrong claim must never be verified, so every gap the method can detect makes the answer unknown.
  - A true claim being refuted is worse than unknown but less harmful. Refutations always carry a counterexample,
    and where the counterexample depends on something the method does not model, the answer is unknown instead.
- **Absence is asymmetric by kind:**

  | Kind | When absence refutes |
  |---|---|
  | `calls` | When no unresolved indirect transfer remains. Call instructions decode precisely, and calls through pointers are detected. |
  | `references` | Never. Data addresses can be formed arithmetically with no detectable sign. |
  | `constant` | Only on x86/x86-64, for values of at least 0x10000, after a complete scan. AArch64 builds constants from 16-bit pieces, 32-bit ARM, MIPS and Xtensa results are lower bounds, and small constants fold into `lea`, shifts and division multipliers. |

  A `constant` scan left incomplete only because some instructions lack typed operands still counts as complete
  when no instruction's rendered text holds the value.
- **Evaluation state.** `evaluate_function` gained an internal stateful entry point. It starts from the image as
  earlier runs left it (pages and a written-byte bitmap) and reports reads of writable data that no run wrote,
  split into `unset` (no file bytes) and `initial` (file values). This serves two purposes:
  - `setup` calls, such as a CRC table initialiser, run before the claimed function.
  - A mismatch after reading unset data is unknown, not refuted, because it is the typical false refutation (a
    table-driven CRC whose table is filled at boot). Initial-value reads are recorded as assumptions in the evidence.
- **Width.** A `returns` claim without `bits` compares the whole result register. When only the low 32 bits match,
  the answer is unknown and names `bits: 32`, so a C `int` on a 64-bit target is never refuted for its undefined
  upper bits, and a 64-bit result is never verified on its low half. Expressions default to 32 bits: most C code
  is `int` or `uint32_t`, and the width is stated in the evidence.
- **Generated inputs** are seeded with xorshift64* and deterministic. Buffer lengths run from 0 to 1024 bytes in the
  default 16 samples, with the CRC catalogue's `"123456789"`, all-zero, all-0xff, ascending and random contents.
  Expressions take edge cases first: 0, 1, all ones, the signed minimum and maximum. An input that leaves the
  expression undefined in C (division by zero, an oversized shift) is skipped rather than compared.
- **Reference implementations** are written from their definitions and tested against published check values. The
  CRC is a generic Rocksoft model of 8 to 64 bits with separate refin and refout, so a claim can name the exact
  variant. Presets follow the CRC catalogue's names. Digests use the `sha2`, `sha1` and `md-5` crates, and the
  SHA-256 block function is written out.
- **`calls … before`** works on the CFG within one function:
  - **Verified:** every path from the entry to a call of the later callee passes a call of the first, and no
    unresolved transfer runs before the first.
  - **Refuted:** no path calls the first before the later one.
  - **Mixed:** unknown with the offending path, because feasibility is not checked.
- **Budgets:**

  | Bound | Value |
  |---|---|
  | Claims per call | 32 |
  | Bytes per claim | 16 KiB |
  | Per-call deadline | Default 60 s, at most 300 s |
  | Per-evaluation steps | Default 1M, at most 20M; the deadline also bounds every run |
  | Samples | At most 64 |
  | Setup calls | At most 4 |
  | `calls` search | Depth 8, 4096 functions |
  | `region` | 64 MiB |

  Claims left when the deadline passes are unknown.

## Not done

- `computes` cannot state an end-pointer argument (the buffer address is chosen inside the run), a context
  structure, or a length in words.
- `before` is intra-procedural and does not check whether a path is feasible.
- No `next` hint from `decompile` or `function_summary` points at `check_claim`. The server instruction line is the
  only prompt, to keep `decompile`'s output unchanged.
