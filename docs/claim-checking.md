# Checking claims about a binary

An agent reading pseudocode states claims: "sub_1234 computes CRC-32", "main calls decrypt_config before connect",
"this function returns x*3+1", "this string is only used by the updater". `check_claim` (MCP core group,
*experimental*) checks such claims mechanically, so they can be confirmed or corrected before anyone relies on them.
Each claim gets one of three answers:

- **verified**, with the evidence;
- **refuted**, with a counterexample;
- **unknown**, with the reason and what would decide it (`needs`).

Every answer also states its `method` and a `confidence` that is never stronger than the method allows.

A claim is structured JSON, not free text. One call checks up to 32 claims in order, each answered separately. A
claim that cannot be read, or names nothing in the binary, is `invalid`; the others are still checked.

```json
{"path": "firmware.bin", "raw": {"profile": "cortex-m3", "base_address": "0x8000000", "vector_table": true},
 "claims": [
   {"kind": "computes", "function": "0x8000040", "algorithm": "crc32"},
   {"kind": "calls", "function": "reset_handler", "callee": "0x8000040", "before": "app_main"},
   {"kind": "region", "start": "0x8000400", "end": "0x80007fc", "algorithm": "crc32", "stored": "0x80007fc"}
 ]}
```

## Verdicts and confidence

| `confidence` | What it establishes |
|---|---|
| `exact` | Concrete facts. The function ran on the stated inputs, the bytes were recomputed, or the layout was read from the type source. A refutation from evaluation is exact for that state of the image. |
| `sampled` | A universal claim (`computes`) held on every generated input listed in the evidence. A different input could still differ. |
| `static` | The decoded code and its recorded references, with no unresolved indirect transfer on the paths that matter. An address or call target computed at run time is not seen. |
| `heuristic` | A detector (`lock_mechanisms`) reported the finding with high confidence. |

The rules that keep a wrong claim from being verified:

- **Refutations carry their counterexample.** That is the input with the expected and actual output, the call site
  outside the allowed set, the CFG path that reaches a call without the earlier one, or the stored and computed
  bytes.
- **What the method cannot see makes the answer unknown.** Examples: an unresolved indirect call, an incomplete
  scan, an evaluation that stops, or a missing reference where references can be computed.
- **A mismatch after reading writable data that the run never set** is unknown, never refuted. Such data has no
  initial value in the file (`.bss`, Raw RAM). A table-driven CRC whose table is filled at boot is the typical
  case: run the initialiser first with `setup`.
- **Without an explicit width,** a 64-bit register whose low 32 bits match but whose upper bits differ is unknown.
  Pass `bits: 32` for a C `int`.

`not: true` negates a claim: verified and refuted swap, and the evidence and confidence stay. An `id` is echoed back.
`timeout_ms` bounds the whole call (default 60000, at most 300000). Claims left when it runs out are unknown.

## Claim kinds

### returns: one call's result

`{kind, function, args, value | float | buffers, bits?, setup?, memory?, mmio?, convention?, max_steps?}`

`args` are exactly as for `evaluate_function`. `value` is an integer (a number, or a hex or decimal string,
negative allowed), compared at `bits` when given. Otherwise the whole result register is compared. `float` takes
a number or `inf`/`nan`, with `bits` 32 or 64. `buffers` lists `{argument, hex | text}` and compares the final
contents of a buffer argument.

```json
{"kind": "returns", "function": "app_scale", "args": [2], "value": 14}
→ {"verdict": "refuted", "confidence": "exact", "method": "evaluate_function on the stated arguments",
   "evidence": {"function": "0x8000400", "steps": 5, "result": "0xd", "expected": "0xe", "bits": 32}}
```

A run that does not return gives unknown, with the stop and what would let it finish:

- `step_limit`: a larger `max_steps`;
- an unmapped MMIO write: `mmio`;
- an import without a model: check its callees instead.

### computes: an algorithm or an expression

`{kind, function, algorithm | expression, args?, bits?, samples?, seed?, setup?, memory?, mmio?}`

The function runs on `samples` generated inputs (default 16, at most 64) and is compared with a reference
implementation written in Rust. The inputs are seeded and deterministic; `seed` changes them. Buffer lengths
cover:

- 0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 255 and 1024 bytes;
- the CRC catalogue's `"123456789"`;
- with more samples, 4096 bytes and seeded lengths.

Contents cycle through random, all-zero, all-0xff and ascending bytes.

**Algorithms**:

- CRC presets: `crc32`, `crc32c`, `crc32_bzip2`, `crc32_mpeg2`, `crc32_jamcrc`, `crc32_posix`, `crc16_arc` (`crc16`,
  `crc16_ibm`), `crc16_modbus`, `crc16_ccitt_false`, `crc16_xmodem`, `crc16_kermit`, `crc16_x25`, `crc8`,
  `crc8_maxim`, `crc64_xz`, `crc64_ecma`.
- Any Rocksoft-model CRC of 8 to 64 bits:
  `{"crc": {"width", "poly", "init", "refin", "refout", "xorout"}}`.
- Checksums and hashes: `adler32`, `fletcher16`, `fletcher32`, `fnv1a32`, `fnv1a64`, `fnv1_32`, `fnv1_64`, `djb2`,
  `djb2_xor`, `sdbm`, `sum8`, `sum16`, `sum32`, `xor8`.
- Digests: `sha256`, `sha1`, `md5`.
- `sha256_block`: one compression of a 64-byte block into an eight-word state.
- Transforms: `rot13`, `not`, `{"xor": "key hex"}`, `{"add": n}`, `{"sub": n}`.

`args` gives the function's arguments in order, by role:

- `data`: the input buffer;
- `length`: its byte count;
- `out`: an output buffer;
- `state`: the `sha256_block` state;
- an integer fixes an argument.

The default roles are:

| Algorithm type | Default `args` |
|---|---|
| Checksums and transforms | `["data", "length"]` |
| Digests | `["data", "length", "out"]` |
| `sha256_block` | `["state", "data"]` |

Without a `length`, the input is passed as a NUL-terminated string, as string hashes take it.

The output compared depends on the type:

| Algorithm type | Output compared |
|---|---|
| Checksum | The return value, masked to the algorithm's width, or the `out` buffer in the image's byte order |
| Digest | The `out` buffer |
| Transform | The data buffer after the call, or `out` |

```json
{"kind": "computes", "function": "0x8000040", "algorithm": "crc32"}
→ {"verdict": "verified", "confidence": "sampled",
   "method": "evaluate_function on 16 generated inputs (seed 0x5eedc1a100000001) compared with crc32 (crc width 32 poly 0x04c11db7 init 0xffffffff refin true refout true xorout 0xffffffff), reading the return value: equal on every input; another input could still differ",
   "evidence": {"samples": 16, "lengths": [0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 31, 32, 63, 64, 255, 1024],
     "shown": [{"length": 9, "data": "313233343536373839", "output": "0xcbf43926"}, ...]}}

{"kind": "computes", "function": "0x8000040", "algorithm": "crc32c"}
→ {"verdict": "refuted", "confidence": "exact",
   "evidence": {"counterexample": {"input": {"length": 1, "data": "00"},
     "expected": "0x527d5351", "actual": "0xd202ef8d"}, "matched_before": 1}}
```

A function whose CRC table is filled at run time needs its initialiser as `setup`. Without it the answer is
unknown, not refuted:

```json
{"kind": "computes", "function": "crc32_update", "algorithm": "crc32", "args": [0, "data", "length"]}
→ {"verdict": "unknown", "evidence": {"counterexample": {...}, "data_reads": {"unset": ["0x31488"]}},
   "reason": "the result differs, but the run read writable data that has no initial value in the file (0x31488) and that nothing in the run set: the program may set it before the call",
   "needs": "run its initialiser first with setup [{at, args}], or give its bytes with memory"}

... "setup": [{"at": "crc32_init"}]  → verified
```

**Expressions** state an integer result:

- **Syntax:** C operators and precedence, literals, and `sdiv srem sar slt sle sgt sge smin smax min max rotl rotr
  ite(c, a, b)` for what C spells with signed types.
- **Width:** arithmetic wraps at `bits` (8, 16, 32 or 64; default 32). `/ % >> <` and the other comparisons are
  unsigned.
- **Arguments:** `args` lists the variable names in argument order (an integer fixes one). The default is `arg0,
  arg1, ...` or else alphabetical.
- **Inputs:** each variable takes the edge cases 0, 1, all ones, 2, the signed minimum and maximum, 0xff, 0x100 and
  others, then seeded values.
- **Skipped inputs:** an input that leaves the expression undefined in C is not a sample. These are division by
  zero, a shift by the width or more, and `sdiv(MIN, -1)`.

```json
{"kind": "computes", "function": "app_scale", "expression": "x*5+3"}          → verified (sampled)
{"kind": "computes", "function": "app_scale", "expression": "(x*5+3) & 0x7fffffff"}
→ refuted: {"counterexample": {"args": ["0xffffffff"], "expected": "0x7ffffffe", "actual": "0xfffffffe"}}
```

### calls: a call, through stubs or callees, and call order

`{kind, function, callee, depth?, before?}`

- **Without `before`:** verified when the function (or, with `depth` up to 8, a function it calls) has a call site
  reaching `callee`. A site reaches it directly, through a tail jump, a resolved indirect call, an import slot, or
  forwarding stubs: PLT entries, import thunks and veneers, matched by address or name.
- **Refuted** when the search found no such site and no unresolved indirect call or jump remains in the functions
  searched. The evidence lists the call sites.
- **Unknown** otherwise: a call through a pointer may reach the callee. The unresolved sites are listed.

```json
{"kind": "calls", "function": "boot_main", "callee": "uart_putc"}
→ {"verdict": "unknown", "evidence": {"call_sites": [..., {"at": "0xbfc003fc", "kind": "unresolved"}, ...],
   "unresolved": [{"function": "boot_main", "site": "0xbfc003fc"}]},
   "reason": "no direct call was found, but indirect calls or jumps with unknown targets remain"}
... "depth": 2 → verified, with the chain boot_main → uart_puts → uart_putc
```

**`before`** reads the claim as "every path through `function` calls `callee` before it calls `before`". With
`depth`, a call that reaches `callee` through its callees counts.

- **Verified** when every CFG path from the entry to a call of the later function passes a call of the first, and
  no unresolved transfer runs before the first on any path.
- **Refuted** when no path calls the first before the later one, including when the later one is never called.
- **Unknown, with the path** when some paths call the first and one reaches the later call without it. Whether
  that path can run is not checked.

### references: who references an address or a string

`{kind, target | string, by? | only_by?}`

`string` is matched exactly against the image's strings. References are those analysis recorded:

- from code;
- from pointers in data, attributed to the code that references the pointer (`via_pointer`).

The answers:

- **Without `by` or `only_by`:** verified when any reference exists.
- **`by`:** verified when one comes from that function.
- **`only_by`:** refuted when a reference comes from a function outside the set, which is the counterexample.
  Verified when every reference comes from inside it. Unknown when some reference comes from data or undiscovered
  code that no function is known to use.

An absence of references is never refuted, since addresses can be computed at run time.

### constant: an immediate in a function's code

`{kind, function, value, bits?}`

Verified when an immediate operand or a loaded literal (32-bit ARM literal pools and movw/movt pairs, MIPS
lui/ori, Xtensa l32r) equals the value. The evidence gives the site and instruction.

An absence refutes only on x86 and x86-64, for values of at least 0x10000, after a complete scan. Smaller
constants are often folded into `lea`, shifts or a division's multiplier. Elsewhere constants are built from
pieces, and the search is a lower bound. Every other absence is unknown.

### region: a checksum covers a byte range

`{kind, start, end, algorithm?, stored?, endian?}`

- **With `stored` and an algorithm:** the algorithm is recomputed over the image bytes of `[start, end)` and
  compared with the value stored there, in the image's byte order unless `endian` says otherwise. The answer is
  verified or refuted, `exact`, with both values. If the stored value matches in the other byte order, the evidence
  says so.
- **Without `stored`:** verified when a check that `integrity_checks` found covers the range (with that algorithm,
  when given). Otherwise unknown: detection is a search, not proof of absence.

### lock: a lock mechanism decides in or guards a function

`{kind, function, category?}`

Verified (`heuristic`) when `lock_mechanisms` reports a high-confidence mechanism that decides in the function, or
one whose outcome transfers into it. Otherwise unknown, listing related mechanisms of lower confidence. It is never
refuted.

### layout: a type's member

`{kind, type, member, offset?, size?}`

Read from the project type library first, then embedded DWARF, then Go runtime type metadata. A dotted `member`
path works with DWARF and Go. The answer is `exact`: verified when every definition with that name agrees, refuted
when none does, and unknown when they disagree.

## Bounds

| Bound | Value |
|---|---|
| Claims per call | At most 32, each at most 16 KiB of JSON |
| Time per call | `timeout_ms` (default 60 s, at most 300 s); a claim is not started with less than 20 ms left |
| Each evaluation | `max_steps` (default 1,000,000, at most 20,000,000), and the time left |
| `computes` samples | Default 16, at most 64; at most 4 setup calls |
| Expression inputs | At most four times `samples` attempts to find defined inputs |
| `calls` search | Depth at most 8, at most 4096 functions; stubs followed up to 4 hops of at most 8 instructions |
| `region` | Recomputes at most 64 MiB |

## Architectures

The evaluation-backed kinds (`returns`, `computes`) work wherever `evaluate_function` does, as do `calls` and
`constant` wherever discovery decodes and `region` on any image. The tests cover:

- Cortex-M Raw and ELF;
- 32-bit x86 and x86-64 (ELF and PE);
- 32-bit ARM and Thumb;
- AArch64;
- MIPS (big- and little-endian userland, a Raw boot ROM);
- Xtensa (ESP32).

An architecture the interpreter does not support gives `invalid`, naming the processor. `lock` needs lock tracing,
which supports ARM/Thumb, AArch64 and x86-64.

## Limits

- **`sampled` is not a proof.** A function that differs only on an input none of the samples hit is verified. Raise
  `samples`, or change `seed`, for more coverage.
- **Static kinds see only discovered code** and the references analysis recorded. Run time is not modelled.
- **The `before` check is intra-procedural.** It does not test whether a path is feasible: a path that cannot run is
  reported, and the answer stays unknown.
- **`computes` takes a buffer and a byte count.** Functions taking an end pointer, a context structure, or a length
  in words cannot be stated yet.
