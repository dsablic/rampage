# Lock mechanisms

*Experimental.* An owner trying to repair an older or orphaned device often meets a refusal the firmware was
built to make: an update that must carry a valid signature, a part paired to one controller's chip ID, a version
counter that blocks an older image, a debug port locked at the factory, a service mode behind a challenge that only
a dealer tool answers, or features fused off for a region. `lock_mechanisms` (group `detection`) finds such
mechanisms in a binary and explains them: what is checked, which data the decision consults, where the decision is
made and what each path does, with the evidence and a confidence.

It explains; it does not defeat. It never suggests a change to the code, never reads out or reconstructs key
material (a key is pointed at by address only) and knows no vendor or product. What to do with the explanation is
the owner's decision.

```json
{"tool": "import_svd", "path": "fw.bin", "raw": {"profile": "cortex-m4", "offset": 0, "length": 65536,
 "base_address": "0x8000000", "vector_table": true}, "svd": "device.svd", "apply": true}
{"tool": "lock_mechanisms", "path": "fw.bin", "raw": {...}}
```

It works on native binaries (ELF, PE, Mach-O) and Cortex-M Raw projects; decisions are traced on 32-bit ARM and
Thumb, AArch64 and x86-64. Other architectures return `supported: false`.

## Categories

| Category | Reported when a branch decides on |
| --- | --- |
| `signature_verification` | the result of a routine whose call tree holds public-key evidence: curve parameters (P-256, secp256k1, Ed25519), PKCS#1 v1.5 DigestInfo prefixes, or a known verify function (mbed TLS, micro-ecc, libsodium, OpenSSL, BearSSL, wolfCrypt and platform APIs) |
| `mac_verification` | a keyed MAC: HMAC pads (0x36, 0x5c) applied around a hash routine, or a known MAC function |
| `challenge_response` | a signature, MAC or digest computed over data that derives from a random source (an RNG register, `getrandom` and similar), in the same function or through a buffer another function filled |
| `device_binding` | a value derived from a unique-ID register |
| `anti_rollback` | a value derived from a counter in fuses or protected storage (a register named as a version or monotonic counter in OTP, fuse or option storage) |
| `debug_lock` | a readout, write or debug protection setting (option-byte fields such as RDP or WRP, a debug-disable bit, ARMv8-M `DAUTHCTRL`), the architectural `DHCSR` debug status (a debugger attached), or a function that writes such a setting |
| `feature_lock` | fuse, OTP or option bits that are none of the above (feature and region bits) |

Register roles come from an imported [SVD map](peripheral-maps.md), by generic names (`UID`, `DEVICEID`, `OTP`,
`FUSE`, `OPTR`, `RDP`, `RNG` and similar) in peripheral, register, field and description text; unlock-key registers
are excluded. Without a map, unique-ID, fuse, option-byte and RNG addresses are unknown, because they differ between
vendors, and only signature, MAC and debugger-detection checks are found; the report says so. The only addresses
known without a map are architectural: `DHCSR`, `DAUTHCTRL` and `AIRCR` (a reset request) on Cortex-M firmware.

## How a decision is found

1. Evidence: algorithm constants (`find_crypto`'s database) and the functions referencing them, library function
   names, CRC routines (as [`integrity_checks`](firmware-patching.md) finds them), and constant-address register
   accesses (as `peripheral_access` finds them).
2. Those functions, their callers up to four levels and their direct callees are lifted to p-code with the bundled
   Sleigh specifications, callees first. A forward dataflow tracks known values (constants, stack offsets) and which
   sources each value derives from: a call's result and the buffers it may write through pointer arguments, and loads
   from fixed addresses outside read-only image data. It follows stack slots, ARM conditional execution (IT blocks)
   and, for an analyzed callee, the arguments its result derives from.
3. Every conditional branch whose condition derives from a source is a decision. Its sources' roles give the
   category. A decision whose verdict is only passed up (a `verify_image` that returns an error code) is folded into
   the caller's decision on it and listed under `related` as `inner_decision`.
4. Each path is followed within the function, up to the next decision: a call that requests a reset (writes
   `SYSRESETREQ` to `AIRCR` or is `NVIC_SystemReset`, `reboot`), exits, never returns, jumps through a pointer (into a
   verified image), a fixed address written, a return value. `failure_path` names the side that resets, exits or
   halts while the other does not, or the side that does not transfer control when the other does; otherwise
   `unknown`.
5. A flag in RAM one side writes, tested by decisions in other functions, lists those as `flag_consumer`s.

## Results

`mechanisms` (paged with `offset` and `limit`, default 10 and at most 50, and filtered with `category`), each with:

- `category`, `confidence` (`high` when the role is named by an SVD map, a public-key constant or the architectural
  debug register and a path's effect is known; `medium` or `low` otherwise; feature locks are at most `medium`) and
  a `summary` sentence;
- `decision`: the function, the branch address and how the condition is formed (`equality with a constant`,
  `equality with another value`, `ordered comparison`, `bit test` or `zero or nonzero test`);
- `checks`: the routine whose result is decided on and what its call tree computes;
- `consults`: algorithms, registers by name and address, and `constant_data` / `external_data` addresses passed to
  the checking routine (a key table, an image header in another flash area);
- `outcomes`, one per path (`branch`/`fallthrough`, or `conditional`/`otherwise` for a conditionally executed
  instruction) with its `effect` (`reset`, `exit`, `halt`, `transfer`, `writes`, `returns`, `calls`, `selects` or
  `continues`) and `failure_path`;
- `related` decisions, inner decisions, flag consumers and protection writes (`configures`), and `evidence`.

`not_locks` lists what was found and is not a lock: `integrity_check` (a decision on a CRC or an unkeyed digest:
it detects damage but does not restrict who may change the data), `identity_read` (a unique ID read that no traced
decision depends on, such as a serial-number string) and `crypto_without_decision` (a digest or signature computed
with no branch or return value depending on it, such as a log digest). `coverage` gives the functions and
instructions analyzed, whether a budget stopped the analysis, the crypto constants and SVD peripherals seen, and
whether the image was treated as firmware.

## Measured

`tests/fixtures/firmware/locks` builds, from committed sources with synthetic keys, a Cortex-M3 firmware for a
made-up device (`tests/fixtures/svd/lock-device.svd`) and an x86-64 Linux program. They hold an ECDSA P-256 boot
signature check that resets on failure, a thermometer-coded OTP rollback counter, a readout-protection setter,
debugger detection, unique-ID pairing, fuse feature and region bits, an HMAC challenge-response unlock (RNG register
and `getrandom`), an RSA-2048 PKCS#1 v1.5 update check, and negative controls: a CRC-checked configuration, a sensor
`WHO_AM_I` read, a log digest, the unique ID formatted as a serial string and a CPUID check. Against `truth.json`
each of the six categories they contain scores precision and recall 1.0 (10 mechanisms; `mac_verification` has no
fixture), the negative controls report nothing or a not-lock, and the repository's ordinary programs (the hello
programs, static musl, a Go program and the other firmware fixtures) report no mechanism. The fixtures were written together with the detector, so these are regression gates, not an estimate of
accuracy on real firmware.

## Limits

The analysis lifts at most 2,048 functions and 1,500,000 instructions (`coverage.incomplete` says when it stopped);
call trees are searched four levels deep. Data flow is tracked through registers, stack slots, fixed addresses and
buffers passed by pointer (a pointer argument is taken to cover 64 bytes, or the length passed after it), not
through heap objects, structures reached through pointers in memory, indirect calls or other threads; a decision
made that way is missed. Crypto is recognized only by constants and names: an implementation without distinctive
tables (or with them computed at run time) and stripped library code with no known constant are unknown. Whether a
digest is keyed is known only from HMAC pads or a MAC function's name; a plain digest compare is listed as an
integrity check. Paths are read within one function and stop at the next decision; which side is the refusal is a
reading of the code, not a proof. Register roles are only as good as the SVD map's names. No CLI command exists yet;
use the MCP tool.
