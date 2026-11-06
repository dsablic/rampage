# Runtime data order and ARM64 evidence

Architecture byte order and a stopped process's runtime DATA byte order are different evidence. rampage keeps
them separate: a raw debugger observation may retain unknown DATA order, while a snapshot must declare how
captured data words are interpreted. An architecture default cannot fill that gap.

This explains the evidence boundary. The [snapshot guide](runtime-snapshots.md#export-from-lldb) covers export
from an already authorized, stopped LLDB process; the [query protocol](lldb-query.md) describes raw inspection.

## Why the LLDB byte-order getters are insufficient

At Swift LLVM commit `1b669c3f63758879bb0c517a589abdea4c6efbeb`, the inspected implementations show:

- [`SBTarget::GetByteOrder`][sbtarget], lines 1726–1731, returns the target architecture's byte order.
- [`SBProcess::GetByteOrder`][sbprocess], lines 550–558, also returns the target architecture's byte order.
- [`ArchSpec::GetByteOrder`][archspec], lines 943–947, returns the recorded architecture order or its default.

The process getter is therefore not an independent runtime check. Agreement between both getters, the target
triple and module byte order does not establish an ARM64 thread's EL0 DATA interpretation at the current stop.
These references establish the inspected implementation, not a claim about every LLDB version or backend.

Apple's [Apple silicon porting guide][apple-porting] states that both Apple silicon and Intel-based Macs use
little-endian data. That is platform guidance for porting applications, not the missing stop-bound SDK fact.
rampage does not convert it into affirmative runtime DATA evidence for an individual capture.

## ARM64 is not ARM32 CPSR.E

ARM32 exposes a DATA-endianness bit, CPSR.E (bit 9). For ARM32 observations, the bridge uses the explicitly
selected thread's freshly read and revalidated CPSR. Without that context, DATA order remains unknown. The
standalone ARM32 exporter requires readable CPSR with E clear for each captured thread, including its default
selected-thread capture.

AArch64 CPSR/PSTATE does not supply the equivalent EL0 DATA-endianness evidence. A readable register named
`cpsr`, a clear bit 9 or familiar condition flags must not be interpreted as ARM32 CPSR.E on ARM64.

The pinned [XNU register definitions][xnu-controls], tag `xnu-11417.101.15`, distinguish:

- `SCTLR_EL1.E0E`, bit 24: EL0 endianness, the relevant control for EL0 DATA interpretation.
- `SCTLR_EL1.EE`, bit 25: exception-level endianness, not a substitute for E0E.

The inspected local macOS SDK's `arm_thread_state64` exposes general registers, PC/SP and CPSR, but no SCTLR
field. The pinned [XNU thread-state definitions][xnu-thread-state] provide the corresponding public structure
context. Neither inspected byte-order getter nor this thread-state surface exposes `SCTLR_EL1.E0E` as a
stop-bound observation. Missing evidence stays unknown; this is not an assertion that the process is big-endian.

## Inspection remains available; export refuses early

The query bridge retains ARM64/arm64e/AArch64 raw inspection with DATA order `unknown`. Session, module, thread,
register, memory and module-address observations retain their ordinary bounds and identity checks. Raw bytes
need not be interpreted as pointer-sized or scalar data values to be useful.

The standalone exporter refuses `arm64`, `arm64e`, `aarch64` and `aarch64_be` after checking the stopped process
and target context, before thread selection, mapping inspection, memory reads or output-file access. Its error
states that the current LLDB SDK cannot affirm runtime DATA endianness. Little-endian x86-64 and ARM32 export
remain supported under their documented validation; ARM BE8 and heterogeneous module endian context do not.

The client-local workspace capture path remains limited to ordinary little-endian x86-64 Darwin Mach-O with
affirmative runtime DATA context. It does not make ARM64 export available. Existing and synthetic ARM64 snapshot
files remain supported by the loader and analysis tools; their declared byte order is a separate input contract.

There is no `--assume` switch to bypass the refusal. A future affirmative ARM64 path would need trustworthy,
stop-bound evidence for the relevant EL0 control, such as `SCTLR_EL1.E0E`, and appropriate revalidation. It cannot
substitute EE, PSTATE, architecture defaults or application-porting guidance. The inspected SDK does not provide
that evidence. No privileged reads, target expressions, target writes, launch or attach controls are introduced
to obtain it, and unavailable evidence is not promoted into a known value.

## Acceptance boundary

**Current confirmation: source/mock only for the corrected ARM64 contract.** The centrally reported controlled
Python run passed 554 tests in 4.63 seconds; scoped Ruff and ty checks also passed. These are not live SDK results.
No compiler, runtime or SDK acceptance run was performed for this documentation update.

The refusal regression covers ARM64 variants, default/explicit/all-thread selection, architecture byte orders
and differing CPSR values. It checks refusal before thread/register selection, mapping reads, memory reads and
file publication, with unchanged process/stop/register context. Bridge regressions retain unknown ARM64 DATA
order despite matching target/process defaults and readable CPSR, while allowing guarded raw inspection.

The controlled native ARM64 exporter-refusal gate passed both owned fixture cases as part of its four-test module
in 1.53 seconds. It checks refusal before memory/file work and preservation of stopped context. Bridge/exporter
mock regressions passed 554 tests, with scoped Ruff, formatting and type checks.

The native ARM64 UI inspection gate passed one real-LLDB case in 8.11 seconds: six protocol operations cover
session/modules/threads/registers/raw memory/module-address resolution and separate explicit static navigation.
DATA order stays unknown, Prepare remains disabled, and no capture is published. Source, annotations, an unsaved
editor and stopped identity remain intact. Register assertions were first corrected to target the debugger window
rather than colliding with disassembly labels; the new-source gate then passed. This is not ARM64 capture acceptance.

The earlier x86-64 live workspace gate was blocked before UI/bridge observations by `Bad CPU type in executable`
on the ARM64 host; Rosetta was not installed to bypass it. That is neither a live workspace pass nor evidence
against native ARM64 inspection. Prepare/Compare/Save/Open acceptance remains a separate gate.

### Historical measurements and the superseded claim

The controlled stopped-process record at `35508ff` used Apple LLDB `2103.0.34.103` with ASLR enabled. It captured
executable bytes, 82 module records and 34 selected-thread registers; the function lifted completely and its
UUID/header slide correlated with the original image address. Leaving ASLR enabled avoided the earlier launch
stall. These observations remain historical measurements, not a current export recipe.

Earlier owned ARM64 export tests verified byte contents and identity under the then-assumed data order.
Subsequent review **superseded that data-order claim**: it was based on target architecture order, not affirmative
runtime DATA evidence. The old measurements are not erased, but those tests did not validate the new early-refusal
contract, did not observe E0E and do not authorize ARM64 export now. Architecture decoding, synthetic snapshot
analysis and native instruction-oracle acceptance remain separate from this debugger DATA-order contract.

[sbtarget]:
https://github.com/swiftlang/llvm-project/blob/1b669c3f63758879bb0c517a589abdea4c6efbeb/lldb/source/API/SBTarget.cpp
[sbprocess]:
https://github.com/swiftlang/llvm-project/blob/1b669c3f63758879bb0c517a589abdea4c6efbeb/lldb/source/API/SBProcess.cpp
[archspec]:
https://github.com/swiftlang/llvm-project/blob/1b669c3f63758879bb0c517a589abdea4c6efbeb/lldb/source/Utility/ArchSpec.cpp
[apple-porting]: https://developer.apple.com/documentation/apple-silicon/porting-your-macos-apps-to-apple-silicon
[xnu-controls]: https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.101.15/osfmk/arm64/proc_reg.h
[xnu-thread-state]: https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.101.15/osfmk/mach/arm/_structs.h
