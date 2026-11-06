# Exact-entry analysis reference

Exact-entry decompilation and entry diagnostics inspect a requested image address without resolving a containing
function or running whole-program discovery. They are separate operations: diagnostics sample local bytes;
decompilation supplies bounded host context to the native engine over the full mapped image. Neither verifies
that an address starts a complete function.

## CLI and shared tools

Replace `sample.elf` and `main` with an authorized image and an address or name it contains.

```sh
rampage binary audit sample.elf --entries --json
rampage binary audit sample.elf --entries --at main --json
rampage function decompile sample.elf --at main --exact-entry --isolated --json
```

The compatibility spellings accept the same options:

```sh
rampage audit sample.elf --entries --at main --json
rampage decompile sample.elf --at main --exact-entry --isolated --json
```

`--at` accepts an existing name, a `0x` hexadecimal or decimal address, or `sub_<hex>`. It refers to the selected
image's virtual address, not a file offset. The architecture and embedded-image selectors apply.
For audits, `--at` requires `--entries`; `--entries` conflicts with `--include-discovery`.

Shared tools, including MCP, expose:

| Tool | Arguments | Behavior |
| --- | --- | --- |
| `entry_diagnostics` | Optional `at`, `offset`, `limit` | Independent bounded entry sampling; diagnostics group |
| `decompile` | Required `at`, optional `exact_entry` | Exact-entry mode only when `exact_entry=true`; core group |

For example, the tool arguments are `{"at":"main","exact_entry":true}` or
`{"at":"main","offset":0,"limit":1}` for `entry_diagnostics`. Enable the diagnostics group when required by
the MCP client's tool configuration. Tool results have a 60,000-byte encoded JSON budget. Decompilation is not
paged: an oversized result is refused with a suggestion to use the CLI or API, not silently shortened.

Without the opt-in, `function decompile`, flat `decompile`, the `decompile` tool and `Project::decompile`
use containing-function and whole-program-context behavior. `binary audit` without `--entries` samples
regions. The ordinary desktop Pseudocode tab uses the legacy decompilation path;
opening an address there alone is not an exact-entry request. The separate
[desktop exact-entry window](exact-entry-ui.md) supports deferred opening, explicit validation and Run without
global analysis. Its context-menu actions open those controls rather than executing automatically.

## Exact-entry API

`Project` exposes these separate methods:

```rust
pub fn decompile_entry(
    &self,
    request: &DecompileEntryRequest,
) -> Result<EntryDecompilation, ApiError>;

pub fn decompile_entry_cancellable(
    &self,
    request: &DecompileEntryRequest,
    cancellation: &AtomicBool,
) -> Result<EntryDecompilation, ApiError>;
```

`DecompileEntryRequest` contains `address: u64` and `validation: EntryValidation`:

- `MetadataBacked` requires an exact function-symbol, export, format-function-start or image-entry declaration.
  A containing symbol alone is insufficient. The entry must still pass code/backing checks.
- `AnalystAsserted` explicitly asserts the requested address, including an interior address without independent
  entry metadata. The CLI flag and shared-tool Boolean select this policy. The assertion does not bypass known
  data, unavailable bytes, executable-mapping, address-width or alignment checks.

Both policies retain exact origins and report overlap with a nonzero-sized symbol extent. Metadata declarations,
analyst assertions and successful decoding are evidence, not instruction-boundary or function-completeness proof.
There is no fallback to a containing function or to legacy whole-program analysis after a refusal.

### Supported inputs and mapping

Exact-entry decompilation accepts little-endian x86, x86-64 and AArch64 only. AArch64 addresses must be four-byte
aligned; x86 addresses must fit 32 bits. ARM/A32, Thumb, big-endian inputs and other architectures are refused.
This narrower contract does not narrow the architectures the legacy decoder/decompiler path supports.

The requested entry must have available, backed executable code and must not be an import slot or overlap a
known data-symbol extent. Each request creates a fresh native engine, or a fresh supervised worker request,
using the project's configured options. It neither consumes nor publishes the cached whole-program analysis,
Go-inference state or legacy native engine. Earlier discovery and decompilation requests do not supply context.

Mapping is not cropped to the entry window. The ordinary full-image mapper retains every nonempty readable or
executable segment's available backing and read/write/execute permissions. Declared file-image zero-fill tails
remain zero-fill; missing backing and snapshot gaps remain unavailable rather than fabricated as zeros.
Read-only data remains available for native string/constant handling. The selected image and the aggregate
backed mapping bytes each have a 128 MiB cap; exceeding either refuses the request rather than shrinking the image.

Mapped inputs undergo physical backing-descriptor/pathname metadata checks around preparation and execution.
`mapped_backing_checked=false` denotes owned input bytes, not a physical-source identity proof. These checks are
not atomic with external writes or truncation; keep source files quiescent.

### Local context and declaration replay

Host preparation retains the entry, actual saved signature targets, bounded referenced exact metadata entries,
import slots and recognized aliases in declared import-stub sections. It does not discover arbitrary callees.
The local walk follows bounded direct branch context, not arbitrary callee bodies, and stops at independent
entries, data extents, unresolved indirect transfers, invalid instructions and window boundaries. Curated
name-backed runtime prototypes/noreturn facts may be supplied; whole-program inferred noreturn facts are not.

A separate bounded check can mark referenced exact-metadata wrappers noreturn when straight-line setup ends
in a direct call/jump to an exact known non-unwinding fatal import stub. At most 32 distinct candidates,
32 decode operations per candidate and a 128-byte window are inspected, charged to the shared decode budgets
with cancellation checks. This is not recursive inference or an arbitrary callee walk. Throwing imports,
conditional/unknown transfers, metadata/data boundaries, ARM64 exception-generation instructions and x86
software interrupts do not supply wrapper proof. Analyst display names alone never establish this fact.

Actual saved types, globals and signatures are required replay input, including dependencies outside the local
walk. Checked layout bundles retain their v1/v2 identity/projection rules and source/specification checks.
Declarations precede layout assertions; assertions precede dependent globals and prototypes. A missing,
conflicting, stale, unsupported or over-budget required declaration/assertion fails the request. A successful
request must not silently drop an actual analyst signature to fit the local context budget.

Canonical `go_results_N` type dependencies used by actual declarations are generated before their consumers.
This requires the selected `golang` compiler model and supported register-ABI width: `N` is 2–9 on x86-64 or
2–16 on AArch64. Canonical definitions must match; shadowing or ambiguous uses refuse. This replays dependency
types, not inferred Go results or callee prototypes, and does not consult the whole-program Go inference cache.

| Preparation budget | Limit |
| --- | --- |
| Combined metadata records | 131,072 |
| Sections / segments | 4,096 each |
| Individual metadata/annotation names | 4,096 bytes |
| Aggregate metadata names | 8 MiB |
| Names, signatures, types and globals combined | 8,192 annotation records |
| Required signature targets | 256 |
| Aggregate annotation text preflight | 8 MiB; at most 1 MiB per value |
| Required declaration replay | 1,024 types/globals/signatures; 1 MiB total text; 128 sealed layout signatures |
| Local preparation decoding, including stub work | 4,096 instructions and 64 KiB decoded bytes |
| Declared-stub decoding sub-budget | 1,024 instructions |
| Walked / queued blocks | 256 each |
| Retained symbols plus imports / distinct direct targets / stub aliases | 256 for each budget |

Declaration syntax and checked-layout validation can impose stricter limits. In particular, checked
layouts also restrict image metadata to 8,192 symbols, exports and starts each, 1,024 imports/slots each,
256 segments and 1 MiB of names, with 4,095 bytes per name. These are admission/work caps, not completeness claims.

Optional context reaching a cap is omitted explicitly and sets `context_budget_exhausted`. Required replay
reaching a cap fails instead. Undeclared PE text thunks and authenticated import stubs are not inferred;
required import-signature alias replay refuses when the focused path cannot prove its needed aliases.

### Results, warnings and timing

`EntryDecompilation` flattens the normal decompilation fields (`address`, `name`, `code`, `language_id`, `tokens`,
`recovery_status`, `structure`) and adds `context`:

- `scope: "exact_entry"`, validation policy, origins and `inside_symbol_extent`;
- `full_image_mapping`, backing-check status, mapped-region and backed-byte counts;
- retained symbols/imports, references, decoded instructions/bytes, walked blocks, stub aliases and cap status;
- generated dependency-type and declaration-replay operation counts;
- an independent exact-address diagnostic `sample`, plus explicit host-context `omissions`;
- `execution: "in_process_native"` or `"supervised_worker"`;
- millisecond `timings`: `configuration_ms`, `metadata_ms`, `replay_ms`, `mapping_ms`, `execution_ms`, `total_ms`.

The diagnostic sample has its own admission limits and can report unavailable evidence without inventing an
assessment. Host omissions are separate from native `recovery_status` and structured recovery diagnostics.
Native warnings do not disappear because host preparation succeeded; generated C is not recovery proof.
Text CLI output includes the exact-entry qualification, native recovery status and context omissions; use JSON
for the full context, counts, evidence and timings.

In-process native initialization and FFI execution are not forcibly interruptible. Cancellation is cooperative
at host checkpoints. When a worker is configured, the elapsed budget starts before configuration/preparation;
checks charge preparation and serialization, and worker dispatch receives only the remaining timeout. The default
total worker budget is 30 seconds. The supervisor's platform/process-creation and cleanup limits still apply.
There is no constant-latency or hard end-to-end interruption guarantee. Full-image mapping, hashing, declaration
replay and native work still cost time. `--isolated` requires the worker; worker failure never silently falls back
to in-process execution.

## Entry diagnostics API and evidence

`Project::entry_diagnostics(address: Option<u64>) -> Result<EntryAudit, ApiError>` samples one exact address when
given, otherwise the lowest bounded distinct metadata-declared addresses. Selection considers function symbols,
exports, format starts and the image entry; exports need not be code. All exact-address symbol kinds are retained
as evidence at selected addresses. Aliases at one address are origins, not additional function counts.

This operation neither runs nor consumes whole-program discovery, follows transfer targets, builds CFG edges,
changes annotations nor imports types. A caller-address origin is emitted only if a complete admitted metadata
scan found no exact origin; failed preflight returns unavailable evidence, not an ungrounded caller assertion.

Each entry reports origins and declaration-record counts, backing/mode status, sampled/decoded bytes, decoder
attempts and instruction/invalid counts, indirect-transfer counts, entropy, signals, stop reason/address, last
flow and window boundaries. The report's `status` is `available`, `empty`, `disabled` or `unavailable`; an individual
entry can separately report non-code, unavailable backing, unsupported architecture/byte order or unresolved mode.
For x86 and ARM, addresses must fit 32 bits: out-of-width origins remain visible but cannot become plausible-code
evidence. Sample windows stop at the target address-space boundary, even when more backing bytes are available.
The three `assessment` labels are:

- `unknown`: insufficient or ambiguous local evidence;
- `suspicious`: a bounded high-entropy window or a decode-failure signal;
- `locally_plausible`: a bounded local decode, not verified code semantics or a function boundary.

These are not percentages, encryption detection, protector identification or product attribution. Random bytes
and data can decode, especially on x86. High entropy means at least 64 sampled bytes with entropy at least
6.5 bits/byte; entropy covers the sampled window, including bytes after the first observed transfer. An invalid
short tail can remain ambiguous between invalid and incomplete code.

### Sampling limits

| Budget | Limit |
| --- | --- |
| Distinct selected entries | 64 |
| Bytes / decoder attempts per entry | 128 bytes / 16 attempts |
| Cumulative bytes / public decoder calls | 8,192 bytes / 1,024 calls |
| Combined sections, segments and Thumb ranges | 16,384 |
| Declaration records before deduplication | 65,536 |
| Individual symbol/export name | 4,096 bytes |
| Aggregate metadata names / copied output names | 4 MiB / 64 KiB |
| Origins per address | 16: seven symbol names, seven export names, format start and image entry |
| Reserved mapping-lookup work | 1,000,000 visits |

The lower-level sampler accepts smaller limits and clamps larger requests. Zero sampling limits disable it.
Preflight refuses excessive metadata, declarations or names and invalid Thumb ranges before sampling. Selection
and origin collection use bounded passes rather than cloning/sorting all declarations or rescanning for every
entry. Truncation reports do not remove candidates from the input image.

Sampling stays in one executable, file-backed code mapping and declared instruction mode. It stops after one
straight-line prefix at the first transfer, including conditional transfers, or invalid decode. Targets, calls
and switches are not followed. Zero-fill, gaps and non-code ranges are not decoded. Supported sampling differs
from exact-entry decompilation: x86, x86-64, little-endian AArch64 and explicitly declared Thumb are sampled;
ARM outside a declared Thumb range has unresolved mode and is not guessed as A32.

### MCP paging and alias omissions

The CLI/API return the bounded report directly. `entry_diagnostics` additionally pages whole entry rows inside
60,000 encoded JSON bytes. `limit` defaults to 64 and must be 1–64; `offset` defaults to zero and is clamped to
the sampled row count. Paging does not increase the sampling cap or resume selection beyond the first 64 entries.

The envelope preserves report status, limits, usage, truncation, warnings and limitations, plus `entries_total`,
`offset`, `limit`, `more`, `next_offset` and `byte_capped`. Continue with the returned `next_offset`. Every call
resamples; pages are not a frozen multi-call snapshot.

An individually oversized row can omit display aliases explicitly: origin `name` becomes null with
`name_omitted=true`; `transport_names_omitted` and `transport.names_omitted_total` account for transport omissions.
Sampling can separately omit names at its copied-name budget. Neither omission changes code-sample evidence or
declaration counts. The transport never clips serialized JSON or splits a row; an envelope or row that still
cannot fit is refused.

## Acceptance boundary

Local owned CLI/API/worker acceptance includes native/worker parity, both CLI spellings, source-oracle cases and
v1/v2 checked declaration replay; ordinary workspace tests run in bounded package slices. The documented caps
are not performance, whole-program quality or arbitrary-binary acceptance claims. See the separately scoped
[entry measurements](entry-measurements.md); neither those measurements nor controlled fixtures establish an
exact-entry latency guarantee.
