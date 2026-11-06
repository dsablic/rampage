# Plugin security boundaries

The experimental triage component host separates untrusted report composition from native analysis. It is a
bounded execution lane, not an OS sandbox, an authenticity system or a proof of upstream native memory safety.
See [plugins and extension points](plugins.md) for commands, source admission and the component contract.

## Trust and authority

The plugin host pins Wasmtime **49.0.3**, including the upstream security fixes in that supported release.
Review [upstream advisories](https://github.com/bytecodealliance/wasmtime/security/advisories) when changing the
pin. The older Wasmtime dependency used by YARA is separate; this pin does not upgrade or audit that path.
The restricted grammar and process boundary are defense in depth, not a substitute for runtime security updates.

Treat the component and everything it says as untrusted. Treat the CLI/API host, selected native worker,
Wasmtime/compiler and native analysis dependencies as trusted code. A component receives only the admitted
immutable fact payload. Its interface has no WASI, filesystem, network, process, environment or host-project
imports and cannot request additional native analysis. Internal core-module wiring does not grant ambient
host capabilities.

The caller explicitly selects the component file and trusted worker executable. There is no directory scanning,
automatic plugin registry, dependency loading from the guest or inline execution fallback. A malicious native
worker is outside this trust model: selecting one gives it ordinary native-process authority.

Compilation uses raw component bytes through safe `Component::new`, never native-artifact deserialization.
The component SHA-256 in host provenance identifies the bytes actually supplied for execution. It is not a
signature, authorship claim or allowlist decision. The host sets the report's workflow, target and provenance;
the guest cannot supply those fields through the contract.

All remaining report content is plugin-authored, including `observed` confidence, primitive-tool source labels,
evidence, summaries and next-step reasons. Valid fact IDs establish references into admitted input, not truth
of prose, correct classification, native/layout proof or runtime-flow evidence. Actions are a closed set of
inert suggestions, not executable guest-selected tool JSON; component execution never applies annotations or
dispatches those suggestions.

## File selection and source preparation

The component reader accepts an explicitly selected regular file of at most 2 MiB. It checks pathname and
retained-descriptor metadata, opens with no-follow/nonblocking semantics, checks before bounded allocation and
between reads, and refuses observable replacement, truncation or growth. Final-leaf symlinks and special files
are refused. Parent-directory permissions are not a security policy, and the checks are not an atomic
filesystem snapshot. Hashing and execution use the returned byte snapshot rather than reopening the path.

Fresh target opening caps the actual opened descriptor at 16 MiB before mmap and admits that same mapping before
native parsing. Conservative little-endian x86-64 ELF, unmanaged AMD64 PE32+ and thin x86-64 Mach-O executable
profiles are supported. PE COFF tables/long names, delay imports, resources, security/load-config/bound-import
directories and chained unwind remain unsupported. Constructor thunk/name work includes both code-marked and
execute-only sections, matching the real name producer.

Mach-O admits canonical PIE layout, restricted bind-only chains, bounded regular exports, symbols and starts.
It refuses ARM64/arm64e, dylibs/bundles, classic dyld streams, chained rebases, signatures and automatic
language/debug/EH metadata; compact unwind stays opaque. Constructor stub work is budgeted per potential decoded
byte. Other formats, universal images, CLR and Go recovery remain refused.
The API's already-loaded-project path has separate admission; it does not retroactively bound initial loading costs.

Source descriptor checks, content hashing and retained name/configuration revisions reject observable changes
during preparation and around execution. They cannot make memory-mapped reads atomic with concurrent writes
or prevent every possible mapping hazard. Native source loading, checked sidecar ingestion, discovery and fact
preparation remain trusted host operations outside the component-worker resource limits.

Completed-analysis preparation is the API default. Cold native preparation requires an explicit API call or
CLI `--prepare-analysis`; it may be expensive. Cancellation is cooperative and discovery is checked before
and after its monolithic producer. A source/fact byte cap is not a bound on every native allocation or elapsed
time. Configured data packs, unavailable required databases or oversized facts reject preparation rather than
quietly dropping collections. Exhaustive input means complete relative to the selected primitives, not complete
knowledge of the program.

## Admission before compilation and copying

An allocation-free raw structural gate precedes dependency readers that own type and instance vectors.
Subsequent structural parsing and Wasmtime validation still run. This admission grammar deliberately accepts
only a subset of components: plain core function types and synchronous primitive/list/tuple component values,
with depth-bounded inline instance types. Explicit recursion groups, subtyping, GC, typed core references,
inline component/resource/record/variant/async types and extended constant expressions are not supported.
A valid general-purpose component may therefore be rejected as `plugin_preflight`.

Structural ceilings include:

| Structure | Ceiling |
| --- | --- |
| Envelope/type nesting | 8 |
| Aggregate entries / types / functions | 32,768 / 4,096 / 8,192 |
| Core function parameters / results | 128 / 16 |
| Instance argument/export vectors / canonical options | 256 / 16 |
| Inline instance type declarations / tuple members | 256 / 16 |
| Function body / locals per function / total locals | 256 KiB / 4,096 / 65,536 |
| Operators / control depth | 1,000,000 / 128 |
| Individual name / aggregate names | 1 KiB / 256 KiB |
| Aggregate custom payload / data / segment count | 512 KiB / 1 MiB / 1,024 |

These checks bound selected parser/compiler inputs; they are not a proof of compiler cost. Compilation and
structural parsing therefore occur inside the supervised worker, not in the API caller.

Strict JSON admission checks byte length, UTF-8, decoded duplicate keys, string size, depth and aggregate shape
before typed deserialization allocates collections or tagged-enum buffers. Both worker and parent validate the
response against the prepared facts. The guest's advertised output length is checked before host reservation;
fixed scalar chunks avoid an unbounded lazy output list or retaining a pointer across component post-return.

## Resource policy

The runtime has one process-wide nonblocking admission permit and no queue. It holds that permit through
supervisor cleanup and result validation, including cancellation and error paths. A busy host rejects another
request. Each admitted request uses a separate one-request native plugin worker and a fresh Wasmtime instance.

| Resource | Maximum policy |
| --- | --- |
| Raw component / fact input / guest response | 2 MiB / 1 MiB / 256 KiB |
| Fact-ID-bearing records / input text value | 16,384 / 4 KiB |
| Output text value / sections / findings per section | 64 KiB / 6 / 200 |
| Evidence items per finding | 8 plus an optional omission marker |
| Next steps | 10 |
| JSON depth / nodes | 16 / 262,144 |
| JSON containers / aggregate array items | 32,768 / 32,768 |
| Decoded object keys / key length / number token | 32 / 64 bytes / 32 bytes |
| Fuel | 50,000,000 |
| Component execution deadline | 500 ms |
| Runtime request timeout | 10 seconds |
| Supervised worker memory | 1 GiB |
| Linear memory | 64 MiB per memory, at most 2 memories |
| Tables | At most 2, each at most 10,000 elements |
| Store instances / Wasm stack | 8 / 512 KiB |
| Final CLI report | 60,000 bytes, including JSON's newline |

Reports require the six fixed triage sections; each section retains at most the requested number of findings.
Input text also has a separate aggregate limit of 16,384 text items, in addition to fact-record and byte quotas.

`PluginConfig` can lower configurable time, memory and fuel limits, not raise them above these ceilings.
Fuel and epoch interruption cover Wasm execution, including instantiation/start and output copying calls;
they do not meter compilation, host-side parsing, OS calls or native fact preparation. The separate worker's
supervised timeout and process memory controls cover compilation. The runtime request budget also checks
parent-side protocol work and response admission, but it is not a hard interruption guarantee for every host
operation. File opening and native preparation precede that runtime request budget.

These are experimental rejection ceilings, not promised latency or throughput. A 10-million fuel ceiling rejects
the actual Rust triage guest; the 50-million ceiling permits the exercised component cases. This does not
guarantee that arbitrary admitted inputs finish within fuel or time limits.

## Supervision and platform limitations

Supported hosts are 64-bit Linux and macOS. Supervision requires default `SIGCHLD` handling and exclusive
ownership of child wait status; an embedding process that reaps those children violates the worker contract.
Linux uses hard address-space/data limits. macOS uses sampled RSS, which can overshoot the configured memory
threshold before termination. Neither platform's memory policy is a proof against every transient allocation.

Cancellation and worker failures use owned process-group cleanup. Spawn and OS queries are not forcibly
interruptible. Descendants that escape the owned process group are outside the cleanup boundary, and abrupt
parent termination cannot guarantee cleanup. Import-free Wasm has no process-creation import, but that does not
turn the trusted native worker into an OS-sandboxed process or protect against runtime/compiler vulnerabilities.

The boundary does not sandbox upstream native loaders, decoders or analysis producers. Use a separate OS-level
isolation policy when the risk of parsing hostile binaries requires it; component controls do not substitute
for that policy.

## Failure and display behavior

Admission, compilation, fuel exhaustion, deadline, resource, trap, protocol and cleanup failures reject the
component invocation. Static `plugin_*` classifications are exposed instead of guest/compiler/worker diagnostic
text. There is no automatic builtin retry that could conceal a failed component run.

Terminal output escapes guest control characters and directional-formatting characters. JSON remains structured
data with the host provenance envelope; downstream consumers must preserve the plugin-claim distinction and
avoid treating guest text as instructions. Rendering buffers the complete admitted report before writing,
including the compact JSON newline in the final byte cap. It does not truncate JSON or execute next steps.

Only triage composition runs in this experimental lane. The other builtin workflows, MCP/UI registries and data
packs do not use it. This boundary is not a stable public plugin SDK, a general component compatibility promise
or a completed security review of a broader plugin system.

## Local acceptance scope

On an ARM64 macOS host, ten compiled cases match the builtin report body: normal/stripped owned
network-client ELF, owned MinGW PE and normal/stripped thin x86-64 Mach-O, each at section limits 1 and 25.
These cases use fresh checked source admission. Native oracles also check multi-page chained slots, decoy
exclusion, exports, backing, starts and constructor names. Target binaries are never executed.

Separate compiled probes exercise forbidden imports, a wrong interface version, malformed and oversized output,
fuel exhaustion in both exports, execution epochs, denied memory growth, pre-cancellation and sequential recovery.
The genuine guest also composes an empty inventory through its actual exports, and the CLI route retains the
host provenance envelope. Native guest tests cover additional classification, managed-token and ingestion cases.

Cancellation-only checkpoint probes park an actual Wasm activation at both call boundaries, cancel, and assert
successful reaping/cleanup plus real-permit retention through the post-cleanup callback. They also exercise
observer-panic recovery and cancellation from that final callback. The activation may be
canonical allocation rather than the probe's source-language loop. This opt-in v2 diagnostic never resumes;
ordinary execution uses v1. Parked/observer time is governed by the outer operation budget, not a 500 ms
hard-return promise; trusted parent callbacks cannot be forcibly interrupted. The checkpoint probes
establish healthy cleanup, not the separate quarantine transition below.

Mandatory parent-owned cleanup proof controls reopening independently of diagnostic collection. A request
without a spawned child, or with confirmed direct-root reap and owned-group cleanup, releases admission when
its real permit drops. Uncertain or missing proof quarantines future plugin requests in that process, including
unwind paths. Safe cleanup during observer panic still permits ordinary recovery. The proof callback runs after
guard cleanup and scoped I/O joins; it must not panic. It adds no PID or signaling authority, default RSS sampling,
resume operation, or application-protocol field. An application error cannot assign this parent-owned state.

Quarantine transitions have local production-state-machine tests; supervisor fault injection separately checks
uncertain proof with retained cleanup authority. This is composed coverage, not a genuine live-worker ownership
loss drill. There is deliberately no such drill: losing authority and then guessing a PID for test cleanup would
violate the boundary. There is no in-process reset; inspect unresolved resources before restarting.

This does not establish cancellation inside compilation, uninstrumented cancellation latency, every native
producer's memory bounds, or Linux runtime acceptance beyond these checks, which the Linux CI job runs on every CI
run. The checks use no privileged tracing or target execution.
