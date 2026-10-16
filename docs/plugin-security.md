# Plugin security boundaries

The experimental triage component host separates untrusted report composition from native analysis. It is a
bounded execution lane, not an OS sandbox, an authenticity system or a proof of upstream native memory safety.
See [plugins and extension points](plugins.md) for commands, source admission and the component contract.

## Trust and authority

The plugin host pins Wasmtime **49.0.3**, including the upstream security fixes in that supported release.
Review [upstream advisories](https://github.com/bytecodealliance/wasmtime/security/advisories) when changing the
pin. The older Wasmtime dependency used by YARA is separate; this does not upgrade or audit that entire path.
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

Fresh target opening separately caps the original regular source file at 16 MiB before native parsing and
uses conservative raw ELF metadata admission. The current profile is little-endian x86-64 ELF only; other
native formats, universal images, CLR and Go recovery candidates are refused on this fresh-load path. The
API's already-loaded-project path has separate admission and can accept native PE; it does not retroactively
bound the cost of loading that project.

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

These are experimental rejection ceilings, not promised latency or throughput. The earlier 10-million-fuel
policy rejected the actual Rust triage guest; the current 50-million ceiling permits the exercised component
cases. That observation does not guarantee arbitrary admitted inputs finish within fuel or time limits.

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

Only triage composition has been migrated into this experimental lane. The other builtin workflows, MCP/UI
registries and data packs retain their existing behavior. This boundary is not a stable public plugin SDK,
general component compatibility promise or completed security review of the broader plugin roadmap.

## Local acceptance scope

On the ARM64 macOS host, the compiled Rust guest matched the unchanged builtin report body for normal/stripped
owned network-client ELF and owned MinGW PE fixtures, each at section limits 1 and 25. The PE cases used the
already-loaded API path, not the restricted fresh CLI loader. Target binaries were never executed.

Separate compiled probes exercised forbidden imports, a wrong interface version, malformed and oversized output,
fuel exhaustion in both exports, execution epochs, denied memory growth, pre-cancellation and sequential recovery.
The genuine guest also composed an empty inventory through its actual exports, and the CLI route retained the
host provenance envelope. Native guest tests cover additional classification, managed-token and ingestion cases.

These checks do not establish cancellation during compilation or active guest work, every native producer's
memory bounds, or Linux runtime acceptance. The Linux CI gate is configured but has not been dispatched as part
of ordinary development. No privileged tracing, target execution or security-policy weakening was used.
