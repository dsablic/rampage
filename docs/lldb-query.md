# Read-only LLDB query protocol

The bridge operates inside an already authorized, stopped LLDB process. It registers `rampage-query` and accepts
bounded JSON requests; it does not attach, launch, resume, insert breakpoints, evaluate target expressions, write
target memory, expose an IP/network listener or publish capture files. For execution control, breakpoints and
writes, see the MCP [debug tools](debug-control.md), which talk to an operator-started GDB remote stub instead.

```text
command script import /path/to/rampage/tools/lldb_bridge.py
rampage-query {"version":1,"operation":"describe_session"}
```

## Requests

Copy the returned `token` into `expected_token` for every operation except initial `describe_session`.
The token contains backend/session identity, process unique ID, target index and stop ID including expression
stops. Stale tokens or changes observed during a query return an error without partial data. Tokens identify
debugger context, not capture content or process authenticity.

## Explicit local transport

The operator can serve the enumerated read-only operations over a local Unix-domain socket from the stopped
LLDB command thread. Serving is explicit: clients do not start LLDB, discover endpoints or control execution.
The endpoint must be an absolute path in a preexisting same-user private directory (mode `0700`), without
symlinked components. Existing endpoints are refused, not replaced; the new socket uses mode `0600`.

```text
rampage-query-serve --socket /absolute/private-directory/query.sock --max-requests 32 --idle-timeout-ms 60000
```

The serve command occupies the LLDB command thread until its request limit, idle deadline or interruption.
It does not access LLDB from a background transport thread. Each connection carries one UTF-8 JSON request
and one JSON response, each terminated by a newline, then closes. The client must write-half-close after its
request; the server validates EOF before querying LLDB, rejecting trailing or incomplete input. Existing query
byte limits apply to the JSON payload, excluding that newline. Operations remain enumerated; debugger commands
and expressions are not inputs.

The default request limit is 32 (allowed 1–256); malformed connections consume it too. The default idle
timeout is 60,000 ms (allowed 1–300,000). Each connection has a shared 3,000 ms request/response I/O deadline.
These limits do not forcibly interrupt an LLDB SDK call; a client timeout is not proof that SDK work has stopped.

Socket permissions restrict local access; they do not establish process authenticity or atomic observations.
Keep the endpoint directory private and do not replace its contents while serving. Binding uses a bind-only helper
process with the validated directory FD, its own working directory and restrictive umask; the helper has no LLDB
access and does not change the debugger's working directory or umask. Helper IPC/wait deadlines do not establish
a hard bound while the platform is creating the interpreter process itself.
Serving requires Python's main thread and a restorable Python SIGINT handler (or an ignored SIGINT policy);
unsupported embeddings refuse launch. Resource ownership transitions defer interruption, restore the prior
handler and then deliver cancellation; the service does not alter the debugger's signal mask.

Shutdown closes owned descriptors but **retains the endpoint pathname**. The server never chmods or unlinks
published pathnames: a same-user process could replace one between a check and a pathname operation. The operator
must clean up the endpoint after serving, or choose a new name. Retained endpoints are not overwritten on restart.
Same-user namespace manipulation remains possible; private-directory permissions are not endpoint authentication.

### CLI and MCP clients

```sh
rampage runtime debugger query --socket /absolute/private-directory/query.sock \
  --request '{"version":1,"operation":"describe_session"}'
```

The CLI requires an explicit socket and request. Follow-ups copy the returned `token` into request `expected_token`,
just as the in-session command does. The client deadline includes connection and request/response I/O; stale tokens
are not automatically refreshed or retried. Responses retain backend errors and non-atomic observation evidence.

MCP exposes `query_debugger` in the `runtime` tool group without requiring a loaded image. Socket paths are
explicit inputs, not environment defaults. Runtime bytes and register values returned to an MCP caller can be
sensitive: use an authorized local client and do not share responses externally without permission.

| Operation | Additional fields |
| --- | --- |
| `describe_session` | Optional `expected_token` |
| `list_modules` | `expected_token`, optional `offset`, `limit` |
| `list_threads` | `expected_token`, optional `offset`, `limit` |
| `read_registers` | `expected_token`, `thread_id`, optional `registers` |
| `read_memory` | `expected_token`, `address`, `size`, exact `permissions`, optional `thread_id` |
| `resolve_module_address` | `expected_token`, explicit `module_uuid`, `file_address` |

All operations accept `response_budget`. Addresses and thread IDs accept integers or hexadecimal strings.
The protocol is `rampage-lldb-query-v1`; successful responses include `ok`, operation, token, data and an
observation descriptor. Errors have valid JSON and no partial result. Operation names are enumerated, not
arbitrary debugger commands.

## Limits and evidence

- Requests: 16 KiB; responses: at most 256 KiB; memory reads: at most 64 KiB.
- Enumeration: at most 4,096 modules/threads; pages: at most 128 items; mapping queries: at most 1,024.
- Memory requires complete readable coverage and exact known permissions. Unknown SDK permission states,
  contradictory descriptions and SDKs that cannot distinguish unknown from denied permissions refuse reads.
- Target, module and thread provenance are rechecked. Register-bearing requests resolve fresh frames and
  revalidate registers and stop evidence. Raw `IsStopped()` may be false on Apple LLDB while current SDK stop
  info is valid; `stop_evidence` reports that distinction without fabricating a true flag or latest stop cause.
- Memory bytes remain raw. ARM32 data byte order requires explicitly selected, revalidated CPSR.E;
  AArch64 data byte order remains `unknown`, including ARM64/arm64e sessions with little-endian target and
  process architecture defaults or readable CPSR. Unsupported ARM/ILP32 variants are rejected, not treated as ARM32.
- Observations have `atomic_snapshot: false`. Keep debugger operations and external writers quiescent:
  matching stop tokens and content hashes do not establish coherent point-in-time capture or proven call flow.

Metadata paths are reported, not opened automatically. Captured bytes and register contents can be sensitive;
keep query results local unless sharing them is authorized. The operation/data content hash covers the returned
query envelope, not memory bytes alone; identical bytes with different metadata can have different hashes. It is
separate from the debugger stop token and from persisted snapshot capture identity.

ARM64 session descriptions, module/thread enumeration, register reads, bounded raw memory reads and qualified
module-address observations remain available under these guards. An unknown DATA order does not prevent raw
inspection, but it cannot authorize snapshot export. Neither `SBTarget.GetByteOrder()` nor
`SBProcess.GetByteOrder()` supplies the missing runtime DATA fact. There is no assumption override, privileged
register read or target-expression fallback. See [runtime data order](runtime-data-order.md) for the pinned
SDK/architecture evidence, historical correction and acceptance boundary; the
[snapshot guide](runtime-snapshots.md#export-from-lldb) describes the supported x86-64/ARM32 export workflow.

## Module-qualified address observations

`resolve_module_address` selects exactly one normalized SDK UUID/build ID, never a basename or recorded path.
`file_address` is the module's image virtual address, not a file offset. Compact hexadecimal IDs and the SDK's
hyphen-separated spelling are accepted case-insensitively, bounded to 1–64 bytes; opaque identifiers are refused.

The result retains raw image/load addresses, module context, leaf-section and ancestor evidence, known-readable
mapping coverage, and the current session/stop token. Traversal is bounded before SDK address construction, and
file/load ranges and inherited arithmetic are checked and revalidated before publication. Gaps, unloaded mappings,
ambiguous identities, overflow, changed provenance and stale stops fail without partial data. Independently loaded
children beneath unloaded ancestors are explicitly unsupported.

The resolver caps cumulative inspection work at 16,384 units, sections at 4,096 per traversal, depth at 32, and
mapping queries at 1,024. These are traversal budgets, not SDK-call latency limits. The deprecated SDK target-byte
size getter is not evidence that arbitrary target address units are supported. SDK section inspection may lazily
load symbol metadata. No project image or path reported by the target is opened by this operation.

These are non-atomic qualified observations, not proven cross-module flow or object layout. The local UI template
requires explicit UUID, address and token replacement and never navigates automatically. A separate explicit
[matching-static-image action](desktop-ui.md#local-debugger-observations) validates local context before navigation;
the [debugger workspace guide](debugger-workspace.md) covers structured inspection and client-local capture over
these unchanged operations. Neither navigation nor capture strengthens the protocol's identity, atomicity or flow
guarantees.
