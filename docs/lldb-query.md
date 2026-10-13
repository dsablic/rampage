# Read-only LLDB query protocol

The bridge operates inside an already authorized, stopped LLDB process. It registers `rampage-query` and accepts
bounded JSON requests; it does not attach, launch, resume, insert breakpoints, evaluate target expressions, write
target memory, expose a network listener or publish capture files. MCP/UI transport integration remains separate.

```text
command script import /path/to/rampage/tools/lldb_bridge.py
rampage-query {"version":1,"operation":"describe_session"}
```

## Requests

Copy the returned `token` into `expected_token` for every operation except initial `describe_session`.
The token contains backend/session identity, process unique ID, target index and stop ID including expression
stops. Stale tokens or changes observed during a query return an error without partial data. Tokens identify
debugger context, not capture content or process authenticity.

| Operation | Additional fields |
| --- | --- |
| `describe_session` | Optional `expected_token` |
| `list_modules` | `expected_token`, optional `offset`, `limit` |
| `list_threads` | `expected_token`, optional `offset`, `limit` |
| `read_registers` | `expected_token`, `thread_id`, optional `registers` |
| `read_memory` | `expected_token`, `address`, `size`, exact `permissions`, optional `thread_id` |

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
  AArch64 data byte order remains unknown. Unsupported ARM/ILP32 variants are rejected, not treated as ARM32.
- Observations have `atomic_snapshot: false`. Keep debugger operations and external writers quiescent:
  matching stop tokens and content hashes do not establish coherent point-in-time capture or proven call flow.

Metadata paths are reported, not opened automatically. Captured bytes and register contents can be sensitive;
keep query results local unless sharing them is authorized. The operation/data content hash covers the returned
query envelope, not memory bytes alone; identical bytes with different metadata can have different hashes. It is
separate from the debugger stop token and from persisted snapshot capture identity.
