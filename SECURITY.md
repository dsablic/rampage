# Security policy

## Reporting a vulnerability

Report vulnerabilities through GitHub's private vulnerability reporting: open the repository's **Security** tab and
choose **Report a vulnerability** (<https://github.com/dsablic/rampage/security/advisories/new>). Please do not open
a public issue, pull request or discussion for a suspected vulnerability.

Include the rampage commit or version, the host OS, the command or MCP call, and a reproducer. If the trigger is a
binary you cannot share, describe its format and the smallest input you can build that reproduces the problem.
Fixes are coordinated in the private advisory before disclosure.

## Supported versions

rampage is a 0.1 preview. Only the latest commit on `main` and the most recent 0.1 preview release receive fixes;
there are no backports to older commits.

## Scope

rampage parses hostile binaries, and its opt-in debugger controls live targets. These count as vulnerabilities:

- **Parser crashes or hangs on crafted input.** A panic, abort, out-of-bounds access, unbounded allocation, or a
  hang or runaway CPU use from a crafted executable, archive, debug-info file, data pack or other input that any
  loader, analysis pass, CLI command or MCP tool reads.
- **Escaping MCP output bounds.** An MCP tool result, page or error that exceeds its documented size cap (see
  [MCP](docs/mcp.md)), or a paging cursor that skips or repeats data without saying so.
- **Bypassing debugger consent flags.** Reaching a debug stub that was not allowed with `--debug-endpoint` (or
  `RAMPAGE_DEBUG_ENDPOINTS`), writing target memory or registers without `--debug-writes`, or killing a target
  without `--debug-kill`; see [debug control](docs/debug-control.md#consent). rampage never launches or attaches
  to a process itself; a path that does is in scope.
- **Defeating the decompiler worker's supervision limits.** The supervised `rampage-worker` enforces a wall-clock
  timeout, a memory limit (a hard limit on Linux, sampled resident memory on macOS) and bounded output, and is
  cleaned up on cancellation. Input that makes the worker outlive or exceed those limits, or that makes its output
  corrupt the host's results, is in scope.

The worker supervision is **not an OS sandbox**. The worker runs with the user's privileges and can read and write
what the user can; it bounds time, memory and output, not file system or network access. Code execution inside the
decompiler engine from a crafted binary is in scope, but escaping a sandbox that does not exist is not a separate
finding. Run untrusted inputs in a VM or container if you need isolation.

Out of scope: findings that need an attacker to already control the rampage command line, MCP client configuration
or environment variables; results an AI client discloses to its own model provider (see the data-disclosure notes in
[MCP](docs/mcp.md)); analysis inaccuracy that is not a crash, hang or bound violation; and anything in a debug target
after the operator allowed writes to it.
