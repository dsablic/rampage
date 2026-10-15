# Desktop UI reference

The desktop client is an egui app over the same API as the CLI and MCP server.

```sh
cargo run --release -p rampage-ui -- sample.elf
cargo run --release -p rampage-ui -- module.dylib --arch aarch64
cargo run --release -p rampage-ui -- container.bin --image-offset 0x1000 --image-length 4096 --pack example-pack
```

The file is optional; drop a file on the window to open it. The UI also opens universal slices,
[runtime snapshots](runtime-snapshots.md) and validated embedded executable views. A sibling worker is selected
when installed; see the [decompiler reference](../crates/rampage-decompiler/README.md) for native supervision.

## Views and controls

Docked functions, strings, imports and exports lists share a disassembly listing with clickable references,
a hex view for data, a control-flow graph, cross-references, triage and a navigation band across the image.
The Pseudocode tab loads Ghidra decompilation in the background and navigates inline address-linked tokens;
reported recovery issues remain visible rather than treating any rendered C as correct.

When a file embeds executables or containers, Carve lists candidates from the same scan as `binary carve`.
A validated executable opens as its own project. A file that cannot open whole shows the candidate list
immediately; an offset and optional length can also be entered explicitly. Carving does not extract/decompress
containers. Embedded-view annotations remain separate from the outer image and are shared with CLI/MCP clients
opening that same view; see [annotation persistence](cli-reference.md#persistence-and-shared-edits).

| Key | Action |
| --- | --- |
| Space | Switch listing/graph |
| G | Go to address/name |
| Esc or Alt+Left | Back |
| Alt+Right | Forward |
| N | Rename |
| `;` | Comment |
| Ctrl/Cmd+Z | Undo |
| Shift+Ctrl/Cmd+Z | Redo |
| Ctrl/Cmd+D | Open the local read-only debugger window |

An undo blocked by another client's edit shows the conflict and offers to discard that step from undo history
without reverting its edits. It does not force an undo through the conflict. Data packs from `--pack` or
`RAMPAGE_PACKS` use CLI precedence; About lists content status and the status bar counts problems. See
[data packs](data-packs.md) and [MCP edit behavior](mcp.md#edits-and-session-state).

## Local debugger observations

The brand's context menu or Ctrl/Cmd+D opens **Read-only debugger**, even without a loaded binary. Opening the
window does not connect. Enter an explicit absolute local Unix socket, then use **Connect stopped session** or
**Refresh stopped session**. The LLDB operator starts the authorized stopped-session endpoint separately.
Module/thread pages, row selection, raw registers, raw memory and UUID-qualified file-address resolution are
explicit actions, without automatic polling, stale-token refresh, retry or navigation. Pages have at most 32 rows;
the structured memory view accepts 1–4,096 bytes and exact mapping permissions.

**Advanced: raw requests and JSON responses** retains the [LLDB protocol](lldb-query.md) templates and **Query**
button. Raw templates require explicit token/placeholder replacement. Responses, paths, registers and bytes remain
local, separate from annotations and the Assistant/provider. **Clear local data** clears window inputs/results
and editor undo state when idle, not saved capture files. Runtime bytes/registers can be sensitive.

An explicit qualified resolution can offer **Go to matching static image address**. Only a separate click uses
the returned file virtual address in the already-open matching Mach-O, never a runtime load address or a reported
module pathname. Typed SDK section/mapping evidence, request/token, exact UUID, architecture/variant, address
width, byte order and readable static backing must agree; otherwise the result remains raw-only. Inputs,
templates, rejected edits, new queries and workspace replacement invalidate the action, including late results.
Source-descriptor/path metadata are checked without mapped-byte reads during painting and revalidated on clicks.

The separate **Prepare capture preview (9 queries)** action composes existing queries for one UUID-matched
ordinary x86-64 Darwin image, one selected thread and at most 4,096 bytes. Prepare semantically validates owned
snapshot bytes without writing files. **Compare prepared capture with original** compares those observations
with the same retained original, not a saved pathname. **Save prepared capture** explicitly publishes historical
data into a private directory without clobbering; staging paths are retained for operator inspection, not unsafe
automatic deletion. Uncertain publication cannot authorize Open or same-destination publication retry.
**Open saved snapshot** requires a current comparison and successful publication, rechecks source/bindings and
actual session document bytes/digest, and refuses while an annotation editor is unsaved. Save never opens itself.

ARM64 runtime DATA order remains unknown, so this new capture composition refuses it while inspection remains
available. Existing standalone exporter architecture support is separate and unchanged. Matching observations
are non-atomic, not proof of authenticity, equal bytes, a current stop, flow or layout; client timeouts cannot
prove SDK work stopped. The window offers no launch, attach, resume, step, breakpoint, expression or target-write
controls. See the [debugger workspace guide](debugger-workspace.md) for the complete action sequence, source/form/
stop-epoch guards, private publication rules, API and acceptance boundary.

## Assistant and data disclosure

The Assistant tab talks to Claude about the open project. It reads functions, graphs, strings and references
through rampage tools, can save names/comments and typed annotations, and can point the listing at what it
discusses. It offers binary tools from every group, plus interactive `show_address`, but not `carve`,
`archive_inventory`, `list_packs` or `query_debugger`. See the [MCP tool groups](mcp.md#tool-groups)
for shared tool names.

Set `ANTHROPIC_API_KEY` through your environment to use the assistant; `RAMPAGE_MODEL` optionally selects the
model. Keep API credentials out of command-line examples, source control and shared logs. Enter submits a
question; Shift+Enter inserts a newline, and Ask also submits. Analysis and conversation run in the background.

Submitting a question sends the conversation and tool results, including code, strings and annotations the
model reads, to Anthropic's API. Use the assistant only with consent to disclose that material to this provider
and to let its tools edit shared annotations. Inspection permission alone does not imply upload permission.
There is no separate per-tool approval dialog in the desktop assistant; do not rely on one to prevent disclosure
or edits. Ordinary local analysis does not require an API key or a model connection. The assistant's analysis
tools do not execute the target or arbitrary shell commands.

## Offscreen checks and performance

`cargo test -p rampage-ui` runs offscreen rendering checks against images in
`crates/rampage-ui/tests/snapshots`. Refresh intentional snapshot changes with:

```sh
UPDATE_SNAPSHOTS=1 cargo test -p rampage-ui --test snapshots
```

Review refreshed images rather than treating an update as a correctness check. Analysis runs in the background;
previously reported Chrome framework samples (about 190,000 functions and 930,000 strings) rendered frames in
a few milliseconds. This sample-specific result is not a frame-time guarantee. See
[reported discovery timings and benchmark limits](features.md#measurements-and-development).
