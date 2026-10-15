# Use the local read-only debugger workspace

The desktop **Read-only debugger** window inspects an existing authorized stopped LLDB session over an explicit
local Unix socket. It offers structured inspection, guarded navigation into an already-open static image, and
separate client-local Prepare, Compare, Save and Open actions. It never starts or controls the target.

Use only programs and observations you own or have permission to inspect. Socket paths, requests, module paths,
registers and memory bytes remain local to the debugger window; they are not sent to the Assistant or a provider.
Runtime memory and register values can contain secrets. Saving is an explicit decision to persist sensitive data,
not a reason to upload it or include it in source control.

## Connect and inspect explicitly

1. Have the LLDB operator start the [read-only query endpoint](lldb-query.md#explicit-local-transport) while the
   authorized process is already stopped. The UI does not discover sockets or start LLDB. Provision enough
   endpoint requests for inspection and the nine-query Prepare sequence; the endpoint's default limit is 32.
2. Open the window from the brand context menu or **Ctrl/Cmd+D**. No connection is made merely by opening it.
   Enter the operator's explicit absolute Unix socket path and click **Connect stopped session**.
3. Click **List modules page** and **List threads page**, then select one module and thread explicitly. Each page
   has at most 32 rows. Offset, Previous and Next controls request pages only on an explicit button click;
   neither opening the window nor selecting a row fetches follow-up data.
4. Click **Read selected thread registers** for raw register values. For memory, enter a **Raw runtime load
   address**, choose 1–4,096 bytes and the exact mapping permissions, then click **Read raw memory**. Memory
   remains hexadecimal bytes, not inferred scalars or object layouts.
5. If you need a new stop context, click **Refresh stopped session** explicitly. Stale-token/backend refusals
   require an explicit Refresh; there is no automatic retry, reconnect, token replacement or background polling.

The structured view retains the returned session token for explicit follow-ups. Connect and Refresh describe a
session; they do not attach to a process. Each inspection button sends one existing query. A single local job
permit prevents overlapping debugger jobs, including after the window closes while work is still pending.
UI client queries use a 3,000 ms deadline. Client timeout does not prove an LLDB SDK call has stopped.

**Advanced: raw requests and JSON responses** retains the six fixed protocol templates and explicit **Query**
button. Raw follow-up templates require replacing their token/placeholders yourself. **Clear local data** clears
window inputs/results and editor undo state when no job is pending; it does not delete saved or retained files.

The bridge does not call the LLDB SDK from a background transport thread. UI work may run off the paint thread,
but SDK access remains on the operator's stopped LLDB command thread. No path reported by LLDB is automatically
opened as a static image.

## Resolve and navigate to the matching static image

Open the original static Mach-O yourself. Select its module UUID, enter its **File virtual address**, not a file
byte offset or runtime load address, and click **Resolve selected file address**. A successful qualified result
can offer **Go to matching static image address**. Only that separate click navigates the already-open static
image through ordinary local history; resolution never navigates automatically or queries LLDB again on Go to.

The action requires matching request/token, exact 16-byte Mach-O UUID, supported architecture/variant, address
width, object byte order, typed section ancestry and readable mapping evidence. The static destination requires
available readable file-backed bytes. Unsupported identities, owned snapshots, missing evidence or mismatches
leave the observation raw-only. Inspection and guarded static resolution can remain useful when capture is not
supported, including ARM64 observations whose runtime DATA order is unknown.

Source-descriptor and pathname metadata are checked without reading mapped headers/bytes during painting;
navigation revalidates at the click. Input/template edits, rejected input, new queries, clearing, window closure
and workspace replacement invalidate the action, including late replies. A UUID match is not proof of equal
runtime/static bytes, the current stop, authentic process identity, control flow or object layout.

## Prepare a bounded capture

The client-local capture path supports ordinary little-endian x86-64 Darwin Mach-O executables, dylibs and
bundles only, with an exact UUID match to the retained original static project. It requires an ordinary Apple
x86-64 runtime triple, eight-byte addresses and affirmatively known little-endian runtime DATA order.
Encrypted images, unsupported CPU subtypes and unknown or conflicting context refuse. ARM64 runtime DATA order
remains unknown in the query protocol, so this capture composition refuses it; raw inspection remains available.

This is narrower than the existing standalone [LLDB snapshot exporter](runtime-snapshots.md#export-from-lldb),
which separately supports its documented ARM64, ARM32 and x86-64 captures. The new workspace path does not remove
or replace that support, and it does not add a server, CLI or MCP capture operation.

With the original static image still open:

1. Explicitly connect/refresh, list and select the matching module and one thread.
2. Enter a **File virtual address**, a size from 1 to 4,096 bytes and exact readable runtime mapping permissions
   (`r--`, `rw-`, `r-x` or `rwx`). The runtime-load-address field is for raw inspection, not capture selection.
3. Click **Prepare capture preview (9 queries)**. This authorizes exactly one bounded composition, not Save.
4. Review the module/thread, file/load addresses, byte count, permissions, historical token, bytes SHA-256,
   document SHA-256 and limitations before choosing further actions.

The whole static range must fit one readable, unambiguous file-backed mapping without contradictory section
backing. The runtime range must fit the one observed SDK leaf, every reported ancestor and one known-readable
mapping with exactly the requested permissions. UUID/header bases and file/load arithmetic must agree.
The selected thread must have current top-frame stop evidence and complete `rip`, `rsp`, `rflags` registers;
PC/SP must agree with those register values. Missing, partial or contradictory evidence is refused.

Prepare uses the unchanged `rampage-lldb-query-v1` operations in this fixed order:

1. `describe_session` with the retained expected token;
2. `list_modules`, exactly the selected module index with `limit=1`;
3. `resolve_module_address`, selected UUID and file virtual address;
4. `read_registers`, selected thread and exactly `rip`, `rsp`, `rflags`;
5. `read_memory`, the resolved load address, selected thread, size and exact permissions;
6. `read_registers` again;
7. `resolve_module_address` again;
8. `list_modules` again;
9. `describe_session` again.

All nine carry the same expected token and share one absolute composition deadline, 3,000 ms in the UI.
Each requests at most 65,536 response bytes. Repeated data and observation envelopes must agree; refusals stop
the sequence without retries or token refresh. Backing-source checks bracket preparation and validate the
selected-image digest again before returning the preview. These are checks, not forcibly interruptible SDK calls.

Prepare performs semantic snapshot loading over owned document bytes, with a 1 MiB document cap and **no file
writes or filesystem staging**. The result has one region/module, three registers, Darwin platform context,
unknown/omitted compiler, null entry and empty seeds. Register PC does not become an entry, function seed or
automatic navigation request. The same original `Arc<Project>` is retained for subsequent actions; a serialized
summary or a copied hash cannot replace that process-local authority.

## Compare prepared bytes with the original

Click **Compare prepared capture with original** to compare the prepared runtime range with that same retained
original image. The result shows equal, changed and unavailable byte counts and address-qualified spans. This
does not query LLDB, refresh a stop or compare a subsequently saved pathname. It remains a prepared-observation
comparison even if Save has already happened.

Compare rechecks source identity/digest and physical backing. UUID/header correlation alone never asserts byte
equality. LLDB `ReadMemory` may normalize inserted software-breakpoint trap bytes; the captured bytes are not a
guaranteed literal view of breakpoint-patched physical process memory.

## Save historical observations locally

Enter an explicit absolute output pathname in a preexisting same-user **0700** directory, without symlinked,
empty, dot or parent components. Click **Save prepared capture**. Save is separate from Prepare and Compare;
it contacts no debugger, imports no annotations and leaves the original workspace open.

Save writes a private **0600** staging file, syncs and checks its content, then atomically publishes the complete
file with a no-clobber hard link. Existing destinations, including symlinks, are refused, never replaced. Source
and namespace checks remain required. Filesystem publication and directory validation require Unix support.
An authorized Save may finish after a form change or window closure; it must not silently become an Open action.

Staging pathnames are intentionally retained, on success and on failures that created them. The UI/API expose
retained paths and warnings for explicit operator inspection and cleanup. Holding a descriptor does not give
authority to unlink a later pathname occupant: a same-user process could replace the name. No automatic unlink,
chmod, overwrite or cleanup is attempted. Treat every retained file as sensitive capture data; inspect the
current occupant before choosing manual cleanup. Prepare itself has no retained staging paths.

A receipt has either `Published` or `PublishedUncertain` status:

- `Published` means publication and required post-link checks succeeded, not continuing immutability or a
  current-source guarantee.
- `PublishedUncertain` means output may exist or a post-publication check failed. The UI retains the destination,
  expected document hash, warnings and staging paths. It does not report ordinary success, authorize Open,
  retry the same recorded publication destination, overwrite it or remove anything. Inspect explicitly instead.

An ordinary failure can also report retained staging without a published destination. Do not infer absence of
sensitive files from a failed Save. Private permissions restrict other users, not same-user namespace replacement
or endpoint impersonation. A publication receipt is display evidence, not authority to delete a pathname.

## Open the saved snapshot separately

After a current preview has both a successful explicit Compare and a `Published` Save, click **Open saved
snapshot**. Equal comparison bytes are not required. Finish or cancel any unsaved annotation editor first.
Save alone never replaces the original workspace, and uncertain publication cannot enable this action.

Open validates the original workspace instance, project, selected image/path and physical source again. It reads
the explicitly saved same-user regular 0600 file through a bounded, no-symlink, identity-checked reader in the
private parent, verifies the expected document SHA-256, and opens through the ordinary session path. The actual
snapshot document bytes returned by that session must equal the verified bytes before workspace replacement;
format or digest checks on a separate temporary read are not sufficient. Refusal leaves the original workspace
open. Successful replacement invalidates debugger actions rather than carrying them into the snapshot workspace.

Socket, form, stop-epoch, source/workspace and output bindings reject obsolete completions or clicks. Changing
the capture form invalidates its prepared preview, comparison and opening authority; changing the output
invalidates the saved-output binding. Closing/replacing the workspace or window also invalidates follow-ups.
There is no automatic recovery sequence; use explicit Refresh and Prepare when the UI requires new evidence.
Already-authorized Save resource notices remain visible even if their opening authority became obsolete.

## API surface and limits

`prepare_debugger_capture` takes the original `Arc<Project>`, explicit socket, `DebuggerCaptureRequest`, timeout
and cancellation flag, returning an immutable `DebuggerCapturePreview`. The request contains `expected_token`,
`module_index`, `module_uuid`, `thread_id`, `file_address`, `size` and `permissions`. The preview exposes
`summary()`, `source_project()`, `compare_original()` and `publish(output)`. No serialized summary authorizes
publication or opening. `read_debugger_capture_publication(path, document_sha256)` validates publication bytes;
callers must separately enforce current workspace/source bindings and semantic opening checks.

These observations are historical and **non-atomic**. Nine matching token-bound queries do not prove a coherent
point-in-time snapshot, process authenticity, full intersecting-section coverage, control flow, C++ layout or
runtime/static byte equality. Metadata checks cannot make mapped reads atomic with external writes/truncation;
keep original images and debugger activity quiescent. Timeouts/cancellation cannot prove SDK work has stopped.

There are no launch, attach, resume, step, breakpoint, expression-evaluation or target-write controls. No arbitrary
debugger commands are accepted. Snapshot analysis after an explicit Open uses the existing local analysis and
annotation interfaces; opening does not execute a target or import proven types/layouts from register values.

## Acceptance boundary

API/UI capture tests use owned fixture images and controlled LLDB protocol responses. Local acceptance includes
21 capture API integration cases, the ordinary UI suite and unchanged offscreen snapshots, including actual
App-control Prepare and explicit Save/Open failure paths. The debug workspace suites passed in bounded package
slices, and all-target Clippy passed. A new live end-to-end workspace Prepare/Compare/Save/Open gate is not yet
earned. The opt-in owned x86-64 live test compiled and LLDB loaded its Mach-O, but Apple LLDB
`2103.0.34.103` could not launch it on the local arm64 host: `Bad CPU type in executable`. The failure occurred
before UI/bridge observations, so it is not a live workspace pass. No Rosetta installation, ASLR disabling or
ARM64 data-order assumption was used to bypass that blocker.

The opt-in runner compiles only its owned plain-C fixture and uses real offscreen App controls; its Rust test is
ignored by default. Successful completion must check 15 bridge operations, unchanged stopped identity and explicit
publication/opening. Earlier controlled live query-bridge and standalone-exporter gates cover those separate
interfaces, not this new composition. No latency, arbitrary-host or broader-architecture acceptance is implied.
