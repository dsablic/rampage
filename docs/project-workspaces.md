# Project workspace reference

A desktop **Project workspace** retains up to eight explicitly selected modules. Its local manifest records
sources, identity, image selectors, decompiler option selection and qualified navigation; it is not an analysis
cache, source archive, dependency resolver or debugger connection. These controls are API/UI only: no workspace
CLI commands or MCP tools are added.

## Retained modules and qualified navigation

Right-click **rampage**, then choose **Project workspace…**. **Add module…** opens a deferred module and
**Add module for exact-entry…** additionally shows the [exact-entry controls](exact-entry-ui.md). Both use
**Full source path** and **Open selected path**. Neither starts global analysis or carves candidates.

Selecting a module in the window or top-bar selector retains the actual Workspace, not a reconstruction from a
pathname. Each keeps its Project, annotations, filters, cursor/history and unsaved annotation editor, including
editor-local state. Switching does not reopen the source or copy code, names or types to another module, even
when basenames and virtual addresses coincide. In-flight exact-entry/debugger authority is invalidated on a
switch. **Close <module ID>** refuses an unsaved editor in that module; **Close workspace** and replacement
require every module's editor to be finished or cancelled. Adding and switching can retain unfinished editors.

Module IDs are stable opaque identifiers, preserved by manifest save/restore. Labels and basenames are not join
keys. **Navigation module ID**, **Navigation hex address** and **Go to module address** explicitly select one
module and navigate its image virtual address. Names do not resolve across modules. Serialized addresses pair
`module_id` with `address`, a canonical lowercase `0x`-prefixed hexadecimal string within 64 bits, not a JSON
number; for example, `{"module_id":"module-a","address":"0xffffffffffffffff"}`.

The same canonical source, architecture and image selection cannot be added twice. Explicit architecture/image
selection is available through the API. For an ordinary bundle opened through native source resolution, the
saved source is its resolved executable file, not the bundle directory. There is no dependency discovery, nested
extraction, cross-module call-graph/xref construction, symbol guessing or serialized analysis cache.
The separate [module references](module-references.md) window queries explicit PE import/export declarations among
loaded modules; it is not runtime binding or dependency discovery.

## Save, preview and explicitly open

**Save workspace…** asks for **Workspace output path**; **Save workspace file** captures and publishes a
manifest without replacing the current modules. Finish or cancel all unsaved editors first. Annotations must
already match their recognized persistent local logs; in-memory-only analyst edits cannot be embedded as a
substitute. Save checks that every source and snapshot profile can be restored under the checked loader limits.

**Preview workspace file…** asks for **Workspace manifest path**; **Preview workspace file** reads only that
manifest. It does not stat, canonicalize or open any listed module source or annotation log. The review displays
module IDs/labels, paths, source/image hashes, architecture/format, selectors, options, cursor and snapshot
annotation-context digests, plus the recognized-log policy. A parsed or serialized manifest is not approval.

Only **Open reviewed workspace** approves opening the listed sources and recognized local annotation logs.
The opaque process-local preview binds the exact manifest descriptor and document digest. Unknown fields,
duplicate fields, unsupported policy/version or invalid identities refuse. Ordinary logs derive from source,
architecture and image selection. Snapshot logs derive from validated capture identity in the current Session's
capture-annotation directory, or the canonical source parent. Checked ingestion is bounded and does not create
missing logs. No manifest-supplied log path is accepted.

Snapshots record an annotation-directory context digest, not the raw directory. Restoring a custom context
requires the same current Session directory context; changed settings or directory identity refuse. The loaded
Session retains current process-local packs and capture-annotation directory settings, rather than importing
them from the manifest.

Reviewed Open stages every module in a fresh Session and validates sources, hashes, image/capture/document
identities, checked logs and option selections before adoption. The UI constructs all candidate Workspaces from
the exact validated loaded Project Arcs, without reopening their paths. Failure at any module, including a later
missing/changed source, malformed log, changed annotation settings, descriptor/path replacement or digest mismatch,
leaves the entire old bank, all editors and all navigation histories intact. Changes to the current bank since
preview invalidate the review, even when switching away and back.

Every restored module starts deferred. Loading eight modules does not automatically launch eight global
analyses. **Start global analysis** remains an explicit per-module action with the existing analysis costs;
this is not a global runtime budget guarantee.

## Background file operations and cancellation

Ordinary desktop **Save workspace file**, **Preview workspace file** and **Open reviewed workspace** dispatch
background jobs. Save does not automatically Preview, Preview does not automatically Open, and no completion
silently chains another operation. The UI captures bounded metadata and navigation, checking each history's
256-entry limit before cloning it. Whole-source hashes, module loading, manifest/log reads and publication run
off the UI thread. Adoption still performs small descriptor/path, annotation-context and configuration metadata
checks on the UI thread; these are not whole-source rehashes.

One App-wide workspace-file execution lease covers Save, Preview and reviewed Open. **Cancel workspace operation**
requests cancellation without releasing that lease. A bank change, replacement or close cannot admit a second
file job before the first actually returns. Closing the Project workspace review window cancels Preview/Open and
clears review authority, but does not cancel Save. Publication notices survive those changes.

The task strip shows observed backend phases, module ID/counts and elapsed milliseconds, not a fabricated
percentage or completion-time estimate. Workspace phases include `CapturingInputs`, `ReadingManifest`,
`PreflightingSources`, `LoadingModule`, `ValidatingIdentity`, `ReadingAnnotations`, `PreparingDocument`, `Publishing`,
`PublicationStaged` and `ResultValidation`. `PublicationStaged` is emitted before the no-clobber hard-link commit;
`ResultValidation` can occur after commit. A phase is an observation, not proof that no later work can fail.

Cancellation is cooperative between phases, modules and hash chunks. It does not forcibly interrupt a regular-file
filesystem syscall and supplies no hard wall-clock bound. Cancellation before publication can refuse the write;
after commit, failed/cancelled result validation returns a `PublishedUncertain` publication rather than hiding a
possibly existing file behind an ordinary error. Own-resource receipts and retained paths are recorded before
stale-binding or cancellation checks, even when the result cannot be adopted.

Save takes a bounded detached annotation snapshot under the read guard, then releases that guard before log I/O
or further whole-source hashing. Final configuration and process-local annotation revision/nonce checks reject
intervening edits, including change-and-change-back. These process-local guards are not serialized consent.
The review/job binding also checks module instances, navigation, settings and editor state; cancellation or a
stale binding discards Preview/Open candidates without replacing the old bank.

The public synchronous `App` capture/Save/Preview/Open methods remain for programmatic compatibility. GUI buttons
use the background `begin_workspace_*` path; `App::blocking` intentionally executes jobs inline for tests. This
does not move every filesystem access out of painting: ordinary annotation-refresh polling remains, and metadata
checks can still perform filesystem operations. No general frame-time or all-I/O-asynchronous guarantee follows.

## Manifest fields and admission limits

Version 1 stores the active module ID, modules and annotation policy `recognized_local_logs_checked`.
Each module stores its ID, label, absolute source path, optional offset/length selector, source/image identity,
optional snapshot capture/document identity and annotation-context digest, navigation and optional decompiler
options. `options: null` retains automatic selection; an explicit options object remains distinct even when its
values are defaults. Platform, compiler and ARM BE8 selections are preserved, not certified ABI-correct.
Specification compatibility is validated when the native engine actually uses the selection.

| Admission budget | Limit |
| --- | --- |
| UTF-8 manifest | 256 KiB |
| Manifest nesting / structural work | Depth 8 / 32,768 units |
| Modules | 1–8 |
| Opaque module ID | 1–64 ASCII bytes |
| Label | 1–256 UTF-8 bytes, no NUL |
| Absolute source path | 4,096 UTF-8 bytes; no empty, dot, parent or NUL components |
| Back / forward history | 256 qualified addresses per direction, per module |
| Source file / aggregate source files | 128 MiB / 256 MiB |
| Checked snapshot raw document / raw string | 16 MiB / 1 MiB |
| Checked snapshot nesting / items in any array | Depth 8 / 4,096 |
| Checked snapshot structural work | 65,536 units |

The checked snapshot raw profile is enforced before copying or serde deserialization, in addition to semantic
snapshot validation. Legacy snapshot loading is unchanged and can admit documents outside this profile; workspace
Save refuses those documents rather than publishing a workspace it cannot restore. Input sources must be bounded
regular files, not symlinks, directories or devices. Descriptor and pathname checks do not make concurrent mapped
reads atomic: keep sources quiescent.

## Local publication and privacy

The manifest contains sensitive source paths and navigation, but does not serialize worker settings, sockets,
session tokens, pack directories, private keys, raw capture bytes, derived code or analysis caches. It refers to
local source files, so moving the manifest alone does not make a portable project bundle.

Save requires an explicit new absolute destination in a preexisting same-user **0700** parent, with no symlinked
or empty/dot/parent components. It creates a private **0600** staging file and atomically publishes without
overwriting an existing destination. Unix checked-file/publication support is required. Staging resources are
intentionally retained for explicit operator inspection; failures can also leave sensitive retained resources.

**Workspace publication notices (retained across module changes)** exposes publication status, hashes, warnings
and retained staging paths. `PublishedUncertain` means the destination may exist; it is not ordinary success,
Open authorization, authority to retry the same publication or deletion authority. Even `Published` is not
continuing immutability or approval to open: Preview and reviewed Open remain separate explicit actions.
Retained staging resources or uncertain publications block further workspace publication pending explicit
inspection. No automatic unlink, overwrite or cleanup is authorized by a receipt. Inspect the current pathname occupant
before manual cleanup. Private permissions do not prevent same-user namespace replacement.
