# Desktop exact-entry reference

The **Exact-entry decompilation** window runs one explicit request at the current image virtual address.
It uses the [exact-entry API](entry-analysis.md), not the ordinary automatic **Pseudocode** path. Bounded local
context and rendered C do not establish a recovered or verified function boundary.

## Open and run

Right-click the **rampage** brand and choose **Open for exact-entry…**. Enter **Full source path**, then click
**Open selected path**. This replaces the module bank only when every unsaved module editor is finished or
cancelled. It opens the selected source through the same Session, retaining its annotations, packs and configured
decompiler options, without starting or requiring global analysis. It does not carve candidate images.

The Session can return an already-cached Project: this route does not promise a pristine discovery history or
that global image work has never occurred. With a fresh Project, opening, navigation and painting deferred panels
do not require Program discovery, functions, strings, triage, an analysis-backed listing or xrefs. The deferred
disassembly view can display mapped bytes. Metadata imports/exports remain available.

For an already-open module, the brand menu's **Exact-entry decompilation…** opens the same controls. Disassembly
context menus include the current address, for example **Exact entry at current cursor 0x1000...**;
Pseudocode and deferred-view buttons use
**Exact entry at current cursor...**. These actions open controls, not an execution. Right-clicking a listing row
does not select that row as a new entry: the request uses the displayed **Current cursor**.

**Entry validation** defaults to **Metadata-backed**. This requires an exact metadata declaration and still
checks code/backing eligibility. Choose **Analyst-asserted** explicitly to assert the exact address without that
declaration; it does not bypass mapping, architecture, alignment or known-data checks. There is no automatic
policy fallback and no snapping to a containing function.

Only **Run** submits a request. Navigation, tab selection and reopening the window do not run it. **Start global
analysis** is a separate action for the active module; it is not needed for exact-entry execution. Outside
deferred mode, ordinary file open and automatic Pseudocode behave as usual. These controls do not change CLI or
MCP decompilation flags or tool names.

## Progress, cancellation and stale results

The window displays **Last observed phase** and elapsed milliseconds from actual host-side API callbacks.
Phases cover configuration, metadata, replay, mapping, worker serialization/execution or native initialization,
replay/execution, and result validation. These are coarse phase boundaries, not percentages or continuous native
engine progress. The API callback runs on the calling thread outside Project locks; observer time counts toward
the worker deadline.

**Cancel**, Escape and window closure invalidate the displayed request and request cooperative cancellation.
An active native FFI call cannot be forcibly interrupted. One App-wide exact-entry permit remains held until the
executing task returns, even after closing the window, changing modules or replacing the workspace. Invalidating
a receiver does not authorize overlapping exact-entry work. Worker supervision retains its own timeout and
cleanup limits; cancellation is not a hard end-to-end interruption guarantee.

Results, errors and progress from obsolete requests are discarded. Bindings include request identity, workspace
activation, Project identity, cursor, validation policy, annotation epoch, decompiler configuration revision and
available backing source. Changing away and back does not revive an old request, including configuration ABA
changes. Edits, annotation refreshes and module switches can require a fresh explicit Run.

## Result evidence

The result shows the exact address, language and native recovery status. **Native recovery diagnostics and
warnings** retains engine diagnostics separately from **Exact-entry context, backing, budgets, typed entry sample
and omissions**. The latter exposes full-image mapping/backing evidence, context/replay counts, timing, budget
exhaustion, local diagnostic samples and host omissions. Host context omissions are not native engine warnings;
neither successful preparation nor a locally plausible sample verifies a complete function.

Exact-entry execution still pays for bounded metadata, mapping, hashing, required declaration replay and native
work. Deferred opening is not a latency guarantee or a claim that the native engine sees only a cropped window.
See [exact-entry limits](entry-analysis.md#supported-inputs-and-mapping) and
[project workspaces](project-workspaces.md) for retained modules and reviewed persistence.
