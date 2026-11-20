# Desktop UI: inspect and assess (2026-11-20)

Status: agreed in outline on 2026-11-20, not started. It is queued behind the functionality tracks in
[todo.md](../../todo.md): analysis features come first, and these slices follow.

## Role

rampage is used through AI, so the MCP server is the product and the desktop UI is not a second way to do the
analyst's work. Its role is narrower: let a person open a binary and quickly see what it is, what it can do, where
to start reading, and what an agent has established about it. It is a viewer of results the API already produces.

The UI is not an interactive debugger, a type or struct editor, or a patch editor. Those stay with the agent
through MCP.

## What is good enough and is wrapped

"Wrapped" means the code stays, its tests stay green and bugs get fixed, but it gets no new features. All of it
remains experimental under the [stability policy](../stability.md).

| Area | State |
| --- | --- |
| Functions, strings, imports and exports lists with filters | Wrapped. |
| Disassembly listing, hex view, clickable references, navigation band, go-to, history | Wrapped. |
| Control-flow graph | Wrapped. |
| Pseudocode with address-linked tokens and recovery issues | Wrapped. |
| Cross-references pane | Wrapped. |
| Rename, comment, undo and redo over the shared annotation log | Wrapped. No further editing features. |
| Carve candidates and opening an embedded executable | Wrapped as it is; extended by slice 4 below. |
| Project workspaces, module references, exact-entry decompilation | Wrapped. |
| Read-only LLDB query window and capture preview | Wrapped. No execution control is added to the UI; `debug_*` stays MCP-only. |
| Assistant tab | Wrapped. It keeps its current tool set. |

The debugger window and the workspace machinery are about half of the crate. They are kept because they work and
are documented, not because the UI is heading that way.

## What is missing for inspection

Seen in the current build:

- The Triage tab shows hashes, format facts, an entropy chart and sections. It shows nothing from detection
  (packer, compiler, protector), encrypted or packed regions, library identification, capabilities, or the guided
  reports (`triage_report`, `find_main`, `network_surface`, `persistence_surface`, `privacy_surface`,
  `find_crypto`, `lock_mechanisms`).
- The findings ledger cannot be read in the UI. A person cannot see what an agent established, what it marked
  unknown, or its open questions, although that is the record beside the binary.
- A file with no executable header gets the carve list only: no file layout, no filesystem listing, no Raw
  project, no APK summary.

## Slices

Each slice is small, renders API results without new analysis in `rampage-ui`, runs as a background job, and adds
an offscreen snapshot test. If a result is awkward to display, fix its shape in `rampage-api` so MCP gets the same
improvement.

1. **Assessment tab.** Replaces Triage as the tab shown on open. One page, top to bottom: what the file is (format,
   architecture, compiler and packer detection, signing); whether code is encrypted or packed, with the regions;
   library identification as counts per library and source; capability tags grouped by area; the entry and
   `find_main` result as "start here" links; then the current hashes, entropy and sections. Every row that names
   an address navigates to it.
2. **Surfaces.** Network, persistence, privacy, crypto and lock mechanisms as collapsible sections of the
   Assessment tab. Each runs only on request, never automatically, because they cost more than triage. Rows show
   evidence and confidence and link to the function. Limits and "left out" counts from the report stay visible.
3. **Agent work.** A Findings tab listing the ledger (established, unknown, open questions) with evidence links and
   confidence, filterable by kind.
4. **Files that are not executables.** For a file that does not open as a binary: `file_layout` as a map (padding,
   entropy, string clusters, labelled hints), carve candidates as now, and `fs_list` as a tree for filesystem
   images and archives, with opening a contained executable as its own project. An APK shows the `dex_metadata`
   summary (permissions, components, native libraries). Raw firmware projects with their starting points come
   last, since they need a selector the UI has no form for.
5. **Export.** Save the assessment as Markdown or JSON, the same content as `rampage workflow run triage-report`,
   so a person can attach it to a ticket.

## Acceptance

A person who opens an unfamiliar binary can answer these within a minute, without typing a query: what it is,
whether it is packed, which libraries it contains, what it can do, where to start reading, and what an agent has
already found. Checked on three owned fixtures: a stripped C++ ELF, a UPX-packed binary, and a binary with a
populated findings ledger.

## Decided (2026-11-20)

- Surfaces run on request only.
- Name provenance (symbol, signature, agent or person) is not part of this plan; it is an unprioritised idea in
  todo.md.
- This work comes after the functionality tracks, one slice at a time.
