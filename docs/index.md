# Documentation

rampage's documentation, grouped by what you want to do. Start with the [README](../README.md) for what rampage
is, then the [tutorial](getting-started.md).

## Tutorial

- [Getting started](getting-started.md): install rampage, connect it to an MCP client, and run a first
  investigation on a committed fixture.

## How-to guides

- [Read the code in a firmware update file](firmware-walkthrough.md): from a vendor container to a compressed
  Cortex-M image opened at its load address, with startup copies mapped, decompiled and its checksums checked.
- [Check a claim about a binary](claim-checking.md): verify, refute or leave unknown what an agent states about
  a function, a call, a reference, a checksum or a layout, with evidence and a counterexample (*experimental*).
- [Compare two versions of a firmware update](firmware-diffing.md): what an update changes, from container
  layout and partitions to files, functions, endpoints, lock mechanisms and integrity checks (*experimental*).
- [Analyse headerless code as a Raw project](raw-code.md): choose a base address, open a compressed image, map
  further regions, scatter-load copies and pointer tables, open
  [MIPS boot ROMs](raw-code.md#mips-boot-roms-and-bare-metal-mips) and
  [ESP32/ESP8266 app images and flash dumps](raw-code.md#esp32-and-esp8266-firmware) (*experimental*), and which
  tools take a `raw` selector.
- [Check what a device records and where it sends it](device-privacy-check.md): unpack an update, list its
  endpoints, write a router blocklist and find capture-to-send paths in its programs and apps, and what starts each
  at boot.
- [Debug a live target](debug-control.md): allow a GDB remote stub, `debugserver` or a Windows stub, then inspect
  and control it through the `debug` tools. Also the reference for those tools.
- [Analyse a captured runtime image](runtime-snapshots.md): export a snapshot from LLDB and open it in rampage.
- [Use the read-only debugger workspace](debugger-workspace.md) in the desktop UI.
- [Analyse several slices and functions in one report](cli-analysis.md) with `binary analyze`.
- [Run the heuristic flywheel](flywheel.md): build the corpus, gate candidates, export and bundle promotions
  (*experimental*).
- [Build and validate without large caches](development.md): build profiles, tests and worktree cleanup, for
  contributors. See also [CONTRIBUTING](../CONTRIBUTING.md).

## Reference

Overviews:

- [Feature overview](features.md): every capability area, its limits and where its reference is.
- [MCP reference](mcp.md): connecting clients, server options, the tool catalog, paging, edits and data
  disclosure.
- [CLI reference](cli-reference.md): every command, its compatibility spelling, global options and addresses.
- [Stability policy](stability.md): what is stable in 1.x and what is experimental.
- [Known limits](known-limits.md): supported hosts, the decompiler worker, and what rampage does not do yet.
- [Changelog](../CHANGELOG.md).

Analysis and decompilation:

- [Search](search.md), [tool views and annotation batches](tool-views.md).
- [Build matching and annotation transfer](build-diffing.md) between versions of a program.
- [Objective-C message sends](objc-dispatch.md) resolved to the methods they reach.
- [Exact-entry analysis](entry-analysis.md) and its [desktop window](exact-entry-ui.md).
- [ARM ELF unwind candidates](arm-unwind-starts.md).
- [Decompiler reference](../crates/rampage-decompiler/README.md): compiler models, worker supervision and
  diagnostics.
- [Persistent analysis store](mcp.md#persistent-analysis-store): stored discovery and decompilations, their keys,
  invalidation after edits, and `rampage server store` (*experimental*).

Typing:

- [Local variables and parameters](local-variables.md), [project type library](type-library.md),
  [data and operand typing](data-types.md), [function frames](function-frame.md),
  [type propagation](type-propagation.md).
- [Checked debug-type import](debug-types.md), [checked DWARF layout import](debug-layout-import.md),
  [embedded debug signatures](debug-signatures.md), [PDB function names](pdb-symbols.md).

Patching:

- [Checked byte patches and export](patching.md) and the [assembler](assembly.md).
- [Firmware patching round trip](firmware-patching.md): integrity checks (CRCs, checksums) found, fixed after
  patching, and the image exported as Intel HEX, S-records or binary.
- [Lock mechanisms](lock-mechanisms.md): signature checks, parts pairing, anti-rollback counters, debug locks and
  other repair blockers explained (experimental).

Formats and raw code:

- [File layout](file-layout.md): regions, padding, entropy, string clusters and hashes of any file.
- [CMSIS-SVD peripheral maps](peripheral-maps.md): register names in decompiled C, disassembly, xrefs and
  evaluation of firmware.
- [Raw projects in MCP](mcp.md#raw-projects): the `raw` selector, regions, decoded and copied regions,
  scatter-load, pointer tables and load-address candidates.
- [Raw-code windows](raw-code.md#raw-code-windows), [explicit Sleigh decoding and Raw Projects](sleigh-decoding.md),
  [explicit content decoding](decoding.md) (including `write_decoded_range` and `probe_compression`),
  [native data inspection](data-inspection.md), [ZIP32 inventory](archive-inventory.md).
- [Object files and static libraries](object-files.md): ELF `.o` files laid out with relocations applied, externs
  named, and `ar` library members opened as `lib.a(member.o)`.
- [Firmware filesystem images](firmware-images.md): list and extract SquashFS, ext2/3/4, UBI and UBIFS, Android
  sparse and OTA payload, cpio, tar and ZIP (APK) images safely.
- [Endpoint inventory and blocklists](endpoint-inventory.md): the hosts, URLs, IPs, pins and certificates a binary or
  firmware tree names, grouped by domain, and a router blocklist of them.
- [Privacy surface](privacy-surface.md): what a program, an APK or an extracted firmware tree can capture
  (microphone, camera, screen, input), where it can send it, the call paths between, what starts each capture
  (including init services at boot), and whether capture starts without a user-facing trigger.
- [Android APKs and DEX](android.md): an APK's manifest, permissions with protection levels, components and
  start-at-boot receivers, native libraries with JNI exports, DEX classes and methods, Dalvik bytecode and
  pseudocode, the capture APIs the code invokes, and strings hidden behind decoder methods.
- [File formats](file-formats.md): Go and Rust build info, PyInstaller archives, WebAssembly modules, PE resources
  and load config, MSVC C++ metadata (vftables and exception tables), and .NET metadata.

Library identification, detection and data packs:

- [Data packs](data-packs.md): manifests, precedence, `.rpack` export and import, constant tables.
- [Signature corpus](signature-corpus.md), [signature input formats](signature-imports.md),
  [fuzzy candidates](fuzzy-signatures.md), [capability indicators](capabilities.md).

Debugging and runtime evidence:

- [Read-only LLDB query protocol](lldb-query.md).

Desktop UI (*experimental*):

- [Desktop UI](desktop-ui.md), [project workspaces](project-workspaces.md),
  [module references](module-references.md), [historical function inventory cache](function-inventory-cache.md).

Plugins (*experimental*):

- [Plugins and extension points](plugins.md) and [plugin security boundaries](plugin-security.md).

Measurement tools:

- [Parity scorecard](parity-scorecard.md), [decompiler corpus runner](decompiler-corpus.md),
  [C++ virtual corpus](cpp-virtual-corpus.md), [exact-entry measurements](entry-measurements.md),
  [worker observations](worker-observations.md).

## Explanation

- [Comparison with Ghidra, IDA and REA](comparison.md): what differs for agent-driven work, what has been
  measured and what rampage does not do.
- [Accuracy benchmarks](benchmarks.md): the head-to-head agent runs and static comparisons with Ghidra, with
  their methods and limits.
- [Deep ARM64 analysis](arm64-development.md): how semantics, conventions and SSA are separated and validated.
- [Runtime data order and ARM64 evidence](runtime-data-order.md): why architecture and runtime byte order are
  kept apart.

## Internal planning (for contributors)

These pages are the project's own working notes: plans, milestones and the open-work list. They are not needed to
use rampage.

- [IDA/Ghidra parity roadmap](plans/2026-10-16-ida-ghidra-parity-roadmap.md): the current plan and status.
- [Debugger design](plans/2026-10-29-debugger-control.md) and [Windows debugger design](plans/2026-11-05-debugger-windows.md).
- [Flywheel fast loop](plans/2026-11-05-flywheel-fast-loop.md) and the
  [flywheel strategy](plans/2026-10-12-heuristic-self-improvement-flywheel.md).
- [Roadmap refresh](plans/2026-11-20-roadmap-refresh.md) (planning rules and the proposed queue),
  [how to proceed with the flywheel](plans/2026-11-20-flywheel-next.md) and the
  [desktop UI plan](plans/2026-11-20-ui-inspection.md), and the
  [acceptance set](plans/2026-11-20-acceptance-set.md) for the 1.6–1.8 features.
- [Open work](../todo.md) and the [archive of done items](plans/todo-archive.md).
- Older plans in [docs/plans](plans/) are marked historical at the top.
