# To do

## Status (2026-11-13)

- Release: 1.0.0-rc.1 (2026-11-06) and rc.2 (2026-11-09) are published as pre-releases; there is no rc.3, and
  1.0.0 is tagged next from `main` (its changelog section is ready to date). Contract snapshots pin every stable
  MCP group; everything since rc.2 changed them only additively. Linux ARM64 host support shipped in rc.1
  (archived).
- Parity roadmap: Phases 0–3 and 4.1 implemented; live Phase 1 sign-off, the Phase 2 recall target and the
  Phase 3.3 live improvement gate are open. 4.2 done for Cortex-M (experimental: vector and pointer tables,
  multi-region, HEX/SREC). Phase 5 partial (MSVC C++ metadata, Objective-C sends, Go runtime types, DWARF lookup).
  Phase 6: persistent analysis store (6.2, first half) and search at scale done. Phase 7 (annotation transfer)
  done. 4.3, the rest of Phase 5, 6.1/6.3 and Phase 8 are open.
- Debugger (Phase 9): 9.1–9.5 done (9.5's live macOS `debugserver` acceptance passed 2026-11-11); 9.6a (Windows through
  RSP stubs) implemented, live acceptance pending (experimental in 1.0). See `docs/plans/2026-10-29-debugger-control.md`.
  Cortex-M flash dump (`debug_snapshot` `raw: true`) live-verified on QEMU 2026-11-14; OpenOCD/pyOCD/J-Link on
  real probes not yet run (flash `Z0` behaviour, FPB comparator exhaustion, read-protected parts).
- REA gap-closing wave 1 (2026-10-29): `formats` tools and the findings ledger done; log compaction open.
- Head-to-head with REA: suite v1 and suite v2 published (`docs/benchmarks/`); follow-ups below. Suite v3
  (tasks where Ghidra is strong) is built in `tests/fixtures/bench-v3`, and a Haiku development pass drove the
  follow-ups below; its published run and report will follow. A second model or client is not run yet.
  Suite v4 (the post-1.0 features plus four v3 tasks) is built, not run: `docs/plans/agent-bench-v4.md`, with
  fairness calls to confirm and six rampage gaps its validation found (address-0 emulation, a missed CRC-16).
- Flywheel fast loop (`docs/plans/2026-11-05-flywheel-fast-loop.md`): the deterministic arm (exact rows, operand
  wildcarding) and call-graph propagation ship in the bundled databases; fuzzy matching failed the final split on
  both corpora and stays suggestion-only. The AI proposer has made no promotion a deterministic generator could
  not; whether it proposes code next (`docs/plans/2026-11-08-flywheel-code-candidates.md`, steps 2–4) is
  undecided. Open: an arm rule for rows that match another library's body (fixed by name for now); regenerating
  the bundled hash databases with callee keys for forwarders (needs the signature-corpus caches).

This file holds open items. Done sections, including every completed parity phase, are archived verbatim in
[docs/plans/todo-archive.md](docs/plans/todo-archive.md); each section below that lost done items links to them.

## Ideas to review (unprioritised, not approved)

Ideas collected while working, to go through together before any becomes a track. The repo stays general: it
explains mechanisms and lets owners inspect and change their own devices. It holds no product-specific bypasses.

### Privacy: what a smart device records and where it sends it (2026-11-14)

Work from representative samples across device categories, not one device. Pick one or two samples per category
where the vendor publishes updates for download. They are local workloads only, never committed and never named
in the repo.

| Category | Typical firmware | Processor | Main concern | What it tests |
| --- | --- | --- | --- | --- |
| Smart TV / streaming stick | Android TV or embedded Linux in a vendor container | ARM64/ARM32 | screen fingerprinting, microphones, telemetry | firmware unpacking, DEX, `privacy_surface` |
| Smart speaker / voice assistant | embedded Linux | ARM | always-listening microphone, cloud upload | audio-capture paths, wake-word gating |
| IP camera / baby monitor | embedded Linux (often uClibc) | MIPS / ARM32 | video upload, backdoor accounts, hard-coded credentials | MIPS, endpoint inventory, credential finding |
| Robot vacuum | embedded Linux | ARM64 | camera and floor-plan maps sent to the cloud | sensor-to-network paths |
| Smart plug / bulb / hub | RTOS on ESP32 or similar | Xtensa / RISC-V | phoning home, cloud dependency | non-ARM microcontrollers (Xtensa is new), RTOS signatures |
| Printer | RTOS or embedded Linux | ARM | cartridge chip lockouts, telemetry | lock-mechanism detection (repair lock) |
| E-bike / scooter controller | bare metal | Cortex-M | parts pairing, dealer-only diagnostics | SVD, checksums, patch round trip |

- **Borrow before building.** Firmware extraction is a long tail of container and filesystem formats that binwalk
  (v3 is a Rust rewrite) and unblob have covered for years. Check their licences and APIs, and prefer using one as a
  crate or subprocess; rampage's own effort goes into what comes after extraction. Likewise, Exodus Privacy's
  tracker list could seed the analytics-SDK signatures, licence permitting. Related tools to learn from and not
  duplicate: OFRAK (unpack, modify, repack), EMBA and FACT (firmware triage), Firmadyne and FirmAE (whole-firmware
  emulation).
- **Cloud-dependency analysis.** Find which features need the vendor's servers and what fails without them: the
  first step to keeping a device working after its service shuts down.

Smart TVs and similar devices may run automatic content recognition (fingerprinting what is on screen or heard),
keep microphones live, and send telemetry. These capabilities would help an owner find and stop that on their own
device:

- **Unpack device firmware.** Approved and moved to the
  [smart-device privacy track](#smart-device-privacy-track-approved-2026-11-15).
- **Android/DEX support.** Many TVs run Android TV, so the interesting logic is in APKs: DEX bytecode, the manifest's
  permissions and receivers, and native JNI libraries. A `dex_metadata`/`dex_code` pair, like the .NET tools, plus
  linking JNI exports to their Java callers.
- **A `privacy_surface` workflow,** a sibling of `network_surface` and `persistence_surface`:
  - Sources: microphone and camera capture (ALSA/tinyalsa, V4L2 ioctls, Android `AudioRecord`/`MediaRecorder`/
    camera APIs), screen or framebuffer capture, HDMI-CEC and input events.
  - Sinks: network sends and files that are later uploaded.
  - Paths between them, ranked by evidence, with the call chains.
  - Flag when capture runs without a user-facing trigger: started from boot, a timer or a network command.
- **Telemetry endpoint inventory.** Approved and first slice done; see the privacy track below.
- **Generic ACR/analytics SDK recognition.** Signatures for common analytics and content-recognition libraries,
  surfaced as "component X does content fingerprinting", without naming any TV vendor in the repo.
- **Configuration and feature flags.** Find settings that switch collection on or off (a viewing-data opt-out, a
  voice-assistant wake word), including ones the menu ignores, and where the code reads them.
- **Acceptance on real vendor updates (local only).** Many TV makers publish firmware updates for download, usually
  in vendor containers, often encrypted or signed. Use one or two as local workloads, never committed: start from
  the vendor's update file and list the components that open the microphone or fingerprint the screen, plus the
  endpoints they contact. Container parsing and decryption with a key the user supplies are in scope. Bundled
  vendor keys are not.
- **Patch to disable.** This builds on the patching round trip (checksum recompute, export in the original format):
  stub a capture or upload path in an owner's own firmware image. Still general tooling, not a recipe for any
  particular device.

### Gaps from a Haiku run on a compressed Cortex-M update file (2026-11-15, 1.5.0)

A vendor update container: a header table, then two LZSS-compressed Thumb-2 images (updater and application), each
behind a six-word record (base, payload offset, compressed length, additive sum, base, decoded size). Haiku found the
container, codec, sums and architecture in 29 turns ($0.32) but no function-level facts, because it never reached the
decoded code.

- [x] **List a directory.** No tool lists files, so an agent given only a folder cannot start. A small `list_dir`
  (names, sizes, kinds, a magic sniff), and `endpoint_inventory` naming the entries it ignored.
- [x] **Open decoded bytes as the primary Raw region.** A Raw region can already carry `decode`, but only as a further
  region; Haiku never found it and concluded nothing could analyse decoded output. Allow `decode` on the primary
  region (vector table and seeds then read the decoded bytes), mention it in `decode_file_range`'s result ("open
  this as a Raw project with ..."), and have `probe_compression` return a ready `raw` selector.
- [x] **Write decoded bytes to a file** (`decode_file_range` with an absolute `output_path`, same rules as
  `fs_extract`), for tools that need a file.
- [x] **String and data tools on Raw projects.** `list_strings` and `inspect_data` refuse them.
- [ ] **Image records in containers.** Recognise records that name a payload's offset, compressed length, checksum and
  decoded size, and report them from `carve`/`file_layout` with the matching `decode` arguments.
- [x] **Vector table placed at runtime.** When offset 0 is code that writes VTOR, follow the VTOR store to find the
  table. In the run's image the reset code does not store VTOR itself: it first copies sections (next item) and
  jumps into the copy, so the store is only reachable once copied code is mapped. Done: the reset-code follow
  goes on after the jump, reports constant VTOR stores and seeds the table at the last value when a mapped region
  holds it. In the run's image the copied code sets VTOR to the start of TCM, 0x300 bytes below the first copy,
  which no startup copy fills, so the table is reported as unmapped.
- [x] **Scatter-load copies.** The decoded image's reset code calls a copy loop and a zero loop for a list of
  (destination, length, source) triples (flash to TCM and RAM), then `bx` to an address in the copied code, so
  discovery from the entry stops after one function (`pointer_tables` still recovers thousands). Recognise such
  copy-table calls from the entry, and let a region take its bytes from a slice of another region (the decoded
  primary) at its run address, reporting each copy as evidence in `binary_info`. Done: regions take
  `from: {region, offset}`, and the reset code is followed by a bounded Thumb interpreter whose copies are reported
  in `raw.scatter_load` and mapped by default; on the run's image all six non-empty copies and fills map and the
  jump target decompiles.
- [ ] **Raw selectors with decode re-decode on every call**: the session's cache key hashes the decoded bytes, so
  each call decodes again before it can find the project (key the cache on the selector and source metadata
  first). `inspect_data` opens its Raw image outside `Session::open_raw` (a file tool has no session), so analyst
  names do not resolve in `at` and its 16 KiB input budget refuses large selectors; route it through the session.
- [ ] **Second Haiku run (2026-11-15, after cd681a9).** With the decoded image open as a Raw project, Haiku found
  the startup copy/zero routine, the relocated code's run addresses, the updater's main loop, the sum ranges, and
  USB, MIDI and storage strings, in 63 turns ($0.64). Started from a folder only, it used `list_dir` and got as far.
  What it still hit:
  - scatter-load (above): calls into the copied code fail with "decompilation requires a file-backed code
    address", so the application's main is never reached;
  - `decompile` with `exact_entry` refuses ARM ("x86, x86-64 and AArch64 only");
  - `triage`, `find_main`, `find_crypto` and `function_summary` refuse Raw projects, so it searched bytes by hand;
  - `xrefs` found no references to strings that Thumb code loads through literal pools in the Raw image;
  - entry-only discovery found three functions and Haiku never tried `pointer_tables`: `binary_info` or
    `list_functions` should suggest it when discovery from the entry is that small; done: both return a one-line
    `next` naming `pointer_tables` (and mapping the startup copies when `scatter_load` false left them unmapped)
    when discovery finds fewer than one function per 16 KiB of code;
  - it never ran `integrity_checks` on the decoded code to find the routine that checks the sums.
- [ ] **Reset-code follow coverage.** The scatter-load interpreter skips calls through instructions it does not
  model: long multiplies (UMULL, SMULL, UMLAL), saturating and SIMD-within-register arithmetic, LDREX/STREX, and
  exception entry (SVC). Add them when a startup routine is seen to need them.
- [ ] **Third Haiku run (2026-11-16, after 2badb62): load-address guessing defeats scatter-load.** Haiku wrote both
  decoded images to files and opened them as Raw projects. The updater it opened at the right base, and decompiled
  its entry, copy and zero helpers and peripheral setup. The application it opened at 0x01000000 (the copy
  destination) instead of the record's base, so the reset-code follow stopped with `bad_fetch` and scatter-load
  mapped nothing; it never used `pointer_tables` either (58 turns, $0.59). It also misread one record field.
  - **Base inference.** Offer load-address candidates for a Raw image: absolute pointers in the reset code's
    literal pool and in pointer tables that land inside the image under a given base (the classic self-pointer
    vote), and container records that name a base next to the payload. `probe_compression`/`open_as_raw` and a
    Raw `binary_info` should report the best candidates with evidence.
  - **Say when the base looks wrong.** When the scatter-load follow ends in `bad_fetch` on a constant target that
    would lie inside the image under another base, or most literal-pool pointers fall outside every region,
    `binary_info` should say so and name the candidate base.
  - `find_crypto` still refuses Raw projects; `integrity_checks` found no fields on the decoded image.
- [ ] **Flaky UI test.** `rampage-ui` `debugger::tests::local_socket::genuine_save_refusal_remains_typed_until_resources_are_recorded_despite_obsolete_binding`
  fails intermittently: locally with BrokenPipe on its socket, and on CI Linux ARM64 (2badb62) with "Harness::run
  exceeded max_steps (4)" from a text-selection repaint in `inspection_harness`. Use `run_steps` or wait for the
  socket explicitly.
- [ ] **Read-only annotations for file tools.** MCP lists read-only file tools (`list_dir`, `decode_file_range`,
  `file_layout`, `carve`, ...) without annotations, which the MCP spec treats as possibly destructive; give them
  `read_only(true)`.

### Other ideas (2026-11-14)

- **2.0 candidates** (breaking changes, only if a 2.0 is justified):
  - move `get_type`/`list_types` into `core` (agents missed them, see the suite v3 Go task);
  - promote proven experimental tools (`evaluate_function`, the analysis store);
  - drop argument aliases.
- **Shorter tool descriptions.** The full catalog is close to the agent-bench harness budget, and every agent
  session pays for it in tokens.
- **`evaluate_function` follow-ups:** SSE/SIMD user-ops, x87 floats, float return values, and a step trace on request
  for explaining a result.

## Smart-device privacy track (approved 2026-11-15)

Device owners inspect what their own devices record and send (right to repair, privacy). The other privacy ideas
above stay under review until each is approved.

- [x] **Unpack device firmware, first slice** ([plan](docs/plans/2026-11-15-firmware-unpacking.md),
  [docs](docs/firmware-images.md)). `fs_list` and `fs_extract` (group `carve`, crate `rampage-unpack`): SquashFS 4.0
  with all six codecs, ext2/3/4, Android sparse, full OTA payloads (delta refused by name), cpio and tar; nesting via
  `inner`, embedded images via `image_offset`; hostile-input limits; pure-Rust codecs on `backhand` and
  `ext4-view`. Opening a filesystem image as a binary points at `fs_list`.
- [ ] **UBI and UBIFS.** Recognised and refused today. UBI: volume table, PEB-to-LEB mapping, volumes as `image`
  entries. UBIFS: superblock and master node, the index B-tree, inode/dentry/data nodes with LZO, zlib and zstd
  data. No local `ubinize`/`mkfs.ubifs` here (mtd-utils is not in Homebrew), so fixtures need a test-side
  generator or a Linux recipe; evaluate the `ubifs` crate (MIT, 0.1) first.
- [ ] **Vendor SquashFS variants and SquashFS 3.x** (backhand has AVM and several LZMA variants behind features
  that build C; they would need pure-Rust codec hooks), and a big-endian SquashFS fixture.
- [ ] **Finding images inside vendor containers.** `carve` tags SquashFS and cpio but not ext4, Android sparse, OTA
  payloads or UBI; teach it those (and `file_layout` hints), so `image_offset` comes from a tool, not by hand.
- [ ] Compressed tar (`.tar.gz`, `.tar.xz`) and a CLI route (`rampage binary fs-list`/`fs-extract`).
- [ ] Acceptance on a real vendor update (local only, never committed or named): from the vendor's update file to
  the binaries inside.
- [x] **Telemetry endpoint inventory, first slice** ([docs](docs/endpoint-inventory.md)). `endpoint_inventory` and
  `endpoint_blocklist` (group `carve`): URLs, PSL-checked hosts, IPv4/IPv6, pins and PEM/DER certificates in a binary
  or an extracted tree, with noise rules, `local`/`package` labels, xref and networking-caller evidence, decoded
  strings, domain and component groups, cursor paging; hosts/dnsmasq/unbound/domain/IP blocklists.
- [x] **`privacy_surface` workflow, first slice (1.6.0)** ([docs](docs/privacy-surface.md)). One binary: capture
  sources (ALSA/tinyalsa/PulseAudio/PortAudio/AAudio, V4L2/framebuffer/DRM/evdev ioctls, device paths, Android
  audio/camera/screen names), `argument` evidence from constant arguments at the call, network/file sinks with
  their endpoints, ranked capture-to-send call paths, triggers (program start, timer, network command, user input)
  and `no_user_trigger`.
- [ ] `privacy_surface` follow-ups: directory mode over an extracted tree (cursor, `max_files`, `timeout_ms`) with
  boot triggers across files (init.d scripts, Android `.rc` services, systemd units starting a program with
  sources); HDMI-CEC (`CEC_RECEIVE`, libcec); MIPS argument reading (delay slots) and 32-bit x86 stack arguments;
  arguments set in a predecessor block; DEX/APK sources once Android support lands.
- [ ] Endpoint follow-ups: IPv4 addresses stored as integers in code (immediates passed to `connect`/`sin_addr`);
  `network_code` through one call level (a string passed to a helper that calls `connect`); hex SHA-256 and
  SHA-1 pins; DEX/APK strings once Android support lands; a CLI route; merging groups across directory pages; a
  real-firmware precision check (local only).

- [ ] **Committed fixtures without local paths.** About 16 older fixtures embed the builder's home directory in
  debug info (e.g. `tests/fixtures/bin/debug-x64.elf`, `tests/fixtures/bench-v2/twins/widgets-x64.elf`,
  `tests/fixtures/firmware/locks-*-sym.elf`, `crates/rampage-api/tests/fixtures/decode-*.elf`). Rebuild them with
  `-ffile-prefix-map` (or same-length filler, as for the endpoints fixtures) and add a CI check that no committed
  binary contains `/Users/` or `/home/`.

## Proposed tracks (2026-11-08, not started)

Queued behind the flywheel work, one at a time; each needs its own design and go-ahead.

- [ ] **Windows corpus for the flywheel.** x86 and x64 PE builds with clang-cl and lld-link against the MSVC CRT
  and SDK fetched locally by `xwin`, which asks the builder to accept Microsoft's licence. Truth comes from PDBs,
  and MSVC CRT versions give the train/final split. The recipe pins origins only and nothing is committed.
  Microsoft's public symbol server and research datasets (BinKit, Cisco Talos `binary_function_similarity`,
  Assemblage) can serve as outside evaluation sets on the same terms.
- [ ] **Malware-analysis workflow** (defensive analysis and detection):
  - dump a decrypted stage or module from a debug session and open it as a linked analysis target, instead of
    a classic OEP/import-rebuilding unpacker;
  - extract indicators (C2, keys, decoded strings) with evidence links;
  - draft YARA rules gated against a goodware corpus, a candidate flywheel family after compiler/tool
    identification.
  Samples run only in disposable QEMU or VM guests reached through the debug stubs, never on the host. Needs a
  real packed fixture.

## Head-to-head agent benchmark follow-ups (2026-11-05)

Observations from [the rampage vs REA runs](docs/benchmarks/agent-h2h-2026-11-05.md); rampage was not tuned
during the benchmark.

- [ ] The model sometimes calls a bare tool name (`enable_tools`, `list_strings`) and the client refuses it: 4
  of 6 C++ runs in the first run, 2 in the second. Check whether tool descriptions or `enable_tools` output name
  tools in a way that invites unprefixed calls.
- [x] The second run's one rampage miss (`objc-superclasses`) never enabled the `types` group for
  `language_metadata`. Done: `language_metadata` and `class_evidence` moved to `core` (2 tools, about 2.3 KB of
  tools/list) instead of enabling `types` by default (20 tools, about 35 KB).
- [x] Results over Claude Code's 50,000-character limit are spilled to an unreadable file. Done: every tool
  declares `anthropic/maxResultSizeChars` = `RESULT_LIMIT_CHARS` (61,024).
- [x] Add harder, less-saturated agent tasks. Done as [suite v2](docs/benchmarks/agent-h2h-v2-2026-11-05.md).
- [ ] Repeat the head-to-head with a second model or client before drawing conclusions beyond this one.

## Benchmark suite v2 follow-ups (2026-11-05)

From [suite v2](docs/benchmarks/agent-h2h-v2-2026-11-05.md). Fixed: `function_summary` fitting, linear exact-text
search with a resume cursor, Go string-run match addresses, raw-profile aliases and headerless guidance, hex ARM
immediates in `inspect_raw_code`, one-line argument errors and unknown-argument refusal, chained-fixup RTTI.

- [x] `search` `functions_referencing` a string stops on `match_work_budget` with nothing scanned on the 50 MB
  Hugo image (all 4 scale-string runs): `prepare_search` charges a B-tree insert for every discovered block of
  the whole program before decoding, then decodes every instruction to compare its references. For string
  references, find the string's addresses first (the now-linear text search) and walk the retained xrefs to
  them, decoding only the referencing sites; until then agents fall back to text search + `xrefs`.
  Done 2026-11-13 (restic 26 MB: budget stop → 1 exact hit; Go literals bounded by the next referenced literal).
- [x] Byte patterns with wildcards still charge their length per candidate start; a 50 MB image needs a
  literal-prefix prefilter or a larger default budget.
- [x] ARM immediates are printed in LLVM's decimal (`movt r1, #1934`) by the shared native renderer, used by
  `disassemble` and search operand globs too. Only `inspect_raw_code` appends hex now; adding it to the native
  listing needs its own field or comment so CLI/UI comment columns and operand-glob matching stay unchanged.
- [x] No Raw Project profile for ARM/Thumb (Cortex-M): firmware runs needed `inspect_raw_code`, which has no
  functions, xrefs or decompilation. A reviewed ARM/Thumb Raw profile would let `raw` serve them. Done:
  experimental `ARM:LE:32:Cortex` (aliases `cortex-m*`, `thumb`, `armv7m`, ...), native Thumb decoder, ARM v8
  decompilation, 4 MiB cap ([Cortex-M profile](docs/sleigh-decoding.md#cortex-m-profile)).
- [x] Go string literals referenced only through static `{ptr, len}` headers in data (not by code) get no
  `go_literal` start, since data-to-data references are not retained; reading headers would bound them too.
- [x] `function_graph` refuses oversized views like `function_summary` did; page its blocks the same way (edges
  index whole-function block positions, so paging keeps them valid).

## Suite v3 Haiku pass follow-ups (2026-11-13)

- [x] DWARF types at scale: `import_debug_types`/`import_debug_layouts` previews stopped on whole-file budgets on a
  7.9 MB SQLite build, so struct layouts were unreachable. Done: `get_type` DWARF fallback with per-request bounds.
- [ ] Whole-file DWARF import previews still return nothing at this size; make them return partial results.
- [ ] DWARF lookup: C++ types nested in classes, DWARF 5 type units / `.debug_types`, zstd-compressed sections.
- [x] Persistent analysis store (roadmap 6.2, first half): SQLite cache of discovery, keyed by every analysis
  input and the rampage build, with an `ANALYSIS_VERSION` golden test. Open: caching signatures and strings if they
  matter, incremental re-analysis after edits, deleting a rejected store automatically.
- [x] `switch-pic-x86-so` took 12–20 rampage calls: unnamed i386 PIC PLT stubs. Done (named through the GOT base).
- [x] Recurring argument-name errors cost a retry per call. Done (unambiguous aliases, numeric strings).
- [x] `go-nested-field` took 20–26 rampage calls against REA's 14: no Go runtime type metadata. Done (`get_type`
  Go source). Open: Go before 1.16, position-independent Go ELF (pointers filled in at load time).

## Function evaluation (2026-11-14)

- [x] `evaluate_function` (core, experimental): run a function on arguments with a p-code interpreter instead of
  simulating it; every suite v3 semantics miss was a hand-evaluated loop. Open: interpret the SIMD processor
  operations Sleigh leaves as CALLOTHER (SSE `memset`/`memcpy` stop with `user_op`), float results, and a
  benchmark run with the tool.
- [x] Library stand-ins for common C imports in `evaluate_function`, and `string_decoding` `evaluate: true`
  running candidate decoders on their blobs. Open: models for `sprintf`/`strdup`/`operator new`, and replays
  that start before the caller's block.

## Firmware patching round trip (2026-11-14)

- [x] `integrity_checks` (CRC/checksum/digest fields, brute force + code + emulation, fix as patches in dependency
  order), `export_image` (HEX/S-record record rewrite, binary file, flat binary, PE CheckSum), Raw project patches.
  Open: checks over several discontiguous ranges or with the value's bytes skipped/zeroed inside the range;
  polynomials built over several instructions (`movs` + shifts/adds) and 8-bit CRC polynomials in code; PE patch
  admission; persisting Raw patches across sessions; a run on a real owner's image.
- [x] Device confirmation of fixes: with `emulate` (the default), each value a fix writes or previews is checked by
  running the routine that confirmed the check (`evaluate_function`, same argument form) over the range as the fix
  leaves it, the fix's earlier writes passed as memory writes: `fix.writes[].device_check` is `agrees`, `disagrees`
  (also a note) or `unconfirmed` with the reason (no routine was confirmed, the run did not return, it could not
  start); it never blocks the write. Open: checks only emulation confirmed have a routine (one confirmed by code
  references alone stays `unconfirmed`); routines with another signature than `(start, length|end)` (a context
  struct, a seed argument, a CRC over a table of ranges); digests (SHA-256/MD5) are never run.
- [x] Static ELF32 ARM firmware patched in place (record version 3, PT_LOAD file-byte mapping, no dynamic/RELR
  relocations or overlapping segments), `integrity_checks` fixes and `export_image` (patched ELF, flat binary at load
  addresses) on it; CRC-16 polynomials formed by one Thumb/A32 immediate or a literal word.
- [ ] Search ELF firmware checks in load-address space too: a CRC over flash that includes `.data` initial values
  (a section loaded at another address than it runs) is not found today, since blocks are run-address segments, and
  a `.data` patch can leave such a check stale (only a note says so). Add the load-address image (the
  `objcopy -O binary` layout) as search blocks, map a found range back to file offsets for the fix, and report the
  check's space as `load`.

## CMSIS-SVD peripheral maps (2026-11-14)

- [x] `import_svd` and `peripheral_access` (types group): SVD registers as struct globals in decompiled C with
  bit-field comments, names in disassembly/xrefs/evaluation faults, constant-address access scan, `mmio` values
  for `evaluate_function`. Open: an `svd` field on the `raw` selector (Raw annotations are per session, so the
  map must be imported again after a restart; skipped to keep the catalog small), carrying maps in
  `transfer_annotations`, accesses through pointers passed between functions, and a run on a real vendor SVD
  and image. (`evaluate_function` on Raw projects landed with the suite v4 gap fixes.)
- [x] Extend the Cortex-M decompiler settings (device-range volatility, flash words read through a formed
  address not folding) from Cortex-M Raw projects to Cortex-M ELF firmware: recognise it by the ARM attributes
  section's CPU profile 'M' (Tag_CPU_arch_profile), not by load address. Done: `Binary::m_profile()` covers
  M-profile ELFs (attributes profile 'M' or an M-only Tag_CPU_arch); the decompiler settings apply to M-profile
  ELF executables (statically linked: no interpreter, needed libraries or `.dynamic`; not relocatable objects).
- [x] Cortex-M decompilation is fast and order-independent (callee inference kept per engine). It was slow on
  library-heavy firmware (`embedded-libs-m0` `0x80092ca` 6.5 s, most of it in callee prototype derivation) because
  `resetCalleeInference` dropped every derived prototype before each top-level decompile; keeping them as derived
  would have made output depend on order (budget cut-offs, cycle verdicts taken against the in-progress root).
  Design (shim.cc, Cortex-M handles, which never have vftables; the MSVC vftable path keeps the old reset):
  - Facts per function from one scratch flow (`flowFacts`): hidden flow (indirect call/jump, `svc`, bad code),
    flow into another function, registers written, direct calls. The scratch flow also replaces following the
    registered function, whose jump-table recovery cost ~150 ms per callee with a switch.
  - Every verdict is a property of the function alone, cached for the engine's life: register effects are Known
    when everything reached is at most 256 functions, at most 16 calls deep, acyclic and clean; a prototype can be
    locked when everything reached (analyst-locked functions excluded) is at most 64 functions, acyclic and
    derivable, and is then derived bottom-up once.
  - Which callees a decompilation sees locked (`calleeView`) is fixed by the function alone: its direct callees in
    the order its flow finds the calls (Ghidra's call specs), each taken while the union of what they reach stays
    within 64 functions (this bounds a cold request's derivations as before, without the old budget spent on subtrees that could never lock). Other derived
    locks among its direct callees, and its own, are set aside for that decompilation and put back before the next.
  - Every analysis on these handles starts without the globals earlier analyses discovered (Ghidra's `mapGlobals`
    adds typed symbols to the global scope) and without `typerecovery_exceeded`, which `Funcdata::clear` keeps
    (vendored `clearTypeRecoveryExceeded`): both made output depend on history on main too (`0x80020b0` read as
    `uint4 *` or `uint4`; `0x8002dd4` lost its "not settling" warning and some propagation once analysed before).
  Measured (release, loaded machine): `0x80092ca` fresh 6.3-8.4 s -> 1.8-2.5 s; every fourth function (138) on one
  engine 294 s -> 29 s; fresh engine per function, every 20th (28) 144 s -> 19 s; all 549 on one engine 1308 s ->
  ~130 s, forward, reverse and fresh-per-function byte-identical. 66 of 549 outputs differ from main: more callees
  locked (arguments recovered, or dropped where the callee never reads them), globals typed only by the function's
  own use. Tested by `cortex_m_elf_decompilation_does_not_depend_on_history` (functions on cycles, over the budget,
  the largest one, a leaf and its caller, and the two above: fresh vs after others vs after all).
  Open: a global that only a callee's analysis typed now reads as an address constant (`(xunknown4 *)0x200009cc`
  instead of `&ram_200009cc`); a program-wide global pass would name them deterministically. The same two leaks
  remain on every other architecture (kept so their output is unchanged). MCP requests run in a fresh worker each,
  so they gain the cheaper cold path but not the cache, unless a worker is kept per project.
- [ ] The same two history leaks exist on every other architecture: a function analysed before (as a top-level
  decompilation or a context) keeps Ghidra's `typerecovery_exceeded`, so it loses the "not settling" warning and
  skips propagation passes the next time, and globals an earlier analysis discovered stay typed for the next one.
  Fixable for all handles by masking the flag in `Funcdata::clear` (vendored) and dropping discovered globals
  before each analysis as Cortex-M handles do, at the cost of output changes wherever a session decompiled
  something before.
- [ ] Return-type contexts can refuse a decompilation: on `embedded-libs-m0`, giving `0x8000058` the signature
  `int4 sub_8000058(xunknown4 param_1)` makes its decompilation fail with "unlocked result type was not retained"
  (its last call's context, `0x800150e`), on main too.

## Objective-C dispatch (2026-11-13)

- [x] `objc_msgSend` resolution (selectors, receiver classes, method lookup, `objc_sends`, xref rows, comments).
- [ ] Receiver classes from ivar and property types (only ~40% of sends in installed apps get one today).
- [ ] Follow selectors and receivers through stack slots (most x86-64 and `-O0` unknowns).
- [ ] Rewrite decompiled sends as `[obj sel]` instead of a comment; Swift metadata.

## Protected and packed code (2026-11-13)

- [x] Encrypted/packed code regions detected per window; discovery skips them; PACE protector signature; real
  UPX-packed fixtures in `tests/fixtures/packed/`.
- [ ] List the named entry points inside a skipped stretch as stubs instead of only counting them.
- [ ] The x86 decode-share margin is thin (random bytes decode ~95% against the 97% threshold); entropy carries x86.

## Build diffing and annotation transfer (roadmap Phase 7, 2026-11-13)

- [x] One-to-one build matching with per-method confidence and `transfer_annotations` (preview/apply, provenance,
  conflicts). zlib 1.2.13 → 1.3 acceptance met with zero false matches.
- [ ] Switch `diff_builds` to the new matcher; CFG-shape similarity for changed functions; a single undo for
  transfers larger than one batch.

## Head-to-head suite v3: tasks where Ghidra is strong (not run yet)

The suite-v2 fairness review found that its categories lean towards what rampage was built around (RTTI evidence,
pclntab names, `diff_builds`). Suite v3 should balance that with tasks where Ghidra is known to be strong. Keep v2's
rules: truth independent of both servers, tool-neutral prompts, owned or pinned fixtures, strict and partial
scores defined before any run.

- [ ] A symbol-rich C or C++ release binary (pinned sqlite or openssl from upstream sources, checksummed), with
  questions answered from its own symbols and DWARF: callers of an internal function, a struct field's use.
- [ ] Decompiler-heavy semantics: what a function computes for given inputs (loops, bit tricks, 64-bit
  arithmetic on 32-bit targets), with truth from host runs of the owned source.
- [ ] Type propagation: apply one struct type and answer a question that needs it carried through several
  functions.
- [ ] Switch tables: the case value that reaches a given block, for jump tables in PIC and non-PIC code.
- [ ] MSVC-built PE C++: RTTI hierarchy, vtables and exception handlers (needs a pinned MSVC-built binary with
  a PDB as truth).
- [ ] 32-bit x86 (cdecl/stdcall/fastcall), including calling-convention questions.
- [ ] Go inside Ghidra's supported range (Go 1.15–1.26 for Ghidra 12.2), stripped and at scale, so its Go
  analyzers apply.
- [ ] Rizin installed on the host, or REA's Rizin-backed tools declared out of scope in the prompt-independent
  setup, so REA's advertised catalog matches what can run.

## Open acceptance gate: live Phase 1 completion

- [ ] Genuine live checked import → central C++ struct retype → owner-linked field verification and fresh replay.
- [ ] Record successful reconstruction call bound N and independent DWARF agreement; execution caps are not N.
- [ ] Diagnose the model-side failure only with new evidence; keep first attempts and prior publications frozen.
- [ ] Do not claim full Phase 1 acceptance from controlled test success alone. The maintainer approved
  proceeding through Phases 2–6 while this live acceptance gate remains open; frozen results are unchanged.
- [ ] Carry forward the native C++ class-evidence limit: stripped exceptions workload currently yields no class
  rows; symbolized vtables are skipped as not mapped read-only. Do not relax evidence rules to inflate scores.

## Audio/firmware investigation acceptance workloads

The workload: explain a third-party audio plugin or firmware image you are authorized to analyse.
The batches below track investigation outcomes and remaining blockers, not a competing feature queue.
The goal is to answer: what features exist, where their code lives, how parameters reach processing, and
which links are static candidates versus observed execution. Ship reusable improvements driven by actual
investigation obstacles, not a plugin-specific analyzer or another extension framework.

### Next three execution batches

#### Batch 2 / P0: explain one complete named effect

Question: how does one simple user-visible effect turn its parameters and input buffers into output?
Choose a small, self-contained effect (EQ, filter or delay sized), not an entire effect suite.

- [x] Match the selected catalogue ID and parameter metadata to code/data evidence, keeping resource
  declarations distinct from binary associations and runtime availability.
  One simple mono/stereo catalogue pair is corroborated by symbolic indices and native model records.
  A separately registered matching primitive is located; their composition link remains unproven.
- [ ] Trace the host/core entry, model creation, parameter-update path, processing schedule and sample kernel.
  Record buffer shapes, state, coefficient updates, bypass and sample-rate/block-size behavior where supported.
- [ ] Produce an evidence-linked feature map using existing annotations/workflows where sufficient:
  feature, module/slice identity, address, role, supporting references, confidence and unresolved links.
  Keep third-party inputs local; repository examples use owned inputs and generic descriptions.
- [ ] Fix only the highest-impact blockers on that path. Current candidates are an unresolved bounded ARM64
  parameter-routing jump table and incorrect/missing recovered signatures or mixed integer/float storage types.
  Diagnose the specific shape before choosing a recovery change; warnings remain visible until actually resolved.
  - [x] Bounded fatal-wrapper recognition prevents a real primitive-update function from absorbing adjacent code
    after its assertion wrapper. Re-tested through MCP; throwing imports, conditional/unknown transfers and
    resumable/system traps are excluded, and wrapper reads consume shared preparation budgets.
- [ ] For each fix, show the failing owned case, corrected result and repeated real investigation. Check the
  important arithmetic/control flow against assembly; use source-known fixtures for independent ground truth.

Done: a reader can follow one named effect from controls to sample processing, locate the relevant code in MCP,
and see exactly which associations remain uncertain. A primitive alone or a plausible decompilation is not enough.

#### Batch 3 / P0: transfer to an independent implementation before expanding scope

- [ ] Apply the same catalogue -> descriptor -> code workflow to a second plugin from a different developer that
  you are authorized to analyse. Do not add developer-specific conditions to make the case pass.
- [ ] Find a meaningful processing or parameter/state path, not just exports or a factory forwarding wrapper.
  If a candidate cannot be inspected statically, record the boundary and select another accessible candidate;
  no installer execution or security-setting changes.
- [ ] Compare manual handoffs, critical unresolved links and query cost against the starting investigation.
  Record regressions as well as gains; an explicit refusal is honest reporting, not transfer success.

Done: the improvements support a second independent implementation and produce another useful code map.
If they do not transfer, fix the demonstrated general limitation before starting another feature family.

### P1: confirm selected links at runtime (after the first static effect map)

- [ ] Add bounded read-only stack-frame enumeration to the existing stop-token-pinned LLDB protocol and
  API/CLI/MCP; include thread/frame identity and qualified module/image/load addresses with explicit failures.
- [ ] Replace the custom stack-walk script in the authorized disposable-host experiment with rampage queries.
- [ ] Observe one selected processing callback and one parameter/state path when safely reachable, then compare
  them with the static map. Keep registered, reachable and observed-execution claims separate.
- [ ] Preserve the stop identity and DATA-order evidence requirements; ARM64 order remains unknown without
  affirmative stop-bound evidence. No automatic launch/attach/resume/stepping/breakpoints/expressions/writes.

Done: an explicitly operator-stopped disposable host can confirm selected links through rampage alone,
without audio-device output, DAW/project changes or unsupported capture claims. This is not full flow coverage.

### Parallel track: efficient unknown-firmware/binary investigation

Decoder-provider implementation and static investigations can run independently from the plugin queue.
Shared API/CLI/MCP edits and builds remain coordinated; each parallel worker owns a disjoint file scope.

- [x] Initial read-only inventory found a raw update header, an updater label, plausible Thumb instructions
  and readable effect/preset names. Standard executable carving found no validated embedded image; this is
  partial visibility, not a recovered container, proven architecture or evidence of encryption.
- [x] Corroborate two compressed component extents and decode both in memory with explicit LZSS parameters:
  exact declared input consumption/output lengths and matching stored additive checksums; no payload files.
  Traceable initial-vector/startup evidence supports a local Thumb mapping, not a proven physical device map.
- [x] Reproduce the actual tool gap: unknown-file inspect/triage/strings and explicit-offset disassembly refuse
  before useful inspection because they require native executable headers. Zero carve candidates missed the
  proprietary components; it did not establish that the image was empty or encrypted.
- [x] First enabling slice: format-independent byte/ASCII-string triage on explicit file ranges, with offsets,
  bounded previews, fill/occupied-region summaries and range hashes; no native loader or extraction required.
  Done: `file_layout` / `binary layout` ([file layout](docs/file-layout.md)).
- [x] Second enabling slice: explicit raw-code windows with file range, address base, architecture, code mode
  and byte order supplied as analyst assertions. Use the existing decoder; no guessed executable layout or seeds.
  MCP and CLI expose bounded original-file windows; owned compiler/IT/literal/boundary cases and a real loader
  window passed. Unknown backward literals and prior out-of-window IT context remain explicit limitations.
- [ ] Use that raw Thumb view to corroborate the initial loader's decode loop, callers and component address
  fields, then follow one decoded startup/control path. Exact chip, field roles and full memory map remain open.
  - [x] Corroborate the ring start, flags, reference assembly and ring wrapping through MCP raw inspection.
- [x] Promote the corroborated codec experiment into an explicit internal decoder-provider interface with
  a built-in LZSS-4K variant, not a public SDK or triage-plugin ABI change. Shared API/CLI/MCP accept an explicit
  file range, codec, dictionary parameters and supplied output size, returning transient bytes/receipts only.
  Source-range/output hashes, consumed/trailing counts and decoded-offset previews remain separate from
  container authentication, source offsets and load addresses. No file publication or execution is supplied.
  Both real components reproduced the independent decoded hashes, exact input/output lengths and stored
  byte sums through the CLI; raw-code loading and the complete loader contract are still open.
- Static only: no updater/installer execution, flashing, emulator execution or security changes. Do not turn
  this into an automatic unpacker or a generic firmware framework before the first traced loader path.

### Embedded library signatures (2026-11-14)

Done: the bundled embedded firmware set (scheme 3; newlib/newlib-nano, libgcc, compiler-rt, FreeRTOS, STM32F4
HAL/LL; [signature corpus](docs/signature-corpus.md#embedded-firmware-set)) and Raw-project `identify_functions`.
Held-out GCC 14.3 firmware: 100% precision, 51% (M4F) and 31% (M0) recall. Open:

- [ ] Recall across compiler releases: newlib and FreeRTOS C code changes with every GCC major. Add older releases
  (10.3, 11.3; x86-64 macOS builds) and, if a fuzzy or operand-wildcard tier ever passes its gate on firmware, use
  it here.
- [ ] FreeRTOS signatures match only configurations laid out like a trained one; add CubeMX's default
  configuration and more ports (ARM_CM7, ARM_CM33_NTZ).
- [ ] More families: picolibc, NXP MCUXpresso drivers, Raspberry Pi pico-sdk, Nordic nrfx, and IAR/Keil runtime
  libraries (licences permitting).
- [ ] `build_signatures` still writes scheme 2, so a user's own Thumb firmware database keeps literal-pool
  addresses in its hashes; build scheme 3 for Thumb there (an additive output change).
- [x] ELF discovery does not seed Cortex-M vector-table handlers (Raw projects do), so `xPortPendSVHandler` and
  friends stay unnamed in ELF firmware. Done: an M-profile ELF's table (vector section, or the lowest flash words,
  corroborated by Reset == entry) seeds its handlers. Open: report the ELF table's per-word evidence in
  `binary_info` as Raw does.

### Firmware gaps seen in an agent run on a Cortex-M image (2026-11-09, done 2026-11-12 except follow-ups)

An agent analysing a headerless ARM Thumb (Cortex-M) firmware image fell back to
`strings`/`xxd`, a Python wrapper around the rampage CLI for range disassembly, an entropy/0xFF-run map, and an
LZ parameter brute force. Each is a candidate MCP tool; one at a time, each needing its own design and go-ahead.
Verify first which of these the existing raw-window and decoder-provider slices above already cover.

- [x] **Firmware layout tool.** Regions, 0xFF/0x00 padding runs, per-block entropy (packed areas), string
  clusters and range hashes in one call. Extends the byte/ASCII triage slice above. Done: `file_layout` (MCP
  `core`) and `binary layout`, up to 64 MiB per call with capped lists and a continuation range, plus labelled
  Cortex-M vector-table candidate hints (evidence only; the Raw selector's `vector_table` does the seeding).
- [x] **Unknown-compression probe.** Try LZSS/LZ4/LZ77 variants and a bit-order/length-encoding sweep against a
  supplied or expected output size or an entropy drop, and return candidate decoder-provider parameters. Builds
  on the explicit LZSS-4K provider; the agent re-derived this by hand.
  Done: `probe_compression` (LZ4 block + 160 LZSS variants; confident only with an expected size). Open: ring fill
  byte often undecidable, deflate/LZMA/LZO/LZ4 frames, arch-aware output checks, a run on a real image.
- [x] **Cortex-M vector table and entry detection.** Reset/SP/handler candidates with evidence, so the first
  load needs no trial and error. Pairs with the ARM/Thumb Raw profile item under the benchmark follow-ups. Done:
  `raw.vector_table` seeds entry and handlers and reports each word's verdict in `binary_info`, with a labelled
  base-address suggestion it never applies.
- [x] **Raw ingest in one call.** Blob plus arch, mode and base address returns a ready project (see the
  ARM/Thumb Raw profile item), so agents need not read `cli-reference.md` and `sleigh-decoding.md` to learn it.
  Done: `"raw":{"profile":"cortex-m","offset":0,"length":N,"base_address":...,"vector_table":true}` on any
  raw-capable tool; the server instructions and headerless-file guidance show it.
- [x] **Range disassembly to text**, native in `inspect_raw_code`, replacing wrapper scripts. Done through the
  Cortex-M Raw Project instead: `disassemble` with `raw`, `count` up to 1000 and `view: "code"` pages over the whole
  image (tested end to end on the owned fixture).
- [x] **Thumb-2 MSR decode bug.** `msr basepri, r0` (`80 f3 11 88`) decoded as invalid, stopping discovery and
  `inspect_raw_code`. Done for the Cortex-M Raw profile, the documented path for Cortex-M code: M-profile
  decoding adds hand-written `MRS`/`MSR` encodings (UNPREDICTABLE forms refused) and makes A-profile-only
  instructions (BLX to A32, Advanced SIMD, SETEND, ERET, ...) UNDEFINED, llvm-mc-checked. `inspect_raw_code`
  `thumb` stays A-profile and its docs point Cortex-M users at the Raw profile.
- [x] **Tail-call splits without symbols.** A function first reached by a tail call (`b.w f`) before its own
  call is seen splits at internal join points: 1,773 of 6,030 starts on a generated 1 MiB Cortex-M image, the same
  on its stripped ELF. Discovery should drop the caller's stale exploration once `f` becomes a function. Done: callers are re-explored
  once a later start appears, before shared tails are counted (generated 6,000-function image: 8,234 → 6,002
  starts, exact; other binaries unchanged). Still open: a function reached only by one tail call stays in its caller.
- [x] **Multi-stage images.** Load a decoded bootloader payload as a second region at its RAM base, linked to the
  source range. Overlaps the dump-as-linked-target idea in the malware-analysis track.
  Done as `raw.regions` (file-range, decoded or unbacked code/data/ram regions) plus `format` `ihex`/`srec`.
  Open: HEX run addresses, regions from a second file, vector/pointer-table scans beyond the primary region.
- [x] **Function discovery from pointer tables.** Discovery seeds only the entry point. Seed from tables of code
  pointers, with evidence per seed, so a raw image needs no hand-built symbol list (the Cortex-M vector table
  is done through `raw.vector_table`). Done: opt-in `raw.pointer_tables` (needs two strong targets per table;
  fixture 17/17 precision, 17/18 recall). Leaf-only tables are refused; adjacent tables report as one run.
- [x] **Decompiler accuracy on a raw Thumb image:**
  - a `bl` checksum call dropped its length argument (a stale `r1` from earlier code);
  - a shift-and-mask rendered as `&0xfff << 4`, which hid the real operation; compare against the disassembly
    on an owned case before changing anything;
  - literal-pool addresses showed as unnamed `iRam…`/`pxRam…` variables, so name or annotate them.
  Done for Cortex-M Raw images: pool folding, region names, IPRA-aware callee effects and parameter-only callee
  prototypes; the shift-and-mask is correct Ghidra output (documented). Open: `--exact-entry` path, other
  architectures, pool constants printed as numbers, callees whose return is used still print `void`.
- [x] **Performance at about 5k symbols.** Listing 5,182 seeded symbols took about 22 seconds, and `xrefs --to`
  ran past 2 minutes on the same image. Profile both and fix the slow path (likely a scan per query rather than
  an index). Done: the slow path was a full-image hash per xref row (binding check); now once per query. The
  22 s listing did not reproduce on the Cortex-M profile; re-time the original Sleigh workflow. Open: one image
  hash per call remains (cache the raw identity in `rampage-loaders`). Done 2026-11-13: hashed once per open.
- [x] **Container recognition.** Triage and `carve` do not flag a proprietary compressed container, i.e. a
  header with load address, sizes and a byte-sum around an LZSS stream. Report "header-checked
  compressed-component candidate" with extents, so the compression probe has a starting range.
  Done as the `file_layout` hint `compressed_component_candidate` (size + byte-sum/CRC-32 or packed payload at a
  boundary with a decoded-size word); triage and `carve` unchanged.
- [x] **MCP tools in subagent sessions.** The agent had no rampage MCP tools and fell back to the CLI. Find out
  why (server config, permissions or startup), and document how to expose them to agents. Done: configuration, not
  a server fault. On the machine that ran it, `rampage` was neither installed on `PATH` nor registered at any
  Claude Code scope, so no session there could start the server.
  [MCP](docs/mcp.md#agents-subagents-and-scripted-sessions) now covers scope, subagent `tools` lists, `claude -p`
  flags and startup checks.

### Execution rules for speed

- One active slice per independent track; shared-file edits and the central build queue stay serialized.
  Each batch ends with a usable investigation result and a short next blocker.
- Use MCP first. Scripts are for genuinely necessary host/process coordination, not routine JSON consumption.
- Timebox an unproductive investigation to 60-90 minutes; record the exact missing evidence or failing query,
  then choose the smallest enabling fix or another accessible target rather than expanding the framework.
- Run changed-area regressions and a real before/after first; expand validation for the touched consumers
  before publication. Use shared `target/`, two build jobs and the existing low-debug/non-incremental profiles.
  Review nontrivial diffs independently; retain timeout/failure limits instead of reporting an unearned pass.
- Keep commercial binaries, payloads, extracted code, captures and secrets out of git. Commit only generic
  implementation, owned fixtures and generic documentation. No release tags or CI dispatch for ordinary work.
- Defer general resource-import frameworks, broad C++ reconstruction, new component-plugin infrastructure,
  raw-firmware support and UI expansion unless the active investigation demonstrates they are the next blocker.

## IDA/Ghidra gap-closing wave 1 (done earlier)

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#idaghidra-gap-closing-wave-1-done-earlier).

### Pending follow-ups from this wave

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#pending-follow-ups-from-this-wave).

- [ ] MIPS signatures: mask `lui`/`addiu` HI/LO address pairs. Needs relocation/dataflow to avoid false matches
  (without it, a masked constant could collide two different functions); do it relocation-gated, not heuristic.
- [x] Verify the MSVC RTTI path against a real PE. Done 2026-11-12 on owned clang-cl x86/x64 fixtures with PDB truth
  (`tests/fixtures/msvc-cpp`): RTTI already correct; vftables, `__CxxFrameHandler3` EH tables and PDB names added.
- [ ] MSVC follow-ups, most valuable first: decode `__CxxFrameHandler4` (cl.exe x64 default; needs a real cl.exe
  FH4 fixture, e.g. via msvc-wine: clang-cl always emits FH3); fold catch-resume points back into parents; x86 SEH
  (`_except_handler3/4`) and ARM64 tables; PDB types; virtual calls through virtual bases or vftables stored by a
  constructor in the caller. Done 2026-11-13: virtual call → vftable slot in decompilation, paged `rtti_classes`
  with base-only rows, `/OPT:ICF` in debug-type import.
- [ ] C++ class LAYOUT reconstruction (fields/sizes), building on the RTTI name/hierarchy recovery now in place.

## Heuristic-database layer (pluggable detection DBs)

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#heuristic-database-layer-pluggable-detection-dbs).

- [x] A real packed fixture: UPX-packed ELF and PE in `tests/fixtures/packed/` (2026-11-13).
- [x] Detect It Easy signatures imported (544, exact conversions only). Open: an alias table to merge DIE and rampage
  names (e.g. "MSVC" vs "Microsoft Visual C/C++"); DIE's UPX scripts (helpers/loops) are not converted, and UPX-packed
  ELF is not detected yet; a Linux userland false-positive sweep.
- [ ] Later DB kinds: Ghidra FidDb import (Apache, library-function ID, format conversion); ClamAV `.ndb/.ldb`
  as a user-supplied runtime input (GPL data -- never bundled); richer capa features once disasm extraction lands.

## Heuristic flywheel (propose -> measure -> gate -> promote)

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#heuristic-flywheel-propose---measure---gate---promote).

- [ ] Additional bound/comparison forms (including `BC.cond`) and broader compiled scheduling acceptance.
- [ ] Masking for 32-bit ARM literal pools and MIPS `lui`/`addiu` pairs, once a cross-program fixture exists.
- [ ] Tool-ID remaining: Zig on stripped builds and PEs, Clang on Mach-O/PE (no producer record), the whole-file
  "rustc version" rule (tentative; scope or drop), real NSIS/Inno Setup installer fixtures, a Zig-language Mach-O
  fixture.
- [ ] PDB-backed type truth and automated proposal/gate/promote stages with held-out provenance and rollback.

## Ideas from adjacent projects (REA, Ghidra-MCP)

### REA gap-closing wave 1 (2026-10-29)

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#rea-gap-closing-wave-1-2026-10-29).

- [ ] Annotation log compaction. Without it, a log at its limits can only be read: renames, undo and the ledger
  are refused. Compaction would also close the remaining gap: a log whose checked state was cleared is still
  replayed checked on open, but ordinary sessions don't apply the checked cache budget, so more than about 2,000
  names there would make the checked open fail.
- [ ] Ledger: deleting entries, clearing optional fields, appending evidence on update.

- [ ] APK (JADX) and Electron unpacking are lower-priority follow-ons; carving is not archive extraction.
- [ ] .NET external or assembly-qualified enums, symbolic enum-attribute names, resource payloads,
  and comparison of `dotnet_il` with ildasm/ILSpy once available. Metadata bindings do not establish accessor behavior.
- [ ] Per-path pointer-comparison offsets. Nontrivial image selection
  does not load embedded snapshot JSON; pointer-peer flags alone would not establish usable support.

## Plugin system (later)

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#plugin-system-later).

- [ ] WASM component plugins (wasmtime is already a dependency via yara-x): sandboxed, language-agnostic code for
  detectors, format loaders and workflows behind a WIT interface; bytes plus read-only analysis queries in,
  findings out. The output schema enforces the evidence/confidence/limitations contract.
  The bounded triage-component milestone below implements the first explicit executable lane and genuine guest
  composition, not general detector/loader plugins, automatic discovery, or a stable public SDK. Static builtin
  registries remain separate. Broader capabilities and module migration require independent acceptance.

### Experimental triage component milestone

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#experimental-triage-component-milestone).

- [ ] Linux component gate is wired but not locally executed; cancellation inside compilation and uninstrumented
  guest-cancellation latency,
  broader source loading and component grammar, other workflow migrations, MCP/UI providers and a stable SDK
  remain unearned. The follow-up below adds opt-in installation and an instrumented activation checkpoint.

## Decompiler: embedded Ghidra (the decompilation path)

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#decompiler-embedded-ghidra-the-decompilation-path).

- [ ] C++ class recovery: typed vtables/RTTI and `this` pointers in the decompiler. The embedded library reads
  types from C declarations or XML, not Ghidra `.gdt` archives, so this needs a header/type pipeline, not a
  `.gdt` import. Larger, separate effort.
- [ ] Richer automatic `main`/entry signature recovery without debug metadata.

### Integration acceptance order

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#integration-acceptance-order).

3. [x] Compiler ABI selection: PE Windows and Darwin PowerPC defaults, explicit API/CLI overrides, strict
   compiler-ID/data-model validation and target-sized runtime declarations. Reviewed coverage includes
   ILP32/LP64/LLP64, Windows x86 cdecl, clangwindows aliases and all 13 bundled processor targets.
   - [x] ARM BE8 mixed instruction/data endian selection, preserved by compiler overrides.
   - [x] Darwin ARM64 fixed stack packing and explicit variadic slot allocator/compiler model.
   - [x] OS/library-specific typedefs: off_t/time_t/mode_t/pid_t prototypes sized by width placeholders, with the
     POSIX I/O and time functions that use them (documented 32-bit Linux off_t and 32-bit Darwin time_t edges).
    - [x] Declared Darwin ARM64 narrow integer input extension to 32 bits, preserving unknown upper bits and
      existing return rules. Owned compiled/recompiled C covers 58 comparisons; input-window controls include
      cloned models, packing, promotions and conservative malformed-spec refusals.
    - [ ] Remaining ABI-specific work: general Darwin ARM64 variadic call recovery and broader ABI/call correctness.
5. [x] Portable specification packaging and supervised resource/cancellation integration,
   including allocation-failure containment at the C ABI. This is not an OS sandbox or native memory-safety proof.
   - [x] Embed specifications, versioned verified cache and relocated executable regression without Ghidra.
   - [x] Bound text/token output; contain standard exceptions during decompilation.
   - [x] Opt-in supervised worker with wall-clock cancellation, bounded concurrent pipe I/O and memory enforcement
     (Linux hard limits; macOS sampled RSS), API/CLI/session integration without native fallback.
   - [x] Packaged sessions automatically select a sibling worker; install script ships worker and CLI together.
   - [x] Complete C ABI exception containment with allocation-free fallback and poisoned-state handling.
   - [ ] Other supervisor platforms and native upstream memory-safety remediation.
6. [ ] Persistent user types/signatures/calling conventions and typed globals, then debug-type imports and
   class recovery.
   - [x] Validated persistent signatures and type declarations, API/MCP tools and shared-log dependency checks.
   - [x] Validated persistent typed globals with complete mapped-data storage and dependency checks.
   - [x] Bounded embedded-DWARF scalar/pointer signature preview/import with non-overwriting application.
    - [x] Bounded named Itanium vtable/RTTI/code-slot class evidence; no asserted object layouts.
    - [x] Bounded read-only verification of parsed flat-struct layouts and ordered worker assertions for x86-64 GCC;
      independent compiled size/alignment/offset and field-use gates. Assertions are ephemeral, not debug imports.
    - [x] Separate checked embedded-DWARF flat-struct pointer import: explicit producer struct alignment, bounded
      C metadata, identity-qualified types, persistent assertions, frozen consent and one atomic dependency batch.
   - [ ] Exact aggregate/debug-layout import, external PDB/dSYM support and automatic class-layout recovery.
8. [ ] Versioned differential benchmarks: precision/recall, thunks, signatures/calls/strings/switches, warnings,
   coverage and time/memory across stripped/symbolized compiler/optimization/ABI corpora.
   - [x] Discovery precision/recall and installed Ghidra version instead of a hard-coded version.
   - [x] Versioned bounded corpus runner with explicit signature/call/string/switch assertions, failure coverage,
     timing and resource diagnostics; not an equivalence score.
   - [ ] Matched-setting differential decompilation corpus and coverage/runtime/memory metrics.

**This supersedes the hand-written "Deep ARM64 track" below as the route to decompiled output.** That native
IR/SSA/pseudocode work stays as complementary, evidence-bounded diagnostics (and feeds the function list the
decompiler works from); it is no longer the path to source recovery, so it is not worth hand-reimplementing what
Ghidra already provides (types, structuring, FP/SIMD, every architecture). Keep only the parts that improve
rampage's own discovery and CFG, which the decompiler depends on.

## Current status (native analysis track, now complementary)

Deep ARM64 support is **in progress**, not IDA/Ghidra parity or complete typed-source recovery.
Checked items below describe bounded, tested capabilities; sections marked partial still have acceptance work remaining.

### Darwin narrow inputs and aggregate-verification bridge

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#darwin-narrow-inputs-and-aggregate-verification-bridge).

- [ ] Full-workspace release gate: interrupted during compilation after an excessive optimized test-link rebuild;
  this is neither a suite pass nor an assertion failure. Focused release validation above passed with unchanged
  profiles.

### Verified-DWARF layout batch — initial bounded scope

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#verified-dwarf-layout-batch--initial-bounded-scope).

- [ ] Initial layout-batch optimized acceptance: the selected API/worker fixture build hit its five-minute cap
  while linking, before assertions. No optimized-suite success is claimed;
  release ThinLTO/codegen settings are unchanged.

### Usable typed-decompilation push

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#usable-typed-decompilation-push).

- [ ] Broader matched-setting C/C++ differential decompilation corpus and runtime/memory metrics. These initial
  independent compiler/source oracles are not that benchmark or general class-layout/virtual-dispatch acceptance.

### Bounded virtual-method evidence

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#bounded-virtual-method-evidence).

- [ ] Broad C++ differential/corpus/performance acceptance, typed virtual dispatch, inheritance and adjusting thunks.
  The owned source/compiler oracles and exact slot correlations do not earn these broader capabilities.

### Exact-entry analysis and local debugger workspace

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#exact-entry-analysis-and-local-debugger-workspace).

- [ ] New live end-to-end LLDB workspace acceptance, broader ABI/platform coverage and performance measurements.
  Owned protocol mocks and image fixtures do not establish arbitrary-host or third-party-runtime acceptance.
  The owned x86-64 live gate compiled but Apple LLDB refused launch with `Bad CPU type in executable` on the
  arm64 host, before UI observations. No Rosetta installation or ARM64 data-order guess bypassed that blocker.
- [ ] Larger matched-setting corpora; bounded host context does not promise constant latency, complete discovery
  context or cropped-image behavior.
- [ ] Windows debugging (9.6a): implemented through RSP stubs; live acceptance on a Windows host is open. The GDB
  remote backend is done (9.1).

### Deferred exact-entry UI and reviewed static workspaces

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#deferred-exact-entry-ui-and-reviewed-static-workspaces).

- [ ] Broader derived analysis caches and runtime cross-module resolution; the historical inventory and static PE
  declaration slices below do not complete these. Broader ABI/type recovery and affirmative
  ARM64 runtime DATA-order evidence remain open. The GDB backend and execution control landed in Phase 9.1–9.4 and
  Windows (live acceptance pending) in 9.6a; see `docs/plans/2026-10-29-debugger-control.md`.

### Static references, responsive file operations and historical inventory

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#static-references-responsive-file-operations-and-historical-inventory).

- [ ] Runtime/converted executable plugins, broader recovery and remaining TODOs are not part of this milestone.

### Validation and external blockers

Done items and notes are archived in [todo-archive.md](docs/plans/todo-archive.md#validation-and-external-blockers).

- [ ] Resolve the local `rust-objcopy` missing-`libLLVM.dylib` stripping warning; release tests still execute.
  - Command-local `DYLD_LIBRARY_PATH=<rustc-sysroot>/lib` resolves the installed tool's library lookup;
    permanent managed-toolchain repair remains open rather than patching rustup-owned executables.

## Deep ARM64 track and remaining work

### 1. Instruction semantics — partial

- [x] Immediate, shifted and extended ADD/SUB; logical operations; wide moves; multiply/divide; variable shifts.
- [x] NZCV, B.cond, CBZ/CBNZ/TBZ/TBNZ, CSEL/CSINC/CSINV/CSNEG, ADR/ADRP and plain BL/BLR/BR/RET.
- [x] Common non-wrapping bitfield aliases; 8/16/32/64-bit scalar memory with separate result/access widths.
- [x] Literal/register/unsigned/unscaled/pre/post addressing; 32/64-bit pairs and signed LDPSW.
- [x] Remaining common integer families: carry arithmetic (ADC/ADCS/SBC/SBCS, NGC/NGCS), conditional compares
  (CCMP/CCMN register/immediate), wrapping bitfields (SBFIZ/UBFIZ/BFI/BFXIL/BFC), long/high multiply
  (S/UMADDL, S/UMSUBL, SMULH/UMULH), EXTR/ROR immediate, CLZ/CLS/RBIT/REV/REV16/REV32, each with native
  boundary regressions (all 16 NZCV inputs for flag-dependent families, also through SSA/dataflow) and
  natively recorded expected values that replay on any host. FEAT_CSSC, RMIF and SETF8/16 remain barriers.
- [x] Valid no-writeback pair loads with base/destination overlap; capture both original addresses before
  assignments for LDP X/W and LDPSW. Writeback overlaps and duplicate destinations remain barriers.
- [ ] FP/SIMD, atomic/exclusive and selected system semantics, with effects and memory ordering explicit.
- [ ] PAC/authenticated flow, exceptions and platform-specific behavior; unsupported forms must remain barriers.

### 2. Stack, memory and signatures — partial

- [x] Integer AAPCS64 caller clobbers/callee preservation; X8 result-buffer and SP call dependencies.
- [x] Entry-SP-relative slots, conflicting-path unknowns, per-RET X0/X1 candidates and input-use argument evidence.
- [x] Exact-width constant-store forwarding with source IDs and all-path agreement; conservative alias boundaries.
- [x] Exact-width nonconstant entry-SP spill/reload aliases when all reaching paths agree. Original load
  observations and recovered-load provenance remain explicit; recovered pointers cannot restart stack-memory
  inference. Source clobbers, width/sign extension, aliases and budgets have behavioral regressions.
- [ ] Partial-width overlap reconstruction, safe cyclic-memory fixpoints and broader alias proofs. Calls,
  unknown aliases, conflicting paths and cyclic proofs remain unresolved.
- [ ] Stack-frame boundaries, outgoing stack arguments, saved-register roles and escaped-stack alias handling.
- [ ] Interprocedural signatures: argument count/types, void versus value, aggregate returns, varargs and FP/SIMD ABI.
- [ ] Propagate type constraints and reconstruct pointer/struct/class layouts; local operand roles alone are not types.

### 3. SSA and pseudocode — partial

- [x] Bounded register/memory SSA, predecessor-indexed phis, constants/affine stack reasoning and semantic gaps.
- [x] Redundant phi aliases, dominators, natural-loop evidence and conservative sequence/branch/single-body regions.
- [x] Labeled and `--structured` SSA pseudocode with explicit predecessor tokens and simultaneous phi bindings.
- [x] Execution comparisons cover both diamond arms, repeated loops and both loop-condition polarities.
- [ ] Minimal phi placement, dead-definition elimination and broader expression simplification without amplification.
- [x] Bounded non-fall-through switch regions with retained table entries and guard evidence; unsupported
  switch shapes preserve labelled SSA diagnostics rather than invented structure.
- [ ] Nested/multi-block loops, broader branch joins, fall-through switch regions and irreducible-flow handling.
- [ ] Typed variables, source-level expressions/returns and readable decompiler output distinct from SSA diagnostics.

### 4. Jump tables and indirect flow — partial

- [x] Conservative ADR/ADRP/ADD/MOV/LDR/BR/BLR discovery; calls/stores invalidate captured-memory assumptions.
- [x] Explicit bounded absolute64/signed-relative32 table inspection, without guessed dispatch bounds.
- [x] Image-validated SSA target evidence, including a spilled constant target.
- [x] Bounded AArch64 and x86/x86-64 dispatch recognition with proven unsigned bounds, read-only backed tables,
  validated destinations and branch-site evidence. Cross-block facts are revalidated after graph expansion.
- [x] Proven immutable switch cases feed discovery/CFG/xrefs as case edges, not function seeds, retaining table
  order and guard evidence. Other indirect-flow forms remain separate acceptance work.
- [ ] Mutable pointers only after alias/reaching-store proof; authenticated or unmapped targets remain unresolved.
- [ ] Fixtures for relative tables, duplicate targets, joins, loops, truncation, overflow and hostile index bounds.

### 5. Controlled runtime capture — initial gate complete

- [x] Successful permitted stopped-process capture, module UUIDs/bases, register provenance and original correlation.
- [x] Mapping-aware snapshot identity and durable identity-scoped annotation persistence, including addresses,
  permissions and endianness. Per-file provenance/register observations are not conflated by identity reuse.
- [x] Persist explicit decompiler configuration, module/source identities and navigation in reviewed workspace files.
- [ ] Persist derived analysis caches and broader reproducible analysis state; the manifest is not an engine cache.
- [ ] Multiple modules/threads and stripped/relocated images; module-qualified navigation and cross-module references.
- [ ] Broader debugger/platform integration, capture failure handling and provenance validation on larger fixtures.

### 6. Accuracy benchmark — partial

- [x] Synthetic snapshots, native instruction oracles, compiled fixtures and malformed-input/resource regressions.
- [x] Versioned, hash-/architecture-matched function-start reference imports; snapshot comparisons reject
  ambiguous identity.
- [x] Versioned x86-64/AArch64 matched-pair corpus for library ID, discovery, tool detection and DWARF-backed
  signature recovery. The committed 13-slice baseline gate passes at `6122f64`.
- [ ] Broader compiler/optimization/ABI coverage with instruction/stack/semantic and time/memory metrics.
- [x] Pinned read-only CI workflow: format, warnings-denied Clippy, ordinary macOS workspace/UI tests and selected
  opt-ins, the 13-slice evaluation gate, an explicit Linux core subset, and redacted HEAD/full merge-history
  secret scans that cannot silently inherit repository allowlists. Hosted gates passed at `ffc84e7`.
- [ ] Quantitative unsupported-coverage and per-analysis time/memory gates; CI job/step timeouts are not substitutes.
  - [x] Explicit corpus recovery-status/flag/count assertions and configurable elapsed-time assertions, with missing
    diagnostics/measurements and identity mismatches retained as unavailable. Controlled fixture recovery gates
    and runner regressions are wired into CI; these do not measure unsupported coverage or per-case peak memory.
  - [x] Three owned compiled-switch fixtures are included in tool-ID truth. The expanded slice measures 129/163
    correct expected tools (recall 0.791411, precision 1.0); its floor is raised to 0.7914, not weakened. This is a
    corpus-denominator change, not a detector improvement or a rewrite of historical measurements.
- [x] Ghidra exports compare function starts, blocks, CFG edges and calls on 18 fixtures; reference output is
  not ground truth, and normalized chain agreement is not decompiler or semantic equivalence.
- [ ] IDA exports/comparisons once an installation is available.
- [ ] Expand beyond current CFG/call and signature metrics to dispatch truth, stack evidence and semantics.

### Next execution order

1. [x] Resolve the earlier full-debug timeout and complete debug/release workspace validation.
2. Extend common integer semantics and nonconstant spill recovery, keeping alias boundaries conservative.
3. Recover bounded dispatch tables and integrate proven targets into CFG/discovery with regression fixtures.
4. Broaden structuring and type/signature propagation; keep SSA diagnostics separate from recovered source.
5. Build the versioned accuracy corpus/CI gates and complete persistence/cross-module runtime work.

Native IR/SSA remains complementary to the embedded Ghidra decompiler above. Vendored Ghidra implementation
and specifications retain their Apache-2.0 license and attribution; any additional copied/ported components
require their applicable license and attribution.

## General-purpose reverse-engineering roadmap

### Transformed static code and runtime analysis

Successful loading, discovery and C emission do not establish usable recovery. High entropy, invalid decoding,
unresolved wrapper jumps, missing debug types and absent named vtables need explicit diagnostics. These are
evidence and limitations, not proof of encryption or verified function counts.

Work in this order, with synthetic regressions and independent review for each increment:

1. [x] Structured recovery diagnostics: export engine warnings, bad-data/unimplemented flags and unresolved
   calls/jump tables. Surface warnings in CLI/API/MCP/UI and separate successful output from usable recovery in
   benchmarks; no unqualified "complete" or "clean implies correct" label.
2. [x] Discovery-confidence summaries: relate candidates to bounded sampled regions and preserve evidence for
   suspicious tiny fragments, invalid decode and code/data ambiguity. Do not silently delete candidate functions
   or infer encryption from entropy alone. Use cached discovery modes; whole-program discovery is an explicit
   opt-in (`audit --include-discovery` / MCP `include_discovery`), not a hidden prerequisite for sampling.
3. [ ] Authorized capture workflow: bounded module/range selection and actual memory-permission checks in the
   stopped-process LLDB exporter, capture failures and provenance. No automatic plugin launch, installation,
   debugger attachment or target-memory writes; controlled live tests use our own fixtures.
   - [x] Exact mapping permissions, bounded inspection, complete reads, expression-stop identity checks and
     atomic no-clobber publication; breakpoint normalization recorded in provenance.
   - [x] Explicit UUID/original-address range and seed selection with checked slides, section coverage and
     conflicting-mapping rejection; controlled live fixture validation.
   - [ ] Broader multi-thread/module capture acceptance and module-specific byte-order context.
   - [x] Explicit bounded thread selectors/all-thread register capture, stop-context and module-provenance
     revalidation; controlled live acceptance covers two owned modules and two threads.
4. [ ] Runtime target identity: persist platform/compiler context, mapping-aware capture identity and module/
   thread provenance so an ARM64 macOS capture does not silently use generic AAPCS64 decompilation defaults.
   - [x] Validated optional platform/compiler context, exported by LLDB and used by native/worker defaults.
   - [x] Canonical mapping-aware triage identity and normalized UUID-duplicate validation.
   - [ ] Broader thread/module provenance consistency checks, module-specific code/data endian validation
     (including ARM BE8), and persisted session reuse by capture identity.
   - [x] Identity-scoped annotation persistence and snapshot revalidation; equal captures can share logs without
     conflating per-file provenance/register observations. Legacy unscoped logs are reported, not migrated.
5. [ ] UUID-validated static/runtime comparison: compare explicit matching captured ranges, retain byte-change
   and unavailable-range evidence, transfer only justified symbol/type information with checked ASLR slides.
   - [x] Bounded API/CLI byte comparison with equal/changed/unavailable spans and capture/original identities;
     annotation-free explicit inputs and controlled live comparison.
   - [ ] Reviewed symbol/type-transfer policy and runtime comparison navigation/agent integration.
   - [x] Shared agent/MCP byte comparisons with paginated spans, full-range totals and identities;
     fresh explicit MCP inputs bypass annotation sidecars and discovery.
6. [ ] Captured indirect-call evidence: show wrapper slot/value/target observations separately from proven flow;
   writable, authenticated, unmapped or incomplete pointers remain unresolved without additional evidence.
   - [x] Explicit API/CLI/MCP pointer-slot observations with raw values, permissions and mapping identity;
     no edge insertion, no authentication/high-bit stripping and checked ARM mode tags.
   - [ ] Link observations to decoded branch sites, module-qualified targets and before/after capture evidence.
   - [x] Bounded explicit ARM64 branch-window links to decoded slot loads, retaining indirect flow and
     raw observations; unsupported/control-flow/authenticated/incomplete cases remain explicit.
   - [x] Explicit API/CLI/MCP paired-slot comparisons across captures with raw equal/changed/unavailable outcomes,
     independent mapping/target assessments and capture identities; no inferred chronology or module ownership.
7. [ ] Authorized runtime acceptance: an analyst supplies an already-loaded/stopped instance in a legitimate host;
   capture selected code and referenced data, correlate the original UUID, rerun diagnostics/decompilation and
   report before/after warning/coverage metrics. This is blocked on an authorized host capture, not static parsing.

Third-party plugin bytes and captured process contents are local investigation inputs, not committed fixtures.
Patching is not part of this work.

Acceptance gate for each milestone: behavioral regressions, malformed-input tests, `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, workspace tests, and independent review. Third-party samples are
read-only triage inputs, never patch fixtures. Runtime tests use programs we build ourselves.

- [x] Initial runtime images: validated sparse snapshot format, CLI/API/UI loading, explicit code seeds, provenance,
  virtual-address handling and controlled LLDB export/correlation. Persistence and cross-module work remain above.
- [ ] Indirect flow: the conservative AArch64 ADR/ADRP/ADD/MOV/LDR/BR/BLR foundation is done (below). Remaining:
  other architectures, and proven targets feeding discovery/CFG (Deep ARM64 track 4). Unknown, authenticated,
  mutable and unmapped targets must remain unresolved.
- [x] Analysis confidence: `audit`/`analysis_diagnostics` explain decode coverage and unreliable-code evidence over
  sparse memory without asserting encryption (below).
- [x] Language metadata: C++/Rust demangling with original lookup names, named/stripped Itanium/MSVC RTTI,
  and bounded Objective-C classes/categories/methods/ivars/properties/protocols with malformed-pointer tests.
  Objective-C metadata handles relative methods and static chained-fixup rebases; it is not runtime PAC recovery
  or automatic C++ object-layout reconstruction.
- [x] Data-flow/decompilation: structured function summaries shipped, and decompilation comes from the embedded
  Ghidra decompiler. The native IR/SSA work continues as diagnostics in the Deep ARM64 track; it is never
  labelled a decompiler.
- [ ] Containers and workspaces: bundle discovery and inventory of already-extracted packages are done (below).
  Remaining: nested-archive inspection with extraction budgets (never executing installers) and cross-module
  navigation with address/module identities.

### Next acceptance-driven milestones

1. **Runtime integration:** extend the verified controlled capture to persistence, mapping-aware identities,
   multiple modules/threads and module-qualified navigation.
2. **Data-flow:** extend exact constant-store forwarding to nonconstant values, partial overlaps and safe loops;
   establish alias proofs before enabling mutable snapshot pointer inference.
3. **IR and SSA:** extend semantics/calling conventions, minimal phi placement and expression simplification;
   compare lifted execution with native fixtures at overflow, width, zero-register and flag boundaries.
4. **Language recovery:** stripped Itanium/MSVC vtables, class layouts, Objective-C method/class references,
   relative/authenticated pointers, DWARF/PDB integration and fixture-based malformed metadata validation.
5. **Decompilation:** expressions, conditions, loops, returns and typed variables over SSA; output must explicitly
   show semantic gaps and must not present unsupported paths as recovered source.
6. **Containers/workspaces:** safe archive indexing/extraction budgets, module-qualified names/addresses,
   dependencies, cross-module references and UI/MCP navigation; never execute installer scripts.
7. **CLI batch workflow:** first-class multi-architecture analysis reports with bounded function selection,
   per-command timeouts, recovery diagnostics and comparison summaries; avoid external orchestration for routine
   static/runtime retests. Keep candidate counts, weak signature proposals and recovered code distinct.
   - [x] Single-image guided reports through `rampage report` and the shared workflow registry, with bounded
     findings, evidence/confidence, explicit truncation and next-step tool calls.
   - [x] `rampage binary analyze` composes selected workflows and supervised function decompilations across supported
     declared architectures; slice failures, identities, warnings and output-limit outcomes are retained in
     bounded valid JSON. Text output includes workflow findings and failed previews, not just query completion.
   - [ ] Runtime comparison report composition and workflow-wide wall-clock/memory supervision. The current
     deadline bounds each supervised decompilation request; workflows retain their existing work/output budgets.
   - [x] Noun/verb command hierarchy with shared argument definitions and typed normalization; flat spellings
     remain hidden compatibility commands. Nested pack ordering and cross-level image dependencies are validated.
8. **Debugger integration:** plan an LLDB-first read-only bridge after static acceptance, with explicit session/
   stop identities, module/thread navigation, quiescent capture manifests and agent/UI queries. Attach, resume,
   breakpoint insertion and target writes require separately reviewed controls; no automatic host or plugin launch.
   Superseded for execution control by Phase 9 (`docs/plans/2026-10-29-debugger-control.md`): resume, step,
   breakpoints and writes now go through the reviewed `debug` tools; rampage still never attaches or launches.
   - [x] In-session `rampage-query` foundation for session/module/thread, fresh-register and raw-memory queries,
     with bounded JSON, stale stop tokens, exact known permissions and honest endian/stop evidence. Controlled
     owned-fixture acceptance covers Apple LLDB; no command passthrough, attach/resume/evaluation/writes/listener.
    - [x] Explicit local Unix transport, typed API/CLI/MCP and local-only UI window, with reviewed cancellation safety;
      EOF before querying, bounded framing/I/O, stale tokens and structured errors retained. Endpoint paths remain
      for operator cleanup; no automatic attach/resume/expression/target-write controls.
     - [x] Stop-pinned UUID-qualified image/load address observations via bounded section/ancestor evidence,
       surfaced in typed queries and a manual local UI template. No basename/slide fallback or automatic navigation.
     - [x] Explicit local navigation to an already-open matching static Mach-O's file address, with typed
       request/result/workspace bindings, UUID/variant/width/endian/backing/permission gates and input invalidation.
       Original mapping-descriptor identity guards observable source changes; debugger painting avoids mapped reads.
       This is neither atomic source reading nor equal-byte/current-stop/flow/layout proof.
     - [ ] Broader static-format navigation and SDK/platform acceptance.
      Query observations remain non-atomic. A disposable-host experiment subsequently exercised live read-only
      queries; broader external-plugin runtime acceptance remains open (see the active investigation queue above).

Committed-foundation validation includes full debug/release suites, warnings-denied Clippy, UI snapshots,
CLI/API/MCP regressions, malformed-input bounds, native/compiled fixtures, exporter tests, the opt-in live
capture test, debugger-cleanup regressions, Ruff/ty and independent reviews. The earlier full-debug timeout
was the one-time vendored C++ build; subsequent debug/release workspace suites passed.
