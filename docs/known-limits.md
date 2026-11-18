# Known limits

What rampage does not do, or does only partly, as of 1.7.0. The
[comparison with Ghidra, IDA and REA](comparison.md) sets these against other tools, and the
[stability policy](stability.md) says which areas are *experimental*.

## Hosts

| Host | Status |
| --- | --- |
| macOS on Apple silicon | Tested; the primary development host. |
| macOS on Intel | Untested. It should build from source, but no one has run the test suite on it. |
| Linux x64 (Ubuntu 24.04) | Supported: CI builds and tests the whole workspace; the desktop UI is untested there. |
| Linux ARM64 (Ubuntu 24.04) | Supported: CI builds and tests the whole workspace on a native ARM64 runner; the desktop UI is untested there. |
| Windows | Not supported as a host in 1.0; planned for 1.x. |

Prebuilt archives cover macOS on Apple silicon, Linux x64 and Linux ARM64 only; other hosts build from source, see
[getting started](getting-started.md#what-you-need) for the prerequisites.

## Decompilation and safety

- **The worker is optional, and without it decompilation runs in-process.** rampage decompiles in a supervised
  `rampage-worker` process when it finds one: `RAMPAGE_WORKER`, or `rampage-worker` beside `rampage`. When it
  finds none, `decompile` runs Ghidra's native decompiler inside the `rampage` process itself, without the
  worker's time, memory and output limits. The MCP server warns on stderr at startup when it has no worker, and
  every `decompile` result names where it ran in its `decompiler` field (`supervised` or `in-process`). Start the
  server with `--require-worker` (or use the CLI's `decompile --isolated`) to refuse to decompile without the
  worker instead.
- **Worker supervision is not an OS sandbox.** It bounds time, memory and output. Analyse hostile files in a VM or
  container if you need isolation.
- **Decompiled C is not proof** that the recovered program is correct. Results report their recovery issues.
- Only MSP430, AVR8 and Cortex-M decompile among the Raw processor profiles; the others disassemble only.

## Analysis

- `search` runs under work budgets. Reference search decodes only the blocks that hold a matching reference, and
  wildcard byte patterns scan for their longest fixed run first, so both complete on a 26 MB stripped Go binary;
  a wildcard pattern whose fixed runs are short or common still covers less of a large image than an exact
  search, and a stopped search says so.
- The Cortex-M Raw profile (`ARM:LE:32:Cortex`) is experimental. Its backed regions hold at most 4 MiB in all
  (a compressed primary region at most 8 MiB encoded), with up to 15 regions beside the primary one, listed by the
  analyst or mapped from the startup copies the reset-code follow finds. The base address is the analyst's
  assertion: `base_candidates` and `raw.base_check` suggest and check one, never set it. A-profile ARM code has no
  Raw profile; `inspect_raw_code` reads it, without functions, cross-references or decompilation.
- The reset-code follow on Cortex-M models the integer Thumb instructions startup code uses. A call through an
  instruction it does not model (long multiplies, saturating and SIMD-within-register arithmetic, LDREX/STREX,
  SVC) or a branch on a peripheral's value is skipped, and a copy that call made is not mapped. Other Raw profiles
  have no reset-code follow.
- On Raw projects `find_main` models Cortex-M reset code only, and finds a main that never returns. `decompile`
  with `exact_entry` takes Raw Cortex-M Thumb code but refuses other ARM code (A32, Thumb in ELF, PE or Mach-O);
  plain `decompile` takes any code address there.
- Raw Cortex-M discovery's record pass and pointer-table scan stop at work budgets (1,000,000 record words and
  decodes; 2,000,000 decodes per region scanned), and say so in `raw.record_seeds.truncated` and
  `walk_budget_exhausted`; `find_main` and the starting points follow at most 50,000 startup instructions.
- A Raw selector with `decode` decodes its input again on every call before the session finds the project, and
  `inspect_data` opens Raw images outside the session, so analyst names do not resolve in its `at` and its 16 KiB
  input budget refuses large selectors.
- Container records (the words before a compressed stream naming its length, decoded size, checksum and address)
  are reported by `probe_compression`, `decode_file_range` and `integrity_checks`, not by `carve` or `file_layout`;
  their roles are inferred from values.
- An odd address formed into a Cortex-M image that does not start a printable NUL-terminated run is still taken
  as a Thumb code pointer; odd-aligned binary constants can become false function starts.
- Go string literal bounds come from code references and pointer-aligned static `{ptr, len}` headers in data
  that point into a printable region of the string blob. Code references win: a header may not run across a
  code-referenced start, and disagreeing header lengths give only a start. Not covered: literals that start with
  `\n` or a non-ASCII byte (the pointer must land on printable ASCII); headers in externally linked ELF PIE
  images, whose pointer words are stored as 0 and filled by RELA relocations; and headers the program builds at
  run time. The scan stops after 256 MiB of data or 1,048,576 candidates, and `list_strings` notes then say some
  starts are missing. Such literals still end at the next referenced literal.
- Encrypted or packed code is detected, not unpacked: a stretch of code judged `likely_encrypted_or_packed` (see
  [triage](features.md#triage-and-detection)) is left out of function discovery, so a protected or packed binary
  lists only the functions in its clear code (a packer's stub included), and symbols, exports and function starts
  inside the stretch are counted, not analysed. `decompile` refuses there unless given `explore_encrypted=true`
  (CLI `--explore-encrypted`). The judgement needs both signals: high-entropy code on an architecture where nearly
  every byte sequence decodes (8-bit microcontrollers) is never judged, and runs under 8 KiB are not judged. The
  edges of a judged stretch are placed to within 512 bytes, so a little clear code next to it may be left out.
- The [persistent analysis store](mcp.md#persistent-analysis-store) (experimental) saves function discovery
  only (on by default in release builds): other derived results are recomputed on each open, runtime captures and
  byte-patched views are never stored, and an annotation edit does not trigger incremental re-analysis.
- Firmware filesystem images: UBI and UBIFS are recognised but not read; vendor SquashFS variants, SquashFS 3.x,
  delta OTA payloads (they need the previous build), compressed tar, and ZIP members that are encrypted or use a
  method other than stored or deflate are not read. `carve` finds SquashFS, ext2/3/4, Android sparse, OTA payload,
  cpio and tar images inside a container (pass the offset as `image_offset`), but not UBI, UBIFS, JFFS2, YAFFS2,
  CramFS or vendor headers. Inside a SquashFS, Android sparse or OTA payload image it reports only executables, and
  inside an ext, tar, cpio or ZIP image only candidates whose headers validate; each image's notes count the rest.
- `endpoint_inventory` matches endpoints lexically: addresses built at run time, encrypted or compressed data and
  IPv4 addresses stored as integers in code are not found. `privacy_surface` on a directory analyses only programs
  that import a capture API or name a capture device, and matches init files to programs by path; see its
  [limits](privacy-surface.md#limits).
- Android: DEX files are read and Dalvik bytecode is listed (`dex_metadata`, `dex_code`, with a structured
  pseudocode view), but not decompiled to Java, and DEX code is not part of function discovery or xrefs.
  `privacy_surface` on an APK follows a call graph of direct invokes, virtual and interface invokes resolved through
  the app's classes (by name to overrides, marked `by_name`), callbacks and const-class component starts, within 6
  levels and 2000 methods per walk: reflection, method handles, framework code and run-time loaded code are not
  followed, and keep `no_user_trigger` from being stated. Strings hidden behind decoders are recovered only for
  static decoder methods called with constants and running within a small interpreter's model (no I/O, reflection,
  instance fields or app objects) and budgets. JNI methods registered with `RegisterNatives` are only suggested by
  the strings a library holds; the registration table is not decoded. Obfuscated names are shown as stored;
  `resources.arsc` is counted, not resolved, so `@0x7f...` manifest values stay resource ids; an AAB's protobuf
  manifest and APK signature blocks are not read; a DEX 041 container with several DEX files has only its first read
  (and says so). JVM class files are not read.
- Not built yet: object-file relocation, Swift metadata, C++ class-layout recovery beyond RTTI and
  vftable evidence, `__CxxFrameHandler4` and Itanium exception tables, and incremental re-analysis after edits.

## Library identification

- Bundled signatures recognise the library builds they were made from, not every version of a library.
- The bundled corpus's recall on matched library versions is below the 80% the project aims for; see the
  [signature corpus](signature-corpus.md).

## Annotations

- The annotation log has no compaction. A log that reaches its size limits can only be read; see
  [MCP edits](mcp.md#edits-and-session-state).

## Debugging

- rampage never launches or attaches to a process: it connects only to a GDB remote stub the operator started.
- Apple `debugserver` and Windows targets through `gdbserver.exe` or `lldb-server` are *experimental*: tested
  against protocol transcripts. `debugserver` also passed a live acceptance run on arm64 macOS (2026-11-11:
  break, step out, watch, interrupt and snapshot); the Windows path has not run against a live target.

## Data disclosure

rampage itself uploads nothing, but an AI client sends tool results (strings, disassembly, decompiled code) to
its model provider. Make sure you may disclose that material; see
[data disclosure](mcp.md#authorization-and-data-disclosure).

## Benchmarks

The [head-to-head benchmarks](benchmarks.md) use one model and one client, on tasks written by the rampage
project. They are not general accuracy guarantees.
