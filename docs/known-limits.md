# Known limits

What rampage does not do, or does only partly, as of 1.9.0. The
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
  search, and a stopped search says so. On 32-bit ARM and Thumb an immediate search matches only constants
  loaded from a literal pool or built by a MOVW/MOVT pair in one block (`loaded_constant`), so its total is always
  a lower bound; see [search](search.md).
- MIPS: the global pointer is the image's `_gp` (or the GOT plus 0x7ff0), one per image; multi-GOT objects
  (very large shared libraries with several GOTs) resolve only through their primary GOT. `$t9` is known only in
  runs that start at a function's entry, so `disassemble` from an arbitrary address shows no GOT references a
  function's prologue sets up. MIPS16e code is decoded only in a 32-bit ELF whose header marks it
  (`EF_MIPS_ARCH_ASE_M16`, as every OpenWrt MIPS16e program's does): a Raw MIPS image, or a file whose header does
  not say so, is read as MIPS32 only, and 64-bit MIPS16e instructions are not decoded. microMIPS is not decoded at
  all, and MIPS64 has no Raw profile. An ELF whose header marks microMIPS, or MIPS16e on MIPS64, gets a
  `binary_info` warning and a `list_functions` note saying so; there `jalx` calls into the other instruction set are
  kept as calls whose target is not followed, and symbols, exports or entries at addresses that are not 4-byte
  aligned (the ISA bit) seed no function. In MIPS16e code, `addiu rx, $pc, imm` and `lw rx, imm($pc)` are shown with
  their encoded offsets, and the instruction-set mode of a MIPS16e function reached only through a function pointer
  in relocated data is not known. A function that only spins (`j .`) is not inferred to never return, so a decompiled caller can run on
  into the data after its last call (`halt_baddata`). Constant search on MIPS matches typed immediates and
  `lui` pairs completed in one block (`loaded_constant`); other sequences are not matched. `integrity_checks`
  takes a 16-bit CRC polynomial immediate as evidence only in a function that also shifts by one bit and XORs, so
  a table-driven CRC-16 without a table in the image is not found. Position-independent switch tables (`.gpword`
  entries added to `$gp`) are not recovered, so case blocks reached only through them, and functions called only
  from those blocks, are missed.
- ELF files without section headers (OpenWrt strips every program with `sstrip`) have their dynamic symbols,
  imports, exports and import slots read through `PT_DYNAMIC`. The symbol count comes from `DT_MIPS_SYMTABNO`,
  `DT_HASH` or `DT_GNU_HASH`; a file with none of them lists no dynamic symbols (the count is not guessed), and on
  64-bit MIPS import slots come only from the GOT, not from relocations. Without sections, `.MIPS.stubs` lazy-binding
  stubs stay unnamed and symbols of the static symbol table are gone. Functions reached only through function
  pointers in relocated data are not seeded on any architecture; `DT_INIT`, `DT_FINI` and the init and fini arrays
  are.
- Decompiling MIPS position-independent code folds loads from read-only mappings, as on Cortex-M, besides the
  local GOT entries it marks read-only: Ghidra prints `.rodata` text as string literals only with that property,
  and one switch governs both. A program that writes its own read-only segment (through `mprotect`) would read as
  constants there.
- The MIPS32 Raw profiles (`MIPS:BE:32:default`, `MIPS:LE:32:default`) are experimental: no vector-table,
  pointer-table or scatter-load support, and the exception vectors at the base plus 0x200 and 0x380 are not seeded.
  Raw MIPS decompilation shows string arguments as addresses unless a callee prototype types them.
- The Cortex-M Raw profile (`ARM:LE:32:Cortex`) is experimental. Its backed regions hold at most 4 MiB in all
  (a compressed primary region at most 8 MiB encoded), with up to 15 regions beside the primary one, listed by the
  analyst or mapped from the startup copies the reset-code follow finds. The base address is the analyst's
  assertion: `base_candidates` and `raw.base_check` suggest and check one, never set it. A-profile ARM code has no
  Raw profile; `inspect_raw_code` reads it, without functions, cross-references or decompilation.
- The reset-code follow on Cortex-M models the integer Thumb instructions startup code uses. A call through an
  instruction it does not model (long multiplies, saturating and SIMD-within-register arithmetic, LDREX/STREX,
  SVC) or a branch on a peripheral's value is skipped, and a copy that call made is not mapped. Other Raw profiles
  have no reset-code follow.
- Xtensa (ESP32, ESP8266) is experimental. The decoder covers the core ISA with the windowed, loop, MUL/DIV,
  MIN/MAX, boolean and single-precision options; MAC16, the ESP32-S3's vector (PIE) instructions and FLIX bundles
  are rendered by opcode or refused, and big-endian Xtensa and the LITBASE option (literals addressed from a base
  register) are not decoded. ESP ROM functions are called by address and not named, and calls through
  `-mlongcalls` resolve only when the `l32r` and the `callx` are in one straight-line run. Discovery seeds windowed
  functions from `entry` prologues and call0 functions from a frame-allocating `addi a1, a1, -N`, so a call0 leaf
  reached only through a pointer is missed. The decompiler uses Ghidra's Xtensa model, whose windowed calls go
  through its register fixups. It does not model zero-overhead loops: the body of a `loop`/`loopnez`/`loopgtz`
  reads as running once (a bitwise CRC's eight-step inner loop shows one step), so check such a function with
  `evaluate_function` or its listing. `evaluate_function` models windows and
  zero-overhead loops but not window overflow exceptions, so call chains deeper than the hardware's register file
  run as if the file were unlimited. ESP app images are read as the ESP8266 and ESP32/S2/S3 bootloaders load them:
  ESP8266 `0xEA` (rBoot, v2) images and encrypted flash are not decoded, and secure-boot signatures are not
  checked. `find_main` finds `app_main` only through ESP-IDF's `main_task` log lines. ESP8266 discovery finds fewer
  functions than ESP32 discovery: on a public MicroPython build it found 61% of the symbol table's starts (91% in
  IRAM, 60% in flash-mapped IROM), against over 99% on ESP32 builds. A flash dump is read from flash 0x1000 only when
  it starts with an ESP32 or ESP32-S2 bootloader or its partition table at file 0x7000 points at application images
  0x1000 bytes early; other dumps that start part-way into flash are read as if they started at flash 0.
- On Raw projects `find_main` models Cortex-M reset code, and finds a main that never returns, and MIPS reset
  code: it follows jumps taken before `$sp` is set (`b reset` over the exception vectors) and takes the first
  forward jump after it, or a kseg1-to-kseg0 jump, as the C entry; a C entry reached by a call is not found. `decompile`
  with `exact_entry` takes Raw Cortex-M Thumb code but refuses other ARM code (A32, Thumb in ELF, PE or Mach-O);
  plain `decompile` takes any code address there.
- Code that only a function pointer or a computed address reaches stays undiscovered on Raw Cortex-M unless a
  pointer table, data record or inferred CRC routine seeds it; `xrefs` to a function then finds no caller and its
  `notes` name any Thumb `bl` in undiscovered code that targets it. `lock_mechanisms` analyses only the functions
  its evidence selects (`coverage.functions_analyzed` of `functions_discovered`).
- A vector table the program builds in RAM at run time (VTOR set to memory with no bytes in the image) is not
  read: `raw.scatter_load.vector_table_refused` says so, and its interrupt handlers are not seeded.
- Raw Cortex-M discovery's record pass and pointer-table scan stop at work budgets (1,000,000 record words and
  decodes; 2,000,000 decodes per region scanned), and say so in `raw.record_seeds.truncated` and
  `walk_budget_exhausted`; `find_main` and the starting points follow at most 50,000 startup instructions.
- An ARM code address with the Thumb bit set is read as Thumb only where the code is known to be Thumb (an
  M-profile image, a Thumb range, or a mode discovery learned there); elsewhere the odd address is used as given,
  with a note.
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
- The [persistent analysis store](mcp.md#persistent-analysis-store) (experimental, on by default in release
  builds) saves function discovery and decompiled functions only: strings, Go and DWARF type indexes, signature
  matches (`identify_functions`) and workflow results (`triage_report`, `integrity_checks`, `lock_mechanisms`) are
  recomputed in each process, and runtime captures are never stored. Invalidation after an edit is coarse: a
  comment or finding keeps every stored decompilation, but any other edit (a rename included) makes every stored
  decompilation of that binary miss, and each is decompiled again when next asked for. With
  `GHIDRA_INSTALL_DIR` set, decompilations are not stored. Entries are checksummed, not authenticated: the checksum
  is not a MAC, so anyone who can write the store file (mode 0600, so the user or root) can change what a later
  open or decompilation returns.
- Firmware filesystem images: vendor SquashFS variants, SquashFS 3.x, delta OTA payloads (they need the previous
  build), compressed tar, ZIP members that are encrypted or use a method other than stored or deflate, UBIFS
  extended attributes and fscrypt-encrypted UBIFS content are not read; UBIFS HMAC authentication is not checked,
  and UBI eraseblock sizes must be powers of two from 4 KiB to 16 MiB. `carve` finds SquashFS, ext2/3/4, UBI,
  UBIFS, JFFS2, CramFS, Android sparse, OTA payload, cpio and tar images inside a container (pass the offset as
  `image_offset`), and TRX, device tree, MBR/GPT, FAT and UEFI containers, but not YAFFS2 (no checksum to tell it
  from data) or vendor headers (TP-Link, CFE, Seama, JBOOT). MBR and GPT disks are found only at 512-byte-aligned
  offsets with 512-byte sectors, FAT volumes only with the "FAT" type string in their boot sector, UBI images only
  with power-of-two erase blocks, and LZ4 and lzop streams have no extent. Inside a SquashFS, UBIFS, JFFS2,
  CramFS, Android sparse or OTA payload image it reports only executables, and inside an ext, UBI, tar, cpio or ZIP
  image only candidates whose headers validate; each image's notes count the rest. Past 65,536 candidates left out
  inside images, the rest of the image being scanned is skipped (a limitation says where). `fs_list` does not read
  JFFS2, CramFS or the containers.
- `diff_firmware` (experimental) analyses only changed programs: added and removed ones are listed (with the
  endpoints they name), not analysed. It finds headerless code by itself only for Cortex-M (a vector table, or an
  LZSS or LZ4-block payload behind a header that describes it) and ESP images; MIPS, Xtensa without an ESP header
  and other Raw profiles need `as_raw` per side. Payloads in other codecs or encrypted ones compare by digest, and
  secure-boot signatures are not verified. Each run is budgeted (time, 8 code images by default, a fixed 2 GiB
  read, 64 MiB per analysed image); what a budget leaves out is listed. The time budget is soft: one image's analysis
  is not interrupted once started. On Cortex-M a change that only moves code, data or padding is not reported; a
  change in instruction selection for the same source (another register, a narrower encoding the normalisation does
  not cover) is. Between two ESP32 application builds, Xtensa code that only moved is still reported as changed: on
  a public MicroPython point release 546 functions were reported changed where about a dozen changed size.
  microMIPS programs compare no functions. See [firmware version diffing](firmware-diffing.md#limits).
- `check_claim` (experimental) can only be as certain as its method.
  - A `computes` verdict is verified on the generated inputs only (`sampled`).
  - Static kinds see discovered code and recorded references, not run time.
  - `calls … before` does not check whether a path is feasible, so a mixed answer stays unknown.
  - An absent reference or constant is never refuted.
  - `computes` cannot yet state an end-pointer argument, a context structure or a length in words.

  See [checking claims](claim-checking.md#limits).
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
- `evaluate_function` (experimental) interprets p-code, not the processor: system calls, imports without a
  model, AVX-512, AES/SHA/`pcmpistri`, x87 `fsin`/`fcos` and other transcendental operations, NEON arithmetic and
  half-precision conversions that Sleigh leaves as processor operations stop the run. The library models leave out
  `%f`-style conversions and `%n`, `vsprintf`-style `va_list` functions, and aligned and placement `operator new`.
  Argument buffers read as zero-padded to their page end, so an unterminated buffer looks terminated. Floats round to nearest even (a rounding mode set at
  run time is not modelled), x87 arithmetic is computed in double precision, and a fused multiply-add rounds twice,
  so a float result can differ from hardware in its last bits. MIPS, PowerPC and RISC-V take no float arguments or
  results. A `string_decoding` replay starts at the block holding the call, so arguments the caller set up in
  earlier blocks are not seen.
- Not built yet: object-file relocation, Swift metadata, C++ class-layout recovery beyond RTTI and
  vftable evidence, `__CxxFrameHandler4` and Itanium exception tables, and per-function (rather than
  per-binary) invalidation of stored decompilations after edits.

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
