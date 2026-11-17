# Changelog

All notable changes to rampage are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org);
see the [stability policy](docs/stability.md) for what the version promises.

## 1.7.0 (2026-11-17)

- Shorter tool descriptions: an agent session's default `tools/list` is 26% smaller (134,699 to 99,455 bytes, about
  8,800 fewer tokens; 24% smaller with every group), and the server instructions leave 358 characters spare before
  Claude Code's cut. Descriptions keep when to use each tool, required arguments, side effects and key outputs; the
  caveats and limits they dropped are in the [MCP reference](docs/mcp.md#tool-details). `inspect_data` no longer
  lists the full Raw request schema beside its compact `raw` selector. Field names, types and required arguments are
  unchanged; description text is outside the stable surface (docs/stability.md). A new test fails if the default
  list grows past its budget.
- Android APKs and DEX files: the new `android` group's `dex_metadata` reads an APK, AAB, JAR or DEX file (or a
  directory of them): package, versions and SDK levels, permissions with their platform protection level and a
  privacy category, components with intent filters, exported state and start-at-boot receivers, native libraries
  per ABI with their `Java_*` JNI exports, DEX 035–041 files with checksum and signature checks, and pages of
  classes, methods, components, permissions, native libraries or DEX files; the summary stays within its byte
  budget with `*_total` counts. The DEX, binary XML and manifest readers are in-house (new crate
  `rampage-dex`) and capped against hostile input. `dex_code` lists one method's Dalvik bytecode, smali style:
  all 256 opcodes and the switch and array payloads, with strings, types, fields, methods, protos, call sites and
  method handles resolved, try ranges with catch types, paged by instruction or from a code address.
  `dex_metadata`'s `privacy` section lists the Android capture and personal-data APIs the DEX code invokes
  (`AudioRecord`, `MediaRecorder`, camera and camera2, `MediaProjection`, `SpeechRecognizer`, location,
  device identifiers) with their callers, whether the manifest requests the guarding permission, and the
  start-at-boot receivers that reach them, plus `AccessibilityService` subclasses. Its `jni` section links each
  declared `native` method to the `Java_` export that binds it (short or long mangled name), names the libraries
  with `JNI_OnLoad` that likely register it by table, and lists exports no native method claims. See
  [Android APKs and DEX](docs/android.md).
- `privacy_surface` reads APKs and DEX files: capture sources are the Android capture APIs each method invokes,
  sinks the network calls (`URL`, `HttpURLConnection`, sockets, OkHttp, Volley, Retrofit, `WebView`, Paho MQTT,
  gRPC, Cronet) and file writes, with the endpoints the method or its direct callers load. Paths follow a call
  graph across every DEX file: direct invokes, virtual and interface invokes resolved through the app's class
  hierarchy (overrides found by name are marked `by_name` and rank lower), callbacks and `const-class` component
  starts. Triggers name boot receivers (and the services they start), the Application class, push messages,
  scheduled work, exported components, UI callbacks and activities; `no_user_trigger` is withheld when the walk is
  cut, a caller is linked by name, reflection is on the way or the app loads code at run time. Each JNI library's
  own report is merged, labelled with its origin, and a Java caller of a `native` method reaches what the bound
  `Java_` export reaches. See [privacy surface](docs/privacy-surface.md#apks-and-dex-files).
- `privacy_surface` on a directory, such as an extracted firmware tree: one page of programs and APKs that may
  capture (`cursor`, `max_files`, `timeout_ms`), merged and labelled by file, plus the tree's Android init `.rc`
  services, systemd units, init.d scripts and inittab, so a capture in a program init starts at boot is tied to
  the init file and line (`no_user_trigger: <program> is started at boot, ...`) and a `Boot services` section
  lists every start read. See [directories](docs/privacy-surface.md#directories-extracted-trees).
- String decryption for DEX code: call sites where constants go into a static app method returning `String` are
  emulated by a bounded Dalvik interpreter (arithmetic, arrays, `String`/`StringBuilder`, chars, Base64, the
  decoder class's statics; no I/O or reflection; any unmodelled instruction or call, and the step, depth,
  allocation and string-length budgets, stop it). `dex_metadata` pages the results with `list:
  "decoded_strings"` (decoder, call site, inputs), `endpoint_inventory` with `decode` reports them as
  `dex_decoded` evidence, and `privacy_surface` names them as sink endpoints and lists them in a `Decoded strings`
  section. See
  [decoded strings](docs/android.md#decoded-strings).
- `dex_code` `view: "pseudo"`: structured pseudocode of one method, paged by line: parameters named `this`, `p1`,
  ..., locals declared with the type their writes give them, `while (true)` loops with `break`/`continue` and
  `if`/`else` read from the control flow, Java-like calls with results and constructors folded, const-strings
  inline, and `goto` labels for jumps that fit no structure. Not Java decompilation; bounded by instructions,
  nesting and lines. See [pseudocode](docs/android.md#pseudocode).
- Rust API: `WorkflowReport::target` is now an `Option<ReportTarget>` (a report on an APK, DEX file or directory has
  an `input` instead); the JSON of binary reports is unchanged.
- `dex_metadata`'s `accessibility_services` follows the class hierarchy across every DEX file of an APK.
- `endpoint_inventory` reads APKs and DEX files: each DEX string pool with the methods that load every string and
  the networking calls they make (`dex_string` evidence), and each native library in the APK. See
  [endpoint inventory](docs/endpoint-inventory.md).
- ZIP archives in `fs_list` and `fs_extract`: stored and deflated members (ZIP64 included) with the central
  directory as the authority, inflation stopped at the declared size, the per-file limit and the ratio meter, so
  an APK's native libraries can be extracted and opened by path. See [firmware images](docs/firmware-images.md).

## 1.6.0 (2026-11-16)

- `integrity_checks` on Raw firmware: on Cortex-M, a CRC polynomial literal that no discovered code references is
  followed to the `ldr` that loads it, and the routine around it is listed with `inferred_range`. On a Raw project
  over a container file, `container_streams` lists each compressed stream a record describes, with the record's
  byte sum or CRC-32 as a check over the stream (or a note that it does not verify), and `next` gives the decoded
  image's `raw` selector. The search is bounded (64 candidates, 64 MiB of CRC-32, 8 decodes within 6 s). See [MCP](docs/mcp.md).
- More tools on Raw projects: `function_summary`, `find_crypto`, `triage` and `triage_report` take the `raw`
  selector and read the mapped regions, decoded ones included, at mapped addresses; on Raw input `triage` and
  `triage_report` say which file-format facts do not apply. See [MCP](docs/mcp.md#raw-projects).
- Raw `binary_info` fits the tool budget: on a Raw project the summary view keeps the first 3 rows of every list
  under `raw` (decode receipts, vector and pointer tables, scatter-load copies, base evidence) with counts and
  omission receipts, a full view too large for 60,000 bytes keeps 16, and sections that still do not fit are
  reduced to their scalar fields and counts, so the call no longer fails over size. Native results are unchanged.
- Sparse Raw discovery runs the pointer-table scan itself: a Cortex-M `raw` selector that leaves `pointer_tables`
  unset now scans for tables of code pointers when discovery from the entry, seeds, vector table and scatter-load
  jump finds fewer than one function per 16 KiB of code, instead of only suggesting it. `binary_info` reports why
  and the `outcome` (`applied`, `found_none` or `refused`) under `raw.pointer_tables.automatic` and
  `list_functions` adds a `note`; `true` and `false` keep their meaning, an explicit request for the resulting
  interpretation shares the project, and discovery in proportion leaves the project unchanged. See [MCP](docs/mcp.md#raw-projects).
- Privacy surface: the new `privacy_surface` report (group `carve`) maps what one binary can capture and where it
  can send it. Sources are microphone, camera, screen and input-device capture: ALSA, tinyalsa, PulseAudio,
  PortAudio and AAudio input, V4L2, framebuffer, DRM and evdev ioctls (matched by type and number at any ABI size),
  libevdev/libinput, X11 screen reads, NDK camera2, Android native `AudioRecord`/`MediaRecorder`/`Camera`/screenshot
  classes in mangled names, and device-path and Android class-name strings. A constant argument read just before
  the call (capture stream, `PCM_IN`, `PA_STREAM_RECORD`, an ioctl request code) raises a source's evidence from
  `name` to `argument`, and a playback-direction call is listed as excluded instead; evidence also used without
  capturing (device nodes, framebuffer and codec-capable requests, unread directions) is marked ambiguous and ranks
  lower. Sinks are TLS, libcurl, WinINet/WinHTTP, MQTT and WebSocket sends, socket sends (network or local IPC, told
  apart when the socket's domain is a constant), with the endpoints the function or its direct callers name, and file
  writes (`fopen` with a writing mode, `open` with write flags; device paths excluded) as weaker sinks. Paths between
  capture and send are ranked (same function, direct call, a few calls down, a shared caller) with their call chains
  and a shared writable global as a data-link hint. Triggers follow callers, callbacks, thread starts and signal
  handlers up to six levels: program start (entry, `main`, `.init_array`, `JNI_OnLoad`), timers and sleeping loops,
  network commands and user input (also a sibling call that reads input); `no_user_trigger` says a capture with
  direction-specific evidence is reached from program start with no input or UI handling found among its callers,
  and is withheld when a caller is referenced from a data table or the walk was cut. Evidence, never intent. See [privacy surface](docs/privacy-surface.md).
- Load-address inference for Raw Cortex-M code: `decode_file_range` and `probe_compression` return
  `base_candidates` for decoded bytes (at most five bases with evidence: pointer words landing on `push {..., lr}`
  prologues and string starts, literal-pool and `movw`/`movt` constants, reset-code constants, a vector table at
  offset 0 and container-record hints), and `next` names the base when one is clearly strongest. Both also return
  `container_record` when words just before the stream hold its compressed length and decoded size: each word's
  inferred role (byte sum or CRC-32 of the compressed bytes, payload offset, address) and `base_hints`. A Cortex-M
  Raw `binary_info` reports `raw.base_check`, whether `base_address` fits the image, and names the better base in
  `next` when it does not, including when the reset-code follow fetched outside every region at an address another
  candidate maps. Bounded (about 65 ms for 3.5 MiB) and memoized. See
  [MCP](docs/mcp.md#load-address-candidates-and-base_check).
- Compressed images as Raw code: the `raw` selector takes `decode` (a region's decoder parameters) on the primary
  region, so a compressed application maps its decoded bytes as the code region; `vector_table`, `pointer_tables`
  and seeds read them, `length` counts encoded bytes (at most 8 MiB) and the decoded size obeys the profile's cap.
  `binary_info` reports the decode receipt as the region's source. See
  [MCP](docs/mcp.md#a-compressed-image-as-the-code-region).
- Decoders name the next step: `decode_file_range` and each reproduced `probe_compression` candidate return
  `open_as_raw`, a `raw` selector for the decoded bytes (offset, length and `decode`), with a one-line `next`
  saying to add a profile and load address and pass it to a Raw-capable tool.
- Decoded bytes to a file: the new `write_decoded_range` file tool (group `carve`) decodes a range as
  `decode_file_range` does and writes the whole output to a new file at an absolute `output_path`. It never
  replaces a file, never writes through a symlinked directory or target, creates the file exclusively with mode
  0644, and reports `written`. `decode_file_range` itself writes nothing. See [decoding](docs/decoding.md#mcp).
- Folders: the new `list_dir` file tool (group `core`) lists a directory, each entry with its kind (symlinks shown,
  never followed), size and a format sniffed from its first bytes (executables, filesystem images, archives and
  compressed streams, Intel HEX, S-records, text), sorted by name and paged by cursor in memory bounded by the page
  (a directory past 1,000,000 entries is listed in part, saying so), so an agent given only a folder can start. `endpoint_inventory` names the first 20 files it ignored, with the reason, in
  `ignored_entries`. See [MCP](docs/mcp.md).
- Raw projects: `list_strings` and `inspect_data` take the `raw` selector. Strings come from every backed region
  at mapped addresses, decoded regions included; in a code region a run is listed when a NUL ends it and no
  discovered instruction overlaps it, since flash images keep constants among their code. `inspect_data` gives a
  file offset only for bytes mapped from a file range. See [MCP](docs/mcp.md#raw-projects).
- Raw regions copied from another region: a Cortex-M `regions` entry takes `from: {region, offset}` instead of a
  file range, mapping `length` bytes of the primary region (decoded bytes included) or an earlier region at its own
  base, as startup code copies code and initialised data to their run addresses. Copies count against the 4 MiB
  cap, `binary_info` reports the source as `slice` (`region`, `offset`, `length`) with the region's SHA-256, and
  patches go to the source region. The interpretation identity is now `rampage-raw-interpretation-v6`. See
  [MCP](docs/mcp.md#multiple-regions-intel-hex-and-s-records).
- Scatter-load copies: a Cortex-M Raw project follows its reset code from the entry with a bounded, deterministic
  Thumb interpreter (no host effects, 2,000,000 instructions at most) and records what startup code copies to run
  addresses and zeroes: GCC-style loops over linker symbols, Arm-style region tables walked with copy and zero
  handlers, and routines called with constant triples alike. `binary_info` reports `raw.scatter_load` (why the
  follow stopped, the jump into copied code, and each copy's kind, destination, length, source, store sites and
  calling routine); by default a copy from mapped bytes to an unmapped destination is mapped there (code when the
  copied code ran and nothing stored into it, RAM otherwise, zero fills as unbacked RAM) unless a skipped call or
  an unclean stop cut it off mid-routine, and the jump into the copied code is seeded, so discovery and
  decompilation reach code that runs from TCM or RAM. `"scatter_load": false` reports without
  mapping. Calls the follow cannot complete are skipped and listed. A patch inside a mapped copy is refused with
  the load address to patch instead. See [MCP](docs/mcp.md#scatter-load-copies).
- Relocated vector tables: after the jump into copied code the reset-code follow goes on (at most 200,000
  instructions) and reports constant stores to VTOR in `raw.scatter_load` (the first eight in `vtor_stores`, the
  last in `last_vtor_store`); the table at the last value is read when a mapped region holds it and its accepted
  handlers are seeded, or `vector_table_refused` says why. A copy the code then stores into is marked
  `written_after_jump` and maps as RAM, not code.
- Thumb disassembly: a 16-bit `add`/`sub Rdn, #imm8` inside an IT block printed its immediate four times too large
  (`subhs r1, #40` as `#160`); only the SP-relative, literal and `adr` forms count words.
- Raw discovery that stops early says so: when a Raw project's discovery finds fewer than one function per 16 KiB
  of code, `list_functions` (and `binary_info` once discovery has run) return a one-line `next` naming
  `"pointer_tables": true` (Cortex-M, when off) and mapping the startup copies (when `"scatter_load": false` left
  them unmapped). See [MCP](docs/mcp.md#scatter-load-copies).

## 1.5.0 (2026-11-15)

- Endpoint inventory and blocklists: the new `endpoint_inventory` and `endpoint_blocklist` file tools (group
  `carve`). `endpoint_inventory` lists the network endpoints of one binary or of a whole extracted firmware tree
  (executables plus scripts and `.conf`/`.json`/`.xml`/`.prop`/`.ini`-style configuration): URLs of every common
  scheme (http(s), ws(s), mqtt(s), coap(s), ftp, rtsp...), host names validated against the Public Suffix List,
  IPv4 and IPv6 literals, `sha256/` certificate pins, and embedded PEM or DER certificates with their names, expiry
  and SPKI pin (a pin is linked to the certificate it pins). Version numbers, file and library names, XML namespace
  and schema URIs, licence URLs, netmasks and dotted identifiers are counted as noise, reversed-DNS names are
  `package`, and private, loopback, link-local, documentation and reserved names and ranges are labelled `local`
  with the reason. Each finding carries its string address and encoding (or text line), whether it was decoded in
  emulation (`decode`, reusing `string_decoding`), the functions referencing it and the networking APIs they call
  (`signal: network_code`). Findings group by registrable domain and by file; a directory scan pages by `cursor`
  under `max_files` and `timeout_ms`. `endpoint_blocklist` writes the chosen hosts or domains as a hosts file,
  dnsmasq (`address=` or `server=`), unbound, a plain domain list (Pi-hole, AdGuard Home) or an IP list, at domain or
  host level with allow/deny filters, to an absolute output path (never through a symlink; an existing file only
  when this tool wrote it, or with `overwrite`). Domain level widens a host only to the registrable domain the
  Public Suffix List gives, never to a public suffix or a shared cloud/CDN domain (`amazonaws.com`, Akamai, Fastly...),
  and on-network addresses, single-label names and public suffixes are never written. The Public Suffix List
  (MPL-2.0 data, compiled into the `psl` crate) is now listed in THIRD-PARTY-NOTICES. See
  [endpoint inventory and blocklists](docs/endpoint-inventory.md).
- Firmware filesystem images: the new `fs_list` and `fs_extract` file tools (group `carve`) list and extract
  SquashFS 4.0 (gzip, xz, lzma, lzo, lz4, zstd), ext2/3/4 (extents included), Android sparse images (unsparsed on
  the fly, the filesystem inside opened directly), full Android OTA `payload.bin` updates (REPLACE, REPLACE_BZ,
  REPLACE_XZ, ZERO; operation and partition SHA-256 checked; delta operations refused by name), cpio (newc) and tar.
  `image_offset` reads an image embedded in a larger file and `inner` opens nested ones (an OTA partition, an image
  inside an archive). Extraction writes only into a new or empty `output_dir`, refuses `..` paths, creates symlinks
  only when they stay inside it (never following them), skips device nodes, FIFOs and sockets, never writes setuid
  bits, and caps total bytes, file count, file size, compression ratio and nesting; it returns the executables it
  wrote, ready to open by path. Opening a filesystem image as a binary now points at `fs_list`. Every codec is pure
  Rust (new crate `rampage-unpack`, on `backhand` and `ext4-view`); nothing external is run. UBI/UBIFS images are
  recognised but not read yet. See [firmware filesystem images](docs/firmware-images.md).
  Hardened after a security review: a deep SquashFS tree is refused before backhand recurses into it, OTA extents
  may not overlap and the rebuild counts against `max_bytes`, synthesised zeros count against the compression ratio
  (`max_ratio` is an argument), a corrupt file is skipped with its reason rather than aborting the extraction, and
  `output_dir` must be absolute and not a symlink.
- Cortex-M decompilation (Raw projects and M-profile ELF firmware) keeps the callee prototypes and register effects
  it derives for the engine's life instead of deriving them again for every function, and what a function
  decompiles to no longer depends on what was decompiled before it. Every verdict is a property of the callee
  alone (what it reaches through direct calls, with fixed budgets: 64 functions for a prototype, 256 functions and
  16 calls deep for register effects); which derived callees a decompilation sees is fixed by the function itself
  (its direct callees in the order its flow finds the calls, while what they reach stays within 64 functions), and
  the rest are set aside while it is decompiled. Callee facts come from one scratch flow per function, which skips the jump-table recovery
  that following each registered callee paid. On these images every analysis also starts without the globals
  earlier analyses discovered and without Ghidra's memory of a previous analysis whose type propagation did not
  settle, two leaks that made output depend on history before this change too. On the stripped `embedded-libs-m0`
  fixture, `0x80092ca` decompiles in about 2 s instead of 6.5 s on a fresh engine (so in the isolated worker too),
  and all 549 functions on one engine in about 2 minutes instead of 22. Output changes on Cortex-M images only (66
  of those 549 functions): callees the old shared budget left unlocked now keep their arguments
  (`sub_80067b4()` becomes `sub_80067b4(x, y)`) or lose ones they never read, and a global is typed only by the
  function's own use (`&ram_200009cc + i * 5` can read as `i * 0x14 + 0x200009cc`). Other images are unchanged.
  The worker protocol version is bumped.
- `integrity_checks` confirms the values a fix writes with the device's own code: with `emulate` (the default),
  each value a fix writes, or would write in a preview, is run through the routine that confirmed its check over the
  range as the fix leaves it, the fix's earlier values included, and reports `device_check`: `agrees`, `disagrees` (also in
  `notes`) or `unconfirmed` with the reason (no routine confirmed the check, or the run gave no value). It never
  blocks a write.

## 1.4.0 (2026-11-15)

- Cortex-M ELF firmware decompiles like a Cortex-M Raw project: an ARM ELF whose build attributes
  (`.ARM.attributes`) name an M-profile CPU (profile `M`, or an M-only architecture such as v6-M or v7E-M) is
  decoded as M-profile with all executable memory Thumb, and a statically linked M-profile executable gets the
  Cortex-M decompiler settings (the peripheral and system ranges are volatile, so a reset-register store before an
  endless loop is kept; literal pools fold; flash words read through a formed address stay reads; region names for
  unnamed globals; callee inference). Its vector table
  (an `.isr_vector`/`.vectors` section, or the first words of flash, when the Reset vector is the ELF entry) seeds
  the interrupt handlers as functions, so stripped firmware finds handlers only the table names (embedded library
  identification on the owned stripped ELF fixtures now matches their Raw projects: 81 and 71 names, up from 80
  and 70). Recognition never uses load addresses: A-profile ARM Linux ELFs, PE and Mach-O are unchanged. An
  unreadable attributes section is a load warning. The analysis cache version is bumped.
- Static ELF32 ARM firmware executables (`ET_EXEC`, little-endian, no interpreter, dynamic section or loaded
  relocations, non-overlapping loadable segments) take byte patches in place as record version 3, so
  `integrity_checks` fixes a firmware ELF's checksum without converting it to a Raw project. Patches map through
  `PT_LOAD` file bytes only (never `.bss` or another zero-fill tail) and never touch headers or tables; any executable
  section is code, any other payload section needs `allow_data`. Version-1 and version-2 records load unchanged.
  `export_image` writes the patched ELF. ELF32 images that admission refuses still export unchanged.
- `export_image` `format: binary` on a little-endian ELF32 image lays its allocated sections out at their load
  addresses like `objcopy -O binary` (`.data` initial values in flash after the code; headers left out), using
  `p_paddr` only when the segments' physical ranges are disjoint. ELF64 keeps its segment layout.
- `integrity_checks` recognises table-less CRC-16 loops in ARM code whose polynomial (0xa001, 0x8408 and 0x1021) is
  one immediate (a Thumb or A32 `movw` with no `movt`, or a `mov` modified immediate) or a literal word read by a
  PC-relative load, as compilers emit at `-Os`; 0x8408 reports `crc16_kermit`. On an ELF32 whose sections load
  elsewhere than they run, `notes` says that checks over the flash image including them are not searched.
- Opening an Intel HEX or S-record file without `raw` now says which it looks like and gives the `raw` selector
  (`"format":"ihex"` or `"srec"`) to read it; the general headerless hint mentions `format` too.
- Fix: `evaluate_function` runs code and reads data in page 0 of a fixed-address image linked there (a Raw project,
  or an ELF executable with a segment at 0, as Cortex-M firmware often is) instead of stopping with
  `unmapped_fetch`; shared objects, PIEs, PE and Mach-O images keep the null-page guard.
- Fix: `integrity_checks` finds checks nested inside another check's range (a CRC-16 over a configuration block
  inside an image CRC-32): code evidence includes CRC tables whose address `movw`/`movt` forms and the addresses
  routines and their callers form with `movw`/`movt` or load through a constant base, and a dropped nested value is
  kept when the image's own routine computes it. Fixes and previews compute each value over the earlier planned
  writes, inner values first; an outer value over an inner check that would stay stale is reported as `blocked`,
  naming it; a stale dropped match, or a CRC routine with no matching check, is noted in `notes`.
- `evaluate_function` (and `function evaluate`) accepts a Raw project's `raw` selector, so a firmware image's own
  routines (a checksum, a decoder) can be run; processors the interpreter does not support, such as MSP430, are
  refused with the reason. `mmio`, with imported SVD register names, works as on an ELF image.
- Fix: decompiling a Cortex-M Raw image no longer folds flash words the code reads through an address it forms
  itself (`mov r1, #0xc80; ldr r1, [r1]`: a pairing token, a version, option bytes) into constants; literal pools
  still fold. The peripheral, external-device and system ranges (0x40000000-0x5fffffff, 0xa0000000-0xdfffffff,
  0xe0000000 and up) are volatile without an SVD too, so a register store before an endless loop
  (`ppb_e000ed0c = 0x5fa0004`, a reset request) is no longer dropped as dead, and every poll of a status register is
  shown. A volatile access with no symbol is named by its region (`periph_40011000`). The ARM address tracker
  follows `mov`/`movs` immediates and keeps r4-r11 across calls (AAPCS), so disassembly and xrefs resolve more
  loads and stores (on every ARM image; the analysis cache version is bumped). Decompiled output of other formats
  and architectures is unchanged.
- `string_decoding` also finds table-driven decoders: a loop with two byte loads, one through a base plus an index
  register (`ldrb w9, [x10, x9]`), and a byte store is a candidate ("table lookup") when a call site passes it
  encoded-looking data, so `evaluate: true` runs it on its blobs.

## 1.3.0 (2026-11-14)

Additions only; nothing in the stable surface changed.

- Embedded library signatures: identification of firmware (Cortex-M Raw projects and static Thumb ELF
  executables) also applies a bundled firmware set (1.3 MB, source `rampage-builtin embedded`) built from
  newlib and newlib-nano, libgcc, compiler-rt builtins, the FreeRTOS kernel and the STM32F4 HAL/LL across three
  Arm GNU Toolchain releases, five Cortex-M multilibs and five optimisation levels. Its hash scheme 3 treats Thumb
  literal pools as data (masking address-like words), records Thumb call targets for callee keys and leaves short
  accessors unnamed. On owned firmware built with a held-out GCC it names 31–51% of the library functions with no
  wrong name. `identify_functions` (and `function identify`, without `--apply`) accepts a Cortex-M Raw project's
  `raw` selector. See [embedded firmware set](docs/signature-corpus.md#embedded-firmware-set).
- `lock_mechanisms` (group `detection`, *experimental*) explains what can make a device refuse a repair:
  signature and MAC verification, challenge-response unlocks, unique-chip-ID binding, anti-rollback counters, debug
  and readout protection and fuse feature locks. A p-code dataflow over the functions near crypto constants,
  library names and SVD-named registers finds the branch each decision is made at, what it consults and what each
  path does (reset, halt, error return, a flag written), with evidence and a confidence; CRC and unkeyed digest
  checks, unused identity reads, debugger presence checks and crypto that decides nothing are listed as not locks.
  It explains only: no patch suggestions, no key extraction. Accepts a Cortex-M Raw project's `raw` selector. `find_crypto` also
  recognizes the PKCS#1 v1.5 DigestInfo prefixes for SHA-224/256/384/512. See
  [lock mechanisms](docs/lock-mechanisms.md).
- Fixed: `evaluate_function`'s `timeout_ms` now starts after the instruction decoder is built, so a cold
  language load no longer uses up a short run's budget (seen as `string_decoding` replays timing out).

## 1.2.0 (2026-11-14)

Additions only; nothing in the stable surface changed.

- `evaluate_function` runs common C library imports (`memcpy`, `memset`, `strlen`, `strcmp`, `strchr`, `malloc`,
  `free` and related functions, under their Mach-O, fortified and MSVC CRT names) as built-in models instead of
  stopping with `external_call`, and lists them in `stubbed`; `stubs: false` restores the old behaviour.
- `string_decoding` takes `evaluate: true` to run each candidate decoder on the blobs passed to it, replaying the
  call site, and reports printable output with the arguments and stop reason, labelled as emulation output.
- `debug_snapshot` takes `raw: true` to write one range of a stopped target as a flat binary, such as a
  microcontroller's flash read through OpenOCD, pyOCD, J-Link or QEMU, which then opens as a Cortex-M Raw project.
  The debug docs gain a Cortex-M probes section and the flash-dump recipe; a live QEMU test checks the dump against
  the loaded image.
- CMSIS-SVD peripheral maps (types group): `import_svd` previews, or with `apply` stores, a device's peripherals,
  registers and bit fields (`derivedFrom`, `dim` arrays, clusters, inherited sizes and reset values, enumerated
  values; bounded, no entity expansion), replacing an earlier import in one undo step. Decompiled MMIO accesses
  are volatile and read `TIMER0.CR = uVar1 | 0x21; /* CR: EN|MODE=Single_MATCH */`; disassembly comments, xref rows (with
  `access: read|write`) and `evaluate_function` faults name `PERIPHERAL.REGISTER`; those names resolve as
  addresses, and `xrefs` to a peripheral's name covers all its registers. `peripheral_access` lists peripherals
  with access counts, or one peripheral's registers with bit fields and the functions reading or writing each.
  `evaluate_function` takes `mmio` register values, so routines that poll a status register run. See
  [peripheral maps](docs/peripheral-maps.md).
- Firmware patching round trip (formats group): `integrity_checks` finds CRC-32 (IEEE, MPEG-2, STM32 word order,
  JAMCRC, CRC-32C), CRC-16/8, sum, XOR, Adler-32, Fletcher and SHA-256/MD5 fields with the ranges they cover, by
  bounded brute force over layout and code-referenced ranges, CRC tables and polynomials in code, and emulation of
  the image's own routine; it reports which checks the active patches broke and, with `fix: true`, writes the
  corrected values as patches in dependency order. `export_image` writes the patched image to a new file as Intel
  HEX or S-records (only changed data records re-encoded), the original binary file, the native file (optional PE
  CheckSum) or a flat binary. Raw projects now take `patch_bytes`, `revert_patch` and `list_patches` (patch record
  version 2). See [firmware patching](docs/firmware-patching.md).

## 1.1.0 (2026-11-14)

Additions only; nothing in the stable surface changed.

- Server instructions now say that `get_type` and `list_types` read Go runtime type data, stripped binaries
  included, as well as DWARF and PDB, so agents stop decoding Go type descriptors by hand.
- `evaluate_function` (core, experimental) runs a function of the image on integer and buffer arguments and
  returns its result, so agents stop simulating loops by hand. A p-code interpreter over the bundled Sleigh
  specifications executes x86, x86-64, AArch64, 32-bit ARM and Thumb, MIPS, PowerPC and RISC-V code with the
  binary's calling convention (cdecl/stdcall/fastcall/thiscall, System V, Win64, AAPCS, o32/n64, RISC-V and
  PowerPC), follows calls inside the image and names why a run stopped. CLI: `rampage function evaluate`.

## 1.0.0 (2026-11-14)

The first stable release. From here a breaking change to the stable surface in the
[stability policy](docs/stability.md) needs a new major version. The surface is the one rc.1 froze, extended since
rc.2 only by additions the policy allows: the core tools `file_layout`, `objc_sends`, `probe_compression` and
`transfer_annotations`, the experimental `exception_handlers`, and new optional arguments and result fields. No
tool, argument or result field was removed, renamed or made required, and no tool changed group.

Highlights since rc.2:

- Annotation transfer between builds: `transfer_annotations` matches functions one-to-one and carries names,
  comments, signatures, types and globals to a new build.
- A persistent analysis store: re-opening an analysed binary skips function discovery (experimental).
- Type layouts for stripped Go binaries from the Go runtime type descriptors, and DWARF layout lookup through
  `get_type`, by member path or byte offset.
- MSVC C++ PE metadata: vftables, exception tables and virtual-call slots in decompiled C.
- Objective-C message sends resolved to their selector and, where the receiver class is evident, the method that
  runs (`objc_sends`).
- Encrypted or packed code detection, and 544 packer, protector and compiler signatures converted from Detect It
  Easy.
- Cortex-M firmware (experimental): a headerless Raw profile with vector-table and pointer-table seeding, multiple
  regions, Intel HEX and S-record input, `file_layout` with compressed-container hints, and `probe_compression`.
- `search` completes on large images where it used to stop on its work budget, and the Rust toolchain is pinned.

### Added

- `transfer_annotations` (MCP; CLI `rampage annotation transfer`) carries an analysed build's annotations to a new
  build. Functions are matched one-to-one by exact bytes, symbol names, masked hashes, unique strings, call-graph
  position and neighbourhood, each with a confidence; ambiguous pairs are reported, never guessed. Preview is the
  default; `apply: true` writes undoable batches with a provenance entry, and existing annotations or real symbols
  in the target are reported as conflicts, never overwritten. It also lists changed, added and removed functions.
  On zlib 1.2.13 → 1.3, stripped, every build had zero false matches; shared libraries transferred 100% of
  unchanged functions' names and static builds about 90%. See [build diffing](docs/build-diffing.md).
- Objective-C message sends resolve to their selector and, where the receiver's class is evident from the code, to
  the method that runs: class references, `self`, `super` and `+alloc` results, looked up through categories and
  the superclass chain like the runtime does. Local overrides make a send `ambiguous`, an unknown receiver lists
  `candidates`, and a single target is never guessed. New `objc_sends` tool (CLI `rampage language objc-sends`);
  `xrefs` gains call rows for resolved and ambiguous sends, and listings and decompiled C name the selector and
  target at each send. On the owned fixtures every selector resolves and no send resolves to a wrong method.
- Stripped Go binaries (Go 1.16–1.27) have type layouts: `get_type` and `list_types` read the Go runtime type
  descriptors (`source: "go"`; `auto` falls back to them after the type library and DWARF). Structs come back with
  field names, offsets, tags and embedded fields, interfaces with their method sets, and named types with their
  methods; `member` follows promoted fields shallowest-first like Go. On a stripped 26 MB Go binary all 3,824 named
  structs that its unstripped twin's DWARF also describes match exactly. When nothing is found, `get_type` now names
  the sources it tried.
- `get_type` falls back to the binary's own DWARF when the type library has no such name (`source`: `auto`,
  `library`, `dwarf`), and can select a member by path (`init.busy`, `aDb[1].pBt`) or by `byte_offset`. A name index
  is built once per project and each lookup reads only the requested type and what it references, so the work per
  request does not grow with the binary: on a 7.9 MB SQLite build both previews used to stop on their budgets, and a
  lookup now answers in under 0.1 s. Nothing is imported. CLI: `rampage type layout`.
- Decompiling an MSVC C++ PE resolves virtual calls through recovered vftables when the object's class is known (a
  method's own `this`, or an analyst type named after the class): the call is annotated with its slot and candidate
  methods and keeps their shared prototype. On x86 such calls pass `this` in ECX (`__thiscall`); calls through C
  operation tables and other unresolved double loads keep the decompiler's default.
- MSVC C++ on x86 and x64 PE: vftables and `__CxxFrameHandler3` exception tables are read at load (bounded by a
  per-image work and memory budget). Virtual methods and catch/cleanup funclets seed function discovery; on owned
  clang-cl fixtures, function starts went from 33/79 (x64) and 32/79 (x86) to 79/79 against the PDB.
  `class_evidence` adds a paged `vftables` list. New experimental `exception_handlers` (MCP `formats`) pages try
  blocks with catch types, cleanups and thrown types. Validated on clang-cl output only; `__CxxFrameHandler4`
  (cl.exe x64 since VS2019 16.3) is reported as undecoded.
- Encrypted or packed code detection. Code is measured in 4 KiB windows; a stretch of at least 8 KiB with entropy
  ≥ 7.6 bits/byte and no more than 97% valid instructions is reported as `encrypted_or_packed_code` in `triage`,
  `triage_report` and `binary_info`, and function discovery stops at it, so a protected binary no longer lists
  thousands of noise functions. Clear code (a packer's stub, a firmware loader before a compressed stage) is still
  explored from the entry point. `list_functions` reports skipped stretches as `unexplored_code`; `decompile`
  refuses addresses inside them unless `explore_encrypted: true`. No fixture's normal code comes close to the
  thresholds. A Mach-O protector signature for PACE (Eden/Fusion) is added to the bundled detection database.
- 544 packer, protector, cryptor, compiler, installer, linker and SFX signatures converted from Detect It Easy (MIT,
  pinned commit, authors credited per signature) join the bundled detection database. Only conditions rampage can
  test exactly are converted (entry patterns that follow jumps, bytes at file offsets or the overlay, exact
  library/import/export names, bit width); patterns copied or truncated from PeID's database are dropped. Matches
  name their source and the DIE script. `tools/die_signatures.py` regenerates the data and reports what it skips.
- `file_layout` (MCP, `core`) and `binary layout` map any regular file, or a range of up to 64 MiB, without a
  loader: 0xff/0x00/repeated-byte fill and occupied regions with per-region SHA-256 and entropy, per-block
  entropy with high and low spans, printable-string clusters, the range's SHA-256, and labelled heuristic hints
  such as Cortex-M vector-table candidates. Capped lists report totals and a continuation range. See
  [file layout](docs/file-layout.md).

### Changed

- `search` scales to large images: `functions_referencing` a string finds the string first and decodes only the
  blocks holding a matching reference, and wildcard byte patterns prefilter on their longest fixed run. On a 26 MB
  stripped Go binary both used to stop on their work budget; they now complete. In Go images a string target's text
  ends where the next code-referenced literal begins, so packed literals no longer match each other's text.
- `function_graph` pages oversized functions by whole blocks (`block_offset`, `blocks_next_offset`) instead of
  refusing them; edges keep whole-function block indices.
- 32-bit x86 ELF PIC PLT stubs (`jmp [ebx+disp]`) are named `name@plt` through `.got.plt`, so decompiled
  dispatchers in i386 shared objects show the called import instead of `sub_…`.
- MCP accepts unambiguous argument aliases (`address`/`addr`/`ea` for `at`, `length`/`len` for `size`,
  `file`/`file_path`/`filename`/`binary` for `path`) and decimal or `0x` strings for integer arguments, so a client
  that calls a tool before loading its schema no longer needs a retry. `xrefs` with `at` still asks for `to` or
  `from`.
- Go images: string headers (`{ptr, len}` pairs) in data give literals referenced only from data their own start
  and length. `list_strings` reports `header_length`, and string matching ends a literal at its header length when
  code references agree with it. On a 26 MB Go binary, literal starts went from 10,709 to 17,700.
- ARM and AArch64 `disassemble` and `function_graph` rows carry `immediates_hex` (for example `0x78e` beside
  `#1934`); the CLI and desktop listings append it as `; 0x78e`. Instruction text, and so operand-glob search, is
  unchanged.
- Raw projects hash their image once per open instead of on every call; drift checks still run per call.
- Raw projects check their analysis binding once per query rather than once per result row: `xrefs --to` with
  5,000 rows on a Sleigh Raw image dropped from about 100 s to under 2 s. Search, call context, tracing, string
  decoding and batch signatures use the same path.
- `class_evidence` pages `rtti_classes` (`rtti_class_offset`/`rtti_class_limit`, 50 by default) and lists classes
  seen only as bases (`source: "rtti_base"`); a client that read the whole list must follow
  `rtti_classes_next_offset`.
- Debug-type import accepts PDBs linked with identical-code folding (`/OPT:ICF`): procedure records that disagree at
  one address are omitted with a warning instead of failing the import.
- PDB name import no longer rejects a whole PDB over conflicting names. Decorated MSVC names become aliases of the
  plain name (templates, operators and overloads keep their decorated name), identical-code-folded publics become
  aliases, and names that collide or are not valid labels are omitted with a warning. See
  [PDB symbols](docs/pdb-symbols.md).
- Function discovery no longer splits a function first reached by a tail call (`b.w f`) at its internal join
  points: callers that explored such a function are re-explored once it becomes a start, before shared tails are
  counted. On a generated 6,000-function Cortex-M image this removes 2,232 bogus starts; starts on other
  binaries are unchanged.
- Decompiler output on every format names otherwise unnamed globals from a unique data symbol of the binary
  (`__hwcap` instead of `xRam00031248`).
- `rust-toolchain.toml` pins Rust 1.100.0, with the `llvm-tools` component and the `wasm32-unknown-unknown` target
  CI needs, so a new stable release cannot change lints under CI. rustup installs that toolchain for a source
  build.

### Firmware

The Cortex-M Raw profile and everything its `raw` selector adds are experimental, like every Raw profile other
than MSP430 and AVR8.

- Experimental Raw Project profile `ARM:LE:32:Cortex` for headerless Cortex-M (ARMv6-M/ARMv7-M Thumb) images, with
  aliases such as `cortex-m4`, `thumb` and `armv7m`. It uses the native ARM decoder in Thumb mode, so listing,
  cross-references, search and decompilation (ARM v8 Thumb with its reviewed C model) work as for ARM ELF. Input
  may be up to 4 MiB for this profile; Sleigh profiles keep 128 KiB.
- `"vector_table": true` (or an address) in the `raw` selector reads the Cortex-M vector table: Reset becomes the
  entry and the other Thumb handlers seeds, and `binary_info` reports every word with its verdict under
  `raw.vector_table`, with a labelled, never applied base-address suggestion when the handlers fall outside the
  asserted mapping. One call with path, profile and base address now opens a firmware image.
- The Cortex-M profile decodes the M-profile instruction set: `MRS`/`MSR` special registers (`msp`, `psp`,
  `primask`, `basepri`, `basepri_max`, `faultmask`, `control`, ...), which used to stop discovery as invalid
  instructions, and no A32 state or A-profile-only instructions (BLX to A32, Advanced SIMD, SETEND, ERET, ...).
  Odd-aligned string literals are not taken for Thumb function pointers. `inspect_raw_code` stays A-profile.
- `"pointer_tables": true` in the Cortex-M `raw` selector seeds discovery from tables of code pointers (plain
  arrays and 8/12/16-byte struct arrays). A table needs at least two distinct targets with strong evidence (a
  push of `lr`, or a decodable `bl` calling it); string-pointer arrays, switch tables and stray constants are
  refused. `binary_info` reports every table with its verdict and per-entry evidence under `raw.pointer_tables`.
  Off by default; repeat calls on the same image reuse the scan.
- Cortex-M Raw images can map several regions (experimental): `regions` adds up to 15 code, read-only data or
  writable RAM regions, each backed by a file range, by bytes decoded through the decoder provider (`lzss-4k`,
  `lzss`, `lz4-block`; nothing is written to disk) or by nothing (zero-filled RAM or MMIO). Calls, references and
  decompilation cross regions; loads from writable RAM are never folded. `format` `ihex` and `srec` read Intel HEX
  and Motorola S-records with every checksum verified; each contiguous run becomes a region and the start-address
  record becomes the entry or a seed. `binary_info` reports each region's source, SHA-256 and decode receipt.
- Raw interpretation identities move to `rampage-raw-interpretation-v5`, which binds every region and record input.
- The session's Raw project cache is also bounded by 64 MiB of input bytes.
- Decompiling a Cortex-M Raw image folds literal-pool loads to the addresses they hold, names unnamed globals by
  ARMv7-M region (`ram_`, `periph_`, `ppb_`, ...) unless the analyst renamed them, keeps caller values live across
  callees that never write a register (interprocedural register allocation), and locks callee parameter lists
  derived from the callees themselves, so call arguments are no longer dropped. Derived locks and caches are reset
  before each decompile, so output does not depend on earlier requests. This applies to Cortex-M Raw images only;
  the worker protocol is now 10. Shift-and-mask forms such as `ubfx` stay in
  Ghidra's equivalent `(x & 0xffff) >> 4` shape; see [Sleigh decoding](docs/sleigh-decoding.md).
- `file_layout` flags header-checked compressed components (`compressed_component_candidate`): a header word equal
  to the following payload's length plus a verifying byte-sum or CRC-32 field, or a packed payload ending at the
  range end or padding with a decoded-size word. Each hint names the field offsets and the checks that passed;
  `bounds.container_search` reports when its limits stopped the search.
- `probe_compression` (MCP `core`; CLI `binary probe-compression`) sweeps LZ4 block and 160 LZSS variants over an
  unknown stream within a work budget and deadline, and ranks candidates whose `decode_arguments` pass straight to
  `decode_file_range`. A candidate is "confident" only with a supplied output size and a clear score margin.
  `decode_file_range` gains the parameterised `lzss` codec and `lz4-block`; `lzss-4k` is unchanged.

### Experimental

- Release builds keep a persistent analysis store: function discovery (functions, blocks, cross-references and
  related facts) is saved to an SQLite file under the user cache directory (`rampage/analysis/`, owner-only) and
  reused when the same image is opened with the same analysis inputs by the same rampage build. Re-opening a 26 MB
  Go binary takes 0.13 s instead of about 1.7 s. Entries are verified before use and anything that does not
  verify is analysed fresh; `binary_info` reports `analysis_store` (hit, miss, rejected, disabled). Disable with
  `RAMPAGE_ANALYSIS_CACHE=off`; `RAMPAGE_ANALYSIS_CACHE_MAX_MB` bounds its size (1024 by default). Experimental.
- `exception_handlers` (MCP `formats`) is experimental: its row shape may change, and `__CxxFrameHandler4` tables
  are not decoded yet.

### Stability

- Contract snapshots now pin the result fields of every stable MCP group (`mcp-results-<group>.json`), not just
  `core` and `debug`. A tool that a group adds without a fixture exercising it fails the test, and
  `query_debugger`'s result envelope is pinned against a scripted bridge.

## 1.0.0-rc.2 (2026-11-09)

The second release candidate. The stable surface is unchanged from rc.1: no contract snapshot changed. This
candidate improves library identification only, which the [stability policy](docs/stability.md) counts as an
analysis improvement, not an API change.

### Library identification

- The bundled signature databases gain rows learned on the flywheel corpus (zlib, lz4, cJSON, zstd and Lua builds
  across compilers and optimisation levels), with operand fields wildcarded so one row covers more builds. On
  held-out library versions, for example, Lua 5.4.6 goes from 70 to 772 named functions and zstd 1.5.5 from 172
  to 348.
- A bundled call graph names unnamed callees of already named functions by their position in known call
  sequences, and only when the callee's own calls also fit. These names report the source
  `rampage-builtin call graph` and never replace a database match or an existing name.
- Precision is traded slightly for recall: on the ledgered final split the new rows gained about 37,000 correct
  names against 100 wrong ones. Names for libc and compiler-runtime functions can be an alias of the binary's own
  symbol (`lseek` for `__lseek`).
- Identification takes slightly longer on large binaries (about 0.16 s on the largest corpus binary).

### Experimental

- The flywheel corpus has a ledgered final split, a false-positive allowance earned by large gains, and an
  operator-only view of development cases. `rampage-eval bundle` gains `--arm`, `--arm-library`,
  `--arm-exclude`, `--call-graph` and `--final-reason`.

## 1.0.0-rc.1 (2026-11-06)

The first public release, as a release candidate for 1.0.0: the stable surface in the
[stability policy](docs/stability.md) is frozen unless the candidate turns up a problem, and 1.0.0 follows once it
runs without unplanned contract-snapshot changes. It summarises what rampage does; the
[roadmap](docs/plans/2026-10-16-ida-ghidra-parity-roadmap.md) and git history have the detail.

### MCP server

- `rampage server serve` (also `rampage mcp`) serves the Model Context Protocol over stdio. It needs no API key.
- Tools are grouped: `core` is listed at startup, and `enable_tools` lists and enables `detection`, `types`,
  `runtime`, `diagnostics`, `dotnet`, `carve` and `formats`. `--all-tools` lists every group from the start.
- Every tool has a result size cap, pages large results with explicit offsets and totals, reports omissions, and
  refuses unknown arguments with a one-line error naming its arguments.

### Analysis and decompilation

- ELF, PE and Mach-O loading, including universal binaries and explicitly selected embedded images.
- Recursive-descent function discovery, control-flow graphs, cross-references, strings, imports and exports, and
  non-returning call detection.
- Stripped Go function names from the pclntab; C++ class names and base classes from RTTI and vtables, including
  Mach-O chained fixups; Objective-C classes, methods and properties.
- C decompilation through the embedded Ghidra decompiler, with processor specifications bundled, run in a
  supervised `rampage-worker` process with time, memory and output limits when the worker is installed. Without
  it, decompilation runs in-process: the MCP server warns at startup, each `decompile` result names its
  `decompiler` (`supervised` or `in-process`), and `rampage server serve --require-worker` refuses to decompile
  without the worker.
- Guided reports: `triage_report`, `find_main`, `network_surface`, `persistence_surface`, `string_decoding` and
  `diff_builds` in `core`, and `find_crypto` in the `detection` group.

### Typing and annotations

- Names, comments, signatures, types and globals in an append-only annotation log beside the binary, shared by
  the MCP server, CLI and desktop UI, with undo, redo and atomic batches.
- Local variable and parameter renames and retypes by storage, a project type library, data and operand typing,
  stack-frame inspection, type propagation across direct calls, and checked DWARF and PDB type import.
- An investigation ledger (`record_finding`, `list_findings`) for findings, unknowns and open questions, with
  evidence and confidence.

### Search and patching

- Byte, text, regex, immediate, instruction and reference search with function context and resumable budgets.
- An assembler for an x86, x86-64 and AArch64 subset, checked byte patches kept in the annotation log, and export
  of the patched image to a new file.

### Formats and processors

- x86 and x86-64; AArch64, A32 and Thumb decoded from Arm's machine-readable specification; MIPS, PowerPC,
  RISC-V, SPARC, s390x and m68k through Capstone.
- Sixteen further processor families open as Raw Projects through Ghidra's Sleigh; MSP430 and AVR8 also
  decompile.
- Raw code windows for headerless images, explicit LZSS decoding of file ranges, and embedded-file carving.
- .NET metadata and CIL disassembly; Go build info and cargo-auditable dependency data; PE resources and load
  config; PyInstaller archives; WebAssembly module summaries; ZIP directory inventory.

### Library identification and detection

- Function signatures with bundled databases for x86-64, AArch64, i386 and A32/Thumb, plus user PAT files and
  explicitly configured Ghidra FunctionID databases; fuzzy candidates that never rename on their own.
- Packer, compiler and toolchain detection, YARA through yara-x, a file-scope subset of capa rules, capability
  tags and a crypto-constant database.
- Data packs extend all of these with data only, and move between machines as checked `.rpack` archives
  (`rampage pack export`, `import` and `diff`).

### Debugging

- The `debug` group connects to a GDB remote stub the operator started and allowed with `--debug-endpoint`:
  registers, memory, modules, snapshots, all-stop execution control, breakpoints and watchpoints, and binding to
  a static project for breakpoints by name and located stops. Live-verified against QEMU (Cortex-M3).
- Memory and register writes need `--debug-writes`, and kill needs `--debug-kill`. rampage never launches or
  attaches to a process.
- A read-only bridge to a stopped LLDB session, and runtime snapshot analysis.

### File formats and compatibility

- The annotation log's identity lines carry `"format": 1`; a reader refuses a log that declares a newer format
  instead of misreading it. Logs 0.1.x wrote are format 1 and keep opening.
- `.rpack` archives declare `min_rampage_version` instead of a rampage version range, and readers accept every
  archive of a format version they support. Archives 0.1.x exported keep importing; 0.1.x builds refuse new
  archives as having an unknown field.
- `rampage-pack.toml` and constants files take an optional `format_version` (absent means 1). Fields a reader
  does not know are ignored with a warning, a content kind it does not know is reported as unsupported, and a
  newer major is refused.
- Snapshot tests in `tests/contract/` pin the MCP tool schemas and result fields and the CLI commands, flags and
  `--json` fields; see [how the stable surface is checked](docs/stability.md#how-the-stable-surface-is-checked).

### Hosts and installation

- Supported hosts are macOS on Apple silicon, Linux x64 and Linux ARM64 (Ubuntu 24.04). Each release has prebuilt
  archives for `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`, and
  `tools/install.sh --archive` verifies an archive's checksum before installing it.

### Experimental

These ship in 1.0.0 but are outside the stability promise:

- The desktop UI.
- Apple `debugserver` and Windows targets through `gdbserver.exe` or `lldb-server`: implemented with protocol
  tests, not yet live-verified.
- Raw processor profiles other than MSP430 and AVR8.
- The heuristic flywheel: the `improve` group served with `--corpus`, `report_observation`, and the `rampage-eval`
  flywheel and bundle commands.
- `rampage-eval`, the evaluation and benchmark harness.
- The WebAssembly triage-component plugin host.

### Known gaps

[Known limits](docs/known-limits.md) lists them in full. In short:

- Hosts: macOS on Apple silicon is tested; Intel macOS is untested. Linux x64 and Linux ARM64 build and test in
  CI, and this is their first release. Windows is not supported as a host.
- Without `rampage-worker` installed, decompilation runs in-process. Decompiled C is not proof of correct
  recovery, and worker supervision is not an OS sandbox.
- Bundled signatures recognise the library builds they were made from, not every version of a library.
- On a 50 MB image, `search` for the functions referencing a string stops on its work budget; a text search
  followed by `xrefs` works.
- Not built yet: DEX/JVM, Intel HEX/SREC and multi-region firmware maps, object-file relocation, Swift metadata,
  C++ layout recovery beyond RTTI evidence, and incremental analysis for very large binaries.
- The annotation log has no compaction; a log at its size limits can only be read.
