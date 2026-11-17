# Android APK and DEX, first slice (2026-11-16, 1.7.0)

Smart-device privacy track (todo.md): on Android TV boxes, streaming sticks and phones the logic that records and
sends lives in APKs: DEX bytecode, the manifest's permissions and components, and native JNI libraries. This slice
lets an owner read all three through MCP, the way `dotnet_metadata`/`dotnet_il` read a managed assembly.

## Scope

| Item | Status |
| --- | --- |
| DEX 035–041: header, checksum (Adler-32) and SHA-1 reported, string/type/proto/field/method ids, class_defs, class_data, code_items with tries and handlers, map_list | slice 1 |
| Multidex (`classes.dex`, `classes2.dex`, ...) | slice 1 |
| APK/AAB as ZIP (stored and deflate members) through `rampage-unpack` | slice 1; also gives `fs_list`/`fs_extract` on any ZIP |
| Android binary XML (AXML) for `AndroidManifest.xml` | slice 1 |
| `resources.arsc` | string pool count only; resource resolution is slice 2 |
| `dex_metadata`, `dex_code` (Dalvik disassembly, every opcode and payload) | slice 1 |
| Android capture APIs invoked from code, linked to permissions and boot receivers | slice 1, as a `privacy` section of `dex_metadata` |
| `endpoint_inventory` on APK/DEX string pools, with the methods that load each string | slice 1 |
| JNI: `native` methods to `Java_*` exports in the APK's `.so` files | slice 1 if time allows |
| `privacy_surface` taking an APK, Dalvik to Java, string decryption, obfuscation-aware naming, resources | slice 2 |

## Borrow before building

The crates.io DEX readers (`dex`, `dexparser`) are unmaintained, stop at 035–038 and trust header counts. The
format is small and fully specified, so the parser is in-house, like the .NET reader. ZIP reading goes into
`rampage-unpack` as a new image format: it already meters decompression ratio, caps per-file and total output and
spools nested images, and `archive_inventory` is deliberately metadata-only (4096 records, no member reads) and
would refuse large real APKs.

## Design

- Crate `rampage-dex` (no I/O beyond what it is handed): `dex` (parser), `insn` (opcode table and decoder),
  `axml` (binary XML), `manifest`, `permissions` (protection levels, vendored from AOSP's platform manifest,
  Apache-2.0), `apk` (members of an APK through `rampage-unpack`), `testkit` (feature `testkit`: a DEX writer
  with a correct map_list, checksum and signature, an AXML writer and an APK assembler for tests).
- `rampage-api/src/android.rs`: `dex_metadata` and `dex_code` as file tools in a new `android` group. Input: an
  `.apk`/`.aab`/`.dex`, or a directory of them (paged by cursor).
- `dex_metadata`: package, versions, SDK levels, permissions (protection level, privacy flag), components with
  intent filters, exported flags and start-at-boot receivers, native libraries per ABI with `Java_*` exports, a
  DEX summary and one page of classes or methods (`list`, `prefix`, `package`), the `privacy` capture-API section
  and the JNI links.
- `dex_code`: one method by `Lpkg/Class;->name(sig)ret`, `pkg.Class.name` or method index; instructions with
  every reference resolved to text, try ranges, payloads, paged by instruction index.

## Hostile-input limits

Every offset and size is bounds-checked before use; nothing is allocated from a header count until the table it
describes is known to fit the file. Caps: DEX file 256 MiB, 16 DEX files per APK, 2^20 entries per id table, 8 MiB
per code item, uleb128 at most 5 bytes, MUTF-8 strings checked against their declared length, class hierarchy walks
cut at 64 levels (cycles cannot loop), AXML file 16 MiB with string pools checked against chunk size, 64 levels of
element nesting, ZIP members through `rampage-unpack`'s ratio meter and per-file limit (64 MiB per DEX or manifest).

## Fixtures and tests

No Java toolchain runs on this machine (no JDK for d8), so fixtures are built by `testkit`: a DEX with a class
calling `AudioRecord.startRecording`, a URL string, a `BOOT_COMPLETED` receiver, a `native` method, and an APK
holding it, a manifest and `lib/arm64-v8a/libnative.so` (a tiny `zig cc` library exporting the matching
`Java_` symbol, committed with its source and no local paths). Hostile tests: truncated and overlapping sections,
huge counts, uleb128 overflow, cyclic superclasses, bad MUTF-8, AXML string pool bombs, ZIP bombs.

## Slice 2 (2026-11-17)

- `rampage-dex::graph`: the app's call graph across every DEX file (direct invokes; virtual and interface invokes
  resolved through the class hierarchy, overrides by name marked `by_name`; callbacks from instantiated classes
  with a framework supertype; const-class component starts), every pass bounded (methods, edges, code units,
  by-name targets and candidates per call) with each bound hit noted.
- `privacy_surface` on an APK or DEX file (`android_privacy.rs`): DEX sources and sinks, paths and Android
  triggers over that graph, merged with each JNI library's native report; directory mode (`privacy_tree.rs`) with
  init `.rc`, systemd and init.d boot starts (`init_services.rs`).
- `rampage-dex::emulate`: string decryption by emulating static decoder methods at constant-argument call sites,
  feeding `dex_metadata` (`decoded_strings`), `endpoint_inventory` (`dex_decoded`) and `privacy_surface`.
- `rampage-dex::pseudo`: `dex_code` `view: "pseudo"`.
- Fixture `watch.apk` with `libnet-arm64.so` (net.c), written by the testkit's Dalvik assembler.
