# Android APKs and DEX files

On Android TV boxes, streaming sticks and phones, the code that records and sends lives in APKs: DEX bytecode,
the manifest's permissions and components, and native JNI libraries. The `android` MCP group reads all three
without a Java toolchain or a device. Inputs are treated as hostile: every offset and count is checked, and
reading is capped (see [Limits](#limits)).

| Tool | Answers |
| --- | --- |
| `dex_metadata` | What the app is and asks for: package, versions, SDK levels, permissions, components, boot receivers, native libraries with JNI exports, DEX files, one page of classes, methods or components, or the strings static decoder methods produce (`decoded_strings`). |
| `dex_code` | What one method does: its Dalvik bytecode, smali style, with every reference resolved, or structured pseudocode. |
| `endpoint_inventory` (group `carve`) | The hosts and URLs in the app's DEX strings and native libraries, with the methods that load them. |
| `privacy_surface` (group `carve`) | What the app can capture and send, the call paths between, and what starts each capture (boot, app start, push, jobs, UI), merged with its native libraries' report. |

Enable the group with `enable_tools {"groups": ["android"]}`. Pull an APK off a firmware image with
[`fs_extract`](firmware-images.md) first; `fs_list` and `fs_extract` also open any APK as a ZIP, so its native
libraries can be extracted and opened by path with the binary tools.

## dex_metadata

```json
{"tool": "dex_metadata", "path": "/work/system/priv-app/Recorder/Recorder.apk"}
```

`path` is an `.apk`, `.aab`, `.jar` or `.dex` file (recognised by its magic bytes), or a directory. A directory is
walked (symlinks not followed) for those files and returns a summary per file, `max_files` per page (default 10,
at most 50), with `next_cursor` for the next page.

For one file the result holds:

- `package`, `version_code`, `version_name`, `sdk` (`min`, `target`, `max`, `compile`) and `application`
  (`debuggable`, `allow_backup`, `uses_cleartext_traffic`, `network_security_config`, `shared_user_id`).
- `permissions`: every `uses-permission` with its `protection_level` as the platform declares it, flags included
  (`dangerous|instant`, `signature|privileged|role`, `signature|appop`, `internal|role`), its `base_level`
  (`dangerous` is a runtime prompt, `normal` is granted at install, `signature` and `internal` only for the
  platform's own or preinstalled system apps), a `category` (`microphone`, `camera`, `screen`, `location`,
  `contacts`, `phone`, `sms`, `storage`, `network`, `boot`, ...) and `privacy: true` when it reaches personal data
  or capture hardware. Platform levels come from the AOSP platform manifest at the `android14-release` tag; a
  permission the app declares itself shows its declared level and `declared_here`; any other is `unknown`.
- `start_at_boot`: receivers of `BOOT_COMPLETED`, `LOCKED_BOOT_COMPLETED` or `QUICKBOOT_POWERON`, code that runs
  when the device starts with no user action.
- `components` (the first 60; `components_total` counts all): activities, activity aliases, services, receivers
  and providers with the absolute class `name`, `exported` (explicit, or the platform default: exported when it
  has an intent filter and the target SDK is below 31; providers below 17), `permission`, intent filters
  (`actions`, `categories`, `data`, `priority`), `foreground_service_type` names (`microphone`, `camera`,
  `mediaProjection`, ...), `bound_role` for services bound by the system for a powerful role
  (`accessibility_service`, `notification_listener`, `device_admin`, `input_method`, `voice_interaction`,
  `vpn_service`), and `in_dex`: whether a DEX file in the APK defines the class.
- `jni`: the native methods linked to their libraries (see [JNI](#jni)).
- `native_libs`: each `lib/<abi>/*.so` with its size, `jni_exports` (the `Java_*` symbols, the JNI names of
  `native` methods) and `jni_onload` (a library with `JNI_OnLoad` may register natives by table instead of by
  name).
- `dex`: each DEX file in multidex order (`classes.dex`, `classes2.dex`, ...) with its version, whether the
  Adler-32 checksum and SHA-1 signature match (reported, never required), and its class, method, field, string and
  type counts; `totals` sums them.
- `page`: one page of the `list` chosen: `classes` (default; name, superclass, the first 32 interfaces with
  `interfaces_total`, access, field and method counts, `native_methods`, source file), `methods` (smali signature,
  method index, access, code units and registers), `components`, `permissions`, `native_libs`, `dex_files` or
  `decoded_strings` ([decoded strings](#decoded-strings)). `prefix` keeps classes whose Java name starts with it
  (`com.example.net`, or the descriptor form `Lcom/example/net/`), `package` keeps a package and its subpackages;
  `offset`/`limit` page (default 100, at most 500) and `next_offset` continues.

The summary beside the page stays within about 20,000 bytes: every list in it is cut (to 200 rows first, halved
until it fits), each cut list keeps its full length as `<list>_total`, and `trimmed` says the lists are cut and
which `list` pages them. Names longer than 1 KiB (types, members, manifest values) are cut with `…`. A bare `.dex`
file has the DEX fields only. A DEX 041 container that holds several DEX files has only its first read; the
`dex` row's warnings say how many more it holds.

## JNI

`jni` links the `native` methods the DEX code declares to the native libraries:

- `linked`: methods bound by name, each with `bound_by_name`: the `library` and `symbol` of every export that binds
  it (`Java_<class>_<method>`, or the long form with `__<signature>` used for overloads), mangled as the JNI
  specification says (`_1` for `_`, `_2` for `;`, `_3` for `[`, `_0xxxx` for other characters).
- `unlinked`: native methods no export binds, with the `expected_symbol`. Libraries with `JNI_OnLoad` that hold the
  method's name and signature as NUL-terminated strings are listed in `possibly_registered_in`: they likely
  register it with `RegisterNatives`, which binds by table at run time; the table itself is not decoded.
- `exports_without_native`: `Java_` exports no declared native method claims (code from another app, a removed
  method or obfuscation).

A bare DEX file lists its native methods as `unlinked`; a directory page keeps `native_methods`. Open a library
with the binary tools (after `fs_extract` of the APK) to decompile the bound function.

## privacy

`dex_metadata` also reports what the app's DEX code can capture, read from the methods its code actually invokes
(`invoke-*` instructions), not from strings:

- `capture_apis`: each Android capture or personal-data API invoked, with its `medium` (`microphone`, `camera`,
  `screen`, `location`, `identifiers`), its `callers` (the first 16, and `callers_total`), the `permissions` that
  guard it and `permission_requested` (whether the manifest asks for one; screen capture asks the user at run time
  instead), and `reached_from_boot`: the start-at-boot receivers from whose methods a caller is reachable through
  direct calls. APIs: `AudioRecord`, `MediaRecorder` audio and video sources, `SpeechRecognizer`,
  `AlwaysOnHotwordDetector`, `AudioPlaybackCaptureConfiguration`, `Camera`, camera2 `CameraManager.openCamera`
  and `CameraDevice` sessions, `MediaProjection` and `MediaProjectionManager`, `PixelCopy`, accessibility window
  reads, `LocationManager`, Wi-Fi scans, and `TelephonyManager`/`Build` device identifiers.
- `accessibility_services`: classes extending `AccessibilityService`, which can read everything on screen once
  enabled.
- `media` sums them up; a directory page keeps `media` and `capture_apis_total` per file.

```json
{"api": "Landroid/media/AudioRecord;->startRecording()V", "medium": "microphone",
 "callers": ["Lcom/example/recorder/Capture;->start()V"], "callers_total": 1,
 "permissions": ["android.permission.RECORD_AUDIO"], "permission_requested": true,
 "reached_from_boot": ["com.example.recorder.BootReceiver"]}
```

Calls through reflection, interfaces or superclass references, native code and code loaded at run time are not
seen; a call reached from a boot receiver says the code path exists, not that it runs. `accessibility_services`
follows the class hierarchy across every DEX file of the APK. For call paths to network sends and the triggers of
each capture, run [`privacy_surface`](privacy-surface.md#apks-and-dex-files) on the APK.

## Endpoints

[`endpoint_inventory`](endpoint-inventory.md) reads APKs and DEX files: every DEX string pool, with the methods
that load each string and the networking calls they make, and every native library in the APK.

## Decoded strings

Apps often hide URLs and keys behind a static decoder method: `static String a(String)` that XORs each character,
`a(int)` that reads from a byte array filled in the class's static initializer, a Base64 step. rampage finds every
call site where constants (`const-string`, `const` ints) go straight into a static app method returning `String`,
and runs that method on those inputs in a small Dalvik interpreter. `dex_metadata` with `list: "decoded_strings"`
pages the results (`prefix`/`package` filter by the calling class):

```json
{"output": "collector.example.net",
 "decoder": "Lcom/example/watch/Strings;->get(I)Ljava/lang/String;",
 "caller": "Lcom/example/watch/Snapshot;->take()V", "address": "0x0004", "dex": "classes.dex",
 "inputs": ["0"], "steps": 425}
```

The same strings feed [`endpoint_inventory`](endpoint-inventory.md) with `decode` (evidence `dex_decoded`) and
[`privacy_surface`](privacy-surface.md#apks-and-dex-files), which names them as the endpoints of the sinks in the
calling method or its callers and lists them in a `Decoded strings` section.

The interpreter models integer and long arithmetic, branches and switches, arrays (`new-array`,
`fill-array-data`, `aget`/`aput`, `filled-new-array` of ints, `System.arraycopy`), `String` (constructors from
`char[]` and `byte[]` with UTF-8, ISO-8859-1 or US-ASCII, `charAt`, `toCharArray`, `getBytes`, `substring`,
`concat`, `valueOf`, ...), `StringBuilder`/`StringBuffer`, `android.util.Base64` and `java.util.Base64` decoders,
`Integer.parseInt`, and the static fields of app classes (initial `static_values`, then the class's `<clinit>`,
run within each emulation under its budget, so no emulation sees another's static writes; a static whose initial
value is a type, enum, method or array constant stops the emulation). Calls into other static app methods nest up
to 16 deep. There is no I/O, no reflection, no instance field and no object of an app class: any other instruction
or call stops that emulation, as does Java behaviour not modelled exactly (case conversion of non-ASCII text, a
lone surrogate in `getBytes`, non-ASCII Base64 input), as do 100,000 instructions (a library call charges one per
character or element it handles, and a switch table is built once per body), 64 Ki elements per array, 1 Mi array
elements and string characters allocated, a string past 64 Ki characters, or a decoder body over 1 Mi code
units. Constants are read within a call site's basic block only (not across switch cases, handlers or jumps).
Each distinct decoder and input is emulated once (shared by every call site passing the same); an app is decoded
at up to 4096 call sites, 2048 emulations and 8 million instructions in all, with 64 Mi code units scanned for
call sites (each body once). The graph and decoded strings of the last APK read are kept, so further pages and
reports on it do not rebuild them. Only printable results of two or more characters that differ from the input are kept.

## dex_code

```json
{"tool": "dex_code", "path": "Recorder.apk", "method": "Lcom/example/recorder/Capture;->start()V"}
```

`method` names one defined method: `Lpkg/Class;->name(params)ret` (the smali form, as `dex_metadata`'s method
list prints it), `Lpkg/Class;->name` or `pkg.Class.name` when the name is not overloaded (an overloaded name is
refused with each candidate), a method index into the first DEX file (`12`) or into a named one
(`classes2.dex:12`).

The result has the method's access flags, `registers`, `ins`, `outs`, `code_units`, `tries` (the try ranges
overlapping the returned instructions, at most 64, with `tries_total` and `tries_on_page`; each with `start`
and `end` labels and its handlers' catch `type` or `<any>`), and a page of `instructions`, each with its code-unit
`address` (hex), `op`, `args` and, for an index operand, `ref` (`kind`: string, type, field, method, proto,
call_site or method_handle, and `index`):

```
0000 new-instance v0, Landroid/media/AudioRecord;
0002 invoke-virtual {v0}, Landroid/media/AudioRecord;->startRecording()V
0005 const-string v1, "https://telemetry.example.com/upload"
```

Branch targets are `:xxxx` code-unit labels. All 256 opcode values decode (`unused` for unassigned ones), including
`invoke-polymorphic` (with its prototype), `invoke-custom` (call site with its bootstrap method handle, name and
type) and `const-method-handle`/`const-method-type`. The `packed-switch`, `sparse-switch` and `fill-array-data`
payloads are listed as `*-payload` pseudo-instructions with their keys and absolute targets, or element width,
count and data (the first 64 bytes). Bytes that decode to no complete instruction show as `.unit`. `offset` and
`limit` (default 200, at most 1000) page by instruction, or `at` (`:0012`, `0x12`, `18`) starts at the instruction
holding that address. A `native` method has `body: null` and points at the native libraries.

### Pseudocode

`view: "pseudo"` renders the method as structured pseudocode instead, paged by line (`offset`/`limit`, the same
defaults, `lines_total`, `next_offset`):

```text
static String Codec.decode(String p1) {
    char[] v0;
    var v1;
    var v2;
    String v3;
    v0 = p1.toCharArray();
    v1 = 0;
    while (true) {
        v2 = v0.length;
        if (v1 >= v2) break;
        v2 = v0[v1];
        v2 = v2 ^ 0x5a;
        v2 = (char) v2;
        v0[v1] = v2;
        v1 = v1 + 1;
    }
    v3 = new String(v0);
    return v3;
}
```

Parameters are named `this` and `p1`, `p2`, ...; other registers keep their `vN` names and are declared with the
type every write gives them (`var` when writes disagree). Loops come from back edges (`while (true)` with `break`
and `continue`), `if`/`else` from forward branches, invokes read as Java-like calls with the result folded into an
assignment, `new-instance` and its constructor as `new T(...)`, and const-strings inline. Every jump that fits no
structure stays a `goto L_xxxx` to a label, so the text keeps the bytecode's meaning; try ranges are listed as
comments with their handler labels. It is not Java: types are not propagated through expressions, and the smali
view is the authority. Bodies over 20,000 instructions render with gotos only, nesting past 48 levels falls back to
gotos, and output stops at 5,000 lines (`truncated`).

## Limits

| What | Cap |
| --- | --- |
| DEX file | 256 MiB; 16 DEX files per APK are parsed, the rest listed |
| Id tables | 2^22 entries each, and every table must fit the file |
| Class members decoded | 4 Mi per file (shared class data counts each time) |
| Method body | 4 Mi code units |
| String | 1 MiB of modified UTF-8 |
| Superclass walk | 64 levels; cycles end the walk |
| Binary XML | 16 MiB, 64 levels of nesting, 200,000 nodes, 32 Mi characters of decoded text |
| Catch clauses | 65,536 per method body, each distinct handler decoded once however many tries share it; 16 listed per try |
| Type lists | 65,535 entries; 32 interfaces listed per class |
| Names in reference text | 1 KiB; a long string many ids share is decoded once |
| Call graph (`privacy_surface`) | 2 Mi methods, 8 Mi edges, 64 Mi code units; 32 by-name targets per call and 4096 candidates checked; walks of 6 levels and 2000 methods |
| String decoding | 100,000 instructions, depth 16, 64 Ki elements per array, 1 Mi elements and characters per emulation; 4096 call sites, 2048 emulations, 8 M instructions per app |
| APK members | 384 MiB read in total; native libraries over 64 MiB are listed without exports; ZIP inflation stops at the declared size and at a 1000:1 ratio past 64 MiB |

DEX files are read in multidex order (`classes.dex`, `classes2.dex`, ...) whatever their order in the archive.
When an APK holds several `AndroidManifest.xml` entries, the first is read, as the installer does, and a warning
says how many there are. ZIP members whose data overlap another's (a ZIP-bomb or polyglot trick) are noted on the
listing. Signed APK blocks are not verified. An AAB's `base/manifest/AndroidManifest.xml` is protobuf and is
reported as not read yet; its `base/dex/` files and native libraries are read.
