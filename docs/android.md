# Android APKs and DEX files

On Android TV boxes, streaming sticks and phones, the code that records and sends lives in APKs: DEX bytecode,
the manifest's permissions and components, and native JNI libraries. The `android` MCP group reads all three
without a Java toolchain or a device. Inputs are treated as hostile: every offset and count is checked, and
reading is capped (see [Limits](#limits)).

| Tool | Answers |
| --- | --- |
| `dex_metadata` | What the app is and asks for: package, versions, SDK levels, permissions, components, boot receivers, native libraries with JNI exports, DEX files, one page of classes, methods or components. |
| `dex_code` | What one method does: its Dalvik bytecode, smali style, with every reference resolved. |
| `endpoint_inventory` (group `carve`) | The hosts and URLs in the app's DEX strings and native libraries, with the methods that load them. |

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
- `permissions`: every `uses-permission` with its `protection_level` (`dangerous` is a runtime prompt,
  `normal` is granted at install, `signature`/`signature|privileged` only for the platform's own or preinstalled
  system apps), a `category` (`microphone`, `camera`, `screen`, `location`, `contacts`, `phone`, `sms`,
  `storage`, `network`, `boot`, ...) and `privacy: true` when it reaches personal data or capture hardware.
  Platform levels come from the AOSP platform manifest (Android 14); a permission the app declares itself shows
  its declared level and `declared_here`; any other is `unknown`.
- `start_at_boot`: receivers of `BOOT_COMPLETED`, `LOCKED_BOOT_COMPLETED` or `QUICKBOOT_POWERON`, code that runs
  when the device starts with no user action.
- `components` (the first 60; `components_total` counts all): activities, activity aliases, services, receivers
  and providers with the absolute class `name`, `exported` (explicit, or the platform default: exported when it
  has an intent filter and the target SDK is below 31; providers below 17), `permission`, intent filters
  (`actions`, `categories`, `data`, `priority`), `foreground_service_type` names (`microphone`, `camera`,
  `mediaProjection`, ...), `bound_role` for services bound by the system for a powerful role
  (`accessibility_service`, `notification_listener`, `device_admin`, `input_method`, `voice_interaction`,
  `vpn_service`), and `in_dex`: whether a DEX file in the APK defines the class.
- `native_libs`: each `lib/<abi>/*.so` with its size, `jni_exports` (the `Java_*` symbols, the JNI names of
  `native` methods) and `jni_onload` (a library with `JNI_OnLoad` may register natives by table instead of by
  name).
- `dex`: each DEX file in multidex order (`classes.dex`, `classes2.dex`, ...) with its version, whether the
  Adler-32 checksum and SHA-1 signature match (reported, never required), and its class, method, field, string and
  type counts; `totals` sums them.
- `page`: one page of the `list` chosen: `classes` (default; name, superclass, interfaces, access, field and method
  counts, `native_methods`, source file), `methods` (smali signature, method index, access, code units and
  registers) or `components`. `prefix` keeps classes whose Java name starts with it (`com.example.net`, or the
  descriptor form `Lcom/example/net/`), `package` keeps a package and its subpackages; `offset`/`limit` page
  (default 100, at most 500) and `next_offset` continues.

A bare `.dex` file has the DEX fields only.

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
seen; a call reached from a boot receiver says the code path exists, not that it runs.

## Endpoints

[`endpoint_inventory`](endpoint-inventory.md) reads APKs and DEX files: every DEX string pool, with the methods
that load each string and the networking calls they make, and every native library in the APK.

## dex_code

```json
{"tool": "dex_code", "path": "Recorder.apk", "method": "Lcom/example/recorder/Capture;->start()V"}
```

`method` names one defined method: `Lpkg/Class;->name(params)ret` (the smali form, as `dex_metadata`'s method
list prints it), `Lpkg/Class;->name` or `pkg.Class.name` when the name is not overloaded (an overloaded name is
refused with each candidate), a method index into the first DEX file (`12`) or into a named one
(`classes2.dex:12`).

The result has the method's access flags, `registers`, `ins`, `outs`, `code_units`, `tries` (each with `start`
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
holding that address. A `native` method has `body: null` and points at the native libraries. There is no
decompilation to Java yet.

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
| APK members | 1 GiB read in total; native libraries over 64 MiB are listed without exports; ZIP inflation stops at the declared size and at a 1000:1 ratio past 64 MiB |

Signed APK blocks are not verified, and an AAB's protobuf manifest is reported as unreadable.
