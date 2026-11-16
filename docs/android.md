# Android APKs and DEX files

On Android TV boxes, streaming sticks and phones, the code that records and sends lives in APKs: DEX bytecode,
the manifest's permissions and components, and native JNI libraries. The `android` MCP group reads all three
without a Java toolchain or a device. Inputs are treated as hostile: every offset and count is checked, and
reading is capped (see [Limits](#limits)).

| Tool | Answers |
| --- | --- |
| `dex_metadata` | What the app is and asks for: package, versions, SDK levels, permissions, components, boot receivers, native libraries with JNI exports, DEX files, one page of classes, methods or components. |

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
