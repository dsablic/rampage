# Privacy surface

A smart device can hold a microphone, a camera, a view of what is on screen and the keys pressed on its remote.
`privacy_surface` answers an owner's question about one of its programs: what can this code capture, where can it
send it, how are the two connected, and is any capture reached from program start with no input handling found
on the way. It reports evidence of what
the code can do and how it is reached, never intent, and never that anything runs.

It is a guided report in the `carve` group, beside [`endpoint_inventory`](endpoint-inventory.md). It takes a
`path` and the usual `max_per_section` (default 25, at most 200). The path is a binary, an APK, AAB, JAR or DEX
file ([APKs and DEX files](#apks-and-dex-files)), or a directory such as an extracted firmware tree
([Directories](#directories-extracted-trees)), paged by `cursor`.

```json
{"tool": "privacy_surface", "path": "/work/rootfs/usr/bin/voiced"}
```

## The owner's flow

[How to check what a device records and where it sends it](device-privacy-check.md) walks through this flow
with the endpoint tools, from the update file to a router blocklist.

1. `fs_extract` the firmware image (see [firmware filesystem images](firmware-images.md)) and pick the programs
   that link audio, video or input libraries and the APKs, or give the whole extracted directory to
   `privacy_surface` ([Directories](#directories-extracted-trees)).
2. `privacy_surface` on each. Read `Capture triggers` first: a `no_user_trigger` finding says a capture is reached
   from program start with no input or UI handling on the way.
3. `Capture-to-send paths` ranks how closely each capture is tied to a network send or a file write; decompile the
   functions the next steps name to read what is recorded and sent.
4. `endpoint_inventory` on the same program lists every host it names, and `endpoint_blocklist` writes them as a
   router blocklist.

## Sections

| Section | What |
| --- | --- |
| `Capture sources` | Each capture in each function: what it uses, the medium (`microphone`, `camera`, `screen`, `input devices`) and an `evidence:` level. |
| `Capture-to-send paths` | Each pair of a capturing function and a sending or writing function connected by calls, best first, with the call chain. |
| `Capture triggers` | For each capturing function, what reaches it: program start, a timer, a network command, user input; and `no_user_trigger` where it applies. |
| `Send and write sinks` | Functions that can send over the network or write a file, with the endpoints they (or their direct callers) name. |
| `Excluded: not capture` | Calls that use a capture API in the other direction, such as an ALSA stream opened for playback. |
| `Capture strings not referenced from code` | Device paths and class names no discovered code references. |

### Evidence levels

Every source carries one of three levels, strongest first:

- `argument`: a capture API and a constant argument at the call that selects capture, read from the instructions
  just before the call (on x86-64, AArch64 and 32-bit ARM). Examples: `snd_pcm_open` with stream
  `SND_PCM_STREAM_CAPTURE`, tinyalsa `pcm_open` with `PCM_IN`, `pa_simple_new` with `PA_STREAM_RECORD`, an
  `ioctl` with `VIDIOC_STREAMON`.
- `name`: the API's name alone (`snd_pcm_readi`, `pa_stream_connect_record`), or a direction-selecting API whose
  argument was not a constant just before the call (`... (direction not read)`).
- `string`: the function references a device path (`/dev/video0`, `/dev/snd/pcmC0D0c`, `/dev/fb0`,
  `/dev/input/event1`) or an Android framework class name (`android/media/AudioRecord`).

A call whose constant argument selects the other direction is listed under `Excluded: not capture`, not as a source.

Some evidence shows a capability without showing capture: every string; a direction-selecting API whose argument
was not read; `/proc/asound`, `/dev/fb*`, `/dev/dri/` and `/dev/video*` (also output and codec devices); a PCM node
without an explicit `c` (`pcmC0D0`, or `pcmC%uD%u%c` whose letter is filled in at run time); and the requests drawing,
compositing and codec code issue too (`FBIOGET_*SCREENINFO`, `DRM_IOCTL_MODE_GETFB*`, `drmModeGetFB*`,
`VIDIOC_QUERYCAP`, `S_FMT`, `REQBUFS`, `QUERYBUF`, `QBUF`). Such a source carries an `ambiguous:` evidence line, is
one confidence step lower, lowers the paths it is on, and never supports `no_user_trigger`.

### What counts as a source

| Medium | APIs | Strings and request codes |
| --- | --- | --- |
| microphone | ALSA `snd_pcm_open` (capture stream), `snd_pcm_readi`/`readn`, `snd_pcm_mmap_readi`/`readn`; tinyalsa `pcm_open` (`PCM_IN`), `pcm_read`, `pcm_readi`; PulseAudio `pa_simple_new` (`PA_STREAM_RECORD`), `pa_simple_read`, `pa_stream_connect_record`; PortAudio input streams; AAudio `AAudioStreamBuilder_setDirection` (input); OpenSL ES `SL_IID_RECORD`; Android native `AudioRecord` and `MediaRecorder` | `/dev/snd/pcmC*D*c` (ending in `p`: playback, excluded; no letter: either direction), `/proc/asound`, `android/media/AudioRecord`, `android/media/MediaRecorder` |
| camera | `ioctl`/`v4l2_ioctl` with a V4L2 request (`VIDIOC_QUERYCAP`, `S_FMT`, `REQBUFS`, `QUERYBUF`, `QBUF`, `DQBUF`, `STREAMON`), `v4l2_read`; NDK camera2 (`ACameraManager_openCamera`, capture sessions); Android native `Camera` | `/dev/video*`, `android/hardware/Camera`, `android.hardware.camera2` |
| screen | `ioctl` with `FBIOGET_VSCREENINFO`/`FBIOGET_FSCREENINFO` or `DRM_IOCTL_MODE_GETFB`/`GETFB2`; `drmModeGetFB`/`drmModeGetFB2`; X11 `XGetImage`/`XShmGetImage`; Android `ScreenshotClient`, `captureDisplay`, `ScreenCapture` | `/dev/fb*`, `/dev/graphics/fb*`, `/dev/dri/`, `android/media/projection/MediaProjection` |
| input devices | `ioctl` with `EVIOCGRAB`, `EVIOCGNAME` or `EVIOCGBIT`; libevdev and libinput event reads | `/dev/input/*` |

ioctl requests are matched by type and number whatever their size and direction bits, so the 32- and 64-bit sizes
of `struct v4l2_buffer` and the MIPS encoding all match. Names match as `network_surface`'s do: case-insensitive,
with or without leading underscores, `@plt` and `__imp_` decorations; C++ framework classes match inside mangled
names.

### Sinks

- Socket: `send`/`sendto`/`sendmsg`/`connect` serve local IPC as well as the network, so they are listed as
  `socket (network or local)` at medium confidence. When the same function calls `socket` with a constant domain,
  `AF_UNIX` drops them (local IPC) and `AF_INET`/`AF_INET6` makes them network sends.
- Network: TLS writes, libcurl (`curl_easy_perform`), WinINet/WinHTTP sends, MQTT (`mosquitto_publish`, `mosquitto_connect`, Paho `MQTTClient_publish`, `MQTTAsync_send`) and WebSocket
  writes (`lws_write`, nopoll). Each network sink lists up to four endpoints that the function, or a function
  calling it directly, names in its strings, classified as [`endpoint_inventory`](endpoint-inventory.md) does.
- File (weaker: a file leaves the device only if something uploads it): `fopen` with a writing mode, `open`/`openat`
  with write flags, `creat`. A read-only open, or an `fopen` or `open` of `/dev/`, `/proc/` or `/sys/`, is not a sink; `fwrite`
  and `write` are named beside a file sink but are not sinks on their own.

### Paths and ranking

A path connects a capturing function and a sinking function through calls, within six call levels. Best first:

1. the same function captures and sends;
2. one calls the other directly;
3. one reaches the other a few calls down;
4. both are reached from a shared caller within four calls in all (a caller shared only through `main` or the
   entry point does not count: everything in a program shares it).

A socket or file sink and an ambiguous source each lower the confidence one step. When both functions reference the same
writable global (a shared buffer), the path says so, as a hint of a data link. A path shows that capture and send
code are connected, not that the captured data is what is sent.

### Triggers

Starting from each capturing function, the report walks callers up to six levels (and 2000 functions). Taking a
function's address counts as calling it, so a callback, a thread start (`pthread_create`) or a signal handler is
followed to the code that registers it. On the way it notes:

- `program start`: the entry point, `main`, an `.init_array` constructor or `JNI_OnLoad` (an exported function is
  reported as `export`: it runs when whatever loads the library calls it);
- `timer`: a function on the chain calls `timer_create`, `setitimer`, `alarm`, `timerfd_*` or similar (stronger when
  it registers the chain's next function as a callback); `periodic loop`: a function with a loop that sleeps;
- `network command`: a function on the chain receives from the network (`recv`, `accept`, `SSL_read`, MQTT
  message callbacks);
- `user input`: a function on the chain reads an input device or runs a UI event loop, or (`may follow user
  input`) a function on the chain also calls one directly, as in `if (button_pressed()) record();`.

`no_user_trigger` is stated for a microphone, camera or screen capture only when all of these hold: it is reached
from program start; its evidence shows direction (an `argument`-level capture or a capture-only API such as
`snd_pcm_readi`); no function among its callers within the bounds, nor a function one of them calls directly, reads
input or runs a UI loop; none of those callers is referenced from data (a table of handlers or operations, found by
scanning non-code segments for pointers, whose callers are not followed); and the walk was not cut. Otherwise the
program-start trigger says `no_user_trigger not stated` and why. It means none was found, not that none exists.

## APKs and DEX files

For an APK or DEX file the report has the same sections, read from the app's DEX code and merged with the native
report of each JNI library it ships (one ABI per library name, arm64-v8a first, at most 16). The report names its
`input` (`kind` `apk` or `dex`, `path`, `sha256`) instead of a binary `target`. Every finding's first evidence line
is its `origin`: `dex classes.dex` (or `classes2.dex`, ...), or the library path, which also prefixes a native
finding's observation (`lib/arm64-v8a/libnet.so: ...`).

```json
{"tool": "privacy_surface", "path": "/work/system/priv-app/Recorder/Recorder.apk"}
```

- **Sources:** the capture and personal-data APIs `dex_metadata`'s [`privacy` section](android.md#privacy) lists,
  as invoked by each method (`evidence: invoke`): `AudioRecord`, `MediaRecorder` audio and video sources, camera
  and camera2, `MediaProjection`, `PixelCopy`, accessibility window reads, location and device identifiers. A
  `native` method bound to a `Java_` export is a source when the export reaches a native capture.
- **Sinks:** network calls (`java.net.URL.openConnection`/`openStream`, `HttpURLConnection` and
  `HttpsURLConnection` `connect`/`getOutputStream`, `Socket`, `DatagramSocket`, `SocketChannel`, OkHttp
  `newCall`/`Call.execute`/`enqueue` and WebSocket `send`, Volley `RequestQueue.add`, Retrofit `create` and
  `Call.execute`/`enqueue`, `WebView.loadUrl`/`postUrl`, Paho MQTT `connect`/`publish`, gRPC channels and client
  calls, Cronet requests, Apache `HttpClient.execute`), `LocalSocket` (local), and file writes, weaker
  (`FileOutputStream`, `FileWriter`, `RandomAccessFile`, `Files.write`, `ContentResolver.insert` and
  `openOutputStream`, `openFileOutput`). Each network sink lists up to four endpoints from the const-strings of
  the method or a method calling it directly, classified as `endpoint_inventory` does, including strings
  [decoded](android.md#decoded-strings) by emulating a static decoder method at a call site there (`decoded by
  ... from ...`). A `native` method is a sink when its export reaches `connect`, `send` or another native sink.
- **Decoded strings:** a section of its own lists each decoded string with the decoder, the call site, the
  constant inputs and the instructions emulated.
- **Paths:** a call graph across every DEX file of the APK: direct, static and super invokes; virtual and
  interface invokes resolved through the app's class hierarchy (across DEX files) to the method the receiver's
  class defines, and by name and prototype to the overriding methods of app subclasses and implementers (at most
  32 per call; such edges are marked `by_name`: possible, not shown, and a path through one ranks lower); an app
  class with a framework supertype instantiated by a method (`registers callback`: a `Runnable`, a listener); and
  a component class loaded with `const-class` beside a call that starts it (`startService`,
  `startForegroundService`, `bindService`, `startActivity`, `sendBroadcast`, `Intent`/`ComponentName`
  constructors, WorkManager work requests, `JobInfo.Builder`), linked to its entry methods (`starts component`).
  A Java caller of a `native` method reaches what the bound export reaches through direct calls in its library.
  Ranking is as for binaries.
- **Triggers:** walking callers from each capture (6 levels, 2000 methods), the report names what the platform
  starts: `start at boot` (a `BOOT_COMPLETED`, `LOCKED_BOOT_COMPLETED` or `QUICKBOOT_POWERON` receiver, including
  through a service it starts), `app start` (the `Application` class or a content provider, which run when the
  app's process starts), `broadcast` (other receivers, exported or not, with their intent filter actions),
  `service start` (a service whose start was not seen, or an exported one other apps can start), `timer` (a
  WorkManager `Worker`, `JobService`, or a method calling `AlarmManager.set*`, `JobScheduler.schedule`,
  `WorkManager.enqueue*`, `Handler.postDelayed`, `Timer.schedule`, `ScheduledExecutorService.schedule*`),
  `network command` (`FirebaseMessagingService.onMessageReceived`, MQTT `messageArrived`, WebSocket `onMessage`,
  or a method calling `ServerSocket.accept`, `Socket.getInputStream`, `DatagramSocket.receive`), `accessibility
  event`, and `user input` (an activity or fragment method, a UI callback such as `onClick`, `onTouch`, `onKey*`,
  or a method registering an input listener).

`no_user_trigger` is stated for a microphone, camera or screen capture reached from boot or app start only when no
caller within the bounds is an activity, a UI callback or registers an input listener; the walk was not cut; no
`by_name` edge is among the callers; nothing in the app uses reflection (`Method.invoke`, `Class.forName`, ...),
method handles, `invoke-custom` or run-time code loading (`DexClassLoader`, `PathClassLoader`,
`InMemoryDexClassLoader`); the call graph hit none of its bounds and every DEX file was read; and every caller
without callers of its own is a known entry point. Otherwise the start trigger says `no_user_trigger not stated`
and why. A native library's own program-start claims are not stated in an APK report: the library starts when
Java code loads it with `System.loadLibrary`, whose callers are not checked.

## Directories (extracted trees)

For a directory the report reads one page of programs and APKs (`max_files` per page, default 10, at most 50;
`timeout_ms`, default 30,000, at most 300,000; at least one file per page) and gives `input.next_cursor` for the
next; pass it back as `cursor`. Executables that import no capture API and name no capture device or Android
capture class are not analysed (they are counted and the first 20 named in `limitations`). Each file's findings
are labelled with its path in the tree.

Every page also reads the tree's init files, so a program defined in one file and started from another is linked:

- Android init `.rc` files: `service <name> <path>` with its `class`, `oneshot` and `disabled`; a service not
  marked `disabled` starts at boot only when a boot-time action runs `class_start` for its class (otherwise it reads
  `no boot-time class_start found`); `start`, `restart`, `exec_start` and `enable` in `on <trigger>` actions, at
  boot when every part of the trigger is `early-init` through `boot`, `property:sys.boot_completed=1` or similar,
  otherwise on that trigger; and `exec -- <path>` commands. Recovery and charger `.rc` files are not boot.
- systemd units (`ExecStart=`, at boot when `[Install] WantedBy=` names `multi-user.target`, `default.target`,
  `graphical.target`, `sysinit.target`, `basic.target` or `network.target` and the target's `.wants` directory
  under `etc`, `lib` or `usr/lib` `systemd/system` links the unit), SysV init scripts (`etc/init.d`, `rc.d`, `rcS`,
  `rc.local`: absolute paths under a `bin` or `sbin` directory, only in the `start)` branch of a `case`) and
  `inittab` entries.

A program is matched to an init file by its device path (`/system/bin/voiced` is `system/bin/voiced` in the tree,
`bin/voiced` in an extracted partition, or `img.extracted/system/bin/voiced` deeper down), or by file name alone
when the path does not match (marked so, one confidence step lower, and never with `no_user_trigger`). An analysed
program with capture sources that is started at boot gets a `Capture triggers` finding naming the init file and
line; when its own report has a `no_user_trigger` finding, it reads `no_user_trigger: <program> is started at
boot, and its capture is reached from program start with no user-facing trigger found`. A `Boot services` section lists every start read, with the file and line and whether the program is
in the tree. Init files are read up to 2000 files, 1 MiB each and 16 MiB in all, 100,000 lines per file and 4096
characters per line, and 10,000 services and actions; a bound hit is a limitation.

## Limits

- Constant arguments are read only from the instructions just before the call in the same basic block, on x86-64,
  AArch64 and 32-bit ARM. Values passed through variables, helpers or other blocks leave a source at `name` level
  (and an ioctl unread); on other architectures ioctl-based sources are missing entirely, and the report says so.
- Virtual calls and other indirect calls in native code are not followed, and nothing is executed. In DEX code,
  reflection, method handles, framework code (a callback the framework makes on an object it was handed, other
  than the instantiation link above) and code loaded at run time are not followed, and natives registered with
  `RegisterNatives` are not linked.
- V4L2 also drives video output, decoders and HDMI input; framebuffer queries are also used to draw. A source shows
  the capability, not what is recorded.
- On a directory, programs started by other programs at run time (a shell script run by a service, a `fork` and
  `exec`) are not traced.
