# Acceptance pass on independently built inputs (2026-11-20)

Part of the [accuracy benchmarks](../benchmarks.md). This is the first run of the
[acceptance set](../plans/2026-11-20-acceptance-set.md): 19 public files built by other people (OpenWrt release
images, MicroPython ESP32/ESP8266 firmware with their ELF files, Debian's `zlib1g` for mipsel with its debug
packages, and an F-Droid APK pair). Planning rule 1 says a track is done when it has run on an input it was not
built from; this run supplies that for the MIPS, Xtensa/ESP, `carve`, `fs_list`, `diff_firmware`,
`evaluate_function`, `check_claim` and Android work.

## How it was run

- **Build:** a release build of `main` at `0c52ac3` (1.8.0 plus the first slice of incremental analysis):
  `rampage` and `rampage-worker`.
- **Inputs and truth:** `tools/acceptance/fetch.py` downloaded all 19 files and every SHA-256 matched.
  `tools/acceptance/derive_truth.py` wrote the truth without rampage (unsquashfs, llvm-nm, llvm-readelf, header
  parsing, the builders' manifests and debug files). One truth value was wrong and is corrected here: C2's link
  count (see C2).
- **Deterministic checks:** each call went through `rampage mcp` over stdio from a small script (the suite v4 MCP
  client), with every tool group enabled and the analysis store off. No model was involved.
- **Agent tasks:** `claude-haiku-5-5` through `tools/agent-bench/claude-runner.py` (Claude Code 2.1.329, no user
  settings, only the rampage server's tools and ToolSearch), default tool groups, one repetition each, at most 40
  turns, $0.25 per task. The prompts name no tool. Each file was copied to a fresh directory under a neutral name
  (`fixture.so`, `firmware.bin`, `old.bin`/`new.bin`, `flash.bin`, `app.apk`, `firmware.trx`).
- **Fixes:** failures were diagnosed in the code. Small ones were fixed on the branch with regression tests on
  self-built or committed fixtures, then the affected checks were run again on a new release build. Those reruns
  are marked "after".

No input is committed and none is named by a local path in the repository.

## Scoreboard

Twenty checks have a bar set before the run. Before fixes, 15 passed and 5 failed (M1, M2, M4, M5, F2). After the
fixes, 17 pass and 3 fail (M1, M5, F2). Six more are recorded without a bar (X6, F3, A2, A3, and the M5 and F2
numbers that remain). The eight agent tasks: 5 correct, 1 partly correct, 2 wrong; after the ESP fix, task 5 is
correct and task 6 is still wrong.

| Id | Before | After | Note |
| --- | --- | --- | --- |
| C1 | pass | pass | |
| C2 | pass | pass | Truth corrected from 202 to 207 links |
| C3 | pass | pass | |
| C4 | pass | pass | After: load address reported, UBI extent covers all 37 erase blocks |
| C5 | pass | pass | |
| C6 | pass | pass | |
| M1 | fail | fail | 90.7% of starts (bar 95%); MIPS PIC switch tables and ELF constructor seeds |
| M2 | fail | pass | Callees now named |
| M3 | pass | pass | |
| M4 | fail | pass | One wrong verdict before the fix |
| M5 | fail | fail | MIPS16e now stated; five sstrip'ed shared libraries still list no functions |
| X1 | pass | pass | After: `file_layout` and the open error also point at the application |
| X2 | pass | pass | 99.3% |
| X3 | pass | pass | |
| X4 | pass | pass | 99.8% |
| X5 | pass | pass | |
| X6 | record | record | 61% recall |
| F1 | pass | pass | |
| F2 | fail | fail | Before: the application was never compared. After: compared, but 546 functions reported changed (bar under 100) |
| F3 | record | record | |
| F4 | pass | pass | |
| A1 | pass | pass | |
| A2 | record | record | No reference tool installed |
| A3 | record | record | |

## Containers and filesystems

**C1, `carve` and `file_layout` on the 23.05.5 sysupgrade image.** Truth: SquashFS at 2338624. `carve` reports one
validated SquashFS at 2338624 (xz, 262144-byte blocks, 4056152 bytes). `file_layout` maps the same span as one
occupied region of entropy 8.0. **Pass.**

**C2, `fs_list` at that offset.** Truth as derived: 1051 regular files and 202 symbolic links. `fs_list` counts
1051 files, 207 symlinks, 115 directories and 1 character device. The five extra links point at directories:
`derive_truth.py` counted links through `os.walk`'s file list, which leaves out links to directories
(`find -type l` gives 207). The script is fixed and the truth is now 207. **Pass.**

**C3, `fs_extract bin/busybox`.** Truth: SHA-256 `2429b3da…` from the unsquashfs tree. The extracted file has the
same hash. **Pass.**

**C4, `carve` on the NAND factory image.** Truth: uImage at 0 (data size 2559594, load 0x80060000), UBI at
0x500000. `carve` reports a validated uImage at 0 (extent 2559658, which is the data plus its 64-byte header),
a validated UBI image at 0x500000 and the SquashFS inside its first volume at 0x541000. `fs_list` at 0x500000
lists the two volumes, `rootfs.img` (holds SquashFS) and `rootfs_data.img`. **Pass.** Two gaps were fixed:
- The uImage notes gave only the name and a numeric compression type. After: load address 0x80060000, entry,
  data size 2559594 and compression `lzma`.
- The UBI extent stopped after 32 erase blocks, and the last five appeared as `magic_only` UBI candidates because
  their erase counter headers carry OpenWrt's end-of-image marker (`EOF` in the header padding). `fs_list` already
  read all 37. After: the extent is 37 blocks and a note says five carry the marker.

**C5, `carve` on the Broadcom TRX.** Truth: length 5771264, partitions at 28, 2344 and 2255872, SquashFS at
2255872. `carve` reports the TRX at 0 with extent 5771264 and notes "partitions at 0x1c, 0x928, 0x226c00", a gzip
stream at 28 and SquashFS at 2255872. **Pass.**

**C6, `carve` on the MediaTek FIT image.** Truth: device tree at 0 (4096 bytes), SquashFS at 5230592. `carve`
reports the DTB at 0 with extent 4096, the embedded kernel and device-tree blobs, and SquashFS at 5230592.
**Pass.**

## MIPS (`libz.so.1.2.13`, mipsel, stripped)

**M1, `list_functions`.** Truth: 129 function symbols from the debug file. rampage lists 134 functions and finds
117 of the 129 starts (90.7%), below the 95% bar. **Fail.** The 17 extra starts are the `.MIPS.stubs` entries at
0x15100–0x15200, which are real code the truth does not list. The 12 missed starts, by cause:
- `inflate_fast` and `inflate_table` are called with `bal` from parts of `inflate` and `inflateBack` that
  discovery never reaches. Those functions dispatch through GCC's position-independent switch tables: the table
  address is a local GOT page plus `%lo`, each entry a `.gpword` (an offset from `$gp`), then `addu $2, $2, $gp;
  jr $2`. rampage has no MIPS switch-table recovery, so every case block is lost.
- `deflate_fast` and `deflate_slow` are reached only through `configuration_table`, a table of function pointers
  in relocated data; `longest_match` is called only from them.
- `_init`, `_fini`, `frame_dummy` and `__do_global_dtors_aux` are reached from `DT_INIT`, `DT_FINI` and the
  init/fini arrays, which rampage does not seed for any architecture; `register_tm_clones` and
  `deregister_tm_clones` are called only from them.
- `_tr_tally` has no caller in this build.

Recorded as follow-ups, not fixed here: MIPS switch tables and ELF constructor seeds are discovery features.

**M2, `decompile` `deflateInit_` (0x7c34) and `uncompress` (0x11088).** Truth: they call `deflateInit2_` and
`uncompress2`. Before: the calls read `(*pcRam000300d4)(param_1,param_2,8,0xf,8,0,param_3,param_4)` and
`(*pcRam000300b8)()`. The library calls its own exported functions through global GOT entries that hold their
addresses, and the decompiler named only entries of imports. **Fail before, fixed:** each global GOT entry that
holds one of the image's functions is now bound to it. After: `deflateInit2_(param_1,param_2,8,0xf,8,0,param_3,
param_4)` and `uncompress2()`. **Pass after.**

**M3, `evaluate_function`.** Truth: `crc32(0, "123456789", 9)` = 0xCBF43926, `adler32(1, "123456789", 9)` =
0x091E01DE, `compressBound(0)` = 13. Results: 0xcbf43926 (118 steps), 0x091e01de (61 steps) and 0xd (7 steps),
each `stop: returned`. **Pass.**

**M4, `check_claim`.** Truth: verified, refuted, verified, refuted. Before: **refuted**, refuted, verified,
refuted. The first claim gave no `args`, so the checker ran `crc32` with the default `(data, length)`, but zlib's
signature is `crc32(crc, buf, len)`; the function returned the buffer pointer and the claim was refuted with
confidence `exact`. A wrong verdict is a failure of the feature. **Fail before, fixed:** a checksum claim without
`args` now also tries `(seed, data, length)` and `(data, length, seed)`, the seed being the checksum of no bytes,
before refuting; a layout whose run faults counts as wrong for that layout only. After: verified (with args
`[0x0, data, length]`), refuted, verified, refuted. **Pass after.**

**M5, `binary_info` and `list_functions` on the 87 OpenWrt programs.** No call crashed or timed out; each took
under 0.1 s. **Fail**, on both halves of the bar:
- **The 76 MIPS16e programs.** Before, nothing said MIPS16e was not decoded: `busybox` listed four functions (its
  MIPS32 startup code) as if that were the program. After, `binary_info` warns and `list_functions` notes "the
  ELF header marks MIPS16e code, which rampage does not decode: … Only the MIPS32 code is analysed". The listed
  functions are genuine MIPS32 code. `jalx` calls into the other instruction set are now calls whose target is
  not followed, so its bytes cannot be decoded as MIPS32. This half now meets the bar.
- **The 11 programs without MIPS16e.** The six executables list functions (`dropbear` 472, `usign` 79, `px5g` 74,
  `jffs2reset` 31, `mount_root` 22). The five shared libraries list none (`libfstools.so`, `libgcc_s.so.1`,
  `libmbedcrypto`, `libmbedtls`, `libmbedx509`) and `libc.so` lists two. OpenWrt strips every program with
  `sstrip`, which removes the section headers. rampage reads dynamic symbols only through the `.dynsym` section,
  so these libraries have no exports and no imports, and with no entry point nothing seeds discovery. Recorded:
  reading the dynamic symbol table from `PT_DYNAMIC` is a loader feature, not a small fix.

## Xtensa and ESP

**X1, the ESP32 `.bin` (a dump from flash 0x1000).** Truth: bootloader at file 0, partition table at 0x7000, four
partitions, `factory` at flash 0x10000. `carve` reports the bootloader at 0, the partition table at 0x7000 with
its four partitions (MD5 valid), and the application image at file 0xf000 with its `raw` selector. **Pass.** But
every other reader took partition offsets as file offsets:
- `file_layout` gave no hint for the application;
- the open error (`binary_info`, `list_functions` and the other path tools) pointed at the bootloader;
- `diff_firmware` hashed the wrong bytes for each partition (F2).

Fixed: the ESP layout now records the flash base (0x1000 when an ESP32 or ESP32-S2 bootloader starts the file)
and maps partition offsets through it. After: `file_layout` adds the `esp_app_image` hint at 0xf000, and the
open error names the application's selector and says the dump starts at flash 0x1000.

**X2, `list_functions` on the application** (`raw` at 0xf000). Truth: 8677 function symbols at 8595 distinct
addresses. rampage lists 8733 functions and finds 8539 of the 8595 (99.3%); 194 starts are not in the truth.
**Pass.**

**X3, `find_main`.** Truth: `app_main` at 0x400d62b8. The single high-confidence candidate is 0x400d62b8, from
`main_task`'s call between the "Calling app_main()" and "Returned from app_main()" strings. **Pass.**

**X4, the ESP32 ELF.** Truth: entry 0x4008127c. It opens with that entry; `list_functions` lists 8770 functions
and finds 8575 of the 8595 symbol addresses (99.8%). **Pass.**

**X5, `evaluate_function` on uzlib.** uzlib's source at v1.24.1: `uzlib_adler32(data, length, prev_sum)` with
`prev_sum` 1 initially, and `uzlib_crc32(data, length, crc)` with `crc` 0xffffffff initially and no final
inversion (`return crc/* ^ 0xffffffff*/;`). So the truth is 0x091E01DE and 0x340BC6D9 (0xCBF43926 inverted). On
the application and on the ELF alike: 0x091e01de and 0x340bc6d9. **Pass.**

**X6, the ESP8266 `.bin`** (`raw` at 0). Truth: entry 0x40100454, 4744 function symbols (4731 addresses). It opens
with that entry and lists 3366 functions, finding 2884 of the 4731 (61%): 182 of 201 in IRAM and 2702 of 4530
in flash-mapped IROM. **Recorded.**

## `diff_firmware`

**F1, OpenWrt 23.05.4 → 23.05.5.** Truth: 75 files added, 75 removed, 191 changed, 785 unchanged; the changed
programs are `bin/busybox`, `usr/lib/rpcd/luci.so` and `usr/sbin/wpad`. The SquashFS component reports 191
changed, 76 added, 76 removed and 785 unchanged; paging `list: files` gives exactly the truth's file sets, the
extra added and removed entry being the kernel modules' directory (`lib/modules/5.15.167` for
`lib/modules/5.15.162`). Three symlink retargets are reported as `metadata_changed`. Exactly the three programs
are reported as changed images. **Pass.** The function comparison inside them says little: `busybox` shows no
changed function (its code is MIPS16e) and the other two say the change is outside the compared functions. The
60 package changes in the manifests are truth only; `diff_firmware` does not read the manifests.

**F2, MicroPython ESP32 1.24.0 → 1.24.1.** Truth: 2 functions added, 1 removed, 12 changed size. Before, the
application was never compared: partition offsets were taken as file offsets, so `esp:factory` was hashed from
0x10000, "ran past the end of the dump" and had no code comparison, while `esp:phy_init` (really the first 4 KiB
of the application) showed as changed. Only the bootloader's code was compared (no changes). **Fail.** After the
ESP fix, `esp:factory` is compared at 0xf000: 8731 → 8733 functions, 8172 unchanged, 546 changed, 15 added and 13
removed. Of the 546, 530 have the same size in both truth ELFs, and 6 of the 12 size changes are among them.
**Still fail:** code that only moved is reported as changed. Paging that list also showed a bug, fixed: a page cut
to fit the result (250 of 500 rows) said `next_offset: 500`, skipping 250 rows; it now continues after the last
row returned.

**F3, `libz.so` 1.2.11 → 1.2.13.** Truth: 5 added, 4 removed, 67 changed size, 57 same size. rampage: 133 → 134
functions, 23 unchanged, 100 changed, 11 added, 10 removed; 102 pairs were matched by name (the exported
symbols), the rest by call graph, position, neighbourhood and strings. **Recorded.** As expected for a
compiler-version change, even same-size exported functions such as `adler32` differ in their bytes.

**F4, Simple Flashlight 5.10.0 → 5.10.1.** Truth: version 5.10.0 → 5.10.1, `classes.dex` differs. The package
component reports `version_code 65` → `66` and `version_name "5.10.0"` → `"5.10.1"`, `classes.dex` replaced
(5064760 → 4594768 bytes), one activity added (`ManageBlockedNumbersActivity`), and a `classes.dex` component
with its class changes. **Pass.**

## Android (Simple Flashlight 5.10.1)

**A1, `dex_metadata`.** Truth: package `com.simplemobiletools.flashlight`, version code 66, name 5.10.1, one DEX
file, no native libraries. All five match (`dex_total` 1, `native_libs_total` 0). **Pass.**

**A2, permissions and components.** No reference tool (`aapt2`, `apkanalyzer`) is installed, so there is no bar.
rampage lists 3 permissions (`CAMERA` with `max_sdk` 23, `FLASHLIGHT`, `SCHEDULE_EXACT_ALARM`), one declared
permission, three features and 40 components. One reading to note: the declared permission's protection level
prints as `"2"` rather than a name. **Recorded.**

**A3, `privacy_surface`.** No independent truth. It reports five capture sources (four "screen", one location)
and six capture-to-send paths. Read by a person: the four screen sources are
`AccessibilityNodeInfo.getText` calls inside AndroidX accessibility delegates, which read the app's own view
text for accessibility services and are not screen capture. The location source (`getLastKnownLocation`) is in
the bundled Simple Mobile Tools commons library. The paths' sinks are file writes. The output is evidence, as it
says, but the screen category is noisy on any AndroidX app. **Recorded.**

## Agent tasks (Haiku, one repetition)

Calls count every tool call, including ToolSearch schema loads. Cost is Claude Code's reported cost.

| # | Task | Answer | Correct | Calls | Cost |
| --- | --- | --- | --- | --- | --- |
| 1 | What 0x2b1c computes and returns for "123456789" | CRC-32 (zlib semantics, initial crc 0), 0xcbf43926 | yes | 9 | $0.0060 |
| 2 | What 0x7c34 calls to do its work | 0x7928 | yes | 2 | $0.0018 |
| 3 | `busybox`'s C library, byte order and processor | musl (`libc.so`), big-endian, "MIPS 32-bit (ELF32, soft-float)" | partly: no MIPS32r2, no MIPS16e | 11 | $0.0065 |
| 4 | Programs changed between the two OpenWrt files | `bin/busybox`, `usr/lib/rpcd/luci.so`, `usr/sbin/wpad` | yes | 10 | $0.0124 |
| 5 | Address of the function ESP-IDF's main task calls | unknown: "the factory app partition at 0x10000 has no ESP image header" | no | 18 | $0.0168 |
| 6 | One function only in the newer ESP32 file | 0x40128310 (in `ble_att_svr_read_group_type_entry_write`, present in both) | no | 37 | $0.0405 |
| 7 | The APK's package name and version | `com.simplemobiletools.flashlight`, 5.10.1, 66 | yes | 5 | $0.0036 |
| 8 | Root filesystem offset and kind in the TRX | 2255872, SquashFS | yes | 4 | $0.0032 |

Tasks 5 and 6 were run again after the ESP flash-base fix:

| # | Answer | Correct | Calls | Cost |
| --- | --- | --- | --- | --- |
| 5 | 0x400d62b8 | yes | 3 | $0.0036 |
| 6 | `sub_400d1ef0` (`esp_app_get_description`, present in both) | no | 22 | $0.0196 |

What the transcripts show:
- **Task 5** failed on the ESP frame bug: the agent read the partition table, looked for the application at
  0x10000 and found no image header there. After the fix, `find_main` with the selector from the open error
  answered in one call.
- **Task 6** never used `diff_firmware`. Both times the agent called the core tool `diff_builds`, which refused
  the flash dumps without naming `diff_firmware` (in the `carve` group), and then compared `list_functions` pages
  by hand. Fixed after the rerun: a `diff_builds` open error now says to use `diff_firmware` and how to enable it.
  Not yet measured with an agent; and with F2 open, `diff_firmware` would offer 15 added functions where the
  truth has 2.
- **Task 3**: the agent extracted `busybox` with `fs_list`/`fs_extract` and read the interpreter and `NEEDED`
  entries. `binary_info` reports neither the MIPS ISA revision (MIPS32r2) nor, before the fix, that the code is
  MIPS16e.

Cost: $0.0908 for the eight tasks and $0.0232 for the two reruns, $0.114 in all, within the $2 cap.

## Fixes made in this run

Each has a regression test on a committed or self-built fixture; none uses the downloaded inputs.
- MIPS16e and microMIPS ELF files are reported as not decoded (`binary_info` warning, `list_functions` note);
  `jalx` targets are not followed (M5).
- `check_claim`: a checksum claim without `args` tries the running-value layouts before refuting (M4).
- ESP flash dumps that start at the ESP32 bootloader are read at flash 0x1000 by `diff_firmware`,
  `file_layout` and the open guidance (X1, F2, task 5).
- `carve`: OpenWrt's UBI end-of-image marker is accepted and noted; a uImage's load address, entry, data size and
  compression are reported (C4).
- Decompiler: MIPS calls through GOT entries of the image's own functions render by name (M2).
- `diff_firmware`: a page cut to fit the result continues after its last row (F2).
- MCP: a `diff_builds` open error points at `diff_firmware` (task 6).
- `derive_truth.py` counts symbolic links to directories (C2).

## What remains

- **M5:** dynamic symbols of section-less (`sstrip`ped) ELF files, from `PT_DYNAMIC`: `DT_SYMTAB`, `DT_STRTAB`
  and the symbol count from `DT_HASH`, `DT_GNU_HASH` or `DT_MIPS_SYMTABNO`. Every OpenWrt program is section-less.
- **M5 / track 2:** MIPS16e decoding and discovery (the next queued track).
- **M1:** MIPS position-independent switch tables (`.gpword` entries added to `$gp`); ELF constructor and
  destructor seeds (`DT_INIT`, `DT_FINI`, `DT_INIT_ARRAY`, `DT_FINI_ARRAY`); function pointers in relocated data.
- **F2:** in Xtensa function comparison, normalise what moves with the code (call targets, `l32r` literal-pool
  words holding code and data addresses) so that moved code does not count as changed.
- **X6:** ESP8266 IROM recall (60%).
- **A3:** `AccessibilityNodeInfo.getText` in AndroidX accessibility delegates is not screen capture.
- **A2:** a reference run with `aapt2` or `apkanalyzer`; declared permission protection levels by name.
- **Task 3:** report the MIPS ISA revision in `binary_info`.
- **Task 6:** an agent run to confirm the `diff_builds` hint leads to `diff_firmware`.
- The maintainer's vendor update pair, the last step of the set, is not part of this run.
