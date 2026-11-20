# Acceptance set for the 1.6–1.8 features (2026-11-20)

Status: the set is built (inputs pinned, truth derived) and the first run was made on 2026-11-20: results and fixes
in [the report](../benchmarks/acceptance-2026-11-20.md).

Planning rule 1 says a track is done when it has run on an input it was not built from. This set supplies those
inputs for the week's work: MIPS, Xtensa and ESP images, `carve` and `fs_list` on firmware containers,
`diff_firmware`, `evaluate_function`, `check_claim` and Android.

## What the set is

- **Inputs:** 19 public files, about 78 MiB, listed in `tools/acceptance/inputs.json` with URL, SHA-256 and size.
  Every one was built by someone else from open source: OpenWrt release images, MicroPython release firmware,
  Debian packages from snapshot.debian.org, and an F-Droid build. None is committed. `tools/acceptance/fetch.py`
  downloads them into `target/acceptance/inputs` and refuses a file whose hash differs.
- **Truth:** `tools/acceptance/derive_truth.py` writes `target/acceptance/truth.json` without using rampage. It
  reads the builders' own artefacts (release manifests, the ELF and map each ESP image was made from, Debian's
  debug files matched by build ID) and uses `unsquashfs`, `llvm-nm` and `llvm-readelf` as reference tools.
- **Checks:** the tables below. Each names the rampage call, the truth it is compared with and the bar. Bars are
  set here, before any run.

```sh
python3 tools/acceptance/fetch.py
python3 tools/acceptance/derive_truth.py
```

| Input | Why it was chosen |
| --- | --- |
| OpenWrt 23.05.4 and 23.05.5, ath79 sysupgrade image for one router model | Real router userland: big-endian MIPS32r2, musl, SquashFS behind a kernel. Two consecutive releases with the builder's package manifests. |
| OpenWrt 23.05.5 NAND factory image, Broadcom `.trx`, MediaTek `.itb` | A uImage followed by UBI, a TRX container and a FIT image: the container kinds `carve` gained this week. |
| MicroPython 1.24.0 and 1.24.1 for ESP32, 1.24.1 for ESP8266, each with its ELF and map | ESP-IDF and ESP8266 firmware with full symbol truth. The ESP32 file is a flash dump that starts at flash offset 0x1000, not 0. |
| Debian `zlib1g` 1.2.11 and 1.2.13 for mipsel, each with its `dbgsym` package | Position-independent MIPS code with DWARF truth, and functions whose results are defined by a standard. |
| Simple Flashlight 5.10.0 and 5.10.1 from F-Droid | A real APK pair for the Android tools and for `diff_firmware`. |

## Already visible before any run

`derive_truth.py` reports that 76 of the 87 programs in the OpenWrt root filesystem carry the MIPS16 flag in their
ELF header, `busybox` among them. rampage does not decode MIPS16e (a listed follow-up). OpenWrt builds most
packages that way to save space, so on this kind of router the MIPS work may reach few programs. Check M5 measures
it.

## Checks

A check passes at its bar or fails; "record" means the number is kept and there is no bar yet.

### MIPS (`zlib-new`: `libz.so.1.2.13`, stripped; truth from its debug file)

| Id | Call | Truth | Bar |
| --- | --- | --- | --- |
| M1 | `list_functions` | 129 function symbols with addresses and sizes | At least 95% of starts found; extra starts recorded |
| M2 | `decompile` `deflateInit_` (0x7c34) and `uncompress` (0x11088) | zlib source: they call `deflateInit2_` and `uncompress2` | The callee is named, reached through `$gp`/`$t9` |
| M3 | `evaluate_function` `crc32`, `adler32`, `compressBound` | `reference_values` in truth: 0xCBF43926, 0x091E01DE, 13 | Exact |
| M4 | `check_claim`: "0x2b1c computes CRC-32", "0x1fd8 computes CRC-32", "0x7c34 calls 0x7928", "0x2b1c calls 0xa4cc" | The second and fourth are false | verified, refuted, verified, refuted; an unknown is a miss, a wrong verdict is a failure of the feature |
| M5 | `binary_info` and `list_functions` on each of the 87 OpenWrt programs | `programs` and `mips16_programs` in truth | No crash or timeout. On the 11 programs without MIPS16: functions found. On the 76 with it: the result says MIPS16 is not decoded, and does not present wrong disassembly as code |

### Containers and filesystems

| Id | Call | Truth | Bar |
| --- | --- | --- | --- |
| C1 | `carve` and `file_layout` on `openwrt-new` | SquashFS at 2338624 | Offset exact |
| C2 | `fs_list` on it with that offset | 1051 regular files, 207 symbolic links (202 until the run: `derive_truth.py` missed the five links to directories) | Counts exact |
| C3 | `fs_extract` `bin/busybox` | SHA-256 from the `unsquashfs` tree | Identical bytes |
| C4 | `carve` on `openwrt-ubi` | uImage at 0 (data size 2559594, load 0x80060000), UBI at 0x500000 | Both reported; `fs_list` reaches the volumes |
| C5 | `carve` on `openwrt-trx` | TRX length 5771264, partitions at 28, 2344 and 2255872, SquashFS at 2255872 | Exact |
| C6 | `carve` on `openwrt-fit` | Device tree at 0 (4096 bytes), SquashFS at 5230592 | Exact |

### Xtensa and ESP (`esp32-new`, `esp8266`; truth from the ELF in each `meta.zip`)

| Id | Call | Truth | Bar |
| --- | --- | --- | --- |
| X1 | `carve` or `file_layout` on the ESP32 `.bin` | Bootloader image at file offset 0, partition table at 0x7000, four partitions, `factory` at flash 0x10000 | The table and the application are found although the file starts at flash 0x1000 |
| X2 | `list_functions` on the application | 8677 function symbols | At least 80% of the starts inside the application's segments; number recorded |
| X3 | `find_main` | `app_main` at 0x400d62b8 | Exact |
| X4 | Open the ESP32 ELF | Entry 0x4008127c | Opens; function recall recorded |
| X5 | `evaluate_function` `uzlib_adler32` (0x400eb21c) and `uzlib_crc32` (0x400eb4ec) | Adler-32 and CRC-32 of "123456789"; confirm each function's seed and final-inversion convention against uzlib's source at the 1.24.1 tag before the run | Exact |
| X6 | Open the ESP8266 `.bin` | Entry 0x40100454, 4744 function symbols | Opens; recall recorded |

### `diff_firmware`

| Id | Pair | Truth | Bar |
| --- | --- | --- | --- |
| F1 | `openwrt-old` → `openwrt-new` | `tree_diff`: 75 files added, 75 removed, 191 changed, 785 unchanged; changed programs are `bin/busybox`, `usr/lib/rpcd/luci.so`, `usr/sbin/wpad`; 60 package changes in the manifests | File sets exact. The three programs are reported as changed and no unchanged program is |
| F2 | `esp32-old` → `esp32-new` | `esp32_diff`: 2 functions added, 1 removed, 12 changed size | The 12 are among the functions reported changed; functions reported changed stay under 100, since code that only moved is not a change |
| F3 | `zlib-old` → `zlib-new` (the two `libz.so`) | `diff`: 5 added, 4 removed, 67 changed size, 57 same size | Recorded: this is a large change between compiler versions, used to see how matching degrades |
| F4 | `apk-old` → `apk-new` | Version 5.10.0 → 5.10.1; `classes.dex` differs | Both reported |

### Android (`apk-new`)

| Id | Call | Truth | Bar |
| --- | --- | --- | --- |
| A1 | `dex_metadata` | Package `com.simplemobiletools.flashlight`, version code 66, name 5.10.1, one DEX file, no native libraries | Exact |
| A2 | `dex_metadata` permissions and components | `aapt2 dump badging` or `apkanalyzer manifest print` (neither is installed here) | Exact once a reference tool is available |
| A3 | `privacy_surface` | None independent | Recorded and read by a person |

### Agent tasks (Haiku, one repetition, each through MCP only)

1. Given the stripped `libz.so.1.2.13`: what does the function at 0x2b1c compute, and what does it return for the
   nine bytes "123456789"? (CRC-32; 0xCBF43926.)
2. Given the same file: which function does 0x7c34 call to do its work? (0x7928.)
3. Given only the OpenWrt sysupgrade file: which C library does `/bin/busybox` link against, and what byte order
   and processor is it built for? (`libc.so`, musl; big-endian MIPS32r2.)
4. Given the two OpenWrt files: which programs changed between them? (The three in F1.)
5. Given the ESP32 `.bin`: at which address does the application's main task start? (0x400d62b8.)
6. Given the two ESP32 files: name one function that exists only in the newer one. (Either of the two in F2.)
7. Given the flashlight APK: what are its package name and version? (A1.)
8. Given the Broadcom `.trx`: at which offset does the root filesystem start, and what kind is it? (2255872,
   SquashFS.)

Tasks 1, 2 and 5 state addresses because the files are stripped. The prompts name no tool.

## What the set does not cover

- **UBIFS as a root filesystem.** The NAND image holds UBI volumes with SquashFS inside; a real image whose root
  is UBIFS still has to be found.
- **JFFS2, CramFS, MBR/GPT, FAT, UEFI capsules** from carve wave 2: no input here.
- **Vendor firmware.** Everything here is open source and built in the open. The maintainer's own vendor update
  pair, kept local and never named, is the last step of the run, with truth from whatever the vendor publishes.
- **MIPS boot ROMs** (the Raw MIPS32 profile) and **ESP32 flash encryption or secure boot.**
- **`evaluate_function` floats and SSE**, which were measured on suite v3.

## Running it

The run needs a release build of `main` and takes the deterministic checks first (no model, no cost), then the
eight agent tasks on Haiku (about $1 by earlier passes). Results go in a dated report beside the benchmark
reports; each failed check becomes one line in `todo.md` or closes a follow-up already there.
