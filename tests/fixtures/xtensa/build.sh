#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuilds the Xtensa fixtures: ESP32 (LX6, windowed ABI) and ESP8266 (LX106, call0 ABI) applications from esp.c, an
# ESP32 second-stage bootloader from boot.c, their ESP app images (esptool elf2image) and a flash dump of each chip.
# Everything runs in the gcc:13 image pinned by digest; esptool is pinned by version.
#   ESP32:   Espressif's xtensa-esp-elf GCC 14.2.0 (crosstool-NG esp-14.2.0_20241119), the release tarball for the
#            container's architecture checked against the SHA-256 below. Download it once into $XTENSA_TOOLCHAIN
#            (default /private/var/tmp/xtensa-toolchain; never into the repository, it is about 175 MB):
#              https://github.com/espressif/crosstool-NG/releases/download/esp-14.2.0_20241119/<tarball>
#   ESP8266: Debian bookworm's gcc-xtensa-lx106 12.2.0-14+deb12u1+13+b2 and binutils-xtensa-lx106 2.40-2+5+b1.
#            Should Debian retire these versions, take them from snapshot.debian.org.
# The programs link nothing but themselves (-nostdlib, no libgcc, libc, HAL or ESP-IDF code); the images and the
# partition table are esptool's and craft_flash.py's data. Each -sym ELF keeps its symbol table as the truth and
# its twin has it stripped (the loaded bytes are the same).
#   esp32-app.elf / esp32-app.bin          ESP32 application, -Os -mlongcalls, and its app image (SHA-256 appended)
#   esp32-bootloader.elf / .bin             ESP32 second-stage bootloader and its image
#   esp32-flash.bin                         1 MiB flash: bootloader at 0x1000, partition table at 0x8000 (nvs,
#                                           phy_init, factory app at 0x10000), the app image at 0x10000
#   esp8266-app.elf                         ESP8266 application, -Os -mlongcalls, call0 ABI
#   esp8266-app-0x00000.bin / -0x10000.bin  its NONOS-style images: IRAM/DRAM image, and IROM mapped at 0x40210000
#   esp8266-flash.bin                       1 MiB flash with both at their offsets
set -euo pipefail
cd "$(dirname "$0")"
docker=${DOCKER:-docker}
toolchain=${XTENSA_TOOLCHAIN:-/private/var/tmp/xtensa-toolchain}
image=gcc:13@sha256:8c0fe724784c6d617cb582f79ddaf5dd2233aaba2fb7a14e0b9d03348fea8088
"$docker" run --rm -v "$PWD":/w -v "$toolchain":/tc:ro -w /w "$image" bash -c '
  set -e
  case $(uname -m) in
    aarch64) tarball=xtensa-esp-elf-14.2.0_20241119-aarch64-linux-gnu.tar.xz
             sum=ac2b311dc0003386425086bfc813bf2aeb3cdf3b117845802df6ebef5f69955f ;;
    x86_64)  tarball=xtensa-esp-elf-14.2.0_20241119-x86_64-linux-gnu.tar.xz
             sum=e3e6dcf3d275c3c9ab0e4c8a9d93fd10e7efc035d435460576c9d95b4140c676 ;;
  esac
  echo "$sum  /tc/$tarball" | sha256sum -c --quiet
  mkdir -p /opt/esp && tar -xJf "/tc/$tarball" -C /opt/esp
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends gcc-xtensa-lx106=12.2.0-14+deb12u1+13+b2 \
    binutils-xtensa-lx106=2.40-2+5+b1 python3-pip >/dev/null 2>&1
  pip3 install -q --break-system-packages esptool==4.8.1 >/dev/null 2>&1
  esp=/opt/esp/xtensa-esp-elf/bin/xtensa-esp32-elf
  flags="-Os -g0 -mlongcalls -ffreestanding -nostdlib -nostartfiles -fno-builtin -ffunction-sections \
    -fdata-sections -Wl,--gc-sections -Wl,--build-id=none"
  $esp-gcc $flags -Wl,-T,esp32.ld -o esp32-app-sym.elf esp.c
  $esp-gcc $flags -Wl,-T,boot.ld -o esp32-bootloader-sym.elf boot.c
  xtensa-lx106-elf-gcc $flags -DESP8266 -Wl,-T,esp8266.ld -o esp8266-app-sym.elf esp.c
  for name in esp32-app esp32-bootloader; do $esp-strip --strip-all -o $name.elf $name-sym.elf; done
  xtensa-lx106-elf-strip --strip-all -o esp8266-app.elf esp8266-app-sym.elf
  for name in esp32-app esp32-bootloader esp8266-app; do
    if $esp-nm -u $name-sym.elf | grep -q .; then echo "$name links undefined symbols" >&2; exit 1; fi
  done
  esptool.py --chip esp32 elf2image --flash_mode dio --flash_freq 40m --flash_size 1MB --elf-sha256-offset 0xb0 \
    -o esp32-app.bin esp32-app-sym.elf >/dev/null
  esptool.py --chip esp32 elf2image --flash_mode dio --flash_freq 40m --flash_size 1MB \
    -o esp32-bootloader.bin esp32-bootloader-sym.elf >/dev/null
  esptool.py --chip esp8266 elf2image --version 1 --flash_mode qio --flash_size 1MB -o esp8266-app- \
    esp8266-app-sym.elf >/dev/null
  python3 -I craft_flash.py
  chown "$(stat -c %u:%g esp.c)" esp32-* esp8266-*'
python3 -I ../scrub-paths.py --check esp32-*.elf esp8266-*.elf
