#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Assembles the Xtensa flash-dump fixtures from the images build.sh makes (run by build.sh, in this directory).

esp32-flash.bin (1 MiB, erased bytes 0xff): the bootloader image at 0x1000, a partition table at 0x8000 laid out as
ESP-IDF's "single factory app" default (nvs, phy_init, factory) with its MD5 entry, a minimal NVS page header at
0x9000 and the application image at 0x10000. esp8266-flash.bin (1 MiB): the NONOS-style image at 0 and its IROM at
0x10000.
"""

import hashlib
import struct
import zlib

FLASH_SIZE = 1024 * 1024


def entry(kind: int, subtype: int, offset: int, size: int, label: str) -> bytes:
    """One 32-byte partition table entry: magic 0xAA50, type, subtype, offset, size, label, flags."""
    return struct.pack("<2sBBII16sI", b"\xaa\x50", kind, subtype, offset, size, label.encode(), 0)


def partition_table() -> bytes:
    entries = b"".join(
        [
            entry(0x01, 0x02, 0x9000, 0x6000, "nvs"),
            entry(0x01, 0x01, 0xF000, 0x1000, "phy_init"),
            entry(0x00, 0x00, 0x10000, 0xF0000, "factory"),
        ]
    )
    md5 = b"\xeb\xeb" + b"\xff" * 14 + hashlib.md5(entries).digest()
    table = entries + md5
    return table + b"\xff" * (0xC00 - len(table))


def nvs_page_header() -> bytes:
    """An active NVS page's 32-byte header: state, sequence number, version, reserved bytes and its CRC-32."""
    body = struct.pack("<IB19x", 0, 0xFE)
    body = body[:5] + b"\xff" * 19
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return struct.pack("<I", 0xFFFFFFFE) + body + struct.pack("<I", crc)


def place(flash: bytearray, offset: int, data: bytes) -> None:
    assert offset + len(data) <= len(flash), offset
    flash[offset : offset + len(data)] = data


def main() -> None:
    flash = bytearray(b"\xff" * FLASH_SIZE)
    place(flash, 0x1000, open("esp32-bootloader.bin", "rb").read())
    place(flash, 0x8000, partition_table())
    place(flash, 0x9000, nvs_page_header())
    place(flash, 0x10000, open("esp32-app.bin", "rb").read())
    open("esp32-flash.bin", "wb").write(flash)

    flash = bytearray(b"\xff" * FLASH_SIZE)
    place(flash, 0, open("esp8266-app-0x00000.bin", "rb").read())
    place(flash, 0x10000, open("esp8266-app-0x10000.bin", "rb").read())
    open("esp8266-flash.bin", "wb").write(flash)


if __name__ == "__main__":
    main()
