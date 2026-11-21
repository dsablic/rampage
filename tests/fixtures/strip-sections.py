#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Removes an ELF file's section headers the way OpenWrt's `sstrip` does, for section-less fixtures.

The program headers stay, and with them everything the dynamic linker reads through PT_DYNAMIC. The section header
fields of the ELF header (e_shoff, e_shnum, e_shstrndx) become zero, and the file is cut after the last byte any
program header covers, which drops the section header table, `.symtab`, `.strtab` and the other unloaded sections.

Usage: strip-sections.py INPUT OUTPUT
"""
import struct
import sys


def strip(data: bytes) -> bytes:
    if data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise ValueError("not a 32- or 64-bit ELF file")
    is_64 = data[4] == 2
    order = "<" if data[5] == 1 else ">"
    if is_64:
        phoff, = struct.unpack_from(order + "Q", data, 32)
        phentsize, phnum = struct.unpack_from(order + "HH", data, 54)
        fields = [(40, "Q"), (60, "H"), (62, "H")]
    else:
        phoff, = struct.unpack_from(order + "I", data, 28)
        phentsize, phnum = struct.unpack_from(order + "HH", data, 42)
        fields = [(32, "I"), (48, "H"), (50, "H")]
    end = phoff + phentsize * phnum
    for index in range(phnum):
        at = phoff + index * phentsize
        if is_64:
            offset, = struct.unpack_from(order + "Q", data, at + 8)
            size, = struct.unpack_from(order + "Q", data, at + 32)
        else:
            offset, size = struct.unpack_from(order + "I", data, at + 4)[0], struct.unpack_from(order + "I", data, at + 16)[0]
        end = max(end, offset + size)
    out = bytearray(data[:end])
    for offset, kind in fields:
        struct.pack_into(order + kind, out, offset, 0)
    return bytes(out)


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1], "rb") as source:
        data = source.read()
    with open(sys.argv[2], "wb") as target:
        target.write(strip(data))


if __name__ == "__main__":
    main()
