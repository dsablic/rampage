#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rewrites a COFF object as a big-object COFF (`ANON_OBJECT_HEADER_BIGOBJ`, what `cl /bigobj` writes), keeping its
sections, relocations and symbols: 32-bit section numbers in 20-byte symbol records. LLVM writes big objects only
past 65279 sections, too large for a fixture. Usage: coff-bigobj.py IN.obj OUT.obj"""
import struct
import sys

CLASS_ID = bytes([0xC7, 0xA1, 0xBA, 0xD1, 0xEE, 0xBA, 0xA9, 0x4B, 0xAF, 0x20, 0xFA, 0xF6, 0x6A, 0xA4, 0xDC, 0xB8])

source, target = sys.argv[1:3]
data = open(source, "rb").read()
machine, sections, stamp, symbols_at, symbols, optional, _ = struct.unpack_from("<HHIIIHH", data, 0)
assert optional == 0, "an object file has no optional header"
shift = 56 - 20
table_end = 20 + 40 * sections
strings_at = symbols_at + 18 * symbols


def moved(offset):
    return offset + shift if offset else 0


header = struct.pack("<HHHHI", 0, 0xFFFF, 2, machine, stamp) + CLASS_ID
header += struct.pack("<IIIIIII", 0, 0, 0, 0, sections, symbols_at + shift, symbols)
table = bytearray(data[20:table_end])
for index in range(sections):
    at = 40 * index
    raw_data, relocations, lines = struct.unpack_from("<III", table, at + 20)
    struct.pack_into("<III", table, at + 20, moved(raw_data), moved(relocations), moved(lines))
body = data[table_end:symbols_at]
records = bytearray()
index = 0
while index < symbols:
    raw = data[symbols_at + 18 * index: symbols_at + 18 * (index + 1)]
    name, value, section, kind, storage, aux = raw[:8], *struct.unpack_from("<IhHBB", raw, 8)
    records += name + struct.pack("<IiHBB", value, section, kind, storage, aux)
    for extra in range(1, aux + 1):
        records += data[symbols_at + 18 * (index + extra): symbols_at + 18 * (index + extra + 1)] + b"\0\0"
    index += 1 + aux
open(target, "wb").write(header + bytes(table) + body + bytes(records) + data[strings_at:])
