#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Assemble raw-cortex-m-stages-lzss.bin: stage 1, then at 0x400 the LZSS-compressed stage 2, then stage 2's data.

The stream is the lzss-4k variant rampage's decoder provider reads: a 4096-byte zero-filled ring written from
0xfee, flag bits LSB first (1 = literal), references of a 12-bit ring position and a length nibble + 3. The
encoder is greedy and deterministic.

Usage: gen-stages.py STAGE1.bin STAGE2.bin STAGE2DATA.bin OUT.bin
"""

import struct
import sys

RING = 4096
START = 0xFEE
STORE = 0x400
DATA_STORE = 0x800


def lzss(data: bytes) -> bytes:
    write = START
    out = bytearray()
    position = 0
    while position < len(data):
        flags_at = len(out)
        out.append(0)
        for bit in range(8):
            if position >= len(data):
                break
            best_length, best_start = 0, 0
            # Only bytes this stream already wrote, and still in the ring after an 18-byte copy.
            for back in range(1, min(position, RING - 18) + 1):
                length = 0
                while (
                    length < 18
                    and length < back
                    and position + length < len(data)
                    and data[position - back + length] == data[position + length]
                ):
                    length += 1
                if length > best_length:
                    best_length, best_start = length, (write - back) % RING
            if best_length >= 3:
                out += bytes([best_start & 0xFF, (best_start >> 4) & 0xF0 | (best_length - 3)])
                step = best_length
            else:
                out[flags_at] |= 1 << bit
                out.append(data[position])
                step = 1
            write = (write + step) % RING
            position += step
    return bytes(out)


def main() -> None:
    stage1, stage2, stage2_data = (open(path, "rb").read() for path in sys.argv[1:4])
    encoded = lzss(stage2)
    assert len(stage1) <= STORE and STORE + 8 + len(encoded) <= DATA_STORE
    image = stage1.ljust(STORE, b"\0") + struct.pack("<II", len(encoded), len(stage2)) + encoded
    image = image.ljust(DATA_STORE, b"\0") + stage2_data
    open(sys.argv[4], "wb").write(image)
    print(f"stage2: {len(stage2)} bytes -> {len(encoded)} encoded at {STORE + 8:#x}")


if __name__ == "__main__":
    main()
