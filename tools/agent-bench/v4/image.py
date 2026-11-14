"""Flash-image helpers for suite v4's patching fixture (tests/fixtures/bench-v4/src/boot.c): its two checksums,
and Intel HEX / Motorola S-record encoding and decoding. Independent of both benchmarked servers.

  python3 -I image.py seal IMAGE.bin            write CRC-16 at 0x840 and CRC-32 at 0x13FC into a flat image at 0x0
  python3 -I image.py ihex IMAGE.bin BASE OUT   encode a flat image as Intel HEX (16-byte data records)
  python3 -I image.py srec IMAGE.bin BASE OUT   encode a flat image as S-records (S0, S1/S2/S3 by address, S5, S9/8/7)
"""

from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

CONFIG_BASE, CONFIG_SIZE, CONFIG_CRC = 0x800, 0x40, 0x840
APP_CRC = 0x13FC


def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def crc32_ieee(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def seal(image: bytearray, base: int = 0) -> tuple[int, int]:
    """Write boot.c's two integrity fields (config CRC first: the application CRC covers it); returns both."""
    config = image[CONFIG_BASE - base : CONFIG_BASE - base + CONFIG_SIZE]
    crc16 = crc16_ccitt_false(bytes(config))
    image[CONFIG_CRC - base : CONFIG_CRC - base + 2] = struct.pack("<H", crc16)
    crc32 = crc32_ieee(bytes(image[CONFIG_BASE - base : APP_CRC - base]))
    image[APP_CRC - base : APP_CRC - base + 4] = struct.pack("<I", crc32)
    return crc16, crc32


def _checksum(record: bytes) -> int:
    return (-sum(record)) & 0xFF


def ihex(image: bytes, base: int) -> str:
    lines, upper = [], None
    for offset in range(0, len(image), 16):
        address = base + offset
        if address >> 16 != upper:
            upper = address >> 16
            if upper or offset:
                record = bytes([2, 0, 0, 4]) + struct.pack(">H", upper)
                lines.append(":" + (record + bytes([_checksum(record)])).hex().upper())
        chunk = image[offset : offset + 16]
        record = bytes([len(chunk)]) + struct.pack(">H", address & 0xFFFF) + b"\x00" + chunk
        lines.append(":" + (record + bytes([_checksum(record)])).hex().upper())
    lines.append(":00000001FF")
    return "\n".join(lines) + "\n"


def srec(image: bytes, base: int) -> str:
    end = base + len(image)
    kind, width = ("1", 2) if end <= 0x10000 else ("2", 3) if end <= 0x1000000 else ("3", 4)
    def line(record_type: str, payload: bytes) -> str:
        body = bytes([len(payload) + 1]) + payload
        return f"S{record_type}" + (body + bytes([(~sum(body)) & 0xFF])).hex().upper()
    lines = [line("0", b"\x00\x00" + b"bench-v4")]
    count = 0
    for offset in range(0, len(image), 16):
        lines.append(line(kind, (base + offset).to_bytes(width, "big") + image[offset : offset + 16]))
        count += 1
    lines.append(line("5", count.to_bytes(2, "big")))
    terminator = {"1": "9", "2": "8", "3": "7"}[kind]
    lines.append(line(terminator, (0).to_bytes(width, "big")))
    return "\n".join(lines) + "\n"


def decode_ihex(text: str) -> dict[int, int]:
    memory: dict[int, int] = {}
    upper = 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if not line.startswith(":"):
            raise ValueError(f"line {number}: not a record")
        record = bytes.fromhex(line[1:])
        if len(record) < 5 or record[0] + 5 != len(record) or sum(record) & 0xFF:
            raise ValueError(f"line {number}: bad length or checksum")
        length, address, kind, data = record[0], (record[1] << 8) | record[2], record[3], record[4:-1]
        if kind == 0:
            for index, byte in enumerate(data):
                memory[upper + address + index] = byte
        elif kind == 1:
            return memory
        elif kind == 2:
            upper = int.from_bytes(data, "big") << 4
        elif kind == 4:
            upper = int.from_bytes(data, "big") << 16
        elif kind not in (3, 5):
            raise ValueError(f"line {number}: record type {kind}")
        del length
    raise ValueError("no end-of-file record")


def decode_srec(text: str) -> dict[int, int]:
    memory: dict[int, int] = {}
    widths = {"1": 2, "2": 3, "3": 4}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if len(line) < 4 or line[0] != "S":
            raise ValueError(f"line {number}: not a record")
        kind, body = line[1], bytes.fromhex(line[2:])
        if body[0] + 1 != len(body) or (sum(body) & 0xFF) != 0xFF:
            raise ValueError(f"line {number}: bad length or checksum")
        if kind in widths:
            width = widths[kind]
            address = int.from_bytes(body[1 : 1 + width], "big")
            for index, byte in enumerate(body[1 + width : -1]):
                memory[address + index] = byte
        elif kind not in "056789":
            raise ValueError(f"line {number}: record type S{kind}")
    return memory


def main() -> int:
    command, path = sys.argv[1], Path(sys.argv[2])
    if command == "seal":
        image = bytearray(path.read_bytes())
        crc16, crc32 = seal(image)
        path.write_bytes(bytes(image))
        print(f"{path}: CRC-16 {crc16:#06x} at {CONFIG_CRC:#x}, CRC-32 {crc32:#010x} at {APP_CRC:#x}")
        return 0
    base, out = int(sys.argv[3], 0), Path(sys.argv[4])
    encoder = {"ihex": ihex, "srec": srec}[command]
    out.write_text(encoder(path.read_bytes(), base))
    return 0


if __name__ == "__main__":
    sys.exit(main())
