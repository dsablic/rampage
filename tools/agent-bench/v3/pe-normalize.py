"""Zero a PE image's build stamps in place, so its bytes do not depend on where it was built: the COFF header
timestamp, the optional header checksum, every debug directory entry's timestamp, and the CodeView record's PDB
GUID (which the linker derives from the PDB, whose contents hold build paths). Code and data are untouched; the
image no longer matches its PDB by GUID, which no truth relies on.

Usage: python3 -I tools/agent-bench/v3/pe-normalize.py IMAGE
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path


def normalize(path: Path) -> None:
    data = bytearray(path.read_bytes())
    pe, = struct.unpack_from("<I", data, 0x3C)
    assert data[pe : pe + 4] == b"PE\0\0"
    struct.pack_into("<I", data, pe + 8, 0)
    optional = pe + 24
    plus = struct.unpack_from("<H", data, optional)[0] == 0x20B
    struct.pack_into("<I", data, optional + 64, 0)
    directory = optional + (112 if plus else 96) + 6 * 8
    rva, size = struct.unpack_from("<II", data, directory)
    count, = struct.unpack_from("<H", data, pe + 6)
    table = optional + struct.unpack_from("<H", data, pe + 20)[0]

    def offset_of(address: int) -> int:
        for index in range(count):
            _, start, raw_size, raw = struct.unpack_from("<IIII", data, table + index * 40 + 8)
            if start <= address < start + raw_size:
                return raw + address - start
        raise SystemExit(f"rva {address:#x} is not in a section")

    if size:
        base = offset_of(rva)
        for entry in range(base, base + size, 28):
            struct.pack_into("<I", data, entry + 4, 0)
            kind, length, _, raw = struct.unpack_from("<IIII", data, entry + 12)
            if kind == 2 and length >= 24 and data[raw : raw + 4] == b"RSDS":
                data[raw + 4 : raw + 20] = bytes(16)
    path.write_bytes(bytes(data))


if __name__ == "__main__":
    normalize(Path(sys.argv[1]))
