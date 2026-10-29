#!/usr/bin/env python3
"""Synthesizes PyInstaller CArchive and malformed WebAssembly fixtures: python3 craft_formats.py <out-dir>.

PyInstaller is not needed: each archive is a small native stub followed by a CArchive written to PyInstaller's
layout (entry data, a TOC of `!IIIIBc` records with NUL-padded names, then the cookie), so the bytes are owned.
"""
import struct
import sys
import zlib

out = sys.argv[1]
MAGIC = b'MEI\x0c\x0b\x0a\x0b\x0e'


def elf_stub():
    ehdr = struct.pack('<4sBBBBB7xHHIQQQIHHHHHH', b'\x7fELF', 2, 1, 1, 0, 0, 2, 0x3e, 1, 0, 0, 0, 0, 64, 0, 0, 64,
                       0, 0)
    # A bootloader holds the cookie magic as a constant; the search must step over it.
    return ehdr + b'\0' * 64 + MAGIC + b'bootloader constant\0'


def macho_stub():
    return struct.pack('<IiiIIIII', 0xfeedfacf, 0x01000007, 3, 2, 0, 0, 0, 0).ljust(256, b'\0')


def carchive(entries, version, library, pyc_magic):
    """A CArchive of `entries` (name, typecode, payload, compress) with a PYZ entry; `library` None writes the
    24-byte pre-2.1 cookie."""
    data = b''
    toc = b''
    for name, typecode, payload, compress in entries:
        if typecode == b'z':
            payload = b'PYZ\0' + pyc_magic + struct.pack('>I', 12 + len(payload)) + payload
        stored = zlib.compress(payload) if compress else payload
        name = name.encode() + b'\0'
        name = name.ljust((len(name) + 15) // 16 * 16, b'\0')
        toc += struct.pack('>IIIIBc', 18 + len(name), len(data), len(stored), len(payload), int(compress),
                           typecode) + name
        data += stored
    cookie_size = 24 if library is None else 88
    length = len(data) + len(toc) + cookie_size
    cookie = MAGIC + struct.pack('>IIii', length, len(data), len(toc), version)
    if library is not None:
        cookie += library.encode().ljust(64, b'\0')
    return data + toc + cookie


modern = [
    ('struct', b'm', b'struct module bytecode', True),
    ('pyimod01_archive', b'm', b'archive module bytecode', True),
    ('pyiboot01_bootstrap', b's', b'bootstrap script bytecode', True),
    ('main', b's', b'print("hello")', True),
    ('PYZ-00.pyz', b'z', zlib.compress(b'marshalled toc'), False),
    ('libpython3.12.so.1.0', b'b', b'\x7fELF shared library', True),
    ('lib-dynload/_ssl.cpython-312-x86_64-linux-gnu.so', b'b', b'\x7fELF extension', True),
    ('base_library.zip', b'x', b'PK\x05\x06' + b'\0' * 18, False),
    ('pyi-contents-directory _internal', b'o', b'', False),
]
# A 3.12 archive (pyc magic 3531) followed by 512 bytes standing in for an appended signature.
open(f'{out}/pyinstaller-312.elf', 'wb').write(
    elf_stub() + carchive(modern, 312, 'libpython3.12.so.1.0', b'\xcb\x0d\x0d\x0a') + b'\xa5' * 512)

legacy = [
    ('main', b's', b'print "hello"', True),
    ('PYZ-00.pyz', b'z', zlib.compress(b'marshalled toc'), False),
    ('Python', b'b', b'\xcf\xfa\xed\xfe framework', True),
]
# A Python 2.7 archive (pyc magic 62211) with the 24-byte pre-2.1 cookie.
open(f'{out}/pyinstaller-27.macho', 'wb').write(macho_stub() + carchive(legacy, 27, None, b'\x03\xf3\x0d\x0a'))

# A core module whose type section is sound but whose import section claims more bytes than the file holds.
types = b'\x01\x60\x01\x7f\x00'
malformed = b'\0asm\x01\0\0\0' + b'\x01' + bytes([len(types)]) + types + b'\x02\x40\x01\x03env\x03log\x00\x00'
open(f'{out}/malformed.wasm', 'wb').write(malformed)
# A component-model header (version 0xd, layer 1) with an empty custom section: recognised, never parsed.
open(f'{out}/component.wasm', 'wb').write(b'\0asm\x0d\0\x01\0' + b'\x00\x02\x01x')
