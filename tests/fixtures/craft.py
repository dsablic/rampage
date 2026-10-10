#!/usr/bin/env python3
"""Generates malformed binaries for loader regression tests: python3 craft.py <out-dir>."""
import struct
import sys

out = sys.argv[1]


def elf64(vaddr, filesz, memsz, data, entry=0, truncate=None):
    ehdr = struct.pack('<4sBBBBB7xHHIQQQIHHHHHH', b'\x7fELF', 2, 1, 1, 0, 0, 2, 0x3e, 1, entry, 64, 0, 0, 64, 56, 1, 64,
                       0, 0)
    phdr = struct.pack('<IIQQQQQQ', 1, 5, 0, vaddr, vaddr, filesz, memsz, 0x1000)
    image = ehdr + phdr + data
    return image.ljust(filesz, b'\0') if truncate is None else image.ljust(truncate, b'\0')[:truncate]


# A segment at the top of the address space, so address + offset overflows.
blob = b'\0' * (0x100 - 120) + b'hello world string\0'
open(f'{out}/wrap.elf', 'wb').write(elf64(0xffffffffffffff00, 0x200, 0x200, blob, entry=0xffffffffffffff78))
# A segment claiming 0x2000 file bytes in a 0x400-byte file.
open(f'{out}/trunc.elf', 'wb').write(
    elf64(0x400000, 0x2000, 0x2000, b'\x90' * 8 + b'SECRETSTRING\0', entry=0x400078, truncate=0x400))


def macho32(entryoff=0xf50):
    commands = struct.pack('<II16sIIIIiiII', 1, 56, b'__PAGEZERO', 0, 0x1000, 0, 0, 0, 0, 0, 0)
    commands += struct.pack('<II16sIIIIiiII', 1, 56, b'__TEXT', 0x1000, 0x1000, 0, 0x1000, 5, 5, 0, 0)
    commands += struct.pack('<IIQQ', 0x80000028, 24, entryoff, 0)
    header = struct.pack('<IiiIIII', 0xfeedface, 7, 3, 2, 3, len(commands), 0)
    return ((header + commands).ljust(entryoff, b'\0') + b'\x55\x89\xe5\xc3').ljust(0x1000, b'\0')


# An i386 Mach-O whose LC_MAIN entry is a file offset.
i386 = macho32()
open(f'{out}/i386.macho', 'wb').write(i386)

# A universal binary whose first slice (ppc) is unsupported.
ppc = b'\xfe\xed\xfa\xce' + b'\0' * 0xffc
fat = struct.pack('>II', 0xcafebabe, 2)
fat += struct.pack('>iiIII', 18, 0, 0x1000, len(ppc), 12)
fat += struct.pack('>iiIII', 7, 3, 0x2000, len(i386), 12)
open(f'{out}/ppc_i386.fat', 'wb').write(fat.ljust(0x1000, b'\0') + ppc + i386)

# The PE fixture with its import directory pointing outside the image.
pe = bytearray(open(f'{out}/../bin/hello-x64.exe', 'rb').read())
optional_header = struct.unpack_from('<I', pe, 0x3c)[0] + 24
struct.pack_into('<I', pe, optional_header + 112 + 8, 0x7ffffff0)
open(f'{out}/badimport.exe', 'wb').write(pe)

# The PE fixture with its exception directory (.pdata) size far larger than the section.
pe = bytearray(open(f'{out}/../bin/hello-x64.exe', 'rb').read())
optional_header = struct.unpack_from('<I', pe, 0x3c)[0] + 24
struct.pack_into('<I', pe, optional_header + 112 + 3 * 8 + 4, 0x7ffffff0)
open(f'{out}/bigpdata.exe', 'wb').write(pe)

# The PE fixture rebased so high that import address table entries would overflow 64 bits.
pe = bytearray(open(f'{out}/../bin/hello-x64.exe', 'rb').read())
optional_header = struct.unpack_from('<I', pe, 0x3c)[0] + 24
struct.pack_into('<Q', pe, optional_header + 24, 0xfffffffffffe0000)
open(f'{out}/highbase.exe', 'wb').write(pe)


def uleb(value):
    encoded = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            return bytes(encoded)


def macho_with_binds(binds):
    """An x86_64 Mach-O with __TEXT and __DATA segments and an LC_DYLD_INFO_ONLY bind stream."""
    def segment(name, vmaddr, fileoff, filesize):
        return struct.pack('<II16sQQQQiiII', 0x19, 72, name, vmaddr, 0x1000, fileoff, filesize, 7, 7, 0, 0)
    commands = segment(b'__TEXT', 0x100000000, 0, 0x1000) + segment(b'__DATA', 0x100001000, 0x1000, 0x1000)
    commands += struct.pack('<II10I', 0x80000022, 48, 0, 0, 0x1800, len(binds), 0, 0, 0, 0, 0, 0)
    header = struct.pack('<IiiIIIII', 0xfeedfacf, 0x01000007, 3, 2, 3, len(commands), 0, 0)
    image = bytearray((header + commands).ljust(0x2000, b'\0'))
    image[0x800:0x804] = b'\x55\x48\x89\xe5'
    image[0x1800:0x1800 + len(binds)] = binds
    return bytes(image)


# Bind symbol _x from dylib 1 in segment 1, then: repeat 2^62 times; bind at an offset that wraps the address
# space; bind past the end of the segment.
bind_x = b'\x11' + b'\x40_x\0' + b'\x51'
open(f'{out}/bindloop.macho', 'wb').write(macho_with_binds(bind_x + b'\x71' + uleb(0) + b'\xc0' + uleb(2**62) + uleb(0) + b'\0'))
open(f'{out}/bindwrap.macho', 'wb').write(macho_with_binds(bind_x + b'\x71' + uleb(0xffffffffffffff00) + b'\x90\0'))
open(f'{out}/bindfar.macho', 'wb').write(macho_with_binds(bind_x + b'\x71' + uleb(0x5000) + b'\x90\0'))
