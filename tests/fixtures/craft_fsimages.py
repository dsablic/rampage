#!/usr/bin/env python3
"""Writes Android sparse images and OTA payloads from the images build-fsimages.sh made: python3 craft_fsimages.py
<dir>.

- ext4.simg: ext4.img as an Android sparse image (raw, fill, don't-care and CRC32 chunks).
- pattern.simg: a sparse image of bytes that are no filesystem.
- payload.bin: a full update_engine payload (major version 2) with partitions `system` (ext4.img, written with
  REPLACE_XZ, REPLACE_BZ, REPLACE and ZERO operations) and `vendor` (squashfs-xz.img, REPLACE), each with data and
  partition SHA-256 hashes.
- delta.bin: a delta payload whose partition needs the previous build (SOURCE_COPY).
- bomb.bin: a full payload whose 80 MiB partition of zeros is one REPLACE_XZ operation of a few kilobytes.
- rootfs.cpio: rootfs.tar's members as a newc archive.
"""
import bz2
import hashlib
import lzma
import os
import struct
import sys
import zlib

out = sys.argv[1]
BLOCK = 4096


def read(name):
    with open(os.path.join(out, name), 'rb') as handle:
        return handle.read()


def write(name, data):
    with open(os.path.join(out, name), 'wb') as handle:
        handle.write(data)


def sparse(image, block=BLOCK):
    image = image.ljust((len(image) + block - 1) // block * block, b'\0')
    blocks = [image[i:i + block] for i in range(0, len(image), block)]
    chunks = []
    index = 0
    while index < len(blocks):
        first = blocks[index]
        word = first[:4]
        if first == word * (block // 4):
            run = index
            while run < len(blocks) and blocks[run] == first:
                run += 1
            if word == b'\0\0\0\0':
                chunks.append(struct.pack('<HHII', 0xCAC3, 0, run - index, 12))
            else:
                chunks.append(struct.pack('<HHII', 0xCAC2, 0, run - index, 16) + word)
            index = run
        else:
            run = index
            while run < len(blocks) and blocks[run] != blocks[run][:4] * (block // 4):
                run += 1
            data = b''.join(blocks[index:run])
            chunks.append(struct.pack('<HHII', 0xCAC1, 0, run - index, 12 + len(data)) + data)
            index = run
    chunks.append(struct.pack('<HHII', 0xCAC4, 0, 0, 16) + struct.pack('<I', zlib.crc32(image)))
    header = struct.pack('<IHHHHIIII', 0xED26FF3A, 1, 0, 28, 12, block, len(blocks), len(chunks), 0)
    return header + b''.join(chunks)


def varint(value):
    out = b''
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out += bytes([byte | 0x80])
        else:
            return out + bytes([byte])


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    return varint(number << 3 | 2) + varint(len(value)) + value


def extent(start, count):
    return field(1, start) + field(2, count)


def operation(kind, dst, data=None, offset=0):
    message = field(1, kind)
    if data is not None:
        message += field(2, offset) + field(3, len(data))
    message += b''.join(field(6, extent(start, count)) for start, count in dst)
    if data is not None:
        message += field(8, hashlib.sha256(data).digest())
    return message


REPLACE, REPLACE_BZ, SOURCE_COPY, ZERO, REPLACE_XZ = 0, 1, 4, 6, 8


def payload(partitions, minor_version=0):
    """partitions: (name, image, [(kind, start_block, block_count)]) with operations in order."""
    blobs = b''
    messages = b''
    for name, image, plan, old in partitions:
        message = field(1, name.encode())
        if old:
            message += field(6, field(1, len(image)) + field(2, hashlib.sha256(image).digest()))
        message += field(7, field(1, len(image)) + field(2, hashlib.sha256(image).digest()))
        for kind, start, count in plan:
            chunk = image[start * BLOCK:(start + count) * BLOCK]
            if kind == REPLACE:
                data = chunk
            elif kind == REPLACE_BZ:
                data = bz2.compress(chunk)
            elif kind == REPLACE_XZ:
                data = lzma.compress(chunk, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64)
            else:
                data = None
            if kind == SOURCE_COPY:
                op = field(1, kind) + field(4, extent(start, count)) + field(6, extent(start, count))
            else:
                op = operation(kind, [(start, count)], data, len(blobs))
            if data is not None:
                blobs += data
            message += field(8, op)
        messages += field(13, message)
    manifest = field(3, BLOCK) + field(12, minor_version) + messages
    return b'CrAU' + struct.pack('>QQI', 2, len(manifest), 0) + manifest + blobs


def plan(image, kinds):
    """Operations of 16 blocks each over `image`, cycling through `kinds`; all-zero runs become ZERO."""
    blocks = len(image) // BLOCK
    steps = []
    for number, start in enumerate(range(0, blocks, 16)):
        count = min(16, blocks - start)
        chunk = image[start * BLOCK:(start + count) * BLOCK]
        kind = ZERO if chunk.count(0) == len(chunk) else kinds[number % len(kinds)]
        steps.append((kind, start, count))
    return steps


def cpio_from_tar(name):
    """A newc archive of the tar's members, with sequential inode numbers and no host device numbers."""
    import tarfile
    out = b''
    with tarfile.open(os.path.join(out_dir, name), format=tarfile.USTAR_FORMAT) as archive:
        members = archive.getmembers()
        for inode, member in enumerate(members, start=1):
            if member.isdir():
                mode, data = 0o040000, b''
            elif member.issym():
                mode, data = 0o120000, member.linkname.encode()
            else:
                mode, data = 0o100000, archive.extractfile(member).read()
            out += cpio_member(member.name, inode, mode | member.mode, member.mtime, data)
    return out + cpio_member('TRAILER!!!', 0, 0, 0, b'')


def cpio_member(name, inode, mode, mtime, data):
    name = name.encode() + b'\0'
    fields = [inode, mode, 0, 0, 1, mtime, len(data), 0, 0, 0, 0, len(name), 0]
    header = b'070701' + b''.join(b'%08X' % value for value in fields)
    member = header + name
    member += b'\0' * (-len(member) % 4) + data
    return member + b'\0' * (-len(member) % 4)


out_dir = out
write('rootfs.cpio', cpio_from_tar('rootfs.tar'))
ext4 = read('ext4.img')
squashfs = read('squashfs-xz.img')
squashfs = squashfs.ljust((len(squashfs) + BLOCK - 1) // BLOCK * BLOCK, b'\0')
write('ext4.simg', sparse(ext4))
write('pattern.simg', sparse(bytes(range(256)) * 32 + b'\0' * 8192 + b'\x5a\xa5\x5a\xa5' * 1024))
write('payload.bin', payload([
    ('system', ext4, plan(ext4, [REPLACE_XZ, REPLACE_BZ, REPLACE]), False),
    ('vendor', squashfs, plan(squashfs, [REPLACE]), False),
]))
bomb = lzma.compress(b'\0' * (80 << 20), format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=9)
bomb_op = field(1, REPLACE_XZ) + field(2, 0) + field(3, len(bomb)) + field(6, extent(0, (80 << 20) // BLOCK))
bomb_manifest = field(3, BLOCK) + field(13, field(1, b'bomb') + field(7, field(1, 80 << 20)) + field(8, bomb_op))
write('bomb.bin', b'CrAU' + struct.pack('>QQI', 2, len(bomb_manifest), 0) + bomb_manifest + bomb)
write('delta.bin', payload([('system', ext4, [(SOURCE_COPY, 0, len(ext4) // BLOCK)], True)], minor_version=8))
