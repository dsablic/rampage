#!/usr/bin/env bash
# Rebuilds the filesystem-image fixtures in fsimages/ for fs_list and fs_extract. Every image holds the same small
# invented tree (a few files, a nested directory, relative and absolute symlinks and bin/hello, a copy of
# bin/hello-mips.elf), plus a character device and a setuid file where the tool can make them without root.
#
# Requires mksquashfs (squashfs-tools 4.6+), mke2fs, debugfs and e2fsck (e2fsprogs; keg-only on Homebrew),
# bsdtar and python3. On macOS: brew install squashfs e2fsprogs. Android sparse images and OTA payloads have no
# local tool here, so craft_fsimages.py writes them from the ext4 and SquashFS images. SquashFS with legacy LZMA
# compression is built by a test-side generator (crates/rampage-unpack/tests), since Homebrew's mksquashfs has no
# LZMA support. Timestamps, UUIDs and hash seeds are fixed, so rebuilding with the same tools reproduces the bytes.
set -euo pipefail
cd "$(dirname "$0")"
export TZ=UTC LC_ALL=C
PATH="/opt/homebrew/opt/e2fsprogs/sbin:/opt/homebrew/opt/e2fsprogs/bin:$PATH"
out=fsimages
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

root="$work/rootfs"
mkdir -p "$root/etc" "$root/bin" "$root/usr/share/demo/nested" "$root/var"
printf 'demo-device\n' > "$root/etc/hostname"
printf 'telemetry=off\nupload_endpoint=https://telemetry.example.invalid/collect\nmicrophone=push-to-talk\n' \
  > "$root/etc/device.conf"
printf 'An invented filesystem for rampage tests.\n' > "$root/usr/share/demo/readme.txt"
printf 'nested file\n' > "$root/usr/share/demo/nested/deep.txt"
# Larger than one 4 KiB block, so SquashFS stores full blocks and a fragment.
python3 -c 'import sys; sys.stdout.write("".join("line %05d of the multi-block file\n" % i for i in range(400)))' \
  > "$root/usr/share/demo/blocks.txt"
: > "$root/usr/share/demo/empty"
cp bin/hello-mips.elf "$root/bin/hello"
chmod 755 "$root/bin/hello"
ln -s hello "$root/bin/sh"
ln -s /etc/hostname "$root/var/hostname"
find "$root" -exec touch -h -t 202601010000 {} +

# SquashFS: one image per compressor, 4 KiB blocks; pseudo definitions add a device node and a setuid mode.
for comp in gzip xz lzo lz4 zstd; do
  rm -f "$out/squashfs-$comp.img"
  mksquashfs "$root" "$out/squashfs-$comp.img" -comp "$comp" -b 4096 -noappend -all-root -no-xattrs \
    -mkfs-time 0 -all-time 0 -quiet -no-progress \
    -p 'dev d 755 0 0' -p 'dev/console c 600 0 0 5 1' -p 'bin/hello m 4755 0 0' > /dev/null
done

# ext4 with extents and ext2, 1 KiB blocks; debugfs adds the device node and the setuid mode.
for type in ext4 ext2; do
  image="$out/$type.img"
  rm -f "$image"
  E2FSPROGS_FAKE_TIME=1767225600 mke2fs -q -t "$type" -O ^has_journal -b 1024 -N 64 -m 0 -L demo \
    -U 5a5a5a5a-0000-4000-8000-000000000001 -E hash_seed=5a5a5a5a-0000-4000-8000-000000000002,root_owner=0:0 \
    -d "$root" "$image" 512k
  # mknod takes a bare name, so it runs inside dev/. mke2fs -d copies each file's owner and ctime from the host,
  # so every inode gets root ownership and the fixed time.
  {
    printf 'mkdir dev\ncd dev\nmknod console c 5 1\ncd /\nsif bin/hello mode 0104755\n'
    (cd "$root" && find . -mindepth 1 | LC_ALL=C sort | sed 's|^\.||'; echo /dev; echo /dev/console; echo /) |
      while read -r path; do
        for field in uid gid; do printf 'sif "%s" %s 0\n' "$path" "$field"; done
        for field in atime ctime mtime crtime; do printf 'sif "%s" %s 20260101000000\n' "$path" "$field"; done
      done
  } > "$work/debugfs.cmds"
  E2FSPROGS_FAKE_TIME=1767225600 debugfs -w -f "$work/debugfs.cmds" "$image" > /dev/null 2>&1
  E2FSPROGS_FAKE_TIME=1767225600 e2fsck -fn "$image" > /dev/null 2>&1
done

# ustar from the same tree, owned by root; craft_fsimages.py writes rootfs.cpio (newc) from it, because bsdcpio
# records host inode and device numbers.
(cd "$root" && find . -mindepth 1 | LC_ALL=C sort | COPYFILE_DISABLE=1 bsdtar -c -f - --format ustar \
  --uid 0 --gid 0 --uname root --gname root -n -T -) > "$out/rootfs.tar"

python3 -I craft_fsimages.py "$out"

# Ratio bombs made of synthesised or highly compressible bytes: a 200 MiB hole in ext4, a 200 MiB file of sparse
# SquashFS blocks, and 200 MiB of one byte in 1 MiB xz blocks.
bombs="$work/bombs"
mkdir -p "$bombs/hole" "$bombs/repeat"
truncate -s 200M "$bombs/hole/hole.bin"
python3 -c 'import sys; sys.stdout.buffer.write(b"A" * (200 << 20))' > "$bombs/repeat/repeat.bin"
find "$bombs" -exec touch -h -t 202601010000 {} +
rm -f "$out/holes.ext4" "$out/holes.sqfs" "$out/repeat-xz.sqfs"
E2FSPROGS_FAKE_TIME=1767225600 mke2fs -q -t ext4 -O ^has_journal -b 1024 -N 16 -m 0 \
  -U 5a5a5a5a-0000-4000-8000-000000000003 -E hash_seed=5a5a5a5a-0000-4000-8000-000000000004,root_owner=0:0 \
  -d "$bombs/hole" "$out/holes.ext4" 128k
printf 'sif "/hole.bin" uid 0\nsif "/hole.bin" gid 0\n' > "$work/holes.cmds"
for field in atime ctime mtime crtime; do printf 'sif "/hole.bin" %s 20260101000000\n' "$field"; done >> "$work/holes.cmds"
E2FSPROGS_FAKE_TIME=1767225600 debugfs -w -f "$work/holes.cmds" "$out/holes.ext4" > /dev/null 2>&1
mksquashfs "$bombs/hole" "$out/holes.sqfs" -b 131072 -noappend -all-root -no-xattrs -mkfs-time 0 -all-time 0 \
  -quiet -no-progress > /dev/null
mksquashfs "$bombs/repeat" "$out/repeat-xz.sqfs" -comp xz -b 1M -noappend -all-root -no-xattrs -mkfs-time 0 \
  -all-time 0 -quiet -no-progress > /dev/null

# The UBI and UBIFS fixtures (ubi.img, ubifs-*.ubifs) come from build-ubi-fsimages.sh, which runs mtd-utils in a
# Debian container.

# deep-8000.sqfs (8,000 nested directories, uncompressed) is not rebuilt here: backhand's writer takes about 40
# minutes for it. It came from nested_squashfs(8000) in crates/rampage-unpack/tests/hardening.rs (backhand 0.25.5,
# mtime 0), run once on a thread with a 1 GiB stack.
