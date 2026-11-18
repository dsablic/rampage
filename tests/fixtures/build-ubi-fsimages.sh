#!/usr/bin/env bash
# Rebuilds the UBI and UBIFS fixtures in fsimages/ with mtd-utils (mkfs.ubifs, ubinize) and squashfs-tools inside
# a Debian container, since neither is packaged for macOS: bash build-ubi-fsimages.sh (needs docker). The tree is
# the one build-fsimages.sh writes, plus a hard link (usr/share/demo/readme.link), a 24 KiB incompressible file
# that spans two 15 KiB LEBs (usr/share/demo/large.bin), a character device (dev/console) and a setuid
# bin/hello.
#
# - ubifs-lzo.ubifs, ubifs-zstd.ubifs, ubifs-none.ubifs: bare UBIFS images (LEBs back to back) per compressor.
# - ubi.img: a UBI image (16 KiB PEBs, 512-byte pages and sub-pages, so 15 KiB LEBs) with two volumes: `rootfs`,
#   dynamic, holding the tree as UBIFS with zlib; `squash`, static, holding the tree as gzip SquashFS.
#
# mkfs.ubifs writes a random UUID into the superblock, so rebuilding changes those bytes; everything else is fixed
# (timestamps, owners, the UBI image sequence number).
set -euo pipefail
cd "$(dirname "$0")"
if [ "${1:-}" != "--inside" ]; then
  exec docker run --rm -v "$PWD:/fixtures" -w /fixtures debian:stable-slim bash /fixtures/build-ubi-fsimages.sh --inside
fi

export TZ=UTC LC_ALL=C DEBIAN_FRONTEND=noninteractive
apt-get update -qq > /dev/null
apt-get install -y -qq mtd-utils squashfs-tools python3 > /dev/null
out=/fixtures/fsimages
work=$(mktemp -d)
root="$work/rootfs"
mkdir -p "$root/etc" "$root/bin" "$root/usr/share/demo/nested" "$root/var" "$root/dev"
printf 'demo-device\n' > "$root/etc/hostname"
printf 'telemetry=off\nupload_endpoint=https://telemetry.example.invalid/collect\nmicrophone=push-to-talk\n' \
  > "$root/etc/device.conf"
printf 'An invented filesystem for rampage tests.\n' > "$root/usr/share/demo/readme.txt"
ln "$root/usr/share/demo/readme.txt" "$root/usr/share/demo/readme.link"
printf 'nested file\n' > "$root/usr/share/demo/nested/deep.txt"
python3 -c 'import sys; sys.stdout.write("".join("line %05d of the multi-block file\n" % i for i in range(400)))' \
  > "$root/usr/share/demo/blocks.txt"
# SHA-256 in counter mode: incompressible, so its data nodes fill more than one LEB whatever the compressor.
python3 -c '
import hashlib, sys
sys.stdout.buffer.write(b"".join(hashlib.sha256(b"large %d" % i).digest() for i in range(768)))' \
  > "$root/usr/share/demo/large.bin"
: > "$root/usr/share/demo/empty"
cp bin/hello-mips.elf "$root/bin/hello"
ln -s hello "$root/bin/sh"
ln -s /etc/hostname "$root/var/hostname"
mknod -m 600 "$root/dev/console" c 5 1
chown -R 0:0 "$root"
# After chown, which clears the setuid bit.
chmod 4755 "$root/bin/hello"
find "$root" -exec touch -h -t 202601010000 {} +

ubifs() {
  mkfs.ubifs -r "$root" -m 512 -e 15360 -c 64 -x "$1" -o "$2"
}
for comp in lzo zstd none; do
  rm -f "$out/ubifs-$comp.ubifs"
  ubifs "$comp" "$out/ubifs-$comp.ubifs"
done
ubifs zlib "$work/rootfs.ubifs"
mksquashfs "$root" "$work/squash.sqfs" -comp gzip -b 4096 -noappend -all-root -no-xattrs -mkfs-time 0 \
  -all-time 0 -quiet -no-progress > /dev/null
cat > "$work/ubinize.ini" <<EOF
[rootfs]
mode=ubi
image=$work/rootfs.ubifs
vol_id=0
vol_type=dynamic
vol_name=rootfs
vol_size=1MiB
[squash]
mode=ubi
image=$work/squash.sqfs
vol_id=1
vol_type=static
vol_name=squash
EOF
rm -f "$out/ubi.img"
ubinize -o "$out/ubi.img" -m 512 -p 16KiB -s 512 -Q 1 "$work/ubinize.ini"
chown "$(stat -c %u:%g /fixtures)" "$out"/ubifs-*.ubifs "$out/ubi.img"
rm -rf "$work"
