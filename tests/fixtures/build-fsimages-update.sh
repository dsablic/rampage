#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Rebuilds the SquashFS update pair for diff_firmware: fsimages/update-v1.sqfs and fsimages/update-v2.sqfs hold two
# versions of one invented device tree. From v1 to v2, bin/controller changes (firmware/raw-cortex-m-update-v1.elf
# becomes -v2.elf), etc/cloud.conf is added and etc/legacy.conf removed; bin/hello (bin/hello-mips.elf),
# etc/hostname, etc/device.conf and usr/share/readme.txt stay the same. Needs mksquashfs (squashfs-tools 4.6+).
# Timestamps and ownership are fixed, so rebuilding with the same tools reproduces the bytes.
set -euo pipefail
cd "$(dirname "$0")"
export TZ=UTC LC_ALL=C
out=fsimages
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tree() {
  local root=$1 version=$2
  mkdir -p "$root/etc" "$root/bin" "$root/usr/share"
  printf 'demo-device\n' > "$root/etc/hostname"
  printf 'telemetry=off\nmicrophone=push-to-talk\n' > "$root/etc/device.conf"
  printf 'An invented device for rampage update tests.\n' > "$root/usr/share/readme.txt"
  cp bin/hello-mips.elf "$root/bin/hello"
  cp "firmware/raw-cortex-m-update-$version.elf" "$root/bin/controller"
  chmod 755 "$root/bin/hello" "$root/bin/controller"
  if [ "$version" = v1 ]; then
    printf 'legacy_port=8080\n' > "$root/etc/legacy.conf"
  else
    printf 'upload_endpoint=https://cloud.example.net/v2/ingest\n' > "$root/etc/cloud.conf"
  fi
  find "$root" -exec touch -h -t 202601010000 {} +
}
for version in v1 v2; do
  tree "$work/$version" "$version"
  rm -f "$out/update-$version.sqfs"
  mksquashfs "$work/$version" "$out/update-$version.sqfs" -comp gzip -b 4096 -noappend -all-root -no-xattrs \
    -mkfs-time 0 -all-time 0 -quiet -no-progress > /dev/null
done
