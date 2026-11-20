#!/usr/bin/env python3
"""Derive ground truth for the acceptance inputs without using rampage.

Reads target/acceptance/inputs (see fetch.py) and writes target/acceptance/truth.json. Truth comes from the
builders' own artefacts (release manifests, the ELF an image was made from, matching debug files) and from
reference tools: unsquashfs, llvm-nm and llvm-readelf. Header fields are parsed here from the format definitions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
LLVM_DIRS = ["/opt/homebrew/opt/llvm/bin", "/usr/local/opt/llvm/bin", "/usr/lib/llvm/bin"]


def tool(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    for directory in LLVM_DIRS:
        candidate = Path(directory) / name
        if candidate.exists():
            return str(candidate)
    raise SystemExit(f"required tool not found: {name}")


def run(*command: str) -> str:
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def function_symbols(elf: Path) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for line in run(tool("llvm-nm"), "--defined-only", "--print-size", str(elf)).splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[2] in "tT":
            out[parts[3]] = {"address": int(parts[0], 16), "size": int(parts[1], 16)}
    return out


def elf_facts(elf: Path) -> dict[str, object]:
    header = run(tool("llvm-readelf"), "-h", str(elf))
    dynamic = subprocess.run([tool("llvm-readelf"), "-d", str(elf)], capture_output=True, text=True).stdout
    field = lambda key: next((l.split(":", 1)[1].strip() for l in header.splitlines() if l.strip().startswith(key)), "")
    return {
        "class": field("Class"),
        "data": field("Data"),
        "machine": field("Machine"),
        "flags": field("Flags"),
        "entry": field("Entry point address"),
        "needed": [l.split("[")[1].rstrip("]") for l in dynamic.splitlines() if "(NEEDED)" in l],
    }


def build_id(elf: Path) -> str:
    notes = subprocess.run([tool("llvm-readelf"), "-n", str(elf)], capture_output=True, text=True).stdout
    return next((l.split(":")[1].strip() for l in notes.splitlines() if "Build ID" in l), "")


def tree_hashes(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for directory, _, files in os.walk(root):
        for name in files:
            path = Path(directory) / name
            if not path.is_symlink():
                out[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def is_elf(path: Path) -> bool:
    with path.open("rb") as handle:
        return handle.read(4) == b"\x7fELF"


def unsquash(image: Path, offset: int, dest: Path) -> None:
    carved = dest.with_suffix(".sqfs")
    carved.write_bytes(image.read_bytes()[offset:])
    shutil.rmtree(dest, ignore_errors=True)
    # Device nodes cannot be created without privileges, so a non-zero exit is expected.
    subprocess.run([tool("unsquashfs"), "-q", "-n", "-no-xattrs", "-d", str(dest), str(carved)], capture_output=True)
    if not dest.is_dir():
        raise SystemExit(f"unsquashfs produced nothing for {image.name}")


def manifest_packages(path: Path) -> dict[str, str]:
    return dict(line.split(" - ", 1) for line in path.read_text().splitlines() if " - " in line)


def openwrt(inputs: Path, work: Path) -> dict[str, object]:
    out: dict[str, object] = {}
    trees: dict[str, dict[str, str]] = {}
    roots: dict[str, Path] = {}
    for key, version in (("old", "23.05.4"), ("new", "23.05.5")):
        image = inputs / f"openwrt-{version}-ath79-generic-tplink_archer-c7-v2-squashfs-sysupgrade.bin"
        offset = image.read_bytes().find(b"hsqs")
        roots[key] = work / f"openwrt-{key}-root"
        unsquash(image, offset, roots[key])
        trees[key] = tree_hashes(roots[key])
        # os.walk lists a symbolic link to a directory among the directories, so both lists are counted.
        links = sum(1 for d, ds, fs in os.walk(roots[key]) for f in ds + fs if (Path(d) / f).is_symlink())
        out[key] = {"squashfs_offset": offset, "regular_files": len(trees[key]), "symlinks": links}
    old, new = trees["old"], trees["new"]
    changed = sorted(p for p in old if p in new and old[p] != new[p])
    out["tree_diff"] = {
        "added": sorted(set(new) - set(old)),
        "removed": sorted(set(old) - set(new)),
        "changed": changed,
        "changed_elf": [p for p in changed if is_elf(roots["new"] / p)],
        "unchanged": sum(1 for p in old if new.get(p) == old[p]),
    }
    programs = sorted(p for p in new if is_elf(roots["new"] / p) and not p.endswith(".ko"))
    out["programs"] = {p: elf_facts(roots["new"] / p) for p in programs}
    out["mips16_programs"] = [p for p, facts in out["programs"].items() if "mips16" in str(facts["flags"])]
    before = manifest_packages(inputs / "openwrt-23.05.4-ath79-generic.manifest")
    after = manifest_packages(inputs / "openwrt-23.05.5-ath79-generic.manifest")
    out["package_changes"] = {n: [before.get(n), after.get(n)] for n in sorted(set(before) | set(after)) if before.get(n) != after.get(n)}
    out["packages"] = after
    return out


def containers(inputs: Path) -> dict[str, object]:
    ubi = (inputs / "openwrt-23.05.5-ath79-nand-aerohive_hiveap-121-squashfs-factory.bin").read_bytes()
    magic, _, _, data_size, load, entry = struct.unpack(">IIIIII", ubi[:24])
    ubi_offset = ubi.find(b"UBI#")
    trx = (inputs / "openwrt-23.05.5-bcm47xx-generic-standard-squashfs.trx").read_bytes()
    trx_magic, trx_len, trx_crc, _, o1, o2, o3 = struct.unpack("<4sIIIIII", trx[:28])
    fit = (inputs / "openwrt-23.05.5-mediatek-filogic-bananapi_bpi-r3-squashfs-sysupgrade.itb").read_bytes()
    fit_magic, fit_size = struct.unpack(">II", fit[:8])
    return {
        "ubi_factory": {
            "uimage_magic_ok": magic == 0x27051956,
            "uimage_data_size": data_size,
            "uimage_load": load,
            "uimage_entry": entry,
            "ubi_offset": ubi_offset,
            "ubi_ec_headers": ubi.count(b"UBI#"),
            "file_size": len(ubi),
        },
        "trx": {
            "magic_ok": trx_magic == b"HDR0",
            "length": trx_len,
            "crc32": trx_crc,
            "partition_offsets": [o for o in (o1, o2, o3) if o],
            "squashfs_offset": trx.find(b"hsqs"),
            "file_size": len(trx),
        },
        "fit": {
            "dtb_magic_ok": fit_magic == 0xD00DFEED,
            "dtb_total_size": fit_size,
            "squashfs_offset": fit.find(b"hsqs"),
            "file_size": len(fit),
        },
    }


def esp_image_offsets(data: bytes) -> dict[str, object]:
    table = next((o for o in range(0, len(data), 0x1000) if data[o : o + 2] == b"\xaa\x50"), None)
    apps: list[dict[str, int]] = []
    if table is not None:
        for i in range(0, 0xC00, 32):
            entry = data[table + i : table + i + 32]
            if entry[:2] != b"\xaa\x50":
                break
            kind, subtype, offset, size = struct.unpack("<BBII", entry[2:12])
            apps.append({"type": kind, "subtype": subtype, "flash_offset": offset, "size": size, "label": entry[12:28].rstrip(b"\0").decode("ascii", "replace")})
    return {"first_byte": data[0], "partition_table_file_offset": table, "partitions": apps}


def micropython(inputs: Path, work: Path) -> dict[str, object]:
    out: dict[str, object] = {}
    symbols: dict[str, dict[str, dict[str, int]]] = {}
    for key, stem in (
        ("esp32_old", "ESP32_GENERIC-20241025-v1.24.0"),
        ("esp32_new", "ESP32_GENERIC-20241129-v1.24.1"),
        ("esp8266", "ESP8266_GENERIC-20241129-v1.24.1"),
    ):
        with zipfile.ZipFile(inputs / f"{stem}.meta.zip") as archive:
            archive.extract(f"{stem}.elf", work)
        elf = work / f"{stem}.elf"
        symbols[key] = function_symbols(elf)
        image = (inputs / f"{stem}.bin").read_bytes()
        out[key] = {
            "elf": elf_facts(elf),
            "function_symbols": len(symbols[key]),
            "functions": symbols[key],
            "image": esp_image_offsets(image),
            "image_size": len(image),
            "version_string_present": stem.split("-")[-1].encode() in image,
        }
    old, new = symbols["esp32_old"], symbols["esp32_new"]
    out["esp32_diff"] = {
        "added": sorted(set(new) - set(old)),
        "removed": sorted(set(old) - set(new)),
        "size_changed": sorted(n for n in old if n in new and old[n]["size"] != new[n]["size"]),
    }
    return out


def unpack_deb(deb: Path, dest: Path) -> None:
    data = deb.read_bytes()
    if data[:8] != b"!<arch>\n":
        raise SystemExit(f"not an ar archive: {deb.name}")
    offset = 8
    while offset < len(data):
        name = data[offset : offset + 16].decode().strip().rstrip("/")
        size = int(data[offset + 48 : offset + 58])
        body = data[offset + 60 : offset + 60 + size]
        if name.startswith("data.tar"):
            if not name.endswith(".xz"):
                raise SystemExit(f"unsupported member {name} in {deb.name}")
            tar_path = dest / "data.tar"
            dest.mkdir(parents=True, exist_ok=True)
            tar_path.write_bytes(lzma.decompress(body))
            with tarfile.open(tar_path) as archive:
                archive.extractall(dest, filter="data")
            return
        offset += 60 + size + (size & 1)
    raise SystemExit(f"no data member in {deb.name}")


def zlib(inputs: Path, work: Path) -> dict[str, object]:
    out: dict[str, object] = {}
    symbols: dict[str, dict[str, dict[str, int]]] = {}
    for key, version in (("old", "1.2.11.dfsg-2+deb11u2"), ("new", "1.2.13.dfsg-1")):
        lib_dir, dbg_dir = work / f"zlib-{key}", work / f"zlib-{key}-dbg"
        unpack_deb(inputs / f"zlib1g_{version}_mipsel.deb", lib_dir)
        unpack_deb(inputs / f"zlib1g-dbgsym_{version}_mipsel.deb", dbg_dir)
        library = next(p for p in lib_dir.rglob("libz.so.1.*") if not p.is_symlink())
        debug = next(dbg_dir.rglob("*.debug"))
        if build_id(library) != build_id(debug):
            raise SystemExit(f"build IDs differ for zlib {version}")
        symbols[key] = function_symbols(debug)
        exported = [l.split()[-1] for l in run(tool("llvm-nm"), "-D", "--defined-only", str(library)).splitlines() if " T " in l]
        out[key] = {
            "library": str(library.relative_to(work)),
            "debug_file": str(debug.relative_to(work)),
            "sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
            "build_id": build_id(library),
            "elf": elf_facts(library),
            "function_symbols": len(symbols[key]),
            "functions": symbols[key],
            "exported_functions": sorted(exported),
        }
    old, new = symbols["old"], symbols["new"]
    out["diff"] = {
        "added": sorted(set(new) - set(old)),
        "removed": sorted(set(old) - set(new)),
        "size_changed": sorted(n for n in old if n in new and old[n]["size"] != new[n]["size"]),
        "size_unchanged": sorted(n for n in old if n in new and old[n]["size"] == new[n]["size"]),
    }
    # Defined by the zlib manual and RFC 1950/1952; the check values are the standard ones for "123456789".
    out["reference_values"] = {
        "crc32(0, \"123456789\", 9)": 0xCBF43926,
        "adler32(1, \"123456789\", 9)": 0x091E01DE,
        "crc32(0, NULL, 0)": 0,
        "adler32(0, NULL, 0)": 1,
        "compressBound(0)": 13,
    }
    return out


def android(inputs: Path) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, code, name in (("old", 65, "5.10.0"), ("new", 66, "5.10.1")):
        with zipfile.ZipFile(inputs / f"com.simplemobiletools.flashlight_{code}.apk") as archive:
            names = archive.namelist()
            dex = {n: hashlib.sha256(archive.read(n)).hexdigest() for n in names if n.endswith(".dex")}
        out[key] = {
            "package": "com.simplemobiletools.flashlight",
            "version_code": code,
            "version_name": name,
            "entries": len(names),
            "dex_files": dex,
            "native_libraries": sorted(n for n in names if n.startswith("lib/")),
        }
    out["dex_changed"] = out["old"]["dex_files"] != out["new"]["dex_files"]
    out["note"] = "Version names are from F-Droid's package index. Manifest fields (permissions, components) need aapt2 or apkanalyzer as the reference and are not derived here."
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, default=REPO / "target" / "acceptance" / "inputs")
    parser.add_argument("--out", type=Path, default=REPO / "target" / "acceptance" / "truth.json")
    args = parser.parse_args()
    work = args.out.parent / "work"
    work.mkdir(parents=True, exist_ok=True)
    truth = {
        "openwrt": openwrt(args.inputs, work),
        "containers": containers(args.inputs),
        "micropython": micropython(args.inputs, work),
        "zlib_mipsel": zlib(args.inputs, work),
        "android": android(args.inputs),
    }
    args.out.write_text(json.dumps(truth, indent=1, sort_keys=True) + "\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
