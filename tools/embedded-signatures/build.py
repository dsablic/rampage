#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the inputs of the embedded Thumb signature set (rampage-builtin's scheme-3 Cortex-M library signatures).

Subcommands:
  fetch        download the pinned toolchains and source archives into WORK/dl, check their SHA-256 and unpack them
               into WORK/tc/<release> and WORK/src/<name>
  refs         link symbolized reference ELFs (WORK/refs/*.elf) from the training toolchains' newlib, newlib-nano,
               libm and libgcc archives, and from FreeRTOS and STM32F4 HAL/LL sources compiled at several
               optimisation levels; `--config hooks` links the kernels with every application hook on
               (WORK/refs-hooks), which the operand tier and the call graph also train on
  compiler-rt  build LLVM compiler-rt builtins references with clang (--clang, default Homebrew llvm@22)
  fixture      build the held-out firmware fixtures with a toolchain not used for training (14.3.rel1); with --eval,
               write their stripped twins, raw images and libid truth into tests/fixtures
  profiles     print the bundled index's build profiles (JSON) for signature_bundle_index
  dev          build the dev split (WORK/dev): the owned dev-app firmware with toolchains, options and a kernel
               configuration training does not use, each with a stripped twin and libid truth (`fetch --dev`
               first). Iterate on dev; the 14.3 fixtures are the final split
  negatives    build the negative references: Thumb builds of libraries no embedded signature covers (the
               flywheel corpus's LZ4, cJSON and tinyexpr; GCC 13.2, -Os and -O2) that the operand tier takes as
               tombstones (WORK/negatives); with --gate, the held-out negative gate instead (zlib and inih, which
               the tombstones never saw, built by GCC 12.2 at -O1 and -O3; WORK/negatives-gate), where any name
               is a false one

The whole regeneration (see docs/signature-corpus.md#embedded-firmware-set):

  python3 -I tools/embedded-signatures/build.py fetch
  python3 -I tools/embedded-signatures/build.py refs
  python3 -I tools/embedded-signatures/build.py compiler-rt
  target/debug/examples/embedded_signatures --output WORK/db.json --gzip WORK/db.json.gz \\
      WORK/refs/*.elf

Downloaded sources, toolchains and build outputs stay under WORK, never in the repository. Nothing that is built
is executed. Run with `python3 -I`.
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

ARM_URL = "https://developer.arm.com/-/media/Files/downloads/gnu/{v}/binrel/arm-gnu-toolchain-{v}-darwin-arm64-arm-none-eabi.tar.xz"

# Pinned inputs: name -> (url, sha256, unpack directory).
TOOLCHAINS = {
    "12.3.rel1": "3b2eee0bdf71c1bbeb3c3b7424fbf7bd9d5c3f0f5a3a4a78159c9e3ad219e7bd",
    "13.3.rel1": "fb6921db95d345dc7e5e487dd43b745e3a5b4d5c0c7ca4f707347148760317b4",
    "14.3.rel1": "30f4d08b219190a37cded6aa796f4549504902c53cfc3c7e044a8490b6eba1f7",
    "15.2.rel1": "1938a84b7105c192e3fb4fa5e893ba25f425f7ddab40515ae608cd40f68669a8",
}
SOURCES = {
    "freertos-V11.1.0": (
        "https://github.com/FreeRTOS/FreeRTOS-Kernel/archive/refs/tags/V11.1.0.tar.gz",
        "0e21928b3bcc4f9bcaf7333fb1c8c0299d97e2ec9e13e3faa2c5a7ac8a3bc573",
    ),
    "freertos-V10.6.2": (
        "https://github.com/FreeRTOS/FreeRTOS-Kernel/archive/refs/tags/V10.6.2.tar.gz",
        "219dfc5d6f51d1e7664cdb162c33725ea7e89703bb5a2becfa6a755a0f765c45",
    ),
    "f4hal-v1.8.3": (
        "https://github.com/STMicroelectronics/stm32f4xx-hal-driver/archive/refs/tags/v1.8.3.tar.gz",
        "8e8a1a4872ab9617684806a6e7bd5aa82b71b5bfe0f88b6679760ca2933a8c02",
    ),
    "cmsis-device-f4-v2.6.10": (
        "https://github.com/STMicroelectronics/cmsis-device-f4/archive/refs/tags/v2.6.10.tar.gz",
        "b0566d2e07f6f38d69f3ba78ffa8bbac6f393c5b0fa31dd9e84f2ab42994fe7b",
    ),
    "cmsis5": (
        "https://github.com/ARM-software/CMSIS_5/archive/refs/tags/5.9.0.tar.gz",
        "9ce693dd15c41f02506adda79323c077912b3211303ca0d9b28b8ebe735a7031",
    ),
}

# Development toolchains, used for the dev split only: never for training, and none is the held-out 14.3. The xPack
# build is the only arm64 macOS GCC 11 (Arm published 11.3.rel1 for x86-64 macOS only); its newlib is built from
# Arm's sources by the xPack project. release -> (url, sha256).
XPACK_URL = ("https://github.com/xpack-dev-tools/arm-none-eabi-gcc-xpack/releases/download/v11.3.1-1.1/"
             "xpack-arm-none-eabi-gcc-11.3.1-1.1-darwin-arm64.tar.gz")
DEV_TOOLCHAINS = {
    "xpack-11.3.1-1.1": (XPACK_URL, "99de78184f5548c65b980130c9438a31a602ddbbe9515f3d82bf000b67f8c835"),
    "12.2.rel1": (ARM_URL.format(v="12.2.rel1"), "21a9e875250bcb0db8df4cb23dd43c94c00a1d3b98ecba9cdd6ed51586b12248"),
    "13.2.rel1": (ARM_URL.format(v="13.2.rel1"), "39c44f8af42695b7b871df42e346c09fee670ea8dfc11f17083e296ea2b0d279"),
}

COMPILER_RT_URL = "https://github.com/llvm/llvm-project/releases/download/llvmorg-22.1.8/llvm-project-22.1.8.src.tar.xz"
COMPILER_RT_SHA256 = "922f1817a0df7b1489272d18134ee0087a8b068828f87ac63b9861b1a9965888"

TRAINING = ["12.3.rel1", "13.3.rel1", "15.2.rel1"]
HELD_OUT = "14.3.rel1"

# Core -> compiler flags. Each selects one of the toolchain's prebuilt multilibs.
CORES = {
    "m0": ["-mcpu=cortex-m0", "-mthumb", "-mfloat-abi=soft"],
    "m3": ["-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft"],
    "m4": ["-mcpu=cortex-m4", "-mthumb", "-mfloat-abi=soft"],
    "m4f": ["-mcpu=cortex-m4", "-mthumb", "-mfpu=fpv4-sp-d16", "-mfloat-abi=hard"],
    "m7d": ["-mcpu=cortex-m7", "-mthumb", "-mfpu=fpv5-d16", "-mfloat-abi=hard"],
}
OPTIMISATIONS = ["Os", "O2", "O3", "Og", "O0"]
FREERTOS_PORTS = {"m0": "ARM_CM0", "m3": "ARM_CM3", "m4f": "ARM_CM4F"}
FREERTOS_FILES = ["tasks.c", "queue.c", "list.c", "timers.c", "event_groups.c", "stream_buffer.c"]
# HAL sources that are templates or need a board, not library code.
HAL_SKIP = re.compile(r"_template\.c$")

LINKER_SCRIPT = """MEMORY { FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 64M
         RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 64M }
SECTIONS {
  .text : { KEEP(*(.isr_vector)) *(.text .text.*) *(.rodata .rodata.*) } > FLASH
  .ARM.exidx : { *(.ARM.exidx*) } > FLASH
  .data : { *(.data .data.*) } > RAM AT > FLASH
  .bss (NOLOAD) : { *(.bss .bss.* COMMON) } > RAM
}
"""

STUB_PREFIX = "embsig_stub_"


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(map(str, command))}\n{result.stderr[-4000:]}")
    return result


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(work, dev=False):
    """The pinned training and held-out inputs; with `dev`, instead the dev toolchains, the 13.3 toolchain the dev
    split's configuration cells use and the negative libraries' sources."""
    downloads = work / "dl"
    downloads.mkdir(parents=True, exist_ok=True)
    if dev:
        items = [(f"{release}.tar.{url.rsplit('.', 1)[1]}", url, digest, work / "tc" / release, 1)
                 for release, (url, digest) in DEV_TOOLCHAINS.items()]
        items.append(("arm-13.3.rel1.tar.xz", ARM_URL.format(v="13.3.rel1"), TOOLCHAINS["13.3.rel1"],
                      work / "tc" / "13.3.rel1", 1))
        items += [(f"{name}.tar.gz", url, digest, work / "src" / name, 1)
                  for name, (url, digest, _) in negative_sources().items()]
    else:
        items = [(f"arm-{v}.tar.xz", ARM_URL.format(v=v), digest, work / "tc" / v, 1)
                 for v, digest in TOOLCHAINS.items()]
        items += [(f"{name}.tar.gz", url, digest, work / "src" / name, 1) for name, (url, digest) in SOURCES.items()]
        # Only compiler-rt's directory of the LLVM monorepo archive is unpacked.
        items.append(("llvm-project-22.1.8.src.tar.xz", COMPILER_RT_URL, COMPILER_RT_SHA256,
                      work / "src" / "compiler-rt-22.1.8", 2))
    for file, url, digest, destination, strip in items:
        archive = downloads / file
        if not archive.exists():
            print(f"downloading {url}", file=sys.stderr)
            partial = archive.with_name(archive.name + ".part")
            urllib.request.urlretrieve(url, partial)
            partial.rename(archive)
        actual = sha256(archive)
        if actual != digest:
            archive.unlink()
            raise RuntimeError(f"{archive}: SHA-256 {actual}, pinned {digest}; the download was deleted")
        if destination.exists():
            continue
        unpack(archive, destination, strip)


def unpack(archive, destination, strip):
    """Extracts `archive` without its first `strip` path components (2: only the LLVM monorepo's compiler-rt) into a
    temporary sibling directory, then renames it into place, so an interrupted run leaves no partial tree."""
    staging = destination.with_name(destination.name + ".partial")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    def stripped(name):
        parts = Path(name).parts
        if strip == 2 and (len(parts) < 2 or parts[1] != "compiler-rt"):
            return None
        parts = parts[strip:]
        return str(Path(*parts)) if parts else None

    with tarfile.open(archive) as tar:
        members = []
        for member in tar.getmembers():
            name = stripped(member.name)
            if name is None or member.issym() and Path(member.linkname).is_absolute():
                continue
            if member.islnk():
                # A hard link names another member by its archive path, which loses the same components.
                target = stripped(member.linkname)
                if target is None:
                    continue
                member.linkname = target
            member.name = name
            members.append(member)
        tar.extractall(staging, members=members, filter="data")
    staging.rename(destination)


class Toolchain:
    def __init__(self, work, release):
        self.release = release
        self.bin = work / "tc" / release / "bin"
        self.gcc = self.bin / "arm-none-eabi-gcc"
        self.ld = self.bin / "arm-none-eabi-ld"
        self.assembler = self.bin / "arm-none-eabi-as"
        self.version = run([self.gcc, "-dumpfullversion"]).stdout.strip()

    def libraries(self, core):
        """The core's multilib directory (newlib archives) and libgcc."""
        flags = CORES[core]
        libgcc = Path(run([self.gcc, *flags, "-print-libgcc-file-name"]).stdout.strip())
        multilib = run([self.gcc, *flags, "-print-multi-directory"]).stdout.strip()
        return self.gcc.parent.parent / "arm-none-eabi" / "lib" / multilib, libgcc


def link_reference(toolchain, output, inputs):
    """Links `inputs` into a symbolized ELF without garbage collection. Symbols nothing in the inputs defines get
    one-instruction stubs (their names prefixed in a section, never signed: the confidence gate rejects them)."""
    script = output.with_suffix(".ld")
    script.write_text(LINKER_SCRIPT)
    names = set()
    for _ in range(6):
        stub = output.with_suffix(".stubs.s")
        lines = [".syntax unified", ".thumb"]
        for name in sorted(names):
            lines += [
                f'.section .text.{STUB_PREFIX}{name},"ax",%progbits',
                f".weak {name}",
                f".type {name},%function",
                ".thumb_func",
                f"{name}: bx lr",
                f".size {name},.-{name}",
            ]
        stub.write_text("\n".join(lines) + "\n")
        run([toolchain.assembler, "-mthumb", "-march=armv6-m", stub, "-o", stub.with_suffix(".o")])
        command = [toolchain.ld, "-T", script, "-e", "0", "--no-gc-sections", "--allow-multiple-definition"]
        command += [stub.with_suffix(".o"), *inputs, "-o", output]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            for path in (script, stub, stub.with_suffix(".o")):
                path.unlink()
            return
        missing = set(re.findall(r"\((\S+)\): Unknown destination type", result.stderr))
        missing |= set(re.findall(r"undefined reference to `([^']+)'", result.stderr))
        if not missing - names:
            raise RuntimeError(f"linking {output}:\n{result.stderr[-4000:]}")
        names |= missing
    raise RuntimeError(f"linking {output}: unresolved symbols did not converge")


def compile_objects(toolchain, flags, sources, build):
    build.mkdir(parents=True, exist_ok=True)
    objects = []
    for source in sources:
        obj = build / (source.stem + ".o")
        run([toolchain.gcc, *flags, "-c", source, "-o", obj])
        objects.append(obj)
    return objects


def library_refs(toolchain, out):
    jobs = []
    for core in CORES:
        multilib, libgcc = toolchain.libraries(core)
        group = lambda libc: ["--start-group", multilib / libc, multilib / "libm.a", libgcc, multilib / "libnosys.a", "--end-group"]
        for name, whole, libc in [
            ("newlib-nano", multilib / "libc_nano.a", "libc_nano.a"),
            ("newlib", multilib / "libc.a", "libc.a"),
            ("libm", multilib / "libm.a", "libc.a"),
            ("libgcc", libgcc, "libc_nano.a"),
        ]:
            output = out / f"{name}-gcc{toolchain.version}-{core}.elf"
            jobs.append((output, ["--whole-archive", whole, "--no-whole-archive", *group(libc)]))
    return jobs


def freertos_flags(core, config, optimisation, includes):
    flags = [*CORES[core], f"-{optimisation}", "-ffunction-sections", "-fdata-sections", "-g0"]
    flags += [f"-DEMBSIG_PRIO_BITS={3 if core == 'm0' else 4}", f"-DEMBSIG_PORT_OPTIMISED={0 if core == 'm0' else 1}"]
    return flags + [f"-I{path}" for path in [config, *includes]]


def port_sources(port):
    """The port's C files; FreeRTOS 11's ARMv6-M port keeps its context switch in portasm.c."""
    return [port / "port.c"] + ([port / "portasm.c"] if (port / "portasm.c").exists() else [])


def build_freertos(work, toolchain, kernel, core, config, optimisation, out):
    source = work / "src" / kernel
    port = source / "portable" / "GCC" / FREERTOS_PORTS[core]
    includes = [source / "include", port]
    flags = freertos_flags(core, HERE / f"freertos-{config}", optimisation, includes)
    sources = [source / file for file in FREERTOS_FILES] + port_sources(port) + [source / "portable" / "MemMang" / "heap_4.c"]
    name = f"freertos-{kernel.split('-')[1]}-{config}-gcc{toolchain.version}-{core}-{optimisation}"
    build = work / "build" / name
    objects = compile_objects(toolchain, flags, sources, build)
    link_reference(toolchain, out / f"{name}.elf", objects)
    shutil.rmtree(build)


def hal_configuration(work, destination):
    """stm32f4xx_hal_conf.h from the driver's template with every module enabled."""
    template = (work / "src" / "f4hal-v1.8.3" / "Inc" / "stm32f4xx_hal_conf_template.h").read_text()
    enabled = re.sub(r"/\* *#define (HAL_(?!\w*LEGACY)\w+_MODULE_ENABLED) *\*/", r"#define \1", template)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "stm32f4xx_hal_conf.h").write_text(enabled)
    return destination


def hal_includes(work):
    return [
        work / "src" / "f4hal-v1.8.3" / "Inc",
        work / "src" / "cmsis-device-f4-v2.6.10" / "Include",
        work / "src" / "cmsis5" / "CMSIS" / "Core" / "Include",
    ]


def hal_sources(work):
    sources = sorted(path for path in (work / "src" / "f4hal-v1.8.3" / "Src").glob("*.c") if not HAL_SKIP.search(path.name))
    return sources + [work / "src" / "cmsis-device-f4-v2.6.10" / "Source" / "Templates" / "system_stm32f4xx.c"]


def build_hal(work, toolchain, optimisation, out):
    name = f"stm32f4-hal-v1.8.3-gcc{toolchain.version}-m4f-{optimisation}"
    build = work / "build" / name
    config = hal_configuration(work, build / "conf")
    flags = [*CORES["m4f"], f"-{optimisation}", "-ffunction-sections", "-fdata-sections", "-g0"]
    flags += ["-DSTM32F407xx", "-DUSE_HAL_DRIVER", "-DUSE_FULL_LL_DRIVER"]
    flags += [f"-I{path}" for path in [config, *hal_includes(work)]]
    objects = compile_objects(toolchain, flags, hal_sources(work), build / "obj")
    link_reference(toolchain, out / f"{name}.elf", objects)
    shutil.rmtree(build)


CLANG_TARGETS = {
    "m0": ["--target=thumbv6m-none-eabi", "-mfloat-abi=soft"],
    "m3": ["--target=thumbv7m-none-eabi", "-mfloat-abi=soft"],
    "m4": ["--target=thumbv7em-none-eabi", "-mfloat-abi=soft"],
    "m4f": ["--target=thumbv7em-none-eabihf", "-mfpu=fpv4-sp-d16", "-mfloat-abi=hard"],
}
# compiler-rt builtins that need an operating system, a hosted libc or 128-bit integers.
COMPILER_RT_SKIP = re.compile(r"^(emutls|enable_execute_stack|gcc_personality_v0|clear_cache|os_version_check|atomic"
                              r"|cpu_model|trampoline_setup|eprintf|apple_versioning|.*tf[0-9]?|.*ti[0-9]?|.*xf[0-9]?"
                              r"|.*xc[0-9]?|.*tc[0-9]?)\.c$")


def build_compiler_rt(work, clang, core, optimisation, ld_toolchain, out):
    """LLVM compiler-rt builtins for one core: the generic C sources, with the ARM assembly versions in place of
    the C files they replace (as compiler-rt's CMake selects them). Sources that do not build for the target
    are left out."""
    version = run([clang, "-dumpversion"]).stdout.strip()
    name = f"compiler-rt-22.1.8-clang{version}-{core}-{optimisation}"
    build = work / "build" / name
    build.mkdir(parents=True, exist_ok=True)
    builtins = work / "src" / "compiler-rt-22.1.8" / "lib" / "builtins"
    sysroot = ld_toolchain.gcc.parent.parent / "arm-none-eabi"
    flags = [*CLANG_TARGETS[core], f"-{optimisation}", "-ffreestanding", "-fno-builtin", "-ffunction-sections"]
    flags += ["-g0", f"--sysroot={sysroot}", f"-I{builtins}"]
    assembly = {path.stem: path for path in sorted((builtins / "arm").glob("*.S"))}
    sources = [path for path in sorted(builtins.glob("*.c")) if not COMPILER_RT_SKIP.match(path.name)]
    sources = [path for path in sources if path.stem not in assembly] + list(assembly.values())
    sources += sorted((builtins / "arm").glob("*.c"))
    objects = []
    for source in sources:
        obj = build / f"{source.parent.name}-{source.stem}.o"
        if subprocess.run([clang, *flags, "-c", source, "-o", obj], capture_output=True).returncode == 0:
            objects.append(obj)
    link_reference(ld_toolchain, out / f"{name}.elf", objects)
    shutil.rmtree(build)


def compiler_rt_refs(work, clangs, out):
    """compiler-rt builtins references from each clang (a path) for every core and optimisation level."""
    out.mkdir(parents=True, exist_ok=True)
    linker = Toolchain(work, TRAINING[-1])
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        tasks = [
            pool.submit(build_compiler_rt, work, Path(clang), core, optimisation, linker, out)
            for clang in clangs
            for core in CLANG_TARGETS
            for optimisation in ["O2", "Os", "O3"]
        ]
        for task in tasks:
            task.result()
    print(f"{len(tasks)} compiler-rt references in {out}", file=sys.stderr)


def refs(work, releases, out, configs=None):
    """Every reference of `releases`; with `configs`, only the FreeRTOS kernels in those configurations (`hooks`
    builds the references the operand tier and the call graph add, into their own directory)."""
    out.mkdir(parents=True, exist_ok=True)
    tasks = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        for release in releases:
            toolchain = Toolchain(work, release)
            if configs is None:
                for output, inputs in library_refs(toolchain, out):
                    tasks.append(pool.submit(link_reference, toolchain, output, inputs))
                for optimisation in OPTIMISATIONS:
                    tasks.append(pool.submit(build_hal, work, toolchain, optimisation, out))
            for kernel in ["freertos-V11.1.0", "freertos-V10.6.2"]:
                for core in FREERTOS_PORTS:
                    for config in configs or ["full", "small"]:
                        for optimisation in OPTIMISATIONS:
                            tasks.append(pool.submit(build_freertos, work, toolchain, kernel, core, config, optimisation, out))
        for task in tasks:
            task.result()
    print(f"{len(tasks)} references in {out}", file=sys.stderr)


FIXTURES = {
    # name: (core, optimisation, libc, uses HAL)
    "embedded-libs-m4f": ("m4f", "Os", "nano", True),
    "embedded-libs-m0": ("m0", "O1", "full", False),
}


def fixture(work, release, destination, evaluator=None):
    toolchain = Toolchain(work, release)
    source = REPO / "tests" / "fixtures" / "firmware" / "embedded-libs"
    for name, (core, optimisation, libc, hal) in FIXTURES.items():
        build = work / "build" / name
        if build.exists():
            shutil.rmtree(build)
        kernel = work / "src" / "freertos-V11.1.0"
        port = kernel / "portable" / "GCC" / FREERTOS_PORTS[core]
        sources = [source / "main.c", source / "startup.c"]
        sources += [kernel / file for file in FREERTOS_FILES] + port_sources(port) + [kernel / "portable" / "MemMang" / "heap_4.c"]
        flags = [*CORES[core], f"-{optimisation}", "-ffunction-sections", "-fdata-sections", "-g0"]
        flags += [f"-DEMBSIG_PRIO_BITS={3 if core == 'm0' else 4}", f"-DEMBSIG_PORT_OPTIMISED={0 if core == 'm0' else 1}"]
        includes = [source, kernel / "include", port]
        if hal:
            config = hal_configuration(work, build / "conf")
            flags += ["-DSTM32F407xx", "-DUSE_HAL_DRIVER", "-DEMBSIG_HAL"]
            includes += [config, *hal_includes(work)]
            hal = work / "src" / "f4hal-v1.8.3" / "Src"
            sources += [hal / f"stm32f4xx_hal{module}.c" for module in ["", "_cortex", "_rcc", "_gpio", "_uart", "_dma", "_flash", "_pwr", "_tim", "_tim_ex"]]
            sources += [work / "src" / "cmsis-device-f4-v2.6.10" / "Source" / "Templates" / "system_stm32f4xx.c"]
        flags += [f"-I{path}" for path in includes]
        objects = compile_objects(toolchain, flags, sources, build / "obj")
        specs = ["--specs=nano.specs"] if libc == "nano" else []
        elf = destination / f"{name}.elf"
        link = [toolchain.gcc, *CORES[core], *specs, "--specs=nosys.specs", "-nostartfiles", "-Wl,--gc-sections"]
        link += ["-Wl,--build-id=none", f"-Wl,-T,{source / 'embedded-libs.ld'}", "-Wl,-e,Reset_Handler"]
        link += [*objects, "-lm", "-o", elf]
        run(link)
        # The fixture's own objects, which name its program (not library) functions for the eval truth.
        program = work / "program" / name
        program.mkdir(parents=True, exist_ok=True)
        for obj in objects[:2]:
            shutil.copy(obj, program / obj.name)
        objcopy = toolchain.bin / "arm-none-eabi-objcopy"
        # The headerless flash image a Raw Project opens (base 0x08000000, vector table first).
        run([objcopy, "-O", "binary", "--only-section=.isr_vector", "--only-section=.text", "--only-section=.ARM.exidx", "--only-section=.data", elf, destination / f"{name}.bin"])
        shutil.rmtree(build)
        print(f"{elf}: GCC {toolchain.version} {core} -{optimisation} newlib-{libc}", file=sys.stderr)
        if evaluator:
            commit(work, evaluator, name, elf, destination)


def commit(work, evaluator, name, elf, destination):
    """The committed forms of a fixture: a stripped twin of `elf` (same layout) and its libid truth, the functions
    of the unstripped build that the held-out toolchain's library references (WORK/refs-heldout, from `refs
    --toolchain 14.3.rel1 --output WORK/refs-heldout`) also define, minus the fixture's own program objects."""
    stripped = REPO / "tests" / "fixtures" / "firmware" / f"{name}.elf"
    run([evaluator, "strip", elf, stripped])
    command = [evaluator, "truth", elf, "--stripped", stripped]
    for library in sorted((work / "refs-heldout").glob("*.elf")):
        command += ["--library", library]
    for program in sorted((work / "program" / name).glob("*.o")):
        command += ["--program", program]
    truth = run(command).stdout
    short = name.removeprefix("embedded-libs-")
    (REPO / "tests" / "fixtures" / "data" / f"eval-truth-embedded-{short}.json").write_text(truth)
    image = REPO / "tests" / "fixtures" / "firmware" / f"{name}.bin"
    shutil.copy(destination / f"{name}.bin", image)
    image.chmod(0o644)


# The dev split: cell -> (toolchain release, core, optimisation, libc, uses HAL). Every cell keeps GCC and changes
# what training has not seen: the GCC release (xPack 11.3, 12.2 and 13.2 never train), or, on a training toolchain
# (13.3), only the options and the kernel configuration. All build the dev program with the dev kernel
# configuration (dev-app/FreeRTOSConfig.h), unlike the two training ones and the fixture's.
DEV_CELLS = {
    f"dev-{tag}-{core}-{optimisation}": (release, core, optimisation, libc, core == "m4f")
    for release, tag in [("xpack-11.3.1-1.1", "gcc11.3"), ("12.2.rel1", "gcc12.2"), ("13.2.rel1", "gcc13.2")]
    for core, optimisation, libc in [("m4f", "Os", "nano"), ("m0", "O1", "full"), ("m3", "O2", "nano")]
}
DEV_CELLS.update({
    "dev-gcc13.3-m4f-O1": ("13.3.rel1", "m4f", "O1", "nano", True),
    "dev-gcc13.3-m0-Os": ("13.3.rel1", "m0", "Os", "full", False),
})
DEV_HAL_MODULES = ["", "_cortex", "_rcc", "_gpio", "_spi", "_i2c", "_adc", "_adc_ex", "_crc", "_dma", "_pwr"]


def build_firmware(work, toolchain, core, optimisation, libc, hal, app, output):
    """Links one FreeRTOS firmware from `app`'s main.c, startup.c, dev.ld and FreeRTOSConfig.h, as `fixture` links
    the fixtures. Returns copies of the program's own objects (main and startup), beside `output`."""
    build = work / "build" / output.stem
    if build.exists():
        shutil.rmtree(build)
    kernel = work / "src" / "freertos-V11.1.0"
    port = kernel / "portable" / "GCC" / FREERTOS_PORTS[core]
    sources = [app / "main.c", app / "startup.c"]
    sources += [kernel / file for file in FREERTOS_FILES] + port_sources(port)
    sources += [kernel / "portable" / "MemMang" / "heap_4.c"]
    flags = [*CORES[core], f"-{optimisation}", "-ffunction-sections", "-fdata-sections", "-g0"]
    flags += [f"-DEMBSIG_PRIO_BITS={3 if core == 'm0' else 4}", f"-DEMBSIG_PORT_OPTIMISED={0 if core == 'm0' else 1}"]
    includes = [app, kernel / "include", port]
    if hal:
        flags += ["-DSTM32F407xx", "-DUSE_HAL_DRIVER", "-DEMBSIG_HAL"]
        includes += [hal_configuration(work, build / "conf"), *hal_includes(work)]
        hal_source = work / "src" / "f4hal-v1.8.3" / "Src"
        sources += [hal_source / f"stm32f4xx_hal{module}.c" for module in DEV_HAL_MODULES]
        sources += [work / "src" / "cmsis-device-f4-v2.6.10" / "Source" / "Templates" / "system_stm32f4xx.c"]
    flags += [f"-I{path}" for path in includes]
    objects = compile_objects(toolchain, flags, sources, build / "obj")
    specs = ["--specs=nano.specs"] if libc == "nano" else []
    link = [toolchain.gcc, *CORES[core], *specs, "--specs=nosys.specs", "-nostartfiles", "-Wl,--gc-sections"]
    link += ["-Wl,--build-id=none", f"-Wl,-T,{app / 'dev.ld'}", "-Wl,-e,Reset_Handler", *objects, "-lm", "-o", output]
    run(link)
    program = output.parent / "program"
    program.mkdir(parents=True, exist_ok=True)
    kept = []
    for obj in objects[:2]:
        kept.append(program / obj.name)
        shutil.copy(obj, kept[-1])
    shutil.rmtree(build)
    return kept


def dev(work, evaluator, cells):
    """The dev split under WORK/dev/<cell>/: the symbolized firmware, its stripped twin and its libid truth (the
    functions the same toolchain's library references define, minus the dev program's objects). A dev
    toolchain's references are linked first, into WORK/refs-dev/<release>; the 13.3 cells use training's."""
    app = HERE / "dev-app"
    for name in cells:
        release, core, optimisation, libc, hal = DEV_CELLS[name]
        toolchain = Toolchain(work, release)
        if release in DEV_TOOLCHAINS:
            libraries = work / "refs-dev" / release
            if not libraries.exists():
                partial = libraries.with_name(release + ".partial")
                refs(work, [release], partial)
                partial.rename(libraries)
            libraries = sorted(libraries.glob("*.elf"))
        else:
            libraries = sorted((work / "refs").glob(f"*-gcc{toolchain.version}-*.elf"))
        if not libraries:
            raise RuntimeError(f"{name}: no library references for {release}")
        cell = work / "dev" / name
        if cell.exists():
            shutil.rmtree(cell)
        cell.mkdir(parents=True)
        elf = cell / f"{name}.elf"
        program = build_firmware(work, toolchain, core, optimisation, libc, hal, app, elf)
        stripped = cell / f"{name}.stripped.elf"
        run([evaluator, "strip", elf, stripped])
        command = [evaluator, "truth", elf, "--stripped", stripped]
        for library in libraries:
            command += ["--library", library]
        for obj in program:
            command += ["--program", obj]
        (cell / f"{name}.truth.json").write_text(run(command).stdout)
        print(f"{elf}: GCC {toolchain.version} {core} -{optimisation} newlib-{libc}", file=sys.stderr)


def negative_sources():
    """The negative libraries, pinned as the flywheel corpus pins them (tools/flywheel/corpus.json): name ->
    (url, sha256, (include directories, sources))."""
    corpus = json.loads((REPO / "tools" / "flywheel" / "corpus.json").read_text())
    wanted = {"zlib": "1.3.1", "lz4": "1.10.0", "cjson": "1.7.18", "inih": "r58", "tinyexpr": "1.1.1"}
    found = {}
    for library in corpus["libraries"]:
        version = wanted.get(library["name"].lower())
        for entry in library["versions"]:
            if entry["version"] == version:
                found[f"neg-{library['name'].lower()}-{version}"] = (
                    entry["url"], entry["sha256"], (library["include"], library["sources"]))
    if len(found) != len(wanted):
        raise RuntimeError(f"negative sources: found {sorted(found)} of {sorted(wanted)} in tools/flywheel/corpus.json")
    return found


# The negative libraries: the operand tier's tombstones, and the held-out gate (other libraries, another GCC
# release and other options): name -> (toolchain release, optimisation levels, libraries).
NEGATIVE_SETS = {
    "tombstones": ("13.2.rel1", ["Os", "O2"], ["lz4", "cjson", "tinyexpr"]),
    "gate": ("12.2.rel1", ["O1", "O3"], ["zlib", "inih"]),
}


def negatives(work, which, out):
    """Thumb references of one negative set (no embedded signature covers its libraries) for three cores, linked
    like the library references (stubs for the C library they call). Any name on them is false."""
    release, optimisations, libraries = NEGATIVE_SETS[which]
    out.mkdir(parents=True, exist_ok=True)
    toolchain = Toolchain(work, release)

    def build(root, flags, sources, output):
        objects = compile_objects(toolchain, flags, sources, work / "build" / output.stem)
        link_reference(toolchain, output, objects)
        shutil.rmtree(work / "build" / output.stem)

    tasks = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        for name, (_, _, (include, sources)) in negative_sources().items():
            if name.split("-")[1] not in libraries:
                continue
            root = work / "src" / name
            for core in ["m0", "m3", "m4f"]:
                for optimisation in optimisations:
                    flags = [*CORES[core], f"-{optimisation}", "-ffunction-sections", "-g0", "-w"]
                    flags += [f"-I{root / path}" for path in include]
                    output = out / f"{name}-gcc{toolchain.version}-{core}-{optimisation}.elf"
                    tasks.append(pool.submit(build, root, flags, [root / source for source in sources], output))
        for task in tasks:
            task.result()
    print(f"{len(tasks)} negative references in {out}", file=sys.stderr)


NEWLIB_VERSIONS = {"12.3.rel1": "4.3.0", "13.3.rel1": "4.4.0", "14.3.rel1": "4.5.0", "15.2.rel1": "4.5.0"}
GCC_VERSIONS = {"12.3.rel1": "12.3.1", "13.3.rel1": "13.3.1", "14.3.rel1": "14.3.1", "15.2.rel1": "15.2.1"}
RECIPE = ("tools/embedded-signatures/build.py {step}; hashed by crates/rampage-eval/examples/embedded_signatures.rs "
          "(scheme 3 over discovered extents, collision-safe union, exact fallbacks withheld)")


OPERAND_RECIPE = ("tools/embedded-signatures/build.py {step}; hashed by "
                  "crates/rampage-eval/examples/embedded_operands.rs (scheme 4: scheme 3 with Thumb load/store offsets "
                  "and stack adjustments masked; collision-safe union, the negative split as tombstones)")


def profiles(releases, operands=False):
    """The bundled index's build profiles: one per library and toolchain (`operands`: the operand tier's, whose
    kernels also include the hooks configuration)."""
    recipe = OPERAND_RECIPE if operands else RECIPE
    kernels = "the full, small and hooks" if operands else "the full and small"
    multilibs = "thumb v6-m/nofp, v7-m/nofp, v7e-m/nofp, v7e-m+fp/hard, v7e-m+dp/hard"
    rows = []
    for release in releases:
        gcc = GCC_VERSIONS[release]
        compiler = f"Arm GNU Toolchain {release} (GCC {gcc}), darwin-arm64 binary release"
        toolchain_url = ARM_URL.format(v=release)
        for library, version, license_, scope in [
            ("newlib-nano", NEWLIB_VERSIONS[release], "newlib (BSD-style; COPYING.NEWLIB)", "libc_nano.a"),
            ("newlib", NEWLIB_VERSIONS[release], "newlib (BSD-style; COPYING.NEWLIB)", "libc.a"),
            ("newlib-libm", NEWLIB_VERSIONS[release], "newlib (BSD-style; COPYING.NEWLIB)", "libm.a"),
            ("libgcc", gcc, "GPL-3.0-or-later WITH GCC-exception-3.1", "libgcc.a"),
        ]:
            rows.append({
                "id": f"{library}-{version}-gcc{gcc}-armv6m-armv7m",
                "library": library,
                "version": version,
                "target": f"arm-none-eabi {multilibs}",
                "compiler": compiler,
                "optimization": "prebuilt multilib archives as the toolchain ships them (build flags unrecorded)",
                "license": license_,
                "source": toolchain_url,
                "source_recipe": recipe.format(step=f"refs: whole-archive link of {scope} per multilib"),
                "archive_sha256": TOOLCHAINS[release],
                "archive_identity_unavailable": None,
            })
        for kernel in ["freertos-V11.1.0", "freertos-V10.6.2"]:
            url, digest = SOURCES[kernel]
            rows.append({
                "id": f"{kernel}-gcc{gcc}-cm0-cm3-cm4f",
                "library": "freertos-kernel",
                "version": kernel.split("-V")[1],
                "target": "arm-none-eabi cortex-m0 (ARM_CM0), cortex-m3 (ARM_CM3), cortex-m4 hard float (ARM_CM4F)",
                "compiler": compiler,
                "optimization": " ".join(f"-{level}" for level in OPTIMISATIONS),
                "license": "MIT",
                "source": url,
                "source_recipe": recipe.format(step=f"refs: kernel, port and heap_4 with {kernels} "
                                               "FreeRTOSConfig.h under tools/embedded-signatures"),
                "archive_sha256": digest,
                "archive_identity_unavailable": None,
            })
        url, digest = SOURCES["f4hal-v1.8.3"]
        rows.append({
            "id": f"stm32f4xx-hal-driver-1.8.3-gcc{gcc}-cm4f",
            "library": "stm32f4xx-hal-driver (HAL and LL, with cmsis-device-f4 2.6.10 system file, CMSIS 5.9.0 core)",
            "version": "1.8.3",
            "target": "arm-none-eabi cortex-m4 hard float, STM32F407xx, every HAL module enabled",
            "compiler": compiler,
            "optimization": " ".join(f"-{level}" for level in OPTIMISATIONS),
            "license": "BSD-3-Clause (HAL/LL); Apache-2.0 (cmsis-device-f4, CMSIS core)",
            "source": url,
            "source_recipe": recipe.format(step="refs: every Src/*.c except templates"),
            "archive_sha256": digest,
            "archive_identity_unavailable": None,
        })
    rows.append({
        "id": "compiler-rt-builtins-22.1.8-clang22.1.8-armv6m-armv7m",
        "library": "LLVM compiler-rt builtins",
        "version": "22.1.8",
        "target": "thumbv6m-none-eabi, thumbv7m-none-eabi, thumbv7em-none-eabi, thumbv7em-none-eabihf",
        "compiler": "Homebrew clang 22.1.8",
        "optimization": "-O2 -Os -O3",
        "license": "Apache-2.0 WITH LLVM-exception",
        "source": COMPILER_RT_URL,
        "source_recipe": recipe.format(step="compiler-rt: generic C builtins with the ARM assembly replacing them"),
        "archive_sha256": COMPILER_RT_SHA256,
        "archive_identity_unavailable": None,
    })
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["fetch", "refs", "compiler-rt", "fixture", "profiles", "dev", "negatives"])
    parser.add_argument("--dev", action="store_true", help="fetch: the dev split's toolchains and negative sources")
    parser.add_argument("--operands", action="store_true", help="profiles: the operand tier's index profiles")
    parser.add_argument("--gate", action="store_true", help="negatives: the held-out negative gate")
    parser.add_argument("--cell", action="append", help="dev: build only these cells (default: all)")
    parser.add_argument("--config", action="append", choices=["full", "small", "hooks"],
                        help="refs: only the FreeRTOS kernels in these configurations (hooks: the operand tier's and "
                        "call graph's extra references, into WORK/refs-hooks)")
    parser.add_argument("--work", type=Path, default=Path("/private/var/tmp/rampage-embsig-work"))
    parser.add_argument("--toolchain", action="append", help="toolchain release (refs: default the training set)")
    parser.add_argument("--clang", action="append", help="compiler-rt: clang executable (default: Homebrew llvm@22)")
    parser.add_argument("--output", type=Path, help="refs: default WORK/refs; fixture: default WORK/fixtures")
    parser.add_argument("--eval", type=Path, help="fixture: rampage-eval, to write the committed stripped ELFs, raw "
                        "images and truth into tests/fixtures; dev: rampage-eval (required)")
    arguments = parser.parse_args()
    work = arguments.work.resolve()
    if arguments.command == "fetch":
        fetch(work, arguments.dev)
    elif arguments.command == "dev":
        if not arguments.eval:
            parser.error("dev needs --eval PATH-TO-rampage-eval")
        dev(work, arguments.eval.resolve(), arguments.cell or list(DEV_CELLS))
    elif arguments.command == "negatives":
        which = "gate" if arguments.gate else "tombstones"
        default = work / ("negatives-gate" if arguments.gate else "negatives")
        negatives(work, which, arguments.output or default)
    elif arguments.command == "refs":
        default = work / ("refs-hooks" if arguments.config == ["hooks"] else "refs")
        refs(work, arguments.toolchain or TRAINING, arguments.output or default, arguments.config)
    elif arguments.command == "compiler-rt":
        clangs = arguments.clang or ["/opt/homebrew/opt/llvm@22/bin/clang"]
        compiler_rt_refs(work, clangs, arguments.output or work / "refs")
    elif arguments.command == "profiles":
        print(json.dumps(profiles(arguments.toolchain or TRAINING, arguments.operands), indent=2))
    else:
        destination = arguments.output or work / "fixtures"
        destination.mkdir(parents=True, exist_ok=True)
        fixture(work, (arguments.toolchain or [HELD_OUT])[0], destination, arguments.eval)


if __name__ == "__main__":
    main()
