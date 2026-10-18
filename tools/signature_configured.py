"""Pinned OpenSSL/curl library-only builds; the parent owns extraction and execution."""

from __future__ import annotations

import hashlib
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

PINS = {
    "openssl-3.0.15": "23c666d0edf20f14249b3d8f0368acaee9ab585b09e1de82107c66e1f3ec9533",
    "curl-8.10.1": "d15ebab765d793e2e96db090f0e172d127859d78ca6f6391d7eafecfd894bbc0",
}
TARGETS = {
    "x86_64-linux-musl": ("linux-x86_64", "x86_64-unknown-linux-musl"),
    "aarch64-linux-musl": ("linux-aarch64", "aarch64-unknown-linux-musl"),
}
CLEAN_ENVIRONMENT_KEYS = frozenset(
    (
        "PATH",
        "HOME",
        "TMPDIR",
        "LC_ALL",
        "TZ",
        "SOURCE_DATE_EPOCH",
        "ZIG_GLOBAL_CACHE_DIR",
        "ZIG_LOCAL_CACHE_DIR",
        "CONFIG_SITE",
        "CC",
        "AR",
        "RANLIB",
        "CFLAGS",
        "CPPFLAGS",
        "LDFLAGS",
        "LIBS",
        "MAKEFLAGS",
        "MFLAGS",
        "PKG_CONFIG",
        "PKG_CONFIG_LIBDIR",
        "PKG_CONFIG_PATH",
        "PERL",
        "CONFIG_SHELL",
    )
)
OPENSSL_OPTIONS = (
    "no-shared",
    "no-tests",
    "no-asm",
    "no-threads",
    "no-async",
    "no-dso",
    "no-engine",
    "no-module",
    "no-legacy",
    "no-zlib",
    "no-comp",
    "no-autoload-config",
    "no-ui-console",
    "no-secure-memory",
    "no-ktls",
    "no-external-tests",
    "no-buildtest-c++",
    "no-makedepend",
    "no-filenames",
)
CURL_OPTIONS = (
    "--disable-shared",
    "--enable-static",
    "--disable-dependency-tracking",
    "--disable-silent-rules",
    "--disable-symbol-hiding",
    "--disable-debug",
    "--disable-warnings",
    "--disable-werror",
    "--without-ssl",
    "--without-zlib",
    "--without-brotli",
    "--without-zstd",
    "--without-libpsl",
    "--without-libidn2",
    "--without-libssh2",
    "--without-libssh",
    "--without-wolfssh",
    "--without-librtmp",
    "--without-nghttp2",
    "--without-nghttp3",
    "--without-ngtcp2",
    "--without-quiche",
    "--without-hyper",
    "--without-gssapi",
    "--without-libgsasl",
    "--without-libuv",
    "--disable-ares",
    "--disable-threaded-resolver",
    "--disable-pthreads",
    "--disable-rt",
    "--enable-http",
    "--disable-ftp",
    "--disable-file",
    "--disable-ldap",
    "--disable-ldaps",
    "--disable-rtsp",
    "--disable-proxy",
    "--disable-dict",
    "--disable-telnet",
    "--disable-tftp",
    "--disable-pop3",
    "--disable-imap",
    "--disable-smb",
    "--disable-smtp",
    "--disable-gopher",
    "--disable-mqtt",
    "--disable-manual",
    "--disable-docs",
    "--disable-libcurl-option",
    "--disable-kerberos-auth",
    "--disable-negotiate-auth",
    "--disable-ntlm",
    "--disable-tls-srp",
    "--disable-doh",
    "--disable-netrc",
    "--disable-alt-svc",
    "--disable-hsts",
    "--disable-websockets",
    "--disable-ech",
    "--disable-httpsrr",
    "--without-ca-bundle",
    "--without-ca-path",
    "--without-ca-embed",
    "--without-ca-fallback",
)


class ConfiguredBuildError(Exception):
    """A configured profile cannot satisfy its explicit producer contract."""


class RunCommand(Protocol):
    def __call__(
        self,
        argv: list[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        clean_environment: bool,
    ) -> str:
        """Record argv, cwd, environment, stdout/stderr and require exit status zero."""
        ...


@dataclass(frozen=True)
class ConfiguredContext:
    """Parent supplies a fresh extracted source tree, resolved host tools and recorder.

    source is the writable per-slice copy from the parent's bounded extractor.
    verified_archive_sha256 comes from hashing the entire selected archive before
    extraction; source_class must be public-source-archive. No download is done here.
    run must honor clean_environment=True by using only the fixed allowlist, not
    merging inherited variables, and record that policy plus the actual clean
    environment. The parent supplies the isolated HOME/cache/TMPDIR environment.
    build_triplet is the actual operator host's config.guess triplet; it must differ
    from the target, even on native Linux, or curl is refused before configure.
    jobs must fit the parent's central job budget. No target executable is run.
    """

    library: str
    target: str
    optimization: str
    source: Path
    directory: Path
    zig: Path
    make: Path
    perl: Path
    shell: Path
    build_triplet: str
    verified_archive_sha256: str
    source_class: str
    environment: Mapping[str, str]
    run: RunCommand
    jobs: int = 1


@dataclass(frozen=True)
class ConfiguredBuild:
    archives: tuple[Path, ...]
    objects: tuple[Path, ...]
    include_directories: tuple[Path, ...]
    link_flags: tuple[str, ...]
    provenance: dict[str, Any]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_wrapper(path: Path, executable: Path, arguments: tuple[str, ...]) -> None:
    command = shlex.join([str(executable), *arguments])
    with path.open("x", encoding="utf-8") as stream:
        stream.write(f'#!/bin/sh\nexec {command} "$@"\n')
    path.chmod(0o755)


def effective_make_flags(
    path: Path, library: str, optimization: str, cflags: str
) -> dict[str, Any]:
    """Expand only retained make variable references in the selected compiler flag expressions."""
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
        raise ConfiguredBuildError(
            f"missing, linked or oversized generated Makefile: {path}"
        )
    text = path.read_text(encoding="utf-8").replace("\\\n", " ")
    variables: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([A-Za-z_][A-Za-z_0-9]*)\s*=\s*(.*)", line)
        if match:
            variables[match[1]] = match[2]
    required = (
        ("CFLAGS", "CPPFLAGS", "LIB_CFLAGS", "LIB_CPPFLAGS")
        if library.startswith("openssl")
        else (
            "CFLAGS",
            "CPPFLAGS",
            "libcurl_la_CFLAGS",
            "libcurl_la_CPPFLAGS",
            "DEFS",
            "DEFAULT_INCLUDES",
        )
    )
    if any(name not in variables for name in required):
        raise ConfiguredBuildError(
            f"generated Makefile lacks the fixed profile flag variables: {path}"
        )
    recorded = {
        name: variables.get(name, "")
        for name in (
            "CFLAGS",
            "CPPFLAGS",
            "CNF_CFLAGS",
            "CNF_CPPFLAGS",
            "LIB_CFLAGS",
            "LIB_CPPFLAGS",
            "AM_CFLAGS",
            "AM_CPPFLAGS",
            "libcurl_la_CFLAGS",
            "libcurl_la_CPPFLAGS",
            "DEFS",
            "DEFAULT_INCLUDES",
            "INCLUDES",
        )
    }
    variables["CFLAGS"] = cflags
    undefined_variables: set[str] = set()

    def expand(value: str, depth: int = 0) -> str:
        if depth > 32 or len(value) > 256 * 1024:
            raise ConfiguredBuildError(
                "generated Makefile flag expansion exceeds bound"
            )

        def replace(match: re.Match[str]) -> str:
            name = match[1] or match[2]
            if name not in variables:
                undefined_variables.add(name)
                return ""
            return expand(variables[name], depth + 1)

        expanded = re.sub(
            r"\$\(([A-Za-z_][A-Za-z_0-9]*)\)|\$\{([A-Za-z_][A-Za-z_0-9]*)\}",
            replace,
            value,
        )
        if "$" in expanded:
            raise ConfiguredBuildError("unsupported generated Makefile flag expression")
        return expanded

    if library.startswith("openssl"):
        effective_cflags = expand(variables["LIB_CFLAGS"])
        effective_cppflags = expand(variables["LIB_CPPFLAGS"])
        ordered_flags = f"{effective_cflags} {effective_cppflags}"
    else:
        effective_cflags = expand(
            f"{variables['libcurl_la_CFLAGS']} {variables['CFLAGS']}"
        )
        effective_cppflags = expand(
            f"{variables['DEFS']} {variables['DEFAULT_INCLUDES']} {variables.get('INCLUDES', '')} "
            f"{variables['libcurl_la_CPPFLAGS']} {variables['CPPFLAGS']}"
        )
        ordered_flags = f"{effective_cppflags} {effective_cflags}"
    optimizations = [
        flag
        for flag in shlex.split(ordered_flags)
        if re.fullmatch(r"-O(?:[0-9]+|s|z|g|fast)", flag)
    ]
    if not optimizations or optimizations[-1] != f"-{optimization}":
        raise ConfiguredBuildError(
            f"effective library flags do not end in requested -{optimization}: {optimizations}"
        )
    return {
        "makefile": str(path),
        "makefile_sha256": _sha256(path),
        "configured_variables": recorded,
        "make_overrides": {"CFLAGS": cflags},
        "effective_cflags": effective_cflags,
        "effective_cppflags": effective_cppflags,
        "last_optimization": optimizations[-1],
        "basis": "Fixed profile make compiler expression with explicit command-line CFLAGS override",
        "undefined_make_variables_expanded_empty": sorted(undefined_variables),
        "scope": "Common library flags; per-object -I/-D operands remain in recorded verbose make stdout",
    }


def _validate_context(context: ConfiguredContext) -> None:
    if context.library not in PINS or context.target not in TARGETS:
        raise ConfiguredBuildError(
            "configured profiles support only pinned OpenSSL/curl on Linux x64/A64"
        )
    if context.optimization not in ("O1", "O2") or context.jobs not in (1, 2):
        raise ConfiguredBuildError(
            "configured profiles require O1/O2 and one or two centrally budgeted jobs"
        )
    if (
        context.source_class != "public-source-archive"
        or context.verified_archive_sha256 != PINS[context.library]
    ):
        raise ConfiguredBuildError(
            "whole public source archive must be SHA-256 verified before host scripts run"
        )
    for path in (
        context.source,
        context.directory,
        context.zig,
        context.make,
        context.perl,
        context.shell,
    ):
        if not path.is_absolute() or not path.exists():
            raise ConfiguredBuildError(
                f"parent must supply an existing absolute path: {path}"
            )
    if context.library.startswith("curl"):
        host = TARGETS[context.target][1]
        if not re.fullmatch(
            r"[A-Za-z0-9_]+(?:-[A-Za-z0-9_.]+){2,}", context.build_triplet
        ):
            raise ConfiguredBuildError(
                "curl requires an explicit actual host build triplet"
            )
        if context.build_triplet == host:
            raise ConfiguredBuildError(
                "equal build/host triplets would permit target configure probes"
            )


def extract_owned_objects(
    context: ConfiguredContext, archive: Path, destination: Path, env: Mapping[str, str]
) -> tuple[Path, ...]:
    """List a known output with host Zig ar, reject unsafe/duplicate names, then extract."""
    if (
        archive.is_symlink()
        or not archive.is_file()
        or archive.stat().st_size > 256 * 1024 * 1024
    ):
        raise ConfiguredBuildError(
            f"missing, linked or oversized configured archive: {archive}"
        )
    with archive.open("rb") as stream:
        if stream.read(8) != b"!<arch>\n":
            raise ConfiguredBuildError(
                f"only regular, non-thin ar output is supported: {archive}"
            )
    listing = context.run(
        [str(context.zig), "ar", "t", str(archive)],
        cwd=context.directory,
        env=env,
        clean_environment=True,
    )
    if len(listing) > 4 * 1024 * 1024:
        raise ConfiguredBuildError("archive member listing exceeds bound")
    members = listing.splitlines()
    if not members or len(members) > 20000 or len(members) != len(set(members)):
        raise ConfiguredBuildError(
            "archive object ownership requires nonempty, bounded, unique members"
        )
    if any(
        not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,239}\.o", name)
        for name in members
    ):
        raise ConfiguredBuildError(
            "archive members must be simple object basenames without traversal"
        )
    destination.mkdir()
    context.run(
        [str(context.zig), "ar", "x", str(archive)],
        cwd=destination,
        env=env,
        clean_environment=True,
    )
    objects = tuple(destination / name for name in members)
    if {path.name for path in destination.iterdir()} != set(members):
        raise ConfiguredBuildError(
            "archive extraction differs from the retained ownership list"
        )
    if any(path.is_symlink() or not path.is_file() for path in objects):
        raise ConfiguredBuildError(
            "owned archive members must extract as regular object files"
        )
    if sum(path.stat().st_size for path in objects) > 256 * 1024 * 1024:
        raise ConfiguredBuildError("extracted object bytes exceed bound")
    return objects


def build_configured_profile(context: ConfiguredContext) -> ConfiguredBuild:
    """Build only pinned static libraries and return regular .o ownership inputs.

    Parent registration: use this instead of its explicit-source compilation loop;
    use archives inside one --whole-archive group (GC disabled), includes for both
    owned harnesses, link_flags after that group, and objects for builder --object.
    Keep the parent's existing inspection/strip/truth/report gate unchanged.
    """
    _validate_context(context)
    source, directory = context.source, context.directory
    wrapper_directory = directory / "configured-tools"
    wrapper_directory.mkdir()
    wrappers = {name: wrapper_directory / name for name in ("cc", "ar", "ranlib")}
    flags = (
        f"-{context.optimization}",
        "-g0",
        "-fno-lto",
        f"-ffile-prefix-map={directory}=.",
        f"-fdebug-prefix-map={directory}=.",
    )
    _write_wrapper(
        wrappers["cc"], context.zig, ("cc", "-target", context.target, *flags)
    )
    _write_wrapper(wrappers["ar"], context.zig, ("ar",))
    _write_wrapper(wrappers["ranlib"], context.zig, ("ranlib",))
    env = {
        key: value
        for key, value in context.environment.items()
        if key in CLEAN_ENVIRONMENT_KEYS
    }
    home = directory / "configured-home"
    home.mkdir(exist_ok=True)
    env.update(
        HOME=str(home),
        SOURCE_DATE_EPOCH="0",
        LC_ALL="C",
        TZ="UTC",
        CONFIG_SITE="/dev/null",
        CC=shlex.quote(str(wrappers["cc"])),
        AR=shlex.quote(str(wrappers["ar"])),
        RANLIB=shlex.quote(str(wrappers["ranlib"])),
        CFLAGS=shlex.join(list(flags)),
        CPPFLAGS="",
        LDFLAGS="",
        LIBS="",
        MAKEFLAGS="",
        MFLAGS="",
        PKG_CONFIG="false",
        PKG_CONFIG_LIBDIR="",
        PKG_CONFIG_PATH="",
        PERL=str(context.perl),
        CONFIG_SHELL=str(context.shell),
    )
    cflags_override = f"CFLAGS={env['CFLAGS']}"
    tools: dict[str, Any] = {}
    for name, path, version_args in (
        ("zig", context.zig, ["version"]),
        ("make", context.make, ["--version"]),
        ("perl", context.perl, ["-v"]),
        (
            "shell",
            context.shell,
            ["-c", "printf '%s\\n' \"${BASH_VERSION:-version-unreported}\""],
        ),
    ):
        version = context.run(
            [str(path), *version_args], cwd=directory, env=env, clean_environment=True
        )
        if name == "zig" and version.strip() != "0.17.0":
            raise ConfiguredBuildError(
                f"exact Zig 0.17.0 required, found {version.strip()!r}"
            )
        tools[name] = {
            "path": str(path),
            "sha256": _sha256(path),
            "version_output": version,
        }
    script_hashes = {
        str(path.relative_to(source)): _sha256(path)
        for path in sorted(source.rglob("*"))
        if path.is_file()
        and (
            path.suffix in (".pl", ".pm", ".tmpl", ".conf", ".sh")
            or path.name
            in ("Configure", "configure", "build.info", "config.guess", "config.sub")
            or path.name.startswith("Makefile")
        )
    }
    openssl_target, curl_host = TARGETS[context.target]
    if context.library == "openssl-3.0.15":
        options = list(OPENSSL_OPTIONS)
        configure_argv = [
            str(context.perl),
            str(source / "Configure"),
            openssl_target,
            *options,
        ]
        context.run(configure_argv, cwd=source, env=env, clean_environment=True)
        effective_flags = effective_make_flags(
            source / "Makefile", context.library, context.optimization, env["CFLAGS"]
        )
        context.run(
            [str(context.make), "-j1", cflags_override, "build_generated"],
            cwd=source,
            env=env,
            clean_environment=True,
        )
        context.run(
            [
                str(context.make),
                f"-j{context.jobs}",
                cflags_override,
                "libcrypto.a",
                "libssl.a",
            ],
            cwd=source,
            env=env,
            clean_environment=True,
        )
        archives = (source / "libssl.a", source / "libcrypto.a")
        includes = (source / "include",)
        link_flags = ("-lm",)
        generated = ("Makefile", "configdata.pm", "include/openssl/configuration.h")
        execution_basis = "Explicit OpenSSL Configure target; no runtime feature probes; library-only make goals"
    else:
        options = [
            f"--build={context.build_triplet}",
            f"--host={curl_host}",
            *CURL_OPTIONS,
        ]
        configure_argv = [str(context.shell), str(source / "configure"), *options]
        context.run(configure_argv, cwd=source, env=env, clean_environment=True)
        effective_flags = effective_make_flags(
            source / "lib/Makefile",
            context.library,
            context.optimization,
            env["CFLAGS"],
        )
        context.run(
            [
                str(context.make),
                "-C",
                "lib",
                f"-j{context.jobs}",
                "V=1",
                cflags_override,
                "libcurl.la",
            ],
            cwd=source,
            env=env,
            clean_environment=True,
        )
        archives = (source / "lib/.libs/libcurl.a",)
        includes = (source / "include",)
        link_flags = ()
        generated = (
            "Makefile",
            "lib/Makefile",
            "lib/curl_config.h",
            "config.log",
            "config.status",
            "libtool",
        )
        execution_basis = "Distinct explicit --build/--host forces cross_compiling=yes before compiler execution check"
    if _sha256(Path(effective_flags["makefile"])) != effective_flags["makefile_sha256"]:
        raise ConfiguredBuildError(
            "generated library Makefile changed after effective flag review"
        )
    objects: list[Path] = []
    for index, archive in enumerate(archives):
        objects.extend(
            extract_owned_objects(context, archive, directory / f"owned-{index}", env)
        )
    provenance: dict[str, Any] = {
        "driver_sha256": _sha256(Path(__file__)),
        "archive_sha256": context.verified_archive_sha256,
        "source_class": context.source_class,
        "env_policy": "configured-clean-allowlist-v1",
        "tools": tools,
        "host_script_sha256": script_hashes,
        "configure_argv": configure_argv,
        "options": options,
        "effective_library_flags": effective_flags,
        "compiler_wrapper": {
            "path": str(wrappers["cc"]),
            "sha256": _sha256(wrappers["cc"]),
        },
        "wrapper_interpreter": {"path": "/bin/sh", "sha256": _sha256(Path("/bin/sh"))},
        "wrapper_sha256": {name: _sha256(path) for name, path in wrappers.items()},
        "generated_configuration_sha256": {
            name: _sha256(source / name) for name in generated
        },
        "archives": {str(path): _sha256(path) for path in archives},
        "object_ownership": [
            {"path": str(path), "sha256": _sha256(path)} for path in objects
        ],
        "target_executed": False,
        "target_execution_basis": execution_basis,
        "ownership_scope": "Parent public-strong ELF function gate only; local/hidden/weak functions excluded",
        "limitations": "Configured reduced profile, not full upstream feature coverage; no target runtime validation",
    }
    return ConfiguredBuild(archives, tuple(objects), includes, link_flags, provenance)
