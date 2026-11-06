# Build and validate without accumulating large caches

Use one toolchain, consistent compiler flags and one shared workspace `target` directory for routine development.
Parallel code review does not require separate builds or target directories. Coordinate build/test runs
instead of starting competing variants of the whole dependency graph.

## Build and check

```sh
cargo build --locked -p rampage-cli -p rampage-worker -p rampage-ui
cargo nextest run --locked --workspace   # --profile full before committing; or: cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Build the CLI and worker before isolated CLI acceptance: `cargo test` alone may not publish the sibling worker.
The native dependency build can be expensive on a cold cache. Build-process concurrency can be limited with
`CARGO_BUILD_JOBS`; this reduces resource pressure, not the amount of code required by the workspace.

Development and test profiles disable debug information. Debug assertions, overflow checks and panic behavior retain
their normal development/test settings. This reduces storage but sacrifices debug-information backtraces. Controlled
debug fixtures generate their own debug information independently of these Rust profile settings. Incremental
compilation stays on (cargo's default; it applies to workspace crates only): after a one-line edit it rebuilds the
`rampage-api` unit-test target in about 13 s instead of 95 s, for several gigabytes of caches under
`target/debug/incremental`. Release optimization settings are unchanged.

Third-party dependencies and `rampage-decompiler` (including its embedded Ghidra C++) build at `opt-level = 2` in
the development/test profiles; workspace crates stay unoptimized so edits rebuild quickly. Tests decompile heavily,
so this cut workspace test execution roughly threefold; it costs a one-time dependency rebuild.

Prefer [`cargo-nextest`](https://nexte.st) (`brew install cargo-nextest`) for local runs. `cargo test` executes the
test binaries one at a time, and the `rampage-api` library binary alone took about 400 s; nextest runs every test
in its own process across all binaries in parallel. Measured on a 10-core M1 Max (2026-10-21), workspace test
execution was about 734 s with `cargo test` at `opt-level = 0`, 170 s with nextest, and 92 s with nextest plus the
optimized dependencies.

The default nextest profile in `.config/nextest.toml` skips 23 of the heaviest tests (roster matrices, type
propagation, Go decompilation), which take about a third of the suite's CPU time. Run everything with
`cargo nextest run --profile full` before committing; `cargo test` ignores the file. Both CI workspace jobs run the
default nextest profile; a manual run with `full=true` runs everything (see [Continuous integration](#continuous-integration)).

### One integration-test binary per crate

Cargo builds every `tests/*.rs` file as its own executable, and each statically links the whole dependency graph
(100-250 MB apiece). Crates with several test files therefore set `autotests = false` and declare one
`[[test]] name = "integration"` whose `tests/integration.rs` includes each file as a module (`mod archive;`). A new
test file needs its `mod` line there; `rampage-api`'s `test_targets` test fails until it has one. Shared helpers that
several files use are declared once in `integration.rs` and imported with `use crate::...`, because Clippy rejects a
file loaded as a module twice. A file that must stay a crate root (such as `rampage-analysis/tests/classes.rs`, which
compiles a `src` file with `crate::` paths) keeps its own `[[test]]` entry.

Select a former test target by its module path:

```sh
cargo nextest run -p rampage-api -E 'test(/^pdb::/)'
cargo test -p rampage-api --test integration -- pdb:: --include-ignored
```

libtest filters are substring matches, so end a module filter with `::`. Several filters go after `--`
(`-- darwin_narrow:: layout::`) because `cargo test` accepts only one before it. A test that re-runs its own binary
with `--exact` must pass the full module path (see `rampage-decompiler/tests/initialization.rs`).

On macOS, the first launch of each newly linked executable waits about 1.5 s for a security assessment, which nextest
pays while listing tests after every rebuild. Adding the terminal application under System Settings › Privacy &
Security › Developer Tools exempts processes it starts.

If debugging Rust code requires symbols, temporarily override `CARGO_PROFILE_DEV_DEBUG=2` or
`CARGO_PROFILE_TEST_DEBUG=2`. That produces a different build variant; return to the normal configuration after
the debugging session and clean obsolete artifacts when no build is running. Merely stripping final executables
does not remove intermediate objects and incremental caches.

## Scope release validation

For routine increments, use the full debug workspace suite and focused release checks for affected paths. Release
uses ThinLTO and one codegen unit: changing the embedded native engine can trigger optimized linking for many
separate integration-test executables. A full workspace release rebuild is an explicit broad acceptance run,
not a prerequisite for every edit. Give release checks an explicit elapsed-time budget; report interrupted or
unrun broad gates as incomplete rather than inferring success from a focused pass. Keep optimization settings
unchanged unless a profile change is deliberately requested.

For example, focused ABI/layout release checks can select existing integration targets without rebuilding unrelated
UI and CLI test executables:

```sh
cargo test --locked --release -p rampage-decompiler -p rampage-api -p rampage-worker --test integration -- \
  darwin_narrow:: layout:: api:: smoke::
cargo test --locked --release -p rampage-decompiler --lib
```

## Continuous integration

`.github/workflows/ci.yml` has four jobs:

| Job | Runner | What it runs |
| --- | --- | --- |
| `hygiene` | Ubuntu 24.04 | `cargo fmt --check`, the Python tool regressions, `tools/test_install.sh`, Gitleaks over HEAD and history |
| `clippy` | Ubuntu 24.04 | warnings-denied workspace Clippy |
| `linux` | Ubuntu 24.04 | CLI and worker build, `cargo nextest run --workspace`, then the owned x86-64 ELF layout, DWARF/C++ layout and component oracles |
| `macos` | macOS 15 (ARM64) | Clippy, the supervised decompiler corpus, `cargo nextest run --workspace` (including the Metal UI snapshots and the rampage-eval accuracy gate), and the macOS-only module-linkage, plugin-triage, DWARF, C++ and compiled-fixture gates |

`clippy`, `linux` and `macos` wait for `hygiene`, so a formatting or secret-scan failure costs seconds, not a build.
All Rust jobs use [sccache](https://github.com/mozilla/sccache) with the GitHub Actions cache. cc-rs adopts the
sccache `RUSTC_WRAPPER` as its C/C++ wrapper, so the embedded Ghidra decompiler's 92 C++ files are cached as well;
each job prints `sccache --show-stats` at the end.

**Triggers.** Manual runs (`workflow_dispatch`) and `v*` tags work now. `push` to `main` and `pull_request` are
declared, but every job checks `github.event.repository.private == false` for those events, so they start running
only once the repository is public (macOS minutes on a private repository cost ten times Linux minutes). Making the
repository public needs no workflow change.

**Manual runs.** Every input defaults to off:

```sh
gh workflow run ci.yml --ref BRANCH                          # Linux jobs only
gh workflow run ci.yml --ref BRANCH -f macos=true            # also macOS
gh workflow run ci.yml --ref BRANCH -f full=true             # nextest `full` profile (all 23 heavy tests)
gh workflow run ci.yml --ref BRANCH -f live=true             # also the live QEMU debugger suite on Linux
gh workflow run ci.yml --ref BRANCH -f release_dry_run=true  # also build and smoke-test release archives
gh run watch RUN_ID; gh run view RUN_ID --log-failed
```

The `full` profile and the live suites never run on push or pull requests. The other live suites need hardware CI
does not have; run them locally:

```sh
RAMPAGE_QEMU_LIVE=1 cargo nextest run -p rampage-api --run-ignored only -E 'test(/^debug_qemu::/)'
RAMPAGE_DEBUGSERVER_LIVE=1 cargo nextest run -p rampage-api --run-ignored only -E 'test(/^debug_debugserver_live::/)'
RAMPAGE_WINDOWS_LIVE=1 cargo nextest run -p rampage-api --run-ignored only -E 'test(/^debug_windows_live::/)'
RAMPAGE_LLDB_LIVE=1 python3 -m pytest tools/test_lldb_live.py
```

Manual runs on one ref share a concurrency group, so a new dispatch cancels the previous run on that ref,
including a release dry run started through it.

Measured on GitHub's 2-vCPU private-repository Ubuntu runners (2026-11-06; single samples, and test execution
varied by about 30% between runs of the same commit):

| Linux | Before (separate jobs, no cache) | After, cold cache | After, warm cache |
| --- | --- | --- | --- |
| Workflow wall clock | 48.1 min | 65.8 min | 26.5 min |
| Clippy | 12.1 min (serial, before the build) | 17.2 min (parallel job) | 7.3 min (parallel job) |
| CLI and worker build | 12.2 min | 19.1 min | 4.5 min |
| Test build | 15.8 min | 25.9 min | 8.4 min |
| Test execution (3,908 tests) | 7.4 min | 9.3 min | 9.7 min |
| Layout and component oracles | 12.5 + 9.4 min in two extra jobs, each rebuilding | 10.3 min | 2.4 min |

A cold cache costs extra time because sccache uploads every object; the decompiler's C/C++ objects and dependency
crates then hit at 100%. Workspace test executables still compile and link on every run (sccache cannot cache
binaries), which is most of the remaining build time.

## Release procedure

`.github/workflows/release.yml` builds `rampage`, `rampage-worker` and `rampage-ui` for `aarch64-apple-darwin` and
`x86_64-unknown-linux-gnu` with ThinLTO and one codegen unit (set in the workflow's environment, so a local profile
edit cannot change shipped binaries). `tools/ci/package-release.sh` packages each target as
`rampage-VERSION-TARGET.tar.gz`: one top-level directory holding `bin/` (the programs, side by side, because the CLI
starts the worker from its own directory), `LICENSE`, `NOTICE`, `THIRD-PARTY-NOTICES` and a README stub, plus a
`.sha256` file. `tools/ci/check-release-archive.sh` verifies the checksum and layout, then runs `rampage --version`,
`rampage server serve --help` and `rampage-ui --version` from the unpacked archive.

- A pushed `v*` tag that matches the workspace version builds every target and creates a **draft** release with
  the archives, their `.sha256` files and a combined `SHA256SUMS`. Nothing is published automatically.
- `gh workflow run release.yml --ref BRANCH` (or CI's `release_dry_run` input) is a dry run: it builds, packages and
  smoke-tests the archives and uploads them as workflow artefacts for 14 days, and never creates a release. Pass
  `-f macos=false` to build Linux only. `gh workflow run release.yml --ref vX.Y.Z -f dry_run=false` rebuilds an
  existing tag and attaches a draft to it; a non-dry run on a ref that is not a tag stops before building.
- `release.yml` must be on the default branch before `gh workflow run release.yml` works; until then, use CI's
  `release_dry_run` input.

Install a downloaded archive with the installer, which verifies the checksum when the `.sha256` file sits next to
the archive and then publishes the programs through the same guarded path as a source install:

```sh
tools/install.sh --archive rampage-0.1.0-x86_64-unknown-linux-gnu.tar.gz [ROOT] [--ui]
tools/install.sh [ROOT] [--ui] [--plugins]   # build from this checkout instead
tools/install.sh [ROOT] --uninstall          # remove rampage, rampage-worker, rampage-ui, rampage-plugin-worker
```

`ROOT` defaults to `~/.local` (programs go to `ROOT/bin`), and the script works from any directory. A source
install builds with the release profile using Cargo's default job count (`CARGO_BUILD_JOBS` overrides it); a cold
build of the CLI, worker and UI took 23 minutes on a 2-vCPU Linux CI runner. After a successful install the
private staging directory is removed; after a failure it is kept in `ROOT/bin/.rampage-install.*` for inspection.

Release archives do not include `rampage-plugin-worker`; install it from source with `--plugins`. Without the
installer, copy the archive's `bin/` contents into one directory on `PATH`.

### Release checklist

1. On `main`, bump `[workspace.package] version` in `Cargo.toml`, run `cargo update --workspace`, and commit with a
   short changelog entry.
2. Regenerate `THIRD-PARTY-NOTICES` with `python3 -I tools/third-party-notices.py` and commit any change.
3. Run the local gates: `cargo fmt --all --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`
   and `cargo nextest run --locked --workspace --profile full`.
4. Run `gh workflow run ci.yml --ref main -f macos=true -f full=true` and wait for it to pass.
5. Run a release dry run (`gh workflow run release.yml --ref main`), download an archive for your host with
   `gh run download RUN_ID`, and run `tools/install.sh --archive …` into a scratch root.
6. Tag and push: `git tag -s vX.Y.Z -m "rampage X.Y.Z" && git push origin vX.Y.Z`. The tag must equal
   `v` plus the workspace version, or the workflow stops.
7. Review the draft release: archive names, checksums, generated notes. Edit the notes, then publish it by hand.

## Inspect and clean build output

```sh
du -sh target
python3 -I tools/prune-target.py --dry-run
python3 -I tools/prune-target.py
cargo clean -p rampage-api
cargo clean
```

Cargo names each executable `<name>-<hash>` and starts a new hash whenever the build configuration changes
(toolchain, profile, dependency versions, `-p` feature unification) without deleting the old copy; on 2026-10-23
superseded test executables were 52 GB of a 69 GB target directory. `tools/prune-target.py` keeps the three newest
executables per target, deletes executables and incremental caches untouched for a week, and refuses to run while
a build holds the target lock or a test binary from the target directory is running. Cargo relinks anything it
deleted that is still current. The package-specific `cargo clean` removes that package's generated artifacts; the
final command removes the full build cache. Neither changes source, fixtures or commits. Stop builds before cleanup; deleting a live target tree
can cause missing-crate/linker failures and competing builds can recreate files during deletion.

Cargo's automatic global download-cache cleanup does not impose an age or size limit on workspace build output.
Changing toolchains, features, compiler flags, profiles or target directories can accumulate separate artifacts.
These defaults reduce growth; they are not a hard disk quota. See
[Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html) and
[Cargo cache configuration](https://doc.rust-lang.org/cargo/reference/config.html#cache).

## Retire completed worktrees

List worktrees with `git worktree list --porcelain`. Before removing a completed checkout:

1. Confirm its commit has been integrated into the intended branch.
2. Check tracked, untracked **and ignored** files; ignored annotations or investigation data may be user work.
3. Confirm no process is using it. A lock is not permission to force removal; investigate its owner.
4. Remove the verified completed checkout with `git worktree remove PATH`.

Removing a clean, integrated worktree also removes its local build cache but does not delete branch references or
commits. Leave a dirty, unintegrated or active checkout intact. Creating worktrees for parallel edits should include
their retirement in the same task, rather than leaving independent target directories behind.
