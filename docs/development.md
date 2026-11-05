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
`cargo nextest run --profile full` before committing; `cargo test` and CI ignore the file.

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
