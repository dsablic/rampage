# Build and validate without accumulating large caches

Use one toolchain, consistent compiler flags and one shared workspace `target` directory for routine development.
Parallel code review does not require per-agent builds or separate target directories. Coordinate build/test runs
instead of starting competing variants of the whole dependency graph.

## Build and check

```sh
cargo build --locked -p rampage-cli -p rampage-worker -p rampage-ui
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Build the CLI and worker before isolated CLI acceptance: `cargo test` alone may not publish the sibling worker.
The native dependency build can be expensive on a cold cache. Build-process concurrency can be limited with
`CARGO_BUILD_JOBS`; this reduces resource pressure, not the amount of code required by the workspace.

Development and test profiles disable debug information and incremental compilation. Debug assertions, overflow
checks and panic behavior retain their normal development/test settings. This reduces storage but sacrifices
debug-information backtraces and incremental rebuild speed. Controlled debug fixtures generate their own debug
information independently of these Rust profile settings. Release optimization settings are unchanged.

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
cargo test --locked --release --workspace --test darwin_narrow --test layout --test api --test smoke
cargo test --locked --release -p rampage-decompiler --lib
```

## Inspect and clean build output

```sh
du -sh target
cargo clean -p rampage-api
cargo clean
```

The package-specific command removes that package's generated artifacts; the final command removes the full
build cache. Neither changes source, fixtures or commits. Stop builds before cleanup; deleting a live target tree
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
