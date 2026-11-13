# Contributing to rampage

rampage is an AI-first reverse-engineering tool, and its MCP server is the product. Bug reports, fixtures and
focused pull requests are welcome. For security problems, follow [SECURITY.md](SECURITY.md) instead of opening an
issue.

## Build and test

You need a Rust toolchain through rustup (`rust-toolchain.toml` pins 1.100.0, edition 2024), a native C/C++ compiler and
zlib development files for the embedded decompiler. See [Supported hosts](README.md#supported-hosts).

```sh
cargo build --locked -p rampage-cli -p rampage-worker
cargo nextest run --locked --workspace          # add --profile full before opening a pull request
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

- Use [cargo-nextest](https://nexte.st). Its default profile (`.config/nextest.toml`) skips the heaviest tests;
  `--profile full` runs everything.
- Each crate builds its integration tests into one binary: `tests/integration.rs` declares every other
  `tests/*.rs` file as a module, so a new test file needs a `mod` line there.
- [docs/development.md](docs/development.md) covers build profiles, cache cleanup, selecting tests by module path
  and keeping `target/` small.

## How a feature lands

A feature lands as an MCP tool (or an extension of one), following the execution rules in the
[parity roadmap](docs/plans/2026-10-16-ida-ghidra-parity-roadmap.md#execution-rules-apply-to-every-phase):

- **Bounded output.** Results stay within the documented size caps and page through large data with explicit
  cursors and totals. Never truncate silently; report omissions.
- **Tests.** An owned fixture that fails before the change and passes after, plus an MCP-level test.
- **Docs.** A few sentences in [docs/features.md](docs/features.md), [docs/mcp.md](docs/mcp.md) and the relevant
  reference doc: what the tool does and one "Limits" line.

The CLI and desktop UI share the same API; they are secondary clients. There is no scripting API.

## Fixtures

Test inputs are owned and built from committed sources: C/C++/assembly under `tests/fixtures/src` (or next to a
fixture's `build.sh`), compiled with `zig cc` or `clang` by the committed build scripts. Never commit third-party
or commercial binaries, bytes extracted from them, captured process memory or secrets. Only permissively licensed
inputs (Apache-2.0, MIT, BSD, zlib, public domain) belong in the repository.

## Pull requests

Keep a pull request to one focused change with an imperative commit subject. Run the four commands above and note
anything you could not run (for example, a test that needs macOS).

## License

rampage is licensed under [Apache-2.0](LICENSE). By contributing, you agree that your contributions are licensed
under the same terms (inbound = outbound, as in section 5 of the license), without additional terms or conditions.
