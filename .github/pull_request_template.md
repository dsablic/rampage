## What and why

<!-- One focused change. Link the issue if there is one. -->

## Checklist

- [ ] `cargo nextest run --locked --workspace --profile full`
- [ ] `cargo clippy --locked --workspace --all-targets -- -D warnings` and `cargo fmt --all --check`
- [ ] New behaviour has an owned fixture built from committed sources and an MCP-level test
- [ ] MCP output stays bounded; `docs/features.md`, `docs/mcp.md` or the relevant reference doc is updated
- [ ] No third-party binaries, extracted bytes, captures or secrets are committed

<!-- Note anything you could not run, such as macOS-only tests. -->
