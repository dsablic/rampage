# REA formats and ledger wave

Part of the [accuracy benchmarks](../benchmarks.md).

## REA formats and ledger wave (2026-10-29)

The `formats` tools (`build_info`, `pe_resources`, `pe_load_config`, `pyinstaller_archive`, `wasm_module`) and the
findings ledger have no scorecard measurement. Their acceptance is API, CLI and MCP tests on owned fixtures
(`tests/fixtures/build-buildinfo.sh`, `build-formats.sh`, `build-pe-metadata.sh`): the `build_info`, `pe_metadata`,
`wasm_pyinstaller` and `findings` integration-test modules of `rampage-api` and `rampage-mcp`, plus CLI tests. See
[toolchain build info](../features.md#toolchain-build-info) and the
[investigation ledger](../features.md#investigation-ledger).
