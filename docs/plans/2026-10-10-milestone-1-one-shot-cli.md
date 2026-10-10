# Milestone 1: One-Shot CLI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** A `rampage` binary with `info`, `disasm`, `strings` and `funcs` subcommands that work on PE, ELF and
Mach-O x86/x64 binaries, with text and JSON output.

**Architecture:** Cargo workspace with three library crates and one binary crate. `rampage-loaders` memory-maps a
file, parses it once with `object`, and exposes an owned, serializable `Binary` model plus address-based byte reads.
`rampage-arch` wraps `iced-x86` behind a small decoder API that also reports control flow (used by milestone 2).
`rampage-analysis` holds string scanning and symbol-derived functions. `rampage-cli` is a thin clap front end.

**Tech Stack:** Rust 1.99 (edition 2024), object 0.40, memmap2 0.9, iced-x86 1.21, clap 4, serde/serde_json,
thiserror 2, anyhow (CLI only), assert_cmd + insta for CLI tests.

**Toolchain note:** on this machine run `export PATH=/opt/homebrew/opt/rustup/bin:$PATH` before cargo commands.

---

### Task 1: Workspace scaffold

**Files:**
- Create: `Cargo.toml`, `.gitignore`, `rust-toolchain.toml`
- Create: `crates/rampage-loaders/{Cargo.toml,src/lib.rs}`, `crates/rampage-arch/...`, `crates/rampage-analysis/...`,
  `crates/rampage-cli/{Cargo.toml,src/main.rs}`

Workspace `Cargo.toml` declares members via `crates/*`, `resolver = "3"`, shared `[workspace.package]`
(edition 2024, license `MIT OR Apache-2.0`) and `[workspace.dependencies]` pinning the versions above.
`[profile.release]` uses `lto = "thin"`, `codegen-units = 1`.

Verify: `cargo build` succeeds, `cargo test` runs zero tests. Commit.

### Task 2: Test fixtures

**Files:**
- Create: `tests/fixtures/src/hello.c`, `tests/fixtures/build.sh`
- Create: built binaries `tests/fixtures/bin/hello-x64.{elf,exe,macho}` and `hello-arm64.macho`

`hello.c` has a known string (`"rampage fixture greeting"`), a known exported function `add`, and `main`.
`build.sh` uses `zig cc -target x86_64-linux-musl -O1 -g0`, `zig cc -target x86_64-windows-gnu -O1 -g0` and
`clang -arch {x86_64,arm64} -O1`. The binaries are committed so tests do not depend on compiler versions.
Tests locate fixtures via `env!("CARGO_MANIFEST_DIR")/../../tests/fixtures/bin`.

Commit.

### Task 3: Loader model and parsing (TDD)

**Files:**
- Create: `crates/rampage-loaders/src/{lib.rs,model.rs,load.rs}`, `crates/rampage-loaders/tests/load.rs`

Model (all `Serialize`):

```rust
pub enum Format { Elf, Pe, MachO }
pub enum Arch { X86, X86_64, Aarch64 }
pub struct Segment { name: String, address: u64, size: u64, file_offset: u64, file_size: u64, perms: Perms }
pub struct Perms { read: bool, write: bool, execute: bool }
pub struct Section { name: String, address: u64, size: u64, kind: SectionKind }
pub enum SectionKind { Code, Data, ReadOnlyData, UninitializedData, Other }
pub struct Symbol { name: String, address: u64, size: u64, kind: SymbolKind }
pub enum SymbolKind { Function, Data, Other }
pub struct Import { library: Option<String>, name: String }
pub struct Export { name: String, address: u64 }
pub struct Binary { format, arch, entry, segments, sections, symbols, imports, exports }
```

`Binary::open(path)` memory-maps the file, keeps the `Mmap`, parses with `object::File::parse`, and fails with a
typed `LoadError::{Io, Parse, Unsupported}`. `Binary::read(address, len) -> Option<&[u8]>` resolves an address
through the segments' file ranges (bytes past `file_size` inside a segment read as unavailable, not zero).
`Binary::section_containing(address)` and `Binary::symbol_by_name(name)` are simple lookups.

Tests (one per format fixture): format and arch detected; entry point lies inside an executable segment; a symbol
named `add` (`_add` on Mach-O) exists; reading 16 bytes at the entry returns `Some`; the greeting string bytes are
found by `read` at its section-derived address. Write tests first, see them fail, implement, see them pass, commit.

### Task 4: x86 decoder wrapper (TDD)

**Files:**
- Create: `crates/rampage-arch/src/{lib.rs,x86.rs}`, tests in `x86.rs`

```rust
pub enum Flow { Next, Jump(u64), ConditionalJump(u64), Call(u64), IndirectJump, IndirectCall, Return, Halt, Invalid }
pub struct Insn { pub address: u64, pub len: u8, pub text: String, pub flow: Flow }
pub fn decoder_for(arch: Arch) -> Result<Box<dyn Disassembler>, UnsupportedArch>;
pub trait Disassembler { fn decode_one(&self, bytes: &[u8], address: u64) -> Insn; }
```

`Arch` lives in `rampage-arch` and `rampage-loaders` re-uses it, so there is a single definition. The x86 decoder
maps iced `FlowControl` to `Flow` and formats with the Intel formatter. Tests: `55 48 89 e5 c3` decodes to
`push rbp`, `mov rbp,rsp`, `ret` with `Return` flow on the last; `e8 00 00 00 00` at `0x1000` is `Call(0x1005)`;
`74 02` is `ConditionalJump`; `ff e0` is `IndirectJump`; a truncated `48` is `Invalid` with `len` 1. Aarch64
returns `UnsupportedArch` until milestone 4. Commit.

### Task 5: Strings and symbol functions (TDD)

**Files:**
- Create: `crates/rampage-analysis/src/{lib.rs,strings.rs,functions.rs}`

`strings::scan(binary, min_len) -> Vec<FoundString { address, encoding: Ascii|Utf16Le, text }>` scans every
segment's file-backed bytes for printable runs (`0x20..=0x7e` plus `\t`) of at least `min_len` characters, in
ASCII and in UTF-16LE. `functions::from_symbols(binary) -> Vec<Function { address, size, name }>` returns defined
function symbols plus the entry point, deduplicated and sorted by address. Tests use small byte buffers for the
scanner and the fixtures for both. Commit.

### Task 6: CLI (`info`, `disasm`, `strings`, `funcs`) with JSON

**Files:**
- Create: `crates/rampage-cli/src/{main.rs,commands/*.rs}`, `crates/rampage-cli/tests/cli.rs`

Global `--json`. `info <file>` prints format, arch, entry, segments, sections, counts. `disasm <file>
[--at <addr|symbol>] [--count N]` defaults to the entry point and 32 instructions. `strings <file> [--min-len 4]`.
`funcs <file>`. Addresses print as `0x…` hex; `--at` accepts hex, decimal or a symbol name. Errors go to stderr with
a non-zero exit. Tests with `assert_cmd`: each command succeeds on each x64 fixture; `strings` output contains the
greeting; `funcs --json` parses and contains `add`/`_add`; `disasm --at add` begins at that symbol's address;
`disasm` on the arm64 fixture fails with a clear "unsupported architecture" message. Commit.

### Task 7: Verify and polish

Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, check lines are under 120 columns,
run the release binary against a large system binary to sanity-check speed, add a short `README.md`. Commit.
