# Milestone 2: Function Discovery and Cross-References Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Find functions in stripped binaries by recursive descent from metadata seeds, record code and data
cross-references, and expose them through `rampage funcs` and a new `rampage xrefs`.

**Architecture:** The analysis reads memory through a small `Memory` trait (implemented by `Binary` and by a flat
test buffer), so the algorithm is unit-testable on hand-written bytes. Function discovery runs in rounds: each round
decodes all newly seeded functions in parallel with rayon, then a single-threaded merge sorts results by address and
collects call targets as the next round's seeds. Output is deterministic regardless of thread count. The decoder gains
a formatting-free `decode` path, because analysis never needs instruction text.

**Tech Stack:** rayon for parallelism; everything else from milestone 1.

**Toolchain note:** on this machine run `export PATH=/opt/homebrew/opt/rustup/bin:$PATH` before cargo commands.

---

### Task 1: Formatting-free decode and data references

**Files:** `crates/rampage-arch/src/{lib.rs,x86.rs}`

Split the decoder API so analysis does not pay for text formatting:

```rust
pub struct Insn { pub address: u64, pub len: u8, pub flow: Flow, pub data_ref: Option<u64> }
pub trait Disassembler {
    fn decode(&mut self, bytes: &[u8], address: u64) -> Insn;
    fn format(&mut self, bytes: &[u8], address: u64) -> String;
}
```

`data_ref` is the absolute target of a RIP-relative memory operand, else of an absolute memory displacement, else of
an immediate operand at least 0x1000 (smaller immediates are almost never addresses). Direct branch targets live in
`flow`, not `data_ref`. Tests: `lea rax,[rip+0x10]` at 0x1000 (`48 8d 05 10 00 00 00`) yields `Some(0x1017)`;
`mov edi,0x401000` yields `Some(0x401000)`; `mov eax,5` yields `None`; `call` yields `None`.

### Task 2: Metadata seeds

**Files:** `crates/rampage-loaders/src/{load.rs,model.rs}`, tests in `tests/load.rs`

Add `Binary::function_starts: Vec<u64>` from format metadata:
- Mach-O `LC_FUNCTION_STARTS`: ULEB128 deltas from the `__TEXT` segment address, terminated by a zero delta.
- PE `.pdata` (x64): 12-byte `RUNTIME_FUNCTION` entries; skip entries whose unwind info has `UNW_FLAG_CHAININFO`
  (0x4), since those are fragments of another function.
- ELF: none yet (`.eh_frame` parsing is a later task).

Tests: the stripped Mach-O and PE fixtures yield a start equal to `add`'s address.
Fixture additions: `hello-x64-stripped.macho` (`strip`), and the PE fixture already lacks a symbol table.

### Task 3: Recursive descent

**Files:** `crates/rampage-analysis/src/{memory.rs,discover.rs}`

```rust
pub trait Memory {
    fn bytes_from(&self, address: u64) -> Option<&[u8]>;
    fn is_executable(&self, address: u64) -> bool;
}
pub struct Program { pub functions: Vec<DiscoveredFunction>, pub xrefs: Vec<Xref> }
pub struct DiscoveredFunction { pub address: u64, pub blocks: Vec<Block>, pub calls: Vec<u64> }
pub struct Block { pub start: u64, pub end: u64 }
pub struct Xref { pub from: u64, pub to: u64, pub kind: XrefKind }  // Call, Jump, Data
pub fn discover(memory: &impl Memory + Sync, decoder: impl Fn() -> Box<dyn Disassembler>, seeds: &[u64]) -> Program
```

Within a function: worklist of block starts; decode until `Return`, `Jump`, `IndirectJump`, `Halt` or `Invalid`;
`ConditionalJump` adds both successors; `Jump` to an address that is already a function seed is a tail call (an xref,
not a block). `Call(target)` in executable memory adds a seed for the next round. `data_ref` into executable memory is
also a seed, which catches function pointers such as `main` passed to `__libc_start_main`. Blocks are split when a
later jump lands inside an existing block. Tests on flat buffers: straight line, diamond, loop, call to a second
function, tail call, jump into the middle of a block, invalid bytes stopping a block, and determinism (same result
with 1 and 8 threads).

### Task 4: CLI

`funcs` runs discovery seeded by entry, symbols, exports and `function_starts`; unnamed functions get `sub_<hex>`
names; text output adds block count and size. `--symbols-only` keeps the milestone 1 behavior. New
`xrefs <file> --to <addr|symbol>` and `--from <addr|symbol>` list references with their kind and containing function.
CLI tests on each fixture plus stripped fixtures: `funcs` finds `add` in stripped Mach-O and PE.

### Task 5: Measure

Time `funcs` on the Chrome framework x86_64 slice and a large ELF; record results in the PR, not in code. Optimize
only what the profile shows.
