# rampage-decompiler

Embeds Ghidra's decompiler as an in-process library and exposes it to rampage through a small, safe Rust API.
A `Decompiler` is opened once over a program's executable segments and decompiles functions to C on demand.

## Vendored source

`vendor/ghidra/` holds the decompiler's C++ sources, taken verbatim from the Ghidra 12.1.4 release
(tag `Ghidra_12.1.4_build`), path `Ghidra/Features/Decompiler/src/decompile/cpp`. They are the decompiler
library set (the Makefile's `LIBDECOMP` sources) without the BFD loader, the Ghidra-process bridge and the
SLEIGH compiler. `src/shim.cc` is rampage's own C ABI over that library.

Ghidra is Copyright the National Security Agency, licensed under the Apache License 2.0; `vendor/ghidra/LICENSE`
is that license. rampage's own code is under the workspace's MIT/Apache-2.0 terms, but this crate links the
vendored Apache-2.0 sources.

## Processor specifications

The compiled SLEIGH specifications (`.sla`) are not vendored. At runtime the crate locates a local Ghidra
install that contains a `Ghidra/Processors` tree: `GHIDRA_INSTALL_DIR` if set, otherwise a Homebrew install
(`brew --prefix ghidra`). Without one, `Decompiler::open` returns `Error::NoSleighHome` and callers fall back
to rampage's own analysis. s390x has no Ghidra specification and is unsupported.
