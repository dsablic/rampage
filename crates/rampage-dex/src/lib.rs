//! Android DEX bytecode, in-house and pure Rust: the DEX format (035 through 041) and Dalvik disassembly. Inputs
//! are hostile: every offset, count and length is checked before use, and work is capped by [`dex::Limits`].
//! Design: docs/plans/2026-11-16-android-dex.md.

pub mod dex;
mod error;
pub mod insn;
mod read;
#[cfg(feature = "testkit")]
pub mod testkit;
mod value;

pub use dex::{Dex, Limits, is_dex};
pub use error::{DexError, Result};
pub use read::Mutf8;
