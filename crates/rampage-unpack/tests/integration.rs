//! The crate's integration tests build into this one test binary, one module per `tests/*.rs` file.

mod fuzz;
mod generator;
mod hardening;
mod refusals;
mod round_trip;
mod support;
mod zip;
