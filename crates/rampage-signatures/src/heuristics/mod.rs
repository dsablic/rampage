//! Heuristics written in the flywheel's code loop (docs/flywheel.md, "The code loop"), and the data they may derive
//! from the training split.
//!
//! [`generate`] turns the training binaries and their truth into one data file. The harness runs it, inside its
//! sandbox and on the training split only, and compiles the result in as [`data`]; a data file left in a change is
//! never used. Identification code may read [`data`]. The file holds at most [`MAX_BYTES`].

pub use crate::heuristics_data::{MAX_BYTES, TrainingBinary, TrainingFunction};

/// The data file for `training`. The default derives nothing.
pub fn generate(training: &[TrainingBinary]) -> Vec<u8> {
    let _ = training;
    Vec::new()
}

/// The generated data compiled into this build.
pub fn data() -> &'static [u8] {
    crate::heuristics_data::BYTES
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_default_generator_derives_nothing_and_no_data_is_compiled_in() {
        assert!(super::generate(&[]).is_empty());
        assert!(super::data().len() <= super::MAX_BYTES);
    }
}
