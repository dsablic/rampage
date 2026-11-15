//! Safety limits: output size, file count, per-file size, compression ratio and nesting depth.

use std::cell::Cell;

use crate::error::{Result, UnpackError};

/// Caps on the work one listing or extraction may do. Every image is treated as hostile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Bytes written in total: extracted files plus nested images spooled to temporary files.
    pub max_total_bytes: u64,
    /// Files, directories and links written by one extraction.
    pub max_files: u64,
    /// Bytes of any one extracted file or spooled nested image.
    pub max_file_bytes: u64,
    /// Decompressed bytes per compressed byte, over the whole call, once more than [`RATIO_FLOOR`] bytes came out.
    pub max_ratio: u64,
    /// Image layers, counting the outer image: sparse → ext4 is two, OTA → partition → ext4 three.
    pub max_depth: usize,
    /// Entries one image may list.
    pub max_entries: usize,
    /// Directory levels inside one image.
    pub max_path_depth: usize,
}

/// Decompressed output below which the ratio is not checked: small files compress well legitimately.
pub const RATIO_FLOOR: u64 = 64 << 20;

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_total_bytes: 4 << 30,
            max_files: 100_000,
            max_file_bytes: 2 << 30,
            max_ratio: 1000,
            max_depth: 4,
            max_entries: 500_000,
            max_path_depth: 128,
        }
    }
}

impl Limits {
    /// The largest values a caller may ask for.
    pub const CEILING: Limits = Limits {
        max_total_bytes: 64 << 30,
        max_files: 1_000_000,
        max_file_bytes: 16 << 30,
        max_ratio: 100_000,
        max_depth: 8,
        max_entries: 1_000_000,
        max_path_depth: 512,
    };

    /// These limits with every field clamped to [`Limits::CEILING`] and at least 1.
    pub fn clamped(self) -> Self {
        let ceiling = Self::CEILING;
        Self {
            max_total_bytes: self.max_total_bytes.clamp(1, ceiling.max_total_bytes),
            max_files: self.max_files.clamp(1, ceiling.max_files),
            max_file_bytes: self.max_file_bytes.clamp(1, ceiling.max_file_bytes),
            max_ratio: self.max_ratio.clamp(1, ceiling.max_ratio),
            max_depth: self.max_depth.clamp(1, ceiling.max_depth),
            max_entries: self.max_entries.clamp(1, ceiling.max_entries),
            max_path_depth: self.max_path_depth.clamp(1, ceiling.max_path_depth),
        }
    }
}

/// Bytes and files written so far in one call, against its [`Limits`].
#[derive(Debug)]
pub struct Budget {
    pub limits: Limits,
    pub bytes: u64,
    pub files: u64,
}

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Self { limits: limits.clamped(), bytes: 0, files: 0 }
    }

    /// Charges `count` more output bytes.
    pub fn charge_bytes(&mut self, count: u64) -> Result<()> {
        let total = self.bytes.checked_add(count).filter(|total| *total <= self.limits.max_total_bytes);
        match total {
            Some(total) => {
                self.bytes = total;
                Ok(())
            }
            None => Err(UnpackError::Limit(format!(
                "output would exceed max_bytes ({} bytes)",
                self.limits.max_total_bytes
            ))),
        }
    }

    /// Charges one more written file, directory or link.
    pub fn charge_file(&mut self) -> Result<()> {
        if self.files >= self.limits.max_files {
            return Err(UnpackError::Limit(format!(
                "more than max_files ({}) entries to write",
                self.limits.max_files
            )));
        }
        self.files += 1;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct Meter {
    input: u64,
    output: u64,
    max_ratio: u64,
}

thread_local! {
    static METER: Cell<Option<Meter>> = const { Cell::new(None) };
}

/// Installs the compression-ratio meter for this thread while it lives; nested scopes share the outermost one.
/// Decompression happens on the calling thread (backhand runs without its parallel feature), so a thread-local
/// meter sees every codec call, including those backhand makes.
pub(crate) struct MeterScope {
    installed: bool,
}

impl MeterScope {
    pub(crate) fn new(max_ratio: u64) -> Self {
        let installed = METER.with(|meter| {
            if meter.get().is_some() {
                return false;
            }
            meter.set(Some(Meter { input: 0, output: 0, max_ratio }));
            true
        });
        Self { installed }
    }
}

impl Drop for MeterScope {
    fn drop(&mut self) {
        if self.installed {
            METER.with(|meter| meter.set(None));
        }
    }
}

/// Records `input` compressed bytes consumed and `output` bytes produced, refusing once the call's output passes
/// [`RATIO_FLOOR`] at more than `max_ratio` times its input: a decompression bomb.
pub(crate) fn account(input: u64, output: u64) -> Result<()> {
    METER.with(|cell| {
        let Some(mut meter) = cell.get() else { return Ok(()) };
        meter.input = meter.input.saturating_add(input);
        meter.output = meter.output.saturating_add(output);
        cell.set(Some(meter));
        if meter.output > RATIO_FLOOR && meter.output / meter.input.max(1) > meter.max_ratio {
            return Err(UnpackError::Limit(format!(
                "decompression ratio above {}:1 ({} bytes from {}): likely a decompression bomb",
                meter.max_ratio, meter.output, meter.input
            )));
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_meter_refuses_a_bomb_only_past_the_floor() {
        let _scope = MeterScope::new(10);
        account(1, RATIO_FLOOR).unwrap();
        assert!(account(0, 1).is_err());
    }

    #[test]
    fn budgets_refuse_overflow() {
        let mut budget = Budget::new(Limits { max_total_bytes: 10, max_files: 1, ..Limits::default() });
        budget.charge_bytes(10).unwrap();
        assert!(budget.charge_bytes(1).is_err());
        assert!(budget.charge_bytes(u64::MAX).is_err());
        budget.charge_file().unwrap();
        assert!(budget.charge_file().is_err());
    }
}
