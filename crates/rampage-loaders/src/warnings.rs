/// A cap on a reader's diagnostics, so hostile input cannot grow them without bound. The last slot is spent on a
/// note that the rest were dropped, so a truncated list says so.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CappedWarnings {
    limit: usize,
    /// Names the reader in the truncation note, e.g. `DWARF`.
    source: &'static str,
}

impl CappedWarnings {
    pub(crate) const fn new(limit: usize, source: &'static str) -> Self {
        assert!(limit > 0);
        Self { limit, source }
    }

    pub(crate) fn push(self, warnings: &mut Vec<String>, warning: String) {
        if warnings.len() + 1 < self.limit {
            warnings.push(warning);
        } else if warnings.len() + 1 == self.limit {
            warnings.push(format!("{} warning limit reached; further diagnostics are truncated", self.source));
        }
    }

    /// Whether further warnings would be dropped.
    pub(crate) fn is_full(self, warnings: &[String]) -> bool {
        warnings.len() + 1 >= self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_slot_notes_the_truncation() {
        let cap = CappedWarnings::new(3, "Test");
        let mut warnings = Vec::new();
        for index in 0..5 {
            cap.push(&mut warnings, format!("warning {index}"));
        }
        assert_eq!(
            warnings,
            ["warning 0", "warning 1", "Test warning limit reached; further diagnostics are truncated"]
        );
        assert!(cap.is_full(&warnings));
        assert!(!cap.is_full(&warnings[..1]));
    }
}
