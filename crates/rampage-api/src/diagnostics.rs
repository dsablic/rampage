use crate::{ApiError, Project};

impl Project {
    /// Bounded byte-sample diagnostics with candidate counts, not verified source/function recovery.
    pub fn analysis_diagnostics(
        &self,
        include_discovery: bool,
    ) -> Result<rampage_analysis::diagnostics::Diagnostics, ApiError> {
        let analysis = if include_discovery { Some(self.analysis()?) } else { self.cached_analysis() };
        let modes = analysis.map_or(&[][..], |analysis| analysis.program.code_modes.as_slice());
        let mut diagnostics = rampage_analysis::diagnostics::diagnostics_with_modes(&self.binary, modes);
        if let Some(analysis) = analysis {
            diagnostics = diagnostics.with_discovery(&analysis.program.functions);
        } else {
            diagnostics.limitations.push(
                concat!(
                    "Discovery evidence is unavailable; sampling does not trigger whole-program discovery. ",
                    "Request discovery explicitly to include candidates and learned instruction-set modes."
                )
                .to_owned(),
            );
        }
        Ok(diagnostics)
    }
}
