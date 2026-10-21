use crate::{ApiError, Project};

impl Project {
    /// Samples exact metadata-declared entries, or one caller-supplied address, without program discovery.
    pub fn entry_diagnostics(
        &self,
        address: Option<u64>,
    ) -> Result<rampage_analysis::entry_audit::EntryAudit, ApiError> {
        let checked = || {
            self.binary
                .validate_available_backing_source()
                .map_err(|error| ApiError::Unavailable(format!("entry diagnostics source: {error}")))
        };
        checked()?;
        let limits = rampage_analysis::entry_audit::EntryAuditLimits::default();
        let report = match address {
            Some(address) => rampage_analysis::entry_audit::sample_entry(&self.binary, address, limits),
            None => rampage_analysis::entry_audit::sample_declared_entries(&self.binary, limits),
        };
        checked()?;
        Ok(report)
    }

    /// Bounded byte-sample diagnostics with candidate counts, not verified source/function recovery.
    pub fn analysis_diagnostics(
        &self,
        include_discovery: bool,
    ) -> Result<rampage_analysis::diagnostics::Diagnostics, ApiError> {
        let analysis = if include_discovery { Some(self.analysis()?) } else { self.cached_analysis_checked()? };
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use rampage_loaders::Binary;

    use super::*;

    struct OwnedFile(PathBuf);

    impl Drop for OwnedFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn copied_image() -> (OwnedFile, Project) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "entry-diagnostics-{}-{}.elf",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let owned = OwnedFile(path);
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/bin/hello-x64-dyn.elf");
        std::fs::copy(source, &owned.0).unwrap();
        let project = Project::new(Binary::open(&owned.0).unwrap());
        (owned, project)
    }

    #[test]
    fn metadata_diagnostics_refuse_a_changed_cached_native_source_without_rediscovery() {
        let (image, project) = copied_image();
        assert!(project.analysis_diagnostics(true).unwrap().discovery.is_some());
        let replacement = OwnedFile(image.0.with_extension("replacement"));
        std::fs::copy(&image.0, &replacement.0).unwrap();
        std::fs::rename(&replacement.0, &image.0).unwrap();
        let error = project.analysis_diagnostics(false).unwrap_err();
        assert!(error.to_string().contains("cached analysis source"), "{error}");
        assert!(project.analysis_cache_status().program);
    }

    #[test]
    fn exact_and_declared_reports_leave_discovery_cold_and_refuse_original_path_replacement() {
        let (image, project) = copied_image();
        let address = project.resolve("main").unwrap();
        assert!(!project.entry_diagnostics(Some(address)).unwrap().entries.is_empty());
        assert!(!project.entry_diagnostics(None).unwrap().entries.is_empty());
        assert!(project.cached_analysis().is_none());
        let replacement = OwnedFile(image.0.with_extension("replacement"));
        std::fs::copy(&image.0, &replacement.0).unwrap();
        std::fs::rename(&replacement.0, &image.0).unwrap();
        for at in [Some(address), None] {
            assert!(project.entry_diagnostics(at).unwrap_err().to_string().contains("source"));
        }
        assert!(project.cached_analysis().is_none());
    }

    #[test]
    fn observable_in_place_modification_is_refused_but_owned_snapshot_bytes_remain_supported() {
        use std::io::{Seek, SeekFrom, Write};
        let (image, project) = copied_image();
        let mut file = std::fs::OpenOptions::new().write(true).open(&image.0).unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[0x55]).unwrap();
        file.sync_all().unwrap();
        assert!(project.entry_diagnostics(None).is_err());
        assert!(project.cached_analysis().is_none());
        let binary = Binary::from_snapshot_bytes(
            serde_json::json!({
                "format":"rampage-snapshot-v1", "arch":"x86_64", "data_big_endian":false,
                "provenance":"owned diagnostics observation", "seeds":["0x1000"],
                "regions":[{"name":"code", "address":"0x1000", "permissions":"r-x", "bytes":"c3"}]
            })
            .to_string()
            .into_bytes(),
        )
        .unwrap();
        assert!(!binary.validate_available_backing_source().unwrap());
        assert!(binary.validate_backing_source().is_err());
        let project = Project::new(binary);
        assert_eq!(project.entry_diagnostics(None).unwrap().entries[0].address, 0x1000);
        assert!(project.cached_analysis().is_none());
    }
}
