use std::io::{self, Write};

use serde::Serialize;

use super::{
    DebugLayoutImport, DebugLayoutPreview, DebugLayoutReport, DebugLayoutVirtualEvidence, Sha256, hex_digest, invalid,
};
use crate::{ApiError, Project};
use sha2::Digest;

const MAX_REVIEW_BYTES: usize = 4 * 1024 * 1024;

/// Owned review content, not a serialized Project-bound receipt or proof of user authorization.
/// Applying its fingerprint requires a fresh, exactly matching checked preview.
#[derive(Debug, Serialize)]
pub struct DebugLayoutReview {
    pub review_sha256: String,
    pub image_sha256: String,
    pub compiler_spec_sha256: String,
    pub report: DebugLayoutReport,
    pub producer_report: Option<rampage_loaders::debug::DebugLayoutReport>,
    pub virtual_evidence: DebugLayoutVirtualEvidence,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub approved: Vec<u64>,
    #[serde(serialize_with = "rampage_arch::hex::addresses")]
    pub preserved: Vec<u64>,
    pub imported: Option<DebugLayoutImport>,
}

struct ReviewHasher {
    hash: Sha256,
    remaining: usize,
}

impl Write for ReviewHasher {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "review encoded-byte limit exceeded"))?;
        self.hash.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DebugLayoutPreview<'_> {
    /// Fingerprints the complete checked review, independently of transport paging or output formatting.
    /// A match is content association, not authentication, filesystem atomicity or receipt rebinding.
    pub fn review_sha256(&self) -> Result<String, ApiError> {
        let platform = match self.options.platform {
            rampage_decompiler::Platform::Default => "default",
            rampage_decompiler::Platform::Windows => "windows",
            rampage_decompiler::Platform::Darwin => "darwin",
        };
        let content = (
            "rampage-debug-layout-review-v2",
            &self.image_sha256,
            &self.compiler_spec_sha256,
            (platform, &self.options.compiler, self.options.arm_be8),
            &self.report,
            &self.producer,
            &self.approved,
            &self.preserved,
            &self.virtual_evidence,
        );
        let mut writer = ReviewHasher { hash: Sha256::new(), remaining: MAX_REVIEW_BYTES };
        serde_json::to_writer(&mut writer, &content).map_err(|error| invalid(&error.to_string()))?;
        Ok(rampage_arch::hex::bytes(&writer.hash.finalize()))
    }

    fn into_review(self, review_sha256: String, imported: Option<DebugLayoutImport>) -> DebugLayoutReview {
        DebugLayoutReview {
            review_sha256,
            image_sha256: rampage_arch::hex::bytes(&self.image_sha256),
            compiler_spec_sha256: rampage_arch::hex::bytes(&self.compiler_spec_sha256),
            report: self.report,
            producer_report: self.producer,
            virtual_evidence: self.virtual_evidence,
            approved: self.approved.into_iter().map(|function| function.address).collect(),
            preserved: self.preserved,
            imported,
        }
    }
}

impl Project {
    /// Returns complete owned content for explicit review without changing annotations or undo history.
    pub fn review_debug_layouts(&self) -> Result<DebugLayoutReview, ApiError> {
        let preview = self.preview_debug_layouts()?;
        let fingerprint = preview.review_sha256()?;
        Ok(preview.into_review(fingerprint, None))
    }

    /// Recomputes the complete checked review and applies only if its fingerprint matches the supplied approval.
    /// Later concurrent analyst edits may shrink the atomic batch, never enlarge the approved functions.
    pub fn apply_reviewed_debug_layouts(&self, review_sha256: &str) -> Result<DebugLayoutReview, ApiError> {
        if !hex_digest(review_sha256) {
            return Err(invalid(
                "review_sha256 requires exactly 64 lowercase hexadecimal characters; nothing imported",
            ));
        }
        let preview = self.preview_debug_layouts()?;
        let fingerprint = preview.review_sha256()?;
        if fingerprint != review_sha256 {
            return Err(invalid("review content changed or fingerprint is incorrect; preview and approve again"));
        }
        let imported = self.apply_debug_layouts(&preview)?;
        Ok(preview.into_review(fingerprint, Some(imported)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug_layout_import::tests::{binary, plan};

    #[test]
    fn complete_review_content_not_only_function_addresses_controls_approval() {
        let project = Project::new(binary());
        let mut preview = project.preview_debug_layout_plan(plan(&project)).unwrap();
        let initial = preview.review_sha256().unwrap();
        preview.report.types[0].layout.fields[0].name = "replacement".to_owned();
        assert_ne!(preview.review_sha256().unwrap(), initial);
        preview.report = plan(&project);
        assert_eq!(preview.review_sha256().unwrap(), initial);
        preview.report.functions[0].declaration = "int4 debug_mix(owned_record *different);".to_owned();
        assert_ne!(preview.review_sha256().unwrap(), initial);
        preview.report = plan(&project);
        preview.preserved.push(0x1234);
        assert_ne!(preview.review_sha256().unwrap(), initial);
        preview.preserved.clear();
        preview.approved.clear();
        assert_ne!(preview.review_sha256().unwrap(), initial);
    }

    #[test]
    fn producer_unknowns_warnings_and_selected_compiler_options_are_committed() {
        let project = Project::new(binary());
        let mut preview = project.preview_debug_layout_plan(plan(&project)).unwrap();
        let initial = preview.review_sha256().unwrap();
        preview.producer = Some(rampage_loaders::debug::DebugLayoutReport::default());
        assert_ne!(preview.review_sha256().unwrap(), initial);
        let with_producer = preview.review_sha256().unwrap();
        preview.producer.as_mut().unwrap().warnings.push("alignment unknown".to_owned());
        assert_ne!(preview.review_sha256().unwrap(), with_producer);
        preview.producer = None;
        preview.options.compiler = Some("gcc".to_owned());
        assert_ne!(preview.review_sha256().unwrap(), initial);
        preview.options.compiler = None;
        preview.compiler_spec_sha256[0] ^= 1;
        assert_ne!(preview.review_sha256().unwrap(), initial);
        preview.compiler_spec_sha256[0] ^= 1;
        preview.image_sha256[0] ^= 1;
        assert_ne!(preview.review_sha256().unwrap(), initial);
    }

    #[test]
    fn absent_and_explicit_producer_alignments_never_share_an_approval_fingerprint() {
        let project = Project::new(binary());
        let mut preview = project.preview_debug_layouts().unwrap();
        let initial = preview.review_sha256().unwrap();
        let layout = preview.producer.as_mut().unwrap().layouts.first_mut().expect("preview-only producer layout");
        assert!(layout.producer_alignment.is_none());
        layout.producer_alignment = Some(8);
        assert_ne!(preview.review_sha256().unwrap(), initial);
    }

    #[test]
    fn invalid_approval_is_refused_before_source_or_native_work() {
        let project = Project::new(binary());
        project.set_decompiler_options(Some(rampage_decompiler::DecompilerOptions {
            compiler: Some("missing_review_compiler".to_owned()),
            ..Default::default()
        }));
        for invalid_digest in ["", "bad", &"A".repeat(64), &"0".repeat(65)] {
            let error = project.apply_reviewed_debug_layouts(invalid_digest).unwrap_err().to_string();
            assert!(error.contains("64 lowercase hexadecimal"), "{error}");
        }
        assert!(project.annotation_list().types.is_empty());
        assert!(project.undo().unwrap().is_empty());
    }

    #[test]
    fn encoded_review_limit_is_checked_before_hashing_a_write() {
        let mut writer = ReviewHasher { hash: Sha256::new(), remaining: 3 };
        writer.write_all(b"abc").unwrap();
        assert!(writer.write_all(b"d").is_err());
        let actual: [u8; 32] = writer.hash.finalize().into();
        let expected: [u8; 32] = Sha256::digest(b"abc").into();
        assert_eq!(actual, expected);
    }

    #[test]
    fn escaped_complete_review_serialization_failure_changes_no_annotations_or_undo() {
        let project = Project::new(binary());
        let mut preview = project.preview_debug_layout_plan(plan(&project)).unwrap();
        let before = serde_json::to_value(project.annotation_list()).unwrap();
        preview.report.warnings.push("\0".repeat(MAX_REVIEW_BYTES / 6 + 1));
        let error = preview.review_sha256().unwrap_err().to_string();
        assert!(error.contains("review encoded-byte limit"), "{error}");
        assert_eq!(serde_json::to_value(project.annotation_list()).unwrap(), before);
        assert!(project.undo().unwrap().is_empty());
    }

    #[test]
    fn projection_and_every_retained_virtual_association_fact_are_part_of_review_approval() {
        use rampage_analysis::classes::{
            ClassEvidence, HeaderClassification, RttiClassification, RttiEvidence, ScanStop, SlotClassification,
            VtableSlot,
        };
        use rampage_loaders::debug::DebugLayoutTypeId;

        let project = Project::new(binary());
        let mut preview = project.preview_debug_layout_plan(plan(&project)).unwrap();
        let original = preview.review_sha256().unwrap();
        preview.report.types[0] = crate::debug_layout_import::projected_bundle_tests::projected_type();
        assert_ne!(preview.review_sha256().unwrap(), original);
        let projected = preview.review_sha256().unwrap();
        let super::super::DebugLayoutProjection::OpaqueVptr { pointer_alignment, .. } =
            &mut preview.report.types[0].projections[0];
        *pointer_alignment = Some(8);
        assert_ne!(preview.review_sha256().unwrap(), projected);
        let id = |die_offset| DebugLayoutTypeId { unit_offset: 16, die_offset };
        preview.virtual_evidence.tables.push(super::super::DebugLayoutVtableEvidence {
            raw: ClassEvidence {
                name: "Record".to_owned(),
                vtable_symbol: "_ZTV6Record".to_owned(),
                address: 0x2000,
                source: "named_itanium_vtable_symbol",
                confidence: "raw_named_vtable_evidence",
                pointer_size: 8,
                header: HeaderClassification::UnverifiedPrefix,
                raw_offset_word: 0,
                offset_to_top: None,
                rtti_candidate: RttiEvidence { address: 0, classification: RttiClassification::Null, symbol: None },
                bound: "symbol_size",
                scan_limit: 0x2018,
                scan_end: 0x2018,
                slots: vec![VtableSlot {
                    index: 0,
                    address: 0x2010,
                    raw_value: 0x1000,
                    classification: SlotClassification::Function,
                    target: Some(0x1000),
                }],
                stop: ScanStop::Bound,
            },
            methods: vec![super::super::DebugLayoutVirtualMethodEvidence {
                slot_index: 0,
                declared_virtual_slot_index: 0,
                method_address: 0x1000,
                definition_id: id(80),
                record_id: id(32),
                declaration_id: id(72),
                object_pointer_id: id(88),
                linkage_name: "_ZN6Record4readEv".to_owned(),
                layout_name: "debug_layout_10_20_Record".to_owned(),
                verification: "native_checked_source_evidence",
            }],
        });
        let baseline = preview.review_sha256().unwrap();
        assert_ne!(baseline, projected);
        preview.virtual_evidence.tables[0].raw.slots[0].raw_value += 1;
        assert_ne!(preview.review_sha256().unwrap(), baseline);
        preview.virtual_evidence.tables[0].raw.slots[0].raw_value -= 1;
        preview.virtual_evidence.tables[0].raw.header = HeaderClassification::KnownRtti;
        assert_ne!(preview.review_sha256().unwrap(), baseline);
        preview.virtual_evidence.tables[0].raw.header = HeaderClassification::UnverifiedPrefix;
        preview.virtual_evidence.tables[0].methods[0].declared_virtual_slot_index = 1;
        assert_ne!(preview.review_sha256().unwrap(), baseline);
        preview.virtual_evidence.tables[0].methods[0].declared_virtual_slot_index = 0;
        preview.virtual_evidence.tables[0].methods[0].object_pointer_id = id(96);
        assert_ne!(preview.review_sha256().unwrap(), baseline);
        preview.virtual_evidence.tables[0].methods[0].object_pointer_id = id(88);
        preview.virtual_evidence.warnings.push("evidence bounded".to_owned());
        assert_ne!(preview.review_sha256().unwrap(), baseline);
    }
}
