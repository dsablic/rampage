//! Evaluating signatures against a loaded image. Every read is bounds-checked, so a malformed or truncated
//! binary can make a condition fail to match but can never panic.
//!
//! Conditions are tested through the [`Image`] trait rather than against [`Binary`] directly. [`Binary`]
//! implements it over its real sections, imports and overlay; the crate's synthetic tests implement it over
//! crafted inputs, which lets the section, import, overlay and entropy paths be unit-tested without forging a
//! whole object file.

use rampage_loaders::Binary;

use crate::model::{Condition, Confidence, Detection, Signature, SignatureDb};

/// The facts a signature is tested against: entry-point bytes, the image, named sections, imports and overlay.
pub(crate) trait Image {
    /// The file-backed bytes at the entry point, or `None` when there is no entry or they are unmapped.
    fn entry_bytes(&self, len: usize) -> Option<&[u8]>;
    /// The whole image's bytes, scanned for un-anchored patterns and image-wide needles.
    fn image_bytes(&self) -> &[u8];
    /// Every section in file order: its name and its file-backed bytes (`None` for zero-fill sections).
    fn sections(&self) -> Vec<(&str, Option<&[u8]>)>;
    /// Whether any imported library's name contains `needle_lowercase` (compared case-insensitively).
    fn imports_library(&self, needle_lowercase: &str) -> bool;
    /// Whether any imported function matches `name` (compared case-insensitively).
    fn imports_function(&self, name: &str) -> bool;
    /// The overlay's size in bytes, when the image has one.
    fn overlay_size(&self) -> Option<u64>;
}

/// Identifies the tools that produced `binary`, testing every signature in `db`. Detections that name the same
/// tool are merged, their evidence pooled, and the result is sorted strongest first, then by name.
pub fn identify(binary: &Binary, db: &SignatureDb) -> Vec<Detection> {
    identify_image(binary, db)
}

pub(crate) fn identify_image(image: &impl Image, db: &SignatureDb) -> Vec<Detection> {
    let mut detections: Vec<Detection> = Vec::new();
    for signature in &db.signatures {
        if let Some(detection) = evaluate(image, signature) {
            merge(&mut detections, detection);
        }
    }
    detections.sort_by(|a, b| {
        let strength = |c| matches!(c, Confidence::Strong);
        strength(b.confidence).cmp(&strength(a.confidence)).then_with(|| a.name.cmp(&b.name))
    });
    detections
}

/// A signature matches only when every condition holds; the detection carries one evidence line per condition
/// and a confidence derived from how distinctive the matched conditions were.
fn evaluate(image: &impl Image, signature: &Signature) -> Option<Detection> {
    if signature.conditions.is_empty() {
        return None;
    }
    let mut evidence = Vec::with_capacity(signature.conditions.len());
    for condition in &signature.conditions {
        evidence.push(check(image, condition)?);
    }
    let distinctive = signature.conditions.iter().any(Condition::is_distinctive);
    // A single generic signal is tentative; a distinctive one, or several corroborating ones, is strong.
    let confidence =
        if distinctive || signature.conditions.len() >= 2 { Confidence::Strong } else { Confidence::Tentative };
    Some(Detection { name: signature.name.clone(), kind: signature.kind, confidence, evidence })
}

/// Tests one condition, returning a human-readable evidence line when it holds.
fn check(image: &impl Image, condition: &Condition) -> Option<String> {
    match condition {
        Condition::Entry { pattern, ep_only } => {
            if *ep_only {
                let bytes = image.entry_bytes(pattern.len())?;
                pattern.matches_at(bytes).then(|| format!("entry-point bytes match {}-byte pattern", pattern.len()))
            } else {
                let at = pattern.find_in(image.image_bytes())?;
                Some(format!("pattern found at image offset {at:#x}"))
            }
        }
        Condition::SectionName(name) => find_section(image, name).is_some().then(|| format!("section {name} present")),
        Condition::AnySectionName(names) | Condition::UniqueSectionName(names) => {
            names.iter().find(|name| find_section(image, name).is_some()).map(|name| format!("section {name} present"))
        }
        Condition::SectionContains { section: wanted, needle } => match wanted {
            Some(name) => {
                let bytes = find_section(image, name).flatten()?;
                contains(bytes, needle).then(|| format!("section {name} contains {:?}", preview(needle)))
            }
            None => contains(image.image_bytes(), needle).then(|| format!("image contains {:?}", preview(needle))),
        },
        Condition::ImportLibrary(library) => image
            .imports_library(&library.to_ascii_lowercase())
            .then(|| format!("imports from a library matching {library:?}")),
        Condition::ImportFunction(name) => image.imports_function(name).then(|| format!("imports function {name}")),
        Condition::OverlayPresent => image.overlay_size().map(|size| format!("{size} bytes of overlay")),
        Condition::MinImageEntropy(min) => {
            let entropy = shannon_entropy(image.image_bytes());
            (entropy >= *min).then(|| format!("image entropy {entropy:.2} >= {min:.2}"))
        }
        Condition::MinSectionEntropy { section, min } => section_entropy(image, section.as_deref())
            .filter(|&(_, entropy)| entropy >= *min)
            .map(|(name, entropy)| format!("section {name} entropy {entropy:.2} >= {min:.2}")),
    }
}

/// The first section named `name`: `None` when absent, `Some(None)` when present but not file-backed.
fn find_section<'a>(image: &'a impl Image, name: &str) -> Option<Option<&'a [u8]>> {
    image.sections().into_iter().find(|(present, _)| *present == name).map(|(_, bytes)| bytes)
}

/// Naive substring search; needles are short and images are bounded, so this stays cheap.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// A short printable preview of a needle for an evidence line.
fn preview(needle: &[u8]) -> String {
    String::from_utf8_lossy(needle).into_owned()
}

/// The entropy of a named section, or of the highest-entropy section when `section` is `None`.
fn section_entropy(image: &impl Image, section: Option<&str>) -> Option<(String, f64)> {
    match section {
        Some(name) => Some((name.to_owned(), shannon_entropy(find_section(image, name).flatten()?))),
        None => image
            .sections()
            .into_iter()
            .filter_map(|(name, bytes)| Some((name.to_owned(), shannon_entropy(bytes?))))
            .max_by(|a, b| a.1.total_cmp(&b.1)),
    }
}

/// Shannon entropy in bits per byte (0-8). Reimplemented here to keep the crate free of an analysis dependency.
pub(crate) fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    let total = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// Folds a new detection into the list, merging it with an existing one for the same tool.
fn merge(detections: &mut Vec<Detection>, detection: Detection) {
    if let Some(existing) = detections.iter_mut().find(|d| d.name == detection.name) {
        for line in detection.evidence {
            if !existing.evidence.contains(&line) {
                existing.evidence.push(line);
            }
        }
        if matches!(detection.confidence, Confidence::Strong) {
            existing.confidence = Confidence::Strong;
        }
        return;
    }
    detections.push(detection);
}

/// [`Binary`] viewed as an [`Image`]: sections by file offset (so unloaded sections such as `.comment` read),
/// imports from its import table, and the loader's overlay.
impl Image for Binary {
    fn entry_bytes(&self, len: usize) -> Option<&[u8]> {
        self.read(self.entry?, len as u64)
    }

    fn image_bytes(&self) -> &[u8] {
        Binary::image_bytes(self)
    }

    fn sections(&self) -> Vec<(&str, Option<&[u8]>)> {
        let image = Binary::image_bytes(self);
        self.sections.iter().map(|section| (section.name.as_str(), section_file_bytes(image, section))).collect()
    }

    fn imports_library(&self, needle_lowercase: &str) -> bool {
        self.imports
            .iter()
            .filter_map(|import| import.library.as_deref())
            .any(|library| library.to_ascii_lowercase().contains(needle_lowercase))
    }

    fn imports_function(&self, name: &str) -> bool {
        self.imports.iter().any(|import| import.name.eq_ignore_ascii_case(name))
    }

    fn overlay_size(&self) -> Option<u64> {
        self.overlay.map(|overlay| overlay.size)
    }
}

/// A section's file-backed bytes, sliced from the image by its file offset (not its virtual address), so that
/// unloaded sections work too. `None` when the section is zero-fill or its range falls outside the image.
fn section_file_bytes<'a>(image: &'a [u8], section: &rampage_loaders::Section) -> Option<&'a [u8]> {
    let offset = usize::try_from(section.file_offset?).ok()?;
    let size = usize::try_from(section.file_size).ok()?;
    image.get(offset..offset.checked_add(size)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Condition, Kind, Signature};
    use crate::pattern::BytePattern;

    /// A crafted image: enough to drive every condition without forging a real object file.
    #[derive(Default)]
    struct Fake {
        entry: Vec<u8>,
        image: Vec<u8>,
        sections: Vec<(String, Vec<u8>)>,
        libraries: Vec<String>,
        functions: Vec<String>,
        overlay: Option<u64>,
    }

    impl Fake {
        fn with_section(mut self, name: &str, bytes: &[u8]) -> Self {
            self.sections.push((name.to_owned(), bytes.to_vec()));
            self
        }
    }

    impl Image for Fake {
        fn entry_bytes(&self, _len: usize) -> Option<&[u8]> {
            (!self.entry.is_empty()).then_some(self.entry.as_slice())
        }
        fn image_bytes(&self) -> &[u8] {
            &self.image
        }
        fn sections(&self) -> Vec<(&str, Option<&[u8]>)> {
            self.sections.iter().map(|(name, bytes)| (name.as_str(), Some(bytes.as_slice()))).collect()
        }
        fn imports_library(&self, needle_lowercase: &str) -> bool {
            self.libraries.iter().any(|library| library.to_ascii_lowercase().contains(needle_lowercase))
        }
        fn imports_function(&self, name: &str) -> bool {
            self.functions.iter().any(|f| f.eq_ignore_ascii_case(name))
        }
        fn overlay_size(&self) -> Option<u64> {
            self.overlay
        }
    }

    fn entry(pattern: &str) -> Condition {
        Condition::Entry { pattern: BytePattern::parse(pattern).unwrap(), ep_only: true }
    }

    #[test]
    fn entry_pattern_with_wildcards_matches_and_rejects_crafted_bytes() {
        let sig = Signature::new("Stub", Kind::Packer, vec![entry("60 BE ?? ?? ?? ??")]);
        let hit = Fake { entry: vec![0x60, 0xbe, 0x11, 0x22, 0x33, 0x44], ..Fake::default() };
        let miss = Fake { entry: vec![0x61, 0xbe, 0x11, 0x22, 0x33, 0x44], ..Fake::default() };
        assert_eq!(super::evaluate(&hit, &sig).map(|d| d.evidence.len()), Some(1));
        assert!(super::evaluate(&miss, &sig).is_none());
    }

    #[test]
    fn an_entry_pattern_is_strong_only_with_four_fixed_bytes() {
        let image = Fake { entry: vec![0x61, 0xbe, 0x11, 0x22], ..Fake::default() };
        let confidence = |pattern: &str| {
            let sig = Signature::new("Stub", Kind::Packer, vec![entry(pattern)]);
            super::evaluate(&image, &sig).unwrap().confidence
        };
        assert_eq!(confidence("61"), Confidence::Tentative);
        assert_eq!(confidence("61 BE 1? ??"), Confidence::Tentative);
        assert_eq!(confidence("61 BE 11 22"), Confidence::Strong);
    }

    #[test]
    fn section_name_signature_fires_on_a_crafted_section_list() {
        let sig = Signature::new(
            "UPX",
            Kind::Packer,
            vec![Condition::SectionName("UPX0".to_owned()), Condition::SectionName("UPX1".to_owned())],
        );
        let packed = Fake::default().with_section("UPX0", &[]).with_section("UPX1", &[0xff; 64]);
        let plain = Fake::default().with_section(".text", &[0x90; 64]);
        let detection = super::evaluate(&packed, &sig).expect("UPX section match");
        assert_eq!(detection.confidence, Confidence::Strong);
        assert!(super::evaluate(&plain, &sig).is_none());
    }

    #[test]
    fn any_section_name_matches_either_alternative() {
        let sig = Signature::new(
            "MPRESS",
            Kind::Packer,
            vec![Condition::AnySectionName(vec![".MPRESS1".to_owned(), ".MPRESS2".to_owned()])],
        );
        let hit = Fake::default().with_section(".MPRESS2", &[0x00; 16]);
        assert!(super::evaluate(&hit, &sig).is_some());
        assert!(super::evaluate(&Fake::default(), &sig).is_none());
    }

    #[test]
    fn import_based_signature_matches_library_and_function() {
        let lib = Signature::new("MSVC", Kind::Compiler, vec![Condition::ImportLibrary("vcruntime".to_owned())]);
        let func = Signature::new(".NET", Kind::Compiler, vec![Condition::ImportFunction("_CorExeMain".to_owned())]);
        let image = Fake {
            libraries: vec!["VCRUNTIME140.dll".to_owned(), "KERNEL32.dll".to_owned()],
            functions: vec!["_CorExeMain".to_owned()],
            ..Fake::default()
        };
        assert!(super::evaluate(&image, &lib).is_some());
        assert!(super::evaluate(&image, &func).is_some());
        assert!(super::evaluate(&Fake::default(), &lib).is_none());
    }

    #[test]
    fn overlay_and_entropy_conditions_gate_on_crafted_values() {
        let overlay_sig = Signature::new("Installer", Kind::Installer, vec![Condition::OverlayPresent]);
        let with_overlay = Fake { overlay: Some(4096), ..Fake::default() };
        assert!(super::evaluate(&with_overlay, &overlay_sig).is_some());
        assert!(super::evaluate(&Fake::default(), &overlay_sig).is_none());

        // A uniform-random section reaches 8 bits/byte; a run of one value sits at 0.
        let high: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let entropy_sig = Signature::new(
            "Packed",
            Kind::Packer,
            vec![Condition::MinSectionEntropy { section: Some(".text".to_owned()), min: 7.0 }],
        );
        let packed = Fake::default().with_section(".text", &high);
        let plain = Fake::default().with_section(".text", &[0x90; 4096]);
        assert!(super::evaluate(&packed, &entropy_sig).is_some());
        assert!(super::evaluate(&plain, &entropy_sig).is_none());
    }

    #[test]
    fn image_wide_needle_matches_anywhere_in_the_image() {
        let sig = Signature::new(
            "NSIS",
            Kind::Installer,
            vec![Condition::SectionContains { section: None, needle: b"NullsoftInst".to_vec() }],
        );
        let image = Fake { image: b"....NullsoftInst0123".to_vec(), ..Fake::default() };
        assert!(super::evaluate(&image, &sig).is_some());
        assert!(super::evaluate(&Fake::default(), &sig).is_none());
    }

    #[test]
    fn same_tool_from_two_signatures_merges_into_one_detection() {
        let mut db = SignatureDb::new();
        db.push(Signature::new("UPX", Kind::Packer, vec![Condition::SectionName("UPX0".to_owned())]));
        db.push(Signature::new("UPX", Kind::Packer, vec![entry("60 BE 01 02 ?? ??")]));
        let image =
            Fake { entry: vec![0x60, 0xbe, 0x01, 0x02, 0x03, 0x04], ..Fake::default() }.with_section("UPX0", &[]);
        let detections = identify_image(&image, &db);
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].evidence.len(), 2);
        assert_eq!(detections[0].confidence, Confidence::Strong);
    }

    #[test]
    fn a_single_generic_section_name_is_only_tentative() {
        let sig = Signature::new("PECompact", Kind::Packer, vec![Condition::SectionName("pec1".to_owned())]);
        let image = Fake::default().with_section("pec1", &[0u8; 8]);
        assert_eq!(super::evaluate(&image, &sig).unwrap().confidence, Confidence::Tentative);
    }

    #[test]
    fn a_single_tool_branded_section_name_is_strong() {
        let names = vec![".gopclntab".to_owned(), "__gopclntab".to_owned()];
        let sig = Signature::new("Go", Kind::Compiler, vec![Condition::UniqueSectionName(names)]);
        let image = Fake::default().with_section(".gopclntab", &[0u8; 8]);
        let detection = super::evaluate(&image, &sig).unwrap();
        assert_eq!(detection.confidence, Confidence::Strong);
        assert_eq!(detection.evidence, ["section .gopclntab present"]);
        // Absent names still do not match.
        assert!(super::evaluate(&Fake::default().with_section(".text", &[0u8; 8]), &sig).is_none());
    }
}
